package main

import (
	"bufio"
	"client/config"
	"client/decoy"
	"client/share"
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io"
	"log"
	"math/big"
	mrand "math/rand"
	"net"
	_ "net/http/pprof"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/anacrolix/utp"
	"github.com/hashicorp/yamux"
)

const (
	pstr         = "BitTorrent protocol"
	pstrlen      = 19
	handshakeLen = 68
	pieceMsgID   = 7
	unchokeMsgID = 1
	interestedID = 2
)

var (
	cfg                 *config.Config
	gServerAddr         string
	gAuthKey            []byte
	gInfoHash           [20]byte
	gSessionsNum        int
	gConnectionsTimeOut time.Duration

	// Session pool
	sessions     []*yamux.Session
	sessMu       []sync.Mutex
	getSessionMu sync.Mutex
)

func main() {
	cfg, err := config.LoadConfig("config.yaml")
	if err != nil {
		log.Printf("[ERR] Config parse failed: " + err.Error())
		return
	}

	ctx, cancel := context.WithCancel(context.Background())

	if cfg.DecoyTraffic {
		log.Printf("[INFO] Decoy traffic: enabled")
		go decoy.StartGlobalDecoy(ctx)
	}

	go func() {
		quit := make(chan os.Signal, 1)
		signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
		<-quit
		log.Printf("[INFO] Shutdown")
		cancel()
	}()

	err = Start(cfg, ctx)
	if err != nil {
		log.Printf("[ERR] Failed start: " + err.Error())
		return
	}
}

// Start initializes and runs the Torrent client module.
func Start(c *config.Config, ctx context.Context) error {
	cfg = c
	gServerAddr = cfg.Server
	gConnectionsTimeOut = time.Duration(cfg.Torrent.ConnectionsTimeOut) * time.Second

	gSessionsNum = cfg.Torrent.SessionsNum
	sessions = make([]*yamux.Session, gSessionsNum)
	sessMu = make([]sync.Mutex, gSessionsNum)

	var err error
	if cfg.Torrent.AuthKey == "" {
		return fmt.Errorf("auth-key is required for torrent protocol")
	}
	gAuthKey, err = hex.DecodeString(cfg.Torrent.AuthKey)
	if err != nil || len(gAuthKey) != 32 {
		return fmt.Errorf("invalid auth-key: must be 64 hex chars (32 bytes)")
	}

	// Prepare InfoHash
	if cfg.Torrent.InfoHash != "" {
		ih, err := hex.DecodeString(cfg.Torrent.InfoHash)
		if err != nil || len(ih) != 20 {
			return fmt.Errorf("invalid info-hash: must be 40 hex chars (20 bytes)")
		}
		copy(gInfoHash[:], ih)
	} else {
		// Generate random InfoHash if not provided
		rand.Read(gInfoHash[:])
		log.Printf("[INFO] Using random info-hash: %s", hex.EncodeToString(gInfoHash[:]))
	}

	// Start White Noise generator (Trackers Announce)
	go startWhiteNoise(ctx)

	ln, err := net.Listen("tcp", cfg.ListenAddr)
	if err != nil {
		return fmt.Errorf("failed to listen on %s: %v", cfg.ListenAddr, err)
	}
	defer ln.Close()

	log.Printf("[INFO] Torrent client (uTP) on %s → %s", cfg.ListenAddr, cfg.Server)

	go func() {
		<-ctx.Done()
		ln.Close()
	}()

	for {
		conn, err := ln.Accept()
		if err != nil {
			select {
			case <-ctx.Done():
				log.Printf("[INFO] Torrent client listener closed, stopping")
				time.Sleep(3 * time.Second)
				return nil
			default:
			}
			log.Printf("[ERR] SOCKS5 accept: %v", err)
			continue
		}
		go handleSOCKS5(ctx, conn)
	}
}

func handleSOCKS5(ctx context.Context, conn net.Conn) {
	sCtx, sCancel := context.WithCancel(ctx)
	defer sCancel()
	defer conn.Close()

	conn = &timeoutConn{Conn: conn}

	cmd, host, port, err := share.Socks5Handshake(conn, cfg.UDPEnabled)
	if err != nil {
		log.Printf("[ERR] SOCKS5 handshake error from %s: %v", conn.RemoteAddr(), err)
		return
	}

	if cmd == 0x03 {
		handleSocks5UDP(ctx, conn)
		return
	}

	conn.Write([]byte{0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0})

	target := net.JoinHostPort(host, fmt.Sprintf("%d", port))
	log.Printf("[INFO] Tunneling %s → %s", conn.RemoteAddr(), target)

	var rawStream net.Conn
	var sErr error

	for attempt := 0; attempt < 3; attempt++ {
		sess, err := getSession(sCtx)
		if err != nil {
			log.Printf("[ERR] failed to get session: %v", err)
			return
		}

		rawStream, sErr = sess.Open()
		if sErr == nil {
			targetBytes := []byte(target)
			lenBuf := make([]byte, 4)
			binary.BigEndian.PutUint32(lenBuf, uint32(len(targetBytes)))
			if _, err := rawStream.Write(lenBuf); err == nil {
				if _, err := rawStream.Write(targetBytes); err == nil {
					break
				}
			}
			rawStream.Close()
			dropSession(sess)
		}
	}

	if sErr != nil || rawStream == nil {
		return
	}

	stream := &timeoutConn{Conn: rawStream}
	defer stream.Close()

	// Relay data with half-close support
	go func() {
		b := share.CopyBufPool.Get().(*[]byte)
		defer share.CopyBufPool.Put(b)
		var dst io.Writer = stream
		io.CopyBuffer(dst, conn, *b)
		share.CloseWrite(stream)
	}()

	go func() {
		defer sCancel()
		b := share.CopyBufPool.Get().(*[]byte)
		defer share.CopyBufPool.Put(b)
		var src io.Reader = stream
		io.CopyBuffer(conn, src, *b)
	}()

	<-sCtx.Done()
}

type timeoutConn struct {
	net.Conn
}

func (ts *timeoutConn) CloseWrite() error {
	type halfCloser interface{ CloseWrite() error }
	if hc, ok := ts.Conn.(halfCloser); ok {
		return hc.CloseWrite()
	}
	return nil
}

func (ts *timeoutConn) Read(p []byte) (n int, err error) {
	if gConnectionsTimeOut > 0 {
		ts.Conn.SetReadDeadline(time.Now().Add(gConnectionsTimeOut))
	}
	n, err = ts.Conn.Read(p)
	return
}

func (ts *timeoutConn) Write(p []byte) (n int, err error) {
	if gConnectionsTimeOut > 0 {
		ts.Conn.SetWriteDeadline(time.Now().Add(gConnectionsTimeOut))
	}
	n, err = ts.Conn.Write(p)
	return
}

type timeoutPacketConn struct {
	net.PacketConn
}

func (ts *timeoutPacketConn) ReadFrom(p []byte) (n int, addr net.Addr, err error) {
	if gConnectionsTimeOut > 0 {
		ts.PacketConn.SetReadDeadline(time.Now().Add(gConnectionsTimeOut))
	}
	n, addr, err = ts.PacketConn.ReadFrom(p)
	return
}

func (ts *timeoutPacketConn) WriteTo(p []byte, addr net.Addr) (n int, err error) {
	if gConnectionsTimeOut > 0 {
		ts.PacketConn.SetWriteDeadline(time.Now().Add(gConnectionsTimeOut))
	}
	n, err = ts.PacketConn.WriteTo(p, addr)
	return
}

func handleSocks5UDP(ctx context.Context, rawTcpConn net.Conn) {
	// Create local UDP socket for SOCKS5 app
	rawUdpConn, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		rawTcpConn.Write([]byte{0x05, 0x01, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
		log.Printf("[ERR] UDP ASSOCIATE listen error: %v", err)
		return
	}
	udpConn := &timeoutPacketConn{PacketConn: rawUdpConn}

	// Жизненный цикл UDP релея
	udpCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	defer udpConn.Close()

	udpAddr := udpConn.LocalAddr().(*net.UDPAddr)
	reply := []byte{0x05, 0x00, 0x00, 0x01, 127, 0, 0, 1, byte(udpAddr.Port >> 8), byte(udpAddr.Port)}
	if _, err := rawTcpConn.Write(reply); err != nil {
		return
	}

	var addrMu sync.Mutex
	var appAddr net.Addr

	// Get a session and open a stream for UDP relay
	var rawStream net.Conn
	for attempt := 0; attempt < 3; attempt++ {
		sess, err := getSession(udpCtx)
		if err != nil {
			log.Printf("[ERR] failed to get session for UDP: %v", err)
			return
		}

		s, err := sess.Open()
		if err == nil {
			targetBytes := []byte("UDP_RELAY")
			lenBuf := make([]byte, 4)
			binary.BigEndian.PutUint32(lenBuf, uint32(len(targetBytes)))
			if _, err := s.Write(lenBuf); err == nil {
				if _, err := s.Write(targetBytes); err == nil {
					rawStream = s
					break
				}
			}
			s.Close()
			dropSession(sess)
		}
	}

	if rawStream == nil {
		log.Printf("[ERR] failed to establish UDP stream after retries")
		return
	}

	stream := &timeoutConn{Conn: rawStream}
	defer stream.Close()

	var relayWriter io.Writer = stream
	var relayReader io.Reader = stream

	log.Printf("[INFO] UDP relay active, local UDP: %s", udpAddr)

	// App -> Server / Bypass
	go func() {
		defer cancel()
		bufPtr := share.UDPBufPool.Get().(*[]byte)
		defer share.UDPBufPool.Put(bufPtr)
		buf := *bufPtr

		frameBufPtr := share.UDPBufPool.Get().(*[]byte)
		defer share.UDPBufPool.Put(frameBufPtr)
		frameBuf := *frameBufPtr

		for {
			n, addr, err := udpConn.ReadFrom(buf)
			if err != nil {
				return
			}

			addrMu.Lock()
			if appAddr == nil {
				appAddr = addr
			}
			isApp := addr.String() == appAddr.String()
			addrMu.Unlock()

			if !isApp {
				addrMu.Lock()
				app := appAddr
				addrMu.Unlock()
				if app != nil {
					udpSrc := addr.(*net.UDPAddr)
					resp := []byte{0, 0, 0}
					if ip4 := udpSrc.IP.To4(); ip4 != nil {
						resp = append(resp, 0x01)
						resp = append(resp, ip4...)
					} else {
						resp = append(resp, 0x04)
						resp = append(resp, udpSrc.IP.To16()...)
					}
					var p [2]byte
					binary.BigEndian.PutUint16(p[:], uint16(udpSrc.Port))
					resp = append(resp, p[:]...)
					resp = append(resp, buf[:n]...)
					udpConn.WriteTo(resp, app)
				}
				continue
			}

			if n < 4 || buf[2] != 0x00 {
				continue
			}

			// Tunnel
			payload := buf[3:n]
			binary.BigEndian.PutUint32(frameBuf[:4], uint32(len(payload)))
			copy(frameBuf[4:], payload)
			if _, err := relayWriter.Write(frameBuf[:4+len(payload)]); err != nil {
				return
			}
		}
	}()

	// Server -> App
	go func() {
		defer cancel()
		lenBuf := make([]byte, 4)
		pktBufPtr := share.UDPBufPool.Get().(*[]byte)
		defer share.UDPBufPool.Put(pktBufPtr)
		pktBuf := *pktBufPtr
		pktBuf[0] = 0x00
		pktBuf[1] = 0x00
		pktBuf[2] = 0x00
		for {
			if _, err := io.ReadFull(relayReader, lenBuf); err != nil {
				return
			}

			payloadLen := binary.BigEndian.Uint32(lenBuf)
			if payloadLen > 65535 {
				return
			}
			payload := pktBuf[3 : 3+payloadLen]
			if _, err := io.ReadFull(relayReader, payload); err != nil {
				return
			}
			addrMu.Lock()
			a := appAddr
			addrMu.Unlock()
			if a != nil {
				udpConn.WriteTo(pktBuf[:3+payloadLen], a)
			}
		}
	}()

	// Ждем закрытия контекста или TCP соединения
	<-udpCtx.Done()
}

func getSession(ctx context.Context) (*yamux.Session, error) {
	getSessionMu.Lock()
	defer getSessionMu.Unlock()

	idx := mrand.Intn(gSessionsNum)
	if sessions[idx] != nil && !sessions[idx].IsClosed() {
		return sessions[idx], nil
	}

	sess, err := establishSession(ctx, idx)
	if err == nil {
		return sess, nil
	}

	for i := 0; i < gSessionsNum; i++ {
		if sessions[i] != nil && !sessions[i].IsClosed() {
			return sessions[i], nil
		}
	}

	return nil, fmt.Errorf("no available sessions: %w", err)
}

func establishSession(ctx context.Context, idx int) (*yamux.Session, error) {
	sessMu[idx].Lock()
	defer sessMu[idx].Unlock()

	if sessions[idx] != nil && !sessions[idx].IsClosed() {
		return sessions[idx], nil
	}

	// Resolve server address and handle port hopping
	host, portStr, err := net.SplitHostPort(gServerAddr)
	if err != nil {
		return nil, fmt.Errorf("invalid server address: %w", err)
	}

	var targetAddr string
	if strings.Contains(portStr, "-") {
		parts := strings.Split(portStr, "-")
		startPort, _ := strconv.Atoi(parts[0])
		endPort, _ := strconv.Atoi(parts[1])
		randomPort := startPort + mrand.Intn(endPort-startPort+1)
		targetAddr = net.JoinHostPort(host, strconv.Itoa(randomPort))
	} else {
		targetAddr = gServerAddr
	}

	// 1. Create uTP connection
	s, err := utp.Dial(targetAddr)
	if err != nil {
		return nil, err
	}

	// 2. Send BitTorrent Handshake with HMAC
	peerID := generatePeerID()
	handshake := make([]byte, handshakeLen)
	handshake[0] = pstrlen
	copy(handshake[1:20], pstr)
	copy(handshake[28:48], gInfoHash[:])
	copy(handshake[48:68], peerID[:])

	if _, err := s.Write(handshake); err != nil {
		s.Close()
		return nil, err
	}

	// 3. Receive server handshake
	s.SetReadDeadline(time.Now().Add(30 * time.Second))
	respHandshake := make([]byte, handshakeLen)
	if _, err := io.ReadFull(s, respHandshake); err != nil {
		s.Close()
		return nil, err
	}
	s.SetReadDeadline(time.Time{}) // Reset deadline

	// 4. Send "Interested" and "Unchoke"
	s.Write([]byte{0, 0, 0, 1, interestedID})
	s.Write([]byte{0, 0, 0, 1, unchokeMsgID})

	// 5. Setup yamux
	muxCfg := yamux.DefaultConfig()
	muxCfg.MaxStreamWindowSize = 8 * 1024 * 1024
	muxCfg.EnableKeepAlive = true
	muxCfg.StreamCloseTimeout = 10 * time.Second
	muxCfg.LogOutput = io.Discard

	sess, err := yamux.Client(NewTorrentConn(s), muxCfg)
	if err != nil {
		s.Close()
		return nil, err
	}

	go func() {
		scheduleReconnect(ctx, sess)
	}()

	sessions[idx] = sess
	return sess, nil
}

func scheduleReconnect(ctx context.Context, s *yamux.Session) {
	// Random delay in [3, 15) minutes using crypto/rand for unpredictability.
	const minDelay = 3 * time.Minute
	const maxJitter = 12 * time.Minute

	delay := minDelay
	n, err := rand.Int(rand.Reader, big.NewInt(int64(maxJitter)))
	if err == nil {
		delay += time.Duration(n.Int64())
	}

	select {
	case <-time.After(delay):
	case <-ctx.Done():
		return
	}

	for i := 0; i < gSessionsNum; i++ {
		sessMu[i].Lock()
		if sessions[i] == s {
			sessions[i] = nil
			go func() {
				time.Sleep(5 * time.Minute)
				s.Close()
			}()
			sessMu[i].Unlock()
			break
		}
		sessMu[i].Unlock()
	}
}

func dropSession(s *yamux.Session) {
	for i := 0; i < gSessionsNum; i++ {
		sessMu[i].Lock()
		if sessions[i] == s {
			sessions[i] = nil
			go s.Close()
			sessMu[i].Unlock()
			break
		}
		sessMu[i].Unlock()
	}
}

func generatePeerID() [20]byte {
	var pid [20]byte
	copy(pid[:8], []byte("-TR4000-"))
	nonce := make([]byte, 4)
	rand.Read(nonce)
	copy(pid[8:12], nonce)
	mac := hmac.New(sha1.New, gAuthKey)
	mac.Write(nonce)
	mac.Write(gInfoHash[:])
	sig := mac.Sum(nil)[:8]
	copy(pid[12:20], sig)
	return pid
}

type TorrentConn struct {
	net.Conn
	reader           *bufio.Reader
	writer           *bufio.Writer
	remainingPayload int
	remainingPadding int
	flushTimer       *time.Timer
	mu               sync.Mutex
}

func NewTorrentConn(conn net.Conn) *TorrentConn {
	tc := &TorrentConn{
		Conn:   conn,
		reader: bufio.NewReaderSize(conn, 256*1024),
	}
	// Оборачиваем запись в буфер для снижения оверхеда паддинга
	tc.writer = bufio.NewWriterSize(&rawPieceWriter{tc}, 16*1024)
	return tc
}

type rawPieceWriter struct {
	tc *TorrentConn
}

func (w *rawPieceWriter) Write(p []byte) (int, error) {
	return w.tc.writePiece(p)
}

func (c *TorrentConn) Read(p []byte) (n int, err error) {
	if c.reader == nil {
		c.reader = bufio.NewReaderSize(c.Conn, 256*1024)
	}

	for {
		if c.remainingPayload > 0 {
			toRead := c.remainingPayload
			if toRead > len(p) {
				toRead = len(p)
			}
			n, err = c.reader.Read(p[:toRead])
			if err != nil {
				return n, err
			}
			c.remainingPayload -= n
			return n, nil
		}

		// Если полезная нагрузка считана, но остался паддинг — сбрасываем его
		if c.remainingPadding > 0 {
			if _, err := c.reader.Discard(c.remainingPadding); err != nil {
				return 0, err
			}
			c.remainingPadding = 0
		}

		var header [4]byte
		// Читаем длину (4 байта)
		if _, err := io.ReadFull(c.reader, header[:]); err != nil {
			return 0, err
		}
		length := binary.BigEndian.Uint32(header[:])
		if length == 0 {
			continue
		}

		// Читаем ID (1 байт)
		msgID, err := c.reader.ReadByte()
		if err != nil {
			return 0, err
		}

		if msgID == pieceMsgID {
			// Discard Index(4) + Offset(4) = 8 bytes
			if _, err := c.reader.Discard(8); err != nil {
				return 0, err
			}

			// Читаем наш внутренний заголовок PayloadLen (2 байта)
			var pLenBuf [2]byte
			if _, err := io.ReadFull(c.reader, pLenBuf[:]); err != nil {
				return 0, err
			}
			pLen := int(binary.BigEndian.Uint16(pLenBuf[:]))

			// Общий остаток в этом piece (за вычетом Index+Offset+PayloadLen)
			totalInPiece := int(length) - 11
			if pLen > totalInPiece {
				return 0, fmt.Errorf("torrent protocol corruption: payload %d > total %d", pLen, totalInPiece)
			}

			c.remainingPayload = pLen
			c.remainingPadding = totalInPiece - pLen

			if c.remainingPayload == 0 {
				// Если пакет пустой (только паддинг), продолжаем цикл
				continue
			}
		} else {
			// Пропускаем другие типы сообщений
			if _, err := c.reader.Discard(int(length) - 1); err != nil {
				return 0, err
			}
		}
	}
}

func (c *TorrentConn) Write(p []byte) (n int, err error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	n, err = c.writer.Write(p)

	// Сбрасываем/запускаем таймер авто-флаша для минимизации задержек
	if c.flushTimer != nil {
		c.flushTimer.Stop()
	}
	c.flushTimer = time.AfterFunc(5*time.Millisecond, func() {
		c.mu.Lock()
		c.writer.Flush()
		c.mu.Unlock()
	})

	return n, err
}

// Внутренний метод записи уже сформированного торрент-пакета
func (c *TorrentConn) writePiece(p []byte) (n int, err error) {
	const bittorrentHeadLen = 9
	const internalHeadLen = 2
	padLen := mrand.Intn(256)

	bufPtr := share.UDPBufPool.Get().(*[]byte)
	defer share.UDPBufPool.Put(bufPtr)
	buf := *bufPtr

	totalMsgLen := bittorrentHeadLen + internalHeadLen + len(p) + padLen
	binary.BigEndian.PutUint32(buf[0:4], uint32(totalMsgLen))
	buf[4] = pieceMsgID
	binary.BigEndian.PutUint32(buf[5:9], uint32(mrand.Int31n(1000)))
	binary.BigEndian.PutUint32(buf[9:13], uint32(mrand.Int31n(131072)))
	binary.BigEndian.PutUint16(buf[13:15], uint16(len(p)))
	copy(buf[15:], p)

	if padLen > 0 {
		rand.Read(buf[15+len(p) : 15+len(p)+padLen])
	}

	_, err = c.Conn.Write(buf[:4+totalMsgLen])
	return len(p), err
}

func startWhiteNoise(ctx context.Context) {
	trackers := []string{
		"udp://tracker.opentrackr.org:1337/announce",
		"udp://tracker.openbittorrent.com:6969/announce",
		"udp://9.rarbg.com:2810/announce",
		"udp://exodus.desync.com:6969/announce",
		"udp://open.stealth.si:80/announce",
	}

	peerID := generatePeerID()

	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()

	// Сразу сделаем первый анонс
	go announceToAll(trackers, gInfoHash, peerID)

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			go announceToAll(trackers, gInfoHash, peerID)
		}
	}
}

func announceToAll(trackers []string, infoHash, peerID [20]byte) {
	for _, tr := range trackers {
		go func(urlStr string) {
			if err := announceToTracker(urlStr, infoHash, peerID); err != nil {
				// log.Printf("[DEBUG] WhiteNoise: announce to %s failed: %v", urlStr, err)
			} else {
				log.Printf("[INFO] WhiteNoise: Announced to tracker %s", urlStr)
			}
		}(tr)
	}
}

func announceToTracker(urlStr string, infoHash, peerID [20]byte) error {
	u, err := net.ResolveUDPAddr("udp", strings.TrimPrefix(urlStr, "udp://"))
	if err != nil {
		return err
	}

	conn, err := net.DialUDP("udp", nil, u)
	if err != nil {
		return err
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(10 * time.Second))

	// 1. Connection request
	transactionID := uint32(mrand.Int31())
	req := make([]byte, 16)
	binary.BigEndian.PutUint64(req[0:8], 0x41727101980) // protocol_id
	binary.BigEndian.PutUint32(req[8:12], 0)            // action: connect
	binary.BigEndian.PutUint32(req[12:16], transactionID)

	if _, err := conn.Write(req); err != nil {
		return err
	}

	resp := make([]byte, 16)
	if _, err := io.ReadFull(conn, resp); err != nil {
		return err
	}

	if binary.BigEndian.Uint32(resp[0:4]) != 0 || binary.BigEndian.Uint32(resp[4:8]) != transactionID {
		return fmt.Errorf("invalid connect response")
	}
	connectionID := binary.BigEndian.Uint64(resp[8:16])

	// 2. Announce request
	ann := make([]byte, 98)
	binary.BigEndian.PutUint64(ann[0:8], connectionID)
	binary.BigEndian.PutUint32(ann[8:12], 1) // action: announce
	binary.BigEndian.PutUint32(ann[12:16], transactionID)
	copy(ann[16:36], infoHash[:])
	copy(ann[36:56], peerID[:])
	binary.BigEndian.PutUint64(ann[56:64], 0)          // downloaded
	binary.BigEndian.PutUint64(ann[64:72], 0)          // left (fake)
	binary.BigEndian.PutUint64(ann[72:80], 0)          // uploaded
	binary.BigEndian.PutUint32(ann[80:84], 0)          // event: none
	binary.BigEndian.PutUint32(ann[84:88], 0)          // IP
	binary.BigEndian.PutUint32(ann[88:92], 0)          // key
	binary.BigEndian.PutUint32(ann[92:96], 0xFFFFFFFF) // num_want: -1 means default
	binary.BigEndian.PutUint16(ann[96:98], 6881)       // port

	if _, err := conn.Write(ann); err != nil {
		return err
	}
	return nil
}
