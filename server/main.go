package main

import (
	"bufio"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"flag"
	"fmt"
	"io"
	"log"
	mrand "math/rand"
	"net"
	"server/config"
	"strconv"
	"strings"
	"sync"
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
	bitfieldID   = 5
	requestID    = 6
)

var (
	gAuthKey    []byte
	gInfoHash   [20]byte
	copyBufPool = sync.Pool{New: func() any { b := make([]byte, 32*1024); return &b }}
	udpBufPool  = sync.Pool{New: func() any { b := make([]byte, 66*1024); return &b }}
)

func main() {
	configPath := flag.String("config", "config.yaml", "path to YAML config file")
	flag.Parse()

	cfg, err := config.LoadConfig(*configPath)
	if err != nil {
		log.Fatalf("[ERR] Failed to load config from %s: %v", *configPath, err)
	}

	TorrentStarter(cfg)
}

func TorrentStarter(cfg *config.Config) {
	if cfg.Torrent.AuthKey == "" {
		log.Fatalf("[ERR] torrent auth-key is required")
	}
	authKey, err := hex.DecodeString(cfg.Torrent.AuthKey)
	if err != nil || len(authKey) != 32 {
		log.Fatalf("[ERR] invalid torrent auth-key: must be 64 hex chars (32 bytes)")
	}
	gAuthKey = authKey

	if cfg.Torrent.InfoHash != "" {
		ih, err := hex.DecodeString(cfg.Torrent.InfoHash)
		if err != nil || len(ih) != 20 {
			log.Fatalf("[ERR] invalid torrent info-hash: must be 40 hex chars (20 bytes)")
		}
		copy(gInfoHash[:], ih)
	}

	host, portStr, err := net.SplitHostPort(cfg.Port)
	if err != nil {
		host = "0.0.0.0"
		portStr = cfg.Port
	}

	var ports []int
	if strings.Contains(portStr, "-") {
		parts := strings.Split(portStr, "-")
		start, _ := strconv.Atoi(parts[0])
		end, _ := strconv.Atoi(parts[1])
		for i := start; i <= end; i++ {
			ports = append(ports, i)
		}
	} else {
		p, _ := strconv.Atoi(portStr)
		ports = append(ports, p)
	}

	log.Printf("[INFO] Torrent server listening on ports %s", portStr)
	for _, p := range ports {
		go func(port int) {
			s, err := utp.NewSocket("udp", net.JoinHostPort(host, strconv.Itoa(port)))
			if err != nil {
				log.Printf("[ERR] failed to listen on port %d: %v", port, err)
				return
			}
			for {
				conn, err := s.Accept()
				if err != nil {
					continue
				}
				go handleTorrentConn(conn)
			}
		}(p)
	}

	select {}
}

func handleTorrentConn(conn net.Conn) {
	defer func() {
		if r := recover(); r != nil {
			log.Printf("[Panic] handleTorrentConn from %s: %v", conn.RemoteAddr(), r)
		}
		conn.Close()
	}()
	log.Printf("[INFO] Incoming connection from %s", conn.RemoteAddr())
	// 1. Read BitTorrent Handshake
	handshake := make([]byte, handshakeLen)
	conn.SetReadDeadline(time.Now().Add(10 * time.Second))
	if _, err := io.ReadFull(conn, handshake); err != nil {
		return
	}
	conn.SetReadDeadline(time.Time{})

	if handshake[0] != pstrlen || string(handshake[1:20]) != pstr {
		return
	}

	clientInfoHash := handshake[28:48]
	peerID := handshake[48:68]

	// 2. Verify HMAC in PeerID
	nonce := peerID[8:12]
	signature := peerID[12:20]

	mac := hmac.New(sha1.New, gAuthKey)
	mac.Write(nonce)
	mac.Write(clientInfoHash)
	expectedSig := mac.Sum(nil)[:8]

	if hmac.Equal(signature, expectedSig) {
		// Valid Client
		respHandshake := make([]byte, handshakeLen)
		respHandshake[0] = pstrlen
		copy(respHandshake[1:20], pstr)
		copy(respHandshake[28:48], clientInfoHash)
		copy(respHandshake[48:56], []byte("-UM1000-"))
		rand.Read(respHandshake[56:68])
		conn.Write(respHandshake)

		handleSess(conn, nonce)
	} else {
		// Foreign Client - Decoy Mode
		beRealTorrentPeer(conn, clientInfoHash)
	}
}

func beRealTorrentPeer(conn net.Conn, infoHash []byte) {
	defer conn.Close()
	log.Printf("[INFO] Decoy: unknown client from %s with infohash %s", conn.RemoteAddr(), hex.EncodeToString(infoHash))

	// 1. Send fake handshake back
	respHandshake := make([]byte, handshakeLen)
	respHandshake[0] = pstrlen
	copy(respHandshake[1:20], pstr)
	copy(respHandshake[28:48], infoHash)
	copy(respHandshake[48:56], []byte("-TR3000-"))
	rand.Read(respHandshake[56:68])
	if _, err := conn.Write(respHandshake); err != nil {
		return
	}

	// 2. Send Bitfield
	bitfieldSize := 100 + mrand.Intn(400)
	bf := make([]byte, 4+1+bitfieldSize)
	binary.BigEndian.PutUint32(bf[0:4], uint32(1+bitfieldSize))
	bf[4] = bitfieldID
	for i := 0; i < bitfieldSize; i++ {
		bf[5+i] = 0xFF
	}
	// Unset a few random bits to look more natural
	for i := 0; i < 3; i++ {
		bf[5+mrand.Intn(bitfieldSize)] &= ^(1 << uint(mrand.Intn(8)))
	}
	conn.Write(bf)

	// 3. Send Unchoke
	conn.Write([]byte{0, 0, 0, 1, unchokeMsgID})

	// 4. Handle incoming messages in a blocking way
	buf := make([]byte, 4096)
	for {
		conn.SetReadDeadline(time.Now().Add(30 * time.Second))
		n, err := conn.Read(buf)
		if err != nil {
			return
		}
		if n >= 4 {
			msgLen := binary.BigEndian.Uint32(buf[:4])
			if msgLen == 0 { // keep-alive
				conn.Write([]byte{0, 0, 0, 0})
				continue
			}
			if n >= 5 {
				msgID := buf[4]
				if msgID == requestID && n >= 17 {
					index := binary.BigEndian.Uint32(buf[5:9])
					begin := binary.BigEndian.Uint32(buf[9:13])
					length := binary.BigEndian.Uint32(buf[13:17])

					if length <= 32768 {
						pieceBuf := make([]byte, 4+1+4+4+int(length))
						binary.BigEndian.PutUint32(pieceBuf[0:4], uint32(9+length))
						pieceBuf[4] = pieceMsgID
						binary.BigEndian.PutUint32(pieceBuf[5:9], index)
						binary.BigEndian.PutUint32(pieceBuf[9:13], begin)
						rand.Read(pieceBuf[13:])
						conn.Write(pieceBuf)
					}
				}
			}
		}
	}
}

func handleSess(conn net.Conn, nonce []byte) {
	defer func() {
		if r := recover(); r != nil {
			log.Printf("[Panic] handleSess from %s: %v", conn.RemoteAddr(), r)
		}
	}()
	// 1. Send Bitfield and Unchoke for mask symmetry
	bitfieldSize := 100 + mrand.Intn(400)
	bf := make([]byte, 4+1+bitfieldSize)
	binary.BigEndian.PutUint32(bf[0:4], uint32(1+bitfieldSize))
	bf[4] = bitfieldID
	for i := 0; i < bitfieldSize; i++ {
		bf[5+i] = 0xFF
	}
	// Unset a few random bits to look more natural
	for i := 0; i < 3; i++ {
		bf[5+mrand.Intn(bitfieldSize)] &= ^(1 << uint(mrand.Intn(8)))
	}
	conn.Write(bf)
	conn.Write([]byte{0, 0, 0, 1, unchokeMsgID})

	// Wrap connection with piece framing
	tConn := NewTorrentConn(conn, gAuthKey, gInfoHash, nonce)
	muxCfg := yamux.DefaultConfig()
	muxCfg.MaxStreamWindowSize = 8 * 1024 * 1024
	muxCfg.EnableKeepAlive = true
	muxCfg.StreamCloseTimeout = 10 * time.Second
	muxCfg.LogOutput = io.Discard

	muxSess, err := yamux.Server(tConn, muxCfg)
	if err != nil {
		log.Printf("[ERR] yamux server %s: %v", conn.RemoteAddr(), err)
		return
	}
	defer muxSess.Close()

	log.Printf("[INFO] Torrent session from %s", conn.RemoteAddr())
	for {
		stream, err := muxSess.Accept()
		if err != nil {
			log.Printf("[INFO] Torrent session %s closed: %v", conn.RemoteAddr(), err)
			break
		}
		go handleStream(stream, conn.RemoteAddr())
	}
}

func handleStream(stream net.Conn, clientAddr net.Addr) {
	defer func() {
		if r := recover(); r != nil {
			log.Printf("[Panic] torrent handleStream from %s: %v", clientAddr, r)
		}
		stream.Close()
	}()

	// 1. Read target address
	lenBuf := make([]byte, 4)
	if _, err := io.ReadFull(stream, lenBuf); err != nil {
		return
	}
	targetLen := binary.BigEndian.Uint32(lenBuf)
	if targetLen > 1024 {
		return
	}
	targetBytes := make([]byte, targetLen)
	if _, err := io.ReadFull(stream, targetBytes); err != nil {
		return
	}
	target := string(targetBytes)

	if target == "UDP_RELAY" {
		handleUDPRelay(stream)
	} else {
		handleTunnel(stream, target)
	}
}

func handleTunnel(conn net.Conn, target string) {
	remote, err := net.DialTimeout("tcp", target, 30*time.Second)
	if err != nil {
		return
	}
	defer remote.Close()

	log.Printf("[INFO] Torrent Proxying %s → %s", conn.RemoteAddr(), target)

	done := make(chan struct{}, 2)
	go func() {
		b := copyBufPool.Get().(*[]byte)
		defer copyBufPool.Put(b)
		io.CopyBuffer(remote, conn, *b)
		if cw, ok := remote.(interface{ CloseWrite() error }); ok {
			cw.CloseWrite()
		}
		done <- struct{}{}
	}()
	go func() {
		b := copyBufPool.Get().(*[]byte)
		defer copyBufPool.Put(b)
		io.CopyBuffer(conn, remote, *b)
		if cw, ok := conn.(interface{ CloseWrite() error }); ok {
			cw.CloseWrite()
		}
		done <- struct{}{}
	}()
	<-done
	<-done
}

func handleUDPRelay(stream net.Conn) {
	pc, err := net.ListenPacket("udp", "0.0.0.0:0")
	if err != nil {
		return
	}
	defer pc.Close()

	const idleTimeout = 30 * time.Second
	done := make(chan struct{})

	// App -> Server
	go func() {
		defer close(done)
		lenBuf := make([]byte, 4)
		addrCache := make(map[string]*net.UDPAddr)

		bufPtr := udpBufPool.Get().(*[]byte)
		defer udpBufPool.Put(bufPtr)
		payloadBuf := *bufPtr

		for {
			stream.SetReadDeadline(time.Now().Add(idleTimeout))
			if _, err := io.ReadFull(stream, lenBuf); err != nil {
				return
			}
			payloadLen := binary.BigEndian.Uint32(lenBuf)
			if payloadLen > 65535 {
				return
			}
			payload := payloadBuf[:payloadLen]
			if _, err := io.ReadFull(stream, payload); err != nil {
				return
			}

			// Simple SOCKS5 UDP framing: [ATYP][ADDR][PORT][DATA]
			if len(payload) < 4 {
				continue
			}
			off := 0
			var host string
			switch payload[off] {
			case 0x01: // IPv4
				if len(payload) < 7 {
					continue
				}
				host = net.IP(payload[1:5]).String()
				off = 5
			case 0x03: // Domain
				nameLen := int(payload[1])
				if len(payload) < 2+nameLen+2 {
					continue
				}
				host = string(payload[2 : 2+nameLen])
				off = 2 + nameLen
			case 0x04: // IPv6
				if len(payload) < 19 {
					continue
				}
				host = net.IP(payload[1:17]).String()
				off = 17
			default:
				continue
			}
			port := binary.BigEndian.Uint16(payload[off : off+2])
			data := payload[off+2:]
			target := net.JoinHostPort(host, fmt.Sprintf("%d", port))

			addr, ok := addrCache[target]
			if !ok {
				addr, _ = net.ResolveUDPAddr("udp", target)
				if len(addrCache) > 1000 { // Ограничиваем кэш, чтобы не было утечки
					for k := range addrCache {
						delete(addrCache, k)
						break
					}
				}
				addrCache[target] = addr
			}
			if addr != nil {
				pc.SetWriteDeadline(time.Now().Add(5 * time.Second))
				pc.WriteTo(data, addr)
			}
		}
	}()

	// Server -> App
	bufPtr := udpBufPool.Get().(*[]byte)
	defer udpBufPool.Put(bufPtr)
	buf := *bufPtr

	frameBufPtr := udpBufPool.Get().(*[]byte)
	defer udpBufPool.Put(frameBufPtr)
	frameBuf := *frameBufPtr

	for {
		select {
		case <-done:
			return
		default:
		}
		pc.SetReadDeadline(time.Now().Add(idleTimeout))
		n, addr, err := pc.ReadFrom(buf)
		if err != nil {
			return
		}
		udpAddr := addr.(*net.UDPAddr)
		off := 4
		if ip4 := udpAddr.IP.To4(); ip4 != nil {
			frameBuf[off] = 0x01
			copy(frameBuf[off+1:], ip4)
			off += 5
		} else {
			frameBuf[off] = 0x04
			copy(frameBuf[off+1:], udpAddr.IP.To16())
			off += 17
		}
		binary.BigEndian.PutUint16(frameBuf[off:off+2], uint16(udpAddr.Port))
		off += 2
		copy(frameBuf[off:], buf[:n])
		off += n
		binary.BigEndian.PutUint32(frameBuf[0:4], uint32(off-4))

		stream.SetWriteDeadline(time.Now().Add(5 * time.Second))
		if _, err := stream.Write(frameBuf[:off]); err != nil {
			return
		}
	}
}


type TorrentConn struct {
	net.Conn
	reader           *bufio.Reader
	writer           *bufio.Writer
	remainingPayload int
	remainingPadding int
	flushTimer       *time.Timer
	mu               sync.Mutex
	enc              cipher.Stream
	dec              cipher.Stream
}

func NewTorrentConn(conn net.Conn, authKey []byte, infoHash [20]byte, nonce []byte) *TorrentConn {
	tc := &TorrentConn{
		Conn:   conn,
		reader: bufio.NewReaderSize(conn, 256*1024),
	}

	// Initialize AES-CTR for light payload encryption
	key := sha256.Sum256(authKey)
	ivSeed := append(nonce, infoHash[:]...)
	iv := sha256.Sum256(ivSeed)

	block, err := aes.NewCipher(key[:])
	if err == nil {
		// Server swap: enc/dec are reversed relative to client
		tc.enc = cipher.NewCTR(block, iv[16:32])
		tc.dec = cipher.NewCTR(block, iv[:16])
	}

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
			if c.dec != nil {
				c.dec.XORKeyStream(p[:n], p[:n])
			}
			c.remainingPayload -= n
			return n, nil
		}

		if c.remainingPadding > 0 {
			if _, err := c.reader.Discard(c.remainingPadding); err != nil {
				return 0, err
			}
			c.remainingPadding = 0
		}

		var header [4]byte
		if _, err := io.ReadFull(c.reader, header[:]); err != nil {
			return 0, err
		}
		length := binary.BigEndian.Uint32(header[:])
		if length == 0 {
			continue
		}

		msgID, err := c.reader.ReadByte()
		if err != nil {
			return 0, err
		}

		if msgID == pieceMsgID {
			if _, err := c.reader.Discard(8); err != nil {
				return 0, err
			}

			var pLenBuf [2]byte
			if _, err := io.ReadFull(c.reader, pLenBuf[:]); err != nil {
				return 0, err
			}
			pLen := int(binary.BigEndian.Uint16(pLenBuf[:]))

			totalInPiece := int(length) - 11
			if pLen > totalInPiece {
				return 0, fmt.Errorf("torrent protocol corruption: payload %d > total %d", pLen, totalInPiece)
			}

			c.remainingPayload = pLen
			c.remainingPadding = totalInPiece - pLen

			if c.remainingPayload == 0 {
				continue
			}
		} else {
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

func (c *TorrentConn) writePiece(p []byte) (n int, err error) {
	const internalHeadLen = 2
	padLen := mrand.Intn(256)

	bufPtr := udpBufPool.Get().(*[]byte)
	defer udpBufPool.Put(bufPtr)
	buf := *bufPtr

	totalMsgLen := 9 + internalHeadLen + len(p) + padLen
	binary.BigEndian.PutUint32(buf[0:4], uint32(totalMsgLen))
	buf[4] = pieceMsgID
	binary.BigEndian.PutUint32(buf[5:9], uint32(mrand.Int31n(1000)))
	binary.BigEndian.PutUint32(buf[9:13], uint32(mrand.Int31n(131072)))

	binary.BigEndian.PutUint16(buf[13:15], uint16(len(p)))
	if c.enc != nil {
		c.enc.XORKeyStream(buf[15:15+len(p)], p)
	} else {
		copy(buf[15:], p)
	}

	if padLen > 0 {
		rand.Read(buf[15+len(p) : 15+len(p)+padLen])
	}

	_, err = c.Conn.Write(buf[:4+totalMsgLen])
	return len(p), err
}
