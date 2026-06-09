package share

import (
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"sync"
)

// CopyBufPool holds reusable 32 KiB buffers.
var CopyBufPool = sync.Pool{New: func() any { b := make([]byte, 32*1024); return &b }}

// UDPBufPool holds reusable buffers large enough for max UDP packet + Torrent headers.
var UDPBufPool = sync.Pool{New: func() any { b := make([]byte, 66*1024); return &b }}

// CloseWrite signals the write-half of a connection is done, allowing the remote
// to flush any remaining data before the connection is fully torn down.
func CloseWrite(c net.Conn) {
	type halfCloser interface{ CloseWrite() error }
	if hc, ok := c.(halfCloser); ok {
		hc.CloseWrite()
	}
}

// Socks5Handshake performs the SOCKS5 greeting + request exchange.
// Returns the command byte (0x01 CONNECT or 0x03 UDP ASSOCIATE) and
// destination host/port (populated for CONNECT; addr hint for UDP ASSOCIATE).
func Socks5Handshake(conn net.Conn, udpEnabled bool) (cmd byte, host string, port uint16, err error) {
	// --- Greeting ---
	header := make([]byte, 2)
	if _, err = io.ReadFull(conn, header); err != nil {
		return 0, "", 0, fmt.Errorf("read greeting: %w", err)
	}
	if header[0] != 0x05 {
		return 0, "", 0, fmt.Errorf("expected SOCKS5, got version %d", header[0])
	}
	methods := make([]byte, header[1])
	if _, err = io.ReadFull(conn, methods); err != nil {
		return 0, "", 0, fmt.Errorf("read methods: %w", err)
	}
	// Select no-auth
	if _, err = conn.Write([]byte{0x05, 0x00}); err != nil {
		return 0, "", 0, fmt.Errorf("write method selection: %w", err)
	}

	// --- Request ---
	req := make([]byte, 4)
	if _, err = io.ReadFull(conn, req); err != nil {
		return 0, "", 0, fmt.Errorf("read request: %w", err)
	}
	if req[0] != 0x05 {
		return 0, "", 0, fmt.Errorf("invalid request version: %d", req[0])
	}
	cmd = req[1]
	switch cmd {
	case 0x01: // CONNECT — TCP
	case 0x03: // UDP ASSOCIATE
		if !udpEnabled {
			conn.Write([]byte{0x05, 0x07, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
			return 0, "", 0, fmt.Errorf("UDP ASSOCIATE disabled")
		}
	default:
		conn.Write([]byte{0x05, 0x07, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
		return 0, "", 0, fmt.Errorf("unsupported SOCKS5 command: 0x%02x", cmd)
	}

	switch req[3] {
	case 0x01: // IPv4
		ip := make([]byte, 4)
		if _, err = io.ReadFull(conn, ip); err != nil {
			return 0, "", 0, fmt.Errorf("read IPv4: %w", err)
		}
		host = net.IP(ip).String()
	case 0x03: // domain
		lenBuf := make([]byte, 1)
		if _, err = io.ReadFull(conn, lenBuf); err != nil {
			return 0, "", 0, fmt.Errorf("read domain length: %w", err)
		}
		domain := make([]byte, lenBuf[0])
		if _, err = io.ReadFull(conn, domain); err != nil {
			return 0, "", 0, fmt.Errorf("read domain: %w", err)
		}
		host = string(domain)
	case 0x04: // IPv6
		ip := make([]byte, 16)
		if _, err = io.ReadFull(conn, ip); err != nil {
			return 0, "", 0, fmt.Errorf("read IPv6: %w", err)
		}
		host = net.IP(ip).String()
	default:
		conn.Write([]byte{0x05, 0x08, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
		return 0, "", 0, fmt.Errorf("unsupported address type: 0x%02x", req[3])
	}

	portBuf := make([]byte, 2)
	if _, err = io.ReadFull(conn, portBuf); err != nil {
		return 0, "", 0, fmt.Errorf("read port: %w", err)
	}
	port = binary.BigEndian.Uint16(portBuf)
	return cmd, host, port, nil
}
