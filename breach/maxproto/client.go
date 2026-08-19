package maxproto

import (
	"bufio"
	"crypto/tls"
	"fmt"
	"net"
	"sync"
	"syscall"
	"time"
)

// Control, when non-nil, is installed as the socket Control hook on the MAX API
// TLS dial so an Android VpnService can protect it from the tun (else the mint
// connection loops into the not-yet-up tunnel). Mirrors turn.Control.
var Control func(network, address string, c syscall.RawConn) error

type Client struct {
	conn net.Conn
	r    *bufio.Reader

	mu      sync.Mutex
	seq     uint16
	pending map[uint16]chan *Packet
}

// Dial opens the TLS socket to a MAX API host. The root pool is the system
// store plus the bundled Минцифры anchors — api2.oneme.ru chains to those and
// nothing else, and the addition is additive so api.oneme.ru and any other host
// still validate against the system roots as before.
func Dial(host string, port int) (*Client, error) {
	roots, err := mincifryRoots()
	if err != nil {
		return nil, err
	}
	addr := net.JoinHostPort(host, fmt.Sprintf("%d", port))
	conn, err := tls.DialWithDialer(&net.Dialer{Timeout: 15 * time.Second, Control: Control}, "tcp", addr,
		&tls.Config{ServerName: host, RootCAs: roots})
	if err != nil {
		return nil, fmt.Errorf("tls dial %s: %w", addr, err)
	}
	return newClient(conn), nil
}

// newClient drives the packet protocol over an already-established connection.
// Dial supplies a TLS socket; tests supply a pipe.
func newClient(conn net.Conn) *Client {
	c := &Client{
		conn:    conn,
		r:       bufio.NewReaderSize(conn, 64*1024),
		pending: make(map[uint16]chan *Packet),
	}
	go c.readLoop()
	return c
}

func (c *Client) Close() { c.conn.Close() }

func (c *Client) readLoop() {
	for {
		pkt, err := readPacket(c.r)
		if err != nil {
			c.conn.Close()
			c.mu.Lock()
			for seq, ch := range c.pending {
				ch <- &Packet{Cmd: cmdError, Seq: seq, Payload: map[string]any{"message": err.Error()}}
				delete(c.pending, seq)
			}
			c.mu.Unlock()
			return
		}
		c.mu.Lock()
		ch, ok := c.pending[pkt.Seq]
		if ok {
			delete(c.pending, pkt.Seq)
		}
		c.mu.Unlock()
		if ok {
			ch <- pkt
		} else {
			logf("<- push opcode=%d cmd=%d", pkt.Opcode, pkt.Cmd)
		}
	}
}

func (c *Client) Request(opcode uint16, payload any) (*Packet, error) {
	c.mu.Lock()
	c.seq++
	seq := c.seq
	ch := make(chan *Packet, 1)
	c.pending[seq] = ch
	c.mu.Unlock()

	frame, err := packPacket(opcode, seq, payload)
	if err != nil {
		return nil, err
	}
	if _, err := c.conn.Write(frame); err != nil {
		return nil, fmt.Errorf("write opcode %d: %w", opcode, err)
	}
	logf("-> opcode=%d seq=%d", opcode, seq)

	select {
	case pkt := <-ch:
		if pkt.IsError() {
			return pkt, fmt.Errorf("opcode %d error: %s", opcode, errMessage(pkt.Payload))
		}
		return pkt, nil
	case <-time.After(30 * time.Second):
		return nil, fmt.Errorf("opcode %d timeout", opcode)
	}
}

func errMessage(payload any) string {
	m, ok := payload.(map[string]any)
	if !ok {
		return fmt.Sprintf("%v", payload)
	}
	for _, k := range []string{"localizedMessage", "message", "title", "error"} {
		if v, ok := m[k].(string); ok && v != "" {
			return v
		}
	}
	return fmt.Sprintf("%v", m)
}
