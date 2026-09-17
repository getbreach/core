package bridge

import (
	"context"
	"net"

	"breach/qtun"
)

// QUICOutbound borrows an authenticated, pinned qtun client. Its owner closes
// it after the Bridge. Reconnection is deliberately left to the future engine.
type QUICOutbound struct{ Client *qtun.Client }

func (o QUICOutbound) DialTCP(ctx context.Context, target string) (net.Conn, error) {
	// qtun currently applies a read deadline during negotiation but does not
	// interrupt every negotiation read on context cancellation. Return promptly
	// to the bridge; dispose of a late result instead of leaking the stream.
	type result struct {
		conn net.Conn
		err  error
	}
	ready := make(chan result)
	go func() {
		c, err := o.Client.Open(ctx, target)
		select {
		case ready <- result{c, err}:
		case <-ctx.Done():
			if c != nil {
				c.Close()
			}
		}
	}()
	select {
	case r := <-ready:
		return r.conn, r.err
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

func (o QUICOutbound) OpenUDP(ctx context.Context) (Datagrams, error) {
	type result struct {
		session *qtun.UDPSession
		err     error
	}
	ready := make(chan result)
	go func() {
		s, err := o.Client.OpenUDP(ctx)
		select {
		case ready <- result{s, err}:
		case <-ctx.Done():
			if s != nil {
				s.Close()
			}
		}
	}()
	select {
	case r := <-ready:
		if r.err != nil {
			return nil, r.err
		}
		return r.session, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}
