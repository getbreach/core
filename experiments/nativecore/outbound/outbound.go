// Package outbound is the common contract for local proxy and packet inputs.
package outbound

import (
	"context"
	"net"
)

type Outbound interface {
	DialTCP(context.Context, string) (net.Conn, error)
	OpenUDP(context.Context) (Datagrams, error)
}

type Datagrams interface {
	WriteTo([]byte, string) error
	ReadFrom(context.Context) ([]byte, string, error)
	Close() error
}
