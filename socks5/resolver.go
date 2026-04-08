// SPDX-License-Identifier: Apache-2.0 OR MIT

// resolver.go defines the Resolver interface for domain-name resolution and
// the DialFunc type for outbound TCP connections.
//
// Resolver is used by the UDP relay to resolve per-datagram domain destinations.
// For TCP CONNECT, name resolution is handled by the [DialFunc] itself (so a
// custom dialer such as a chained proxy can do its own DNS).
//
// DialFunc is used by the server for every outbound CONNECT connection.
// The default is built from [Config.BindAddr]; callers may replace it to
// route through another proxy, add metrics, enforce TLS, etc.
package socks5

import (
	"context"
	"fmt"
	"net"
	"net/netip"
)

// Resolver resolves a host name to an IP address.
type Resolver interface {
	// Resolve looks up host and returns one address.
	// The context may carry a deadline or cancellation signal.
	Resolve(ctx context.Context, host string) (netip.Addr, error)
}

// DefaultResolver uses the system DNS resolver via [net.Resolver.LookupNetIP]
// (Go 1.21+), which returns [netip.Addr] values directly.
// It returns the first result, preferring IPv4 when both families are available.
type DefaultResolver struct{}

func (DefaultResolver) Resolve(ctx context.Context, host string) (netip.Addr, error) {
	// "ip" returns both A and AAAA records; the first result is used.
	addrs, err := net.DefaultResolver.LookupNetIP(ctx, "ip", host)
	if err != nil {
		return netip.Addr{}, err
	}
	if len(addrs) == 0 {
		return netip.Addr{}, fmt.Errorf("no addresses for %q", host)
	}
	return addrs[0].Unmap(), nil
}

// DialFunc establishes an outgoing TCP connection.
// The network argument is always "tcp"; addr is in "host:port" form.
// The context carries the configured dial deadline.
//
// The method value of [net.Dialer.DialContext] satisfies this type, so
// callers can write:
//
//	cfg.Dial = (&net.Dialer{LocalAddr: bindAddr}).DialContext
type DialFunc func(ctx context.Context, network, addr string) (net.Conn, error)
