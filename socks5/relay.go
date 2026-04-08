// SPDX-License-Identifier: Apache-2.0 OR MIT

// relay.go implements bidirectional TCP data forwarding with idle-timeout
// detection and proper TCP half-close handling.
package socks5

import (
	"io"
	"net"
	"time"
)

// halfCloser is implemented by *net.TCPConn and any future wrapper (e.g.
// TLS) that exposes one-directional shutdown. Using an interface instead of
// a concrete type assertion keeps relay and gracefulClose agnostic of the
// underlying transport.
type halfCloser interface {
	CloseWrite() error
}

// closeWrite shuts down the write side of a connection, signalling EOF to
// the peer while still allowing reads in the opposite direction.
func closeWrite(conn net.Conn) {
	if hc, ok := conn.(halfCloser); ok {
		hc.CloseWrite()
	}
}

// idleReader wraps a net.Conn to set a per-Read deadline, implementing a
// sliding idle timeout: the deadline is reset each time the caller asks for
// more data, so a connection that is slow but continuously active is never
// timed out prematurely.
type idleReader struct {
	conn    net.Conn
	timeout time.Duration
}

func (r *idleReader) Read(p []byte) (int, error) {
	r.conn.SetReadDeadline(time.Now().Add(r.timeout))
	return r.conn.Read(p)
}

// relay copies data bidirectionally between client and remote until either
// side closes or the connection is idle for longer than idleTimeout. Half-
// close is propagated: when one side finishes sending, CloseWrite is called
// on the other so it receives a clean EOF without tearing down the reverse
// direction prematurely.
//
// It returns the first non-nil error so a meaningful failure is not
// swallowed when a clean EOF arrives first due to goroutine scheduling.
func relay(client, remote net.Conn, idleTimeout time.Duration) error {
	errc := make(chan error, 2)

	forward := func(dst, src net.Conn) {
		_, err := io.Copy(dst, &idleReader{conn: src, timeout: idleTimeout})
		closeWrite(dst)
		errc <- err
	}

	go forward(remote, client)
	go forward(client, remote)

	err1 := <-errc
	err2 := <-errc
	if err1 != nil {
		return err1
	}
	return err2
}
