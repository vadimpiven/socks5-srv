// SPDX-License-Identifier: Apache-2.0 OR MIT

// session.go drives one client connection through the full SOCKS5 pipeline:
//
//	negotiate → authenticate → read request → rule check → connect/relay
package socks5

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/netip"
	"slices"
	"time"
)

// session holds the state for one accepted client connection.
type session struct {
	conn   net.Conn
	srv    *Server
	remote string         // "host:port" string for log fields
	ap     netip.AddrPort // client's TCP address; .Addr() is already Unmap'd
}

// newSession constructs a session and extracts the client's address once.
// net.TCPAddr.AddrPort() (Go 1.18+) gives netip.AddrPort without allocating
// a net.IP slice.
func newSession(conn net.Conn, srv *Server) *session {
	remote := conn.RemoteAddr().String()
	var ap netip.AddrPort
	if tcp, ok := conn.RemoteAddr().(*net.TCPAddr); ok {
		raw := tcp.AddrPort()
		// Normalise IPv4-mapped IPv6 to plain IPv4.
		ap = netip.AddrPortFrom(raw.Addr().Unmap(), raw.Port())
	}
	return &session{conn: conn, srv: srv, remote: remote, ap: ap}
}

// log returns a logger pre-populated with the client's address.
// Falls back to slog.Default() for Server structs constructed directly in tests.
func (s *session) log() *slog.Logger {
	l := s.srv.cfg.Logger
	if l == nil {
		l = slog.Default()
	}
	return l.With("client", s.remote)
}

// negotiateAuth performs RFC 1928 §3 method negotiation followed by the
// sub-negotiation of the selected method.
//
// Trusted-IP bypass: a client whose source IP is in the runtime trusted set
// is offered NoAuth even when all configured authenticators require credentials.
//
// Auth-once promotion: after the first successful sub-negotiation for a
// non-NoAuth method, the client's IP is added to the trusted set when
// cfg.AuthOnce is true.
//
// Wire format — greeting:  VER(1) | NMETHODS(1) | METHODS(1-255)
// Wire format — selection: VER(1) | METHOD(1)
func (s *session) negotiateAuth() (AuthInfo, error) {
	var hdr [2]byte
	if _, err := io.ReadFull(s.conn, hdr[:]); err != nil {
		return nil, fmt.Errorf("read greeting: %w", err)
	}
	if hdr[0] != version5 {
		return nil, fmt.Errorf("unsupported SOCKS version: %#x", hdr[0])
	}
	if hdr[1] == 0 {
		// RFC 1928 §3: NMETHODS must be 1-255.
		_, _ = s.conn.Write([]byte{version5, methodNoAcceptable})
		return nil, errors.New("NMETHODS is 0: client offered no methods (RFC 1928 §3)")
	}

	methods := make([]byte, hdr[1])
	if _, err := io.ReadFull(s.conn, methods); err != nil {
		return nil, fmt.Errorf("read methods: %w", err)
	}

	// Build the effective authenticator list. Trusted client IPs bypass any
	// credential-requiring authenticators by prepending a NoAuth shortcut.
	authenticators := s.srv.cfg.Authenticators
	if s.srv.isTrusted(s.ap.Addr()) {
		authenticators = append([]Authenticator{NoAuthAuthenticator{}}, authenticators...)
	}

	// Select the first authenticator whose code the client also offered.
	var selected Authenticator
	for _, a := range authenticators {
		if slices.Contains(methods, a.Code()) {
			selected = a
			break
		}
	}

	if selected == nil {
		_, _ = s.conn.Write([]byte{version5, methodNoAcceptable})
		return nil, errors.New("no acceptable authentication method")
	}

	// Send the method-selection response, then run the sub-negotiation.
	if _, err := s.conn.Write([]byte{version5, selected.Code()}); err != nil {
		return nil, fmt.Errorf("write method selection: %w", err)
	}

	info, err := selected.Authenticate(s.conn)
	if err != nil {
		return nil, err
	}

	// Auth-once: promote this IP for future connections.
	if s.srv.cfg.AuthOnce && selected.Code() != methodNoAuth {
		s.srv.addTrusted(s.ap.Addr())
		s.log().Info("IP promoted to trusted list (auth-once)")
	}

	return info, nil
}

// readRequest reads VER | CMD | RSV | ATYP | DST.ADDR | DST.PORT and returns
// the command and destination. Protocol violations send a reply and return an
// error; unsupported commands are NOT rejected here — the caller dispatches.
func (s *session) readRequest() (Command, AddrSpec, error) {
	var hdr [3]byte
	if _, err := io.ReadFull(s.conn, hdr[:]); err != nil {
		return 0, AddrSpec{}, fmt.Errorf("read request header: %w", err)
	}
	if hdr[0] != version5 {
		return 0, AddrSpec{}, fmt.Errorf("unexpected version in request: %#x", hdr[0])
	}
	// RFC 1928 §4: RSV must be 0x00.
	if hdr[2] != 0x00 {
		_ = writeReply(s.conn, replyGeneralFailure, AddrSpec{})
		return 0, AddrSpec{}, fmt.Errorf("non-zero RSV byte: %#x", hdr[2])
	}

	dest, err := readAddr(s.conn)
	if err != nil {
		code := replyGeneralFailure
		if errors.Is(err, errUnsupportedAddrType) {
			code = replyAddrNotSupported
		}
		_ = writeReply(s.conn, code, AddrSpec{})
		return 0, AddrSpec{}, fmt.Errorf("read destination: %w", err)
	}
	return Command(hdr[1]), dest, nil
}

// handleConnect dials the destination, sends the success reply, and relays
// data until both sides close.
func (s *session) handleConnect(dest AddrSpec) {
	dialCtx, dialCancel := context.WithTimeout(context.Background(), s.srv.timeouts.dial)
	defer dialCancel()

	remote, err := s.srv.dial(dialCtx, "tcp", dest.String())
	if err != nil {
		_ = writeReply(s.conn, replyFromError(err), AddrSpec{})
		s.log().Info("connect failed", "target", dest, "err", err)
		gracefulClose(s.conn)
		return
	}
	defer remote.Close()

	// Report the actual bound address to the client (RFC 1928 §6).
	ap := remote.LocalAddr().(*net.TCPAddr).AddrPort()
	bound := AddrSpec{IP: ap.Addr().Unmap(), Port: ap.Port()}
	if err := writeReply(s.conn, replySuccess, bound); err != nil {
		s.log().Warn("write success reply", "err", err)
		return
	}

	s.log().Info("relay started", "target", dest)
	if err := relay(s.conn, remote, s.srv.timeouts.tcpIdle); err != nil {
		s.log().Info("relay ended", "target", dest, "err", err)
		return
	}
	s.log().Info("relay ended", "target", dest)
}

// gracefulClose signals EOF to the peer (TCP half-close) then drains pending
// inbound data so close(2) sends a FIN rather than a RST.
//
// RFC 1928 §6: the server MUST terminate the connection within 10 s of
// sending a failure reply; we cap the drain at gracefulDrainTime (2 s).
func gracefulClose(conn net.Conn) {
	if hc, ok := conn.(halfCloser); ok {
		hc.CloseWrite()
	}
	conn.SetReadDeadline(time.Now().Add(gracefulDrainTime))
	io.Copy(io.Discard, conn)
}

// handle drives the full SOCKS5 session pipeline to completion.
func (s *session) handle() {
	defer s.conn.Close()

	// A single deadline covers the entire handshake (greeting + auth +
	// request) to prevent slow-loris resource exhaustion.
	s.conn.SetDeadline(time.Now().Add(s.srv.timeouts.handshake))

	authInfo, err := s.negotiateAuth()
	if err != nil {
		s.log().Info("auth failed", "err", err)
		gracefulClose(s.conn)
		return
	}

	cmd, dest, err := s.readRequest()
	if err != nil {
		s.log().Info("bad request", "err", err)
		gracefulClose(s.conn)
		return
	}

	// Present the request to the rule set before doing anything observable
	// externally (e.g. a DNS lookup or TCP connection).
	req := Request{
		Command:    cmd,
		ClientAddr: s.ap,
		Dest:       dest,
		Auth:       authInfo,
	}
	if !s.srv.rules.Allow(context.Background(), req) {
		_ = writeReply(s.conn, replyNotAllowed, AddrSpec{})
		s.log().Info("request denied by rule set",
			"cmd", fmt.Sprintf("%#x", byte(cmd)), "target", dest)
		gracefulClose(s.conn)
		return
	}

	// Clear the handshake deadline before entering the data phase.
	s.conn.SetDeadline(time.Time{})

	switch cmd {
	case CommandConnect:
		s.handleConnect(dest)
	case CommandUDPAssociate:
		s.handleUDPAssociate(dest)
	default:
		_ = writeReply(s.conn, replyCmdNotSupported, AddrSpec{})
		s.log().Info("command not supported", "cmd", fmt.Sprintf("%#x", byte(cmd)))
		gracefulClose(s.conn)
	}
}
