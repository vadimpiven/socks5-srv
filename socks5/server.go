// SPDX-License-Identifier: Apache-2.0 OR MIT

// server.go is the public entry point: Config, Server, NewServer,
// ListenAndServe, and Serve.
package socks5

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"sync"
	"time"
)

// Default timeout values used when the corresponding Config field is zero.
const (
	defaultHandshakeTimeout = 30 * time.Second
	defaultDialTimeout      = 30 * time.Second
	defaultTCPIdleTimeout   = 5 * time.Minute
	defaultUDPIdleTimeout   = 5 * time.Minute

	// gracefulDrainTime is the maximum time spent draining inbound data after
	// sending a failure reply. Not user-configurable: RFC 1928 §6 requires
	// the server to close within 10 s, and 2 s is a safe, fixed upper bound.
	gracefulDrainTime = 2 * time.Second

	defaultMaxConns = 1024
)

// Config holds all settings for a SOCKS5 server.
// All fields are read-only after being passed to [NewServer].
type Config struct {
	// Logger is used for all server-level and session-level log output.
	// Defaults to [slog.Default] when nil.
	Logger *slog.Logger

	// Authenticators is the ordered list of authentication methods the server
	// supports. The server selects the first method that the client also
	// offers. Defaults to [NoAuthAuthenticator{}] when empty.
	Authenticators []Authenticator

	// Rules gates each request before any outbound connection is made.
	// Defaults to [PermitAll] when nil.
	Rules RuleSet

	// Resolver resolves domain names for UDP ASSOCIATE relay. TCP CONNECT
	// lets the [DialFunc] handle DNS internally.
	// Defaults to [DefaultResolver] when nil.
	Resolver Resolver

	// Dial establishes outgoing TCP connections for CONNECT requests.
	// The context it receives already carries a deadline equal to DialTimeout.
	// Defaults to a [net.Dialer] bound to BindAddr (if set).
	// Mutually exclusive with BindAddr: setting both is an error.
	Dial DialFunc

	// BindAddr, when non-empty, pins all outgoing TCP connections to this
	// local IP address (e.g. "203.0.113.1" or "2001:db8::1").
	// Parsed and validated by [NewServer]. Mutually exclusive with Dial.
	BindAddr string

	// MaxConns limits concurrent client connections. Zero means 1024.
	MaxConns int

	// TrustedIPs lists client source addresses that bypass authentication
	// even when Authenticators require credentials. IPv4 and IPv4-mapped IPv6
	// forms are treated as equal (equivalent to microsocks -w).
	TrustedIPs []netip.Addr

	// AuthOnce, when true, promotes a client IP to the trusted list after its
	// first successful authentication. Subsequent connections from that IP
	// skip auth (equivalent to microsocks -1). Has no effect when all
	// Authenticators accept unauthenticated clients.
	AuthOnce bool

	// HandshakeTimeout limits the total time allowed for the greeting,
	// authentication, and request phases. Zero means 30 seconds.
	HandshakeTimeout time.Duration

	// DialTimeout limits the time for establishing each outbound TCP
	// connection. The context passed to [DialFunc] carries this deadline.
	// Zero means 30 seconds.
	DialTimeout time.Duration

	// TCPIdleTimeout closes TCP relay connections that have been idle for
	// this long. Zero means 5 minutes.
	TCPIdleTimeout time.Duration

	// UDPIdleTimeout tears down UDP associations that have been idle for
	// this long. Zero means 5 minutes.
	UDPIdleTimeout time.Duration
}

// serverTimeouts holds resolved (non-zero) timeout values for use at runtime.
type serverTimeouts struct {
	handshake time.Duration
	dial      time.Duration
	tcpIdle   time.Duration
	udpIdle   time.Duration
}

// Server is a SOCKS5 proxy server.
type Server struct {
	cfg      Config
	sem      chan struct{}
	timeouts serverTimeouts

	// Resolved interface defaults — always non-nil after NewServer.
	dial     DialFunc
	resolver Resolver
	rules    RuleSet

	// Runtime trusted-IP set. Starts as a copy of cfg.TrustedIPs and grows
	// when AuthOnce is enabled. Keyed on Unmap()-normalised addresses.
	trustedMu  sync.RWMutex
	trustedIPs map[netip.Addr]bool
}

// NewServer creates a Server from cfg, validates the configuration, and fills
// in defaults for nil interface fields and zero timeout values.
//
// Returns an error when:
//   - Both Dial and BindAddr are set (mutually exclusive).
//   - BindAddr is non-empty but not a valid IP address.
//   - A [UserPassAuthenticator] has a nil [CredentialStore].
func NewServer(cfg Config) (*Server, error) {
	// Mutual exclusion: Dial and BindAddr serve the same purpose.
	if cfg.Dial != nil && cfg.BindAddr != "" {
		return nil, fmt.Errorf("socks5: Dial and BindAddr are mutually exclusive; provide one or the other")
	}

	// Interface defaults.
	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}
	if len(cfg.Authenticators) == 0 {
		cfg.Authenticators = []Authenticator{NoAuthAuthenticator{}}
	}
	if cfg.Rules == nil {
		cfg.Rules = PermitAll{}
	}
	if cfg.Resolver == nil {
		cfg.Resolver = DefaultResolver{}
	}

	// Numeric defaults.
	if cfg.MaxConns <= 0 {
		cfg.MaxConns = defaultMaxConns
	}

	// Timeout defaults: zero means "use the library default".
	to := serverTimeouts{
		handshake: cfg.HandshakeTimeout,
		dial:      cfg.DialTimeout,
		tcpIdle:   cfg.TCPIdleTimeout,
		udpIdle:   cfg.UDPIdleTimeout,
	}
	if to.handshake == 0 {
		to.handshake = defaultHandshakeTimeout
	}
	if to.dial == 0 {
		to.dial = defaultDialTimeout
	}
	if to.tcpIdle == 0 {
		to.tcpIdle = defaultTCPIdleTimeout
	}
	if to.udpIdle == 0 {
		to.udpIdle = defaultUDPIdleTimeout
	}

	// Validate every UserPassAuthenticator upfront: a nil CredentialStore
	// would otherwise panic on the first authentication attempt.
	for i, a := range cfg.Authenticators {
		if upa, ok := a.(UserPassAuthenticator); ok && upa.Credentials == nil {
			return nil, fmt.Errorf("socks5: Authenticators[%d] (UserPassAuthenticator) has a nil Credentials store", i)
		}
	}

	// Build the outbound dialer when the caller hasn't provided one.
	var dial DialFunc
	if cfg.Dial != nil {
		dial = cfg.Dial
	} else {
		d := &net.Dialer{Timeout: to.dial}
		if cfg.BindAddr != "" {
			parsed, err := netip.ParseAddr(cfg.BindAddr)
			if err != nil {
				return nil, fmt.Errorf("socks5: BindAddr %q is not a valid IP address: %w", cfg.BindAddr, err)
			}
			d.LocalAddr = &net.TCPAddr{IP: parsed.Unmap().AsSlice()}
		}
		dial = d.DialContext
	}

	// Seed the runtime trusted set. netip.Addr is a value type — no copies needed.
	trusted := make(map[netip.Addr]bool, len(cfg.TrustedIPs))
	for _, ip := range cfg.TrustedIPs {
		trusted[ip.Unmap()] = true
	}

	return &Server{
		cfg:        cfg,
		sem:        make(chan struct{}, cfg.MaxConns),
		timeouts:   to,
		dial:       dial,
		resolver:   cfg.Resolver,
		rules:      cfg.Rules,
		trustedIPs: trusted,
	}, nil
}

// isTrusted reports whether ip is in the runtime trusted set.
func (s *Server) isTrusted(ip netip.Addr) bool {
	if !ip.IsValid() {
		return false
	}
	s.trustedMu.RLock()
	defer s.trustedMu.RUnlock()
	return s.trustedIPs[ip.Unmap()]
}

// addTrusted inserts ip into the runtime trusted set (idempotent).
func (s *Server) addTrusted(ip netip.Addr) {
	if !ip.IsValid() {
		return
	}
	ip = ip.Unmap()
	s.trustedMu.Lock()
	defer s.trustedMu.Unlock()
	if s.trustedIPs == nil {
		s.trustedIPs = make(map[netip.Addr]bool)
	}
	s.trustedIPs[ip] = true
}

// ListenAndServe binds to addr and serves SOCKS5 connections until ctx is
// cancelled. On shutdown it waits for all active sessions to finish.
//
// addr uses the same format as [net.Listen] (e.g. ":1080" or "[::]:1080").
func (s *Server) ListenAndServe(ctx context.Context, addr string) error {
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return err
	}
	return s.Serve(ctx, ln)
}

// Serve accepts SOCKS5 connections on ln until ctx is cancelled. It closes
// the listener on shutdown and waits for all active sessions to finish.
func (s *Server) Serve(ctx context.Context, ln net.Listener) error {
	go func() {
		<-ctx.Done()
		ln.Close()
	}()

	var wg sync.WaitGroup
	for {
		conn, err := ln.Accept()
		if err != nil {
			select {
			case <-ctx.Done():
				wg.Wait()
				return nil
			default:
				s.cfg.Logger.Warn("accept failed", "err", err)
				continue
			}
		}

		select {
		case s.sem <- struct{}{}:
		case <-ctx.Done():
			conn.Close()
			wg.Wait()
			return nil
		default:
			s.cfg.Logger.Warn("connection limit reached, rejecting",
				"limit", s.cfg.MaxConns,
				"remote", conn.RemoteAddr())
			conn.Close()
			continue
		}

		wg.Add(1)
		go func() {
			defer wg.Done()
			defer func() { <-s.sem }()
			newSession(conn, s).handle()
		}()
	}
}
