// SPDX-License-Identifier: Apache-2.0 OR MIT

// udp.go implements the SOCKS5 UDP ASSOCIATE command (RFC 1928 §7).
//
// Design summary
// ──────────────
// Each UDP ASSOCIATE creates one PacketConn (the "relay socket") on a random
// port. The client is told to send its encapsulated UDP datagrams there.
//
// Direction detection uses a two-phase rule (see runUDPRelay for details):
//
//	Phase 1 — client UDP address not yet known:
//	  • from.IP == clientTCPIP  →  client; learn the full address (IP:port)
//	  • otherwise              →  remote; drop (can't reply yet)
//
//	Phase 2 — client UDP address known:
//	  • from == clientUDPAddr (exact IP:port)  →  client
//	  • from.IP == clientTCPIP, different port  →  remote on same host
//	  • any other IP                            →  remote
//
// This correctly handles the loopback case (client and remote on the same IP)
// and remotes that reply from a port different from the one they listen on
// (e.g. NAT devices, load balancers).
//
// Fragmentation (FRAG != 0x00) is not implemented; such datagrams are dropped
// silently, as explicitly permitted by RFC 1928 §7.
//
// Lifetime: the association is torn down when the TCP control connection
// closes (monitored via io.Copy(io.Discard, …)) or the relay is idle for
// udpIdleTimeout.
package socks5

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/netip"
	"time"
)

const (
	// udpBufSize is the maximum UDP datagram size we handle. The IP/UDP
	// stack caps packets at ~65 507 bytes on IPv4.
	udpBufSize = 64 * 1024
)

// handleUDPAssociate implements the SOCKS5 UDP ASSOCIATE command.
//
// clientHint is the DST.ADDR:DST.PORT the client supplied in the request;
// it MAY be all zeros when the client does not know its UDP source address.
// The authoritative client IP is taken from the TCP control connection.
func (s *session) handleUDPAssociate(clientHint AddrSpec) {
	if !s.ap.Addr().IsValid() {
		// Cannot enforce source-IP filtering without a known client IP.
		// In practice this only happens in tests using net.Pipe.
		_ = writeReply(s.conn, replyGeneralFailure, AddrSpec{})
		gracefulClose(s.conn)
		return
	}

	// Bind the relay socket on the same address family as the TCP connection.
	localTCP := s.conn.LocalAddr().(*net.TCPAddr)
	udpNet := "udp4"
	if localTCP.IP.To4() == nil {
		udpNet = "udp6"
	}

	pc, err := net.ListenPacket(udpNet, ":0")
	if err != nil {
		s.log().Warn("UDP: failed to create relay socket", "err", err)
		_ = writeReply(s.conn, replyGeneralFailure, AddrSpec{})
		gracefulClose(s.conn)
		return
	}
	defer pc.Close()

	// Tell the client where to send UDP datagrams.
	// BND.ADDR = TCP local IP (the interface the client reaches us on).
	// BND.PORT = OS-assigned UDP relay port.
	relayPort := pc.LocalAddr().(*net.UDPAddr).Port
	localAP := localTCP.AddrPort()
	bound := AddrSpec{IP: localAP.Addr().Unmap(), Port: uint16(relayPort)}
	if err := writeReply(s.conn, replySuccess, bound); err != nil {
		return
	}

	s.log().Info("UDP association started", "relay_port", relayPort)

	// The association lives as long as the TCP control connection.
	// io.Copy(io.Discard, …) blocks until the connection closes, then
	// cancels the relay context.
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go func() {
		defer cancel()
		io.Copy(io.Discard, s.conn) //nolint:errcheck
	}()
	// When ctx is cancelled, unblock ReadFrom by closing the relay socket.
	go func() {
		<-ctx.Done()
		pc.Close()
	}()

	runUDPRelay(ctx, pc, s.ap.Addr(), s.srv.resolver, s.log(), s.srv.timeouts.udpIdle)
	s.log().Info("UDP association ended", "relay_port", relayPort)
}

// runUDPRelay is the core UDP relay loop.
//
//	client → relay  : parse SOCKS5 header, resolve dst via resolver, forward
//	remote → relay  : wrap in SOCKS5 header, forward to client
//
// Direction detection
// ───────────────────
// RFC 1928 §7 mandates IP-based filtering for CLIENT datagrams only; remote
// replies may arrive from any source.
//
// Two-phase rule:
//
//	Phase 1 — clientUDPAddr not yet learned:
//	  from.IP == clientIP → client; record full IP:port
//	  otherwise           → remote; drop (no reply path)
//
//	Phase 2 — clientUDPAddr known:
//	  from.String() == clientUDPAddr → client
//	  from.IP == clientIP (diff port) → remote on same host (wrap & forward)
//	  other IP                        → remote (wrap & forward)
func runUDPRelay(
	ctx context.Context,
	pc net.PacketConn,
	clientIP netip.Addr,
	resolver Resolver,
	log *slog.Logger,
	idleTimeout time.Duration,
) {
	var (
		clientUDPAddr    net.Addr
		clientUDPAddrStr string
	)

	buf := make([]byte, udpBufSize)

	for {
		pc.SetReadDeadline(time.Now().Add(idleTimeout))

		n, from, err := pc.ReadFrom(buf)
		if err != nil {
			var netErr net.Error
			if errors.As(err, &netErr) && netErr.Timeout() && ctx.Err() == nil {
				log.Info("UDP relay idle timeout")
			}
			return
		}

		fromUDP := from.(*net.UDPAddr)
		fromIP := fromUDP.AddrPort().Addr().Unmap()

		// ── Classify ─────────────────────────────────────────────────────
		isClient := false
		if clientUDPAddr == nil {
			if fromIP == clientIP {
				clientUDPAddr = from
				clientUDPAddrStr = from.String()
				isClient = true
			}
		} else {
			isClient = (from.String() == clientUDPAddrStr)
		}

		if isClient {
			// ── Client → Remote ───────────────────────────────────────────
			dest, payload, err := parseUDPHeader(buf[:n])
			if err != nil {
				log.Debug("UDP: dropping client datagram", "from", from, "err", err)
				continue
			}

			// Resolve domain names via the configured Resolver.
			// IP destinations are used directly.
			var dstAP netip.AddrPort
			if dest.Domain != "" {
				resolveCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
				ip, err := resolver.Resolve(resolveCtx, dest.Domain)
				cancel()
				if err != nil {
					log.Debug("UDP: failed to resolve destination", "domain", dest.Domain, "err", err)
					continue
				}
				dstAP = netip.AddrPortFrom(ip, dest.Port)
			} else {
				dstAP = dest.AddrPort()
			}

			if _, err := pc.WriteTo(payload, net.UDPAddrFromAddrPort(dstAP)); err != nil {
				log.Debug("UDP: forward to remote failed", "dst", dstAP, "err", err)
			}

		} else if fromIP == clientIP {
			// ── Remote on same host (Phase 2, different port) ─────────────
			// A service co-located with the client replies from a different
			// port. Treat as remote: wrap and deliver.
			if clientUDPAddr == nil {
				continue
			}
			response := buildUDPResponse(fromUDP.AddrPort(), buf[:n])
			if _, err := pc.WriteTo(response, clientUDPAddr); err != nil {
				log.Debug("UDP: forward same-IP remote to client failed", "err", err)
			}

		} else {
			// ── Remote → Client ───────────────────────────────────────────
			if clientUDPAddr == nil {
				continue
			}
			response := buildUDPResponse(fromUDP.AddrPort(), buf[:n])
			if _, err := pc.WriteTo(response, clientUDPAddr); err != nil {
				log.Debug("UDP: forward remote to client failed", "err", err)
			}
		}
	}
}

// parseUDPHeader parses the SOCKS5 UDP request header (RFC 1928 §7):
//
//	+------+------+------+----------+----------+----------+
//	| RSV  | FRAG | ATYP | DST.ADDR | DST.PORT |   DATA   |
//	+------+------+------+----------+----------+----------+
//	|  2   |  1   |  1   | Variable |    2     | Variable |
//	+------+------+------+----------+----------+----------+
//
// Fragmented datagrams (FRAG != 0x00) are rejected; implementations that do
// not support fragmentation MUST drop them (RFC 1928 §7).
func parseUDPHeader(b []byte) (dest AddrSpec, payload []byte, err error) {
	if len(b) < 4 {
		return AddrSpec{}, nil, errors.New("UDP header too short")
	}
	if b[0] != 0x00 || b[1] != 0x00 {
		return AddrSpec{}, nil, fmt.Errorf("non-zero RSV in UDP header: [%#x %#x]", b[0], b[1])
	}
	if b[2] != 0x00 {
		return AddrSpec{}, nil, fmt.Errorf("fragmented UDP datagram (FRAG=%#x)", b[2])
	}

	// Reuse readAddr by wrapping the remainder in a bytes.Reader.
	// Track bytes consumed to locate the payload start.
	r := bytes.NewReader(b[3:])
	before := r.Len()
	dest, err = readAddr(r)
	if err != nil {
		return AddrSpec{}, nil, fmt.Errorf("parse UDP destination: %w", err)
	}
	consumed := before - r.Len()

	return dest, b[3+consumed:], nil
}

// buildUDPResponse wraps a raw payload in a SOCKS5 UDP response header
// (RFC 1928 §7) for delivery to the client. from is the remote source.
//
//	+------+------+------+----------+----------+----------+
//	| RSV  | FRAG | ATYP | DST.ADDR | DST.PORT |   DATA   |
//	+------+------+------+----------+----------+----------+
//	| 0000 | 0x00 |  …   |    …     |    …     |    …     |
func buildUDPResponse(from netip.AddrPort, payload []byte) []byte {
	src := AddrSpec{IP: from.Addr().Unmap(), Port: from.Port()}

	// Pre-allocate: RSV(2) + FRAG(1) + addr encoding + port(2) + payload.
	buf := make([]byte, 0, 3+1+16+2+len(payload))
	buf = append(buf, 0x00, 0x00, 0x00) // RSV RSV FRAG
	buf = appendAddr(buf, src)
	buf = append(buf, byte(src.Port>>8), byte(src.Port&0xff))
	buf = append(buf, payload...)
	return buf
}
