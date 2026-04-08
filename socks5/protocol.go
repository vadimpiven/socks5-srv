// SPDX-License-Identifier: Apache-2.0 OR MIT

// Package socks5 implements a SOCKS5 proxy server (RFC 1928 / RFC 1929).
//
// Supported commands:
//   - CONNECT (0x01): tunnels a TCP stream to any IPv4, IPv6, or domain-name
//     destination.
//   - UDP ASSOCIATE (0x03): relays UDP datagrams with SOCKS5 encapsulation;
//     fragmentation is not supported (RFC 1928 §7 permits this).
//
// BIND (0x02) and GSSAPI are not implemented; both are rejected with the
// appropriate reply codes.
//
// All behaviour is configurable through interfaces: auth methods via
// [Authenticator], credential validation via [CredentialStore], access
// control via [RuleSet], name resolution via [Resolver], and outbound
// dialing via [DialFunc].
package socks5

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"strconv"
	"syscall"
)

// ── Wire-protocol constants ──────────────────────────────────────────────────

// version5 is the only SOCKS protocol version we support (RFC 1928 §3).
const version5 byte = 0x05

// Authentication methods (RFC 1928 §3).
const (
	methodNoAuth       byte = 0x00
	methodUserPass     byte = 0x02
	methodNoAcceptable byte = 0xFF
)

// Sub-negotiation version for username/password auth (RFC 1929 §2).
const (
	authSubVersion byte = 0x01
	authSuccess    byte = 0x00
	authFailure    byte = 0x01
)

// Command is a SOCKS5 request command (RFC 1928 §4).
type Command byte

const (
	CommandConnect      Command = 0x01
	CommandBind         Command = 0x02 // not implemented; rejected with 0x07
	CommandUDPAssociate Command = 0x03
)

// Address types (RFC 1928 §5).
const (
	addrTypeIPv4   byte = 0x01
	addrTypeDomain byte = 0x03
	addrTypeIPv6   byte = 0x04
)

// Reply codes (RFC 1928 §6).
const (
	replySuccess          byte = 0x00
	replyGeneralFailure   byte = 0x01
	replyNotAllowed       byte = 0x02
	replyNetUnreachable   byte = 0x03
	replyHostUnreachable  byte = 0x04
	replyConnRefused      byte = 0x05
	replyTTLExpired       byte = 0x06 // ICMP time-exceeded; NOT used for dial timeouts
	replyCmdNotSupported  byte = 0x07
	replyAddrNotSupported byte = 0x08
)

// ── AddrSpec ─────────────────────────────────────────────────────────────────

// AddrSpec is a SOCKS5 network destination: either a literal IP address or a
// domain name, plus a port. Exactly one of IP and Domain is set.
//
// IP destinations always use the plain IPv4 or IPv6 form — IPv4-mapped IPv6
// (::ffff:a.b.c.d) is normalised to plain IPv4 by the parser.
type AddrSpec struct {
	// IP is the destination for literal-IP requests.
	// Zero (not IsValid) when Domain is set.
	IP netip.Addr
	// Domain is the fully-qualified host name for DOMAINNAME requests.
	// Empty when IP is set.
	Domain string
	// Port is the destination TCP or UDP port.
	Port uint16
}

// String returns a "host:port" string suitable for net.Dial.
func (a AddrSpec) String() string {
	if a.Domain != "" {
		return net.JoinHostPort(a.Domain, strconv.Itoa(int(a.Port)))
	}
	return netip.AddrPortFrom(a.IP, a.Port).String()
}

// AddrPort returns the netip.AddrPort for IP destinations, or the zero value
// for domain destinations (where no IP is known yet).
func (a AddrSpec) AddrPort() netip.AddrPort {
	return netip.AddrPortFrom(a.IP, a.Port)
}

// isIP reports whether this is a literal-IP (non-domain) destination.
func (a AddrSpec) isIP() bool { return a.Domain == "" }

var (
	errUnsupportedAddrType = errors.New("unsupported address type")
	errEmptyDomainName     = errors.New("empty domain name")
)

// ── Wire encoding / decoding ─────────────────────────────────────────────────

// readAddr reads ATYP + address + port from the wire (RFC 1928 §4/§5) and
// returns the destination as an AddrSpec. IPv4-mapped IPv6 is normalised.
func readAddr(r io.Reader) (AddrSpec, error) {
	var atype [1]byte
	if _, err := io.ReadFull(r, atype[:]); err != nil {
		return AddrSpec{}, err
	}

	switch atype[0] {
	case addrTypeIPv4:
		var a [4]byte
		if _, err := io.ReadFull(r, a[:]); err != nil {
			return AddrSpec{}, err
		}
		port, err := readPort(r)
		if err != nil {
			return AddrSpec{}, err
		}
		return AddrSpec{IP: netip.AddrFrom4(a), Port: port}, nil

	case addrTypeIPv6:
		var a [16]byte
		if _, err := io.ReadFull(r, a[:]); err != nil {
			return AddrSpec{}, err
		}
		port, err := readPort(r)
		if err != nil {
			return AddrSpec{}, err
		}
		return AddrSpec{IP: netip.AddrFrom16(a).Unmap(), Port: port}, nil

	case addrTypeDomain:
		var dlen [1]byte
		if _, err := io.ReadFull(r, dlen[:]); err != nil {
			return AddrSpec{}, err
		}
		if dlen[0] == 0 {
			return AddrSpec{}, errEmptyDomainName
		}
		domain := make([]byte, dlen[0])
		if _, err := io.ReadFull(r, domain); err != nil {
			return AddrSpec{}, err
		}
		port, err := readPort(r)
		if err != nil {
			return AddrSpec{}, err
		}
		return AddrSpec{Domain: string(domain), Port: port}, nil

	default:
		return AddrSpec{}, fmt.Errorf("%w: %#x", errUnsupportedAddrType, atype[0])
	}
}

func readPort(r io.Reader) (uint16, error) {
	var b [2]byte
	if _, err := io.ReadFull(r, b[:]); err != nil {
		return 0, err
	}
	return binary.BigEndian.Uint16(b[:]), nil
}

// appendAddr appends the ATYP + address wire encoding of spec to buf.
// A zero AddrSpec (both IP and Domain unset) encodes as IPv4 0.0.0.0,
// which is the convention for error replies (RFC 1928 §6).
func appendAddr(buf []byte, spec AddrSpec) []byte {
	switch {
	case spec.Domain != "":
		buf = append(buf, addrTypeDomain, byte(len(spec.Domain)))
		buf = append(buf, spec.Domain...)
	case spec.IP.Is4():
		a := spec.IP.As4()
		buf = append(buf, addrTypeIPv4)
		buf = append(buf, a[:]...)
	case spec.IP.Is6():
		a := spec.IP.As16()
		buf = append(buf, addrTypeIPv6)
		buf = append(buf, a[:]...)
	default:
		// Zero or invalid IP: use IPv4 0.0.0.0 as per convention.
		buf = append(buf, addrTypeIPv4, 0, 0, 0, 0)
	}
	return buf
}

// writeReply sends a SOCKS5 reply: VER | REP | RSV | ATYP | BND.ADDR | BND.PORT.
// A zero AddrSpec encodes as 0.0.0.0:0 (used for all error replies).
func writeReply(w io.Writer, code byte, bound AddrSpec) error {
	buf := make([]byte, 0, 22) // max: 4 header + 16 IPv6 + 2 port
	buf = append(buf, version5, code, 0x00)
	buf = appendAddr(buf, bound)
	buf = append(buf, byte(bound.Port>>8), byte(bound.Port&0xff))
	_, err := w.Write(buf)
	return err
}

// replyFromError maps a Go network error to the closest SOCKS5 reply code
// (RFC 1928 §6).
//
// Mapping rationale:
//   - replyTTLExpired (0x06) is reserved for ICMP "time exceeded" (IP TTL
//     reached zero in transit). It must NOT be used for a dial deadline.
//   - A dial deadline or TCP retransmit timeout (ETIMEDOUT) means the remote
//     host did not respond → replyHostUnreachable (0x04).
//   - EHOSTUNREACH covers both ICMP host-unreachable and ICMP TTL-exceeded,
//     since the kernel surfaces both as the same errno.
func replyFromError(err error) byte {
	var opErr *net.OpError
	if errors.As(err, &opErr) && opErr.Timeout() {
		return replyHostUnreachable
	}
	var sysErr *os.SyscallError
	if errors.As(err, &sysErr) {
		switch {
		case errors.Is(sysErr.Err, syscall.ECONNREFUSED):
			return replyConnRefused
		case errors.Is(sysErr.Err, syscall.ETIMEDOUT):
			return replyHostUnreachable
		case errors.Is(sysErr.Err, syscall.ENETUNREACH):
			return replyNetUnreachable
		case errors.Is(sysErr.Err, syscall.EHOSTUNREACH):
			return replyHostUnreachable
		}
	}
	return replyGeneralFailure
}
