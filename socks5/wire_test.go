// SPDX-License-Identifier: Apache-2.0 OR MIT

package socks5

import (
	"bytes"
	"errors"
	"net"
	"net/netip"
	"testing"
	"time"
)

// readAddr edge cases
//
// Happy-path parsing (IPv4, IPv6, domain) is covered end-to-end by
// TestUDPHeaderRoundtrip and the integration tests. The cases below exercise
// error paths and normalisation that cannot be triggered through a standard
// client.

// TestReadAddr_EmptyDomain verifies that DLEN=0 is rejected; the RFC diagram
// marks the DOMAINNAME field as "1 to 255" octets.
func TestReadAddr_EmptyDomain(t *testing.T) {
	input := []byte{addrTypeDomain, 0x00, 0x00, 0x50}
	_, err := readAddr(bytes.NewReader(input))
	if !errors.Is(err, errEmptyDomainName) {
		t.Fatalf("err = %v, want errEmptyDomainName", err)
	}
}

// TestReadAddr_UnsupportedATYP verifies that an unknown ATYP byte returns
// errUnsupportedAddrType, which the session maps to reply 0x08.
func TestReadAddr_UnsupportedATYP(t *testing.T) {
	input := []byte{0x02, 0x00, 0x00} // ATYP=0x02 is not defined by RFC 1928
	_, err := readAddr(bytes.NewReader(input))
	if !errors.Is(err, errUnsupportedAddrType) {
		t.Fatalf("err = %v, want errUnsupportedAddrType", err)
	}
}

// TestReadAddr_IPv4MappedNormalised verifies that an IPv6-encoded IPv4-mapped
// address (::ffff:a.b.c.d) is stored as plain IPv4 after parsing.
func TestReadAddr_IPv4MappedNormalised(t *testing.T) {
	mapped := netip.MustParseAddr("::ffff:1.2.3.4")
	b := mapped.As16()
	input := append([]byte{addrTypeIPv6}, b[:]...)
	input = append(input, 0x00, 0x50)

	a, err := readAddr(bytes.NewReader(input))
	if err != nil {
		t.Fatal(err)
	}
	if !a.IP.Is4() {
		t.Fatalf("expected plain IPv4 after Unmap, got %v", a.IP)
	}
}

// parseAddrFromBytes — direct unit tests
//
// parseAddrFromBytes is the allocation-free slice-based sibling of readAddr,
// used by the UDP relay hot path. Each address family and every error branch
// is exercised here; the integration tests cover the full relay pipeline.

func TestParseAddrFromBytes_IPv4(t *testing.T) {
	b := []byte{addrTypeIPv4, 1, 2, 3, 4, 0x00, 0x50} // 1.2.3.4:80
	addr, n, err := parseAddrFromBytes(b)
	if err != nil {
		t.Fatal(err)
	}
	if n != 7 {
		t.Fatalf("consumed %d bytes, want 7", n)
	}
	if addr.IP.String() != "1.2.3.4" {
		t.Fatalf("IP = %v, want 1.2.3.4", addr.IP)
	}
	if addr.Port != 80 {
		t.Fatalf("Port = %d, want 80", addr.Port)
	}
}

func TestParseAddrFromBytes_IPv6(t *testing.T) {
	ip6 := netip.MustParseAddr("2001:db8::1")
	a16 := ip6.As16()
	b := append([]byte{addrTypeIPv6}, a16[:]...)
	b = append(b, 0x01, 0xBB) // port 443
	addr, n, err := parseAddrFromBytes(b)
	if err != nil {
		t.Fatal(err)
	}
	if n != 19 {
		t.Fatalf("consumed %d bytes, want 19", n)
	}
	if addr.IP != ip6 {
		t.Fatalf("IP = %v, want %v", addr.IP, ip6)
	}
	if addr.Port != 443 {
		t.Fatalf("Port = %d, want 443", addr.Port)
	}
}

func TestParseAddrFromBytes_IPv4MappedNormalised(t *testing.T) {
	mapped := netip.MustParseAddr("::ffff:1.2.3.4")
	a16 := mapped.As16()
	b := append([]byte{addrTypeIPv6}, a16[:]...)
	b = append(b, 0x00, 0x50)
	addr, _, err := parseAddrFromBytes(b)
	if err != nil {
		t.Fatal(err)
	}
	if !addr.IP.Is4() {
		t.Fatalf("expected plain IPv4 after Unmap, got %v", addr.IP)
	}
	if addr.IP.String() != "1.2.3.4" {
		t.Fatalf("IP = %v, want 1.2.3.4", addr.IP)
	}
}

func TestParseAddrFromBytes_Domain(t *testing.T) {
	domain := "example.com"
	b := []byte{addrTypeDomain, byte(len(domain))}
	b = append(b, []byte(domain)...)
	b = append(b, 0x1F, 0x90) // port 8080
	addr, n, err := parseAddrFromBytes(b)
	if err != nil {
		t.Fatal(err)
	}
	want := 1 + 1 + len(domain) + 2 // ATYP + DLEN + domain + port
	if n != want {
		t.Fatalf("consumed %d bytes, want %d", n, want)
	}
	if addr.Domain != domain {
		t.Fatalf("Domain = %q, want %q", addr.Domain, domain)
	}
	if addr.Port != 8080 {
		t.Fatalf("Port = %d, want 8080", addr.Port)
	}
}

func TestParseAddrFromBytes_EmptyDomain(t *testing.T) {
	b := []byte{addrTypeDomain, 0x00, 0x00, 0x50}
	_, _, err := parseAddrFromBytes(b)
	if !errors.Is(err, errEmptyDomainName) {
		t.Fatalf("err = %v, want errEmptyDomainName", err)
	}
}

func TestParseAddrFromBytes_UnsupportedATYP(t *testing.T) {
	b := []byte{0x02, 0x00, 0x00} // ATYP=0x02 is not defined
	_, _, err := parseAddrFromBytes(b)
	if !errors.Is(err, errUnsupportedAddrType) {
		t.Fatalf("err = %v, want errUnsupportedAddrType", err)
	}
}

func TestParseAddrFromBytes_Truncated(t *testing.T) {
	cases := []struct {
		name string
		b    []byte
	}{
		{"empty", []byte{}},
		{"IPv4 no addr bytes", []byte{addrTypeIPv4}},
		{"IPv4 missing port", []byte{addrTypeIPv4, 1, 2, 3, 4}},
		{"IPv6 no addr bytes", []byte{addrTypeIPv6}},
		{"domain no length", []byte{addrTypeDomain}},
		{"domain truncated body", []byte{addrTypeDomain, 5, 'h', 'e', 'l', 'l'}},
		{"domain missing port", []byte{addrTypeDomain, 5, 'h', 'e', 'l', 'l', 'o'}},
	}
	for _, tc := range cases {
		if _, _, err := parseAddrFromBytes(tc.b); err == nil {
			t.Errorf("%s: expected error for truncated input %x", tc.name, tc.b)
		}
	}
}

// writeReply invariants

// TestWriteReply_RSVIsZero verifies RFC 1928 §6: RSV must be 0x00 in every reply.
func TestWriteReply_RSVIsZero(t *testing.T) {
	for _, code := range []byte{
		replySuccess, replyGeneralFailure, replyNotAllowed,
		replyNetUnreachable, replyHostUnreachable, replyConnRefused,
		replyCmdNotSupported, replyAddrNotSupported,
	} {
		var buf bytes.Buffer
		writeReply(&buf, code, AddrSpec{})
		if got := buf.Bytes()[2]; got != 0x00 {
			t.Errorf("RSV = %#x for reply code %#x, want 0x00 (RFC 1928 §6)", got, code)
		}
	}
}

// TestWriteReply_ZeroAddrIsIPv4 verifies that a zero AddrSpec (used for all
// error replies) encodes as ATYP=IPv4 / 0.0.0.0:0.
func TestWriteReply_ZeroAddrIsIPv4(t *testing.T) {
	var buf bytes.Buffer
	writeReply(&buf, replyGeneralFailure, AddrSpec{})
	got := buf.Bytes()
	if got[3] != addrTypeIPv4 {
		t.Fatalf("ATYP = %#x, want 0x01 (IPv4) for zero AddrSpec", got[3])
	}
	if len(got) != 10 { // 4 header + 4 addr + 2 port
		t.Fatalf("len = %d, want 10 for IPv4 error reply", len(got))
	}
}

// AddrSpec encode/decode consistency

// TestAddrSpec_Roundtrip verifies that appendAddr + readAddr are inverses
// across all three address families.
func TestAddrSpec_Roundtrip(t *testing.T) {
	cases := []AddrSpec{
		{IP: netip.MustParseAddr("1.2.3.4"), Port: 80},
		{IP: netip.MustParseAddr("::1"), Port: 443},
		{Domain: "example.com", Port: 8080},
	}
	for _, orig := range cases {
		var buf bytes.Buffer
		buf.Write(appendAddr(nil, orig))
		buf.WriteByte(byte(orig.Port >> 8))
		buf.WriteByte(byte(orig.Port & 0xff))

		got, err := readAddr(&buf)
		if err != nil {
			t.Fatalf("readAddr(%v): %v", orig, err)
		}
		if got.String() != orig.String() {
			t.Fatalf("roundtrip: got %v, want %v", got, orig)
		}
	}
}

// replyFromError mapping

// TestReplyFromError_ConnRefused verifies that ECONNREFUSED maps to reply 0x05.
func TestReplyFromError_ConnRefused(t *testing.T) {
	// Listen then immediately close — dialing that address gives ECONNREFUSED.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().String()
	ln.Close()

	_, dialErr := net.DialTimeout("tcp", addr, time.Second)
	if dialErr == nil {
		t.Skip("expected ECONNREFUSED but connection succeeded")
	}
	if got := replyFromError(dialErr); got != replyConnRefused {
		t.Fatalf("replyFromError = %#x, want %#x (conn refused) for ECONNREFUSED", got, replyConnRefused)
	}
}

// TestReplyFromError_Generic verifies that an unrecognised error maps to reply
// 0x01 (general SOCKS server failure).
func TestReplyFromError_Generic(t *testing.T) {
	err := errors.New("some unknown network error")
	if got := replyFromError(err); got != replyGeneralFailure {
		t.Fatalf("replyFromError = %#x, want %#x (general failure)", got, replyGeneralFailure)
	}
}
