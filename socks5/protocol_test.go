// SPDX-License-Identifier: Apache-2.0 OR MIT

package socks5

import (
	"bytes"
	"errors"
	"net/netip"
	"testing"
)

// ── readAddr edge cases ──────────────────────────────────────────────────────
//
// Happy-path parsing (IPv4, IPv6, domain) is covered end-to-end by
// TestUDPHeaderRoundtrip and the integration tests. The cases below exercise
// error paths and subtle normalization that cannot be triggered through a
// standard client.

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
// The integration test TestRequest_UnknownATYP exercises the full pipeline.
func TestReadAddr_UnsupportedATYP(t *testing.T) {
	input := []byte{0x02, 0x00, 0x00} // ATYP=0x02 is not defined
	_, err := readAddr(bytes.NewReader(input))
	if !errors.Is(err, errUnsupportedAddrType) {
		t.Fatalf("err = %v, want errUnsupportedAddrType", err)
	}
}

// TestReadAddr_IPv4MappedNormalised verifies that an IPv6-encoded
// IPv4-mapped address (::ffff:a.b.c.d) is stored as plain IPv4 after parsing.
// This normalisation is required so that trusted-IP lookups and direction
// detection work correctly on dual-stack listeners.
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

// ── writeReply invariants ────────────────────────────────────────────────────

// TestWriteReply_RSVIsZero verifies RFC 1928 §6: "Fields marked RESERVED
// (RSV) must be set to X'00'." Every reply must carry RSV=0x00 at byte [2].
func TestWriteReply_RSVIsZero(t *testing.T) {
	for _, code := range []byte{replySuccess, replyGeneralFailure, replyNotAllowed,
		replyConnRefused, replyCmdNotSupported, replyAddrNotSupported} {
		var buf bytes.Buffer
		writeReply(&buf, code, AddrSpec{})
		if got := buf.Bytes()[2]; got != 0x00 {
			t.Errorf("RSV = %#x for reply code %#x, want 0x00 (RFC 1928 §6)", got, code)
		}
	}
}

// TestWriteReply_ZeroAddrIsIPv4 verifies that a zero AddrSpec (used for all
// error replies) encodes as ATYP=IPv4 / 0.0.0.0:0, which is the conventional
// encoding for error replies (RFC 1928 §6 does not mandate a specific address
// for failure replies, but 0.0.0.0:0 is universally used).
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

// ── AddrSpec encode/decode consistency ──────────────────────────────────────

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
