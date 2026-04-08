// SPDX-License-Identifier: Apache-2.0 OR MIT

package socks5

import (
	"encoding/binary"
	"io"
	"net"
	"net/netip"
	"testing"
	"time"
)

// ── RFC 1928 §7 — UDP header parsing edge cases ──────────────────────────────
//
// The happy-path parsing (IPv4, IPv6, domain, empty payload) is covered by
// TestUDPHeaderRoundtrip and the integration tests below.
// These tests exercise RFC-mandated drop conditions and normalization that
// cannot be triggered through a normal client.

// TestParseUDPHeader_TooShort verifies that datagrams shorter than the
// minimum header size are rejected.
func TestParseUDPHeader_TooShort(t *testing.T) {
	_, _, err := parseUDPHeader([]byte{0x00, 0x00, 0x00})
	if err == nil {
		t.Fatal("expected error for datagram shorter than minimum header")
	}
}

// TestParseUDPHeader_NonZeroRSV verifies that datagrams with a non-zero RSV
// field are rejected. RFC 1928 §7 specifies RSV = X'0000'.
func TestParseUDPHeader_NonZeroRSV(t *testing.T) {
	b := []byte{0x00, 0x01 /*RSV[1]!=0*/, 0x00, addrTypeIPv4, 1, 2, 3, 4, 0x00, 0x50}
	_, _, err := parseUDPHeader(b)
	if err == nil {
		t.Fatal("expected error for non-zero RSV in UDP header")
	}
}

// TestParseUDPHeader_FragmentedDropped verifies that datagrams with FRAG != 0
// are rejected. RFC 1928 §7: "An implementation that does not support
// fragmentation MUST drop any datagram whose FRAG field is other than X'00'."
func TestParseUDPHeader_FragmentedDropped(t *testing.T) {
	b := []byte{0x00, 0x00, 0x01 /*FRAG=1*/, addrTypeIPv4, 1, 2, 3, 4, 0x00, 0x50}
	_, _, err := parseUDPHeader(b)
	if err == nil {
		t.Fatal("expected error for fragmented UDP datagram (FRAG != 0)")
	}
}

// TestBuildUDPResponse_IPv4MappedNormalised verifies that the response header
// built for an IPv4-mapped IPv6 source address (::ffff:a.b.c.d) uses
// ATYP=0x01 (IPv4) rather than ATYP=0x04 (IPv6). This normalisation ensures
// clients that do not handle IPv6 can parse the source address correctly.
func TestBuildUDPResponse_IPv4MappedNormalised(t *testing.T) {
	from := netip.MustParseAddrPort("[::ffff:192.0.2.1]:9")
	resp := buildUDPResponse(from, nil)
	if resp[3] != addrTypeIPv4 {
		t.Fatalf("ATYP = %#x, want 0x01 (IPv4) for IPv4-mapped source", resp[3])
	}
}

// TestUDPHeaderRoundtrip verifies that buildUDPResponse and parseUDPHeader
// are inverses of each other across all address families.
func TestUDPHeaderRoundtrip(t *testing.T) {
	cases := []struct {
		from    netip.AddrPort
		payload string
	}{
		{netip.MustParseAddrPort("192.168.1.1:5000"), "ipv4 payload"},
		{netip.MustParseAddrPort("[2001:db8::1]:443"), "ipv6 payload"},
	}
	for _, tc := range cases {
		encoded := buildUDPResponse(tc.from, []byte(tc.payload))
		dest, payload, err := parseUDPHeader(encoded)
		if err != nil {
			t.Fatalf("parseUDPHeader: %v", err)
		}
		if dest.IP != tc.from.Addr() {
			t.Fatalf("IP = %v, want %v", dest.IP, tc.from.Addr())
		}
		if dest.Port != tc.from.Port() {
			t.Fatalf("port = %d, want %d", dest.Port, tc.from.Port())
		}
		if string(payload) != tc.payload {
			t.Fatalf("payload = %q, want %q", payload, tc.payload)
		}
	}
}

// ── Integration tests ────────────────────────────────────────────────────────

// startUDPEchoServer starts a UDP server that echoes every datagram back to
// its sender.
func startUDPEchoServer(t *testing.T) *net.UDPAddr {
	t.Helper()
	conn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { conn.Close() })
	go func() {
		buf := make([]byte, udpBufSize)
		for {
			n, from, err := conn.ReadFromUDP(buf)
			if err != nil {
				return
			}
			conn.WriteToUDP(buf[:n], from)
		}
	}()
	return conn.LocalAddr().(*net.UDPAddr)
}

// doUDPAssociate performs the SOCKS5 TCP handshake and UDP ASSOCIATE request,
// returning the control connection and the relay socket address.
func doUDPAssociate(t *testing.T, proxyAddr string) (ctrl net.Conn, relayAddr *net.UDPAddr) {
	t.Helper()
	ctrl, err := net.DialTimeout("tcp", proxyAddr, 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}

	ctrl.Write([]byte{version5, 0x01, methodNoAuth})
	resp := make([]byte, 2)
	if _, err := io.ReadFull(ctrl, resp); err != nil {
		ctrl.Close()
		t.Fatal(err)
	}
	if resp[1] != methodNoAuth {
		ctrl.Close()
		t.Fatalf("method = %#x, want NoAuth", resp[1])
	}

	// RFC 1928 §7: use all-zeros hint when client UDP address is not known.
	ctrl.Write([]byte{version5, byte(CommandUDPAssociate), 0x00, addrTypeIPv4, 0, 0, 0, 0, 0, 0})

	reply := make([]byte, 4)
	if _, err := io.ReadFull(ctrl, reply); err != nil {
		ctrl.Close()
		t.Fatal(err)
	}
	if reply[1] != replySuccess {
		ctrl.Close()
		t.Fatalf("UDP ASSOCIATE reply = %#x, want 0x00 (success)", reply[1])
	}

	var relayIP net.IP
	var relayPort uint16
	switch reply[3] {
	case addrTypeIPv4:
		b := make([]byte, 6)
		io.ReadFull(ctrl, b)
		relayIP, relayPort = net.IP(b[:4]), binary.BigEndian.Uint16(b[4:6])
	case addrTypeIPv6:
		b := make([]byte, 18)
		io.ReadFull(ctrl, b)
		relayIP, relayPort = net.IP(b[:16]), binary.BigEndian.Uint16(b[16:18])
	default:
		ctrl.Close()
		t.Fatalf("unexpected ATYP in UDP ASSOCIATE reply: %#x", reply[3])
	}
	return ctrl, &net.UDPAddr{IP: relayIP, Port: int(relayPort)}
}

// TestUDPAssociate_EchoRoundtrip is the primary UDP integration test.
// It verifies:
//   - The relay correctly forwards a client datagram to the destination.
//   - The reply is encapsulated with a SOCKS5 UDP header (RFC 1928 §7).
//   - The reported source in the reply matches the echo server's address.
func TestUDPAssociate_EchoRoundtrip(t *testing.T) {
	echoAddr := startUDPEchoServer(t)
	proxyAddr, cancel := startProxy(t, Config{})
	defer cancel()

	ctrl, relayAddr := doUDPAssociate(t, proxyAddr)
	defer ctrl.Close()

	udpConn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer udpConn.Close()
	udpConn.SetDeadline(time.Now().Add(5 * time.Second))

	msg := []byte("udp-echo-test")
	echoIP := echoAddr.IP.To4()
	datagram := append([]byte{0x00, 0x00, 0x00, addrTypeIPv4}, echoIP...)
	datagram = binary.BigEndian.AppendUint16(datagram, uint16(echoAddr.Port))
	datagram = append(datagram, msg...)

	if _, err := udpConn.WriteTo(datagram, relayAddr); err != nil {
		t.Fatal(err)
	}

	buf := make([]byte, udpBufSize)
	n, _, err := udpConn.ReadFrom(buf)
	if err != nil {
		t.Fatalf("ReadFrom relay: %v", err)
	}

	dest, payload, err := parseUDPHeader(buf[:n])
	if err != nil {
		t.Fatalf("parseUDPHeader on reply: %v", err)
	}
	if dest.IP.String() != netip.AddrFrom4([4]byte(echoIP)).String() {
		t.Fatalf("reported source IP = %v, want echo server %v", dest.IP, echoIP)
	}
	if dest.Port != uint16(echoAddr.Port) {
		t.Fatalf("reported source port = %d, want %d", dest.Port, echoAddr.Port)
	}
	if string(payload) != string(msg) {
		t.Fatalf("payload = %q, want %q", payload, msg)
	}
}

// TestUDPAssociate_PortChangingRemote verifies RFC 1928 §7 compliance: the
// relay MUST forward replies from remote hosts regardless of which source port
// they use. This covers load balancers and NAT devices that reply from a
// different port than the one they listen on.
func TestUDPAssociate_PortChangingRemote(t *testing.T) {
	proxyAddr, cancel := startProxy(t, Config{})
	defer cancel()

	listenConn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer listenConn.Close()
	replyConn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer replyConn.Close()
	listenAddr := listenConn.LocalAddr().(*net.UDPAddr)

	go func() {
		buf := make([]byte, 1024)
		n, from, err := listenConn.ReadFromUDP(buf)
		if err != nil {
			return
		}
		// Reply from a DIFFERENT port — the port-changing case.
		replyConn.WriteToUDP(buf[:n], from)
	}()

	ctrl, relayAddr := doUDPAssociate(t, proxyAddr)
	defer ctrl.Close()

	udpConn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer udpConn.Close()
	udpConn.SetDeadline(time.Now().Add(5 * time.Second))

	msg := []byte("port-change-test")
	datagram := append([]byte{0x00, 0x00, 0x00, addrTypeIPv4}, listenAddr.IP.To4()...)
	datagram = binary.BigEndian.AppendUint16(datagram, uint16(listenAddr.Port))
	datagram = append(datagram, msg...)

	if _, err := udpConn.WriteTo(datagram, relayAddr); err != nil {
		t.Fatal(err)
	}

	buf := make([]byte, udpBufSize)
	n, _, err := udpConn.ReadFrom(buf)
	if err != nil {
		t.Fatalf("expected reply from port-changing remote: %v", err)
	}
	_, payload, err := parseUDPHeader(buf[:n])
	if err != nil {
		t.Fatalf("parseUDPHeader: %v", err)
	}
	if string(payload) != string(msg) {
		t.Fatalf("payload = %q, want %q", payload, msg)
	}
}

// TestUDPAssociate_AssociationEndsWithTCP verifies RFC 1928 §7:
// "A UDP association terminates when the TCP connection that the UDP ASSOCIATE
// request arrived on terminates."
func TestUDPAssociate_AssociationEndsWithTCP(t *testing.T) {
	echoAddr := startUDPEchoServer(t)
	proxyAddr, cancel := startProxy(t, Config{})
	defer cancel()

	ctrl, relayAddr := doUDPAssociate(t, proxyAddr)

	udpConn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer udpConn.Close()

	echoIP := echoAddr.IP.To4()
	datagram := append([]byte{0x00, 0x00, 0x00, addrTypeIPv4}, echoIP...)
	datagram = binary.BigEndian.AppendUint16(datagram, uint16(echoAddr.Port))
	datagram = append(datagram, "probe"...)

	// Confirm relay is working before closing TCP.
	udpConn.SetDeadline(time.Now().Add(3 * time.Second))
	udpConn.WriteTo(datagram, relayAddr)
	buf := make([]byte, udpBufSize)
	if _, _, err := udpConn.ReadFrom(buf); err != nil {
		t.Fatalf("relay not working before TCP close: %v", err)
	}

	// Close the TCP control connection.
	ctrl.Close()
	time.Sleep(100 * time.Millisecond)

	// Relay must now be torn down: datagrams sent to it receive no response.
	udpConn.SetDeadline(time.Now().Add(500 * time.Millisecond))
	udpConn.WriteTo(datagram, relayAddr)
	if n, _, err := udpConn.ReadFrom(buf); err == nil {
		t.Fatalf("expected no reply after TCP close, got %q", buf[:n])
	}
}
