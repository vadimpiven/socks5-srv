// SPDX-License-Identifier: Apache-2.0 OR MIT

package socks5

import (
	"context"
	"encoding/binary"
	"io"
	"log/slog"
	"net"
	"net/netip"
	"testing"
	"time"

	"golang.org/x/net/proxy"
)

// discardLogger returns a logger that silences all output, suitable for tests
// where log noise would obscure failures.
func discardLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

// startEchoServer starts a TCP server that echoes all received data.
func startEchoServer(t *testing.T) net.Listener {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer conn.Close()
				io.Copy(conn, conn)
			}()
		}
	}()
	return ln
}

// startProxy starts a SOCKS5 server with the given Config on a random port.
// If cfg.Logger is nil it is set to a discard logger so tests stay silent.
func startProxy(t *testing.T, cfg Config) (string, context.CancelFunc) {
	t.Helper()
	if cfg.Logger == nil {
		cfg.Logger = discardLogger()
	}

	ctx, cancel := context.WithCancel(context.Background())
	srv, err := NewServer(cfg)
	if err != nil {
		cancel()
		t.Fatalf("NewServer: %v", err)
	}

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		cancel()
		t.Fatal(err)
	}
	addr := ln.Addr().String()
	go srv.Serve(ctx, ln)
	return addr, cancel
}

// dialThroughProxy connects to target via the SOCKS5 proxy at proxyAddr using
// golang.org/x/net/proxy — a real, independent SOCKS5 client implementation.
// Passing a non-nil auth enables username/password authentication.
// The connection is registered for cleanup with t.Cleanup.
func dialThroughProxy(t *testing.T, proxyAddr string, auth *proxy.Auth, target string) net.Conn {
	t.Helper()
	d, err := proxy.SOCKS5("tcp", proxyAddr, auth, proxy.Direct)
	if err != nil {
		t.Fatal(err)
	}
	conn, err := d.Dial("tcp", target)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { conn.Close() })
	return conn
}

// ── Core session tests ───────────────────────────────────────────────────────

func TestFullSession_NoAuth_Connect(t *testing.T) {
	echo := startEchoServer(t)
	defer echo.Close()
	proxyAddr, cancel := startProxy(t, Config{})
	defer cancel()

	conn := dialThroughProxy(t, proxyAddr, nil, echo.Addr().String())

	conn.Write([]byte("hello proxy"))
	buf := make([]byte, 64)
	n, err := conn.Read(buf)
	if err != nil {
		t.Fatal(err)
	}
	if string(buf[:n]) != "hello proxy" {
		t.Fatalf("got %q, want %q", buf[:n], "hello proxy")
	}
}

func TestFullSession_UserPass_Connect(t *testing.T) {
	echo := startEchoServer(t)
	defer echo.Close()

	creds := StaticCredentials{Username: "user", Password: "pass"}
	proxyAddr, cancel := startProxy(t, Config{
		Authenticators: []Authenticator{
			UserPassAuthenticator{Credentials: creds},
		},
	})
	defer cancel()

	conn := dialThroughProxy(t, proxyAddr,
		&proxy.Auth{User: "user", Password: "pass"},
		echo.Addr().String())

	conn.Write([]byte("authenticated"))
	buf := make([]byte, 64)
	n, err := conn.Read(buf)
	if err != nil {
		t.Fatal(err)
	}
	if string(buf[:n]) != "authenticated" {
		t.Fatalf("got %q, want %q", buf[:n], "authenticated")
	}
}

// TestFullSession_AuthFailure probes the server's RFC 1929 failure path at
// the wire level: it sends deliberately wrong credentials and checks that the
// server responds with STATUS=0x01 and then closes the connection.
// proxy.SOCKS5 is not used here because we need to inject the wrong password.
func TestFullSession_AuthFailure(t *testing.T) {
	creds := StaticCredentials{Username: "user", Password: "pass"}
	proxyAddr, cancel := startProxy(t, Config{
		Authenticators: []Authenticator{
			UserPassAuthenticator{Credentials: creds},
		},
	})
	defer cancel()

	conn, err := net.DialTimeout("tcp", proxyAddr, 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	conn.Write([]byte{version5, 0x01, methodUserPass})
	resp := make([]byte, 2)
	io.ReadFull(conn, resp)

	authReq := []byte{authSubVersion, 0x04}
	authReq = append(authReq, "user"...)
	authReq = append(authReq, 0x05)
	authReq = append(authReq, "wrong"...)
	conn.Write(authReq)

	authResp := make([]byte, 2)
	io.ReadFull(conn, authResp)
	if authResp[1] != authFailure {
		t.Fatalf("STATUS = %#x, want %#x (failure)", authResp[1], authFailure)
	}

	// RFC 1929 §2: server MUST close the connection after a failure response.
	conn.SetReadDeadline(time.Now().Add(time.Second))
	buf := make([]byte, 1)
	if _, err = conn.Read(buf); err == nil {
		t.Fatal("expected connection to be closed after auth failure")
	}
}

// TestFullSession_UnsupportedCommand probes the BIND rejection path at the
// wire level to verify the exact reply code (0x07).
func TestFullSession_UnsupportedCommand(t *testing.T) {
	proxyAddr, cancel := startProxy(t, Config{})
	defer cancel()

	conn, err := net.DialTimeout("tcp", proxyAddr, 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	conn.Write([]byte{version5, 0x01, methodNoAuth})
	io.ReadFull(conn, make([]byte, 2)) // consume method selection

	conn.Write([]byte{version5, byte(CommandBind), 0x00, addrTypeIPv4, 127, 0, 0, 1, 0x00, 0x50})

	reply := make([]byte, 10)
	io.ReadFull(conn, reply)
	if reply[1] != replyCmdNotSupported {
		t.Fatalf("REP = %#x, want %#x (cmd not supported)", reply[1], replyCmdNotSupported)
	}
	conn.SetReadDeadline(time.Now().Add(time.Second))
	if _, err := conn.Read(make([]byte, 1)); err == nil {
		t.Fatal("expected connection close after failure reply (RFC 1928 §6)")
	}
}

// TestFullSession_ConnectionRefused verifies the exact SOCKS5 reply code
// (0x05) when the target port is not listening.
func TestFullSession_ConnectionRefused(t *testing.T) {
	proxyAddr, cancel := startProxy(t, Config{})
	defer cancel()

	conn, err := net.DialTimeout("tcp", proxyAddr, 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	conn.Write([]byte{version5, 0x01, methodNoAuth})
	io.ReadFull(conn, make([]byte, 2))

	// Port 1 is almost certainly not listening.
	req := []byte{version5, byte(CommandConnect), 0x00, addrTypeIPv4, 127, 0, 0, 1, 0x00, 0x01}
	conn.Write(req)

	reply := make([]byte, 10)
	io.ReadFull(conn, reply)
	if reply[1] != replyConnRefused {
		t.Fatalf("REP = %#x, want %#x (conn refused)", reply[1], replyConnRefused)
	}
}

func TestGracefulShutdown(t *testing.T) {
	echo := startEchoServer(t)
	defer echo.Close()
	proxyAddr, cancel := startProxy(t, Config{})

	conn := dialThroughProxy(t, proxyAddr, nil, echo.Addr().String())

	cancel() // simulate SIGTERM

	conn.Write([]byte("after shutdown"))
	buf := make([]byte, 64)
	n, err := conn.Read(buf)
	if err != nil {
		t.Fatal(err)
	}
	if string(buf[:n]) != "after shutdown" {
		t.Fatalf("got %q, want %q", buf[:n], "after shutdown")
	}
}

// ── RFC 1928 §3 — Greeting compliance ──────────────────────────────────────

// TestGreeting_WrongVersion verifies RFC 1928 §3: VER must be 0x05.
// A client speaking a different SOCKS version receives no method-selection
// response; the server closes the connection.
func TestGreeting_WrongVersion(t *testing.T) {
	proxyAddr, cancel := startProxy(t, Config{})
	defer cancel()

	conn, err := net.DialTimeout("tcp", proxyAddr, 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	// SOCKS4 greeting.
	conn.Write([]byte{0x04, 0x01, methodNoAuth})

	conn.SetReadDeadline(time.Now().Add(time.Second))
	buf := make([]byte, 4)
	n, _ := conn.Read(buf)
	// Server MUST NOT send a valid method-selection response.
	if n >= 2 && buf[0] == version5 && buf[1] != methodNoAcceptable {
		t.Fatalf("server returned a valid method selection for wrong VER: %x", buf[:n])
	}
	// RFC 1928 §3: server must close the connection after rejecting.
	conn.SetReadDeadline(time.Now().Add(time.Second))
	if _, err := conn.Read(make([]byte, 1)); err == nil {
		t.Fatal("expected connection to be closed after wrong VER")
	}
}

// TestGreeting_ZeroNMethods verifies RFC 1928 §3: NMETHODS is described as
// containing 1 to 255 method bytes. A value of 0 must be rejected with 0xFF.
func TestGreeting_ZeroNMethods(t *testing.T) {
	proxyAddr, cancel := startProxy(t, Config{})
	defer cancel()

	conn, err := net.DialTimeout("tcp", proxyAddr, 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	conn.Write([]byte{version5, 0x00}) // NMETHODS=0

	resp := make([]byte, 2)
	if _, err := io.ReadFull(conn, resp); err != nil {
		t.Fatalf("read method selection: %v", err)
	}
	if resp[1] != methodNoAcceptable {
		t.Fatalf("METHOD = %#x, want 0xFF (no acceptable) for NMETHODS=0", resp[1])
	}
}

// ── RFC 1928 §4 — Request compliance ────────────────────────────────────────

// TestRequest_NonZeroRSV verifies RFC 1928 §4: "Fields marked RESERVED (RSV)
// must be set to X'00'." A non-zero RSV byte must produce reply 0x01
// (general failure) and close the connection.
func TestRequest_NonZeroRSV(t *testing.T) {
	proxyAddr, cancel := startProxy(t, Config{})
	defer cancel()

	conn, err := net.DialTimeout("tcp", proxyAddr, 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	conn.Write([]byte{version5, 0x01, methodNoAuth})
	io.ReadFull(conn, make([]byte, 2))

	// RSV=0x01 instead of 0x00.
	conn.Write([]byte{version5, byte(CommandConnect), 0x01, addrTypeIPv4, 127, 0, 0, 1, 0x00, 0x50})

	reply := make([]byte, 10)
	io.ReadFull(conn, reply)
	if reply[1] != replyGeneralFailure {
		t.Fatalf("REP = %#x, want 0x01 (general failure) for non-zero RSV", reply[1])
	}
	// RFC 1928 §6: MUST terminate the connection shortly after a failure reply.
	conn.SetReadDeadline(time.Now().Add(time.Second))
	if _, err := conn.Read(make([]byte, 1)); err == nil {
		t.Fatal("expected connection close after failure reply (RFC 1928 §6)")
	}
}

// TestRequest_UnknownATYP verifies RFC 1928 §5: an unknown address type must
// produce reply 0x08 (address type not supported).
func TestRequest_UnknownATYP(t *testing.T) {
	proxyAddr, cancel := startProxy(t, Config{})
	defer cancel()

	conn, err := net.DialTimeout("tcp", proxyAddr, 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	conn.Write([]byte{version5, 0x01, methodNoAuth})
	io.ReadFull(conn, make([]byte, 2))

	// ATYP=0x02 is not defined by RFC 1928.
	conn.Write([]byte{version5, byte(CommandConnect), 0x00, 0x02, 0x00, 0x00})

	reply := make([]byte, 10)
	io.ReadFull(conn, reply)
	if reply[1] != replyAddrNotSupported {
		t.Fatalf("REP = %#x, want 0x08 (address type not supported)", reply[1])
	}
	conn.SetReadDeadline(time.Now().Add(time.Second))
	if _, err := conn.Read(make([]byte, 1)); err == nil {
		t.Fatal("expected connection close after failure reply (RFC 1928 §6)")
	}
}

// ── RFC 1928 §5 — DOMAINNAME addressing ─────────────────────────────────────

// TestConnect_DomainName verifies that the server handles ATYP=0x03 (domain
// name) by resolving the name server-side and establishing the connection.
// This exercises the DialFunc DNS path end-to-end.
func TestConnect_DomainName(t *testing.T) {
	echo := startEchoServer(t)
	defer echo.Close()
	proxyAddr, cancel := startProxy(t, Config{})
	defer cancel()

	// "localhost" is the canonical loopback name; port comes from the echo server.
	_, portStr, _ := net.SplitHostPort(echo.Addr().String())
	conn := dialThroughProxy(t, proxyAddr, nil, "localhost:"+portStr)

	conn.Write([]byte("domain-name-test"))
	buf := make([]byte, 64)
	n, err := conn.Read(buf)
	if err != nil {
		t.Fatal(err)
	}
	if string(buf[:n]) != "domain-name-test" {
		t.Fatalf("got %q, want %q", buf[:n], "domain-name-test")
	}
}

// TestRequest_WrongVersion verifies that a wrong VER byte in the request
// (after successful auth) causes the server to close without sending a reply.
// RFC 1928 §4 requires VER=0x05; no specific reply code is defined for this
// violation, so the server closes cleanly.
func TestRequest_WrongVersion(t *testing.T) {
	proxyAddr, cancel := startProxy(t, Config{})
	defer cancel()

	conn, err := net.DialTimeout("tcp", proxyAddr, 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	// Successful NoAuth greeting.
	conn.Write([]byte{version5, 0x01, methodNoAuth})
	io.ReadFull(conn, make([]byte, 2))

	// Request with VER=0x04 (wrong version).
	conn.Write([]byte{0x04, byte(CommandConnect), 0x00, addrTypeIPv4, 127, 0, 0, 1, 0x00, 0x50})

	// Server sends no reply for wrong VER in the request phase; it just closes.
	conn.SetReadDeadline(time.Now().Add(time.Second))
	if _, err := conn.Read(make([]byte, 1)); err == nil {
		t.Fatal("expected connection to be closed after wrong VER in request")
	}
}

// TestConnect_BNDAddrPort verifies RFC 1928 §6: "In the reply to a CONNECT,
// BND.PORT contains the port number that the server assigned to connect to
// the target host, while BND.ADDR contains the associated IP address."
// proxy.SOCKS5 reads and discards BND.ADDR/PORT, so this test inspects the
// raw reply bytes directly.
func TestConnect_BNDAddrPort(t *testing.T) {
	echo := startEchoServer(t)
	defer echo.Close()
	proxyAddr, cancel := startProxy(t, Config{})
	defer cancel()

	conn, err := net.DialTimeout("tcp", proxyAddr, 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(5 * time.Second))

	// NoAuth greeting.
	conn.Write([]byte{version5, 0x01, methodNoAuth})
	io.ReadFull(conn, make([]byte, 2))

	// CONNECT to echo server.
	echoTCP := echo.Addr().(*net.TCPAddr)
	req := append([]byte{version5, byte(CommandConnect), 0x00, addrTypeIPv4}, echoTCP.IP.To4()...)
	req = binary.BigEndian.AppendUint16(req, uint16(echoTCP.Port))
	conn.Write(req)

	// Read reply header: VER | REP | RSV | ATYP.
	hdr := make([]byte, 4)
	if _, err := io.ReadFull(conn, hdr); err != nil {
		t.Fatal(err)
	}
	if hdr[1] != replySuccess {
		t.Fatalf("REP = %#x, want 0x00 (success)", hdr[1])
	}

	// Read and validate BND.ADDR and BND.PORT.
	var bndIP net.IP
	var bndPort uint16
	switch hdr[3] {
	case addrTypeIPv4:
		b := make([]byte, 6)
		io.ReadFull(conn, b)
		bndIP, bndPort = net.IP(b[:4]), binary.BigEndian.Uint16(b[4:6])
	case addrTypeIPv6:
		b := make([]byte, 18)
		io.ReadFull(conn, b)
		bndIP, bndPort = net.IP(b[:16]), binary.BigEndian.Uint16(b[16:18])
	default:
		t.Fatalf("unexpected ATYP in reply: %#x", hdr[3])
	}

	if bndPort == 0 {
		t.Error("BND.PORT is 0: RFC 1928 §6 requires the actual assigned port")
	}
	if bndIP.IsUnspecified() {
		t.Error("BND.ADDR is all-zeros: RFC 1928 §6 requires the actual bound address")
	}
}

// ── RuleSet integration tests ────────────────────────────────────────────────

// TestRuleSet_DenyAll verifies the exact reply code (0x02) when the RuleSet
// denies a request.
func TestRuleSet_DenyAll(t *testing.T) {
	proxyAddr, cancel := startProxy(t, Config{Rules: PermitCommand{}})
	defer cancel()

	conn, err := net.DialTimeout("tcp", proxyAddr, 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	conn.Write([]byte{version5, 0x01, methodNoAuth})
	io.ReadFull(conn, make([]byte, 2))

	conn.Write([]byte{version5, byte(CommandConnect), 0x00, addrTypeIPv4, 127, 0, 0, 1, 0x00, 0x50})

	reply := make([]byte, 10)
	io.ReadFull(conn, reply)
	if reply[1] != replyNotAllowed {
		t.Fatalf("REP = %#x, want %#x (not allowed)", reply[1], replyNotAllowed)
	}
	conn.SetReadDeadline(time.Now().Add(time.Second))
	if _, err := conn.Read(make([]byte, 1)); err == nil {
		t.Fatal("expected connection close after failure reply (RFC 1928 §6)")
	}
}

func TestRuleSet_AuthInfoAvailable(t *testing.T) {
	echo := startEchoServer(t)
	defer echo.Close()

	var gotAuth AuthInfo
	rules := ruleSetFunc(func(_ context.Context, req Request) bool {
		gotAuth = req.Auth
		return true
	})

	creds := StaticCredentials{Username: "user", Password: "pass"}
	proxyAddr, cancel := startProxy(t, Config{
		Authenticators: []Authenticator{UserPassAuthenticator{Credentials: creds}},
		Rules:          rules,
	})
	defer cancel()

	conn := dialThroughProxy(t, proxyAddr,
		&proxy.Auth{User: "user", Password: "pass"},
		echo.Addr().String())
	conn.Close()
	time.Sleep(50 * time.Millisecond)

	info, ok := gotAuth.(UserPassInfo)
	if !ok {
		t.Fatalf("Auth is %T, want UserPassInfo", gotAuth)
	}
	if info.Username != "user" {
		t.Fatalf("Username = %q, want %q", info.Username, "user")
	}
}

// ── TrustedIPs tests ─────────────────────────────────────────────────────────

func TestTrustedIPs_BypassAuth(t *testing.T) {
	echo := startEchoServer(t)
	defer echo.Close()

	creds := StaticCredentials{Username: "user", Password: "pass"}
	proxyAddr, cancel := startProxy(t, Config{
		Authenticators: []Authenticator{UserPassAuthenticator{Credentials: creds}},
		TrustedIPs:     []netip.Addr{netip.MustParseAddr("127.0.0.1")},
	})
	defer cancel()

	// Connect without credentials — 127.0.0.1 is trusted, so NoAuth must succeed.
	conn := dialThroughProxy(t, proxyAddr, nil, echo.Addr().String())

	conn.Write([]byte("trusted"))
	buf := make([]byte, 64)
	n, _ := conn.Read(buf)
	if string(buf[:n]) != "trusted" {
		t.Fatalf("got %q", buf[:n])
	}
}

// TestTrustedIPs_UnknownIPRequiresAuth verifies that a non-trusted IP is
// rejected at method negotiation when it offers only NoAuth.
func TestTrustedIPs_UnknownIPRequiresAuth(t *testing.T) {
	creds := StaticCredentials{Username: "user", Password: "pass"}
	// Trust only 10.0.0.1; the test client arrives from 127.0.0.1.
	proxyAddr, cancel := startProxy(t, Config{
		Authenticators: []Authenticator{UserPassAuthenticator{Credentials: creds}},
		TrustedIPs:     []netip.Addr{netip.MustParseAddr("10.0.0.1")},
	})
	defer cancel()

	conn, err := net.DialTimeout("tcp", proxyAddr, 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	conn.Write([]byte{version5, 0x01, methodNoAuth})
	resp := make([]byte, 2)
	io.ReadFull(conn, resp)
	if resp[1] != methodNoAcceptable {
		t.Fatalf("METHOD = %#x, want 0xFF (no acceptable)", resp[1])
	}
}

// ── AuthOnce tests ───────────────────────────────────────────────────────────

func TestAuthOnce_SecondConnectionSkipsAuth(t *testing.T) {
	echo := startEchoServer(t)
	defer echo.Close()

	creds := StaticCredentials{Username: "user", Password: "pass"}
	proxyAddr, cancel := startProxy(t, Config{
		Authenticators: []Authenticator{UserPassAuthenticator{Credentials: creds}},
		AuthOnce:       true,
	})
	defer cancel()

	// First connection: authenticate with credentials.
	conn1 := dialThroughProxy(t, proxyAddr,
		&proxy.Auth{User: "user", Password: "pass"},
		echo.Addr().String())
	conn1.Write([]byte("first"))
	io.ReadAll(io.LimitReader(conn1, 5))
	conn1.Close()

	time.Sleep(50 * time.Millisecond)

	// Second connection: IP is now trusted — no credentials required.
	conn2 := dialThroughProxy(t, proxyAddr, nil, echo.Addr().String())

	conn2.Write([]byte("second"))
	buf := make([]byte, 64)
	n, err := conn2.Read(buf)
	if err != nil {
		t.Fatal(err)
	}
	if string(buf[:n]) != "second" {
		t.Fatalf("got %q, want %q", buf[:n], "second")
	}
}
