// SPDX-License-Identifier: Apache-2.0 OR MIT

package socks5

import (
	"io"
	"net"
	"testing"
	"time"
)

// pipeWithDeadline creates a net.Pipe with a test-scoped deadline so tests
// fail fast instead of hanging on deadlocks.
func pipeWithDeadline(t *testing.T) (client, server net.Conn) {
	t.Helper()
	c, s := net.Pipe()
	dl := time.Now().Add(5 * time.Second)
	c.SetDeadline(dl)
	s.SetDeadline(dl)
	t.Cleanup(func() { c.Close(); s.Close() })
	return c, s
}

// ── UserPassAuthenticator — RFC 1929 §2 edge cases ──────────────────────────
//
// The happy paths (correct credentials → success, wrong password → failure)
// are covered end-to-end by TestFullSession_UserPass_Connect and
// TestFullSession_AuthFailure in server_test.go.
// The tests below cover RFC 1929 §2 wire constraints that are deliberately
// violated by a malformed client and cannot be exercised through proxy.SOCKS5.

// TestUserPassAuth_BadSubVersion verifies that the server rejects an auth
// sub-negotiation whose VER field is not 0x01 (RFC 1929 §2).
func TestUserPassAuth_BadSubVersion(t *testing.T) {
	client, server := pipeWithDeadline(t)
	a := UserPassAuthenticator{Credentials: StaticCredentials{Username: "u", Password: "p"}}

	errc := make(chan error, 1)
	go func() {
		_, err := a.Authenticate(server)
		errc <- err
	}()

	// Sub-version 0x02 instead of 0x01 — server reads 2 bytes then rejects.
	go client.Write([]byte{0x02, 0x01, 'u', 0x01, 'p'})

	if err := <-errc; err == nil {
		t.Fatal("expected error for bad sub-negotiation version")
	}
}

// TestUserPassAuth_ZeroLengthUsername verifies that the server rejects a
// username length of 0 with STATUS=0x01 (RFC 1929 §2: ULEN is "1 to 255").
func TestUserPassAuth_ZeroLengthUsername(t *testing.T) {
	client, server := pipeWithDeadline(t)
	a := UserPassAuthenticator{Credentials: StaticCredentials{Username: "u", Password: "p"}}

	errc := make(chan error, 1)
	go func() {
		_, err := a.Authenticate(server)
		errc <- err
	}()

	// ULEN=0 — server reads 2 bytes, sends failure, then rejects.
	go client.Write([]byte{authSubVersion, 0x00, 0x01, 'p'})

	resp := make([]byte, 2)
	io.ReadFull(client, resp)
	if resp[1] != authFailure {
		t.Fatalf("STATUS = %#x, want 0x01 (failure) for ULEN=0", resp[1])
	}
	if err := <-errc; err == nil {
		t.Fatal("expected error for ULEN=0")
	}
}

// TestUserPassAuth_ZeroLengthPassword verifies that the server rejects a
// password length of 0 with STATUS=0x01 (RFC 1929 §2: PLEN is "1 to 255").
func TestUserPassAuth_ZeroLengthPassword(t *testing.T) {
	client, server := pipeWithDeadline(t)
	a := UserPassAuthenticator{Credentials: StaticCredentials{Username: "u", Password: "p"}}

	errc := make(chan error, 1)
	go func() {
		_, err := a.Authenticate(server)
		errc <- err
	}()

	// PLEN=0 — server reads VER+ULEN+UNAME+PLEN, sends failure, then rejects.
	go client.Write([]byte{authSubVersion, 0x01, 'u', 0x00})

	resp := make([]byte, 2)
	io.ReadFull(client, resp)
	if resp[1] != authFailure {
		t.Fatalf("STATUS = %#x, want 0x01 (failure) for PLEN=0", resp[1])
	}
	if err := <-errc; err == nil {
		t.Fatal("expected error for PLEN=0")
	}
}

// ── CredentialStore implementations ─────────────────────────────────────────

func TestStaticCredentials(t *testing.T) {
	s := StaticCredentials{Username: "alice", Password: "secret"}
	if !s.Valid("alice", "secret") {
		t.Error("expected valid for correct credentials")
	}
	if s.Valid("alice", "wrong") {
		t.Error("expected invalid for wrong password")
	}
	if s.Valid("bob", "secret") {
		t.Error("expected invalid for wrong username")
	}
}

func TestMapCredentials(t *testing.T) {
	m := MapCredentials{"alice": "secret", "bob": "pass"}
	if !m.Valid("alice", "secret") {
		t.Error("expected valid")
	}
	if m.Valid("alice", "wrong") {
		t.Error("expected invalid for wrong password")
	}
	if m.Valid("unknown", "anything") {
		t.Error("expected invalid for missing user")
	}
}
