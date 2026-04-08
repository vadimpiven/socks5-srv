// SPDX-License-Identifier: Apache-2.0 OR MIT

// auth.go contains the authentication interfaces and their implementations.
//
// The two-level abstraction mirrors the SOCKS5 wire protocol:
//   - [Authenticator] handles one method (the method code + sub-negotiation).
//   - [CredentialStore] handles credential validation inside [UserPassAuthenticator].
//
// Adding a new auth method requires only implementing [Authenticator].
package socks5

import (
	"crypto/sha256"
	"crypto/subtle"
	"errors"
	"fmt"
	"io"
	"net"
)

// ── AuthInfo ─────────────────────────────────────────────────────────────────

// AuthInfo carries identity metadata from a completed authentication
// sub-negotiation into the request pipeline. The concrete type is
// method-specific; rule sets may type-assert to inspect it.
type AuthInfo interface {
	// Method returns the SOCKS5 method byte that produced this info.
	Method() byte
}

// NoAuthInfo is the AuthInfo produced by [NoAuthAuthenticator].
type NoAuthInfo struct{}

func (NoAuthInfo) Method() byte { return methodNoAuth }

// UserPassInfo is the AuthInfo produced by [UserPassAuthenticator] on success.
// Username is available to [RuleSet] implementations.
type UserPassInfo struct{ Username string }

func (UserPassInfo) Method() byte { return methodUserPass }

// ── Authenticator interface ───────────────────────────────────────────────────

// Authenticator handles a single SOCKS5 authentication method.
//
// The server calls [Authenticator.Authenticate] only AFTER it has already
// written the method-selection response byte to the client, so implementations
// should only perform the method-specific sub-negotiation.
type Authenticator interface {
	// Code returns the SOCKS5 method byte this authenticator handles.
	Code() byte
	// Authenticate performs the method-specific sub-negotiation on conn.
	// Returns [AuthInfo] on success, or an error that causes the server to
	// close the connection.
	Authenticate(conn net.Conn) (AuthInfo, error)
}

// ── NoAuthAuthenticator ───────────────────────────────────────────────────────

// NoAuthAuthenticator implements SOCKS5 method 0x00 (no authentication).
// The sub-negotiation is empty; Authenticate returns immediately.
type NoAuthAuthenticator struct{}

func (NoAuthAuthenticator) Code() byte { return methodNoAuth }

func (NoAuthAuthenticator) Authenticate(_ net.Conn) (AuthInfo, error) {
	return NoAuthInfo{}, nil
}

// ── UserPassAuthenticator ─────────────────────────────────────────────────────

// UserPassAuthenticator implements RFC 1929 username/password authentication
// (SOCKS5 method 0x02).
type UserPassAuthenticator struct {
	// Credentials is the store consulted to validate username/password pairs.
	// It must not be nil.
	Credentials CredentialStore
}

func (a UserPassAuthenticator) Code() byte { return methodUserPass }

// Authenticate performs the RFC 1929 sub-negotiation, validates credentials
// against a.Credentials, and returns [UserPassInfo] on success.
//
// Wire format — request:  VER(1) | ULEN(1) | UNAME(1-255) | PLEN(1) | PASSWD(1-255)
// Wire format — response: VER(1) | STATUS(1)
func (a UserPassAuthenticator) Authenticate(conn net.Conn) (AuthInfo, error) {
	username, err := doUserPassAuth(conn, a.Credentials)
	if err != nil {
		return nil, err
	}
	return UserPassInfo{Username: username}, nil
}

// doUserPassAuth is the stateless RFC 1929 wire implementation shared by
// UserPassAuthenticator. It returns the authenticated username on success.
func doUserPassAuth(rw io.ReadWriter, store CredentialStore) (string, error) {
	var header [2]byte
	if _, err := io.ReadFull(rw, header[:]); err != nil {
		return "", fmt.Errorf("read auth header: %w", err)
	}
	if header[0] != authSubVersion {
		return "", fmt.Errorf("unsupported auth sub-version: %#x (want %#x)", header[0], authSubVersion)
	}
	if header[1] == 0 {
		// Best-effort: the error return signals failure to the caller.
		_, _ = rw.Write([]byte{authSubVersion, authFailure})
		return "", errors.New("ULEN is 0: username must be 1-255 bytes (RFC 1929 §2)")
	}

	username := make([]byte, header[1])
	if _, err := io.ReadFull(rw, username); err != nil {
		return "", fmt.Errorf("read username: %w", err)
	}

	var plen [1]byte
	if _, err := io.ReadFull(rw, plen[:]); err != nil {
		return "", fmt.Errorf("read password length: %w", err)
	}
	if plen[0] == 0 {
		_, _ = rw.Write([]byte{authSubVersion, authFailure})
		return "", errors.New("PLEN is 0: password must be 1-255 bytes (RFC 1929 §2)")
	}

	password := make([]byte, plen[0])
	if _, err := io.ReadFull(rw, password); err != nil {
		return "", fmt.Errorf("read password: %w", err)
	}

	status := authSuccess
	if !store.Valid(string(username), string(password)) {
		status = authFailure
	}
	if _, err := rw.Write([]byte{authSubVersion, status}); err != nil {
		return "", fmt.Errorf("write auth response: %w", err)
	}
	if status != authSuccess {
		return "", errors.New("authentication failed")
	}
	return string(username), nil
}

// ── CredentialStore ───────────────────────────────────────────────────────────

// CredentialStore validates username/password pairs.
// Implementations should use constant-time comparison to prevent timing attacks.
type CredentialStore interface {
	Valid(username, password string) bool
}

// StaticCredentials is a single-pair credential store. Both comparisons are
// constant-time (SHA-256 normalised) to resist timing side-channels.
type StaticCredentials struct {
	Username, Password string
}

func (s StaticCredentials) Valid(username, password string) bool {
	return constantTimeEqual([]byte(username), []byte(s.Username)) &&
		constantTimeEqual([]byte(password), []byte(s.Password))
}

// MapCredentials is a multi-user credential store backed by a map of
// username → password. The map lookup is not constant-time (the map
// reveals whether the username exists via timing), but password comparison
// is. Suitable when the username list is not sensitive.
type MapCredentials map[string]string

func (m MapCredentials) Valid(username, password string) bool {
	stored, ok := m[username]
	if !ok {
		// Run a dummy comparison to avoid a trivial timing oracle on usernames.
		constantTimeEqual([]byte(password), nil)
		return false
	}
	return constantTimeEqual([]byte(password), []byte(stored))
}

// constantTimeEqual compares two byte slices in constant time regardless
// of length. subtle.ConstantTimeCompare returns 0 immediately when lengths
// differ, leaking length information via timing; hashing to fixed-size
// 32-byte arrays first eliminates that.
func constantTimeEqual(a, b []byte) bool {
	ha := sha256.Sum256(a)
	hb := sha256.Sum256(b)
	return subtle.ConstantTimeCompare(ha[:], hb[:]) == 1
}
