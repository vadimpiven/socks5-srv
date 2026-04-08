// SPDX-License-Identifier: Apache-2.0 OR MIT

package socks5

import (
	"context"
	"net/netip"
	"testing"
)

// ruleSetFunc adapts a function to the [RuleSet] interface.
// Used by server_test.go to capture [Request] values inside integration tests.
type ruleSetFunc func(context.Context, Request) bool

func (f ruleSetFunc) Allow(ctx context.Context, req Request) bool { return f(ctx, req) }

// TestAddrSpec_String verifies String() for all three address families (IPv4,
// IPv6, domain). The output must be a valid "host:port" argument for net.Dial.
func TestAddrSpec_String(t *testing.T) {
	cases := []struct {
		spec AddrSpec
		want string
	}{
		{AddrSpec{IP: netip.MustParseAddr("1.2.3.4"), Port: 80}, "1.2.3.4:80"},
		{AddrSpec{IP: netip.MustParseAddr("::1"), Port: 443}, "[::1]:443"},
		{AddrSpec{Domain: "example.com", Port: 8080}, "example.com:8080"},
	}
	for _, tc := range cases {
		if got := tc.spec.String(); got != tc.want {
			t.Errorf("AddrSpec(%v).String() = %q, want %q", tc.spec, got, tc.want)
		}
	}
}

// TestAddrSpec_AddrPort verifies that AddrPort() returns the correct
// netip.AddrPort for IP destinations and a zero (invalid) value for domain
// destinations (whose IP is not yet resolved at request time).
func TestAddrSpec_AddrPort(t *testing.T) {
	ip := netip.MustParseAddr("1.2.3.4")
	spec := AddrSpec{IP: ip, Port: 80}
	ap := spec.AddrPort()
	if ap.Addr() != ip {
		t.Errorf("Addr() = %v, want %v", ap.Addr(), ip)
	}
	if ap.Port() != 80 {
		t.Errorf("Port() = %d, want 80", ap.Port())
	}

	// A domain AddrSpec has no IP yet; AddrPort must be invalid.
	domain := AddrSpec{Domain: "example.com", Port: 8080}
	if domain.AddrPort().IsValid() {
		t.Errorf("domain AddrSpec.AddrPort() should be invalid (IP not resolved), got %v",
			domain.AddrPort())
	}
}

// TestPermitAll verifies that [PermitAll] allows every request unconditionally,
// regardless of command or authentication method.
func TestPermitAll(t *testing.T) {
	r := PermitAll{}
	ctx := context.Background()
	cmds := []Command{CommandConnect, CommandUDPAssociate, CommandBind, Command(0xFF)}
	for _, cmd := range cmds {
		req := Request{
			Command:    cmd,
			ClientAddr: netip.MustParseAddrPort("127.0.0.1:1234"),
			Auth:       NoAuthInfo{},
		}
		if !r.Allow(ctx, req) {
			t.Errorf("PermitAll.Allow(%#x) = false, want true", byte(cmd))
		}
	}
}

// TestPermitCommand verifies that [PermitCommand] allows and denies the
// correct command types according to its configuration.
func TestPermitCommand(t *testing.T) {
	r := PermitCommand{EnableConnect: true, EnableUDPAssociate: false}
	ctx := context.Background()
	base := Request{
		ClientAddr: netip.MustParseAddrPort("127.0.0.1:1234"),
		Auth:       NoAuthInfo{},
	}

	cases := []struct {
		cmd  Command
		want bool
		name string
	}{
		{CommandConnect, true, "CONNECT"},
		{CommandUDPAssociate, false, "UDP ASSOCIATE"},
		{CommandBind, false, "BIND"},
		{Command(0xFF), false, "unknown command"},
	}
	for _, tc := range cases {
		req := base
		req.Command = tc.cmd
		if got := r.Allow(ctx, req); got != tc.want {
			t.Errorf("PermitCommand.Allow(%s) = %v, want %v", tc.name, got, tc.want)
		}
	}
}
