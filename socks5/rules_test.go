// SPDX-License-Identifier: Apache-2.0 OR MIT

package socks5

import (
	"context"
	"net/netip"
	"testing"
)

// ruleSetFunc adapts a function to the RuleSet interface.
// Used by server_test.go to capture Request values inside integration tests.
type ruleSetFunc func(context.Context, Request) bool

func (f ruleSetFunc) Allow(ctx context.Context, req Request) bool { return f(ctx, req) }

// TestPermitCommand verifies that PermitCommand allows and denies the correct
// command types according to its configuration.
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
