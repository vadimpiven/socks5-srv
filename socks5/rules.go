// SPDX-License-Identifier: Apache-2.0 OR MIT

// rules.go defines the RuleSet interface and the Request type it operates on,
// together with the two built-in implementations: [PermitAll] and [PermitCommand].
package socks5

import (
	"context"
	"net/netip"
)

// Request holds the information about an incoming SOCKS5 request, made
// available to a [RuleSet] before any outbound connection is established.
type Request struct {
	// Command is the SOCKS5 command ([CommandConnect] or [CommandUDPAssociate]).
	Command Command
	// ClientAddr is the client's TCP source address (IP already Unmap'd).
	ClientAddr netip.AddrPort
	// Dest is the destination address parsed from the request. It may contain
	// either a literal IP or a domain name; the IP is not yet resolved for
	// domain destinations at the time Allow is called.
	Dest AddrSpec
	// Auth carries identity metadata from the completed auth phase.
	// Type-assert to [NoAuthInfo] or [UserPassInfo] for method-specific data.
	Auth AuthInfo
}

// RuleSet gates incoming SOCKS5 requests before any outbound connection is
// attempted. Returning false causes the server to send replyNotAllowed (0x02)
// and close the connection cleanly.
//
// Allow receives a copy of Request; modifying it has no effect on the server.
// The context is derived from context.Background(); implementations may use it
// for deadline-bounded lookups.
type RuleSet interface {
	Allow(ctx context.Context, req Request) bool
}

// PermitAll is a [RuleSet] that allows every request unconditionally.
// It is the default when no RuleSet is provided to [NewServer].
type PermitAll struct{}

func (PermitAll) Allow(_ context.Context, _ Request) bool { return true }

// PermitCommand is a [RuleSet] that selectively enables SOCKS5 commands.
// Commands not explicitly enabled are rejected.
type PermitCommand struct {
	// EnableConnect permits CONNECT (TCP tunnel) requests.
	EnableConnect bool
	// EnableUDPAssociate permits UDP ASSOCIATE requests.
	EnableUDPAssociate bool
}

func (p PermitCommand) Allow(_ context.Context, req Request) bool {
	switch req.Command {
	case CommandConnect:
		return p.EnableConnect
	case CommandUDPAssociate:
		return p.EnableUDPAssociate
	default:
		return false
	}
}
