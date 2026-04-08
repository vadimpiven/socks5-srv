// SPDX-License-Identifier: Apache-2.0 OR MIT

package socks5

import (
	"context"
	"testing"
)

func TestDefaultResolver_Localhost(t *testing.T) {
	r := DefaultResolver{}
	addr, err := r.Resolve(context.Background(), "localhost")
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if !addr.IsLoopback() {
		t.Fatalf("expected loopback address, got %v", addr)
	}
	if !addr.IsValid() {
		t.Fatal("expected a valid address")
	}
}

func TestDefaultResolver_InvalidHost(t *testing.T) {
	r := DefaultResolver{}
	_, err := r.Resolve(context.Background(), "this.host.does.not.exist.invalid.")
	if err == nil {
		t.Fatal("expected error for non-existent host")
	}
}
