// Copyright 2026 TAJMAC Group (GoHaSeMo)
// SPDX-License-Identifier: Apache-2.0

package core

import (
	"fmt"
	"strings"
	"testing"
	"unsafe"
)

// TestSecureBytes_DestroyZeroesBackingArray verifies that Destroy actually
// zeroes the backing array — inspected through a raw pointer captured BEFORE
// Destroy, so the assertion reads the same memory, not a fresh allocation.
func TestSecureBytes_DestroyZeroesBackingArray(t *testing.T) {
	const n = 32
	s := NewSecureBytes(n)
	b := s.Bytes()
	for i := range b {
		b[i] = 0xAA
	}
	ptr := unsafe.SliceData(b) // *byte to the backing array

	s.Destroy()

	view := unsafe.Slice(ptr, n)
	for i, v := range view {
		if v != 0 {
			t.Fatalf("backing array byte %d = %#x, want 0 after Destroy", i, v)
		}
	}
	if s.Bytes() != nil {
		t.Fatal("Bytes() should be nil after Destroy")
	}
	if s.Len() != 0 {
		t.Fatalf("Len() = %d, want 0 after Destroy", s.Len())
	}
}

// TestSecureBytes_Redaction ensures the secret never leaks through fmt, for
// both value and pointer, across %v / %s / %#v.
func TestSecureBytes_Redaction(t *testing.T) {
	const secret = "super-secret-master-key"
	s := SecureBytesFrom([]byte(secret))
	defer s.Destroy()

	// %s and %v route through the same Stringer for these types, so %v covers
	// both (staticcheck S1025 flags the redundant %s form).
	cases := []string{
		fmt.Sprintf("%v", s),   // *SecureBytes
		fmt.Sprintf("%v", *s),  // value
		fmt.Sprintf("%#v", s),  // *SecureBytes GoString
		fmt.Sprintf("%#v", *s), // value GoString
	}
	for _, got := range cases {
		if strings.Contains(got, "secret") || strings.Contains(got, secret) {
			t.Fatalf("secret leaked through fmt: %q", got)
		}
		if !strings.Contains(got, "REDACTED") {
			t.Fatalf("expected redaction marker, got %q", got)
		}
	}
	if got := fmt.Sprintf("%v", *s); got != "[REDACTED]" {
		t.Fatalf("value %%v = %q, want [REDACTED]", got)
	}
}

// TestSecureBytes_DestroyIdempotentAndZeroValueSafe verifies Destroy never
// panics on nil, zero-value, or repeated calls.
func TestSecureBytes_DestroyIdempotentAndZeroValueSafe(t *testing.T) {
	var nilPtr *SecureBytes
	nilPtr.Destroy() // nil receiver, must not panic

	var zero SecureBytes
	zero.Destroy() // zero value, must not panic

	(&SecureBytes{}).Destroy() // empty literal, must not panic

	s := NewSecureBytes(16)
	s.Destroy()
	s.Destroy() // double destroy, must not panic
}

// TestSecureBytesFrom_CopiesAndIsIndependent verifies the constructor copies
// src (so later mutation of src does not affect the secret) and round-trips.
func TestSecureBytesFrom_CopiesAndIsIndependent(t *testing.T) {
	src := []byte{1, 2, 3, 4}
	s := SecureBytesFrom(src)
	defer s.Destroy()

	src[0] = 0xFF // mutate caller's slice
	if s.Bytes()[0] != 1 {
		t.Fatal("SecureBytesFrom did not copy src — secret aliases caller memory")
	}
	if s.Len() != 4 {
		t.Fatalf("Len() = %d, want 4", s.Len())
	}
}
