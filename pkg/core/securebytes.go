// Copyright 2026 TAJMAC Group (GoHaSeMo)
// SPDX-License-Identifier: Apache-2.0

package core

import "runtime"

// SecureBytes holds sensitive byte material — key material, Shamir shares,
// session keys, or plaintext — and provides best-effort zeroing of its backing
// array, plus redaction so a secret can never leak through fmt formatting.
//
// Zeroing is best-effort by necessity: Go is garbage-collected and the runtime
// may have copied the bytes during a stack or heap growth. SecureBytes narrows
// the window a secret lives in memory and removes the most common disclosure
// paths (logging, struct dumps). A finalizer zeroes the buffer as a backstop if
// Destroy is missed, but callers MUST call Destroy explicitly — the finalizer
// is not a substitute and may run arbitrarily late or never.
//
// SecureBytes is not safe for concurrent use; synchronise externally.
//
// String and GoString use value receivers deliberately, so that BOTH a
// SecureBytes value and a *SecureBytes redact under %v / %s / %#v — a
// pointer-only Stringer would let a value copy print its raw bytes.
type SecureBytes struct {
	b []byte
}

// NewSecureBytes returns a SecureBytes with an n-byte zeroed backing array and
// a finalizer that zeroes it as a backstop.
func NewSecureBytes(n int) *SecureBytes {
	s := &SecureBytes{b: make([]byte, n)}
	runtime.SetFinalizer(s, (*SecureBytes).Destroy)
	return s
}

// SecureBytesFrom copies src into a new SecureBytes. The caller remains
// responsible for zeroing src (wrap it in its own SecureBytes if it is itself
// sensitive).
func SecureBytesFrom(src []byte) *SecureBytes {
	s := NewSecureBytes(len(src))
	copy(s.b, src)
	return s
}

// Bytes returns the underlying slice for use in cryptographic operations. The
// slice is valid only until Destroy is called; do not retain it beyond the
// SecureBytes' lifetime. Returns nil after Destroy or on a nil receiver.
func (s *SecureBytes) Bytes() []byte {
	if s == nil {
		return nil
	}
	return s.b
}

// Len reports the secret length: 0 after Destroy or on a nil/zero value.
func (s *SecureBytes) Len() int {
	if s == nil {
		return 0
	}
	return len(s.b)
}

// Destroy zeroes the backing array and drops the reference. It is idempotent
// and safe on a nil or zero-value SecureBytes.
func (s *SecureBytes) Destroy() {
	if s == nil || s.b == nil {
		return
	}
	secureZero(s.b)
	s.b = nil
	runtime.SetFinalizer(s, nil) // nothing left to zero.
}

// Clear is an alias for Destroy.
func (s *SecureBytes) Clear() { s.Destroy() }

// String implements fmt.Stringer and never reveals the secret.
func (s SecureBytes) String() string { return "[REDACTED]" }

// GoString implements fmt.GoStringer so %#v also never reveals the secret.
func (s SecureBytes) GoString() string { return "core.SecureBytes{[REDACTED]}" }

// secureZero overwrites b with zeros. It is //go:noinline and ends with
// runtime.KeepAlive(b) to inhibit dead-store elimination of the clear, which
// the compiler might otherwise remove if it could prove b is never read again.
//
//go:noinline
func secureZero(b []byte) {
	clear(b)
	runtime.KeepAlive(b)
}
