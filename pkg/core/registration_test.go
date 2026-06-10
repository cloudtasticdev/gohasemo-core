// Copyright 2026 TAJMAC Group (GoHaSeMo)
// SPDX-License-Identifier: Apache-2.0

package core

import (
	"bytes"
	"crypto/hkdf"
	"crypto/mlkem"
	"crypto/sha512"
	"testing"
)

// deriveTestClientKEK mirrors EstablishKEK's HKDF step on the Node side, using
// only the same public derivation, to assert both sides agree.
func deriveTestClientKEK(t *testing.T, shared []byte, clientID string) []byte {
	t.Helper()
	k, err := hkdf.Key(sha512.New384, shared, nil, clientKEKDomain+clientID, clientKEKLen)
	if err != nil {
		t.Fatalf("hkdf: %v", err)
	}
	return k
}

// newTestNodeKey returns a fresh ML-KEM-768 encapsulation key (raw bytes) and
// the decapsulation key, standing in for a Node's published identity.
func newTestNodeKey(t *testing.T) (encapKey []byte, dk *mlkem.DecapsulationKey768) {
	t.Helper()
	dk, err := mlkem.GenerateKey768()
	if err != nil {
		t.Fatalf("GenerateKey768: %v", err)
	}
	return dk.EncapsulationKey().Bytes(), dk
}

func TestPinNodeIdentity_RejectsFingerprintMismatch(t *testing.T) {
	encapKey, _ := newTestNodeKey(t)
	good := NodeKeyFingerprint(encapKey)

	// Correct fingerprint pins successfully.
	if _, err := PinNodeIdentity(encapKey, good); err != nil {
		t.Fatalf("PinNodeIdentity with correct fingerprint: %v", err)
	}

	// A single flipped bit in the expected fingerprint must be rejected (no TOFU,
	// no silent acceptance).
	bad := good
	bad[0] ^= 0x01
	if _, err := PinNodeIdentity(encapKey, bad); err == nil {
		t.Fatal("PinNodeIdentity accepted a mismatched fingerprint — TOFU/MITM not prevented")
	}
}

func TestPinNodeIdentity_RejectsMalformedKey(t *testing.T) {
	junk := make([]byte, 10)
	fp := NodeKeyFingerprint(junk) // fingerprint matches the junk, isolating the parse failure
	if _, err := PinNodeIdentity(junk, fp); err == nil {
		t.Fatal("PinNodeIdentity accepted a malformed encapsulation key")
	}
}

func TestEstablishKEK_DeterministicLengthAndDestroy(t *testing.T) {
	encapKey, _ := newTestNodeKey(t)
	node, err := PinNodeIdentity(encapKey, NodeKeyFingerprint(encapKey))
	if err != nil {
		t.Fatalf("PinNodeIdentity: %v", err)
	}

	kek, ct, err := node.EstablishKEK("client-x")
	if err != nil {
		t.Fatalf("EstablishKEK: %v", err)
	}
	if kek.Len() != clientKEKLen {
		t.Fatalf("KEK length = %d, want %d", kek.Len(), clientKEKLen)
	}
	if len(ct) != mlkem.CiphertextSize768 {
		t.Fatalf("ciphertext length = %d, want %d", len(ct), mlkem.CiphertextSize768)
	}
	// The KEK must not equal the raw ciphertext (sanity: derivation happened).
	if bytes.Equal(kek.Bytes(), ct[:kek.Len()]) {
		t.Fatal("KEK looks like raw ciphertext bytes")
	}
	kek.Destroy()
	if kek.Len() != 0 {
		t.Fatal("KEK not destroyed")
	}

	if _, _, err := node.EstablishKEK(""); err == nil {
		t.Error("empty clientID should error")
	}
}

// TestEstablishKEK_NodeCanDeriveSameKEK confirms the SDK's client output lets the
// holder of the decapsulation key derive the identical KEK using the same
// public derivation — the round-trip property, verified here without the
// server-side internal package.
func TestEstablishKEK_NodeCanDeriveSameKEK(t *testing.T) {
	encapKey, dk := newTestNodeKey(t)
	node, err := PinNodeIdentity(encapKey, NodeKeyFingerprint(encapKey))
	if err != nil {
		t.Fatalf("PinNodeIdentity: %v", err)
	}

	const clientID = "client-roundtrip"
	kek, ct, err := node.EstablishKEK(clientID)
	if err != nil {
		t.Fatalf("EstablishKEK: %v", err)
	}
	defer kek.Destroy()

	// Node side: decapsulate and derive with the same domain/length.
	shared, err := dk.Decapsulate(ct)
	if err != nil {
		t.Fatalf("Decapsulate: %v", err)
	}
	nodeKEK := deriveTestClientKEK(t, shared, clientID)
	if !bytes.Equal(kek.Bytes(), nodeKEK) {
		t.Fatal("client and node-side derivation disagree")
	}
}
