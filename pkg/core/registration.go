// Copyright 2026 TAJMAC Group (GoHaSeMo)
// SPDX-License-Identifier: Apache-2.0

// Client-side registration (EPIC-21, ADR-008).
//
// A GoHaSeMo client registers with a Node to establish its own per-client
// Key-Encryption Key (KEK). The client encapsulates to the Node's ML-KEM-768
// public key and derives the KEK; the Node decapsulates and derives the same
// KEK independently (it then keeps only an HMAC fingerprint, never the raw KEK).
//
// TOFU IS FORBIDDEN (ADR-008 invariant 9). A client must authenticate the
// Node's encapsulation key against an out-of-band fingerprint BEFORE
// encapsulating — otherwise a man-in-the-middle could substitute its own key and
// learn the KEK. This package makes that structural: the only way to obtain a
// NodeIdentity is PinNodeIdentity, which verifies the fingerprint. There is no
// constructor that trusts a key on first sight.
//
// This file is part of the Apache-2.0-licensed Core SDK and depends only on the
// Go standard library (crypto/mlkem, crypto/hkdf) — never on the server-side
// internal packages (ADR-008 import isolation). The derivation constants below
// MUST match the Node's; a cross-agreement test in internal/node pins parity so
// the two sides can never silently diverge.

package core

import (
	"crypto/hkdf"
	"crypto/mlkem"
	"crypto/sha512"
	"crypto/subtle"
	"errors"
	"fmt"
)

const (
	// EncapsulationKeySize is the byte length of an ML-KEM-768 encapsulation
	// (public) key per FIPS 203.
	EncapsulationKeySize = 1184

	// EncapsulationKeySize1024 is the byte length of an ML-KEM-1024 encapsulation
	// key (CNSA 2.0 confidentiality profile).
	EncapsulationKeySize1024 = 1568

	// NodeKeyFingerprintSize is the byte length of a Node key fingerprint
	// (SHA-384 digest).
	NodeKeyFingerprintSize = 48

	// clientKEKDomain is the HKDF-SHA384 info-string prefix for per-client KEK
	// derivation. The client_id is appended. This MUST match the Node's
	// regKEKDomainPrefix (internal/node/registration.go).
	clientKEKDomain = "GoHaSeMo/registration/v1/client-kek/"

	// clientKEKLen is the derived KEK length (32 bytes → AES-256). MUST match
	// the Node's HKDFOutputSize.
	clientKEKLen = 32
)

// NodeKeyFingerprint returns the SHA-384 fingerprint of a Node encapsulation
// key. Operators publish this out-of-band (e.g. in provisioning material);
// clients pass it to PinNodeIdentity to authenticate the Node before
// registering.
func NodeKeyFingerprint(encapKey []byte) [NodeKeyFingerprintSize]byte {
	return sha512.Sum384(encapKey)
}

// NodeIdentity is an authenticated, pinned GoHaSeMo Node encapsulation key.
// It can only be constructed via PinNodeIdentity, which verifies the key against
// an out-of-band fingerprint — so trust-on-first-use is impossible by design.
type NodeIdentity struct {
	ek768  *mlkem.EncapsulationKey768
	ek1024 *mlkem.EncapsulationKey1024 // set instead of ek768 for the CNSA profile
}

// PinNodeIdentity verifies that encapKey matches the expected out-of-band
// SHA-384 fingerprint (constant-time), then parses it. It returns an error if
// the fingerprint does not match (possible MITM / wrong Node) or the key is
// malformed. TOFU is forbidden: there is intentionally no variant that skips
// the fingerprint check.
func PinNodeIdentity(encapKey []byte, expectedFingerprint [NodeKeyFingerprintSize]byte) (*NodeIdentity, error) {
	got := sha512.Sum384(encapKey)
	if subtle.ConstantTimeCompare(got[:], expectedFingerprint[:]) != 1 {
		return nil, errors.New("core: node key fingerprint mismatch — refusing to register (possible MITM)")
	}
	// Auto-detect the ML-KEM variant by encapsulation-key length (768 vs 1024).
	switch len(encapKey) {
	case EncapsulationKeySize:
		ek, err := mlkem.NewEncapsulationKey768(encapKey)
		if err != nil {
			return nil, fmt.Errorf("core: parse node encapsulation key: %w", err)
		}
		return &NodeIdentity{ek768: ek}, nil
	case EncapsulationKeySize1024:
		ek, err := mlkem.NewEncapsulationKey1024(encapKey)
		if err != nil {
			return nil, fmt.Errorf("core: parse node encapsulation key: %w", err)
		}
		return &NodeIdentity{ek1024: ek}, nil
	default:
		return nil, fmt.Errorf("core: unexpected encapsulation-key length %d (want %d or %d)",
			len(encapKey), EncapsulationKeySize, EncapsulationKeySize1024)
	}
}

// EstablishKEK performs the client side of the registration handshake:
// encapsulate to the pinned Node key and derive the per-client KEK. It returns
//
//   - kek:        the per-client KEK, wrapped in SecureBytes. The client keeps
//     this to protect its data; the caller MUST Destroy it when done.
//   - ciphertext: the ML-KEM-768 ciphertext to POST to the Node's /v1/register
//     endpoint, from which the Node derives the identical KEK.
//
// The ML-KEM shared secret is zeroed before return; only the derived KEK leaves
// this function.
func (n *NodeIdentity) EstablishKEK(clientID string) (kek *SecureBytes, ciphertext []byte, err error) {
	if clientID == "" {
		return nil, nil, errors.New("core: clientID must not be empty")
	}
	var shared, ct []byte
	if n.ek1024 != nil {
		shared, ct = n.ek1024.Encapsulate()
	} else {
		shared, ct = n.ek768.Encapsulate()
	}
	defer secureZero(shared)

	raw, err := hkdf.Key(sha512.New384, shared, nil, clientKEKDomain+clientID, clientKEKLen)
	if err != nil {
		return nil, nil, fmt.Errorf("core: derive client KEK: %w", err)
	}
	defer secureZero(raw)

	return SecureBytesFrom(raw), ct, nil
}
