// Copyright 2026 TAJMAC Group (GoHaSeMo)
// SPDX-License-Identifier: Apache-2.0

// ML-DSA-87 client operations (CNSA 2.0 signature half, ADR-007).
//
// These methods require the Node to have been started with an MLDSAFactory
// (see node.ServeOptions.MLDSAFactory). If the Node was started without one,
// calls return a 404 APIError.

package core

import (
	"context"
	"encoding/base64"
	"fmt"
	"net/http"
)

// MLDSAKeyInfo is metadata about a managed ML-DSA-87 signing key.
// PublicKey is the 2592-byte serialised ML-DSA-87 public key, base64-encoded.
// It is populated on GenerateMLDSAKey and DescribeMLDSAKey; absent on ListMLDSAKeys.
type MLDSAKeyInfo struct {
	KeyID     string `json:"key_id"`
	Label     string `json:"label"`
	Algorithm string `json:"algorithm"` // "ML-DSA-87"
	State     string `json:"state"`     // ACTIVE | DEPRECATED | DISABLED | DELETED
	Version   int    `json:"version"`
	PublicKey string `json:"public_key,omitempty"` // base64, 2592 bytes; present on describe
	CreatedAt string `json:"created_at"`
	UpdatedAt string `json:"updated_at"`
}

// MLDSASignResult is the response from a successful SignMLDSA call.
type MLDSASignResult struct {
	// KeyID is the signing key used.
	KeyID string
	// Signature is the raw 4627-byte ML-DSA-87 signature.
	Signature []byte
	// PublicKey is the 2592-byte serialised public key corresponding to KeyID.
	// Callers can distribute this alongside the signature without a separate
	// DescribeMLDSAKey round trip.
	PublicKey []byte
	// Algorithm is always "ML-DSA-87".
	Algorithm string
}

// GenerateMLDSAKey asks the Node to generate a new ML-DSA-87 keypair with the
// given label.  Returns the key ID and the 2592-byte serialised public key.
// The public key can be shared freely; the private seed remains on the Node,
// envelope-encrypted by the master KEK.
func (c *Client) GenerateMLDSAKey(ctx context.Context, label string) (keyID string, publicKey []byte, err error) {
	var resp struct {
		KeyID     string `json:"key_id"`
		PublicKey string `json:"public_key"`
	}
	if err := c.do(ctx, http.MethodPost, "/v1/mldsa/keys",
		map[string]string{"label": label}, &resp); err != nil {
		return "", nil, err
	}
	pub, err := base64.StdEncoding.DecodeString(resp.PublicKey)
	if err != nil {
		return "", nil, fmt.Errorf("core: decode ML-DSA public key: %w", err)
	}
	return resp.KeyID, pub, nil
}

// ListMLDSAKeys returns metadata for all non-deleted ML-DSA-87 keys on the Node.
func (c *Client) ListMLDSAKeys(ctx context.Context) ([]MLDSAKeyInfo, error) {
	var resp struct {
		Keys []MLDSAKeyInfo `json:"keys"`
	}
	if err := c.do(ctx, http.MethodGet, "/v1/mldsa/keys", nil, &resp); err != nil {
		return nil, err
	}
	return resp.Keys, nil
}

// DescribeMLDSAKey returns metadata and the serialised public key for the
// ML-DSA-87 key identified by keyID.
func (c *Client) DescribeMLDSAKey(ctx context.Context, keyID string) (*MLDSAKeyInfo, error) {
	var info MLDSAKeyInfo
	if err := c.do(ctx, http.MethodGet, "/v1/mldsa/keys/"+keyID, nil, &info); err != nil {
		return nil, err
	}
	return &info, nil
}

// SignMLDSA signs message with the ML-DSA-87 key identified by keyID.
// Returns the 4627-byte raw signature and the corresponding 2592-byte public key.
// The message is sent as raw bytes (not encrypted); only the signature and public
// key are returned — the message itself is not stored on the Node.
func (c *Client) SignMLDSA(ctx context.Context, keyID string, message []byte) (*MLDSASignResult, error) {
	var resp struct {
		KeyID     string `json:"key_id"`
		Signature string `json:"signature"`
		PublicKey string `json:"public_key"`
		Algorithm string `json:"algorithm"`
	}
	if err := c.do(ctx, http.MethodPost, "/v1/mldsa/keys/"+keyID+"/sign",
		map[string]string{"message": base64.StdEncoding.EncodeToString(message)},
		&resp); err != nil {
		return nil, err
	}
	sig, err := base64.StdEncoding.DecodeString(resp.Signature)
	if err != nil {
		return nil, fmt.Errorf("core: decode ML-DSA signature: %w", err)
	}
	pub, err := base64.StdEncoding.DecodeString(resp.PublicKey)
	if err != nil {
		return nil, fmt.Errorf("core: decode ML-DSA public key: %w", err)
	}
	return &MLDSASignResult{
		KeyID:     resp.KeyID,
		Signature: sig,
		PublicKey: pub,
		Algorithm: resp.Algorithm,
	}, nil
}

// VerifyMLDSA checks that signature is a valid ML-DSA-87 signature of message
// under publicKey.  This is stateless — no key ID is required; the Node uses
// its configured factory to verify.
//
// publicKey is the 2592-byte serialised public key (from GenerateMLDSAKey or
// SignMLDSA.PublicKey).  message and signature are raw bytes.
//
// Returns nil if the signature is valid; an *APIError with StatusCode 422 if
// the signature is invalid.
func (c *Client) VerifyMLDSA(ctx context.Context, publicKey, message, signature []byte) error {
	return c.do(ctx, http.MethodPost, "/v1/mldsa/verify", map[string]string{
		"public_key": base64.StdEncoding.EncodeToString(publicKey),
		"message":    base64.StdEncoding.EncodeToString(message),
		"signature":  base64.StdEncoding.EncodeToString(signature),
	}, nil)
}

// SetMLDSAKeyState transitions an ML-DSA-87 key to a new lifecycle state.
// Valid states: ACTIVE, DEPRECATED, DISABLED, DELETED.
// DISABLED blocks signing; DELETED is permanent.
func (c *Client) SetMLDSAKeyState(ctx context.Context, keyID, state string) (*MLDSAKeyInfo, error) {
	var info MLDSAKeyInfo
	if err := c.do(ctx, http.MethodPost, "/v1/mldsa/keys/"+keyID+"/state",
		map[string]string{"state": state}, &info); err != nil {
		return nil, err
	}
	return &info, nil
}
