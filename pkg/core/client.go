// Copyright 2026 TAJMAC Group (GoHaSeMo)
// SPDX-License-Identifier: Apache-2.0

// Node API client (EPIC-09 client side).
//
// Client is the exported Go entry point an application uses to perform key
// operations against a running GoHaSeMo Node: generate a data key, then encrypt
// and decrypt caller data under it. All traffic is over the Node's mTLS API; the
// SDK never holds long-term key material (the Node does) and never talks to the
// Cloud control plane.
//
// This file depends only on the Go standard library (ADR-008 import isolation).

package core

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// maxResponseBytes caps how much of a Node response the client will read, to
// bound memory use against a misbehaving or hostile endpoint.
const maxResponseBytes = 64 << 20 // 64 MiB

// Client performs key operations against a GoHaSeMo Node over mTLS.
// Construct it with NewClient; it is safe for concurrent use.
type Client struct {
	baseURL    string
	httpClient *http.Client
}

// ClientOption customises a Client.
type ClientOption func(*Client)

// WithHTTPClient supplies a fully configured *http.Client (e.g. for tests, or a
// custom transport/proxy). When set, the tlsConfig passed to NewClient is
// ignored.
func WithHTTPClient(h *http.Client) ClientOption {
	return func(c *Client) { c.httpClient = h }
}

// NewClient builds a client for the Node at baseURL (e.g.
// "https://node.example:8443"). tlsConfig provides the client's mTLS identity
// and the trust anchor for the Node certificate; TLS 1.3 is enforced as the
// floor. Pass WithHTTPClient to supply your own *http.Client instead, in which
// case tlsConfig may be nil.
func NewClient(baseURL string, tlsConfig *tls.Config, opts ...ClientOption) (*Client, error) {
	if baseURL == "" {
		return nil, errors.New("core: baseURL must not be empty")
	}
	c := &Client{baseURL: strings.TrimRight(baseURL, "/")}
	for _, o := range opts {
		o(c)
	}
	if c.httpClient == nil {
		if tlsConfig == nil {
			return nil, errors.New("core: tlsConfig is required (or use WithHTTPClient)")
		}
		cfg := tlsConfig.Clone()
		if cfg.MinVersion < tls.VersionTLS13 {
			cfg.MinVersion = tls.VersionTLS13
		}
		c.httpClient = &http.Client{Transport: &http.Transport{TLSClientConfig: cfg}}
	}
	return c, nil
}

// APIError is returned when the Node responds with a non-2xx status. StatusCode
// lets callers branch (e.g. 404 key-not-found, 410 deleted, 403 disabled).
type APIError struct {
	StatusCode int
	Message    string
}

func (e *APIError) Error() string {
	return fmt.Sprintf("core: node API error %d: %s", e.StatusCode, e.Message)
}

// GenerateKey asks the Node to generate a new AES-256-GCM data key with the
// given label and returns its key ID.
func (c *Client) GenerateKey(ctx context.Context, label string) (keyID string, err error) {
	var resp struct {
		KeyID string `json:"key_id"`
	}
	err = c.do(ctx, http.MethodPost, "/v1/keys",
		map[string]string{"label": label, "algorithm": "AES-256-GCM"}, &resp)
	if err != nil {
		return "", err
	}
	return resp.KeyID, nil
}

// Encrypt encrypts plaintext under the Node-held key identified by keyID and
// returns the ciphertext. plaintext is the caller's to zero after the call.
func (c *Client) Encrypt(ctx context.Context, keyID string, plaintext []byte) ([]byte, error) {
	var resp struct {
		Ciphertext string `json:"ciphertext"`
	}
	err := c.do(ctx, http.MethodPost, "/v1/encrypt", map[string]string{
		"key_id":    keyID,
		"plaintext": base64.StdEncoding.EncodeToString(plaintext),
	}, &resp)
	if err != nil {
		return nil, err
	}
	ct, err := base64.StdEncoding.DecodeString(resp.Ciphertext)
	if err != nil {
		return nil, fmt.Errorf("core: decode ciphertext: %w", err)
	}
	return ct, nil
}

// Decrypt decrypts ciphertext under the Node-held key identified by keyID. The
// recovered plaintext is returned in SecureBytes; the caller MUST Destroy it
// when done.
func (c *Client) Decrypt(ctx context.Context, keyID string, ciphertext []byte) (*SecureBytes, error) {
	var resp struct {
		Plaintext string `json:"plaintext"`
	}
	err := c.do(ctx, http.MethodPost, "/v1/decrypt", map[string]string{
		"key_id":     keyID,
		"ciphertext": base64.StdEncoding.EncodeToString(ciphertext),
	}, &resp)
	if err != nil {
		return nil, err
	}
	pt, err := base64.StdEncoding.DecodeString(resp.Plaintext)
	if err != nil {
		return nil, fmt.Errorf("core: decode plaintext: %w", err)
	}
	out := SecureBytesFrom(pt)
	secureZero(pt) // zero the transient decode buffer; SecureBytes holds the copy
	return out, nil
}

// GenerateDataKey requests a fresh data key (DEK) for envelope encryption. It
// returns the DEK in the clear (in SecureBytes — encrypt your bulk data locally
// with it, then Destroy it) AND the wrapped DEK (persist this alongside your
// data). This is the high-throughput pattern: call once per data key, then
// encrypt many records locally — instead of one Node round trip per record.
func (c *Client) GenerateDataKey(ctx context.Context, keyID string) (plaintext *SecureBytes, wrapped []byte, err error) {
	var resp struct {
		PlaintextKey string `json:"plaintext_key"`
		WrappedKey   string `json:"wrapped_key"`
	}
	if err := c.do(ctx, http.MethodPost, "/v1/datakey/generate", map[string]string{"key_id": keyID}, &resp); err != nil {
		return nil, nil, err
	}
	dek, err := base64.StdEncoding.DecodeString(resp.PlaintextKey)
	if err != nil {
		return nil, nil, fmt.Errorf("core: decode data key: %w", err)
	}
	wrapped, err = base64.StdEncoding.DecodeString(resp.WrappedKey)
	if err != nil {
		secureZero(dek)
		return nil, nil, fmt.Errorf("core: decode wrapped data key: %w", err)
	}
	out := SecureBytesFrom(dek)
	secureZero(dek) // SecureBytes holds the copy
	return out, wrapped, nil
}

// DecryptDataKey unwraps a wrapped DEK (from GenerateDataKey) so you can decrypt
// your locally-sealed data. The plaintext DEK is returned in SecureBytes; Destroy
// it after use.
func (c *Client) DecryptDataKey(ctx context.Context, keyID string, wrapped []byte) (*SecureBytes, error) {
	var resp struct {
		PlaintextKey string `json:"plaintext_key"`
	}
	if err := c.do(ctx, http.MethodPost, "/v1/datakey/decrypt", map[string]string{
		"key_id":      keyID,
		"wrapped_key": base64.StdEncoding.EncodeToString(wrapped),
	}, &resp); err != nil {
		return nil, err
	}
	dek, err := base64.StdEncoding.DecodeString(resp.PlaintextKey)
	if err != nil {
		return nil, fmt.Errorf("core: decode data key: %w", err)
	}
	out := SecureBytesFrom(dek)
	secureZero(dek)
	return out, nil
}

// KeyState is a key's lifecycle state, as exposed by the Node's key-state model.
// Setting a key's state is a MUTATING (write-path) operation: it is audited and
// subject to the write-path license gate. It is NOT decryption and does not
// violate ADR-014 §1 — an operator-driven lifecycle transition is a separate,
// intentional control from license state.
//
// State semantics (match the Node, internal/store):
//   - KeyStateActive:     normal use; encrypt and decrypt both succeed.
//   - KeyStateDeprecated: advisory; operations still succeed (steer new traffic
//     to a successor key).
//   - KeyStateDisabled:   blocks BOTH encrypt AND decrypt. This is the surgical
//     "revoke" state — data sealed under the key becomes unusable until/unless
//     the key is re-enabled.
//   - KeyStateDeleted:    terminal; the key material is gone and cannot be
//     revived. Data sealed under it is permanently unrecoverable.
type KeyState string

const (
	KeyStateActive     KeyState = "ACTIVE"
	KeyStateDeprecated KeyState = "DEPRECATED"
	KeyStateDisabled   KeyState = "DISABLED"
	KeyStateDeleted    KeyState = "DELETED"
)

// SetKeyState transitions the Node-held key identified by keyID to a new
// lifecycle state via POST /v1/keys/{id}/state. This is a write-path operation
// (audited; subject to any write-path license gate) — it is not decryption and
// is never on the recovery path.
//
// Illegal transitions (e.g. reviving a DELETED key) and unknown states are
// rejected by the Node with a 4xx, surfaced here as an *APIError.
func (c *Client) SetKeyState(ctx context.Context, keyID string, state KeyState) error {
	return c.do(ctx, http.MethodPost, "/v1/keys/"+url.PathEscape(keyID)+"/state",
		map[string]string{"state": string(state)}, nil)
}

// RevokeKey surgically revokes the Node-held key identified by keyID by
// transitioning it to KeyStateDisabled, which blocks BOTH encrypt and decrypt
// under that key. This is the SDK entry point a caller uses to make a per-client
// KEK / namespace key unusable (e.g. BasuyuDB's RevokeNamespace).
//
// It is a thin convenience over SetKeyState(ctx, keyID, KeyStateDisabled): a
// write-path, audited operation. To permanently destroy the key material instead
// (irreversible), call SetKeyState(ctx, keyID, KeyStateDeleted).
func (c *Client) RevokeKey(ctx context.Context, keyID string) error {
	return c.SetKeyState(ctx, keyID, KeyStateDisabled)
}

// KeyInfo is metadata about a stored key (never key material).
type KeyInfo struct {
	KeyID     string `json:"key_id"`
	Label     string `json:"label"`
	Algorithm string `json:"algorithm"`
	State     string `json:"state"`
	Version   int    `json:"version"`
	CreatedAt string `json:"created_at"`
	UpdatedAt string `json:"updated_at"`
}

// ListKeys returns metadata for all non-deleted keys on the Node.
func (c *Client) ListKeys(ctx context.Context) ([]KeyInfo, error) {
	var resp struct {
		Keys []KeyInfo `json:"keys"`
	}
	if err := c.do(ctx, http.MethodGet, "/v1/keys", nil, &resp); err != nil {
		return nil, err
	}
	return resp.Keys, nil
}

// RegisterClient performs the full client-registration handshake against the
// Node and returns the established per-client KEK (the caller MUST Destroy it):
//
//  1. fetch the Node's ML-KEM encapsulation key (GET /v1/register/node-key);
//  2. pin it against expectedNodeKeyFingerprint — the out-of-band SHA-384 the
//     operator published — refusing to proceed on mismatch (TOFU forbidden);
//  3. encapsulate and derive the per-client KEK;
//  4. POST the ciphertext (with a fresh replay nonce + timestamp) to
//     /v1/register.
//
// The Node keeps only an HMAC fingerprint of the KEK; the raw KEK never leaves
// the client. On any failure after the KEK is derived it is zeroed before the
// error is returned.
func (c *Client) RegisterClient(ctx context.Context, clientID string, expectedNodeKeyFingerprint [NodeKeyFingerprintSize]byte) (*SecureBytes, error) {
	var nk struct {
		EncapsulationKey string `json:"encapsulation_key"`
	}
	if err := c.do(ctx, http.MethodGet, "/v1/register/node-key", nil, &nk); err != nil {
		return nil, err
	}
	ek, err := base64.StdEncoding.DecodeString(nk.EncapsulationKey)
	if err != nil {
		return nil, fmt.Errorf("core: decode node key: %w", err)
	}
	node, err := PinNodeIdentity(ek, expectedNodeKeyFingerprint)
	if err != nil {
		return nil, err // fingerprint mismatch or malformed key — do NOT register
	}
	kek, ciphertext, err := node.EstablishKEK(clientID)
	if err != nil {
		return nil, err
	}

	nonce := make([]byte, 16)
	if _, err := rand.Read(nonce); err != nil {
		kek.Destroy()
		return nil, fmt.Errorf("core: generate nonce: %w", err)
	}
	req := map[string]any{
		"client_id":  clientID,
		"ciphertext": base64.StdEncoding.EncodeToString(ciphertext),
		"nonce":      base64.StdEncoding.EncodeToString(nonce),
		"timestamp":  time.Now().Unix(),
	}
	if err := c.do(ctx, http.MethodPost, "/v1/register", req, nil); err != nil {
		kek.Destroy()
		return nil, err
	}
	return kek, nil
}

// do performs a JSON request/response against the Node. reqBody is marshalled as
// JSON when non-nil; respBody is decoded from the response when non-nil. A
// non-2xx status yields an *APIError.
func (c *Client) do(ctx context.Context, method, path string, reqBody, respBody any) error {
	var body io.Reader
	if reqBody != nil {
		buf, err := json.Marshal(reqBody)
		if err != nil {
			return fmt.Errorf("core: marshal request: %w", err)
		}
		body = bytes.NewReader(buf)
	}
	req, err := http.NewRequestWithContext(ctx, method, c.baseURL+path, body)
	if err != nil {
		return fmt.Errorf("core: build request: %w", err)
	}
	if reqBody != nil {
		req.Header.Set("Content-Type", "application/json")
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("core: %s %s: %w", method, path, err)
	}
	defer resp.Body.Close()

	data, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseBytes))
	if err != nil {
		return fmt.Errorf("core: read response: %w", err)
	}
	if resp.StatusCode/100 != 2 {
		return parseAPIError(resp.StatusCode, data)
	}
	if respBody != nil {
		if err := json.Unmarshal(data, respBody); err != nil {
			return fmt.Errorf("core: decode response: %w", err)
		}
	}
	return nil
}

// parseAPIError extracts the Node's {"error":...} message, falling back to the
// raw body or HTTP status text.
func parseAPIError(status int, body []byte) *APIError {
	msg := strings.TrimSpace(string(body))
	var e struct {
		Error string `json:"error"`
	}
	if json.Unmarshal(body, &e) == nil && e.Error != "" {
		msg = e.Error
	}
	if msg == "" {
		msg = http.StatusText(status)
	}
	return &APIError{StatusCode: status, Message: msg}
}
