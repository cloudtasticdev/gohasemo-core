// Copyright 2026 TAJMAC Group (GoHaSeMo)
// SPDX-License-Identifier: Apache-2.0

package core

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

// mldsaStubNode returns an httptest.Server that stubs the /v1/mldsa/* routes.
func mldsaStubNode(t *testing.T) *httptest.Server {
	t.Helper()

	const (
		stubKeyID    = "mldsa-key-1"
		stubLabel    = "test-key"
		stubAlgo     = "ML-DSA-87"
		stubPubBytes = 2592
		stubSigBytes = 4627
	)

	mux := http.NewServeMux()

	// POST /v1/mldsa/keys — generate
	mux.HandleFunc("POST /v1/mldsa/keys", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusCreated)
		_ = json.NewEncoder(w).Encode(map[string]string{
			"key_id":     stubKeyID,
			"public_key": base64.StdEncoding.EncodeToString(make([]byte, stubPubBytes)),
			"algorithm":  stubAlgo,
		})
	})

	// GET /v1/mldsa/keys — list
	mux.HandleFunc("GET /v1/mldsa/keys", func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{
			"keys": []map[string]any{{
				"key_id": stubKeyID, "label": stubLabel,
				"algorithm": stubAlgo, "state": "ACTIVE",
				"version": 1, "created_at": "2026-01-01T00:00:00Z", "updated_at": "2026-01-01T00:00:00Z",
			}},
		})
	})

	// GET /v1/mldsa/keys/{id} — describe
	mux.HandleFunc("GET /v1/mldsa/keys/{id}", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]string{
			"key_id": r.PathValue("id"), "label": stubLabel,
			"algorithm": stubAlgo, "state": "ACTIVE",
			"public_key": base64.StdEncoding.EncodeToString(make([]byte, stubPubBytes)),
			"created_at": "2026-01-01T00:00:00Z", "updated_at": "2026-01-01T00:00:00Z",
		})
	})

	// POST /v1/mldsa/keys/{id}/sign
	mux.HandleFunc("POST /v1/mldsa/keys/{id}/sign", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]string{
			"key_id":     r.PathValue("id"),
			"signature":  base64.StdEncoding.EncodeToString(make([]byte, stubSigBytes)),
			"public_key": base64.StdEncoding.EncodeToString(make([]byte, stubPubBytes)),
			"algorithm":  stubAlgo,
		})
	})

	// POST /v1/mldsa/verify — returns 200 for any input (stub always valid)
	mux.HandleFunc("POST /v1/mldsa/verify", func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{"valid": true, "algorithm": stubAlgo})
	})

	// POST /v1/mldsa/keys/{id}/state
	mux.HandleFunc("POST /v1/mldsa/keys/{id}/state", func(w http.ResponseWriter, r *http.Request) {
		var req map[string]string
		_ = json.NewDecoder(r.Body).Decode(&req)
		_ = json.NewEncoder(w).Encode(map[string]string{
			"key_id": r.PathValue("id"), "label": stubLabel,
			"algorithm": stubAlgo, "state": req["state"],
			"created_at": "2026-01-01T00:00:00Z", "updated_at": "2026-01-01T00:00:00Z",
		})
	})

	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv
}

func newMLDSAStubClient(t *testing.T) *Client {
	t.Helper()
	srv := mldsaStubNode(t)
	c, err := NewClient(srv.URL, nil, WithHTTPClient(srv.Client()))
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	return c
}

func TestSDK_GenerateMLDSAKey(t *testing.T) {
	c := newMLDSAStubClient(t)
	id, pub, err := c.GenerateMLDSAKey(context.Background(), "test-key")
	if err != nil {
		t.Fatalf("GenerateMLDSAKey: %v", err)
	}
	if id != "mldsa-key-1" {
		t.Errorf("key_id = %q, want mldsa-key-1", id)
	}
	if len(pub) != 2592 {
		t.Errorf("public key len = %d, want 2592", len(pub))
	}
}

func TestSDK_ListMLDSAKeys(t *testing.T) {
	c := newMLDSAStubClient(t)
	keys, err := c.ListMLDSAKeys(context.Background())
	if err != nil {
		t.Fatalf("ListMLDSAKeys: %v", err)
	}
	if len(keys) != 1 || keys[0].KeyID != "mldsa-key-1" {
		t.Errorf("keys = %+v, want 1 key", keys)
	}
	if keys[0].Algorithm != "ML-DSA-87" {
		t.Errorf("algorithm = %q, want ML-DSA-87", keys[0].Algorithm)
	}
}

func TestSDK_DescribeMLDSAKey(t *testing.T) {
	c := newMLDSAStubClient(t)
	info, err := c.DescribeMLDSAKey(context.Background(), "mldsa-key-1")
	if err != nil {
		t.Fatalf("DescribeMLDSAKey: %v", err)
	}
	if info.KeyID != "mldsa-key-1" {
		t.Errorf("key_id = %q", info.KeyID)
	}
	if info.PublicKey == "" {
		t.Error("public_key must be present on describe")
	}
}

func TestSDK_SignMLDSA(t *testing.T) {
	c := newMLDSAStubClient(t)
	result, err := c.SignMLDSA(context.Background(), "mldsa-key-1", []byte("hello world"))
	if err != nil {
		t.Fatalf("SignMLDSA: %v", err)
	}
	if result.KeyID != "mldsa-key-1" {
		t.Errorf("key_id = %q", result.KeyID)
	}
	if len(result.Signature) != 4627 {
		t.Errorf("signature len = %d, want 4627", len(result.Signature))
	}
	if len(result.PublicKey) != 2592 {
		t.Errorf("public key len = %d, want 2592", len(result.PublicKey))
	}
	if result.Algorithm != "ML-DSA-87" {
		t.Errorf("algorithm = %q, want ML-DSA-87", result.Algorithm)
	}
}

func TestSDK_VerifyMLDSA(t *testing.T) {
	c := newMLDSAStubClient(t)
	pub := make([]byte, 2592)
	msg := []byte("test message")
	sig := make([]byte, 4627)
	if err := c.VerifyMLDSA(context.Background(), pub, msg, sig); err != nil {
		t.Fatalf("VerifyMLDSA: %v", err)
	}
}

func TestSDK_VerifyMLDSA_InvalidReturns422(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnprocessableEntity)
		_ = json.NewEncoder(w).Encode(map[string]string{"error": "signature verification failed"})
	}))
	t.Cleanup(srv.Close)
	c, _ := NewClient(srv.URL, nil, WithHTTPClient(srv.Client()))

	err := c.VerifyMLDSA(context.Background(), make([]byte, 2592), []byte("msg"), make([]byte, 4627))
	var apiErr *APIError
	if err == nil {
		t.Fatal("expected error from invalid signature, got nil")
	}
	if !isAPIError(err, &apiErr) || apiErr.StatusCode != 422 {
		t.Errorf("expected APIError 422, got %v", err)
	}
}

func TestSDK_SetMLDSAKeyState(t *testing.T) {
	c := newMLDSAStubClient(t)
	info, err := c.SetMLDSAKeyState(context.Background(), "mldsa-key-1", "DEPRECATED")
	if err != nil {
		t.Fatalf("SetMLDSAKeyState: %v", err)
	}
	if info.State != "DEPRECATED" {
		t.Errorf("state = %q, want DEPRECATED", info.State)
	}
}

// TestSDK_MLDSARoundTrip is an end-to-end check of the full flow:
// generate → sign → decode → verify at the SDK layer (stub server).
func TestSDK_MLDSARoundTrip(t *testing.T) {
	c := newMLDSAStubClient(t)
	ctx := context.Background()

	id, pub, err := c.GenerateMLDSAKey(ctx, "round-trip")
	if err != nil {
		t.Fatalf("generate: %v", err)
	}

	msg := []byte("GoHaSeMo ML-DSA-87 SDK round trip")
	result, err := c.SignMLDSA(ctx, id, msg)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	if !bytes.Equal(pub, result.PublicKey) {
		// In a real server pub == result.PublicKey; the stub returns zeroed
		// bytes for both so they should still match.
		t.Error("generate public key and sign public key differ")
	}

	if err := c.VerifyMLDSA(ctx, result.PublicKey, msg, result.Signature); err != nil {
		t.Fatalf("verify: %v", err)
	}
}

// isAPIError is a type assertion helper.
func isAPIError(err error, target **APIError) bool {
	if e, ok := err.(*APIError); ok {
		*target = e
		return true
	}
	return false
}
