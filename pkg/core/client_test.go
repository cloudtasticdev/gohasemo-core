// Copyright 2026 TAJMAC Group (GoHaSeMo)
// SPDX-License-Identifier: Apache-2.0

package core

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
)

// stubNode is a minimal in-memory stand-in for the Node API contract, letting us
// test the client without any server-side package (stdlib only).
func stubNode(t *testing.T) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc("POST /v1/keys", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusCreated)
		_ = json.NewEncoder(w).Encode(map[string]string{"key_id": "key-123"})
	})
	mux.HandleFunc("POST /v1/encrypt", func(w http.ResponseWriter, r *http.Request) {
		var req map[string]string
		_ = json.NewDecoder(r.Body).Decode(&req)
		// "Encrypt" by prefixing a marker so the round-trip is observable.
		pt, _ := base64.StdEncoding.DecodeString(req["plaintext"])
		ct := append([]byte("enc:"), pt...)
		_ = json.NewEncoder(w).Encode(map[string]string{
			"ciphertext": base64.StdEncoding.EncodeToString(ct),
		})
	})
	mux.HandleFunc("POST /v1/decrypt", func(w http.ResponseWriter, r *http.Request) {
		var req map[string]string
		_ = json.NewDecoder(r.Body).Decode(&req)
		ct, _ := base64.StdEncoding.DecodeString(req["ciphertext"])
		pt := ct[len("enc:"):]
		_ = json.NewEncoder(w).Encode(map[string]string{
			"plaintext": base64.StdEncoding.EncodeToString(pt),
		})
	})
	// GET /v1/keys deliberately returns a 404 with the Node's error envelope so
	// the client's APIError status passthrough can be asserted.
	mux.HandleFunc("GET /v1/keys", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNotFound)
		_ = json.NewEncoder(w).Encode(map[string]string{"error": "not found"})
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv
}

func newStubClient(t *testing.T, srv *httptest.Server) *Client {
	t.Helper()
	c, err := NewClient(srv.URL, nil, WithHTTPClient(srv.Client()))
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	return c
}

func TestClient_GenerateEncryptDecrypt(t *testing.T) {
	c := newStubClient(t, stubNode(t))
	ctx := context.Background()

	id, err := c.GenerateKey(ctx, "my-key")
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	if id != "key-123" {
		t.Fatalf("key_id = %q, want key-123", id)
	}

	plaintext := []byte("sensitive payload")
	ct, err := c.Encrypt(ctx, id, plaintext)
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}
	pt, err := c.Decrypt(ctx, id, ct)
	if err != nil {
		t.Fatalf("Decrypt: %v", err)
	}
	defer pt.Destroy()
	if string(pt.Bytes()) != string(plaintext) {
		t.Fatalf("round trip = %q, want %q", pt.Bytes(), plaintext)
	}
}

func TestClient_APIErrorExposesStatus(t *testing.T) {
	c := newStubClient(t, stubNode(t))
	// ListKeys hits GET /v1/keys which the stub does not define → 404.
	_, err := c.ListKeys(context.Background())
	var apiErr *APIError
	if !errors.As(err, &apiErr) {
		t.Fatalf("error = %v, want *APIError", err)
	}
	if apiErr.StatusCode != http.StatusNotFound {
		t.Fatalf("status = %d, want 404", apiErr.StatusCode)
	}
}

func TestNewClient_Validation(t *testing.T) {
	if _, err := NewClient("", nil); err == nil {
		t.Error("empty baseURL should error")
	}
	if _, err := NewClient("https://node", nil); err == nil {
		t.Error("nil tlsConfig without WithHTTPClient should error")
	}
}
