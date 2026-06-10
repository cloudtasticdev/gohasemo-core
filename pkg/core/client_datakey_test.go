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

// dataKeyStub mimics the Node's datakey contract: generate returns a plaintext
// DEK + a "wrapped" form ("WRAP"||plaintext); decrypt reverses it. This exercises
// the SDK's encode/decode + SecureBytes handling (the real crypto round trip is
// covered by the internal/node integration test).
func dataKeyStub(t *testing.T) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()
	dek := bytes.Repeat([]byte{0xD3}, 32)
	mux.HandleFunc("POST /v1/datakey/generate", func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]string{
			"plaintext_key": base64.StdEncoding.EncodeToString(dek),
			"wrapped_key":   base64.StdEncoding.EncodeToString(append([]byte("WRAP"), dek...)),
		})
	})
	mux.HandleFunc("POST /v1/datakey/decrypt", func(w http.ResponseWriter, r *http.Request) {
		var req map[string]string
		_ = json.NewDecoder(r.Body).Decode(&req)
		wrapped, _ := base64.StdEncoding.DecodeString(req["wrapped_key"])
		_ = json.NewEncoder(w).Encode(map[string]string{
			"plaintext_key": base64.StdEncoding.EncodeToString(wrapped[len("WRAP"):]),
		})
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv
}

func TestClient_DataKeyEnvelope(t *testing.T) {
	c := newStubClient(t, dataKeyStub(t))
	ctx := context.Background()

	dek, wrapped, err := c.GenerateDataKey(ctx, "key-1")
	if err != nil {
		t.Fatalf("GenerateDataKey: %v", err)
	}
	defer dek.Destroy()
	if dek.Len() != 32 {
		t.Fatalf("DEK len = %d, want 32", dek.Len())
	}
	if len(wrapped) != len("WRAP")+32 {
		t.Fatalf("wrapped len = %d, want %d", len(wrapped), len("WRAP")+32)
	}

	dek2, err := c.DecryptDataKey(ctx, "key-1", wrapped)
	if err != nil {
		t.Fatalf("DecryptDataKey: %v", err)
	}
	defer dek2.Destroy()
	if !bytes.Equal(dek.Bytes(), dek2.Bytes()) {
		t.Fatal("unwrapped DEK differs from generated DEK")
	}
}
