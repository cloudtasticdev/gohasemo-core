// Copyright 2026 TAJMAC Group (GoHaSeMo)
// SPDX-License-Identifier: Apache-2.0

package core

import (
	"bytes"
	"context"
	"crypto/mlkem"
	"crypto/sha512"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
)

// registrarStub is an in-memory stand-in for the Node's registration endpoints.
// It holds the decapsulation key, so /v1/register can derive the KEK the same
// way the real Node does — letting the test assert client/Node KEK agreement
// through the full RegisterClient flow.
type registrarStub struct {
	dk         *mlkem.DecapsulationKey768
	derived    []byte // KEK the "Node" derived from the posted ciphertext
	clientID   string
	gotRegPOST bool
}

func newRegistrarStub(t *testing.T) (*httptest.Server, *registrarStub) {
	t.Helper()
	dk, err := mlkem.GenerateKey768()
	if err != nil {
		t.Fatalf("GenerateKey768: %v", err)
	}
	st := &registrarStub{dk: dk}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /v1/register/node-key", func(w http.ResponseWriter, _ *http.Request) {
		ek := dk.EncapsulationKey().Bytes()
		fp := sha512.Sum384(ek)
		_ = json.NewEncoder(w).Encode(map[string]string{
			"encapsulation_key":  base64.StdEncoding.EncodeToString(ek),
			"fingerprint_sha384": base64.StdEncoding.EncodeToString(fp[:]),
		})
	})
	mux.HandleFunc("POST /v1/register", func(w http.ResponseWriter, r *http.Request) {
		var req map[string]any
		_ = json.NewDecoder(r.Body).Decode(&req)
		st.clientID, _ = req["client_id"].(string)
		ctB64, _ := req["ciphertext"].(string)
		ct, _ := base64.StdEncoding.DecodeString(ctB64)
		shared, err := dk.Decapsulate(ct)
		if err != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		st.derived = deriveTestClientKEK(t, shared, st.clientID)
		st.gotRegPOST = true
		w.WriteHeader(http.StatusCreated)
		_ = json.NewEncoder(w).Encode(map[string]string{"client_id": st.clientID})
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv, st
}

func TestClient_RegisterClient_FullFlow(t *testing.T) {
	srv, st := newRegistrarStub(t)
	c := newStubClient(t, srv)

	// Pin against the correct fingerprint (what the operator would publish OOB).
	ek := st.dk.EncapsulationKey().Bytes()
	fp := NodeKeyFingerprint(ek)

	kek, err := c.RegisterClient(context.Background(), "client-flow", fp)
	if err != nil {
		t.Fatalf("RegisterClient: %v", err)
	}
	defer kek.Destroy()

	if !st.gotRegPOST {
		t.Fatal("Node never received the registration POST")
	}
	if st.clientID != "client-flow" {
		t.Fatalf("Node saw client_id %q, want client-flow", st.clientID)
	}
	// The client's KEK must match the one the Node derived from the ciphertext.
	if !bytes.Equal(kek.Bytes(), st.derived) {
		t.Fatal("client KEK and Node-derived KEK disagree through RegisterClient")
	}
}

func TestClient_RegisterClient_RejectsFingerprintMismatch(t *testing.T) {
	srv, _ := newRegistrarStub(t)
	c := newStubClient(t, srv)

	var wrong [NodeKeyFingerprintSize]byte // all-zero, will not match
	_, err := c.RegisterClient(context.Background(), "client-mismatch", wrong)
	if err == nil {
		t.Fatal("RegisterClient accepted a mismatched node-key fingerprint (TOFU not prevented)")
	}
	if errors.As(err, new(*APIError)) {
		t.Fatalf("expected a pinning error before any POST, got API error: %v", err)
	}
}
