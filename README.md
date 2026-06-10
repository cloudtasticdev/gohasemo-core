<!--
Copyright 2026 TAJMAC Group (GoHaSeMo)
SPDX-License-Identifier: Apache-2.0
-->

# GoHaSeMo Core SDK

The official Go SDK for **GoHaSeMo** — a software-defined HSM / virtual trust
anchor. This module is the exported Go API your application uses to perform key
operations against a **GoHaSeMo Node that you run yourself**.

## What this is

- **Pure Go, `CGO_ENABLED=0`.** Statically linkable, no C toolchain, no cgo
  dependencies. Standard-library only — there is no third-party `require` block.
- **Talks to a Node you host, over mTLS.** All key operations go to a running
  GoHaSeMo Node on the Node's mutual-TLS API (TLS 1.3 enforced as the floor).
  You run the Node; the SDK is a client.
- **No key material to any cloud.** The SDK never sends key material to, or
  fetches it from, a GoHaSeMo cloud control plane. Long-term key material lives
  on your Node. The SDK holds secrets only transiently, in `SecureBytes` that
  you `Destroy()` after use.
- **Post-quantum registration.** Client registration establishes a per-client
  KEK via ML-KEM (FIPS 203) encapsulation to the Node's pinned key. Trust-on-
  first-use is **not** supported by design — you must pin the Node's key
  fingerprint out-of-band before registering.

The GoHaSeMo **Node engine is distributed separately** (it is not in this repo
and is not Apache-2.0). This repository contains only the open-source SDK.

## Install

```bash
go get gohasemo.com/core@vX.Y.Z
```

```go
import "gohasemo.com/core/pkg/core"
```

Requires Go 1.25 or newer.

## Quick start

End-to-end: register a client, ask the Node for a key, generate and unwrap a
data key for envelope encryption, then revoke the key. Error handling is
abbreviated for brevity — check every error in real code.

```go
package main

import (
	"context"
	"crypto/tls"
	"log"

	"gohasemo.com/core/pkg/core"
)

func main() {
	ctx := context.Background()

	// 1. Configure the client's mTLS identity and the trust anchor for your
	//    Node's certificate. TLS 1.3 is enforced as the floor by NewClient.
	tlsCfg := &tls.Config{
		// Certificates:  your client certificate/key (mTLS identity).
		// RootCAs:       the CA that signed your Node's server certificate.
	}

	client, err := core.NewClient("https://node.internal.example:8443", tlsCfg)
	if err != nil {
		log.Fatal(err)
	}

	// 2. Register this client to establish its per-client KEK. You MUST pin the
	//    Node's encapsulation-key fingerprint out-of-band (the SHA-384 your
	//    operator published) — there is no trust-on-first-use path.
	var nodeFingerprint [core.NodeKeyFingerprintSize]byte
	// copy(nodeFingerprint[:], decodedOutOfBandFingerprint)

	kek, err := client.RegisterClient(ctx, "billing-service-01", nodeFingerprint)
	if err != nil {
		log.Fatal(err)
	}
	defer kek.Destroy() // the per-client KEK — zero it when done.

	// 3. Generate a Node-held master key (AES-256-GCM) to wrap data keys under.
	keyID, err := client.GenerateKey(ctx, "billing-records")
	if err != nil {
		log.Fatal(err)
	}

	// 4. Generate a data key (DEK) for envelope encryption. You get the DEK in
	//    the clear (encrypt your bulk data locally with it, then Destroy it) and
	//    the wrapped DEK (persist this alongside your ciphertext).
	dek, wrapped, err := client.GenerateDataKey(ctx, keyID)
	if err != nil {
		log.Fatal(err)
	}
	// ... use dek.Bytes() to seal your records locally ...
	dek.Destroy()

	// 5. Later, unwrap the stored wrapped DEK to decrypt your sealed data.
	recovered, err := client.DecryptDataKey(ctx, keyID, wrapped)
	if err != nil {
		log.Fatal(err)
	}
	// ... use recovered.Bytes() to open your records ...
	recovered.Destroy()

	// 6. Surgically revoke the key (transitions it to DISABLED — blocks both
	//    encrypt and decrypt under it). To permanently destroy the key material
	//    instead, use SetKeyState(ctx, keyID, core.KeyStateDeleted).
	if err := client.RevokeKey(ctx, keyID); err != nil {
		log.Fatal(err)
	}
}
```

### Handling Node errors

A non-2xx response from the Node is returned as `*core.APIError`, whose
`StatusCode` lets you branch (e.g. 404 key-not-found, 410 deleted, 403
disabled):

```go
var apiErr *core.APIError
if errors.As(err, &apiErr) && apiErr.StatusCode == 404 {
	// key not found
}
```

## Secret hygiene

Anything secret the SDK returns is wrapped in `core.SecureBytes`, which:

- redacts under `%v` / `%s` / `%#v` so secrets cannot leak through logging, and
- best-effort zeroes its backing array on `Destroy()` (a finalizer is a backstop
  only — always call `Destroy()` explicitly).

## Licence

Apache-2.0. See [`LICENSE`](./LICENSE).

## The Node engine is separate

This repository is the **SDK only**. The GoHaSeMo Node engine — the server you
run that holds key material — is distributed under separate terms and is not
included here. See the GoHaSeMo documentation for how to obtain and run a Node.
