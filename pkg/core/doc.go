// Copyright 2026 TAJMAC Group (GoHaSeMo)
// SPDX-License-Identifier: Apache-2.0

// Package core is the GoHaSeMo Core SDK — the exported Go API for embedding
// GoHaSeMo's cryptographic key management capabilities into any Go application.
//
// # Architecture
//
// GoHaSeMo Core is a pure-Go, CGO_ENABLED=0, statically linkable library.
// It communicates with a running GoHaSeMo Node to perform all key operations.
// No key material ever transits to or from the Cloud control plane.
//
// # Quick Start
//
// See the repository README.md for integration examples. The GoHaSeMo Node
// (the server this SDK talks to) is distributed separately.
//
// # Compatibility Promise
//
// The module path gohasemo.com/core is stable from v0.1.0 onwards.
// Backward compatibility is maintained within each major version.
// Breaking changes require a major version bump.
//
// # FIPS Status
//
// GoHaSeMo FIPS mode uses the NIST CMVP-validated Go Cryptographic Module
// (CMVP Certificate #5247, CAVP A6650; GOFIPS140=certified, Go 1.24+). GoHaSeMo itself does not hold a standalone
// NIST CMVP certificate. (Internal decision record: ADR-006.)
package core
