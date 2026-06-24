// Package cip30 verifies CIP-30 data signatures so a Cardano wallet's
// api.signData() result can be used for authentication and identification in
// web2 backend systems.
//
// A CIP-30 data signature is a [DataSignature]: a COSE_Sign1 structure and a
// COSE_Key, both hex-encoded CBOR exactly as a wallet returns them. [Verify]
// checks the Ed25519 signature and, optionally, that the signed payload matches
// an expected message ([WithMessage]) and that the signing key matches a
// Cardano address ([WithAddress] or [WithEmbeddedAddress], optionally tightened
// with [StrictAddress]). It returns a [Result] describing each check; use
// [Result.Valid] for the overall verdict. A non-nil error means the input could
// not be processed, which is distinct from a signature that ran and was found
// invalid.
//
// [Parse] decodes a [DataSignature] into a [Signature] without verifying it,
// for callers that want to run the individual checks themselves.
//
// The scope is intentionally narrow: this package validates CIP-30 data. It is
// not an HTTP framework or middleware — the caller owns the transport. See the
// package examples for end-to-end usage, and the project documentation at
// https://meigma.github.io/go-cip-30/ for usage and security guidance.
package cip30
