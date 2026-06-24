---
title: go-cip-30
slug: /
description: Go library for verifying CIP-30 data signatures in web2 backends.
---

# go-cip-30

`go-cip-30` verifies [CIP-30](https://cips.cardano.org/cip/CIP-30) data
signatures so a Cardano wallet's `api.signData()` result can be used for
authentication and identification in a Go backend.

The scope is intentionally narrow. This library validates CIP-30 data — it is
**not** an HTTP framework or middleware. You bring the transport; it handles the
cryptography and the Cardano address logic.

## Install

```sh
go get github.com/meigma/go-cip-30
```

The package is imported as `cip30`.

## Quick start

A wallet returns a data signature as two hex-encoded CBOR strings — a
`signature` (COSE_Sign1) and a `key` (COSE_Key). Verify the signature and the
message it was meant to sign:

```go
import cip30 "github.com/meigma/go-cip-30"

ds := cip30.DataSignature{
    Signature: sigHex, // from api.signData(...)
    Key:       keyHex,
}

result, err := cip30.Verify(ds, cip30.WithMessage([]byte("Sign in to Example")))
if err != nil {
    // Unprocessable input: bad hex/CBOR, wrong key or signature length, etc.
    return err
}
if !result.Valid() {
    // The signature ran but did not verify, or a requested check failed.
    return errAuthFailed
}

// result.KeyHash is the signer's stable identity (blake2b-224 of the key).
```

## How it works

A CIP-30 data signature is a [COSE_Sign1](https://cips.cardano.org/cip/CIP-8)
structure plus a COSE_Key carrying a raw Ed25519 public key. Verification
reconstructs the COSE `Sig_structure` from the signed bytes and checks it with
Ed25519. Identity is the **key hash** — `blake2b-224` of the public key — which
is the credential embedded in a
[CIP-19](https://cips.cardano.org/cip/CIP-19) Cardano address. Binding a key to
an address therefore means matching that key hash against the address's payment
or stake credential. See the linked CIPs for the wire formats and address
structure.

## Next steps

- **[Verifying data signatures](verifying.md)** — task-oriented guide to the
  common verification flows.
- **[Security](security.md)** — the pitfalls that matter when a signature is an
  identity, and how to avoid them. Read this before going to production.
- **[API reference](https://pkg.go.dev/github.com/meigma/go-cip-30)** — full
  godoc on pkg.go.dev, with runnable examples.
