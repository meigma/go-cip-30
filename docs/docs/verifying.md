---
title: Verifying data signatures
description: How to verify CIP-30 data signatures with go-cip-30.
---

# Verifying data signatures

How to run the common CIP-30 verification flows. Each section is independent —
jump to the one that matches your goal.

## Prerequisites

- A `DataSignature` from a wallet's `api.signData(address, payload)`, carried to
  your backend as two hex strings:

    ```go
    ds := cip30.DataSignature{Signature: sigHex, Key: keyHex}
    ```

- The package imported: `import cip30 "github.com/meigma/go-cip-30"`.

Fully runnable versions of these snippets are in the
[package examples](https://pkg.go.dev/github.com/meigma/go-cip-30#pkg-examples).

## Verify the signature

Call `Verify` and gate on `Result.Valid`:

```go
result, err := cip30.Verify(ds)
if err != nil {
    return err // input could not be processed
}
if !result.Valid() {
    return errInvalid // signature did not verify
}
```

`result.SignatureValid` is the raw Ed25519 verdict; `result.Valid()` also
folds in any message or address checks you requested.

## Verify the signed message

Pass the message you expect with `WithMessage`:

```go
result, err := cip30.Verify(ds, cip30.WithMessage([]byte("Sign in to Example")))
if err != nil {
    return err
}
if !result.Valid() {
    return errInvalid
}
```

The hashed and detached-payload conventions are applied automatically. The
exact rules — and the one input shape that needs care — are covered in
[Security](security.md#messages-the-hashed-and-hex-conventions).

## Bind the key to an address you expect

When you already know which address should have signed, pass it with
`WithAddress`. It accepts bech32 (`addr…`/`stake…`, mainnet or `_test`) or
hex-encoded raw bytes:

```go
result, err := cip30.Verify(ds,
    cip30.WithMessage(msg),
    cip30.WithAddress("addr1qxtu4w2rq2mdguw4fkms2ge4m070nq8cmlyjfhghwlh8sjscnp7pvysxn4qgpg8ty3uzpjuc0l4gr0w74t7ag8uev2qseuyw6u"),
)
if err != nil {
    return err
}
if !result.Valid() {
    return errInvalid
}

// result.Address.MatchedVia reports Payment or Stake.
```

By default a base address matches via **either** its payment or its stake
credential. Which one matched is reported in `result.Address.MatchedVia`. This
distinction is a security boundary — see
[Require control of the payment credential](#require-control-of-the-payment-credential).

## Verify the address the signer claims

When the signature itself is the identity ("which address signed?"), check the
address embedded in the signature rather than supplying your own:

```go
result, err := cip30.Verify(ds, cip30.WithEmbeddedAddress())
if err != nil {
    return err // includes ErrNoEmbeddedAddress if the signature carries none
}
if !result.Valid() {
    return errInvalid
}
```

`WithAddress` and `WithEmbeddedAddress` are mutually exclusive. Trusting the
embedded address without verifying it is an impersonation vector — see
[Security](security.md#the-embedded-address-is-self-asserted).

## Require control of the payment credential

To demand that the key controls the address's **funds** (its payment
credential), not merely its delegation, add `StrictAddress`:

```go
result, err := cip30.Verify(ds,
    cip30.WithAddress(addr),
    cip30.StrictAddress(),
)
```

Under strict mode a base address that matched only its stake credential fails
(`Matched == false`, `MatchedVia == CredentialStake`). Strict mode has no effect
on enterprise or reward addresses, whose single credential is unambiguous.

## Reuse a parsed signature

To run checks individually, or to avoid re-decoding, `Parse` once and call the
methods on the returned `Signature`:

```go
sig, err := cip30.Parse(ds)
if err != nil {
    return err
}

ok := sig.Verify()                                  // bool
msg := sig.VerifyMessage([]byte("Sign in"))         // *MessageCheck
addr, err := sig.MatchesAddress(addr, cip30.StrictAddress()) // *AddressCheck
id := sig.KeyHash()                                 // []byte
```

## Tell "couldn't process" from "didn't verify"

The two failure modes are distinct, and conflating them is a security bug:

- A **non-nil error** means the input was unprocessable (bad hex or CBOR, wrong
  key/signature length, unsupported algorithm). There is no verdict.
- A **nil error with `result.Valid() == false`** means the checks ran and the
  signature is a forgery or a requested check did not match.

Always branch on both, and treat anything short of `result.Valid()` as a
rejection. See [Security](security.md#error-is-not-the-same-as-invalid).

## Use the key hash as a stable identity

`result.KeyHash` (or `sig.KeyHash()`) is `blake2b-224` of the public key — 28
bytes that identify the signer regardless of which address they present. Store
it, not the raw address, as a user's stable identity:

```go
userID := hex.EncodeToString(result.KeyHash)
```
