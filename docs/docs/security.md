---
title: Security
description: Security considerations and pitfalls when verifying CIP-30 data signatures.
---

# Security

A CIP-30 data signature is often used as an **identity** — "this user controls
this wallet." That makes verification a security boundary, and several details
decide whether it actually holds. This page collects the pitfalls. Read it
before relying on `go-cip-30` in production.

For reporting a vulnerability in the library itself, see
[`SECURITY.md`](https://github.com/meigma/go-cip-30/blob/master/SECURITY.md).

## Always verify on the server

!!! danger "Never trust client-side verification"

    A signature only proves anything where the relying party controls the
    check. Verify on the server, over a `DataSignature` received from the
    client, and make the authentication decision there. Client-side
    verification can be bypassed and proves nothing to your backend.

## The embedded address is self-asserted

A signature carries an address in its protected header (`Signature.Address`).
It is signed, but the signer chose it — it is not an authenticated claim about
who they are.

!!! warning "Do not trust `Signature.Address` unverified"

    Reading the embedded address and treating it as the signer's identity is an
    impersonation vector: anyone can sign with their own key while embedding
    someone else's address.

    - To check a signer's *claimed* address, use
      [`WithEmbeddedAddress`](verifying.md#verify-the-address-the-signer-claims),
      which verifies the key against that address.
    - To check against an address *you* already expect, use
      [`WithAddress`](verifying.md#bind-the-key-to-an-address-you-expect).

## A stake-only match is not control of funds

A Cardano base address has two credentials: a **payment** key hash (controls
funds) and a **delegation/stake** key hash (controls staking). By default
`go-cip-30` accepts a match against **either** — mirroring the reference
verifier — and reports which one via `AddressCheck.MatchedVia`.

This is the subtlest footgun in the library:

!!! danger "The mangled-address attack"

    An attacker who controls key `K` can construct a base address whose payment
    credential is a **victim's** and whose stake credential is `hash(K)`. Under
    the default policy, a signature from `K` against that address returns
    `Matched == true` (via `MatchedVia == CredentialStake`) — even though the
    attacker controls none of the victim's funds.

    When the match needs to mean "controls this address's funds", require the
    payment credential:

    ```go
    result, err := cip30.Verify(ds,
        cip30.WithAddress(addr),
        cip30.StrictAddress(), // a stake-only match now fails
    )
    ```

    Equivalently, inspect `result.Address.MatchedVia` and accept only
    `cip30.CredentialPayment`. `StrictAddress` has no effect on enterprise or
    reward addresses, whose single credential is unambiguous.

## Messages: the hashed and hex conventions

`WithMessage` follows the reference verifier's conventions, and they interact in
one way worth knowing:

- When the signature's unprotected `hashed` flag is set, the message is
  `blake2b-224`-hashed before comparison — **unless** the message is already an
  all-hex string, which is treated as a pre-computed digest (an is-hex guard).
- When the payload is detached (CBOR null or empty), the message reconstructs
  the signed bytes, so the signature itself proves the message.

!!! warning "Be deliberate with hex-looking input"

    If your application lets users sign arbitrary strings and a message happens
    to be all hexadecimal, the is-hex guard treats it as a digest rather than
    raw text. Prefer signing a structured, non-hex challenge (see below) so the
    interpretation is never ambiguous.

## Error is not the same as invalid

`Verify` separates *unprocessable input* from *a signature that failed*:

| Outcome | Meaning |
|---------|---------|
| non-nil `error` | Input could not be decoded (bad hex/CBOR, wrong lengths, unsupported algorithm). No verdict was produced. |
| nil `error`, `result.Valid() == false` | The checks ran; the signature is a forgery or a requested check did not match. |
| nil `error`, `result.Valid() == true` | The signature and every requested check passed. |

!!! warning "Gate on `result.Valid()`"

    Checking only `err != nil` and proceeding on a nil error accepts every
    invalid signature. Always require `result.Valid()` before treating a request
    as authenticated.

## Signatures prove authenticity, not freshness

A data signature has no built-in nonce or timestamp. Verifying one proves the
key signed the message — not that it did so recently, or for this login.

!!! danger "Bind a server-issued challenge"

    Without freshness, a captured signature can be replayed. Issue a
    single-use, time-bounded challenge from the server, include it in the
    message the wallet signs, and reject any signature whose message is not a
    live challenge you issued.

## Network is informational for raw and embedded addresses

`AddressCheck.Network` reports the network nibble of the checked address. For a
bech32 address the nibble is cross-checked against the human-readable prefix;
for raw hex or an embedded protected-header address there is no prefix to check
against, so the value is taken verbatim and is **informational only**.

!!! note

    `Matched` does not depend on `Network`. Do not treat `Network` as a trust
    boundary for raw or embedded input — enforce the expected network yourself
    if it matters.
