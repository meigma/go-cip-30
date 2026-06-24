# go-cip-30 — Design Proposal (TEMPORARY)

> **Status: temporary working draft, session 002 (2026-06-23).**
> This document lives in the journal as scaffolding for future implementation
> sessions. It is **not** a committed spec, **not** the public docs, and **not**
> binding. Treat it as a starting point to refine against working code, per the
> project's agile / prototype-early stance. Supersede it freely.

## 1. Purpose & scope

`github.com/meigma/go-cip-30` is a **library-only** Go module whose public API
lives at the repo root in `package cip30`. Its job is narrow and concrete:

> **Verify a [CIP-30] `DataSignature`** — confirm that a message was signed by
> the private key behind a given public key, and (optionally) that the signed
> payload matches an expected message and that the signing key corresponds to a
> given Cardano address.

This is the authentication / identification primitive: a backend ("web2") proves
a caller controls a particular Cardano key/address by checking a signature the
caller's wallet produced via `api.signData()`.

**In scope**

- Decode a CIP-30 `DataSignature` (`{ signature: cbor<COSE_Sign1>, key:
  cbor<COSE_Key> }`, both hex).
- Verify the Ed25519 signature over the reconstructed COSE `Sig_structure`
  (`Signature1` context), per [CIP-8].
- Optional: check the embedded payload against an expected plaintext message
  (honoring the `hashed` / blake2b-224 convention and the detached-payload case).
- Optional: check that `blake2b-224(publicKey)` matches the key-hash credential
  in a supplied bech32 address ([CIP-19]): base, enterprise, pointer, and reward
  (stake) addresses.

**Out of scope** (caller's responsibility / explicitly excluded)

- Any transport: no HTTP handlers, middleware, sessions, nonce/challenge
  storage, or replay protection. The library is pure functions over bytes.
- Producing signatures (signing), wallet connection, the CIP-30 JS bridge.
- Transaction signing/verification (`signTx`), key derivation (BIP32-Ed25519),
  Byron addresses, COSE encryption/MAC, multi-signer `COSE_Sign`.
- On-chain lookups (whether an address is used, holds funds, etc.).

Design fidelity: **spec-first** (CIP-8 / CIP-19 / CIP-30), using the canonical
TypeScript reference [`cardano-verify-datasignature`][ref-ts] only as a
behavioral cross-check for edge cases. Dependency stance: **lean on established
libraries**; hand-roll only the tiny, stable glue (the `Sig_structure` assembly
and the CIP-19 header parse), which the reference itself effectively hand-rolls.

## 2. Background: anatomy of a CIP-30 DataSignature

`api.signData(addr, payload)` returns:

```
DataSignature = { signature: hex(cbor<COSE_Sign1>), key: hex(cbor<COSE_Key>) }
```

**`COSE_Sign1`** — a 4-element CBOR array ([CIP-8] / RFC 8152):

```
COSE_Sign1 = [
  protected   : bstr,        ; a CBOR-encoded header map, kept AS-IS on the wire
  unprotected : { * label => any },
  payload     : bstr / nil,  ; the signed message, or its blake2b-224 hash, or absent
  signature   : bstr,        ; 64-byte Ed25519 signature
]
```

- **Protected map** (these bytes are part of what is signed):
  `alg(1) = EdDSA(-8)`; `"address" = <raw address bytes>` (no CBOR tag wrapper);
  optional `kid(4)`.
- **Unprotected map** (not signed): `"hashed": bool`; optionally CIP-8 `version`.

**`COSE_Key`** — a CBOR map:
`kty(1)=OKP(1)`, `alg(3)=EdDSA(-8)`, `crv(-1)=Ed25519(6)`,
`x(-2)=<32-byte raw Ed25519 public key>`, optional `kid(2)`.

**What is actually signed** — the COSE `Sig_structure`, NOT the whole array:

```
Sig_structure = [
  "Signature1",     ; context (text)
  body_protected,   ; bstr: the protected-header bytes exactly as received
  external_aad,     ; bstr: empty (h'') for CIP-30
  payload,          ; bstr: the message, or blake2b-224(message) if hashed
]
```

Verification is therefore:
`ed25519.Verify(x, cbor.Marshal(Sig_structure), signature)`.

> Hand-decoded primary test vector (confirms the above):
> `84` array(4) → `582a a201 27 67"address" 581d e1…` protected
> `{alg:-8, "address":0xe1…}` (header `0xe1` = type 14 stake-key / mainnet) →
> `a1 66"hashed" f4` unprotected `{hashed:false}` → `5826 41…`
> payload `"Augusta Ada King, Countess of Lovelace"` → `5840 …` 64-byte sig.
> COSE_Key `a4 0101 0327 2006 2158 20 b89526…` =
> `{kty:OKP, alg:EdDSA, crv:Ed25519, x:b89526…420c6}`.

A useful simplification: the reference wraps `x` in a BIP32 public-key type, but
the only operation that touches it is `blake2b-224(x)`. **No BIP32 / extended-key
machinery is needed for verification** — `x` is a raw 32-byte Ed25519 key and a
plain `crypto/ed25519.Verify` works directly on it.

## 3. Dependencies

Established libraries for everything non-trivial; no hand-rolled crypto. (Survey
grounded against current upstreams, 2026-06.)

| Concern | Dependency | License | Use |
|---|---|---|---|
| CBOR decode/encode | `github.com/fxamacker/cbor/v2` | MIT | Decode `COSE_Sign1` array + `COSE_Key` map + the nested protected-header bstr; marshal the `Sig_structure` |
| Ed25519 verify | `crypto/ed25519` (stdlib) | BSD | `Verify(x[32], sigStruct, sig[64])` |
| blake2b-224 | `golang.org/x/crypto/blake2b` | BSD-3 | `blake2b.New(28, nil)` → 28-byte credential hash |
| bech32 decode | `github.com/btcsuite/btcd/btcutil/bech32` | ISC | `DecodeNoLimit` + `ConvertBits(_,5,8,false)`; header parsed in-house |

**Deliberately NOT depended on:**

- **`github.com/veraison/go-cose`** (Apache-2.0) — capable and well-maintained,
  but two frictions push us to hand-assemble the `Sig_structure` over fxamacker
  instead: (1) it treats its `external` arg as `external_aad`, with no clean hook
  to verify against an **externally-supplied payload** — exactly CIP-30's
  empty-payload reconstruction case; (2) it re-derives `body_protected` from its
  decoded headers, which has historically mis-verified non-minimal protected
  encodings (their issue #119). Hand-assembly reuses the **wire bytes**, which is
  strictly safer for a verifier. *May keep go-cose as a test-only cross-check.*
- **`github.com/echovl/cardano-go`, `github.com/blinklabs-io/gouroboros`** — full
  Cardano SDKs / node frameworks; far too heavy to extract one header byte and a
  28-byte credential.

**Critical gotchas (write these into the code as comments):**

1. **Never re-encode `body_protected`.** The signature is over the *exact*
   protected-header bytes as received. Decode element [0] to `[]byte`, reuse it
   verbatim in the `Sig_structure`; decode it a *second* time (separately) only
   to read `alg` / `"address"`. Re-marshalling — even canonically — breaks valid
   signatures.
2. **`blake2b` has no `New224`.** Use `blake2b.New(28, nil)`.
3. **Cardano bech32 has no length limit.** Standard `bech32.Decode` enforces
   BIP-173's 90-char cap; base addresses exceed it. Use `DecodeNoLimit`.
4. **`ed25519.Verify` panics on a wrong-length key.** Validate `len(x)==32`
   (and `len(sig)==64`) before calling, and return a typed error instead.

## 4. Package structure (hexagonal seams)

This is a pure, deterministic library — there is no network/filesystem/clock to
isolate. The hexagonal payoff here is **insulating the domain (CIP-8/19/30
rules) from the specific codec libraries**, so swapping fxamacker or btcsuite
never touches the public API or the verification logic.

```
cip30/                      (package cip30 — public API)
  cip30.go                  DataSignature, Verify, VerifyOption, Parse, Signature
  errors.go                 typed/sentinel errors
  doc.go                    package doc (exists)
  internal/
    cose/                   COSE_Sign1 + COSE_Key decode, Sig_structure assembly
      cose.go
    address/                CIP-19 bech32 decode + header parse + credential extract
      address.go
```

- `internal/cose` owns fxamacker/cbor and returns our own structs (decoded
  protected map, raw protected bytes, payload, hashed flag, signature, public
  key). It exposes a `SigStructure(...)` helper that marshals the `Signature1`
  array.
- `internal/address` owns btcsuite/bech32, parses the CIP-19 header, and exposes
  credential extraction (network, type, payment/stake key-hash).
- The root package orchestrates and calls `crypto/ed25519` + `blake2b` directly.

**On interfaces / ports:** do **not** put `crypto/ed25519` or `blake2b` behind an
interface by default. They are deterministic, fast, stdlib-grade pure functions;
an indirection buys nothing and the go-style guidance is to add interfaces at the
consumer only when a real second implementation or test seam demands it. If an
HSM/remote-verify need ever appears, introduce a port then. Keep `internal/cose`
and `internal/address` as concrete packages with small surfaces.

## 5. Public API (proposal)

Idiomatic Go shaped by the spec. `Verify` returns a structured **`Result`** that
reports *exactly what was checked and how it matched* — not just yes/no — so an
auth backend can apply its own policy (e.g. "I only accept a payment-key match").
The `(*Result, error)` split keeps "couldn't process the input" (`error`)
separate from "processed; here is the verdict" (`Result`). `Parse` is the lower
level for callers who want the authenticated identity (key / address / payload).

```go
package cip30

// DataSignature is the CIP-30 signData() result. Both fields are hex-encoded
// CBOR, exactly as a wallet returns them.
type DataSignature struct {
    Signature string // hex(cbor<COSE_Sign1>)
    Key       string // hex(cbor<COSE_Key>)
}

// Verify checks the Ed25519 signature and, when the matching options are given,
// the payload message and the signing address. It returns a Result describing
// each check performed. A non-nil error means the input could not be processed
// (bad hex/CBOR, wrong key/signature length, unsupported address) — distinct
// from a check that ran and failed, which is reported in the Result.
func Verify(sig DataSignature, opts ...VerifyOption) (*Result, error)

// Result reports what Verify checked. Use Valid for the overall verdict; inspect
// the sub-results to learn how each check resolved.
type Result struct {
    SignatureValid bool              // the Ed25519 signature verified
    Message        *MessageCheck     // non-nil iff WithMessage was supplied
    Address        *AddressCheck     // non-nil iff WithAddress/WithEmbeddedAddress was supplied
    PublicKey      ed25519.PublicKey // the 32-byte key from the COSE_Key
    KeyHash        []byte            // blake2b-224(PublicKey): the 28-byte credential
}

// Valid is the overall verdict: signature valid AND every requested check passed.
func (r *Result) Valid() bool

type MessageCheck struct {
    Matched bool // payload equals the expected message
    Hashed  bool // payload was blake2b-224(message) rather than the raw message
}

type AddressCheck struct {
    Matched    bool          // satisfied under the active (default / strict) policy
    MatchedVia Credential    // which credential the key hash matched (or None)
    Strict     bool          // whether StrictAddress was in force
    Source     AddressSource // caller-supplied vs the signer's embedded header address
    Type       AddressType   // base / enterprise / pointer / reward
    Network    Network       // mainnet / testnet
}

// Credential names which part of an address the signing key hash matched.
type Credential uint8

const (
    CredentialNone    Credential = iota // nothing matched
    CredentialPayment                   // matched the payment key hash
    CredentialStake                     // matched the delegation/stake key hash
)

// AddressSource records where the checked address came from.
type AddressSource uint8

const (
    AddressSupplied AddressSource = iota // from WithAddress
    AddressEmbedded                      // from the COSE_Sign1 protected "address" header
)

type VerifyOption func(*verifyConfig)

// WithMessage checks the signed payload against the expected message. Following
// the reference verifier: if the COSE_Sign1 sets unprotected "hashed": true, the
// message is hashed with blake2b-224 before comparison UNLESS it is already a hex
// string (treated as a pre-computed digest, via an is-hex guard). When the
// COSE_Sign1 carries no embedded payload (detached), the message reconstructs the
// signed bytes so the signature check still runs (and the message is then proven
// by the signature itself).
func WithMessage(message []byte) VerifyOption

// WithAddress checks that blake2b-224(publicKey) matches a key-hash credential of
// the given address. Per CIP-30, the address may be bech32 (addr/stake, mainnet
// or _test) OR hex-encoded raw bytes; both are accepted. DEFAULT policy mirrors
// the reference verifier: for a base address EITHER the payment OR the
// delegation (stake) credential is accepted, and Result.Address.MatchedVia
// reports which. Reward (stake) addresses match only their stake key; enterprise
// addresses only their payment key.
func WithAddress(addr string) VerifyOption

// WithEmbeddedAddress checks the key against the address embedded in the
// COSE_Sign1 protected header — the address the signer itself claimed — instead
// of a caller-supplied one. Same credential logic; StrictAddress applies; the
// result carries Source=AddressEmbedded. Use this when the signature is the
// identity ("which address signed?"): it closes the impersonation vector of
// trusting Signature.Address unverified. Mutually exclusive with WithAddress.
func WithEmbeddedAddress() VerifyOption

// StrictAddress tightens WithAddress / WithEmbeddedAddress: a base address must
// match its PAYMENT credential — a stake-only match becomes a failure
// (Matched=false, MatchedVia=CredentialStake, Strict=true). This proves control
// of the address's funds, not merely its delegation. No effect on
// enterprise/reward addresses, whose only key-hash credential is unambiguous.
func StrictAddress() VerifyOption
```

For identification use cases (auth backends usually want *who* signed, not just
yes/no):

```go
// Parse decodes a DataSignature into its COSE components without verifying.
func Parse(sig DataSignature) (*Signature, error)

// Signature is a decoded, not-yet-verified CIP-30 data signature.
type Signature struct {
    PublicKey ed25519.PublicKey // 32-byte key from COSE_Key x(-2)
    Payload   []byte            // embedded payload; nil/empty if detached
    Hashed    bool              // unprotected "hashed" flag
    Address   []byte            // SELF-ASSERTED address from the protected header (signed but
                                //   attacker-chosen): trust only after WithEmbeddedAddress
    // unexported: raw protected bytes, signature, decoded protected map
}

func (s *Signature) Verify() bool                                  // signature only
func (s *Signature) VerifyMessage(message []byte) *MessageCheck
func (s *Signature) MatchesAddress(addr string, opts ...VerifyOption) (*AddressCheck, error)

// KeyHash returns blake2b-224(PublicKey) — the 28-byte credential to compare
// against an address or persist as a stable identity.
func (s *Signature) KeyHash() []byte
```

`Verify(sig, opts...)` is sugar over `Parse` + these methods. The one-shot is the
headline; `Parse` is the power tool.

### Alternatives considered (decide during implementation)

- **Error-only `Verify(...) error`** (typed sentinels per failed check) —
  simplest, but it cannot express "matched, but via the *stake* credential,"
  which is exactly the transparency we want. Rejected in favor of `Result`.
- **`(bool, error)`** — same transparency gap, and invites
  `if ok, _ := Verify(...)` that silently drops decode errors. Rejected.
- **A `Verifier` struct** holding expected message/address — heavier than
  functional options for a stateless one-call operation.

## 6. Constants & domain types

Internal (in `internal/cose` unless they need to be public):

```go
// COSE algorithm / key-type / curve values (RFC 8152, CIP-8/30)
algEdDSA   = -8
keyTypeOKP = 1
curveEd25519 = 6

// COSE_Sign1 protected/unprotected labels
labelAlg     = 1
labelKid     = 4
headerAddress = "address"   // protected, CIP-8 extension
headerHashed  = "hashed"    // unprotected, CIP-8 extension

// COSE_Key labels
keyLabelKty = 1
keyLabelKid = 2
keyLabelAlg = 3
keyLabelCrv = -1
keyLabelX   = -2

sigContextSignature1 = "Signature1"

blake2b224Size = 28
ed25519KeySize = 32
ed25519SigSize = 64
```

CIP-19 address model (`internal/address`):

```go
type Network uint8 // 0 = testnet, 1 = mainnet

type AddressType uint8 // header >> 4: 0..7 Shelley, 14/15 reward, 8 Byron

type Address struct {
    Network    Network
    Type       AddressType
    Payment    Credential // for base/enterprise/pointer (addr…)
    Stake      Credential // for base (deleg part) and reward (stake…)
}

type Credential struct {
    Hash     []byte // 28 bytes
    IsScript bool   // true for odd Shelley payment types / type 15 — cannot match a key
}
```

## 7. Verification algorithm

```
Verify(sig, opts):
  cfg ← apply(opts)                       // optional message, optional address

  # ---- decode (parse) ----
  sBytes ← hexDecode(sig.Signature)
  arr    ← cborDecode(sBytes)             // require array len 4
  protectedRaw ← arr[0] as bstr           // KEEP these bytes verbatim
  unprotected  ← arr[1] as map
  payload      ← arr[2] as bstr|nil
  signature    ← arr[3] as bstr           // require len 64
  protectedMap ← cborDecode(protectedRaw) // separate decode, read-only
  require protectedMap[alg] == EdDSA(-8)
  hashed ← bool(unprotected["hashed"])    // default false
  embeddedAddr ← protectedMap["address"]  // optional raw bytes

  kBytes ← hexDecode(sig.Key)
  keyMap ← cborDecode(kBytes)
  require keyMap[kty]==OKP, keyMap[alg]==EdDSA, keyMap[crv]==Ed25519
  x ← keyMap[x(-2)]                        // require len 32

  res ← &Result{ PublicKey: x, KeyHash: blake2b224(x) }

  # digest(msg, hashed): expected payload bytes for a message (reference parity)
  #   not hashed            → msg
  #   hashed & msg is hex   → hexDecode(msg)   # msg is already a blake2b-224 digest
  #   hashed & msg not hex  → blake2b224(msg)

  # ---- 1. signature (always) ----
  detached ← cfg.message != nil and empty(payload)   # nil or zero-length payload
  payloadForSig ← detached ? digest(cfg.message, hashed) : payload
  sigStruct ← cborMarshal(["Signature1", protectedRaw, h'', payloadForSig])
  res.SignatureValid ← ed25519.Verify(x, sigStruct, signature)

  # ---- 2. message check (optional) ----
  if cfg.message != nil:
      if detached:                                   # message IS the signed payload…
          res.Message ← { Hashed: hashed, Matched: res.SignatureValid }  # …proven by the sig
      else:
          res.Message ← { Hashed: hashed, Matched: bytesEqual(payload, digest(cfg.message, hashed)) }

  # ---- 3. address check (optional; WithAddress XOR WithEmbeddedAddress) ----
  addr, source ← cfg.useEmbedded ? (embeddedAddr, Embedded) : (cfg.address, Supplied)
  if addr present:
      res.Address ← matchAddress(addr, res.KeyHash, cfg.strict)   # see §8; accepts bech32 or hex
      res.Address.Source ← source

  return res, nil

# Result.Valid() = SignatureValid
#                  && (Message == nil || Message.Matched)
#                  && (Address == nil || Address.Matched)
```

Malformed input — bad hex, bad CBOR, `len(arr) != 4`, `len(x) != 32`,
`len(sig) != 64`, unsupported/undecodable address — returns `(nil, wrapped
error)` from the decode/parse stage, never a `Result`.

Notes:

- **Empty payload** means CBOR `nil` (`0xf6`) **or** zero-length bstr (`0x40`).
  Both trigger reconstruction-from-message. With no payload *and* no message, the
  `Sig_structure` payload is `h''` and the signature will (correctly) fail —
  matching the reference's "null payload ⇒ false" vector.
- When the payload is detached, the message *is* the signature check (a wrong
  message yields wrong reconstructed bytes → verify fails), so there is no
  separate equality step in that branch.
- **Detached + hashed** (rare, and *untested* in the reference) reconstructs with
  the raw 28-byte `blake2b224(message)`. The reference's code path here appears to
  use the UTF-8 bytes of the hex digest instead — a likely bug we deliberately do
  not replicate. Confirm against a real wallet vector before finalizing.

## 8. Address matching (CIP-19)

```
matchAddress(addr, keyHash[28], strict) AddressCheck:
  raw    ← bech32DecodeNoLimit(addr) ∘ convertBits(5→8)   # or hex-decode if raw hex
  header ← raw[0]; type ← header>>4; net ← header & 0x0f
  ac     ← { Type: type, Network: net, Strict: strict, MatchedVia: None }
  # network sanity: addr_test/stake_test HRP ⇒ net==0; addr/stake ⇒ net==1

  # which credentials are KEY hashes (per the CIP-19 type table)?
  #   payment key hash @ raw[1:29]   for types 0,2,4,6   (odd payment types ⇒ script)
  #   stake   key hash @ raw[1:29]   for type 14         (15 ⇒ script)
  #   deleg   key hash @ raw[29:57]  for types 0,1       (2,3 ⇒ script; 4,5 ⇒ pointer; 6,7 ⇒ none)

  if   type in {0,2,4,6} and raw[1:29]  == keyHash: ac.MatchedVia ← Payment
  elif type == 14        and raw[1:29]  == keyHash: ac.MatchedVia ← Stake   # reward: stake IS the key
  elif type in {0,1}     and raw[29:57] == keyHash: ac.MatchedVia ← Stake   # base delegation key

  ac.Matched ←  (ac.MatchedVia == Payment)
             or (ac.MatchedVia == Stake and type == 14)                    # reward: its only key
             or (ac.MatchedVia == Stake and type in {0,1} and not strict)  # base fallback
  return ac
```

- Credential is `blake2b-224(x)` (28 bytes) — the `PaymentKeyHash` /
  `StakeKeyHash` from CIP-19.
- **Script-hash credentials** (odd Shelley payment types; the delegation part of
  types 2/3; type 15) can never equal a key hash → `MatchedVia=None` (analogous
  to CIP-30 `AddressNotPK`).
- **Base-address stake fallback (default ON, reference parity):** when the key is
  the *delegation* key of a base address (types 0/1) rather than its payment key,
  the match still succeeds and `MatchedVia=Stake` records it. `StrictAddress`
  flips that to `Matched=false`. Reward addresses are unaffected — their sole
  key-hash credential *is* the stake key, so `MatchedVia=Stake` always counts
  there.
- **Pointer (4/5) and enterprise (6/7)** carry no inline delegation key hash, so
  only their (even-type) payment key can match — no fallback applies.
- Network is taken from the HRP; assert it agrees with the header nibble and
  reject inconsistent inputs.

## 9. Edge cases & open decisions

Behavioral oracle: the 14 vectors in
`ref/cardano-verify-datasignature/index.test.ts` (mainnet/testnet,
stake/enterprise/base, hashed/plain, embedded/detached/null payload,
wrong key/message/address). Port them verbatim (§10).

| # | Case | Handling |
|---|---|---|
| 1 | Embedded payload + correct message | message equality passes |
| 2 | Detached/empty/null payload + message | reconstruct payload from message; sig check is the message check |
| 3 | `hashed=true` | compare/sign over `blake2b-224(message)` |
| 4 | Enterprise (type 6) | match payment key-hash only |
| 5 | Base (type 0/1) | match payment; stake fallback by default (`MatchedVia=Stake`), failed under `StrictAddress` |
| 6 | Reward (type 14) | match stake key-hash (`MatchedVia=Stake`, always counts) |
| 7 | Testnet vs mainnet | HRP + header nibble |
| 8 | Wrong key / message / address | typed error (not a decode error) |
| 9 | Byron (type 8) / script credential | unsupported → typed error / no match |
| 10 | Malformed: bad hex, bad CBOR, len≠4, x≠32, sig≠64 | wrapped parse error, never panic |

**Resolved (session 002):**

- **R1. Return shape** → `Verify(...) (*Result, error)`. A structured `Result`
  (overall `Valid()` plus per-check detail) beats error-only/`(bool, error)`
  because it can report *how* the address matched. `error` is reserved for
  unprocessable input. Keep this shape consistent across `Verify` and the
  `Signature` methods.
- **R4. Base-address stake-key fallback** → **default = reference parity** (a
  base address is satisfied by its payment *or* delegation key), with
  `Result.Address.MatchedVia` disclosing which. **`StrictAddress()`** makes a
  stake-only match fail for callers who require proof of payment-key control.
  This pairs the transparent result (decide-for-yourself) with an opt-in hard
  guarantee. Confirm `MatchedVia` semantics against real wallet output.

- **R2. `hashed` + pre-hashed message** → **follow the reference.** `WithMessage`
  accepts either the raw plaintext (hashed with blake2b-224 when `hashed=true`) or
  an already-hex digest (used as-is, via the is-hex guard). Caveat replicated: a
  raw message that happens to be all-hex is treated as pre-hashed. (The detached +
  hashed reconstruction follows the *correct* hash bytes, not the reference's
  apparent bug — see §7.)
- **R3. Embedded protected-header `address`** → **expose and offer to check it.**
  `Signature.Address` carries the raw bytes, documented as self-asserted /
  unverified; `WithEmbeddedAddress()` runs the credential check against it
  (`Result.Address.Source = AddressEmbedded`), closing the impersonation vector of
  trusting it blindly (§10). Mutually exclusive with `WithAddress`.
- **R5. Address input forms** → **CIP-faithful.** `WithAddress` accepts bech32
  (`addr`/`stake`, mainnet or `_test`) *or* hex-encoded raw bytes, per CIP-30's
  "must accept either format for inputs."

**Still open (minor, resolve while implementing):** none blocking. Confirm the
detached+hashed reconstruction (§7) and the `MatchedVia` semantics against a real
wallet vector during hardening.

## 10. Security considerations

This is an **authentication** primitive; the threat model is an attacker
supplying a crafted `DataSignature`.

- **Bind key → identity explicitly.** The only thing that proves "key K controls
  address A" is `blake2b-224(K) == credential(A)`. The protected-header
  `"address"` is attacker-chosen at signing time (though signed), so it proves
  only what the signer *claimed*. Auth callers must check the key against an
  address: `WithAddress` for one they independently expect, or
  `WithEmbeddedAddress` to validate the header's self-asserted address against the
  key. Never read `Signature.Address` as "who signed" without one of those — it is
  attacker-chosen.
- **Payment vs delegation control are different claims.** A base address's
  payment and stake parts may belong to different parties (CIP-19 "mangled"
  addresses). A default (`MatchedVia=Stake`) match proves control of the
  delegation key, *not* the funds. `Result.Address.MatchedVia` exposes which
  credential matched so the caller can enforce policy; `StrictAddress()` rejects
  a stake-only match outright when proof of payment-key control is required.
- **No replay protection here.** Identical inputs verify identically forever.
  Callers must bind each signature to a fresh server-issued nonce/challenge in
  the signed message and reject reuse. Document this loudly; it's the most likely
  misuse.
- **Constant-time / panics.** `ed25519.Verify` is fine; ensure no code path
  panics on hostile input (length checks before `Verify`, defensive CBOR
  decoding). Add a Go fuzz target over `Verify` to guarantee it.
- **Strictness.** Reject unexpected `alg`/`kty`/`crv`, oversized inputs, and
  inconsistent network nibbles rather than coercing.

## 11. Test strategy

Per TECH_NOTES: behavior-first, and **functional testing before "complete."**

1. **Golden vectors (primary oracle).** Table-driven test porting all 14
   `index.test.ts` cases with their exact hex. Each asserts the same overall
   verdict as the reference, and — for the address cases — also asserts
   `Result.Address.MatchedVia` (the base-address "payment key" test must report
   `Stake`, since that vector's key is the delegation key) and that
   `StrictAddress()` turns those stake-only matches into failures. Do **not**
   copy the reference's test bug (one case passes the address in the `message`
   slot, ~line 103); keep the corrected intent.
2. **Unit tests per internal package** — `cose` (decode, `Sig_structure` byte
   exactness, hashed/detached payload), `address` (header parse, each type,
   testnet/mainnet, script vs key, Byron rejection).
3. **Functional / integration.** Capture one or two *real* `DataSignature`s from
   a live wallet (Eternl / Lace / Nami) as fixtures and verify end-to-end — proof
   the library works against real wallet output, not just the reference vectors.
4. **Negative & robustness.** Malformed hex/CBOR, truncated arrays, wrong
   lengths → typed errors, no panics. A native Go **fuzz** target on `Verify`.
5. **Optional cross-check.** A test that runs the happy path through
   `veraison/go-cose` to corroborate our hand-rolled `Sig_structure`.

Skills to load when implementing: `go-style`, `go-testing`, and (for the fuzz /
perf-sensitive bits) `go-benchmarking`.

## 12. Suggested implementation milestones (agile)

1. **Walking skeleton** — `DataSignature`, `Parse`, decode COSE_Sign1 + COSE_Key,
   `Signature.Verify()` (signature only). Green on the no-message/no-address
   golden vectors. *Prove the core before adding options.*
2. **Message check** — `WithMessage`, hashed + detached-payload reconstruction.
   Green on all message vectors.
3. **Address check** — `internal/address`, CIP-19 parse (bech32 + hex input),
   `WithAddress`, `WithEmbeddedAddress`, `StrictAddress`, `MatchesAddress`. Green
   on all address vectors incl. `MatchedVia` / `Source` / strict assertions.
4. **Hardening** — typed errors, fuzz target, real-wallet fixtures, docs, then
   resolve the §9 open decisions against observed behavior.

## 13. References

- [CIP-30 — dApp-Wallet bridge / `signData` / `DataSignature`][CIP-30]
- [CIP-8 — Message Signing (COSE_Sign1, Sig_structure, hashed)][CIP-8]
- [CIP-19 — Cardano Addresses (header byte, credentials)][CIP-19]
- [`cardano-verify-datasignature` — canonical TS reference][ref-ts]
  (`ref/cardano-verify-datasignature/index.ts` + `index.test.ts`)
- RFC 8152 (COSE), RFC 9053; RFC 7693 (BLAKE2)

[CIP-30]: https://github.com/cardano-foundation/CIPs/tree/master/CIP-0030
[CIP-8]: https://github.com/cardano-foundation/CIPs/tree/master/CIP-0008
[CIP-19]: https://github.com/cardano-foundation/CIPs/tree/master/CIP-0019
[ref-ts]: https://github.com/cardano-foundation/cardano-verify-datasignature
