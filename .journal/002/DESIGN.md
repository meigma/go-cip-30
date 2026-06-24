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

Idiomatic Go shaped by the spec; `nil` error means "verified." Two levels: a
one-shot `Verify` for the common case, and `Parse` for callers who need the
authenticated identity (key / address / payload) afterward.

```go
package cip30

// DataSignature is the CIP-30 signData() result. Both fields are hex-encoded
// CBOR, exactly as a wallet returns them.
type DataSignature struct {
    Signature string // hex(cbor<COSE_Sign1>)
    Key       string // hex(cbor<COSE_Key>)
}

// Verify reports whether sig is cryptographically valid and, when the matching
// options are supplied, whether the signed payload equals an expected message
// and whether the signing key matches a Cardano address.
//
// Returns nil when every requested check passes. A failed check returns a typed
// error (ErrSignatureInvalid / ErrMessageMismatch / ErrAddressMismatch) that is
// inspectable with errors.Is. Malformed input (bad hex, bad CBOR, wrong key or
// signature length, unsupported address) returns a wrapped parse error.
func Verify(sig DataSignature, opts ...VerifyOption) error

type VerifyOption func(*verifyConfig)

// WithMessage checks the signed payload against the expected plaintext, hashing
// it with blake2b-224 iff the COSE_Sign1 sets unprotected "hashed": true. When
// the COSE_Sign1 carries no embedded payload (detached), the message is used to
// reconstruct the signed bytes so the signature check still runs.
func WithMessage(message []byte) VerifyOption

// WithAddress checks that blake2b-224(publicKey) matches the key-hash credential
// of the given bech32 address (addr1/addr_test1/stake1/stake_test1).
func WithAddress(bech32Addr string) VerifyOption
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
    Address   []byte            // raw address bytes from the protected "address" header, if present
    // unexported: raw protected bytes, signature, decoded protected map
}

func (s *Signature) Verify() error                    // signature only
func (s *Signature) VerifyMessage(message []byte) error
func (s *Signature) MatchesAddress(bech32Addr string) (bool, error)

// KeyHash returns blake2b-224(PublicKey) — the 28-byte credential to compare
// against an address or persist as a stable identity.
func (s *Signature) KeyHash() []byte
```

`Verify(sig, opts...)` is sugar over `Parse` + the methods. Both are part of the
proposal; the one-shot is the headline, `Parse` is the power tool.

### Alternatives considered (decide during implementation)

- **`(bool, error)`** instead of error-only — separates "didn't match" from
  "couldn't process." Rejected as the default because it invites
  `if ok, _ := Verify(...)` and silently dropping decode errors; typed errors +
  `errors.Is` give the same information more safely. (Could still offer it.)
- **A `Verifier` struct** holding expected message/address — heavier than
  functional options for a stateless one-call operation. Options are lighter and
  extend cleanly.

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

  # ---- 1. signature (always) ----
  payloadForSig ← payload
  if cfg.message != nil and empty(payload):     # detached payload → rebuild from message
      payloadForSig ← hashed ? blake2b224(cfg.message) : cfg.message
  sigStruct ← cborMarshal(["Signature1", protectedRaw, h'', payloadForSig])
  if not ed25519.Verify(x, sigStruct, signature): return ErrSignatureInvalid

  # ---- 2. message check (optional, only if a payload is embedded) ----
  if cfg.message != nil and not empty(payload):
      want ← hashed ? blake2b224(cfg.message) : cfg.message
      if not bytesEqual(payload, want): return ErrMessageMismatch

  # ---- 3. address check (optional) ----
  if cfg.address != "":
      if not matchAddress(cfg.address, blake2b224(x)): return ErrAddressMismatch

  return nil
```

Notes:

- **Empty payload** means CBOR `nil` (`0xf6`) **or** zero-length bstr (`0x40`).
  Both trigger reconstruction-from-message. With no payload *and* no message, the
  `Sig_structure` payload is `h''` and the signature will (correctly) fail —
  matching the reference's "null payload ⇒ false" vector.
- When the payload is detached, the message *is* the signature check (a wrong
  message yields wrong reconstructed bytes → verify fails), so there is no
  separate equality step in that branch.

## 8. Address matching (CIP-19)

```
matchAddress(bech32Addr, keyHash[28]) bool:
  hrp, data5 ← bech32.DecodeNoLimit(bech32Addr)
  raw ← convertBits(data5, 5→8)
  header ← raw[0]; type ← header>>4; net ← header & 0x0f
  # network sanity: hrp prefix (addr_test/stake_test ⇒ testnet) must agree with net nibble
  switch type:
    case 0..5:  payment ← raw[1:29]                 # base / pointer: payment credential
                if type is even (key-hash) and payment==keyHash: return true
                # reference fallback: allow the signing key to be the STAKE key of a base addr
                if type in {0,1,2,3} (has deleg): stake ← raw[29:57]
                   return stake==keyHash
                return false
    case 6,7:   payment ← raw[1:29]                 # enterprise (no deleg)
                return type==6 and payment==keyHash
    case 14,15: stake ← raw[1:29]                   # reward
                return type==14 and stake==keyHash
    case 8:     return false                        # Byron — unsupported
    default:    return false
```

- Credential is `blake2b-224(x)` (28 bytes) — the `PaymentKeyHash` / `StakeKeyHash`
  from CIP-19.
- **Script-hash credentials** (odd Shelley payment types, type 15) can never
  equal a key hash → no match (analogous to CIP-30 `AddressNotPK`).
- **Reference parity quirk (flag for decision):** for a base address the
  reference compares the payment part but *falls back* to the stake part, letting
  a stake-key signature satisfy a base address. Reproduced above for parity;
  consider making it strict or opt-in (see §9).
- Network is taken from the bech32 HRP (`addr`/`stake` vs `_test`); we should
  *also* assert it agrees with the header nibble and reject inconsistent inputs.

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
| 5 | Base (type 0) | match payment, fallback to stake (parity) |
| 6 | Reward (type 14) | match stake key-hash |
| 7 | Testnet vs mainnet | HRP + header nibble |
| 8 | Wrong key / message / address | typed error (not a decode error) |
| 9 | Byron (type 8) / script credential | unsupported → typed error / no match |
| 10 | Malformed: bad hex, bad CBOR, len≠4, x≠32, sig≠64 | wrapped parse error, never panic |

**Open decisions (resolve while implementing):**

1. **Return shape** — error-only (recommended) vs `(bool, error)`. Pick one,
   keep it consistent across `Verify` and the methods.
2. **`hashed` + pre-hashed message** — the reference accepts *either* the raw
   message (it hashes) *or* an already-hex blake2b-224 digest (used as-is, via a
   `!isHex` guard). Proposal: `WithMessage([]byte)` always means raw plaintext
   and we hash iff `hashed`; expose pre-hashed input as a separate explicit
   option only if a real caller needs it. Decide.
3. **Embedded protected-header `address`** — it is signed (tamper-evident) but
   the reference never checks it against the key. Proposal: expose it on
   `Signature.Address`, and optionally offer a check that
   `blake2b-224(x)` matches the embedded address (useful for auth: see §11).
4. **Base-address stake-key fallback** — parity vs strict. Strict is safer for
   identification ("this is the *payment* key of this address"); parity matches
   the reference. Lean: implement strict-by-default with the fallback behind an
   option, but confirm against real wallet output first.
5. **Address input forms** — CIP-30 says addresses may be bech32 *or* hex bytes.
   `WithAddress` should likely accept both (bech32 primary; raw hex as a
   convenience), mirroring CIP-30's "accept either format for inputs."

## 10. Security considerations

This is an **authentication** primitive; the threat model is an attacker
supplying a crafted `DataSignature`.

- **Bind key → identity explicitly.** The only thing that proves "key K controls
  address A" is `blake2b-224(K) == credential(A)`. The protected-header
  `"address"` is attacker-chosen at signing time (though signed), so it proves
  only what the signer *claimed*. Auth callers must use `WithAddress` (or
  `MatchesAddress`) against an address they independently expect — never trust
  the embedded address alone.
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
   `index.test.ts` cases with their exact hex. Each asserts the same verdict as
   the reference. Do **not** copy the reference's test bug (one case passes the
   address in the `message` slot, ~line 103); keep the corrected intent.
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
3. **Address check** — `internal/address`, CIP-19 parse, `WithAddress` /
   `MatchesAddress`. Green on all address vectors.
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
