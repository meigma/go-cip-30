---
id: 002
title: CIP-30 design proposal
started: 2026-06-23
---

## 2026-06-23 17:27 — Kickoff
Goal for the session: produce a *temporary* design proposal document, written
into this session's journal, that future sessions will use as the working
resource for implementing the `cip30` library. The doc is scaffolding for design
alignment — not a permanent committed artifact and not the implementation itself.

Current state of the world:
- Repo is a library-only Go module `github.com/meigma/go-cip-30`, public API at
  the repo root in `package cip30`. Only a `doc.go` placeholder exists; no CIP-30
  API code yet (session 001 rebranded the template and stopped before any API).
- Scope (from TECH_NOTES + session 001): tools to validate CIP-30 data
  signatures for authentication/identification — verify a message was signed by a
  key, optionally matching a wallet address. NOT an HTTP framework/middleware;
  transport is the caller's job.
- Reference material is pulled via `moon run setup-ref` into the gitignored
  `ref/` dir: `ref/cardano-verify-datasignature` (TS reference impl, Apache-2.0)
  and `ref/CIPs` (authoritative spec source). Need to confirm these are cloned
  locally before designing against them.
- Architecture constraints (TECH_NOTES): hexagonal — keep business logic
  isolated from external adapters; prefer functional testing before "complete";
  agile, prototype-early approach.

Plan (rough):
- Confirm `ref/` is populated (run `moon run setup-ref` if not); read the TS
  reference impl and the relevant CIP-30 spec sections (data-signature / CIP-8
  COSE_Sign1, address matching).
- Draft the design proposal in this session's journal: scope, public API surface
  for `package cip30`, types, verification flow, hexagonal seams, edge cases, and
  test strategy.
- Keep it labeled temporary; it informs future implementation sessions.

Awaiting the user's go-ahead before substantive design work.

## 2026-06-23 17:40 — Spec + reference analysis
Ran `moon run setup-ref` (ref/ was empty) — both reference repos now cloned.
User decisions for the design: (1) **spec-first**, TS impl as edge-case
cross-check; (2) **lean on established libs** (maintained CBOR/COSE + stdlib
ed25519). Launched a background agent to survey the Go ecosystem
(CBOR/COSE/blake2b/bech32) — result pending.

Read CIP-8 (message signing), CIP-19 (addresses), CIP-30 (§DataSignature +
signData), and the TS reference `index.ts` + `index.test.ts`. Consolidated
understanding (verified by hand-decoding the primary test vector):

**What a CIP-30 DataSignature is.** `{ signature: hex(cbor<COSE_Sign1>), key:
hex(cbor<COSE_Key>) }`.
- `COSE_Sign1 = [protected: bstr(.cbor map), unprotected: map, payload: bstr/nil,
  signature: bstr]` (a 4-element CBOR array).
- Protected header map (signed): `alg(1) = EdDSA(-8)`; `"address" = raw address
  bytes` (no CBOR tag wrapper); optional `kid(4)`.
- Unprotected header map (not signed): `"hashed": bool`; optionally a CIP-8
  `version`.
- `COSE_Key` map: `kty(1)=OKP(1)`, `alg(3)=EdDSA(-8)`, `crv(-1)=Ed25519(6)`,
  `x(-2)=<32-byte raw public key>`, optional `kid(2)`.

**Core verification (always).** Build the COSE `Sig_structure` and Ed25519-verify
it:
`Sig_structure = ["Signature1", body_protected: <protected bstr>, external_aad:
h'' , payload: <payload bstr>]`. CBOR-encode it, then
`ed25519.Verify(x, cbor(Sig_structure), signature)`. CIP-30 sets no external_aad
(empty) and does not hash inside Sig_structure beyond the `hashed` payload
convention.

**Optional message check.** Caller passes expected plaintext.
- `isHashed = unprotected["hashed"]`.
- If embedded payload is nil/empty, reconstruct the signed payload from the
  message: `blake2b224(message)` if hashed, else raw `message` bytes — so the
  signature verify uses the right payload (the "payload known to both parties /
  detached payload" CIP-8 case).
- Compare embedded payload to the (optionally blake2b224-hashed) message; mismatch
  ⇒ not verified.

**Optional address check.** Confirm the COSE_Key belongs to a bech32 address.
- Credential = `blake2b224(x)` (28 bytes). (Reference wraps x in a BIP32 key type,
  but the actual op is just blake2b-224 over the 32-byte key — no BIP32 needed for
  verification.)
- Decode the bech32 address (CIP-19): `header byte = type<<4 | network_nibble`;
  for base/enterprise/pointer (`addr…`) the payment credential is bytes[1:29]; for
  reward (`stake…`, type 14) the stake credential is bytes[1:29].
- Match `blake2b224(x)` against the address's relevant key-hash. Reference quirk:
  for a base address it compares the payment part but **falls back** to testing the
  stake part (lets a stake-key signature satisfy a base address). Network derived
  from the `addr_test`/`stake_test` prefix.

**CIP-19 address header.** 1 header byte + payload. Bits[7:4]=type, bits[3:0]=
network (0 testnet / 1 mainnet). Types: 0–3 base (payment+deleg), 4–5 pointer,
6–7 enterprise (payment only), 14–15 reward (stake only), 8 Byron. Even payment
types = key hash, odd = script hash. KeyHash = blake2b-224 (28 bytes). Cardano
bech32 has **no length limit** → must use a no-limit bech32 decode.

**Test vectors.** The 14 hex vectors in `index.test.ts` are the behavioral
ground truth (mainnet/testnet, stake/enterprise/base, hashed/plain, empty payload,
null payload, wrong key/message/address). Port them verbatim as golden tests.
Note a reference test bug (line ~103) passes `address` in the `message` slot —
don't copy that mistake; keep the corrected intent.

Next: fold the library survey into a design doc written to `.journal/002/`
(scope, public API for `package cip30`, internal seams, types, flow, edge cases,
test strategy). Doc is temporary scaffolding for future implementation sessions.

## 2026-06-23 17:55 — Library survey + design draft
Background survey returned. Confirmed dependency set (lean-on-libs):
- **CBOR:** `github.com/fxamacker/cbor/v2` (MIT) — the standard. Decode
  COSE_Sign1 array + COSE_Key map; second decode of the protected bstr.
  **Never re-encode `body_protected`** — sign over the wire bytes.
- **COSE:** *hand-roll* the `Sig_structure` over fxamacker rather than
  `veraison/go-cose` — go-cose treats `external` as external_aad (no hook for
  CIP-30's externally-supplied/detached payload) and re-derives protected bytes
  (mis-verifies non-minimal encodings, their #119). Wire-byte fidelity wins.
  Keep go-cose as an optional test cross-check only.
- **Ed25519:** stdlib `crypto/ed25519`; `x` is a raw 32-byte key (no BIP32);
  validate `len(x)==32` / `len(sig)==64` (Verify panics otherwise).
- **blake2b:** `golang.org/x/crypto/blake2b`, `blake2b.New(28, nil)` (no
  `New224`).
- **bech32:** `github.com/btcsuite/btcd/btcutil/bech32` — must use
  `DecodeNoLimit` (Cardano addresses exceed BIP-173's 90-char cap); parse the
  CIP-19 header byte in-house. Reject Byron/script. No heavy Cardano SDK.
Net deps: 2 third-party + x/crypto + stdlib; only hand-rolled logic is the
~15-line Sig_structure assembly and ~30-line CIP-19 parse.

Wrote the proposal to **`.journal/002/DESIGN.md`** (temporary, clearly marked).
Sections: scope, DataSignature anatomy, deps + gotchas, hexagonal package
seams (`internal/cose`, `internal/address`; no premature crypto interfaces),
public API (`Verify(sig, opts...) error` one-shot + `Parse`/`Signature` for
extracting authenticated identity), constants/types, full verification
algorithm, CIP-19 address matching, edge cases + open decisions, security
(replay protection is the caller's job; bind key→identity via blake2b224(x)),
test strategy (port all 14 reference vectors as golden tests + real-wallet
fixtures + fuzz), and agile milestones (walking skeleton → message → address →
hardening).

Open decisions left for implementation (documented in DESIGN §9): return shape
(error-only vs bool,error); raw vs pre-hashed message input; whether to check
the embedded protected-header address against the key; base-address stake-key
fallback (parity vs strict); accept hex addresses too.

Next: review the draft with the user; refine per feedback. Doc is the resource
for future implementation sessions — not committed to master.

## 2026-06-23 18:20 — Design refinement: address result + strict mode
User reviewed the base-address stake-key fallback (verified concretely: the
reference's "payment address" vector signs with the STAKE key —
blake2b224(b89526…)=18987c…, which is the *delegation* part of base addr
`addr1qxtu4w2rq…`, payment part 97cab943…). User's call, folded into DESIGN.md:
1. **Default = reference parity** (base address satisfied by payment OR stake
   credential). Add **`StrictAddress()`** that makes a stake-only match FAIL —
   strict tightens, rather than the permissive path being opt-in.
2. **Structured output** so the receiver knows exactly what was verified.

API consequence: `Verify` now returns **`(*Result, error)`** (was `error`).
`error` = unprocessable input only; verdict + detail live in `Result`:
- `Result{ SignatureValid, Message *MessageCheck, Address *AddressCheck,
  PublicKey, KeyHash }`, with `Valid()` = AND of requested checks.
- `AddressCheck{ Matched, MatchedVia (Payment|Stake|None), Strict, Type,
  Network }` — `MatchedVia` discloses which credential matched.
Updated §5 (API + Result types + StrictAddress), §7 (algorithm populates
Result), §8 (matchAddress returns AddressCheck; fixed credential/type table —
deleg key hash only in types 0/1; pointer/enterprise payment-only), §9
(resolved R1 return-shape and R4 fallback; 3 decisions still open), §10
(security: payment vs delegation are different claims), §11 (golden tests assert
MatchedVia + strict failure).

Still-open decisions (impl-time): pre-hashed message input; whether to check the
embedded protected-header address against the key; accept hex addresses too.
Committed + pushed.

## 2026-06-23 18:45 — Resolved remaining 3 design decisions
User settled the last open decisions; all folded into DESIGN.md (§5/§7/§9/§10):
- **R2 pre-hashed message** → follow the reference: `WithMessage` accepts raw
  plaintext (hashed iff `hashed`) OR an already-hex digest (is-hex guard,
  quirk replicated). Added a `digest(msg, hashed)` helper to §7. Flagged that
  the reference's detached+hashed reconstruction looks buggy (uses UTF-8 bytes
  of the hex digest) and is untested — we use the correct 28 raw hash bytes,
  confirm against a real vector.
- **R3 embedded address** → my recommendation, accepted: expose
  `Signature.Address` (raw, documented self-asserted/unverified) AND add
  **`WithEmbeddedAddress()`** to run the credential check against the header's
  address. Reuses matchAddress; `StrictAddress` composes; `AddressCheck.Source`
  (`AddressSupplied`/`AddressEmbedded`) records origin. Rationale: the embedded
  address is signed but attacker-chosen, so trusting it unverified is an
  impersonation vector — making the check a one-liner closes it.
- **R5 hex address input** → CIP-faithful: `WithAddress` accepts bech32 OR
  hex-encoded raw bytes ("must accept either format for inputs").

All five §9 decisions now resolved; nothing blocking remains. The design is
ready to hand to an implementation session. Committed + pushed.
