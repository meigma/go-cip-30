---
id: 002
title: CIP-30 design proposal
date: 2026-06-23
status: complete
repos_touched: []
related_sessions: [001]
---

## Goal
Produce a **temporary design proposal document** in this session's journal to
serve as the working resource for implementing the `cip30` library in a future
session. No implementation code — design only.

## Outcome
Goal met. The proposal lives at **`.journal/002/DESIGN.md`** — read it first when
starting CIP-30 implementation. It is comprehensive and all open design questions
were resolved during the session, so an implementation session can start from it
directly. No code was written and no PR was opened (design-only session); the
only artifacts are journal files on `journal/jmgilman`. The default branch
(`master`) is untouched.

`DESIGN.md` covers: scope, `DataSignature`/COSE_Sign1/COSE_Key anatomy, the
dependency set (+ gotchas), hexagonal package seams, the full public API, all
constants/types, the step-by-step verification algorithm, CIP-19 address
matching, an edge-case table, security considerations, the test strategy, and
agile implementation milestones.

## Key Decisions
- **Spec-first, lean on established libs** (user calls). Design from CIP-8/19/30;
  use the TS reference (`ref/cardano-verify-datasignature`) only as an edge-case
  oracle. Dependency set: `fxamacker/cbor/v2`, stdlib `crypto/ed25519`,
  `x/crypto/blake2b` (`New(28,nil)`), `btcsuite` bech32 (`DecodeNoLimit`).
- **Hand-roll the COSE `Sig_structure`** over fxamacker rather than depend on
  `veraison/go-cose` -> wire-byte fidelity (never re-encode `body_protected`) and
  clean support for CIP-30's detached/`hashed` payload, which go-cose fights.
- **No BIP32 needed for verification** -> the COSE_Key `x` is a raw 32-byte
  Ed25519 key; the only op on it beyond `ed25519.Verify` is `blake2b224(x)`.
- **`Verify` returns `(*Result, error)`**, not a bare bool/error -> the structured
  `Result` reports *how* the address matched (`AddressCheck.MatchedVia` =
  Payment/Stake) so callers can apply policy; `error` is reserved for
  unprocessable input.
- **Address matching: reference-faithful by default + opt-in `StrictAddress()`**
  -> a base address is satisfied by its payment OR delegation key (parity), but
  `StrictAddress()` rejects a stake-only match (proves funds control). The result
  discloses which credential matched. (Investigated concretely: the reference's
  "payment address" test vector actually signs with the *stake* key —
  `blake2b224(b89526…)=18987c…` is the delegation part of `addr1qxtu4w2rq…`.)
- **Pre-hashed message: follow the reference** (`WithMessage` accepts raw text or
  an already-hex digest via an is-hex guard). But the reference's detached+hashed
  *reconstruction* looks buggy (uses UTF-8 bytes of the hex digest) and is
  untested -> we use the correct 28 raw hash bytes; confirm with a real vector.
- **Embedded protected-header `address`: expose AND offer to check it**
  (`WithEmbeddedAddress()`) -> it is signed but attacker-chosen, so trusting
  `Signature.Address` unverified is an impersonation vector; the check closes it.
- **Hex address input accepted** alongside bech32, per CIP-30's "accept either
  format for inputs."
- **Test fixtures via `cardano-signer` (CLI), not a browser wallet** -> generating
  a CIP-30 data signature needs no chain/funds/network. `keygen` + `sign --cip30`
  produce real vectors offline; `verify --cip30` is an independent oracle.

## Changes
No source/repo changes. Journal-only artifacts on `journal/jmgilman`:
- `.journal/002/DESIGN.md` (new) - the design proposal (the deliverable).
- `.journal/002/NOTES.md` - running log (spec analysis, library survey, decisions).
- `.journal/002/SUMMARY.md` (this file); `.journal/INDEX.md` row -> complete;
  `.journal/TECH_NOTES.md` gained a pointer to the design doc.
- Side effect: `moon run setup-ref` populated the gitignored `ref/` dir
  (`cardano-verify-datasignature`, `CIPs`) — local scaffolding, not committed.

## Open Threads
- **Implement the library** — the next session's work. Start from
  `.journal/002/DESIGN.md`; follow its milestones (walking skeleton: decode +
  signature-only `Verify` green on the no-option golden vectors → message →
  address → hardening).
- **Two hardening-time confirmations** (not design blockers), to settle with
  `cardano-signer` vectors: the detached+hashed reconstruction (where we diverge
  from the reference's apparent bug) and the `MatchedVia` payment-vs-stake
  semantics.
- **Optional starter fixtures** — offered to generate a `cardano-signer` fixture
  set this session; deferred as out of design-only scope. A future session can
  produce them to nail down exact CLI sub-flags (keygen → address derivation).
- **DESIGN.md is temporary scaffolding** — supersede/delete once the library and
  its real docs exist; it is not a committed spec.

## References
- **Design proposal: `.journal/002/DESIGN.md`** (read this first for CIP-30 impl).
- Session 001: `.journal/001/SUMMARY.md` (rebrand; left "design doc + API" as next).
- Specs: CIP-30, CIP-8, CIP-19 (in `ref/CIPs/`, also on cardano-foundation/CIPs).
- TS reference: `ref/cardano-verify-datasignature` (index.ts + index.test.ts).
- Fixture/oracle CLI: https://github.com/gitmachtl/cardano-signer
