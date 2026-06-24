---
id: 005
title: Security review findings
started: 2026-06-24
---

## 2026-06-24 09:17 — Kickoff
Goal for the session: address a few security review findings in the `cip30`
verification library. The specific findings have not been shared yet — waiting on
the developer to provide them before scoping the work.

Current state of the world:
- The `cip30` library is fully implemented and on `master` (PR #6, `8fd783d`),
  documented (PR #7, `4c03f95`), and has had one post-docs follow-up fix:
  PR #8 `c26c4ce` "fix(address): enforce bech32 HRP address class".
- `master` HEAD is `c26c4ce`. Tip of the journal branch is the session 004 close.
- Architecture (per TECH_NOTES): `package cip30` at the repo root over
  `internal/cose` (CBOR/COSE codec) and `internal/address` (CIP-19 parsing);
  matching policy + public vocabulary live in the root. Key security invariants
  already in place: verbatim `body_protected` bytes (never re-encode), strict CBOR
  decode rejecting duplicate COSE map keys, length-guard before `ed25519.Verify`,
  `h''` for empty/detached payload, script credentials never match a key,
  `StrictAddress` to reject stake-only matches, raw blake2b-224 for detached+hashed.
- Test oracle: proto-managed `cardano-signer` functional fixtures + 15 reference
  golden vectors + `FuzzVerify`. Gate is `moon run root:check`.

Plan: wait for the developer to enumerate the security review findings, then scope
each one (severity, affected code path, fix), confirm approach, branch an
implementation worktree off `master` via `wt`, and integrate via a GitHub PR with
squash merge. Re-run the full check gate (incl. fuzz) before each commit.

## 2026-06-24 09:39 — Finding 1: noncanonical address shapes (PR #9)

**Finding (Codex Security, Low, CWE-20):** `internal/address.Parse` validated
lengths as minimums and ignored bytes outside the fixed credential window, and
routed pointer addresses (CIP-19 types 4/5) through the enterprise-only parser
(no chain-pointer payload required). So a reward address + trailing bytes, or a
29-byte "pointer" with no pointer payload, reached `Result.Valid()==true` via
raw-hex or embedded protected-header input. Matched key hash still belongs to the
signer → identity confusion, not a key-ownership bypass.

**Investigation:** confirmed both address paths funnel through `Parse`
(`Decode` for supplied bech32/hex; `Parse` on the exact COSE byte string for
embedded), and a parse error already surfaces as `ErrDecodeAddress`. Canonical
CIP-19 lengths verified against `ref/CIPs/CIP-0019`: base 57, enterprise 29,
reward 29; pointer = 29 + chain pointer (3 base-128 varints). One existing test
(`internal/address/address_test.go:253`) encoded the bug ("oversized base
tolerated"). Pointer types had zero coverage.

**Decision (developer):** reject pointer addresses as unsupported (like Byron)
rather than add a varint pointer parser — smallest/safest, no attacker-controlled
varint parsing, and only the payment credential was ever matchable anyway.

**Fix (PR #9, branch `fix/address-noncanonical-shapes`):**
- `internal/address/address.go`: exact-length enforcement via new `checkLen`
  (base/enterprise/reward), new sentinel `ErrTrailingBytes`, split
  `fillPaymentOnly` → `fillEnterprise`, pointer types 4/5 → `ErrUnsupportedType`,
  rewrote `Parse` doc.
- `address.go`: godoc note that `AddressPointer` is no longer produced.
- Tests: inverted the oversized-base test; added `TestParseRejectsNonCanonicalShapes`
  (length boundaries + pointer rejection) and root `TestVerifyRejectsNonCanonicalAddress`
  (supplied-hex + embedded paths) via new `sign1WithEmbeddedAddress` helper.
- `docs/docs/security.md`: "Addresses must be canonical" note.

**Verification:** `moon run root:check` green; `go test -fuzz=FuzzVerify
-fuzztime=30s` no panics (6.7M execs); golden/functional fixtures unchanged.
PR #9 opened, CI pending. Lint gotcha: `gochecknoglobals` forbids package-level
`var` in tests → folded the regression table into the test function.

**PR #9 merged** (squash `77bde8e`); developer confirmed LGTM. Worktree + stale
branch cleaned up; local `master` synced.

## 2026-06-24 11:25 — Finding 2: reserved network tags (PR #10)

**Finding (Codex Security, Low, CWE-20):** `internal/address.Parse` stores any
header network nibble, and the public `network()` mapping (`address.go`) collapsed
every non-mainnet value to `Testnet`. CIP-19 defines only nibble 0 (testnet) /
1 (mainnet); 2–15 are reserved. So a raw/embedded address with a reserved nibble
(e.g. reward `0xe2…`) returned `Valid()==true` reporting `Network=Testnet`.
(Developer noted finding 3 of 3 was already addressed previously — this is the
last one.)

**Decision (developer):** **accept but report accurately** (option B), not reject.
Key realization: the internal decoder already preserves the raw nibble; only the
public `network()` mapping collapses it. So the fix is purely root-package and
`Valid()`/matching/`internal/address` are unchanged — a matching credential still
verifies; only the reported `Network` becomes accurate.

**Fix (PR #10, branch `fix/address-reserved-network`):**
- `address.go`: added public `Network` value `NetworkUnknown` (nibble 2–15),
  rewrote `network()` collapse → switch (default → `NetworkUnknown`), added
  `String()` case `"Unknown"`, updated `AddressCheck.Network` godoc.
- Tests: root `TestVerifyReportsReservedNetworkAsUnknown` (supplied hex + embedded;
  supplied path asserts `Valid()==true`, embedded path asserts address-check fields
  since `sign1WithEmbeddedAddress` carries a zero sig), `TestNetworkUnknownString`,
  and internal `TestParsePreservesReservedNetworkNibble`.
- `docs/docs/security.md`: updated the "Network is informational" section.

**Verification:** `moon run root:check` green; fuzz 30s no panics (5.6M execs);
golden/functional fixtures unchanged. PR #10 opened, CI pending. Note: bech32 path
still rejects reserved nibbles via `checkHRP` (`ErrNetworkMismatch`) — only
raw/embedded reach `NetworkUnknown`.
