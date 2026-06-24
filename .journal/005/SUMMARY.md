---
id: 005
title: Security review findings
date: 2026-06-24
status: complete
repos_touched: [go-cip-30]
related_sessions: [003, 004]
---

## Goal
Address the address-handling findings from a Codex security review of the `cip30`
verification library. Three findings were reported; one had already been fixed in
a prior change (PR #8, the bech32 HRP address-class check), leaving two to
remediate this session.

## Outcome
Goal met. Both outstanding findings are fixed and merged to `master` via
squash-merged PRs, each with green CI (ci / GitHub Pages / Kusari) and the full
`moon run root:check` gate (build / format / lint / test / docs) passing:

- **PR #9** (`77bde8e`) — *Noncanonical address shapes can satisfy address binding*
  (Low, CWE-20).
- **PR #10** (`2f7aba2`) — *Reserved network tags are accepted and collapsed to
  Testnet* (Low, CWE-20).

Both findings were Low severity: the key-hash ownership check was always sound;
the issues were improper validation / misreporting of attacker-controlled
raw-hex or embedded protected-header address bytes (the bech32 path was already
guarded by `checkHRP`). No follow-up work outstanding.

## Key Decisions
- **Finding 1 — reject pointer addresses (types 4/5) as unsupported, like Byron**,
  rather than add a canonical chain-pointer (varint) parser. Only a pointer
  address's payment credential is ever matchable (identical to enterprise), so no
  canonical address loses coverage, and no attacker-controlled variable-length
  parsing is introduced. Developer's call when offered reject-vs-fully-validate.
- **Finding 1 — enforce exact canonical CIP-19 lengths** (base 57, enterprise 29,
  reward 29) via a new `checkLen`, with over-length now `ErrTrailingBytes`. A
  noncanonical address becomes unprocessable input (`ErrDecodeAddress`), consistent
  with existing Byron/truncated handling. Both address paths funnel through
  `Parse`, so supplied and embedded are covered by one change.
- **Finding 2 — accept but report accurately, do NOT reject** reserved network
  tags. Developer chose this over rejection. Key realization: the internal decoder
  already preserves the raw nibble; only the public `network()` mapping collapsed
  non-mainnet values to Testnet. So the fix is purely root-package — `Valid()`,
  matching, and `internal/address` are unchanged; a matching credential still
  verifies, and the reported `Network` is now honest (`NetworkUnknown` for nibbles
  2–15) so a consumer can reject it if they enforce a network.

## Changes
All on `master`, both PRs.

PR #9 (`fix/address-noncanonical-shapes`):
- `internal/address/address.go` — `checkLen` exact-length enforcement for
  base/enterprise/reward; new `ErrTrailingBytes`; split `fillPaymentOnly` →
  `fillEnterprise`; pointer types 4/5 → `ErrUnsupportedType`; rewrote `Parse` doc.
- `address.go` — godoc note that `AddressPointer` is no longer produced by a
  successful parse.
- Tests — inverted the prior "oversized base tolerated" test to expect
  `ErrTrailingBytes`; added `TestParseRejectsNonCanonicalShapes` (length boundaries
  + pointer rejection) and root `TestVerifyRejectsNonCanonicalAddress` (supplied
  hex + embedded) via a new `sign1WithEmbeddedAddress` helper.
- `docs/docs/security.md` — "Addresses must be canonical" note.

PR #10 (`fix/address-reserved-network`):
- `address.go` — new public `Network` value `NetworkUnknown`; `network()` rewritten
  from the Testnet-collapse to an explicit switch (default → `NetworkUnknown`);
  `String()` case `"Unknown"`; `AddressCheck.Network` godoc updated.
- Tests — root `TestVerifyReportsReservedNetworkAsUnknown` (supplied hex + embedded),
  `TestNetworkUnknownString`, and internal `TestParsePreservesReservedNetworkNibble`.
- `docs/docs/security.md` — updated the "Network is informational" section.

## Open Threads
None. All three review findings are resolved (finding 3 pre-addressed in PR #8;
findings 1 and 2 this session). Both PRs merged; local `master` fast-forwarded to
`2f7aba2`; both implementation worktrees removed.

## Lessons
- **Read the finding's root cause before scoping the fix location.** Finding 2
  pointed at two sites (parser + mapping), but the parser already stored the raw
  nibble correctly — the real defect was only the public `network()` collapse. That
  turned a presumed `internal/address` change into a small root-package one and
  kept `Valid()`/matching untouched.
- **`gochecknoglobals` forbids package-level `var` in test files** in this repo
  (it allows `const`). A shared test table must live inside the test function, not
  as a package var — caught by `moon run root:lint`.
- **`moon run root:format` is `golangci-lint fmt --diff` (check-only).** Apply
  formatting in place first with `proto run golangci-lint -- fmt --config
  .golangci.yml` or the gate fails on the diff (gofumpt + golines wrap long lines).
- **Embedded-address test fixtures carry a zero signature**, so on the embedded
  path `Verify` returns `SignatureValid == false` (and thus `Valid() == false`).
  When the assertion is about the *address* sub-check (e.g. `Network`,
  `MatchedVia`), assert those fields directly rather than `Valid()`.

## References
- **PR #9 (merged):** https://github.com/meigma/go-cip-30/pull/9 (squash `77bde8e`)
- **PR #10 (merged):** https://github.com/meigma/go-cip-30/pull/10 (squash `2f7aba2`)
- Prior session: `.journal/003/SUMMARY.md` (library implementation, PR #6),
  `.journal/004/SUMMARY.md` (docs, PR #7). Pre-session fix: PR #8 (`c26c4ce`,
  bech32 HRP class — finding 3).
- Spec: CIP-19 (`ref/CIPs/CIP-0019`) — address shapes and network tags.
