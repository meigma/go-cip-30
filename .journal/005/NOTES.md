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
