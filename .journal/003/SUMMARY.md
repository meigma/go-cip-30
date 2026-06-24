---
id: 003
title: Implement CIP-30 verification library
date: 2026-06-23
status: complete
repos_touched: [go-cip-30]
related_sessions: [001, 002]
---

## Goal
Implement the full CIP-30 data-signature verification library from the session
002 design (`.journal/002/DESIGN.md`), using a multi-agent Workflow harness,
split into larger logical phases each gated for explicit human review, abiding
by `go-style`/`go-testing`, deviating from the design only on obvious
errors/contradictions (and noting them). No `docs/` changes this pass.

## Outcome
Goal met. The `cip30` library is implemented, reviewed across three human-gated
phases, and merged to `master` as **PR #6** (squash commit `8fd783d`). It builds,
lints clean (golangci-lint 0 issues), and passes all tests — the 15 reference
golden vectors, a `cardano-signer` functional oracle, a no-panic fuzz target, and
per-package negative/robustness suites. The session's design open question
(detached+hashed reconstruction) was resolved in our favor against an independent
oracle. `docs/` was intentionally left for a future session per the brief.

## Key Decisions
- **One Workflow per phase, human gate between** -> Workflows run to completion
  (no mid-run pause), so the review gate lives between invocations. Each phase ran
  implement (xhigh) → independent verify → 3 parallel adversarial reviewers
  (correctness / security / go-style+go-testing) → triage+fix. I personally
  re-verified (build/test/lint/fuzz + read the security-critical code) before
  committing each gate — this caught that workflow "green" self-reports can
  reflect a transient mid-run tree state.
- **3 phases on one feature branch, checkpoint commit per phase, single PR** ->
  P1 signature core (`02e81b2`), P2 message+address (`4dad2d3`), P3 hardening
  (`0308964`), plus the proto chore (`00c779e`). Larger phases, fewer gates.
- **Hand-rolled COSE `Sig_structure` over the verbatim protected-header bytes;
  strict CBOR decode mode rejecting duplicate map keys** -> wire-byte fidelity
  (never re-encode `body_protected`) and closing a parser-differential surface
  the adversarial review found (fxamacker's default decoder silently accepts and
  inconsistently resolves duplicate COSE keys).
- **Hexagonal seams**: `internal/cose` owns the CBOR codec, `internal/address`
  owns CIP-19 bech32/hex parsing (bounds-checked, no policy), and the root package
  owns the matching policy (`MatchedVia` payment/stake, base-stake fallback,
  `StrictAddress`) and public vocabulary.
- **`cardano-signer` managed via `proto`** (per developer request) mirroring
  `golangci-lint`: a `.moon/proto/cardano-signer.toml` schema plugin pinned in
  `.prototools`. Upstream ships only `mac-x64`, so macos is pinned to x64 (runs
  under Rosetta on Apple Silicon).
- **Anti-circular functional fixtures** -> each fixture's expected verdict comes
  from the signing construction + cardano-signer's own `verify --cip30` oracle,
  never from our own `Verify`. CI reads committed `testdata/fixtures/`.
- **detached+hashed: spec-correct raw blake2b-224** -> diverge from the
  reference's apparent UTF-8-of-hex-digest bug; confirmed correct against the
  independent oracle (true for the right message, false for a wrong one).

## Changes
All on `master` via PR #6 (`8fd783d`). Library is `package cip30` at the repo root.
- `internal/cose/cose.go` (new) - COSE_Sign1/COSE_Key decode, strict dup-key
  decode mode, `SigStructure` assembly from verbatim protected bytes.
- `internal/address/address.go` (new) - CIP-19 bech32/hex decoder, bounds-checked,
  HRP↔network-nibble check, Byron/truncated rejected; no matching policy.
- `cip30.go`, `errors.go`, `address.go`, `message.go` (new) - `DataSignature`,
  `Parse`, `Signature` (+`Verify`/`VerifyMessage`/`MatchesAddress`/`KeyHash`),
  one-shot `Verify` with `WithMessage`/`WithAddress`/`WithEmbeddedAddress`/
  `StrictAddress`, structured `Result`/`MessageCheck`/`AddressCheck`, typed errors.
- Tests: `cip30_test.go`, `golden_test.go` (15 reference vectors), `message_test.go`,
  `verify_test.go`, `functional_test.go` (cardano-signer oracle), `fuzz_test.go`
  (`FuzzVerify` + committed corpus), `robustness_test.go`, `embedded_address_test.go`,
  `helpers_test.go`, `internal/*/_test.go`.
- `.moon/proto/cardano-signer.toml`, `.prototools` (new/edit) - proto-managed
  `cardano-signer` 1.35.0.
- `scripts/gen-fixtures.sh` + `moon.yml` `gen-fixtures` task - regenerate the
  committed `testdata/fixtures/manifest.json` (local-only, `runInCI: false`).
- `go.mod`/`go.sum` - added `fxamacker/cbor/v2`, `x/crypto`, `btcsuite` bech32,
  `stretchr/testify`.

## Open Threads
- **Real library docs** - the `docs/` MkDocs site was intentionally untouched;
  `.journal/002/DESIGN.md` is now superseded scaffolding (the code + tests are the
  source of truth). Developer deferred docs to the next session.
- **Base-address functional fixtures** - skipped in the cardano-signer matrix
  (keygen yields enterprise/reward; a combined `addr1q…` base address would need
  `cardano-cli`). Base-address matching is covered by the committed reference
  golden vectors and the Phase-2 unit tests, so coverage is not lost.

## Lessons
- **Never instruct agents to "clean up scratch files."** That instruction caused a
  workflow fix-agent to attempt `rm -f $VAR/*.json` (glob + shell variable), which
  the developer rightly denied twice. The scratchpad is session-temporary and
  auto-cleaned; a leftover temp file is harmless, a bad `rm` is not. The fix was to
  remove all cleanup language and add a hard "never run `rm` (no glob, no var,
  ever)" rule to the workflow prompt. Agents can consolidate stray files with
  `git mv` instead.
- **Independently re-verify before committing a gate.** A workflow reported all
  green while editor diagnostics showed a broken mid-run tree (stray probe files,
  duplicate decls). It was a transient snapshot the fix stage resolved, but the
  lesson holds: run build/test/lint/fuzz and read the security-critical code
  yourself rather than trusting the self-report.

## References
- **PR #6 (merged):** https://github.com/meigma/go-cip-30/pull/6 (squash `8fd783d`)
- Branch commits: `02e81b2` P1, `4dad2d3` P2, `00c779e` proto, `0308964` P3.
- Design proposal (now superseded): `.journal/002/DESIGN.md`.
- Prior sessions: `.journal/001/SUMMARY.md` (rebrand), `.journal/002/SUMMARY.md` (design).
- TS reference + oracle: `ref/cardano-verify-datasignature`,
  `cardano-signer` (gitmachtl) 1.35.0 via proto.
