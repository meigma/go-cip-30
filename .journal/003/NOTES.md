---
id: 003
title: Review CIP-30 design proposal
started: 2026-06-23
---

## 2026-06-23 19:24 — Kickoff
Goal for the session: set up a new session and review the CIP-30 verification
design proposal produced in session 002 (`.journal/002/DESIGN.md`), then pause
for further instructions from the developer.

Current state of the world:
- `go-cip-30` is a library-only Go module (`package cip30` at the repo root),
  dual-licensed Apache-2.0/MIT, rebranded from `template-go` in session 001
  (PRs #4, #5 merged to `master`).
- No CIP-30 API code exists yet. The repo is a clean library skeleton (`doc.go`
  only).
- Session 002 produced a comprehensive, temporary design proposal at
  `.journal/002/DESIGN.md`: scope, `DataSignature`/COSE_Sign1/COSE_Key anatomy,
  the dependency set (`fxamacker/cbor/v2`, stdlib `crypto/ed25519`,
  `x/crypto/blake2b` via `New(28,nil)`, `btcsuite` bech32 `DecodeNoLimit`),
  hexagonal package seams (`internal/cose`, `internal/address`), the full public
  API (`Verify` → `(*Result, error)`, `Parse`, `Signature` methods, functional
  options incl. `WithMessage`/`WithAddress`/`WithEmbeddedAddress`/`StrictAddress`),
  the verification algorithm, CIP-19 address matching, an edge-case table,
  security considerations, the test strategy (`cardano-signer` oracle + 14 golden
  vectors), and agile milestones. All open design questions were marked resolved.
- Reference material (`ref/cardano-verify-datasignature`, `ref/CIPs`) is cloned
  locally via `moon run setup-ref` (gitignored, not committed).

Plan:
- Reviewed `DESIGN.md` in full during startup (read alongside both prior session
  summaries and TECH_NOTES).
- Pause here and wait for the developer's actual request before any substantive
  work.

## 2026-06-23 20:14 — Phase 1 implemented (Gate 1 reached)
Developer asked (effort: ultracode) to build a multi-phase workflow that
implements the full `DESIGN.md`, abiding by `go-style`/`go-testing`, deviating
from the design only on obvious errors (and noting them), keeping code simple/
readable, splitting into larger logical phases each gated for human review, and
excluding `docs/` this pass.

Decisions (via AskUserQuestion): **3 phases** (P1 core decode + signature; P2
message + address options; P3 hardening) on **one feature branch**
(`feat/cip30-verification`, worktree `.wt/feat-cip30-verification` off `master`),
checkpoint commit per phase, single PR at the end.

Workflow design: one Workflow per phase (workflows run to completion, so the
human gate lives between invocations). Each phase = implement (1 agent, xhigh) →
independent verify (1) → 3 parallel adversarial reviewers (correctness /
security / go-style+go-testing) → triage+fix (1). Ran `cip30-impl-phase1`
(6 agents, ~363k tokens, ~16 min).

Phase 1 result — committed `02e81b2` on `feat/cip30-verification` (+935 lines,
7 files): `internal/cose` (CBOR/COSE decode + Sig_structure assembly, fxamacker
isolated), root `cip30.go`/`errors.go` (`DataSignature`, `Parse`,
`Signature.Verify/KeyHash`, one-shot `Verify` → `Result`, typed sentinels),
tests (4 signature-only golden vectors + 19 negative-path cases). build/vet/
gofmt/`golangci-lint`(v2.11.4, 0 issues)/test all green; 34 tests pass.

Notable: the adversarial review caught a real subtle issue — fxamacker's default
decoder silently accepts duplicate COSE map keys and resolves them differently
across decode targets (map[any]any keeps last, keyasint struct keeps first), a
parser-differential surface. Fixed with one shared strict `DecMode`
(`DupMapKeyEnforcedAPF`). I read all core + test files myself before committing.

Design deviations noted (intentional, not design errors): Phase-1 `Result` is
minimal (signature/key only) — `Message`/`Address` are additive in P2/P3; only
the constants/`internal/address` actually needed yet were created; `asInt64`
rejects uint64 > MaxInt64 (hostile-input hardening, satisfies gosec G115).
Carried forward: DESIGN says "14 golden vectors" but `index.test.ts` has **15**
test cases — surfaces in P2.

Status: **paused at Gate 1** awaiting developer approval before Phase 2.
