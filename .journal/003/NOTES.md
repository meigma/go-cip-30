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

## 2026-06-23 20:48 — Phase 2 implemented (Gate 2 reached)
Gate 1 approved ("LGTM. Proceed to phase 2"). Ran `cip30-impl-phase2` (same
4-stage harness, 6 agents, ~521k tokens, ~19 min). Committed `4dad2d3` on
`feat/cip30-verification` (+1811/-22, 11 files).

Added: `internal/address` (pure CIP-19 decoder — bech32 via btcsuite
`DecodeNoLimit` or hex; payment/stake credential extraction; bounds-checked;
network-nibble vs HRP check; Byron/truncated rejected; holds NO matching
policy), root `address.go` (the matching policy + public enums
Credential/AddressSource/AddressType/Network + MessageCheck/AddressCheck),
`message.go` (digest/is-hex-guard/detached logic). Extended `cip30.go`
(WithMessage/WithAddress/WithEmbeddedAddress/StrictAddress, Signature
VerifyMessage/MatchesAddress, Verify orchestration, Result.Message/Address,
extended Valid(), conflicting-option rejection) and `errors.go`. Ported ALL 15
golden vectors (design said 14) with MatchedVia/Strict/Source assertions + a
CIP-19 type matrix + attacker paths. build/vet/gofmt/golangci-lint(0)/test all
green; 94 tests. I read internal/address.go, address.go, message.go, cip30.go,
and golden_test.go in full and re-ran build/vet/fmt/lint/test myself.

Matching policy verified correct vs DESIGN §8: payment-first, reward-stake
always counts, base-stake fallback gated by `!strict`, script/nil credentials
never match (constant-time compare). The addr1qxtu4w2 base address matches
keyStake via Stake (default true, strict false) and keyPayment via Payment
(true under strict); enterprise via Payment; wrong address → None with
SignatureValid=true.

Review found only LOW-severity doc/style items (no logic defects). Fix stage
applied 8 (doc clarifications incl. the WithEmbeddedAddress mangled-address
warning; removed a withStrict indirection; dropped a dead Source default) and
deferred fuzz + cardano-signer + full strictness audit to Phase 3.

Noted for Phase 3 (deferred, documented, none are false-accept/panic vectors):
detached+hashed correct-path NOT yet confirmed against a real cardano-signer
`--hashed` detached vector; oversized raw addresses tolerated (trailing bytes
ignored); network nibble taken verbatim for raw/hex/embedded input
(informational, does not gate Valid); HRP-type vs address-type consistency
unchecked. Also: a reviewer's transient `zz_adversarial_test.go` scratch probe
was created+deleted during review — tree is clean, confirmed via git status.
Other deviations: used `crypto/subtle.ConstantTimeCompare` (defensive,
harmless); internal/address owns CIP-19 parsing while root owns policy + public
enums (clean hexagonal reorg from DESIGN §6's struct layout).

Status: **paused at Gate 2** awaiting developer approval before Phase 3
(hardening: typed-error audit, fuzz target, cardano-signer functional oracle,
negative/robustness tests, resolve the deferred confirmations). No docs/ this
pass per the brief.

## 2026-06-23 21:54 — Phase 3 implemented (Gate 3 reached)
Gate 2 approved with a request: manage `cardano-signer` via `proto` like other
tools (not a raw install).

Proto setup (done by me directly, committed `00c779e`): authored
`.moon/proto/cardano-signer.toml` mirroring `golangci-lint.toml`, pinned
`=1.35.0` + registered in `.prototools`. Upstream ships only `mac-x64` (no
arm64), so macos is pinned to x64 (runs under Rosetta); linux resolves
arm64/x64. Verified `proto install` + a full keygen→sign→our-Verify round-trip
(Valid=true, MatchedVia=Payment). Captured the CIP-30 CLI incl. detached+hashed
(`--hashed --nopayload`).

**Safety incident:** the first Phase-3 workflow run (w3kew21xo) had a fix/cleanup
agent attempt `rm -f $SCRATCHPAD/*.json` (glob+var) — the developer denied it
twice. Root cause was MY prompt instruction to "clean up scratch files" (both
unnecessary — scratchpad is session-temp — and unsafe). I stopped the workflow
(worktree was pristine, nothing half-applied), removed all cleanup instructions
from the script, and added a hard "never run rm (no glob, no var, ever)" rule,
then re-ran (wv4qjxbuh). Lesson: never instruct agents to delete; a leftover
temp file is harmless, a bad rm is not.

Second run completed. NOTE: the stale editor diagnostics showed a broken tree
(stray `noaddr_main_tmp.go`/`probe_test.go`, dup decls) — that was a MID-RUN
snapshot; the fix stage consolidated via `git mv` (no rm) and hoisted shared
helpers into `helpers_test.go`. Final tree is clean and green. I re-verified
everything myself: build/vet/gofmt/test/golangci-lint(0) all green; an
independent 20s live fuzz (5.6M execs, no crasher); and I re-derived the
detached+hashed fixture through cardano-signer's OWN verify (true for correct
msg, false for wrong) — confirming non-circularly that our spec-correct raw
blake2b-224 reconstruction is right. **DESIGN §7 open question resolved.**

Committed `0308964` (+1026, 32 files): `fuzz_test.go` (FuzzVerify, 38 seeds + 23
committed corpus), `functional_test.go` (reads committed
`testdata/fixtures/manifest.json`; anti-circular — verdicts from construction +
cardano-signer oracle, never our code), `scripts/gen-fixtures.sh` (moon
`gen-fixtures`, fixed throwaway mnemonic, oracle cross-check; safe quoted
`mktemp -d` trap), `robustness_test.go`, `embedded_address_test.go`,
`helpers_test.go`, error-audit on `internal/address/address.go` (dropped dead
`ErrInvalidHex`), `moon.yml` gen-fixtures task. Review: correctness lens clean;
the one security finding (documented is-hex parity quirk) correctly rejected as
the resolved R2 design decision; style fixes applied.

Deviation: base-address fixtures skipped (cardano-signer alone yields
enterprise/reward; a combined base addr needs cardano-cli — unwanted dep). Base
is covered by the committed reference golden vectors.

Branch `feat/cip30-verification` commits: 02e81b2 (P1), 4dad2d3 (P2), 00c779e
(proto), 0308964 (P3). All four prior phases' tests stay green.

Status: **paused at Gate 3** (final). On approval: open the single PR to master.

## 2026-06-23 22:09 — Close
Gate 3 approved. Opened **PR #6** (`feat(cip30): implement CIP-30 data signature
verification`); CI green (`ci`/Moon, GitHub Pages, Kusari Inspector all pass;
mergeable/CLEAN). Developer approved the merge.

Closed out: squash-merged PR #6 → `master` (squash commit `8fd783d`), fast-
forwarded the local `master` checkout, and removed the `feat/cip30-verification`
worktree + branch via `wt remove` (only `master` + `journal/jmgilman` remain).

Handoff: the `cip30` library is live on `master`. `SUMMARY.md` written; `INDEX.md`
row → complete; `TECH_NOTES.md` updated to mark the library implemented and
`.journal/002/DESIGN.md` superseded. **Next session:** real `docs/` (the MkDocs
site was intentionally untouched this pass, per the developer). Also tracked:
base-address functional fixtures deferred (covered by the reference golden
vectors). Session complete.
