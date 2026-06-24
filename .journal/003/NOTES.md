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
