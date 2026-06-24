---
id: 004
title: Library docs / README
started: 2026-06-23
---

## 2026-06-23 22:11 — Kickoff
Goal for the session: update the project docs and README now that the `cip30`
library implementation is complete (session 003, PR #6 / `8fd783d` on `master`).

Current state of the world:
- The `cip30` library is implemented and merged to `master`: `package cip30` at
  the repo root (`cip30.go`, `address.go`, `message.go`, `errors.go`) over
  `internal/cose` and `internal/address`. Builds, lints clean, fully tested
  (15 reference golden vectors, a `cardano-signer` functional oracle, a fuzz
  target, per-package negative suites).
- Public API surface (from session 003): `DataSignature`, `Parse`, `Signature`
  (+ `Verify`/`VerifyMessage`/`MatchesAddress`/`KeyHash`), one-shot `Verify`
  with `WithMessage`/`WithAddress`/`WithEmbeddedAddress`/`StrictAddress`, and
  structured `Result`/`MessageCheck`/`AddressCheck` plus typed errors.
- Docs are **stale/scaffolding**: `README.md` and the MkDocs `docs/` site were
  rebranded in session 001 but never updated to reflect the real API.
  `.journal/002/DESIGN.md` is superseded scaffolding — the code + tests are the
  source of truth.

Plan (rough, to refine after surveying the current docs):
- Read the current `README.md`, `docs/` site, and the actual public API in the
  code to ground the docs in what shipped.
- Survey relevant skills (`readme-writer`, `repo-docs`, `diataxis`,
  `docusaurus`/`mkdocs`, `go-style`) before writing.
- Update README + docs to document real usage; keep them honest (no invented
  features). Branch off `master` via a Worktrunk worktree; integrate via GitHub PR.
