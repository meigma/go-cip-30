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
