---
id: 001
title: Rebrand template repo
date: 2026-06-23
status: complete
repos_touched: [go-cip-30]
related_sessions: []
---

## Goal
Rebrand the `meigma/template-go` scaffold into the real `go-cip-30` project — a
public, library-only Go module for implementing CIP-30 (Cardano dApp–wallet
bridge) in web2 backends. Scope grew during the session to also dual-license the
repo and add a moon recipe for pulling CIP-30 reference material.

## Outcome
Goal met. Three pieces of work merged to `master`:
- **PR #4** — rebrand: module, packages, config, CI, docs all retargeted; all
  template/CLI/binary machinery removed.
- **PR #4** — dual license added (folded into the same PR before merge).
- **PR #5** — `moon run setup-ref` recipe that clones the reference repos.

The repo now builds/lints/tests clean as a library skeleton. No CIP-30 API code
exists yet — that is the next session's work, pending a design doc.

## Key Decisions
- **Library-only, package `cip30` at repo root** -> public-library ergonomics
  (`import "github.com/meigma/go-cip-30"` → `cip30.X`); no `cmd/`. Added a
  minimal `doc.go` so the module compiles/lints with no API yet.
- **Keep release-please, drop GoReleaser/container/ghd/binary release** -> Go
  libraries are consumed via semver git tags + changelog, not shipped binaries.
  Manifest reset to `0.0.0` for a fresh start.
- **Keep + rebrand the MkDocs site** rather than deleting it.
- **Dual-license Apache-2.0 OR MIT** (Rust-style split `LICENSE-APACHE` +
  `LICENSE-MIT`); copyright holder `Meigma`, 2026. GitHub's sidebar badge won't
  auto-detect split-file dual licenses — accepted as cosmetic.
- **Reference repos via idempotent `moon run setup-ref` into gitignored `ref/`**
  -> local scaffolding, never committed, not a dependency. Documented in
  `AGENTS.md` *after* the managed `<!-- … ai-protocol … -->` block (CLAUDE.md is
  a symlink to AGENTS.md, so both stay in sync).

## Changes
- `go.mod` - module → `github.com/meigma/go-cip-30`; `go mod tidy` dropped
  Cobra/Viper (removed empty `go.sum`).
- `doc.go` (new) - root `package cip30` doc comment.
- Deleted `cmd/`, `internal/`, `Dockerfile`, `.dockerignore`, `.goreleaser.yaml`,
  `ghd.toml`, `DELETE_ME.md`, the release/release-dry-run/security-scan
  workflows, and the ghd asset-staging scripts.
- Rebranded `.golangci.yml`, `moon.yml`, `.github/dependabot.yml`,
  `.github/repository-settings.toml`, `release-please-config.json` +
  `.release-please-manifest.json`, and the `configure_github_repo` test fixtures.
- Rewrote `README.md`, `CONTRIBUTING.md`, `SECURITY.md`, the MkDocs site
  (`docs/`), and reset `CHANGELOG.md`.
- Added `LICENSE-APACHE`, `LICENSE-MIT`.
- `moon.yml` - added `setup-ref` task cloning
  `cardano-foundation/cardano-verify-datasignature` and
  `cardano-foundation/CIPs` into `ref/`; `.gitignore` ignores `/ref/`;
  `AGENTS.md` gained a "Reference Material" section.

## Open Threads
- **Apply repo settings:** `.github/repository-settings.toml` changes
  (`is_template=false`, required status checks reduced to `ci`) are committed but
  not applied to the live GitHub repo — run
  `uv run .github/scripts/configure_github_repo.py apply --repo meigma/go-cip-30`.
- **Next work:** design doc + actual CIP-30 Go API in package `cip30`. Use the
  cloned references (`ref/cardano-verify-datasignature`, `ref/CIPs`).
- **Benign moon WARN:** `moon.yml` `goSources` lists `go.sum`, which won't exist
  until the first dependency is added; harmless.

## References
- PR #4 (rebrand + dual license): https://github.com/meigma/go-cip-30/pull/4
- PR #5 (setup-ref recipe): https://github.com/meigma/go-cip-30/pull/5
- Reference impl: https://github.com/cardano-foundation/cardano-verify-datasignature
- CIP specs: https://github.com/cardano-foundation/CIPs
