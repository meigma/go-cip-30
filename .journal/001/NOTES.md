---
id: 001
title: Rebrand template repo
started: 2026-06-23
---

## 2026-06-23 16:10 — Kickoff
Goal for the session: rebrand the `template-go` template into the real
`go-cip-30` project — replace template identifiers/branding throughout the repo
so it reflects the actual project rather than the upstream template.

Current state of the world:
- Repo is a fresh clone of the `meigma/template-go` GitHub template, retargeted
  to origin `git@github.com:meigma/go-cip-30.git` (default branch `master`).
- `go.mod` module path is still `github.com/meigma/template-go` (Go 1.26.4).
- `template-go` references are spread across many files: `cmd/template-go/main.go`,
  `README.md`, `CONTRIBUTING.md`, `CHANGELOG.md`, `.goreleaser.yaml`, `Dockerfile`,
  `moon.yml`, `.golangci.yml`, `ghd.toml`, `release-please-config.json`,
  `internal/config/config.go`, `internal/cli/root.go` + `root_test.go`,
  `internal/templateinfo/info.go`, the `docs/` site, and several
  `.github/workflows` + `.github/scripts`.
- A `DELETE_ME.md` template artifact is present at the repo root.
- Working tree is clean on `master`; journal lives on `journal/jmgilman`.

Plan (rough):
- Confirm the target naming/branding with the user (module path, binary name,
  project description, CIP-30 context) before mass-editing.
- Do the rebrand on a dedicated implementation worktree off `master`, integrate
  via a GitHub PR (squash merge) per repo policy.
- Sweep every `template-go` reference, rename the `cmd/` binary dir, update
  module path + imports, and remove template-only artifacts like `DELETE_ME.md`.

Status: session primed; paused, awaiting the user's go-ahead and naming details.

## 2026-06-23 16:29 — Rebrand implemented, PR opened
Confirmed naming with the user: public root package `cip30`, module
`github.com/meigma/go-cip-30`, library-only (no `cmd/`), code at root, scope
limited to validating CIP-30 for auth/identification (no HTTP middleware).
Decisions: keep release-please for semver tags (drop GoReleaser/container/ghd);
keep + rebrand the MkDocs site.

Done on worktree `.wt/feat-rebrand-cip30` (branch `feat/rebrand-cip30`):
- Deleted CLI/binary/container machinery: `cmd/`, `internal/` (cli/config/
  templateinfo), `Dockerfile`, `.dockerignore`, `.goreleaser.yaml`, `ghd.toml`,
  `DELETE_ME.md`, the release/release-dry-run/security-scan workflows, and the
  ghd asset-staging scripts.
- Module → `github.com/meigma/go-cip-30`; added root `cip30` package (`doc.go`);
  `go mod tidy` dropped Cobra/Viper (removed now-empty `go.sum`).
- Rebranded config/CI: `.golangci.yml` local-prefix, `moon.yml` (project meta,
  `build → go build ./...`, file groups), Dependabot (dropped docker),
  `repository-settings.toml` (`is_template=false`, dry-run status checks → just
  `ci`), release-please config (`package-name`) + manifest reset to `0.0.0`.
- Rewrote README/CONTRIBUTING/SECURITY, MkDocs site (regenerated `docs/uv.lock`
  for the renamed docs project), reset `CHANGELOG.md`.

Verification all green: `go build/vet/test ./...`, `go mod tidy` no-op,
`gofmt -l`, `golangci-lint run`, `mkdocs build --strict`; branding sweep for
`template-go`/`templateinfo`/`TEMPLATE_GO` returns zero hits.

PR: https://github.com/meigma/go-cip-30/pull/4 (chore: rebrand template-go
scaffold into go-cip-30 library). CI running at checkpoint time (ci / Pages /
Kusari pending). 35 files changed, +103/-2170.

Next: confirm CI passes, then squash-merge the PR. Design doc + actual CIP-30
API are the follow-up work.

## 2026-06-23 17:23 — Close
Session closed. All work merged to `master` (now at the PR #5 squash commit) and
both implementation worktrees removed.

Landed after the rebrand checkpoint:
- Dual-licensed the repo (Apache-2.0 + MIT, Rust-style split LICENSE files,
  holder "Meigma"); folded into PR #4 before it merged.
- Added `moon run setup-ref` — idempotent shallow clone of
  `cardano-foundation/cardano-verify-datasignature` and `cardano-foundation/CIPs`
  into the gitignored `ref/` folder; documented in AGENTS.md "Reference
  Material" (PR #5).

Merged PRs: #4 (rebrand + dual license), #5 (setup-ref recipe). Local `master`
fast-forwarded to `dcb9388`; `feat/rebrand-cip30` and `feat/ref-impl` worktrees/
branches removed.

Hand-off / open threads (see SUMMARY.md): apply `repository-settings.toml` to the
live repo via `configure_github_repo.py apply`; next session writes the design
doc + real CIP-30 API in `package cip30`, using the cloned `ref/` material.
