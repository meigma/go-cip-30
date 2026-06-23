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
