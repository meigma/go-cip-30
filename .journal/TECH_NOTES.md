# Technical Notes

- Use hexagonal architecture at all times. Keep business logic isolated from CLI, filesystem, network, storage, and other external adapters.
- Prefer functional testing before calling any feature complete. Unit tests are useful, but they do not prove the tool works the way the design intends.
- Take an agile approach to development. Avoid waterfall: underspecify when useful, prototype early, learn from the result, and refine from working behavior.

## go-cip-30 project shape (session 001)

- **Library-only** Go module `github.com/meigma/go-cip-30`; public API lives at the repo root in `package cip30` (no `cmd/`, minimal `internal/`). Dual-licensed Apache-2.0 / MIT.
- **Scope:** tools to validate CIP-30 for authentication/identification. NOT an HTTP framework/middleware — transport is the caller's job.
- **Reference material:** run `moon run setup-ref` to clone `cardano-foundation/cardano-verify-datasignature` (TS reference impl) and `cardano-foundation/CIPs` (spec source) into the gitignored `ref/` folder. Read these before designing the Go API.
- **Release:** release-please cuts semver tags + CHANGELOG (no binaries/containers). `.github/repository-settings.toml` is declarative — apply it with `configure_github_repo.py apply`.
