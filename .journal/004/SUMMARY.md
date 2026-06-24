---
id: 004
title: Library docs / README
date: 2026-06-24
status: complete
repos_touched: [go-cip-30]
related_sessions: [002, 003]
---

## Goal
Update the project documentation and README now that the `cip30` verification
library is implemented and merged (session 003, PR #6). Follow the `diataxis`
skill, prefer fewer/smaller docs that link out to the authoritative CIP specs,
and add a dedicated security/footgun guide. Audience: Go developers integrating
the library.

## Outcome
Goal met. The docs are rewritten to match the shipped API and merged to `master`
as **PR #7** (squash commit `4c03f95`). CI is green (ci / GitHub Pages build /
Kusari), and the GitHub Pages deploy runs on the push to `master`, so the live
site at https://meigma.github.io/go-cip-30/ refreshes with the new pages. The
godoc examples are `go test`-verified, and the full `moon run root:check` gate
passes (build / format / lint / test / docs). No follow-up work outstanding.

## Key Decisions
Three structural calls were made with the developer up front via plan-mode
questions; two more surfaced during implementation.
- **3-page docs site, each a clean diátaxis type** (Home, a how-to, a security
  guide) -> honors "fewer/smaller docs". Deep concepts are deferred to the CIP
  specs (linked) rather than re-derived, matching the "avoid over-explaining /
  link to authoritative material" steer.
- **API reference = pkg.go.dev + tested godoc `Example` functions**, no markdown
  reference page -> godoc is already exhaustive; a hand-written reference would
  duplicate it and drift. The examples are compile/run-checked by `go test`.
- **Dropped the "early development / API taking shape" status** from README and
  Home -> the implementation is complete; present the library as finished
  (developer's call).
- **Examples use `fmt.Println(err); return`, not `log.Fatal`** -> the repo's
  `depguard` lint forbids the `log` package in non-main files. For valid fixture
  inputs the error branch is dead code, so the `// Output:` blocks stay
  deterministic.
- **Security guide leans on the API's existing godoc threat notes** (mangled
  base address, self-asserted embedded address, stake-vs-payment) rather than
  authoring new analysis -> keeps the docs consistent with the code's own
  contract.

## Changes
All on `master` via PR #7 (`4c03f95`).
- `docs/docs/index.md` (Home) - rewritten: overview, scope, install, quick-start,
  a short "how it works" linking CIP-30/8/19 + pkg.go.dev; dropped the Status stub.
- `docs/docs/verifying.md` (new, how-to) - signature / message / address /
  embedded address / strict mode / reuse-parsed-signature / error-vs-invalid /
  key-hash identity; imperative, links "why" out to the security guide.
- `docs/docs/security.md` (new, footgun guide) - server-side verification,
  self-asserted embedded address, mangled base-address & stake-vs-payment
  (`StrictAddress` / `MatchedVia == Payment`), hashed/hex message conventions,
  error-vs-invalid (gate on `Result.Valid()`), replay/freshness, informational
  network nibble. Material admonitions.
- `docs/mkdocs.yml` - nav extended to the three pages.
- `example_test.go` (new) - `ExampleVerify`, `ExampleVerify_withAddress`,
  `ExampleParse` in external `package cip30_test`, seeded from the golden vectors
  with verified `// Output:` blocks.
- `doc.go` - enriched package overview + pointer to the examples and docs site.
- `README.md` - dropped the status caveat, added a quick-start, linked the docs
  site / pkg.go.dev / security guide.

## Open Threads
None blocking. Notes for future sessions:
- pkg.go.dev renders the new examples and package doc on its next fetch of a
  tagged/known version; the module is still un-tagged (manifest `0.0.0`).
- `mkdocs-material` prints an upstream "MkDocs 2.0" breaking-change banner during
  the build; informational only, build passes under `--strict`.

## Lessons
- **`depguard` blocks `log` in non-main files in this repo.** Godoc example
  files (`*_test.go`) are non-main, so the idiomatic `log.Fatal(err)` fails lint.
  Use `fmt.Println(err); return` in example error branches — with valid inputs
  the branch never runs, so `// Output:` stays deterministic.
- **`moon run root:format` runs `golangci-lint fmt --diff` (gofumpt + golines).**
  Long literals (e.g. a bech32 address argument) get wrapped; run the formatter
  in-place before committing or the format gate fails.
- **Verify cross-page MkDocs anchors against the generated HTML.** `--strict`
  did not fail on the inter-page `#anchor` links, so grep the built
  `docs/build/<page>/index.html` for the slugified `id="..."` to be sure they
  resolve.

## References
- **PR #7 (merged):** https://github.com/meigma/go-cip-30/pull/7 (squash `4c03f95`)
- Live docs: https://meigma.github.io/go-cip-30/ · API: https://pkg.go.dev/github.com/meigma/go-cip-30
- Prior sessions: `.journal/003/SUMMARY.md` (implementation, PR #6),
  `.journal/002/SUMMARY.md` (design).
- CIP specs: CIP-30, CIP-8, CIP-19 (cips.cardano.org).
