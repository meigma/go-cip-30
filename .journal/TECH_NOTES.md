# Technical Notes

- Use hexagonal architecture at all times. Keep business logic isolated from CLI, filesystem, network, storage, and other external adapters.
- Prefer functional testing before calling any feature complete. Unit tests are useful, but they do not prove the tool works the way the design intends.
- Take an agile approach to development. Avoid waterfall: underspecify when useful, prototype early, learn from the result, and refine from working behavior.

## go-cip-30 project shape (session 001)

- **Library-only** Go module `github.com/meigma/go-cip-30`; public API lives at the repo root in `package cip30` (no `cmd/`, minimal `internal/`). Dual-licensed Apache-2.0 / MIT.
- **Scope:** tools to validate CIP-30 for authentication/identification. NOT an HTTP framework/middleware — transport is the caller's job.
- **Reference material:** run `moon run setup-ref` to clone `cardano-foundation/cardano-verify-datasignature` (TS reference impl) and `cardano-foundation/CIPs` (spec source) into the gitignored `ref/` folder. Read these before designing the Go API.
- **Release:** release-please cuts semver tags + CHANGELOG (no binaries/containers). `.github/repository-settings.toml` is declarative — apply it with `configure_github_repo.py apply`.

## CIP-30 library (implemented — session 003, PR #6 / `8fd783d`)

The `cip30` library is now implemented and on `master`. `.journal/002/DESIGN.md`
is **superseded scaffolding** — the code + tests are the source of truth; read it
only for design rationale. Real `docs/` are still TODO (a future session).

- **Layout:** `package cip30` at the repo root (`cip30.go`, `address.go`,
  `message.go`, `errors.go`) over two internal packages: `internal/cose` (CBOR
  codec + `Sig_structure`) and `internal/address` (CIP-19 parsing). Matching
  policy and the public vocabulary live in the root, not in `internal/address`.
- **Verification model:** a `DataSignature` = `{signature: hex(cbor<COSE_Sign1>),
  key: hex(cbor<COSE_Key>)}`. Verify = `ed25519.Verify(x, cbor(["Signature1",
  protectedBytesVerbatim, h'', payload]), sig)`. Optional `WithMessage` (honors
  `hashed`/is-hex-digest/detached), `WithAddress`/`WithEmbeddedAddress`/
  `StrictAddress` (`blake2b224(x)` vs a CIP-19 key-hash credential). `Verify`
  returns `(*Result, error)`; error = unprocessable input, `Result` = the verdict
  (`Valid()`, `SignatureValid`, `Message`, `Address.MatchedVia`).
- **Key invariants (don't break):** never re-encode `body_protected` (reuse wire
  bytes); a strict CBOR decode mode rejects duplicate COSE map keys; length-guard
  before `ed25519.Verify`; empty/detached payload encodes as `h''` not null;
  script credentials never match a key; base-address stake fallback is default-on,
  off under `StrictAddress`. detached+hashed reconstructs the **raw** 28-byte
  blake2b-224 (the reference's UTF-8-of-hex approach is a bug we do not copy).
- **Deps:** `fxamacker/cbor/v2`, stdlib `crypto/ed25519`,
  `golang.org/x/crypto/blake2b` (`New(28,nil)`), `btcsuite/.../bech32`
  (`DecodeNoLimit`). No `veraison/go-cose`, no BIP32.
- **Test oracle:** `cardano-signer` (gitmachtl) is **proto-managed**
  (`.moon/proto/cardano-signer.toml`, pinned in `.prototools`; macos pinned to x64
  / Rosetta). `moon run gen-fixtures` (`scripts/gen-fixtures.sh`, `runInCI:false`)
  regenerates committed `testdata/fixtures/manifest.json` from a fixed throwaway
  mnemonic, cross-checked against cardano-signer's own `verify --cip30`
  (anti-circular). CI reads the committed fixtures. Plus the 15 golden vectors in
  `ref/cardano-verify-datasignature/index.test.ts` (the design's "14" was off by
  one) and a `FuzzVerify` no-panic target with a committed seed corpus.
