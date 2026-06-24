# Technical Notes

- Use hexagonal architecture at all times. Keep business logic isolated from CLI, filesystem, network, storage, and other external adapters.
- Prefer functional testing before calling any feature complete. Unit tests are useful, but they do not prove the tool works the way the design intends.
- Take an agile approach to development. Avoid waterfall: underspecify when useful, prototype early, learn from the result, and refine from working behavior.

## go-cip-30 project shape (session 001)

- **Library-only** Go module `github.com/meigma/go-cip-30`; public API lives at the repo root in `package cip30` (no `cmd/`, minimal `internal/`). Dual-licensed Apache-2.0 / MIT.
- **Scope:** tools to validate CIP-30 for authentication/identification. NOT an HTTP framework/middleware — transport is the caller's job.
- **Reference material:** run `moon run setup-ref` to clone `cardano-foundation/cardano-verify-datasignature` (TS reference impl) and `cardano-foundation/CIPs` (spec source) into the gitignored `ref/` folder. Read these before designing the Go API.
- **Release:** release-please cuts semver tags + CHANGELOG (no binaries/containers). `.github/repository-settings.toml` is declarative — apply it with `configure_github_repo.py apply`.

## CIP-30 verification design (session 002)

- **Read `.journal/002/DESIGN.md` first** before implementing the `cip30`
  library — it is the full design proposal (scope, deps, public API, verification
  algorithm, CIP-19 address matching, edge cases, tests, milestones). Temporary
  scaffolding; supersede once the library + real docs exist.
- **Verification model:** a CIP-30 `DataSignature` = `{signature: hex(cbor<COSE_Sign1>), key: hex(cbor<COSE_Key>)}`. Verify = `ed25519.Verify(x, cbor(["Signature1", protectedBytes, h'', payload]), sig)` where `x` is the raw 32-byte key from COSE_Key. Optional message check (honors `hashed`/detached payload) and address check (`blake2b224(x)` vs the bech32 address's key-hash credential, CIP-19).
- **Dependencies (decided):** `fxamacker/cbor/v2`, stdlib `crypto/ed25519`, `golang.org/x/crypto/blake2b` (`New(28,nil)`), `btcsuite/btcd/btcutil/bech32` (`DecodeNoLimit`). Hand-roll the COSE `Sig_structure` (never re-encode `body_protected`); do NOT pull `veraison/go-cose`. No BIP32 needed.
- **Test oracle:** `cardano-signer` CLI (gitmachtl) generates real CIP-30 vectors offline (`keygen` + `sign --cip30`) and verifies them (`verify --cip30`) — no browser wallet/funds/network. Plus the 14 golden vectors in `ref/cardano-verify-datasignature/index.test.ts`.
