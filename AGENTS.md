<!-- BEGIN ai-protocol -->
# Agent Instructions

This repository's operating protocol lives in `.session.md`.

Before doing substantive work, read `.session.md` in full and follow it. It
covers startup context loading, session setup, session lifecycle, skill loading,
Worktrunk branching, session journaling, file schemas, architecture, and process
expectations.

If `.session.md` is missing, stop and tell the user the session protocol is not
installed correctly.
<!-- END ai-protocol -->

## Reference Material

This library is a Go port of CIP-30 data-signature verification. To avoid
designing from scratch, `moon run setup-ref` clones a few upstream references
into the gitignored `ref/` directory — local scaffolding only, never committed
and not a dependency of this module:

- [`ref/cardano-verify-datasignature`](https://github.com/cardano-foundation/cardano-verify-datasignature)
  — "a lightweight typescript library to verify a cip30 datasignature"
  (Apache-2.0). A known-good TypeScript implementation whose scope (verify a
  message was signed by a key, optionally matching a wallet address) maps
  directly onto our authentication/identification goals; a useful cross-check
  for behavior and edge cases.
- [`ref/CIPs`](https://github.com/cardano-foundation/CIPs) — the Cardano
  Foundation CIPs repository, the authoritative source for all CIP
  specifications (including CIP-30 itself).

On a fresh clone, set everything up with:

```sh
moon run setup-ref
```

Each repo is shallow-cloned, skipping any that already exist. To refresh one,
delete its folder under `ref/` and re-run the task.
