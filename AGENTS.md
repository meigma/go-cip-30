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

## Reference Implementations

This library is a Go port of CIP-30 data-signature verification. To avoid
designing from scratch, we keep a known-good TypeScript reference on hand:
[cardano-foundation/cardano-verify-datasignature](https://github.com/cardano-foundation/cardano-verify-datasignature)
— "a lightweight typescript library to verify a cip30 datasignature"
(Apache-2.0). Its scope (verify a message was signed by a key, optionally
matching a wallet address) maps directly onto our authentication/identification
goals, so it is a useful cross-check for behavior and edge cases.

The reference lives in `ref/cardano-verify-datasignature`. The `ref/` directory
is gitignored and never committed — it is local scaffolding for reading the
reference, not a dependency of this module.

On a fresh clone, set it up with:

```sh
moon run setup-ref
```

This shallow-clones the reference into `ref/`, skipping the clone if it already
exists. To refresh it, delete `ref/cardano-verify-datasignature` and re-run the
task.
