# go-cip-30

`go-cip-30` is a Go library for implementing the [CIP-30][cip30] Cardano
dApp–wallet bridge in web2 backend systems.

It targets backend API builders who integrate with Cardano wallet extensions
over CIP-30. The scope is intentionally narrow: the tools needed to **validate
CIP-30 data for authentication and identification**. It is not an HTTP framework
or middleware — you bring the transport, this library handles CIP-30.

> **Status:** early development. The public API is still taking shape and may
> change before the first tagged release.

## Install

```sh
go get github.com/meigma/go-cip-30
```

```go
import "github.com/meigma/go-cip-30"
```

The package is imported as `cip30`.

## Documentation

Project documentation is published from the `docs/` MkDocs site. API reference
and usage guides will be added as the API stabilizes.

## Development

[Moon](https://moonrepo.dev) is the task front door:

```sh
moon run root:format   # format
moon run root:lint     # lint
moon run root:build    # compile all packages
moon run root:test     # run tests
moon run root:check    # the full aggregate gate (also run in CI)
```

CI runs the same aggregate check:

```sh
moon ci --summary minimal
```

Prerequisites: Go 1.26.4 and Moon 2.x. The MkDocs documentation project under
`docs/` additionally needs Python 3.14+ and uv.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for contribution guidelines, local setup
expectations, and the pull request workflow.

## Security

See [SECURITY.md](SECURITY.md) for the private vulnerability reporting path.

## License

A license has not yet been declared for this repository.

[cip30]: https://cips.cardano.org/cip/CIP-30
