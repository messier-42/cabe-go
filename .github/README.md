# cabe-go

[![Go Reference](https://pkg.go.dev/badge/github.com/messier-42/cabe-go.svg)](https://pkg.go.dev/github.com/messier-42/cabe-go) [![CI](https://github.com/messier-42/cabe-go/actions/workflows/build.yml/badge.svg)](https://github.com/messier-42/cabe-go/actions/workflows/build.yml)

This is the official Go client library for [CABE](https://cabespec.org/), a
cryptographic key management architecture for interoperable object-level
encryption of information.

See the [CABE specifications](https://cabespec.org/) for the normative
definition of the protocol.

## Usage

Go 1.25 or later is required.

```shell
go get github.com/messier-42/cabe-go
```

## Building from source

```shell
make build        # Build the library.
make clean        # Remove build artifacts.
make test         # Run unit tests.
make test-race    # Run unit tests with the race detector enabled.
make test-cover   # Run unit tests with the race detector and coveraging.
make lint         # Run golangci-lint.
make vet          # Run go vet.
make sbom         # Generate the SBOM.
make grype        # Scan dependencies for vulnerabilities using Grype.
```

## Specifications

The CABE specifications define the wire protocol and envelope format this
library implements:

- [CABE Architecture](https://cabespec.org/spec/arch/)
- [CABE Baseline Envelope Structure (CBES)](https://cabespec.org/spec/cbes/)
- [CABE Key Access Protocol (CKAP)](https://cabespec.org/spec/ckap/)

## Contributing

Issues and pull requests are welcome. You should run `make test lint` before
submitting a pull request. This repository is licensed under the [Apache 2
license.](../doc/COPYING)
