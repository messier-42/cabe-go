// Package cabego provides the official Go client library for the [CABE] ecosystem.
//
// The library is split into the following packages:
//
//   - `cabe`, providing common types and utility functions common to all CABE software.
//
//   - `attrset`, providing a safe interface for working with, serializing and deserializing
//     CABE Attribute Set representations.
//
//   - `ckapclient`, providing low level raw CKAP protocol operations.
//
//   - `cabecap`, providing a managed CABE Encapsulator/Decapsulator.
//
//   - `cbes`, providing utilities for extracting information from CBES Envelope headers.
//
// Most applications will want to use the high-level `cabecap` interface.
//
// [CABE]: https://cabespec.org/
package cabego
