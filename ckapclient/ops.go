package ckapclient

// CKAP operation names. Each is used verbatim as:
//
//   - the Op field of *cabe.Error surfaced from the corresponding
//     client method;
//   - the last URL path component of the POST endpoint for CBOR
//     operations (e.g. BaseURL + opPrograde);
//   - the prefix of the wire-level request and response kind fields
//     (e.g. opPrograde + kindRequestSuffix == "ProgradeRequest").
//
// Centralising them here keeps the operation name, the URL path, and
// the kind strings in lockstep. A typo in one place that would
// otherwise pass quietly becomes a compile error.
const (
	opGetSelf             = "GetSelf"
	opPrograde            = "Prograde"
	opRetrograde          = "Retrograde"
	opAssistedEncapsulate = "AssistedEncapsulate"
	opAssistedDecapsulate = "AssistedDecapsulate"
	opARINToken           = "ARINToken"
	opARIN                = "ARIN"
)

// Wire-level kind suffixes as required by the CKAP spec: every
// Request/Response CBOR structure carries a "kind" field set to the
// structure name, e.g. "ProgradeRequest" / "ProgradeResponse".
const (
	kindRequestSuffix  = "Request"
	kindResponseSuffix = "Response"
)
