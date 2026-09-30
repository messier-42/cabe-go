package ckapclient

// CKAP operation names. Each is used verbatim as:
//
//   - the Op field of *ckap.Error surfaced from the corresponding
//     client method;
//   - the last URL path component of the POST endpoint for CBOR
//     operations (e.g. BaseURL + opPrograde).
const (
	opFederationIdentity  = "FederationIdentity"
	opGetSelf             = "GetSelf"
	opPrograde            = "Prograde"
	opRetrograde          = "Retrograde"
	opAssistedEncapsulate = "AssistedEncapsulate"
	opAssistedDecapsulate = "AssistedDecapsulate"
	opARINToken           = "ARINToken"
	opARIN                = "ARIN"
)
