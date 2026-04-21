package cabe

// Code is a CABE error code reported by a Key Server in a CKAP Error
// structure. These codes are the baseline set; future CKAP specification
// revisions may extend the catalogue.
type Code int

const (
	// CodeReserved is reserved and MUST NOT be sent by a Key Server.
	CodeReserved Code = iota

	// CodeMalformedRequest indicates the Key Server could not parse
	// the request, or the request violated a structural requirement
	// of CKAP (wrong content type, missing required field, etc.).
	CodeMalformedRequest

	// CodeUnauthorized indicates the request was rejected because the
	// Key Server could not authenticate the caller. This is distinct
	// from CodePolicyDenied, which applies to an authenticated caller
	// whose Principal is not authorised for the requested operation.
	CodeUnauthorized

	// CodePolicyDenied indicates an authenticated Principal was denied
	// access to the requested Envelope Set or operation by the Key
	// Server's Policy.
	CodePolicyDenied

	// CodeInvalidRef indicates a quoted Lease Reference (Retrograde
	// resolution or Assisted Encapsulation/Decapsulation via an LKAT)
	// was not recognised by the Key Server.
	CodeInvalidRef

	// CodeUnsupported indicates the requested operation is not
	// supported by this Key Server implementation. For example, a Key
	// Server that does not implement ARIN returns this code in response
	// to an ARINToken request.
	CodeUnsupported

	// CodeInvalidAttributeSet indicates the supplied Attribute Set is
	// not well-formed (e.g. invalid key grammar, value outside the CBOR
	// Basic Data Model, duplicate keys).
	CodeInvalidAttributeSet

	// CodeRequestTooLarge indicates the request body exceeded the
	// Key Server's configured size limit. It is reported with HTTP
	// status 413 (Payload Too Large) over the HTTP transport.
	CodeRequestTooLarge
)

const (
	// CodeInternal indicates an unspecified server-side failure. The
	// Summary and Details fields may carry an opaque diagnostic
	// intended for operator inspection rather than programmatic
	// handling.
	CodeInternal Code = 100
)
