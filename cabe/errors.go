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
)

const (
	// CodeInternal indicates an unspecified server-side failure. The
	// Summary and Details fields may carry an opaque diagnostic
	// intended for operator inspection rather than programmatic
	// handling.
	CodeInternal Code = 100
)

// Error represents a CKAP operation error, as indicated by a Key Server.
type Error struct {
	// Code is the CABE error code reported by the Key Server.
	Code Code

	// Summary is a brief, one-line, human-readable summary of the error.
	Summary string

	// Details is optional additional information a Key Server might
	// choose to provide. The schema is implementation-specific.
	Details map[string]any

	// Op is the operation name that failed, e.g. "Prograde".
	Op string

	// Err is the underlying error, if any.
	Err error
}

func (e *Error) Error() string {
	if e == nil {
		return "<nil>"
	}
	if e.Err != nil {
		return e.Err.Error()
	}
	if e.Summary != "" {
		return "cabe: " + e.Op + ": " + e.Summary
	}
	return "cabe: operation failed"
}

func (e *Error) Unwrap() error { return e.Err }
