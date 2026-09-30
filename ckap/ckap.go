// Package ckap defines the transport-independent request and response
// types for each operation in the CABE Key Access Protocol (CKAP). Both
// client and server implementations share these types: a client constructs
// a request and receives a response; a server matches the shapes from the other side.
//
// The types here represent operations in abstract CABE terms ([attrset.Set],
// [cabe.Lease], [cabe.LKAI], [cabe.PrincipalInfo], [cabe.ARINEvent], …)
// and are independent of any given wire format encoding.
package ckap

import (
	"fmt"

	"github.com/messier-42/cabe-go/attrset"
	"github.com/messier-42/cabe-go/cabe"
)

// MediaType is the MIME type for CKAP.
const MediaType = "application/ckap+cbor"

// GetSelfRequest is the request structure for the CKAP GetSelf
// operation. It is currently empty.
type GetSelfRequest struct{}

// GetSelfResponse is the response structure for the CKAP GetSelf
// operation. It carries the Key Server's view of the calling principal.
type GetSelfResponse struct {
	// Information about the calling principal as viewed by the Key
	// Server.
	PrincipalInfo cabe.PrincipalInfo
}

// ProgradeRequest is the request structure for the CKAP Prograde
// operation. It carries the Attribute Set to use for Key Resolution
// and, optionally, an ARIN Token to subscribe the resulting Lease into
// an ARIN Stream.
type ProgradeRequest struct {
	// AttributeSet is the CABE Attribute Set to resolve a Lease for.
	AttributeSet attrset.Set

	// ARINToken is an optional ARIN Token. If non-nil, the Lease
	// returned by the Key Server is subscribed into the associated
	// ARIN Stream and is eligible to receive invalidate events.
	ARINToken []byte
}

// ProgradeResponse is the response structure for the CKAP Prograde
// operation. It carries the Lease created as a result of prograde key
// resolution.
type ProgradeResponse struct {
	// Information about the Lease created as a result of the Prograde
	// operation.
	Lease *cabe.Lease
}

// RetrogradeRequest is the request structure for the CKAP Retrograde
// operation. It carries the Attribute Set and Lease Reference
// extracted from a previously received CBES Envelope, and ultimately
// from a Lease previously created via a Prograde operation.
type RetrogradeRequest struct {
	// Federation quotes the Envelope Origin and any inline or sidecar FLPs.
	// An empty FLP set is valid; the service may already know the capability.
	Federation *RetrogradeFederation

	// The Attribute Set from an Envelope.
	AttributeSet attrset.Set

	// The opaque Lease Reference from an Envelope.
	LeaseRef []byte
}

// RetrogradeResponse is the response structure for the CKAP Retrograde
// operation. It carries the Lease Key Access Information (LKAI)
// provided by the Retrograde operation.
type RetrogradeResponse struct {
	// The Lease Key Access Information.
	LKAI *cabe.LKAI
}

// AssistedEncapsulateRequest is the request structure for the CKAP
// AssistedEncapsulate operation. It carries the Lease Key Access Token
// and the plaintext COSE Content Encryption Key to be wrapped.
type AssistedEncapsulateRequest struct {
	// The Lease Key Access Token previously quoted by the Key Server.
	LKAT []byte
	// The COSE Content Encryption Key to wrap.
	CEK []byte
}

// AssistedEncapsulateResponse is the response structure for the CKAP
// AssistedEncapsulate operation. It carries the wrapped CEK.
type AssistedEncapsulateResponse struct {
	WrappedCEK []byte
}

// AssistedDecapsulateRequest is the request structure for the CKAP
// AssistedDecapsulate operation. It carries the Lease Key Access Token
// and the wrapped Content Encryption Key to be unwrapped.
type AssistedDecapsulateRequest struct {
	// The Lease Key Access Token previously quoted by the Key Server.
	LKAT []byte
	// The wrapped COSE Content Encryption Key to unwrap.
	WrappedCEK []byte
}

// AssistedDecapsulateResponse is the response structure for the CKAP
// AssistedDecapsulate operation. It carries the unwrapped COSE Content
// Encryption Key.
type AssistedDecapsulateResponse struct {
	// The unwrapped COSE Content Encryption Key.
	CEK []byte
}

// GetARINTokenRequest is the request structure for GetARINToken. It is
// currently empty.
type GetARINTokenRequest struct{}

// GetARINTokenResponse is the response structure for GetARINToken. It
// carries a freshly issued ARIN Token. The token is an opaque byte
// string to be quoted in subsequent Prograde requests (via
// ProgradeRequest.ARINToken) and when opening an ARIN Stream.
type GetARINTokenResponse struct {
	// The opaque ARIN Token newly issued by the Key Server.
	Token []byte
}

// Error represents a CKAP error, as indicated by a Key Server.
type Error struct {
	// Code is the CABE error code reported by the Key Server.
	Code cabe.Code

	// Summary is a brief, one-line, human-readable summary of the error.
	Summary string

	// Details provides any additional information a Key Server might
	// choose to provide. The schema is implementation-specific.
	Details map[string]any

	// Op is the name of the operation that failed, e.g. "Prograde".
	Op string

	// Err is the underlying error, if any.
	Err error
}

func (e *Error) Error() string {
	if e == nil {
		return "<nil>"
	}

	summaryLine := fmt.Sprintf("CKAP error %v: operation %q: %q", e.Code, e.Op, e.Summary)

	if e.Err != nil {
		return fmt.Sprintf("%s: %s", summaryLine, e.Err.Error())
	} else {
		return summaryLine
	}
}

func (e *Error) Unwrap() error { return e.Err }

// RetrogradeFederation is the context for foreign key resolution.
type RetrogradeFederation struct {
	OriginDomain string
	FLPs         cabe.FLPSet
}

// FederationIdentityRequest requests the public federation discovery resource.
type FederationIdentityRequest struct{}

// FederationIdentityResponse carries the advertised Domain identity and keys.
type FederationIdentityResponse struct {
	Identity cabe.FederationIdentity
	// CacheControl and Expires preserve the resource's HTTP cache metadata.
	CacheControl string
	Expires      string
}
