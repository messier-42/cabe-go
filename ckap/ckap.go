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
	"github.com/messier-42/cabe-go/attrset"
	"github.com/messier-42/cabe-go/cabe"
)

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
