// Package cbes provides functionality for working with CBES envelopes.
//
// Currently, only envelope inspection is exposed here. For
// encapsulation/decapsulation, see the high-level cabecap package.
package cbes

import (
	"errors"
	"fmt"

	"github.com/ldclabs/cose/cose"
	"github.com/ldclabs/cose/iana"
	"github.com/messier-42/cabe-go/attrset"
)

// COSE header label strings used by CBES to carry CABE-specific fields
// in the protected header.
const (
	HeaderAttributeSet = "CABE_AttributeSet"
	HeaderLeaseRef     = "CABE_LeaseRef"
)

// COSETag identifies a COSE structural tag used by CBES envelopes.
// Values match the CBOR tag numbers assigned by RFC 9052.
type COSETag int

const (
	// TagCOSEEncrypt0 corresponds to a non-captive (Encrypt0) CBES
	// envelope. RFC 9052 CBOR tag 16.
	TagCOSEEncrypt0 COSETag = 16
	// TagCOSEEncrypt corresponds to a captive (Encrypt, with recipients)
	// CBES envelope. RFC 9052 CBOR tag 96.
	TagCOSEEncrypt COSETag = 96
)

// allowedAlgorithms is the set of COSE content encryption algorithm
// identifiers this package is willing to decode. An envelope declaring
// any other algorithm is rejected by [Inspect] as an invalid envelope.
var allowedAlgorithms = map[int]struct{}{
	iana.AlgorithmA128GCM:          {},
	iana.AlgorithmA192GCM:          {},
	iana.AlgorithmA256GCM:          {},
	iana.AlgorithmChaCha20Poly1305: {},
	iana.AlgorithmA128KW:           {},
	iana.AlgorithmA192KW:           {},
	iana.AlgorithmA256KW:           {},
}

// InspectResult describes the COSE/CBES-related headers of a CBES
// envelope. It is produced by [Inspect]. No cryptographic verification
// is performed; every field reflects only what the protected or
// unprotected headers declare.
type InspectResult struct {
	// AttributeSet is the decoded Attribute Set declared in the
	// protected header. Inspect rejects envelopes whose Attribute Set
	// encodings are not canonical.
	AttributeSet attrset.Set

	// LeaseRef is the opaque Lease Reference declared in the protected
	// header.
	LeaseRef []byte

	// ContentType is the COSE Content Type header value, or "" if
	// the envelope did not specify one.
	ContentType string

	// IsCaptive is true if the envelope was encrypted using a captive
	// Lease Key.
	IsCaptive bool

	// Tag identifies the COSE structure used by the envelope.
	Tag COSETag

	// Alg is the COSE content encryption algorithm identifier from the
	// protected header. Only values supported by this package are
	// returned; Inspect rejects envelopes declaring any other
	// algorithm.
	Alg int

	// ProtectedHeaderSize is the length of the serialised protected
	// header map in bytes.
	ProtectedHeaderSize int

	// PartialIV is the `Partial IV` unprotected header when IsCaptive is
	// false, nil otherwise.
	PartialIV []byte

	// IV is the `IV` unprotected header when IsCaptive is true, nil
	// otherwise.
	IV []byte
}

// Inspect parses a CBES envelope's headers without performing
// cryptographic verification. It returns an [InspectResult] describing
// the envelope's shape and parameters. Returned errors indicate an
// envelope-level problem (malformed CBOR, missing or inconsistent CBES
// headers, a non-canonically encoded Attribute Set, or an unsupported
// content-encryption algorithm).
func Inspect(data []byte) (InspectResult, error) {
	var msg cose.Encrypt0Message[[]byte]
	e0Err := msg.UnmarshalCBOR(data)
	if e0Err == nil {
		return inspectEncrypt0(msg)
	}

	var emsg cose.EncryptMessage[[]byte]
	eErr := emsg.UnmarshalCBOR(data)
	if eErr == nil {
		return inspectEncrypt(emsg)
	}

	return InspectResult{}, fmt.Errorf("cbes: parse envelope: not a COSE_Encrypt0 (%w) or COSE_Encrypt (%w)", e0Err, eErr)
}

func inspectEncrypt0(msg cose.Encrypt0Message[[]byte]) (InspectResult, error) {
	attr, err := validatedAttributeSet(msg.Protected)
	if err != nil {
		return InspectResult{}, err
	}
	leaseRef, err := msg.Protected.GetBytes(HeaderLeaseRef)
	if err != nil {
		return InspectResult{}, fmt.Errorf("cbes: read lease reference header: %w", err)
	}
	if len(leaseRef) == 0 {
		return InspectResult{}, errors.New("cbes: empty or missing lease reference header")
	}
	partialIV, _ := msg.Unprotected.GetBytes(iana.HeaderParameterPartialIV)
	iv, _ := msg.Unprotected.GetBytes(iana.HeaderParameterIV)
	if len(partialIV) == 0 {
		return InspectResult{}, errors.New("cbes: COSE_Encrypt0 envelope missing Partial IV")
	}
	if len(iv) != 0 {
		return InspectResult{}, errors.New("cbes: COSE_Encrypt0 envelope must not carry IV")
	}
	alg, _ := msg.Protected.GetInt(iana.HeaderParameterAlg)
	if _, ok := allowedAlgorithms[alg]; !ok {
		return InspectResult{}, fmt.Errorf("cbes: unsupported content encryption algorithm %d", alg)
	}
	protSize, err := protectedHeaderSize(msg.Protected)
	if err != nil {
		return InspectResult{}, err
	}

	return InspectResult{
		AttributeSet:        attr,
		LeaseRef:            leaseRef,
		ContentType:         contentType(msg.Protected),
		IsCaptive:           false,
		Tag:                 TagCOSEEncrypt0,
		Alg:                 alg,
		ProtectedHeaderSize: protSize,
		PartialIV:           append([]byte(nil), partialIV...),
	}, nil
}

func inspectEncrypt(msg cose.EncryptMessage[[]byte]) (InspectResult, error) {
	attr, err := validatedAttributeSet(msg.Protected)
	if err != nil {
		return InspectResult{}, err
	}
	leaseRef, err := msg.Protected.GetBytes(HeaderLeaseRef)
	if err != nil {
		return InspectResult{}, fmt.Errorf("cbes: read lease reference header: %w", err)
	}
	if len(leaseRef) == 0 {
		return InspectResult{}, errors.New("cbes: empty or missing lease reference header")
	}
	iv, _ := msg.Unprotected.GetBytes(iana.HeaderParameterIV)
	partialIV, _ := msg.Unprotected.GetBytes(iana.HeaderParameterPartialIV)
	if len(iv) == 0 {
		return InspectResult{}, errors.New("cbes: COSE_Encrypt envelope missing IV")
	}
	if len(partialIV) != 0 {
		return InspectResult{}, errors.New("cbes: COSE_Encrypt envelope must not carry Partial IV")
	}
	alg, _ := msg.Protected.GetInt(iana.HeaderParameterAlg)
	if _, ok := allowedAlgorithms[alg]; !ok {
		return InspectResult{}, fmt.Errorf("cbes: unsupported content encryption algorithm %d", alg)
	}
	protSize, err := protectedHeaderSize(msg.Protected)
	if err != nil {
		return InspectResult{}, err
	}

	return InspectResult{
		AttributeSet:        attr,
		LeaseRef:            leaseRef,
		ContentType:         contentType(msg.Protected),
		IsCaptive:           true,
		Tag:                 TagCOSEEncrypt,
		Alg:                 alg,
		ProtectedHeaderSize: protSize,
		IV:                  append([]byte(nil), iv...),
	}, nil
}

// validatedAttributeSet reads the CABE Attribute Set bytes from h and
// decodes them into an [attrset.Set]. The underlying bytes must be a
// well-formed canonically-encoded Attribute Set.
func validatedAttributeSet(h cose.Headers) (attrset.Set, error) {
	raw, err := h.GetBytes(HeaderAttributeSet)
	if err != nil {
		return attrset.Set{}, fmt.Errorf("cbes: read attribute set header: %w", err)
	}
	if len(raw) == 0 {
		return attrset.Set{}, errors.New("cbes: empty or missing attribute set header")
	}
	set, err := attrset.NewFromBytes(raw)
	if err != nil {
		return attrset.Set{}, fmt.Errorf("cbes: decode attribute set: %w", err)
	}
	return set, nil
}

// protectedHeaderSize returns the CBOR-encoded byte length of h. Used
// for diagnostic output; the zero-length case short-circuits so that
// an absent/empty header reports as 0 instead of 1 (a bare 0xA0 CBOR
// empty map).
func protectedHeaderSize(h cose.Headers) (int, error) {
	if len(h) == 0 {
		return 0, nil
	}
	b, err := h.Bytes()
	if err != nil {
		return 0, fmt.Errorf("encode protected header: %w", err)
	}
	return len(b), nil
}

// contentType reads the COSE Content Type header from h, accepting
// both the string and the []byte CBOR encodings. Returns "" if the
// header is absent or carries an unexpected type.
func contentType(h cose.Headers) string {
	v := h.Get(iana.HeaderParameterContentType)
	switch x := v.(type) {
	case string:
		return x
	case []byte:
		return string(x)
	default:
		return ""
	}
}
