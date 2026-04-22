package ckapraw

import (
	"errors"

	"github.com/fxamacker/cbor/v2"
	"github.com/messier-42/cabe-go/attrset"
)

// cborEmptyMap is the CBOR core deterministic encoding rules encoding of an
// empty map.
var cborEmptyMap = []byte{0xA0}

// AttrSet is the CKAP wire-level placeholder for an Attribute Set. It
// intentionally carries the raw CBOR encoding of the field for deferred
// processing rather than parsing it at unmarshal time.
//
// This split exists so that callers (e.g. a CKAP transport) can first
// decode the enclosing request structure and report protocol-level
// errors (malformed request, wrong kind, missing required fields) on
// one error path, and then parse the Attribute Set (e.g. via [AttrSet.Parse])
// to surface errors specific to the Attribute Set encoding (e.g. non-canonical
// encoding, invalid attribute name, etc.) This makes it possible to unmarshal
// structures with badly encoded Attribute Sets and at least do some basic
// processing to provide better error handling, and use the correct CKAP
// error code for Attribute Set-related encoding issues.
//
// The zero value encodes as a validly-encoded empty attribute set. Callers
// should set a value using [AttrSet.Set], and readers should call
// [AttrSet.Parse] to obtain a validated [attrset.Set].
type AttrSet struct {
	// raw holds the (purported, not necessarily validated) CBOR encoding of the
	// Attribute Set map as it appeared on the wire (on decode) or as
	// [AttrSEt.Set] populated it.
	raw cbor.RawMessage
}

// MarshalCBOR implements cbor.Marshaler. It emits the raw bytes obtained
// previously by UnmarshalCBOR or Set. Note that if the data came from
// UnmarshalCBOR (i.e., an external source), this function can pass that
// encoding on even if it is invalid.
func (a AttrSet) MarshalCBOR() ([]byte, error) {
	toCopy := a.raw
	if len(toCopy) == 0 {
		toCopy = cborEmptyMap
	}

	// Return a copy so downstream callers cannot mutate our stored bytes.
	out := make([]byte, len(toCopy))
	copy(out, toCopy)
	return out, nil
}

// UnmarshalCBOR implements cbor.Unmarshaler. It copies the raw CBOR bytes
// verbatim without validation; it performs no parsing and no canonicality
// check. Use [AttrSet.Parse] to subsequently decode and validate.
func (a *AttrSet) UnmarshalCBOR(data []byte) error {
	if a == nil {
		return errors.New("ckapraw: UnmarshalCBOR on nil *AttrSet")
	}

	a.raw = append(a.raw[:0], data...)
	return nil
}

// IsZero reports whether the receiver holds no bytes. The CBOR library
// consults this for struct fields tagged `omitempty`: a zero-value AttrSet is
// omitted from the encoded map rather than emitted as an empty-map value.
//
// This function intentionally distinguishes the len() == 0 case from an
// empty-map encoding to allow the latter to be used to affirmatively express
// an empty attribute set.
func (a AttrSet) IsZero() bool {
	return len(a.raw) == 0
}

// Parse decodes and validates the captured CBOR bytes as a CABE Attribute Set,
// returning an [attrset.Set]. The bytes must be in Core Deterministic form as
// per RFC 8949 s. 4.2.1, and must satisfy the CABE Attribute Set requirements.
//
// Parse is intentionally a separate step from CBOR unmarshalling of the
// enclosing request; this allows the caller to handle Attribute Set-level
// errors differently to overall CBOR encoding issues.
//
// A zero-value AttrSet (e.g. one that was never populated by UnmarshalCBOR or
// Set) parses to the empty Attribute Set.
func (a AttrSet) Parse() (attrset.Set, error) {
	if len(a.raw) == 0 {
		return attrset.Set{}, nil
	}

	return attrset.NewFromBytes([]byte(a.raw))
}

// Set populates the [AttrSet] from a validated CABE [attrset.Set]. The Set's
// canonical CBOR representation (Set.Repr) is stored verbatim.
func (a *AttrSet) Set(s attrset.Set) {
	a.raw = append(a.raw[:0], []byte(s.Repr())...)
}

// FromSet returns an AttrSet populated from s. It is equivalent
// to constructing a zero AttrSet and calling Set(s), but is more
// convenient inside struct literals.
func FromSet(s attrset.Set) AttrSet {
	var a AttrSet
	a.Set(s)
	return a
}
