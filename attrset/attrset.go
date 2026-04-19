// Package attrset provides [Set], a type which represents an Attribute Set as defined in the CABE
// Architecture specification.
//
// Conceptually, Attribute Set is an unordered collection of (name, value) tuples
// with no more than one tuple per name.
//
// # Attribute Names
//
// Attribute names are strings and must conform to the following ABNF grammar:
//
//	ALNUM          = ALPHA / DIGIT
//	ATTRIBUTE_NAME = ALPHA *ALNUM *('-' 1*ALNUM)
//
// The UTF-8 representation of a name may not exceed 255 bytes.
//
// # Attribute Values
//
// Values are arbitrary data items from the CBOR Basic Data Model as defined in [RFC 8949] § 2.
// This package represents values as corresponding Go-native values and manages
// their encoding and decoding as needed.
//
// # Invariants
//
// All Set objects are immutable, safe to copy, concurrency-safe, and enforce the above
// invariants by construction. Once a Set exists, the names of its attributes are known to be
// valid and unique, and its values are known to be representable.
// Consumers can rely on this to avoid re-validating inputs.
//
// [RFC 8949]: https://www.rfc-editor.org/rfc/rfc8949.html
package attrset

import (
	"bytes"
	"errors"
	"fmt"
	"maps"
	"slices"

	"github.com/fxamacker/cbor/v2"
)

const maxNameLen = 255

// detEncMode is the CBOR encoding mode used for Repr. CABE requires
// use of the Core Deterministic encoding rules as defined in
// RFC 8949 § 4.2.1.
var detEncMode cbor.EncMode

// detDecMode is the CBOR decoding mode used for NewFromRepr. It
// restricts the decoding rules used to a subset adequate to decode serialized
// attributes produced using the Core Deterministic encoding rules. It does not,
// by itself, guarantee that an input conforms to those rules. Therefore, it must not
// by itself be used to process serialized inputs; see [Repr.Set] for details.
var detDecMode cbor.DecMode

func init() {
	var err error

	// Encoding mode
	detEncMode, err = cbor.CoreDetEncOptions().EncMode()
	if err != nil {
		panic(fmt.Errorf("cabe/attrset: build deterministic encoder: %w", err))
	}

	// Decoding mode
	detDecMode, err = cbor.DecOptions{
		DupMapKey:        cbor.DupMapKeyEnforcedAPF,
		IndefLength:      cbor.IndefLengthForbidden,
		TagsMd:           cbor.TagsForbidden,
		IntDec:           cbor.IntDecConvertNone,
		UTF8:             cbor.UTF8RejectInvalid,
		MapKeyByteString: cbor.MapKeyByteStringForbidden,
	}.DecMode()
	if err != nil {
		panic(fmt.Errorf("cabe/attrset: build deterministic decoder: %w", err))
	}
}

// InvalidNameError is an error structure used to indicate that an invalid
// Attribute Name was encountered.
type InvalidNameError struct {
	// The invalid name.
	Name string
}

func (err InvalidNameError) Error() string {
	return fmt.Sprintf("cabe/attrset: invalid attribute name %q", err.Name)
}

// Set is a validated, immutable Attribute Set.
// The zero value is an empty, valid Set. Sets may be copied
// by value safely.
type Set struct {
	m    map[string]any
	repr Repr
}

// Repr returns the deterministically serialized CBOR representation of an Attribute Set,
// as defined in CABE. See [Repr] for more information.
func (s *Set) Repr() Repr {
	return s.repr
}

// New constructs a Set from the given map. The keys must be valid attribute
// names (see [ValidName]). The values must be representable as CBOR data items
// in the CBOR Basic Data Model.
//
// If the input is not representable as an Attribute Set, for example because of
// a key which is not a valid attribute name or a value which is not representable
// in the CBOR Basic Data Model, an error is returned. The first error encountered
// is returned; in the case of an invalid attribute name, this is an InvalidNameError
// structure. In the case of an unrepresentable value or other error, the returned error
// is unspecified.
//
// The map passed as m is not used after this function returns; its contents are copied
// into an internal representation.
func New(m map[string]any) (Set, error) {
	// Return constant empty set for {}.
	if len(m) == 0 {
		return emptySet, nil
	}

	// Copy and validate attribute names.
	mm, err := validateAndCloneMap(m)
	if err != nil {
		return emptySet, err
	}

	// Ensure we can encode the representation and cache the
	// serialized representation for ready access.
	mmRepr, err := detEncMode.Marshal(mm)
	if err != nil {
		return emptySet, err
	}

	return Set{m: mm, repr: Repr(mmRepr)}, nil
}

func validateAndCloneMap(m map[string]any) (map[string]any, error) {
	mm := maps.Clone(m)
	for attrName := range mm {
		if !ValidName(attrName) {
			return nil, &InvalidNameError{Name: attrName}
		}
	}
	return mm, nil
}

// Repr is a serialized Attribute Set representation encoded according to the Core Deterministic
// encoding rules as defined in [RFC 8949] and required by CABE.
//
// Two Attribute Sets are equal iff their corresponding Repr values are byte-for-byte identical.
// It is idiomatic to compare Repr values using the equality operator.
//
// To ensure that this invariant holds, Repr values should never be constructed directly
// by a caller, especially from an external source. An external source could provide a serialized
// representation which is valid CBOR and which deserializes correctly, but which is not encoded
// using the Core Deterministic encoding rules and which therefore violates the above invariant.
//
// This package provides a safe set of functions for constructing Set and Repr values safely
// which ensure that the invariant holds and only input which conforms to the deterministic encoding
// rules are accepted. To construct a Repr from a byte string, use [ReprFromBytes].
//
// To convert a Repr to a Set, use [Repr.Decode]. This performs revalidation
// of the canonicality of the representation. Although a Repr obtained following the above rules
// should never fail such reverification, there is nonetheless intentionally no unchecked variant which
// bypasses this reverification.
type Repr string

var emptyRepr = Repr("\xA0") // CBOR deterministic encoding of an empty map
var emptySet = Set{m: nil, repr: emptyRepr}

// Decode returns a Set constructed by deserializing the Repr. The validity and canonicality
// of Repr's encoding is revalidated. This is equivalent to calling [NewFromBytes].
func (r Repr) Decode() (Set, error) {
	return NewFromBytes([]byte(r))
}

// NewFromBytes decodes a serialized Attribute Set back into a Set. It is the
// inverse of [Set.Repr]; `NewFromBytes([]byte(s.Repr()))` is identical
// to s for any given Set s.
//
// This function verifies that a serialized Attribute Set conforms to the Core
// Deterministic encoding rules and rejects inputs which do not
// conform to these rules, even if they are well-formed CBOR encodings. This
// ensures that the [Repr] equality invariant stated above is maintained.
func NewFromBytes(r []byte) (Set, error) {
	// A zero-byte Repr is always invalid — note this is distinct
	// from the valid empty-set Repr {0xa0} (CBOR map with zero
	// pairs), which decodes normally via the path below.
	if len(r) == 0 {
		return Set{}, errors.New("cabe/attrset: zero-length encoding")
	}

	var m map[string]any
	if err := detDecMode.Unmarshal(r, &m); err != nil {
		return Set{}, fmt.Errorf("cabe/attrset: decode error: %w", err)
	}

	s, err := New(m)
	if err != nil {
		return Set{}, err
	}

	// While the strict DecMode above rejects many non-canonical forms,
	// it is not sufficient to reject all of them. Verify round-trip
	// equality the long way by re-encoding and comparing.
	if !bytes.Equal([]byte(s.Repr()), r) {
		return emptySet, errors.New("cabe/attrset: not in deterministic form")
	}

	return s, nil
}

// ReprFromBytes returns a Repr constructed from the given bytestring.
//
// The validity of the input as a canonically serialized Attribute Set is verified
// by round-tripping deserialization and serialization. An error is returned if
// the input is not a valid, deterministically serialized Attribute Set.
//
// This function is equivalent to NewFromBytes(b).Repr().
func ReprFromBytes(b []byte) (Repr, error) {
	s, err := NewFromBytes(b)
	if err != nil {
		return "", err
	}

	return s.Repr(), nil
}

// ValidName reports whether k satisfies the Attribute Set key grammar.
func ValidName(name string) bool {
	if name == "" || len(name) > maxNameLen {
		return false
	}
	if !isAlpha(name[0]) {
		return false
	}
	// After the initial ALPHA, the remainder is *ALNUM *('-' 1*ALNUM): a run of
	// alphanumerics, optionally followed by one or more '-'-separated runs of
	// 1*ALNUM. A trailing '-' is invalid, as is a double '-'.
	prevHyphen := false
	for i := 1; i < len(name); i++ {
		c := name[i]
		switch {
		case isAlnum(c):
			prevHyphen = false
		case c == '-':
			if prevHyphen {
				return false
			}
			prevHyphen = true
		default:
			return false
		}
	}
	return !prevHyphen
}

func isAlpha(c byte) bool {
	return (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z')
}

func isAlnum(c byte) bool {
	return isAlpha(c) || (c >= '0' && c <= '9')
}

// Len returns the number of attributes in s.
func (s Set) Len() int { return len(s.m) }

// Get returns the value of the attribute with the given name.
// The second return value is false if an attribute with the given name is not present.
func (s Set) Get(name string) (any, bool) {
	v, ok := s.m[name]
	return v, ok
}

// Has reports whether s contains an attribute with the given name.
func (s Set) Has(name string) bool {
	_, ok := s.m[name]
	return ok
}

// Names returns the attribute names in sorted order.
func (s Set) Names() []string {
	if len(s.m) == 0 {
		return nil
	}
	return slices.Sorted(maps.Keys(s.m))
}

// Range iterates over s in unspecified order, calling f for each attribute.
// Iteration stops if f returns false.
func (s Set) Range(f func(name string, value any) bool) {
	for k, v := range s.m {
		if !f(k, v) {
			return
		}
	}
}

// Map returns a new (copied) map value representing the contents of the Attribute Set.
// Returns nil for the empty set.
func (s Set) Map() map[string]any {
	if len(s.m) == 0 {
		return nil
	}
	return maps.Clone(s.m)
}
