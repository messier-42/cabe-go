// Package coserecipient provides COSE recipient key management.
// Recipient operations select an internal construction from the COSE algorithm
// identifier and use the COSE library for key conversion, agreement and KDFs.
package coserecipient

import (
	"errors"
	"fmt"
	"math"
	"reflect"

	"github.com/ldclabs/cose/cose"
	"github.com/ldclabs/cose/iana"
	"github.com/ldclabs/cose/key"
)

// ErrUnsupportedAlgorithm identifies an unsupported recipient algorithm.
var ErrUnsupportedAlgorithm = errors.New("coserecipient: unsupported algorithm")

// Context contains inputs to recipient key management. Keys and slices are
// read-only. RecipientProtected must contain the exact received protected-header
// bytes during recovery; it is unused during generation.
type Context struct {
	RecipientProtected []byte
	// SenderKey supplies the sender's private key for static agreement during
	// generation, or a resolved public key for a received static key identifier.
	// An embedded sender public key does not establish its identity or trust.
	SenderKey key.Key
	// ContentAlgorithm and KeySize describe the derived content key. They are
	// required for KDF-based direct derivation and its recovery.
	ContentAlgorithm any
	KeySize          int
	// RequireWrappedKey rejects direct recipients during recovery when the
	// enclosing protocol requires a separately chosen, distributed content key.
	RequireWrappedKey bool
}

// WrapKey distributes cek using the key's explicit recipient algorithm.
// Direct algorithms cannot distribute an independently supplied key.
func WrapKey(k key.Key, cek []byte, ctx Context) (*cose.Recipient, error) {
	id, err := algorithmID(k.Get(iana.KeyParameterAlg))
	if err != nil {
		return nil, err
	}
	a, err := selectAlgorithm(id)
	if err != nil {
		return nil, err
	}
	return a.wrapKey(k, cek, ctx)
}

// UnwrapKey recovers the recipient's content key. The received algorithm selects
// the construction and must match the key's alg if present. KDF-based direct
// derivation requires ContentAlgorithm and KeySize in ctx.
func UnwrapKey(k key.Key, r *cose.Recipient, ctx Context) ([]byte, error) {
	id, err := recipientAlgorithm(r)
	if err != nil {
		return nil, err
	}
	if k.Has(iana.KeyParameterAlg) {
		keyID, err := algorithmID(k.Get(iana.KeyParameterAlg))
		if err != nil {
			return nil, err
		}
		if keyID != id {
			return nil, errors.New("coserecipient: key algorithm mismatch")
		}
	}
	a, err := selectAlgorithm(id)
	if err != nil {
		return nil, err
	}
	return a.unwrapKey(k, r, ctx)
}

// DeriveKey creates a recipient and its content key for a direct algorithm.
// This does not distribute a caller-supplied random key and must not be used
// by protocols that require that property, such as SFLP. Direct recipients
// cannot be mixed with key-wrapping recipients in a message.
func DeriveKey(k key.Key, ctx Context) ([]byte, *cose.Recipient, error) {
	id, err := algorithmID(k.Get(iana.KeyParameterAlg))
	if err != nil {
		return nil, nil, err
	}
	a, err := selectAlgorithm(id)
	if err != nil {
		return nil, nil, err
	}
	return a.deriveKey(k, ctx)
}

func recipientAlgorithm(r *cose.Recipient) (any, error) {
	if r == nil {
		return nil, errors.New("coserecipient: nil recipient")
	}
	for label := range r.Protected {
		if r.Unprotected.Has(label) {
			return nil, errors.New("coserecipient: header present in both sections")
		}
	}
	if r.Unprotected.Has(iana.HeaderParameterCrit) {
		return nil, errors.New("coserecipient: unprotected crit")
	}
	return algorithmID(headerValue(r, iana.HeaderParameterAlg))
}

// Normalize all Go integer representations without truncation. COSE also permits
// text identifiers, including private algorithms; do not convert these to ints.
func algorithmID(value any) (any, error) {
	if value != nil {
		v := reflect.ValueOf(value)
		kind := v.Kind()
		if kind == reflect.String {
			return v.String(), nil
		}
		if kind >= reflect.Int && kind <= reflect.Int64 {
			return v.Int(), nil
		}
		if kind >= reflect.Uint && kind <= reflect.Uint64 && v.Uint() <= math.MaxInt64 {
			return int64(v.Uint()), nil
		}
	}
	return nil, fmt.Errorf("coserecipient: invalid or missing algorithm: %T", value)
}
