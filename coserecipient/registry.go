// Package coserecipient provides extensible COSE recipient key management.
// It complements the COSE library's message and content-encryption support.
// Dispatch uses algorithm identifiers; keys and their parameters remain opaque
// to the registry. Each provider implements its algorithm's key validation,
// key distribution, and critical-header processing.
package coserecipient

import (
	"errors"
	"fmt"
	"math"
	"reflect"
	"sync"

	"github.com/ldclabs/cose/cose"
	"github.com/ldclabs/cose/iana"
	"github.com/ldclabs/cose/key"
)

// ErrUnsupportedAlgorithm identifies an algorithm with no registered provider.
var ErrUnsupportedAlgorithm = errors.New("coserecipient: unsupported algorithm")

// Context contains COSE inputs a provider may need for its key schedule.
// Maps, slices, and keys passed to providers are read-only. RecipientProtected
// and RecipientEncoded contain the exact received bytes during recovery and are
// nil during generation. RecipientEncoded preserves nested encodings as well.
type Context struct {
	BodyProtected      []byte
	BodyUnprotected    cose.Headers
	ExternalAAD        []byte
	RecipientProtected []byte
	RecipientEncoded   []byte
}

// Algorithm distributes and recovers a caller-supplied content key. A provider
// must preserve that key rather than substitute a derived content key. It owns
// algorithm-specific key parameters, key_ops and critical-header validation.
// It must not modify its inputs and must be safe for concurrent calls if shared.
// No particular asymmetric key family, KDF, or key-wrap primitive is assumed.
type Algorithm interface {
	WrapKey(publicKey key.Key, cek []byte, context Context) (*cose.Recipient, error)
	UnwrapKey(secretKey key.Key, recipient *cose.Recipient, context Context) ([]byte, error)
}

// Registry dispatches recipient operations by COSE algorithm identifier.
// Its zero value is an empty registry. Register and dispatch are concurrency-safe;
// a Registry must not be copied after first use. Registration never inspects kty.
type Registry struct {
	mu         sync.RWMutex
	algorithms map[any]Algorithm
}

// NewRegistry returns an independent registry with the standard providers.
// Currently these implement ECDH-ES with AES Key Wrap. This set is extensible
// through Register and is not an allowlist of key types or algorithms.
func NewRegistry() *Registry {
	r := &Registry{}
	registerStandardAlgorithms(r)
	return r
}

// Default supplies standard providers and accepts additional registrations.
// Register private-fork algorithms here, or use an independent Registry.
// Do not reassign Default while it is in use.
var Default = NewRegistry()

// Register associates a COSE integer or text algorithm identifier with a
// provider. Duplicate registrations are errors; existing providers cannot be
// silently replaced. Use an empty Registry to supply a different implementation
// of a standard algorithm. This method does not allocate registry identifiers.
func (r *Registry) Register(algorithm any, implementation Algorithm) error {
	id, err := algorithmID(algorithm)
	if err != nil {
		return err
	}
	if implementation == nil {
		return errors.New("coserecipient: nil implementation")
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.algorithms == nil {
		r.algorithms = make(map[any]Algorithm)
	}
	if _, exists := r.algorithms[id]; exists {
		return fmt.Errorf("coserecipient: algorithm %v already registered", algorithm)
	}
	r.algorithms[id] = implementation
	return nil
}

func (r *Registry) lookup(id any) (Algorithm, error) {
	r.mu.RLock()
	a, ok := r.algorithms[id]
	r.mu.RUnlock()
	if !ok {
		return nil, fmt.Errorf("%w: %v", ErrUnsupportedAlgorithm, id)
	}
	return a, nil
}

// WrapKey selects the public key's explicit alg. It never guesses from kty or
// other key parameters. The provider must emit the same algorithm in its result.
func (r *Registry) WrapKey(k key.Key, cek []byte, ctx Context) (*cose.Recipient, error) {
	id, err := algorithmID(k.Get(iana.KeyParameterAlg))
	if err != nil {
		return nil, err
	}
	a, err := r.lookup(id)
	if err != nil {
		return nil, err
	}
	recipient, err := a.WrapKey(k, cek, ctx)
	if err != nil {
		return nil, err
	}
	got, err := recipientAlgorithm(recipient)
	if err != nil {
		return nil, err
	}
	if got != id {
		return nil, errors.New("coserecipient: provider returned a different algorithm")
	}
	return recipient, nil
}

// UnwrapKey selects the received recipient algorithm and checks agreement with
// the key's alg if present. Key type and cryptographic validity are the selected
// provider's responsibility. Unknown algorithms do not trigger a fallback.
func (r *Registry) UnwrapKey(k key.Key, recipient *cose.Recipient, ctx Context) ([]byte, error) {
	id, err := recipientAlgorithm(recipient)
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
	a, err := r.lookup(id)
	if err != nil {
		return nil, err
	}
	return a.UnwrapKey(k, recipient, ctx)
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
	if err := checkCritical(r.Protected, func(any) bool { return true }); err != nil {
		return nil, err
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
