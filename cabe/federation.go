package cabe

import (
	"bytes"
	"errors"
	"unicode/utf8"
)

// FLPSet is a set of opaque Federated Lease Packages. A nil set and an empty
// set are both valid; their wire representation depends on the containing object.
type FLPSet [][]byte

// Validate rejects empty packages and byte-identical duplicates.
func (s FLPSet) Validate() error {
	seen := make(map[string]struct{}, len(s))
	for _, p := range s {
		if len(p) == 0 {
			return errors.New("cabe: empty FLP")
		}
		if _, ok := seen[string(p)]; ok {
			return errors.New("cabe: duplicate FLP")
		}
		seen[string(p)] = struct{}{}
	}
	return nil
}

// Clone returns an independent copy, preserving nil versus empty sets.
func (s FLPSet) Clone() FLPSet {
	if s == nil {
		return nil
	}
	out := make(FLPSet, len(s))
	for i, p := range s {
		out[i] = bytes.Clone(p)
	}
	return out
}

// LeaseFederation is the Origin Domain and optional FLPs reported with a Lease.
type LeaseFederation struct {
	OriginDomain string
	FLPs         FLPSet
}

// Validate checks the Domain ID and FLP set.
func (f LeaseFederation) Validate() error {
	if f.OriginDomain == "" || !utf8.ValidString(f.OriginDomain) {
		return errors.New("cabe: invalid Origin Domain ID")
	}
	return f.FLPs.Validate()
}

// Clone returns an independent copy. A nil receiver returns nil.
func (f *LeaseFederation) Clone() *LeaseFederation {
	if f == nil {
		return nil
	}
	return &LeaseFederation{OriginDomain: f.OriginDomain, FLPs: f.FLPs.Clone()}
}

// FederationPublicKey advertises a COSE public key and its rollover status.
// RawCOSEKey preserves the complete CBOR COSE_Key, including its FKID in kid.
type FederationPublicKey struct {
	RawCOSEKey []byte
	Status     string
}

// FederationIdentity describes a Domain's advertised federation public keys.
// All advertised keys are valid, including future and retired keys.
type FederationIdentity struct {
	DomainID string
	Keys     []FederationPublicKey
}
