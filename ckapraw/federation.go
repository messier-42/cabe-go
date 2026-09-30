package ckapraw

import (
	"errors"
	"unicode/utf8"

	"github.com/fxamacker/cbor/v2"
	"github.com/ldclabs/cose/iana"
	"github.com/ldclabs/cose/key"
	"github.com/messier-42/cabe-go/cabe"
)

// LeaseFederation is the optional federation member of a Lease.
type LeaseFederation struct {
	OriginDomain string      `cbor:"originDomain"`
	FLPs         cabe.FLPSet `cbor:"flps,omitempty"`
}

// RetrogradeFederation quotes an Origin and a required, possibly empty FLP set.
type RetrogradeFederation struct {
	OriginDomain string      `cbor:"originDomain"`
	FLPs         cabe.FLPSet `cbor:"flps"`
}

// MarshalCBOR preserves the distinction between absent and empty Lease FLPs.
func (f LeaseFederation) MarshalCBOR() ([]byte, error) {
	if err := (cabe.LeaseFederation{OriginDomain: f.OriginDomain, FLPs: f.FLPs}).Validate(); err != nil {
		return nil, err
	}
	m := map[string]any{"originDomain": f.OriginDomain}
	if f.FLPs != nil {
		m["flps"] = f.FLPs
	}
	return key.MarshalCBOR(m)
}

// UnmarshalCBOR validates the federation metadata on receipt.
func (f *LeaseFederation) UnmarshalCBOR(data []byte) error {
	origin, flps, err := decodeFederation(data, false)
	if err != nil {
		return err
	}
	*f = LeaseFederation{OriginDomain: origin, FLPs: flps}
	return nil
}

// MarshalCBOR emits an array even when the request's FLP set is nil.
func (f RetrogradeFederation) MarshalCBOR() ([]byte, error) {
	if err := (cabe.LeaseFederation{OriginDomain: f.OriginDomain, FLPs: f.FLPs}).Validate(); err != nil {
		return nil, err
	}
	flps := f.FLPs
	if flps == nil {
		flps = cabe.FLPSet{}
	}
	return key.MarshalCBOR(map[string]any{"originDomain": f.OriginDomain, "flps": flps})
}

// UnmarshalCBOR rejects an absent required FLP set, while accepting an empty one.
func (f *RetrogradeFederation) UnmarshalCBOR(data []byte) error {
	origin, flps, err := decodeFederation(data, true)
	if err != nil {
		return err
	}
	*f = RetrogradeFederation{OriginDomain: origin, FLPs: flps}
	return nil
}

func decodeFederation(data []byte, required bool) (string, cabe.FLPSet, error) {
	var fields map[string]cbor.RawMessage
	if err := key.UnmarshalCBOR(data, &fields); err != nil {
		return "", nil, err
	}
	var f cabe.LeaseFederation
	if err := key.UnmarshalCBOR(fields["originDomain"], &f.OriginDomain); err != nil {
		return "", nil, err
	}
	raw, ok := fields["flps"]
	if required && !ok {
		return "", nil, errors.New("ckap: missing federation flps")
	}
	if ok {
		if len(raw) == 0 || raw[0]>>5 != 4 {
			return "", nil, errors.New("ckap: flps must be an array")
		}
		if err := key.UnmarshalCBOR(raw, &f.FLPs); err != nil {
			return "", nil, err
		}
	}
	return f.OriginDomain, f.FLPs, f.Validate()
}

// FederationIdentity is the public CKAP discovery resource.
type FederationIdentity struct {
	Kind     string                `cbor:"kind"`
	DomainID string                `cbor:"domainID"`
	Keys     []FederationPublicKey `cbor:"keys"`
}

// MarshalCBOR encodes an empty advertised key set as an array.
func (f FederationIdentity) MarshalCBOR() ([]byte, error) {
	type wireIdentity FederationIdentity
	w := wireIdentity(f)
	if w.Keys == nil {
		w.Keys = []FederationPublicKey{}
	}
	return key.MarshalCBOR(w)
}

// FederationPublicKey is an advertised COSE federation public key.
type FederationPublicKey struct {
	PublicKey COSEKey `cbor:"publicKey"`
	Status    string  `cbor:"status"`
}

// ToCABE validates and converts the resource without selecting a key algorithm.
func (f FederationIdentity) ToCABE() (*cabe.FederationIdentity, error) {
	if f.DomainID == "" || !utf8.ValidString(f.DomainID) || f.Keys == nil {
		return nil, errors.New("ckap: invalid FederationIdentity")
	}
	out := &cabe.FederationIdentity{DomainID: f.DomainID, Keys: make([]cabe.FederationPublicKey, len(f.Keys))}
	for i, k := range f.Keys {
		kid, err := k.PublicKey.GetBytes(iana.KeyParameterKid)
		if err != nil || len(kid) == 0 {
			return nil, errors.New("ckap: federation key missing kid")
		}
		switch k.Status {
		case "current", "future", "retired":
		default:
			return nil, errors.New("ckap: invalid federation key status")
		}
		raw, err := key.MarshalCBOR(k.PublicKey)
		if err != nil {
			return nil, err
		}
		out.Keys[i] = cabe.FederationPublicKey{RawCOSEKey: raw, Status: k.Status}
	}
	return out, nil
}

func (f *FederationIdentity) GetKind() string   { return f.Kind }
func (*FederationIdentity) DefaultKind() string { return KindFederationIdentity }
