package ckapraw

import (
	"errors"
	"fmt"
	"time"

	"github.com/ldclabs/cose/key"
	"github.com/messier-42/cabe-go/cabe"
)

// ToCABE converts a wire-format ckap.Lease into the abstract cabe.Lease
// used by higher-level CABE code. The non-captive lease key is
// re-serialised to CBOR so callers do not have to import the COSE
// library.
func (in Lease) ToCABE() (*cabe.Lease, error) {
	var federation *cabe.LeaseFederation
	if in.Federation != nil {
		federation = &cabe.LeaseFederation{OriginDomain: in.Federation.OriginDomain, FLPs: in.Federation.FLPs.Clone()}
		if err := federation.Validate(); err != nil {
			return nil, err
		}
	}
	lkai, err := in.LKAI.ToCABE()
	if err != nil {
		return nil, err
	}
	set, err := in.AttributeSet.Parse()
	if err != nil {
		return nil, fmt.Errorf("construct attribute set: %w", err)
	}
	return &cabe.Lease{
		Federation:   federation,
		LeaseID:      in.LeaseID,
		LeaseRef:     append([]byte(nil), in.LeaseRef...),
		AttributeSet: set,
		LKAI:         *lkai,
		Expiry:       time.Unix(in.Expiry, 0).UTC(),
	}, nil
}

// ToCABE converts a wire-format ckap.LKAI into the abstract cabe.LKAI.
// Exactly one of NonCaptive or Captive must be set on the wire; the
// function returns an error otherwise.
func (in LKAI) ToCABE() (*cabe.LKAI, error) {
	switch {
	case in.NonCaptive != nil && in.Captive != nil:
		return nil, errors.New("ckap: LKAI has both captive and non-captive forms")
	case in.NonCaptive != nil:
		raw, err := key.MarshalCBOR(in.NonCaptive.LeaseKey)
		if err != nil {
			return nil, fmt.Errorf("serialise non-captive lease key: %w", err)
		}
		return &cabe.LKAI{NonCaptive: &cabe.LKAINonCaptive{RawCOSEKey: raw}}, nil
	case in.Captive != nil:
		return &cabe.LKAI{Captive: &cabe.LKAICaptive{
			LKAT: append([]byte(nil), in.Captive.LeaseKeyAccessToken...),
		}}, nil
	default:
		return nil, errors.New("ckap: LKAI has neither captive nor non-captive form")
	}
}
