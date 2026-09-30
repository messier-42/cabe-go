package cbes

import (
	"errors"
	"fmt"
	"unicode/utf8"

	"github.com/fxamacker/cbor/v2"
	"github.com/ldclabs/cose/cose"
	"github.com/ldclabs/cose/iana"
	"github.com/ldclabs/cose/key"
	"github.com/messier-42/cabe-go/cabe"
)

// CFAR header labels. Origin is protected; FLPs are unprotected and mutable.
const (
	HeaderOriginDomain = "CABE_OriginDomain"
	HeaderFLPs         = "CABE_FLPs"
)

func inspectFederation(protected, unprotected cose.Headers) (string, cabe.FLPSet, error) {
	if unprotected.Has(HeaderOriginDomain) || protected.Has(HeaderFLPs) {
		return "", nil, errors.New("cbes: federation header in wrong section")
	}
	for _, h := range []cose.Headers{protected, unprotected} {
		if crit, ok := h.Get(iana.HeaderParameterCrit).([]any); ok {
			for _, v := range crit {
				if label, ok := v.(string); ok && (label == HeaderOriginDomain || label == HeaderFLPs) {
					return "", nil, errors.New("cbes: federation header must not be critical")
				}
			}
		}
	}
	var origin string
	if protected.Has(HeaderOriginDomain) {
		var ok bool
		origin, ok = protected.Get(HeaderOriginDomain).(string)
		if !ok || origin == "" || !utf8.ValidString(origin) {
			return "", nil, errors.New("cbes: invalid Origin Domain")
		}
	}
	var flps cabe.FLPSet
	if unprotected.Has(HeaderFLPs) {
		array, ok := unprotected.Get(HeaderFLPs).([]any)
		if !ok || len(array) == 0 {
			return "", nil, errors.New("cbes: FLPs must be a nonempty array")
		}
		flps = make(cabe.FLPSet, len(array))
		for i, v := range array {
			p, ok := v.([]byte)
			if !ok || len(p) == 0 {
				return "", nil, errors.New("cbes: FLP must be a nonempty byte string")
			}
			flps[i] = append([]byte(nil), p...)
		}
		if err := flps.Validate(); err != nil {
			return "", nil, fmt.Errorf("cbes: invalid FLP set: %w", err)
		}
	}
	return origin, flps, nil
}

// SetFLPs replaces an Envelope's inline FLPs without a key or plaintext access.
// Pass an empty set to remove the header. Empty packages and byte-identical
// duplicates are rejected. To add packages, append new entries to the set
// returned by Inspect. The protected header bytes, ciphertext, recipients,
// other unprotected values and tagged/untagged form are preserved. This does
// not perform cryptographic verification or authenticate the packages.
func SetFLPs(envelope []byte, flps cabe.FLPSet) ([]byte, error) {
	if _, err := Inspect(envelope); err != nil {
		return nil, err
	}
	if err := flps.Validate(); err != nil {
		return nil, fmt.Errorf("cbes: invalid FLP set: %w", err)
	}
	content := cose.RemoveCBORTag(envelope)
	prefix := envelope[:len(envelope)-len(content)]
	var parts []cbor.RawMessage
	if err := key.UnmarshalCBOR(content, &parts); err != nil {
		return nil, err
	}
	var headers map[any]cbor.RawMessage
	if err := key.UnmarshalCBOR(parts[1], &headers); err != nil {
		return nil, err
	}
	if len(flps) == 0 {
		delete(headers, HeaderFLPs)
	} else {
		raw, err := key.MarshalCBOR(flps)
		if err != nil {
			return nil, err
		}
		headers[HeaderFLPs] = raw
	}
	raw, err := key.MarshalCBOR(headers)
	if err != nil {
		return nil, fmt.Errorf("cbes: encode unprotected headers: %w", err)
	}
	parts[1] = raw
	raw, err = key.MarshalCBOR(parts)
	if err != nil {
		return nil, err
	}
	return append(append([]byte(nil), prefix...), raw...), nil
}
