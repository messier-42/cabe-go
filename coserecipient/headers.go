package coserecipient

import (
	"errors"
	"fmt"

	"github.com/ldclabs/cose/cose"
	"github.com/ldclabs/cose/iana"
	"github.com/ldclabs/cose/key"
)

func checkCritical(h cose.Headers, understood func(any) bool) error {
	if !h.Has(iana.HeaderParameterCrit) {
		return nil
	}
	// Callers can construct typed Go arrays as well as decoded []any values.
	// Normalize through the COSE encoder before checking their structure.
	raw, err := key.MarshalCBOR(h.Get(iana.HeaderParameterCrit))
	if err != nil {
		return err
	}
	var labels []any
	if err := key.UnmarshalCBOR(raw, &labels); err != nil {
		return err
	}
	if len(labels) == 0 {
		return errors.New("coserecipient: malformed crit")
	}
	for _, v := range labels {
		var label any
		if s, ok := v.(string); ok {
			label = s
		} else {
			n, err := integer(v)
			if err != nil {
				return err
			}
			label = n
		}
		if !h.Has(label) || !understood(label) {
			return fmt.Errorf("coserecipient: unsupported critical header %v", label)
		}
	}
	return nil
}

func headerBytes(p, u cose.Headers, label any) ([]byte, error) {
	if p.Has(label) {
		return p.GetBytes(label)
	}
	if u.Has(label) {
		return u.GetBytes(label)
	}
	return nil, fmt.Errorf("coserecipient: missing byte-string header %v", label)
}

// integer checks the type before calling the dependency's reflection helper,
// which assumes a non-nil value.
func integer(v any) (int, error) {
	switch v.(type) {
	case int, int8, int16, int32, int64, uint, uint8, uint16, uint32, uint64, key.Alg:
		return key.ToInt(v)
	}
	return 0, fmt.Errorf("coserecipient: expected integer, got %T", v)
}

func headerValue(r *cose.Recipient, label any) any {
	if r.Protected.Has(label) {
		return r.Protected.Get(label)
	}
	return r.Unprotected.Get(label)
}
