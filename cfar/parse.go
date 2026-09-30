package cfar

import (
	"bytes"
	"errors"
	"fmt"

	"github.com/fxamacker/cbor/v2"
	"github.com/ldclabs/cose/cose"
	"github.com/ldclabs/cose/iana"
	"github.com/ldclabs/cose/key"
	"github.com/messier-42/cabe-go/cbes"
)

type parsedPackage struct {
	protectedBytes []byte
	protected      cose.Headers
	unprotected    cose.Headers
	ciphertext     []byte
	recipients     []cbor.RawMessage
}

func parsePackage(raw []byte) (*parsedPackage, error) {
	if len(raw) > 0 && raw[0]>>5 == 6 {
		var tag cbor.RawTag
		if err := key.UnmarshalCBOR(raw, &tag); err != nil {
			return nil, err
		}
		if tag.Number != uint64(cbes.TagCOSEEncrypt) {
			return nil, errors.New("cfar: incorrect COSE tag")
		}
		raw = tag.Content
	}
	var parts []cbor.RawMessage
	if err := key.UnmarshalCBOR(raw, &parts); err != nil {
		return nil, err
	}
	if len(parts) != 4 {
		return nil, errors.New("cfar: expected COSE_Encrypt")
	}
	p := &parsedPackage{}
	var err error
	p.protectedBytes, p.protected, p.unprotected, err = parseHeaders(parts[0], parts[1])
	if err != nil {
		return nil, err
	}
	if err := checkCritical(p.protected, func(label any) bool {
		switch label {
		case iana.HeaderParameterAlg, iana.HeaderParameterContentType, iana.HeaderParameterIV, cbes.HeaderOriginDomain, cbes.HeaderAttributeSet, cbes.HeaderLeaseRef:
			return true
		}
		return false
	}); err != nil {
		return nil, err
	}
	if len(parts[2]) == 0 || parts[2][0]>>5 != 2 {
		return nil, errors.New("cfar: ciphertext must be embedded")
	}
	if err := key.UnmarshalCBOR(parts[2], &p.ciphertext); err != nil {
		return nil, err
	}
	if err := key.UnmarshalCBOR(parts[3], &p.recipients); err != nil {
		return nil, err
	}
	if len(p.recipients) == 0 {
		return nil, errors.New("cfar: missing recipients")
	}
	return p, nil
}

func parseRecipient(raw []byte) (*cose.Recipient, []byte, error) {
	var parts []cbor.RawMessage
	if err := key.UnmarshalCBOR(raw, &parts); err != nil {
		return nil, nil, err
	}
	if len(parts) != 3 && len(parts) != 4 {
		return nil, nil, errors.New("cfar: malformed recipient")
	}
	protected, p, u, err := parseHeaders(parts[0], parts[1])
	if err != nil {
		return nil, nil, err
	}
	// Validate critical-header structure here; algorithm-specific critical
	// header semantics belong to the recipient implementation.
	if err := checkCritical(p, func(any) bool { return true }); err != nil {
		return nil, nil, err
	}
	r := &cose.Recipient{Protected: p, Unprotected: u}
	if len(parts[2]) == 0 || (parts[2][0]>>5 != 2 && !bytes.Equal(parts[2], []byte{0xf6})) {
		return nil, nil, errors.New("cfar: invalid recipient ciphertext")
	}
	if err := key.UnmarshalCBOR(parts[2], &r.Ciphertext); err != nil {
		return nil, nil, err
	}
	if len(parts) == 4 {
		var children []cbor.RawMessage
		if err := key.UnmarshalCBOR(parts[3], &children); err != nil {
			return nil, nil, err
		}
		if len(children) == 0 {
			return nil, nil, errors.New("cfar: empty nested recipients")
		}
		for _, child := range children {
			nested, _, err := parseRecipient(child)
			if err != nil {
				return nil, nil, err
			}
			if err := r.AddRecipient(nested); err != nil {
				return nil, nil, err
			}
		}
	}
	return r, protected, nil
}

func parseHeaders(p, u []byte) ([]byte, cose.Headers, cose.Headers, error) {
	var raw []byte
	if len(p) == 0 || p[0]>>5 != 2 {
		return nil, nil, nil, errors.New("cfar: protected headers must be a byte string")
	}
	if err := key.UnmarshalCBOR(p, &raw); err != nil {
		return nil, nil, nil, err
	}
	if len(raw) > 0 && raw[0]>>5 != 5 {
		return nil, nil, nil, errors.New("cfar: protected headers must contain a map")
	}
	protected, err := cose.HeadersFromBytes(raw)
	if err != nil {
		return nil, nil, nil, err
	}
	if len(u) == 0 || u[0]>>5 != 5 {
		return nil, nil, nil, errors.New("cfar: unprotected headers must be a map")
	}
	var unprotected cose.Headers
	if err := key.UnmarshalCBOR(u, &unprotected); err != nil {
		return nil, nil, nil, err
	}
	for label := range protected {
		if unprotected.Has(label) {
			return nil, nil, nil, errors.New("cfar: header present in both sections")
		}
	}
	if unprotected.Has(iana.HeaderParameterCrit) {
		return nil, nil, nil, errors.New("cfar: unprotected crit")
	}
	if len(protected) == 0 {
		raw = []byte{}
	}
	return raw, protected, unprotected, nil
}

func checkCritical(h cose.Headers, understood func(any) bool) error {
	if !h.Has(iana.HeaderParameterCrit) {
		return nil
	}
	labels, ok := h.Get(iana.HeaderParameterCrit).([]any)
	if !ok || len(labels) == 0 {
		return errors.New("cfar: malformed crit")
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
			return fmt.Errorf("cfar: unsupported critical header %v", label)
		}
	}
	return nil
}

func headerBytes(p, u cose.Headers, label any) ([]byte, error) {
	v := u.Get(label)
	if p.Has(label) {
		v = p.Get(label)
	}
	b, ok := v.([]byte)
	if !ok {
		return nil, fmt.Errorf("cfar: header %v must be a byte string", label)
	}
	return b, nil
}

// integer checks the type before calling the dependency's reflection helper,
// which assumes a non-nil value.
func integer(v any) (int, error) {
	switch v.(type) {
	case int, int8, int16, int32, int64, uint, uint8, uint16, uint32, uint64, key.Alg:
		return key.ToInt(v)
	}
	return 0, fmt.Errorf("cfar: expected integer, got %T", v)
}
