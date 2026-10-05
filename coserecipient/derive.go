package coserecipient

import (
	"errors"
	"fmt"

	"github.com/ldclabs/cose/cose"
	"github.com/ldclabs/cose/iana"
	"github.com/ldclabs/cose/key"
	"github.com/ldclabs/cose/key/hkdf"
)

const (
	kdfSHA256 = iota + 1
	kdfSHA512
	kdfAES
)

func deriveKey(shared []byte, alg any, size, kdf int, r *cose.Recipient, protected []byte) ([]byte, error) {
	var err error
	var salt []byte
	if r.Protected.Has(iana.HeaderAlgorithmParameterSalt) || r.Unprotected.Has(iana.HeaderAlgorithmParameterSalt) {
		salt, err = headerBytes(r.Protected, r.Unprotected, iana.HeaderAlgorithmParameterSalt)
		if err != nil {
			return nil, err
		}
	}
	party := func(labels [3]int) ([]any, error) {
		out := make([]any, 3)
		for i, label := range labels {
			if !r.Protected.Has(label) && !r.Unprotected.Has(label) {
				continue
			}
			encoded, err := key.MarshalCBOR(headerValue(r, label))
			if err != nil {
				return nil, err
			}
			var v any
			if err := key.UnmarshalCBOR(encoded, &v); err != nil {
				return nil, err
			}
			if b, ok := v.([]byte); ok {
				out[i] = b
				continue
			}
			if i == 1 {
				switch v.(type) {
				case int, int64, uint64:
					out[i] = v
					continue
				}
			}
			return nil, fmt.Errorf("coserecipient: invalid party information header %d", label)
		}
		return out, nil
	}
	u, err := party([3]int{iana.HeaderAlgorithmParameterPartyUIdentity, iana.HeaderAlgorithmParameterPartyUNonce, iana.HeaderAlgorithmParameterPartyUOther})
	if err != nil {
		return nil, err
	}
	v, err := party([3]int{iana.HeaderAlgorithmParameterPartyVIdentity, iana.HeaderAlgorithmParameterPartyVNonce, iana.HeaderAlgorithmParameterPartyVOther})
	if err != nil {
		return nil, err
	}
	if len(protected) == 0 {
		protected = []byte{}
	}
	// Encode the RFC 9053 section 5.2 context directly to preserve protected bytes
	// and support integer PartyInfo nonces (the dependency's struct uses []byte).
	info, err := key.MarshalCBOR([]any{alg, u, v, []any{size * 8, protected}})
	if err != nil {
		return nil, err
	}
	switch kdf {
	case kdfSHA256:
		return hkdf.HKDF256(shared, salt, info, size)
	case kdfSHA512:
		return hkdf.HKDF512(shared, salt, info, size)
	case kdfAES:
		return hkdf.HKDFAES(shared, info, size)
	default:
		return nil, errors.New("coserecipient: missing key derivation function")
	}
}

func requireDerivationNonce(r *cose.Recipient, allowSalt bool) error {
	if allowSalt {
		salt, err := headerBytes(r.Protected, r.Unprotected, iana.HeaderAlgorithmParameterSalt)
		if err == nil && len(salt) > 0 {
			return nil
		}
	}
	value := headerValue(r, iana.HeaderAlgorithmParameterPartyUNonce)
	if nonce, err := headerBytes(r.Protected, r.Unprotected, iana.HeaderAlgorithmParameterPartyUNonce); err == nil && len(nonce) > 0 {
		return nil
	}
	raw, err := key.MarshalCBOR(value)
	if err == nil && len(raw) > 0 && raw[0]>>5 <= 1 {
		return nil
	}
	return errors.New("coserecipient: key derivation requires a salt or party nonce")
}
