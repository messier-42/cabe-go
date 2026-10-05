package coserecipient

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	_ "crypto/sha1"
	_ "crypto/sha256"
	_ "crypto/sha512"
	"errors"
	"fmt"
	"math/big"

	"github.com/ldclabs/cose/iana"
	"github.com/ldclabs/cose/key"
)

// The dependency defines the COSE transport identifiers and key parameters,
// but exposes no transport primitive. Use Go's standard implementation.
func encryptKey(k key.Key, cek []byte, hash crypto.Hash) ([]byte, error) {
	if err := checkOperations(k, iana.KeyOperationEncrypt, iana.KeyOperationWrapKey); err != nil {
		return nil, err
	}
	parsed, err := transportKey(k, false)
	if err != nil {
		return nil, err
	}
	if len(cek) == 0 {
		return nil, errors.New("coserecipient: empty content key")
	}
	return rsa.EncryptOAEP(hash.New(), rand.Reader, &parsed.PublicKey, cek, nil)
}

func decryptKey(k key.Key, ciphertext []byte, hash crypto.Hash) ([]byte, error) {
	if err := checkOperations(k, iana.KeyOperationDecrypt, iana.KeyOperationUnwrapKey); err != nil {
		return nil, err
	}
	parsed, err := transportKey(k, true)
	if err != nil {
		return nil, err
	}
	return rsa.DecryptOAEP(hash.New(), rand.Reader, parsed, ciphertext, nil)
}

func transportKey(k key.Key, private bool) (*rsa.PrivateKey, error) {
	kty, err := integer(k.Get(iana.KeyParameterKty))
	if err != nil || kty != iana.KeyTypeRSA {
		return nil, errors.New("coserecipient: invalid transport key type")
	}
	n, err := keyInteger(k, iana.RSAKeyParameterN)
	if err != nil {
		return nil, err
	}
	e, err := keyInteger(k, iana.RSAKeyParameterE)
	if err != nil {
		return nil, err
	}
	if !e.IsInt64() || e.Int64() < 3 || e.Int64() > (1<<31)-1 || e.Bit(0) == 0 {
		return nil, errors.New("coserecipient: invalid public exponent")
	}
	parsed := &rsa.PrivateKey{PublicKey: rsa.PublicKey{N: n, E: int(e.Int64())}}
	if !private {
		for label := iana.RSAKeyParameterD; label >= iana.RSAKeyParameterTI; label-- {
			if k.Has(label) {
				return nil, errors.New("coserecipient: expected public transport key")
			}
		}
		return parsed, nil
	}
	for _, label := range []int{iana.RSAKeyParameterRI, iana.RSAKeyParameterDI, iana.RSAKeyParameterTI} {
		if k.Has(label) {
			return nil, errors.New("coserecipient: extra prime parameters must be nested")
		}
	}
	parsed.D, err = keyInteger(k, iana.RSAKeyParameterD)
	if err != nil {
		return nil, err
	}
	for _, label := range []int{iana.RSAKeyParameterP, iana.RSAKeyParameterQ} {
		prime, err := keyInteger(k, label)
		if err != nil {
			return nil, err
		}
		parsed.Primes = append(parsed.Primes, prime)
	}
	var crt []*big.Int
	for _, label := range []int{iana.RSAKeyParameterDP, iana.RSAKeyParameterDQ, iana.RSAKeyParameterQInv} {
		value, err := keyInteger(k, label)
		if err != nil {
			return nil, err
		}
		crt = append(crt, value)
	}
	if k.Has(iana.RSAKeyParameterOther) {
		raw, err := key.MarshalCBOR(k.Get(iana.RSAKeyParameterOther))
		if err != nil {
			return nil, err
		}
		var others []key.Key
		if err := key.UnmarshalCBOR(raw, &others); err != nil {
			return nil, err
		}
		if len(others) == 0 {
			return nil, errors.New("coserecipient: empty extra primes")
		}
		for _, other := range others {
			prime, err := keyInteger(other, iana.RSAKeyParameterRI)
			if err != nil {
				return nil, err
			}
			parsed.Primes = append(parsed.Primes, prime)
			for _, label := range []int{iana.RSAKeyParameterDI, iana.RSAKeyParameterTI} {
				value, err := keyInteger(other, label)
				if err != nil {
					return nil, err
				}
				crt = append(crt, value)
			}
		}
	}
	if err := parsed.Validate(); err != nil {
		return nil, err
	}
	parsed.Precompute()
	expected := []*big.Int{parsed.Precomputed.Dp, parsed.Precomputed.Dq, parsed.Precomputed.Qinv}
	product := new(big.Int).Mul(parsed.Primes[0], parsed.Primes[1])
	for _, prime := range parsed.Primes[2:] {
		exponent := new(big.Int).Mod(parsed.D, new(big.Int).Sub(prime, big.NewInt(1)))
		coefficient := new(big.Int).ModInverse(product, prime)
		expected = append(expected, exponent, coefficient)
		product.Mul(product, prime)
	}
	for i, value := range expected {
		if value == nil || value.Cmp(crt[i]) != 0 {
			return nil, errors.New("coserecipient: inconsistent private key parameters")
		}
	}
	return parsed, nil
}

func keyInteger(k key.Key, label int) (*big.Int, error) {
	value, err := k.GetBytes(label)
	if err != nil || len(value) == 0 || value[0] == 0 {
		return nil, fmt.Errorf("coserecipient: invalid unsigned key parameter %d", label)
	}
	return new(big.Int).SetBytes(value), nil
}
