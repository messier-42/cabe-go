package coserecipient

import (
	"bytes"
	"crypto"
	"crypto/aes"
	"crypto/rand"
	"errors"
	"fmt"
	"slices"

	josecipher "github.com/go-jose/go-jose/v4/cipher"
	"github.com/ldclabs/cose/cose"
	"github.com/ldclabs/cose/iana"
	"github.com/ldclabs/cose/key"
)

// standardAlgorithm describes a recipient construction, not a key family.
// Key parsing and agreement are delegated to the COSE dependency. Keeping the
// dispatch here makes the public key-management API independent of algorithms.
type standardAlgorithm struct {
	wrapAlg   int
	size      int
	agreement bool
	static    bool
	direct    bool
	kdf       int
	transport crypto.Hash
}

func selectAlgorithm(id any) (standardAlgorithm, error) {
	switch id {
	case int64(iana.AlgorithmA128KW):
		return standardAlgorithm{wrapAlg: iana.AlgorithmA128KW, size: 16}, nil
	case int64(iana.AlgorithmA192KW):
		return standardAlgorithm{wrapAlg: iana.AlgorithmA192KW, size: 24}, nil
	case int64(iana.AlgorithmA256KW):
		return standardAlgorithm{wrapAlg: iana.AlgorithmA256KW, size: 32}, nil
	case int64(iana.AlgorithmDirect):
		return standardAlgorithm{direct: true}, nil
	case int64(iana.AlgorithmDirect_HKDF_SHA_256):
		return standardAlgorithm{direct: true, kdf: kdfSHA256}, nil
	case int64(iana.AlgorithmDirect_HKDF_SHA_512):
		return standardAlgorithm{direct: true, kdf: kdfSHA512}, nil
	case int64(iana.AlgorithmDirect_HKDF_AES_128):
		return standardAlgorithm{direct: true, kdf: kdfAES, size: 16}, nil
	case int64(iana.AlgorithmDirect_HKDF_AES_256):
		return standardAlgorithm{direct: true, kdf: kdfAES, size: 32}, nil
	case int64(iana.AlgorithmECDH_ES_HKDF_256):
		return standardAlgorithm{direct: true, agreement: true, kdf: kdfSHA256}, nil
	case int64(iana.AlgorithmECDH_ES_HKDF_512):
		return standardAlgorithm{direct: true, agreement: true, kdf: kdfSHA512}, nil
	case int64(iana.AlgorithmECDH_ES_A128KW):
		return standardAlgorithm{wrapAlg: iana.AlgorithmA128KW, size: 16, agreement: true}, nil
	case int64(iana.AlgorithmECDH_ES_A192KW):
		return standardAlgorithm{wrapAlg: iana.AlgorithmA192KW, size: 24, agreement: true}, nil
	case int64(iana.AlgorithmECDH_ES_A256KW):
		return standardAlgorithm{wrapAlg: iana.AlgorithmA256KW, size: 32, agreement: true}, nil
	case int64(iana.AlgorithmECDH_SS_HKDF_256):
		return standardAlgorithm{direct: true, agreement: true, static: true, kdf: kdfSHA256}, nil
	case int64(iana.AlgorithmECDH_SS_HKDF_512):
		return standardAlgorithm{direct: true, agreement: true, static: true, kdf: kdfSHA512}, nil
	case int64(iana.AlgorithmECDH_SS_A128KW):
		return standardAlgorithm{wrapAlg: iana.AlgorithmA128KW, size: 16, agreement: true, static: true}, nil
	case int64(iana.AlgorithmECDH_SS_A192KW):
		return standardAlgorithm{wrapAlg: iana.AlgorithmA192KW, size: 24, agreement: true, static: true}, nil
	case int64(iana.AlgorithmECDH_SS_A256KW):
		return standardAlgorithm{wrapAlg: iana.AlgorithmA256KW, size: 32, agreement: true, static: true}, nil
	case int64(iana.AlgorithmRSAES_OAEP_RFC_8017_default):
		return standardAlgorithm{transport: crypto.SHA1}, nil
	case int64(iana.AlgorithmRSAES_OAEP_SHA_256):
		return standardAlgorithm{transport: crypto.SHA256}, nil
	case int64(iana.AlgorithmRSAES_OAEP_SHA_512):
		return standardAlgorithm{transport: crypto.SHA512}, nil
	default:
		return standardAlgorithm{}, fmt.Errorf("%w: %v", ErrUnsupportedAlgorithm, id)
	}
}

func (a standardAlgorithm) wrapKey(k key.Key, cek []byte, ctx Context) (*cose.Recipient, error) {
	if a.direct {
		return nil, errors.New("coserecipient: direct algorithm requires DeriveKey, not a caller-supplied CEK")
	}
	if a.transport == 0 && (len(cek) < 16 || len(cek)%8 != 0) {
		return nil, errors.New("coserecipient: AES Key Wrap needs at least two 8-byte blocks")
	}
	alg, err := integer(k.Get(iana.KeyParameterAlg))
	if err != nil {
		return nil, err
	}
	r := &cose.Recipient{Protected: cose.Headers{}, Unprotected: cose.Headers{iana.HeaderParameterAlg: alg}}
	if k.Has(iana.KeyParameterKid) {
		kid, err := k.GetBytes(iana.KeyParameterKid)
		if err != nil {
			return nil, err
		}
		r.Unprotected[iana.HeaderParameterKid] = bytes.Clone(kid)
	}
	if a.transport != 0 {
		r.Ciphertext, err = encryptKey(k, cek, a.transport)
		return r, err
	}
	var kek []byte
	if a.agreement {
		delete(r.Unprotected, iana.HeaderParameterAlg)
		r.Protected[iana.HeaderParameterAlg] = alg
		var shared []byte
		shared, err = createAgreement(k, r, ctx, a.static)
		if err == nil {
			protected, e := r.Protected.Bytes()
			if e != nil {
				return nil, e
			}
			kek, err = deriveKey(shared, a.wrapAlg, a.size, kdfSHA256, r, protected)
		}
	} else {
		kek, err = symmetricKey(k, a.size, iana.KeyOperationWrapKey, iana.KeyOperationEncrypt)
	}
	if err != nil {
		return nil, err
	}
	block, err := aes.NewCipher(kek)
	if err != nil {
		return nil, err
	}
	r.Ciphertext, err = josecipher.KeyWrap(block, cek)
	return r, err
}

func (a standardAlgorithm) unwrapKey(k key.Key, r *cose.Recipient, ctx Context) ([]byte, error) {
	if len(r.Recipients()) != 0 {
		return nil, errors.New("coserecipient: nested recipients require separate key recovery")
	}
	if err := r.Validate(); err != nil {
		return nil, err
	}
	if err := checkCritical(r.Protected, func(label any) bool { return a.understands(label) }); err != nil {
		return nil, err
	}
	if a.transport != 0 {
		return decryptKey(k, r.Ciphertext, a.transport)
	}
	if a.direct {
		if ctx.RequireWrappedKey {
			return nil, errors.New("coserecipient: direct recipient cannot distribute an independent content key")
		}
		return a.recoverDirect(k, r, ctx)
	}
	if len(r.Ciphertext) < 24 || len(r.Ciphertext)%8 != 0 {
		return nil, errors.New("coserecipient: invalid wrapped key length")
	}
	var kek []byte
	var err error
	if a.agreement {
		shared, e := recoverAgreement(k, r, ctx, a.static)
		if e != nil {
			return nil, e
		}
		kek, err = deriveKey(shared, a.wrapAlg, a.size, kdfSHA256, r, ctx.RecipientProtected)
	} else {
		kek, err = symmetricKey(k, a.size, iana.KeyOperationUnwrapKey, iana.KeyOperationDecrypt)
	}
	if err != nil {
		return nil, err
	}
	block, err := aes.NewCipher(kek)
	if err != nil {
		return nil, err
	}
	return josecipher.KeyUnwrap(block, r.Ciphertext)
}

func (a standardAlgorithm) understands(label any) bool {
	switch label {
	case iana.HeaderParameterAlg, iana.HeaderParameterKid:
		return true
	case iana.HeaderAlgorithmParameterEphemeralKey:
		return a.agreement && !a.static
	case iana.HeaderAlgorithmParameterStaticKey, iana.HeaderAlgorithmParameterStaticKeyId:
		return a.agreement && a.static
	case iana.HeaderAlgorithmParameterSalt, iana.HeaderAlgorithmParameterPartyUIdentity, iana.HeaderAlgorithmParameterPartyUNonce,
		iana.HeaderAlgorithmParameterPartyUOther, iana.HeaderAlgorithmParameterPartyVIdentity, iana.HeaderAlgorithmParameterPartyVNonce, iana.HeaderAlgorithmParameterPartyVOther:
		return a.agreement || a.kdf != 0
	}
	return false
}

func symmetricKey(k key.Key, size int, ops ...int) ([]byte, error) {
	kty, err := integer(k.Get(iana.KeyParameterKty))
	if err != nil || kty != iana.KeyTypeSymmetric {
		return nil, errors.New("coserecipient: expected symmetric key")
	}
	if err := checkOperations(k, ops...); err != nil {
		return nil, err
	}
	secret, err := k.GetBytes(iana.SymmetricKeyParameterK)
	if err != nil || len(secret) == 0 || (size > 0 && len(secret) != size) {
		return nil, fmt.Errorf("coserecipient: invalid key length, expected %d", size)
	}
	return secret, nil
}

func checkOperations(k key.Key, allowed ...int) error {
	if !k.Has(iana.KeyParameterKeyOps) {
		return nil
	}
	raw, err := key.MarshalCBOR(k.Get(iana.KeyParameterKeyOps))
	if err != nil {
		return err
	}
	if len(raw) == 0 || raw[0]>>5 != 4 {
		return errors.New("coserecipient: invalid key_ops")
	}
	var ops []int
	if err := key.UnmarshalCBOR(raw, &ops); err != nil {
		return err
	}
	if len(allowed) == 0 && len(ops) == 0 {
		return nil
	}
	for _, op := range ops {
		if slices.Contains(allowed, op) {
			return nil
		}
	}
	return errors.New("coserecipient: key_ops does not permit operation")
}

func (a standardAlgorithm) deriveKey(k key.Key, ctx Context) ([]byte, *cose.Recipient, error) {
	if !a.direct {
		return nil, nil, errors.New("coserecipient: algorithm requires a caller-supplied CEK")
	}
	alg, err := integer(k.Get(iana.KeyParameterAlg))
	if err != nil {
		return nil, nil, err
	}
	r := &cose.Recipient{Protected: cose.Headers{}, Unprotected: cose.Headers{}, Ciphertext: []byte{}}
	if a.kdf != 0 {
		r.Protected[iana.HeaderParameterAlg] = alg
	} else {
		r.Unprotected[iana.HeaderParameterAlg] = alg
	}
	if k.Has(iana.KeyParameterKid) {
		kid, err := k.GetBytes(iana.KeyParameterKid)
		if err != nil {
			return nil, nil, err
		}
		r.Unprotected[iana.HeaderParameterKid] = bytes.Clone(kid)
	}
	if a.kdf == 0 {
		cek, err := symmetricKey(k, ctx.KeySize, iana.KeyOperationEncrypt)
		return bytes.Clone(cek), r, err
	}
	if err := derivationContext(ctx); err != nil {
		return nil, nil, err
	}
	var secret []byte
	if a.agreement {
		secret, err = createAgreement(k, r, ctx, a.static)
	} else {
		secret, err = symmetricKey(k, a.size, iana.KeyOperationDeriveKey, iana.KeyOperationDeriveBits)
		if err == nil {
			nonce := make([]byte, 32)
			if _, err = rand.Read(nonce); err != nil {
				return nil, nil, err
			}
			label := iana.HeaderAlgorithmParameterSalt
			if a.kdf == kdfAES {
				label = iana.HeaderAlgorithmParameterPartyUNonce
			}
			r.Unprotected[label] = nonce
		}
	}
	if err != nil {
		return nil, nil, err
	}
	protected, err := r.Protected.Bytes()
	if err != nil {
		return nil, nil, err
	}
	cek, err := deriveKey(secret, ctx.ContentAlgorithm, ctx.KeySize, a.kdf, r, protected)
	return cek, r, err
}

func (a standardAlgorithm) recoverDirect(k key.Key, r *cose.Recipient, ctx Context) ([]byte, error) {
	if a.kdf == 0 {
		if len(r.Protected) != 0 {
			return nil, errors.New("coserecipient: direct key requires empty protected headers")
		}
		cek, err := symmetricKey(k, ctx.KeySize, iana.KeyOperationDecrypt)
		return bytes.Clone(cek), err
	}
	if err := derivationContext(ctx); err != nil {
		return nil, err
	}
	var secret []byte
	var err error
	if a.agreement {
		secret, err = recoverAgreement(k, r, ctx, a.static)
	} else {
		if err := requireDerivationNonce(r, a.kdf != kdfAES); err != nil {
			return nil, err
		}
		secret, err = symmetricKey(k, a.size, iana.KeyOperationDeriveKey, iana.KeyOperationDeriveBits)
	}
	if err != nil {
		return nil, err
	}
	return deriveKey(secret, ctx.ContentAlgorithm, ctx.KeySize, a.kdf, r, ctx.RecipientProtected)
}

func derivationContext(ctx Context) error {
	if _, err := algorithmID(ctx.ContentAlgorithm); err != nil {
		return err
	}
	if ctx.KeySize <= 0 || ctx.KeySize > 65535 {
		return errors.New("coserecipient: derived key size must be between 1 and 65535 bytes")
	}
	return nil
}
