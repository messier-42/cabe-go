package coserecipient

import (
	"bytes"
	"crypto/aes"
	"crypto/ecdh"
	"crypto/elliptic"
	"crypto/rand"
	"errors"
	"fmt"

	josecipher "github.com/go-jose/go-jose/v4/cipher"
	"github.com/ldclabs/cose/cose"
	"github.com/ldclabs/cose/iana"
	"github.com/ldclabs/cose/key"
	coseecdh "github.com/ldclabs/cose/key/ecdh"
	"github.com/ldclabs/cose/key/hkdf"
)

// ecdhES implements RFC 9053 ECDH-ES+A128KW, ECDH-ES+A192KW and
// ECDH-ES+A256KW. It supports P-256, P-384, P-521 and X25519 keys.
// Generation uses the public key's explicit alg and crv; recovery checks the
// recipient algorithm against the secret key's alg when present.
type ecdhES struct{}

// WrapKey encrypts a package CEK using a fresh ephemeral ECDH key and AES Key Wrap.
func (ecdhES) WrapKey(publicKey key.Key, cek []byte, _ Context) (*cose.Recipient, error) {
	alg, err := integer(publicKey.Get(iana.KeyParameterAlg))
	if err != nil {
		return nil, err
	}
	if _, _, err := wrapParameters(alg); err != nil {
		return nil, err
	}
	if err := checkAgreementKey(publicKey, alg, false); err != nil {
		return nil, err
	}
	if len(cek) < 16 || len(cek)%8 != 0 {
		return nil, errors.New("coserecipient: AES Key Wrap needs at least two 8-byte blocks")
	}
	public, err := publicECDH(publicKey)
	if err != nil {
		return nil, err
	}
	ephemeral, err := public.Curve().GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	shared, err := ephemeral.ECDH(public)
	if err != nil {
		return nil, err
	}
	epk, err := coseecdh.KeyFromPublic(ephemeral.PublicKey())
	if err != nil {
		return nil, err
	}
	delete(epk, iana.KeyParameterKid)
	r := &cose.Recipient{Protected: cose.Headers{iana.HeaderParameterAlg: alg}, Unprotected: cose.Headers{iana.HeaderAlgorithmParameterEphemeralKey: epk}}
	if publicKey.Has(iana.KeyParameterKid) {
		kid, err := publicKey.GetBytes(iana.KeyParameterKid)
		if err != nil {
			return nil, err
		}
		r.Unprotected[iana.HeaderParameterKid] = bytes.Clone(kid)
	}
	protected, err := r.Protected.Bytes()
	if err != nil {
		return nil, err
	}
	kek, err := deriveKEK(shared, alg, r, protected)
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

// UnwrapKey recovers a package CEK after ECDH and AES Key Wrap integrity checking.
func (ecdhES) UnwrapKey(secretKey key.Key, r *cose.Recipient, ctx Context) ([]byte, error) {
	if r == nil {
		return nil, errors.New("coserecipient: missing recipient")
	}
	if len(r.Recipients()) != 0 {
		return nil, errors.New("coserecipient: ECDH-ES key wrap must not have nested recipients")
	}
	if err := checkCritical(r.Protected, ecdhHeader); err != nil {
		return nil, err
	}
	alg, err := integer(headerValue(r, iana.HeaderParameterAlg))
	if err != nil {
		return nil, err
	}
	if _, _, err := wrapParameters(alg); err != nil {
		return nil, err
	}
	if err := checkAgreementKey(secretKey, alg, true); err != nil {
		return nil, err
	}
	raw, err := key.MarshalCBOR(headerValue(r, iana.HeaderAlgorithmParameterEphemeralKey))
	if err != nil {
		return nil, err
	}
	var epk key.Key
	if err := key.UnmarshalCBOR(raw, &epk); err != nil {
		return nil, err
	}
	if err := checkAgreementKey(epk, alg, false); err != nil {
		return nil, err
	}
	public, err := publicECDH(epk)
	if err != nil {
		return nil, err
	}
	curve, _, _, err := keyCurve(secretKey)
	if err != nil {
		return nil, err
	}
	d, ok := secretKey.Get(iana.EC2KeyParameterD).([]byte)
	if !ok {
		return nil, errors.New("coserecipient: missing private key material")
	}
	private, err := curve.NewPrivateKey(d)
	if err != nil {
		return nil, err
	}
	shared, err := private.ECDH(public)
	if err != nil {
		return nil, err
	}
	// RFC 9053 KDF input uses the original recipient protected bytes, even
	// when their map encoding differs from the encoder's preferred ordering.
	kek, err := deriveKEK(shared, alg, r, ctx.RecipientProtected)
	if err != nil {
		return nil, err
	}
	block, err := aes.NewCipher(kek)
	if err != nil {
		return nil, err
	}
	if len(r.Ciphertext) < 24 {
		return nil, errors.New("coserecipient: truncated wrapped CEK")
	}
	return josecipher.KeyUnwrap(block, r.Ciphertext)
}

func wrapParameters(alg int) (int, int, error) {
	switch alg {
	case iana.AlgorithmECDH_ES_A128KW:
		return iana.AlgorithmA128KW, 16, nil
	case iana.AlgorithmECDH_ES_A192KW:
		return iana.AlgorithmA192KW, 24, nil
	case iana.AlgorithmECDH_ES_A256KW:
		return iana.AlgorithmA256KW, 32, nil
	default:
		return 0, 0, fmt.Errorf("coserecipient: unsupported ECDH key wrap algorithm %d", alg)
	}
}

func deriveKEK(shared []byte, alg int, r *cose.Recipient, protected []byte) ([]byte, error) {
	wrapAlg, size, err := wrapParameters(alg)
	if err != nil {
		return nil, err
	}
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
			v := headerValue(r, label)
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
	info, err := key.MarshalCBOR([]any{wrapAlg, u, v, []any{size * 8, protected}})
	if err != nil {
		return nil, err
	}
	return hkdf.HKDF256(shared, salt, info, size)
}

func ecdhHeader(label any) bool {
	switch label {
	case iana.HeaderParameterAlg, iana.HeaderParameterKid, iana.HeaderAlgorithmParameterEphemeralKey,
		iana.HeaderAlgorithmParameterSalt, iana.HeaderAlgorithmParameterPartyUIdentity, iana.HeaderAlgorithmParameterPartyUNonce,
		iana.HeaderAlgorithmParameterPartyUOther, iana.HeaderAlgorithmParameterPartyVIdentity, iana.HeaderAlgorithmParameterPartyVNonce, iana.HeaderAlgorithmParameterPartyVOther:
		return true
	}
	return false
}

func checkAgreementKey(k key.Key, alg int, private bool) error {
	if k.Has(iana.KeyParameterAlg) {
		a, err := integer(k.Get(iana.KeyParameterAlg))
		if err != nil || a != alg {
			return errors.New("coserecipient: key algorithm mismatch")
		}
	}
	if _, _, _, err := keyCurve(k); err != nil {
		return err
	}
	if !private && k.Has(iana.EC2KeyParameterD) {
		return errors.New("coserecipient: expected a public key")
	}
	if k.Has(iana.KeyParameterKeyOps) {
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
		allowed := false
		for _, op := range ops {
			if op == iana.KeyOperationDeriveKey || op == iana.KeyOperationDeriveBits {
				allowed = true
			}
		}
		if (private && !allowed) || (!private && len(ops) != 0) {
			return errors.New("coserecipient: key_ops does not permit ECDH")
		}
	}
	return nil
}

func keyCurve(k key.Key) (ecdh.Curve, elliptic.Curve, int, error) {
	kty, err := integer(k.Get(iana.KeyParameterKty))
	if err != nil {
		return nil, nil, 0, err
	}
	crv, err := integer(k.Get(iana.EC2KeyParameterCrv))
	if err != nil {
		return nil, nil, 0, err
	}
	switch {
	case kty == iana.KeyTypeEC2 && crv == iana.EllipticCurveP_256:
		return ecdh.P256(), elliptic.P256(), 32, nil
	case kty == iana.KeyTypeEC2 && crv == iana.EllipticCurveP_384:
		return ecdh.P384(), elliptic.P384(), 48, nil
	case kty == iana.KeyTypeEC2 && crv == iana.EllipticCurveP_521:
		return ecdh.P521(), elliptic.P521(), 66, nil
	case kty == iana.KeyTypeOKP && crv == iana.EllipticCurveX25519:
		return ecdh.X25519(), nil, 32, nil
	default:
		return nil, nil, 0, errors.New("coserecipient: unsupported or inconsistent ECDH key type and curve")
	}
}

func publicECDH(k key.Key) (*ecdh.PublicKey, error) {
	curve, ec, size, err := keyCurve(k)
	if err != nil {
		return nil, err
	}
	x, ok := k.Get(iana.EC2KeyParameterX).([]byte)
	if !ok || len(x) == 0 || len(x) > size {
		return nil, errors.New("coserecipient: invalid public x coordinate")
	}
	if ec == nil {
		if k.Has(iana.EC2KeyParameterY) {
			return nil, errors.New("coserecipient: OKP key has y coordinate")
		}
		return curve.NewPublicKey(x)
	}
	point := make([]byte, 1+2*size)
	point[0] = 4
	copy(point[1+size-len(x):1+size], x)
	if y, ok := k.Get(iana.EC2KeyParameterY).(bool); ok {
		compressed := append([]byte{2}, point[1:1+size]...)
		if y {
			compressed[0] = 3
		}
		px, py := elliptic.UnmarshalCompressed(ec, compressed)
		if px == nil {
			return nil, errors.New("coserecipient: invalid compressed public point")
		}
		px.FillBytes(point[1 : 1+size])
		py.FillBytes(point[1+size:])
		return curve.NewPublicKey(point)
	}
	y, ok := k.Get(iana.EC2KeyParameterY).([]byte)
	if !ok || len(y) == 0 || len(y) > size {
		return nil, errors.New("coserecipient: invalid public y coordinate")
	}
	copy(point[1+2*size-len(y):], y)
	return curve.NewPublicKey(point)
}

// registerStandardAlgorithms supplies providers without teaching the dispatcher
// about their key types. Additional providers register through the same API.
func registerStandardAlgorithms(r *Registry) {
	for _, alg := range []int{iana.AlgorithmECDH_ES_A128KW, iana.AlgorithmECDH_ES_A192KW, iana.AlgorithmECDH_ES_A256KW} {
		if err := r.Register(alg, ecdhES{}); err != nil {
			panic(err)
		}
	}
}
