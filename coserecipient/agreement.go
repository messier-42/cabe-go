package coserecipient

import (
	"bytes"
	"crypto/rand"
	"errors"
	"fmt"

	"github.com/ldclabs/cose/cose"
	"github.com/ldclabs/cose/iana"
	"github.com/ldclabs/cose/key"
	"github.com/ldclabs/cose/key/ecdh"
)

func checkAgreementKey(k key.Key, alg int, private bool) error {
	if k.Has(iana.KeyParameterAlg) {
		got, err := integer(k.Get(iana.KeyParameterAlg))
		if err != nil || got != alg {
			return errors.New("coserecipient: key algorithm mismatch")
		}
	}
	// Validate types before calling dependency helpers that use reflection.
	for _, label := range []int{iana.KeyParameterKty, iana.EC2KeyParameterCrv} {
		if _, err := integer(k.Get(label)); err != nil {
			return err
		}
	}
	for label, value := range k {
		if value == nil {
			return fmt.Errorf("coserecipient: null key parameter %v", label)
		}
	}
	if private {
		if err := checkOperations(k, iana.KeyOperationDeriveKey, iana.KeyOperationDeriveBits); err != nil {
			return err
		}
	} else {
		if k.Has(iana.EC2KeyParameterD) {
			return errors.New("coserecipient: expected public key")
		}
		if err := checkOperations(k); err != nil {
			return err
		}
	}
	if err := ecdh.CheckKey(k); err != nil {
		return err
	}
	if private {
		parsed, err := ecdh.KeyToPrivate(k)
		if err != nil {
			return err
		}
		canonical, err := ecdh.KeyFromPrivate(parsed)
		if err != nil {
			return err
		}
		if canonical.Kty() != k.Kty() {
			return errors.New("coserecipient: inconsistent key type and curve")
		}
	}
	return nil
}

// The dependency's compressed-point conversion can panic for invalid points.
// Contain that failure at this parsing boundary, treating it as an invalid key.
func validatePublicKey(k key.Key) (err error) {
	defer func() {
		if recover() != nil {
			err = errors.New("coserecipient: invalid public key")
		}
	}()
	parsed, err := ecdh.KeyToPublic(k)
	if err != nil {
		return err
	}
	canonical, err := ecdh.KeyFromPublic(parsed)
	if err != nil {
		return err
	}
	if canonical.Kty() != k.Kty() {
		return errors.New("coserecipient: inconsistent key type and curve")
	}
	return nil
}

func createAgreement(k key.Key, r *cose.Recipient, ctx Context, static bool) ([]byte, error) {
	alg, err := integer(headerValue(r, iana.HeaderParameterAlg))
	if err != nil {
		return nil, err
	}
	if err := checkAgreementKey(k, alg, false); err != nil {
		return nil, err
	}
	if err := validatePublicKey(k); err != nil {
		return nil, err
	}
	sender := ctx.SenderKey
	label := iana.HeaderAlgorithmParameterEphemeralKey
	if static {
		if err := checkAgreementKey(sender, alg, true); err != nil {
			return nil, err
		}
		salt := make([]byte, 32)
		if _, err := rand.Read(salt); err != nil {
			return nil, err
		}
		r.Unprotected[iana.HeaderAlgorithmParameterSalt] = salt
		label = iana.HeaderAlgorithmParameterStaticKey
	} else {
		curve, _ := integer(k.Get(iana.EC2KeyParameterCrv))
		sender, err = ecdh.GenerateKey(curve)
		if err != nil {
			return nil, err
		}
	}
	public, err := ecdh.ToPublicKey(sender)
	if err != nil {
		return nil, err
	}
	delete(public, iana.KeyParameterKid)
	r.Unprotected[label] = public
	agreement, err := ecdh.NewECDHer(sender)
	if err != nil {
		return nil, err
	}
	return agreement.ECDH(k)
}

func recoverAgreement(k key.Key, r *cose.Recipient, ctx Context, static bool) ([]byte, error) {
	alg, err := integer(headerValue(r, iana.HeaderParameterAlg))
	if err != nil {
		return nil, err
	}
	if err := checkAgreementKey(k, alg, true); err != nil {
		return nil, err
	}
	label := iana.HeaderAlgorithmParameterEphemeralKey
	if static {
		label = iana.HeaderAlgorithmParameterStaticKey
		if r.Protected.Has(iana.HeaderAlgorithmParameterEphemeralKey) || r.Unprotected.Has(iana.HeaderAlgorithmParameterEphemeralKey) {
			return nil, errors.New("coserecipient: unexpected ephemeral key")
		}
		if err := requireDerivationNonce(r, true); err != nil {
			return nil, err
		}
	} else if headerValue(r, iana.HeaderAlgorithmParameterStaticKey) != nil || headerValue(r, iana.HeaderAlgorithmParameterStaticKeyId) != nil {
		return nil, errors.New("coserecipient: unexpected static key")
	}
	var public key.Key
	value := headerValue(r, label)
	if static && value == nil {
		kid, err := headerBytes(r.Protected, r.Unprotected, iana.HeaderAlgorithmParameterStaticKeyId)
		if err != nil || len(kid) == 0 || !bytes.Equal(kid, ctx.SenderKey.Kid()) {
			return nil, errors.New("coserecipient: unresolved sender key")
		}
		public = ctx.SenderKey
	} else {
		if static && headerValue(r, iana.HeaderAlgorithmParameterStaticKeyId) != nil {
			return nil, errors.New("coserecipient: both sender key and identifier present")
		}
		raw, err := key.MarshalCBOR(value)
		if err != nil {
			return nil, err
		}
		if err := key.UnmarshalCBOR(raw, &public); err != nil {
			return nil, err
		}
	}
	if err := checkAgreementKey(public, alg, false); err != nil {
		return nil, err
	}
	if err := validatePublicKey(public); err != nil {
		return nil, err
	}
	agreement, err := ecdh.NewECDHer(k)
	if err != nil {
		return nil, err
	}
	return agreement.ECDH(public)
}
