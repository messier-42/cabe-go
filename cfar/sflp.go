// Package cfar generates and recovers Simple Federated Lease Packages (SFLPs).
// It supplies cryptographic packaging, not authorization, Origin authentication,
// capability storage or propagation policy.
package cfar

import (
	"bytes"
	"crypto/rand"
	"errors"
	"fmt"

	"github.com/fxamacker/cbor/v2"
	"github.com/ldclabs/cose/cose"
	"github.com/ldclabs/cose/iana"
	"github.com/ldclabs/cose/key"
	_ "github.com/ldclabs/cose/key/aesccm"
	_ "github.com/ldclabs/cose/key/aesgcm"
	_ "github.com/ldclabs/cose/key/chacha20poly1305"
	"github.com/messier-42/cabe-go/attrset"
	"github.com/messier-42/cabe-go/cabe"
	"github.com/messier-42/cabe-go/cbes"
	"github.com/messier-42/cabe-go/coserecipient"
)

// MediaType identifies the protected content type of an SFLP.
const MediaType = "application/cose-sflp+cbor"

// ErrNoUsablePackage means none of the supplied packages and keys satisfied the
// requested context. In particular, an empty package set yields this error.
var ErrNoUsablePackage = errors.New("cfar: no usable SFLP")

// LeaseContext is the exact context an SFLP must protect or satisfy.
type LeaseContext struct {
	OriginDomain string
	AttributeSet attrset.Set
	LeaseRef     []byte
}

func (c LeaseContext) validate() error {
	if err := (cabe.LeaseFederation{OriginDomain: c.OriginDomain}).Validate(); err != nil {
		return err
	}
	if len(c.LeaseRef) == 0 {
		return errors.New("cfar: missing Lease Reference")
	}
	if _, err := attrset.NewFromBytes([]byte(c.AttributeSet.Repr())); err != nil {
		return fmt.Errorf("cfar: invalid Attribute Set: %w", err)
	}
	return nil
}

// Options selects SFLP content encryption and recipient providers.
// Nil uses AES-256-GCM and coserecipient.Default.
type Options struct {
	// Recipients selects generic COSE recipient providers. Nil uses coserecipient.Default.
	Recipients *coserecipient.Registry
	// ContentAlgorithm is a registered COSE AEAD algorithm, or zero for AES-256-GCM.
	ContentAlgorithm int
	// CEKSize is the key length in bytes. Zero selects the standard length for
	// AES-GCM, AES-CCM or ChaCha20/Poly1305. Supply it for an additional algorithm
	// registered with the COSE key package. The encryptor validates the key size.
	CEKSize int
}

// Generate creates a tagged COSE_Encrypt SFLP for a nonempty recipient set.
// One freshly generated CEK protects the complete Non-Captive LKAI, independently
// of the Lease Key algorithm, parameters and Base IV. No Origin signature or
// authentication is added. Recipient keys must advertise alg and a nonempty kid
// containing the FKID. Their types and remaining parameters are opaque to CFAR.
// Configured providers must implement the asymmetric key distribution required
// by SFLP; CFAR cannot infer that property from an opaque key type.
// To omit the tag, use cose.RemoveCBORTag on the result.
func Generate(ctx LeaseContext, lkai cabe.LKAINonCaptive, recipients []key.Key, options *Options) ([]byte, error) {
	if err := ctx.validate(); err != nil {
		return nil, err
	}
	if len(recipients) == 0 {
		return nil, errors.New("cfar: at least one recipient is required")
	}
	if err := validateLeaseKey(lkai.RawCOSEKey); err != nil {
		return nil, err
	}
	opts := Options{}
	if options != nil {
		opts = *options
	}
	if opts.ContentAlgorithm == 0 {
		opts.ContentAlgorithm = iana.AlgorithmA256GCM
	}
	size := opts.CEKSize
	if size == 0 {
		size = contentKeySize(opts.ContentAlgorithm)
	}
	if size <= 0 {
		return nil, errors.New("cfar: content algorithm needs a positive CEK size")
	}
	cek := make([]byte, size)
	if _, err := rand.Read(cek); err != nil {
		return nil, err
	}
	enc, err := contentKey(opts.ContentAlgorithm, cek).Encryptor()
	if err != nil {
		return nil, err
	}
	protected := cose.Headers{
		iana.HeaderParameterAlg:         opts.ContentAlgorithm,
		iana.HeaderParameterContentType: MediaType,
		cbes.HeaderOriginDomain:         ctx.OriginDomain,
		cbes.HeaderAttributeSet:         []byte(ctx.AttributeSet.Repr()),
		cbes.HeaderLeaseRef:             bytes.Clone(ctx.LeaseRef),
	}
	nonce := make([]byte, enc.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	unprotected := cose.Headers{iana.HeaderParameterIV: nonce}
	body, err := key.MarshalCBOR(map[string]any{"nonCaptive": map[string]any{"leaseKey": cbor.RawMessage(lkai.RawCOSEKey)}})
	if err != nil {
		return nil, err
	}
	msg := cose.EncryptMessage[[]byte]{Protected: protected, Unprotected: unprotected, Payload: body}
	protectedBytes, err := protected.Bytes()
	if err != nil {
		return nil, err
	}
	registry := opts.Recipients
	if registry == nil {
		registry = coserecipient.Default
	}
	for i, r := range recipients {
		kid, err := r.GetBytes(iana.KeyParameterKid)
		if err != nil || len(kid) == 0 {
			return nil, fmt.Errorf("cfar: recipient %d missing FKID", i)
		}
		recipient, err := registry.WrapKey(r, cek, coserecipient.Context{BodyProtected: protectedBytes, BodyUnprotected: unprotected})
		if err != nil {
			return nil, fmt.Errorf("cfar: recipient %d: %w", i, err)
		}
		if recipient == nil {
			return nil, errors.New("cfar: recipient implementation returned nil")
		}
		got, err := headerBytes(recipient.Protected, recipient.Unprotected, iana.HeaderParameterKid)
		if err != nil || !bytes.Equal(got, kid) {
			return nil, errors.New("cfar: recipient FKID mismatch")
		}
		if err := msg.AddRecipient(recipient); err != nil {
			return nil, err
		}
	}
	return msg.EncryptAndEncode(enc, nil)
}

// Recover tries packages and matching recipient keys until one passes integrity,
// content type, LKAI structure and exact Lease context checks. It accepts tagged
// and untagged SFLPs and skips unusable or unrelated packages and recipients.
// A nil registry uses coserecipient.Default. Recipient keys are opaque to CFAR;
// their explicit algorithms select registered providers.
// The caller must authorize access separately. Recovery does not authenticate
// the claimed Origin or establish trust in the returned key material.
func Recover(ctx LeaseContext, packages cabe.FLPSet, keys []key.Key, registry *coserecipient.Registry) (*cabe.LKAINonCaptive, error) {
	if err := ctx.validate(); err != nil {
		return nil, err
	}
	if registry == nil {
		registry = coserecipient.Default
	}
	for _, raw := range packages {
		got, err := recoverPackage(ctx, raw, keys, registry)
		if err == nil {
			return got, nil
		}
	}
	return nil, ErrNoUsablePackage
}

func recoverPackage(ctx LeaseContext, raw []byte, keys []key.Key, registry *coserecipient.Registry) (*cabe.LKAINonCaptive, error) {
	p, err := parsePackage(raw)
	if err != nil {
		return nil, err
	}
	algorithm := p.unprotected.Get(iana.HeaderParameterAlg)
	if p.protected.Has(iana.HeaderParameterAlg) {
		algorithm = p.protected.Get(iana.HeaderParameterAlg)
	}
	alg, err := integer(algorithm)
	if err != nil {
		return nil, err
	}
	origin, ok := p.protected.Get(cbes.HeaderOriginDomain).(string)
	if !ok || origin != ctx.OriginDomain {
		return nil, ErrNoUsablePackage
	}
	attrs, ok := p.protected.Get(cbes.HeaderAttributeSet).([]byte)
	if !ok || !bytes.Equal(attrs, []byte(ctx.AttributeSet.Repr())) {
		return nil, ErrNoUsablePackage
	}
	ref, ok := p.protected.Get(cbes.HeaderLeaseRef).([]byte)
	if !ok || !bytes.Equal(ref, ctx.LeaseRef) {
		return nil, ErrNoUsablePackage
	}
	if ct, ok := p.protected.Get(iana.HeaderParameterContentType).(string); !ok || ct != MediaType {
		return nil, ErrNoUsablePackage
	}
	nonce, err := headerBytes(p.protected, p.unprotected, iana.HeaderParameterIV)
	if err != nil || nonce == nil {
		return nil, ErrNoUsablePackage
	}
	if p.protected.Has(iana.HeaderParameterPartialIV) || p.unprotected.Has(iana.HeaderParameterPartialIV) {
		return nil, ErrNoUsablePackage
	}
	aad, err := key.MarshalCBOR([]any{"Encrypt", p.protectedBytes, []byte{}})
	if err != nil {
		return nil, err
	}
	for _, rawRecipient := range p.recipients {
		r, protectedBytes, err := parseRecipient(rawRecipient)
		if err != nil {
			continue
		}
		kid, err := headerBytes(r.Protected, r.Unprotected, iana.HeaderParameterKid)
		if err != nil || len(kid) == 0 {
			continue
		}
		for _, k := range keys {
			if !bytes.Equal(kid, k.Kid()) {
				continue
			}
			cek, err := registry.UnwrapKey(k, r, coserecipient.Context{BodyProtected: p.protectedBytes, BodyUnprotected: p.unprotected, RecipientProtected: protectedBytes, RecipientEncoded: rawRecipient})
			if err != nil {
				continue
			}
			enc, err := contentKey(alg, cek).Encryptor()
			if err != nil {
				continue
			}
			// Validate the nonce before calling any registered AEAD implementation.
			if len(nonce) != enc.NonceSize() {
				continue
			}
			plain, err := enc.Decrypt(nonce, p.ciphertext, aad)
			if err != nil {
				continue
			}
			lkai, err := decodeBody(plain)
			if err == nil {
				return lkai, nil
			}
		}
	}
	return nil, ErrNoUsablePackage
}

func contentKey(alg int, cek []byte) key.Key {
	return key.Key{iana.KeyParameterKty: iana.KeyTypeSymmetric, iana.KeyParameterAlg: alg, iana.SymmetricKeyParameterK: cek}
}

func contentKeySize(alg int) int {
	switch alg {
	case iana.AlgorithmA128GCM, iana.AlgorithmAES_CCM_16_64_128, iana.AlgorithmAES_CCM_64_64_128, iana.AlgorithmAES_CCM_16_128_128, iana.AlgorithmAES_CCM_64_128_128:
		return 16
	case iana.AlgorithmA192GCM:
		return 24
	case iana.AlgorithmA256GCM, iana.AlgorithmChaCha20Poly1305, iana.AlgorithmAES_CCM_16_64_256, iana.AlgorithmAES_CCM_64_64_256, iana.AlgorithmAES_CCM_16_128_256, iana.AlgorithmAES_CCM_64_128_256:
		return 32
	default:
		return 0
	}
}

func validateLeaseKey(raw []byte) error {
	var k key.Key
	if err := key.UnmarshalCBOR(raw, &k); err != nil {
		return fmt.Errorf("cfar: decode Lease Key: %w", err)
	}
	kty, err := integer(k.Get(iana.KeyParameterKty))
	if err != nil || kty != iana.KeyTypeSymmetric {
		return errors.New("cfar: Lease Key must be symmetric")
	}
	secret, ok := k.Get(iana.SymmetricKeyParameterK).([]byte)
	if !ok || len(secret) == 0 {
		return errors.New("cfar: missing Lease Key material")
	}
	return nil
}

func decodeBody(raw []byte) (*cabe.LKAINonCaptive, error) {
	var body map[string]cbor.RawMessage
	if err := key.UnmarshalCBOR(raw, &body); err != nil {
		return nil, err
	}
	if len(body) != 1 || body["nonCaptive"] == nil {
		return nil, errors.New("cfar: expected Non-Captive LKAI")
	}
	var nonCaptive map[string]cbor.RawMessage
	if err := key.UnmarshalCBOR(body["nonCaptive"], &nonCaptive); err != nil {
		return nil, err
	}
	if len(nonCaptive) != 1 || nonCaptive["leaseKey"] == nil {
		return nil, errors.New("cfar: missing Lease Key")
	}
	k := nonCaptive["leaseKey"]
	if err := validateLeaseKey(k); err != nil {
		return nil, err
	}
	return &cabe.LKAINonCaptive{RawCOSEKey: bytes.Clone(k)}, nil
}
