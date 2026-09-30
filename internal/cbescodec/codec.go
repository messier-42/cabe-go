// Package cbescodec implements the CBES envelope encap/decap codec.
//
// This package is internal to this module and consumed by cabecap.
// It supplements the functionality offered by the public cbes package,
// which only offers envelope inspection at this time.
//
// The functionality of this package might eventually be moved into the
// public cbes package if the interface stabilises and valid use cases
// materialise.
package cbescodec

import (
	"context"
	"errors"
	"fmt"

	"github.com/ldclabs/cose/cose"
	"github.com/ldclabs/cose/iana"
	"github.com/ldclabs/cose/key"
	_ "github.com/ldclabs/cose/key/aesgcm"
	"github.com/messier-42/cabe-go/attrset"
	"github.com/messier-42/cabe-go/cabe"
	"github.com/messier-42/cabe-go/cbes"
	"github.com/messier-42/cabe-go/internal/leasemgr"
)

// Codec encapsulates and decapsulates CBES envelopes.
type Codec interface {
	// Encapsulate encapsulates a message into a CBES Envelope. The ctx
	// is forwarded to EncapsulateArgs.Wrap when the request's Lease
	// carries a captive LKAI; the non-captive path is purely local but
	// still honours ctx cancellation at the boundary.
	Encapsulate(ctx context.Context, req EncapsulateArgs) (EncapsulateResult, error)

	// Decapsulate decapsulates a CBES Envelope. The ctx is forwarded to
	// DecapsulateArgs.Unwrap when the envelope is captive; the
	// non-captive path is purely local but still honours ctx
	// cancellation at the boundary.
	Decapsulate(ctx context.Context, req DecapsulateArgs) (DecapsulateResult, error)
}

// New creates a new [Codec].
func New() Codec {
	return &codec{}
}

// codec is the default [Codec] implementation.
type codec struct{}

// WrapFunc is a callback function type for wrapping a CEK using a
// captive LKAI. Implementations typically perform network I/O (an
// AssistedEncapsulate call against the Key Server) and must honour the
// supplied ctx.
type WrapFunc func(ctx context.Context, token []byte, cek []byte) ([]byte, error)

// UnwrapFunc is a callback function type for unwrapping a CEK using a
// captive LKAI. Implementations typically perform network I/O (an
// AssistedDecapsulate call against the Key Server) and must honour the
// supplied ctx.
type UnwrapFunc func(ctx context.Context, token []byte, wrapped []byte) ([]byte, error)

// EncapsulateArgs provides input arguments to a [Codec.Encapsulate]
// invocation.
type EncapsulateArgs struct {
	// Payload is the plaintext message to encrypt. Required.
	Payload []byte

	// ContentType, if non-empty, is written as the COSE Content Type
	// header in the envelope's protected header. If specified, it
	// should be a MIME type.
	ContentType string

	// AttributeSet is the canonical CBOR encoding of the Attribute Set
	// as produced by attrset.Set.Repr(). Written verbatim into the
	// protected header. Required.
	AttributeSet attrset.Repr

	// Lease is the current Lease the envelope will be keyed
	// against. Required.
	Lease *leasemgr.Lease

	// Wrap is the callback invoked to wrap the CEK when Lease carries
	// a captive LKAI. Ignored (and may be nil) for non-captive Leases.
	Wrap WrapFunc
}

// EncapsulateResult carries the outputs of a successful
// [Codec.Encapsulate] invocation.
type EncapsulateResult struct {
	// Envelope is the serialised CBES envelope bytes.
	Envelope []byte

	// LeaseRef is the Lease Reference that was written into the
	// envelope's protected header.
	LeaseRef []byte
}

// DecapsulateArgs provides input arguments to a [Codec.Decapsulate]
// invocation.
type DecapsulateArgs struct {
	// Envelope is the encrypted CBES envelope to decrypt. Required.
	Envelope []byte

	// LKAI is the Lease Key Access Information for the envelope. It
	// should have been resolved for the Envelope's Attribute Set and
	// Lease Reference via a prior Retrograde operation. Required.
	LKAI cabe.LKAI

	// Unwrap is the callback invoked to unwrap the CEK when LKAI is
	// captive. Ignored (and may be nil) for non-captive Envelopes.
	Unwrap UnwrapFunc
}

// DecapsulateResult carries the outputs of a successful
// [Codec.Decapsulate] invocation.
type DecapsulateResult struct {
	// Payload is the recovered plaintext message.
	Payload []byte

	// ContentType is the COSE content-type header value declared in
	// the envelope's protected header, or "" when absent.
	ContentType string
}

func (c *codec) Encapsulate(ctx context.Context, req EncapsulateArgs) (EncapsulateResult, error) {
	if req.Lease == nil {
		return EncapsulateResult{}, errors.New("cabecap: active lease is required")
	}
	if req.Lease.Federation != nil {
		if err := req.Lease.Federation.Validate(); err != nil {
			return EncapsulateResult{}, err
		}
	}
	if req.Lease.LKAI.NonCaptive != nil {
		return c.encapsulateNonCaptive(req)
	}
	if req.Lease.LKAI.Captive == nil {
		return EncapsulateResult{}, errors.New("cabecap: missing lease key access information")
	}
	if req.Wrap == nil {
		return EncapsulateResult{}, errors.New("cabecap: wrap callback is required for captive keys")
	}
	return c.encapsulateCaptive(ctx, req)
}

func (c *codec) encapsulateNonCaptive(req EncapsulateArgs) (EncapsulateResult, error) {
	leaseKey, err := decodeCOSEKey(req.Lease.LKAI.NonCaptive.RawCOSEKey)
	if err != nil {
		return EncapsulateResult{}, fmt.Errorf("cabecap: decode lease key: %w", err)
	}
	encryptor, err := leaseKey.Encryptor()
	if err != nil {
		return EncapsulateResult{}, fmt.Errorf("cabecap: build encryptor: %w", err)
	}

	protected := cose.Headers{
		iana.HeaderParameterAlg: int(leaseKey.Alg()),
		cbes.HeaderAttributeSet: append([]byte(nil), []byte(req.AttributeSet)...),
		cbes.HeaderLeaseRef:     append([]byte(nil), req.Lease.LeaseRef...),
	}
	if req.ContentType != "" {
		protected[iana.HeaderParameterContentType] = req.ContentType
	}

	msg := &cose.Encrypt0Message[[]byte]{
		Protected: protected,
		Unprotected: cose.Headers{
			iana.HeaderParameterPartialIV: req.Lease.NextPartialIV(),
		},
		Payload: req.Payload,
	}

	addFederationHeaders(req.Lease.Federation, msg.Protected, &msg.Unprotected)
	data, err := msg.EncryptAndEncode(encryptor, nil)
	if err != nil {
		return EncapsulateResult{}, fmt.Errorf("cabecap: encrypt envelope: %w", err)
	}
	return EncapsulateResult{
		Envelope: data,
		LeaseRef: append([]byte(nil), req.Lease.LeaseRef...),
	}, nil
}

func (c *codec) encapsulateCaptive(ctx context.Context, req EncapsulateArgs) (EncapsulateResult, error) {
	cek, err := randomBytes(32)
	if err != nil {
		return EncapsulateResult{}, fmt.Errorf("generate cek: %w", err)
	}

	cekKey := key.Key{
		iana.KeyParameterKty:        iana.KeyTypeSymmetric,
		iana.KeyParameterAlg:        iana.AlgorithmA256GCM,
		iana.SymmetricKeyParameterK: cek,
	}
	encryptor, err := cekKey.Encryptor()
	if err != nil {
		return EncapsulateResult{}, fmt.Errorf("build cek encryptor: %w", err)
	}

	wrapped, err := req.Wrap(ctx, req.Lease.LKAI.Captive.LKAT, cek)
	if err != nil {
		return EncapsulateResult{}, fmt.Errorf("wrap cek: %w", err)
	}

	protected := cose.Headers{
		iana.HeaderParameterAlg: iana.AlgorithmA256GCM,
		cbes.HeaderAttributeSet: append([]byte(nil), []byte(req.AttributeSet)...),
		cbes.HeaderLeaseRef:     append([]byte(nil), req.Lease.LeaseRef...),
	}
	if req.ContentType != "" {
		protected[iana.HeaderParameterContentType] = req.ContentType
	}

	msg := &cose.EncryptMessage[[]byte]{
		Protected: protected,
		Payload:   req.Payload,
	}
	if err := msg.AddRecipient(&cose.Recipient{
		Protected: cose.Headers{
			iana.HeaderParameterAlg: iana.AlgorithmDirect,
		},
		Ciphertext: wrapped,
	}); err != nil {
		return EncapsulateResult{}, fmt.Errorf("add recipient: %w", err)
	}

	addFederationHeaders(req.Lease.Federation, msg.Protected, &msg.Unprotected)
	data, err := msg.EncryptAndEncode(encryptor, nil)
	if err != nil {
		return EncapsulateResult{}, fmt.Errorf("encrypt captive envelope: %w", err)
	}
	return EncapsulateResult{
		Envelope: data,
		LeaseRef: append([]byte(nil), req.Lease.LeaseRef...),
	}, nil
}

func (c *codec) Decapsulate(ctx context.Context, req DecapsulateArgs) (DecapsulateResult, error) {
	if _, err := cbes.Inspect(req.Envelope); err != nil {
		return DecapsulateResult{}, err
	}
	if req.LKAI.NonCaptive != nil {
		return c.decapsulateNonCaptive(req.Envelope, req.LKAI.NonCaptive)
	}
	if req.LKAI.Captive == nil {
		return DecapsulateResult{}, errors.New("cabe: missing lease key access information")
	}
	if req.Unwrap == nil {
		return DecapsulateResult{}, errors.New("cabe: unwrap callback is required for captive keys")
	}
	return c.decapsulateCaptive(ctx, req.Envelope, req.LKAI.Captive, req.Unwrap)
}

func (c *codec) decapsulateNonCaptive(data []byte, info *cabe.LKAINonCaptive) (DecapsulateResult, error) {
	leaseKey, err := decodeCOSEKey(info.RawCOSEKey)
	if err != nil {
		return DecapsulateResult{}, fmt.Errorf("decode lease key: %w", err)
	}
	encryptor, err := leaseKey.Encryptor()
	if err != nil {
		return DecapsulateResult{}, fmt.Errorf("build decryptor: %w", err)
	}

	msg, err := cose.DecryptEncrypt0Message[[]byte](encryptor, data, nil)
	if err != nil {
		return DecapsulateResult{}, fmt.Errorf("decrypt envelope: %w", err)
	}
	return DecapsulateResult{
		Payload:     append([]byte(nil), msg.Payload...),
		ContentType: contentType(msg.Protected),
	}, nil
}

func (c *codec) decapsulateCaptive(ctx context.Context, data []byte, info *cabe.LKAICaptive, unwrap UnwrapFunc) (DecapsulateResult, error) {
	var msg cose.EncryptMessage[[]byte]
	if err := msg.UnmarshalCBOR(data); err != nil {
		return DecapsulateResult{}, fmt.Errorf("parse captive envelope: %w", err)
	}
	if len(msg.Recipients()) == 0 {
		return DecapsulateResult{}, errors.New("captive envelope has no recipients")
	}

	wrapped := msg.Recipients()[0].Ciphertext
	cek, err := unwrap(ctx, info.LKAT, wrapped)
	if err != nil {
		return DecapsulateResult{}, fmt.Errorf("unwrap cek: %w", err)
	}

	alg, err := msg.Protected.GetInt(iana.HeaderParameterAlg)
	if err != nil {
		return DecapsulateResult{}, fmt.Errorf("read content algorithm: %w", err)
	}

	cekKey := key.Key{
		iana.KeyParameterKty:        iana.KeyTypeSymmetric,
		iana.KeyParameterAlg:        alg,
		iana.SymmetricKeyParameterK: cek,
	}
	encryptor, err := cekKey.Encryptor()
	if err != nil {
		return DecapsulateResult{}, fmt.Errorf("build cek decryptor: %w", err)
	}
	if err := msg.Decrypt(encryptor, nil); err != nil {
		return DecapsulateResult{}, fmt.Errorf("decrypt captive envelope: %w", err)
	}

	return DecapsulateResult{
		Payload:     append([]byte(nil), msg.Payload...),
		ContentType: contentType(msg.Protected),
	}, nil
}

func addFederationHeaders(f *cabe.LeaseFederation, protected cose.Headers, unprotected *cose.Headers) {
	if f == nil {
		return
	}
	protected[cbes.HeaderOriginDomain] = f.OriginDomain
	if len(f.FLPs) > 0 {
		if *unprotected == nil {
			*unprotected = cose.Headers{}
		}
		(*unprotected)[cbes.HeaderFLPs] = f.FLPs.Clone()
	}
}
