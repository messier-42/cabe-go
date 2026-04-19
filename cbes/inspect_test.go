package cbes_test

import (
	"bytes"
	"context"
	"testing"

	"github.com/ldclabs/cose/cose"
	"github.com/ldclabs/cose/iana"
	"github.com/ldclabs/cose/key"
	_ "github.com/ldclabs/cose/key/aesgcm"
	"github.com/messier-42/cabe-go/attrset"
	"github.com/messier-42/cabe-go/cabe"
	"github.com/messier-42/cabe-go/cbes"
	"github.com/messier-42/cabe-go/internal/cbescodec"
	"github.com/messier-42/cabe-go/internal/leasemgr"
)

func mustMarshalCOSEKey(t *testing.T, k key.Key) []byte {
	t.Helper()
	raw, err := key.MarshalCBOR(k)
	if err != nil {
		t.Fatalf("MarshalCBOR() error = %v", err)
	}
	return raw
}

func buildNonCaptive(t *testing.T, payload string, attrBytes []byte, contentType string) []byte {
	t.Helper()
	leaseKey := key.Key{
		iana.KeyParameterKty:        iana.KeyTypeSymmetric,
		iana.KeyParameterAlg:        iana.AlgorithmA128GCM,
		iana.SymmetricKeyParameterK: []byte("0123456789abcdef"),
		iana.KeyParameterBaseIV:     []byte("abcdefghijkl"),
	}
	active := &leasemgr.Lease{
		LeaseRef: []byte("lease-ref"),
		LKAI:     cabe.LKAI{NonCaptive: &cabe.LKAINonCaptive{RawCOSEKey: mustMarshalCOSEKey(t, leaseKey)}},
	}
	res, err := cbescodec.New().Encapsulate(context.Background(), cbescodec.EncapsulateArgs{
		Payload:      []byte(payload),
		ContentType:  contentType,
		AttributeSet: attrset.Repr(attrBytes),
		Lease:        active,
	})
	if err != nil {
		t.Fatalf("Encapsulate() error = %v", err)
	}
	return res.Envelope
}

func buildCaptive(t *testing.T, payload string, attrBytes []byte, contentType string) []byte {
	t.Helper()
	active := &leasemgr.Lease{
		LeaseRef: []byte("lease-ref"),
		LKAI:     cabe.LKAI{Captive: &cabe.LKAICaptive{LKAT: []byte("access-token")}},
	}
	res, err := cbescodec.New().Encapsulate(context.Background(), cbescodec.EncapsulateArgs{
		Payload:      []byte(payload),
		ContentType:  contentType,
		AttributeSet: attrset.Repr(attrBytes),
		Lease:        active,
		Wrap: func(_ context.Context, _, cek []byte) ([]byte, error) {
			return append([]byte("wrapped:"), cek...), nil
		},
	})
	if err != nil {
		t.Fatalf("Encapsulate() error = %v", err)
	}
	return res.Envelope
}

func TestInspectNonCaptive(t *testing.T) {
	attrs := []byte{0xa1, 0x67, 'p', 'r', 'o', 'j', 'e', 'c', 't', 0x64, 'c', 'a', 'b', 'e'}
	env := buildNonCaptive(t, "hello", attrs, "text/plain")

	r, err := cbes.Inspect(env)
	if err != nil {
		t.Fatalf("Inspect() error = %v", err)
	}
	if r.Tag != cbes.TagCOSEEncrypt0 {
		t.Fatalf("Tag = %d, want TagCOSEEncrypt0 (%d)", r.Tag, cbes.TagCOSEEncrypt0)
	}
	if r.Alg != iana.AlgorithmA128GCM {
		t.Fatalf("Alg = %d, want AlgorithmA128GCM (%d)", r.Alg, iana.AlgorithmA128GCM)
	}
	if r.IsCaptive {
		t.Fatal("expected non-captive")
	}
	if len(r.PartialIV) == 0 {
		t.Fatal("expected non-empty PartialIV")
	}
	if r.IV != nil {
		t.Fatalf("IV = %x, want nil", r.IV)
	}
	if r.ProtectedHeaderSize <= 0 {
		t.Fatalf("ProtectedHeaderSize = %d, want >0", r.ProtectedHeaderSize)
	}
	if !bytes.Equal([]byte(r.AttributeSet.Repr()), attrs) {
		t.Fatalf("AttributeSet mismatch")
	}
	if !bytes.Equal(r.LeaseRef, []byte("lease-ref")) {
		t.Fatalf("LeaseRef mismatch")
	}
	if r.ContentType != "text/plain" {
		t.Fatalf("ContentType = %q", r.ContentType)
	}
}

func TestInspectCaptive(t *testing.T) {
	attrs := []byte{0xa1, 0x64, 't', 'i', 'e', 'r', 0x01}
	env := buildCaptive(t, "captured", attrs, "application/octet-stream")

	r, err := cbes.Inspect(env)
	if err != nil {
		t.Fatalf("Inspect() error = %v", err)
	}
	if r.Tag != cbes.TagCOSEEncrypt {
		t.Fatalf("Tag = %d, want TagCOSEEncrypt (%d)", r.Tag, cbes.TagCOSEEncrypt)
	}
	if !r.IsCaptive {
		t.Fatal("expected captive")
	}
	if len(r.IV) == 0 {
		t.Fatal("expected non-empty IV")
	}
	if r.PartialIV != nil {
		t.Fatalf("PartialIV = %x, want nil", r.PartialIV)
	}
}

func TestInspectRejectsMalformed(t *testing.T) {
	_, err := cbes.Inspect([]byte{0xff, 0xff})
	if err == nil {
		t.Fatal("expected error for malformed CBOR")
	}
}

func TestInspectRejectsMissingHeaders(t *testing.T) {
	k := key.Key{
		iana.KeyParameterKty:        iana.KeyTypeSymmetric,
		iana.KeyParameterAlg:        iana.AlgorithmA128GCM,
		iana.SymmetricKeyParameterK: []byte("0123456789abcdef"),
	}
	enc, err := k.Encryptor()
	if err != nil {
		t.Fatalf("Encryptor() error = %v", err)
	}
	msg := &cose.Encrypt0Message[[]byte]{
		Protected: cose.Headers{
			iana.HeaderParameterAlg: iana.AlgorithmA128GCM,
		},
		Payload: []byte("missing headers"),
	}
	data, err := msg.EncryptAndEncode(enc, nil)
	if err != nil {
		t.Fatalf("EncryptAndEncode() error = %v", err)
	}
	if _, err := cbes.Inspect(data); err == nil {
		t.Fatal("expected error")
	}
}

func TestInspectRejectsWrongIVCombination(t *testing.T) {
	active := &leasemgr.Lease{
		LeaseRef: []byte("lease-ref"),
		LKAI:     cabe.LKAI{Captive: &cabe.LKAICaptive{LKAT: []byte("access-token")}},
	}
	res, err := cbescodec.New().Encapsulate(context.Background(), cbescodec.EncapsulateArgs{
		Payload:      []byte("payload"),
		ContentType:  "application/octet-stream",
		AttributeSet: attrset.Repr([]byte{0xa0}),
		Lease:        active,
		Wrap: func(_ context.Context, _, cek []byte) ([]byte, error) {
			return append([]byte("wrapped:"), cek...), nil
		},
	})
	if err != nil {
		t.Fatalf("Encapsulate() error = %v", err)
	}

	var msg cose.EncryptMessage[[]byte]
	if err := msg.UnmarshalCBOR(res.Envelope); err != nil {
		t.Fatalf("UnmarshalCBOR() error = %v", err)
	}
	msg.Unprotected[iana.HeaderParameterPartialIV] = []byte{1}
	badBytes, err := msg.MarshalCBOR()
	if err != nil {
		t.Fatalf("MarshalCBOR() error = %v", err)
	}

	if _, err := cbes.Inspect(badBytes); err == nil {
		t.Fatal("expected error")
	}
}

func TestInspectRejectsInvalidAttributeSet(t *testing.T) {
	// Craft a non-canonical Attribute Set encoding: a CBOR map with
	// a non-string key (integer 1). attrset.NewFromBytes rejects this,
	// so Inspect must also reject the envelope.
	badAttr := []byte{0xa1, 0x01, 0x01}
	msg := cose.Encrypt0Message[[]byte]{
		Protected: cose.Headers{
			iana.HeaderParameterAlg: iana.AlgorithmA128GCM,
			cbes.HeaderAttributeSet: badAttr,
			cbes.HeaderLeaseRef:     []byte("lease-ref"),
		},
		Unprotected: cose.Headers{
			iana.HeaderParameterPartialIV: []byte{0x01},
		},
		Payload: []byte("x"),
	}
	var tagged struct {
		_    struct{} `cbor:",toarray"`
		Prot []byte
		Unpr map[any]any
		CT   []byte
	}
	protBytes, err := msg.Protected.Bytes()
	if err != nil {
		t.Fatalf("Protected.Bytes() error = %v", err)
	}
	tagged.Prot = protBytes
	tagged.Unpr = map[any]any{iana.HeaderParameterPartialIV: []byte{0x01}}
	tagged.CT = []byte("ciphertext")
	body, err := key.MarshalCBOR(tagged)
	if err != nil {
		t.Fatalf("MarshalCBOR() error = %v", err)
	}
	data := append([]byte{0xd0}, body...)

	if _, err := cbes.Inspect(data); err == nil {
		t.Fatal("expected error for malformed Attribute Set")
	}
}

func TestInspectRejectsUnsupportedAlgorithm(t *testing.T) {
	env := buildNonCaptive(t, "hi", []byte{0xa1, 0x61, 'a', 0x01}, "")

	// Decode the envelope and rewrite the protected header's Alg to
	// a value outside the allow-list (1234).
	var tagged struct {
		_    struct{} `cbor:",toarray"`
		Prot []byte
		Unpr map[any]any
		CT   []byte
	}
	if env[0] != 0xd0 {
		t.Fatalf("unexpected envelope prefix: %x", env[0])
	}
	if err := key.UnmarshalCBOR(env[1:], &tagged); err != nil {
		t.Fatalf("decode envelope array: %v", err)
	}
	var protMap map[any]any
	if err := key.UnmarshalCBOR(tagged.Prot, &protMap); err != nil {
		t.Fatalf("decode protected header: %v", err)
	}
	protMap[iana.HeaderParameterAlg] = 1234
	newProt, err := key.MarshalCBOR(protMap)
	if err != nil {
		t.Fatalf("encode protected header: %v", err)
	}
	tagged.Prot = newProt
	body, err := key.MarshalCBOR(tagged)
	if err != nil {
		t.Fatalf("encode envelope array: %v", err)
	}
	badBytes := append([]byte{0xd0}, body...)

	if _, err := cbes.Inspect(badBytes); err == nil {
		t.Fatal("expected error for unsupported algorithm")
	}
}

func TestHeaderConstants(t *testing.T) {
	if cbes.HeaderAttributeSet == "" || cbes.HeaderLeaseRef == "" {
		t.Fatal("expected CABE header constants")
	}
}
