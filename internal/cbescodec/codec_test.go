package cbescodec

import (
	"bytes"
	"context"
	"testing"

	"github.com/ldclabs/cose/iana"
	"github.com/ldclabs/cose/key"
	_ "github.com/ldclabs/cose/key/aesgcm"
	"github.com/messier-42/cabe-go/attrset"
	"github.com/messier-42/cabe-go/cabe"
	"github.com/messier-42/cabe-go/cbes"
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

func TestNonCaptiveEncapsulateAndDecapsulate(t *testing.T) {
	leaseKey := key.Key{
		iana.KeyParameterKty:        iana.KeyTypeSymmetric,
		iana.KeyParameterAlg:        iana.AlgorithmA128GCM,
		iana.SymmetricKeyParameterK: []byte("0123456789abcdef"),
		iana.KeyParameterBaseIV:     []byte("abcdefghijkl"),
	}
	active := &leasemgr.Lease{
		LeaseRef: []byte("lease-ref"),
		LKAI: cabe.LKAI{
			NonCaptive: &cabe.LKAINonCaptive{RawCOSEKey: mustMarshalCOSEKey(t, leaseKey)},
		},
	}

	codec := New()
	attrs := []byte{0xa1, 0x67, 'p', 'r', 'o', 'j', 'e', 'c', 't', 0x64, 'c', 'a', 'b', 'e'}
	payload := []byte("hello cabe")

	encRes, err := codec.Encapsulate(context.Background(), EncapsulateArgs{
		Payload:      payload,
		ContentType:  "application/octet-stream",
		AttributeSet: attrset.Repr(attrs),
		Lease:        active,
	})
	if err != nil {
		t.Fatalf("Encapsulate() error = %v", err)
	}
	if !bytes.Equal(encRes.LeaseRef, []byte("lease-ref")) {
		t.Fatalf("LeaseRef = %q, want %q", encRes.LeaseRef, "lease-ref")
	}

	// Use the public cbes.Inspect to cross-check that the envelope
	// codec emits metadata the spec-level inspector accepts.
	r, err := cbes.Inspect(encRes.Envelope)
	if err != nil {
		t.Fatalf("cbes.Inspect() error = %v", err)
	}
	if r.IsCaptive {
		t.Fatal("expected non-captive envelope")
	}
	if !bytes.Equal([]byte(r.AttributeSet.Repr()), attrs) {
		t.Fatalf("attribute set mismatch: %x != %x", r.AttributeSet.Repr(), attrs)
	}
	if !bytes.Equal(r.LeaseRef, []byte("lease-ref")) {
		t.Fatalf("lease ref mismatch: %q", r.LeaseRef)
	}

	decRes, err := codec.Decapsulate(context.Background(), DecapsulateArgs{
		Envelope: encRes.Envelope,
		LKAI:     active.LKAI,
	})
	if err != nil {
		t.Fatalf("Decapsulate() error = %v", err)
	}
	if !bytes.Equal(decRes.Payload, payload) {
		t.Fatalf("payload mismatch: %q != %q", decRes.Payload, payload)
	}
	if decRes.ContentType != "application/octet-stream" {
		t.Fatalf("ContentType = %q", decRes.ContentType)
	}
}

func TestCaptiveEncapsulateAndDecapsulate(t *testing.T) {
	active := &leasemgr.Lease{
		LeaseRef: []byte("lease-ref"),
		LKAI: cabe.LKAI{
			Captive: &cabe.LKAICaptive{LKAT: []byte("access-token")},
		},
	}

	var wrappedInput []byte
	codec := New()
	attrs := []byte{0xa1, 0x64, 't', 'i', 'e', 'r', 0x01}
	payload := []byte("captured payload")

	encRes, err := codec.Encapsulate(context.Background(), EncapsulateArgs{
		Payload:      payload,
		ContentType:  "application/octet-stream",
		AttributeSet: attrset.Repr(attrs),
		Lease:        active,
		Wrap: func(_ context.Context, token []byte, cek []byte) ([]byte, error) {
			if !bytes.Equal(token, []byte("access-token")) {
				t.Fatalf("wrap token = %q", token)
			}
			wrappedInput = append([]byte(nil), cek...)
			return append([]byte("wrapped:"), cek...), nil
		},
	})
	if err != nil {
		t.Fatalf("Encapsulate() error = %v", err)
	}

	r, err := cbes.Inspect(encRes.Envelope)
	if err != nil {
		t.Fatalf("cbes.Inspect() error = %v", err)
	}
	if !r.IsCaptive {
		t.Fatal("expected captive envelope")
	}

	decRes, err := codec.Decapsulate(context.Background(), DecapsulateArgs{
		Envelope: encRes.Envelope,
		LKAI:     active.LKAI,
		Unwrap: func(_ context.Context, token []byte, wrapped []byte) ([]byte, error) {
			if !bytes.Equal(token, []byte("access-token")) {
				t.Fatalf("unwrap token = %q", token)
			}
			if !bytes.Equal(wrapped, append([]byte("wrapped:"), wrappedInput...)) {
				t.Fatalf("wrapped cek mismatch: %x", wrapped)
			}
			return append([]byte(nil), wrappedInput...), nil
		},
	})
	if err != nil {
		t.Fatalf("Decapsulate() error = %v", err)
	}
	if !bytes.Equal(decRes.Payload, payload) {
		t.Fatalf("payload mismatch: %q != %q", decRes.Payload, payload)
	}
}
