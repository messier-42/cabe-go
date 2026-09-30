package coserecipient_test

import (
	"bytes"
	"errors"
	"fmt"
	"sync"
	"testing"

	"github.com/ldclabs/cose/cose"
	"github.com/ldclabs/cose/iana"
	"github.com/ldclabs/cose/key"
	"github.com/ldclabs/cose/key/ecdh"
	"github.com/messier-42/cabe-go/coserecipient"
)

const opaqueAlgorithm = "test-only:opaque-recipient"
const opaqueKeyType = "test-only:opaque-key"
const opaqueParameter = "preserve"

// A dispatch probe, not a cryptographic construction or a registry assignment.
// No ECDH fields exist in these keys. Even their key type is a text identifier.
type probe struct{ calls int }

func (p *probe) WrapKey(k key.Key, cek []byte, ctx coserecipient.Context) (*cose.Recipient, error) {
	p.calls++
	if k.Get(iana.KeyParameterKty) != opaqueKeyType || !bytes.Equal(ctx.BodyProtected, []byte{1, 2}) {
		return nil, errors.New("key or context was changed")
	}
	return &cose.Recipient{Protected: cose.Headers{iana.HeaderParameterAlg: k.Get(iana.KeyParameterAlg)}, Ciphertext: bytes.Clone(cek)}, nil
}

func (p *probe) UnwrapKey(k key.Key, r *cose.Recipient, ctx coserecipient.Context) ([]byte, error) {
	p.calls++
	if k.Get("opaque-parameter") != opaqueParameter || !bytes.Equal(ctx.RecipientProtected, []byte{3, 4}) || !bytes.Equal(ctx.RecipientEncoded, []byte{5, 6}) {
		return nil, errors.New("key or exact recipient bytes were changed")
	}
	return bytes.Clone(r.Ciphertext), nil
}

func TestOpaqueKeyDispatch(t *testing.T) {
	var registry coserecipient.Registry
	provider := &probe{}
	if err := registry.Register(opaqueAlgorithm, provider); err != nil {
		t.Fatal(err)
	}
	k := key.Key{iana.KeyParameterKty: opaqueKeyType, iana.KeyParameterAlg: opaqueAlgorithm, "opaque-parameter": opaqueParameter}
	ctx := coserecipient.Context{BodyProtected: []byte{1, 2}, RecipientProtected: []byte{3, 4}, RecipientEncoded: []byte{5, 6}}
	cek := []byte("opaque content key")
	r, err := registry.WrapKey(k, cek, ctx)
	if err != nil {
		t.Fatal(err)
	}
	got, err := registry.UnwrapKey(k, r, ctx)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, cek) || provider.calls != 2 {
		t.Fatal("provider was not used")
	}
	// The received algorithm selects the implementation when the key omits alg.
	delete(k, iana.KeyParameterAlg)
	if _, err := registry.UnwrapKey(k, r, ctx); err != nil {
		t.Fatal(err)
	}
}

func TestAlgorithmDispatchValidation(t *testing.T) {
	var registry coserecipient.Registry
	p := &probe{}
	if err := registry.Register(opaqueAlgorithm, p); err != nil {
		t.Fatal(err)
	}
	if err := registry.Register(opaqueAlgorithm, p); err == nil {
		t.Fatal("duplicate registration")
	}
	for _, alg := range []any{nil, []byte{1}, true, uint64(1) << 63} {
		if err := registry.Register(alg, p); err == nil {
			t.Fatalf("accepted invalid algorithm %v", alg)
		}
	}
	if err := registry.Register("nil-provider", nil); err == nil {
		t.Fatal("nil implementation")
	}
	// Integer representations of the same identifier must select one entry.
	if err := registry.Register(iana.AlgorithmECDH_ES_A128KW, p); err != nil {
		t.Fatal(err)
	}
	if err := registry.Register(int64(iana.AlgorithmECDH_ES_A128KW), p); err == nil {
		t.Fatal("duplicate integer identifier")
	}
	k := key.Key{iana.KeyParameterKty: opaqueKeyType, iana.KeyParameterAlg: opaqueAlgorithm}
	r := &cose.Recipient{Unprotected: cose.Headers{iana.HeaderParameterAlg: "unregistered"}}
	if _, err := registry.UnwrapKey(k, r, coserecipient.Context{}); err == nil {
		t.Fatal("accepted algorithm mismatch")
	}
	delete(k, iana.KeyParameterAlg)
	if _, err := registry.WrapKey(k, nil, coserecipient.Context{}); err == nil {
		t.Fatal("guessed missing algorithm")
	}
	if _, err := registry.UnwrapKey(k, r, coserecipient.Context{}); !errors.Is(err, coserecipient.ErrUnsupportedAlgorithm) {
		t.Fatalf("unknown algorithm: %v", err)
	}
	if _, err := registry.UnwrapKey(k, nil, coserecipient.Context{}); err == nil {
		t.Fatal("nil recipient")
	}
	r.Protected = cose.Headers{iana.HeaderParameterAlg: "unregistered"}
	if _, err := registry.UnwrapKey(k, r, coserecipient.Context{}); err == nil {
		t.Fatal("duplicate algorithm headers")
	}
	if p.calls != 0 {
		t.Fatal("invalid inputs reached provider")
	}
}

func TestConcurrentRegistration(t *testing.T) {
	var registry coserecipient.Registry
	var wg sync.WaitGroup
	for i := range 30 {
		wg.Go(func() {
			if err := registry.Register(fmt.Sprintf("test-only:%d", i), &probe{}); err != nil {
				t.Error(err)
			}
			if _, err := registry.WrapKey(key.Key{iana.KeyParameterAlg: "unknown"}, nil, coserecipient.Context{}); !errors.Is(err, coserecipient.ErrUnsupportedAlgorithm) {
				t.Error(err)
			}
		})
	}
	wg.Wait()
}

func TestProviderCriticalHeaders(t *testing.T) {
	var registry coserecipient.Registry
	p := &probe{}
	if err := registry.Register(opaqueAlgorithm, p); err != nil {
		t.Fatal(err)
	}
	k := key.Key{"opaque-parameter": opaqueParameter}
	ctx := coserecipient.Context{RecipientProtected: []byte{3, 4}, RecipientEncoded: []byte{5, 6}}
	r := &cose.Recipient{Protected: cose.Headers{
		iana.HeaderParameterAlg:  opaqueAlgorithm,
		iana.HeaderParameterCrit: []int{iana.HeaderParameterAlg},
	}}
	// Generic structural checks must accept valid typed Go header arrays.
	if _, err := registry.UnwrapKey(k, r, ctx); err != nil {
		t.Fatal(err)
	}
	for _, invalid := range []any{nil, []any{}, []any{nil}, []any{[]byte{1}}, []any{"absent"}} {
		r.Protected[iana.HeaderParameterCrit] = invalid
		if _, err := registry.UnwrapKey(k, r, ctx); err == nil {
			t.Fatalf("accepted malformed crit %v", invalid)
		}
	}
	if p.calls != 1 {
		t.Fatal("malformed headers reached provider")
	}
}

func TestStandardProviders(t *testing.T) {
	registry := coserecipient.NewRegistry()
	cek := bytes.Repeat([]byte{7}, 32)
	for _, curve := range []int{iana.EllipticCurveP_256, iana.EllipticCurveP_384, iana.EllipticCurveP_521, iana.EllipticCurveX25519} {
		for _, alg := range []int{iana.AlgorithmECDH_ES_A128KW, iana.AlgorithmECDH_ES_A192KW, iana.AlgorithmECDH_ES_A256KW} {
			secret, err := ecdh.GenerateKey(curve)
			if err != nil {
				t.Fatal(err)
			}
			secret[iana.KeyParameterAlg] = alg
			public, err := ecdh.ToPublicKey(secret)
			if err != nil {
				t.Fatal(err)
			}
			// COSE itself does not require a kid; FKID requirements belong to CFAR.
			delete(public, iana.KeyParameterKid)
			delete(secret, iana.KeyParameterKid)
			r, err := registry.WrapKey(public, cek, coserecipient.Context{})
			if err != nil {
				t.Fatal(err)
			}
			protected, err := r.Protected.Bytes()
			if err != nil {
				t.Fatal(err)
			}
			got, err := registry.UnwrapKey(secret, r, coserecipient.Context{RecipientProtected: protected})
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(got, cek) {
				t.Fatal("content key changed")
			}
			r.Ciphertext[0] ^= 1
			if _, err := registry.UnwrapKey(secret, r, coserecipient.Context{RecipientProtected: protected}); err == nil {
				t.Fatal("tampering accepted")
			}
		}
	}
	// Standard registrations do not constrain additional algorithms or key types.
	if err := registry.Register(opaqueAlgorithm, &probe{}); err != nil {
		t.Fatal(err)
	}
	k := key.Key{iana.KeyParameterKty: opaqueKeyType, iana.KeyParameterAlg: opaqueAlgorithm}
	if _, err := registry.WrapKey(k, cek, coserecipient.Context{BodyProtected: []byte{1, 2}}); err != nil {
		t.Fatal(err)
	}
}
