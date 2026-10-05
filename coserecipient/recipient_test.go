package coserecipient_test

import (
	"bytes"
	"errors"
	"testing"

	"github.com/ldclabs/cose/cose"
	"github.com/ldclabs/cose/iana"
	"github.com/ldclabs/cose/key"
	"github.com/ldclabs/cose/key/ecdh"
	"github.com/messier-42/cabe-go/coserecipient"
)

func TestAlgorithmSelection(t *testing.T) {
	k := key.Key{iana.KeyParameterKty: iana.KeyTypeSymmetric, iana.KeyParameterAlg: int64(iana.AlgorithmA128KW), iana.SymmetricKeyParameterK: bytes.Repeat([]byte{7}, 16)}
	cek := bytes.Repeat([]byte{3}, 32)
	r, err := coserecipient.WrapKey(k, cek, coserecipient.Context{})
	if err != nil {
		t.Fatal(err)
	}
	// Recovery selects the received algorithm when the key omits alg.
	delete(k, iana.KeyParameterAlg)
	got, err := coserecipient.UnwrapKey(k, r, coserecipient.Context{})
	if err != nil || !bytes.Equal(got, cek) {
		t.Fatalf("recovery: %v", err)
	}
	if _, err := coserecipient.WrapKey(k, cek, coserecipient.Context{}); err == nil {
		t.Fatal("guessed missing algorithm")
	}
	k[iana.KeyParameterAlg] = iana.AlgorithmA256KW
	if _, err := coserecipient.UnwrapKey(k, r, coserecipient.Context{}); err == nil {
		t.Fatal("accepted algorithm mismatch")
	}
	delete(k, iana.KeyParameterAlg)
	if _, err := coserecipient.UnwrapKey(k, nil, coserecipient.Context{}); err == nil {
		t.Fatal("accepted nil recipient")
	}
	r.Protected = cose.Headers{iana.HeaderParameterAlg: iana.AlgorithmA128KW}
	if _, err := coserecipient.UnwrapKey(k, r, coserecipient.Context{}); err == nil {
		t.Fatal("accepted duplicate algorithm headers")
	}
	for _, alg := range []any{nil, []byte{1}, true, uint64(1) << 63} {
		k[iana.KeyParameterAlg] = alg
		if _, err := coserecipient.WrapKey(k, cek, coserecipient.Context{}); err == nil {
			t.Fatalf("accepted invalid algorithm %v", alg)
		}
	}
	for _, alg := range []any{int64(-99999), "unknown"} {
		k[iana.KeyParameterAlg] = alg
		if _, err := coserecipient.WrapKey(k, cek, coserecipient.Context{}); !errors.Is(err, coserecipient.ErrUnsupportedAlgorithm) {
			t.Fatalf("wrap unknown algorithm: %v", err)
		}
		if _, _, err := coserecipient.DeriveKey(k, coserecipient.Context{}); !errors.Is(err, coserecipient.ErrUnsupportedAlgorithm) {
			t.Fatalf("derive unknown algorithm: %v", err)
		}
		r = &cose.Recipient{Unprotected: cose.Headers{iana.HeaderParameterAlg: alg}}
		if _, err := coserecipient.UnwrapKey(k, r, coserecipient.Context{}); !errors.Is(err, coserecipient.ErrUnsupportedAlgorithm) {
			t.Fatalf("unwrap unknown algorithm: %v", err)
		}
	}
}

func TestCriticalHeaders(t *testing.T) {
	k := key.Key{iana.KeyParameterKty: iana.KeyTypeSymmetric, iana.KeyParameterAlg: iana.AlgorithmDirect_HKDF_SHA_256, iana.SymmetricKeyParameterK: bytes.Repeat([]byte{7}, 16)}
	ctx := coserecipient.Context{ContentAlgorithm: iana.AlgorithmA256GCM, KeySize: 32}
	_, r, err := coserecipient.DeriveKey(k, ctx)
	if err != nil {
		t.Fatal(err)
	}
	r.Protected[iana.HeaderParameterCrit] = []int{iana.HeaderParameterAlg}
	ctx.RecipientProtected, err = r.Protected.Bytes()
	if err != nil {
		t.Fatal(err)
	}
	got, err := coserecipient.UnwrapKey(k, r, ctx)
	if err != nil || len(got) != ctx.KeySize {
		t.Fatalf("typed critical header: %v", err)
	}
	for _, invalid := range []any{nil, []any{}, []any{nil}, []any{[]byte{1}}, []any{"absent"}} {
		r.Protected[iana.HeaderParameterCrit] = invalid
		if _, err := coserecipient.UnwrapKey(k, r, ctx); err == nil {
			t.Fatalf("accepted malformed crit %v", invalid)
		}
	}
	r.Protected["unknown"] = true
	r.Protected[iana.HeaderParameterCrit] = []string{"unknown"}
	if _, err := coserecipient.UnwrapKey(k, r, ctx); err == nil {
		t.Fatal("accepted unknown critical header")
	}
	delete(r.Protected, iana.HeaderParameterCrit)
	r.Unprotected[iana.HeaderParameterCrit] = []int{iana.HeaderParameterAlg}
	if _, err := coserecipient.UnwrapKey(k, r, ctx); err == nil {
		t.Fatal("accepted unprotected crit")
	}
}

func TestEphemeralKeyWrap(t *testing.T) {
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
			r, err := coserecipient.WrapKey(public, cek, coserecipient.Context{})
			if err != nil {
				t.Fatal(err)
			}
			protected, err := r.Protected.Bytes()
			if err != nil {
				t.Fatal(err)
			}
			got, err := coserecipient.UnwrapKey(secret, r, coserecipient.Context{RecipientProtected: protected})
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(got, cek) {
				t.Fatal("content key changed")
			}
			r.Ciphertext[0] ^= 1
			if _, err := coserecipient.UnwrapKey(secret, r, coserecipient.Context{RecipientProtected: protected}); err == nil {
				t.Fatal("tampering accepted")
			}
		}
	}
}
