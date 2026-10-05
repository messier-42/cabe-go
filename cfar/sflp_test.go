package cfar_test

import (
	"bytes"
	"errors"
	"testing"

	"github.com/fxamacker/cbor/v2"
	"github.com/ldclabs/cose/cose"
	"github.com/ldclabs/cose/iana"
	"github.com/ldclabs/cose/key"
	"github.com/ldclabs/cose/key/ecdh"
	"github.com/messier-42/cabe-go/attrset"
	"github.com/messier-42/cabe-go/cabe"
	"github.com/messier-42/cabe-go/cbes"
	"github.com/messier-42/cabe-go/cfar"
)

func contextForTest(t *testing.T) cfar.LeaseContext {
	t.Helper()
	attrs, err := attrset.New(map[string]any{"project": "cfar", "level": 2})
	if err != nil {
		t.Fatal(err)
	}
	return cfar.LeaseContext{OriginDomain: "origin", AttributeSet: attrs, LeaseRef: []byte("reference")}
}
func leaseForTest() cabe.LKAINonCaptive {
	return cabe.LKAINonCaptive{RawCOSEKey: key.MustMarshalCBOR(key.Key{1: 4, 2: []byte("lease-kid"), 3: 1, 4: []int{3, 4}, 5: []byte("abcdefghijkl"), -1: []byte("0123456789abcdef"), "extension": []byte("preserve")})}
}
func recipientForTest(t *testing.T, curve, alg int) (key.Key, key.Key) {
	t.Helper()
	priv, err := ecdh.GenerateKey(curve)
	if err != nil {
		t.Fatal(err)
	}
	priv[iana.KeyParameterAlg] = alg
	pub, err := ecdh.ToPublicKey(priv)
	if err != nil {
		t.Fatal(err)
	}
	return pub, priv
}
func TestSFLPMultipleRecipientsAndAlgorithms(t *testing.T) {
	ctx, lkai := contextForTest(t), leaseForTest()
	public := make([]key.Key, 0, 12)
	secret := make([]key.Key, 0, 12)
	for _, curve := range []int{iana.EllipticCurveP_256, iana.EllipticCurveP_384, iana.EllipticCurveP_521, iana.EllipticCurveX25519} {
		for _, alg := range []int{iana.AlgorithmECDH_ES_A128KW, iana.AlgorithmECDH_ES_A192KW, iana.AlgorithmECDH_ES_A256KW} {
			p, s := recipientForTest(t, curve, alg)
			public = append(public, p)
			secret = append(secret, s)
		}
	}
	for _, alg := range []int{iana.AlgorithmA128GCM, iana.AlgorithmA192GCM, iana.AlgorithmA256GCM, iana.AlgorithmChaCha20Poly1305, iana.AlgorithmAES_CCM_16_128_128} {
		raw, err := cfar.Generate(ctx, lkai, public, &cfar.Options{ContentAlgorithm: alg})
		if err != nil {
			t.Fatal(err)
		}
		var msg cose.EncryptMessage[[]byte]
		if err := msg.UnmarshalCBOR(raw); err != nil {
			t.Fatal(err)
		}
		if len(msg.Recipients()) != len(public) {
			t.Fatal("missing recipients")
		}
		for _, label := range []any{cbes.HeaderOriginDomain, cbes.HeaderAttributeSet, cbes.HeaderLeaseRef, iana.HeaderParameterContentType} {
			if !msg.Protected.Has(label) || msg.Unprotected.Has(label) {
				t.Fatalf("unprotected metadata %v", label)
			}
		}
		if msg.Protected.Get(iana.HeaderParameterContentType) != cfar.MediaType {
			t.Fatal("content type")
		}
		for i, s := range secret {
			r := msg.Recipients()[i]
			kid, _ := r.Unprotected.GetBytes(iana.HeaderParameterKid)
			if !bytes.Equal(kid, public[i].Kid()) {
				t.Fatal("FKID changed")
			}
			for _, form := range [][]byte{raw, cose.RemoveCBORTag(raw)} {
				got, err := cfar.Recover(ctx, cabe.FLPSet{form}, []key.Key{s})
				if err != nil {
					t.Fatal(err)
				}
				if !bytes.Equal(got.RawCOSEKey, lkai.RawCOSEKey) {
					t.Fatal("complete LKAI not preserved")
				}
			}
		}
	}
}

func mutate(t *testing.T, raw []byte, fn func([]cbor.RawMessage)) []byte {
	t.Helper()
	var fields []cbor.RawMessage
	if err := key.UnmarshalCBOR(cose.RemoveCBORTag(raw), &fields); err != nil {
		t.Fatal(err)
	}
	fn(fields)
	return key.MustMarshalCBOR(fields)
}
func TestSFLPRejectsMismatchTamperingAndContinues(t *testing.T) {
	ctx, lkai := contextForTest(t), leaseForTest()
	pub, sec := recipientForTest(t, iana.EllipticCurveX25519, iana.AlgorithmECDH_ES_A256KW)
	good, err := cfar.Generate(ctx, lkai, []key.Key{pub}, nil)
	if err != nil {
		t.Fatal(err)
	}
	wrongOrigin := ctx
	wrongOrigin.OriginDomain = "elsewhere"
	wrongRef := ctx
	wrongRef.LeaseRef = []byte("other")
	wrongAttrs := ctx
	wrongAttrs.AttributeSet, _ = attrset.New(map[string]any{"project": "different"})
	bad := make(cabe.FLPSet, 0, 8)
	bad = append(bad, []byte("garbage"))
	for _, other := range []cfar.LeaseContext{wrongOrigin, wrongRef, wrongAttrs} {
		raw, err := cfar.Generate(other, lkai, []key.Key{pub}, nil)
		if err != nil {
			t.Fatal(err)
		}
		bad = append(bad, raw)
	}
	bad = append(bad, mutate(t, good, func(fields []cbor.RawMessage) {
		var ct []byte
		if err := key.UnmarshalCBOR(fields[2], &ct); err != nil {
			t.Fatal(err)
		}
		ct[0] ^= 1
		fields[2] = key.MustMarshalCBOR(ct)
	}))
	bad = append(bad, mutate(t, good, func(fields []cbor.RawMessage) { fields[2] = []byte{0xf6} }))
	bad = append(bad, mutate(t, good, func(fields []cbor.RawMessage) { fields[3] = key.MustMarshalCBOR([]any{}) }))
	for _, p := range bad {
		got, err := cfar.Recover(ctx, cabe.FLPSet{p}, []key.Key{sec})
		if !errors.Is(err, cfar.ErrNoUsablePackage) || got != nil {
			t.Fatalf("bad package accepted: %v", err)
		}
	}
	otherPub, _ := recipientForTest(t, iana.EllipticCurveX25519, iana.AlgorithmECDH_ES_A256KW)
	unrelated, err := cfar.Generate(ctx, lkai, []key.Key{otherPub}, nil)
	if err != nil {
		t.Fatal(err)
	}
	bad = append(bad, unrelated)
	for _, flps := range []cabe.FLPSet{nil, {}, bad} {
		if _, err := cfar.Recover(ctx, flps, []key.Key{sec}); !errors.Is(err, cfar.ErrNoUsablePackage) {
			t.Fatalf("expected no usable package: %v", err)
		}
	}
	got, err := cfar.Recover(ctx, append(bad, good), []key.Key{sec})
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got.RawCOSEKey, lkai.RawCOSEKey) {
		t.Fatal("wrong LKAI")
	}
}

func TestSFLPGenerationValidation(t *testing.T) {
	ctx, lkai := contextForTest(t), leaseForTest()
	pub, _ := recipientForTest(t, iana.EllipticCurveP_256, iana.AlgorithmECDH_ES_A128KW)
	if _, err := cfar.Generate(ctx, lkai, nil, nil); err == nil {
		t.Fatal("accepted no recipients")
	}
	delete(pub, iana.KeyParameterAlg)
	if _, err := cfar.Generate(ctx, lkai, []key.Key{pub}, nil); err == nil {
		t.Fatal("guessed missing algorithm")
	}
	pub[iana.KeyParameterAlg] = iana.AlgorithmECDH_ES_A128KW
	delete(pub, iana.KeyParameterKid)
	if _, err := cfar.Generate(ctx, lkai, []key.Key{pub}, nil); err == nil {
		t.Fatal("accepted no FKID")
	}
}
