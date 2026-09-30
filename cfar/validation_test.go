package cfar_test

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
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

func TestSFLPProtectedMetadataAndBodyValidation(t *testing.T) {
	ctx := contextForTest(t)
	pub, sec := recipientForTest(t, iana.EllipticCurveX25519, iana.AlgorithmECDH_ES_A256KW)
	recorder := &recordingAlgorithm{}
	options := recordingOptions(t, recorder, pub)
	good, err := cfar.Generate(ctx, leaseForTest(), []key.Key{pub}, options)
	if err != nil {
		t.Fatal(err)
	}
	for _, label := range []any{cbes.HeaderOriginDomain, cbes.HeaderAttributeSet, cbes.HeaderLeaseRef, iana.HeaderParameterContentType} {
		moved := mutate(t, good, func(parts []cbor.RawMessage) {
			var raw []byte
			var p, u cose.Headers
			if err := key.UnmarshalCBOR(parts[0], &raw); err != nil {
				t.Fatal(err)
			}
			if err := key.UnmarshalCBOR(raw, &p); err != nil {
				t.Fatal(err)
			}
			if err := key.UnmarshalCBOR(parts[1], &u); err != nil {
				t.Fatal(err)
			}
			u[label] = p[label]
			delete(p, label)
			parts[0] = key.MustMarshalCBOR(key.MustMarshalCBOR(p))
			parts[1] = key.MustMarshalCBOR(u)
		})
		if _, err := cfar.Recover(ctx, cabe.FLPSet{moved}, []key.Key{sec}, nil); err == nil {
			t.Fatalf("accepted unprotected %v", label)
		}
	}
	// Change the context and request together so only the integrity check catches
	// the modification; context matching alone must never release the LKAI.
	changed := mutate(t, good, func(parts []cbor.RawMessage) {
		var raw []byte
		var p cose.Headers
		if err := key.UnmarshalCBOR(parts[0], &raw); err != nil {
			t.Fatal(err)
		}
		if err := key.UnmarshalCBOR(raw, &p); err != nil {
			t.Fatal(err)
		}
		p[cbes.HeaderOriginDomain] = "changed"
		parts[0] = key.MustMarshalCBOR(key.MustMarshalCBOR(p))
	})
	other := ctx
	other.OriginDomain = "changed"
	if _, err := cfar.Recover(other, cabe.FLPSet{changed}, []key.Key{sec}, nil); err == nil {
		t.Fatal("accepted tampered metadata with matching request")
	}
	// Use the real package CEK to create integrity-valid but structurally invalid
	// bodies, including Captive LKAI, null data and a nonsymmetric Lease Key.
	for _, body := range []any{nil, map[string]any{}, map[string]any{"captive": map[string]any{"leaseKeyAccessToken": []byte("token")}}, map[string]any{nonCaptiveField: nil}, map[string]any{nonCaptiveField: map[string]any{leaseKeyField: key.Key{1: 2, -1: []byte("secret")}}}, map[string]any{nonCaptiveField: map[string]any{leaseKeyField: key.Key{1: 4, -1: []byte("secret")}}, "captive": nil}} {
		raw := mutate(t, good, func(parts []cbor.RawMessage) {
			var protected []byte
			var u cose.Headers
			if err := key.UnmarshalCBOR(parts[0], &protected); err != nil {
				t.Fatal(err)
			}
			if err := key.UnmarshalCBOR(parts[1], &u); err != nil {
				t.Fatal(err)
			}
			block, err := aes.NewCipher(recorder.ceks[0])
			if err != nil {
				t.Fatal(err)
			}
			aead, err := cipher.NewGCM(block)
			if err != nil {
				t.Fatal(err)
			}
			nonce, err := u.GetBytes(iana.HeaderParameterIV)
			if err != nil {
				t.Fatal(err)
			}
			parts[2] = key.MustMarshalCBOR(aead.Seal(nil, nonce, key.MustMarshalCBOR(body), key.MustMarshalCBOR([]any{encryptContext, protected, []byte{}})))
		})
		if _, err := cfar.Recover(ctx, cabe.FLPSet{raw}, []key.Key{sec}, nil); err == nil {
			t.Fatalf("accepted invalid body %#v", body)
		}
	}
	wrongTag := append([]byte{0xd8, 0x62}, cose.RemoveCBORTag(good)...)
	if _, err := cfar.Recover(ctx, cabe.FLPSet{wrongTag}, []key.Key{sec}, nil); err == nil {
		t.Fatal("accepted wrong COSE tag")
	}
}

func TestRecipientKeysAndFallback(t *testing.T) {
	ctx := contextForTest(t)
	pub, sec := recipientForTest(t, iana.EllipticCurveP_256, iana.AlgorithmECDH_ES_A256KW)
	good, err := cfar.Generate(ctx, leaseForTest(), []key.Key{pub}, nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, change := range []func(key.Key){
		func(k key.Key) { k[iana.KeyParameterAlg] = nil },
		func(k key.Key) { k[iana.KeyParameterAlg] = iana.AlgorithmECDH_ES_A128KW },
		func(k key.Key) { k[iana.KeyParameterKid] = []byte("different") },
		func(k key.Key) { k[iana.KeyParameterKeyOps] = []int{} },
		func(k key.Key) { k[iana.KeyParameterKeyOps] = []int{iana.KeyOperationSign} },
		func(k key.Key) { k[iana.KeyParameterKeyOps] = nil },
		func(k key.Key) { k[iana.EC2KeyParameterD] = []byte("bad") },
		func(k key.Key) { k[iana.KeyParameterKty] = iana.KeyTypeOKP },
		func(k key.Key) { k[iana.EC2KeyParameterCrv] = nil },
	} {
		var k key.Key
		if err := key.UnmarshalCBOR(key.MustMarshalCBOR(sec), &k); err != nil {
			t.Fatal(err)
		}
		change(k)
		bad := k
		if _, err := cfar.Recover(ctx, cabe.FLPSet{good}, []key.Key{bad}, nil); err == nil {
			t.Fatal("accepted invalid key")
		}
		if _, err := cfar.Recover(ctx, cabe.FLPSet{good}, []key.Key{bad, sec}, nil); err != nil {
			t.Fatal(err)
		}
	}
	for _, change := range []func(key.Key){
		func(k key.Key) { k[iana.EC2KeyParameterX] = []byte{0} },
		func(k key.Key) {
			k[iana.EC2KeyParameterY] = true
			k[iana.EC2KeyParameterX] = bytes.Repeat([]byte{0xff}, 32)
		},
		func(k key.Key) { k[iana.KeyParameterKeyOps] = []int{iana.KeyOperationDeriveKey} },
		func(k key.Key) { k[iana.EC2KeyParameterD] = sec.Get(iana.EC2KeyParameterD) },
	} {
		var k key.Key
		if err := key.UnmarshalCBOR(key.MustMarshalCBOR(pub), &k); err != nil {
			t.Fatal(err)
		}
		change(k)
		if _, err := cfar.Generate(ctx, leaseForTest(), []key.Key{k}, nil); err == nil {
			t.Fatal("accepted invalid public key")
		}
	}
}

func FuzzRecover(f *testing.F) {
	attrs, err := attrset.New(map[string]any{})
	if err != nil {
		f.Fatal(err)
	}
	ctx := cfar.LeaseContext{OriginDomain: "origin", AttributeSet: attrs, LeaseRef: []byte("ref")}
	priv, err := ecdh.GenerateKey(iana.EllipticCurveX25519)
	if err != nil {
		f.Fatal(err)
	}
	priv[iana.KeyParameterAlg] = iana.AlgorithmECDH_ES_A256KW
	pub, err := ecdh.ToPublicKey(priv)
	if err != nil {
		f.Fatal(err)
	}
	good, err := cfar.Generate(ctx, leaseForTest(), []key.Key{pub}, nil)
	if err != nil {
		f.Fatal(err)
	}
	f.Add(good)
	f.Add([]byte{0x84, 0x40, 0xa0, 0x40, 0x80})
	f.Add([]byte{0xf6})
	f.Fuzz(func(t *testing.T, raw []byte) {
		got, err := cfar.Recover(ctx, cabe.FLPSet{raw, good}, []key.Key{priv}, nil)
		if err != nil || got == nil {
			t.Fatalf("unusable package prevented fallback: %v", err)
		}
	})
}

func TestUnprotectedContentAlgorithm(t *testing.T) {
	ctx := contextForTest(t)
	pub, sec := recipientForTest(t, iana.EllipticCurveX25519, iana.AlgorithmECDH_ES_A128KW)
	recorder := &recordingAlgorithm{}
	options := recordingOptions(t, recorder, pub)
	raw, err := cfar.Generate(ctx, leaseForTest(), []key.Key{pub}, options)
	if err != nil {
		t.Fatal(err)
	}
	raw = mutate(t, raw, func(parts []cbor.RawMessage) {
		var protected, encrypted []byte
		var p, u cose.Headers
		if err := key.UnmarshalCBOR(parts[0], &protected); err != nil {
			t.Fatal(err)
		}
		if err := key.UnmarshalCBOR(protected, &p); err != nil {
			t.Fatal(err)
		}
		if err := key.UnmarshalCBOR(parts[1], &u); err != nil {
			t.Fatal(err)
		}
		if err := key.UnmarshalCBOR(parts[2], &encrypted); err != nil {
			t.Fatal(err)
		}
		block, err := aes.NewCipher(recorder.ceks[0])
		if err != nil {
			t.Fatal(err)
		}
		aead, err := cipher.NewGCM(block)
		if err != nil {
			t.Fatal(err)
		}
		nonce, err := u.GetBytes(iana.HeaderParameterIV)
		if err != nil {
			t.Fatal(err)
		}
		plaintext, err := aead.Open(nil, nonce, encrypted, key.MustMarshalCBOR([]any{encryptContext, protected, []byte{}}))
		if err != nil {
			t.Fatal(err)
		}
		u[iana.HeaderParameterAlg] = p[iana.HeaderParameterAlg]
		delete(p, iana.HeaderParameterAlg)
		protected = key.MustMarshalCBOR(p)
		parts[0] = key.MustMarshalCBOR(protected)
		parts[1] = key.MustMarshalCBOR(u)
		parts[2] = key.MustMarshalCBOR(aead.Seal(nil, nonce, plaintext, key.MustMarshalCBOR([]any{encryptContext, protected, []byte{}})))
	})
	if _, err := cfar.Recover(ctx, cabe.FLPSet{raw}, []key.Key{sec}, nil); err != nil {
		t.Fatal(err)
	}
}
