package cfar_test

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"errors"
	"maps"
	"testing"

	"github.com/fxamacker/cbor/v2"
	"github.com/ldclabs/cose/cose"
	"github.com/ldclabs/cose/iana"
	"github.com/ldclabs/cose/key"
	"github.com/messier-42/cabe-go/cabe"
	"github.com/messier-42/cabe-go/cfar"
	"github.com/messier-42/cabe-go/ckapraw"
	"github.com/messier-42/cabe-go/coserecipient"
)

const opaqueAlgorithm = "test-only:opaque-recipient"

// This test-only provider verifies the extension boundary with actual integrity
// protection. Its symmetric wrapping is NOT a federation algorithm or an ML-KEM
// profile. Its text identifiers allocate no numeric COSE registry assignments.
type opaqueProvider struct{ ceks [][]byte }

func opaqueAEAD(k key.Key) (cipher.AEAD, error) {
	if k.Get(iana.KeyParameterKty) != "test-only:opaque-key" {
		return nil, errors.New("unexpected opaque key type")
	}
	secret, err := k.GetBytes("test-only:material")
	if err != nil {
		return nil, err
	}
	b, err := aes.NewCipher(secret)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(b)
}

func (p *opaqueProvider) WrapKey(k key.Key, cek []byte, ctx coserecipient.Context) (*cose.Recipient, error) {
	aead, err := opaqueAEAD(k)
	if err != nil {
		return nil, err
	}
	if len(ctx.BodyProtected) == 0 || len(ctx.ExternalAAD) != 0 {
		return nil, errors.New("incorrect SFLP context")
	}
	nonce := make([]byte, aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	p.ceks = append(p.ceks, bytes.Clone(cek))
	return &cose.Recipient{
		Protected:   cose.Headers{},
		Unprotected: cose.Headers{iana.HeaderParameterAlg: k.Get(iana.KeyParameterAlg), iana.HeaderParameterKid: bytes.Clone(k.Kid()), "test-only:nonce": nonce},
		Ciphertext:  aead.Seal(nil, nonce, cek, ctx.BodyProtected),
	}, nil
}

func (*opaqueProvider) UnwrapKey(k key.Key, r *cose.Recipient, ctx coserecipient.Context) ([]byte, error) {
	aead, err := opaqueAEAD(k)
	if err != nil {
		return nil, err
	}
	var parts []cbor.RawMessage
	if err := key.UnmarshalCBOR(ctx.RecipientEncoded, &parts); err != nil {
		return nil, err
	}
	var protected []byte
	if err := key.UnmarshalCBOR(parts[0], &protected); err != nil {
		return nil, err
	}
	if !bytes.Equal(protected, ctx.RecipientProtected) {
		return nil, errors.New("recipient encoding changed")
	}
	nonce, err := r.Unprotected.GetBytes("test-only:nonce")
	if err != nil {
		return nil, err
	}
	if len(nonce) != aead.NonceSize() {
		return nil, errors.New("invalid nonce")
	}
	return aead.Open(nil, nonce, r.Ciphertext, ctx.BodyProtected)
}

func TestSFLPOpaqueRecipientRegistry(t *testing.T) {
	opaque := key.Key{iana.KeyParameterKty: "test-only:opaque-key", iana.KeyParameterKid: []byte("opaque-fkid"), iana.KeyParameterAlg: opaqueAlgorithm, "test-only:material": bytes.Repeat([]byte{5}, 32)}
	// Discovery must carry unfamiliar keys unchanged into generation.
	wire := ckapraw.FederationIdentity{DomainID: "target", Keys: []ckapraw.FederationPublicKey{{PublicKey: opaque, Status: "current"}}}
	discovered, err := wire.ToCABE()
	if err != nil {
		t.Fatal(err)
	}
	var public key.Key
	if err := key.UnmarshalCBOR(discovered.Keys[0].RawCOSEKey, &public); err != nil {
		t.Fatal(err)
	}
	provider := &opaqueProvider{}
	var registry coserecipient.Registry
	if err := registry.Register(opaqueAlgorithm, provider); err != nil {
		t.Fatal(err)
	}
	legacyRecorder := &recordingAlgorithm{}
	if err := registry.Register(iana.AlgorithmECDH_ES_A256KW, legacyRecorder); err != nil {
		t.Fatal(err)
	}
	legacy, legacySecret := recipientForTest(t, iana.EllipticCurveX25519, iana.AlgorithmECDH_ES_A256KW)
	ctx, lkai := contextForTest(t), leaseForTest()
	for _, recipients := range [][]key.Key{{public}, {public, legacy}} {
		raw, err := cfar.Generate(ctx, lkai, recipients, &cfar.Options{Recipients: &registry})
		if err != nil {
			t.Fatal(err)
		}
		for _, form := range [][]byte{raw, cose.RemoveCBORTag(raw)} {
			got, err := cfar.Recover(ctx, cabe.FLPSet{form}, []key.Key{opaque}, &registry)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(got.RawCOSEKey, lkai.RawCOSEKey) {
				t.Fatal("LKAI changed")
			}
		}
		// An unsupported provider does not prevent the next recipient from working.
		if len(recipients) > 1 {
			// Share the FKID to ensure the unsupported algorithm is actually tried.
			candidate := key.Key{}
			maps.Copy(candidate, legacySecret)
			candidate[iana.KeyParameterKid] = opaque.Kid()
			delete(candidate, iana.KeyParameterAlg)
			if _, err := cfar.Recover(ctx, cabe.FLPSet{raw}, []key.Key{candidate, legacySecret}, nil); err != nil {
				t.Fatal(err)
			}
		}
		corrupt := mutate(t, raw, func(parts []cbor.RawMessage) {
			var ciphertext []byte
			if err := key.UnmarshalCBOR(parts[2], &ciphertext); err != nil {
				t.Fatal(err)
			}
			ciphertext[0] ^= 1
			parts[2] = key.MustMarshalCBOR(ciphertext)
		})
		if _, err := cfar.Recover(ctx, cabe.FLPSet{corrupt}, []key.Key{opaque}, &registry); err == nil {
			t.Fatal("tampered package accepted")
		}
		if _, err := cfar.Recover(ctx, cabe.FLPSet{corrupt, raw}, []key.Key{opaque}, &registry); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := cfar.Generate(ctx, lkai, []key.Key{public}, nil); !errors.Is(err, coserecipient.ErrUnsupportedAlgorithm) {
		t.Fatalf("unregistered provider: %v", err)
	}
	if len(provider.ceks) != 2 || bytes.Equal(provider.ceks[0], provider.ceks[1]) {
		t.Fatal("package CEKs not fresh")
	}
	if len(legacyRecorder.ceks) != 1 || !bytes.Equal(provider.ceks[1], legacyRecorder.ceks[0]) {
		t.Fatal("recipient providers did not receive the same package CEK")
	}
	// An empty registry can run only a private provider, with no legacy provider.
	var privateOnly coserecipient.Registry
	if err := privateOnly.Register(opaqueAlgorithm, provider); err != nil {
		t.Fatal(err)
	}
	raw, err := cfar.Generate(ctx, lkai, []key.Key{public}, &cfar.Options{Recipients: &privateOnly})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := cfar.Recover(ctx, cabe.FLPSet{raw}, []key.Key{opaque}, &privateOnly); err != nil {
		t.Fatal(err)
	}
}
