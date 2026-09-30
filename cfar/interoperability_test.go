package cfar_test

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/hkdf"
	"crypto/sha256"
	"testing"

	"github.com/fxamacker/cbor/v2"
	josecipher "github.com/go-jose/go-jose/v4/cipher"
	"github.com/ldclabs/cose/cose"
	"github.com/ldclabs/cose/iana"
	"github.com/ldclabs/cose/key"
	"github.com/messier-42/cabe-go/cabe"
	"github.com/messier-42/cabe-go/cbes"
	"github.com/messier-42/cabe-go/cfar"
	"github.com/messier-42/cabe-go/coserecipient"
	"github.com/messier-42/cabe-go/internal/cbescodec"
	"github.com/messier-42/cabe-go/internal/leasemgr"
)

const (
	leaseKeyField   = "leaseKey"
	nonCaptiveField = "nonCaptive"
	encryptContext  = "Encrypt"
)

// Build a package using standard Go ECDH, HKDF and AEAD directly, independently
// of coserecipient's key schedule and COSE message encryption. Include a non-preferred
// encoding of the recipient protected map, both PartyInfo tuples, integer
// nonces and salt to verify the full RFC 9053 section 5.2 KDF context.
func TestIndependentSFLPWithFullKDFContext(t *testing.T) {
	ctx := contextForTest(t)
	receiver, err := ecdh.X25519().NewPrivateKey(bytes.Repeat([]byte{1}, 32))
	if err != nil {
		t.Fatal(err)
	}
	sender, err := ecdh.X25519().NewPrivateKey(bytes.Repeat([]byte{2}, 32))
	if err != nil {
		t.Fatal(err)
	}
	shared, err := sender.ECDH(receiver.PublicKey())
	if err != nil {
		t.Fatal(err)
	}
	// {1: -31}, with deliberately non-preferred integer encoding for label 1.
	rp := []byte{0xa1, 0x18, 0x01, 0x38, 0x1e}
	info := key.MustMarshalCBOR([]any{-5, []any{[]byte("sender"), int64(-7), []byte("u")}, []any{[]byte("receiver"), uint64(42), []byte("v")}, []any{256, rp}})
	salt := []byte("salt")
	kek, err := hkdf.Key(sha256.New, shared, salt, string(info), 32)
	if err != nil {
		t.Fatal(err)
	}
	block, err := aes.NewCipher(kek)
	if err != nil {
		t.Fatal(err)
	}
	cek := bytes.Repeat([]byte{3}, 32)
	wrapped, err := josecipher.KeyWrap(block, cek)
	if err != nil {
		t.Fatal(err)
	}
	recipient := []any{rp, map[int]any{4: []byte("fkid"), -1: map[int]any{1: 1, -1: 4, -2: sender.PublicKey().Bytes()}, -20: salt, -21: []byte("sender"), -22: int64(-7), -23: []byte("u"), -24: []byte("receiver"), -25: uint64(42), -26: []byte("v")}, wrapped}
	lkai := cabe.LKAINonCaptive{RawCOSEKey: key.MustMarshalCBOR(map[int]any{1: 4, 3: 1, 5: []byte("abcdefghijkl"), -1: []byte("0123456789abcdef")})}
	protected := key.MustMarshalCBOR(map[any]any{1: 3, 3: cfar.MediaType, cbes.HeaderOriginDomain: ctx.OriginDomain, cbes.HeaderAttributeSet: []byte(ctx.AttributeSet.Repr()), cbes.HeaderLeaseRef: ctx.LeaseRef})
	plaintext := key.MustMarshalCBOR(map[string]any{nonCaptiveField: map[string]any{leaseKeyField: cbor.RawMessage(lkai.RawCOSEKey)}})
	block, err = aes.NewCipher(cek)
	if err != nil {
		t.Fatal(err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		t.Fatal(err)
	}
	nonce := bytes.Repeat([]byte{4}, aead.NonceSize())
	encrypted := aead.Seal(nil, nonce, plaintext, key.MustMarshalCBOR([]any{encryptContext, protected, []byte{}}))
	raw := key.MustMarshalCBOR([]any{protected, map[int]any{5: nonce}, encrypted, []any{recipient}})
	secret := key.Key{1: 1, 2: []byte("fkid"), 3: -31, -1: 4, -4: receiver.Bytes()}
	recovered, err := cfar.Recover(ctx, cabe.FLPSet{raw}, []key.Key{secret}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(recovered.RawCOSEKey, lkai.RawCOSEKey) {
		t.Fatal("independent fixture key changed")
	}
	// The recovered Base IV must work for an actual CBES Envelope.
	env, err := cbescodec.New().Encapsulate(t.Context(), cbescodec.EncapsulateArgs{AttributeSet: ctx.AttributeSet.Repr(), Lease: &leasemgr.Lease{LeaseRef: ctx.LeaseRef, LKAI: cabe.LKAI{NonCaptive: &lkai}}, Payload: []byte("interoperable")})
	if err != nil {
		t.Fatal(err)
	}
	msg, err := cbescodec.New().Decapsulate(t.Context(), cbescodec.DecapsulateArgs{Envelope: env.Envelope, LKAI: cabe.LKAI{NonCaptive: recovered}})
	if err != nil {
		t.Fatal(err)
	}
	if string(msg.Payload) != "interoperable" {
		t.Fatal("Envelope plaintext changed")
	}
}

type recordingAlgorithm struct{ ceks [][]byte }

func recordingOptions(t *testing.T, recorder *recordingAlgorithm, keys ...key.Key) *cfar.Options {
	t.Helper()
	var registry coserecipient.Registry
	for _, k := range keys {
		if err := registry.Register(k.Get(iana.KeyParameterAlg), recorder); err != nil {
			t.Fatal(err)
		}
	}
	return &cfar.Options{Recipients: &registry}
}

func (r *recordingAlgorithm) WrapKey(k key.Key, cek []byte, ctx coserecipient.Context) (*cose.Recipient, error) {
	r.ceks = append(r.ceks, bytes.Clone(cek))
	return coserecipient.Default.WrapKey(k, cek, ctx)
}
func (*recordingAlgorithm) UnwrapKey(k key.Key, r *cose.Recipient, ctx coserecipient.Context) ([]byte, error) {
	return coserecipient.Default.UnwrapKey(k, r, ctx)
}

func TestOneFreshCEKPerPackage(t *testing.T) {
	a, _ := recipientForTest(t, iana.EllipticCurveP_256, iana.AlgorithmECDH_ES_A128KW)
	b, _ := recipientForTest(t, iana.EllipticCurveX25519, iana.AlgorithmECDH_ES_A256KW)
	recorder := &recordingAlgorithm{}
	options := recordingOptions(t, recorder, a, b)
	for range 2 {
		if _, err := cfar.Generate(contextForTest(t), leaseForTest(), []key.Key{a, b}, options); err != nil {
			t.Fatal(err)
		}
	}
	if len(recorder.ceks) != 4 || !bytes.Equal(recorder.ceks[0], recorder.ceks[1]) || !bytes.Equal(recorder.ceks[2], recorder.ceks[3]) || bytes.Equal(recorder.ceks[0], recorder.ceks[2]) {
		t.Fatal("CEK not fresh per package and shared among recipients")
	}
}

func TestMalformedRecipientDoesNotBlockGoodRecipient(t *testing.T) {
	ctx := contextForTest(t)
	p, s := recipientForTest(t, iana.EllipticCurveX25519, iana.AlgorithmECDH_ES_A256KW)
	raw, err := cfar.Generate(ctx, leaseForTest(), []key.Key{p}, nil)
	if err != nil {
		t.Fatal(err)
	}
	raw = mutate(t, raw, func(parts []cbor.RawMessage) {
		var recipients []cbor.RawMessage
		if err := key.UnmarshalCBOR(parts[3], &recipients); err != nil {
			t.Fatal(err)
		}
		malformed := key.MustMarshalCBOR([]any{[]byte{}, map[int]any{}, nil, []any{[]any{key.MustMarshalCBOR(map[int]any{2: []any{nil}}), map[int]any{}, nil}}})
		parts[3] = key.MustMarshalCBOR(append([]cbor.RawMessage{malformed}, recipients...))
	})
	if _, err := cfar.Recover(ctx, cabe.FLPSet{raw}, []key.Key{s}, nil); err != nil {
		t.Fatal(err)
	}
}
