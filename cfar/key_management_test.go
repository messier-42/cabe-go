package cfar_test

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"maps"
	"math/big"
	"testing"

	"github.com/fxamacker/cbor/v2"
	"github.com/ldclabs/cose/iana"
	"github.com/ldclabs/cose/key"
	"github.com/ldclabs/cose/key/ecdh"
	"github.com/messier-42/cabe-go/cabe"
	"github.com/messier-42/cabe-go/cfar"
)

func TestSFLPMixedKeyFamilies(t *testing.T) {
	transport, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	public := key.Key{iana.KeyParameterKty: iana.KeyTypeRSA, iana.KeyParameterAlg: iana.AlgorithmRSAES_OAEP_SHA_256, iana.KeyParameterKid: []byte("transport"),
		iana.RSAKeyParameterN: transport.N.Bytes(), iana.RSAKeyParameterE: big.NewInt(int64(transport.E)).Bytes()}
	secret := key.Key{}
	maps.Copy(secret, public)
	secret[iana.RSAKeyParameterD] = transport.D.Bytes()
	secret[iana.RSAKeyParameterP] = transport.Primes[0].Bytes()
	secret[iana.RSAKeyParameterQ] = transport.Primes[1].Bytes()
	secret[iana.RSAKeyParameterDP] = transport.Precomputed.Dp.Bytes()
	secret[iana.RSAKeyParameterDQ] = transport.Precomputed.Dq.Bytes()
	secret[iana.RSAKeyParameterQInv] = transport.Precomputed.Qinv.Bytes()
	ephemeralPublic, ephemeralSecret := recipientForTest(t, iana.EllipticCurveP_256, iana.AlgorithmECDH_ES_A128KW)
	staticPublic, staticSecret := recipientForTest(t, iana.EllipticCurveX25519, iana.AlgorithmECDH_SS_A256KW)
	sender, err := ecdh.GenerateKey(iana.EllipticCurveX25519)
	if err != nil {
		t.Fatal(err)
	}
	ctx, lkai := contextForTest(t), leaseForTest()
	raw, err := cfar.Generate(ctx, lkai, []key.Key{public, ephemeralPublic, staticPublic}, &cfar.Options{SenderKey: sender})
	if err != nil {
		t.Fatal(err)
	}
	for _, k := range []key.Key{secret, ephemeralSecret, staticSecret} {
		got, err := cfar.Recover(ctx, cabe.FLPSet{raw}, []key.Key{k})
		if err != nil || !bytes.Equal(got.RawCOSEKey, lkai.RawCOSEKey) {
			t.Fatalf("recovery with %v: %v", k.Get(iana.KeyParameterAlg), err)
		}
	}
}

func TestSFLPRejectsDirectRecipient(t *testing.T) {
	ctx, lkai := contextForTest(t), leaseForTest()
	public, secret := recipientForTest(t, iana.EllipticCurveX25519, iana.AlgorithmECDH_ES_A256KW)
	raw, err := cfar.Generate(ctx, lkai, []key.Key{public}, nil)
	if err != nil {
		t.Fatal(err)
	}
	// A valid content ciphertext still cannot turn direct key use into the
	// independently generated, distributed key required by SFLP.
	direct := key.Key{iana.KeyParameterKty: iana.KeyTypeSymmetric, iana.KeyParameterAlg: iana.AlgorithmDirect,
		iana.KeyParameterKid: []byte("direct"), iana.SymmetricKeyParameterK: packageCEK(t, raw, secret)}
	raw = mutate(t, raw, func(parts []cbor.RawMessage) {
		parts[3] = key.MustMarshalCBOR([]any{[]any{[]byte{}, map[int]any{iana.HeaderParameterAlg: iana.AlgorithmDirect, iana.HeaderParameterKid: []byte("direct")}, []byte{}}})
	})
	if _, err := cfar.Recover(ctx, cabe.FLPSet{raw}, []key.Key{direct}); err == nil {
		t.Fatal("accepted a direct recipient")
	}
}
