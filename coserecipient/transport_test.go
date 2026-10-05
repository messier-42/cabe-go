package coserecipient_test

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"hash"
	"maps"
	"math/big"
	"strconv"
	"testing"

	"github.com/ldclabs/cose/cose"
	"github.com/ldclabs/cose/iana"
	"github.com/ldclabs/cose/key"
	"github.com/messier-42/cabe-go/coserecipient"
)

func TestStandardKeyTransport(t *testing.T) {
	private, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	testKeyTransport(t, private)
}

func TestMultiPrimeKeyTransport(t *testing.T) {
	// Exercise legacy COSE key import as well as modern two-prime keys.
	private, err := rsa.GenerateMultiPrimeKey(rand.Reader, 3, 2048) //nolint:staticcheck // Interoperability coverage for COSE multi-prime keys.
	if err != nil {
		t.Fatal(err)
	}
	testKeyTransport(t, private)
}

func testKeyTransport(t *testing.T, private *rsa.PrivateKey) {
	t.Helper()
	for _, tc := range []struct {
		alg  int
		hash func() hash.Hash
	}{
		{iana.AlgorithmRSAES_OAEP_RFC_8017_default, sha1.New},
		{iana.AlgorithmRSAES_OAEP_SHA_256, sha256.New},
		{iana.AlgorithmRSAES_OAEP_SHA_512, sha512.New},
	} {
		t.Run(strconv.Itoa(tc.alg), func(t *testing.T) {
			public := key.Key{iana.KeyParameterKty: iana.KeyTypeRSA, iana.KeyParameterAlg: tc.alg,
				iana.RSAKeyParameterN: private.N.Bytes(), iana.RSAKeyParameterE: big.NewInt(int64(private.E)).Bytes()}
			secret := key.Key{}
			maps.Copy(secret, public)
			secret[iana.RSAKeyParameterD] = private.D.Bytes()
			secret[iana.RSAKeyParameterP] = private.Primes[0].Bytes()
			secret[iana.RSAKeyParameterQ] = private.Primes[1].Bytes()
			secret[iana.RSAKeyParameterDP] = private.Precomputed.Dp.Bytes()
			secret[iana.RSAKeyParameterDQ] = private.Precomputed.Dq.Bytes()
			secret[iana.RSAKeyParameterQInv] = private.Precomputed.Qinv.Bytes()
			if len(private.Primes) > 2 {
				others := make([]key.Key, 0, len(private.Primes)-2)
				for i, prime := range private.Primes[2:] {
					crt := private.Precomputed.CRTValues[i] //nolint:staticcheck // Import Go's legacy CRT representation independently of the production converter.
					others = append(others, key.Key{iana.RSAKeyParameterRI: prime.Bytes(), iana.RSAKeyParameterDI: crt.Exp.Bytes(), iana.RSAKeyParameterTI: crt.Coeff.Bytes()})
				}
				secret[iana.RSAKeyParameterOther] = others
			}

			// Transport is not constrained to AES Key Wrap's block size.
			cek := bytes.Repeat([]byte{9}, 31)
			r, err := coserecipient.WrapKey(public, cek, coserecipient.Context{})
			if err != nil {
				t.Fatal(err)
			}
			if err := r.Validate(); err != nil {
				t.Fatal(err)
			}
			got, err := rsa.DecryptOAEP(tc.hash(), rand.Reader, private, r.Ciphertext, nil)
			if err != nil || !bytes.Equal(got, cek) {
				t.Fatalf("independent decryption: %x, %v", got, err)
			}
			ciphertext, err := rsa.EncryptOAEP(tc.hash(), rand.Reader, &private.PublicKey, cek, nil)
			if err != nil {
				t.Fatal(err)
			}
			r = &cose.Recipient{Unprotected: cose.Headers{iana.HeaderParameterAlg: tc.alg}, Ciphertext: ciphertext}
			got, err = coserecipient.UnwrapKey(secret, r, coserecipient.Context{})
			if err != nil || !bytes.Equal(got, cek) {
				t.Fatalf("independent encryption: %x, %v", got, err)
			}
			r.Ciphertext[0] ^= 1
			if _, err := coserecipient.UnwrapKey(secret, r, coserecipient.Context{}); err == nil {
				t.Fatal("accepted tampering")
			}
			if _, err := coserecipient.WrapKey(secret, cek, coserecipient.Context{}); err == nil {
				t.Fatal("accepted private key for generation")
			}
			r.Ciphertext[0] ^= 1
			secret[iana.RSAKeyParameterDP] = []byte{1}
			if _, err := coserecipient.UnwrapKey(secret, r, coserecipient.Context{}); err == nil {
				t.Fatal("accepted invalid private key")
			}
		})
	}
}
