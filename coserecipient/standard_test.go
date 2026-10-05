package coserecipient_test

import (
	"bytes"
	"crypto/hkdf"
	"crypto/sha256"
	"crypto/sha512"
	"fmt"
	"hash"
	"strconv"
	"testing"

	"github.com/ldclabs/cose/cose"
	"github.com/ldclabs/cose/iana"
	"github.com/ldclabs/cose/key"
	"github.com/ldclabs/cose/key/ecdh"
	"github.com/messier-42/cabe-go/coserecipient"
)

func TestStandardSymmetricKeyWrap(t *testing.T) {
	for i, alg := range []int{iana.AlgorithmA128KW, iana.AlgorithmA192KW, iana.AlgorithmA256KW} {
		t.Run(strconv.Itoa(alg), func(t *testing.T) {
			k := key.Key{iana.KeyParameterKty: iana.KeyTypeSymmetric, iana.KeyParameterAlg: alg, iana.SymmetricKeyParameterK: bytes.Repeat([]byte{7}, 16+8*i)}
			cek := bytes.Repeat([]byte{3}, 32)
			r, err := coserecipient.WrapKey(k, cek, coserecipient.Context{})
			if err != nil {
				t.Fatal(err)
			}
			if err := r.Validate(); err != nil {
				t.Fatal(err)
			}
			got, err := coserecipient.UnwrapKey(k, r, coserecipient.Context{})
			if err != nil || !bytes.Equal(got, cek) {
				t.Fatalf("unwrap: %x, %v", got, err)
			}
			r.Ciphertext[0] ^= 1
			if _, err := coserecipient.UnwrapKey(k, r, coserecipient.Context{}); err == nil {
				t.Fatal("accepted tampering")
			}
		})
	}
}

func TestStandardAgreementModes(t *testing.T) {
	for _, curve := range []int{iana.EllipticCurveP_256, iana.EllipticCurveP_384, iana.EllipticCurveP_521, iana.EllipticCurveX25519} {
		for _, alg := range []int{-25, -26, -27, -28, -29, -30, -31, -32, -33, -34} {
			t.Run(fmt.Sprintf("%d/%d", curve, alg), func(t *testing.T) {
				secret, err := ecdh.GenerateKey(curve)
				if err != nil {
					t.Fatal(err)
				}
				secret[iana.KeyParameterAlg] = alg
				public, err := ecdh.ToPublicKey(secret)
				if err != nil {
					t.Fatal(err)
				}
				ctx := coserecipient.Context{ContentAlgorithm: iana.AlgorithmA256GCM, KeySize: 32}
				static := alg == -27 || alg == -28 || alg <= -32
				if static {
					ctx.SenderKey, err = ecdh.GenerateKey(curve)
					if err != nil {
						t.Fatal(err)
					}
					ctx.SenderKey[iana.KeyParameterAlg] = alg
				}
				direct := alg >= -28
				cek := bytes.Repeat([]byte{3}, 32)
				var r *cose.Recipient
				if direct {
					cek, r, err = coserecipient.DeriveKey(public, ctx)
				} else {
					r, err = coserecipient.WrapKey(public, cek, ctx)
				}
				if err != nil {
					t.Fatal(err)
				}
				if len(cek) != 32 {
					t.Fatal("incorrect key size")
				}
				if err := r.Validate(); err != nil {
					t.Fatal(err)
				}
				if static {
					peer, ok := r.Unprotected.Get(iana.HeaderAlgorithmParameterStaticKey).(key.Key)
					if !ok || peer.Has(iana.EC2KeyParameterD) {
						t.Fatal("missing public sender key, or leaked private key")
					}
					salt, err := r.Unprotected.GetBytes(iana.HeaderAlgorithmParameterSalt)
					if err != nil || len(salt) < 16 {
						t.Fatal("missing fresh salt")
					}
				}
				encoded, err := r.MarshalCBOR()
				if err != nil {
					t.Fatal(err)
				}
				var received cose.Recipient
				if err := received.UnmarshalCBOR(encoded); err != nil {
					t.Fatal(err)
				}
				ctx.RecipientProtected, err = received.Protected.Bytes()
				if err != nil {
					t.Fatal(err)
				}
				ctx.SenderKey = nil
				got, err := coserecipient.UnwrapKey(secret, &received, ctx)
				if err != nil || !bytes.Equal(got, cek) {
					t.Fatalf("recover: %x, %v", got, err)
				}
				if direct {
					if _, err := coserecipient.WrapKey(public, cek, ctx); err == nil {
						t.Fatal("direct derivation claimed to wrap a caller-supplied key")
					}
				}
			})
		}
	}
}

func TestStandardDirectKeys(t *testing.T) {
	for _, alg := range []int{iana.AlgorithmDirect, iana.AlgorithmDirect_HKDF_SHA_256, iana.AlgorithmDirect_HKDF_SHA_512, iana.AlgorithmDirect_HKDF_AES_128, iana.AlgorithmDirect_HKDF_AES_256} {
		t.Run(strconv.Itoa(alg), func(t *testing.T) {
			size := 32
			if alg == iana.AlgorithmDirect_HKDF_AES_128 {
				size = 16
			}
			k := key.Key{iana.KeyParameterKty: iana.KeyTypeSymmetric, iana.KeyParameterAlg: alg, iana.SymmetricKeyParameterK: bytes.Repeat([]byte{7}, size)}
			ctx := coserecipient.Context{ContentAlgorithm: iana.AlgorithmA256GCM, KeySize: 32}
			cek, r, err := coserecipient.DeriveKey(k, ctx)
			if err != nil {
				t.Fatal(err)
			}
			if err := r.Validate(); err != nil {
				t.Fatal(err)
			}
			ctx.RecipientProtected, err = r.Protected.Bytes()
			if err != nil {
				t.Fatal(err)
			}
			got, err := coserecipient.UnwrapKey(k, r, ctx)
			if err != nil || !bytes.Equal(got, cek) {
				t.Fatalf("recover: %x, %v", got, err)
			}
			if _, err := coserecipient.WrapKey(k, cek, ctx); err == nil {
				t.Fatal("direct key claimed to wrap supplied CEK")
			}
			if alg == iana.AlgorithmDirect {
				cek[0] ^= 1
				if bytes.Equal(cek, k.Get(iana.SymmetricKeyParameterK).([]byte)) {
					t.Fatal("aliased key material")
				}
			} else {
				next, _, err := coserecipient.DeriveKey(k, ctx)
				if err != nil || bytes.Equal(next, cek) {
					t.Fatalf("repeated derived key: %v", err)
				}
			}
		})
	}
}

func TestStaticSenderResolutionAndValidation(t *testing.T) {
	receiver, err := ecdh.GenerateKey(iana.EllipticCurveX25519)
	if err != nil {
		t.Fatal(err)
	}
	receiver[iana.KeyParameterAlg] = iana.AlgorithmECDH_SS_A256KW
	public, err := ecdh.ToPublicKey(receiver)
	if err != nil {
		t.Fatal(err)
	}
	sender, err := ecdh.GenerateKey(iana.EllipticCurveX25519)
	if err != nil {
		t.Fatal(err)
	}
	senderPublic, err := ecdh.ToPublicKey(sender)
	if err != nil {
		t.Fatal(err)
	}
	cek := bytes.Repeat([]byte{7}, 32)
	if _, err := coserecipient.WrapKey(public, cek, coserecipient.Context{}); err == nil {
		t.Fatal("accepted missing sender key")
	}
	r, err := coserecipient.WrapKey(public, cek, coserecipient.Context{SenderKey: sender})
	if err != nil {
		t.Fatal(err)
	}
	ctx := coserecipient.Context{SenderKey: senderPublic}
	ctx.RecipientProtected, _ = r.Protected.Bytes()
	r.Unprotected[iana.HeaderAlgorithmParameterStaticKeyId] = senderPublic.Kid()
	if _, err := coserecipient.UnwrapKey(receiver, r, ctx); err == nil {
		t.Fatal("accepted both sender key forms")
	}
	delete(r.Unprotected, iana.HeaderAlgorithmParameterStaticKey)
	got, err := coserecipient.UnwrapKey(receiver, r, ctx)
	if err != nil || !bytes.Equal(got, cek) {
		t.Fatalf("sender key resolution: %v", err)
	}
	ctx.SenderKey = nil
	if _, err := coserecipient.UnwrapKey(receiver, r, ctx); err == nil {
		t.Fatal("accepted unresolved sender key")
	}
	ctx.SenderKey = senderPublic
	delete(r.Unprotected, iana.HeaderAlgorithmParameterSalt)
	if _, err := coserecipient.UnwrapKey(receiver, r, ctx); err == nil {
		t.Fatal("accepted static agreement without nonce or salt")
	}
}

func TestDirectRecipientStructure(t *testing.T) {
	for _, alg := range []int{iana.AlgorithmDirect, iana.AlgorithmDirect_HKDF_SHA_256, iana.AlgorithmDirect_HKDF_SHA_512, iana.AlgorithmDirect_HKDF_AES_128, iana.AlgorithmDirect_HKDF_AES_256} {
		t.Run(strconv.Itoa(alg), func(t *testing.T) {
			size := 32
			if alg == iana.AlgorithmDirect_HKDF_AES_128 {
				size = 16
			}
			k := key.Key{iana.KeyParameterKty: iana.KeyTypeSymmetric, iana.KeyParameterAlg: alg, iana.SymmetricKeyParameterK: bytes.Repeat([]byte{7}, size)}
			ctx := coserecipient.Context{ContentAlgorithm: iana.AlgorithmA256GCM, KeySize: 32}
			_, r, err := coserecipient.DeriveKey(k, ctx)
			if err != nil {
				t.Fatal(err)
			}
			ctx.RecipientProtected, _ = r.Protected.Bytes()
			if alg == iana.AlgorithmDirect {
				r.Protected = cose.Headers{iana.HeaderParameterAlg: alg}
				delete(r.Unprotected, iana.HeaderParameterAlg)
			} else {
				delete(r.Unprotected, iana.HeaderAlgorithmParameterSalt)
				delete(r.Unprotected, iana.HeaderAlgorithmParameterPartyUNonce)
			}
			if _, err := coserecipient.UnwrapKey(k, r, ctx); err == nil {
				t.Fatal("accepted invalid direct-recipient structure")
			}
		})
	}
}

func TestKeyWrapVectorAndOperations(t *testing.T) {
	// RFC 3394 section 4.1: 128-bit key data with a 128-bit KEK.
	k := key.Key{iana.KeyParameterKty: iana.KeyTypeSymmetric, iana.KeyParameterAlg: iana.AlgorithmA128KW,
		iana.SymmetricKeyParameterK: key.HexBytesify("000102030405060708090A0B0C0D0E0F"),
		iana.KeyParameterKeyOps:     []int{iana.KeyOperationEncrypt}}
	cek := key.HexBytesify("00112233445566778899AABBCCDDEEFF")
	want := key.HexBytesify("1FA68B0A8112B447AEF34BD8FB5A7B829D3E862371D2CFE5")
	r, err := coserecipient.WrapKey(k, cek, coserecipient.Context{})
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(r.Ciphertext, want) {
		t.Fatalf("wrapped key: %x", r.Ciphertext)
	}
	k[iana.KeyParameterKeyOps] = []int{iana.KeyOperationDecrypt}
	got, err := coserecipient.UnwrapKey(k, r, coserecipient.Context{})
	if err != nil || !bytes.Equal(got, cek) {
		t.Fatalf("unwrapped key: %x, %v", got, err)
	}
	for _, ops := range []any{nil, []int{}, []int{iana.KeyOperationSign}} {
		k[iana.KeyParameterKeyOps] = ops
		if _, err := coserecipient.WrapKey(k, cek, coserecipient.Context{}); err == nil {
			t.Fatal("invalid key_ops accepted for wrapping")
		}
		if _, err := coserecipient.UnwrapKey(k, r, coserecipient.Context{}); err == nil {
			t.Fatal("invalid key_ops accepted for recovery")
		}
	}
}

func TestDirectDerivationContext(t *testing.T) {
	for _, tc := range []struct {
		alg  int
		hash func() hash.Hash
	}{
		{iana.AlgorithmDirect_HKDF_SHA_256, sha256.New},
		{iana.AlgorithmDirect_HKDF_SHA_512, sha512.New},
	} {
		t.Run(strconv.Itoa(tc.alg), func(t *testing.T) {
			secret := bytes.Repeat([]byte{7}, 32)
			k := key.Key{iana.KeyParameterKty: iana.KeyTypeSymmetric, iana.KeyParameterAlg: tc.alg, iana.SymmetricKeyParameterK: secret}
			ctx := coserecipient.Context{ContentAlgorithm: iana.AlgorithmA256GCM, KeySize: 32}
			cek, r, err := coserecipient.DeriveKey(k, ctx)
			if err != nil {
				t.Fatal(err)
			}
			protected, err := r.Protected.Bytes()
			if err != nil {
				t.Fatal(err)
			}
			salt, err := r.Unprotected.GetBytes(iana.HeaderAlgorithmParameterSalt)
			if err != nil {
				t.Fatal(err)
			}
			info := key.MustMarshalCBOR([]any{iana.AlgorithmA256GCM, []any{nil, nil, nil}, []any{nil, nil, nil}, []any{256, protected}})
			expected, err := hkdf.Key(tc.hash, secret, salt, string(info), 32)
			if err != nil || !bytes.Equal(cek, expected) {
				t.Fatalf("independent KDF: %x, %v", expected, err)
			}
			ctx.RecipientProtected = protected
			ctx.ContentAlgorithm = iana.AlgorithmChaCha20Poly1305
			changed, err := coserecipient.UnwrapKey(k, r, ctx)
			if err != nil || bytes.Equal(cek, changed) {
				t.Fatalf("content algorithm not bound: %v", err)
			}
		})
	}
}
