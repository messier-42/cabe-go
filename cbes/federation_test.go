package cbes_test

import (
	"bytes"
	"maps"
	"testing"

	"github.com/fxamacker/cbor/v2"
	"github.com/ldclabs/cose/cose"
	"github.com/ldclabs/cose/iana"
	"github.com/ldclabs/cose/key"
	"github.com/messier-42/cabe-go/attrset"
	"github.com/messier-42/cabe-go/cabe"
	"github.com/messier-42/cabe-go/cbes"
	"github.com/messier-42/cabe-go/internal/cbescodec"
	"github.com/messier-42/cabe-go/internal/leasemgr"
)

const federationTestOrigin = "origin"

func TestFederationHeadersAndReplacement(t *testing.T) {
	k := key.Key{1: 4, 3: 1, -1: []byte("0123456789abcdef"), 5: []byte("abcdefghijkl")}
	lkai := cabe.LKAI{NonCaptive: &cabe.LKAINonCaptive{RawCOSEKey: key.MustMarshalCBOR(k)}}
	for _, flps := range []cabe.FLPSet{nil, {}, {[]byte("first")}} {
		lease := &leasemgr.Lease{LeaseRef: []byte("ref"), LKAI: lkai, Federation: &cabe.LeaseFederation{OriginDomain: federationTestOrigin, FLPs: flps}}
		result, err := cbescodec.New().Encapsulate(t.Context(), cbescodec.EncapsulateArgs{Lease: lease, AttributeSet: attrset.Repr("\xa0"), Payload: []byte("payload")})
		if err != nil {
			t.Fatal(err)
		}
		inspected, err := cbes.Inspect(result.Envelope)
		if err != nil {
			t.Fatal(err)
		}
		if inspected.OriginDomain != federationTestOrigin || len(inspected.FLPs) != len(flps) {
			t.Fatalf("metadata lost: %#v", inspected)
		}
		var msg cose.Encrypt0Message[[]byte]
		if err := msg.UnmarshalCBOR(result.Envelope); err != nil {
			t.Fatal(err)
		}
		if !msg.Protected.Has(cbes.HeaderOriginDomain) || msg.Unprotected.Has(cbes.HeaderOriginDomain) || msg.Protected.Has(cbes.HeaderFLPs) || msg.Unprotected.Has(cbes.HeaderFLPs) != (len(flps) > 0) {
			t.Fatal("wrong header placement or empty behavior")
		}
		for _, tagged := range []bool{false, true} {
			original := result.Envelope
			if !tagged {
				original = cose.RemoveCBORTag(original)
			}
			for _, replacement := range []cabe.FLPSet{nil, {}, {[]byte("new"), []byte("sidecar")}} {
				updated, err := cbes.SetFLPs(original, replacement)
				if err != nil {
					t.Fatal(err)
				}
				got, err := cbes.Inspect(updated)
				if err != nil {
					t.Fatal(err)
				}
				if got.OriginDomain != federationTestOrigin || len(got.FLPs) != len(replacement) {
					t.Fatal("replacement lost")
				}
				if (updated[0]>>5 == 6) != tagged {
					t.Fatal("tag changed")
				}
				var before, after []cbor.RawMessage
				if err := key.UnmarshalCBOR(cose.RemoveCBORTag(original), &before); err != nil {
					t.Fatal(err)
				}
				if err := key.UnmarshalCBOR(cose.RemoveCBORTag(updated), &after); err != nil {
					t.Fatal(err)
				}
				if !bytes.Equal(before[0], after[0]) || !bytes.Equal(before[2], after[2]) {
					t.Fatal("protected bytes or ciphertext changed")
				}
				plain, err := cbescodec.New().Decapsulate(t.Context(), cbescodec.DecapsulateArgs{Envelope: updated, LKAI: lkai})
				if err != nil {
					t.Fatal(err)
				}
				if string(plain.Payload) != "payload" {
					t.Fatal("plaintext changed")
				}
			}
		}
	}
}

func TestFederationRejectsInvalidHeaders(t *testing.T) {
	for _, captive := range []bool{false, true} {
		env := buildNonCaptive(t, "data", []byte{0xa0}, "")
		if captive {
			env = buildCaptive(t, "data", []byte{0xa0}, "")
		}
		cases := []struct {
			name                   string
			protected, unprotected cose.Headers
		}{
			{"unprotected origin", nil, cose.Headers{cbes.HeaderOriginDomain: federationTestOrigin}},
			{"protected FLPs", cose.Headers{cbes.HeaderFLPs: [][]byte{[]byte("p")}}, nil},
			{"empty origin", cose.Headers{cbes.HeaderOriginDomain: ""}, nil},
			{"bytes origin", cose.Headers{cbes.HeaderOriginDomain: []byte("o")}, nil},
			{"empty FLPs", nil, cose.Headers{cbes.HeaderFLPs: [][]byte{}}},
			{"null FLPs", nil, cose.Headers{cbes.HeaderFLPs: nil}},
			{"empty package", nil, cose.Headers{cbes.HeaderFLPs: [][]byte{{}}}},
			{"duplicate packages", nil, cose.Headers{cbes.HeaderFLPs: [][]byte{[]byte("p"), []byte("p")}}},
			{"separated duplicate packages", nil, cose.Headers{cbes.HeaderFLPs: [][]byte{[]byte("p"), []byte("q"), []byte("p")}}},
			{"text package", nil, cose.Headers{cbes.HeaderFLPs: []string{"p"}}},
			{"critical origin", cose.Headers{cbes.HeaderOriginDomain: "o", iana.HeaderParameterCrit: []any{cbes.HeaderOriginDomain}}, nil},
			{"critical FLPs", cose.Headers{iana.HeaderParameterCrit: []any{cbes.HeaderFLPs}}, cose.Headers{cbes.HeaderFLPs: [][]byte{[]byte("p")}}},
		}
		for _, tc := range cases {
			t.Run(tc.name, func(t *testing.T) {
				var parts []cbor.RawMessage
				if err := key.UnmarshalCBOR(cose.RemoveCBORTag(env), &parts); err != nil {
					t.Fatal(err)
				}
				var p []byte
				if err := key.UnmarshalCBOR(parts[0], &p); err != nil {
					t.Fatal(err)
				}
				headers, err := cose.HeadersFromBytes(p)
				if err != nil {
					t.Fatal(err)
				}
				maps.Copy(headers, tc.protected)
				parts[0] = key.MustMarshalCBOR(key.MustMarshalCBOR(headers))
				var u cose.Headers
				if err := key.UnmarshalCBOR(parts[1], &u); err != nil {
					t.Fatal(err)
				}
				maps.Copy(u, tc.unprotected)
				parts[1] = key.MustMarshalCBOR(u)
				raw := key.MustMarshalCBOR(parts)
				prefix := env[:len(env)-len(cose.RemoveCBORTag(env))]
				tagged := append(bytes.Clone(prefix), raw...)
				for _, form := range [][]byte{raw, tagged} {
					if _, err := cbes.Inspect(form); err == nil {
						t.Fatal("accepted invalid headers")
					}
				}
			})
		}
	}
}

func TestSetFLPsRejectsInvalidSets(t *testing.T) {
	for _, env := range [][]byte{
		buildNonCaptive(t, "data", []byte{0xa0}, ""),
		buildCaptive(t, "data", []byte{0xa0}, ""),
	} {
		for _, form := range [][]byte{env, cose.RemoveCBORTag(env)} {
			before := bytes.Clone(form)
			for _, invalid := range []cabe.FLPSet{
				{[]byte("p"), []byte("p")},
				{[]byte("p"), []byte("q"), []byte("p")},
				{[]byte("p"), nil},
			} {
				if got, err := cbes.SetFLPs(form, invalid); err == nil || got != nil {
					t.Fatal("accepted an invalid FLP set")
				}
				if !bytes.Equal(before, form) {
					t.Fatal("modified the input Envelope")
				}
			}
		}
	}
}

func TestSetFLPsPreservesCaptiveRecipients(t *testing.T) {
	env := buildCaptive(t, "data", []byte{0xa0}, "")
	updated, err := cbes.SetFLPs(env, cabe.FLPSet{[]byte("sidecar")})
	if err != nil {
		t.Fatal(err)
	}
	var before, after []cbor.RawMessage
	if err := key.UnmarshalCBOR(cose.RemoveCBORTag(env), &before); err != nil {
		t.Fatal(err)
	}
	if err := key.UnmarshalCBOR(cose.RemoveCBORTag(updated), &after); err != nil {
		t.Fatal(err)
	}
	for _, i := range []int{0, 2, 3} {
		if !bytes.Equal(before[i], after[i]) {
			t.Fatalf("field %d changed", i)
		}
	}
}
