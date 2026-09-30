package ckapraw_test

import (
	"bytes"
	"encoding/hex"
	"testing"

	"github.com/ldclabs/cose/key"
	"github.com/messier-42/cabe-go/ckapraw"
)

const federationTestOrigin = "origin"

func TestFederationWire(t *testing.T) {
	for _, flps := range [][][]byte{nil, {}, {[]byte("package")}} {
		in := ckapraw.Lease{LKAI: ckapraw.LKAI{NonCaptive: &ckapraw.LKAINonCaptive{LeaseKey: key.Key{1: 4, 3: 1, -1: []byte("0123456789abcdef"), 5: []byte("abcdefghijkl")}}}, Federation: &ckapraw.LeaseFederation{OriginDomain: federationTestOrigin, FLPs: flps}}
		raw, err := key.MarshalCBOR(in)
		if err != nil {
			t.Fatal(err)
		}
		var out ckapraw.Lease
		if err := key.UnmarshalCBOR(raw, &out); err != nil {
			t.Fatal(err)
		}
		if (out.Federation.FLPs == nil) != (flps == nil) || len(out.Federation.FLPs) != len(flps) {
			t.Fatalf("optional FLPs lost: %#v", out.Federation)
		}
		public, err := out.ToCABE()
		if err != nil {
			t.Fatal(err)
		}
		if public.Federation.OriginDomain != federationTestOrigin {
			t.Fatal("origin lost")
		}
		if len(flps) > 0 {
			out.Federation.FLPs[0][0] = 'X'
			if !bytes.Equal(public.Federation.FLPs[0], flps[0]) {
				t.Fatal("conversion aliases FLPs")
			}
		}
	}
	for _, flps := range [][][]byte{nil, {}} {
		raw, err := key.MarshalCBOR(ckapraw.RetrogradeFederation{OriginDomain: federationTestOrigin, FLPs: flps})
		if err != nil {
			t.Fatal(err)
		}
		var fields map[string]any
		if err := key.UnmarshalCBOR(raw, &fields); err != nil {
			t.Fatal(err)
		}
		a, ok := fields["flps"].([]any)
		if !ok || len(a) != 0 {
			t.Fatalf("required empty FLPs not array: %#v", fields)
		}
	}
}

func TestFederationValidation(t *testing.T) {
	for _, raw := range []string{
		"a16c6f726967696e446f6d61696e60",
		"a26c6f726967696e446f6d61696e616f64666c7073f6",
		"a26c6f726967696e446f6d61696e616f64666c70738140",
		"a26c6f726967696e446f6d61696e616f64666c70738241614161",
	} {
		decoded, err := hex.DecodeString(raw)
		if err != nil {
			t.Fatal(err)
		}
		var fed ckapraw.LeaseFederation
		if err := key.UnmarshalCBOR(decoded, &fed); err == nil {
			t.Fatalf("accepted invalid federation %s", raw)
		}
	}
	var req ckapraw.RetrogradeFederation
	if err := key.UnmarshalCBOR(key.MustMarshalCBOR(map[string]any{"originDomain": "o"}), &req); err == nil {
		t.Fatal("accepted missing required flps")
	}
}

func TestFederationIdentityEmptyKeysWire(t *testing.T) {
	raw, err := key.MarshalCBOR(ckapraw.FederationIdentity{Kind: ckapraw.KindFederationIdentity, DomainID: federationTestOrigin})
	if err != nil {
		t.Fatal(err)
	}
	var got ckapraw.FederationIdentity
	if err := key.UnmarshalCBOR(raw, &got); err != nil {
		t.Fatal(err)
	}
	if got.Keys == nil {
		t.Fatal("empty advertised key set encoded as null")
	}
	if _, err := got.ToCABE(); err != nil {
		t.Fatal(err)
	}
}
