package ckapraw_test

import (
	"bytes"
	"reflect"
	"testing"
	"time"

	"github.com/ldclabs/cose/key"
	"github.com/messier-42/cabe-go/attrset"
	"github.com/messier-42/cabe-go/ckapraw"
)

func TestLeaseToCABENonCaptive(t *testing.T) {
	rawKey := ckapraw.COSEKey{
		1:  4,
		3:  1,
		-1: []byte("0123456789abcdef"),
		5:  []byte("abcdefghijkl"),
	}
	inAttrs, err := attrset.New(map[string]any{
		"project": "cabe",
		"tier":    2,
	})
	if err != nil {
		t.Fatalf("attrset.New: %v", err)
	}
	in := ckapraw.Lease{
		LeaseID:  "l-42",
		LeaseRef: []byte("lease-ref"),
		LKAI: ckapraw.LKAI{
			NonCaptive: &ckapraw.LKAINonCaptive{LeaseKey: rawKey},
		},
		Expiry:       4070908800,
		AttributeSet: ckapraw.FromSet(inAttrs),
	}

	out, err := in.ToCABE()
	if err != nil {
		t.Fatalf("ToCABE() error = %v", err)
	}
	if out.LeaseID != "l-42" {
		t.Fatalf("LeaseID = %q", out.LeaseID)
	}
	if !bytes.Equal(out.LeaseRef, []byte("lease-ref")) {
		t.Fatalf("LeaseRef = %q", out.LeaseRef)
	}
	if !out.Expiry.Equal(time.Unix(4070908800, 0).UTC()) {
		t.Fatalf("Expiry = %v", out.Expiry)
	}
	if got, _ := out.AttributeSet.Get("project"); got != "cabe" {
		t.Fatalf("AttributeSet[project] = %v", got)
	}
	if out.LKAI.NonCaptive == nil {
		t.Fatal("expected non-captive LKAI")
	}
	if out.LKAI.Captive != nil {
		t.Fatal("Captive should be nil")
	}

	var decoded key.Key
	if err := key.UnmarshalCBOR(out.LKAI.NonCaptive.RawCOSEKey, &decoded); err != nil {
		t.Fatalf("UnmarshalCBOR(RawCOSEKey) error = %v", err)
	}
	if !reflect.DeepEqual(map[int]any{
		1:  decoded[1],
		3:  decoded[3],
		-1: decoded[-1],
		5:  decoded[5],
	}, map[int]any{
		1:  uint64(4),
		3:  uint64(1),
		-1: []byte("0123456789abcdef"),
		5:  []byte("abcdefghijkl"),
	}) {
		t.Fatalf("round-tripped COSE_Key mismatch: %#v", decoded)
	}
}

func TestLeaseToCABECaptive(t *testing.T) {
	in := ckapraw.Lease{
		LeaseRef: []byte("lease-ref-cap"),
		LKAI: ckapraw.LKAI{
			Captive: &ckapraw.LKAIActive{LeaseKeyAccessToken: []byte("lkat-bytes")},
		},
		Expiry: 2000000000,
	}

	out, err := in.ToCABE()
	if err != nil {
		t.Fatalf("ToCABE() error = %v", err)
	}
	if out.LKAI.NonCaptive != nil {
		t.Fatal("NonCaptive should be nil")
	}
	if out.LKAI.Captive == nil {
		t.Fatal("expected captive LKAI")
	}
	if !bytes.Equal(out.LKAI.Captive.LKAT, []byte("lkat-bytes")) {
		t.Fatalf("LKAT = %q", out.LKAI.Captive.LKAT)
	}
	if out.AttributeSet.Len() != 0 {
		t.Fatalf("AttributeSet = %v, want empty", out.AttributeSet)
	}
}

func TestLKAIToCABERejectsBothSet(t *testing.T) {
	_, err := ckapraw.LKAI{
		NonCaptive: &ckapraw.LKAINonCaptive{LeaseKey: ckapraw.COSEKey{}},
		Captive:    &ckapraw.LKAIActive{LeaseKeyAccessToken: []byte("x")},
	}.ToCABE()
	if err == nil {
		t.Fatal("expected error when both forms are set")
	}
}

func TestLKAIToCABERejectsEmpty(t *testing.T) {
	if _, err := (ckapraw.LKAI{}).ToCABE(); err == nil {
		t.Fatal("expected error when neither form is set")
	}
}
