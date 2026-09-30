package leasemgr

import (
	"testing"
	"time"

	"github.com/messier-42/cabe-go/attrset"
	"github.com/messier-42/cabe-go/cabe"
	"github.com/messier-42/cabe-go/ckap"
)

func TestFederationCache(t *testing.T) {
	l := nonCaptiveLease([]byte("ref"), []byte("key"), time.Now().Add(time.Hour))
	l.LeaseID = "id"
	l.Federation = &cabe.LeaseFederation{OriginDomain: "a", FLPs: cabe.FLPSet{[]byte("package")}}
	r := &fakeResolver{progradeResponse: l, retrogradeResponse: &l.LKAI}
	m := New(r, nil)
	attrs := attrset.Set{}
	active, err := m.ResolveForEncapsulation(t.Context(), attrs, nil)
	if err != nil {
		t.Fatal(err)
	}
	if active.Federation.OriginDomain != "a" || string(active.Federation.FLPs[0]) != "package" {
		t.Fatal("metadata lost")
	}
	l.Federation.FLPs[0][0] = 'X'
	if string(active.Federation.FLPs[0]) != "package" {
		t.Fatal("cache aliases response")
	}
	for _, origin := range []string{"a", "b", "a", "b", ""} {
		var fed *ckap.RetrogradeFederation
		if origin != "" {
			fed = &ckap.RetrogradeFederation{OriginDomain: origin}
		}
		if _, err := m.ResolveForDecapsulation(t.Context(), attrs, []byte("ref"), fed); err != nil {
			t.Fatal(err)
		}
	}
	if r.retrogradeCalls != 2 {
		t.Fatalf("origin cache isolation failed: %d calls", r.retrogradeCalls)
	}
	m.InvalidateLeaseID("id")
	if _, err := m.ResolveForDecapsulation(t.Context(), attrs, []byte("ref"), &ckap.RetrogradeFederation{OriginDomain: "a"}); err != nil {
		t.Fatal(err)
	}
	if r.retrogradeCalls != 3 {
		t.Fatal("invalidation missed federated entry")
	}
}
