package leasemgr

import (
	"bytes"
	"context"
	"testing"
	"time"

	"github.com/messier-42/cabe-go/attrset"
	"github.com/messier-42/cabe-go/cabe"
	"github.com/messier-42/cabe-go/ckap"
)

const (
	testProjectAttribute = "project"
	testProject          = "cabe"
)

func nonCaptiveLease(ref []byte, key []byte, expiry time.Time) *cabe.Lease {
	return &cabe.Lease{
		LeaseRef: ref,
		LKAI:     cabe.LKAI{NonCaptive: &cabe.LKAINonCaptive{RawCOSEKey: key}},
		Expiry:   expiry,
	}
}

func TestManagerCachesUntilExpiry(t *testing.T) {
	now := time.Unix(100, 0)
	tr := &fakeResolver{
		progradeResponse: nonCaptiveLease([]byte("lease-1"), []byte("key-a"), now.Add(time.Minute)),
	}
	mgr := New(tr, &Config{Now: func() time.Time { return now }})

	attrs, _ := attrset.New(map[string]any{testProjectAttribute: testProject})
	first, err := mgr.ResolveForEncapsulation(context.Background(), attrs, nil)
	if err != nil {
		t.Fatalf("ResolveForEncapsulation(first) error = %v", err)
	}

	second, err := mgr.ResolveForEncapsulation(context.Background(), attrs, nil)
	if err != nil {
		t.Fatalf("ResolveForEncapsulation(second) error = %v", err)
	}

	if tr.progradeCalls != 1 {
		t.Fatalf("prograde calls = %d, want 1", tr.progradeCalls)
	}
	if !bytes.Equal(first.LeaseRef, second.LeaseRef) {
		t.Fatalf("lease refs mismatch: %q != %q", first.LeaseRef, second.LeaseRef)
	}
}

func TestManagerRefreshesAfterExpiry(t *testing.T) {
	now := time.Unix(100, 0)
	tr := &fakeResolver{
		progradeResponses: []*cabe.Lease{
			nonCaptiveLease([]byte("lease-1"), []byte("key-a"), now.Add(time.Second)),
			nonCaptiveLease([]byte("lease-2"), []byte("key-b"), now.Add(time.Minute)),
		},
	}
	current := now
	mgr := New(tr, &Config{Now: func() time.Time { return current }})

	attrs, _ := attrset.New(map[string]any{testProjectAttribute: testProject})
	first, err := mgr.ResolveForEncapsulation(context.Background(), attrs, nil)
	if err != nil {
		t.Fatalf("ResolveForEncapsulation(first) error = %v", err)
	}

	current = now.Add(2 * time.Second)
	second, err := mgr.ResolveForEncapsulation(context.Background(), attrs, nil)
	if err != nil {
		t.Fatalf("ResolveForEncapsulation(second) error = %v", err)
	}

	if tr.progradeCalls != 2 {
		t.Fatalf("prograde calls = %d, want 2", tr.progradeCalls)
	}
	if bytes.Equal(first.LeaseRef, second.LeaseRef) {
		t.Fatalf("expected refreshed lease, got same ref %q", first.LeaseRef)
	}
}

func TestManagerInvalidatesLeaseID(t *testing.T) {
	now := time.Unix(100, 0)
	tr := &fakeResolver{
		progradeResponses: []*cabe.Lease{
			{
				LeaseID:  "lease-id-1",
				LeaseRef: []byte("lease-1"),
				LKAI:     cabe.LKAI{NonCaptive: &cabe.LKAINonCaptive{RawCOSEKey: []byte("a")}},
				Expiry:   now.Add(time.Minute),
			},
			{
				LeaseID:  "lease-id-2",
				LeaseRef: []byte("lease-2"),
				LKAI:     cabe.LKAI{NonCaptive: &cabe.LKAINonCaptive{RawCOSEKey: []byte("b")}},
				Expiry:   now.Add(time.Minute),
			},
		},
	}
	mgr := New(tr, &Config{Now: func() time.Time { return now }})

	attrs, _ := attrset.New(map[string]any{testProjectAttribute: testProject})
	first, err := mgr.ResolveForEncapsulation(context.Background(), attrs, nil)
	if err != nil {
		t.Fatalf("ResolveForEncapsulation(first) error = %v", err)
	}

	mgr.InvalidateLeaseID("lease-id-1")

	second, err := mgr.ResolveForEncapsulation(context.Background(), attrs, nil)
	if err != nil {
		t.Fatalf("ResolveForEncapsulation(second) error = %v", err)
	}

	if tr.progradeCalls != 2 {
		t.Fatalf("prograde calls = %d, want 2", tr.progradeCalls)
	}
	if bytes.Equal(first.LeaseRef, second.LeaseRef) {
		t.Fatalf("expected new lease after invalidation, got %q", first.LeaseRef)
	}
}

func TestManagerProgradeCacheLRUEvicts(t *testing.T) {
	now := time.Unix(100, 0)
	tr := &fakeResolver{
		progradeResponses: []*cabe.Lease{
			{LeaseID: "id-a", LeaseRef: []byte("ref-a"), LKAI: cabe.LKAI{NonCaptive: &cabe.LKAINonCaptive{RawCOSEKey: []byte("k")}}, Expiry: now.Add(time.Minute)},
			{LeaseID: "id-b", LeaseRef: []byte("ref-b"), LKAI: cabe.LKAI{NonCaptive: &cabe.LKAINonCaptive{RawCOSEKey: []byte("k")}}, Expiry: now.Add(time.Minute)},
			{LeaseID: "id-c", LeaseRef: []byte("ref-c"), LKAI: cabe.LKAI{NonCaptive: &cabe.LKAINonCaptive{RawCOSEKey: []byte("k")}}, Expiry: now.Add(time.Minute)},
			// When A is re-fetched after eviction, the server returns
			// a fresh record.
			{LeaseID: "id-a2", LeaseRef: []byte("ref-a2"), LKAI: cabe.LKAI{NonCaptive: &cabe.LKAINonCaptive{RawCOSEKey: []byte("k")}}, Expiry: now.Add(time.Minute)},
		},
	}
	mgr := New(tr, &Config{
		ProgradeCacheSize: 2,
		Now:               func() time.Time { return now },
	})
	ctx := context.Background()

	attrsA, _ := attrset.New(map[string]any{"x": "a"})
	attrsB, _ := attrset.New(map[string]any{"x": "b"})
	attrsC, _ := attrset.New(map[string]any{"x": "c"})

	// Populate A and B.
	if _, err := mgr.ResolveForEncapsulation(ctx, attrsA, nil); err != nil {
		t.Fatalf("A: %v", err)
	}
	if _, err := mgr.ResolveForEncapsulation(ctx, attrsB, nil); err != nil {
		t.Fatalf("B: %v", err)
	}
	// Inserting C evicts A (the LRU entry).
	if _, err := mgr.ResolveForEncapsulation(ctx, attrsC, nil); err != nil {
		t.Fatalf("C: %v", err)
	}
	// Re-resolving A goes back to the server (cache miss).
	before := tr.progradeCalls
	if _, err := mgr.ResolveForEncapsulation(ctx, attrsA, nil); err != nil {
		t.Fatalf("A re-resolve: %v", err)
	}
	if tr.progradeCalls != before+1 {
		t.Fatalf("expected cache miss on A; calls delta = %d", tr.progradeCalls-before)
	}
	// ARIN bookkeeping for evicted id-a should be gone: InvalidateLeaseID
	// on it must not affect the current cache contents.
	mgr.InvalidateLeaseID("id-a") // the original id-a; has been evicted.
	if _, err := mgr.ResolveForEncapsulation(ctx, attrsA, nil); err != nil {
		t.Fatalf("A after stale invalidation: %v", err)
	}
	// The refreshed entry (id-a2) should still be cached: no new server
	// call from the line above.
	if tr.progradeCalls != before+1 {
		t.Fatalf("stale InvalidateLeaseID affected cache; calls delta = %d", tr.progradeCalls-before)
	}
}

func TestManagerRetrogradeCacheLRUEvicts(t *testing.T) {
	tr := &fakeResolver{
		retrogradeResponses: []*cabe.LKAI{
			{NonCaptive: &cabe.LKAINonCaptive{RawCOSEKey: []byte("a")}},
			{NonCaptive: &cabe.LKAINonCaptive{RawCOSEKey: []byte("b")}},
			{NonCaptive: &cabe.LKAINonCaptive{RawCOSEKey: []byte("c")}},
			{NonCaptive: &cabe.LKAINonCaptive{RawCOSEKey: []byte("a2")}},
		},
	}
	mgr := New(tr, &Config{
		RetrogradeCacheSize: 2,
		Now:                 func() time.Time { return time.Unix(100, 0) },
	})
	ctx := context.Background()
	attrs, _ := attrset.New(map[string]any{testProjectAttribute: testProject})

	if _, err := mgr.ResolveForDecapsulation(ctx, attrs, []byte("ref-a"), nil); err != nil {
		t.Fatalf("A: %v", err)
	}
	if _, err := mgr.ResolveForDecapsulation(ctx, attrs, []byte("ref-b"), nil); err != nil {
		t.Fatalf("B: %v", err)
	}
	// Third unique lookup evicts ref-a.
	if _, err := mgr.ResolveForDecapsulation(ctx, attrs, []byte("ref-c"), nil); err != nil {
		t.Fatalf("C: %v", err)
	}
	before := tr.retrogradeCalls
	if _, err := mgr.ResolveForDecapsulation(ctx, attrs, []byte("ref-a"), nil); err != nil {
		t.Fatalf("A re-resolve: %v", err)
	}
	if tr.retrogradeCalls != before+1 {
		t.Fatalf("expected cache miss on ref-a; calls delta = %d", tr.retrogradeCalls-before)
	}
}

func TestLeaseAllocatesUniquePartialIVs(t *testing.T) {
	active := Lease{}
	first := active.NextPartialIV()
	second := active.NextPartialIV()
	if bytes.Equal(first, second) {
		t.Fatalf("partial IVs must be unique: %x", first)
	}
}

func TestManagerCachesRetrogradeByLeaseRef(t *testing.T) {
	tr := &fakeResolver{
		retrogradeResponse: &cabe.LKAI{
			NonCaptive: &cabe.LKAINonCaptive{RawCOSEKey: []byte("k")},
		},
	}
	mgr := New(tr, &Config{Now: func() time.Time { return time.Unix(100, 0) }})
	attrs, _ := attrset.New(map[string]any{testProjectAttribute: testProject})

	first, err := mgr.ResolveForDecapsulation(context.Background(), attrs, []byte("lease-ref"), nil)
	if err != nil {
		t.Fatalf("ResolveForDecapsulation(first) error = %v", err)
	}
	second, err := mgr.ResolveForDecapsulation(context.Background(), attrs, []byte("lease-ref"), nil)
	if err != nil {
		t.Fatalf("ResolveForDecapsulation(second) error = %v", err)
	}

	if tr.retrogradeCalls != 1 {
		t.Fatalf("retrograde calls = %d, want 1", tr.retrogradeCalls)
	}
	if first.NonCaptive == nil || second.NonCaptive == nil {
		t.Fatal("expected non-captive lkai")
	}
}

func TestManagerInvalidationClearsRetrogradeCache(t *testing.T) {
	now := time.Unix(100, 0)
	tr := &fakeResolver{
		progradeResponse: &cabe.Lease{
			LeaseID:  "lease-id-1",
			LeaseRef: []byte("lease-ref"),
			LKAI:     cabe.LKAI{NonCaptive: &cabe.LKAINonCaptive{RawCOSEKey: []byte("a")}},
			Expiry:   now.Add(time.Minute),
		},
		retrogradeResponses: []*cabe.LKAI{
			{NonCaptive: &cabe.LKAINonCaptive{RawCOSEKey: []byte("a")}},
			{NonCaptive: &cabe.LKAINonCaptive{RawCOSEKey: []byte("b")}},
		},
	}
	mgr := New(tr, &Config{Now: func() time.Time { return now }})
	attrs, _ := attrset.New(map[string]any{testProjectAttribute: testProject})

	active, err := mgr.ResolveForEncapsulation(context.Background(), attrs, nil)
	if err != nil {
		t.Fatalf("ResolveForEncapsulation() error = %v", err)
	}
	if _, err := mgr.ResolveForDecapsulation(context.Background(), attrs, active.LeaseRef, nil); err != nil {
		t.Fatalf("ResolveForDecapsulation(first) error = %v", err)
	}

	mgr.InvalidateLeaseID("lease-id-1")

	if _, err := mgr.ResolveForDecapsulation(context.Background(), attrs, active.LeaseRef, nil); err != nil {
		t.Fatalf("ResolveForDecapsulation(second) error = %v", err)
	}
	if tr.retrogradeCalls != 1 {
		t.Fatalf("retrograde calls = %d, want 1 after invalidation", tr.retrogradeCalls)
	}
}

type fakeResolver struct {
	progradeCalls       int
	progradeResponse    *cabe.Lease
	progradeResponses   []*cabe.Lease
	retrogradeCalls     int
	retrogradeResponse  *cabe.LKAI
	retrogradeResponses []*cabe.LKAI
}

func (f *fakeResolver) Prograde(ctx context.Context, req ckap.ProgradeRequest) (*ckap.ProgradeResponse, error) {
	f.progradeCalls++
	if len(f.progradeResponses) > 0 {
		resp := f.progradeResponses[0]
		f.progradeResponses = f.progradeResponses[1:]
		return &ckap.ProgradeResponse{Lease: resp}, nil
	}
	return &ckap.ProgradeResponse{Lease: f.progradeResponse}, nil
}

func (f *fakeResolver) Retrograde(ctx context.Context, req ckap.RetrogradeRequest) (*ckap.RetrogradeResponse, error) {
	f.retrogradeCalls++
	if len(f.retrogradeResponses) > 0 {
		resp := f.retrogradeResponses[0]
		f.retrogradeResponses = f.retrogradeResponses[1:]
		return &ckap.RetrogradeResponse{LKAI: resp}, nil
	}
	return &ckap.RetrogradeResponse{LKAI: f.retrogradeResponse}, nil
}
