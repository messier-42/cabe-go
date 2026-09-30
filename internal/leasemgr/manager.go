// Package leasemgr provides a client-side Lease cache keyed by Attribute Set
// (for Prograde key resolution) and by Lease Reference (for Retrograde key
// resolution).
//
// It is consumed by cabecap and is not part of the public API.
package leasemgr

import (
	"context"
	"encoding/binary"
	"fmt"
	"sync"
	"sync/atomic"
	"time"

	lru "github.com/hashicorp/golang-lru/v2"
	"github.com/messier-42/cabe-go/attrset"
	"github.com/messier-42/cabe-go/cabe"
	"github.com/messier-42/cabe-go/ckap"
)

// Default cache sizes applied when Config leaves them at zero.
const (
	defaultProgradeCacheSize   = 256
	defaultRetrogradeCacheSize = 1024
)

// Resolver abstracts the Prograde and Retrograde operations the Manager
// depends on. [ckapclient.Client] satisfies this interface, so it can
// be used directly.
type Resolver interface {
	Prograde(ctx context.Context, req ckap.ProgradeRequest) (*ckap.ProgradeResponse, error)
	Retrograde(ctx context.Context, req ckap.RetrogradeRequest) (*ckap.RetrogradeResponse, error)
}

// Config configures a [Manager].
type Config struct {
	// ProgradeCacheSize bounds the number of cached active Leases
	// (one per distinct Attribute Set). Specify 0 to use a reasonable
	// default.
	ProgradeCacheSize int

	// RetrogradeCacheSize bounds the number of cached LKAI entries
	// keyed by (Origin, Attribute Set, Lease Reference). Specify 0 to use a reasonable
	// default.
	RetrogradeCacheSize int

	// Now overrides time.Now for testing. nil means time.Now.
	Now func() time.Time
}

// Manager is a cache of active Leases used for encapsulation and
// of LKAI values obtained through Retrograde Key Resolution of existing
// Lease References witnessed during decapsulation.
//
// It is concurrency-safe; different Goroutines can call methods on the
// same Manager concurrently.
type Manager struct {
	resolver Resolver
	now      func() time.Time

	mu sync.Mutex
	// byAttrs maps Attribute Set Repr to active Leases. Bounded by
	// Config.ProgradeCacheSize.
	byAttrs *lru.Cache[attrset.Repr, *Lease]
	// byID maps server-issued Lease IDs to Attribute Set Reprs, so ARIN
	// invalidation events can evict the matching byAttrs entry.
	byID map[string]attrset.Repr
	// byRef maps (Origin, Attribute Set Repr, Lease Reference) to LKAIs. Bounded
	// by Config.RetrogradeCacheSize.
	byRef *lru.Cache[resolutionKey, cabe.LKAI]
}

// Lease is the cache record for a currently-valid lease.
type Lease struct {
	// Federation preserves the issuing service's metadata for every Envelope.
	Federation *cabe.LeaseFederation

	// The lease ID for ARIN purposes, if any.
	LeaseID string

	// The opaque lease reference.
	LeaseRef []byte

	// The Lease Key Access Information which was provided by the Key Server.
	LKAI cabe.LKAI

	// The time at which the Lease expires.
	Expiry time.Time

	counter atomic.Uint64
}

// New constructs a Manager backed by res. A nil cfg is equivalent to a
// zero-valued Config (all defaults).
func New(res Resolver, cfg *Config) *Manager {
	var c Config
	if cfg != nil {
		c = *cfg
	}
	if c.ProgradeCacheSize <= 0 {
		c.ProgradeCacheSize = defaultProgradeCacheSize
	}
	if c.RetrogradeCacheSize <= 0 {
		c.RetrogradeCacheSize = defaultRetrogradeCacheSize
	}
	if c.Now == nil {
		c.Now = time.Now
	}

	m := &Manager{
		resolver: res,
		now:      c.Now,
		byID:     map[string]attrset.Repr{},
	}

	// Size-bound the prograde cache, and drop byID / byRef shadows when
	// an entry is evicted so the secondary maps do not accumulate
	// stale keys.
	byAttrs, err := lru.NewWithEvict(c.ProgradeCacheSize, func(repr attrset.Repr, lease *Lease) {
		m.onAttrsEvict(repr, lease)
	})
	if err != nil {
		// lru.New only errors on non-positive size; we have clamped
		// above, so this is programmer error.
		panic(fmt.Sprintf("leasemgr: prograde cache size %d: %v", c.ProgradeCacheSize, err))
	}
	byRef, err := lru.New[resolutionKey, cabe.LKAI](c.RetrogradeCacheSize)
	if err != nil {
		panic(fmt.Sprintf("leasemgr: retrograde cache size %d: %v", c.RetrogradeCacheSize, err))
	}
	m.byAttrs = byAttrs
	m.byRef = byRef
	return m
}

// onAttrsEvict cleans up the byID and byRef shadows when an entry
// leaves byAttrs (whether via explicit invalidation, LRU eviction, or
// overwrite). Runs under m.mu: lru invokes the evict callback
// synchronously from within its own mutations, and we always hold m.mu
// when we call into m.byAttrs.
func (m *Manager) onAttrsEvict(attrSetRepr attrset.Repr, lease *Lease) {
	if lease == nil {
		return
	}
	if lease.LeaseID != "" {
		// Only drop the byID pointer if it still refers to us; a
		// newer entry for the same LeaseID should not be clobbered.
		if cur, ok := m.byID[lease.LeaseID]; ok && cur == attrSetRepr {
			delete(m.byID, lease.LeaseID)
		}
	}
	m.byRef.Remove(retrogradeKey(attrSetRepr, lease.LeaseRef, leaseOrigin(lease)))
}

// ResolveForEncapsulation returns a cached or newly fetched active lease
// for attrs. If arinToken is non-nil it is quoted in a fresh Prograde
// request so the Key Server subscribes the lease into the corresponding
// ARIN stream.
func (m *Manager) ResolveForEncapsulation(ctx context.Context, attrs attrset.Set, arinToken []byte) (*Lease, error) {
	repr := attrs.Repr()

	m.mu.Lock()
	if lease, ok := m.byAttrs.Get(repr); ok && m.now().Before(lease.Expiry) {
		m.mu.Unlock()
		return lease, nil
	}
	m.mu.Unlock()

	resp, err := m.resolver.Prograde(ctx, ckap.ProgradeRequest{
		AttributeSet: attrs,
		ARINToken:    append([]byte(nil), arinToken...),
	})
	if err != nil {
		return nil, fmt.Errorf("prograde: %w", err)
	}
	lease := resp.Lease

	active := &Lease{
		Federation: lease.Federation.Clone(),
		LeaseID:    lease.LeaseID,
		LeaseRef:   append([]byte(nil), lease.LeaseRef...),
		LKAI:       lease.LKAI,
		Expiry:     lease.Expiry,
	}

	m.mu.Lock()
	m.byAttrs.Add(repr, active)
	if active.LeaseID != "" {
		m.byID[active.LeaseID] = repr
	}
	m.byRef.Add(retrogradeKey(repr, active.LeaseRef, leaseOrigin(active)), active.LKAI)
	m.mu.Unlock()

	return active, nil
}

// ResolveForDecapsulation returns the LKAI for the given attribute set
// and lease reference in the supplied federation context, consulting the cache first.
func (m *Manager) ResolveForDecapsulation(ctx context.Context, attrs attrset.Set, leaseRef []byte, federation *ckap.RetrogradeFederation) (cabe.LKAI, error) {
	origin := ""
	if federation != nil {
		if err := (cabe.LeaseFederation{OriginDomain: federation.OriginDomain, FLPs: federation.FLPs}).Validate(); err != nil {
			return cabe.LKAI{}, err
		}
		origin = federation.OriginDomain
	}
	cacheKey := retrogradeKey(attrs.Repr(), leaseRef, origin)

	m.mu.Lock()
	if lkai, ok := m.byRef.Get(cacheKey); ok {
		m.mu.Unlock()
		return lkai, nil
	}
	m.mu.Unlock()

	resp, err := m.resolver.Retrograde(ctx, ckap.RetrogradeRequest{
		AttributeSet: attrs,
		LeaseRef:     append([]byte(nil), leaseRef...),
		Federation:   federation,
	})
	if err != nil {
		return cabe.LKAI{}, fmt.Errorf("retrograde: %w", err)
	}
	lkai := resp.LKAI

	m.mu.Lock()
	m.byRef.Add(cacheKey, *lkai)
	m.mu.Unlock()
	return *lkai, nil
}

// InvalidateLeaseID evicts all cache entries for the given server-issued
// lease ID.
func (m *Manager) InvalidateLeaseID(leaseID string) {
	m.mu.Lock()
	defer m.mu.Unlock()

	repr, ok := m.byID[leaseID]
	if !ok {
		return
	}
	// Remove triggers onAttrsEvict, which cleans up byID and byRef.
	m.byAttrs.Remove(repr)
}

// NextPartialIV returns the next per-lease partial IV. The result is
// monotonically increasing for a given lease; its bytes are the minimal
// big-endian encoding of the counter value.
func (a *Lease) NextPartialIV() []byte {
	v := a.counter.Add(1)
	buf := make([]byte, 8)
	binary.BigEndian.PutUint64(buf, v)

	i := 0
	for i < len(buf)-1 && buf[i] == 0 {
		i++
	}
	return buf[i:]
}

// resolutionKey separates all context values, including an absent Origin.
type resolutionKey struct {
	attributes attrset.Repr
	reference  string
	origin     string
}

func retrogradeKey(attrs attrset.Repr, ref []byte, origin string) resolutionKey {
	return resolutionKey{attributes: attrs, reference: string(ref), origin: origin}
}

func leaseOrigin(lease *Lease) string {
	if lease.Federation == nil {
		return ""
	}
	return lease.Federation.OriginDomain
}
