// Package cabecap provides a managed encapsulation/decapsulation layer on
// top of the thin ckapclient.Client. It owns the client-side lease cache
// and the CBES codec, and when ARIN is explicitly enabled it subscribes to
// the key server's invalidation event stream to keep the cache coherent.
//
// Callers who just need a managed Encapsulate/Decapsulate service can use
// [NewWithClient], which constructs and owns its own ckapclient
// transport. Conversely, callers who need to share a CKAP client across
// subsystems (e.g. a diagnostic tool that also calls raw CKAP operations)
// can use [New] with an externally-owned *ckapclient.Client.
package cabecap

// config carries the resolved values of the [Option]s applied when a
// [Capsulator] is constructed.
type config struct {
	// DisableARIN suppresses the background ARIN subscription that
	// would otherwise invalidate lease-cache entries on receipt of an
	// invalidate event. ARIN is disabled by default.
	DisableARIN bool
}

// Option is a functional option applied by [New] and [NewWithClient].
type Option func(*config)

// WithARIN enables or disables the background ARIN subscription (disabled
// by default). When disabled, cached leases are kept until their Expiry
// or local eviction; no invalidation events are delivered.
func WithARIN(enable bool) Option {
	return func(c *config) { c.DisableARIN = !enable }
}
