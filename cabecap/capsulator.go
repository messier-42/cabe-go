package cabecap

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/messier-42/cabe-go/attrset"
	"github.com/messier-42/cabe-go/cabe"
	"github.com/messier-42/cabe-go/cbes"
	"github.com/messier-42/cabe-go/ckap"
	"github.com/messier-42/cabe-go/ckapclient"
	"github.com/messier-42/cabe-go/internal/cbescodec"
	"github.com/messier-42/cabe-go/internal/leasemgr"
)

// Capsulator provides managed CABE envelope encapsulation and decapsulation.
// It manages cached leases returned by Prograde key resolution, reuses them across
// Encapsulate calls for the same attribute set, and (unless ARIN has been
// disabled) invalidates cache entries when asynchronously notified of
// lease invalidation.
//
// Construct a Capsulator with [New] (when the caller owns the underlying
// [ckapclient.Client]) or [NewWithClient] (when the Capsulator should own
// it). Close stops any background lease management activity. If an external
// client was provided using [New], it does not close that client.
type Capsulator struct {
	// Capsulator configuration.
	cfg config

	// The low-level CKAP protocol client used to invoke CKAP operations.
	client      *ckapclient.Client
	clientOwned bool // Do we close this client when Close is called?

	leaseMgr      *leasemgr.Manager
	envelopeCodec cbescodec.Codec

	mu              sync.Mutex
	arinToken       []byte
	arinStarted     bool
	arinUnsupported bool

	arinCtx    context.Context //nolint:containedctx // lifecycle ctx for background ARIN stream, cancelled from Close
	arinCancel context.CancelFunc
	arinDone   chan struct{}

	closeOnce sync.Once
	closeErr  error
}

// New constructs a [Capsulator] wrapping a caller-supplied client. The
// client is borrowed; a subsequent call to [Capsulator.Close] on a
// [Capsulator] constructed using this function will stop background
// maintenance processes but will not close the underlying
// [ckapclient.Client].
func New(client *ckapclient.Client, opts ...Option) *Capsulator {
	return newCapsulator(client, false, opts)
}

// NewWithClient constructs a [Capsulator]. It creates and manages its
// own [ckapclient.Client] internally, configured via cfg. The client is
// torn down with the [Capsulator] when [Capsulator.Close] is called.
func NewWithClient(cfg ckapclient.Config, opts ...Option) (*Capsulator, error) {
	client, err := ckapclient.NewClient(cfg)
	if err != nil {
		return nil, err
	}
	return newCapsulator(client, true, opts), nil
}

func newCapsulator(client *ckapclient.Client, owned bool, opts []Option) *Capsulator {
	cfg := config{}
	for _, apply := range opts {
		apply(&cfg)
	}
	c := &Capsulator{
		client:        client,
		clientOwned:   owned,
		cfg:           cfg,
		envelopeCodec: cbescodec.New(),
	}
	c.leaseMgr = leasemgr.New(client, nil)
	return c
}

// Close stops the background ARIN subscription, if any, and (for owned
// clients) closes the underlying *ckapclient.Client.
func (c *Capsulator) Close() error {
	c.closeOnce.Do(func() {
		c.mu.Lock()
		cancel := c.arinCancel
		done := c.arinDone
		c.mu.Unlock()

		if cancel != nil {
			cancel()
		}
		if done != nil {
			<-done
		}
		if c.clientOwned {
			c.closeErr = c.client.Close()
		}
	})
	return c.closeErr
}

// Encapsulate builds a CBES envelope from the given message.
func (c *Capsulator) Encapsulate(ctx context.Context, msg cabe.Message) ([]byte, error) {
	repr := msg.Attributes.Repr()

	arinToken, err := c.ensureARINToken(ctx)
	if err != nil {
		return nil, fmt.Errorf("initialize ARIN: %w", err)
	}

	active, err := c.leaseMgr.ResolveForEncapsulation(ctx, msg.Attributes, arinToken)
	if err != nil {
		return nil, err
	}
	c.ensureARINStream()

	res, err := c.envelopeCodec.Encapsulate(ctx, cbescodec.EncapsulateArgs{
		Payload:      msg.Payload,
		ContentType:  msg.ContentType,
		AttributeSet: repr,
		Lease:        active,
		Wrap: func(ctx context.Context, token, cek []byte) ([]byte, error) {
			resp, err := c.client.AssistedEncapsulate(ctx, ckap.AssistedEncapsulateRequest{
				LKAT: token,
				CEK:  cek,
			})
			if err != nil {
				return nil, err
			}
			return resp.WrappedCEK, nil
		},
	})
	if err != nil {
		return nil, fmt.Errorf("encapsulate: %w", err)
	}
	return res.Envelope, nil
}

// Decapsulate recovers the plaintext message from a CBES envelope.
func (c *Capsulator) Decapsulate(ctx context.Context, envelopeBytes []byte) (cabe.Message, error) {
	inspected, err := cbes.Inspect(envelopeBytes)
	if err != nil {
		// All Inspect errors mean the envelope is unusable; translate
		// to cabecap.ErrInvalidEnvelope so callers have a single
		// sentinel to match on, while preserving the underlying
		// diagnostic via %w chain length.
		return cabe.Message{}, fmt.Errorf("%w: %w", ErrInvalidEnvelope, err)
	}

	attrs := inspected.AttributeSet

	lkai, err := c.leaseMgr.ResolveForDecapsulation(ctx, attrs, inspected.LeaseRef)
	if err != nil {
		return cabe.Message{}, err
	}

	res, err := c.envelopeCodec.Decapsulate(ctx, cbescodec.DecapsulateArgs{
		Envelope: envelopeBytes,
		LKAI:     lkai,
		Unwrap: func(ctx context.Context, token, wrapped []byte) ([]byte, error) {
			resp, err := c.client.AssistedDecapsulate(ctx, ckap.AssistedDecapsulateRequest{
				LKAT:       token,
				WrappedCEK: wrapped,
			})
			if err != nil {
				return nil, err
			}
			return resp.CEK, nil
		},
	})
	if err != nil {
		return cabe.Message{}, fmt.Errorf("decapsulate: %w", err)
	}

	return cabe.Message{
		Payload:     res.Payload,
		Attributes:  attrs,
		ContentType: res.ContentType,
	}, nil
}

// WarmLease resolves the lease for the given attribute set without
// encapsulating anything, populating the client-side cache. Subsequent
// Encapsulate calls for the same attribute set reuse this lease until
// it expires or is invalidated.
func (c *Capsulator) WarmLease(ctx context.Context, attrs attrset.Set) error {
	arinToken, err := c.ensureARINToken(ctx)
	if err != nil {
		return err
	}
	if _, err := c.leaseMgr.ResolveForEncapsulation(ctx, attrs, arinToken); err != nil {
		return err
	}
	c.ensureARINStream()
	return nil
}

func (c *Capsulator) ensureARINToken(ctx context.Context) ([]byte, error) {
	if c.cfg.DisableARIN || c.isARINUnsupported() {
		return nil, nil
	}
	if tok := c.cachedARINToken(); tok != nil {
		return tok, nil
	}
	resp, err := c.client.GetARINToken(ctx, ckap.GetARINTokenRequest{})
	if err != nil {
		var srv *ckap.Error
		if errors.As(err, &srv) && srv.Code == cabe.CodeUnsupported {
			c.markARINUnsupported()
			return nil, nil
		}
		return nil, err
	}
	return c.storeARINToken(resp.Token), nil
}

// isARINUnsupported reports whether a previous GetARINToken confirmed
// that the Key Server does not implement ARIN.
func (c *Capsulator) isARINUnsupported() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.arinUnsupported
}

// markARINUnsupported records that the Key Server lacks ARIN support,
// logging once so operators who expected ARIN see that it has been
// downgraded. Further ensureARINToken calls short-circuit to nil.
func (c *Capsulator) markARINUnsupported() {
	c.mu.Lock()
	first := !c.arinUnsupported
	c.arinUnsupported = true
	c.mu.Unlock()
	if first {
		slog.Warn("cabecap: ARIN not supported by Key Server; continuing without invalidation")
	}
}

// cachedARINToken returns a copy of the currently-cached ARIN token, or
// nil if the cache is empty.
func (c *Capsulator) cachedARINToken() []byte {
	c.mu.Lock()
	defer c.mu.Unlock()
	if len(c.arinToken) == 0 {
		return nil
	}
	return append([]byte(nil), c.arinToken...)
}

// storeARINToken populates the cache if it is still empty and returns a
// copy of whatever is now canonical (which may be a token a racing
// caller stored first).
func (c *Capsulator) storeARINToken(fetched []byte) []byte {
	c.mu.Lock()
	defer c.mu.Unlock()
	if len(c.arinToken) == 0 {
		c.arinToken = append([]byte(nil), fetched...)
	}
	return append([]byte(nil), c.arinToken...)
}

// ensureARINStream starts the background ARIN subscription the first
// time a lease is established under ARIN, if ARIN is enabled. The
// subscription is per-token: when the Key Server rejects a token
// (ckapclient.ErrTokenRejected), this goroutine obtains a new one and
// starts a fresh Subscription. Transient stream failures are handled
// inside the Subscription via go-sse's retry loop.
func (c *Capsulator) ensureARINStream() {
	if c.cfg.DisableARIN || c.isARINUnsupported() {
		return
	}

	c.mu.Lock()
	if c.arinStarted || len(c.arinToken) == 0 {
		c.mu.Unlock()
		return
	}
	c.arinCtx, c.arinCancel = context.WithCancel(context.Background())
	c.arinDone = make(chan struct{})
	c.arinStarted = true
	c.mu.Unlock()

	go c.arinLoop()
}

// arinLoop drives per-token ARIN subscriptions for the lifetime of the
// capsulator. On token rejection it invalidates the cached token,
// re-fetches, and restarts; on any other permanent error it logs and
// backs off before retrying.
func (c *Capsulator) arinLoop() {
	defer close(c.arinDone)

	const (
		tokenFetchBackoff = time.Second
		permanentBackoff  = 5 * time.Second
	)

	for {
		if c.arinCtx.Err() != nil {
			return
		}

		token, err := c.ensureARINToken(c.arinCtx)
		if err != nil {
			if sleepCtx(c.arinCtx, tokenFetchBackoff) != nil {
				return
			}
			continue
		}
		if len(token) == 0 {
			// ARIN was marked unsupported mid-flight (e.g. after a
			// token rejection, the server stopped supporting it).
			// Exit cleanly; the capsulator continues without ARIN.
			return
		}

		sub := ckapclient.NewSubscription(c.client, ckapclient.SubscriptionOptions{
			Token: token,
			Handler: func(event cabe.ARINEvent) {
				if event.Event == cabe.ARINEventInvalidate && event.Data != "" {
					c.leaseMgr.InvalidateLeaseID(event.Data)
				}
			},
		})
		err = sub.Run(c.arinCtx)
		if c.arinCtx.Err() != nil {
			return
		}
		if errors.Is(err, ckapclient.ErrTokenRejected) {
			// Drop the stale token; next iteration fetches a fresh
			// one.
			c.resetARINToken()
			continue
		}
		// Unexpected permanent failure — back off to avoid hammering
		// the server, then try again from scratch.
		if sleepCtx(c.arinCtx, permanentBackoff) != nil {
			return
		}
	}
}

// resetARINToken clears the cached ARIN token so the next
// ensureARINToken call performs a fresh GetARINToken against the Key
// Server.
func (c *Capsulator) resetARINToken() {
	c.mu.Lock()
	c.arinToken = nil
	c.mu.Unlock()
}

// sleepCtx sleeps for d or until ctx is cancelled, whichever comes
// first. Returns ctx.Err() on cancellation, nil otherwise.
func sleepCtx(ctx context.Context, d time.Duration) error {
	if d <= 0 {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		return nil
	}
	timer := time.NewTimer(d)
	defer timer.Stop()
	select {
	case <-timer.C:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}
