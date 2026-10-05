package ckapclient

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"

	"github.com/messier-42/cabe-go/cabe"
	"github.com/messier-42/cabe-go/ckap"
	"github.com/tmaxmax/go-sse"
)

// ErrTokenRejected sentinels a Subscription terminating because the Key
// Server rejected the configured ARIN token (typically a non-2xx
// response from the ARIN endpoint indicating the token has expired or
// been revoked). Use errors.Is on a Subscription.Run return value to
// detect this condition and respond by obtaining a fresh token via
// GetARINToken and starting a new Subscription.
//
// The underlying *ckap.Error carrying the server's Code, Summary, and
// Details is preserved via errors.Unwrap; ErrTokenRejected merely
// identifies the broad category.
var ErrTokenRejected = errors.New("ckapclient: ARIN token rejected by key server")

// SubscriptionOptions controls the behaviour of a Subscription.
type SubscriptionOptions struct {
	// Token is the ARIN token to attach to the stream request. It must
	// be non-nil; the Subscription does not fetch tokens on its own.
	Token []byte

	// Handler is invoked synchronously for every received ARIN event.
	// A nil handler is allowed and discards events.
	Handler func(cabe.ARINEvent)

	// Backoff controls the reconnection policy for transient SSE-stream
	// failures (connection reset, EOF without a terminal error, etc.).
	// It is forwarded directly to go-sse's Client. The zero value
	// selects the library's defaults: 500ms initial interval, 1.5x
	// multiplier, 0.5 jitter, unbounded retries. A server Retry-After
	// value received over the stream is honoured via the library's
	// retry-field handling. Set MaxRetries or MaxElapsedTime to bound
	// how long Run will keep reconnecting on transient failures.
	Backoff sse.Backoff
}

// Subscription is a per-token ARIN stream primitive. It opens an ARIN
// stream with the configured token, delivers events to a handler, and
// reconnects automatically on transient failures using the go-sse
// library's policy (Last-Event-ID preservation, exponential backoff
// with jitter, server-advertised Retry-After).
//
// Subscription does not fetch tokens. If the Key Server rejects the
// configured token, Run returns an error satisfying errors.Is(err,
// ErrTokenRejected); the caller is responsible for obtaining a fresh
// token and starting a new Subscription. The cabecap package
// demonstrates the pattern.
type Subscription struct {
	client *Client
	opts   SubscriptionOptions
}

// NewSubscription constructs a Subscription. The subscription does not
// start until Run is called. NewSubscription does not validate the
// token; an empty token yields an error from Run.
func NewSubscription(client *Client, opts SubscriptionOptions) *Subscription {
	return &Subscription{client: client, opts: opts}
}

// Run opens the ARIN stream and blocks until the context is cancelled,
// the Key Server rejects the token, the library's retry budget is
// exhausted, or an unrecoverable error occurs.
//
// Returns:
//
//   - ctx.Err() on cancellation or client close;
//   - an error satisfying errors.Is(err, ErrTokenRejected) when the
//     server returned a non-2xx response on the ARIN endpoint;
//   - a *ckap.Error otherwise (transport failure, retry budget
//     exhausted, malformed response).
func (s *Subscription) Run(ctx context.Context) error {
	if len(s.opts.Token) == 0 {
		return newClientError(opARIN, cabe.CodeReserved, 0,
			"Subscription.Run: Token is required", nil)
	}
	return s.client.withCtx(ctx, s.run)
}

func (s *Subscription) run(ctx context.Context) error {
	u, err := url.Parse(s.client.cfg.BaseURL + opARIN)
	if err != nil {
		return fmt.Errorf("build %s url: %w", opARIN, err)
	}
	q := u.Query()
	q.Set("token", string(s.opts.Token))
	u.RawQuery = q.Encode()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), http.NoBody)
	if err != nil {
		return fmt.Errorf("build %s request: %w", opARIN, err)
	}
	req.Header.Set("Accept", contentTypeEventStream)
	req.Header.Set("User-Agent", s.client.cfg.UserAgent)

	sseClient := &sse.Client{
		HTTPClient: s.client.cfg.HTTPClient,
		Backoff:    s.opts.Backoff,
		ResponseValidator: func(resp *http.Response) error {
			if resp.StatusCode == http.StatusOK {
				return nil
			}
			body, _ := readLimitedBody(resp.Body)
			// Wrap decodeServerError's result so the caller can
			// distinguish token-rejection via errors.Is while still
			// retrieving the structured *ckap.Error via errors.As.
			return &tokenRejectionError{inner: decodeServerError(opARIN, resp.StatusCode, body)}
		},
	}

	conn := sseClient.NewConnection(req)
	conn.SubscribeToAll(func(ev sse.Event) {
		if s.opts.Handler == nil {
			return
		}
		s.opts.Handler(cabe.ARINEvent{
			Event: cabe.ARINEventType(ev.Type),
			ID:    ev.LastEventID,
			Data:  ev.Data,
		})
	})

	err = conn.Connect()
	if err == nil || errors.Is(err, io.EOF) {
		return nil
	}
	if ctx.Err() != nil {
		return ctx.Err()
	}

	// Token rejections propagate as-is so callers can errors.Is
	// against ErrTokenRejected.
	if rej, ok := errors.AsType[*tokenRejectionError](err); ok {
		return rej
	}
	// Any remaining *ckap.Error flows through unchanged; anything
	// else (ConnectionError with a non-cabe underlying cause, e.g.
	// DNS failure after retry budget exhaustion) gets wrapped.
	if cabeErr, ok := errors.AsType[*ckap.Error](err); ok {
		return cabeErr
	}
	return newClientError(opARIN, cabe.CodeReserved, 0, "", err)
}

// tokenRejectionError wraps a server-side *ckap.Error produced by the ARIN
// ResponseValidator so that errors.Is matches ErrTokenRejected while
// errors.As still retrieves the underlying *ckap.Error for structured
// inspection.
type tokenRejectionError struct {
	inner error
}

func (t *tokenRejectionError) Error() string {
	if t.inner == nil {
		return ErrTokenRejected.Error()
	}
	return t.inner.Error()
}

func (t *tokenRejectionError) Unwrap() error { return t.inner }

func (t *tokenRejectionError) Is(target error) bool {
	return target == ErrTokenRejected
}
