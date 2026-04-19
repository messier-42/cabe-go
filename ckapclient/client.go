package ckapclient

import (
	"context"
	"errors"
	"net/http"
	"runtime"
	"strings"
	"sync"
	"time"
)

// Client is a direct CKAP protocol client. Each method maps 1:1 to a CKAP
// operation. There is no caching or retry functionality implemented in this
// package.
//
// Client is concurrency-safe; multiple goroutines may initiate operations
// in parallel using the same Client.
type Client struct {
	// cfg holds a normalised copy of the Config used to construct the
	// client.
	cfg Config

	// reconnectBackoff applies to the streaming ARIN path when the
	// connection terminates cleanly but the context has not been
	// cancelled. It is not user visible at this time.
	reconnectBackoff time.Duration

	// sleep is the function used to implement reconnectBackoff. Tests
	// substitute a no-op.
	sleep func(time.Duration)

	closeCtx    context.Context //nolint:containedctx // lifecycle ctx for background subscriptions, cancelled from Close
	closeCancel context.CancelFunc
	closeOnce   sync.Once
}

// NewClient creates a Client from the given Config.
func NewClient(cfg Config) (*Client, error) {
	if err := normaliseConfig(&cfg); err != nil {
		return nil, err
	}

	closeCtx, closeCancel := context.WithCancel(context.Background())
	return &Client{
		cfg:              cfg,
		reconnectBackoff: 1 * time.Second,
		sleep:            time.Sleep,
		closeCtx:         closeCtx,
		closeCancel:      closeCancel,
	}, nil
}

// normaliseConfig validates cfg and fills in defaults in place. On
// return, cfg.BaseURL has a trailing slash, cfg.HTTPClient is non-nil,
// and cfg.UserAgent holds the fully composed User-Agent string that
// will be sent on every request.
func normaliseConfig(cfg *Config) error {
	if strings.TrimSpace(cfg.BaseURL) == "" {
		return errors.New("ckapclient: Config.BaseURL is required")
	}
	cfg.BaseURL = strings.TrimRight(cfg.BaseURL, "/") + "/"

	if cfg.HTTPClient == nil {
		cfg.HTTPClient = http.DefaultClient
	}

	def := defaultUserAgent()
	if cfg.UserAgent == "" {
		cfg.UserAgent = def
	} else {
		cfg.UserAgent = cfg.UserAgent + " " + def
	}

	return nil
}

// defaultUserAgent is the baseline User-Agent string this package
// appends to (or uses verbatim as) outgoing request headers.
//
//	cabe-go go/<goversion> <goos>/<goarch>
//
// e.g. "cabe-go go/1.24.4 linux/amd64". runtime.Version() returns
// values like "go1.24.4" and we trim the redundant leading "go" to
// avoid doubling it in the final string.
func defaultUserAgent() string {
	return "cabe-go go/" + strings.TrimPrefix(runtime.Version(), "go") + " " + runtime.GOOS + "/" + runtime.GOARCH
}

// Config returns a copy of the Config used to construct the client.
// Fields reflect the normalised values the client actually uses.
func (c *Client) Config() Config { return c.cfg }

// Close implements [io.Closer]. It is idempotent and concurrency-safe.
//
// Calling Close aborts any in-flight CKAP requests, causing those calls
// to return immediately. Attempting to invoke CKAP operations on a Client
// after this method has been called results in an error.
func (c *Client) Close() error {
	c.closeOnce.Do(c.closeCancel)
	return nil
}

// withCtx runs fn with a context that is cancelled when either the
// caller-supplied ctx or the client's close context is cancelled.
// Cleanup of the helper goroutine is handled here so callers cannot leak
// it by forgetting a deferred cancel.
func (c *Client) withCtx(ctx context.Context, fn func(context.Context) error) error {
	merged, cancel := context.WithCancel(ctx)
	done := make(chan struct{})
	go func() {
		select {
		case <-c.closeCtx.Done():
			cancel()
		case <-done:
		}
	}()
	defer func() {
		cancel()
		close(done)
	}()
	return fn(merged)
}
