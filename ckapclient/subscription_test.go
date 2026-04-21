package ckapclient_test

import (
	"context"
	"errors"
	"io"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/ldclabs/cose/key"
	"github.com/messier-42/cabe-go/cabe"
	"github.com/messier-42/cabe-go/ckap"
	"github.com/messier-42/cabe-go/ckapclient"
	"github.com/messier-42/cabe-go/ckapraw"
	"github.com/tmaxmax/go-sse"
)

// TestSubscriptionStreamsEventsAndClosesOnCancel verifies the happy
// path: a valid token yields events until the caller cancels.
func TestSubscriptionStreamsEventsAndClosesOnCancel(t *testing.T) {
	client, err := ckapclient.NewClient(ckapclient.Config{
		BaseURL: "https://example.com/ckap/",
		HTTPClient: &http.Client{
			Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
				if r.URL.Path != "/ckap/ARIN" {
					t.Fatalf("unexpected path %s", r.URL.Path)
				}
				if got := r.URL.Query().Get("token"); got != "tok" {
					t.Fatalf("token = %q", got)
				}
				return &http.Response{
					StatusCode: http.StatusOK,
					Header:     http.Header{"Content-Type": []string{"text/event-stream"}},
					Body:       io.NopCloser(strings.NewReader("id: 1\nevent: invalidate\ndata: l-1\n\n")),
				}, nil
			}),
		},
	})
	if err != nil {
		t.Fatalf("NewClient() error = %v", err)
	}
	defer client.Close() // best effort

	var mu sync.Mutex
	var events []cabe.ARINEvent
	ctx, cancel := context.WithCancel(context.Background())
	sub := ckapclient.NewSubscription(client, ckapclient.SubscriptionOptions{
		Token: []byte("tok"),
		// Use a single-shot retry budget so the test finishes once
		// the mock server's one response is consumed, rather than
		// looping against an exhausted server.
		Backoff: sse.Backoff{MaxRetries: -1},
		Handler: func(e cabe.ARINEvent) {
			mu.Lock()
			events = append(events, e)
			mu.Unlock()
			cancel()
		},
	})
	err = sub.Run(ctx)
	if err != nil && !errors.Is(err, context.Canceled) {
		t.Fatalf("Run() error = %v", err)
	}
	mu.Lock()
	if len(events) == 0 {
		t.Fatal("no events received")
	}
	mu.Unlock()
}

// TestSubscriptionReturnsErrTokenRejected verifies that a non-2xx
// response from the ARIN endpoint causes Run to return an error
// satisfying errors.Is(err, ErrTokenRejected). The underlying
// *ckap.Error survives via errors.As for structured inspection.
func TestSubscriptionReturnsErrTokenRejected(t *testing.T) {
	var arinCalls atomic.Int32
	client, err := ckapclient.NewClient(ckapclient.Config{
		BaseURL: "https://example.com/ckap/",
		HTTPClient: &http.Client{
			Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
				if r.URL.Path == "/ckap/ARINToken" {
					t.Fatalf("Subscription must not fetch tokens on its own")
				}
				if r.URL.Path != "/ckap/ARIN" {
					t.Fatalf("unexpected path %s", r.URL.Path)
				}
				arinCalls.Add(1)
				data, _ := key.MarshalCBOR(ckapraw.Error{
					ErrorCode: 3, // CodePolicyDenied
					Summary:   "token expired",
				})
				return cborResponse(http.StatusUnauthorized, data), nil
			}),
		},
	})
	if err != nil {
		t.Fatalf("NewClient() error = %v", err)
	}
	defer client.Close() // best effort

	sub := ckapclient.NewSubscription(client, ckapclient.SubscriptionOptions{
		Token: []byte("bad-token"),
		// MaxRetries = -1 so the test doesn't spin: the library
		// exits on the first ResponseValidator rejection and we
		// get back ErrTokenRejected promptly.
		Backoff: sse.Backoff{MaxRetries: -1},
	})
	err = sub.Run(context.Background())
	if err == nil {
		t.Fatal("expected error")
	}
	if !errors.Is(err, ckapclient.ErrTokenRejected) {
		t.Fatalf("errors.Is(err, ErrTokenRejected) = false; err = %v", err)
	}
	var ckapErr *ckap.Error
	if !errors.As(err, &ckapErr) {
		t.Fatalf("errors.As(err, *ckap.Error) = false; err = %v (%T)", err, err)
	}
	if ckapErr.Code != cabe.CodePolicyDenied {
		t.Fatalf("Code = %d, want CodePolicyDenied", ckapErr.Code)
	}
	if ckapErr.Summary != "token expired" {
		t.Fatalf("Summary = %q", ckapErr.Summary)
	}
	if got := arinCalls.Load(); got != 1 {
		t.Fatalf("arinCalls = %d, want 1 (no retry on ResponseValidator rejection)", got)
	}
}

// TestSubscriptionRejectsEmptyToken verifies Run fails fast when the
// caller forgot to supply a token.
func TestSubscriptionRejectsEmptyToken(t *testing.T) {
	client, err := ckapclient.NewClient(ckapclient.Config{
		BaseURL: "https://example.com/ckap/",
		HTTPClient: &http.Client{
			Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
				t.Fatal("HTTP layer should not be contacted for an empty token")
				return nil, nil
			}),
		},
	})
	if err != nil {
		t.Fatalf("NewClient() error = %v", err)
	}
	defer client.Close() // best effort

	sub := ckapclient.NewSubscription(client, ckapclient.SubscriptionOptions{})
	if err := sub.Run(context.Background()); err == nil {
		t.Fatal("expected error for missing token")
	}
}
