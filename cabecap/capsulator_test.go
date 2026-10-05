package cabecap_test

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ldclabs/cose/key"
	"github.com/messier-42/cabe-go/attrset"
	"github.com/messier-42/cabe-go/cabe"
	"github.com/messier-42/cabe-go/cabecap"
	"github.com/messier-42/cabe-go/ckapclient"
	"github.com/messier-42/cabe-go/ckapraw"
)

const (
	testProjectAttribute  = "project"
	testBaseURL           = "https://example.com/ckap/"
	testProject           = "cabe"
	testBinaryContentType = "application/octet-stream"
	testTextContentType   = "text/plain"
	testContentTypeHeader = "Content-Type"
	pathProgradePath      = "/ckap/Prograde"
	pathARINTokenPath     = "/ckap/ARINToken"
	pathARINPath          = "/ckap/ARIN"
)

func mustSet(t *testing.T, m map[string]any) attrset.Set {
	t.Helper()
	s, err := attrset.New(m)
	if err != nil {
		t.Fatalf("attrset.New: %v", err)
	}
	return s
}

func TestCapsulatorManagedNonCaptive(t *testing.T) {
	var calls []string
	var retrogradeCalls int
	transport := roundTripFunc(func(r *http.Request) (*http.Response, error) {
		calls = append(calls, r.URL.Path)
		body, _ := io.ReadAll(r.Body)
		switch r.URL.Path {
		case pathProgradePath:
			var req ckapraw.ProgradeRequest
			if err := key.UnmarshalCBOR(body, &req); err != nil {
				t.Fatalf("UnmarshalCBOR() error = %v", err)
			}
			data, err := key.MarshalCBOR(ckapraw.ProgradeResponse{
				Kind: ckapraw.KindProgradeResponse,
				Lease: ckapraw.Lease{
					LeaseRef: []byte("lease-ref"),
					LKAI: ckapraw.LKAI{
						NonCaptive: &ckapraw.LKAINonCaptive{
							LeaseKey: ckapraw.COSEKey{
								1: 4, 3: 1,
								-1: []byte("0123456789abcdef"),
								5:  []byte("abcdefghijkl"),
							},
						},
					},
					Expiry: 4070908800,
				},
			})
			if err != nil {
				t.Fatalf("MarshalCBOR() error = %v", err)
			}
			return cborResponse(http.StatusOK, data), nil
		case "/ckap/Retrograde":
			retrogradeCalls++
			data, _ := key.MarshalCBOR(ckapraw.RetrogradeResponse{
				Kind: ckapraw.KindRetrogradeResponse,
				LKAI: ckapraw.LKAI{
					NonCaptive: &ckapraw.LKAINonCaptive{
						LeaseKey: ckapraw.COSEKey{
							1: 4, 3: 1,
							-1: []byte("0123456789abcdef"),
							5:  []byte("abcdefghijkl"),
						},
					},
				},
			})
			return cborResponse(http.StatusOK, data), nil
		default:
			t.Fatalf("unexpected path %s", r.URL.Path)
			return nil, nil
		}
	})

	client, err := ckapclient.NewClient(ckapclient.Config{
		BaseURL:    testBaseURL,
		HTTPClient: &http.Client{Transport: transport},
	})
	if err != nil {
		t.Fatalf("NewClient() error = %v", err)
	}
	c := cabecap.New(client, cabecap.WithARIN(false))
	defer c.Close()      // best effort
	defer client.Close() // best effort

	env, err := c.Encapsulate(context.Background(), cabe.Message{
		Payload:     []byte("hello cabe"),
		Attributes:  mustSet(t, map[string]any{testProjectAttribute: testProject}),
		ContentType: testBinaryContentType,
	})
	if err != nil {
		t.Fatalf("Encapsulate() error = %v", err)
	}
	msg, err := c.Decapsulate(context.Background(), env)
	if err != nil {
		t.Fatalf("Decapsulate() error = %v", err)
	}
	if !bytes.Equal(msg.Payload, []byte("hello cabe")) {
		t.Fatalf("payload = %q", msg.Payload)
	}
	if _, err := c.Decapsulate(context.Background(), env); err != nil {
		t.Fatalf("second Decapsulate() error = %v", err)
	}
	if retrogradeCalls != 0 {
		t.Fatalf("retrogradeCalls = %d, want 0 (cache should reuse)", retrogradeCalls)
	}
	if len(calls) != 1 {
		t.Fatalf("calls = %v, want only one Prograde", calls)
	}
}

func TestCapsulatorManagedCaptive(t *testing.T) {
	var assistedEnc, assistedDec bool
	transport := roundTripFunc(func(r *http.Request) (*http.Response, error) {
		body, _ := io.ReadAll(r.Body)
		switch r.URL.Path {
		case pathProgradePath:
			data, _ := key.MarshalCBOR(ckapraw.ProgradeResponse{
				Kind: ckapraw.KindProgradeResponse,
				Lease: ckapraw.Lease{
					LeaseRef: []byte("lease-ref"),
					LKAI:     ckapraw.LKAI{Captive: &ckapraw.LKAIActive{LeaseKeyAccessToken: []byte("lkat")}},
					Expiry:   4070908800,
				},
			})
			return cborResponse(http.StatusOK, data), nil
		case "/ckap/AssistedEncapsulate":
			assistedEnc = true
			var req ckapraw.AssistedEncapsulateRequest
			_ = key.UnmarshalCBOR(body, &req)
			data, _ := key.MarshalCBOR(ckapraw.AssistedEncapsulateResponse{
				Kind:       ckapraw.KindAssistedEncapsulateResponse,
				WrappedCEK: append([]byte("wrapped:"), req.CEK...),
			})
			return cborResponse(http.StatusOK, data), nil
		case "/ckap/AssistedDecapsulate":
			assistedDec = true
			var req ckapraw.AssistedDecapsulateRequest
			_ = key.UnmarshalCBOR(body, &req)
			data, _ := key.MarshalCBOR(ckapraw.AssistedDecapsulateResponse{
				Kind: ckapraw.KindAssistedDecapsulateResponse,
				CEK:  bytes.TrimPrefix(req.WrappedCEK, []byte("wrapped:")),
			})
			return cborResponse(http.StatusOK, data), nil
		default:
			t.Fatalf("unexpected path %s", r.URL.Path)
			return nil, nil
		}
	})

	c, err := cabecap.NewWithClient(ckapclient.Config{
		BaseURL:    testBaseURL,
		HTTPClient: &http.Client{Transport: transport},
	}, cabecap.WithARIN(false))
	if err != nil {
		t.Fatalf("NewWithClient() error = %v", err)
	}
	defer c.Close() // best effort

	env, err := c.Encapsulate(context.Background(), cabe.Message{
		Payload:     []byte("captive hello"),
		Attributes:  mustSet(t, map[string]any{"level": "secret"}),
		ContentType: testTextContentType,
	})
	if err != nil {
		t.Fatalf("Encapsulate() error = %v", err)
	}
	if !assistedEnc {
		t.Fatal("expected AssistedEncapsulate to be called")
	}
	msg, err := c.Decapsulate(context.Background(), env)
	if err != nil {
		t.Fatalf("Decapsulate() error = %v", err)
	}
	if !assistedDec {
		t.Fatal("expected AssistedDecapsulate to be called")
	}
	if !bytes.Equal(msg.Payload, []byte("captive hello")) {
		t.Fatalf("payload = %q", msg.Payload)
	}
}

func TestCapsulatorDecapsulateInvalidEnvelopeError(t *testing.T) {
	c, err := cabecap.NewWithClient(ckapclient.Config{
		BaseURL:    testBaseURL,
		HTTPClient: &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) { t.Fatal("should not be called"); return nil, nil })},
	})
	if err != nil {
		t.Fatalf("NewWithClient() error = %v", err)
	}
	defer c.Close() // best effort

	_, err = c.Decapsulate(context.Background(), []byte("not-cbor"))
	if err == nil {
		t.Fatal("expected error")
	}
	if !errors.Is(err, cabecap.ErrInvalidEnvelope) {
		t.Fatalf("error = %v, want cabecap.ErrInvalidEnvelope", err)
	}
}

func TestCapsulatorARINInvalidatesCache(t *testing.T) {
	var progradeCalls atomic.Int32
	streamDelivered := make(chan struct{}, 1)

	transport := roundTripFunc(func(r *http.Request) (*http.Response, error) {
		switch {
		case r.Method == http.MethodGet && r.URL.Path == pathARINTokenPath:
			data, _ := key.MarshalCBOR(map[string]any{"arinToken": []byte("arin-token")})
			return cborResponse(http.StatusOK, data), nil
		case r.Method == http.MethodGet && r.URL.Path == pathARINPath:
			select {
			case streamDelivered <- struct{}{}:
			default:
			}
			return &http.Response{
				StatusCode: http.StatusOK,
				Header:     http.Header{testContentTypeHeader: []string{"text/event-stream"}},
				Body:       io.NopCloser(strings.NewReader("id: 1\nevent: invalidate\ndata: lease-id-1\n\n")),
			}, nil
		case r.Method == http.MethodPost && r.URL.Path == pathProgradePath:
			progradeCalls.Add(1)
			data, _ := key.MarshalCBOR(ckapraw.ProgradeResponse{
				Kind: ckapraw.KindProgradeResponse,
				Lease: ckapraw.Lease{
					LeaseID:  "lease-id-1",
					LeaseRef: []byte("lease-ref"),
					LKAI: ckapraw.LKAI{
						NonCaptive: &ckapraw.LKAINonCaptive{
							LeaseKey: ckapraw.COSEKey{
								1: 4, 3: 1,
								-1: []byte("0123456789abcdef"),
								5:  []byte("abcdefghijkl"),
							},
						},
					},
					Expiry: 4070908800,
				},
			})
			return cborResponse(http.StatusOK, data), nil
		default:
			t.Fatalf("unexpected request %s %s", r.Method, r.URL.Path)
			return nil, nil
		}
	})

	c, err := cabecap.NewWithClient(ckapclient.Config{
		BaseURL:    testBaseURL,
		HTTPClient: &http.Client{Transport: transport},
	})
	if err != nil {
		t.Fatalf("NewWithClient() error = %v", err)
	}
	defer c.Close() // best effort

	if _, err := c.Encapsulate(context.Background(), cabe.Message{
		Payload:     []byte("hello"),
		Attributes:  mustSet(t, map[string]any{testProjectAttribute: testProject}),
		ContentType: testTextContentType,
	}); err != nil {
		t.Fatalf("Encapsulate() error = %v", err)
	}

	select {
	case <-streamDelivered:
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for ARIN stream delivery")
	}

	requireEventually(t, 2*time.Second, func() bool {
		_, err := c.Encapsulate(context.Background(), cabe.Message{
			Payload:     []byte("hello"),
			Attributes:  mustSet(t, map[string]any{testProjectAttribute: testProject}),
			ContentType: testTextContentType,
		})
		return err == nil && progradeCalls.Load() >= 2
	})
}

func TestCapsulatorARINRefreshesExpiredToken(t *testing.T) {
	var progradeCalls, tokenCalls, streamCalls atomic.Int32

	transport := roundTripFunc(func(r *http.Request) (*http.Response, error) {
		switch {
		case r.Method == http.MethodGet && r.URL.Path == pathARINTokenPath:
			n := tokenCalls.Add(1)
			token := "arin-token-1"
			if n > 1 {
				token = "arin-token-2"
			}
			data, _ := key.MarshalCBOR(map[string]any{"arinToken": []byte(token)})
			return cborResponse(http.StatusOK, data), nil
		case r.Method == http.MethodGet && r.URL.Path == pathARINPath:
			n := streamCalls.Add(1)
			token := r.URL.Query().Get("token")
			switch n {
			case 1:
				if token != "arin-token-1" {
					t.Fatalf("first stream token = %q", token)
				}
				data, _ := key.MarshalCBOR(ckapraw.Error{ErrorCode: 4401, Summary: "token expired"})
				return cborResponse(http.StatusUnauthorized, data), nil
			default:
				if token != "arin-token-2" {
					t.Fatalf("reconnect stream token = %q", token)
				}
				return &http.Response{
					StatusCode: http.StatusOK,
					Header:     http.Header{testContentTypeHeader: []string{"text/event-stream"}},
					Body:       io.NopCloser(strings.NewReader("id: 1\nevent: invalidate\ndata: lease-id-1\n\n")),
				}, nil
			}
		case r.Method == http.MethodPost && r.URL.Path == pathProgradePath:
			progradeCalls.Add(1)
			data, _ := key.MarshalCBOR(ckapraw.ProgradeResponse{
				Kind: ckapraw.KindProgradeResponse,
				Lease: ckapraw.Lease{
					LeaseID:  "lease-id-1",
					LeaseRef: []byte("lease-ref"),
					LKAI: ckapraw.LKAI{
						NonCaptive: &ckapraw.LKAINonCaptive{
							LeaseKey: ckapraw.COSEKey{
								1: 4, 3: 1,
								-1: []byte("0123456789abcdef"),
								5:  []byte("abcdefghijkl"),
							},
						},
					},
					Expiry: 4070908800,
				},
			})
			return cborResponse(http.StatusOK, data), nil
		default:
			t.Fatalf("unexpected request %s %s", r.Method, r.URL.Path)
			return nil, nil
		}
	})

	c, err := cabecap.NewWithClient(ckapclient.Config{
		BaseURL:    testBaseURL,
		HTTPClient: &http.Client{Transport: transport},
	})
	if err != nil {
		t.Fatalf("NewWithClient() error = %v", err)
	}
	defer c.Close() // best effort

	if _, err := c.Encapsulate(context.Background(), cabe.Message{
		Payload:     []byte("hello"),
		Attributes:  mustSet(t, map[string]any{testProjectAttribute: testProject}),
		ContentType: testBinaryContentType,
	}); err != nil {
		t.Fatalf("Encapsulate(first) error = %v", err)
	}

	requireEventually(t, 2*time.Second, func() bool {
		_, err := c.Encapsulate(context.Background(), cabe.Message{
			Payload:     []byte("hello"),
			Attributes:  mustSet(t, map[string]any{testProjectAttribute: testProject}),
			ContentType: testBinaryContentType,
		})
		return err == nil &&
			progradeCalls.Load() >= 2 &&
			tokenCalls.Load() >= 2 &&
			streamCalls.Load() >= 2
	})
}

func TestCapsulatorARINUnsupportedServerIsBestEffort(t *testing.T) {
	var tokenCalls, progradeCalls, streamCalls atomic.Int32

	transport := roundTripFunc(func(r *http.Request) (*http.Response, error) {
		switch {
		case r.Method == http.MethodGet && r.URL.Path == pathARINTokenPath:
			tokenCalls.Add(1)
			data, _ := key.MarshalCBOR(ckapraw.Error{
				ErrorCode: int(cabe.CodeUnsupported),
				Summary:   "ARIN not implemented",
			})
			return cborResponse(http.StatusNotImplemented, data), nil
		case r.Method == http.MethodGet && r.URL.Path == pathARINPath:
			streamCalls.Add(1)
			return cborResponse(http.StatusNotImplemented, nil), nil
		case r.Method == http.MethodPost && r.URL.Path == pathProgradePath:
			progradeCalls.Add(1)
			data, _ := key.MarshalCBOR(ckapraw.ProgradeResponse{
				Kind: ckapraw.KindProgradeResponse,
				Lease: ckapraw.Lease{
					LeaseRef: []byte("lease-ref"),
					LKAI: ckapraw.LKAI{
						NonCaptive: &ckapraw.LKAINonCaptive{
							LeaseKey: ckapraw.COSEKey{
								1: 4, 3: 1,
								-1: []byte("0123456789abcdef"),
								5:  []byte("abcdefghijkl"),
							},
						},
					},
					Expiry: 4070908800,
				},
			})
			return cborResponse(http.StatusOK, data), nil
		default:
			t.Fatalf("unexpected request %s %s", r.Method, r.URL.Path)
			return nil, nil
		}
	})

	c, err := cabecap.NewWithClient(ckapclient.Config{
		BaseURL:    testBaseURL,
		HTTPClient: &http.Client{Transport: transport},
	})
	if err != nil {
		t.Fatalf("NewWithClient() error = %v", err)
	}
	defer c.Close() // best effort

	if _, err := c.Encapsulate(context.Background(), cabe.Message{
		Payload:     []byte("hello"),
		Attributes:  mustSet(t, map[string]any{testProjectAttribute: testProject}),
		ContentType: testTextContentType,
	}); err != nil {
		t.Fatalf("Encapsulate() error = %v", err)
	}

	if tokenCalls.Load() != 1 {
		t.Fatalf("tokenCalls = %d, want 1", tokenCalls.Load())
	}
	if progradeCalls.Load() != 1 {
		t.Fatalf("progradeCalls = %d, want 1", progradeCalls.Load())
	}
	if streamCalls.Load() != 0 {
		t.Fatalf("streamCalls = %d, want 0 (unsupported server must not open a stream)", streamCalls.Load())
	}

	// A second Encapsulate must not re-query GetARINToken: the
	// unsupported state is sticky for the capsulator's lifetime.
	if _, err := c.Encapsulate(context.Background(), cabe.Message{
		Payload:     []byte("hello"),
		Attributes:  mustSet(t, map[string]any{testProjectAttribute: "cabe2"}),
		ContentType: testTextContentType,
	}); err != nil {
		t.Fatalf("Encapsulate() second error = %v", err)
	}
	if tokenCalls.Load() != 1 {
		t.Fatalf("tokenCalls after second call = %d, want 1 (state should be sticky)", tokenCalls.Load())
	}
}

func TestCapsulatorARINServerErrorPropagates(t *testing.T) {
	transport := roundTripFunc(func(r *http.Request) (*http.Response, error) {
		switch {
		case r.Method == http.MethodGet && r.URL.Path == pathARINTokenPath:
			data, _ := key.MarshalCBOR(ckapraw.Error{
				ErrorCode: int(cabe.CodeInternal),
				Summary:   "boom",
			})
			return cborResponse(http.StatusInternalServerError, data), nil
		default:
			t.Fatalf("unexpected request %s %s", r.Method, r.URL.Path)
			return nil, nil
		}
	})

	c, err := cabecap.NewWithClient(ckapclient.Config{
		BaseURL:    testBaseURL,
		HTTPClient: &http.Client{Transport: transport},
	})
	if err != nil {
		t.Fatalf("NewWithClient() error = %v", err)
	}
	defer c.Close() // best effort

	_, err = c.Encapsulate(context.Background(), cabe.Message{
		Payload:     []byte("hello"),
		Attributes:  mustSet(t, map[string]any{testProjectAttribute: testProject}),
		ContentType: testTextContentType,
	})
	if err == nil {
		t.Fatal("expected Encapsulate error when GetARINToken fails with a non-unsupported code")
	}
}

func TestCapsulatorCloseWithOwnedClient(t *testing.T) {
	c, err := cabecap.NewWithClient(ckapclient.Config{
		BaseURL:    testBaseURL,
		HTTPClient: &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) { return nil, errors.New("unused") })},
	})
	if err != nil {
		t.Fatalf("NewWithClient() error = %v", err)
	}
	if err := c.Close(); err != nil {
		t.Fatalf("Close() error = %v", err)
	}
	// Second close is idempotent.
	if err := c.Close(); err != nil {
		t.Fatalf("Close() second error = %v", err)
	}
}

// --- test helpers ---

func requireEventually(t *testing.T, timeout time.Duration, fn func() bool) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if fn() {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("condition did not become true")
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (fn roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return fn(r) }

func cborResponse(status int, data []byte) *http.Response {
	return &http.Response{
		StatusCode: status,
		Header:     http.Header{testContentTypeHeader: []string{"application/ckap+cbor"}},
		Body:       io.NopCloser(bytes.NewReader(data)),
	}
}
