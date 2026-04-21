package ckapclient_test

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/ldclabs/cose/key"
	"github.com/messier-42/cabe-go/attrset"
	"github.com/messier-42/cabe-go/cabe"
	"github.com/messier-42/cabe-go/ckap"
	"github.com/messier-42/cabe-go/ckapclient"
	"github.com/messier-42/cabe-go/ckapraw"
)

func mustSet(t *testing.T, m map[string]any) attrset.Set {
	t.Helper()
	s, err := attrset.New(m)
	if err != nil {
		t.Fatalf("attrset.New: %v", err)
	}
	return s
}

func TestNewClientRejectsEmptyBaseURL(t *testing.T) {
	_, err := ckapclient.NewClient(ckapclient.Config{})
	if err == nil {
		t.Fatal("expected error")
	}
}

func TestClientGetSelf(t *testing.T) {
	client, err := ckapclient.NewClient(ckapclient.Config{
		BaseURL: "https://example.com/ckap/",
		HTTPClient: &http.Client{
			Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
				if r.URL.Path != "/ckap/GetSelf" {
					t.Fatalf("unexpected path %s", r.URL.Path)
				}
				data, err := key.MarshalCBOR(ckapraw.GetSelfResponse{
					Kind: "GetSelfResponse",
					Principal: ckapraw.Principal{
						URI:    "principal:test",
						Claims: map[string]any{"role": "operator"},
					},
					ServerInfo: map[string]any{"name": "test-ks"},
				})
				if err != nil {
					t.Fatalf("MarshalCBOR() error = %v", err)
				}
				return cborResponse(http.StatusOK, data), nil
			}),
		},
	})
	if err != nil {
		t.Fatalf("NewClient() error = %v", err)
	}
	defer client.Close() // best effort

	resp, err := client.GetSelf(context.Background(), ckap.GetSelfRequest{})
	if err != nil {
		t.Fatalf("GetSelf() error = %v", err)
	}
	if resp.PrincipalInfo.URI != "principal:test" {
		t.Fatalf("URI = %q", resp.PrincipalInfo.URI)
	}
	if resp.PrincipalInfo.Claims["role"] != "operator" {
		t.Fatalf("Claims = %v", resp.PrincipalInfo.Claims)
	}
}

func TestClientProgradeReturnsLease(t *testing.T) {
	client, err := ckapclient.NewClient(ckapclient.Config{
		BaseURL: "https://example.com/ckap/",
		HTTPClient: &http.Client{
			Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
				if r.URL.Path != "/ckap/Prograde" {
					t.Fatalf("unexpected path %s", r.URL.Path)
				}
				body, _ := io.ReadAll(r.Body)
				var req ckapraw.ProgradeRequest
				if err := key.UnmarshalCBOR(body, &req); err != nil {
					t.Fatalf("UnmarshalCBOR() error = %v", err)
				}
				if len(req.ARINToken) != 0 {
					t.Fatalf("unexpected ARIN token on Prograde: %x", req.ARINToken)
				}
				data, err := key.MarshalCBOR(ckapraw.ProgradeResponse{
					Kind: "ProgradeResponse",
					Lease: ckapraw.Lease{
						LeaseID:  "l-1",
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
			}),
		},
	})
	if err != nil {
		t.Fatalf("NewClient() error = %v", err)
	}
	defer client.Close() // best effort

	resp, err := client.Prograde(context.Background(), ckap.ProgradeRequest{
		AttributeSet: mustSet(t, map[string]any{"project": "cabe"}),
	})
	if err != nil {
		t.Fatalf("Prograde() error = %v", err)
	}
	if resp.Lease.LeaseID != "l-1" {
		t.Fatalf("LeaseID = %q", resp.Lease.LeaseID)
	}
	if !bytes.Equal(resp.Lease.LeaseRef, []byte("lease-ref")) {
		t.Fatalf("LeaseRef = %q", resp.Lease.LeaseRef)
	}
	if resp.Lease.LKAI.NonCaptive == nil || len(resp.Lease.LKAI.NonCaptive.RawCOSEKey) == 0 {
		t.Fatal("expected non-captive LKAI with COSE_Key bytes")
	}
	if resp.Lease.Expiry.IsZero() {
		t.Fatal("Expiry not set")
	}
}

func TestClientProgradeAttachesARINToken(t *testing.T) {
	var gotToken []byte
	client, err := ckapclient.NewClient(ckapclient.Config{
		BaseURL: "https://example.com/ckap/",
		HTTPClient: &http.Client{
			Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
				body, _ := io.ReadAll(r.Body)
				var req ckapraw.ProgradeRequest
				if err := key.UnmarshalCBOR(body, &req); err != nil {
					t.Fatalf("UnmarshalCBOR() error = %v", err)
				}
				gotToken = append([]byte(nil), req.ARINToken...)
				data, _ := key.MarshalCBOR(ckapraw.ProgradeResponse{
					Kind: "ProgradeResponse",
					Lease: ckapraw.Lease{
						LeaseRef: []byte("ref"),
						LKAI:     ckapraw.LKAI{Captive: &ckapraw.LKAIActive{LeaseKeyAccessToken: []byte("lkat")}},
						Expiry:   4070908800,
					},
				})
				return cborResponse(http.StatusOK, data), nil
			}),
		},
	})
	if err != nil {
		t.Fatalf("NewClient() error = %v", err)
	}
	defer client.Close() // best effort

	if _, err := client.Prograde(context.Background(), ckap.ProgradeRequest{
		AttributeSet: mustSet(t, map[string]any{"project": "cabe"}),
		ARINToken:    []byte("arin-tok"),
	}); err != nil {
		t.Fatalf("Prograde() error = %v", err)
	}
	if !bytes.Equal(gotToken, []byte("arin-tok")) {
		t.Fatalf("token = %q", gotToken)
	}
}

func TestClientRetrogradeReturnsLKAI(t *testing.T) {
	client, err := ckapclient.NewClient(ckapclient.Config{
		BaseURL: "https://example.com/ckap/",
		HTTPClient: &http.Client{
			Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
				if r.URL.Path != "/ckap/Retrograde" {
					t.Fatalf("unexpected path %s", r.URL.Path)
				}
				data, _ := key.MarshalCBOR(ckapraw.RetrogradeResponse{
					Kind: "RetrogradeResponse",
					LKAI: ckapraw.LKAI{Captive: &ckapraw.LKAIActive{LeaseKeyAccessToken: []byte("lkat")}},
				})
				return cborResponse(http.StatusOK, data), nil
			}),
		},
	})
	if err != nil {
		t.Fatalf("NewClient() error = %v", err)
	}
	defer client.Close() // best effort

	resp, err := client.Retrograde(context.Background(), ckap.RetrogradeRequest{
		AttributeSet: mustSet(t, map[string]any{"p": "x"}),
		LeaseRef:     []byte("ref"),
	})
	if err != nil {
		t.Fatalf("Retrograde() error = %v", err)
	}
	if resp.LKAI.Captive == nil || !bytes.Equal(resp.LKAI.Captive.LKAT, []byte("lkat")) {
		t.Fatalf("LKAI = %+v", resp.LKAI)
	}
}

func TestClientAssistedEncapDecap(t *testing.T) {
	client, err := ckapclient.NewClient(ckapclient.Config{
		BaseURL: "https://example.com/ckap/",
		HTTPClient: &http.Client{
			Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
				body, _ := io.ReadAll(r.Body)
				switch r.URL.Path {
				case "/ckap/AssistedEncapsulate":
					var req ckapraw.AssistedEncapsulateRequest
					_ = key.UnmarshalCBOR(body, &req)
					data, _ := key.MarshalCBOR(ckapraw.AssistedEncapsulateResponse{
						Kind:       "AssistedEncapsulateResponse",
						WrappedCEK: append([]byte("wrapped:"), req.CEK...),
					})
					return cborResponse(http.StatusOK, data), nil
				case "/ckap/AssistedDecapsulate":
					var req ckapraw.AssistedDecapsulateRequest
					_ = key.UnmarshalCBOR(body, &req)
					data, _ := key.MarshalCBOR(ckapraw.AssistedDecapsulateResponse{
						Kind: "AssistedDecapsulateResponse",
						CEK:  bytes.TrimPrefix(req.WrappedCEK, []byte("wrapped:")),
					})
					return cborResponse(http.StatusOK, data), nil
				default:
					t.Fatalf("unexpected path %s", r.URL.Path)
					return nil, nil
				}
			}),
		},
	})
	if err != nil {
		t.Fatalf("NewClient() error = %v", err)
	}
	defer client.Close() // best effort

	encResp, err := client.AssistedEncapsulate(context.Background(), ckap.AssistedEncapsulateRequest{
		LKAT: []byte("lkat"),
		CEK:  []byte("rawcek"),
	})
	if err != nil {
		t.Fatalf("AssistedEncapsulate() error = %v", err)
	}
	decResp, err := client.AssistedDecapsulate(context.Background(), ckap.AssistedDecapsulateRequest{
		LKAT:       []byte("lkat"),
		WrappedCEK: encResp.WrappedCEK,
	})
	if err != nil {
		t.Fatalf("AssistedDecapsulate() error = %v", err)
	}
	if !bytes.Equal(decResp.CEK, []byte("rawcek")) {
		t.Fatalf("cek = %q", decResp.CEK)
	}
}

func TestClientServerErrorSurfacesAsCabeError(t *testing.T) {
	client, err := ckapclient.NewClient(ckapclient.Config{
		BaseURL: "https://example.com/ckap/",
		HTTPClient: &http.Client{
			Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
				data, _ := key.MarshalCBOR(ckapraw.Error{ErrorCode: 3, Summary: "denied"})
				return cborResponse(http.StatusForbidden, data), nil
			}),
		},
	})
	if err != nil {
		t.Fatalf("NewClient() error = %v", err)
	}
	defer client.Close() // best effort

	_, err = client.Prograde(context.Background(), ckap.ProgradeRequest{
		AttributeSet: mustSet(t, map[string]any{"p": "x"}),
	})
	if err == nil {
		t.Fatal("expected error")
	}
	var opErr *ckap.Error
	if !errors.As(err, &opErr) {
		t.Fatalf("error type = %T", err)
	}
	if opErr.Op != "Prograde" {
		t.Fatalf("Op = %q", opErr.Op)
	}
	if opErr.Code != cabe.CodePolicyDenied {
		t.Fatalf("Code = %d, want CodePolicyDenied", opErr.Code)
	}
	if opErr.Summary != "denied" {
		t.Fatalf("Summary = %q", opErr.Summary)
	}
}

func TestClientCloseCancelsInFlight(t *testing.T) {
	started := make(chan struct{})
	client, err := ckapclient.NewClient(ckapclient.Config{
		BaseURL: "https://example.com/ckap/",
		HTTPClient: &http.Client{
			Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
				close(started)
				<-r.Context().Done()
				return nil, r.Context().Err()
			}),
		},
	})
	if err != nil {
		t.Fatalf("NewClient() error = %v", err)
	}

	done := make(chan error, 1)
	go func() {
		_, err := client.GetSelf(context.Background(), ckap.GetSelfRequest{})
		done <- err
	}()
	<-started
	if err := client.Close(); err != nil {
		t.Fatalf("Close() error = %v", err)
	}
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("expected error from in-flight request after Close")
		}
	case <-time.After(time.Second):
		t.Fatal("in-flight request did not abort after Close")
	}
}

func TestClientRejectsWrongResponseKind(t *testing.T) {
	client, err := ckapclient.NewClient(ckapclient.Config{
		BaseURL: "https://example.com/ckap/",
		HTTPClient: &http.Client{
			Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
				// Intentionally return a mis-labeled response.
				data, _ := key.MarshalCBOR(ckapraw.GetSelfResponse{
					Kind: "NotTheRightKind",
					Principal: ckapraw.Principal{
						URI: "principal:test",
					},
				})
				return cborResponse(http.StatusOK, data), nil
			}),
		},
	})
	if err != nil {
		t.Fatalf("NewClient() error = %v", err)
	}
	defer client.Close() // best effort

	_, err = client.GetSelf(context.Background(), ckap.GetSelfRequest{})
	if err == nil {
		t.Fatal("expected error on wrong response kind")
	}
	var opErr *ckap.Error
	if !errors.As(err, &opErr) {
		t.Fatalf("error type = %T", err)
	}
	if opErr.Op != "GetSelf" {
		t.Fatalf("Op = %q", opErr.Op)
	}
	if !strings.Contains(opErr.Summary, "NotTheRightKind") {
		t.Fatalf("Summary = %q, want it to mention the bad kind", opErr.Summary)
	}
}

func TestClientRejectsOversizedResponse(t *testing.T) {
	// The transport caps response bodies at 1 MiB. Return 2 MiB of
	// zeroes to trip the limit. The actual bytes don't need to be
	// valid CBOR — the size check fires before decoding.
	big := bytes.Repeat([]byte{0x00}, 2<<20)
	client, err := ckapclient.NewClient(ckapclient.Config{
		BaseURL: "https://example.com/ckap/",
		HTTPClient: &http.Client{
			Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
				return &http.Response{
					StatusCode:    http.StatusOK,
					Header:        http.Header{"Content-Type": []string{"application/ckap+cbor"}},
					Body:          io.NopCloser(bytes.NewReader(big)),
					ContentLength: int64(len(big)),
				}, nil
			}),
		},
	})
	if err != nil {
		t.Fatalf("NewClient() error = %v", err)
	}
	defer client.Close() // best effort

	_, err = client.GetSelf(context.Background(), ckap.GetSelfRequest{})
	if err == nil {
		t.Fatal("expected error on oversized response")
	}
	if !strings.Contains(err.Error(), "exceeds") {
		t.Fatalf("error = %v, want size-limit message", err)
	}
}

func TestClientGetARINToken(t *testing.T) {
	client, err := ckapclient.NewClient(ckapclient.Config{
		BaseURL: "https://example.com/ckap/",
		HTTPClient: &http.Client{
			Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
				data, _ := key.MarshalCBOR(map[string]any{"arinToken": []byte("tok")})
				return cborResponse(http.StatusOK, data), nil
			}),
		},
	})
	if err != nil {
		t.Fatalf("NewClient() error = %v", err)
	}
	defer client.Close() // best effort

	resp, err := client.GetARINToken(context.Background(), ckap.GetARINTokenRequest{})
	if err != nil {
		t.Fatalf("GetARINToken() error = %v", err)
	}
	if !bytes.Equal(resp.Token, []byte("tok")) {
		t.Fatalf("token = %q", resp.Token)
	}
}

func TestClientDefaultUserAgent(t *testing.T) {
	var gotUA string
	client, err := ckapclient.NewClient(ckapclient.Config{
		BaseURL: "https://example.com/ckap/",
		HTTPClient: &http.Client{
			Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
				gotUA = r.Header.Get("User-Agent")
				data, _ := key.MarshalCBOR(ckapraw.GetSelfResponse{
					Kind:      "GetSelfResponse",
					Principal: ckapraw.Principal{URI: "p:x"},
				})
				return cborResponse(http.StatusOK, data), nil
			}),
		},
	})
	if err != nil {
		t.Fatalf("NewClient() error = %v", err)
	}
	defer client.Close() // best effort

	if _, err := client.GetSelf(context.Background(), ckap.GetSelfRequest{}); err != nil {
		t.Fatalf("GetSelf() error = %v", err)
	}
	if !strings.HasPrefix(gotUA, "cabe-go go/") {
		t.Fatalf("User-Agent = %q, want prefix %q", gotUA, "cabe-go go/")
	}
	// Sanity: the Config accessor reports the same string actually
	// sent on the wire.
	if client.Config().UserAgent != gotUA {
		t.Fatalf("Config().UserAgent = %q, sent = %q", client.Config().UserAgent, gotUA)
	}
}

func TestClientCustomUserAgent(t *testing.T) {
	var gotUA string
	client, err := ckapclient.NewClient(ckapclient.Config{
		BaseURL:   "https://example.com/ckap/",
		UserAgent: "cabetool/0.1",
		HTTPClient: &http.Client{
			Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
				gotUA = r.Header.Get("User-Agent")
				data, _ := key.MarshalCBOR(ckapraw.GetSelfResponse{
					Kind:      "GetSelfResponse",
					Principal: ckapraw.Principal{URI: "p:x"},
				})
				return cborResponse(http.StatusOK, data), nil
			}),
		},
	})
	if err != nil {
		t.Fatalf("NewClient() error = %v", err)
	}
	defer client.Close() // best effort

	if _, err := client.GetSelf(context.Background(), ckap.GetSelfRequest{}); err != nil {
		t.Fatalf("GetSelf() error = %v", err)
	}
	if !strings.HasPrefix(gotUA, "cabetool/0.1 cabe-go go/") {
		t.Fatalf("User-Agent = %q, want prefix %q", gotUA, "cabetool/0.1 cabe-go go/")
	}
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (fn roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) {
	return fn(r)
}

func cborResponse(status int, data []byte) *http.Response {
	return &http.Response{
		StatusCode: status,
		Header:     http.Header{"Content-Type": []string{"application/ckap+cbor"}},
		Body:       io.NopCloser(bytes.NewReader(data)),
	}
}
