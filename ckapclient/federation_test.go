package ckapclient_test

import (
	"bytes"
	"io"
	"net/http"
	"reflect"
	"testing"

	"github.com/ldclabs/cose/key"
	"github.com/messier-42/cabe-go/cabe"
	"github.com/messier-42/cabe-go/ckap"
	"github.com/messier-42/cabe-go/ckapclient"
	"github.com/messier-42/cabe-go/ckapraw"
)

const (
	domainIDField  = "domainID"
	kindField      = "kind"
	publicKeyField = "publicKey"
	statusField    = "status"
	keysField      = "keys"
)

func TestClientFederationIdentity(t *testing.T) {
	for _, status := range []string{"current", "future", "retired"} {
		t.Run(status, func(t *testing.T) {
			advertised := key.Key{1: 2, 2: []byte("fkid"), 3: -31, -1: 1, -2: []byte("public-x"), -3: []byte("public-y")}
			client, err := ckapclient.NewClient(ckapclient.Config{BaseURL: "https://example.com/ckap", HTTPClient: &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
				if r.Method != http.MethodGet || r.URL.Path != "/ckap/FederationIdentity" || r.Header.Get("Accept") != ckap.MediaType {
					t.Fatalf("unexpected request: %s %s %v", r.Method, r.URL, r.Header)
				}
				body := key.MustMarshalCBOR(ckapraw.FederationIdentity{Kind: ckapraw.KindFederationIdentity, DomainID: "domain", Keys: []ckapraw.FederationPublicKey{{PublicKey: advertised, Status: status}}})
				resp := cborResponse(http.StatusOK, body)
				resp.Header.Set("Cache-Control", "max-age=60")
				resp.Header.Set("Expires", "Mon, 28 Sep 2026 12:00:00 GMT")
				return resp, nil
			})}})
			if err != nil {
				t.Fatal(err)
			}
			defer client.Close() // best effort
			got, err := client.FederationIdentity(t.Context(), ckap.FederationIdentityRequest{})
			if err != nil {
				t.Fatal(err)
			}
			if got.Identity.DomainID != "domain" || len(got.Identity.Keys) != 1 || got.Identity.Keys[0].Status != status || !bytes.Equal(got.Identity.Keys[0].RawCOSEKey, key.MustMarshalCBOR(advertised)) {
				t.Fatalf("identity lost: %#v", got)
			}
			if got.CacheControl != "max-age=60" || got.Expires != "Mon, 28 Sep 2026 12:00:00 GMT" {
				t.Fatalf("cache headers lost: %#v", got)
			}
		})
	}
}

func TestClientFederationIdentityInvalid(t *testing.T) {
	for _, body := range []any{
		map[string]any{kindField: "Other", domainIDField: "d", keysField: []any{}},
		map[string]any{kindField: ckapraw.KindFederationIdentity, domainIDField: "", keysField: []any{}},
		map[string]any{kindField: ckapraw.KindFederationIdentity, domainIDField: "d"},
		map[string]any{kindField: ckapraw.KindFederationIdentity, domainIDField: "d", keysField: []any{map[string]any{publicKeyField: key.Key{1: 2}, statusField: "current"}}},
		map[string]any{kindField: ckapraw.KindFederationIdentity, domainIDField: "d", keysField: []any{map[string]any{publicKeyField: key.Key{1: 2, 2: []byte("id")}, statusField: "bad"}}},
	} {
		client, err := ckapclient.NewClient(ckapclient.Config{BaseURL: "https://example.com/", HTTPClient: &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
			return cborResponse(http.StatusOK, key.MustMarshalCBOR(body)), nil
		})}})
		if err != nil {
			t.Fatal(err)
		}
		_, err = client.FederationIdentity(t.Context(), ckap.FederationIdentityRequest{})
		if err == nil {
			t.Fatalf("accepted %#v", body)
		}
		if err := client.Close(); err != nil {
			t.Fatal(err)
		}
	}
}

func TestClientRetrogradeFederation(t *testing.T) {
	for _, flps := range []cabe.FLPSet{nil, {}, {[]byte("one"), []byte("two")}} {
		client, err := ckapclient.NewClient(ckapclient.Config{BaseURL: "https://example.com/", HTTPClient: &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
			raw, err := io.ReadAll(r.Body)
			if err != nil {
				t.Fatal(err)
			}
			var req ckapraw.RetrogradeRequest
			if err := key.UnmarshalCBOR(raw, &req); err != nil {
				t.Fatal(err)
			}
			if req.Federation == nil || req.Federation.OriginDomain != "origin" || len(req.Federation.FLPs) != len(flps) {
				t.Fatalf("federation lost: %#v", req)
			}
			if len(flps) > 0 && !reflect.DeepEqual(req.Federation.FLPs, flps) {
				t.Fatal("FLPs changed")
			}
			return cborResponse(http.StatusOK, key.MustMarshalCBOR(ckapraw.RetrogradeResponse{Kind: ckapraw.KindRetrogradeResponse, LKAI: ckapraw.LKAI{NonCaptive: &ckapraw.LKAINonCaptive{LeaseKey: key.Key{1: 4, 3: 1, -1: []byte("0123456789abcdef")}}}})), nil
		})}})
		if err != nil {
			t.Fatal(err)
		}
		_, err = client.Retrograde(t.Context(), ckap.RetrogradeRequest{LeaseRef: []byte("ref"), Federation: &ckap.RetrogradeFederation{OriginDomain: "origin", FLPs: flps}})
		if err != nil {
			t.Fatal(err)
		}
		if err := client.Close(); err != nil {
			t.Fatal(err)
		}
	}
}
