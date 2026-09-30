package cabecap_test

import (
	"errors"
	"io"
	"net/http"
	"testing"

	"github.com/fxamacker/cbor/v2"
	"github.com/ldclabs/cose/cose"
	"github.com/ldclabs/cose/key"
	"github.com/messier-42/cabe-go/cabe"
	"github.com/messier-42/cabe-go/cabecap"
	"github.com/messier-42/cabe-go/cbes"
	"github.com/messier-42/cabe-go/ckapclient"
	"github.com/messier-42/cabe-go/ckapraw"
)

const federationTestOrigin = "origin"

func TestCapsulatorFederationPropagation(t *testing.T) {
	for _, flps := range []cabe.FLPSet{nil, {}, {[]byte("package")}} {
		lkai := ckapraw.LKAI{NonCaptive: &ckapraw.LKAINonCaptive{LeaseKey: key.Key{1: 4, 3: 1, -1: []byte("0123456789abcdef"), 5: []byte("abcdefghijkl")}}}
		progrades, retrogrades := 0, 0
		origin, err := cabecap.NewWithClient(ckapclient.Config{BaseURL: "https://origin/", HTTPClient: &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
			if r.URL.Path != "/Prograde" {
				t.Fatalf("unexpected origin request %s", r.URL.Path)
			}
			progrades++
			return cborResponse(http.StatusOK, key.MustMarshalCBOR(ckapraw.ProgradeResponse{Kind: ckapraw.KindProgradeResponse, Lease: ckapraw.Lease{LeaseRef: []byte("ref"), LKAI: lkai, Expiry: 4070908800, Federation: &ckapraw.LeaseFederation{OriginDomain: federationTestOrigin, FLPs: flps}}})), nil
		})}}, cabecap.WithARIN(false))
		if err != nil {
			t.Fatal(err)
		}
		target, err := cabecap.NewWithClient(ckapclient.Config{BaseURL: "https://target/", HTTPClient: &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
			if r.URL.Path != "/Retrograde" {
				t.Fatalf("unexpected target request %s", r.URL.Path)
			}
			retrogrades++
			raw, err := io.ReadAll(r.Body)
			if err != nil {
				t.Fatal(err)
			}
			var req ckapraw.RetrogradeRequest
			if err := key.UnmarshalCBOR(raw, &req); err != nil {
				t.Fatal(err)
			}
			if req.Federation == nil || req.Federation.OriginDomain != federationTestOrigin || len(req.Federation.FLPs) != len(flps) {
				t.Fatalf("metadata lost: %#v", req.Federation)
			}
			return cborResponse(http.StatusOK, key.MustMarshalCBOR(ckapraw.RetrogradeResponse{Kind: ckapraw.KindRetrogradeResponse, LKAI: lkai})), nil
		})}}, cabecap.WithARIN(false))
		if err != nil {
			t.Fatal(err)
		}
		for range 2 {
			envelope, err := origin.Encapsulate(t.Context(), cabe.Message{Payload: []byte("hello"), Attributes: mustSet(t, map[string]any{})})
			if err != nil {
				t.Fatal(err)
			}
			inspected, err := cbes.Inspect(envelope)
			if err != nil {
				t.Fatal(err)
			}
			if inspected.OriginDomain != federationTestOrigin || len(inspected.FLPs) != len(flps) {
				t.Fatal("cached Lease metadata lost")
			}
			if len(flps) > 0 {
				// Inject an invalid wire set directly. Reject it before Retrograde,
				// even if an earlier decapsulation has populated the key cache.
				var fields []cbor.RawMessage
				if err := key.UnmarshalCBOR(cose.RemoveCBORTag(envelope), &fields); err != nil {
					t.Fatal(err)
				}
				var headers cose.Headers
				if err := key.UnmarshalCBOR(fields[1], &headers); err != nil {
					t.Fatal(err)
				}
				headers[cbes.HeaderFLPs] = append(flps.Clone(), flps[0])
				fields[1] = key.MustMarshalCBOR(headers)
				before := retrogrades
				if _, err := target.Decapsulate(t.Context(), key.MustMarshalCBOR(fields)); !errors.Is(err, cabecap.ErrInvalidEnvelope) {
					t.Fatalf("duplicate FLPs should invalidate the Envelope: %v", err)
				}
				if retrogrades != before {
					t.Fatal("invalid FLP set reached key resolution")
				}
			}
			msg, err := target.Decapsulate(t.Context(), envelope)
			if err != nil {
				t.Fatal(err)
			}
			if string(msg.Payload) != "hello" {
				t.Fatal("wrong payload")
			}
			if _, err := origin.Decapsulate(t.Context(), envelope); err != nil {
				t.Fatal(err)
			}
		}
		if progrades != 1 || retrogrades != 1 {
			t.Fatalf("cache not reused: %d %d", progrades, retrogrades)
		}
		if err := origin.Close(); err != nil {
			t.Fatal(err)
		}
		if err := target.Close(); err != nil {
			t.Fatal(err)
		}
	}
}
