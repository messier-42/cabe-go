package cabecap_test

import (
	"io"
	"net/http"
	"testing"

	"github.com/ldclabs/cose/iana"
	"github.com/ldclabs/cose/key"
	"github.com/ldclabs/cose/key/ecdh"
	"github.com/messier-42/cabe-go/cabe"
	"github.com/messier-42/cabe-go/cabecap"
	"github.com/messier-42/cabe-go/cbes"
	"github.com/messier-42/cabe-go/cfar"
	"github.com/messier-42/cabe-go/ckapclient"
	"github.com/messier-42/cabe-go/ckapraw"
)

// Exercise the library operations Khaled can integrate, including a capability
// learned independently of the current request and quoted empty FLP sets.
func TestSFLPEndToEnd(t *testing.T) {
	attrs := mustSet(t, map[string]any{"scenario": "federated"})
	context := cfar.LeaseContext{OriginDomain: federationTestOrigin, AttributeSet: attrs, LeaseRef: []byte("federated-ref")}
	lkai := ckapraw.LKAI{NonCaptive: &ckapraw.LKAINonCaptive{LeaseKey: key.Key{1: 4, 3: 2, -1: []byte("0123456789abcdefghijklmn"), 5: []byte("abcdefghijkl")}}}
	publicLKAI, err := lkai.ToCABE()
	if err != nil {
		t.Fatal(err)
	}
	// AES-192 Lease Key differs from the default AES-256 package CEK.
	priv, err := ecdh.GenerateKey(iana.EllipticCurveX25519)
	if err != nil {
		t.Fatal(err)
	}
	priv[iana.KeyParameterAlg] = iana.AlgorithmECDH_ES_A256KW
	pub, err := ecdh.ToPublicKey(priv)
	if err != nil {
		t.Fatal(err)
	}
	packageBytes, err := cfar.Generate(context, *publicLKAI.NonCaptive, []key.Key{pub}, nil)
	if err != nil {
		t.Fatal(err)
	}
	origin, err := cabecap.NewWithClient(ckapclient.Config{BaseURL: "https://origin/", HTTPClient: &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
		if r.URL.Path != "/Prograde" {
			t.Fatalf("unexpected request %s", r.URL.Path)
		}
		return cborResponse(http.StatusOK, key.MustMarshalCBOR(ckapraw.ProgradeResponse{Kind: ckapraw.KindProgradeResponse, Lease: ckapraw.Lease{LeaseRef: context.LeaseRef, LKAI: lkai, Expiry: 4070908800, Federation: &ckapraw.LeaseFederation{OriginDomain: context.OriginDomain, FLPs: cabe.FLPSet{packageBytes}}}})), nil
	})}}, cabecap.WithARIN(false))
	if err != nil {
		t.Fatal(err)
	}
	defer origin.Close() // best effort
	envelope, err := origin.Encapsulate(t.Context(), cabe.Message{Payload: []byte("federated payload"), Attributes: attrs})
	if err != nil {
		t.Fatal(err)
	}
	for _, inline := range []bool{true, false} {
		t.Run(map[bool]string{true: "inline", false: "already known"}[inline], func(t *testing.T) {
			target, err := cabecap.NewWithClient(ckapclient.Config{BaseURL: "https://target/", HTTPClient: &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
				raw, err := io.ReadAll(r.Body)
				if err != nil {
					t.Fatal(err)
				}
				var req ckapraw.RetrogradeRequest
				if err := key.UnmarshalCBOR(raw, &req); err != nil {
					t.Fatal(err)
				}
				if req.Federation == nil {
					t.Fatal("missing federation context")
				}
				requestAttrs, err := req.AttributeSet.Parse()
				if err != nil {
					t.Fatal(err)
				}
				packages := req.Federation.FLPs
				if !inline {
					if len(packages) != 0 {
						t.Fatal("request should quote an empty FLP set")
					}
					packages = cabe.FLPSet{packageBytes}
				}
				recovered, err := cfar.Recover(cfar.LeaseContext{OriginDomain: req.Federation.OriginDomain, AttributeSet: requestAttrs, LeaseRef: req.LeaseRef}, packages, []key.Key{priv}, nil)
				if err != nil {
					t.Fatal(err)
				}
				var recoveredKey key.Key
				if err := key.UnmarshalCBOR(recovered.RawCOSEKey, &recoveredKey); err != nil {
					t.Fatal(err)
				}
				return cborResponse(http.StatusOK, key.MustMarshalCBOR(ckapraw.RetrogradeResponse{Kind: ckapraw.KindRetrogradeResponse, LKAI: ckapraw.LKAI{NonCaptive: &ckapraw.LKAINonCaptive{LeaseKey: recoveredKey}}})), nil
			})}}, cabecap.WithARIN(false))
			if err != nil {
				t.Fatal(err)
			}
			defer target.Close() // best effort
			input := envelope
			if !inline {
				input, err = cbes.SetFLPs(input, nil)
				if err != nil {
					t.Fatal(err)
				}
			}
			message, err := target.Decapsulate(t.Context(), input)
			if err != nil {
				t.Fatal(err)
			}
			if string(message.Payload) != "federated payload" {
				t.Fatal("payload changed")
			}
		})
	}
}
