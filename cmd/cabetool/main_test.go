package main

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/ldclabs/cose/iana"
	"github.com/ldclabs/cose/key"
	"github.com/messier-42/cabe-go/ckapraw"
)

// runArgs invokes cabetool in-process with the given argv. stdin / out
// / err are captured into strings. Returns exit code + captured
// streams. Callers that want to set a flag to the test server's URL
// prepend --base-url <ts.URL> themselves.
func runArgs(t *testing.T, stdin string, args ...string) (exit int, stdout, stderr string) {
	t.Helper()
	var stdoutBuf, stderrBuf bytes.Buffer
	exit = run(context.Background(), args, strings.NewReader(stdin), &stdoutBuf, &stderrBuf)
	return exit, stdoutBuf.String(), stderrBuf.String()
}

// stubKeyServer returns an httptest.Server that handles the CKAP
// operations cabetool exercises in this test suite: GetSelf, Prograde,
// Retrograde. The non-captive lease key is a fixed A128GCM symmetric
// key so encap→decap round-trips without needing a real Key Server.
func stubKeyServer(t *testing.T) *httptest.Server {
	t.Helper()
	leaseKey := ckapraw.COSEKey{
		iana.KeyParameterKty:        iana.KeyTypeSymmetric,
		iana.KeyParameterAlg:        iana.AlgorithmA128GCM,
		iana.SymmetricKeyParameterK: []byte("0123456789abcdef"),
		iana.KeyParameterBaseIV:     []byte("abcdefghijkl"),
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/ckap/GetSelf", func(w http.ResponseWriter, r *http.Request) {
		data, err := key.MarshalCBOR(ckapraw.GetSelfResponse{
			Kind: ckapraw.KindGetSelfResponse,
			Principal: ckapraw.Principal{
				URI:    "spiffe://example.org/test",
				Claims: map[string]any{"role": "operator"},
			},
			ServerInfo: map[string]any{"version": "stub-0"},
		})
		if err != nil {
			t.Errorf("MarshalCBOR: %v", err)
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/ckap+cbor")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(data)
	})
	mux.HandleFunc("/ckap/Prograde", func(w http.ResponseWriter, r *http.Request) {
		data, err := key.MarshalCBOR(ckapraw.ProgradeResponse{
			Kind: ckapraw.KindProgradeResponse,
			Lease: ckapraw.Lease{
				LeaseRef: []byte("lease-ref"),
				LKAI: ckapraw.LKAI{
					NonCaptive: &ckapraw.LKAINonCaptive{LeaseKey: leaseKey},
				},
				Expiry: 4070908800,
			},
		})
		if err != nil {
			t.Errorf("MarshalCBOR: %v", err)
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/ckap+cbor")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(data)
	})
	mux.HandleFunc("/ckap/Retrograde", func(w http.ResponseWriter, r *http.Request) {
		data, err := key.MarshalCBOR(ckapraw.RetrogradeResponse{
			Kind: ckapraw.KindRetrogradeResponse,
			LKAI: ckapraw.LKAI{
				NonCaptive: &ckapraw.LKAINonCaptive{LeaseKey: leaseKey},
			},
		})
		if err != nil {
			t.Errorf("MarshalCBOR: %v", err)
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/ckap+cbor")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(data)
	})
	ts := httptest.NewServer(mux)
	t.Cleanup(ts.Close)
	return ts
}

func TestWhoami(t *testing.T) {
	ts := stubKeyServer(t)
	exit, stdout, stderr := runArgs(t, "",
		"--base-url", ts.URL+"/ckap/",
		"-J",
		"whoami",
	)
	if exit != 0 {
		t.Fatalf("exit = %d; stderr = %s", exit, stderr)
	}
	var got map[string]any
	if err := json.Unmarshal([]byte(stdout), &got); err != nil {
		t.Fatalf("stdout not JSON: %v\n%s", err, stdout)
	}
	p, _ := got["principal"].(map[string]any)
	if p == nil || p["uri"] != "spiffe://example.org/test" {
		t.Fatalf("unexpected principal: %v", got)
	}
}

func TestEncapDecapRoundTrip(t *testing.T) {
	ts := stubKeyServer(t)

	// encap plaintext → envelope on stdout.
	exit, envBytes, stderr := runArgs(t, "hello cabe",
		"--base-url", ts.URL+"/ckap/",
		"encap",
		"-A", "project=str:cabe",
		"-A", "tier=int:2",
		"--content-type", "text/plain",
	)
	if exit != 0 {
		t.Fatalf("encap exit = %d; stderr = %s", exit, stderr)
	}
	if len(envBytes) == 0 {
		t.Fatal("encap produced empty envelope")
	}

	// decap envelope → plaintext on stdout, metadata on stderr.
	exit, plaintext, meta := runArgs(t, envBytes,
		"--base-url", ts.URL+"/ckap/",
		"-J",
		"decap",
	)
	if exit != 0 {
		t.Fatalf("decap exit = %d; stderr = %s", exit, meta)
	}
	if plaintext != "hello cabe" {
		t.Fatalf("decap plaintext = %q, want %q", plaintext, "hello cabe")
	}
	// The metadata JSON reports the decoded attribute set and
	// content type on stderr.
	var decodedMeta map[string]any
	if err := json.Unmarshal([]byte(meta), &decodedMeta); err != nil {
		t.Fatalf("decap meta not JSON: %v\n%s", err, meta)
	}
	attrs, _ := decodedMeta["attributeSet"].(map[string]any)
	if attrs == nil || attrs["project"] != "cabe" {
		t.Fatalf("unexpected meta: %v", decodedMeta)
	}
	if decodedMeta["contentType"] != "text/plain" {
		t.Fatalf("contentType = %v, want text/plain", decodedMeta["contentType"])
	}
}

func TestEncapRejectsMissingAttr(t *testing.T) {
	ts := stubKeyServer(t)
	exit, _, stderr := runArgs(t, "",
		"--base-url", ts.URL+"/ckap/",
		"encap",
	)
	if exit == 0 {
		t.Fatal("expected non-zero exit for missing --attr")
	}
	if !strings.Contains(stderr, "--attr is required") {
		t.Fatalf("stderr = %q, want mention of --attr", stderr)
	}
}

// TestAuthFlagValidation drives the CLI through selectAuthMode's
// failure modes to make sure invalid combinations produce a useful
// error at startup rather than being silently ignored.
func TestAuthFlagValidation(t *testing.T) {
	cases := []struct {
		name   string
		args   []string
		errSub string
	}{
		{
			name:   "cert without key",
			args:   []string{testClientCertFlag, "/nowhere"},
			errSub: "must be set together",
		},
		{
			name:   "cert and spiffe",
			args:   []string{testClientCertFlag, "/a", "--client-key", "/b", testSPIFFESocketFlag, "/s", "--server-spiffe-id-regex", "^.*$"},
			errSub: "mutually exclusive",
		},
		{
			name:   "spiffe without regex",
			args:   []string{testSPIFFESocketFlag, "/s"},
			errSub: "--server-spiffe-id-regex is required",
		},
		{
			name:   "bad ca cert",
			args:   []string{"--ca-cert", "/definitely/not/a/file/cabetool-test"},
			errSub: "read --ca-cert",
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			full := append([]string{"--base-url", "https://example.com/ckap/"}, c.args...)
			full = append(full, "whoami")
			exit, _, stderr := runArgs(t, "", full...)
			if exit == 0 {
				t.Fatalf("expected non-zero exit; stderr = %q", stderr)
			}
			if !strings.Contains(stderr, c.errSub) {
				t.Fatalf("stderr = %q, want substring %q", stderr, c.errSub)
			}
		})
	}
}
