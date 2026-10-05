package main

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"io"
	"log"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/messier-42/cabe-go/cbes"
	"github.com/spiffe/go-spiffe/v2/bundle/x509bundle"
	"github.com/spiffe/go-spiffe/v2/proto/spiffe/workload"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/go-spiffe/v2/spiffetls/tlsconfig"
	"github.com/spiffe/go-spiffe/v2/svid/x509svid"
	"github.com/spiffe/go-spiffe/v2/workloadapi"
	"google.golang.org/grpc"
)

const (
	tlsClientID          = "spiffe://cabe.test/client"
	tlsServerID          = "spiffe://cabe.test/server"
	testClientCertFlag   = "--client-cert"
	testSPIFFESocketFlag = "--spiffe-socket"
)

type tlsTestCredential struct {
	cert *x509.Certificate
	key  crypto.Signer
	der  []byte
}

func issueTLSCredential(t *testing.T, key crypto.Signer, ca *tlsTestCredential, id string, serial int64) *tlsTestCredential {
	t.Helper()
	u, err := url.Parse(id)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(serial), NotBefore: time.Now().Add(-time.Minute),
		NotAfter: time.Now().Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature,
		URIs: []*url.URL{u},
	}
	parent, signer := template, key
	if ca == nil {
		template.IsCA = true
		template.BasicConstraintsValid = true
		template.KeyUsage |= x509.KeyUsageCertSign
	} else {
		parent, signer = ca.cert, ca.key
		template.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth}
		// DNS/IP SANs belong only on the file-based server, not on SPIFFE SVIDs.
		if id == "" {
			template.URIs = nil
			template.DNSNames = []string{"localhost"}
			template.IPAddresses = []net.IP{net.ParseIP("127.0.0.1")}
		}
	}
	der, err := x509.CreateCertificate(rand.Reader, template, parent, key.Public(), signer)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return &tlsTestCredential{cert: cert, key: key, der: der}
}

func pkcs8TLSKey(t *testing.T, key crypto.Signer) []byte {
	t.Helper()
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	return der
}

func writeTLSPEM(t *testing.T, name, kind string, der []byte) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: kind, Bytes: der}), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func fileTLSOptions(t *testing.T, ca, client *tlsTestCredential) *options {
	t.Helper()
	return &options{
		CACert:     writeTLSPEM(t, "ca.pem", "CERTIFICATE", ca.der),
		ClientCert: writeTLSPEM(t, "client.pem", "CERTIFICATE", client.der),
		ClientKey:  writeTLSPEM(t, "key.pem", "PRIVATE KEY", pkcs8TLSKey(t, client.key)),
	}
}

func serveTLS(t *testing.T, cfg *tls.Config, handler http.Handler) *httptest.Server {
	t.Helper()
	if handler == nil {
		handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Returning the actual peer certificate proves which SVID was used.
			_, _ = w.Write(r.TLS.PeerCertificates[0].Raw)
		})
	}
	s := httptest.NewUnstartedServer(handler)
	s.Config.ErrorLog = log.New(io.Discard, "", 0)
	// StartTLS injects a default certificate when only GetCertificate is set.
	// Serve the supplied callback directly so SPIFFE is actually exercised.
	s.Listener = tls.NewListener(s.Listener, cfg)
	s.Start()
	s.URL = "https://" + s.Listener.Addr().String()
	t.Cleanup(s.Close)
	return s
}

func requestTLS(t *testing.T, ctx context.Context, cfg *tls.Config, endpoint string, version uint16, peer *tlsTestCredential, wantErr string) {
	t.Helper()
	client := makeHTTPClient(cfg, 3*time.Second)
	defer client.CloseIdleConnections()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := client.Do(req)
	if err != nil {
		if wantErr == "" || !strings.Contains(err.Error(), wantErr) {
			t.Fatalf("TLS request: %v; wanted %q", err, wantErr)
		}
		return
	}
	defer resp.Body.Close() // best effort
	if wantErr != "" {
		t.Fatalf("TLS request succeeded; wanted %q", wantErr)
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	if resp.TLS.Version != version || !bytes.Equal(body, peer.der) {
		t.Fatalf("wrong TLS version (%x) or client certificate", resp.TLS.Version)
	}
}

func TestClassicalTLSBoundaries(t *testing.T) {
	testTLSBoundaries(t, func(t *testing.T) crypto.Signer {
		t.Helper()
		key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		return key
	}, tls.VersionTLS12)
}

// minVersion is the earliest TLS version supported by the test credentials.
func testTLSBoundaries(t *testing.T, newKey func(*testing.T) crypto.Signer, minVersion uint16) {
	t.Helper()
	ca := issueTLSCredential(t, newKey(t), nil, "spiffe://cabe.test", 1)
	otherCA := issueTLSCredential(t, newKey(t), nil, "spiffe://cabe.test", 2)
	client := issueTLSCredential(t, newKey(t), ca, tlsClientID, 3)
	server := issueTLSCredential(t, newKey(t), ca, "", 4)
	roots := x509.NewCertPool()
	roots.AddCert(ca.cert)
	serverCfg := &tls.Config{
		Certificates: []tls.Certificate{{Certificate: [][]byte{server.der}, PrivateKey: server.key}},
		ClientAuth:   tls.RequireAndVerifyClientCert, ClientCAs: roots, MinVersion: tls.VersionTLS12,
	}
	t.Run("file", func(t *testing.T) {
		opts := fileTLSOptions(t, ca, client)
		cfg, cleanup, err := buildTLSConfig(t.Context(), opts)
		if err != nil {
			t.Fatal(err)
		}
		defer cleanup()
		if !cfg.Certificates[0].PrivateKey.(crypto.Signer).Public().(interface {
			Equal(other crypto.PublicKey) bool
		}).Equal(client.key.Public()) {
			t.Fatal("loaded key changed")
		}
		s := serveTLS(t, serverCfg.Clone(), nil)
		requestTLS(t, t.Context(), cfg, s.URL, tls.VersionTLS13, client, "")
		t.Run("wrong_hostname", func(t *testing.T) {
			bad := cfg.Clone()
			bad.ServerName = "wrong.test"
			requestTLS(t, t.Context(), bad, s.URL, 0, nil, "certificate is valid for")
		})
		t.Run("wrong_root", func(t *testing.T) {
			badOpts := *opts
			badOpts.CACert = writeTLSPEM(t, "wrong.pem", "CERTIFICATE", otherCA.der)
			bad, err := buildFileTLSConfig(&badOpts)
			if err != nil {
				t.Fatal(err)
			}
			requestTLS(t, t.Context(), bad, s.URL, 0, nil, "unknown authority")
		})
		t.Run("mismatched_key", func(t *testing.T) {
			badOpts := *opts
			badOpts.ClientKey = writeTLSPEM(t, "wrong.key", "PRIVATE KEY", pkcs8TLSKey(t, newKey(t)))
			if _, err := buildFileTLSConfig(&badOpts); err == nil {
				t.Fatal("accepted mismatched key")
			}
		})
		t.Run("tls12", func(t *testing.T) {
			old := cfg.Clone()
			old.MaxVersion = tls.VersionTLS12
			wantErr := ""
			if minVersion > tls.VersionTLS12 {
				wantErr = "remote error: tls:"
			}
			requestTLS(t, t.Context(), old, s.URL, tls.VersionTLS12, client, wantErr)
		})
		t.Run("cli_round_trip", func(t *testing.T) {
			stub := stubKeyServer(t)
			secure := serveTLS(t, serverCfg.Clone(), stub.Config.Handler)
			testTLSCLIRoundTrip(t, secure.URL, []string{"--ca-cert", opts.CACert, testClientCertFlag, opts.ClientCert, "--client-key", opts.ClientKey})
		})
	})
	t.Run("workload_api", func(t *testing.T) {
		testWorkloadTLS(t, newKey, ca, otherCA, client, minVersion)
	})
}

// testWorkloadServer speaks the real streaming Workload API over a Unix socket.
type testWorkloadServer struct {
	workload.UnimplementedSpiffeWorkloadAPIServer

	initial *workload.X509SVIDResponse
	updates chan *workload.X509SVIDResponse
}

func (s *testWorkloadServer) FetchX509SVID(_ *workload.X509SVIDRequest, stream grpc.ServerStreamingServer[workload.X509SVIDResponse]) error {
	if err := stream.Send(s.initial); err != nil {
		return err
	}
	for {
		select {
		case <-stream.Context().Done():
			return stream.Context().Err()
		case update := <-s.updates:
			if err := stream.Send(update); err != nil {
				return err
			}
		}
	}
}

func startWorkloadServer(t *testing.T, initial *workload.X509SVIDResponse) (string, chan<- *workload.X509SVIDResponse) {
	t.Helper()
	// Keep Unix socket paths short even when the test name is long.
	dir, err := os.MkdirTemp("", "cabe-wapi-") //nolint:usetesting // t.TempDir includes long subtest names that exceed Unix socket path limits.
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	socket := filepath.Join(dir, "api.sock")
	var lc net.ListenConfig
	listener, err := lc.Listen(t.Context(), "unix", socket)
	if err != nil {
		t.Fatal(err)
	}
	updates := make(chan *workload.X509SVIDResponse, 1)
	s := grpc.NewServer()
	workload.RegisterSpiffeWorkloadAPIServer(s, &testWorkloadServer{initial: initial, updates: updates})
	done := make(chan struct{})
	go func() {
		defer close(done)
		if err := s.Serve(listener); err != nil {
			t.Errorf("Workload API: %v", err)
		}
	}()
	t.Cleanup(func() { s.Stop(); <-done })
	return socket, updates
}

func workloadResponse(t *testing.T, ca, client *tlsTestCredential) *workload.X509SVIDResponse {
	t.Helper()
	return &workload.X509SVIDResponse{Svids: []*workload.X509SVID{{
		SpiffeId: tlsClientID, X509Svid: client.der, X509SvidKey: pkcs8TLSKey(t, client.key), Bundle: ca.der,
	}}}
}

func spiffeServerConfig(t *testing.T, ca, server *tlsTestCredential) *tls.Config {
	t.Helper()
	svid, err := x509svid.ParseRaw(server.der, pkcs8TLSKey(t, server.key))
	if err != nil {
		t.Fatal(err)
	}
	bundle := x509bundle.FromX509Authorities(spiffeid.RequireTrustDomainFromString("cabe.test"), []*x509.Certificate{ca.cert})
	return tlsconfig.MTLSServerConfig(svid, bundle, tlsconfig.AuthorizeID(spiffeid.RequireFromString(tlsClientID)))
}

func testWorkloadTLS(t *testing.T, newKey func(*testing.T) crypto.Signer, ca, otherCA, client *tlsTestCredential, minVersion uint16) {
	t.Helper()
	server := issueTLSCredential(t, newKey(t), ca, tlsServerID, 5)
	socket, updates := startWorkloadServer(t, workloadResponse(t, ca, client))
	opts := &options{SPIFFESocket: socket, ServerSPIFFEIDRegex: "^spiffe://cabe[.]test/server$"}
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()
	cfg, src, err := buildSPIFFETLSConfig(ctx, opts)
	if err != nil {
		t.Fatal(err)
	}
	defer src.Close() // best effort
	s := serveTLS(t, spiffeServerConfig(t, ca, server), nil)
	current, err := src.GetX509SVID()
	if err != nil {
		t.Fatal(err)
	}
	if reflect.TypeOf(current.PrivateKey) != reflect.TypeOf(client.key) || reflect.TypeOf(current.Certificates[0].PublicKey) != reflect.TypeOf(client.cert.PublicKey) {
		t.Fatal("SVID changed key types")
	}
	requestTLS(t, ctx, cfg, s.URL, tls.VersionTLS13, client, "")
	t.Run("wrong_identity", func(t *testing.T) {
		wrong := issueTLSCredential(t, newKey(t), ca, "spiffe://cabe.test/intruder", 6)
		bad := serveTLS(t, spiffeServerConfig(t, ca, wrong), nil)
		requestTLS(t, ctx, cfg, bad.URL, 0, nil, "does not match")
	})
	t.Run("wrong_root", func(t *testing.T) {
		wrong := issueTLSCredential(t, newKey(t), otherCA, tlsServerID, 7)
		bad := serveTLS(t, spiffeServerConfig(t, otherCA, wrong), nil)
		requestTLS(t, ctx, cfg, bad.URL, 0, nil, "unknown authority")
	})
	t.Run("tls12", func(t *testing.T) {
		old := cfg.Clone()
		old.MaxVersion = tls.VersionTLS12
		wantErr := ""
		if minVersion > tls.VersionTLS12 {
			wantErr = "remote error: tls:"
		}
		requestTLS(t, ctx, old, s.URL, tls.VersionTLS12, client, wantErr)
	})
	t.Run("renewal", func(t *testing.T) {
		renewed := issueTLSCredential(t, newKey(t), ca, tlsClientID, 8)
		updates <- workloadResponse(t, ca, renewed)
		for {
			current, err := src.GetX509SVID()
			if err != nil {
				t.Fatal(err)
			}
			if bytes.Equal(current.Certificates[0].Raw, renewed.der) {
				if !bytes.Equal(pkcs8TLSKey(t, current.PrivateKey), pkcs8TLSKey(t, renewed.key)) {
					t.Fatal("renewed private key changed")
				}
				break
			}
			if err := src.WaitUntilUpdated(ctx); err != nil {
				t.Fatal(err)
			}
		}
		// Reuse the original config; only a fresh connection should be needed.
		requestTLS(t, ctx, cfg, s.URL, tls.VersionTLS13, renewed, "")
	})
	t.Run("mismatched_key", func(t *testing.T) {
		bad := workloadResponse(t, ca, client)
		bad.Svids[0].X509SvidKey = pkcs8TLSKey(t, newKey(t))
		testRejectedWorkloadResponse(t, bad)
	})
	t.Run("cli_round_trip", func(t *testing.T) {
		stub := stubKeyServer(t)
		secure := serveTLS(t, spiffeServerConfig(t, ca, server), stub.Config.Handler)
		testTLSCLIRoundTrip(t, secure.URL, []string{testSPIFFESocketFlag, socket, "--server-spiffe-id-regex", opts.ServerSPIFFEIDRegex})
	})
}

func testRejectedWorkloadResponse(t *testing.T, response *workload.X509SVIDResponse) {
	t.Helper()
	socket, _ := startWorkloadServer(t, response)
	fetchCtx, fetchCancel := context.WithTimeout(t.Context(), 3*time.Second)
	defer fetchCancel()
	client, err := workloadapi.New(fetchCtx, workloadapi.WithAddr(normaliseSPIFFEAddr(socket)))
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close() // best effort
	// Prove a credential validation failure, rather than only a startup timeout.
	if _, err := client.FetchX509SVID(fetchCtx); err == nil || !strings.Contains(err.Error(), "x509svid:") {
		t.Fatalf("expected SVID validation failure, got %v", err)
	}
	ctx, cancel := context.WithTimeout(t.Context(), 250*time.Millisecond)
	defer cancel()
	cfg, src, err := buildSPIFFETLSConfig(ctx, &options{SPIFFESocket: socket, ServerSPIFFEIDRegex: ".*"})
	if src != nil {
		_ = src.Close()
	}
	if err == nil || cfg != nil {
		t.Fatal("accepted invalid Workload API credential")
	}
}

func testTLSCLIRoundTrip(t *testing.T, endpoint string, auth []string) {
	t.Helper()
	args := append([]string{"--base-url", endpoint + "/ckap/", "--timeout", "3s"}, auth...)
	exit, envelope, stderr := runArgs(t, "TLS payload", append(args, "encap", "-A", "project=str:cabe", "--content-type", "text/plain")...)
	if exit != 0 {
		t.Fatalf("encap: exit %d: %s", exit, stderr)
	}
	info, err := cbes.Inspect([]byte(envelope))
	if err != nil || info.IsCaptive || string(info.LeaseRef) != "lease-ref" {
		t.Fatalf("CBES metadata changed: %+v, %v", info, err)
	}
	exit, plaintext, meta := runArgs(t, envelope, append(args, "-J", "decap")...)
	if exit != 0 || plaintext != "TLS payload" {
		t.Fatalf("decap: exit %d, plaintext %q: %s", exit, plaintext, meta)
	}
	var decoded map[string]any
	if err := json.Unmarshal([]byte(meta), &decoded); err != nil {
		t.Fatal(err)
	}
	attrs, ok := decoded["attributeSet"].(map[string]any)
	if !ok || attrs["project"] != "cabe" || decoded["contentType"] != "text/plain" {
		t.Fatalf("CLI metadata changed: %s", meta)
	}
}
