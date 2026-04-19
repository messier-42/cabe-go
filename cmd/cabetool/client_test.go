package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// writeTestKeyPair generates a self-signed ECDSA cert + key PEM pair
// in dir and returns the two file paths. The cert is valid for a day,
// which is ample for a unit test.
func writeTestKeyPair(t *testing.T, dir string) (certPath, keyPath string) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "cabetool-test"},
		NotBefore:    time.Now().Add(-time.Minute),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create cert: %v", err)
	}
	certPath = filepath.Join(dir, "client.crt")
	keyPath = filepath.Join(dir, "client.key")
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	if err := os.WriteFile(certPath, certPEM, 0o600); err != nil {
		t.Fatalf("write cert: %v", err)
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatalf("marshal key: %v", err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})
	if err := os.WriteFile(keyPath, keyPEM, 0o600); err != nil {
		t.Fatalf("write key: %v", err)
	}
	return certPath, keyPath
}

func TestBuildFileTLSConfigLoadsKeyPair(t *testing.T) {
	dir := t.TempDir()
	certPath, keyPath := writeTestKeyPair(t, dir)

	opts := &options{ClientCert: certPath, ClientKey: keyPath}
	cfg, err := buildFileTLSConfig(opts)
	if err != nil {
		t.Fatalf("buildFileTLSConfig: %v", err)
	}
	if len(cfg.Certificates) != 1 {
		t.Fatalf("Certificates length = %d, want 1", len(cfg.Certificates))
	}
	if cfg.Certificates[0].PrivateKey == nil {
		t.Fatal("Certificates[0].PrivateKey is nil")
	}
	if cfg.MinVersion < 0x0303 { // TLS 1.2
		t.Errorf("MinVersion = %#x, want >= TLS 1.2", cfg.MinVersion)
	}
}

func TestBuildFileTLSConfigWithCACert(t *testing.T) {
	dir := t.TempDir()
	certPath, keyPath := writeTestKeyPair(t, dir)
	// Re-use the client cert PEM as a plausible CA bundle; the builder
	// just needs at least one parseable certificate.
	caPath := filepath.Join(dir, "ca.pem")
	pemBytes, err := os.ReadFile(certPath)
	if err != nil {
		t.Fatalf("read client cert: %v", err)
	}
	if err := os.WriteFile(caPath, pemBytes, 0o600); err != nil {
		t.Fatalf("write ca bundle: %v", err)
	}

	opts := &options{ClientCert: certPath, ClientKey: keyPath, CACert: caPath}
	cfg, err := buildFileTLSConfig(opts)
	if err != nil {
		t.Fatalf("buildFileTLSConfig: %v", err)
	}
	if cfg.RootCAs == nil {
		t.Fatal("RootCAs is nil; --ca-cert should populate it")
	}
}

func TestLoadCAPoolRejectsGarbage(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "garbage.pem")
	if err := os.WriteFile(path, []byte("this is not a certificate"), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	_, err := loadCAPool(path)
	if err == nil || !strings.Contains(err.Error(), "no PEM certificates parsed") {
		t.Fatalf("expected PEM parse error, got %v", err)
	}
}

func TestSelectAuthMode(t *testing.T) {
	cases := []struct {
		name   string
		opts   options
		want   authMode
		errSub string
	}{
		{name: "anonymous", opts: options{}, want: authAnonymous},
		{name: "file mTLS", opts: options{ClientCert: "c", ClientKey: "k"}, want: authFileMTLS},
		{name: "spiffe", opts: options{SPIFFESocket: "/sock", ServerSPIFFEIDRegex: "^spiffe://.*$"}, want: authSPIFFE},
		{name: "cert without key", opts: options{ClientCert: "c"}, errSub: "must be set together"},
		{name: "key without cert", opts: options{ClientKey: "k"}, errSub: "must be set together"},
		{name: "cert and spiffe", opts: options{ClientCert: "c", ClientKey: "k", SPIFFESocket: "/s"}, errSub: "mutually exclusive"},
		{name: "spiffe without regex", opts: options{SPIFFESocket: "/s"}, errSub: "--server-spiffe-id-regex is required"},
		{name: "regex without spiffe", opts: options{ServerSPIFFEIDRegex: "^.*$"}, errSub: "requires --spiffe-socket"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, err := selectAuthMode(&c.opts)
			if c.errSub != "" {
				if err == nil || !strings.Contains(err.Error(), c.errSub) {
					t.Fatalf("error = %v, want substring %q", err, c.errSub)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got != c.want {
				t.Fatalf("mode = %v, want %v", got, c.want)
			}
		})
	}
}

func TestBuildTLSConfigAnonymous(t *testing.T) {
	opts := &options{}
	cfg, cleanup, err := buildTLSConfig(context.Background(), opts)
	if err != nil {
		t.Fatalf("buildTLSConfig: %v", err)
	}
	defer cleanup()
	if cfg != nil {
		t.Fatalf("anonymous with no CA: cfg = %v, want nil", cfg)
	}
}

func TestBuildTLSConfigFile(t *testing.T) {
	dir := t.TempDir()
	certPath, keyPath := writeTestKeyPair(t, dir)

	opts := &options{ClientCert: certPath, ClientKey: keyPath}
	cfg, cleanup, err := buildTLSConfig(context.Background(), opts)
	if err != nil {
		t.Fatalf("buildTLSConfig: %v", err)
	}
	defer cleanup()
	if cfg == nil || len(cfg.Certificates) != 1 {
		t.Fatalf("expected TLS config with 1 cert, got %#v", cfg)
	}
}

func TestNormaliseSPIFFEAddr(t *testing.T) {
	cases := map[string]string{
		"/run/spiffe/agent.sock":      "unix:///run/spiffe/agent.sock",
		"unix:///run/spiffe/api.sock": "unix:///run/spiffe/api.sock",
		"tcp://127.0.0.1:8082":        "tcp://127.0.0.1:8082",
	}
	for in, want := range cases {
		if got := normaliseSPIFFEAddr(in); got != want {
			t.Errorf("normaliseSPIFFEAddr(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestBuildSPIFFETLSConfigRejectsBadRegex(t *testing.T) {
	opts := &options{SPIFFESocket: "/tmp/nonexistent.sock", ServerSPIFFEIDRegex: "(["}
	_, _, err := buildSPIFFETLSConfig(context.Background(), opts)
	if err == nil || !strings.Contains(err.Error(), "--server-spiffe-id-regex") {
		t.Fatalf("expected regex compile error, got %v", err)
	}
}

// TestSPIFFESmoke exercises the real workloadapi against a running
// agent, selected by the standard SPIFFE env var. Skipped in all
// ordinary CI runs; present so an integration harness can invoke it.
func TestSPIFFESmoke(t *testing.T) {
	sock := os.Getenv("SPIFFE_ENDPOINT_SOCKET")
	if sock == "" {
		t.Skip("SPIFFE_ENDPOINT_SOCKET not set")
	}
	opts := &options{SPIFFESocket: sock, ServerSPIFFEIDRegex: "^spiffe://.*$"}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	cfg, src, err := buildSPIFFETLSConfig(ctx, opts)
	if err != nil {
		t.Fatalf("buildSPIFFETLSConfig: %v", err)
	}
	defer src.Close() //nolint:errcheck // best-effort; test already passed by the time we return
	if cfg == nil {
		t.Fatal("nil *tls.Config from SPIFFE builder")
	}
}
