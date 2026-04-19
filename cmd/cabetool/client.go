package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net/http"
	"os"
	"regexp"
	"strings"
	"time"

	"github.com/messier-42/cabe-go/ckapclient"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/go-spiffe/v2/spiffetls/tlsconfig"
	"github.com/spiffe/go-spiffe/v2/workloadapi"
)

// authMode identifies which of the mutually-exclusive client-auth
// configurations opts selects.
type authMode int

const (
	authAnonymous authMode = iota // no client auth, server verified via CA bundle or system roots
	authFileMTLS                  // --client-cert + --client-key (+ optional --ca-cert)
	authSPIFFE                    // SPIFFE Workload API
)

// selectAuthMode decides how the client should authenticate based on
// which of the mutually-exclusive flag groups are set. The rules:
//
//   - --client-cert and --client-key must be set together.
//   - --client-cert and --spiffe-socket are mutually exclusive.
//   - If SPIFFE_ENDPOINT_SOCKET is set in the environment but no flag
//     is, that also selects SPIFFE mode (the env binding already folded
//     the var into opts.SPIFFESocket before we got here).
//   - Otherwise the client is anonymous.
func selectAuthMode(opts *options) (authMode, error) {
	hasCert := opts.ClientCert != ""
	hasKey := opts.ClientKey != ""
	hasSPIFFE := opts.SPIFFESocket != ""

	if hasCert != hasKey {
		return 0, errors.New("--client-cert and --client-key must be set together")
	}
	if hasCert && hasSPIFFE {
		return 0, errors.New("--client-cert and --spiffe-socket are mutually exclusive")
	}
	if hasSPIFFE {
		if opts.ServerSPIFFEIDRegex == "" {
			return 0, errors.New("--server-spiffe-id-regex is required when using SPIFFE")
		}
		return authSPIFFE, nil
	}
	if hasCert {
		return authFileMTLS, nil
	}
	if opts.ServerSPIFFEIDRegex != "" {
		return 0, errors.New("--server-spiffe-id-regex requires --spiffe-socket")
	}
	return authAnonymous, nil
}

// buildFileTLSConfig returns a *tls.Config configured for file-based
// mTLS: client certificate loaded from opts.ClientCert / opts.ClientKey,
// server verification roots taken from opts.CACert when set and the
// system trust store otherwise.
func buildFileTLSConfig(opts *options) (*tls.Config, error) {
	cert, err := tls.LoadX509KeyPair(opts.ClientCert, opts.ClientKey)
	if err != nil {
		return nil, fmt.Errorf("load client cert/key: %w", err)
	}
	cfg := &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS12,
	}
	if opts.CACert != "" {
		pool, err := loadCAPool(opts.CACert)
		if err != nil {
			return nil, err
		}
		cfg.RootCAs = pool
	}
	return cfg, nil
}

// buildAnonymousTLSConfig returns a *tls.Config that presents no client
// certificate; server verification honours --ca-cert when set. It
// returns nil when no TLS customisation is required, so the caller can
// fall back to http.Transport defaults.
func buildAnonymousTLSConfig(opts *options) (*tls.Config, error) {
	if opts.CACert == "" {
		return nil, nil
	}
	pool, err := loadCAPool(opts.CACert)
	if err != nil {
		return nil, err
	}
	return &tls.Config{
		RootCAs:    pool,
		MinVersion: tls.VersionTLS12,
	}, nil
}

// loadCAPool reads a PEM bundle from path and returns it as an
// *x509.CertPool. At least one certificate must parse successfully.
func loadCAPool(path string) (*x509.CertPool, error) {
	pem, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read --ca-cert %s: %w", path, err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(pem) {
		return nil, fmt.Errorf("--ca-cert %s: no PEM certificates parsed", path)
	}
	return pool, nil
}

// buildSPIFFETLSConfig opens an X509Source against the configured
// Workload API socket and returns an mTLS *tls.Config keyed off the
// resulting SVID. The X509Source is returned alongside the config so
// the caller can Close it on shutdown.
func buildSPIFFETLSConfig(ctx context.Context, opts *options) (*tls.Config, *workloadapi.X509Source, error) {
	re, err := regexp.Compile(opts.ServerSPIFFEIDRegex)
	if err != nil {
		return nil, nil, fmt.Errorf("--server-spiffe-id-regex: %w", err)
	}

	srcOpts := []workloadapi.X509SourceOption{
		workloadapi.WithClientOptions(workloadapi.WithAddr(normaliseSPIFFEAddr(opts.SPIFFESocket))),
	}
	src, err := workloadapi.NewX509Source(ctx, srcOpts...)
	if err != nil {
		return nil, nil, fmt.Errorf("open SPIFFE Workload API at %s: %w", opts.SPIFFESocket, err)
	}

	authorizer := tlsconfig.AdaptMatcher(func(id spiffeid.ID) error {
		if !re.MatchString(id.String()) {
			return fmt.Errorf("server SPIFFE ID %q does not match %q", id.String(), opts.ServerSPIFFEIDRegex)
		}
		return nil
	})
	cfg := tlsconfig.MTLSClientConfig(src, src, authorizer)
	return cfg, src, nil
}

// normaliseSPIFFEAddr accepts the user-facing --spiffe-socket value and
// returns a form acceptable to workloadapi.WithAddr. A bare path is
// treated as a unix socket.
func normaliseSPIFFEAddr(addr string) string {
	if strings.Contains(addr, "://") {
		return addr
	}
	return "unix://" + addr
}

// buildTLSConfig resolves the auth mode from opts and returns the
// corresponding *tls.Config. The returned cleanup function must be
// called when the client is no longer needed; it releases any resources
// (e.g. a SPIFFE X509Source) the auth mode acquired. The returned
// config may be nil in anonymous mode, meaning "use default TLS".
func buildTLSConfig(ctx context.Context, opts *options) (*tls.Config, func(), error) {
	mode, err := selectAuthMode(opts)
	if err != nil {
		return nil, nil, err
	}
	switch mode {
	case authFileMTLS:
		cfg, err := buildFileTLSConfig(opts)
		if err != nil {
			return nil, nil, err
		}
		return cfg, func() {}, nil
	case authSPIFFE:
		cfg, src, err := buildSPIFFETLSConfig(ctx, opts)
		if err != nil {
			return nil, nil, err
		}
		return cfg, func() { _ = src.Close() }, nil
	case authAnonymous:
		cfg, err := buildAnonymousTLSConfig(opts)
		if err != nil {
			return nil, nil, err
		}
		return cfg, func() {}, nil
	default:
		return nil, nil, fmt.Errorf("internal: unhandled auth mode %d", mode)
	}
}

// makeHTTPClient wraps a *tls.Config in an *http.Client suitable for
// use as ckapclient.Config.HTTPClient. When tlsCfg is nil, the default
// transport's TLS settings are used. Timeout comes from --timeout.
func makeHTTPClient(tlsCfg *tls.Config, timeout time.Duration) *http.Client {
	if tlsCfg == nil {
		return &http.Client{Timeout: timeout}
	}
	tr := http.DefaultTransport.(*http.Transport).Clone()
	tr.TLSClientConfig = tlsCfg
	return &http.Client{Transport: tr, Timeout: timeout}
}

// makeClientConfig turns the global flag set into a ckapclient.Config
// together with a cleanup func that releases any TLS resources acquired
// during construction. Callers must invoke cleanup when finished with
// the returned config (or the Client built from it).
func makeClientConfig(ctx context.Context, opts *options) (ckapclient.Config, func(), error) {
	if opts.BaseURL == "" {
		return ckapclient.Config{}, nil, fmt.Errorf("--base-url is required (or set %s)", envBaseURL)
	}
	tlsCfg, cleanup, err := buildTLSConfig(ctx, opts)
	if err != nil {
		return ckapclient.Config{}, nil, err
	}
	return ckapclient.Config{
		BaseURL:    opts.BaseURL,
		HTTPClient: makeHTTPClient(tlsCfg, opts.Timeout),
		UserAgent:  userAgent(),
	}, cleanup, nil
}

// newClient builds a *ckapclient.Client from opts. The returned cleanup
// must be called after the client is Closed; it releases the SPIFFE
// X509Source in SPIFFE mode and is a no-op otherwise.
func newClient(ctx context.Context, opts *options) (*ckapclient.Client, func(), error) {
	cfg, cleanup, err := makeClientConfig(ctx, opts)
	if err != nil {
		return nil, nil, err
	}
	client, err := ckapclient.NewClient(cfg)
	if err != nil {
		cleanup()
		return nil, nil, err
	}
	return client, cleanup, nil
}
