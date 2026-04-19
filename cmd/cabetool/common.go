package main

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/messier-42/cabe-go/attrset"
	"github.com/spf13/cobra"
	"gopkg.in/yaml.v3"
)

// options holds resolved values for the global flags. A single instance
// is threaded into every subcommand via cobra's PersistentPreRunE so
// subcommands read from it instead of the raw flag set. The TLS and
// SPIFFE fields are consumed by buildTLSConfig in client.go.
type options struct {
	BaseURL             string
	CACert              string
	ClientCert          string
	ClientKey           string
	SPIFFESocket        string
	ServerSPIFFEIDRegex string
	Timeout             time.Duration
	LogFormat           string
	LogSeverity         string
	Verbose             bool
	JSON                bool
}

const (
	envBaseURL             = "CABE_BASE_URL"
	envCACert              = "CABE_CA_CERT"
	envClientCert          = "CABE_CLIENT_CERT"
	envClientKey           = "CABE_CLIENT_KEY"
	envSPIFFESocket        = "SPIFFE_ENDPOINT_SOCKET"
	envServerSPIFFEIDRegex = "CABE_SERVER_SPIFFE_ID_REGEX"
	envTimeout             = "CABE_TIMEOUT"
	envLogFormat           = "CABE_LOG_FORMAT"
	envLogSeverity         = "CABE_LOG_SEVERITY"
)

// registerGlobalFlags installs the flags listed in the cabetool design
// doc onto cmd as persistent flags. The resulting values are bound to
// opts so that cobra's PersistentPreRunE can act on a single options
// struct rather than re-reading flags.
func registerGlobalFlags(cmd *cobra.Command, opts *options) {
	f := cmd.PersistentFlags()
	f.StringVar(&opts.BaseURL, "base-url", "", "CKAP base URL (required for commands that contact a key server)")
	f.StringVar(&opts.CACert, "ca-cert", "", "PEM bundle for verifying the server; ignored under SPIFFE")
	f.StringVar(&opts.ClientCert, "client-cert", "", "client certificate (PEM); requires --client-key")
	f.StringVar(&opts.ClientKey, "client-key", "", "client private key (PEM)")
	f.StringVar(&opts.SPIFFESocket, "spiffe-socket", "", "SPIFFE Workload API socket; mutually exclusive with --client-cert")
	f.StringVar(&opts.ServerSPIFFEIDRegex, "server-spiffe-id-regex", "", "RE2 regex required for SPIFFE; matched against the server SVID SPIFFE ID")
	f.DurationVar(&opts.Timeout, "timeout", 30*time.Second, "per-request timeout")
	f.StringVar(&opts.LogFormat, "log-format", "text", `log format: "text" or "json"`)
	f.StringVar(&opts.LogSeverity, "log-severity", "warn", `log severity: "debug", "info", "warn", or "error"`)
	f.BoolVarP(&opts.Verbose, "verbose", "v", false, `shorthand for --log-severity debug; exclusive with --log-severity`)
	f.BoolVarP(&opts.JSON, "json", "J", false, "emit JSON output rather than YAML")
}

// bindEnv applies env-var fallback to a flag: if the flag was not
// explicitly set on the command line and the env var is non-empty, the
// env value replaces the flag's current value. Precedence: flag > env
// > default.
//
// The flag is resolved by searching cmd.Flags() first (which cobra
// fills with inherited parent persistent flags after Execute) and
// falling back to cmd.PersistentFlags() (which holds flags registered
// directly on cmd). This covers both the real runtime case (called
// from a subcommand's PersistentPreRunE) and direct unit-test usage
// (called on a bare command that registered flags itself).
func bindEnv(cmd *cobra.Command, flag, env string) {
	f := cmd.Flags().Lookup(flag)
	if f == nil {
		f = cmd.PersistentFlags().Lookup(flag)
	}
	if f == nil {
		// Programmer error; fail loudly at startup.
		panic(fmt.Sprintf("bindEnv: flag %q not registered", flag))
	}
	if f.Changed {
		return
	}
	v, ok := os.LookupEnv(env)
	if !ok || v == "" {
		return
	}
	if err := f.Value.Set(v); err != nil {
		// Don't swallow; cobra's PersistentPreRunE will surface it.
		panic(fmt.Sprintf("bindEnv: invalid %s=%q: %v", env, v, err))
	}
}

// applyEnv overlays environment variables onto opts after cobra has
// parsed flags. Called from the root command's PersistentPreRunE.
func applyEnv(cmd *cobra.Command) {
	bindEnv(cmd, "base-url", envBaseURL)
	bindEnv(cmd, "ca-cert", envCACert)
	bindEnv(cmd, "client-cert", envClientCert)
	bindEnv(cmd, "client-key", envClientKey)
	bindEnv(cmd, "spiffe-socket", envSPIFFESocket)
	bindEnv(cmd, "server-spiffe-id-regex", envServerSPIFFEIDRegex)
	bindEnv(cmd, "timeout", envTimeout)
	bindEnv(cmd, "log-format", envLogFormat)
	bindEnv(cmd, "log-severity", envLogSeverity)
}

// resolveLogConfig applies the -v / --log-severity mutual-exclusion
// rule and parses the resulting strings.
func resolveLogConfig(cmd *cobra.Command, opts *options) (LogConfig, error) {
	// -v is a shorthand for --log-severity debug. It is an error to
	// set both to distinguishable values on the same invocation.
	if opts.Verbose {
		lsFlag := cmd.Flags().Lookup("log-severity")
		if lsFlag != nil && lsFlag.Changed && opts.LogSeverity != "debug" {
			return LogConfig{}, fmt.Errorf("--verbose and --log-severity=%s are mutually exclusive", opts.LogSeverity)
		}
		opts.LogSeverity = "debug"
	}
	format, err := ParseFormat(opts.LogFormat)
	if err != nil {
		return LogConfig{}, err
	}
	severity, err := ParseSeverity(opts.LogSeverity)
	if err != nil {
		return LogConfig{}, err
	}
	return LogConfig{Format: format, Severity: severity}, nil
}

// parseAttrSpec parses a single -A/--attr argument. The accepted form
// is KEY=TYPE:VALUE with TYPE in {str, string, int, bool}. str and
// string are aliases. The value is parsed into the corresponding Go
// type: string, int64, or bool.
//
// Attribute key validity is deferred to attrset.ValidName via the
// caller building an attrset.Set from the collected pairs; this
// function only splits the spec and types the value.
func parseAttrSpec(s string) (key string, value any, err error) {
	eq := strings.IndexByte(s, '=')
	if eq <= 0 {
		return "", nil, fmt.Errorf("attribute spec %q: missing '='", s)
	}
	key = s[:eq]
	rest := s[eq+1:]
	typ, val, ok := strings.Cut(rest, ":")
	if !ok {
		return "", nil, fmt.Errorf("attribute spec %q: missing ':' after type", s)
	}
	switch typ {
	case "str", "string":
		return key, val, nil
	case "int":
		n, err := strconv.ParseInt(val, 10, 64)
		if err != nil {
			return "", nil, fmt.Errorf("attribute %q: invalid int value %q: %w", key, val, err)
		}
		return key, n, nil
	case "bool":
		switch strings.ToLower(val) {
		case "true":
			return key, true, nil
		case "false":
			return key, false, nil
		default:
			return "", nil, fmt.Errorf("attribute %q: invalid bool value %q (want true or false)", key, val)
		}
	default:
		return "", nil, fmt.Errorf("attribute %q: unknown type %q (want str, string, int, or bool)", key, typ)
	}
}

// buildAttributeSet collects a slice of -A specs into an attrset.Set.
// Duplicate keys across specs are an error (CABE-ARCH forbids
// duplicate keys in an attribute set). Empty slice yields the empty
// Set.
func buildAttributeSet(specs []string) (attrset.Set, error) {
	m := make(map[string]any, len(specs))
	for _, s := range specs {
		k, v, err := parseAttrSpec(s)
		if err != nil {
			return attrset.Set{}, err
		}
		if _, dup := m[k]; dup {
			return attrset.Set{}, fmt.Errorf("attribute %q specified more than once", k)
		}
		m[k] = v
	}
	return attrset.New(m)
}

// writeStructured marshals v and writes it to w. The format is YAML
// unless opts.JSON is set. Binary fields ([]byte in the serialised
// shape) must be encoded by the caller in a form both marshallers
// accept; see base64URL for the usual choice.
//
// YAML documents are prefixed with "---\n" so callers that write
// multiple documents to the same stream produce a valid multi-document
// YAML file.
func writeStructured(w io.Writer, v any, jsonMode bool) error {
	if jsonMode {
		enc := json.NewEncoder(w)
		enc.SetIndent("", "  ")
		return enc.Encode(v)
	}
	if _, err := io.WriteString(w, "---\n"); err != nil {
		return err
	}
	enc := yaml.NewEncoder(w)
	enc.SetIndent(2)
	if err := enc.Encode(v); err != nil {
		return err
	}
	return enc.Close()
}

// base64URL encodes b as unpadded base64url, the form this CLI uses
// uniformly for binary fields in YAML and JSON output.
func base64URL(b []byte) string {
	return base64.RawURLEncoding.EncodeToString(b)
}

// readInput reads all bytes from path, or from stdin when path is
// empty or "-". The stdin fallback is the caller-supplied reader so
// tests can drive input in-process via cobra's Command.InOrStdin().
func readInput(path string, stdin io.Reader) ([]byte, error) {
	if path == "" || path == "-" {
		return io.ReadAll(stdin)
	}
	return os.ReadFile(path)
}

// writeOutput writes data to path, or to stdout (the caller-supplied
// writer) when path is empty or "-".
func writeOutput(path string, data []byte, stdout io.Writer) error {
	if path == "" || path == "-" {
		_, err := stdout.Write(data)
		return err
	}
	return os.WriteFile(path, data, 0o644)
}

// openMetaOut returns an io.WriteCloser for the --meta-out flag.
// Special cases:
//
//   - "" or "-" → stderr (Close is a no-op).
//   - "/dev/null" → io.Discard wrapped as a WriteCloser. Explicit so
//     environments without a real /dev/null still work.
//
// Anything else is a file path opened for writing with 0o644.
func openMetaOut(path string, stderr io.Writer) (io.WriteCloser, error) {
	if path == "" || path == "-" {
		return nopWriteCloser{stderr}, nil
	}
	if path == "/dev/null" {
		return nopWriteCloser{io.Discard}, nil
	}
	return os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o644)
}

type nopWriteCloser struct{ io.Writer }

func (nopWriteCloser) Close() error { return nil }
