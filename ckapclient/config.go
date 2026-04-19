// Package ckapclient provides a thin protocol-surface client for the CABE
// Key Access Protocol (CKAP).
//
// Each client method maps exactly to one CKAP operation; there is no
// caching functionality of any kind. For a higher-level API suitable for
// most applications requiring encapsulation/decapsulation services, see
// the cabecap package.
package ckapclient

import "net/http"

// Config specifies configuration for a [Client].
type Config struct {
	// Required; must be specified. BaseURL is the CKAP base URL. A trailing slash
	// is automatically appended if not present.
	BaseURL string

	// HTTPClient can be used to specify a custom HTTP client to use for
	// outgoing requests. If nil, a default client is used.
	HTTPClient *http.Client

	// UserAgent, if non-empty, is prepended (with a trailing space) to
	// the default User-Agent string this package sends. The default
	// itself has the form
	//
	//	cabe-go go/<goversion> <goos>/<goarch>
	//
	// e.g. "cabe-go go/1.24.4 linux/amd64". A non-empty UserAgent lets
	// an embedding application identify itself, e.g. setting
	// UserAgent = "cabetool/0.1" yields the wire value
	// "cabetool/0.1 cabe-go go/1.24.4 linux/amd64".
	//
	// After NewClient returns, Client.Config().UserAgent holds the
	// fully composed string that is actually sent.
	UserAgent string
}
