// Package ckaphttp provides CKAP-related utilities which are specific to
// the HTTP transport.
package ckaphttp

import (
	"context"
	"log/slog"
	"net/http"

	"github.com/fxamacker/cbor/v2"
	"github.com/messier-42/cabe-go/ckap"
	"github.com/messier-42/cabe-go/ckapraw"
)

// WriteErrorHTTP writes e as a CKAP Error transported in an HTTP response
// with the given HTTP status.
func WriteErrorHTTP(ctx context.Context, e ckap.Error, w http.ResponseWriter, httpStatus int) {
	body, err := cbor.Marshal(ckapraw.Error{
		Kind:      ckapraw.KindError,
		ErrorCode: int(e.Code),
		Summary:   e.Summary,
		Details:   e.Details,
	})

	if err != nil {
		// CBOR marshal of a fixed-shape struct should never fail; if
		// it does the cleanest fallback is a header-only response so
		// the client at least sees the status code.
		slog.ErrorContext(ctx, "cabe: error body marshal failed", "error", err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", ckap.MediaType)
	w.WriteHeader(httpStatus)

	if _, err = w.Write(body); err != nil {
		slog.DebugContext(ctx, "cabe: error body write failed", "error", err)
	}
}
