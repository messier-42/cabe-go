package ckaphttp_test

import (
	"context"
	"net/http/httptest"
	"testing"

	"github.com/fxamacker/cbor/v2"

	"github.com/messier-42/cabe-go/cabe"
	"github.com/messier-42/cabe-go/ckap"
	"github.com/messier-42/cabe-go/ckaphttp"
)

func TestWriteErrorHTTPSetsHeadersStatusAndCBORBody(t *testing.T) {
	w := httptest.NewRecorder()
	ckaphttp.WriteErrorHTTP(context.Background(), ckap.Error{
		Code:    cabe.CodeUnauthorized,
		Summary: "unauthorized",
	}, w, 401)

	if got, want := w.Code, 401; got != want {
		t.Errorf("status = %d, want %d", got, want)
	}
	if got := w.Header().Get("Content-Type"); got != ckap.MediaType {
		t.Errorf("Content-Type = %q, want %q", got, ckap.MediaType)
	}

	var body struct {
		Kind      string         `cbor:"kind"`
		ErrorCode int            `cbor:"errorCode"`
		Summary   string         `cbor:"summary"`
		Details   map[string]any `cbor:"details,omitempty"`
	}
	if err := cbor.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode body: %v", err)
	}
	if body.Kind != "Error" {
		t.Errorf("Kind = %q, want %q", body.Kind, "Error")
	}
	if cabe.Code(body.ErrorCode) != cabe.CodeUnauthorized {
		t.Errorf("ErrorCode = %d, want CodeUnauthorized (%d)", body.ErrorCode, cabe.CodeUnauthorized)
	}
	if body.Summary != "unauthorized" {
		t.Errorf("Summary = %q, want %q", body.Summary, "unauthorized")
	}
	if body.Details != nil {
		t.Errorf("Details = %v, want nil (omitempty)", body.Details)
	}
}

// TestWriteErrorHTTPIncludesDetails pins that non-nil Details is carried
// on the wire under the "details" CBOR key.
func TestWriteErrorHTTPIncludesDetails(t *testing.T) {
	w := httptest.NewRecorder()
	ckaphttp.WriteErrorHTTP(context.Background(), ckap.Error{
		Code:    cabe.CodeInternal,
		Summary: "internal error",
		Details: map[string]any{"trace": "abc123"},
	}, w, 500)

	var body struct {
		Details map[string]any `cbor:"details"`
	}
	if err := cbor.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode body: %v", err)
	}
	if got, want := body.Details["trace"], "abc123"; got != want {
		t.Errorf("Details[trace] = %v, want %v", got, want)
	}
}

// TestWriteErrorHTTPOmitsServerLocalFields pins that the Op and Err
// server-local diagnostic fields never travel on the wire. Leaking
// them would undermine the "detailed messages belong in logs"
// contract that motivates the split.
func TestWriteErrorHTTPOmitsServerLocalFields(t *testing.T) {
	w := httptest.NewRecorder()
	ckaphttp.WriteErrorHTTP(context.Background(), ckap.Error{
		Code:    cabe.CodePolicyDenied,
		Summary: "access denied",
		Op:      "Prograde",
	}, w, 403)

	var raw map[string]any
	if err := cbor.Unmarshal(w.Body.Bytes(), &raw); err != nil {
		t.Fatalf("decode body: %v", err)
	}
	if _, ok := raw["op"]; ok {
		t.Errorf("op key leaked on wire: %v", raw)
	}
	if _, ok := raw["err"]; ok {
		t.Errorf("err key leaked on wire: %v", raw)
	}
}
