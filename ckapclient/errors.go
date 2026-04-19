package ckapclient

import (
	"maps"

	"github.com/messier-42/cabe-go/cabe"
	"github.com/messier-42/cabe-go/ckapraw"
)

// newClientError builds a *cabe.Error describing a failure that occurred
// on the client side (e.g. a connection failure, an HTTP non-2xx
// response whose body did not parse as a CKAP Error structure, or a
// local marshaling problem). The caller supplies the fields; any
// server-provided Details must not be used here, since by definition
// the server did not produce a parseable Error for this path.
func newClientError(op string, code cabe.Code, statusCode int, summary string, underlying error) *cabe.Error {
	return &cabe.Error{
		Op:      op,
		Code:    code,
		Summary: summary,
		Details: httpStatusDetails(statusCode),
		Err:     underlying,
	}
}

// newServerError builds a *cabe.Error from a parsed CKAP Error response.
// The CKAP Error wire structure is defined by the spec and is the
// authoritative source for Code, Summary, and Details; this function
// passes those through as-is. The observed HTTP status is merged into
// Details under the reserved "httpStatus" key for operator-level
// diagnostic visibility, but only when the server did not already
// populate that key itself (the server's own value always wins).
func newServerError(op string, statusCode int, serverErr ckapraw.Error) *cabe.Error {
	details := serverErr.Details
	if statusCode != 0 {
		if _, already := details["httpStatus"]; !already {
			if details == nil {
				details = map[string]any{}
			} else {
				// Copy so we do not mutate the caller's map.
				cp := make(map[string]any, len(details)+1)
				maps.Copy(cp, details)
				details = cp
			}
			details["httpStatus"] = statusCode
		}
	}
	return &cabe.Error{
		Op:      op,
		Code:    cabe.Code(serverErr.ErrorCode),
		Summary: serverErr.Summary,
		Details: details,
		Err:     nil,
	}
}

// httpStatusDetails returns a Details map carrying the HTTP status code
// for a client-side structured Error if and only if a non-zero status
// was observed. Used only by newClientError; server-side errors carry
// whatever Details the server chose to include.
func httpStatusDetails(statusCode int) map[string]any {
	if statusCode == 0 {
		return nil
	}
	return map[string]any{"httpStatus": statusCode}
}
