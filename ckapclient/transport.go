package ckapclient

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"

	"github.com/ldclabs/cose/key"
	"github.com/messier-42/cabe-go/cabe"
	"github.com/messier-42/cabe-go/ckapraw"
)

const (
	contentTypeCKAPCBOR    = "application/ckap+cbor"
	contentTypeEventStream = "text/event-stream"

	// maxResponseSize bounds the number of bytes read from a CKAP
	// response body. A well-formed CKAP response is well below this
	// limit; the cap protects clients against a hostile or malfunctioning
	// server streaming an unbounded amount of data to exhaust memory.
	maxResponseSize = 1 << 20 // 1 MiB
)

// readLimitedBody reads up to maxResponseSize+1 bytes from body. If the
// server sends more than that, we return an error rather than accepting
// an open-ended payload.
func readLimitedBody(body io.Reader) ([]byte, error) {
	data, err := io.ReadAll(io.LimitReader(body, maxResponseSize+1))
	if err != nil {
		return nil, err
	}
	if len(data) > maxResponseSize {
		return nil, fmt.Errorf("response exceeds %d bytes", maxResponseSize)
	}
	return data, nil
}

// doCBOR performs a CKAP POST request. reqBody is the wire-format request
// struct (e.g. ckapraw.ProgradeRequest); respBody is a pointer to the matching
// wire-format response struct into which the successful response is
// decoded. On non-2xx or decoding failure, doCBOR returns a *cabe.Error.
func (c *Client) doCBOR(ctx context.Context, op string, reqBody any, respBody any) error {
	body, err := key.MarshalCBOR(reqBody)
	if err != nil {
		return fmt.Errorf("marshal %s request: %w", op, err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.cfg.BaseURL+op, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("build %s request: %w", op, err)
	}
	req.Header.Set("Accept", contentTypeCKAPCBOR)
	req.Header.Set("Content-Type", contentTypeCKAPCBOR)
	req.Header.Set("User-Agent", c.cfg.UserAgent)

	httpResp, err := c.cfg.HTTPClient.Do(req)
	if err != nil {
		return newClientError(op, cabe.CodeReserved, 0, "", err)
	}
	defer httpResp.Body.Close() // best effort

	data, err := readLimitedBody(httpResp.Body)
	if err != nil {
		return fmt.Errorf("read %s response: %w", op, err)
	}

	if httpResp.StatusCode != http.StatusOK {
		return decodeServerError(op, httpResp.StatusCode, data)
	}

	if err := key.UnmarshalCBOR(data, respBody); err != nil {
		return fmt.Errorf("decode %s response: %w", op, err)
	}
	return nil
}

// doGetARINToken performs the GET /ARINToken request that initialises an
// ARIN stream on the Key Server.
func (c *Client) doGetARINToken(ctx context.Context) ([]byte, error) {
	const op = opARINToken

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.cfg.BaseURL+op, nil)
	if err != nil {
		return nil, fmt.Errorf("build %s request: %w", op, err)
	}
	req.Header.Set("Accept", contentTypeCKAPCBOR)
	req.Header.Set("User-Agent", c.cfg.UserAgent)

	httpResp, err := c.cfg.HTTPClient.Do(req)
	if err != nil {
		return nil, newClientError(op, cabe.CodeReserved, 0, "", err)
	}
	defer httpResp.Body.Close() // best effort

	data, err := readLimitedBody(httpResp.Body)
	if err != nil {
		return nil, fmt.Errorf("read %s response: %w", op, err)
	}

	if httpResp.StatusCode != http.StatusOK {
		return nil, decodeServerError(op, httpResp.StatusCode, data)
	}

	var resp struct {
		ARINToken []byte `cbor:"arinToken"`
	}
	if err := key.UnmarshalCBOR(data, &resp); err != nil {
		return nil, fmt.Errorf("decode %s response: %w", op, err)
	}
	return resp.ARINToken, nil
}

// decodeServerError attempts to parse a CKAP Error response body. If the
// body is a well-formed CKAP Error structure, its Code, Summary, and
// Details come through authoritatively via newServerError. Otherwise
// the response body is opaque to us and we fall back to a client-side
// Error carrying only the HTTP status for diagnostic context.
func decodeServerError(op string, statusCode int, body []byte) error {
	var serverErr ckapraw.Error
	if err := key.UnmarshalCBOR(body, &serverErr); err == nil {
		return newServerError(op, statusCode, serverErr)
	}
	return newClientError(op, cabe.CodeReserved, statusCode, "", nil)
}
