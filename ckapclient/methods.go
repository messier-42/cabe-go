package ckapclient

import (
	"context"
	"fmt"

	"github.com/messier-42/cabe-go/cabe"
	"github.com/messier-42/cabe-go/ckap"
	"github.com/messier-42/cabe-go/ckapraw"
)

// checkKind validates the kind field on a CKAP response against the
// value required by the spec. A mismatch indicates the peer violated
// the Request/Response pairing: treat it as a client-side protocol
// error so callers receive a structured *ckap.Error rather than a
// successful-looking zero-valued response.
func checkKind(op, got, want string) error {
	if got != want {
		return newClientError(op, cabe.CodeReserved, 0,
			fmt.Sprintf("response kind = %q, want %q", got, want), nil)
	}
	return nil
}

// GetSelf executes a CKAP GetSelf operation and returns the Key Server's
// view of the calling principal.
func (c *Client) GetSelf(ctx context.Context, _ ckap.GetSelfRequest) (*ckap.GetSelfResponse, error) {
	var resp *ckap.GetSelfResponse
	err := c.withCtx(ctx, func(ctx context.Context) error {
		var wire ckapraw.GetSelfResponse
		if err := c.doCBOR(ctx, opGetSelf, ckapraw.GetSelfRequest{Kind: opGetSelf + kindRequestSuffix}, &wire); err != nil {
			return err
		}
		if err := checkKind(opGetSelf, wire.Kind, opGetSelf+kindResponseSuffix); err != nil {
			return err
		}
		resp = &ckap.GetSelfResponse{
			PrincipalInfo: cabe.PrincipalInfo{
				URI:        wire.Principal.URI,
				Claims:     wire.Principal.Claims,
				ServerInfo: wire.ServerInfo,
			},
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return resp, nil
}

// Prograde performs a CKAP Prograde key resolution operation. If
// req.ARINToken is specified, the resulting Lease is subscribed into the
// corresponding ARIN Stream.
func (c *Client) Prograde(ctx context.Context, req ckap.ProgradeRequest) (*ckap.ProgradeResponse, error) {
	var resp *ckap.ProgradeResponse
	err := c.withCtx(ctx, func(ctx context.Context) error {
		var wire ckapraw.ProgradeResponse
		if err := c.doCBOR(ctx, opPrograde, ckapraw.ProgradeRequest{
			Kind:         opPrograde + kindRequestSuffix,
			AttributeSet: ckapraw.AttributeSet(req.AttributeSet.Map()),
			ARINToken:    req.ARINToken,
		}, &wire); err != nil {
			return err
		}
		if err := checkKind(opPrograde, wire.Kind, opPrograde+kindResponseSuffix); err != nil {
			return err
		}
		lease, err := wire.Lease.ToCABE()
		if err != nil {
			return err
		}
		resp = &ckap.ProgradeResponse{Lease: lease}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return resp, nil
}

// Retrograde performs a CKAP Retrograde key resolution operation.
func (c *Client) Retrograde(ctx context.Context, req ckap.RetrogradeRequest) (*ckap.RetrogradeResponse, error) {
	var resp *ckap.RetrogradeResponse
	err := c.withCtx(ctx, func(ctx context.Context) error {
		var wire ckapraw.RetrogradeResponse
		if err := c.doCBOR(ctx, opRetrograde, ckapraw.RetrogradeRequest{
			Kind:         opRetrograde + kindRequestSuffix,
			AttributeSet: ckapraw.AttributeSet(req.AttributeSet.Map()),
			LeaseRef:     req.LeaseRef,
		}, &wire); err != nil {
			return err
		}
		if err := checkKind(opRetrograde, wire.Kind, opRetrograde+kindResponseSuffix); err != nil {
			return err
		}
		lkai, err := wire.LKAI.ToCABE()
		if err != nil {
			return err
		}
		resp = &ckap.RetrogradeResponse{LKAI: lkai}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return resp, nil
}

// AssistedEncapsulate performs a CKAP AssistedEncapsulate operation,
// wrapping the given COSE Content Encryption Key under the captive Lease Key
// identified by a given Lease Key Access Token (LKAT).
func (c *Client) AssistedEncapsulate(ctx context.Context, req ckap.AssistedEncapsulateRequest) (*ckap.AssistedEncapsulateResponse, error) {
	var resp *ckap.AssistedEncapsulateResponse
	err := c.withCtx(ctx, func(ctx context.Context) error {
		var wire ckapraw.AssistedEncapsulateResponse
		if err := c.doCBOR(ctx, opAssistedEncapsulate, ckapraw.AssistedEncapsulateRequest{
			Kind:                opAssistedEncapsulate + kindRequestSuffix,
			LeaseKeyAccessToken: req.LKAT,
			CEK:                 req.CEK,
		}, &wire); err != nil {
			return err
		}
		if err := checkKind(opAssistedEncapsulate, wire.Kind, opAssistedEncapsulate+kindResponseSuffix); err != nil {
			return err
		}
		resp = &ckap.AssistedEncapsulateResponse{WrappedCEK: wire.WrappedCEK}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return resp, nil
}

// AssistedDecapsulate performs a CKAP AssistedDecapsulate operation,
// unwrapping the given wrapped COSE Content Encryption Key under the captive Lease Key
// identified by a given Lease Key Access Token (LKAT).
func (c *Client) AssistedDecapsulate(ctx context.Context, req ckap.AssistedDecapsulateRequest) (*ckap.AssistedDecapsulateResponse, error) {
	var resp *ckap.AssistedDecapsulateResponse
	err := c.withCtx(ctx, func(ctx context.Context) error {
		var wire ckapraw.AssistedDecapsulateResponse
		if err := c.doCBOR(ctx, opAssistedDecapsulate, ckapraw.AssistedDecapsulateRequest{
			Kind:                opAssistedDecapsulate + kindRequestSuffix,
			LeaseKeyAccessToken: req.LKAT,
			WrappedCEK:          req.WrappedCEK,
		}, &wire); err != nil {
			return err
		}
		if err := checkKind(opAssistedDecapsulate, wire.Kind, opAssistedDecapsulate+kindResponseSuffix); err != nil {
			return err
		}
		resp = &ckap.AssistedDecapsulateResponse{CEK: wire.CEK}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return resp, nil
}

// GetARINToken obtains a fresh ARIN Token from the key server. The token
// is an opaque byte string that identifies an event stream on the server.
// It is quoted in subsequent Prograde requests (via
// ckap.ProgradeRequest.ARINToken) and when opening an ARIN Stream.
//
// The CKAP ARINTokenResponse structure has no kind field, so no kind
// validation applies here.
func (c *Client) GetARINToken(ctx context.Context, _ ckap.GetARINTokenRequest) (*ckap.GetARINTokenResponse, error) {
	var resp *ckap.GetARINTokenResponse
	err := c.withCtx(ctx, func(ctx context.Context) error {
		tok, err := c.doGetARINToken(ctx)
		if err != nil {
			return err
		}
		resp = &ckap.GetARINTokenResponse{Token: tok}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return resp, nil
}
