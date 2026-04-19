// Package ckapraw defines the request and response structures
// for CBOR-marshalled CKAP.
//
// This package should not be used directly and its stability
// is not guaranteed.
package ckapraw

import "github.com/ldclabs/cose/key"

type AttributeSet map[string]any

type GetSelfRequest struct {
	Kind string `cbor:"kind"`
}

type Principal struct {
	URI    string         `cbor:"uri"`
	Claims map[string]any `cbor:"claims,omitempty"`
}

type GetSelfResponse struct {
	Kind       string         `cbor:"kind"`
	Principal  Principal      `cbor:"principal"`
	ServerInfo map[string]any `cbor:"serverInfo"`
}

type Error struct {
	ErrorCode int            `cbor:"errorCode"`
	Summary   string         `cbor:"summary"`
	Details   map[string]any `cbor:"details,omitempty"`
}

type ProgradeRequest struct {
	Kind         string       `cbor:"kind"`
	AttributeSet AttributeSet `cbor:"attributeSet"`
	ARINToken    []byte       `cbor:"arinToken,omitempty"`
}

type ProgradeResponse struct {
	Kind  string `cbor:"kind"`
	Lease Lease  `cbor:"lease"`
}

type RetrogradeRequest struct {
	Kind         string       `cbor:"kind"`
	AttributeSet AttributeSet `cbor:"attributeSet"`
	LeaseRef     []byte       `cbor:"leaseRef"`
}

type RetrogradeResponse struct {
	Kind         string       `cbor:"kind"`
	AttributeSet AttributeSet `cbor:"attributeSet,omitempty"`
	LKAI         LKAI         `cbor:"lkai"`
}

type AssistedEncapsulateRequest struct {
	Kind                string `cbor:"kind"`
	LeaseKeyAccessToken []byte `cbor:"leaseKeyAccessToken"`
	CEK                 []byte `cbor:"cek"`
}

type AssistedEncapsulateResponse struct {
	Kind       string `cbor:"kind"`
	WrappedCEK []byte `cbor:"wrappedCEK"`
}

type AssistedDecapsulateRequest struct {
	Kind                string `cbor:"kind"`
	LeaseKeyAccessToken []byte `cbor:"leaseKeyAccessToken"`
	WrappedCEK          []byte `cbor:"wrappedCEK"`
}

type AssistedDecapsulateResponse struct {
	Kind string `cbor:"kind"`
	CEK  []byte `cbor:"cek"`
}

type Lease struct {
	LeaseID      string       `cbor:"leaseID,omitempty"`
	LeaseRef     []byte       `cbor:"leaseRef"`
	AttributeSet AttributeSet `cbor:"attributeSet,omitempty"`
	LKAI         LKAI         `cbor:"lkai"`
	Expiry       int64        `cbor:"expiry"`
}

type LKAI struct {
	NonCaptive *LKAINonCaptive `cbor:"nonCaptive,omitempty"`
	Captive    *LKAIActive     `cbor:"captive,omitempty"`
}

type LKAINonCaptive struct {
	LeaseKey COSEKey `cbor:"leaseKey"`
}

type LKAIActive struct {
	LeaseKeyAccessToken []byte `cbor:"leaseKeyAccessToken"`
}

type COSEKey = key.Key
