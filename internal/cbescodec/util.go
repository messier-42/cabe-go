package cbescodec

import (
	"crypto/rand"

	"github.com/ldclabs/cose/cose"
	"github.com/ldclabs/cose/iana"
	"github.com/ldclabs/cose/key"
)

// contentType reads the COSE content-type header from h, accepting both
// the string and the []byte CBOR encodings. Returns "" when the header
// is absent or carries an unexpected type.
func contentType(h cose.Headers) string {
	v := h.Get(iana.HeaderParameterContentType)
	switch x := v.(type) {
	case string:
		return x
	case []byte:
		return string(x)
	default:
		return ""
	}
}

// Generate cryptographically secure random bytes.
func randomBytes(n int) ([]byte, error) {
	buf := make([]byte, n)
	if _, err := rand.Read(buf); err != nil {
		return nil, err
	}
	return buf, nil
}

// decodeCOSEKey parses a CBOR-serialised COSE_Key (the RawCOSEKey bytes
// carried by cabe.LKAINonCaptive) into a usable key.Key value.
func decodeCOSEKey(raw []byte) (key.Key, error) {
	var k key.Key
	if err := key.UnmarshalCBOR(raw, &k); err != nil {
		return nil, err
	}
	return k, nil
}
