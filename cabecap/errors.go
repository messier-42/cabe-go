package cabecap

import "errors"

// ErrInvalidEnvelope is returned by Decapsulate when the input bytes do
// not parse as a valid CBES envelope.
var ErrInvalidEnvelope = errors.New("cabecap: invalid envelope")
