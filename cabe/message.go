package cabe

import "github.com/messier-42/cabe-go/attrset"

// Message represents a plaintext message which is to be encapsulated by
// CABE, or which has been decapsulated.
type Message struct {
	// The application-specific payload of the Message. This is an arbitrary
	// octet string.
	Payload []byte

	// The Attribute Set of the Message used to characterise it for the
	// purposes of CABE policy enforcement and key management.
	Attributes attrset.Set

	// The content type of the message, which should be a MIME type
	// identifying the application-specific format of the Payload.
	// However, it may be left empty.
	ContentType string
}
