package cabe

// ARINEventType is the type of an ARIN event.
type ARINEventType string

const (
	// ARINEventInvalidate indicates that a Lease previously issued
	// by a Key Server has been invalidated.
	ARINEventInvalidate ARINEventType = "invalidate"
)

// ARINEvent represents an event delivered over an ARIN (Asynchronous
// Resolution Invalidation Notification) stream.
type ARINEvent struct {
	// Event is the SSE event type, e.g. "invalidate".
	Event ARINEventType

	// ID is the event ID assigned by the underlying event transport.
	// For HTTP SSE, this is the SSE "id" field.
	ID string

	// Data is the SSE data payload. For the ARINEventInvalidate
	// event type, it contains a lease ID as previously indicated in
	// a Lease issued by the Key Server.
	Data string
}
