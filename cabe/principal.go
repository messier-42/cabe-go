package cabe

// PrincipalInfo is the result of a CKAP GetSelf operation and gives a
// Key Server's view of the calling Principal.
type PrincipalInfo struct {
	// URI uniquely identifies the Principal
	URI string

	// Claims are the claims attached to the principal. This field
	// may be empty if the Key Server chose not to disclose the Claims.
	Claims map[string]any

	// ServerInfo is free-form information about the Key Server.
	// It may include information such as the Key Server's software version,
	// etc.
	ServerInfo map[string]any
}
