package ckapraw

// Kinded is implemented by any CKAP wire-struct that carries a "kind"
// discriminator. GetKind reports the value currently held in the
// receiver's Kind field; DefaultKind reports the canonical Kind* string
// for this type (independent of the field's current value).
//
// The two differ only when a caller is inspecting a partially-filled or
// just-decoded struct: DefaultKind lets generic code know what kind
// string the struct ought to carry in a generic fashion.
//
// All ckapraw request/response types (plus Error) satisfy this
// interface.
type Kinded interface {
	GetKind() string
	DefaultKind() string
}

func (r *GetSelfRequest) GetKind() string     { return r.Kind }
func (*GetSelfRequest) DefaultKind() string   { return KindGetSelfRequest }
func (r *GetSelfResponse) GetKind() string    { return r.Kind }
func (*GetSelfResponse) DefaultKind() string  { return KindGetSelfResponse }
func (r *ProgradeRequest) GetKind() string    { return r.Kind }
func (*ProgradeRequest) DefaultKind() string  { return KindProgradeRequest }
func (r *ProgradeResponse) GetKind() string   { return r.Kind }
func (*ProgradeResponse) DefaultKind() string { return KindProgradeResponse }
func (r *RetrogradeRequest) GetKind() string  { return r.Kind }
func (*RetrogradeRequest) DefaultKind() string {
	return KindRetrogradeRequest
}
func (r *RetrogradeResponse) GetKind() string { return r.Kind }
func (*RetrogradeResponse) DefaultKind() string {
	return KindRetrogradeResponse
}
func (r *AssistedEncapsulateRequest) GetKind() string { return r.Kind }
func (*AssistedEncapsulateRequest) DefaultKind() string {
	return KindAssistedEncapsulateRequest
}
func (r *AssistedEncapsulateResponse) GetKind() string { return r.Kind }
func (*AssistedEncapsulateResponse) DefaultKind() string {
	return KindAssistedEncapsulateResponse
}
func (r *AssistedDecapsulateRequest) GetKind() string { return r.Kind }
func (*AssistedDecapsulateRequest) DefaultKind() string {
	return KindAssistedDecapsulateRequest
}
func (r *AssistedDecapsulateResponse) GetKind() string { return r.Kind }
func (*AssistedDecapsulateResponse) DefaultKind() string {
	return KindAssistedDecapsulateResponse
}
func (r *Error) GetKind() string   { return r.Kind }
func (*Error) DefaultKind() string { return KindError }
