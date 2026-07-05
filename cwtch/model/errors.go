package model

// Error models some common errors that need to be handled by applications that use Cwtch
type Error string

// Error is the error interface
func (e Error) Error() string {
	return string(e)
}

// Error definitions
const (
	InvalidEd25519PublicKey    = Error("InvalidEd25519PublicKey")
	InconsistentKeyBundleError = Error("InconsistentKeyBundleError")
)
