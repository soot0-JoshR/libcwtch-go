package features

import "errors"

// Response is a wrapper to better semantically convey the response type...
type Response error

const errorSeparator = "."

// ConstructResponse is a helper function for creating Response structures.
func ConstructResponse(prefix string, error string) Response {
	return errors.New(prefix + errorSeparator + error)
}
