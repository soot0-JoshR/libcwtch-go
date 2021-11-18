package constants

// We offer "un-passworded" profiles but our storage encrypts everything with a password. We need an agreed upon
// password to use in that case, that the app case use behind the scenes to password and unlock with
// https://docs.openprivacy.ca/cwtch-security-handbook/profile_encryption_and_storage.html
const DefactoPasswordForUnencryptedProfiles = "be gay do crime"

const (
	// StatusSuccess is an event response for event.Status signifying a call succeeded
	StatusSuccess = "success"
	// StatusError is an event response for event.Status signifying a call failed in error, ideally accompanied by a event.Error
	StatusError = "error"
)
