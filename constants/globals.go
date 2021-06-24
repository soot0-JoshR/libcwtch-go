package constants

// We offer "un-passworded" profiles but our storage encrypts everything with a password. We need an agreed upon
// password to use in that case, that the app case use behind the scenes to password and unlock with
const DefactoPasswordForUnencryptedProfiles = "be gay do crime"
