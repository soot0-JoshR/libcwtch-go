package model

import (
	"crypto/sha256"
	"encoding/base64"
)

// CalculateContentHash derives a hash using the author and the message body. It is intended to be
// globally referencable in the context of a single conversation
func CalculateContentHash(author string, messageBody string) string {
	content := []byte(author + messageBody)
	contentBasedHash := sha256.Sum256(content)
	return base64.StdEncoding.EncodeToString(contentBasedHash[:])
}
