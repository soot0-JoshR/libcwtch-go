package groups

import (
	"encoding/json"
	"git.openprivacy.ca/cwtch.im/tapir"
	"git.openprivacy.ca/cwtch.im/tapir/primitives/privacypass"
)

// CwtchServerSyncedCapability is used to indicate that a given cwtch server is synced
const CwtchServerSyncedCapability = tapir.Capability("CwtchServerSyncedCapability")

// GroupInvite provides a structured type for communicating group information to peers
type GroupInvite struct {
	GroupID       string
	GroupName     string
	SignedGroupID []byte
	Timestamp     uint64
	SharedKey     []byte
	ServerHost    string
}

// DecryptedGroupMessage is the main encapsulation of group message data
type DecryptedGroupMessage struct {
	Text      string
	Onion     string
	Timestamp uint64
	// NOTE: SignedGroupID is now a misnomer, the only way this is signed is indirectly via the signed encrypted group messages
	// We now treat GroupID as binding to a server/key rather than an "owner" - additional validation logic (to e.g.
	// respect particular group constitutions) can be built on top of group messages, but the underlying groups are
	// now agnostic to those models.
	SignedGroupID      []byte
	PreviousMessageSig []byte
	Padding            []byte
}

// EncryptedGroupMessage provides an encapsulation of the encrypted group message stored on the server
type EncryptedGroupMessage struct {
	Ciphertext []byte
	Signature  []byte
}

// CachedEncryptedGroupMessage provides an encapsulation of the encrypted group message for local caching / error reporting
type CachedEncryptedGroupMessage struct {
	EncryptedGroupMessage
	Group string
}

// ToBytes converts the encrypted group message to a set of bytes for serialization
func (egm EncryptedGroupMessage) ToBytes() []byte {
	data, _ := json.Marshal(egm)
	return data
}

// MessageType defines the enum for TokenBoard messages
type MessageType int

// Message Types
const (
	ReplayRequestMessage MessageType = iota
	ReplayResultMessage
	PostRequestMessage
	PostResultMessage
	NewMessageMessage
)

// Message encapsulates the application protocol
type Message struct {
	MessageType   MessageType
	PostRequest   *PostRequest   `json:",omitempty"`
	PostResult    *PostResult    `json:",omitempty"`
	NewMessage    *NewMessage    `json:",omitempty"`
	ReplayRequest *ReplayRequest `json:",omitempty"`
	ReplayResult  *ReplayResult  `json:",omitempty"`
}

// ReplayRequest requests a reply from the given Commit
type ReplayRequest struct {
	LastCommit []byte
}

// PostRequest requests to post the message to the board with the given token
type PostRequest struct {
	Token privacypass.SpentToken
	EGM   EncryptedGroupMessage
}

// PostResult returns the success of a given post attempt
type PostResult struct {
	Success bool
}

// ReplayResult is sent by the server before a stream of replayed messages
type ReplayResult struct {
	NumMessages int
}

// NewMessage is used to send a new bulletin board message to interested peers.
type NewMessage struct {
	//Token   privacypass.SpentToken
	EGM EncryptedGroupMessage
}
