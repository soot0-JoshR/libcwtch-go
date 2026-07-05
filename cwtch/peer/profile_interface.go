package peer

import (
	"cwtch.im/cwtch/event"
	"cwtch.im/cwtch/model"
	"cwtch.im/cwtch/model/attr"
	"cwtch.im/cwtch/protocol/connections"
	"git.openprivacy.ca/cwtch.im/tapir/primitives/privacypass"
	"git.openprivacy.ca/openprivacy/connectivity"
)

// AccessPeeringState provides access to functions relating to the underlying connections of a peer.
type AccessPeeringState interface {
	GetPeerState(string) connections.ConnectionState
}

// ModifyPeeringState is a meta-interface intended to restrict callers to modify-only access to connection peers
type ModifyPeeringState interface {
	BlockUnknownConnections()
	AllowUnknownConnections()
	PeerWithOnion(string)
	JoinServer(string) error
}

// ModifyContactsAndPeers is a meta-interface intended to restrict a call to reading and modifying contacts
// and peers.
type ModifyContactsAndPeers interface {
	ModifyPeeringState
}

// ReadServers provides access to the servers
type ReadServers interface {
	GetServers() []string
}

// ModifyGroups provides write-only access add/edit/remove new groups
type ModifyGroups interface {
	ImportGroup(string) (int, error)
	StartGroup(string, string) (int, error)
}

// ModifyServers provides write-only access to servers
type ModifyServers interface {
	AddServer(string) (string, error)
	ResyncServer(onion string) error
}

// SendMessages enables a caller to sender messages to a contact
type SendMessages interface {
	SendMessage(conversation int, message string) (int, error)
	SendInviteToConversation(conversationID int, inviteConversationID int) (int, error)
	SendScopedZonedGetValToContact(conversationID int, scope attr.Scope, zone attr.Zone, key string)
}

// CwtchPeer provides us with a way of testing systems built on top of cwtch without having to
// directly implement a cwtchPeer.
type CwtchPeer interface {

	// Core Cwtch Peer Functions that should not be exposed to
	// most functions
	Init(event.Manager)

	GenerateProtocolEngine(acn connectivity.ACN, bus event.Manager) (connections.Engine, error)

	AutoHandleEvents(events []event.Type)
	Listen()
	StartConnections(doPeers, doServers bool)
	// Deprecated in 1.10
	StartPeersConnections()
	// Deprecated in 1.10
	StartServerConnections()

	Shutdown()

	// GetOnion is deprecated. If you find yourself needing to rely on this method it is time
	// to consider replacing this with a GetAddress(es) function that can fully expand cwtch beyond the boundaries
	// of tor v3 onion services.
	// Deprecated
	GetOnion() string

	// SetScopedZonedAttribute allows the setting of an attribute by scope and zone
	// scope.zone.key = value
	SetScopedZonedAttribute(scope attr.Scope, zone attr.Zone, key string, value string)

	// GetScopedZonedAttribute allows the retrieval of an attribute by scope and zone
	// scope.zone.key = value
	GetScopedZonedAttribute(scope attr.Scope, zone attr.Zone, key string) (string, bool)

	// GetScopedZonedAttributeKeys returns all keys associated with a given scope and zone
	GetScopedZonedAttributeKeys(scope attr.Scope, zone attr.Zone) ([]string, error)

	AccessPeeringState
	ModifyPeeringState

	ModifyGroups

	ReadServers
	ModifyServers

	SendMessages

	// Import Bundle
	ImportBundle(string) error

	// New Unified Conversation Interfaces
	NewContactConversation(handle string, acl model.AccessControl, accepted bool) (int, error)
	FetchConversations() ([]*model.Conversation, error)
	GetConversationInfo(conversation int) (*model.Conversation, error)
	FetchConversationInfo(handle string) (*model.Conversation, error)
	AcceptConversation(conversation int) error
	BlockConversation(conversation int) error
	UnblockConversation(conversation int) error
	SetConversationAttribute(conversation int, path attr.ScopedZonedPath, value string) error
	GetConversationAttribute(conversation int, path attr.ScopedZonedPath) (string, error)
	DeleteConversation(conversation int) error

	// New Unified Conversation Channel Interfaces
	GetChannelMessage(conversation int, channel int, id int) (string, model.Attributes, error)
	GetChannelMessageCount(conversation int, channel int) (int, error)
	GetChannelMessageByContentHash(conversation int, channel int, contenthash string) (int, error)
	GetMostRecentMessages(conversation int, channel int, offset int, limit int) ([]model.ConversationMessage, error)
	UpdateMessageAttribute(conversation int, channel int, id int, key string, value string) error

	// File Sharing APIS
	// TODO move these to feature protected interfaces
	ShareFile(fileKey string, serializedManifest string)
	StopFileShare(fileKey string)
	StopAllFileShares()

	// Server Token APIS
	// TODO move these to feature protected interfaces
	StoreCachedTokens(tokenServer string, tokens []*privacypass.Token)

	// Profile Management
	CheckPassword(password string) bool
	ChangePassword(oldpassword string, newpassword string, newpasswordAgain string) error
	Export(file string) error
	Delete()
	SignMessage(message []byte) ([]byte, error)
}
