package model

import (
	"cwtch.im/cwtch/model/attr"
	"cwtch.im/cwtch/model/constants"
	"encoding/json"
	"time"
)

// AccessControl is a type determining client assigned authorization to a peer
type AccessControl struct {
	Blocked bool // Any attempts from this handle to connect are blocked
	Read    bool // Allows a handle to access the conversation
	Append  bool // Allows a handle to append new messages to the conversation
}

// DefaultP2PAccessControl - because in the year 2021, go does not support constant structs...
func DefaultP2PAccessControl() AccessControl {
	return AccessControl{Read: true, Append: true, Blocked: false}
}

// AccessControlList represents an access control list for a conversation. Mapping handles to conversation
// functions
type AccessControlList map[string]AccessControl

// Serialize transforms the ACL into json.
func (acl *AccessControlList) Serialize() []byte {
	data, _ := json.Marshal(acl)
	return data
}

// DeserializeAccessControlList takes in JSON and returns an AccessControlList
func DeserializeAccessControlList(data []byte) AccessControlList {
	var acl AccessControlList
	json.Unmarshal(data, &acl)
	return acl
}

// Attributes a type-driven encapsulation of an Attribute map.
type Attributes map[string]string

// Serialize transforms an Attributes map into a JSON struct
func (a *Attributes) Serialize() []byte {
	data, _ := json.Marshal(a)
	return data
}

// DeserializeAttributes converts a JSON struct into an Attributes map
func DeserializeAttributes(data []byte) Attributes {
	var attributes Attributes
	json.Unmarshal(data, &attributes)
	return attributes
}

// Conversation encapsulates high-level information about a conversation, including the
// handle, any set attributes, the access control list associated with the message tree and the
// accepted status of the conversation (whether the user has consented into the conversation).
type Conversation struct {
	ID         int
	Handle     string
	Attributes Attributes
	ACL        AccessControlList
	Accepted   bool
}

// GetAttribute is a helper function that fetches a conversation attribute by scope, zone and key
func (ci *Conversation) GetAttribute(scope attr.Scope, zone attr.Zone, key string) (string, bool) {
	if value, exists := ci.Attributes[scope.ConstructScopedZonedPath(zone.ConstructZonedPath(key)).ToString()]; exists {
		return value, true
	}
	return "", false
}

// IsGroup is a helper attribute that identifies whether a conversation is a legacy group
func (ci *Conversation) IsGroup() bool {
	if _, exists := ci.Attributes[attr.LocalScope.ConstructScopedZonedPath(attr.LegacyGroupZone.ConstructZonedPath(constants.GroupID)).ToString()]; exists {
		return true
	}
	return false
}

// IsServer is a helper attribute that identifies whether a conversation is with a server
func (ci *Conversation) IsServer() bool {
	if _, exists := ci.Attributes[attr.PublicScope.ConstructScopedZonedPath(attr.ServerKeyZone.ConstructZonedPath(string(BundleType))).ToString()]; exists {
		return true
	}
	return false
}

// ServerSyncProgress is only valid during a server being in the AUTHENTICATED state and therefor in the syncing process
// it returns a double (0-1) representing the estimated progress of the syncing
func (ci *Conversation) ServerSyncProgress() float64 {
	startTimeStr, startExists := ci.Attributes[attr.LocalScope.ConstructScopedZonedPath(attr.LegacyGroupZone.ConstructZonedPath(constants.SyncPreLastMessageTime)).ToString()]
	recentTimeStr, recentExists := ci.Attributes[attr.LocalScope.ConstructScopedZonedPath(attr.LegacyGroupZone.ConstructZonedPath(constants.SyncMostRecentMessageTime)).ToString()]

	if !startExists || !recentExists {
		return 0.0
	}

	startTime, err := time.Parse(startTimeStr, time.RFC3339Nano)
	if err != nil {
		return 0.0
	}
	recentTime, err := time.Parse(recentTimeStr, time.RFC3339Nano)
	if err != nil {
		return 0.0
	}

	syncRange := time.Since(startTime)
	pointFromStart := startTime.Sub(recentTime)
	return pointFromStart.Seconds() / syncRange.Seconds()
}

// ConversationMessage bundles an instance of a conversation message row
type ConversationMessage struct {
	ID          int
	Body        string
	Attr        Attributes
	Signature   string
	ContentHash string
}
