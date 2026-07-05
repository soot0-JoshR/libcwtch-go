package attr

import (
	"git.openprivacy.ca/openprivacy/log"
	"strings"
)

/*
Scope model for peer attributes and requests

A local peer "Alice" has a PublicScope that is queryable by getVal requests.
By default, for now, other scopes are private, of which we here define SettingsScope

Alice's peer structs of remote peers such as "Bob" keep the queried
PublicScope values in the PeerScope, which can be overridden by the same named
values stored in the LocalScope.

*/

// Scope strongly types Scope strings
type Scope string

// ScopedZonedPath typed path with a scope and a zone
type ScopedZonedPath string

// scopes for attributes
const (
	// on a peer, local and peer supplied data
	LocalScope        = Scope("local")
	PeerScope         = Scope("peer")
	ConversationScope = Scope("conversation")

	// on a local profile, public data and private settings
	PublicScope = Scope("public")

	UnknownScope = Scope("unknown")
)

// Separator for scope and the rest of path
const Separator = "."

// IntoScope converts a string to a Scope
func IntoScope(scope string) Scope {
	switch scope {
	case "local":
		return LocalScope
	case "peer":
		return PeerScope
	case "conversation":
		return ConversationScope
	case "public":
		return PublicScope
	}
	return UnknownScope
}

// ConstructScopedZonedPath enforces a scope over a zoned path
func (scope Scope) ConstructScopedZonedPath(zonedPath ZonedPath) ScopedZonedPath {
	return ScopedZonedPath(string(scope) + Separator + string(zonedPath))
}

// ToString converts a ScopedZonedPath to a string
func (szp ScopedZonedPath) ToString() string {
	return string(szp)
}

// IsLocal returns true if the scope is a local scope
func (scope Scope) IsLocal() bool {
	return scope == LocalScope
}

// IsPeer returns true if the scope is a peer scope
func (scope Scope) IsPeer() bool {
	return scope == PeerScope
}

// IsPublic returns true if the scope is a public scope
func (scope Scope) IsPublic() bool {
	return scope == PublicScope
}

// IsConversation returns true if the scope is a conversation scope
func (scope Scope) IsConversation() bool {
	return scope == ConversationScope
}

// ParseScope takes in an untyped string and returns an explicit Scope along with the rest of the untyped path
func ParseScope(path string) (Scope, string) {
	parts := strings.SplitN(path, Separator, 3)

	log.Debugf("parsed scope: %v %v", parts, path)

	if len(parts) != 3 {
		return UnknownScope, ""
	}

	return IntoScope(parts[0]), parts[1] + Separator + parts[2]
}
