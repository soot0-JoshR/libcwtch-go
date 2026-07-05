package attr

import (
	"git.openprivacy.ca/openprivacy/log"
	"strings"
)

// Zone forces attributes to belong to a given subsystem e.g profile or filesharing
// Note: Zone is different from Scope which deals with public visibility of a given attribute
type Zone string

// ZonedPath explicitly types paths that contain a zone for strongly typed APIs
type ZonedPath string

const (

	// ProfileZone for attributes related to profile details like name and profile image
	ProfileZone = Zone("profile")

	// LegacyGroupZone for attributes related to legacy group experiment
	LegacyGroupZone = Zone("legacygroup")

	// FilesharingZone for attributes related to file sharing
	FilesharingZone = Zone("filesharing")

	// ServerKeyZone for attributes related to Server Keys
	ServerKeyZone = Zone("serverkey")

	// ServerZone is for attributes related to the server
	ServerZone = Zone("server")

	// UnknownZone is a catch all useful for error handling
	UnknownZone = Zone("unknown")
)

// ConstructZonedPath takes a path and attaches a zone to it.
// Note that this returns a ZonedPath which isn't directly usable, it must be given to ConstructScopedZonedPath
// in order to be realized into an actual attribute path.
func (zone Zone) ConstructZonedPath(path string) ZonedPath {
	return ZonedPath(string(zone) + Separator + path)
}

func (zp ZonedPath) ToString() string {
	return string(zp)
}

// ParseZone takes in an untyped string and returns an explicit Zone along with the rest of the untyped path
func ParseZone(path string) (Zone, string) {
	parts := strings.SplitN(path, Separator, 2)

	log.Debugf("parsed zone: %v %v", parts, path)

	if len(parts) != 2 {
		return UnknownZone, ""
	}

	switch Zone(parts[0]) {
	case ProfileZone:
		return ProfileZone, parts[1]
	case LegacyGroupZone:
		return LegacyGroupZone, parts[1]
	case FilesharingZone:
		return FilesharingZone, parts[1]
	case ServerKeyZone:
		return ServerKeyZone, parts[1]
	case ServerZone:
		return ServerZone, parts[1]
	default:
		return UnknownZone, parts[1]
	}
}
