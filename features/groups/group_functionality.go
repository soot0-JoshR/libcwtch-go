package groups

import (
	"cwtch.im/cwtch/event"
	"cwtch.im/cwtch/model"
	"cwtch.im/cwtch/model/attr"
	"cwtch.im/cwtch/peer"
	"cwtch.im/cwtch/protocol/connections"
	"fmt"
	"git.openprivacy.ca/cwtch.im/libcwtch-go/constants"
	"git.openprivacy.ca/cwtch.im/libcwtch-go/features/servers"
)
<<<<<<< HEAD
"git.openprivacy.ca/cwtch.im/libcwtch-go/features/servers"
=======
"git.openprivacy.ca/cwtch.im/libcwtch-go/features"
"git.openprivacy.ca/cwtch.im/libcwtch-go/features/servers"
"git.openprivacy.ca/openprivacy/log"
"strings"
>>>>>>> minor support to manage profile servers
)

const groupExperiment = "tapir-groups-experiment"

const (
	// ServerList is a json encoded list of servers
	ServerList = event.Field("ServerList")
)

const (
	// UpdateServerInfo is an event containing a ProfileOnion and a ServerList
	UpdateServerInfo = event.Type("UpdateServerInfo")
)

// GroupFunctionality provides experiment gated server functionality
type GroupFunctionality struct {
}

// ExperimentGate returns GroupFunctionality if the experiment is enabled, and an error otherwise.
func ExperimentGate(experimentMap map[string]bool) (*GroupFunctionality, error) {
	if experimentMap[groupExperiment] {
		return new(GroupFunctionality), nil
	}
	return nil, fmt.Errorf("gated by %v", groupExperiment)
}

// GetServerInfoList compiles all the information the UI might need regarding all servers..
func (gf *GroupFunctionality) GetServerInfoList(profile peer.CwtchPeer) []Server {
	var servers []Server
	for _, server := range profile.GetServers() {
		servers = append(servers, gf.GetServerInfo(server, profile))
	}
	return servers
}

// GetServerInfo compiles all the information the UI might need regarding a particular server including any verified
// cryptographic keys
func (gf *GroupFunctionality) GetServerInfo(serverOnion string, profile peer.CwtchPeer) Server {
	serverInfo, _ := profile.FetchConversationInfo(serverOnion)
	keyTypes := []model.KeyType{model.KeyTypeServerOnion, model.KeyTypeTokenOnion, model.KeyTypePrivacyPass}
	var serverKeys []ServerKey

	for _, keyType := range keyTypes {
		if key, has := serverInfo.GetAttribute(attr.PublicScope, attr.ServerKeyZone, string(keyType)); has {
			serverKeys = append(serverKeys, ServerKey{Type: string(keyType), Key: key})
		}
	}

	description, _ := serverInfo.GetAttribute(attr.LocalScope, servers.ServerZone, constants.Description)
	return Server{Onion: serverOnion, Status: connections.ConnectionStateName[profile.GetPeerState(serverInfo.Handle)], Keys: serverKeys, Description: description}
}
