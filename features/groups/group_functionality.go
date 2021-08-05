package groups

import (
	"cwtch.im/cwtch/event"
	"cwtch.im/cwtch/model"
	"cwtch.im/cwtch/peer"
	"encoding/base64"
	"fmt"
	"git.openprivacy.ca/cwtch.im/libcwtch-go/features"
	"git.openprivacy.ca/openprivacy/log"
	"strings"
)

const serverPrefix = "server:"
const tofuBundlePrefix = "tofubundle:"
const groupPrefix = "torv3"
const groupExperiment = "tapir-groups-experiment"

const importBundlePrefix = "importBundle"

const (
	// ServerList is a json encoded list of servers
	ServerList = event.Field("ServerList")
)

const (
	// UpdateServerInfo is an event containing a ProfileOnion and a ServerList
	UpdateServerInfo = event.Type("UpdateServerInfo")
)

// ReadServerInfo is a meta-interface for reading information about servers..
type ReadServerInfo interface {
	peer.ReadContacts
	peer.ReadServers
}

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

// SendMessage is a deprecated api
func (gf *GroupFunctionality) SendMessage(peer peer.CwtchPeer, handle string, message string) (string, error) {
	// TODO this auto accepting behaviour needs some thinking through
	if !peer.GetGroup(handle).Accepted {
		err := peer.AcceptInvite(handle)
		if err != nil {
			log.Errorf("tried to mark a nonexistent group as existed. bad!")
			return "", err
		}
	}
	return peer.SendMessageToGroupTracked(handle, message)
}

// ValidPrefix returns true if an import string contains a prefix that indicates it contains information about a
// server or a group
func (gf *GroupFunctionality) ValidPrefix(importString string) bool {
	return strings.HasPrefix(importString, tofuBundlePrefix) || strings.HasPrefix(importString, serverPrefix) || strings.HasPrefix(importString, groupPrefix)
}

// GetServerInfoList compiles all the information the UI might need regarding all servers..
func (gf *GroupFunctionality) GetServerInfoList(profile ReadServerInfo) []Server {
	var servers []Server
	for _, server := range profile.GetServers() {
		servers = append(servers, gf.GetServerInfo(server, profile))
	}
	return servers
}

// GetServerInfo compiles all the information the UI might need regarding a particular server including any verified
// cryptographic keys
func (gf *GroupFunctionality) GetServerInfo(serverOnion string, profile peer.ReadContacts) Server {
	serverInfo := profile.GetContact(serverOnion)
	keyTypes := []model.KeyType{model.KeyTypeServerOnion, model.KeyTypeTokenOnion, model.KeyTypePrivacyPass}
	var serverKeys []ServerKey

	for _, keyType := range keyTypes {
		if key, has := serverInfo.GetAttribute(string(keyType)); has {
			serverKeys = append(serverKeys, ServerKey{Type: string(keyType), Key: key})
		}
	}
	return Server{Onion: serverOnion, Status: serverInfo.State, Keys: serverKeys}
}

// HandleImportString handles import strings for groups and servers
func (gf *GroupFunctionality) HandleImportString(peer peer.CwtchPeer, importString string) error {
	if strings.HasPrefix(importString, tofuBundlePrefix) {
		bundle := strings.Split(importString, "||")
		if len(bundle) == 2 {
			err := gf.HandleImportString(peer, bundle[0][len(tofuBundlePrefix):])
			// if the server import failed then abort the whole process..
			if !strings.HasSuffix(err.Error(), "success") {
				return features.ConstructResponse(importBundlePrefix, err.Error())
			}
			return gf.HandleImportString(peer, bundle[1])
		}
	} else if strings.HasPrefix(importString, serverPrefix) {
		// Server Key Bundles are prefixed with
		bundle, err := base64.StdEncoding.DecodeString(importString[len(serverPrefix):])
		if err == nil {
			if err = peer.AddServer(string(bundle)); err != nil {
				return features.ConstructResponse(importBundlePrefix, err.Error())
			}
			return features.ConstructResponse(importBundlePrefix, "success")
		}
		return features.ConstructResponse(importBundlePrefix, err.Error())
	} else if strings.HasPrefix(importString, groupPrefix) {
		//eg: torv3JFDWkXExBsZLkjvfkkuAxHsiLGZBk0bvoeJID9ItYnU=EsEBCiBhOWJhZDU1OTQ0NWI3YmM2N2YxYTM5YjkzMTNmNTczNRIgpHeNaG+6jy750eDhwLO39UX4f2xs0irK/M3P6mDSYQIaOTJjM2ttb29ibnlnaGoyenc2cHd2N2Q1N3l6bGQ3NTNhdW8zdWdhdWV6enB2ZmFrM2FoYzRiZHlkCiJAdVSSVgsksceIfHe41OJu9ZFHO8Kwv3G6F5OK3Hw4qZ6hn6SiZjtmJlJezoBH0voZlCahOU7jCOg+dsENndZxAA==
		if gid, err := peer.ImportGroup(importString); err != nil {
			return features.ConstructResponse(importBundlePrefix, err.Error())
		} else {
			// Auto accept the group here.
			if peer.AcceptInvite(gid) != nil {
				log.Errorf("Error accepting invite: %v", err)
			}
			return features.ConstructResponse(importBundlePrefix, "success")
		}
	}
	return features.ConstructResponse(importBundlePrefix, "invalid_group_invite_prefix")
}
