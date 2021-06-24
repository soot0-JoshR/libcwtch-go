package contact

import (
	"cwtch.im/cwtch/model"
	"cwtch.im/cwtch/peer"
	"git.openprivacy.ca/flutter/libcwtch-go/features"
	"git.openprivacy.ca/openprivacy/connectivity/tor"
)

// Functionality groups some common UI triggered functions for contacts...
type Functionality struct {
}

const addContactPrefix = "addcontact"

const sendMessagePrefix = "sendmessage"

// FunctionalityGate returns contact.Functionality always
func FunctionalityGate(experimentMap map[string]bool) (*Functionality, error) {
	return new(Functionality), nil
}

// SendMessage handles sending messages to contacts
func (pf *Functionality) SendMessage(peer peer.SendMessages, handle string, message string) features.Response {
	eventID := peer.SendMessageToPeer(handle, message)
	return features.ConstructResponse(sendMessagePrefix, eventID)
}

// HandleImportString handles contact import strings
func (pf *Functionality) HandleImportString(peer peer.ModifyContactsAndPeers, importString string) features.Response {
	if tor.IsValidHostname(importString) {
		if peer.GetContact(importString) == nil {
			peer.AddContact(importString, importString, model.AuthApproved)
			// Implicit Peer Attempt
			peer.PeerWithOnion(importString)
			return features.ConstructResponse(addContactPrefix, "success")
		}
		return features.ConstructResponse(addContactPrefix, "contact_already_exists")
	}
	return features.ConstructResponse(addContactPrefix, "invalid_import_string")
}
