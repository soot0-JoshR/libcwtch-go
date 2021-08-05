package contact

import (
	"cwtch.im/cwtch/model"
	"git.openprivacy.ca/cwtch.im/libcwtch-go/features"
	"testing"
)

const ValidHostname = "openpravyvc6spbd4flzn4g2iqu4sxzsizbtb5aqec25t76dnoo5w7yd"

type MockPeer struct {
	hasContact  bool
	addContact  bool
	peerRequest bool
}

func (m MockPeer) BlockUnknownConnections() {
	panic("should never be called")
}

func (m MockPeer) AllowUnknownConnections() {
	panic("should never be called")
}

func (m MockPeer) GetContacts() []string {
	panic("should never be called")
}

func (m MockPeer) GetContact(s string) *model.PublicProfile {
	if m.hasContact {
		return &(model.GenerateNewProfile("").PublicProfile)
	}
	return nil
}

func (m MockPeer) GetContactAttribute(s string, s2 string) (string, bool) {
	panic("should never be called")
}

func (m *MockPeer) AddContact(nick, onion string, authorization model.Authorization) {
	m.addContact = true
}

func (m MockPeer) SetContactAuthorization(s string, authorization model.Authorization) error {
	panic("should never be called")
}

func (m MockPeer) SetContactAttribute(s string, s2 string, s3 string) {
	panic("should never be called")
}

func (m MockPeer) DeleteContact(s string) {
	panic("should never be called")
}

func (m *MockPeer) PeerWithOnion(s string) {
	m.peerRequest = true
}

func (m MockPeer) JoinServer(s string) error {
	panic("should never be called")
}

func TestContactFunctionality_InValidHostname(t *testing.T) {
	cf, _ := FunctionalityGate(map[string]bool{})

	peer := &MockPeer{
		hasContact:  false,
		addContact:  false,
		peerRequest: false,
	}

	response := cf.HandleImportString(peer, "")

	if peer.addContact || peer.peerRequest {
		t.Fatalf("HandleImportString for a malformed import string should have no resulted in addContact or a peerRequest: %v", peer)
	}

	if response.Error() != features.ConstructResponse(addContactPrefix, "invalid_import_string").Error() {
		t.Fatalf("Response to a successful import is malformed: %v", response)
	}

}

func TestContactFunctionality_ValidHostnameExistingContact(t *testing.T) {
	cf, _ := FunctionalityGate(map[string]bool{})

	peer := &MockPeer{
		hasContact:  true,
		addContact:  false,
		peerRequest: false,
	}

	response := cf.HandleImportString(peer, ValidHostname)

	if peer.addContact || peer.peerRequest {
		t.Fatalf("HandleImportString for a valid string should not  call addContact or a peerRequest when the contact already exists: %v", peer)
	}

	if response.Error() != features.ConstructResponse(addContactPrefix, "contact_already_exists").Error() {
		t.Fatalf("Response to a successful import is malformed: %v", response)
	}

}

func TestContactFunctionality_ValidHostnameUnknownContact(t *testing.T) {
	cf, _ := FunctionalityGate(map[string]bool{})

	peer := &MockPeer{
		hasContact:  false,
		addContact:  false,
		peerRequest: false,
	}

	response := cf.HandleImportString(peer, ValidHostname)

	if peer.addContact && peer.peerRequest {
		if response.Error() != features.ConstructResponse(addContactPrefix, "success").Error() {
			t.Fatalf("Response to a successful import is malformed: %v", response)
		}
	} else {
		t.Fatalf("HandleImportString for a valid import string should have resulted in addContact or a peerRequest: %v", peer)
	}
}
