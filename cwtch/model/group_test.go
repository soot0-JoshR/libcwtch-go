package model

import (
	"crypto/sha256"
	"cwtch.im/cwtch/protocol/groups"
	"strings"
	"testing"
	"time"
)

func TestGroup(t *testing.T) {
	g, _ := NewGroup("2c3kmoobnyghj2zw6pwv7d57yzld753auo3ugauezzpvfak3ahc4bdyd")
	dgm := &groups.DecryptedGroupMessage{
		Onion:              "onion",
		Text:               "Hello World!",
		Timestamp:          uint64(time.Now().Unix()),
		SignedGroupID:      []byte{},
		PreviousMessageSig: []byte{},
		Padding:            []byte{},
	}

	invite, err := g.Invite()

	if err != nil {
		t.Fatalf("error creating group invite: %v", err)
	}

	validatedInvite, err := ValidateInvite(invite)

	if err != nil {
		t.Fatalf("error validating group invite: %v", err)
	}

	if validatedInvite.GroupID != g.GroupID {
		t.Fatalf("after validate group invite id should be identical to original: %v", err)
	}

	encMessage, _ := g.EncryptMessage(dgm)
	ok, message := g.DecryptMessage(encMessage)
	if !ok || message.Text != "Hello World!" {
		t.Errorf("group encryption was invalid, or returned wrong message decrypted:%v message:%v", ok, message)
		return
	}

	t.Logf("Got message %v", message)
}

func TestGroupErr(t *testing.T) {
	_, err := NewGroup("not a real group name")
	if err == nil {
		t.Errorf("Group Setup Should Have Failed")
	}
}

// Test various group invite validation failures...
func TestGroupValidation(t *testing.T) {

	group := &Group{
		GroupID:     "",
		GroupKey:    [32]byte{},
		GroupServer: "",
		Timeline:    Timeline{},
		LocalID:     "",
		Version:     0,
	}

	invite, _ := group.Invite()
	_, err := ValidateInvite(invite)

	if err == nil {
		t.Fatalf("Group with empty group id should have been an error")
	}
	t.Logf("Error: %v", err)

	// Generate a valid group but replace the group server...
	group, _ = NewGroup("2c3kmoobnyghj2zw6pwv7d57yzld753auo3ugauezzpvfak3ahc4bdyd")
	group.GroupServer = "tcnkoch4nyr3cldkemejtkpqok342rbql6iclnjjs3ndgnjgufzyxvqd"
	invite, _ = group.Invite()
	_, err = ValidateInvite(invite)

	if err == nil {
		t.Fatalf("Group with empty group id should have been an error")
	}
	t.Logf("Error: %v", err)

	// Generate a valid group but replace the group key...
	group, _ = NewGroup("2c3kmoobnyghj2zw6pwv7d57yzld753auo3ugauezzpvfak3ahc4bdyd")
	group.GroupKey = sha256.Sum256([]byte{})
	invite, _ = group.Invite()
	_, err = ValidateInvite(invite)

	if err == nil {
		t.Fatalf("Group with different group key should have errored")
	}
	t.Logf("Error: %v", err)

	// mangle the invite
	_, err = ValidateInvite(strings.ReplaceAll(invite, GroupInvitePrefix, ""))
	if err == nil {
		t.Fatalf("Group with different group key should have errored")
	}
	t.Logf("Error: %v", err)

}
