package cwtchcore

import (
	"cwtch.im/cwtch/model"
	"cwtch.im/cwtch/model/attr"
	constants2 "cwtch.im/cwtch/model/constants"
	"encoding/json"
	"strings"
	"testing"
)

func TestConversationDisplayNamePrefersLocalThenPublic(t *testing.T) {
	publicNameKey := attr.PublicScope.ConstructScopedZonedPath(
		attr.ProfileZone.ConstructZonedPath(constants2.Name),
	).ToString()
	localNameKey := attr.LocalScope.ConstructScopedZonedPath(
		attr.ProfileZone.ConstructZonedPath(constants2.Name),
	).ToString()
	conversation := &model.Conversation{
		Handle: strings.Repeat("b", 56),
		Attributes: model.Attributes{
			publicNameKey: "Vanilla Bob",
		},
	}

	if name := conversationDisplayName(conversation); name != "Vanilla Bob" {
		t.Fatalf("expected public nickname, got %q", name)
	}

	conversation.Attributes[localNameKey] = "My Bob"
	if name := conversationDisplayName(conversation); name != "My Bob" {
		t.Fatalf("expected local nickname override, got %q", name)
	}
}

func TestConversationMetadataIncludesAcceptedState(t *testing.T) {
	encoded, err := json.Marshal(ConversationMetadata{PeerOnion: strings.Repeat("b", 56), Accepted: true})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(encoded), `"accepted":true`) {
		t.Fatalf("expected accepted state in metadata JSON, got %s", encoded)
	}
}

func TestConversationBlockedReadsPeerACL(t *testing.T) {
	peerOnion := strings.Repeat("b", 56)
	conversation := &model.Conversation{
		Handle: peerOnion,
		ACL: model.AccessControlList{
			peerOnion: model.AccessControl{Blocked: true},
		},
	}

	if !conversationBlocked(conversation) {
		t.Fatal("expected peer ACL to mark the conversation blocked")
	}
	conversation.ACL[peerOnion] = model.AccessControl{Blocked: false}
	if conversationBlocked(conversation) {
		t.Fatal("expected unblocked peer ACL to remain visible")
	}
}
