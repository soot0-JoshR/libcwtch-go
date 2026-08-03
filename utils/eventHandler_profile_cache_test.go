package utils

import (
	"testing"

	"cwtch.im/cwtch/model"
	"cwtch.im/cwtch/protocol/connections"
)

func TestForgetProfileStateDoesNotAffectOtherProfiles(t *testing.T) {
	handler := NewEventHandler(LCG_API_Handler{})
	handler.contactStateCache["alice\x00peer"] = connections.AUTHENTICATED
	handler.contactStateCache["bob\x00peer"] = connections.AUTHENTICATED

	handler.ForgetProfileState("alice.onion")

	if _, exists := handler.contactStateCache["alice\x00peer"]; exists {
		t.Fatal("locked profile state was retained")
	}
	if _, exists := handler.contactStateCache["bob\x00peer"]; !exists {
		t.Fatal("locking one profile cleared another profile's state")
	}
}

func TestResolveConversationHandleByID(t *testing.T) {
	conversations := []*model.Conversation{
		{ID: 3, Handle: "first-peer"},
		{ID: 7, Handle: "expected-peer"},
	}

	if handle := resolveConversationHandleByID(conversations, "7"); handle != "expected-peer" {
		t.Fatalf("unexpected conversation handle: %q", handle)
	}
	if handle := resolveConversationHandleByID(conversations, "9"); handle != "" {
		t.Fatalf("guessed an unrelated conversation handle: %q", handle)
	}
	if handle := resolveConversationHandleByID(conversations, "invalid"); handle != "" {
		t.Fatalf("accepted an invalid conversation ID: %q", handle)
	}
}
