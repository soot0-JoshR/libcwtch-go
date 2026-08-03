package cwtch

import (
	"testing"

	"cwtch.im/cwtch/app"
	"cwtch.im/cwtch/peer"
	"git.openprivacy.ca/cwtch.im/libcwtch-go/cwtchcore"
)

type importApplicationStub struct {
	app.Application
	err error
}

func (stub importApplicationStub) ImportProfile(string, string) (peer.CwtchPeer, error) {
	return nil, stub.err
}

func TestConversationMetadataBindingIsExported(t *testing.T) {
	var binding func(string) string = GetConversationMetadataForProfile
	if got := binding("invalid-profile"); got != "[]" {
		t.Fatalf("unexpected metadata response for invalid profile: %s", got)
	}
}

func TestImportProfilePreservesCoreJSONResponse(t *testing.T) {
	previous := cwtchcore.Application
	cwtchcore.Application = importApplicationStub{}
	t.Cleanup(func() { cwtchcore.Application = previous })

	if got := ImportProfile("profile.cwtch", "password"); got != `{"status":"ok"}` {
		t.Fatalf("successful import response was rewritten: %s", got)
	}
}
