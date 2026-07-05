package model

import (
	"git.openprivacy.ca/cwtch.im/tapir/primitives"
	"testing"
)

func TestDeserializeAndVerify(t *testing.T) {
	server, _ := primitives.InitializeEphemeralIdentity()

	serverKeyBundle := NewKeyBundle()

	serverKeyBundle.Keys[KeyTypeServerOnion] = Key(server.Hostname())
	serverKeyBundle.Keys[KeyTypePrivacyPass] = Key("random 1")
	serverKeyBundle.Keys[KeyTypeTokenOnion] = Key("random 2")
	serverKeyBundle.Sign(server)

	//eyeball keys are sorted
	t.Logf("%s", serverKeyBundle.Serialize())
	serialize := serverKeyBundle.Serialize()

	newKeyBundle, err := DeserializeAndVerify(serialize)
	if err != nil {
		t.Fatalf("Key Bundle did not Deserialize %v", err)
	}

	if newKeyBundle.Keys[KeyTypeServerOnion] != Key(server.Hostname()) {
		t.Fatalf("Key Bundle did not Serialize Correctly Actual: %v Expected: %v", newKeyBundle, serverKeyBundle)
	}
}

func TestDeserializeAndVerifyMaliciousSignShouldFail(t *testing.T) {
	server, _ := primitives.InitializeEphemeralIdentity()
	maliciousServer, _ := primitives.InitializeEphemeralIdentity()
	serverKeyBundle := NewKeyBundle()

	serverKeyBundle.Keys[KeyTypeServerOnion] = Key(server.Hostname())

	// This time we sign with a malicious server
	serverKeyBundle.Sign(maliciousServer)
	serialize := serverKeyBundle.Serialize()

	newKeyBundle, err := DeserializeAndVerify(serialize)
	if err == nil {
		t.Fatalf("Key Bundle did Deserialize (it should have failed): %v", newKeyBundle)
	}
}

func TestDeserializeAndVerifyUnsignedShouldFail(t *testing.T) {
	server, _ := primitives.InitializeEphemeralIdentity()

	serverKeyBundle := NewKeyBundle()

	serverKeyBundle.Keys[KeyTypeServerOnion] = Key(server.Hostname())

	// This time we don't sign
	// serverKeyBundle.Sign(server)
	serialize := serverKeyBundle.Serialize()

	newKeyBundle, err := DeserializeAndVerify(serialize)
	if err == nil {
		t.Fatalf("Key Bundle did Deserialize (it should have failed): %v", newKeyBundle)
	}
}
