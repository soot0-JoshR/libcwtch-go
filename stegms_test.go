package main

import (
	"crypto/ed25519"
	"encoding/base64"
	"testing"
	"time"

	"git.openprivacy.ca/cwtch.im/libcwtch-go/cwtchcore"
)

func TestChallengePrefixing(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("Failed to generate key: %v", err)
	}

	challenge := "abc123xyz"
	prefix := "StegMS-Auth-v1:"
	message := []byte(prefix + challenge)

	sig := ed25519.Sign(priv, message)

	if !ed25519.Verify(pub, message, sig) {
		t.Fatalf("Failed to verify raw signature")
	}

	encodedSig := base64.StdEncoding.EncodeToString(sig)
	if encodedSig == "" {
		t.Fatalf("Failed to encode signature")
	}
}

func TestConcurrentExecution(t *testing.T) {
	done := make(chan bool)
	for i := 0; i < 10; i++ {
		go func() {
			cwtchcore.SignChallenge("nonexistent", "challenge")
			cwtchcore.GetAppBusEvent()
			cwtchcore.GetMediaOffers()
			done <- true
		}()
	}

	timeout := time.After(2 * time.Second)
	for i := 0; i < 10; i++ {
		select {
		case <-done:
		case <-timeout:
			t.Fatalf("Deadlock detected during concurrent execution")
		}
	}
}
