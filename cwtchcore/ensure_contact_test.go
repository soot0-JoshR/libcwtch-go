package cwtchcore

import (
	"encoding/json"
	"testing"
)

func TestNormalizeOnion(t *testing.T) {
	const onion = "abcdefghijklmnopqrstuvwxyz234567abcdefghijklmnopqrstuvwxyz2345"
	if got := normalizeOnion("  " + onion + ".ONION  "); got != onion {
		t.Fatalf("normalizeOnion() = %q, want %q", got, onion)
	}
}

func TestEnsureContactRequiresInitializedApplication(t *testing.T) {
	previous := Application
	Application = nil
	t.Cleanup(func() { Application = previous })

	var result EnsureContactResult
	if err := json.Unmarshal([]byte(EnsureContact("invalid", "invalid")), &result); err != nil {
		t.Fatalf("EnsureContact returned invalid JSON: %v", err)
	}
	if result.Status != "error" || result.Reason != "application_not_initialized" {
		t.Fatalf("EnsureContact result = %+v", result)
	}
}
