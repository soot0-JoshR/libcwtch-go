package cwtchcore

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestSafeMediaFilenameRemovesTraversalAndPreservesExtension(t *testing.T) {
	name := safeMediaFilename(strings.Repeat("a", 128)+".nonce", "../../hidden photo.PNG")
	if strings.Contains(name, "/") || strings.Contains(name, "\\") || strings.Contains(name, "..") {
		t.Fatalf("unsafe media filename: %q", name)
	}
	if !strings.HasSuffix(name, ".PNG") {
		t.Fatalf("media extension was not preserved: %q", name)
	}
}

func TestSafeMediaFilenameSanitizesTransferIDPrefix(t *testing.T) {
	tests := []struct {
		name       string
		transferID string
	}{
		{name: "relative traversal", transferID: "../../outside.nonce"},
		{name: "windows traversal", transferID: `..\..\outside.nonce`},
		{name: "absolute path", transferID: "/tmp/outside.nonce"},
		{name: "punctuation only", transferID: "...."},
		{name: "embedded separator", transferID: "safe/../../outside.nonce"},
	}

	root := t.TempDir()
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			name := safeMediaFilename(test.transferID, "photo.png")
			if filepath.Base(name) != name || strings.Contains(name, "/") || strings.Contains(name, `\`) {
				t.Fatalf("transfer ID produced an unsafe filename: %q", name)
			}
			if name == "." || name == ".." || strings.Contains(name, "..") {
				t.Fatalf("transfer ID retained traversal syntax: %q", name)
			}
			if !pathInsideRoot(root, filepath.Join(root, name)) {
				t.Fatalf("sanitized filename escaped its media root: %q", name)
			}
		})
	}
}

func TestSafeMediaFilenameKeepsStableValidTransferPrefix(t *testing.T) {
	transferID := strings.Repeat("a", 128) + ".nonce"
	name := safeMediaFilename(transferID, "photo.png")
	if !strings.HasPrefix(name, strings.Repeat("a", 32)+"-") {
		t.Fatalf("valid transfer prefix changed unexpectedly: %q", name)
	}
}

func TestTorStateIsOfflineWithoutRuntime(t *testing.T) {
	stateMutex.Lock()
	previousApplication := Application
	previousACN := GlobalACN
	Application = nil
	GlobalACN = nil
	stateMutex.Unlock()
	t.Cleanup(func() {
		stateMutex.Lock()
		Application = previousApplication
		GlobalACN = previousACN
		stateMutex.Unlock()
	})

	if got := GetTorState(); got != `{"progress":0,"status":"Offline"}` {
		t.Fatalf("unexpected Tor state without a runtime: %s", got)
	}
	ShutdownCwtch()
}

func TestPathInsideRootRejectsTraversalAndTheRootItself(t *testing.T) {
	root := t.TempDir()
	if !pathInsideRoot(root, filepath.Join(root, "profile", "media.bin")) {
		t.Fatal("valid nested media path was rejected")
	}
	if pathInsideRoot(root, root) {
		t.Fatal("media root itself was accepted as a file path")
	}
	if pathInsideRoot(root, filepath.Join(root, "..", "outside.bin")) {
		t.Fatal("traversal path was accepted")
	}
}

func TestSniffMediaTypeRecognizesOpaqueDownload(t *testing.T) {
	filePath := filepath.Join(t.TempDir(), "opaque.download")
	pngHeader := []byte{0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a, 0x00}
	if err := os.WriteFile(filePath, pngHeader, 0600); err != nil {
		t.Fatal(err)
	}
	if mediaType := sniffMediaType(filePath); mediaType != "image/png" {
		t.Fatalf("unexpected media type: %q", mediaType)
	}
}

func TestRequestMediaReportsUnavailableRuntime(t *testing.T) {
	stateMutex.Lock()
	previous := Application
	Application = nil
	stateMutex.Unlock()
	defer func() {
		stateMutex.Lock()
		Application = previous
		stateMutex.Unlock()
	}()

	var result MediaRequestResult
	if err := json.Unmarshal([]byte(RequestMedia("missing")), &result); err != nil {
		t.Fatalf("invalid request response: %v", err)
	}
	if result.Status != "error" || result.Reason != "application_not_initialized" {
		t.Fatalf("unexpected request response: %#v", result)
	}
}

func TestNormalizeStegmsConversationIDAcceptsFormattedIDs(t *testing.T) {
	formatted := "cwtch:" + strings.Repeat("a", 56) + ":" + strings.Repeat("b", 56)
	if value, valid := normalizeStegmsConversationID(formatted); !valid || value != formatted {
		t.Fatalf("formatted conversation ID rejected: valid=%v value=%q", valid, value)
	}
	if _, valid := normalizeStegmsConversationID("   "); valid {
		t.Fatal("blank conversation ID accepted")
	}
	if _, valid := normalizeStegmsConversationID(strings.Repeat("x", 257)); valid {
		t.Fatal("oversized conversation ID accepted")
	}
}

func TestPurgeGuestMediaRemovesOnlyTheSelectedProfile(t *testing.T) {
	root := t.TempDir()
	profileA := strings.Repeat("a", 56)
	profileB := strings.Repeat("b", 56)
	pathA := filepath.Join(root, "media", profileA, "a.png")
	pathB := filepath.Join(root, "media", profileB, "b.png")
	if err := os.MkdirAll(filepath.Dir(pathA), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Dir(pathB), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(pathA, []byte("a"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(pathB, []byte("b"), 0600); err != nil {
		t.Fatal(err)
	}

	stateMutex.Lock()
	previousRoot := GlobalAppDir
	GlobalAppDir = root
	stateMutex.Unlock()
	mediaOffersMutex.Lock()
	previousOffers := mediaOffers
	mediaOffers = map[string]MediaOffer{
		"a": {TransferID: "a", ProfileOnion: profileA, LocalPath: pathA},
		"b": {TransferID: "b", ProfileOnion: profileB, LocalPath: pathB},
	}
	mediaOffersMutex.Unlock()
	defer func() {
		stateMutex.Lock()
		GlobalAppDir = previousRoot
		stateMutex.Unlock()
		mediaOffersMutex.Lock()
		mediaOffers = previousOffers
		mediaOffersMutex.Unlock()
	}()

	var result map[string]string
	if err := json.Unmarshal([]byte(PurgeGuestMedia(profileA)), &result); err != nil {
		t.Fatal(err)
	}
	if result["status"] != "ok" {
		t.Fatalf("unexpected purge result: %#v", result)
	}
	if _, err := os.Stat(pathA); !os.IsNotExist(err) {
		t.Fatalf("profile A media still exists: %v", err)
	}
	if _, err := os.Stat(pathB); err != nil {
		t.Fatalf("profile B media was removed: %v", err)
	}
	mediaOffersMutex.Lock()
	defer mediaOffersMutex.Unlock()
	if _, exists := mediaOffers["a"]; exists {
		t.Fatal("profile A offer was retained")
	}
	if _, exists := mediaOffers["b"]; !exists {
		t.Fatal("profile B offer was removed")
	}
}
