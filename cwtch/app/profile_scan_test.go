package app

import (
	"os"
	"path/filepath"
	"testing"
)

func writeProfileCandidate(t *testing.T, profilesDir string, name string, files map[string][]byte) {
	t.Helper()
	candidateDir := filepath.Join(profilesDir, name)
	if err := os.Mkdir(candidateDir, 0700); err != nil {
		t.Fatal(err)
	}
	for filename, contents := range files {
		if err := os.WriteFile(filepath.Join(candidateDir, filename), contents, 0600); err != nil {
			t.Fatal(err)
		}
	}
}

func profileEntries(t *testing.T, profilesDir string) map[string]os.DirEntry {
	t.Helper()
	entries, err := os.ReadDir(profilesDir)
	if err != nil {
		t.Fatal(err)
	}
	result := make(map[string]os.DirEntry)
	for _, entry := range entries {
		result[entry.Name()] = entry
	}
	return result
}

func TestInspectProfileStorageCandidate(t *testing.T) {
	profilesDir := t.TempDir()
	writeProfileCandidate(t, profilesDir, "current", map[string][]byte{
		"SALT":    make([]byte, 128),
		"VERSION": []byte("2"),
		"db":      []byte("encrypted"),
	})
	writeProfileCandidate(t, profilesDir, "legacy", map[string][]byte{
		"SALT":    make([]byte, 128),
		"profile": []byte("encrypted"),
	})
	writeProfileCandidate(t, profilesDir, "broken.bak", map[string][]byte{
		"SALT": make([]byte, 128),
		"db":   []byte("not a database"),
	})
	writeProfileCandidate(t, profilesDir, "incomplete", map[string][]byte{
		"SALT": make([]byte, 12),
	})
	entries := profileEntries(t, profilesDir)

	if valid, format := inspectProfileStorageCandidate(profilesDir, entries["current"]); !valid || format != "v2" {
		t.Fatalf("current profile rejected: valid=%v format=%q", valid, format)
	}
	if valid, format := inspectProfileStorageCandidate(profilesDir, entries["legacy"]); !valid || format != "legacy" {
		t.Fatalf("legacy profile rejected: valid=%v format=%q", valid, format)
	}
	if valid, _ := inspectProfileStorageCandidate(profilesDir, entries["broken.bak"]); valid {
		t.Fatal("backup directory was accepted")
	}
	if valid, _ := inspectProfileStorageCandidate(profilesDir, entries["incomplete"]); valid {
		t.Fatal("malformed profile directory was accepted")
	}
}
