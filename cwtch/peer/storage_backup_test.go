package peer

import (
	"archive/tar"
	"compress/gzip"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

type backupTestEntry struct {
	name     string
	contents string
	size     int64
	typeflag byte
}

func writeBackupTestArchive(t *testing.T, entries []backupTestEntry) string {
	t.Helper()
	archivePath := filepath.Join(t.TempDir(), "backup.tar.gz")
	file, err := os.Create(archivePath)
	if err != nil {
		t.Fatal(err)
	}
	gzipWriter := gzip.NewWriter(file)
	tarWriter := tar.NewWriter(gzipWriter)
	for _, entry := range entries {
		size := entry.size
		if size == 0 {
			size = int64(len(entry.contents))
		}
		typeflag := entry.typeflag
		if typeflag == 0 {
			typeflag = tar.TypeReg
		}
		if err := tarWriter.WriteHeader(&tar.Header{Name: entry.name, Mode: 0600, Size: size, Typeflag: typeflag}); err != nil {
			t.Fatal(err)
		}
		if entry.contents != "" {
			if _, err := tarWriter.Write([]byte(entry.contents)); err != nil {
				t.Fatal(err)
			}
		}
	}
	if err := tarWriter.Close(); err != nil {
		t.Fatal(err)
	}
	if err := gzipWriter.Close(); err != nil {
		t.Fatal(err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
	return archivePath
}

func validBackupTestEntries(profileID string) []backupTestEntry {
	return []backupTestEntry{
		{name: profileID + "/db", contents: "database"},
		{name: profileID + "/SALT", contents: strings.Repeat("s", 128)},
		{name: profileID + "/VERSION", contents: "2"},
	}
}

func TestExtractCwtchProfileBackupIsBoundedAndExact(t *testing.T) {
	const profileID = "00112233445566778899aabbccddeeff"
	tests := []struct {
		name    string
		entries []backupTestEntry
	}{
		{name: "backslash traversal", entries: []backupTestEntry{
			{name: profileID + `/..\outside`, contents: "x"},
			{name: profileID + "/SALT", contents: strings.Repeat("s", 128)},
			{name: profileID + "/VERSION", contents: "2"},
		}},
		{name: "duplicate entry", entries: append(validBackupTestEntries(profileID), backupTestEntry{name: profileID + "/db", contents: "again"})},
		{name: "missing entry", entries: validBackupTestEntries(profileID)[:2]},
		{name: "non-regular entry", entries: []backupTestEntry{
			{name: profileID + "/db", typeflag: tar.TypeSymlink},
			{name: profileID + "/SALT", contents: strings.Repeat("s", 128)},
			{name: profileID + "/VERSION", contents: "2"},
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			profilesDir := filepath.Join(t.TempDir(), "profiles")
			archivePath := writeBackupTestArchive(t, test.entries)
			if _, _, err := extractCwtchProfileBackupFile(archivePath, profilesDir); err == nil {
				t.Fatal("malformed backup was accepted")
			}
			entries, err := os.ReadDir(profilesDir)
			if err != nil {
				t.Fatal(err)
			}
			if len(entries) != 0 {
				t.Fatalf("failed extraction left files behind: %v", entries)
			}
		})
	}
}

func TestProfileBackupEntrySizePolicy(t *testing.T) {
	if validProfileBackupEntrySize(dbFile, maxProfileBackupDatabaseBytes+1) {
		t.Fatal("oversized profile database was accepted")
	}
	if validProfileBackupEntrySize(saltFile, 127) || validProfileBackupEntrySize(versionFile, maxProfileBackupVersionBytes+1) {
		t.Fatal("invalid metadata size was accepted")
	}
}

func TestExtractCwtchProfileBackupDoesNotMerge(t *testing.T) {
	const profileID = "00112233445566778899aabbccddeeff"
	profilesDir := filepath.Join(t.TempDir(), "profiles")
	existingDir := filepath.Join(profilesDir, profileID)
	if err := os.MkdirAll(existingDir, 0700); err != nil {
		t.Fatal(err)
	}
	sentinel := filepath.Join(existingDir, "sentinel")
	if err := os.WriteFile(sentinel, []byte("keep"), 0600); err != nil {
		t.Fatal(err)
	}
	archivePath := writeBackupTestArchive(t, validBackupTestEntries(profileID))
	if _, _, err := extractCwtchProfileBackupFile(archivePath, profilesDir); err == nil {
		t.Fatal("backup merged into an existing profile directory")
	}
	contents, err := os.ReadFile(sentinel)
	if err != nil || string(contents) != "keep" {
		t.Fatalf("existing profile was changed: contents=%q err=%v", contents, err)
	}
}
