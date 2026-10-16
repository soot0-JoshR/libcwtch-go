package app

import (
	"os"
	"path/filepath"
	"testing"
)

func TestDuplicateBackupReceiptsAreBoundToSavedFilesAndStorePair(t *testing.T) {
	directory := t.TempDir()
	app := &application{directory: directory}
	conflict := DuplicateProfile{
		currentDirectory:   filepath.Join(directory, "profiles", "current"),
		duplicateDirectory: filepath.Join(directory, "profiles", "duplicate"),
	}
	backup := filepath.Join(t.TempDir(), "current.tar.gz")
	if err := os.WriteFile(backup, []byte("saved backup"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := app.recordDuplicateBackup(conflict, "current", backup); err != nil {
		t.Fatal(err)
	}
	if receipt := app.readDuplicateReceipt(conflict); receipt.Current == nil || receipt.Duplicate != nil {
		t.Fatalf("unexpected receipt: %+v", receipt)
	}
	reversed := DuplicateProfile{currentDirectory: conflict.duplicateDirectory, duplicateDirectory: conflict.currentDirectory}
	if receipt := app.readDuplicateReceipt(reversed); receipt.Current != nil || receipt.Duplicate == nil {
		t.Fatalf("receipt did not follow the correct store after load-order reversal: %+v", receipt)
	}
	if err := os.WriteFile(backup, []byte("changed backup"), 0600); err != nil {
		t.Fatal(err)
	}
	if receipt := app.readDuplicateReceipt(conflict); receipt.Current != nil {
		t.Fatal("changed backup still counted as saved")
	}
	if receipt := app.readDuplicateReceipt(DuplicateProfile{
		currentDirectory:   conflict.currentDirectory,
		duplicateDirectory: filepath.Join(directory, "profiles", "unrelated"),
	}); receipt.Current != nil || receipt.Duplicate != nil {
		t.Fatal("receipt counted for a different store pair")
	}
}
