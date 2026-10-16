package app

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
)

// A receipt records only where a successful safety export was saved and its
// digest. It contains no passwords or profile contents. The two source store
// paths bind it to one particular conflict even when the in-memory ID changes
// after a restart.
type duplicateBackupReceipt struct {
	CurrentDirectory   string             `json:"currentDirectory"`
	DuplicateDirectory string             `json:"duplicateDirectory"`
	Current            *backupFileReceipt `json:"current,omitempty"`
	Duplicate          *backupFileReceipt `json:"duplicate,omitempty"`
}

type backupFileReceipt struct {
	Path   string `json:"path"`
	SHA256 string `json:"sha256"`
}

func (app *application) duplicateReceiptPath(conflict DuplicateProfile) string {
	first, second := conflict.currentDirectory, conflict.duplicateDirectory
	if first > second {
		first, second = second, first
	}
	key := sha256.Sum256([]byte(first + "\x00" + second))
	return filepath.Join(app.directory, "duplicate-backup-receipts", hex.EncodeToString(key[:])+".json")
}

func validBackupFile(receipt *backupFileReceipt) bool {
	if receipt == nil || !filepath.IsAbs(receipt.Path) || len(receipt.SHA256) != 64 {
		return false
	}
	file, err := os.Open(receipt.Path)
	if err != nil {
		return false
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() {
		return false
	}
	hash := sha256.New()
	if _, err := io.Copy(hash, file); err != nil {
		return false
	}
	return hex.EncodeToString(hash.Sum(nil)) == receipt.SHA256
}

func (app *application) readDuplicateReceipt(conflict DuplicateProfile) duplicateBackupReceipt {
	receipt := duplicateBackupReceipt{
		CurrentDirectory:   conflict.currentDirectory,
		DuplicateDirectory: conflict.duplicateDirectory,
	}
	contents, err := os.ReadFile(app.duplicateReceiptPath(conflict))
	if err != nil {
		return receipt
	}
	var stored duplicateBackupReceipt
	if err := json.Unmarshal(contents, &stored); err != nil {
		return receipt
	}
	current, duplicate := stored.Current, stored.Duplicate
	if stored.CurrentDirectory == receipt.DuplicateDirectory && stored.DuplicateDirectory == receipt.CurrentDirectory {
		current, duplicate = duplicate, current
	} else if stored.CurrentDirectory != receipt.CurrentDirectory || stored.DuplicateDirectory != receipt.DuplicateDirectory {
		return receipt
	}
	if validBackupFile(current) {
		receipt.Current = current
	}
	if validBackupFile(duplicate) {
		receipt.Duplicate = duplicate
	}
	return receipt
}

func (app *application) recordDuplicateBackup(conflict DuplicateProfile, side string, filePath string) error {
	absolutePath, err := filepath.Abs(filePath)
	if err != nil {
		return err
	}
	file, err := os.Open(absolutePath)
	if err != nil {
		return err
	}
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() {
		file.Close()
		return fmt.Errorf("backup is not a regular file")
	}
	hash := sha256.New()
	_, err = io.Copy(hash, file)
	closeErr := file.Close()
	if err != nil {
		return err
	}
	if closeErr != nil {
		return closeErr
	}
	receipt := app.readDuplicateReceipt(conflict)
	entry := &backupFileReceipt{Path: absolutePath, SHA256: hex.EncodeToString(hash.Sum(nil))}
	if side == "current" {
		receipt.Current = entry
	} else {
		receipt.Duplicate = entry
	}
	destination := app.duplicateReceiptPath(conflict)
	if err := os.MkdirAll(filepath.Dir(destination), 0700); err != nil {
		return err
	}
	temporary, err := os.CreateTemp(filepath.Dir(destination), ".receipt-")
	if err != nil {
		return err
	}
	defer os.Remove(temporary.Name())
	if err := json.NewEncoder(temporary).Encode(receipt); err != nil {
		temporary.Close()
		return err
	}
	if err := temporary.Sync(); err != nil {
		temporary.Close()
		return err
	}
	if err := temporary.Close(); err != nil {
		return err
	}
	return os.Rename(temporary.Name(), destination)
}
