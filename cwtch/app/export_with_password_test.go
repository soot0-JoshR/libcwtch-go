package app

import (
	"archive/tar"
	"compress/gzip"
	"errors"
	"io"
	"os"
	"path/filepath"
	"testing"
	"time"

	"cwtch.im/cwtch/model/attr"
	"cwtch.im/cwtch/peer"
	"git.openprivacy.ca/openprivacy/connectivity"
	_ "github.com/mutecomm/go-sqlcipher/v4"
)

func rewriteBackupProfileID(t *testing.T, source string, destination string, profileID string) {
	t.Helper()
	input, err := os.Open(source)
	if err != nil {
		t.Fatal(err)
	}
	defer input.Close()
	gzipInput, err := gzip.NewReader(input)
	if err != nil {
		t.Fatal(err)
	}
	output, err := os.Create(destination)
	if err != nil {
		t.Fatal(err)
	}
	gzipOutput := gzip.NewWriter(output)
	tarOutput := tar.NewWriter(gzipOutput)
	tarInput := tar.NewReader(gzipInput)
	for {
		header, err := tarInput.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		copy := *header
		copy.Name = profileID + "/" + filepath.Base(header.Name)
		if err := tarOutput.WriteHeader(&copy); err != nil {
			t.Fatal(err)
		}
		if _, err := io.Copy(tarOutput, tarInput); err != nil {
			t.Fatal(err)
		}
	}
	if err := tarOutput.Close(); err != nil {
		t.Fatal(err)
	}
	if err := gzipOutput.Close(); err != nil {
		t.Fatal(err)
	}
	if err := output.Close(); err != nil {
		t.Fatal(err)
	}
}

// StegMS identity backup: a backup is encrypted with its own password, imports
// as a standard Cwtch backup, and leaves the live profile's password alone.
func TestExportWithPasswordRoundTrip(t *testing.T) {
	const backupPassword = "correct horse battery staple"
	dir := t.TempDir()
	source := NewApp(connectivity.NewLocalACN(), dir)
	source.CreatePeer("backup-probe", "", map[attr.ZonedPath]string{
		attr.ProfileZone.ConstructZonedPath("stegms_lifetime"): "persistent",
	})
	created := source.ListProfiles()
	if len(created) != 1 {
		t.Fatalf("expected one profile, got %v", created)
	}
	onion := created[0]
	profile := source.GetPeer(onion)
	backup := filepath.Join(t.TempDir(), "identity.tar.gz")
	if err := profile.ExportWithPassword(backup, "", "", ""); err == nil {
		t.Fatal("a password-less identity was backed up under the blank password")
	}

	if err := profile.ExportWithPassword(backup, "", "too-short", ""); err == nil {
		t.Fatal("a backup password shorter than the minimum was accepted")
	}
	if err := profile.ExportWithPassword(backup, "not the password", backupPassword, ""); err == nil {
		t.Fatal("the wrong current password was accepted")
	}
	// The system temp directory is not writable by apps on Android, so the
	// export must not depend on it.
	t.Setenv("TMPDIR", filepath.Join(dir, "not-writable-does-not-exist"))
	profileDirs, err := filepath.Glob(filepath.Join(dir, "profiles", "*"))
	if err != nil || len(profileDirs) != 1 {
		t.Fatalf("could not locate profile directory: %v %v", profileDirs, err)
	}
	staleExport := filepath.Join(profileDirs[0], ".cwtch-export-stale")
	if err := os.Mkdir(staleExport, 0700); err != nil {
		t.Fatal(err)
	}
	if err := profile.ExportWithPassword(backup, "", backupPassword, ""); err != nil {
		t.Fatalf("export failed: %v", err)
	}
	if leftovers, _ := filepath.Glob(filepath.Join(profileDirs[0], ".cwtch-export-*")); len(leftovers) != 0 {
		t.Fatalf("the temporary export copy was left behind: %v", leftovers)
	}
	info, err := os.Stat(backup)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm()&0077 != 0 {
		t.Fatalf("backup permissions are not private: mode=%v", info.Mode())
	}
	existing := filepath.Join(t.TempDir(), "existing.tar.gz")
	if err := os.WriteFile(existing, []byte("keep"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := profile.ExportWithPassword(existing, "", backupPassword, ""); err == nil {
		t.Fatal("export overwrote an existing file")
	}
	if contents, err := os.ReadFile(existing); err != nil || string(contents) != "keep" {
		t.Fatalf("existing export target was changed: contents=%q err=%v", contents, err)
	}
	time.Sleep(200 * time.Millisecond)
	source.Shutdown()

	// The live profile still opens with its own (blank) password.
	reopened := NewApp(connectivity.NewLocalACN(), dir)
	reopened.LoadProfiles("")
	if got := reopened.ListProfiles(); len(got) != 1 || got[0] != onion {
		t.Fatalf("the live profile no longer loads with its own password: %v", got)
	}
	reopened.Shutdown()

	// The backup does not open with the blank password or a wrong one...
	for _, wrong := range []string{"", "wrong backup password"} {
		if imported, err := peer.ImportProfile(backup, filepath.Join(t.TempDir(), "profiles"), wrong); err == nil || imported != nil {
			t.Fatalf("the backup opened with %q", wrong)
		}
	}
	// ...and restores the same identity with the backup password.
	restored, err := peer.ImportProfile(backup, filepath.Join(t.TempDir(), "profiles"), backupPassword)
	if err != nil {
		t.Fatalf("import with the backup password failed: %v", err)
	}
	if restored.GetOnion() != onion {
		t.Fatalf("restored a different identity: %s, want %s", restored.GetOnion(), onion)
	}

	// Restoring through the app brings the password-less identity back without
	// a password, so it loads at startup like the others.
	restoreDir := t.TempDir()
	target := NewApp(connectivity.NewLocalACN(), restoreDir)
	imported, err := target.ImportProfile(backup, backupPassword)
	if err != nil || imported == nil {
		t.Fatalf("app import failed: %v", err)
	}
	// The identity had no password, so restoring returns it to none.
	removed, err := imported.RestorePasswordAsItWas(backupPassword, "")
	if err != nil || !removed {
		t.Fatalf("restoring a password-less identity kept a password: removed=%v err=%v", removed, err)
	}
	time.Sleep(200 * time.Millisecond)
	target.Shutdown()
	again := NewApp(connectivity.NewLocalACN(), restoreDir)
	again.LoadProfiles("")
	if got := again.ListProfiles(); len(got) != 1 || got[0] != onion {
		t.Fatalf("the restored identity does not load with a blank password: %v", got)
	}
	again.Shutdown()
}

// An identity with its own password reports it, and is backed up under that
// same password regardless of its length.
func TestExportUnderTheIdentitysOwnPassword(t *testing.T) {
	const own = "short-pw"
	dir := t.TempDir()
	source := NewApp(connectivity.NewLocalACN(), dir)
	source.CreatePeer("protected-probe", own, map[attr.ZonedPath]string{})
	onion := source.ListProfiles()[0]
	profile := source.GetPeer(onion)
	if !profile.HasPassword("") {
		t.Fatal("a password-protected identity reported no password")
	}
	backup := filepath.Join(t.TempDir(), "identity.tar.gz")
	if err := profile.ExportWithPassword(backup, own, "a different backup password", ""); err == nil {
		t.Fatal("a password-protected identity was backed up under a separate password")
	}
	if err := profile.ExportWithPassword(backup, own, own, ""); err != nil {
		t.Fatalf("export under the identity's own password failed: %v", err)
	}
	source.Shutdown()
	restored, err := peer.ImportProfile(backup, filepath.Join(t.TempDir(), "profiles"), own)
	if err != nil || restored.GetOnion() != onion {
		t.Fatalf("the backup did not restore with the identity's password: %v", err)
	}

	blank := NewApp(connectivity.NewLocalACN(), t.TempDir())
	blank.CreatePeer("open-probe", "", map[attr.ZonedPath]string{})
	if blank.GetPeer(blank.ListProfiles()[0]).HasPassword("") {
		t.Fatal("a password-less identity reported a password")
	}
	blank.Shutdown()
}

// A backup under the identity's own password, and one made by plain Cwtch
// Export (as Vanilla Cwtch does), restore with that password kept.
func TestRestoreKeepsTheIdentitysOwnPassword(t *testing.T) {
	const own = "identity-password"
	for _, plain := range []bool{false, true} {
		dir := t.TempDir()
		source := NewApp(connectivity.NewLocalACN(), dir)
		source.CreatePeer("keep-probe", own, map[attr.ZonedPath]string{})
		onion := source.ListProfiles()[0]
		backup := filepath.Join(t.TempDir(), "identity.tar.gz")
		var err error
		if plain {
			err = source.GetPeer(onion).Export(backup)
		} else {
			err = source.GetPeer(onion).ExportWithPassword(backup, own, own, "")
		}
		if err != nil {
			t.Fatalf("export (plain=%v) failed: %v", plain, err)
		}
		source.Shutdown()

		restoreDir := t.TempDir()
		target := NewApp(connectivity.NewLocalACN(), restoreDir)
		imported, err := target.ImportProfile(backup, own)
		if err != nil {
			t.Fatalf("import (plain=%v) failed: %v", plain, err)
		}
		if removed, err := imported.RestorePasswordAsItWas(own, ""); removed || err != nil {
			t.Fatalf("restore (plain=%v) removed the identity's own password: %v %v", plain, removed, err)
		}
		time.Sleep(200 * time.Millisecond)
		target.Shutdown()

		again := NewApp(connectivity.NewLocalACN(), restoreDir)
		again.LoadProfiles("")
		if got := again.ListProfiles(); len(got) != 0 {
			t.Fatalf("restore (plain=%v): a password-protected identity loaded without its password", plain)
		}
		again.LoadProfiles(own)
		if got := again.ListProfiles(); len(got) != 1 || got[0] != onion {
			t.Fatalf("restore (plain=%v): the identity does not load with its password: %v", plain, got)
		}
		again.Shutdown()
	}
}

func TestDuplicateIdentityCanBeBackedUpAndJoined(t *testing.T) {
	const password = "identity-password"
	dir := t.TempDir()
	application := NewApp(connectivity.NewLocalACN(), dir).(*application)
	application.CreatePeer("duplicate-probe", password, map[attr.ZonedPath]string{})
	onion := application.ListProfiles()[0]
	backup := filepath.Join(t.TempDir(), "identity.tar.gz")
	if err := application.GetPeer(onion).ExportWithPassword(backup, password, password, ""); err != nil {
		t.Fatal(err)
	}
	renamed := filepath.Join(t.TempDir(), "renamed.tar.gz")
	rewriteBackupProfileID(t, backup, renamed, "00112233445566778899aabbccddeeff")
	if profile, err := application.ImportProfile(renamed, password); err == nil || profile != nil {
		t.Fatal("renamed duplicate backup was not routed to conflict review")
	}
	conflicts := application.ListDuplicateProfiles()
	if len(conflicts) != 1 || conflicts[0].Onion != onion {
		t.Fatalf("unexpected duplicate conflicts: %+v", conflicts)
	}
	currentBackup := filepath.Join(t.TempDir(), "current.tar.gz")
	duplicateBackup := filepath.Join(t.TempDir(), "duplicate.tar.gz")
	if err := application.ExportDuplicateProfile(conflicts[0].ID, "current", currentBackup, password, password, ""); err != nil {
		t.Fatal(err)
	}
	if err := application.ExportDuplicateProfile(conflicts[0].ID, "duplicate", duplicateBackup, password, password, ""); err != nil {
		t.Fatal(err)
	}
	if _, err := application.ResolveDuplicateProfile(conflicts[0].ID, "join", password, password, ""); err != nil {
		t.Fatal(err)
	}
	if conflicts := application.ListDuplicateProfiles(); len(conflicts) != 0 {
		t.Fatalf("conflict remained after join: %+v", conflicts)
	}
	if got := application.ListProfiles(); len(got) != 1 || got[0] != onion {
		t.Fatalf("joined identity is not active: %v", got)
	}
	if marker, ok := application.GetPeer(onion).GetScopedZonedAttribute(attr.LocalScope, attr.ProfileZone, peer.BackupPasswordAttribute); ok && marker != "" {
		t.Fatalf("temporary backup password marker leaked into joined profile: %q", marker)
	}
	profileDirectories, err := filepath.Glob(filepath.Join(dir, "profiles", "[0-9a-f]*"))
	if err != nil || len(profileDirectories) != 1 {
		t.Fatalf("join did not leave exactly one profile store: %v %v", profileDirectories, err)
	}
	application.Shutdown()
}

func TestKeepDuplicateRestoresPasswordlessIdentityBeforeDeletingCurrent(t *testing.T) {
	const backupPassword = "separate-backup-password"
	dir := t.TempDir()
	application := NewApp(connectivity.NewLocalACN(), dir).(*application)
	application.CreatePeer("passwordless-duplicate", "", map[attr.ZonedPath]string{})
	onion := application.ListProfiles()[0]
	currentDirectory := application.GetPeer(onion).StorageDirectory()

	backup := filepath.Join(t.TempDir(), "identity.tar.gz")
	if err := application.GetPeer(onion).ExportWithPassword(backup, "", backupPassword, ""); err != nil {
		t.Fatal(err)
	}
	renamed := filepath.Join(t.TempDir(), "renamed.tar.gz")
	rewriteBackupProfileID(t, backup, renamed, "ffeeddccbbaa99887766554433221100")
	if profile, err := application.ImportProfile(renamed, backupPassword); err == nil || profile != nil {
		t.Fatal("renamed duplicate backup was not routed to conflict review")
	}
	conflicts := application.ListDuplicateProfiles()
	if len(conflicts) != 1 {
		t.Fatalf("unexpected duplicate conflicts: %+v", conflicts)
	}
	duplicateDirectory := application.duplicateProfiles[conflicts[0].ID].duplicateDirectory
	if _, err := application.ResolveDuplicateProfile(conflicts[0].ID, "keep_duplicate", "", backupPassword, ""); err != nil {
		t.Fatal(err)
	}
	replacement := application.GetPeer(onion)
	if replacement == nil || replacement.StorageDirectory() != duplicateDirectory {
		t.Fatal("selected duplicate was not activated")
	}
	if !replacement.CheckPassword("") || replacement.CheckPassword(backupPassword) {
		t.Fatal("selected duplicate did not return to its original passwordless state")
	}
	if _, err := os.Stat(currentDirectory); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("discarded current directory remains: %v", err)
	}
	application.Shutdown()
}

func TestRepeatedLoadDoesNotRegisterActiveStoreAsDuplicate(t *testing.T) {
	dir := t.TempDir()
	application := NewApp(connectivity.NewLocalACN(), dir).(*application)
	application.CreatePeer("load-once", "profile-password", map[attr.ZonedPath]string{})
	application.LoadProfiles("profile-password")
	if conflicts := application.ListDuplicateProfiles(); len(conflicts) != 0 {
		t.Fatalf("active store was registered as a duplicate: %+v", conflicts)
	}
	application.Shutdown()
}
