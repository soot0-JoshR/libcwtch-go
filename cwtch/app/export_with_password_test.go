package app

import (
	"path/filepath"
	"testing"
	"time"

	"cwtch.im/cwtch/model/attr"
	"cwtch.im/cwtch/peer"
	"git.openprivacy.ca/openprivacy/connectivity"
	_ "github.com/mutecomm/go-sqlcipher/v4"
)

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

	if err := profile.ExportWithPassword(backup, "", "too-short"); err == nil {
		t.Fatal("a backup password shorter than the minimum was accepted")
	}
	if err := profile.ExportWithPassword(backup, "not the password", backupPassword); err == nil {
		t.Fatal("the wrong current password was accepted")
	}
	// The system temp directory is not writable by apps on Android, so the
	// export must not depend on it.
	t.Setenv("TMPDIR", filepath.Join(dir, "not-writable-does-not-exist"))
	if err := profile.ExportWithPassword(backup, "", backupPassword); err != nil {
		t.Fatalf("export failed: %v", err)
	}
	if leftovers, _ := filepath.Glob(filepath.Join(dir, "cwtch-export-*")); len(leftovers) != 0 {
		t.Fatalf("the temporary export copy was left behind: %v", leftovers)
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

	// Restoring through the app and re-keying to a blank password makes the
	// identity load at startup like any password-less one.
	restoreDir := t.TempDir()
	target := NewApp(connectivity.NewLocalACN(), restoreDir)
	imported, err := target.ImportProfile(backup, backupPassword)
	if err != nil || imported == nil {
		t.Fatalf("app import failed: %v", err)
	}
	if err := imported.ChangePassword(backupPassword, "", ""); err != nil {
		t.Fatalf("re-keying the restored profile failed: %v", err)
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
	if err := profile.ExportWithPassword(backup, own, own); err != nil {
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
