package peer

import (
	"archive/tar"
	"compress/gzip"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"git.openprivacy.ca/openprivacy/log"
	"golang.org/x/crypto/pbkdf2"
	"golang.org/x/crypto/sha3"
	"io"
	"os"
	"path"
	"path/filepath"
	"strings"
)

const versionFile = "VERSION"
const version = "2"
const saltFile = "SALT"
const dbFile = "db"

const (
	maxProfileBackupEntries       = 3
	maxProfileBackupDatabaseBytes = int64(2 * 1024 * 1024 * 1024)
	maxProfileBackupVersionBytes  = int64(32)
)

// CreateKeySalt derives a key and salt from a password: returns key, salt, err
func CreateKeySalt(password string) ([32]byte, [128]byte, error) {
	var salt [128]byte
	if _, err := io.ReadFull(rand.Reader, salt[:]); err != nil {
		log.Errorf("Cannot read from random: %v\n", err)
		return [32]byte{}, salt, err
	}
	dk := pbkdf2.Key([]byte(password), salt[:], 4096, 32, sha3.New512)

	var dkr [32]byte
	copy(dkr[:], dk)
	return dkr, salt, nil
}

// createKey derives a key from a password and salt
func createKey(password string, salt []byte) [32]byte {
	dk := pbkdf2.Key([]byte(password), salt, 4096, 32, sha3.New512)

	var dkr [32]byte
	copy(dkr[:], dk)
	return dkr
}

func initV2Directory(directory, password string) ([32]byte, [128]byte, error) {
	os.Mkdir(directory, 0700)

	key, salt, err := CreateKeySalt(password)
	if err != nil {
		log.Errorf("Could not create key for profile store from password: %v\n", err)
		return [32]byte{}, [128]byte{}, err
	}

	if err = os.WriteFile(path.Join(directory, versionFile), []byte(version), 0600); err != nil {
		log.Errorf("Could not write version file: %v", err)
		return [32]byte{}, [128]byte{}, err
	}

	if err = os.WriteFile(path.Join(directory, saltFile), salt[:], 0600); err != nil {
		log.Errorf("Could not write salt file: %v", err)
		return [32]byte{}, [128]byte{}, err
	}

	return key, salt, nil
}

func openEncryptedDatabase(profileDirectory string, password string, createIfNotExists bool) (*sql.DB, error) {
	salt, err := os.ReadFile(path.Join(profileDirectory, saltFile))
	if err != nil {
		return nil, err
	}

	key := createKey(password, salt)
	dbPath := filepath.Join(profileDirectory, "db")

	if !createIfNotExists {
		if _, err := os.Stat(dbPath); errors.Is(err, os.ErrNotExist) {
			return nil, err
		}
	}

	dbname := fmt.Sprintf("%v?_pragma_key=x'%x'&_pragma_cipher_page_size=8192", dbPath, key)
	db, err := sql.Open("sqlite3", dbname)
	if err != nil {
		log.Errorf("could not open encrypted database", err)
		return nil, err
	}
	return db, nil
}

func randomMemoryStoreID() (string, error) {
	var id [16]byte
	if _, err := io.ReadFull(rand.Reader, id[:]); err != nil {
		return "", err
	}
	return hex.EncodeToString(id[:]), nil
}

func openMemoryDatabase(password string, storeID string) (*sql.DB, error) {
	// We use a dummy key to initialize the SQLCipher memory database
	key := createKey(password, []byte("ephemeral-salt"))
	dbname := fmt.Sprintf("file:cwtch-ephemeral-%s?mode=memory&cache=shared&_pragma_key=x'%x'&_pragma_cipher_page_size=8192", storeID, key)
	db, err := sql.Open("sqlite3", dbname)
	if err != nil {
		log.Errorf("could not open memory database", err)
		return nil, err
	}
	return db, nil
}

// CreateMemoryStorePeer creates a *new* Cwtch Profile backed by an in-memory datastore
func CreateMemoryStorePeer(name string, password string) (CwtchPeer, error) {
	log.Debugf("Opening Memory Database")
	storeID, err := randomMemoryStoreID()
	if err != nil {
		return nil, fmt.Errorf("unable to generate memory store id: %v", err)
	}
	db, err := openMemoryDatabase(password, storeID)
	if db == nil || err != nil {
		return nil, fmt.Errorf("unable to open memory database: error: %v", err)
	}

	log.Debugf("Initializing Database")
	err = initializeDatabase(db)

	if err != nil {
		db.Close()
		return nil, err
	}

	log.Debugf("Creating Cwtch Profile Backed By Memory Database")

	profileDirectory := "memory://" + storeID
	cps, err := NewMemoryCwtchProfileStorage(db, profileDirectory)
	if err != nil {
		db.Close()
		return nil, err
	}

	return NewProfileWithEncryptedStorage(name, cps), nil
}

// CreateEncryptedStorePeer creates a *new* Cwtch Profile backed by an encrypted datastore
func CreateEncryptedStorePeer(profileDirectory string, name string, password string) (CwtchPeer, error) {
	log.Debugf("Initializing Encrypted Storage Directory")
	_, _, err := initV2Directory(profileDirectory, password)
	if err != nil {
		return nil, err
	}

	log.Debugf("Opening Encrypted Database")
	db, err := openEncryptedDatabase(profileDirectory, password, true)
	if db == nil || err != nil {
		return nil, fmt.Errorf("unable to open encrypted database: error: %v", err)
	}

	log.Debugf("Initializing Database")
	err = initializeDatabase(db)

	if err != nil {
		db.Close()
		return nil, err
	}

	log.Debugf("Creating Cwtch Profile Backed By Encrypted Database")

	cps, err := NewCwtchProfileStorage(db, profileDirectory)
	if err != nil {
		db.Close()
		return nil, err
	}

	return NewProfileWithEncryptedStorage(name, cps), nil
}

// CreateEncryptedStore creates a encrypted datastore
func CreateEncryptedStore(profileDirectory string, password string) (*CwtchProfileStorage, error) {

	log.Debugf("Creating Encrypted Database")
	db, err := openEncryptedDatabase(profileDirectory, password, true)
	if db == nil || err != nil {
		return nil, fmt.Errorf("unable to open encrypted database: error: %v", err)
	}

	log.Debugf("Initializing Database")
	err = initializeDatabase(db)

	if err != nil {
		db.Close()
		return nil, err
	}

	log.Debugf("Creating Cwtch Profile Backed By Encrypted Database")

	cps, err := NewCwtchProfileStorage(db, profileDirectory)
	if err != nil {
		db.Close()
		return nil, err
	}

	return cps, nil
}

// FromEncryptedDatabase constructs a Cwtch Profile from an existing Encrypted Database
func FromEncryptedDatabase(profileDirectory string, password string) (CwtchPeer, error) {
	log.Infof("Loading Encrypted Profile: %v", profileDirectory)
	db, err := openEncryptedDatabase(profileDirectory, password, false)
	if db == nil || err != nil {
		return nil, fmt.Errorf("unable to open encrypted database: error: %v", err)
	}

	log.Debugf("Initializing Profile from Encrypted Storage")
	cps, err := NewCwtchProfileStorage(db, profileDirectory)
	if err != nil {
		db.Close()
		return nil, err
	}
	return FromEncryptedStorage(cps), nil
}

func ImportProfile(exportedCwtchFile string, profilesDir string, password string) (CwtchPeer, error) {
	profileID, profileDir, err := extractCwtchProfileBackupFile(exportedCwtchFile, profilesDir)
	if err != nil {
		log.Errorf("%s is an invalid cwtch backup file: %v", profileID, err)
		return nil, err
	}
	keepProfileDir := false
	defer func() {
		if !keepProfileDir {
			_ = os.RemoveAll(profileDir)
		}
	}()

	profile, err := FromEncryptedDatabase(profileDir, password)
	if err != nil {
		log.Errorf("error importing profile: %v. removing %s", err, profileDir)
		return nil, err
	}
	keepProfileDir = true
	return profile, nil
}

// extractCwtchProfileBackupFile validates and extracts one archive from one
// open file descriptor. It writes into a private sibling directory and only
// renames that directory to the archive's profile ID after all three expected
// regular files have been written and closed successfully.
func extractCwtchProfileBackupFile(srcFile string, profilesDir string) (string, string, error) {
	f, err := os.Open(srcFile)
	if err != nil {
		return "", "", err
	}
	defer f.Close()

	gzf, err := gzip.NewReader(f)
	if err != nil {
		return "", "", err
	}
	defer gzf.Close()

	tarReader := tar.NewReader(gzf)
	if err := os.MkdirAll(profilesDir, 0700); err != nil {
		return "", "", err
	}
	stagingDir, err := os.MkdirTemp(profilesDir, ".cwtch-import-")
	if err != nil {
		return "", "", err
	}
	keepStagingDir := false
	defer func() {
		if !keepStagingDir {
			_ = os.RemoveAll(stagingDir)
		}
	}()

	profileName := ""
	seen := make(map[string]bool, maxProfileBackupEntries)
	entryCount := 0

	for {
		header, err := tarReader.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return profileName, "", err
		}
		entryCount++
		if entryCount > maxProfileBackupEntries || header.Typeflag != tar.TypeReg {
			return profileName, "", errors.New("invalid cwtch backup file")
		}
		parts := strings.Split(header.Name, "/")
		if len(parts) != 2 {
			return profileName, "", errors.New("invalid header name")
		}
		dir, base := parts[0], parts[1]
		_, hexErr := hex.DecodeString(dir)
		if len(dir) != 32 || hexErr != nil {
			return profileName, "", errors.New("invalid profile name")
		}
		if profileName == "" {
			profileName = dir
		}
		if dir != profileName || seen[base] {
			return profileName, "", errors.New("invalid cwtch backup file")
		}
		switch base {
		case dbFile, saltFile, versionFile:
			if !validProfileBackupEntrySize(base, header.Size) {
				return profileName, "", fmt.Errorf("invalid %s size in cwtch backup", base)
			}
		default:
			return profileName, "", errors.New("invalid cwtch backup file")
		}
		seen[base] = true

		outFile, err := os.OpenFile(filepath.Join(stagingDir, base), os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
		if err != nil {
			return profileName, "", fmt.Errorf("error importing cwtch profile file: %w", err)
		}
		_, copyErr := io.CopyN(outFile, tarReader, header.Size)
		closeErr := outFile.Close()
		if copyErr != nil {
			return profileName, "", fmt.Errorf("error importing cwtch profile file: %w", copyErr)
		}
		if closeErr != nil {
			return profileName, "", fmt.Errorf("error closing imported cwtch profile file: %w", closeErr)
		}
	}
	if profileName == "" || len(seen) != maxProfileBackupEntries || !seen[dbFile] || !seen[saltFile] || !seen[versionFile] {
		return profileName, "", errors.New("cwtch backup is missing required files")
	}
	// tar.Reader stops at the archive end markers. Drain the gzip stream so its
	// checksum and trailer are verified before installing the extracted files.
	if _, err := io.Copy(io.Discard, gzf); err != nil {
		return profileName, "", fmt.Errorf("invalid compressed cwtch backup: %w", err)
	}

	profileDir := filepath.Join(profilesDir, profileName)
	if _, err := os.Lstat(profileDir); err == nil {
		return profileName, "", fmt.Errorf("%s is already a profile for this app", profileName)
	} else if !errors.Is(err, os.ErrNotExist) {
		return profileName, "", err
	}
	if err := os.Rename(stagingDir, profileDir); err != nil {
		return profileName, "", fmt.Errorf("could not install imported profile: %w", err)
	}
	keepStagingDir = true
	return profileName, profileDir, nil
}

func validProfileBackupEntrySize(base string, size int64) bool {
	switch base {
	case dbFile:
		return size > 0 && size <= maxProfileBackupDatabaseBytes
	case saltFile:
		return size == 128
	case versionFile:
		return size > 0 && size <= maxProfileBackupVersionBytes
	default:
		return false
	}
}
