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
	profileID, err := checkCwtchProfileBackupFile(exportedCwtchFile)
	if profileID == "" || err != nil {
		log.Errorf("%s is an invalid cwtch backup file: %s", profileID, err)
		return nil, err
	}
	log.Infof("%s is a valid cwtch backup file", profileID)

	profileDBFile := filepath.Join(profilesDir, profileID, dbFile)
	log.Debugf("checking %v", profileDBFile)
	if _, err := os.Stat(profileDBFile); errors.Is(err, os.ErrNotExist) {
		// backup is valid and the profile hasn't been imported yet, time to extract and check the password
		profileDir := filepath.Join(profilesDir, profileID)
		os.MkdirAll(profileDir, 0700)
		err := importCwtchProfileBackupFile(exportedCwtchFile, profilesDir)
		if err == nil {
			profile, err := FromEncryptedDatabase(profileDir, password)
			if err == nil {
				return profile, err
			}
			//  Otherwise purge
			log.Errorf("error importing profile: %v. removing %s", err, profileDir)
			os.RemoveAll(profileDir)
			return nil, err
		}
		return nil, err
	}
	return nil, fmt.Errorf("%s is already a profile for this app", profileID)
}

func checkCwtchProfileBackupFile(srcFile string) (string, error) {
	f, err := os.Open(srcFile)
	if err != nil {
		return "", err
	}
	defer f.Close()

	gzf, err := gzip.NewReader(f)
	if err != nil {
		return "", err
	}

	tarReader := tar.NewReader(gzf)

	profileName := ""

	for {
		header, err := tarReader.Next()

		if err == io.EOF {
			break
		}

		if err != nil {
			return "", err
		}

		switch header.Typeflag {
		case tar.TypeDir:
			return "", errors.New("invalid cwtch backup file")
		case tar.TypeReg:
			parts := strings.Split(header.Name, "/")
			if len(parts) != 2 {
				return "", errors.New("invalid header name")
			}
			dir := parts[0]
			profileFileType := parts[1]

			_, hexErr := hex.DecodeString(dir)
			if dir == "." || dir == ".." || len(dir) != 32 || hexErr != nil {
				return "", errors.New("invalid profile name")
			}

			if profileName == "" {
				profileName = dir
			}
			if dir != profileName {
				return "", errors.New("invalid cwtch backup file")
			}

			if profileFileType != dbFile && profileFileType != saltFile && profileFileType != versionFile {
				return "", errors.New("invalid cwtch backup file")
			}
		default:
			return "", errors.New("invalid cwtch backup file")
		}
	}
	return profileName, nil
}

func importCwtchProfileBackupFile(srcFile string, profilesDir string) error {
	f, err := os.Open(srcFile)
	if err != nil {
		return err
	}
	defer f.Close()

	gzf, err := gzip.NewReader(f)
	if err != nil {
		return err
	}

	tarReader := tar.NewReader(gzf)

	profileName := ""

	for {
		header, err := tarReader.Next()

		if err == io.EOF {
			break
		}

		if err != nil {
			return err
		}

		switch header.Typeflag {
		case tar.TypeDir:
			return errors.New("invalid cwtch backup file")
		case tar.TypeReg:
			// using split here because we deliberately construct these paths in a cross-platform consistent way
			parts := strings.Split(header.Name, "/")
			if len(parts) != 2 {
				return errors.New("invalid header name")
			}
			dir := parts[0]
			base := parts[1]

			_, hexErr := hex.DecodeString(dir)
			if dir == "." || dir == ".." || len(dir) != 32 || hexErr != nil {
				return errors.New("invalid profile name")
			}

			if profileName == "" {
				profileName = dir
			}

			if dir != profileName {
				return errors.New("invalid cwtch backup file")
			}

			// here we use filepath.Join to construct a valid directory path
			outFile, err := os.Create(filepath.Join(profilesDir, dir, base))
			if err != nil {
				return fmt.Errorf("error importing cwtch profile file: %s", err)
			}
			defer outFile.Close()
			if _, err := io.Copy(outFile, tarReader); err != nil {
				return fmt.Errorf("error importing cwtch profile file: %s", err)
			}
		default:
			return errors.New("invalid cwtch backup file")
		}
	}
	return nil
}
