package v1

import (
	"git.openprivacy.ca/openprivacy/log"
	"os"
	"path"
)

// fileStore stores a cwtchPeer in an encrypted file
type fileStore struct {
	directory string
	filename  string
	key       [32]byte
}

// FileStore is a primitive around storing encrypted files
type FileStore interface {
	Write([]byte) error
	Read() ([]byte, error)
	Delete()
	ChangeKey(newkey [32]byte)
}

// NewFileStore instantiates a fileStore given a filename and a password
func NewFileStore(directory string, filename string, key [32]byte) FileStore {
	filestore := new(fileStore)
	filestore.key = key
	filestore.filename = filename
	filestore.directory = directory
	return filestore
}

// write serializes a cwtchPeer to a file
func (fps *fileStore) Write(data []byte) error {
	encryptedbytes, err := EncryptFileData(data, fps.key)
	if err != nil {
		return err
	}

	err = os.WriteFile(path.Join(fps.directory, fps.filename), encryptedbytes, 0600)
	return err
}

func (fps *fileStore) Read() ([]byte, error) {
	return ReadEncryptedFile(fps.directory, fps.filename, fps.key)
}

func (fps *fileStore) Delete() {
	err := os.Remove(path.Join(fps.directory, fps.filename))
	if err != nil {
		log.Errorf("Deleting file %v\n", err)
	}
}

func (fps *fileStore) ChangeKey(newkey [32]byte) {
	fps.key = newkey
}
