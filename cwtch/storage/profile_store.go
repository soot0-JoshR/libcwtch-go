package storage

import (
	"cwtch.im/cwtch/model"
	"cwtch.im/cwtch/storage/v1"
)

// ProfileStore is an interface to managing the storage of Cwtch Profiles
type ProfileStore interface {
	GetProfileCopy(timeline bool) *model.Profile
}

// LoadProfileWriterStore loads a profile store from filestore listening for events and saving them
// directory should be $appDir/profiles/$rand
func LoadProfileWriterStore(directory, password string) (ProfileStore, error) {
	return v1.LoadProfileWriterStore(directory, password)
}
