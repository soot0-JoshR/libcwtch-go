package v1

import (
	"cwtch.im/cwtch/event"
	"cwtch.im/cwtch/model"
	"encoding/json"
	"git.openprivacy.ca/openprivacy/log"
	"os"
	"path"
)

const profileFilename = "profile"
const saltFile = "SALT"

// ProfileStoreV1 storage for profiles and message streams that uses in memory key and fs stored salt instead of in memory password
type ProfileStoreV1 struct {
	fs        FileStore
	directory string
	profile   *model.Profile
	key       [32]byte
	salt      [128]byte
}

// LoadProfileWriterStore loads a profile store from filestore listening for events and saving them
// directory should be $appDir/profiles/$rand
func LoadProfileWriterStore(directory, password string) (*ProfileStoreV1, error) {
	salt, err := os.ReadFile(path.Join(directory, saltFile))
	if err != nil {
		return nil, err
	}

	key := CreateKey(password, salt)

	ps := &ProfileStoreV1{fs: NewFileStore(directory, profileFilename, key), key: key, directory: directory, profile: nil}
	copy(ps.salt[:], salt)

	err = ps.load()
	if err != nil {
		return nil, err
	}

	return ps, nil
}

// load instantiates a cwtchPeer from the file store
func (ps *ProfileStoreV1) load() error {
	decrypted, err := ps.fs.Read()
	if err != nil {
		return err
	}
	cp := new(model.Profile)
	err = json.Unmarshal(decrypted, &cp)

	if err == nil {
		ps.profile = cp

		// TODO 2020.06.09: v1 update, Remove on v2
		// if we already have the contact it can be assumed "approved" unless blocked
		for _, contact := range cp.Contacts {
			if contact.Authorization == "" {
				if contact.DeprecatedBlocked {
					contact.Authorization = model.AuthBlocked
				} else {
					contact.Authorization = model.AuthApproved
				}
			}

			if contact.Attributes[event.SaveHistoryKey] == event.SaveHistoryConfirmed {
				ss := NewStreamStore(ps.directory, contact.LocalID, ps.key)
				cp.Contacts[contact.Onion].Timeline.SetMessages(ss.Read())
			}
		}

		for gid, group := range cp.Groups {
			if group.Version == 0 {
				log.Infof("group %v is of unsupported version 0. dropping group...\n", group.GroupID)
				delete(cp.Groups, gid)
				continue
			}
			ss := NewStreamStore(ps.directory, group.LocalID, ps.key)
			cp.Groups[gid].Timeline.SetMessages(ss.Read())
			cp.Groups[gid].Timeline.Sort()
		}
	}

	return err
}

// GetProfileCopy returns a copy of the stored profile
func (ps *ProfileStoreV1) GetProfileCopy(timeline bool) *model.Profile {
	return ps.profile.GetCopy(timeline)
}
