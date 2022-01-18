package utils

import (
	"sync"

	"cwtch.im/cwtch/event"
	"cwtch.im/cwtch/storage/v1"

	"encoding/json"
	"io/ioutil"
	"os"
	"path"

	"git.openprivacy.ca/openprivacy/log"
)

const (
	CwtchStarted         = event.Type("CwtchStarted")
	CwtchStartError      = event.Type("CwtchStartError")
	UpdateGlobalSettings = event.Type("UpdateGlobalSettings")
)

var GlobalSettingsFile v1.FileStore
var lock sync.Mutex

const GlobalSettingsFilename = "ui.globals"
const saltFile = "SALT"

type GlobalSettings struct {
	Locale                  string
	Theme                   string
	ThemeMode               string
	PreviousPid             int64
	ExperimentsEnabled      bool
	Experiments             map[string]bool
	BlockUnknownConnections bool
	StreamerMode            bool
	StateRootPane           int
	FirstTime               bool
	UIColumnModePortrait    string
	UIColumnModeLandscape   string
	DownloadPath            string
	AllowAdvancedTorConfig  bool
	CustomTorrc             string
	UseCustomTorrc          bool
	UseExternalTor          bool
	CustomSocksPort         int
	CustomControlPort       int
	UseTorCache             bool
	TorCacheDir             string
}

var DefaultGlobalSettings = GlobalSettings{
	Locale:                  "en",
	Theme:                   "dark",
	PreviousPid:             -1,
	ExperimentsEnabled:      false,
	Experiments:             make(map[string]bool),
	StateRootPane:           0,
	FirstTime:               true,
	BlockUnknownConnections: false,
	StreamerMode:            false,
	UIColumnModePortrait:    "DualpaneMode.Single",
	UIColumnModeLandscape:   "DualpaneMode.CopyPortrait",
	DownloadPath:            "",
	AllowAdvancedTorConfig:  false,
	CustomTorrc:             "",
	UseCustomTorrc:          false,
	CustomSocksPort:         -1,
	CustomControlPort:       -1,
	UseTorCache:             false,
	TorCacheDir:             "",
}

func InitGlobalSettingsFile(directory string, password string) error {
	lock.Lock()
	defer lock.Unlock()
	var key [32]byte
	salt, err := ioutil.ReadFile(path.Join(directory, saltFile))
	if err != nil {
		log.Infof("Could not find salt file: %v (creating a new settings file)", err)
		var newSalt [128]byte
		key, newSalt, err = v1.CreateKeySalt(password)
		if err != nil {
			log.Errorf("Could not initialize salt: %v", err)
			return err
		}
		os.Mkdir(directory, 0700)
		err := ioutil.WriteFile(path.Join(directory, saltFile), newSalt[:], 0600)
		if err != nil {
			log.Errorf("Could not write salt file: %v", err)
			return err
		}
	} else {
		key = v1.CreateKey(password, salt)
	}

	GlobalSettingsFile = v1.NewFileStore(directory, GlobalSettingsFilename, key)
	log.Infof("initialized global settings file: %v", GlobalSettingsFile)
	return nil
}

func ReadGlobalSettings() *GlobalSettings {
	lock.Lock()
	defer lock.Unlock()
	settings := DefaultGlobalSettings

	if GlobalSettingsFile == nil {
		log.Errorf("Global Settings File was not Initialized Properly")
		return &settings
	}

	settingsBytes, err := GlobalSettingsFile.Read()
	if err != nil {
		log.Infof("Could not read global ui settings: %v (assuming this is a first time app deployment...)", err)
		return &settings //firstTime = true
	}

	err = json.Unmarshal(settingsBytes, &settings)
	if err != nil {
		log.Errorf("Could not parse global ui settings: %v\n", err)
		// TODO if settings is corrupted, we probably want to alert the UI.
		return &settings //firstTime = true
	}

	log.Debugf("Settings: %#v", settings)
	return &settings
}

func WriteGlobalSettings(globalSettings GlobalSettings) {
	lock.Lock()
	defer lock.Unlock()
	bytes, _ := json.Marshal(globalSettings)
	// override first time setting
	globalSettings.FirstTime = true
	err := GlobalSettingsFile.Write(bytes)
	if err != nil {
		log.Errorf("Could not write global ui settings: %v\n", err)
	}
}
