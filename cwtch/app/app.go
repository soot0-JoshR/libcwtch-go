package app

import (
	"cwtch.im/cwtch/app/plugins"
	"cwtch.im/cwtch/event"
	"cwtch.im/cwtch/model"
	"cwtch.im/cwtch/model/attr"
	"cwtch.im/cwtch/model/constants"
	"cwtch.im/cwtch/peer"
	"cwtch.im/cwtch/protocol/connections"
	"cwtch.im/cwtch/storage"
	"errors"
	"fmt"
	"git.openprivacy.ca/openprivacy/connectivity"
	"git.openprivacy.ca/openprivacy/log"
	"os"
	path "path/filepath"
	"strconv"
	"strings"
	"sync"
)

type application struct {
	eventBuses map[string]event.Manager
	directory  string

	peerLock sync.Mutex
	peers    map[string]peer.CwtchPeer
	acn      connectivity.ACN
	plugins  sync.Map //map[string] []plugins.Plugin

	engines  map[string]connections.Engine
	appBus   event.Manager
	appmutex sync.Mutex

	duplicateProfiles map[string]*DuplicateProfile
	duplicateMutex    sync.Mutex
}

// DuplicateProfile is safe metadata for two on-disk stores containing the
// same identity. Paths and passwords deliberately remain private to app.
type DuplicateProfile struct {
	ID                    string `json:"id"`
	Onion                 string `json:"onion"`
	CurrentName           string `json:"currentName"`
	DuplicateName         string `json:"duplicateName"`
	CurrentModifiedUnix   int64  `json:"currentModifiedUnix"`
	DuplicateModifiedUnix int64  `json:"duplicateModifiedUnix"`
	CurrentBackedUp       bool   `json:"currentBackedUp"`
	DuplicateBackedUp     bool   `json:"duplicateBackedUp"`
	currentDirectory      string
	duplicateDirectory    string
}

// Application is a full cwtch peer application. It allows management, usage and storage of multiple peers
type Application interface {
	LoadProfiles(password string)
	CreatePeer(name string, password string, attributes map[attr.ZonedPath]string)
	CreateEphemeralPeer(name string, password string, attributes map[attr.ZonedPath]string)
	// Deprecated in 1.10
	CreateTaggedPeer(name string, password string, tag string)
	ImportProfile(exportedCwtchFile string, password string) (peer.CwtchPeer, error)
	ListDuplicateProfiles() []DuplicateProfile
	ExportDuplicateProfile(id string, side string, file string, currentPassword string, backupPassword string, blankPassword string) error
	ConfirmDuplicateBackup(id string, side string, file string, backupPassword string) error
	ResolveDuplicateProfile(id string, action string, currentPassword string, duplicatePassword string, blankPassword string) (*peer.ProfileMergeSummary, error)
	PromoteEphemeralProfile(onion string, password string) error
	DeletePeer(onion string, currentPassword string)
	AddPeerPlugin(onion string, pluginID plugins.PluginID)

	GetPrimaryBus() event.Manager
	GetEventBus(onion string) event.Manager
	QueryACNStatus()
	QueryACNVersion()

	ActivateEngines(doListn, doPeers, doServers bool)
	ActivatePeerEngine(onion string, doListen, doPeers, doServers bool)
	DeactivatePeerEngine(onion string)

	ShutdownPeer(string)
	Shutdown()

	GetPeer(onion string) peer.CwtchPeer
	ListProfiles() []string
}

const (
	stegmsProfileLifetimeAttribute = "stegms_lifetime"
	stegmsProfileStorageAttribute  = "stegms_storage"
	stegmsProfileSourceAttribute   = "stegms_source"
)

// LoadProfileFn is the function signature for a function in an app that loads a profile
type LoadProfileFn func(profile peer.CwtchPeer)

// NewApp creates a new app with some environment awareness and initializes a Tor Manager
func NewApp(acn connectivity.ACN, appDirectory string) Application {
	log.Debugf("NewApp(%v)\n", appDirectory)
	os.MkdirAll(path.Join(appDirectory, "profiles"), 0700)

	app := &application{engines: make(map[string]connections.Engine), eventBuses: make(map[string]event.Manager), directory: appDirectory, appBus: event.NewEventManager(), duplicateProfiles: make(map[string]*DuplicateProfile)}
	app.peers = make(map[string]peer.CwtchPeer)

	app.acn = acn
	statusHandler := app.getACNStatusHandler()
	acn.SetStatusCallback(statusHandler)
	acn.SetVersionCallback(app.getACNVersionHandler())
	prog, status := acn.GetBootstrapStatus()
	statusHandler(prog, status)

	return app
}

// ListProfiles returns a map of onions to their profile's Name
func (app *application) ListProfiles() []string {
	var keys []string

	app.peerLock.Lock()
	defer app.peerLock.Unlock()
	for handle := range app.peers {
		keys = append(keys, handle)
	}
	return keys
}

// GetPeer returns a cwtchPeer for a given onion address
func (app *application) GetPeer(onion string) peer.CwtchPeer {
	if peer, ok := app.peers[onion]; ok {
		return peer
	}
	return nil
}

func (ap *application) AddPlugin(peerid string, id plugins.PluginID, bus event.Manager, acn connectivity.ACN) {
	if _, exists := ap.plugins.Load(peerid); !exists {
		ap.plugins.Store(peerid, []plugins.Plugin{})
	}

	pluginsinf, _ := ap.plugins.Load(peerid)
	peerPlugins := pluginsinf.([]plugins.Plugin)

	for _, plugin := range peerPlugins {
		if plugin.Id() == id {
			log.Errorf("trying to add second instance of plugin %v to peer %v", id, peerid)
			return
		}
	}

	newp, err := plugins.Get(id, bus, acn, peerid)
	if err == nil {
		newp.Start()
		peerPlugins = append(peerPlugins, newp)
		log.Debugf("storing plugin for %v %v", peerid, peerPlugins)
		ap.plugins.Store(peerid, peerPlugins)
	} else {
		log.Errorf("error adding plugin: %v", err)
	}
}

// Deprecated in 1.10
func (app *application) CreateTaggedPeer(name string, password string, tag string) {
	app.CreatePeer(name, password, map[attr.ZonedPath]string{attr.ProfileZone.ConstructZonedPath(constants.Tag): tag})
}

func (app *application) CreatePeer(name string, password string, attributes map[attr.ZonedPath]string) {
	app.appmutex.Lock()
	defer app.appmutex.Unlock()

	profileDirectory := path.Join(app.directory, "profiles", model.GenerateRandomID())

	profile, err := peer.CreateEncryptedStorePeer(profileDirectory, name, password)
	if err != nil {
		log.Errorf("Error Creating Peer: %v", err)
		app.appBus.Publish(event.NewEventList(event.PeerError, event.Error, err.Error()))
		return
	}

	eventBus := event.NewEventManager()
	app.eventBuses[profile.GetOnion()] = eventBus
	profile.Init(app.eventBuses[profile.GetOnion()])
	app.peers[profile.GetOnion()] = profile

	for zp, val := range attributes {
		zone, key := attr.ParseZone(zp.ToString())
		profile.SetScopedZonedAttribute(attr.LocalScope, zone, key, val)
	}
	if _, ok := profile.GetScopedZonedAttribute(attr.LocalScope, attr.ProfileZone, stegmsProfileLifetimeAttribute); !ok {
		profile.SetScopedZonedAttribute(attr.LocalScope, attr.ProfileZone, stegmsProfileLifetimeAttribute, "persistent")
	}
	if _, ok := profile.GetScopedZonedAttribute(attr.LocalScope, attr.ProfileZone, stegmsProfileStorageAttribute); !ok {
		profile.SetScopedZonedAttribute(attr.LocalScope, attr.ProfileZone, stegmsProfileStorageAttribute, "disk")
	}
	if _, ok := profile.GetScopedZonedAttribute(attr.LocalScope, attr.ProfileZone, stegmsProfileSourceAttribute); !ok {
		profile.SetScopedZonedAttribute(attr.LocalScope, attr.ProfileZone, stegmsProfileSourceAttribute, "stegms")
	}

	app.AddPeerPlugin(profile.GetOnion(), plugins.CONNECTIONRETRY) // Now Mandatory
	app.appBus.Publish(event.NewEvent(event.NewPeer, map[event.Field]string{event.Identity: profile.GetOnion(), event.Created: event.True, "name": name}))
}

func (app *application) CreateEphemeralPeer(name string, password string, attributes map[attr.ZonedPath]string) {
	app.appmutex.Lock()
	defer app.appmutex.Unlock()

	profile, err := peer.CreateMemoryStorePeer(name, password)
	if err != nil {
		log.Errorf("Error Creating Ephemeral Peer: %v", err)
		app.appBus.Publish(event.NewEventList(event.PeerError, event.Error, err.Error()))
		return
	}

	eventBus := event.NewEventManager()
	app.eventBuses[profile.GetOnion()] = eventBus
	profile.Init(app.eventBuses[profile.GetOnion()])
	app.peers[profile.GetOnion()] = profile

	for zp, val := range attributes {
		zone, key := attr.ParseZone(zp.ToString())
		profile.SetScopedZonedAttribute(attr.LocalScope, zone, key, val)
	}

	// Mark as ephemeral in StegMS metadata attributes.
	profile.SetScopedZonedAttribute(attr.LocalScope, attr.ProfileZone, stegmsProfileLifetimeAttribute, "ephemeral")
	profile.SetScopedZonedAttribute(attr.LocalScope, attr.ProfileZone, stegmsProfileStorageAttribute, "memory")
	if _, ok := profile.GetScopedZonedAttribute(attr.LocalScope, attr.ProfileZone, stegmsProfileSourceAttribute); !ok {
		profile.SetScopedZonedAttribute(attr.LocalScope, attr.ProfileZone, stegmsProfileSourceAttribute, "guest")
	}

	app.AddPeerPlugin(profile.GetOnion(), plugins.CONNECTIONRETRY)
	app.appBus.Publish(event.NewEvent(event.NewPeer, map[event.Field]string{
		event.Identity: profile.GetOnion(),
		event.Created:  event.True,
		"name":         name,
	}))
}

func (app *application) PromoteEphemeralProfile(onion string, password string) error {
	app.appmutex.Lock()
	defer app.appmutex.Unlock()

	p, exists := app.peers[onion]
	if !exists {
		return fmt.Errorf("ephemeral profile not found")
	}

	profileDirectory := path.Join(app.directory, "profiles", model.GenerateRandomID())

	previousLifetime, hadPreviousLifetime := p.GetScopedZonedAttribute(attr.LocalScope, attr.ProfileZone, stegmsProfileLifetimeAttribute)
	previousStorage, hadPreviousStorage := p.GetScopedZonedAttribute(attr.LocalScope, attr.ProfileZone, stegmsProfileStorageAttribute)
	previousSource, hadPreviousSource := p.GetScopedZonedAttribute(attr.LocalScope, attr.ProfileZone, stegmsProfileSourceAttribute)

	p.SetScopedZonedAttribute(attr.LocalScope, attr.ProfileZone, stegmsProfileLifetimeAttribute, "persistent")
	p.SetScopedZonedAttribute(attr.LocalScope, attr.ProfileZone, stegmsProfileStorageAttribute, "disk")
	p.SetScopedZonedAttribute(attr.LocalScope, attr.ProfileZone, stegmsProfileSourceAttribute, "guest_promoted")

	err := p.PromoteToEncryptedStore(profileDirectory, password)
	if err != nil {
		if hadPreviousLifetime {
			p.SetScopedZonedAttribute(attr.LocalScope, attr.ProfileZone, stegmsProfileLifetimeAttribute, previousLifetime)
		} else {
			p.SetScopedZonedAttribute(attr.LocalScope, attr.ProfileZone, stegmsProfileLifetimeAttribute, "ephemeral")
		}
		if hadPreviousStorage {
			p.SetScopedZonedAttribute(attr.LocalScope, attr.ProfileZone, stegmsProfileStorageAttribute, previousStorage)
		} else {
			p.SetScopedZonedAttribute(attr.LocalScope, attr.ProfileZone, stegmsProfileStorageAttribute, "memory")
		}
		if hadPreviousSource {
			p.SetScopedZonedAttribute(attr.LocalScope, attr.ProfileZone, stegmsProfileSourceAttribute, previousSource)
		} else {
			p.SetScopedZonedAttribute(attr.LocalScope, attr.ProfileZone, stegmsProfileSourceAttribute, "guest")
		}
		return err
	}

	return nil
}

func (app *application) DeletePeer(onion string, password string) {
	log.Infof("DeletePeer called on %v\n", onion)
	app.appmutex.Lock()
	defer app.appmutex.Unlock()

	if app.peers[onion].CheckPassword(password) {
		// soft-shutdown
		app.peers[onion].Shutdown()
		// delete the underlying storage
		app.peers[onion].Delete()
		// hard shutdown / remove from app
		app.shutdownPeer(onion)

		// Shutdown and Remove the Engine
		log.Debugf("Delete peer for %v Done\n", onion)
		app.appBus.Publish(event.NewEventList(event.PeerDeleted, event.Identity, onion))
		return
	}
	app.appBus.Publish(event.NewEventList(event.AppError, event.Error, event.PasswordMatchError, event.Identity, onion))
}

func (app *application) AddPeerPlugin(onion string, pluginID plugins.PluginID) {
	app.AddPlugin(onion, pluginID, app.eventBuses[onion], app.acn)
}

func (app *application) ImportProfile(exportedCwtchFile string, password string) (peer.CwtchPeer, error) {
	profileDirectory := path.Join(app.directory, "profiles")
	profile, err := peer.ImportProfile(exportedCwtchFile, profileDirectory, password)
	if profile != nil && err == nil {
		if _, ok := profile.GetScopedZonedAttribute(attr.LocalScope, attr.ProfileZone, stegmsProfileLifetimeAttribute); !ok {
			profile.SetScopedZonedAttribute(attr.LocalScope, attr.ProfileZone, stegmsProfileLifetimeAttribute, "persistent")
		}
		profile.SetScopedZonedAttribute(attr.LocalScope, attr.ProfileZone, stegmsProfileStorageAttribute, "disk")
		profile.SetScopedZonedAttribute(attr.LocalScope, attr.ProfileZone, stegmsProfileSourceAttribute, "imported")
		if !app.installProfile(profile) {
			conflict := app.registerDuplicateProfile(profile)
			profile.ShutdownWithoutPurgingMessages()
			return nil, fmt.Errorf("duplicate identity conflict:%s", conflict.ID)
		}
	}
	return profile, err
}

func regularProfileFileSize(filePath string) int64 {
	info, err := os.Stat(filePath)
	if err != nil || !info.Mode().IsRegular() {
		return -1
	}
	return info.Size()
}

func inspectProfileStorageCandidate(profilesDirectory string, entry os.DirEntry) (bool, string) {
	if !entry.IsDir() {
		return false, "not a directory"
	}
	lowerName := strings.ToLower(entry.Name())
	for _, suffix := range []string{".bak", ".tmp", ".partial"} {
		if strings.HasSuffix(lowerName, suffix) {
			return false, "ignored backup or temporary directory"
		}
	}

	profileDirectory := path.Join(profilesDirectory, entry.Name())
	if regularProfileFileSize(path.Join(profileDirectory, "SALT")) != 128 {
		return false, "missing or invalid SALT"
	}

	versionPath := path.Join(profileDirectory, "VERSION")
	if regularProfileFileSize(versionPath) >= 0 {
		versionBytes, err := os.ReadFile(versionPath)
		if err != nil {
			return false, "unreadable VERSION"
		}
		if strings.TrimSpace(string(versionBytes)) != "2" {
			return false, "unsupported profile storage version"
		}
		if regularProfileFileSize(path.Join(profileDirectory, "db")) <= 0 {
			return false, "missing or empty profile database"
		}
		return true, "v2"
	}

	if regularProfileFileSize(path.Join(profileDirectory, "profile")) <= 0 {
		return false, "unrecognized profile storage layout"
	}
	return true, "legacy"
}

// LoadProfiles takes a password and attempts to load any profiles it can from storage with it and create Peers for them
func (app *application) LoadProfiles(password string) {
	count := 0
	migrating := false

	files, err := os.ReadDir(path.Join(app.directory, "profiles"))
	if err != nil {
		log.Errorf("error: cannot read profiles directory: %v", err)
		return
	}

	for _, file := range files {
		if valid, reason := inspectProfileStorageCandidate(path.Join(app.directory, "profiles"), file); !valid {
			log.Warnf("skipping non-profile storage candidate %q: %s", file.Name(), reason)
			continue
		}
		// Attempt to load an encrypted database
		profileDirectory := path.Join(app.directory, "profiles", file.Name())
		profile, encryptedErr := peer.FromEncryptedDatabase(profileDirectory, password)
		loaded := false
		if encryptedErr == nil {
			// return the load the profile...
			log.Infof("loading profile from new-type storage database...")
			loaded = app.installProfile(profile)
			if !loaded {
				// LoadProfiles can be called again after a profile is already
				// active. Reopening that exact storage directory is not a
				// duplicate and must not create a recovery conflict.
				current := app.GetPeer(profile.GetOnion())
				if current == nil || current.StorageDirectory() != profile.StorageDirectory() {
					app.registerDuplicateProfile(profile)
				}
				profile.ShutdownWithoutPurgingMessages()
			}
		} else { // On failure attempt to load a legacy profile
			profileStore, legacyErr := storage.LoadProfileWriterStore(profileDirectory, password)
			if legacyErr != nil {
				log.Warnf(
					"unable to load profile candidate %q as v2 (%v) or legacy storage (%v)",
					file.Name(),
					encryptedErr,
					legacyErr,
				)
				continue
			}
			log.Infof("found legacy profile. importing to new database structure...")
			legacyProfile := profileStore.GetProfileCopy(true)
			if !migrating {
				migrating = true
				app.appBus.Publish(event.NewEventList(event.StartingStorageMiragtion))
			}

			cps, err := peer.CreateEncryptedStore(profileDirectory, password)
			if err != nil {
				log.Errorf("error creating encrypted store: %v", err)
				continue
			}
			profile := peer.ImportLegacyProfile(legacyProfile, cps)
			loaded = app.installProfile(profile)
		}
		if loaded {
			count++
		}
	}
	if count == 0 {
		message := event.NewEventList(event.AppError, event.Error, event.AppErrLoaded0)
		app.appBus.Publish(message)
	}
	if migrating {
		app.appBus.Publish(event.NewEventList(event.DoneStorageMigration))
	}
}

// installProfile takes a profile and if it isn't loaded in the app, installs it and returns true
func (app *application) installProfile(profile peer.CwtchPeer) bool {
	app.appmutex.Lock()
	defer app.appmutex.Unlock()

	// Only attempt to finalize the profile if we don't have one loaded...
	if app.peers[profile.GetOnion()] == nil {
		eventBus := event.NewEventManager()
		app.eventBuses[profile.GetOnion()] = eventBus
		profile.Init(app.eventBuses[profile.GetOnion()])
		app.peers[profile.GetOnion()] = profile
		app.AddPeerPlugin(profile.GetOnion(), plugins.CONNECTIONRETRY) // Now Mandatory
		app.appBus.Publish(event.NewEvent(event.NewPeer, map[event.Field]string{event.Identity: profile.GetOnion(), event.Created: event.False}))
		return true
	}
	return false
}

func profileDisplayName(profile peer.CwtchPeer) string {
	if name, ok := profile.GetScopedZonedAttribute(attr.LocalScope, attr.ProfileZone, constants.Name); ok && name != "" {
		return name
	}
	if name, ok := profile.GetScopedZonedAttribute(attr.PublicScope, attr.ProfileZone, constants.Name); ok && name != "" {
		return name
	}
	return "Cwtch identity"
}

func profileModifiedUnix(directory string) int64 {
	info, err := os.Stat(path.Join(directory, "db"))
	if err != nil {
		return 0
	}
	return info.ModTime().Unix()
}

func (app *application) ListDuplicateProfiles() []DuplicateProfile {
	app.duplicateMutex.Lock()
	defer app.duplicateMutex.Unlock()
	app.appmutex.Lock()
	defer app.appmutex.Unlock()
	result := make([]DuplicateProfile, 0, len(app.duplicateProfiles))
	for _, conflict := range app.duplicateProfiles {
		copy := *conflict
		copy.currentDirectory = ""
		copy.duplicateDirectory = ""
		result = append(result, copy)
	}
	return result
}

func (app *application) ExportDuplicateProfile(id string, side string, file string, currentPassword string, backupPassword string, blankPassword string) error {
	app.duplicateMutex.Lock()
	defer app.duplicateMutex.Unlock()
	app.appmutex.Lock()
	conflict := app.duplicateProfiles[id]
	if conflict == nil {
		app.appmutex.Unlock()
		return errors.New("duplicate profile conflict not found")
	}
	onion := conflict.Onion
	directory := conflict.duplicateDirectory
	if side == "current" {
		directory = conflict.currentDirectory
	} else if side != "duplicate" {
		app.appmutex.Unlock()
		return errors.New("invalid duplicate profile side")
	}
	app.appmutex.Unlock()

	var profile peer.CwtchPeer
	var err error
	if side == "current" {
		profile = app.GetPeer(onion)
		if profile == nil || profile.StorageDirectory() != directory {
			return errors.New("current profile copy is no longer active")
		}
	} else {
		profile, err = peer.FromEncryptedDatabase(directory, currentPassword)
		if err != nil {
			return errors.New(constants.InvalidPasswordError)
		}
		defer profile.ShutdownWithoutPurgingMessages()
		if profile.GetOnion() != onion {
			return errors.New("duplicate profile identity changed")
		}
	}
	if err := profile.ExportWithPassword(file, currentPassword, backupPassword, blankPassword); err != nil {
		return err
	}
	if err := app.recordDuplicateBackup(*conflict, side, file); err != nil {
		return fmt.Errorf("backup saved, but its recovery receipt could not be recorded: %w", err)
	}
	app.appmutex.Lock()
	if current := app.duplicateProfiles[id]; current != nil {
		if side == "current" {
			current.CurrentBackedUp = true
		} else {
			current.DuplicateBackedUp = true
		}
	}
	app.appmutex.Unlock()
	return nil
}

// ConfirmDuplicateBackup accepts an already-saved archive only after Cwtch's
// normal safe archive extraction, successful decryption, and a match to the
// selected store's profile ID and identity. This lets a successful export be
// acknowledged after an app crash without exporting the same data again.
func (app *application) ConfirmDuplicateBackup(id string, side string, file string, backupPassword string) error {
	app.duplicateMutex.Lock()
	defer app.duplicateMutex.Unlock()
	app.appmutex.Lock()
	conflict := app.duplicateProfiles[id]
	if conflict == nil {
		app.appmutex.Unlock()
		return errors.New("duplicate profile conflict not found")
	}
	copy := *conflict
	app.appmutex.Unlock()
	directory := copy.currentDirectory
	if side == "duplicate" {
		directory = copy.duplicateDirectory
	} else if side != "current" {
		return errors.New("invalid duplicate profile side")
	}
	tempRoot, err := os.MkdirTemp(app.directory, ".cwtch-backup-verify-")
	if err != nil {
		return err
	}
	defer os.RemoveAll(tempRoot)
	archived, err := peer.ImportProfile(file, tempRoot, backupPassword)
	if err != nil {
		return fmt.Errorf("backup could not be opened with that password: %w", err)
	}
	archiveDirectory := archived.StorageDirectory()
	archiveOnion := archived.GetOnion()
	archived.ShutdownWithoutPurgingMessages()
	if archiveOnion == copy.Onion && path.Base(archiveDirectory) != path.Base(directory) {
		otherDirectory := copy.duplicateDirectory
		otherSide := "other"
		if side == "duplicate" {
			otherDirectory = copy.currentDirectory
			otherSide = "current"
		}
		if path.Base(archiveDirectory) == path.Base(otherDirectory) {
			return fmt.Errorf("this archive belongs to the %s copy; use its saved-backup button", otherSide)
		}
	}
	if path.Base(archiveDirectory) != path.Base(directory) || archiveOnion != copy.Onion {
		return errors.New("backup does not belong to the selected identity copy")
	}
	if err := app.recordDuplicateBackup(copy, side, file); err != nil {
		return fmt.Errorf("backup verified, but its recovery receipt could not be recorded: %w", err)
	}
	app.appmutex.Lock()
	if current := app.duplicateProfiles[id]; current != nil {
		if side == "current" {
			current.CurrentBackedUp = true
		} else {
			current.DuplicateBackedUp = true
		}
	}
	app.appmutex.Unlock()
	return nil
}

func (app *application) ResolveDuplicateProfile(id string, action string, currentPassword string, duplicatePassword string, blankPassword string) (*peer.ProfileMergeSummary, error) {
	app.duplicateMutex.Lock()
	defer app.duplicateMutex.Unlock()
	app.appmutex.Lock()
	conflict := app.duplicateProfiles[id]
	if conflict == nil {
		app.appmutex.Unlock()
		return nil, errors.New("duplicate profile conflict not found")
	}
	conflictCopy := *conflict
	current := app.peers[conflict.Onion]
	app.appmutex.Unlock()
	if current == nil || current.StorageDirectory() != conflictCopy.currentDirectory {
		return nil, errors.New("current profile copy is no longer active")
	}
	if !current.CheckPassword(currentPassword) {
		return nil, errors.New(constants.InvalidPasswordError)
	}
	duplicate, err := peer.FromEncryptedDatabase(conflictCopy.duplicateDirectory, duplicatePassword)
	if err != nil || duplicate.GetOnion() != conflictCopy.Onion {
		if duplicate != nil {
			duplicate.ShutdownWithoutPurgingMessages()
		}
		return nil, errors.New(constants.InvalidPasswordError)
	}
	if action == "keep_duplicate" {
		removed, restoreErr := duplicate.RestorePasswordAsItWas(duplicatePassword, blankPassword)
		if restoreErr != nil {
			duplicate.ShutdownWithoutPurgingMessages()
			return nil, restoreErr
		}
		if removed {
			duplicatePassword = blankPassword
		}
	}
	duplicate.ShutdownWithoutPurgingMessages()

	switch action {
	case "keep_current":
		if err := os.RemoveAll(conflictCopy.duplicateDirectory); err != nil {
			return nil, err
		}
		app.appmutex.Lock()
		delete(app.duplicateProfiles, id)
		app.appmutex.Unlock()
		os.Remove(app.duplicateReceiptPath(conflictCopy))
		return &peer.ProfileMergeSummary{}, nil
	case "keep_duplicate", "join":
		if action == "join" && (!conflictCopy.CurrentBackedUp || !conflictCopy.DuplicateBackedUp) {
			return nil, errors.New("both profile copies must be backed up before joining")
		}
	default:
		return nil, errors.New("invalid duplicate profile action")
	}

	app.appmutex.Lock()
	// A normal session shutdown applies the user's save-history policy and can
	// purge messages. Recovery preserves the current store until the merge or
	// replacement has reopened and validated, so rollback cannot lose history.
	app.shutdownPeerWithoutPurgingMessages(conflictCopy.Onion)
	app.appmutex.Unlock()
	var replacement peer.CwtchPeer
	var summary *peer.ProfileMergeSummary
	if action == "join" {
		replacement, summary, err = peer.MergeEncryptedProfileDirectories(
			conflictCopy.currentDirectory, currentPassword,
			conflictCopy.duplicateDirectory, duplicatePassword,
		)
	} else {
		replacement, err = peer.FromEncryptedDatabase(conflictCopy.duplicateDirectory, duplicatePassword)
		summary = &peer.ProfileMergeSummary{}
	}
	if err != nil {
		if reopened, reopenErr := peer.FromEncryptedDatabase(conflictCopy.currentDirectory, currentPassword); reopenErr == nil {
			app.installProfile(reopened)
		}
		return nil, err
	}
	if !app.installProfile(replacement) {
		replacement.ShutdownWithoutPurgingMessages()
		if reopened, reopenErr := peer.FromEncryptedDatabase(conflictCopy.currentDirectory, currentPassword); reopenErr == nil {
			app.installProfile(reopened)
		}
		return nil, errors.New("could not activate resolved profile")
	}
	if action == "keep_duplicate" {
		if err := os.RemoveAll(conflictCopy.currentDirectory); err != nil {
			// The selected replacement is active and the old copy still exists.
			// Reverse this conflict so a retry accurately describes both stores.
			app.appmutex.Lock()
			if conflict := app.duplicateProfiles[id]; conflict != nil {
				conflict.currentDirectory, conflict.duplicateDirectory = conflictCopy.duplicateDirectory, conflictCopy.currentDirectory
				conflict.CurrentName, conflict.DuplicateName = conflictCopy.DuplicateName, conflictCopy.CurrentName
				conflict.CurrentModifiedUnix, conflict.DuplicateModifiedUnix = conflictCopy.DuplicateModifiedUnix, conflictCopy.CurrentModifiedUnix
				conflict.CurrentBackedUp, conflict.DuplicateBackedUp = conflictCopy.DuplicateBackedUp, conflictCopy.CurrentBackedUp
			}
			app.appmutex.Unlock()
			return nil, fmt.Errorf("other copy activated but old current copy could not be removed: %w", err)
		}
	}
	app.appmutex.Lock()
	delete(app.duplicateProfiles, id)
	for _, conflict := range app.duplicateProfiles {
		if conflict.Onion != conflictCopy.Onion {
			continue
		}
		conflict.currentDirectory = replacement.StorageDirectory()
		conflict.CurrentName = profileDisplayName(replacement)
		conflict.CurrentModifiedUnix = profileModifiedUnix(conflict.currentDirectory)
		if action == "join" {
			// A backup of either input is not a backup of the newly merged store.
			conflict.CurrentBackedUp = false
		} else {
			conflict.CurrentBackedUp = conflictCopy.DuplicateBackedUp
		}
	}
	app.appmutex.Unlock()
	os.Remove(app.duplicateReceiptPath(conflictCopy))
	return summary, nil
}

func (app *application) registerDuplicateProfile(duplicate peer.CwtchPeer) *DuplicateProfile {
	app.duplicateMutex.Lock()
	defer app.duplicateMutex.Unlock()
	app.appmutex.Lock()
	defer app.appmutex.Unlock()
	onion := duplicate.GetOnion()
	current := app.peers[onion]
	currentDirectory := current.StorageDirectory()
	duplicateDirectory := duplicate.StorageDirectory()
	for _, conflict := range app.duplicateProfiles {
		if conflict.Onion == onion && conflict.currentDirectory == currentDirectory && conflict.duplicateDirectory == duplicateDirectory {
			return conflict
		}
	}
	conflict := &DuplicateProfile{
		ID:                    model.GenerateRandomID(),
		Onion:                 onion,
		CurrentName:           profileDisplayName(current),
		DuplicateName:         profileDisplayName(duplicate),
		CurrentModifiedUnix:   profileModifiedUnix(currentDirectory),
		DuplicateModifiedUnix: profileModifiedUnix(duplicateDirectory),
		currentDirectory:      currentDirectory,
		duplicateDirectory:    duplicateDirectory,
	}
	receipt := app.readDuplicateReceipt(*conflict)
	conflict.CurrentBackedUp = receipt.Current != nil
	conflict.DuplicateBackedUp = receipt.Duplicate != nil
	app.duplicateProfiles[conflict.ID] = conflict
	return conflict
}

// ActivateEngines launches all peer engines
func (app *application) ActivateEngines(doListen, doPeers, doServers bool) {
	log.Debugf("ActivateEngines")

	for _, profile := range app.peers {
		app.engines[profile.GetOnion()], _ = profile.GenerateProtocolEngine(app.acn, app.eventBuses[profile.GetOnion()])
		app.eventBuses[profile.GetOnion()].Publish(event.NewEventList(event.ProtocolEngineCreated))
	}
	app.QueryACNStatus()

	if doListen {
		for _, profile := range app.peers {
			log.Debugf("  Listen for %v", profile.GetOnion())
			profile.Listen()
		}
	}

	if doPeers || doServers {
		for _, profile := range app.peers {
			log.Debugf("  Start Connections for %v doPeers:%v doServers:%v", profile.GetOnion(), doPeers, doServers)
			profile.StartConnections(doPeers, doServers)
		}
	}
}

// ActivePeerEngine creates a peer engine for use with an ACN, should be called once the underlying ACN is online
func (app *application) ActivatePeerEngine(onion string, doListen, doPeers, doServers bool) {
	profile := app.GetPeer(onion)
	if profile != nil {
		if _, exists := app.engines[onion]; !exists {
			app.engines[profile.GetOnion()], _ = profile.GenerateProtocolEngine(app.acn, app.eventBuses[profile.GetOnion()])

			app.eventBuses[profile.GetOnion()].Publish(event.NewEventList(event.ProtocolEngineCreated))
			app.QueryACNStatus()
			if doListen {
				profile.Listen()
			}
			profile.StartConnections(doPeers, doServers)
		}
	}
}

// DeactivatePeerEngine shutsdown and cleans up a peer engine, should be called when an underlying ACN goes offline
func (app *application) DeactivatePeerEngine(onion string) {
	if engine, exists := app.engines[onion]; exists {
		engine.Shutdown()
		delete(app.engines, onion)
	}
}

// GetPrimaryBus returns the bus the Application uses for events that aren't peer specific
func (app *application) GetPrimaryBus() event.Manager {
	return app.appBus
}

// GetEventBus returns a cwtchPeer's event bus
func (app *application) GetEventBus(onion string) event.Manager {
	if manager, ok := app.eventBuses[onion]; ok {
		return manager
	}
	return nil
}

func (app *application) getACNStatusHandler() func(int, string) {
	return func(progress int, status string) {
		progStr := strconv.Itoa(progress)
		app.appmutex.Lock()
		app.appBus.Publish(event.NewEventList(event.ACNStatus, event.Progress, progStr, event.Status, status))
		for _, bus := range app.eventBuses {
			bus.Publish(event.NewEventList(event.ACNStatus, event.Progress, progStr, event.Status, status))
		}
		app.appmutex.Unlock()
	}
}

func (app *application) getACNVersionHandler() func(string) {
	return func(version string) {
		app.appmutex.Lock()
		defer app.appmutex.Unlock()
		app.appBus.Publish(event.NewEventList(event.ACNVersion, event.Data, version))
	}
}

func (app *application) QueryACNStatus() {
	prog, status := app.acn.GetBootstrapStatus()
	app.getACNStatusHandler()(prog, status)
}

func (app *application) QueryACNVersion() {
	version := app.acn.GetVersion()
	app.appBus.Publish(event.NewEventList(event.ACNVersion, event.Data, version))
}

// ShutdownPeer shuts down a peer and removes it from the app's management
func (app *application) ShutdownPeer(onion string) {
	app.appmutex.Lock()
	defer app.appmutex.Unlock()
	app.shutdownPeer(onion)
}

// shutdownPeer mutex unlocked helper shutdown peer
func (app *application) shutdownPeer(onion string) {
	app.shutdownPeerStorage(onion, true)
}

func (app *application) shutdownPeerWithoutPurgingMessages(onion string) {
	app.shutdownPeerStorage(onion, false)
}

func (app *application) shutdownPeerStorage(onion string, purgeMessages bool) {
	app.eventBuses[onion].Publish(event.NewEventList(event.ShutdownPeer, event.Identity, onion))
	app.eventBuses[onion].Shutdown()
	delete(app.eventBuses, onion)
	if purgeMessages {
		app.peers[onion].Shutdown()
	} else {
		app.peers[onion].ShutdownWithoutPurgingMessages()
	}
	delete(app.peers, onion)
	if _, ok := app.engines[onion]; ok {
		app.engines[onion].Shutdown()
		delete(app.engines, onion)
	}
	log.Debugf("shutting down plugins for %v", onion)
	pluginsI, ok := app.plugins.Load(onion)
	if ok {
		plugins := pluginsI.([]plugins.Plugin)
		for _, plugin := range plugins {
			plugin.Shutdown()
		}
	}
	app.plugins.Delete(onion)
}

// Shutdown shutsdown all peers of an app
func (app *application) Shutdown() {
	app.appmutex.Lock()
	defer app.appmutex.Unlock()
	for id := range app.peers {
		log.Debugf("Shutting Down Peer %v", id)
		app.shutdownPeer(id)
	}
	log.Debugf("Shutting Down App")
	app.appBus.Shutdown()
	log.Debugf("Shut Down Complete")
}
