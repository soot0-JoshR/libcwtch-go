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
	"fmt"
	"git.openprivacy.ca/openprivacy/connectivity"
	"git.openprivacy.ca/openprivacy/log"
	"os"
	path "path/filepath"
	"strconv"
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
}

// Application is a full cwtch peer application. It allows management, usage and storage of multiple peers
type Application interface {
	LoadProfiles(password string)
	CreatePeer(name string, password string, attributes map[attr.ZonedPath]string)
	CreateEphemeralPeer(name string, password string, attributes map[attr.ZonedPath]string)
	// Deprecated in 1.10
	CreateTaggedPeer(name string, password string, tag string)
	ImportProfile(exportedCwtchFile string, password string) (peer.CwtchPeer, error)
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

	app := &application{engines: make(map[string]connections.Engine), eventBuses: make(map[string]event.Manager), directory: appDirectory, appBus: event.NewEventManager()}
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
		event.Created: event.True,
		"name": name,
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
		app.installProfile(profile)
	}
	return profile, err
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
		// Attempt to load an encrypted database
		profileDirectory := path.Join(app.directory, "profiles", file.Name())
		profile, err := peer.FromEncryptedDatabase(profileDirectory, password)
		loaded := false
		if err == nil {
			// return the load the profile...
			log.Infof("loading profile from new-type storage database...")
			loaded = app.installProfile(profile)
		} else { // On failure attempt to load a legacy profile
			profileStore, err := storage.LoadProfileWriterStore(profileDirectory, password)
			if err != nil {
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
	// Otherwise shutdown the connections
	profile.Shutdown()
	return false
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
	app.eventBuses[onion].Publish(event.NewEventList(event.ShutdownPeer, event.Identity, onion))
	app.eventBuses[onion].Shutdown()
	delete(app.eventBuses, onion)
	app.peers[onion].Shutdown()
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
