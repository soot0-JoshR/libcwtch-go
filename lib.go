//package cwtch

package main

// //Needed to invoke C.free
// #include <stdlib.h>
import "C"

import (
	"crypto/rand"
	"encoding/json"
	"fmt"
	"os/user"
	"runtime"
	"strconv"
	"strings"
	"unsafe"

	"cwtch.im/cwtch/app"
	"cwtch.im/cwtch/event"
	"cwtch.im/cwtch/functionality/filesharing"
	"cwtch.im/cwtch/model"
	"cwtch.im/cwtch/model/attr"
	"cwtch.im/cwtch/peer"
	"git.openprivacy.ca/cwtch.im/libcwtch-go/constants"
	contact "git.openprivacy.ca/cwtch.im/libcwtch-go/features/contacts"
	"git.openprivacy.ca/cwtch.im/libcwtch-go/features/groups"
	"git.openprivacy.ca/cwtch.im/libcwtch-go/features/servers"
	"git.openprivacy.ca/cwtch.im/server"
	"git.openprivacy.ca/openprivacy/connectivity"

	"git.openprivacy.ca/cwtch.im/libcwtch-go/utils"

	"encoding/base64"
	mrand "math/rand"
	"os"
	"path/filepath"
	"time"

	"git.openprivacy.ca/openprivacy/connectivity/tor"
	"git.openprivacy.ca/openprivacy/log"
)

const (
	// ProfileOnion is an event field that contains the handle for a given profile.
	// todo: this should probably be moved back into Cwtch, and renamed ProfileHandle (onions are too tor-specific)
	ProfileOnion = event.Field("ProfileOnion")
)

var application app.Application
var globalAppDir string
var eventHandler *utils.EventHandler
var globalACN connectivity.ACN

// ChatMessage API currently not officially documented, see
// https://git.openprivacy.ca/cwtch.im/secure-development-handbook/issues/3
// for latest updates for now
//
// A ChatMessage is the application-layer Cwtch message, delivered to the UI
// as serialized json.
type ChatMessage struct {
	O int    `json:"o"`
	D string `json:"d"`
}

//export c_StartCwtch
func c_StartCwtch(dir_c *C.char, len C.int, tor_c *C.char, torLen C.int) C.int {
	applicationDirectory := C.GoStringN(dir_c, len)
	torDirectory := C.GoStringN(tor_c, torLen)
	return C.int(StartCwtch(applicationDirectory, torDirectory))
}

// StartCwtch starts cwtch in the library and initlaizes all data structures
// 	 GetAppbusEvents is always safe to use
//   the rest of functions are unsafe until the CwtchStarted event has been received indicating StartCwtch has completed
//   returns:
//     message: CwtchStarted when start up is complete and app is safe to use
//              CwtchStartError message when start up fails (includes event.Error data field)
func StartCwtch(appDir string, torPath string) int {
	if logfile := os.Getenv("LOG_FILE"); logfile != "" {
		filelog, err := log.NewFile(log.LevelInfo, logfile)
		if err == nil {
			filelog.SetUseColor(false)
			log.SetStd(filelog)
		} else {
			// not so likely to be seen since we're usually creating file log in situations we can't access console logs...
			log.Errorf("could not create file log: %v\n", err)
		}
	}
	if runtime.GOOS == "android" {
		log.SetUseColor(false)
	}
	log.SetLevel(log.LevelInfo)
	log.AddEverythingFromPattern("libcwtch-go")
	if logLevel := os.Getenv("LOG_LEVEL"); strings.ToLower(logLevel) == "debug" {
		log.SetLevel(log.LevelDebug)
	}

	log.Infof("StartCwtch(...)")
	// Quick hack check that we're being called with the correct params
	// On android a stale worker could be calling us with "last apps" directory. Best to abort fast so the app can make a new worker
	if runtime.GOOS == "android" {
		fh, err := os.Open(torPath)
		if err != nil {
			log.Errorf("%v", err)
			log.Errorf("failed to stat tor, skipping StartCwtch(). potentially normal if the app was reinstalled or the device was restarted; this workorder should get canceled soon")
			return 1
		}
		_ = fh.Close()
	}
	go _startCwtch(appDir, torPath)
	return 0
}

func _startCwtch(appDir string, torPath string) {
	log.Infof("application: %v eventHandler: %v acn: %v", application, eventHandler, globalACN)

	if application != nil {
		log.Infof("_startCwtch detected existing application; resuming instead of relaunching")
		ReconnectCwtchForeground()
		return
	}

	log.Infof("Creating new EventHandler()")
	eventHandler = utils.NewEventHandler()

	// Exclude Tapir wire Messages
	//(We need a TRACE level)
	log.ExcludeFromPattern("service.go")

	// Environment variables don't get '~' expansion so if CWTCH_DIR was set, it likely needs manual handling
	usr, _ := user.Current()
	homeDir := usr.HomeDir
	if appDir == "~" {
		appDir = homeDir
	} else if strings.HasPrefix(appDir, "~/") {
		appDir = filepath.Join(homeDir, appDir[2:])
	}

	// Ensure that the application directory exists...and then initialize settings..
	err := os.MkdirAll(appDir, 0700)
	if err != nil {
		log.Errorf("Error creating appDir %v: %v\n", appDir, err)
		eventHandler.PublishAppEvent(event.NewEventList(utils.CwtchStartError, event.Error, fmt.Sprintf("Error creating appDir %v: %v", appDir, err)))
		return
	}

	err = utils.InitGlobalSettingsFile(appDir, constants.DefactoPasswordForUnencryptedProfiles)
	if err != nil {
		log.Errorf("error initializing global settings file %. Global settings might not be loaded or saves", err)
	}

	log.Infof("Loading Cwtch Directory %v and tor path: %v", appDir, torPath)

	mrand.Seed(int64(time.Now().Nanosecond()))
	port := mrand.Intn(1000) + 9600
	controlPort := port + 1

	// generate a random password (actually random, stored in memory, for the control port)
	key := make([]byte, 64)
	_, err = rand.Read(key)
	if err != nil {
		panic(err)
	}

	log.Infof("making directory %v", appDir)
	err = os.MkdirAll(filepath.Join(appDir, "tor"), 0700)

	if err != nil {
		log.Errorf("error creating tor data directory: %v. Aborting app start up", err)
		eventHandler.PublishAppEvent(event.NewEventList(utils.CwtchStartError, event.Error, fmt.Sprintf("Error connecting to Tor: %v", err)))
		return
	}

	err = tor.NewTorrc().WithSocksPort(port).WithOnionTrafficOnly().WithControlPort(controlPort).WithHashedPassword(base64.StdEncoding.EncodeToString(key)).Build(filepath.Join(appDir, "tor", "torrc"))

	if err != nil {
		log.Errorf("error constructing torrc: %v", err)
		eventHandler.PublishAppEvent(event.NewEventList(utils.CwtchStartError, event.Error, fmt.Sprintf("Error connecting to Tor: %v", err)))
		return
	}

	acn, err := tor.NewTorACNWithAuth(appDir, torPath, controlPort, tor.HashedPasswordAuthenticator{Password: base64.StdEncoding.EncodeToString(key)})
	if err != nil {
		log.Errorf("Error connecting to Tor replacing with ErrorACN: %v\n", err)
		eventHandler.PublishAppEvent(event.NewEventList(utils.CwtchStartError, event.Error, fmt.Sprintf("Error connecting to Tor: %v", err)))
		return
	}
	globalAppDir = appDir
	globalACN = acn
	newApp := app.NewApp(acn, appDir)
	servers.InitServers(acn, appDir)

	eventHandler.HandleApp(newApp)

	peer.DefaultEventsToHandle = []event.Type{
		event.EncryptedGroupMessage,
		event.NewMessageFromPeer,
		event.PeerAcknowledgement,
		event.PeerError,
		event.SendMessageToPeerError,
		event.SendMessageToGroupError,
		event.NewGetValMessageFromPeer,
		event.PeerStateChange,
		event.NewRetValMessageFromPeer,
		event.NewGroupInvite,
		event.ServerStateChange,
		event.ProtocolEngineStopped,
		event.RetryServerRequest,
		event.ManifestReceived,
	}
	settings := utils.ReadGlobalSettings()
	settingsJson, _ := json.Marshal(settings)

	newApp.LoadProfiles(constants.DefactoPasswordForUnencryptedProfiles)
	application = newApp
	publishLoadedServers()
	LaunchServers()

	// Send global settings to the UI...
	application.GetPrimaryBus().Publish(event.NewEvent(utils.UpdateGlobalSettings, map[event.Field]string{event.Data: string(settingsJson)}))
	log.Infof("libcwtch-go application launched")
	application.GetPrimaryBus().Publish(event.NewEvent(utils.CwtchStarted, map[event.Field]string{}))
	application.QueryACNVersion()
}

//export c_ReconnectCwtchForeground
func c_ReconnectCwtchForeground() {
	ReconnectCwtchForeground()
}

// Like StartCwtch, but StartCwtch has already been called so we don't need to restart Tor etc (probably)
// Do need to re-send initial state tho, eg profiles that are already loaded
func ReconnectCwtchForeground() {
	log.Infof("Reconnecting cwtchforeground")
	if application == nil {
		log.Errorf("ReconnectCwtchForeground: Application is nil, presuming stale thread, EXITING Reconnect\n")
		return
	}

	// populate profile list
	peerList := application.ListProfiles()
	for _, onion := range peerList {
		eventHandler.Push(event.NewEvent(event.NewPeer, map[event.Field]string{event.Identity: onion, event.Created: event.False, "Reload": event.True}))
	}

	settings := utils.ReadGlobalSettings()

	for _, profileOnion := range peerList {
		// fix peerpeercontact message counts
		contactList := application.GetPeer(profileOnion).GetContacts()
		for _, handle := range contactList {
			totalMessages := application.GetPeer(profileOnion).GetContact(handle).Timeline.Len() + len(application.GetPeer(profileOnion).GetContact(handle).UnacknowledgedMessages)
			eventHandler.Push(event.NewEvent(event.MessageCounterResync, map[event.Field]string{
				event.Identity:   profileOnion,
				event.RemotePeer: handle,
				event.Data:       strconv.Itoa(totalMessages),
			}))
		}

		// Group Experiment Refresh
		groupHandler, err := groups.ExperimentGate(settings.Experiments)
		if err == nil {
			// fix peergroupcontact message counts
			groupList := application.GetPeer(profileOnion).GetGroups()
			for _, groupID := range groupList {
				totalMessages := len(application.GetPeer(profileOnion).GetGroup(groupID).GetTimeline())
				eventHandler.Push(event.NewEvent(event.MessageCounterResync, map[event.Field]string{
					event.Identity: profileOnion,
					event.GroupID:  groupID,
					event.Data:     strconv.Itoa(totalMessages),
				}))
			}

			serverListForOnion := groupHandler.GetServerInfoList(application.GetPeer(profileOnion))
			serversListBytes, _ := json.Marshal(serverListForOnion)
			eventHandler.Push(event.NewEvent(groups.UpdateServerInfo, map[event.Field]string{"ProfileOnion": profileOnion, groups.ServerList: string(serversListBytes)}))
		}
	}

	publishLoadedServers()

	settingsJson, _ := json.Marshal(settings)
	application.GetPrimaryBus().Publish(event.NewEvent(utils.UpdateGlobalSettings, map[event.Field]string{event.Data: string(settingsJson)}))
	application.GetPrimaryBus().Publish(event.NewEvent(utils.CwtchStarted, map[event.Field]string{}))
	application.QueryACNStatus()
	application.QueryACNVersion()
}

func publishLoadedServers() {
	serversHandler, err := servers.ExperimentGate(utils.ReadGlobalSettings().Experiments)
	if err == nil {
		serversList := serversHandler.ListServers()
		for _, server := range serversList {
			serverInfo := serversHandler.GetServerInfo(server)
			ev := event.NewEvent(servers.NewServer, make(map[event.Field]string))
			serverInfo.EnrichEvent(&ev)
			application.GetPrimaryBus().Publish(ev)
		}
	}
}

//export c_SendAppEvent
// A generic method for Rebroadcasting App Events from a UI
func c_SendAppEvent(json_ptr *C.char, json_len C.int) {
	eventJson := C.GoStringN(json_ptr, json_len)
	SendAppEvent(eventJson)
}

// SendAppEvent is a generic method for Rebroadcasting App Events from a UI
func SendAppEvent(eventJson string) {
	// Convert the Event Json back to a typed Event Struct, this will make the
	// rest of the logic nicer.
	var new_event event.Event
	json.Unmarshal([]byte(eventJson), &new_event)
	log.Debugf("Event: %v", new_event.EventType)

	// We need to update the local cache
	// Ideally I think this would be pushed back into Cwtch
	switch new_event.EventType {
	case utils.UpdateGlobalSettings:
		var globalSettings utils.GlobalSettings
		err := json.Unmarshal([]byte(new_event.Data[event.Data]), &globalSettings)
		if err != nil {
			log.Errorf("Error Unmarshalling Settings %v [%v]", err, new_event.Data[event.Data])
		}
		log.Debugf("New Settings %v", globalSettings)
		utils.WriteGlobalSettings(globalSettings)

		settings := utils.ReadGlobalSettings()

		_, err = servers.ExperimentGate(settings.Experiments)
		if err == nil {
			servers.InitServers(globalACN, globalAppDir)
			publishLoadedServers()
			LaunchServers()
		} else {
			servers.DeactivateServers()
		}

		// Group Experiment Refresh
		groupHandler, err := groups.ExperimentGate(settings.Experiments)
		if err == nil {
			for _, profileOnion := range application.ListProfiles() {
				serverListForOnion := groupHandler.GetServerInfoList(application.GetPeer(profileOnion))
				serversListBytes, _ := json.Marshal(serverListForOnion)
				eventHandler.Push(event.NewEvent(groups.UpdateServerInfo, map[event.Field]string{"ProfileOnion": profileOnion, groups.ServerList: string(serversListBytes)}))
			}
		}

		// Explicitly toggle blocking/unblocking of unknown connections for profiles
		// that have been loaded.
		if settings.BlockUnknownConnections {
			for _, onion := range application.ListProfiles() {
				application.GetPeer(onion).BlockUnknownConnections()
			}
		} else {
			for _, onion := range application.ListProfiles() {
				application.GetPeer(onion).AllowUnknownConnections()
			}
		}

	case utils.SetLoggingLevel:
		_, warn := new_event.Data[utils.Warn]
		_, err := new_event.Data[utils.Error]
		_, debug := new_event.Data[utils.Debug]
		_, info := new_event.Data[utils.Info]
		// Assign logging level in priority order. The highest logging level wins in the
		// event of multiple fields.
		if info {
			log.SetLevel(log.LevelInfo)
		} else if warn {
			log.SetLevel(log.LevelWarn)
		} else if err {
			log.SetLevel(log.LevelError)
		} else if debug {
			log.SetLevel(log.LevelDebug)
		}
	default: // do nothing
	}
}

//export c_SendProfileEvent
// A generic method for Rebroadcasting Profile Events from a UI
func c_SendProfileEvent(onion_ptr *C.char, onion_len C.int, json_ptr *C.char, json_len C.int) {
	onion := C.GoStringN(onion_ptr, onion_len)
	eventJson := C.GoStringN(json_ptr, json_len)
	SendProfileEvent(onion, eventJson)
}

const (
	AddContact   = event.Type("AddContact")
	ImportString = event.Field("ImportString")
)

// SendProfileEvent is a generic method for Rebroadcasting Profile Events from a UI
// Should generally be used for rapidly prototyping new APIs
func SendProfileEvent(onion string, eventJson string) {
	// Convert the Event Json back to a typed Event Struct, this will make the
	// rest of the logic nicer.
	var new_event event.Event
	json.Unmarshal([]byte(eventJson), &new_event)
	log.Infof("Event: %v %v", onion, new_event)

	// Get the correct Peer
	peer := application.GetPeer(onion)
	if peer == nil {
		return
	}

	// We need to update the local cache
	// Ideally I think this would be pushed back into Cwtch
	switch new_event.EventType {
	// DEPRECATED: use ImportBundle
	case AddContact:
		pf, _ := contact.FunctionalityGate(utils.ReadGlobalSettings().Experiments)
		err := pf.HandleImportString(peer, new_event.Data[ImportString])
		eventHandler.Push(event.NewEvent(event.AppError, map[event.Field]string{event.Data: err.Error()}))
	// DEPRECATED: use SetProfileAttribute()
	case event.SetAttribute:
		log.Errorf("SetAttribute is deprecated.")
	// DEPRECATED: use SetContactAttribute()
	case event.SetPeerAttribute:
		peer.SetContactAttribute(new_event.Data[event.RemotePeer], new_event.Data[event.Key], new_event.Data[event.Data])
	// DEPRECATED: use AcceptContact() and BlockContact()
	case event.SetPeerAuthorization:
		peer.SetContactAuthorization(new_event.Data[event.RemotePeer], model.Authorization(new_event.Data[event.Authorization]))

		// If approved (e.g. after an unblock) we want to kick off peering again...
		if model.Authorization(new_event.Data[event.Authorization]) == model.AuthApproved {
			peer.PeerWithOnion(new_event.Data[event.RemotePeer])
		}
	default:
		// rebroadcast catch all
		log.Infof("Received Event %v for %v but no libCwtch handler found, relaying the event directly", new_event, onion)
		application.GetEventBus(onion).Publish(new_event)
	}
}

//export c_GetAppBusEvent
// the pointer returned from this function **must** be freed using c_Free
func c_GetAppBusEvent() *C.char {
	return C.CString(GetAppBusEvent())
}

// GetAppBusEvent blocks until an event
func GetAppBusEvent() string {
	for eventHandler == nil {
		log.Debugf("waiting for eventHandler != nil")
		time.Sleep(time.Second)
	}

	var json = ""
	for json == "" {
		json = eventHandler.GetNextEvent()
	}
	return json
}

//export c_CreateProfile
func c_CreateProfile(nick_ptr *C.char, nick_len C.int, pass_ptr *C.char, pass_len C.int) {
	CreateProfile(C.GoStringN(nick_ptr, nick_len), C.GoStringN(pass_ptr, pass_len))
}

func CreateProfile(nick, pass string) {
	if pass == constants.DefactoPasswordForUnencryptedProfiles {
		application.CreateTaggedPeer(nick, pass, constants.ProfileTypeV1DefaultPassword)
	} else {
		application.CreateTaggedPeer(nick, pass, constants.ProfileTypeV1Password)
	}
}

//export c_LoadProfiles
func c_LoadProfiles(passwordPtr *C.char, passwordLen C.int) {
	LoadProfiles(C.GoStringN(passwordPtr, passwordLen))
}

func LoadProfiles(pass string) {
	application.LoadProfiles(pass)
}

//export c_AcceptContact
func c_AcceptContact(profilePtr *C.char, profileLen C.int, handlePtr *C.char, handleLen C.int) {
	AcceptContact(C.GoStringN(profilePtr, profileLen), C.GoStringN(handlePtr, handleLen))
}

// AcceptContact takes in a profileOnion and a handle to either a group or a peer and authorizes the handle
// for further action (e.g. messaging / connecting to the server / joining the group etc.)
func AcceptContact(profileOnion string, handle string) {
	profile := application.GetPeer(profileOnion)
	profileHandler := utils.NewPeerHelper(profile)
	if profileHandler.IsGroup(handle) {
		profile.AcceptInvite(handle)
	} else {
		err := profile.SetContactAuthorization(handle, model.AuthApproved)
		if err == nil {
			eventHandler.Push(event.NewEvent(event.PeerStateChange, map[event.Field]string{
				ProfileOnion:     profileOnion,
				event.RemotePeer: handle,
				"authorization":  string(model.AuthApproved),
			}))
		} else {
			log.Errorf("error accepting contact: %s", err.Error())
		}
	}
}

//export c_RejectInvite
func c_RejectInvite(profilePtr *C.char, profileLen C.int, handlePtr *C.char, handleLen C.int) {
	RejectInvite(C.GoStringN(profilePtr, profileLen), C.GoStringN(handlePtr, handleLen))
}

// RejectInvite rejects a group invite
func RejectInvite(profileOnion string, handle string) {
	log.Debugf("rejecting invite %v for %v", handle, profileOnion)
	profile := application.GetPeer(profileOnion)
	profileHandler := utils.NewPeerHelper(profile)
	if profileHandler.IsGroup(handle) {
		profile.RejectInvite(handle)
		log.Debugf("successfully rejected invite %v for %v", handle, profileOnion)
	}
}

//export c_BlockContact
func c_BlockContact(profilePtr *C.char, profileLen C.int, handlePtr *C.char, handleLen C.int) {
	BlockContact(C.GoStringN(profilePtr, profileLen), C.GoStringN(handlePtr, handleLen))
}

func BlockContact(profile, handle string) {
	err := application.GetPeer(profile).SetContactAuthorization(handle, model.AuthBlocked)
	if err == nil {
		eventHandler.Push(event.NewEvent(event.PeerStateChange, map[event.Field]string{
			ProfileOnion:     profile,
			event.RemotePeer: handle,
			"authorization":  string(model.AuthBlocked),
		}))
	} else {
		log.Errorf("error blocking contact: %s", err.Error())
	}
}

//export c_UpdateMessageFlags
func c_UpdateMessageFlags(profile_ptr *C.char, profile_len C.int, handle_ptr *C.char, handle_len C.int, mIdx C.int, message_flags C.ulong) {
	profile := C.GoStringN(profile_ptr, profile_len)
	handle := C.GoStringN(handle_ptr, handle_len)
	UpdateMessageFlags(profile, handle, int(mIdx), int64(message_flags))
}

// UpdateMessageFlags sets the messages flags on a given message for a given profile.
// gomobile doesn't support uint64...so here we are....
func UpdateMessageFlags(profileOnion, handle string, mIdx int, flags int64) {
	profile := application.GetPeer(profileOnion)
	if profile != nil {
		profile.UpdateMessageFlags(handle, mIdx, uint64(flags))
	} else {
		log.Errorf("called updatemessageflags with invalid profile onion")
	}
}

//export c_GetMessage
// the pointer returned from this function **must** be Freed  by c_Free
func c_GetMessage(profile_ptr *C.char, profile_len C.int, handle_ptr *C.char, handle_len C.int, message_index C.int) *C.char {
	profile := C.GoStringN(profile_ptr, profile_len)
	handle := C.GoStringN(handle_ptr, handle_len)
	return C.CString(GetMessage(profile, handle, int(message_index)))
}

// EnhancedMessage wraps a Cwtch model.Message with some additional data to reduce calls from the UI.
type EnhancedMessage struct {
	model.Message
	ContactImage string
}

func GetMessage(profileOnion, handle string, messageIndex int) string {
	var message EnhancedMessage
	// There is an edge case that can happen on Android when the app is shutdown while fetching messages...
	// The worker threads that are spawned can become activated again when the app is opened attempt to finish their job...
	// In that case we skip processing and just return the empty message...
	// Note: This is far less likely to happen now that the UI only requests messages *after* syncing has happened and
	// these requests complete almost immediately v.s. being stalled for seconds to minutes on large groups.
	if application != nil {
		profile := application.GetPeer(profileOnion)
		ph := utils.NewPeerHelper(profile)
		if ph.IsGroup(handle) {
			if profile.GetGroup(handle) != nil {

				exists, timelineMessage, length := profile.GetGroup(handle).GetMessage(messageIndex)
				if exists {
					message.Message = timelineMessage
					message.ContactImage = ph.GetProfilePic(message.Message.PeerID)
				} else {
					eventHandler.Push(event.NewEvent(event.MessageCounterResync, map[event.Field]string{
						event.Identity:   profileOnion,
						event.GroupID: handle,
						event.Data:   strconv.Itoa(length),
					}))
					log.Errorf("Couldn't find message in timeline %v / %v or unacked messages, probably transient threading issue, but logging for visibility..", messageIndex, length)
				}
			}
		} else {
			if profile.GetContact(handle) != nil {
				// If we are safely within the limits of the timeline just grab the message at the index..
				if len(profile.GetContact(handle).Timeline.Messages) > messageIndex {
					message.Message = profile.GetContact(handle).Timeline.Messages[messageIndex]
					message.ContactImage = ph.GetProfilePic(handle)
				} else {
					// Otherwise Send a counter resync event...this shouldn't really happen for p2p messages so we
					// throw an error.
					log.Errorf("peerpeercontact getmessage out of range; sending counter resync just in case")
					eventHandler.Push(event.NewEvent(event.MessageCounterResync, map[event.Field]string{
						event.Identity:   profileOnion,
						event.RemotePeer: handle,
						event.Data:       strconv.Itoa(len(profile.GetContact(handle).Timeline.Messages)),
					}))
				}
			}
		}
	}
	bytes, _ := json.Marshal(message)
	return string(bytes)
}

//export c_GetMessagesByContentHash
// the pointer returned from this function **must** be freed by calling c_Free
func c_GetMessagesByContentHash(profile_ptr *C.char, profile_len C.int, handle_ptr *C.char, handle_len C.int, contenthash_ptr *C.char, contenthash_len C.int) *C.char {
	profile := C.GoStringN(profile_ptr, profile_len)
	handle := C.GoStringN(handle_ptr, handle_len)
	contentHash := C.GoStringN(contenthash_ptr, contenthash_len)
	return C.CString(GetMessagesByContentHash(profile, handle, contentHash))
}

//export c_FreePointer
// Dangerous function. Should only be used as documented in `MEMORY.md`
func c_FreePointer(ptr *C.char) {
	C.free(unsafe.Pointer(ptr))
}

func GetMessagesByContentHash(profileOnion, handle string, contentHash string) string {
	var indexedMessages []model.LocallyIndexedMessage
	if application != nil {
		profile := application.GetPeer(profileOnion)
		ph := utils.NewPeerHelper(profile)
		var err error
		timeline := ph.GetTimeline(handle)
		if timeline != nil {
			indexedMessages, err = timeline.GetMessagesByHash(contentHash)
			if err != nil {
				indexedMessages = []model.LocallyIndexedMessage{}
			}
		}
	}
	bytes, _ := json.Marshal(indexedMessages)
	return string(bytes)
}

//export c_SendMessage
func c_SendMessage(profile_ptr *C.char, profile_len C.int, handle_ptr *C.char, handle_len C.int, msg_ptr *C.char, msg_len C.int) {
	profile := C.GoStringN(profile_ptr, profile_len)
	handle := C.GoStringN(handle_ptr, handle_len)
	msg := C.GoStringN(msg_ptr, msg_len)
	SendMessage(profile, handle, msg)
}

func SendMessage(profileOnion, handle, msg string) {
	profile := application.GetPeer(profileOnion)
	ph := utils.NewPeerHelper(profile)
	if ph.IsGroup(handle) {
		groupHandler, err := groups.ExperimentGate(utils.ReadGlobalSettings().Experiments)
		if err == nil {
			groupHandler.SendMessage(profile, handle, msg)
			profile.SetGroupAttribute(handle, attr.GetLocalScope(constants.Archived), event.False)
		}
	} else {
		contactHandler, _ := contact.FunctionalityGate(utils.ReadGlobalSettings().Experiments)
		contactHandler.SendMessage(profile, handle, msg)
		profile.SetContactAttribute(handle, attr.GetLocalScope(constants.Archived), event.False)
	}
}

//export c_SendInvitation
func c_SendInvitation(profile_ptr *C.char, profile_len C.int, handle_ptr *C.char, handle_len C.int, target_ptr *C.char, target_len C.int) {
	profile := C.GoStringN(profile_ptr, profile_len)
	handle := C.GoStringN(handle_ptr, handle_len)
	target := C.GoStringN(target_ptr, target_len)
	SendInvitation(profile, handle, target)
}

// Send an invitation from `profileOnion` to contact `handle` (peer or group)
// asking them to add the contact `target`  (also peer or group).
// For groups, the profile must already have `target` as a contact.
func SendInvitation(profileOnion, handle, target string) {
	profile := application.GetPeer(profileOnion)
	ph := utils.NewPeerHelper(profile)

	var invite ChatMessage
	if ph.IsGroup(target) {
		bundle, _ := profile.GetContact(profile.GetGroup(target).GroupServer).GetAttribute(string(model.BundleType))
		inviteStr, err := profile.GetGroup(target).Invite()
		if err == nil {
			invite = ChatMessage{O: 101, D: fmt.Sprintf("tofubundle:server:%s||%s", base64.StdEncoding.EncodeToString([]byte(bundle)), inviteStr)}
		}
	} else {
		invite = ChatMessage{O: 100, D: target}
	}

	inviteBytes, err := json.Marshal(invite)
	if err != nil {
		log.Errorf("malformed invite: %v", err)
	} else {
		SendMessage(profileOnion, handle, string(inviteBytes))
	}
}

//export c_ShareFile
func c_ShareFile(profile_ptr *C.char, profile_len C.int, handle_ptr *C.char, handle_len C.int, filepath_ptr *C.char, filepath_len C.int) {
	profile := C.GoStringN(profile_ptr, profile_len)
	handle := C.GoStringN(handle_ptr, handle_len)
	sharefilepath := C.GoStringN(filepath_ptr, filepath_len)
	ShareFile(profile, handle, sharefilepath)
}

func ShareFile(profileOnion, handle, sharefilepath string) {
	profile := application.GetPeer(profileOnion)
	fh, err := filesharing.FunctionalityGate(utils.ReadGlobalSettings().Experiments)
	if err != nil {
		log.Errorf("file sharing error: %v", err)
	} else {
		err = fh.ShareFile(sharefilepath, profile, handle)
		if err != nil {
			log.Errorf("error sharing file: %v", err)
		}
	}
}

//export c_DownloadFile
func c_DownloadFile(profile_ptr *C.char, profile_len C.int, handle_ptr *C.char, handle_len C.int, filepath_ptr *C.char, filepath_len C.int, manifestpath_ptr *C.char, manifestpath_len C.int, filekey_ptr *C.char, filekey_len C.int) {
	profile := C.GoStringN(profile_ptr, profile_len)
	handle := C.GoStringN(handle_ptr, handle_len)
	downloadfilepath := C.GoStringN(filepath_ptr, filepath_len)
	manifestpath := C.GoStringN(manifestpath_ptr, manifestpath_len)
	filekey := C.GoStringN(filekey_ptr, filekey_len)
	DownloadFile(profile, handle, downloadfilepath, manifestpath, filekey)
}

func DownloadFile(profileOnion, handle, filepath, manifestpath, filekey string) {
	profile := application.GetPeer(profileOnion)
	fh, err := filesharing.FunctionalityGate(utils.ReadGlobalSettings().Experiments)
	if err != nil {
		log.Errorf("file sharing error: %v", err)
	} else {
		fh.DownloadFile(profile, handle, filepath, manifestpath, filekey)
	}
}

//export c_CheckDownloadStatus
func c_CheckDownloadStatus(profilePtr *C.char, profileLen C.int, fileKeyPtr *C.char, fileKeyLen C.int) {
	CheckDownloadStatus(C.GoStringN(profilePtr, profileLen), C.GoStringN(fileKeyPtr, fileKeyLen))
}

func CheckDownloadStatus(profileOnion, fileKey string) {
	profile := application.GetPeer(profileOnion)
	if path, exists := profile.GetScopedZonedAttribute(attr.LocalScope, attr.FilesharingZone, fileKey); exists {
		eventHandler.Push(event.NewEvent(event.FileDownloaded, map[event.Field]string{
			ProfileOnion:   profileOnion,
			event.FileKey:  fileKey,
			event.FilePath: path,
			event.TempFile: "",
		}))
	}
}

//export c_ResetTor
func c_ResetTor() {
	ResetTor()
}

func ResetTor() {
	globalACN.Restart()
}

//export c_CreateGroup
func c_CreateGroup(profile_ptr *C.char, profile_len C.int, server_ptr *C.char, server_len C.int, name_ptr *C.char, name_len C.int) {
	profile := C.GoStringN(profile_ptr, profile_len)
	server := C.GoStringN(server_ptr, server_len)
	name := C.GoStringN(name_ptr, name_len)
	CreateGroup(profile, server, name)
}

// CreateGroup takes in a profile and server in addition to a name and creates a new group.
func CreateGroup(profileHandle string, server string, name string) {
	profile := application.GetPeer(profileHandle)
	_, err := groups.ExperimentGate(utils.ReadGlobalSettings().Experiments)
	if err == nil {
		gid, _, err := profile.StartGroup(server)
		if err == nil {
			log.Debugf("created group %v on %v: $v", profileHandle, server, gid)
			// set the group name
			profile.SetGroupAttribute(gid, attr.GetLocalScope("name"), name)
		} else {
			log.Errorf("error creating group or %v on server %v: %v", profileHandle, server, err)
		}
	}
}

//export c_DeleteProfile
func c_DeleteProfile(profile_ptr *C.char, profile_len C.int, password_ptr *C.char, password_len C.int) {
	profile := C.GoStringN(profile_ptr, profile_len)
	password := C.GoStringN(password_ptr, password_len)
	DeleteProfile(profile, password)
}

// DeleteProfile deletes a profile given the right password
func DeleteProfile(profile string, password string) {

	// allow a blank password to delete "unencrypted" accounts...
	if password == "" {
		password = constants.DefactoPasswordForUnencryptedProfiles
	}

	application.DeletePeer(profile, password)
}

//export c_ArchiveConversation
func c_ArchiveConversation(profile_ptr *C.char, profile_len C.int, handle_ptr *C.char, handle_len C.int) {
	profile := C.GoStringN(profile_ptr, profile_len)
	handle := C.GoStringN(handle_ptr, handle_len)
	ArchiveConversation(profile, handle)
}

// ArchiveConversation sets the conversation to archived
func ArchiveConversation(profileHandle string, handle string) {
	profile := application.GetPeer(profileHandle)
	ph := utils.NewPeerHelper(profile)
	if ph.IsGroup(handle) {
		profile.SetGroupAttribute(handle, attr.GetLocalScope(constants.Archived), event.True)
	} else {
		profile.SetContactAttribute(handle, attr.GetLocalScope(constants.Archived), event.True)
	}
}

//export c_DeleteContact
func c_DeleteContact(profile_ptr *C.char, profile_len C.int, hanlde_ptr *C.char, handle_len C.int) {
	profile := C.GoStringN(profile_ptr, profile_len)
	groupID := C.GoStringN(hanlde_ptr, handle_len)
	DeleteContact(profile, groupID)
}

// DeleteContact removes all trace of the contact from the profile
func DeleteContact(profileHandle string, handle string) {
	profile := application.GetPeer(profileHandle)
	ph := utils.NewPeerHelper(profile)
	if ph.IsGroup(handle) {
		_, err := groups.ExperimentGate(utils.ReadGlobalSettings().Experiments)
		if err == nil {
			profile.DeleteGroup(handle)
		}
	} else {
		profile.DeleteContact(handle)
	}
}

//export c_ImportBundle
func c_ImportBundle(profile_ptr *C.char, profile_len C.int, bundle_ptr *C.char, bundle_len C.int) {
	profile := C.GoStringN(profile_ptr, profile_len)
	name := C.GoStringN(bundle_ptr, bundle_len)
	ImportBundle(profile, name)
}

// ImportBundle takes in a handle to a profile and an invite string which could have one of many
// different formats (e.g. a peer address, a group invite, a server key bundle, or a combination)
func ImportBundle(profileOnion string, bundle string) {
	profile := application.GetPeer(profileOnion)
	peerHandler, _ := contact.FunctionalityGate(utils.ReadGlobalSettings().Experiments)
	response := peerHandler.HandleImportString(profile, bundle)
	if strings.Contains(response.Error(), "invalid_import_string") {
		groupHandler, err := groups.ExperimentGate(utils.ReadGlobalSettings().Experiments)
		if err == nil {
			response = groupHandler.HandleImportString(profile, bundle)
			eventHandler.Push(event.NewEvent(event.AppError, map[event.Field]string{event.Data: response.Error()}))

			// We might have added a new server, so refresh the server list...
			serverListForOnion := groupHandler.GetServerInfoList(profile)
			serversListBytes, _ := json.Marshal(serverListForOnion)
			eventHandler.Push(event.NewEvent(groups.UpdateServerInfo, map[event.Field]string{"ProfileOnion": profileOnion, groups.ServerList: string(serversListBytes)}))
			return
		}
	}
	eventHandler.Push(event.NewEvent(event.AppError, map[event.Field]string{event.Data: response.Error()}))
}

//export c_SetProfileAttribute
func c_SetProfileAttribute(profile_ptr *C.char, profile_len C.int, key_ptr *C.char, key_len C.int, val_ptr *C.char, val_len C.int) {
	profileOnion := C.GoStringN(profile_ptr, profile_len)
	key := C.GoStringN(key_ptr, key_len)
	value := C.GoStringN(val_ptr, val_len)
	SetProfileAttribute(profileOnion, key, value)
}

// SetProfileAttribute provides a wrapper around profile.SetScopedZonedAttribute
// WARNING: Because this function is potentially dangerous all keys and zones must be added
// explicitly. If you are attempting to added behaviour to the UI that requires the existence of new keys
// you probably want to be building out functionality/subsystem in the UI itself.
// Key must have the format zone.key where Zone is defined in Cwtch. Unknown zones are not permitted.
func SetProfileAttribute(profileOnion string, key string, value string) {
	profile := application.GetPeer(profileOnion)

	zone, key := attr.ParseZone(key)

	// TODO We only allow public.profile.zone to be set for now.
	// All other scopes and zones need to be added explicitly or handled by Cwtch.
	if zone == attr.ProfileZone && key == constants.Name {
		profile.SetScopedZonedAttribute(attr.PublicScope, attr.ProfileZone, constants.Name, value)
	} else {
		log.Errorf("attempted to set an attribute with an unknown zone: %v", key)
	}
}

//export c_SetContactAttribute
func c_SetContactAttribute(profile_ptr *C.char, profile_len C.int, contact_ptr *C.char, contact_len C.int, key_ptr *C.char, key_len C.int, val_ptr *C.char, val_len C.int) {
	profileOnion := C.GoStringN(profile_ptr, profile_len)
	contactHandle := C.GoStringN(contact_ptr, contact_len)
	key := C.GoStringN(key_ptr, key_len)
	value := C.GoStringN(val_ptr, val_len)
	SetContactAttribute(profileOnion, contactHandle, key, value)
}

// SetContactAttribute provides a wrapper around profile.SetProfileAttribute
func SetContactAttribute(profileOnion string, contactHandle string, key string, value string) {
	profile := application.GetPeer(profileOnion)
	profile.SetContactAttribute(contactHandle, key, value)
}

//export c_SetGroupAttribute
func c_SetGroupAttribute(profile_ptr *C.char, profile_len C.int, group_ptr *C.char, group_len C.int, key_ptr *C.char, key_len C.int, val_ptr *C.char, val_len C.int) {
	profileOnion := C.GoStringN(profile_ptr, profile_len)
	groupHandle := C.GoStringN(group_ptr, group_len)
	key := C.GoStringN(key_ptr, key_len)
	value := C.GoStringN(val_ptr, val_len)
	SetGroupAttribute(profileOnion, groupHandle, key, value)
}

// SetGroupAttribute provides a wrapper around profile.SetGroupAttribute, gated by global experiments...
func SetGroupAttribute(profileOnion string, groupHandle string, key string, value string) {
	profile := application.GetPeer(profileOnion)
	_, err := groups.ExperimentGate(utils.ReadGlobalSettings().Experiments)
	if err == nil {
		profile.SetGroupAttribute(groupHandle, key, value)
	}
}

//export c_ShutdownCwtch
func c_ShutdownCwtch() {
	ShutdownCwtch()
}

// ShutdownCwtch is a safe way to shutdown any active cwtch applications and associated ACNs
func ShutdownCwtch() {
	if application != nil && globalACN != nil {
		// Kill the isolate
		eventHandler.Push(event.NewEvent(event.Shutdown, map[event.Field]string{}))

		// Allow for the shutdown events to go through and then purge everything else...
		log.Infof("Shutting Down Application...")
		application.Shutdown()
		log.Infof("Shutting Down ACN...")
		globalACN.Close()
		log.Infof("Library Shutdown Complete!")
		// do not remove - important for state checks elsewhere
		application = nil
		globalACN = nil
		eventHandler = nil
	}
}

//***** Server APIs *****

//export c_LoadServers
func c_LoadServers(passwordPtr *C.char, passwordLen C.int) {
	LoadServers(C.GoStringN(passwordPtr, passwordLen))
}

func LoadServers(password string) {
	serversHandler, err := servers.ExperimentGate(utils.ReadGlobalSettings().Experiments)
	if err == nil {
		serversList, err := serversHandler.LoadServers(password)
		if err != nil {
			log.Errorf("Error attempting to load servers :%s\n", err)
			application.GetPrimaryBus().Publish(event.NewEventList(servers.ZeroServersLoaded))
		} else if len(serversList) == 0 {
			application.GetPrimaryBus().Publish(event.NewEventList(servers.ZeroServersLoaded))
		} else {
			for _, serverOnion := range serversList {
				serverInfo := serversHandler.GetServerInfo(serverOnion)
				log.Debugf("Load Server NewServer event: %s", serverInfo)
				ev := event.NewEvent(servers.NewServer, make(map[event.Field]string))
				serverInfo.EnrichEvent(&ev)
				application.GetPrimaryBus().Publish(ev)
			}
		}
	}
}

//export c_CreateServer
func c_CreateServer(passwordPtr *C.char, passwordLen C.int, descPtr *C.char, descLen C.int, autostart C.char) {
	CreateServer(C.GoStringN(passwordPtr, passwordLen), C.GoStringN(descPtr, descLen), autostart == 1)
}

func CreateServer(password string, description string, autostart bool) {
	serversHandler, err := servers.ExperimentGate(utils.ReadGlobalSettings().Experiments)
	if err == nil {
		s, err := serversHandler.CreateServer(password)
		if err != nil {
			log.Errorf("Could not create new server: %s\n", err)
		} else {
			s.SetAttribute(server.AttrDescription, description)
			if autostart {
				s.SetAttribute(server.AttrAutostart, "true")
				LaunchServer(s.Onion())
			} else {
				s.SetAttribute(server.AttrAutostart, "false")
			}
			if password == constants.DefactoPasswordForUnencryptedProfiles {
				s.SetAttribute(server.AttrStorageType, server.StorageTypeDefaultPassword)
			} else {
				s.SetAttribute(server.AttrStorageType, server.StorageTypePassword)
			}
			serverInfo := serversHandler.GetServerInfo(s.Onion())
			log.Debugf("Creating Server NewServer event: %s", serverInfo)
			ev := event.NewEvent(servers.NewServer, make(map[event.Field]string))
			serverInfo.EnrichEvent(&ev)
			application.GetPrimaryBus().Publish(ev)
		}
	}
}

//export c_DeleteServer
func c_DeleteServer(onionPtr *C.char, onionLen C.int, currentPasswordPtr *C.char, currentPasswordLen C.int) {
	DeleteServer(C.GoStringN(onionPtr, onionLen), C.GoStringN(currentPasswordPtr, currentPasswordLen))
}

func DeleteServer(onion string, currentPassword string) {
	serversHandler, err := servers.ExperimentGate(utils.ReadGlobalSettings().Experiments)
	if err == nil {
		serversHandler.StopServer(onion)
		application.GetPrimaryBus().Publish(event.NewEventList(servers.ServerIntentUpdate, event.Identity, onion, servers.Intent, servers.IntentStopped))
		serversHandler.DeleteServer(onion, currentPassword)
		// TODO HANDLE err from DeleteServer?
	}
}

//export c_LaunchServers
func c_LaunchServers() {
	LaunchServers()
}

func LaunchServers() {
	serversHandler, err := servers.ExperimentGate(utils.ReadGlobalSettings().Experiments)
	if err == nil {
		for _, onion := range serversHandler.ListServers() {
			autostart := false
			if s := serversHandler.GetServer(onion); s != nil {
				autostart = s.GetAttribute(server.AttrAutostart) == "true"
			}
			if autostart {
				LaunchServer(onion)
			}
		}
	}
}

//export c_LaunchServer
func c_LaunchServer(onionPtr *C.char, onionLen C.int) {
	LaunchServer(C.GoStringN(onionPtr, onionLen))
}

func LaunchServer(onion string) {
	serversHandler, err := servers.ExperimentGate(utils.ReadGlobalSettings().Experiments)
	if err == nil {
		serversHandler.LaunchServer(onion)
		application.GetPrimaryBus().Publish(event.NewEventList(servers.ServerIntentUpdate, event.Identity, onion, servers.Intent, servers.IntentRunning))
	}
}


//export c_StopServer
func c_StopServer(onionPtr *C.char, onionLen C.int) {
	StopServer(C.GoStringN(onionPtr, onionLen))
}

func StopServer(onion string) {
	serversHandler, err := servers.ExperimentGate(utils.ReadGlobalSettings().Experiments)
	if err == nil {
		serversHandler.StopServer(onion)
		application.GetPrimaryBus().Publish(event.NewEventList(servers.ServerIntentUpdate, event.Identity, onion, servers.Intent, servers.IntentStopped))
	}
}

//export c_StopServers
func c_StopServers() {
	StopServers()
}

func StopServers() {
	serversHandler, err := servers.ExperimentGate(utils.ReadGlobalSettings().Experiments)
	if err == nil {
		for _, onion := range serversHandler.ListServers() {
			StopServer(onion)
		}
	}
}

//export c_DestroyServers
func c_DestroyServers() {
	DestroyServers()
}

func DestroyServers() {
	serversHandler, err := servers.ExperimentGate(utils.ReadGlobalSettings().Experiments)
	if err == nil {
		serversHandler.DestroyServers()
	}
}

//export c_SetServerAttribute
func c_SetServerAttribute(onionPtr *C.char, onionLen C.int, keyPtr *C.char, keyLen C.int, valPtr *C.char, valLen C.int) {
	SetServerAttribute(C.GoStringN(onionPtr, onionLen), C.GoStringN(keyPtr, keyLen), C.GoStringN(valPtr, valLen))
}

func SetServerAttribute(onion string, key string, val string) {
	serversHandler, err := servers.ExperimentGate(utils.ReadGlobalSettings().Experiments)
	if err == nil {
		server := serversHandler.GetServer(onion)
		if server != nil {
			server.SetAttribute(key, val)
		}
	}
}

// ***** END Server APIs *****

// Leave as is, needed by ffi
func main() {}
