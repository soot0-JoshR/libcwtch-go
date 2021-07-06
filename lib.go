//package cwtch

package main

import "C"
import (
	"crypto/rand"
	"cwtch.im/cwtch/app"
	"cwtch.im/cwtch/event"
	"cwtch.im/cwtch/model"
	"cwtch.im/cwtch/model/attr"
	"cwtch.im/cwtch/peer"
	"encoding/json"
	"fmt"
	"git.openprivacy.ca/flutter/libcwtch-go/constants"
	contact "git.openprivacy.ca/flutter/libcwtch-go/features/contacts"
	"git.openprivacy.ca/flutter/libcwtch-go/features/groups"
	"git.openprivacy.ca/flutter/libcwtch-go/utils"
	"git.openprivacy.ca/openprivacy/connectivity"
	"runtime"
	"strconv"
	"strings"

	"encoding/base64"
	"git.openprivacy.ca/openprivacy/connectivity/tor"
	"git.openprivacy.ca/openprivacy/log"
	mrand "math/rand"
	"os"
	"path"
	"path/filepath"
	"time"
)

const (
	// ProfileOnion is an event field that contains the handle for a given profile.
	// todo: this should probably be moved back into Cwtch, and renamed ProfileHandle (onions are too tor-specific)
	ProfileOnion = event.Field("ProfileOnion")
)

var application app.Application
var eventHandler *utils.EventHandler
var acnQueue event.Queue
var contactEventsQueue event.Queue
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
func c_StartCwtch(dir_c *C.char, len C.int, tor_c *C.char, torLen C.int) int8 {
	dir := C.GoStringN(dir_c, len)
	tor := C.GoStringN(tor_c, torLen)
	return int8(StartCwtch(dir, tor))
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
		filelog.SetUseColor(false)
		if err == nil {
			log.SetStd(filelog)
		} else {
			// not so likely to be seen since we're usually creating file log in situations we can't access console logs...
			log.Errorf("could not create file log: %v\n", err)
		}
	}
	log.SetLevel(log.LevelInfo)
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

	// Exclude Tapir wire Messages
	//(We need a TRACE level)
	log.ExcludeFromPattern("service.go")

	// Ensure that the application directory exists...and then initialize settings..
	os.MkdirAll(path.Join(appDir), 0700)
	utils.InitGlobalSettingsFile(appDir, constants.DefactoPasswordForUnencryptedProfiles)

	log.Infof("Loading Cwtch Directory %v and tor path: %v", appDir, torPath)

	mrand.Seed(int64(time.Now().Nanosecond()))
	port := mrand.Intn(1000) + 9600
	controlPort := port + 1

	// generate a random password (actually random, stored in memory, for the control port)
	key := make([]byte, 64)
	_, err := rand.Read(key)
	if err != nil {
		panic(err)
	}

	log.Infof("Creating new EventHandler()")
	eventHandler = utils.NewEventHandler()

	log.Infof("making directory %v", appDir)
	os.MkdirAll(path.Join(appDir, "/.tor", "tor"), 0700)
	tor.NewTorrc().WithSocksPort(port).WithOnionTrafficOnly().WithControlPort(controlPort).WithHashedPassword(base64.StdEncoding.EncodeToString(key)).Build(filepath.Join(appDir, ".tor", "tor", "torrc"))
	acn, err := tor.NewTorACNWithAuth(path.Join(appDir, "/.tor"), torPath, controlPort, tor.HashedPasswordAuthenticator{Password: base64.StdEncoding.EncodeToString(key)})
	if err != nil {
		log.Errorf("\nError connecting to Tor replacing with ErrorACN: %v\n", err)
		eventHandler.PublishAppEvent(event.NewEventList(utils.CwtchStartError, event.Error, fmt.Sprintf("Error connecting to Tor: %v", err)))
		return
	}
	globalACN = acn
	newApp := app.NewApp(acn, appDir)
	acnQueue = event.NewQueue()
	newApp.GetPrimaryBus().Subscribe(event.ACNStatus, acnQueue)
	newApp.GetPrimaryBus().Subscribe(utils.UpdateGlobalSettings, acnQueue)
	newApp.GetPrimaryBus().Subscribe(utils.SetLoggingLevel, acnQueue)
	newApp.GetPrimaryBus().Subscribe(event.AppError, acnQueue)

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
	}
	settings := utils.ReadGlobalSettings()
	settingsJson, _ := json.Marshal(settings)

	newApp.LoadProfiles(constants.DefactoPasswordForUnencryptedProfiles)
	application = newApp

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
	peerList := application.ListPeers()
	for onion := range peerList {
		eventHandler.Push(event.NewEvent(event.NewPeer, map[event.Field]string{event.Identity: onion, event.Created: event.False, "Reload": event.True}))
	}

	settings := utils.ReadGlobalSettings()

	for profileOnion := range peerList {
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
				totalMessages := application.GetPeer(profileOnion).GetGroup(groupID).Timeline.Len() + len(application.GetPeer(profileOnion).GetGroup(groupID).UnacknowledgedMessages)
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

	settingsJson, _ := json.Marshal(settings)
	application.GetPrimaryBus().Publish(event.NewEvent(utils.UpdateGlobalSettings, map[event.Field]string{event.Data: string(settingsJson)}))
	application.GetPrimaryBus().Publish(event.NewEvent(utils.CwtchStarted, map[event.Field]string{}))
	application.QueryACNStatus()
	application.QueryACNVersion()

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

		// Group Experiment Refresh
		groupHandler, err := groups.ExperimentGate(utils.ReadGlobalSettings().Experiments)
		if err == nil {
			for profileOnion := range application.ListPeers() {
				serverListForOnion := groupHandler.GetServerInfoList(application.GetPeer(profileOnion))
				serversListBytes, _ := json.Marshal(serverListForOnion)
				eventHandler.Push(event.NewEvent(groups.UpdateServerInfo, map[event.Field]string{"ProfileOnion": profileOnion, groups.ServerList: string(serversListBytes)}))
			}
		}

		// Explicitly toggle blocking/unblocking of unknown connections for profiles
		// that have been loaded.
		if utils.ReadGlobalSettings().BlockUnknownConnections {
			for onion := range application.ListPeers() {
				application.GetPeer(onion).BlockUnknownConnections()
			}
		} else {
			for onion := range application.ListPeers() {
				application.GetPeer(onion).AllowUnknownConnections()
			}
		}

	case utils.SetLoggingLevel:
		_, warn := new_event.Data[utils.Warn]
		_, error := new_event.Data[utils.Error]
		_, debug := new_event.Data[utils.Debug]
		_, info := new_event.Data[utils.Info]
		// Assign logging level in priority order. The highest logging level wins in the
		// event of multiple fields.
		if info {
			log.SetLevel(log.LevelInfo)
		} else if warn {
			log.SetLevel(log.LevelWarn)
		} else if error {
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
	case AddContact:
		// Peer Functionality is Always Enabled, so we forgo the existence check...
		// TODO: Combine with GroupFunctionality to make a meta-handleimportstring that can do both!
		pf, _ := contact.FunctionalityGate(utils.ReadGlobalSettings().Experiments)
		err := pf.HandleImportString(peer, new_event.Data[ImportString])
		eventHandler.Push(event.NewEvent(event.AppError, map[event.Field]string{event.Data: err.Error()}))
	case event.SetAttribute:
		peer.SetAttribute(new_event.Data[event.Key], new_event.Data[event.Data])
	case event.SetPeerAttribute:
		peer.SetContactAttribute(new_event.Data[event.RemotePeer], new_event.Data[event.Key], new_event.Data[event.Data])
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

type Profile struct {
	Name      string `json:"name"`
	Onion     string `json:"onion"`
	ImagePath string `json:"imagePath"`
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

//export c_ContactEvents
func c_ContactEvents() *C.char {
	return C.CString(ContactEvents())
}

func ContactEvents() string {
	select {
	case myevent := <-contactEventsQueue.OutChan():
		return fmt.Sprintf("%v", myevent)
	default:
		return ""
	}
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

func GetMessage(profileOnion, handle string, message_index int) string {
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
			// If we are safely within the limits of the timeline just grab the message at the index..
			if len(profile.GetGroup(handle).Timeline.Messages) > message_index {
				message.Message = profile.GetGroup(handle).Timeline.Messages[message_index]
				message.ContactImage = ph.GetProfilePic(message.Message.PeerID)
			} else {
				// Message Index Request exceeded Timeline, most likely reason is this is a request for an
				// unacknowledged sent message (it can take a many seconds for a message to be confirmed in the worst
				// case).
				offset := message_index - len(profile.GetGroup(handle).Timeline.Messages)
				if len(profile.GetGroup(handle).UnacknowledgedMessages) > offset {
					message.Message = profile.GetGroup(handle).UnacknowledgedMessages[offset]
					message.ContactImage = ph.GetProfilePic(message.Message.PeerID)
				} else {
					log.Errorf("Couldn't find message in timeline or unacked messages, probably transient threading issue, but logging for visibility..")
				}
			}
		} else {
			// If we are safely within the limits of the timeline just grab the message at the index..
			if len(profile.GetContact(handle).Timeline.Messages) > message_index {
				message.Message = profile.GetContact(handle).Timeline.Messages[message_index]
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
	bytes, _ := json.Marshal(message)
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
		}
	} else {
		contactHandler, _ := contact.FunctionalityGate(utils.ReadGlobalSettings().Experiments)
		contactHandler.SendMessage(profile, handle, msg)
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
func CreateGroup(profile string, server string, name string) {
	peer := application.GetPeer(profile)
	_, err := groups.ExperimentGate(utils.ReadGlobalSettings().Experiments)
	if err == nil {
		gid, _, err := peer.StartGroup(server)
		if err == nil {
			log.Debugf("created group %v on %v: $v", profile, server, gid)
			// set the group name
			peer.SetGroupAttribute(gid, attr.GetLocalScope("name"), name)
		} else {
			log.Errorf("error creating group or %v on server %v: %v", profile, server, err)
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

//export c_LeaveConversation
func c_LeaveConversation(profile_ptr *C.char, profile_len C.int, contact_ptr *C.char, contact_len C.int) {
	profile := C.GoStringN(profile_ptr, profile_len)
	contact := C.GoStringN(contact_ptr, contact_len)
	LeaveConversation(profile, contact)
}

// LeaveConversation forces profile to leave the peer
func LeaveConversation(profile string, contact string) {
	peer := application.GetPeer(profile)
	peer.DeleteContact(contact)
}

//export c_LeaveGroup
func c_LeaveGroup(profile_ptr *C.char, profile_len C.int, group_ptr *C.char, group_len C.int) {
	profile := C.GoStringN(profile_ptr, profile_len)
	groupID := C.GoStringN(group_ptr, group_len)
	LeaveGroup(profile, groupID)
}

// LeaveGroup forces profile to leave the group groupID
func LeaveGroup(profile string, groupID string) {
	peer := application.GetPeer(profile)
	_, err := groups.ExperimentGate(utils.ReadGlobalSettings().Experiments)
	if err == nil {
		peer.DeleteGroup(groupID)
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

// Leave as is, needed by ffi
func main() {}
