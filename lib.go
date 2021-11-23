//package cwtch

package main

// //Needed to invoke C.free
// #include <stdlib.h>
import "C"

import (
	"crypto/rand"
	constants2 "cwtch.im/cwtch/model/constants"
	"encoding/json"
	"fmt"
	// Import SQL Cipher
	_ "github.com/mutecomm/go-sqlcipher/v4"
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
		event.FileDownloaded,
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
	groupHandler, _ := groups.ExperimentGate(settings.Experiments)
	for _, profileOnion := range peerList {
		// fix peerpeercontact message counts
		profile := application.GetPeer(profileOnion)
		conversations, _ := profile.FetchConversations()
		for _, conversation := range conversations {
			if (conversation.IsGroup() && groupHandler != nil) || conversation.IsServer() == false {
				totalMessages, _ := profile.GetChannelMessageCount(conversation.ID, 0)
				eventHandler.Push(event.NewEvent(event.MessageCounterResync, map[event.Field]string{
					event.Identity:       profileOnion,
					event.ConversationID: strconv.Itoa(conversation.ID),
					event.Data:           strconv.Itoa(totalMessages),
				}))
			}
		}

		// Group Experiment Server Refresh
		if groupHandler != nil {
			serverListForOnion := groupHandler.GetServerInfoList(profile)
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

//export c_AcceptConversation
func c_AcceptConversation(profilePtr *C.char, profileLen C.int, conversation_id C.int) {
	AcceptConversation(C.GoStringN(profilePtr, profileLen), int(conversation_id))
}

// AcceptConversation takes in a profileOnion and a handle to either a group or a peer and authorizes the handle
// for further action (e.g. messaging / connecting to the server / joining the group etc.)
func AcceptConversation(profileOnion string, conversation_id int) {
	profile := application.GetPeer(profileOnion)
	profile.AcceptConversation(int(conversation_id))
}

//export c_BlockContact
func c_BlockContact(profilePtr *C.char, profileLen C.int, conversation_id C.int) {
	BlockContact(C.GoStringN(profilePtr, profileLen), int(conversation_id))
}

func BlockContact(profileOnion string, conversationID int) {
	profile := application.GetPeer(profileOnion)
	profile.BlockConversation(conversationID)
}


//export c_GetMessage
// the pointer returned from this function **must** be Freed  by c_Free
func c_GetMessage(profile_ptr *C.char, profile_len C.int, conversation_id C.int, message_index C.int) *C.char {
	profile := C.GoStringN(profile_ptr, profile_len)
	return C.CString(GetMessage(profile, int(conversation_id), int(message_index)))
}

// EnhancedMessage wraps a Cwtch model.Message with some additional data to reduce calls from the UI.
type EnhancedMessage struct {
	model.Message
	ID           int // the actual ID of the message in the database (not the row number)
	ContactImage string
}

func GetMessage(profileOnion string, conversationID int, messageIndex int) string {
	var message EnhancedMessage
	// There is an edge case that can happen on Android when the app is shutdown while fetching messages...
	// The worker threads that are spawned can become activated again when the app is opened attempt to finish their job...
	// In that case we skip processing and just return the empty message...
	// Note: This is far less likely to happen now that the UI only requests messages *after* syncing has happened and
	// these requests complete almost immediately v.s. being stalled for seconds to minutes on large groups.
	if application != nil {
		profile := application.GetPeer(profileOnion)
		messages, err := profile.GetMostRecentMessages(conversationID, 0, messageIndex, 1)
		if err == nil && len(messages) == 1 {
			time, _ := time.Parse(time.RFC3339Nano, messages[0].Attr[constants2.AttrSentTimestamp])
			message.Message = model.Message{
				Message:      messages[0].Body,
				Acknowledged: messages[0].Attr[constants2.AttrAck] == constants2.True,
				Error:        messages[0].Attr[constants2.AttrErr],
				PeerID:       messages[0].Attr[constants2.AttrAuthor],
				Timestamp:    time,
			}
			message.ID = messages[0].ID
			message.ContactImage = utils.RandomProfileImage(message.PeerID)
		}
	}
	bytes, _ := json.Marshal(message)
	return string(bytes)
}

//export c_GetMessagesByContentHash
// the pointer returned from this function **must** be freed by calling c_Free
func c_GetMessagesByContentHash(profile_ptr *C.char, profile_len C.int, conversation_id C.int, contenthash_ptr *C.char, contenthash_len C.int) *C.char {
	profile := C.GoStringN(profile_ptr, profile_len)
	contentHash := C.GoStringN(contenthash_ptr, contenthash_len)
	return C.CString(GetMessagesByContentHash(profile, int(conversation_id), contentHash))
}

func GetMessagesByContentHash(profileOnion string, handle int, contentHash string) string {
	var indexedMessages []model.LocallyIndexedMessage
	if application != nil {
		profile := application.GetPeer(profileOnion)
		offset, err := profile.GetChannelMessageByContentHash(handle, 0, contentHash)
		if err == nil {
			messages, err := profile.GetMostRecentMessages(handle, 0, offset, 1)
			if err == nil {
					time, _ := time.Parse(time.RFC3339Nano, messages[0].Attr[constants2.AttrSentTimestamp])
					msg := model.Message{
						Message:      messages[0].Body,
						Acknowledged: messages[0].Attr[constants2.AttrAck] == constants2.True,
						Error:        messages[0].Attr[constants2.AttrErr],
						PeerID:       messages[0].Attr[constants2.AttrAuthor],
						Timestamp:    time,
					}
					indexedMessages = append(indexedMessages, model.LocallyIndexedMessage{LocalIndex: offset, Message: msg})
			} else {
				log.Errorf("error fetching local index {} ", err)
			}
		}
	}
	bytes, _ := json.Marshal(indexedMessages)
	return string(bytes)
}

//export c_FreePointer
// Dangerous function. Should only be used as documented in `MEMORY.md`
func c_FreePointer(ptr *C.char) {
	C.free(unsafe.Pointer(ptr))
}

//export c_SendMessage
func c_SendMessage(profile_ptr *C.char, profile_len C.int, conversation_id C.int, msg_ptr *C.char, msg_len C.int) {
	profile := C.GoStringN(profile_ptr, profile_len)
	msg := C.GoStringN(msg_ptr, msg_len)
	SendMessage(profile, int(conversation_id), msg)
}

func SendMessage(profileOnion string, conversationID int, msg string) {
	profile := application.GetPeer(profileOnion)
	profile.SendMessage(conversationID, msg)
}

//export c_SendInvitation
func c_SendInvitation(profile_ptr *C.char, profile_len C.int, conversation_id C.int, target_id C.int) {
	profile := C.GoStringN(profile_ptr, profile_len)
	SendInvitation(profile, int(conversation_id), int(target_id))
}

// SendInvitation sends an invitation from `profileOnion` to contact `handle` (peer or group)
// asking them to add the contact `target`  (also peer or group).
// For groups, the profile must already have `target` as a contact.
func SendInvitation(profileOnion string, conversationID int, targetID int) {
	profile := application.GetPeer(profileOnion)
	profile.SendInviteToConversation(conversationID, targetID)
}

//export c_ShareFile
func c_ShareFile(profile_ptr *C.char, profile_len C.int, conversation_id C.int, filepath_ptr *C.char, filepath_len C.int) {
	profile := C.GoStringN(profile_ptr, profile_len)
	sharefilepath := C.GoStringN(filepath_ptr, filepath_len)
	ShareFile(profile, int(conversation_id), sharefilepath)
}

func ShareFile(profileOnion string, conversationID int, sharefilepath string) {
	profile := application.GetPeer(profileOnion)
	fh, err := filesharing.FunctionalityGate(utils.ReadGlobalSettings().Experiments)
	if err != nil {
		log.Errorf("file sharing error: %v", err)
	} else {
		err = fh.ShareFile(sharefilepath, profile, conversationID)
		if err != nil {
			log.Errorf("error sharing file: %v", err)
		}
	}
}

//export c_DownloadFile
func c_DownloadFile(profile_ptr *C.char, profile_len C.int, conversation_id C.int, filepath_ptr *C.char, filepath_len C.int, manifestpath_ptr *C.char, manifestpath_len C.int, filekey_ptr *C.char, filekey_len C.int) {
	profile := C.GoStringN(profile_ptr, profile_len)
	downloadfilepath := C.GoStringN(filepath_ptr, filepath_len)
	manifestpath := C.GoStringN(manifestpath_ptr, manifestpath_len)
	filekey := C.GoStringN(filekey_ptr, filekey_len)
	DownloadFile(profile, int(conversation_id), downloadfilepath, manifestpath, filekey)
}

func DownloadFile(profileOnion string, conversationID int, filepath, manifestpath, filekey string) {
	profile := application.GetPeer(profileOnion)
	fh, err := filesharing.FunctionalityGate(utils.ReadGlobalSettings().Experiments)
	if err != nil {
		log.Errorf("file sharing error: %v", err)
	} else {
		fh.DownloadFile(profile, conversationID, filepath, manifestpath, filekey)
	}
}

//export c_CheckDownloadStatus
func c_CheckDownloadStatus(profilePtr *C.char, profileLen C.int, fileKeyPtr *C.char, fileKeyLen C.int) {
	CheckDownloadStatus(C.GoStringN(profilePtr, profileLen), C.GoStringN(fileKeyPtr, fileKeyLen))
}

func CheckDownloadStatus(profileOnion, fileKey string) {
	profile := application.GetPeer(profileOnion)
	path, _ := profile.GetScopedZonedAttribute(attr.LocalScope, attr.FilesharingZone, fmt.Sprintf("%s.path", fileKey))
	if _, exists := profile.GetScopedZonedAttribute(attr.LocalScope, attr.FilesharingZone, fmt.Sprintf("%s.complete", fileKey)); exists {
		eventHandler.Push(event.NewEvent(event.FileDownloaded, map[event.Field]string{
			ProfileOnion:   profileOnion,
			event.FileKey:  fileKey,
			event.FilePath: path,
			event.TempFile: "",
		}))
	} else {
		log.Infof("CheckDownloadStatus found .path but not .complete")
		eventHandler.Push(event.NewEvent(event.FileDownloadProgressUpdate, map[event.Field]string{
			ProfileOnion:           profileOnion,
			event.FileKey:          fileKey,
			event.Progress:         "-1",
			event.FileSizeInChunks: "-1",
			event.FilePath:         path,
		}))
	}
}

//export c_VerifyOrResumeDownload
func c_VerifyOrResumeDownload(profile_ptr *C.char, profile_len C.int, conversation_id C.int, filekey_ptr *C.char, filekey_len C.int) {
	profile := C.GoStringN(profile_ptr, profile_len)
	filekey := C.GoStringN(filekey_ptr, filekey_len)
	VerifyOrResumeDownload(profile, int(conversation_id), filekey)
}

func VerifyOrResumeDownload(profileOnion string, conversationID int, fileKey string) {
	profile := application.GetPeer(profileOnion)
	if manifestFilePath, exists := profile.GetScopedZonedAttribute(attr.LocalScope, attr.FilesharingZone, fmt.Sprintf("%v.manifest", fileKey)); exists {
		if downloadfilepath, exists := profile.GetScopedZonedAttribute(attr.LocalScope, attr.FilesharingZone, fmt.Sprintf("%s.path", fileKey)); exists {
			log.Infof("resuming %s", fileKey)
			DownloadFile(profileOnion, conversationID, downloadfilepath, manifestFilePath, fileKey)
		} else {
			log.Errorf("found manifest path but not download path for %s", fileKey)
		}
	} else {
		log.Errorf("no stored manifest path found for %s", fileKey)
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
		conversationID, err := profile.StartGroup(name, server)
		if err == nil {
			log.Debugf("created group %v on %v: $v", profileHandle, server, conversationID)
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
func c_ArchiveConversation(profile_ptr *C.char, profile_len C.int, conversation_id C.int) {
	profile := C.GoStringN(profile_ptr, profile_len)
	ArchiveConversation(profile, int(conversation_id))
}

// ArchiveConversation sets the conversation to archived
func ArchiveConversation(profileHandle string, conversationID int) {
	profile := application.GetPeer(profileHandle)
	profile.SetConversationAttribute(conversationID, attr.LocalScope.ConstructScopedZonedPath(attr.ProfileZone.ConstructZonedPath(constants.Archived)), constants2.True)
}

//export c_DeleteContact
func c_DeleteContact(profile_ptr *C.char, profile_len C.int, conversation_id C.int) {
	profile := C.GoStringN(profile_ptr, profile_len)
	DeleteContact(profile, int(conversation_id))
}

// DeleteContact removes all trace of the contact from the profile
func DeleteContact(profileHandle string, conversationID int) {
	profile := application.GetPeer(profileHandle)
	profile.DeleteConversation(conversationID)
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
	response := profile.ImportBundle(bundle)

	// We might have added a new server, so refresh the server list if applicable...
	groupHandler, err := groups.ExperimentGate(utils.ReadGlobalSettings().Experiments)
	if err == nil {
		serverListForOnion := groupHandler.GetServerInfoList(profile)
		serversListBytes, _ := json.Marshal(serverListForOnion)
		eventHandler.Push(event.NewEvent(groups.UpdateServerInfo, map[event.Field]string{"ProfileOnion": profileOnion, groups.ServerList: string(serversListBytes)}))
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

//export c_SetConversationAttribute
func c_SetConversationAttribute(profile_ptr *C.char, profile_len C.int, conversation_id C.int, key_ptr *C.char, key_len C.int, val_ptr *C.char, val_len C.int) {
	profileOnion := C.GoStringN(profile_ptr, profile_len)
	key := C.GoStringN(key_ptr, key_len)
	value := C.GoStringN(val_ptr, val_len)
	SetConversationAttribute(profileOnion, int(conversation_id), key, value)
}

// SetConversationAttribute provides a wrapper around profile.SetProfileAttribute
func SetConversationAttribute(profileOnion string, conversationID int, key string, value string) {
	profile := application.GetPeer(profileOnion)
	zone, key := attr.ParseZone(key)
	profile.SetConversationAttribute(conversationID, attr.LocalScope.ConstructScopedZonedPath(zone.ConstructZonedPath(key)), value)
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
				if serverInfo.Autostart {
					LaunchServer(serverOnion)
				}
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
			if autostart {
				LaunchServer(s.Onion())
			}
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

		err := serversHandler.DeleteServer(onion, currentPassword)
		if err == nil {
			application.GetPrimaryBus().Publish(event.NewEventList(servers.ServerDeleted, event.Status, constants.StatusSuccess, event.Identity, onion))
		} else {
			application.GetPrimaryBus().Publish(event.NewEventList(servers.ServerDeleted, event.Status, constants.StatusError, event.Error, err.Error(), event.Identity, onion))
		}
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
