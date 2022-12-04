package utils

import (
	"encoding/json"
	"fmt"
	"git.openprivacy.ca/cwtch.im/libcwtch-go/features/servers"
	"os"
	"strconv"

	"cwtch.im/cwtch/app"
	"cwtch.im/cwtch/app/plugins"
	"cwtch.im/cwtch/model"
	"cwtch.im/cwtch/model/attr"
	"cwtch.im/cwtch/model/constants"
	"cwtch.im/cwtch/peer"
	"cwtch.im/cwtch/protocol/connections"
	constants2 "git.openprivacy.ca/cwtch.im/libcwtch-go/constants"
	"git.openprivacy.ca/cwtch.im/libcwtch-go/features/groups"
	"git.openprivacy.ca/openprivacy/log"

	"time"

	"cwtch.im/cwtch/event"
	"cwtch.im/cwtch/functionality/filesharing"
)

type EventProfileEnvelope struct {
	Event   event.Event
	Profile string
}

type LCG_API_Handler struct {
	LaunchServers func()
	StopServers   func()
}

type EventHandler struct {
	app           app.Application
	appBusQueue   event.Queue
	profileEvents chan EventProfileEnvelope
	api           LCG_API_Handler
}

// We should be reading from profile events pretty quickly, but we make this buffer fairly large...
const profileEventsBufferSize = 512

func NewEventHandler(api LCG_API_Handler) *EventHandler {
	eh := &EventHandler{app: nil, appBusQueue: event.NewQueue(), profileEvents: make(chan EventProfileEnvelope, profileEventsBufferSize), api: api}
	return eh
}

func (eh *EventHandler) HandleApp(application app.Application) {
	eh.app = application
	application.GetPrimaryBus().Subscribe(event.NewPeer, eh.appBusQueue)
	application.GetPrimaryBus().Subscribe(event.PeerError, eh.appBusQueue)
	application.GetPrimaryBus().Subscribe(event.PeerDeleted, eh.appBusQueue)
	application.GetPrimaryBus().Subscribe(event.Shutdown, eh.appBusQueue)
	application.GetPrimaryBus().Subscribe(event.AppError, eh.appBusQueue)
	application.GetPrimaryBus().Subscribe(event.ACNStatus, eh.appBusQueue)
	application.GetPrimaryBus().Subscribe(event.ACNVersion, eh.appBusQueue)
	application.GetPrimaryBus().Subscribe(UpdateGlobalSettings, eh.appBusQueue)
	application.GetPrimaryBus().Subscribe(CwtchStarted, eh.appBusQueue)
	application.GetPrimaryBus().Subscribe(servers.NewServer, eh.appBusQueue)
	application.GetPrimaryBus().Subscribe(servers.ServerIntentUpdate, eh.appBusQueue)
	application.GetPrimaryBus().Subscribe(servers.ServerDeleted, eh.appBusQueue)
	application.GetPrimaryBus().Subscribe(servers.ServerStatsUpdate, eh.appBusQueue)
	application.GetPrimaryBus().Subscribe(event.StartingStorageMiragtion, eh.appBusQueue)
	application.GetPrimaryBus().Subscribe(event.DoneStorageMigration, eh.appBusQueue)
}

func (eh *EventHandler) GetNextEvent() string {
	appChan := eh.appBusQueue.OutChan()

	select {
	case e := <-appChan:
		return eh.handleAppBusEvent(&e)
	default:
		select {
		case e := <-appChan:
			return eh.handleAppBusEvent(&e)
		case ev := <-eh.profileEvents:
			return eh.handleProfileEvent(&ev)
		}
	}
}

// track acnStatus across events
var acnStatus = -1

// handleAppBusEvent enriches AppBus events so they are usable with out further data fetches
func (eh *EventHandler) handleAppBusEvent(e *event.Event) string {

	if eh.app != nil {
		switch e.EventType {
		case event.ACNStatus:
			newAcnStatus, err := strconv.Atoi(e.Data[event.Progress])
			if err != nil {
				break
			}
			if newAcnStatus == 100 {
				if acnStatus != 100 {
					// just came online
					doServers := false
					if _, err := groups.ExperimentGate(ReadGlobalSettings().Experiments); err == nil {
						doServers = true
					}
					eh.app.ActivateEngines(true, true, doServers)
					eh.api.LaunchServers()
				}
			} else {
				if acnStatus == 100 {
					// just fell offline
					for _, onion := range eh.app.ListProfiles() {
						eh.app.DeactivatePeerEngine(onion)
					}
					eh.api.StopServers()
				}
			}
			acnStatus = newAcnStatus

		case event.NewPeer:
			onion := e.Data[event.Identity]
			profile := eh.app.GetPeer(e.Data[event.Identity])
			if profile == nil {
				log.Errorf("NewPeer: skipping profile initialization. this should only happen when the app is rapidly opened+closed (eg during testing)")
				break
			}
			log.Debug("New Peer Event: %v", e)

			if e.Data["Reload"] != event.True {
				eh.startHandlingPeer(onion)
			}

			// CwtchPeer will always set this now...
			tag, _ := profile.GetScopedZonedAttribute(attr.LocalScope, attr.ProfileZone, constants.Tag)
			e.Data[constants.Tag] = tag

			if e.Data[event.Created] == event.True {
				profile.SetScopedZonedAttribute(attr.PublicScope, attr.ProfileZone, constants2.Picture, ImageToString(NewImage(RandomProfileImage(onion), TypeImageDistro)))
			}

			profile.SetScopedZonedAttribute(attr.LocalScope, attr.ProfileZone, constants2.PeerOnline, event.False)
			// disabeling network check for connection attempt reservation, needs rework
			//eh.app.AddPeerPlugin(onion, plugins.NETWORKCHECK)
			eh.app.AddPeerPlugin(onion, plugins.ANTISPAM)

			// If the user has chosen to block unknown profiles
			// then explicitly configure the protocol engine to do so..
			settings := ReadGlobalSettings()
			if settings.BlockUnknownConnections {
				profile.BlockUnknownConnections()
			} else {
				// For completeness
				profile.AllowUnknownConnections()
			}

			// Start up the Profile
			if acnStatus == 100 {
				doServers := false
				if _, err := groups.ExperimentGate(ReadGlobalSettings().Experiments); err == nil {
					doServers = true
				}
				eh.app.ActivatePeerEngine(onion, true, true, doServers)
			}

			online, _ := profile.GetScopedZonedAttribute(attr.LocalScope, attr.ProfileZone, constants2.PeerOnline)
			// Name always exists
			e.Data[constants.Name], _ = profile.GetScopedZonedAttribute(attr.PublicScope, attr.ProfileZone, constants.Name)
			e.Data[constants2.DefaultProfilePicture] = RandomProfileImage(onion)
			// if a custom profile image exists then default to it.
			key, exists := profile.GetScopedZonedAttribute(attr.PublicScope, attr.ProfileZone, constants.CustomProfileImageKey)
			if !exists {
				e.Data[constants2.Picture] = RandomProfileImage(onion)
			} else {
				e.Data[constants2.Picture], _ = profile.GetScopedZonedAttribute(attr.LocalScope, attr.FilesharingZone, fmt.Sprintf("%s.path", key))
				serializedManifest, _ := profile.GetScopedZonedAttribute(attr.ConversationScope, attr.FilesharingZone, fmt.Sprintf("%s.manifest", key))
				profile.ShareFile(key, serializedManifest)
				log.Debugf("Custom Profile Image: %v %s", e.Data[constants2.Picture], serializedManifest)
			}

			// Resolve the profile image of the profile.

			e.Data["Online"] = online

			// If file sharing is enabled then reshare all active files...
			fsf, err := filesharing.FunctionalityGate(settings.Experiments)
			if err == nil {
				fsf.ReShareFiles(profile)
			}

			// Construct our conversations and our srever lists
			var contacts []Contact
			var servers []groups.Server

			conversations, err := profile.FetchConversations()

			if err == nil {
				// We have conversations attached to this profile...
				for _, conversationInfo := range conversations {
					// Only compile the server info if we have enabled the experiment...
					// Note that this means that this info can become stale if when first loaded the experiment
					// has been disabled and then is later re-enabled. As such we need to ensure that this list is
					// re-fetched when the group experiment is enabled via a dedicated ListServerInfo event...
					if conversationInfo.IsServer() {
						groupHandler, err := groups.ExperimentGate(ReadGlobalSettings().Experiments)
						if err == nil {
							servers = append(servers, groupHandler.GetServerInfo(conversationInfo.Handle, profile))
						}
						continue
					}

					// Prefer local override to public name...
					name, exists := conversationInfo.GetAttribute(attr.LocalScope, attr.ProfileZone, constants.Name)
					if !exists {
						name, exists = conversationInfo.GetAttribute(attr.PublicScope, attr.ProfileZone, constants.Name)
						if !exists {
							name = conversationInfo.Handle
						}
					}

					// Resolve the profile image of the contact
					var cpicPath string
					var defaultPath string
					if conversationInfo.IsGroup() {
						cpicPath = RandomGroupImage(conversationInfo.Handle)
						defaultPath = RandomGroupImage(conversationInfo.Handle)
					} else {
						cpicPath = GetProfileImage(profile, conversationInfo, settings.DownloadPath)
						defaultPath = RandomProfileImage(conversationInfo.Handle)
					}

					// Resolve Save History Setting
					saveHistory, set := conversationInfo.GetAttribute(attr.LocalScope, attr.ProfileZone, event.SaveHistoryKey)
					if !set {
						saveHistory = event.DeleteHistoryDefault
					}

					// Resolve Archived Setting
					isArchived, set := conversationInfo.GetAttribute(attr.LocalScope, attr.ProfileZone, constants2.Archived)
					if !set {
						isArchived = event.False
					}

					unread := 0
					lastSeenMessageId := -1
					lastSeenTimeStr, set := conversationInfo.GetAttribute(attr.LocalScope, attr.ProfileZone, constants2.LastSeenTime)
					if set {
						lastSeenTime, err := time.Parse(constants2.DartIso8601, lastSeenTimeStr)
						if err == nil {
							// get last 100 messages and count how many are after the lastSeenTime (100 cus hte ui just shows 99+ after)
							messages, err := profile.GetMostRecentMessages(conversationInfo.ID, 0, 0, 100)
							if err == nil {
								for _, message := range messages {
									msgTime, err := time.Parse(time.RFC3339Nano, message.Attr[constants.AttrSentTimestamp])
									if err == nil {
										if msgTime.UTC().After(lastSeenTime.UTC()) {
											unread++
										} else {
											lastSeenMessageId = message.ID
											break
										}
									}
								}
							}
						}
					}

					groupServer, _ := conversationInfo.GetAttribute(attr.LocalScope, attr.LegacyGroupZone, constants.GroupServer)

					stateHandle := conversationInfo.Handle
					if conversationInfo.IsGroup() {
						stateHandle = groupServer
					}
					state := profile.GetPeerState(stateHandle)
					if !set {
						state = connections.DISCONNECTED
					}

					blocked := false
					if conversationInfo.ACL[conversationInfo.Handle].Blocked {
						blocked = true
					}

					// Fetch the message count, and the time of the most recent message
					count, err := profile.GetChannelMessageCount(conversationInfo.ID, 0)
					if err != nil {
						log.Errorf("error fetching channel message count %v %v", conversationInfo.ID, err)
					}

					lastMessage, _ := profile.GetMostRecentMessages(conversationInfo.ID, 0, 0, 1)

					notificationPolicy := constants2.ConversationNotificationPolicyDefault
					if notificationPolicyAttr, exists := conversationInfo.GetAttribute(attr.LocalScope, attr.ProfileZone, constants2.ConversationNotificationPolicy); exists {
						notificationPolicy = notificationPolicyAttr
					}

					contacts = append(contacts, Contact{
						Name:               name,
						Identifier:         conversationInfo.ID,
						Onion:              conversationInfo.Handle,
						Status:             connections.ConnectionStateName[state],
						Picture:            cpicPath,
						DefaultPicture:     defaultPath,
						Accepted:           conversationInfo.Accepted,
						AccessControlList:  conversationInfo.ACL,
						Blocked:            blocked,
						SaveHistory:        saveHistory,
						Messages:           count,
						Unread:             unread,
						LastSeenMessageId:  lastSeenMessageId,
						LastMessage:        strconv.Itoa(getLastMessageTime(lastMessage)),
						IsGroup:            conversationInfo.IsGroup(),
						GroupServer:        groupServer,
						IsArchived:         isArchived == event.True,
						NotificationPolicy: notificationPolicy,
						Attributes:         conversationInfo.Attributes,
					})
				}
			}

			bytes, _ := json.Marshal(contacts)
			e.Data["ContactsJson"] = string(bytes)

			// Marshal the server list into the new peer event...
			serversListBytes, _ := json.Marshal(servers)
			e.Data[groups.ServerList] = string(serversListBytes)

			log.Debugf("contactsJson %v", e.Data["ContactsJson"])
		}
	}

	json, _ := json.Marshal(e)
	return string(json)
}

func GetProfileImage(profile peer.CwtchPeer, conversationInfo *model.Conversation, basepath string) string {
	fileKey, err := profile.GetConversationAttribute(conversationInfo.ID, attr.PublicScope.ConstructScopedZonedPath(attr.ProfileZone.ConstructZonedPath(constants.CustomProfileImageKey)))
	if err == nil {
		if value, exists := profile.GetScopedZonedAttribute(attr.LocalScope, attr.FilesharingZone, fmt.Sprintf("%s.complete", fileKey)); exists && value == event.True {
			fp, _ := filesharing.GenerateDownloadPath(basepath, fileKey, true)
			// check if the file exists...if it does then set the path...
			if _, err := os.Stat(fp); err == nil {
				image, _ := profile.GetScopedZonedAttribute(attr.LocalScope, attr.FilesharingZone, fmt.Sprintf("%s.path", fileKey))
				return image
			}
		}
	}
	return RandomProfileImage(conversationInfo.Handle)
}

// handleProfileEvent enriches Profile events so they are usable with out further data fetches
func (eh *EventHandler) handleProfileEvent(ev *EventProfileEnvelope) string {
	// cache of contact states to use to filter out events repeating known states
	var contactStateCache = make(map[string]connections.ConnectionState)

	if eh.app == nil {
		log.Errorf("eh.app == nil in handleProfileEvent... this shouldnt happen?")
	} else {
		profile := eh.app.GetPeer(ev.Profile)
		log.Debugf("New Profile Event to Handle: %v", ev)
		switch ev.Event.EventType {
		case event.NewMessageFromPeer: //event.TimestampReceived, event.RemotePeer, event.Data
			// only needs contact nickname and picture, for displaying on popup notifications
			ci, err := profile.FetchConversationInfo(ev.Event.Data["RemotePeer"])
			ev.Event.Data[constants2.Picture] = RandomProfileImage(ev.Event.Data["RemotePeer"])
			if ci != nil && err == nil {
				ev.Event.Data[event.ConversationID] = strconv.Itoa(ci.ID)
				profile.SetConversationAttribute(ci.ID, attr.LocalScope.ConstructScopedZonedPath(attr.ProfileZone.ConstructZonedPath(constants2.Archived)), event.False)
				ev.Event.Data[constants2.Picture] = GetProfileImage(profile, ci, ReadGlobalSettings().DownloadPath)
			} else {
				// TODO This Conversation May Not Exist Yet...But we are not in charge of creating it...
				log.Errorf("todo wait for contact to be added before processing this event...")
				return ""
			}
			var exists bool
			ev.Event.Data["Nick"], exists = ci.GetAttribute(attr.LocalScope, attr.ProfileZone, constants.Name)
			if !exists {
				ev.Event.Data["Nick"], exists = ci.GetAttribute(attr.PublicScope, attr.ProfileZone, constants.Name)
				if !exists {
					ev.Event.Data["Nick"] = ev.Event.Data["RemotePeer"]
					// If we dont have a name val for a peer, but they have sent us a message, we might be approved now, re-ask
					profile.SendScopedZonedGetValToContact(ci.ID, attr.PublicScope, attr.ProfileZone, constants.Name)
					profile.SendScopedZonedGetValToContact(ci.ID, attr.PublicScope, attr.ProfileZone, constants.CustomProfileImageKey)
				}
			}

			if ci.Accepted {
				handleImagePreviews(profile, &ev.Event, ci.ID, ci.ID)
			}

			ev.Event.Data["notification"] = string(determineNotification(ci))
		case event.NewMessageFromGroup:
			// only needs contact nickname and picture, for displaying on popup notifications
			ci, err := profile.FetchConversationInfo(ev.Event.Data["RemotePeer"])
			ev.Event.Data[constants2.Picture] = RandomProfileImage(ev.Event.Data["RemotePeer"])
			if ci != nil && err == nil {
				var exists bool
				ev.Event.Data["Nick"], exists = ci.GetAttribute(attr.LocalScope, attr.ProfileZone, constants.Name)
				if !exists {
					ev.Event.Data["Nick"], exists = ci.GetAttribute(attr.PublicScope, attr.ProfileZone, constants.Name)
					if !exists {
						ev.Event.Data["Nick"] = ev.Event.Data["RemotePeer"]
					}
				}
				ev.Event.Data[constants2.Picture] = GetProfileImage(profile, ci, ReadGlobalSettings().DownloadPath)
			}

			conversationID, _ := strconv.Atoi(ev.Event.Data[event.ConversationID])
			profile.SetConversationAttribute(conversationID, attr.LocalScope.ConstructScopedZonedPath(attr.ProfileZone.ConstructZonedPath(constants2.Archived)), event.False)

			if ci != nil && ci.Accepted {
				handleImagePreviews(profile, &ev.Event, conversationID, ci.ID)
			}

			gci, _ := profile.GetConversationInfo(conversationID)
			groupServer := gci.Attributes[attr.LocalScope.ConstructScopedZonedPath(attr.LegacyGroupZone.ConstructZonedPath(constants.GroupServer)).ToString()]
			state := profile.GetPeerState(groupServer)
			// if syncing, don't flood with notifications
			if state == connections.SYNCED {
				ev.Event.Data["notification"] = string(determineNotification(gci))
			} else {
				ev.Event.Data["notification"] = string(constants2.NotificationNone)
			}
		case event.PeerAcknowledgement:
			ci, err := profile.FetchConversationInfo(ev.Event.Data["RemotePeer"])
			if ci != nil && err == nil {
				ev.Event.Data[event.ConversationID] = strconv.Itoa(ci.ID)
			}
		case event.ContactCreated:
			conversationID, _ := strconv.Atoi(ev.Event.Data[event.ConversationID])
			count, err := profile.GetChannelMessageCount(conversationID, 0)
			if err != nil {
				log.Errorf("error fetching channel message count %v %v", conversationID, err)
			}

			conversationInfo, err := profile.GetConversationInfo(conversationID)
			if err != nil {
				log.Errorf("error fetching conversation info for %v %v", conversationID, err)
			}

			blocked := constants.False
			if conversationInfo.ACL[conversationInfo.Handle].Blocked {
				blocked = constants.True
			}

			accepted := constants.False
			if conversationInfo.Accepted {
				accepted = constants.True
			}

			acl, _ := json.Marshal(conversationInfo.ACL)

			lastMessage, _ := profile.GetMostRecentMessages(conversationID, 0, 0, 1)
			ev.Event.Data["unread"] = strconv.Itoa(count) // if this is a new contact with messages attached then by-definition these are unread...
			ev.Event.Data[constants2.Picture] = RandomProfileImage(conversationInfo.Handle)
			ev.Event.Data[constants2.DefaultProfilePicture] = RandomProfileImage(conversationInfo.Handle)
			ev.Event.Data["numMessages"] = strconv.Itoa(count)
			ev.Event.Data["nick"] = conversationInfo.Handle
			ev.Event.Data["status"] = connections.ConnectionStateName[profile.GetPeerState(conversationInfo.Handle)]
			ev.Event.Data["accepted"] = accepted
			ev.Event.Data["accessControlList"] = string(acl)
			ev.Event.Data["blocked"] = blocked
			ev.Event.Data["loading"] = "false"
			ev.Event.Data["lastMsgTime"] = strconv.Itoa(getLastMessageTime(lastMessage))
		case event.GroupCreated:
			// This event should only happen after we have validated the invite, as such the error
			// condition *should* never happen.
			groupPic := RandomGroupImage(ev.Event.Data[event.GroupID])
			ev.Event.Data[constants2.Picture] = groupPic

			conversationID, _ := strconv.Atoi(ev.Event.Data[event.ConversationID])
			conversationInfo, _ := profile.GetConversationInfo(conversationID)
			acl, _ := json.Marshal(conversationInfo.ACL)
			ev.Event.Data["accessControlList"] = string(acl)
		case event.NewGroup:
			// This event should only happen after we have validated the invite, as such the error
			// condition *should* never happen.
			serializedInvite := ev.Event.Data[event.GroupInvite]
			if invite, err := model.ValidateInvite(serializedInvite); err == nil {
				groupPic := RandomGroupImage(invite.GroupID)
				ev.Event.Data[constants2.Picture] = groupPic

				conversationID, _ := strconv.Atoi(ev.Event.Data[event.ConversationID])
				conversationInfo, _ := profile.GetConversationInfo(conversationID)
				acl, _ := json.Marshal(conversationInfo.ACL)
				ev.Event.Data["accessControlList"] = string(acl)
			} else {
				log.Errorf("received a new group event which contained an invalid invite %v. this should never happen and likely means there is a bug in cwtch. Please file a ticket @ https://git.openprivacy.ca/cwtch.im/cwtch", err)
				return ""
			}
		case event.PeerStateChange:
			cxnState := connections.ConnectionStateToType()[ev.Event.Data[event.ConnectionState]]

			// skip events the UI doesn't act on
			if cxnState == connections.CONNECTING || cxnState == connections.CONNECTED {
				return ""
			}

			contact, err := profile.FetchConversationInfo(ev.Event.Data[event.RemotePeer])

			if ev.Event.Data[event.RemotePeer] == profile.GetOnion() {
				return "" // suppress events from our own profile...
			}

			// We do not know who this is...don't send any event until we see a message from them
			// (at that point the conversation will have been created...)
			if contact == nil || err != nil || contact.ID == 0 {
				return ""
			}

			// if we already know this state, suppress
			if knownState, exists := contactStateCache[ev.Event.Data[event.RemotePeer]]; exists && cxnState == knownState {
				return ""
			}
			contactStateCache[ev.Event.Data[event.RemotePeer]] = cxnState

			if contact != nil {
				// No enrichment needed
				if cxnState == connections.AUTHENTICATED {
					// if known and authed, get vars
					profile.SendScopedZonedGetValToContact(contact.ID, attr.PublicScope, attr.ProfileZone, constants.Name)
					profile.SendScopedZonedGetValToContact(contact.ID, attr.PublicScope, attr.ProfileZone, constants.CustomProfileImageKey)
				}
			}
		case event.ServerStateChange:
			cxnState := connections.ConnectionStateToType()[ev.Event.Data[event.ConnectionState]]

			// skip events the UI doesn't act on
			if cxnState == connections.CONNECTING || cxnState == connections.CONNECTED {
				return ""
			}

			// if we already know this state, suppress
			if knownState, exists := contactStateCache[ev.Event.Data[event.RemotePeer]]; exists && cxnState == knownState {
				return ""
			}
			contactStateCache[ev.Event.Data[event.RemotePeer]] = cxnState

		case event.NewRetValMessageFromPeer:
			// auto handled event means the setting is already done, we're just deciding if we need to tell the UI
			onion := ev.Event.Data[event.RemotePeer]
			scope := ev.Event.Data[event.Scope]
			path := ev.Event.Data[event.Path]
			val := ev.Event.Data[event.Data]
			exists, _ := strconv.ParseBool(ev.Event.Data[event.Exists])

			conversation, err := profile.FetchConversationInfo(onion)
			if err == nil {

				if exists && attr.IntoScope(scope) == attr.PublicScope {
					zone, path := attr.ParseZone(path)

					// auto download profile images from contacts...
					settings := ReadGlobalSettings()
					if settings.ExperimentsEnabled && zone == attr.ProfileZone && path == constants.CustomProfileImageKey {
						fileKey := val
						fsf, err := filesharing.FunctionalityGate(settings.Experiments)
						imagePreviewsEnabled := settings.Experiments["filesharing-images"]
						if err == nil && imagePreviewsEnabled && conversation.Accepted {

							basepath := settings.DownloadPath
							fp, mp := filesharing.GenerateDownloadPath(basepath, fileKey, true)

							if value, exists := profile.GetScopedZonedAttribute(attr.LocalScope, attr.FilesharingZone, fmt.Sprintf("%s.complete", fileKey)); exists && value == event.True {
								if _, err := os.Stat(fp); err == nil {
									// file is marked as completed downloaded and exists...
									return ""
								} else {
									// the user probably deleted the file, mark completed as false...
									profile.SetScopedZonedAttribute(attr.LocalScope, attr.FilesharingZone, fmt.Sprintf("%s.complete", fileKey), event.False)
								}
							}

							log.Debugf("Downloading Profile Image %v %v %v", fp, mp, fileKey)
							ev.Event.Data[event.FilePath] = fp
							fsf.DownloadFile(profile, conversation.ID, fp, mp, val, constants.ImagePreviewMaxSizeInBytes)
						} else {
							// if image previews are disabled then ignore this event...
							return ""
						}
					}
					if val, err := profile.GetConversationAttribute(conversation.ID, attr.LocalScope.ConstructScopedZonedPath(zone.ConstructZonedPath(path))); err == nil || val != "" {
						// we have a locally set override, don't pass this remote set public scope update to UI
						return ""
					}
				}
			}
		case event.TokenManagerInfo:
			conversations, err := profile.FetchConversations()
			if err == nil {
				var associatedGroups []int
				for _, ci := range conversations {
					groupServer, groupServerExists := ci.Attributes[attr.LocalScope.ConstructScopedZonedPath(attr.LegacyGroupZone.ConstructZonedPath(constants.GroupServer)).ToString()]
					if groupServerExists {
						gci, err := profile.FetchConversationInfo(groupServer)
						if err == nil {
							tokenOnion, onionExists := gci.Attributes[attr.PublicScope.ConstructScopedZonedPath(attr.ServerKeyZone.ConstructZonedPath(string(model.KeyTypeTokenOnion))).ToString()]
							if onionExists && tokenOnion == ev.Event.Data[event.ServerTokenOnion] {
								associatedGroups = append(associatedGroups, ci.ID)
							}
						}
					}
				}
				associatedGroupsJson, _ := json.Marshal(associatedGroups)
				ev.Event.Data[event.Data] = string(associatedGroupsJson)
			}
		}
	}

	json, _ := json.Marshal(unwrap(ev))
	return string(json)
}

func unwrap(original *EventProfileEnvelope) *event.Event {
	unwrapped := &original.Event
	unwrapped.Data["ProfileOnion"] = original.Profile
	return unwrapped
}

func (eh *EventHandler) startHandlingPeer(onion string) {
	eventBus := eh.app.GetEventBus(onion)
	q := event.NewQueue()

	eventBus.Subscribe(event.NetworkStatus, q)
	eventBus.Subscribe(event.ACNInfo, q)
	eventBus.Subscribe(event.NewMessageFromPeer, q)
	eventBus.Subscribe(event.UpdatedProfileAttribute, q)
	eventBus.Subscribe(event.PeerAcknowledgement, q)
	eventBus.Subscribe(event.DeleteContact, q)
	eventBus.Subscribe(event.AppError, q)
	eventBus.Subscribe(event.IndexedAcknowledgement, q)
	eventBus.Subscribe(event.IndexedFailure, q)
	eventBus.Subscribe(event.ContactCreated, q)
	eventBus.Subscribe(event.NewMessageFromGroup, q)
	eventBus.Subscribe(event.GroupCreated, q)
	eventBus.Subscribe(event.NewGroup, q)
	eventBus.Subscribe(event.ServerStateChange, q)
	eventBus.Subscribe(event.PeerStateChange, q)
	eventBus.Subscribe(event.NewRetValMessageFromPeer, q)
	eventBus.Subscribe(event.ShareManifest, q)
	eventBus.Subscribe(event.ManifestSizeReceived, q)
	eventBus.Subscribe(event.ManifestError, q)
	eventBus.Subscribe(event.ManifestReceived, q)
	eventBus.Subscribe(event.ManifestSaved, q)
	eventBus.Subscribe(event.FileDownloadProgressUpdate, q)
	eventBus.Subscribe(event.FileDownloaded, q)
	eventBus.Subscribe(event.TokenManagerInfo, q)

	go eh.forwardProfileMessages(onion, q)

}

func (eh *EventHandler) forwardProfileMessages(onion string, q event.Queue) {
	log.Infof("Launching Forwarding Goroutine")
	// TODO: graceful shutdown, via an injected event of special QUIT type exiting loop/go routine
	for {
		e := q.Next()
		ev := EventProfileEnvelope{Event: e, Profile: onion}
		eh.profileEvents <- ev
		if ev.Event.EventType == event.Shutdown {
			return
		}
	}
}

// Push pushes an event onto the app event bus
//
//	It is also a way for libCwtch-go to publish an event for consumption by a UI before a Cwtch app has been initialized
//	  use: to signal an error before a cwtch app could be created
func (eh *EventHandler) Push(newEvent event.Event) {
	eh.appBusQueue.Publish(newEvent)
}

func getLastMessageTime(conversationMessages []model.ConversationMessage) int {
	if len(conversationMessages) == 0 {
		return 0
	}
	time, err := time.Parse(time.RFC3339Nano, conversationMessages[0].Attr[constants.AttrSentTimestamp])
	if err != nil {
		return 0
	}
	return int(time.Unix())
}

// handleImagePreviews checks settings and, if appropriate, auto-downloads any images
func handleImagePreviews(profile peer.CwtchPeer, ev *event.Event, conversationID, senderID int) {
	settings := ReadGlobalSettings()
	fh, err := filesharing.PreviewFunctionalityGate(settings.Experiments)

	// Short-circuit if file sharing is disabled
	if err != nil {
		return
	}

	// Short-circuit failures
	// Don't autodownload images if the download path does not exist.
	if settings.DownloadPath == "" {
		return
	}

	// Don't autodownload images if the download path does not exist.
	if _, err := os.Stat(settings.DownloadPath); os.IsNotExist(err) {
		return
	}

	// Now look at the image preview experiment
	imagePreviewsEnabled := settings.Experiments["filesharing-images"]
	if imagePreviewsEnabled {
		var cm model.MessageWrapper
		err := json.Unmarshal([]byte(ev.Data[event.Data]), &cm)
		if err == nil && cm.Overlay == model.OverlayFileSharing {
			var fm filesharing.OverlayMessage
			err = json.Unmarshal([]byte(cm.Data), &fm)
			if err == nil {
				if fm.ShouldAutoDL() {
					basepath := settings.DownloadPath
					fp, mp := filesharing.GenerateDownloadPath(basepath, fm.Name, false)
					log.Debugf("autodownloading file!")
					ev.Data["Auto"] = constants.True
					mID, _ := strconv.Atoi(ev.Data["Index"])
					profile.UpdateMessageAttribute(conversationID, 0, mID, constants.AttrDownloaded, constants.True)
					fh.DownloadFile(profile, senderID, fp, mp, fm.FileKey(), constants.ImagePreviewMaxSizeInBytes)
				}
			}
		}
	}
}
