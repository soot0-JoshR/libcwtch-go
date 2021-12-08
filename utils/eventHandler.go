package utils

import (
	"cwtch.im/cwtch/app"
	"cwtch.im/cwtch/app/plugins"
	"cwtch.im/cwtch/model"
	"cwtch.im/cwtch/model/attr"
	"cwtch.im/cwtch/model/constants"
	"cwtch.im/cwtch/protocol/connections"
	"encoding/json"
	constants2 "git.openprivacy.ca/cwtch.im/libcwtch-go/constants"
	"git.openprivacy.ca/cwtch.im/libcwtch-go/features/groups"
	"git.openprivacy.ca/cwtch.im/libcwtch-go/features/servers"
	"git.openprivacy.ca/openprivacy/log"
	"strconv"
	"time"
)
import "cwtch.im/cwtch/event"

type EventProfileEnvelope struct {
	Event   event.Event
	Profile string
}

type EventHandler struct {
	app           app.Application
	appBusQueue   event.Queue
	profileEvents chan EventProfileEnvelope
}

func NewEventHandler() *EventHandler {
	eh := &EventHandler{app: nil, appBusQueue: event.NewQueue(), profileEvents: make(chan EventProfileEnvelope)}
	return eh
}

// PublishAppEvent is a way for libCwtch-go to publish an event for consumption by a UI before a Cwtch app has been initialized
//   Main use: to signal an error before a cwtch app could be created
func (eh *EventHandler) PublishAppEvent(event event.Event) {
	eh.appBusQueue.Publish(event)
}

func (eh *EventHandler) HandleApp(application app.Application) {
	eh.app = application
	application.GetPrimaryBus().Subscribe(event.NewPeer, eh.appBusQueue)
	application.GetPrimaryBus().Subscribe(event.PeerError, eh.appBusQueue)
	application.GetPrimaryBus().Subscribe(event.PeerDeleted, eh.appBusQueue)
	application.GetPrimaryBus().Subscribe(event.Shutdown, eh.appBusQueue)
	application.GetPrimaryBus().Subscribe(event.AppError, eh.appBusQueue)
	application.GetPrimaryBus().Subscribe(event.ACNStatus, eh.appBusQueue)
	application.GetPrimaryBus().Subscribe(event.ReloadDone, eh.appBusQueue)
	application.GetPrimaryBus().Subscribe(event.ACNVersion, eh.appBusQueue)
	application.GetPrimaryBus().Subscribe(UpdateGlobalSettings, eh.appBusQueue)
	application.GetPrimaryBus().Subscribe(CwtchStarted, eh.appBusQueue)
	application.GetPrimaryBus().Subscribe(servers.NewServer, eh.appBusQueue)
	application.GetPrimaryBus().Subscribe(servers.ServerIntentUpdate, eh.appBusQueue)
	application.GetPrimaryBus().Subscribe(servers.ServerDeleted, eh.appBusQueue)
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

// handleAppBusEvent enriches AppBus events so they are usable with out further data fetches
func (eh *EventHandler) handleAppBusEvent(e *event.Event) string {
	if eh.app != nil {
		switch e.EventType {
		case event.ACNStatus:
			if e.Data[event.Progress] == "100" {
				for _, onion := range eh.app.ListProfiles() {
					// launch a listen thread (internally this does a check that the protocol engine is not listening)
					// and as such is safe to call.
					eh.app.GetPeer(onion).Listen()
				}
			}
		case event.NewPeer:
			onion := e.Data[event.Identity]
			profile := eh.app.GetPeer(e.Data[event.Identity])
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
			if e.Data[event.Status] != event.StorageRunning || e.Data[event.Created] == event.True {
				profile.SetScopedZonedAttribute(attr.LocalScope, attr.ProfileZone, constants2.PeerOnline, event.False)
				eh.app.AddPeerPlugin(onion, plugins.CONNECTIONRETRY)
				eh.app.AddPeerPlugin(onion, plugins.NETWORKCHECK)

				// If the user has chosen to block unknown profiles
				// then explicitly configure the protocol engine to do so..
				if ReadGlobalSettings().BlockUnknownConnections {
					profile.BlockUnknownConnections()
				} else {
					// For completeness
					profile.AllowUnknownConnections()
				}

				// Start up the Profile
				profile.Listen()
				profile.StartPeersConnections()
				if _, err := groups.ExperimentGate(ReadGlobalSettings().Experiments); err == nil {
					profile.StartServerConnections()
				}
			}

			online, _ := profile.GetScopedZonedAttribute(attr.LocalScope, attr.ProfileZone, constants2.PeerOnline)
			// Name always exists
			e.Data[constants.Name], _ = profile.GetScopedZonedAttribute(attr.PublicScope, attr.ProfileZone, constants.Name)

			// Resolve the profile image of the profile.
			e.Data[constants2.Picture] = RandomProfileImage(onion)
			e.Data["Online"] = online

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
					if conversationInfo.IsGroup() {
						cpicPath = RandomGroupImage(conversationInfo.Handle)
					} else {
						cpicPath = RandomProfileImage(conversationInfo.Handle)
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

					// Resolve Peer State (should probably be DISCONNECTED)
					state := profile.GetPeerState(conversationInfo.Handle)
					if !set {
						state = connections.DISCONNECTED
					}

					// Resolve Conversation Auth State
					// TODO: Align this with ACLs
					authorization := model.AuthUnknown
					if conversationInfo.Accepted {
						authorization = model.AuthApproved
					}

					// If ACL has blocked conversation then hide them...
					if acl, exists := conversationInfo.ACL[conversationInfo.Handle]; exists && acl.Blocked {
						authorization = model.AuthBlocked
					}

					// Check if we are a server...
					groupServer, _ := conversationInfo.GetAttribute(attr.LocalScope, attr.LegacyGroupZone, constants.GroupServer)

					// Fetch the message count, and the time of the most recent message
					count, err := profile.GetChannelMessageCount(conversationInfo.ID, 0)
					if err != nil {
						log.Errorf("error fetching channel message count %v %v", conversationInfo.ID, err)
					}

					lastMessage, _ := profile.GetMostRecentMessages(conversationInfo.ID, 0, 0, 1)

					contacts = append(contacts, Contact{
						Name:          name,
						Identifier:    conversationInfo.ID,
						Onion:         conversationInfo.Handle,
						Status:        connections.ConnectionStateName[state],
						Picture:       cpicPath,
						Authorization: string(authorization),
						SaveHistory:   saveHistory,
						Messages:      count,
						Unread:        0,
						LastMessage:   strconv.Itoa(getLastMessageTime(lastMessage)),
						IsGroup:       conversationInfo.IsGroup(),
						GroupServer:   groupServer,
						IsArchived:    isArchived == event.True,
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

// handleProfileEvent enriches Profile events so they are usable with out further data fetches
func (eh *EventHandler) handleProfileEvent(ev *EventProfileEnvelope) string {
	if eh.app == nil {
		log.Errorf("eh.app == nil in handleProfileEvent... this shouldnt happen?")
	} else {
		profile := eh.app.GetPeer(ev.Profile)
		log.Debugf("New Profile Event to Handle: %v", ev)
		switch ev.Event.EventType {
		case event.NewMessageFromPeer: //event.TimestampReceived, event.RemotePeer, event.Data
			// only needs contact nickname and picture, for displaying on popup notifications
			ci, err := profile.FetchConversationInfo(ev.Event.Data["RemotePeer"])
			if ci != nil && err == nil {
				ev.Event.Data[event.ConversationID] = strconv.Itoa(ci.ID)
				profile.SetConversationAttribute(ci.ID, attr.LocalScope.ConstructScopedZonedPath(attr.ProfileZone.ConstructZonedPath(constants2.Archived)), event.False)
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
				}
			}
			ev.Event.Data["Picture"] = RandomProfileImage(ev.Event.Data["RemotePeer"])

		case event.NewMessageFromGroup:
			// only needs contact nickname and picture, for displaying on popup notifications
			ci, err := profile.FetchConversationInfo(ev.Event.Data["RemotePeer"])
			if ci != nil && err == nil {
				var exists bool
				ev.Event.Data["Nick"], exists = ci.GetAttribute(attr.LocalScope, attr.ProfileZone, constants.Name)
				if !exists {
					ev.Event.Data["Nick"], exists = ci.GetAttribute(attr.PublicScope, attr.ProfileZone, constants.Name)
					if !exists {
						ev.Event.Data["Nick"] = ev.Event.Data["RemotePeer"]
					}
				}
			}
			ev.Event.Data["Picture"] = RandomProfileImage(ev.Event.Data[event.RemotePeer])
			conversationID, _ := strconv.Atoi(ev.Event.Data[event.ConversationID])
			profile.SetConversationAttribute(conversationID, attr.LocalScope.ConstructScopedZonedPath(attr.ProfileZone.ConstructZonedPath(constants2.Archived)), event.False)
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

			// Resolve Conversation Auth State
			// TODO: Align this with ACLs
			authorization := model.AuthUnknown
			if conversationInfo.Accepted {
				authorization = model.AuthApproved
			}

			// If ACL has blocked conversation then hide them...
			if acl, exists := conversationInfo.ACL[conversationInfo.Handle]; exists && acl.Blocked {
				authorization = model.AuthBlocked
			}

			lastMessage, _ := profile.GetMostRecentMessages(conversationID, 0, 0, 1)
			ev.Event.Data["unread"] = strconv.Itoa(count) // if this is a new contact with messages attached then by-definition these are unread...
			ev.Event.Data["picture"] = RandomProfileImage(conversationInfo.Handle)
			ev.Event.Data["numMessages"] = strconv.Itoa(count)
			ev.Event.Data["nick"] = conversationInfo.Handle
			ev.Event.Data["status"] = connections.ConnectionStateName[profile.GetPeerState(conversationInfo.Handle)]
			ev.Event.Data["authorization"] = string(authorization)
			ev.Event.Data["loading"] = "false"
			ev.Event.Data["lastMsgTime"] = strconv.Itoa(getLastMessageTime(lastMessage))
		case event.GroupCreated:
			// This event should only happen after we have validated the invite, as such the error
			// condition *should* never happen.
			groupPic := RandomGroupImage(ev.Event.Data[event.GroupID])
			ev.Event.Data["PicturePath"] = groupPic
		case event.NewGroup:
			// This event should only happen after we have validated the invite, as such the error
			// condition *should* never happen.
			serializedInvite := ev.Event.Data[event.GroupInvite]
			if invite, err := model.ValidateInvite(serializedInvite); err == nil {
				groupPic := RandomGroupImage(invite.GroupID)
				ev.Event.Data["PicturePath"] = groupPic
			} else {
				log.Errorf("received a new group event which contained an invalid invite %v. this should never happen and likely means there is a bug in cwtch. Please file a ticket @ https://git.openprivcy.ca/cwtch.im/cwtch", err)
				return ""
			}
		case event.PeerStateChange:
			cxnState := connections.ConnectionStateToType()[ev.Event.Data[event.ConnectionState]]
			contact, _ := profile.FetchConversationInfo(ev.Event.Data[event.RemotePeer])

			if ev.Event.Data[event.RemotePeer] == profile.GetOnion() {
				return "" // suppress events from our own profile...
			}

			// We do not know who this is...don't send any event until we see a message from them
			// (at that point the conversation will have been created...)
			if cxnState == connections.AUTHENTICATED && contact == nil {
				return ""
			}

			if contact != nil {
				// No enrichment needed
				//uiManager.UpdateContactStatus(contact.Onion, int(cxnState), false)
				if cxnState == connections.AUTHENTICATED {
					// if known and authed, get vars
					profile.SendScopedZonedGetValToContact(contact.ID, attr.PublicScope, attr.ProfileZone, constants.Name)
					profile.SendScopedZonedGetValToContact(contact.ID, attr.PublicScope, attr.ProfileZone, constants2.Picture)
				}
			}

		case event.NewRetValMessageFromPeer:
			// auto handled event means the setting is already done, we're just deciding if we need to tell the UI
			conversationID, _ := strconv.Atoi(ev.Event.Data[event.ConversationID])
			scope := ev.Event.Data[event.Scope]
			path := ev.Event.Data[event.Path]
			exists, _ := strconv.ParseBool(ev.Event.Data[event.Exists])

			if exists && attr.IntoScope(scope) == attr.PublicScope {
				zone, path := attr.ParseZone(path)
				if _, err := profile.GetConversationAttribute(conversationID, attr.LocalScope.ConstructScopedZonedPath(zone.ConstructZonedPath(path))); err != nil {
					// we have a locally set override, don't pass this remote set public scope update to UI
					return ""
				}
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

	// eventBus.Subscribe(event.NetworkStatus, q)

	eventBus.Subscribe(event.NewMessageFromPeer, q)
	eventBus.Subscribe(event.UpdatedProfileAttribute, q)
	eventBus.Subscribe(event.PeerAcknowledgement, q)
	eventBus.Subscribe(event.DeleteContact, q)
	eventBus.Subscribe(event.AppError, q)
	eventBus.Subscribe(event.IndexedAcknowledgement, q)
	eventBus.Subscribe(event.IndexedFailure, q)
	eventBus.Subscribe(event.ContactCreated, q)
	eventBus.Subscribe(event.NewMessageFromGroup, q)
	eventBus.Subscribe(event.MessageCounterResync, q)
	eventBus.Subscribe(event.GroupCreated, q)
	eventBus.Subscribe(event.NewGroup, q)
	eventBus.Subscribe(event.AcceptGroupInvite, q)
	eventBus.Subscribe(event.SetPeerAttribute, q)
	eventBus.Subscribe(event.SetGroupAttribute, q)
	eventBus.Subscribe(event.DeleteGroup, q)
	eventBus.Subscribe(event.SendMessageToGroupError, q)
	eventBus.Subscribe(event.SendMessageToPeerError, q)
	eventBus.Subscribe(event.ServerStateChange, q)
	eventBus.Subscribe(event.PeerStateChange, q)
	eventBus.Subscribe(event.ChangePasswordSuccess, q)
	eventBus.Subscribe(event.ChangePasswordError, q)
	eventBus.Subscribe(event.NewRetValMessageFromPeer, q)
	eventBus.Subscribe(event.SetAttribute, q)
	eventBus.Subscribe(event.ShareManifest, q)
	eventBus.Subscribe(event.ManifestSizeReceived, q)
	eventBus.Subscribe(event.ManifestError, q)
	eventBus.Subscribe(event.ManifestReceived, q)
	eventBus.Subscribe(event.ManifestSaved, q)
	eventBus.Subscribe(event.FileDownloadProgressUpdate, q)
	eventBus.Subscribe(event.FileDownloaded, q)

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
