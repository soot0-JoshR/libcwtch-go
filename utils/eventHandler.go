package utils

import (
	"cwtch.im/cwtch/app"
	"cwtch.im/cwtch/app/plugins"
	"cwtch.im/cwtch/model"
	"cwtch.im/cwtch/model/attr"
	"cwtch.im/cwtch/protocol/connections"
	"encoding/json"
	"git.openprivacy.ca/flutter/libcwtch-go/constants"
	"git.openprivacy.ca/flutter/libcwtch-go/features/groups"
	"git.openprivacy.ca/openprivacy/log"
	"strconv"
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
}

func (eh *EventHandler) GetNextEvent() string {
	appChan := eh.appBusQueue.OutChan()

	select {
	case e := <-appChan:
		return eh.handleAppBusEvent(&e)
	case ev := <-eh.profileEvents:
		return eh.handleProfileEvent(&ev)
	}
}

// handleAppBusEvent enriches AppBus events so they are usable with out further data fetches
func (eh *EventHandler) handleAppBusEvent(e *event.Event) string {
	log.Debugf("New AppBus Event to Handle: %v", e)
	if eh.app != nil {
		switch e.EventType {
		case event.ACNStatus:
			if e.Data[event.Progress] == "100" {
				for onion := range eh.app.ListPeers() {
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

			tag,isTagged := profile.GetAttribute(app.AttributeTag)
			if isTagged {
				e.Data[app.AttributeTag] = tag
			} else {
				// Assume encrypted for non-tagged profiles - this isn't always true, but all post-beta profiles
				// are tagged on creation.
				e.Data[app.AttributeTag] = constants.ProfileTypeV1Password
			}

			if e.Data[event.Created] == event.True {
				name, _ := profile.GetAttribute(attr.GetLocalScope(constants.Name))
				profile.SetAttribute(attr.GetPublicScope(constants.Name), name)
				profile.SetAttribute(attr.GetPublicScope(constants.Picture), ImageToString(NewImage(RandomProfileImage(onion), TypeImageDistro)))
			}
			if e.Data[event.Status] != event.StorageRunning || e.Data[event.Created] == event.True {
				profile.SetAttribute(attr.GetLocalScope(constants.PeerOnline), event.False)
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

			nick, exists := profile.GetAttribute(attr.GetPublicScope(constants.Name))
			if !exists {
				nick = onion
			}

			picVal, ok := profile.GetAttribute(attr.GetPublicScope(constants.Picture))
			if !ok {
				picVal = ImageToString(NewImage(RandomProfileImage(onion), TypeImageDistro))
			}
			pic, err := StringToImage(picVal)
			if err != nil {
				pic = NewImage(RandomProfileImage(onion), TypeImageDistro)
			}
			picPath := GetPicturePath(pic)

			//tag, _ := profile.GetAttribute(app.AttributeTag)

			online, _ := profile.GetAttribute(attr.GetLocalScope(constants.PeerOnline))

			e.Data[constants.Name] = nick
			e.Data[constants.Picture] = picPath
			e.Data["Online"] = online

			var contacts []Contact
			var servers []groups.Server
			for _, contact := range profile.GetContacts() {

				// Only compile the server info if we have enabled the experiment...
				// Note that this means that this info can become stale if when first loaded the experiment
				// has been disabled and then is later re-enabled. As such we need to ensure that this list is
				// re-fetched when the group experiment is enabled via a dedicated ListServerInfo event...
				if profile.GetContact(contact).IsServer() {
					groupHandler, err := groups.ExperimentGate(ReadGlobalSettings().Experiments)
					if err == nil {
						servers = append(servers, groupHandler.GetServerInfo(contact, profile))
					}
					continue
				}

				contactInfo := profile.GetContact(contact)
				ph := NewPeerHelper(profile)
				name := ph.GetNick(contact)
				cpicPath := ph.GetProfilePic(contact)
				saveHistory, set := contactInfo.GetAttribute(event.SaveHistoryKey)
				if !set {
					saveHistory = event.DeleteHistoryDefault
				}
				contacts = append(contacts, Contact{
					Name:          name,
					Onion:         contactInfo.Onion,
					Status:        contactInfo.State,
					Picture:       cpicPath,
					Authorization: string(contactInfo.Authorization),
					SaveHistory:   saveHistory,
					Messages:      contactInfo.Timeline.Len(),
					Unread:        0,
					LastMessage:   strconv.Itoa(getLastMessageTime(&contactInfo.Timeline)),
					IsGroup:       false,
				})
			}

			// We compile and send the groups regardless of the experiment flag, and hide them in the UI
			for _, groupId := range profile.GetGroups() {
				group := profile.GetGroup(groupId)

				// Check that the group is cryptographically valid
				if !group.CheckGroup() {
					continue
				}

				ph := NewPeerHelper(profile)
				cpicPath := ph.GetProfilePic(groupId)

				authorization := model.AuthUnknown
				if group.Accepted {
					authorization = model.AuthApproved
				}

				contacts = append(contacts, Contact{
					Name:          ph.GetNick(groupId),
					Onion:         group.GroupID,
					Status:        group.State,
					Picture:       cpicPath,
					Authorization: string(authorization),
					SaveHistory:   event.SaveHistoryConfirmed,
					Messages:      group.Timeline.Len(),
					Unread:        0,
					LastMessage:   strconv.Itoa(getLastMessageTime(&group.Timeline)),
					IsGroup:       true,
					GroupServer:   group.GroupServer,
				})
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
		peer := eh.app.GetPeer(ev.Profile)
		ph := NewPeerHelper(peer)
		log.Debugf("New Profile Event to Handle: %v", ev)
		switch ev.Event.EventType {

		/*
				TODO: still handle this somewhere - network info from plugin Network check
				case event.NetworkStatus:
			online, _ := peer.GetAttribute(attr.GetLocalScope(constants.PeerOnline))
			if e.Data[event.Status] == plugins.NetworkCheckSuccess && online == event.False {
				peer.SetAttribute(attr.GetLocalScope(constants.PeerOnline), event.True)
				uiManager.UpdateNetworkStatus(true)
				// TODO we may have to reinitialize the peer
			} else if e.Data[event.Status] == plugins.NetworkCheckError && online == event.True {
				peer.SetAttribute(attr.GetLocalScope(constants.PeerOnline), event.False)
				uiManager.UpdateNetworkStatus(false)
			}*/

		case event.NewMessageFromPeer: //event.TimestampReceived, event.RemotePeer, event.Data
			// only needs contact nickname and picture, for displaying on popup notifications
			ev.Event.Data["Nick"] = ph.GetNick(ev.Event.Data["RemotePeer"])
			ev.Event.Data["Picture"] = ph.GetProfilePic(ev.Event.Data["RemotePeer"])
		case event.NewMessageFromGroup:
			// only needs contact nickname and picture, for displaying on popup notifications
			ev.Event.Data["Nick"] = ph.GetNick(ev.Event.Data[event.GroupID])
			ev.Event.Data["Picture"] = ph.GetProfilePic(ev.Event.Data[event.GroupID])
		case event.PeerAcknowledgement:
			// No enrichement required
		case event.PeerCreated:
			handle := ev.Event.Data[event.RemotePeer]
			err := EnrichNewPeer(handle, ph, ev)
			if err != nil {
				return ""
			}
		case event.GroupCreated:
			// This event should only happen after we have validated the invite, as such the error
			// condition *should* never happen.

			groupPic := ph.GetProfilePic(ev.Event.Data[event.GroupID])
			ev.Event.Data["PicturePath"] = groupPic
			ev.Event.Data["GroupName"] = ph.GetNick(ev.Event.Data[event.GroupID])

		case event.NewGroup:
			// This event should only happen after we have validated the invite, as such the error
			// condition *should* never happen.
			serializedInvite := ev.Event.Data[event.GroupInvite]
			if invite, err := model.ValidateInvite(serializedInvite); err == nil {
				groupPic := ph.GetProfilePic(invite.GroupID)
				ev.Event.Data["PicturePath"] = groupPic
			} else {
				log.Errorf("received a new group event which contained an invalid invite %v. this should never happen and likely means there is a bug in cwtch. Please file a ticket @ https://git.openprivcy.ca/cwtch.im/cwtch", err)
				return ""
			}
		case event.PeerStateChange:
			cxnState := connections.ConnectionStateToType()[ev.Event.Data[event.ConnectionState]]
			contact := peer.GetContact(ev.Event.Data[event.RemotePeer])

			if cxnState == connections.AUTHENTICATED && contact == nil {
				peer.AddContact(ev.Event.Data[event.RemotePeer], ev.Event.Data[event.RemotePeer], model.AuthUnknown)
				return ""
			}

			if contact != nil {
				// No enrichment needed
				//uiManager.UpdateContactStatus(contact.Onion, int(cxnState), false)
				if cxnState == connections.AUTHENTICATED {
					// if known and authed, get vars
					peer.SendGetValToPeer(ev.Event.Data[event.RemotePeer], attr.PublicScope, constants.Name)
					peer.SendGetValToPeer(ev.Event.Data[event.RemotePeer], attr.PublicScope, constants.Picture)
				}
			}

		case event.NewRetValMessageFromPeer:
			// auto handled event means the setting is already done, we're just deciding if we need to tell the UI
			onion := ev.Event.Data[event.RemotePeer]
			scope := ev.Event.Data[event.Scope]
			path := ev.Event.Data[event.Path]
			//val := ev.Event.Data[event.Data]
			exists, _ := strconv.ParseBool(ev.Event.Data[event.Exists])

			if exists && scope == attr.PublicScope {
				if _, exists := peer.GetContactAttribute(onion, attr.GetLocalScope(path)); exists {
					// we have a locally set ovverride, don't pass this remote set public scope update to UI
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
	eventBus.Subscribe(event.NewMessageFromPeer, q)
	eventBus.Subscribe(event.PeerAcknowledgement, q)
	eventBus.Subscribe(event.DeleteContact, q)
	eventBus.Subscribe(event.AppError, q)
	eventBus.Subscribe(event.IndexedAcknowledgement, q)
	eventBus.Subscribe(event.IndexedFailure, q)
	eventBus.Subscribe(event.NewMessageFromGroup, q)
	eventBus.Subscribe(event.GroupCreated, q)
	eventBus.Subscribe(event.NewGroup, q)
	eventBus.Subscribe(event.AcceptGroupInvite, q)
	eventBus.Subscribe(event.SetGroupAttribute, q)
	eventBus.Subscribe(event.DeleteGroup, q)
	eventBus.Subscribe(event.SendMessageToGroupError, q)
	eventBus.Subscribe(event.SendMessageToPeerError, q)
	eventBus.Subscribe(event.ServerStateChange, q)
	eventBus.Subscribe(event.PeerStateChange, q)
	eventBus.Subscribe(event.PeerCreated, q)
	eventBus.Subscribe(event.NetworkStatus, q)
	eventBus.Subscribe(event.ChangePasswordSuccess, q)
	eventBus.Subscribe(event.ChangePasswordError, q)
	eventBus.Subscribe(event.NewRetValMessageFromPeer, q)
	eventBus.Subscribe(event.SetAttribute, q)

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
