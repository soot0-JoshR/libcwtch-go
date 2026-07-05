package connections

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"git.openprivacy.ca/cwtch.im/tapir/primitives/privacypass"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"cwtch.im/cwtch/event"
	"cwtch.im/cwtch/model"
	"cwtch.im/cwtch/protocol/files"
	"cwtch.im/cwtch/protocol/groups"
	pmodel "cwtch.im/cwtch/protocol/model"
	"git.openprivacy.ca/cwtch.im/tapir"
	"git.openprivacy.ca/cwtch.im/tapir/applications"
	"git.openprivacy.ca/cwtch.im/tapir/networks/tor"
	"git.openprivacy.ca/cwtch.im/tapir/primitives"
	"git.openprivacy.ca/openprivacy/connectivity"
	torProvider "git.openprivacy.ca/openprivacy/connectivity/tor"
	"git.openprivacy.ca/openprivacy/log"
	"github.com/gtank/ristretto255"
	"golang.org/x/crypto/ed25519"
)

// 32 from tor/src/app/config/config.c MaxClientCircuitsPending
// we lower a bit because there's a lot of spillage
// - just cus we get a SOCKS timeout doesn't mean tor has stopped trying as a huge sorce
// - potential multiple profiles as a huge source
// - second order connections like token service's second servers aren't tracked in our system adding a few extra periodically
const TorMaxPendingConns = 28

type connectionLockedService struct {
	service        tapir.Service
	connectingLock sync.Mutex
}

type engine struct {
	queue event.Queue

	// Engine Attributes
	identity primitives.Identity
	acn      connectivity.ACN

	// Authorization list of contacts to authorization status
	authorizations sync.Map // string(onion) => model.Authorization

	// Block Unknown Contacts
	blockUnknownContacts bool

	// Pointer to the Global Event Manager
	eventManager event.Manager

	// Nextgen Tapir Service
	service tapir.Service

	getValRequests sync.Map // [string]string eventID:Data

	// Nextgen Tapir Service
	ephemeralServices     map[string]*connectionLockedService //sync.Map // string(onion) => tapir.Service
	ephemeralServicesLock sync.Mutex

	// Required for listen(), inaccessible from identity
	privateKey ed25519.PrivateKey

	// file sharing subsystem is responsible for maintaining active shares and downloads
	filesharingSubSystem files.FileSharingSubSystem

	tokenManagers sync.Map // [tokenService][]TokenManager

	shuttingDown atomic.Bool
}

// Engine (ProtocolEngine) encapsulates the logic necessary to make and receive Cwtch connections.
// Note: ProtocolEngine doesn't have access to any information necessary to encrypt or decrypt GroupMessages
// Protocol Engine *can* associate Group Identifiers with Group Servers, although we don't currently make use of this fact
// other than to route errors back to the UI.
type Engine interface {
	ACN() connectivity.ACN
	EventManager() event.Manager
	Shutdown()
}

// NewProtocolEngine initializes a new engine that runs Cwtch using the given parameters
func NewProtocolEngine(identity primitives.Identity, privateKey ed25519.PrivateKey, acn connectivity.ACN, eventManager event.Manager, peerAuthorizations map[string]model.Authorization) Engine {
	engine := new(engine)
	engine.identity = identity
	engine.privateKey = privateKey
	engine.ephemeralServices = make(map[string]*connectionLockedService)
	engine.queue = event.NewQueue()
	go engine.eventHandler()

	engine.acn = acn

	// Init the Server running the Simple App.
	engine.service = new(tor.BaseOnionService)
	engine.service.Init(acn, privateKey, &identity)

	engine.eventManager = eventManager

	engine.eventManager.Subscribe(event.ProtocolEngineStartListen, engine.queue)
	engine.eventManager.Subscribe(event.ProtocolEngineShutdown, engine.queue)
	engine.eventManager.Subscribe(event.PeerRequest, engine.queue)
	engine.eventManager.Subscribe(event.RetryPeerRequest, engine.queue)
	engine.eventManager.Subscribe(event.InvitePeerToGroup, engine.queue)
	engine.eventManager.Subscribe(event.JoinServer, engine.queue)
	engine.eventManager.Subscribe(event.LeaveServer, engine.queue)
	engine.eventManager.Subscribe(event.SendMessageToGroup, engine.queue)
	engine.eventManager.Subscribe(event.SendMessageToPeer, engine.queue)
	engine.eventManager.Subscribe(event.SendGetValMessageToPeer, engine.queue)
	engine.eventManager.Subscribe(event.SendRetValMessageToPeer, engine.queue)
	engine.eventManager.Subscribe(event.DeleteContact, engine.queue)

	engine.eventManager.Subscribe(event.UpdateConversationAuthorization, engine.queue)
	engine.eventManager.Subscribe(event.BlockUnknownPeers, engine.queue)
	engine.eventManager.Subscribe(event.AllowUnknownPeers, engine.queue)

	// File Handling
	engine.eventManager.Subscribe(event.ShareManifest, engine.queue)
	engine.eventManager.Subscribe(event.StopFileShare, engine.queue)
	engine.eventManager.Subscribe(event.StopAllFileShares, engine.queue)
	engine.eventManager.Subscribe(event.ManifestSizeReceived, engine.queue)
	engine.eventManager.Subscribe(event.ManifestSaved, engine.queue)

	// Token Server
	engine.eventManager.Subscribe(event.MakeAntispamPayment, engine.queue)

	for peer, authorization := range peerAuthorizations {
		engine.authorizations.Store(peer, authorization)
	}
	return engine
}

func (e *engine) ACN() connectivity.ACN {
	return e.acn
}

func (e *engine) EventManager() event.Manager {
	return e.eventManager
}

// eventHandler process events from other subsystems
func (e *engine) eventHandler() {
	for {
		ev := e.queue.Next()
		// optimistic shutdown...
		if e.shuttingDown.Load() {
			return
		}
		switch ev.EventType {
		case event.StatusRequest:
			e.eventManager.Publish(event.Event{EventType: event.ProtocolEngineStatus, EventID: ev.EventID})
		case event.PeerRequest:
			if torProvider.IsValidHostname(ev.Data[event.RemotePeer]) {
				go e.peerWithOnion(ev.Data[event.RemotePeer])
			}
		case event.RetryPeerRequest:
			// This event allows engine to treat (automated) retry peering requests differently to user-specified
			// peer events
			if torProvider.IsValidHostname(ev.Data[event.RemotePeer]) {
				log.Debugf("Retrying Peer Request: %v", ev.Data[event.RemotePeer])
				go e.peerWithOnion(ev.Data[event.RemotePeer])
			}
		case event.InvitePeerToGroup:
			err := e.sendPeerMessage(ev.Data[event.RemotePeer], pmodel.PeerMessage{ID: ev.EventID, Context: event.ContextInvite, Data: []byte(ev.Data[event.GroupInvite])})
			if err != nil {
				e.eventManager.Publish(event.NewEvent(event.SendMessageToPeerError, map[event.Field]string{event.EventContext: string(event.InvitePeerToGroup), event.RemotePeer: ev.Data[event.RemotePeer], event.EventID: ev.EventID, event.Error: "peer is offline or the connection has yet to finalize"}))
			}
		case event.JoinServer:
			signature, err := base64.StdEncoding.DecodeString(ev.Data[event.Signature])
			if err != nil {
				// will result in a full sync
				signature = []byte{}
			}
			// if we have been sent cached tokens, also deserialize them
			cachedTokensJson := ev.Data[event.CachedTokens]
			var cachedTokens []*privacypass.Token
			if len(cachedTokensJson) != 0 {
				json.Unmarshal([]byte(cachedTokensJson), &cachedTokens)
			}

			// create a new token handler...
			e.NewTokenHandler(ev.Data[event.ServerTokenOnion], cachedTokens)
			go e.peerWithTokenServer(ev.Data[event.GroupServer], ev.Data[event.ServerTokenOnion], ev.Data[event.ServerTokenY], signature, cachedTokens)
		case event.MakeAntispamPayment:
			go e.makeAntispamPayment(ev.Data[event.GroupServer])
		case event.LeaveServer:
			e.leaveServer(ev.Data[event.GroupServer])
		case event.DeleteContact:
			onion := ev.Data[event.RemotePeer]
			// We remove this peer from out blocklist which will prevent them from contacting us if we have "block unknown peers" turned on.
			e.authorizations.Delete(ev.Data[event.RemotePeer])
			e.deleteConnection(onion)
		case event.SendMessageToGroup:
			ciphertext, _ := base64.StdEncoding.DecodeString(ev.Data[event.Ciphertext])
			signature, _ := base64.StdEncoding.DecodeString(ev.Data[event.Signature])

			// launch a goroutine to post to the server
			go e.sendMessageToGroup(ev.Data[event.GroupID], ev.Data[event.GroupServer], ciphertext, signature, 0)
		case event.SendMessageToPeer:
			// TODO: remove this passthrough once the UI is integrated.
			context, ok := ev.Data[event.EventContext]
			if !ok {
				context = event.ContextRaw
			}
			if err := e.sendPeerMessage(ev.Data[event.RemotePeer], pmodel.PeerMessage{ID: ev.EventID, Context: context, Data: []byte(ev.Data[event.Data])}); err != nil {
				e.eventManager.Publish(event.NewEvent(event.SendMessageToPeerError, map[event.Field]string{event.EventContext: string(event.SendMessageToPeer), event.RemotePeer: ev.Data[event.RemotePeer], event.EventID: ev.EventID, event.Error: "peer is offline or the connection has yet to finalize"}))
			}
		case event.SendGetValMessageToPeer:
			if err := e.sendGetValToPeer(ev.EventID, ev.Data[event.RemotePeer], ev.Data[event.Scope], ev.Data[event.Path]); err != nil {
				e.eventManager.Publish(event.NewEvent(event.SendMessageToPeerError, map[event.Field]string{event.EventContext: string(event.SendGetValMessageToPeer), event.RemotePeer: ev.Data[event.RemotePeer], event.EventID: ev.EventID, event.Error: err.Error()}))
			}
		case event.SendRetValMessageToPeer:
			if err := e.sendRetValToPeer(ev.EventID, ev.Data[event.RemotePeer], ev.Data[event.Data], ev.Data[event.Exists]); err != nil {
				e.eventManager.Publish(event.NewEvent(event.SendMessageToPeerError, map[event.Field]string{event.EventContext: string(event.SendRetValMessageToPeer), event.RemotePeer: ev.Data[event.RemotePeer], event.EventID: ev.EventID, event.Error: err.Error()}))
			}
		case event.UpdateConversationAuthorization:
			accepted, _ := strconv.ParseBool(ev.Data[event.Accepted])
			blocked, _ := strconv.ParseBool(ev.Data[event.Blocked])
			auth := model.AuthUnknown
			if blocked {
				auth = model.AuthBlocked
			} else if accepted {
				auth = model.AuthApproved
			}
			e.authorizations.Store(ev.Data[event.RemotePeer], auth)
			if auth == model.AuthBlocked {
				connection, err := e.service.GetConnection(ev.Data[event.RemotePeer])
				if connection != nil && err == nil {
					connection.Close()
				}
				// Explicitly send a disconnected event (if we don't do this here then the UI can wait for a while before
				// an ongoing Open() connection fails and so the user will see a blocked peer as still connecting (because
				// there isn't an active connection and we are stuck waiting for tor to time out)
				e.peerDisconnected(ev.Data[event.RemotePeer])
			}
		case event.AllowUnknownPeers:
			log.Debugf("%v now allows unknown connections", e.identity.Hostname())
			e.blockUnknownContacts = false
		case event.BlockUnknownPeers:
			log.Debugf("%v now forbids unknown connections", e.identity.Hostname())
			e.blockUnknownContacts = true
		case event.ProtocolEngineStartListen:
			go e.listenFn()
		case event.ShareManifest:
			e.filesharingSubSystem.ShareFile(ev.Data[event.FileKey], ev.Data[event.SerializedManifest])
		case event.StopFileShare:
			e.filesharingSubSystem.StopFileShare(ev.Data[event.FileKey])
		case event.StopAllFileShares:
			e.filesharingSubSystem.StopAllFileShares()
		case event.ManifestSizeReceived:
			handle := ev.Data[event.Handle]
			key := ev.Data[event.FileKey]
			size, _ := strconv.Atoi(ev.Data[event.ManifestSize])
			if err := e.sendPeerMessage(handle, e.filesharingSubSystem.FetchManifest(key, uint64(size))); err != nil {
				e.eventManager.Publish(event.NewEvent(event.SendMessageToPeerError, map[event.Field]string{event.RemotePeer: ev.Data[event.RemotePeer], event.EventID: ev.EventID, event.Error: err.Error()}))
			}
		case event.ManifestSaved:
			handle := ev.Data[event.Handle]
			key := ev.Data[event.FileKey]
			serializedManifest := ev.Data[event.SerializedManifest]
			tempFile := ev.Data[event.TempFile]
			title := ev.Data[event.NameSuggestion]
			// NOTE: for now there will probably only ever be a single chunk request. When we enable group
			// sharing and rehosting then this loop will serve as a a way of splitting the request among multiple
			// contacts
			for _, message := range e.filesharingSubSystem.CompileChunkRequests(key, serializedManifest, tempFile, title) {
				if err := e.sendPeerMessage(handle, message); err != nil {
					e.eventManager.Publish(event.NewEvent(event.SendMessageToPeerError, map[event.Field]string{event.RemotePeer: ev.Data[event.RemotePeer], event.EventID: ev.EventID, event.Error: err.Error()}))
				}
			}
		case event.ProtocolEngineShutdown:
			return
		default:
			return
		}
	}
}

func (e *engine) isBlocked(onion string) bool {
	authorization, known := e.authorizations.Load(onion)
	if !known {
		// if we block unknown peers we will block this contact
		return e.blockUnknownContacts
	}
	return authorization.(model.Authorization) == model.AuthBlocked
}

func (e *engine) isAllowed(onion string) bool {
	authorization, known := e.authorizations.Load(onion)
	if !known {
		log.Errorf("attempted to lookup authorization of onion not in map...that should never happen")
		return false
	}
	if e.blockUnknownContacts {
		return authorization.(model.Authorization) == model.AuthApproved
	}
	return authorization.(model.Authorization) != model.AuthBlocked
}

func (e *engine) createPeerTemplate() *PeerApp {
	peerAppTemplate := new(PeerApp)
	peerAppTemplate.IsBlocked = e.isBlocked
	peerAppTemplate.IsAllowed = e.isAllowed
	peerAppTemplate.MessageHandler = e.handlePeerMessage
	peerAppTemplate.OnAcknowledgement = e.ignoreOnShutdown2(e.peerAck)
	peerAppTemplate.OnAuth = e.ignoreOnShutdown(e.peerAuthed)
	peerAppTemplate.OnConnecting = e.ignoreOnShutdown(e.peerConnecting)
	peerAppTemplate.OnClose = e.ignoreOnShutdown(e.peerDisconnected)
	return peerAppTemplate
}

// Listen sets up an onion listener to process incoming cwtch messages
func (e *engine) listenFn() {
	err := e.service.Listen(e.createPeerTemplate())
	if !e.shuttingDown.Load() {
		e.eventManager.Publish(event.NewEvent(event.ProtocolEngineStopped, map[event.Field]string{event.Identity: e.identity.Hostname(), event.Error: err.Error()}))
	}
}

// Shutdown tears down the eventHandler goroutine
func (e *engine) Shutdown() {
	// don't accept any more events...
	e.queue.Publish(event.NewEvent(event.ProtocolEngineShutdown, map[event.Field]string{}))
	e.service.Shutdown()

	e.shuttingDown.Store(true)

	e.ephemeralServicesLock.Lock()
	defer e.ephemeralServicesLock.Unlock()
	for _, connection := range e.ephemeralServices {
		log.Infof("shutting down ephemeral service")
		connection.connectingLock.Lock()
		connection.service.Shutdown()
		connection.connectingLock.Unlock()
	}

	e.queue.Shutdown()
}

// peerWithOnion is the entry point for cwtchPeer relationships
// needs to be run in a goroutine as will block on Open.
func (e *engine) peerWithOnion(onion string) {
	log.Debugf("Called PeerWithOnion for %v", onion)
	if !e.isBlocked(onion) {
		e.ignoreOnShutdown(e.peerConnecting)(onion)
		connected, err := e.service.Connect(onion, e.createPeerTemplate())

		// If we are already connected...check if we are authed and issue an auth event
		// (This allows the ui to be stateless)
		if connected && err != nil {
			conn, err := e.service.GetConnection(onion)
			if err == nil {
				if conn.HasCapability(cwtchCapability) {
					e.ignoreOnShutdown(e.peerAuthed)(onion)
					return
				}
			}
		}

		// Only issue a disconnected error if we are disconnected (Connect will fail if a connection already exists)
		if !connected && err != nil {
			e.ignoreOnShutdown(e.peerDisconnected)(onion)
		}
	}
}

func (e *engine) makeAntispamPayment(onion string) {
	log.Debugf("making antispam payment")
	e.ephemeralServicesLock.Lock()
	ephemeralService, ok := e.ephemeralServices[onion]
	e.ephemeralServicesLock.Unlock()

	if ephemeralService == nil || !ok {
		log.Debugf("could not find associated group for antispam payment")
		return
	}

	conn, err := ephemeralService.service.GetConnection(onion)
	if err == nil {
		tokenApp, ok := (conn.App()).(*TokenBoardClient)
		if ok {
			tokenManagerPointer, _ := e.tokenManagers.LoadOrStore(tokenApp.tokenServiceOnion, NewTokenManager())
			tokenManager := tokenManagerPointer.(*TokenManager)
			log.Debugf("checking antispam tokens %v", tokenManager.NumTokens())
			if tokenManager.NumTokens() < 5 {
				go tokenApp.PurchaseTokens()
			}
		}
	}
}

// peerWithTokenServer is the entry point for cwtchPeer - server relationships
// needs to be run in a goroutine as will block on Open.
func (e *engine) peerWithTokenServer(onion string, tokenServerOnion string, tokenServerY string, lastKnownSignature []byte, cachedTokens []*privacypass.Token) {
	e.ephemeralServicesLock.Lock()
	_, exists := e.ephemeralServices[onion]

	if exists {
		e.ephemeralServicesLock.Unlock()
		log.Debugf("attempted to join a server with an active connection")
		return
	}

	connectionService := &connectionLockedService{service: new(tor.BaseOnionService)}
	e.ephemeralServices[onion] = connectionService

	connectionService.connectingLock.Lock()
	defer connectionService.connectingLock.Unlock()
	e.ephemeralServicesLock.Unlock()

	log.Debugf("Peering with Token Server %v %v", onion, tokenServerOnion)
	e.ignoreOnShutdown(e.serverConnecting)(onion)
	// Create a new ephemeral service for this connection
	eid, epk := primitives.InitializeEphemeralIdentity()
	connectionService.service.Init(e.acn, epk, &eid)

	Y := new(ristretto255.Element)
	Y.UnmarshalText([]byte(tokenServerY))
	connected, err := connectionService.service.Connect(onion, NewTokenBoardClient(e.acn, Y, tokenServerOnion, lastKnownSignature, e))
	// If we are already connected...check if we are authed and issue an auth event
	// (This allows the ui to be stateless)
	if connected && err != nil {
		conn, err := connectionService.service.GetConnection(onion)
		if err == nil {

			// If the server is synced, resend the synced status update
			if conn.HasCapability(groups.CwtchServerSyncedCapability) {
				e.ignoreOnShutdown(e.serverSynced)(onion)
				return
			}

			// If the server is authed, resend the auth status update
			if conn.HasCapability(applications.AuthCapability) {
				// Resend the authed event...
				e.ignoreOnShutdown(e.serverAuthed)(onion)
				return
			}
		}
	}

	// Only issue a disconnected error if we are disconnected (Connect will fail if a connection already exists)
	if !connected && err != nil {
		e.ignoreOnShutdown(e.serverDisconnected)(onion)
	}
}

func (e *engine) ignoreOnShutdown(f func(string)) func(string) {
	return func(x string) {
		if !e.shuttingDown.Load() {
			f(x)
		}
	}
}

func (e *engine) ignoreOnShutdown2(f func(string, string)) func(string, string) {
	return func(x, y string) {
		if !e.shuttingDown.Load() {
			f(x, y)
		}
	}
}

func (e *engine) peerAuthed(onion string) {
	_, known := e.authorizations.Load(onion)
	if !known {
		e.authorizations.Store(onion, model.AuthUnknown)
	}

	// FIXME: This call uses WAY too much memory, and was responsible for the vast majority
	// of allocations in the UI
	// This is because Bine ends up reading the entire response into memory and then passes that back
	// into Connectivity which eventually extracts just what it needs.
	// Ideally we would just read from the control stream directly into reusable buffers.

	//details, err := e.acn.GetInfo(onion)
	//if err == nil {
	//    if hops, exists := details["circuit"]; exists {
	//        e.eventManager.Publish(event.NewEvent(event.ACNInfo, map[event.Field]string{
	//            event.Handle: onion,
	//            event.Key:    "circuit",
	//            event.Data:   hops,
	//        }))
	//    }
	//} else {
	//    log.Errorf("error getting info for onion %v", err)
	//}

	e.eventManager.Publish(event.NewEvent(event.PeerStateChange, map[event.Field]string{
		event.RemotePeer:      string(onion),
		event.ConnectionState: ConnectionStateName[AUTHENTICATED],
	}))
}

func (e *engine) peerConnecting(onion string) {
	e.eventManager.Publish(event.NewEvent(event.PeerStateChange, map[event.Field]string{
		event.RemotePeer:      onion,
		event.ConnectionState: ConnectionStateName[CONNECTING],
	}))
}

func (e *engine) serverConnecting(onion string) {
	e.eventManager.Publish(event.NewEvent(event.ServerStateChange, map[event.Field]string{
		event.GroupServer:     onion,
		event.ConnectionState: ConnectionStateName[CONNECTING],
	}))
}

func (e *engine) serverAuthed(onion string) {
	e.eventManager.Publish(event.NewEvent(event.ServerStateChange, map[event.Field]string{
		event.GroupServer:     onion,
		event.ConnectionState: ConnectionStateName[AUTHENTICATED],
	}))
}

func (e *engine) serverSynced(onion string) {
	e.eventManager.Publish(event.NewEvent(event.ServerStateChange, map[event.Field]string{
		event.GroupServer:     onion,
		event.ConnectionState: ConnectionStateName[SYNCED],
	}))
}

func (e *engine) serverDisconnected(onion string) {
	e.leaveServer(onion)

	e.eventManager.Publish(event.NewEvent(event.ServerStateChange, map[event.Field]string{
		event.GroupServer:     onion,
		event.ConnectionState: ConnectionStateName[DISCONNECTED],
	}))
}

func (e *engine) peerAck(onion string, eventID string) {
	e.eventManager.Publish(event.NewEvent(event.PeerAcknowledgement, map[event.Field]string{
		event.EventID:    eventID,
		event.RemotePeer: onion,
	}))
}

func (e *engine) peerDisconnected(onion string) {

	// Clean up any existing get value requests...
	e.getValRequests.Range(func(key, value interface{}) bool {
		keyString := key.(string)
		if strings.HasPrefix(keyString, onion) {
			e.getValRequests.Delete(keyString)
		}
		return true
	})

	// Purge circuit information...
	e.eventManager.Publish(event.NewEvent(event.ACNInfo, map[event.Field]string{
		event.Handle: onion,
		event.Key:    "circuit",
		event.Data:   "",
	}))

	e.eventManager.Publish(event.NewEvent(event.PeerStateChange, map[event.Field]string{
		event.RemotePeer:      string(onion),
		event.ConnectionState: ConnectionStateName[DISCONNECTED],
	}))
}

func (e *engine) sendGetValToPeer(eventID, onion, scope, path string) error {
	log.Debugf("sendGetValMessage to peer %v %v.%v\n", onion, scope, path)
	getVal := peerGetVal{Scope: scope, Path: path}
	message, err := json.Marshal(getVal)
	if err != nil {
		return err
	}

	key := onion + eventID
	e.getValRequests.Store(key, message)
	err = e.sendPeerMessage(onion, pmodel.PeerMessage{ID: eventID, Context: event.ContextGetVal, Data: message})
	if err != nil {
		e.getValRequests.Delete(key)
	}
	return err
}

func (e *engine) sendRetValToPeer(eventID, onion, val, existsStr string) error {
	log.Debugf("sendRetValMessage to peer %v (%v) %v %v\n", onion, eventID, val, existsStr)
	exists, _ := strconv.ParseBool(existsStr)
	retVal := peerRetVal{Val: val, Exists: exists}
	message, err := json.Marshal(retVal)
	if err != nil {
		return err
	}
	return e.sendPeerMessage(onion, pmodel.PeerMessage{ID: eventID, Context: event.ContextRetVal, Data: message})
}

func (e *engine) deleteConnection(id string) {
	conn, err := e.service.GetConnection(id)
	if err == nil {
		conn.Close()
	}
}

// receiveGroupMessage is a callback function that processes GroupMessages from a given server
func (e *engine) receiveGroupMessage(server string, gm *groups.EncryptedGroupMessage) {
	// Publish Event so that a Profile Engine can deal with it.
	// Note: This technically means that *multiple* Profile Engines could listen to the same ProtocolEngine!
	e.eventManager.Publish(event.NewEvent(event.EncryptedGroupMessage, map[event.Field]string{event.GroupServer: server, event.Ciphertext: base64.StdEncoding.EncodeToString(gm.Ciphertext), event.Signature: base64.StdEncoding.EncodeToString(gm.Signature)}))
}

// sendMessageToGroup attempts to sent the given message to the given group id.
func (e *engine) sendMessageToGroup(groupID string, server string, ct []byte, sig []byte, attempts int) {
	// sending to groups can fail for a few reasons (slow server, not enough tokens, etc.)
	// rather than trying to keep all that logic in method we simply back-off and try again
	// but if we fail more than 5 times then we report back to the client so they can investigate other options.
	// Note: This flow only applies to online-and-connected servers (this method will return faster if the server is not
	// online)
	if attempts >= 5 {
		log.Errorf("failed to post a message to a group after %v attempts", attempts)
		e.eventManager.Publish(event.NewEvent(event.SendMessageToGroupError, map[event.Field]string{event.GroupID: groupID, event.GroupServer: server, event.Error: "could not make payment to server", event.Signature: base64.StdEncoding.EncodeToString(sig)}))
		return
	}

	e.ephemeralServicesLock.Lock()
	ephemeralService, ok := e.ephemeralServices[server]
	e.ephemeralServicesLock.Unlock()

	if ephemeralService == nil || !ok {
		log.Debugf("could not send message to group: serve not found")
		e.eventManager.Publish(event.NewEvent(event.SendMessageToGroupError, map[event.Field]string{event.GroupID: groupID, event.GroupServer: server, event.Error: "server-not-found", event.Signature: base64.StdEncoding.EncodeToString(sig)}))
		return
	}

	conn, err := ephemeralService.service.WaitForCapabilityOrClose(server, groups.CwtchServerSyncedCapability)
	if err == nil {
		tokenApp, ok := (conn.App()).(*TokenBoardClient)
		if ok {
			if spent, numtokens := tokenApp.Post(groupID, ct, sig); !spent {
				// we failed to post, probably because we ran out of tokens... so make a payment
				go tokenApp.PurchaseTokens()
				// backoff
				time.Sleep(time.Second * 5)
				// try again
				log.Debugf("sending message to group error attempt: %v", attempts)
				e.sendMessageToGroup(groupID, server, ct, sig, attempts+1)
			} else {
				if numtokens < 5 {
					go tokenApp.PurchaseTokens()
				}
			}
			// regardless we return....
			return
		}
	}
	log.Debugf("could not send message to group")
	e.eventManager.Publish(event.NewEvent(event.SendMessageToGroupError, map[event.Field]string{event.GroupID: groupID, event.GroupServer: server, event.Error: "server-connection-not-valid", event.Signature: base64.StdEncoding.EncodeToString(sig)}))
}

// TODO this is becoming cluttered
func (e *engine) handlePeerMessage(hostname string, eventID string, context string, message []byte) {
	log.Debugf("New message from peer: %v %v", hostname, context)

	if context == event.ContextAck {
		e.peerAck(hostname, eventID)
	} else if context == event.ContextRetVal {
		req, ok := e.getValRequests.Load(hostname + eventID)
		if ok {
			reqStr := req.([]byte)
			e.handlePeerRetVal(hostname, reqStr, message)
			e.getValRequests.Delete(hostname + eventID)
		} else {
			log.Errorf("could not find val request for %v %s", hostname, eventID)
		}
	} else if context == event.ContextGetVal {
		var getVal peerGetVal
		err := json.Unmarshal(message, &getVal)
		if err == nil {
			ev := event.NewEventList(event.NewGetValMessageFromPeer, event.RemotePeer, hostname, event.Scope, getVal.Scope, event.Path, getVal.Path)
			ev.EventID = eventID
			e.eventManager.Publish(ev)
		}
	} else if context == event.ContextRequestManifest {
		for _, message := range e.filesharingSubSystem.RequestManifestParts(eventID) {
			if err := e.sendPeerMessage(hostname, message); err != nil {
				e.eventManager.Publish(event.NewEvent(event.SendMessageToPeerError, map[event.Field]string{event.RemotePeer: hostname, event.EventID: eventID, event.Error: err.Error()}))
			}
		}
	} else if context == event.ContextSendManifest {
		if fileKey, manifest := e.filesharingSubSystem.ReceiveManifestPart(eventID, message); len(manifest) != 0 {
			// We have a valid manifest
			e.eventManager.Publish(event.NewEvent(event.ManifestReceived, map[event.Field]string{event.Handle: hostname, event.FileKey: fileKey, event.SerializedManifest: manifest}))
		}
	} else if context == event.ContextRequestFile {
		chunks := e.filesharingSubSystem.ProcessChunkRequest(eventID, message)
		go func() {
			for _, message := range chunks {
				if err := e.sendPeerMessage(hostname, message); err != nil {
					e.eventManager.Publish(event.NewEvent(event.SendMessageToPeerError, map[event.Field]string{event.RemotePeer: hostname, event.EventID: eventID, event.Error: err.Error()}))
				}
			}
		}()
	} else if context == event.ContextSendFile {
		fileKey, progress, totalChunks, _, title := e.filesharingSubSystem.ProcessChunk(eventID, message)
		if len(fileKey) != 0 {
			e.eventManager.Publish(event.NewEvent(event.FileDownloadProgressUpdate, map[event.Field]string{event.FileKey: fileKey, event.Progress: strconv.Itoa(int(progress)), event.FileSizeInChunks: strconv.Itoa(int(totalChunks)), event.NameSuggestion: title}))
			if progress == totalChunks {
				if tempFile, filePath, success := e.filesharingSubSystem.VerifyFile(fileKey); success {
					log.Debugf("file verified and downloaded!")
					e.eventManager.Publish(event.NewEvent(event.FileDownloaded, map[event.Field]string{event.FileKey: fileKey, event.FilePath: filePath, event.TempFile: tempFile}))
				} else {
					log.Debugf("file failed to verify!")
					e.eventManager.Publish(event.NewEvent(event.FileVerificationFailed, map[event.Field]string{event.FileKey: fileKey}))
				}
			}
		}
	} else {
		// Fall through handler for the default text conversation.
		e.eventManager.Publish(event.NewEvent(event.NewMessageFromPeerEngine, map[event.Field]string{event.TimestampReceived: time.Now().Format(time.RFC3339Nano), event.RemotePeer: hostname, event.Data: string(message)}))

		// Send an explicit acknowledgement
		// Every other protocol should have an explicit acknowledgement message e.g. value lookups have responses, and file handling has an explicit flow
		if err := e.sendPeerMessage(hostname, pmodel.PeerMessage{ID: eventID, Context: event.ContextAck, Data: []byte{}}); err != nil {
			e.eventManager.Publish(event.NewEvent(event.SendMessageToPeerError, map[event.Field]string{event.RemotePeer: hostname, event.EventID: eventID, event.Error: err.Error()}))
		}
	}
}

func (e *engine) handlePeerRetVal(hostname string, getValData, retValData []byte) {
	var getVal peerGetVal
	var retVal peerRetVal

	err := json.Unmarshal(getValData, &getVal)
	if err != nil {
		log.Errorf("Unmarshalling our own getVal request: %v\n", err)
		return
	}
	err = json.Unmarshal(retValData, &retVal)
	if err != nil {
		log.Errorf("Unmarshalling peer response to getVal request")
		return
	}

	e.eventManager.Publish(event.NewEventList(event.NewRetValMessageFromPeer, event.RemotePeer, hostname, event.Scope, getVal.Scope, event.Path, getVal.Path, event.Exists, strconv.FormatBool(retVal.Exists), event.Data, retVal.Val))
}

// leaveServer disconnects from a server and deletes the ephemeral service
func (e *engine) leaveServer(server string) {
	e.ephemeralServicesLock.Lock()
	defer e.ephemeralServicesLock.Unlock()
	ephemeralService, ok := e.ephemeralServices[server]
	if ok {
		ephemeralService.service.Shutdown()
		delete(e.ephemeralServices, server)
	}
}

func (e *engine) sendPeerMessage(handle string, message pmodel.PeerMessage) error {
	conn, err := e.service.WaitForCapabilityOrClose(handle, cwtchCapability)
	if err == nil {
		peerApp, ok := (conn.App()).(*PeerApp)
		if ok {
			return peerApp.SendMessage(message)
		}
		log.Debugf("could not derive peer app: %v", err)
		return fmt.Errorf("could not find peer app to send message to: %v", handle)
	}
	log.Debugf("could not send peer message: %v", err)
	return err
}
