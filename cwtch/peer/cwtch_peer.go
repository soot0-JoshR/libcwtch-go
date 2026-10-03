package peer

import (
	"crypto/rand"
	"cwtch.im/cwtch/model/constants"
	"cwtch.im/cwtch/protocol/groups"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"git.openprivacy.ca/cwtch.im/tapir/primitives"
	"git.openprivacy.ca/cwtch.im/tapir/primitives/privacypass"
	"git.openprivacy.ca/openprivacy/connectivity"
	"git.openprivacy.ca/openprivacy/connectivity/tor"
	"golang.org/x/crypto/ed25519"
	"math/bits"
	"os"
	path "path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"cwtch.im/cwtch/event"
	"cwtch.im/cwtch/model"
	"cwtch.im/cwtch/model/attr"
	"cwtch.im/cwtch/protocol/connections"
	"cwtch.im/cwtch/protocol/files"
	"git.openprivacy.ca/openprivacy/log"
)

const lastKnownSignature = "LastKnowSignature"
const lastReceivedSignature = "LastReceivedSignature"

var autoHandleableEvents = map[event.Type]bool{event.EncryptedGroupMessage: true, event.PeerStateChange: true,
	event.ServerStateChange: true, event.NewGroupInvite: true, event.NewMessageFromPeerEngine: true,
	event.PeerAcknowledgement: true, event.PeerError: true, event.SendMessageToPeerError: true, event.SendMessageToGroupError: true,
	event.NewGetValMessageFromPeer: true, event.NewRetValMessageFromPeer: true, event.ProtocolEngineStopped: true, event.RetryServerRequest: true,
	event.ManifestSizeReceived: true, event.ManifestReceived: true, event.FileDownloaded: true, event.TriggerAntispamCheck: true}

// DefaultEventsToHandle specifies which events will be subscribed to
//
//	when a peer has its Init() function called
var DefaultEventsToHandle = []event.Type{
	event.EncryptedGroupMessage,
	event.NewMessageFromPeerEngine,
	event.PeerAcknowledgement,
	event.NewGroupInvite,
	event.PeerError,
	event.SendMessageToGroupError,
	event.NewGetValMessageFromPeer,
	event.ProtocolEngineStopped,
	event.RetryServerRequest,
	event.PeerStateChange,
	event.ServerStateChange,
	event.SendMessageToPeerError,
	event.NewRetValMessageFromPeer,
	event.ManifestReceived,
	event.FileDownloaded,
	event.TriggerAntispamCheck,
}

// cwtchPeer manages incoming and outgoing connections and all processing for a Cwtch cwtchPeer
type cwtchPeer struct {
	mutex        sync.Mutex
	shutdown     bool
	listenStatus bool
	storage      *CwtchProfileStorage

	state map[string]connections.ConnectionState

	queue    event.Queue
	eventBus event.Manager
}

func (cp *cwtchPeer) StoreCachedTokens(tokenServer string, tokens []*privacypass.Token) {
	ci, err := cp.FetchConversationInfo(tokenServer)
	if ci != nil && err == nil {
		// Overwrite any existing tokens..
		tokenPath := attr.LocalScope.ConstructScopedZonedPath(attr.ServerZone.ConstructZonedPath("tokens"))
		data, _ := json.Marshal(tokens)
		log.Debugf("storing cached tokens for %v", tokenServer)
		cp.SetConversationAttribute(ci.ID, tokenPath, string(data))
	}
}

func (cp *cwtchPeer) Export(file string) error {
	cp.mutex.Lock()
	defer cp.mutex.Unlock()
	return cp.storage.Export(file)
}

func (cp *cwtchPeer) PromoteToEncryptedStore(profileDirectory string, password string) error {
	return cp.storage.PromoteToEncryptedStore(profileDirectory, password)
}

func (cp *cwtchPeer) IsMemoryStore() bool {
	cp.mutex.Lock()
	defer cp.mutex.Unlock()
	return cp.storage.IsMemoryStore()
}

func (cp *cwtchPeer) Delete() {
	cp.mutex.Lock()
	defer cp.mutex.Unlock()
	cp.storage.Delete()
}

func (cp *cwtchPeer) SignMessage(message []byte) ([]byte, error) {
	cp.mutex.Lock()
	defer cp.mutex.Unlock()
	privateKey, err := cp.storage.LoadProfileKeyValue(TypePrivateKey, "Ed25519PrivateKey")
	if err != nil {
		return nil, err
	}
	if len(privateKey) != ed25519.PrivateKeySize {
		return nil, errors.New("invalid private key size")
	}
	return ed25519.Sign(ed25519.PrivateKey(privateKey), message), nil
}

// CheckPassword returns true if the given password can be used to derive the key that encrypts the underlying
// cwtch storage database. Returns false otherwise.
func (cp *cwtchPeer) CheckPassword(password string) bool {

	// this lock is not really needed, but because we directly access cp.storage.ProfileDirectory
	// we keep it here.
	cp.mutex.Lock()
	defer cp.mutex.Unlock()

	if cp.storage.IsMemoryStore() {
		return true
	}

	// open *our* database with the given password (set createIfNotExists to false)
	db, err := openEncryptedDatabase(cp.storage.ProfileDirectory, password, false)
	if db == nil || err != nil {
		// this will only fail in the rare cases that ProfileDirectory has been moved or deleted
		// it is actually a critical error, but far beyond the scope of Cwtch to deal with.
		return false
	}
	// check that the storage object is valid (this will fail if the DB key is incorrect)
	cps, err := NewCwtchProfileStorage(db, cp.storage.ProfileDirectory)
	if err != nil {
		// this will error if any SQL queries fail, which will be the case if the profile is invalid.
		return false
	}
	// we have a valid database, close the storage (but don't purge as we may be using those conversations...)
	cps.Close(false)

	// success!
	return true
}

func (cp *cwtchPeer) ChangePassword(password string, newpassword string, newpasswordAgain string) error {
	if cp.CheckPassword(password) {
		cp.mutex.Lock()
		defer cp.mutex.Unlock()

		salt, err := os.ReadFile(path.Join(cp.storage.ProfileDirectory, saltFile))
		if err != nil {
			return err
		}

		// probably redundant but we like api safety
		if newpassword == newpasswordAgain {
			rekey := createKey(newpassword, salt)
			log.Infof("rekeying database...")
			return cp.storage.Rekey(rekey)
		}
		return errors.New(constants.PasswordsDoNotMatchError)
	}
	return errors.New(constants.InvalidPasswordError)
}

// GenerateProtocolEngine
// Status: New in 1.5
func (cp *cwtchPeer) GenerateProtocolEngine(acn connectivity.ACN, bus event.Manager) (connections.Engine, error) {
	cp.mutex.Lock()
	defer cp.mutex.Unlock()
	conversations, _ := cp.storage.FetchConversations()

	authorizations := make(map[string]model.Authorization)
	for _, conversation := range conversations {
		if tor.IsValidHostname(conversation.Handle) {
			if conversation.ACL[conversation.Handle].Blocked {
				authorizations[conversation.Handle] = model.AuthBlocked
			} else {
				authorizations[conversation.Handle] = model.AuthApproved
			}
		}
	}

	privateKey, err := cp.storage.LoadProfileKeyValue(TypePrivateKey, "Ed25519PrivateKey")
	if err != nil {
		log.Errorf("error loading private key from storage")
		return nil, err
	}

	publicKey, err := cp.storage.LoadProfileKeyValue(TypePublicKey, "Ed25519PublicKey")
	if err != nil {
		log.Errorf("error loading public key from storage")
		return nil, err
	}

	identity := primitives.InitializeIdentity("", (*ed25519.PrivateKey)(&privateKey), (*ed25519.PublicKey)(&publicKey))

	return connections.NewProtocolEngine(identity, privateKey, acn, bus, authorizations), nil
}

// SendScopedZonedGetValToContact
// Status: No change in 1.5
func (cp *cwtchPeer) SendScopedZonedGetValToContact(conversationID int, scope attr.Scope, zone attr.Zone, path string) {
	ci, err := cp.GetConversationInfo(conversationID)
	if err == nil {
		ev := event.NewEventList(event.SendGetValMessageToPeer, event.RemotePeer, ci.Handle, event.Scope, string(scope), event.Path, string(zone.ConstructZonedPath(path)))
		cp.eventBus.Publish(ev)
	} else {
		log.Errorf("Error sending scoped zone to contact %v %v", conversationID, err)
	}
}

// GetScopedZonedAttribute
// Status: Ready for 1.5
func (cp *cwtchPeer) GetScopedZonedAttribute(scope attr.Scope, zone attr.Zone, key string) (string, bool) {

	scopedZonedKey := scope.ConstructScopedZonedPath(zone.ConstructZonedPath(key))

	value, err := cp.storage.LoadProfileKeyValue(TypeAttribute, scopedZonedKey.ToString())

	if err != nil {
		return "", false
	}

	return string(value), true
}

// GetScopedZonedAttributes finds all keys associated with the given scope and zone
func (cp *cwtchPeer) GetScopedZonedAttributeKeys(scope attr.Scope, zone attr.Zone) ([]string, error) {

	scopedZonedKey := scope.ConstructScopedZonedPath(zone.ConstructZonedPath(""))

	keys, err := cp.storage.FindProfileKeysByPrefix(TypeAttribute, scopedZonedKey.ToString())

	if err != nil {
		return nil, err
	}

	return keys, nil
}

// SetScopedZonedAttribute
func (cp *cwtchPeer) SetScopedZonedAttribute(scope attr.Scope, zone attr.Zone, key string, value string) {

	scopedZonedKey := scope.ConstructScopedZonedPath(zone.ConstructZonedPath(key))

	err := cp.storage.StoreProfileKeyValue(TypeAttribute, scopedZonedKey.ToString(), []byte(value))

	if err != nil {
		log.Errorf("error setting attribute %v")
		return
	}

	//  We always want to publish profile level attributes to the ui
	// This should be low traffic.
	if cp.eventBus != nil {
		cp.eventBus.Publish(event.NewEvent(event.UpdatedProfileAttribute, map[event.Field]string{event.Key: scopedZonedKey.ToString(), event.Data: value}))
	}
}

// SendMessage is a  higher level that merges sending messages to contacts and group handles
// If you try to send a message to a handle that doesn't exist, malformed or an incorrect type then
// this function will error
func (cp *cwtchPeer) SendMessage(conversation int, message string) (int, error) {

	// We assume we are sending to a Contact.
	conversationInfo, err := cp.storage.GetConversation(conversation)
	// If the contact exists replace the event id with the index of this message in the contacts timeline...
	// Otherwise assume we don't log the message in the timeline...
	if conversationInfo != nil && err == nil {

		if tor.IsValidHostname(conversationInfo.Handle) {
			ev := event.NewEvent(event.SendMessageToPeer, map[event.Field]string{event.ConversationID: strconv.Itoa(conversationInfo.ID), event.RemotePeer: conversationInfo.Handle, event.Data: message})
			onion, _ := cp.storage.LoadProfileKeyValue(TypeAttribute, attr.PublicScope.ConstructScopedZonedPath(attr.ProfileZone.ConstructZonedPath(constants.Onion)).ToString())

			// For p2p messages we store the event id of the message as the "signature" we can then look this up in the database later for acks
			id, err := cp.storage.InsertMessage(conversationInfo.ID, 0, message, model.Attributes{constants.AttrAuthor: string(onion), constants.AttrAck: event.False, constants.AttrSentTimestamp: time.Now().Format(time.RFC3339Nano)}, ev.EventID, model.CalculateContentHash(string(onion), message))
			if err != nil {
				return -1, err
			}
			cp.eventBus.Publish(ev)
			return id, nil
		} else {
			group, err := cp.constructGroupFromConversation(conversationInfo)
			if err != nil {
				log.Errorf("error constructing group")
				return -1, err
			}

			privateKey, err := cp.storage.LoadProfileKeyValue(TypePrivateKey, "Ed25519PrivateKey")
			if err != nil {
				log.Errorf("error loading private key from storage")
				return -1, err
			}

			publicKey, err := cp.storage.LoadProfileKeyValue(TypePublicKey, "Ed25519PublicKey")
			if err != nil {
				log.Errorf("error loading public key from storage")
				return -1, err
			}

			identity := primitives.InitializeIdentity("", (*ed25519.PrivateKey)(&privateKey), (*ed25519.PublicKey)(&publicKey))

			latestMessage, err := cp.storage.GetMostRecentMessages(conversation, 0, 0, 1)
			signatureBytes, _ := hex.DecodeString(group.GroupID)
			signature := base64.StdEncoding.EncodeToString(signatureBytes)
			if len(latestMessage) > 0 && err == nil {
				signature = latestMessage[0].Signature
			}

			ct, sig, dm, err := model.EncryptMessageToGroup(message, identity, group, signature)
			if err != nil {
				return -1, err
			}

			// Insert the Group Message
			log.Debugf("sending message to group: %v", conversationInfo.ID)
			id, err := cp.storage.InsertMessage(conversationInfo.ID, 0, dm.Text, model.Attributes{constants.AttrAck: constants.False, "PreviousSignature": base64.StdEncoding.EncodeToString(dm.PreviousMessageSig), constants.AttrAuthor: dm.Onion, constants.AttrSentTimestamp: time.Now().Format(time.RFC3339Nano)}, base64.StdEncoding.EncodeToString(sig), model.CalculateContentHash(dm.Onion, dm.Text))
			if err == nil {
				ev := event.NewEvent(event.SendMessageToGroup, map[event.Field]string{event.ConversationID: strconv.Itoa(conversationInfo.ID), event.GroupID: conversationInfo.Handle, event.GroupServer: group.GroupServer, event.Ciphertext: base64.StdEncoding.EncodeToString(ct), event.Signature: base64.StdEncoding.EncodeToString(sig)})
				cp.eventBus.Publish(ev)
				return id, nil
			}
			return -1, err
		}
	}
	return -1, fmt.Errorf("error sending message to conversation %v", err)
}

// BlockUnknownConnections will auto disconnect from connections if authentication doesn't resolve a hostname
// known to peer.
// Status: Ready for 1.5
func (cp *cwtchPeer) BlockUnknownConnections() {
	cp.eventBus.Publish(event.NewEvent(event.BlockUnknownPeers, map[event.Field]string{}))
}

// AllowUnknownConnections will permit connections from unknown contacts.
// Status: Ready for 1.5
func (cp *cwtchPeer) AllowUnknownConnections() {
	cp.eventBus.Publish(event.NewEvent(event.AllowUnknownPeers, map[event.Field]string{}))
}

// NewProfileWithEncryptedStorage instantiates a new Cwtch Profile from encrypted storage
func NewProfileWithEncryptedStorage(name string, cps *CwtchProfileStorage) CwtchPeer {
	cp := new(cwtchPeer)
	cp.shutdown = false
	cp.storage = cps
	cp.queue = event.NewQueue()
	cp.state = make(map[string]connections.ConnectionState)

	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	// Store all the Necessary Base Attributes In The Database
	cp.SetScopedZonedAttribute(attr.PublicScope, attr.ProfileZone, constants.Name, name)
	cp.storage.StoreProfileKeyValue(TypeAttribute, attr.PublicScope.ConstructScopedZonedPath(attr.ProfileZone.ConstructZonedPath(constants.Onion)).ToString(), []byte(tor.GetTorV3Hostname(pub)))
	cp.storage.StoreProfileKeyValue(TypePrivateKey, "Ed25519PrivateKey", priv)
	cp.storage.StoreProfileKeyValue(TypePublicKey, "Ed25519PublicKey", pub)

	return cp
}

var saveHistoryPath = attr.LocalScope.ConstructScopedZonedPath(
	attr.ProfileZone.ConstructZonedPath(event.SaveHistoryKey),
)

func shouldPreserveHistoryOnStegmsLoad(conversation *model.Conversation) bool {
	if conversation == nil || conversation.IsGroup() || conversation.IsServer() {
		return false
	}
	saveHistory, _ := conversation.GetAttribute(attr.LocalScope, attr.ProfileZone, event.SaveHistoryKey)
	return saveHistory != event.DeleteHistoryConfirmed
}

// preserveDefaultPeerHistory migrates Cwtch's default-delete policy to the
// persistent-history policy used by StegMS before the startup purge runs. An
// explicit user choice to delete history remains authoritative.
func preserveDefaultPeerHistory(cps *CwtchProfileStorage) error {
	conversations, err := cps.FetchConversations()
	if err != nil {
		return err
	}
	for _, conversation := range conversations {
		if !shouldPreserveHistoryOnStegmsLoad(conversation) {
			continue
		}
		if err := cps.SetConversationAttribute(conversation.ID, saveHistoryPath, event.SaveHistoryConfirmed); err != nil {
			return err
		}
	}
	return nil
}

// FromEncryptedStorage loads an existing Profile from Encrypted Storage
func FromEncryptedStorage(cps *CwtchProfileStorage) CwtchPeer {
	cp := new(cwtchPeer)
	cp.shutdown = false
	cp.storage = cps
	cp.queue = event.NewQueue()
	cp.state = make(map[string]connections.ConnectionState)
	// At some point we may want to populate caches here, for now we will assume hitting the
	// database directly is tolerable
	// Clean up anything that wasn't cleaned up on shutdown
	// TODO ideally this shouldn't need to be done but the UI sometimes doesn't shut down cleanly
	if err := preserveDefaultPeerHistory(cp.storage); err != nil {
		// Retaining too much on a storage error is safer than deleting history
		// before StegMS can establish the intended conversation policy.
		log.Errorf("could not migrate peer history policy before startup purge: %v", err)
	} else {
		cp.storage.PurgeNonSavedMessages()
	}
	return cp
}

// ImportLegacyProfile generates a new peer from a profile.
// Deprecated - Only to be used for importing new profiles
func ImportLegacyProfile(profile *model.Profile, cps *CwtchProfileStorage) CwtchPeer {
	cp := new(cwtchPeer)
	cp.shutdown = false
	cp.storage = cps
	cp.eventBus = event.NewEventManager()
	cp.queue = event.NewQueue()
	cp.state = make(map[string]connections.ConnectionState)
	// Store all the Necessary Base Attributes In The Database
	cp.SetScopedZonedAttribute(attr.PublicScope, attr.ProfileZone, constants.Name, profile.Name)
	cp.storage.StoreProfileKeyValue(TypeAttribute, attr.PublicScope.ConstructScopedZonedPath(attr.ProfileZone.ConstructZonedPath(constants.Onion)).ToString(), []byte(tor.GetTorV3Hostname(profile.Ed25519PublicKey)))
	cp.storage.StoreProfileKeyValue(TypePrivateKey, "Ed25519PrivateKey", profile.Ed25519PrivateKey)
	cp.storage.StoreProfileKeyValue(TypePublicKey, "Ed25519PublicKey", profile.Ed25519PublicKey)

	for k, v := range profile.Attributes {
		parts := strings.SplitN(k, ".", 2)
		if len(parts) == 2 {
			scope := attr.IntoScope(parts[0])
			zone, path := attr.ParseZone(parts[1])
			cp.SetScopedZonedAttribute(scope, zone, path, v)
		} else {
			log.Debugf("could not import legacy style attribute %v", k)
		}
	}

	for _, contact := range profile.Contacts {
		var conversationID int
		var err error
		if contact.Authorization == model.AuthApproved {
			conversationID, err = cp.NewContactConversation(contact.Onion, model.DefaultP2PAccessControl(), true)
		} else if contact.Authorization == model.AuthBlocked {
			conversationID, err = cp.NewContactConversation(contact.Onion, model.AccessControl{Blocked: true, Read: false, Append: false}, true)
		} else {
			conversationID, err = cp.NewContactConversation(contact.Onion, model.DefaultP2PAccessControl(), false)
		}

		if err == nil {
			for key, value := range contact.Attributes {
				switch key {
				case event.SaveHistoryKey:
					cp.SetConversationAttribute(conversationID, attr.LocalScope.ConstructScopedZonedPath(attr.ProfileZone.ConstructZonedPath(event.SaveHistoryKey)), value)
				case string(model.BundleType):
					cp.AddServer(value)
				case string(model.KeyTypeTokenOnion):
					//ignore
				case string(model.KeyTypeServerOnion):
					// ignore
				case string(model.KeyTypePrivacyPass):
					// ignore
				case lastKnownSignature:
					cp.SetConversationAttribute(conversationID, attr.LocalScope.ConstructScopedZonedPath(attr.ProfileZone.ConstructZonedPath(lastReceivedSignature)), value)
				default:
					log.Debugf("could not import conversation attribute %v", key)
				}
			}

			if name, exists := contact.Attributes["local.name"]; exists {
				cp.SetConversationAttribute(conversationID, attr.LocalScope.ConstructScopedZonedPath(attr.ProfileZone.ConstructZonedPath(constants.Name)), name)
			}
			if name, exists := contact.Attributes["peer.name"]; exists {
				cp.SetConversationAttribute(conversationID, attr.PublicScope.ConstructScopedZonedPath(attr.ProfileZone.ConstructZonedPath(constants.Name)), name)
			}

			for _, message := range contact.Timeline.GetMessages() {
				// By definition anything stored in legacy timelines in acknowledged
				attr := model.Attributes{constants.AttrAuthor: message.PeerID, constants.AttrAck: event.True, constants.AttrSentTimestamp: message.Timestamp.Format(time.RFC3339Nano)}
				if message.Flags&0x01 == 0x01 {
					attr[constants.AttrRejected] = event.True
				}
				if message.Flags&0x02 == 0x02 {
					attr[constants.AttrDownloaded] = event.True
				}
				cp.storage.InsertMessage(conversationID, 0, message.Message, attr, model.GenerateRandomID(), model.CalculateContentHash(message.PeerID, message.Message))
			}
		}
	}

	for _, group := range profile.Groups {
		group.GroupName = group.Attributes["local.name"]
		invite, err := group.Invite()
		if err == nil {
			// Automatically grab all the important fields...
			conversationID, err := cp.ImportGroup(invite)
			if err == nil {
				for _, message := range group.Timeline.GetMessages() {
					// By definition anything stored in legacy timelines in acknowledged
					attr := model.Attributes{constants.AttrAuthor: message.PeerID, constants.AttrAck: event.True, constants.AttrSentTimestamp: message.Timestamp.Format(time.RFC3339Nano)}
					if message.Flags&0x01 == 0x01 {
						attr[constants.AttrRejected] = event.True
					}
					if message.Flags&0x02 == 0x02 {
						attr[constants.AttrDownloaded] = event.True
					}
					cp.storage.InsertMessage(conversationID, 0, message.Message, attr, base64.StdEncoding.EncodeToString(message.Signature), model.CalculateContentHash(message.PeerID, message.Message))
				}
			}
		}
	}
	cp.eventBus.Shutdown() // We disregard all events from profile...
	return cp
}

// Init instantiates a cwtchPeer
// Status: Ready for 1.5
func (cp *cwtchPeer) Init(eventBus event.Manager) {
	cp.InitForEvents(eventBus, DefaultEventsToHandle)

	// At this point we can safely assume that public.profile.name exists
	localName, _ := cp.GetScopedZonedAttribute(attr.LocalScope, attr.ProfileZone, constants.Name)
	publicName, _ := cp.GetScopedZonedAttribute(attr.PublicScope, attr.ProfileZone, constants.Name)

	if localName != publicName {
		cp.SetScopedZonedAttribute(attr.LocalScope, attr.ProfileZone, constants.Name, publicName)
	}
}

// InitForEvents
// Status: Ready for 1.5
func (cp *cwtchPeer) InitForEvents(eventBus event.Manager, toBeHandled []event.Type) {
	go cp.eventHandler()

	cp.eventBus = eventBus
	cp.AutoHandleEvents(toBeHandled)
}

// AutoHandleEvents sets an event (if able) to be handled by this peer
// Status: Ready for 1.5
func (cp *cwtchPeer) AutoHandleEvents(events []event.Type) {
	for _, ev := range events {
		if _, exists := autoHandleableEvents[ev]; exists {
			cp.eventBus.Subscribe(ev, cp.queue)
		} else {
			log.Errorf("Peer asked to autohandle event it cannot: %v\n", ev)
		}
	}
}

// ImportGroup initializes a group from an imported source rather than a peer invite
func (cp *cwtchPeer) ImportGroup(exportedInvite string) (int, error) {
	gci, err := model.ValidateInvite(exportedInvite)
	if err != nil {
		return -1, err
	}
	cp.mutex.Lock()
	conversationInfo, _ := cp.storage.GetConversationByHandle(gci.GroupID)
	if conversationInfo != nil {
		cp.mutex.Unlock()
		return -1, fmt.Errorf("group already exists")
	}
	groupConversationID, err := cp.storage.NewConversation(gci.GroupID, map[string]string{}, model.AccessControlList{}, true)
	cp.mutex.Unlock()

	if err == nil {
		cp.SetConversationAttribute(groupConversationID, attr.LocalScope.ConstructScopedZonedPath(attr.LegacyGroupZone.ConstructZonedPath(constants.GroupID)), gci.GroupID)
		cp.SetConversationAttribute(groupConversationID, attr.LocalScope.ConstructScopedZonedPath(attr.LegacyGroupZone.ConstructZonedPath(constants.GroupServer)), gci.ServerHost)
		cp.SetConversationAttribute(groupConversationID, attr.LocalScope.ConstructScopedZonedPath(attr.LegacyGroupZone.ConstructZonedPath(constants.GroupKey)), base64.StdEncoding.EncodeToString(gci.SharedKey))
		cp.SetConversationAttribute(groupConversationID, attr.LocalScope.ConstructScopedZonedPath(attr.ProfileZone.ConstructZonedPath(constants.Name)), gci.GroupName)
		cp.eventBus.Publish(event.NewEvent(event.NewGroup, map[event.Field]string{event.ConversationID: strconv.Itoa(groupConversationID), event.GroupServer: gci.ServerHost, event.GroupInvite: exportedInvite, event.GroupName: gci.GroupName}))
		cp.JoinServer(gci.ServerHost)
	}
	return groupConversationID, err
}

// NewContactConversation create a new p2p conversation with the given acl applied to the handle.
func (cp *cwtchPeer) NewContactConversation(handle string, acl model.AccessControl, accepted bool) (int, error) {
	cp.mutex.Lock()
	defer cp.mutex.Unlock()
	conversationInfo, _ := cp.storage.GetConversationByHandle(handle)
	if conversationInfo == nil {
		conversationID, err := cp.storage.NewConversation(handle, model.Attributes{event.SaveHistoryKey: event.DeleteHistoryDefault}, model.AccessControlList{handle: acl}, accepted)
		cp.eventBus.Publish(event.NewEvent(event.ContactCreated, map[event.Field]string{event.ConversationID: strconv.Itoa(conversationID), event.RemotePeer: handle}))
		return conversationID, err
	}
	return -1, fmt.Errorf("contact conversation already exists")
}

// AcceptConversation looks up a conversation by `handle` and sets the Accepted status to `true`
// This will cause Cwtch to auto connect to this conversation on start up
func (cp *cwtchPeer) AcceptConversation(id int) error {
	err := cp.storage.AcceptConversation(id)
	if err == nil {
		// If a p2p conversation then attempt to peer with the onion...
		// Groups and Server have their own acceptance flow.,
		ci, err := cp.storage.GetConversation(id)
		if err != nil {
			log.Errorf("Could not get conversation for %v: %v", id, err)
			return err
		}
		if !ci.IsGroup() && !ci.IsServer() {
			cp.sendUpdateAuth(id, ci.Handle, ci.Accepted, ci.ACL[ci.Handle].Blocked)
			cp.PeerWithOnion(ci.Handle)
		}
	}
	return err
}

// BlockConversation looks up a conversation by `handle` and sets the Blocked ACL field to `true`
// This will cause Cwtch to never try to connect to and refuse connections from the peer
func (cp *cwtchPeer) BlockConversation(id int) error {
	ci, err := cp.storage.GetConversation(id)
	if err != nil {
		return err
	}

	// p2p conversations have a single ACL referencing the remote peer. Set this to blocked...
	if ac, exists := ci.ACL[ci.Handle]; exists {
		ac.Blocked = true
		ci.ACL[ci.Handle] = ac
	}

	// Send an event in any case to block the protocol engine...
	// TODO at some point in the future engine needs to understand ACLs not just legacy auth status
	cp.sendUpdateAuth(id, ci.Handle, ci.Accepted, ci.ACL[ci.Handle].Blocked)

	return cp.storage.SetConversationACL(id, ci.ACL)
}

// UnblockConversation looks up a conversation by `handle` and sets the Blocked ACL field to `true`
// Further actions depend on the Accepted field
func (cp *cwtchPeer) UnblockConversation(id int) error {
	ci, err := cp.storage.GetConversation(id)
	if err != nil {
		return err
	}

	// p2p conversations have a single ACL referencing the remote peer. Set ACL's blocked to false...
	if ac, exists := ci.ACL[ci.Handle]; exists {
		ac.Blocked = false
		ci.ACL[ci.Handle] = ac
	}

	// Send an event in any case to block the protocol engine...
	// TODO at some point in the future engine needs to understand ACLs not just legacy auth status
	cp.sendUpdateAuth(id, ci.Handle, ci.Accepted, ci.ACL[ci.Handle].Blocked)

	if !ci.IsGroup() && !ci.IsServer() && ci.Accepted {
		cp.PeerWithOnion(ci.Handle)
	}

	return cp.storage.SetConversationACL(id, ci.ACL)
}

func (cp *cwtchPeer) sendUpdateAuth(id int, handle string, accepted bool, blocked bool) {
	cp.eventBus.Publish(event.NewEvent(event.UpdateConversationAuthorization, map[event.Field]string{event.ConversationID: strconv.Itoa(id), event.RemotePeer: handle, event.Accepted: strconv.FormatBool(accepted), event.Blocked: strconv.FormatBool(blocked)}))
}

func (cp *cwtchPeer) FetchConversations() ([]*model.Conversation, error) {
	return cp.storage.FetchConversations()
}

func (cp *cwtchPeer) GetConversationInfo(conversation int) (*model.Conversation, error) {
	return cp.storage.GetConversation(conversation)
}

// FetchConversationInfo returns information about the given conversation referenced by the handle
func (cp *cwtchPeer) FetchConversationInfo(handle string) (*model.Conversation, error) {
	return cp.storage.GetConversationByHandle(handle)
}

// DeleteConversation purges all data about the conversation, including message timelines, referenced by the handle
func (cp *cwtchPeer) DeleteConversation(id int) error {
	cp.mutex.Lock()
	defer cp.mutex.Unlock()
	ci, err := cp.storage.GetConversation(id)
	if err == nil && ci != nil {
		cp.eventBus.Publish(event.NewEventList(event.DeleteContact, event.RemotePeer, ci.Handle))
		return cp.storage.DeleteConversation(id)
	}
	return fmt.Errorf("could not delete conversation, did not exist")
}

// SetConversationAttribute sets the conversation attribute at path to value
func (cp *cwtchPeer) SetConversationAttribute(id int, path attr.ScopedZonedPath, value string) error {
	return cp.storage.SetConversationAttribute(id, path, value)
}

// GetConversationAttribute is a shortcut method for retrieving the value of a given path
func (cp *cwtchPeer) GetConversationAttribute(id int, path attr.ScopedZonedPath) (string, error) {
	ci, err := cp.storage.GetConversation(id)
	if err != nil {
		return "", err
	}
	val, exists := ci.Attributes[path.ToString()]
	if !exists {
		return "", fmt.Errorf("%v does not exist for conversation %v", path.ToString(), id)
	}
	return val, nil
}

// GetChannelMessage returns a message from a conversation channel referenced by the absolute ID.
// Note: This should note be used to index a list as the ID is not expected to be tied to absolute position
// in the table (e.g. deleted messages, expired messages, etc.)
func (cp *cwtchPeer) GetChannelMessage(conversation int, channel int, id int) (string, model.Attributes, error) {
	return cp.storage.GetChannelMessage(conversation, channel, id)
}

// GetChannelMessageCount returns the absolute number of messages in a given conversation channel
func (cp *cwtchPeer) GetChannelMessageCount(conversation int, channel int) (int, error) {
	return cp.storage.GetChannelMessageCount(conversation, channel)
}

// GetMostRecentMessages returns a selection of messages, ordered by most recently inserted
func (cp *cwtchPeer) GetMostRecentMessages(conversation int, channel int, offset int, limit int) ([]model.ConversationMessage, error) {
	return cp.storage.GetMostRecentMessages(conversation, channel, offset, limit)
}

// UpdateMessageAttribute sets a given key/value attribute on the message in the given conversation/channel
// errors if the message doesn't exist, or for underlying database issues.
func (cp *cwtchPeer) UpdateMessageAttribute(conversation int, channel int, id int, key string, value string) error {
	_, attr, err := cp.GetChannelMessage(conversation, channel, id)
	if err == nil {
		cp.mutex.Lock()
		defer cp.mutex.Unlock()
		attr[key] = value
		return cp.storage.UpdateMessageAttributes(conversation, channel, id, attr)
	}
	return err
}

// StartGroup create a new group linked to the given server and returns the group ID, an invite or an error.
// Status: TODO change server handle to conversation id...?
func (cp *cwtchPeer) StartGroup(name string, server string) (int, error) {
	group, err := model.NewGroup(server)
	if err == nil {
		cp.mutex.Lock()
		conversationID, err := cp.storage.NewConversation(group.GroupID, map[string]string{}, model.AccessControlList{}, true)
		cp.mutex.Unlock()
		if err != nil {
			return -1, err
		}
		cp.SetConversationAttribute(conversationID, attr.LocalScope.ConstructScopedZonedPath(attr.LegacyGroupZone.ConstructZonedPath(constants.GroupID)), group.GroupID)
		cp.SetConversationAttribute(conversationID, attr.LocalScope.ConstructScopedZonedPath(attr.LegacyGroupZone.ConstructZonedPath(constants.GroupServer)), group.GroupServer)
		cp.SetConversationAttribute(conversationID, attr.LocalScope.ConstructScopedZonedPath(attr.LegacyGroupZone.ConstructZonedPath(constants.GroupKey)), base64.StdEncoding.EncodeToString(group.GroupKey[:]))
		cp.SetConversationAttribute(conversationID, attr.LocalScope.ConstructScopedZonedPath(attr.ProfileZone.ConstructZonedPath(constants.Name)), name)

		cp.eventBus.Publish(event.NewEvent(event.GroupCreated, map[event.Field]string{
			event.ConversationID: strconv.Itoa(conversationID),
			event.GroupID:        group.GroupID,
			event.GroupServer:    group.GroupServer,
			event.GroupName:      name,
		}))
		return conversationID, nil
	}
	log.Errorf("error creating group: %v", err)
	return -1, err
}

// AddServer takes in a serialized server specification (a bundle of related keys) and adds a contact for the
// server assuming there are no errors and the contact doesn't already exist.
// Returns the onion of the new server if added
// TODO in the future this function should also integrate with a trust provider to validate the key bundle.
// Status: Ready for 1.5
func (cp *cwtchPeer) AddServer(serverSpecification string) (string, error) {
	// This confirms that the server did at least sign the bundle
	keyBundle, err := model.DeserializeAndVerify([]byte(serverSpecification))
	if err != nil {
		return "", err
	}
	log.Debugf("Got new key bundle %v", keyBundle.Serialize())

	//  if the key bundle is incomplete then error out.
	// TODO In the future we may allow servers to attest to new
	// keys or subsets of keys, but for now they must commit only to a complete set of keys required for Cwtch Groups
	// (that way we can be assured that the keybundle we store is a valid one)
	if !keyBundle.HasKeyType(model.KeyTypeTokenOnion) || !keyBundle.HasKeyType(model.KeyTypeServerOnion) || !keyBundle.HasKeyType(model.KeyTypePrivacyPass) {
		return "", errors.New("keybundle is incomplete")
	}

	if keyBundle.HasKeyType(model.KeyTypeServerOnion) {
		onionKey, _ := keyBundle.GetKey(model.KeyTypeServerOnion)
		onion := string(onionKey)

		// Add the contact if we don't already have it
		conversationInfo, _ := cp.FetchConversationInfo(onion)
		if conversationInfo == nil {
			cp.mutex.Lock()
			// Create a new conversation but do **not** push an event out.
			_, err := cp.storage.NewConversation(onion, map[string]string{}, model.AccessControlList{onion: model.DefaultP2PAccessControl()}, true)
			cp.mutex.Unlock()
			if err != nil {
				return "", err
			}
		}

		conversationInfo, err = cp.FetchConversationInfo(onion)
		if conversationInfo != nil && err == nil {
			ab := keyBundle.AttributeBundle()
			for k, v := range ab {
				val, exists := conversationInfo.Attributes[k]
				if exists {
					if val != v {
						// the keybundle is inconsistent!
						return "", model.InconsistentKeyBundleError
					}
				}
				// we haven't seen this key associated with the server before
			}

			//    // If we have gotten to this point we can assume this is a safe key bundle signed by the
			//    // server with no conflicting keys. So we are going to save all the keys
			for k, v := range ab {
				cp.SetConversationAttribute(conversationInfo.ID, attr.PublicScope.ConstructScopedZonedPath(attr.ServerKeyZone.ConstructZonedPath(k)), v)
			}
			cp.SetConversationAttribute(conversationInfo.ID, attr.PublicScope.ConstructScopedZonedPath(attr.ServerKeyZone.ConstructZonedPath(string(model.BundleType))), serverSpecification)
			cp.JoinServer(onion)
			return onion, err
		}
		return "", err
	}
	return "", model.InconsistentKeyBundleError
}

// GetServers returns an unordered list of server handles
func (cp *cwtchPeer) GetServers() []string {
	var servers []string
	conversations, err := cp.FetchConversations()
	if err == nil {
		for _, conversationInfo := range conversations {
			if conversationInfo.IsServer() {
				servers = append(servers, conversationInfo.Handle)
			}
		}
	}
	return servers
}

// GetOnion
// Status: Deprecated in 1.5
func (cp *cwtchPeer) GetOnion() string {
	cp.mutex.Lock()
	defer cp.mutex.Unlock()
	onion, _ := cp.storage.LoadProfileKeyValue(TypeAttribute, attr.PublicScope.ConstructScopedZonedPath(attr.ProfileZone.ConstructZonedPath(constants.Onion)).ToString())
	return string(onion)
}

// GetPeerState
// Status: Ready for 1.5
func (cp *cwtchPeer) GetPeerState(handle string) connections.ConnectionState {
	cp.mutex.Lock()
	defer cp.mutex.Unlock()
	if state, ok := cp.state[handle]; ok {
		return state
	}
	return connections.DISCONNECTED
}

// PeerWithOnion initiates a request to the Protocol Engine to set up Cwtch Session with a given tor v3 onion
// address.
func (cp *cwtchPeer) PeerWithOnion(onion string) {
	lastSeen := event.CwtchEpoch
	ci, err := cp.FetchConversationInfo(onion)
	if err == nil {
		lastSeen = cp.GetConversationLastSeenTime(ci.ID)
	}
	cp.eventBus.Publish(event.NewEvent(event.PeerRequest, map[event.Field]string{event.RemotePeer: onion, event.LastSeen: lastSeen.Format(time.RFC3339Nano)}))
}

// QueuePeeringWithOnion sends the request to peer with an onion directly to the contact retry queue; this is a mechanism to not flood tor with circuit requests
// Status: Ready for 1.10
func (cp *cwtchPeer) QueuePeeringWithOnion(handle string) {
	lastSeen := event.CwtchEpoch
	ci, err := cp.FetchConversationInfo(handle)
	if err == nil {
		lastSeen = cp.GetConversationLastSeenTime(ci.ID)
	}
	if !ci.ACL[ci.Handle].Blocked && ci.Accepted {
		cp.eventBus.Publish(event.NewEvent(event.QueuePeerRequest, map[event.Field]string{event.RemotePeer: handle, event.LastSeen: lastSeen.Format(time.RFC3339Nano)}))
	}
}

// QueueJoinServer sends the request to join a server directly to the contact retry queue; this is a mechanism to not flood tor with circuit requests
// Status: Ready for 1.10
func (cp *cwtchPeer) QueueJoinServer(handle string) {
	lastSeen := event.CwtchEpoch
	ci, err := cp.FetchConversationInfo(handle)
	if err == nil {
		lastSeen = cp.GetConversationLastSeenTime(ci.ID)
	}
	cp.eventBus.Publish(event.NewEvent(event.QueueJoinServer, map[event.Field]string{event.GroupServer: handle, event.LastSeen: lastSeen.Format(time.RFC3339Nano)}))
}

// SendInviteToConversation kicks off the invite process
func (cp *cwtchPeer) SendInviteToConversation(conversationID int, inviteConversationID int) (int, error) {
	var invite model.MessageWrapper

	inviteConversationInfo, err := cp.GetConversationInfo(inviteConversationID)

	if inviteConversationInfo == nil || err != nil {
		return -1, err
	}

	if tor.IsValidHostname(inviteConversationInfo.Handle) {
		invite = model.MessageWrapper{Overlay: model.OverlayInviteContact, Data: inviteConversationInfo.Handle}
	} else {
		// Reconstruct Group
		groupID, ok := inviteConversationInfo.Attributes[attr.LocalScope.ConstructScopedZonedPath(attr.LegacyGroupZone.ConstructZonedPath(constants.GroupID)).ToString()]
		if !ok {
			return -1, errors.New("group structure is malformed - no id")
		}
		groupServer, ok := inviteConversationInfo.Attributes[attr.LocalScope.ConstructScopedZonedPath(attr.LegacyGroupZone.ConstructZonedPath(constants.GroupServer)).ToString()]
		if !ok {
			return -1, errors.New("group structure is malformed - no server")
		}
		groupKeyBase64, ok := inviteConversationInfo.Attributes[attr.LocalScope.ConstructScopedZonedPath(attr.LegacyGroupZone.ConstructZonedPath(constants.GroupKey)).ToString()]
		if !ok {
			return -1, errors.New("group structure is malformed - no key")
		}
		groupName, ok := inviteConversationInfo.Attributes[attr.LocalScope.ConstructScopedZonedPath(attr.ProfileZone.ConstructZonedPath(constants.Name)).ToString()]
		if !ok {
			return -1, errors.New("group structure is malformed - no name")
		}

		groupKey, err := base64.StdEncoding.DecodeString(groupKeyBase64)
		if err != nil {
			return -1, errors.New("malformed group key")
		}

		var groupKeyFixed = [32]byte{}
		copy(groupKeyFixed[:], groupKey[:])

		group := model.Group{
			GroupID:     groupID,
			GroupName:   groupName,
			GroupKey:    groupKeyFixed,
			GroupServer: groupServer,
		}

		groupInvite, err := group.Invite()
		if err != nil {
			return -1, errors.New("group invite is malformed")
		}

		serverInfo, err := cp.FetchConversationInfo(groupServer)
		if err != nil {
			return -1, errors.New("unknown server associated with group")
		}

		bundle, exists := serverInfo.Attributes[attr.PublicScope.ConstructScopedZonedPath(attr.ServerKeyZone.ConstructZonedPath(string(model.BundleType))).ToString()]
		if !exists {
			return -1, errors.New("server bundle not found")
		}

		invite = model.MessageWrapper{Overlay: model.OverlayInviteGroup, Data: fmt.Sprintf("tofubundle:server:%s||%s", base64.StdEncoding.EncodeToString([]byte(bundle)), groupInvite)}
	}

	inviteBytes, err := json.Marshal(invite)
	if err != nil {
		log.Errorf("malformed invite: %v", err)
		return -1, err
	}
	return cp.SendMessage(conversationID, string(inviteBytes))
}

func (cp *cwtchPeer) ImportBundle(importString string) error {
	if strings.HasPrefix(importString, constants.TofuBundlePrefix) {
		bundle := strings.Split(importString, "||")
		if len(bundle) == 2 {
			err := cp.ImportBundle(bundle[0][len(constants.TofuBundlePrefix):])
			// if the server import failed then abort the whole process..
			if err != nil && !strings.HasSuffix(err.Error(), "success") {
				return ConstructResponse(constants.ImportBundlePrefix, err.Error())
			}
			return cp.ImportBundle(bundle[1])
		}
	} else if strings.HasPrefix(importString, constants.ServerPrefix) {
		// Server Key Bundles are prefixed with
		bundle, err := base64.StdEncoding.DecodeString(importString[len(constants.ServerPrefix):])
		if err == nil {
			if _, err = cp.AddServer(string(bundle)); err != nil {
				return ConstructResponse(constants.ImportBundlePrefix, err.Error())
			}
			return ConstructResponse(constants.ImportBundlePrefix, "success")
		}
		return ConstructResponse(constants.ImportBundlePrefix, err.Error())
	} else if strings.HasPrefix(importString, constants.GroupPrefix) {
		//eg: torv3JFDWkXExBsZLkjvfkkuAxHsiLGZBk0bvoeJID9ItYnU=EsEBCiBhOWJhZDU1OTQ0NWI3YmM2N2YxYTM5YjkzMTNmNTczNRIgpHeNaG+6jy750eDhwLO39UX4f2xs0irK/M3P6mDSYQIaOTJjM2ttb29ibnlnaGoyenc2cHd2N2Q1N3l6bGQ3NTNhdW8zdWdhdWV6enB2ZmFrM2FoYzRiZHlkCiJAdVSSVgsksceIfHe41OJu9ZFHO8Kwv3G6F5OK3Hw4qZ6hn6SiZjtmJlJezoBH0voZlCahOU7jCOg+dsENndZxAA==
		if _, err := cp.ImportGroup(importString); err != nil {
			return ConstructResponse(constants.ImportBundlePrefix, err.Error())
		}
		return ConstructResponse(constants.ImportBundlePrefix, "success")
	} else if tor.IsValidHostname(importString) {
		_, err := cp.NewContactConversation(importString, model.DefaultP2PAccessControl(), true)
		if err == nil {
			// Assuming all is good, we should peer with this contact.
			cp.PeerWithOnion(importString)
			return ConstructResponse(constants.ImportBundlePrefix, "success")
		}
		return ConstructResponse(constants.ImportBundlePrefix, err.Error())
	}
	return ConstructResponse(constants.ImportBundlePrefix, "invalid_group_invite_prefix")
}

// JoinServer manages a new server connection with the given onion address
func (cp *cwtchPeer) JoinServer(onion string) error {
	ci, err := cp.FetchConversationInfo(onion)
	if ci == nil || err != nil {
		return errors.New("no keys found for server connection")
	}

	//if cp.GetContact(onion) != nil {
	tokenY, yExists := ci.Attributes[attr.PublicScope.ConstructScopedZonedPath(attr.ServerKeyZone.ConstructZonedPath(string(model.KeyTypePrivacyPass))).ToString()]
	tokenOnion, onionExists := ci.Attributes[attr.PublicScope.ConstructScopedZonedPath(attr.ServerKeyZone.ConstructZonedPath(string(model.KeyTypeTokenOnion))).ToString()]
	if yExists && onionExists {
		signature, exists := ci.Attributes[attr.LocalScope.ConstructScopedZonedPath(attr.ProfileZone.ConstructZonedPath(lastReceivedSignature)).ToString()]
		if !exists {
			signature = base64.StdEncoding.EncodeToString([]byte{})
		}
		cachedTokensJson, hasCachedTokens := ci.GetAttribute(attr.LocalScope, attr.ServerZone, "tokens")
		if hasCachedTokens {
			log.Debugf("using cached tokens for %v", ci.Handle)
		}

		cp.eventBus.Publish(event.NewEvent(event.JoinServer, map[event.Field]string{event.GroupServer: onion, event.ServerTokenY: tokenY, event.ServerTokenOnion: tokenOnion, event.Signature: signature, event.CachedTokens: cachedTokensJson}))
		return nil
	}
	return errors.New("no keys found for server connection")
}

// MakeAntispamPayment allows a peer to retrigger antispam, important if the initial connection somehow fails...
// TODO in the future we might want to expose this in CwtchPeer interface
// Additionally we may want to add extra checks here to deduplicate groups from tokenservers to cut down
// on the number of events (right now it should be minimal)
func (cp *cwtchPeer) MakeAntispamPayment(server string) {
	cp.eventBus.Publish(event.NewEvent(event.MakeAntispamPayment, map[event.Field]string{event.GroupServer: server}))
}

// ResyncServer completely tears down and resyncs a new server connection with the given handle
func (cp *cwtchPeer) ResyncServer(handle string) error {
	ci, err := cp.FetchConversationInfo(handle)
	if ci == nil || err != nil {
		return errors.New("no keys found for server connection")
	}

	// delete lastReceivedSignature - this will cause JoinServer to issue a resync
	cp.SetConversationAttribute(ci.ID, attr.LocalScope.ConstructScopedZonedPath(attr.ProfileZone.ConstructZonedPath(lastReceivedSignature)), base64.StdEncoding.EncodeToString([]byte{}))

	// send an explicit leave server event...
	leaveServerEvent := event.NewEventList(event.LeaveServer, event.GroupServer, handle)
	cp.eventBus.Publish(leaveServerEvent)

	// rejoin the server
	return cp.JoinServer(handle)
}

// SendGetValToPeer
// Status: Ready for 1.5
func (cp *cwtchPeer) SendGetValToPeer(onion string, scope string, path string) {
	ev := event.NewEventList(event.SendGetValMessageToPeer, event.RemotePeer, onion, event.Scope, scope, event.Path, path)
	cp.eventBus.Publish(ev)
}

// Listen makes the peer open a listening port to accept incoming connections (and be detectably online)
// Status: Ready for 1.5
func (cp *cwtchPeer) Listen() {
	cp.mutex.Lock()
	defer cp.mutex.Unlock()
	if !cp.listenStatus {
		log.Debugf("cwtchPeer Listen sending ProtocolEngineStartListen\n")
		cp.listenStatus = true
		onion, _ := cp.storage.LoadProfileKeyValue(TypeAttribute, attr.PublicScope.ConstructScopedZonedPath(attr.ProfileZone.ConstructZonedPath(constants.Onion)).ToString())
		cp.eventBus.Publish(event.NewEvent(event.ProtocolEngineStartListen, map[event.Field]string{event.Onion: string(onion)}))
	}
	// else protocol engine is already listening

}

type LastSeenConversation struct {
	model    *model.Conversation
	lastSeen time.Time
}

func (cp *cwtchPeer) GetConversationLastSeenTime(conversationId int) time.Time {
	lastTime := event.CwtchEpoch

	timestamp, err := cp.GetConversationAttribute(conversationId, attr.LocalScope.ConstructScopedZonedPath(attr.ProfileZone.ConstructZonedPath(constants.AttrLastConnectionTime)))
	if err == nil {
		if time, err := time.Parse(time.RFC3339Nano, timestamp); err == nil {
			lastTime = time
		}
	}

	// for peers
	lastMessage, _ := cp.GetMostRecentMessages(conversationId, 0, 0, 1)
	if len(lastMessage) != 0 {
		lastMsgTime, err := time.Parse(time.RFC3339Nano, lastMessage[0].Attr[constants.AttrSentTimestamp])
		if err == nil {
			if lastMsgTime.After(lastTime) {
				lastTime = lastMsgTime
			}
		}
	}

	// for servers
	recentTimeStr, err := cp.GetConversationAttribute(conversationId, attr.LocalScope.ConstructScopedZonedPath(attr.LegacyGroupZone.ConstructZonedPath(constants.SyncMostRecentMessageTime)))
	if err == nil {
		if recentTime, err := time.Parse(time.RFC3339Nano, recentTimeStr); err == nil && recentTime.After(lastTime) {
			lastTime = recentTime
		}
	}

	return lastTime
}

func (cp *cwtchPeer) getConnectionsSortedByLastSeen(doPeers, doServers bool) []*LastSeenConversation {
	conversations, _ := cp.FetchConversations()
	byRecent := []*LastSeenConversation{}

	for _, conversation := range conversations {
		if !conversation.IsGroup() {
			if conversation.IsServer() {
				if !doServers {
					continue
				}
			} else {
				if !doPeers || !conversation.Accepted {
					continue
				}
			}
			byRecent = append(byRecent, &LastSeenConversation{conversation, cp.GetConversationLastSeenTime(conversation.ID)})
		}
	}
	sort.Slice(byRecent, func(i, j int) bool {
		return byRecent[i].lastSeen.After(byRecent[j].lastSeen)
	})
	return byRecent
}

func (cp *cwtchPeer) StartConnections(doPeers, doServers bool) {
	byRecent := cp.getConnectionsSortedByLastSeen(doPeers, doServers)
	log.Infof("StartConnections for %v", cp.GetOnion())
	for _, conversation := range byRecent {
		if conversation.model.IsServer() {
			log.Debugf("  QueueJoinServer(%v)", conversation.model.Handle)
			cp.QueueJoinServer(conversation.model.Handle)
		} else {
			log.Debugf("  QueuePeerWithOnion(%v)", conversation.model.Handle)
			cp.QueuePeeringWithOnion(conversation.model.Handle)
		}
		time.Sleep(50 * time.Millisecond)
	}
}

// StartPeersConnections attempts to connect to peer connections
// Status: Ready for 1.5
// Deprecated: for 1.10 use StartConnections
func (cp *cwtchPeer) StartPeersConnections() {
	log.Infof("StartPeerConnections")

	byRecent := cp.getConnectionsSortedByLastSeen(true, false)

	for _, conversation := range byRecent {
		log.Debugf("  QueuePeerWithOnion(%v)", conversation.model.Handle)
		cp.QueuePeeringWithOnion(conversation.model.Handle)
	}
}

// StartServerConnections attempts to connect to all server connections
// Status: Ready for 1.5
// Deprecated: for 1.10 use StartConnections
func (cp *cwtchPeer) StartServerConnections() {
	log.Infof("StartServerConections")
	byRecent := cp.getConnectionsSortedByLastSeen(false, true)

	for _, conversation := range byRecent {
		if conversation.model.IsServer() {
			log.Debugf("  QueueJoinServer(%v)", conversation.model.Handle)
			cp.QueueJoinServer(conversation.model.Handle)
		}
	}
}

// Shutdown kills all connections and cleans up all goroutines for the peer
// Status: Ready for 1.5
func (cp *cwtchPeer) Shutdown() {
	cp.mutex.Lock()
	defer cp.mutex.Unlock()
	// don't allow this to be shutdown twice...
	if !cp.shutdown {
		cp.shutdown = true
		cp.queue.Shutdown()
		if cp.storage != nil {
			cp.storage.Close(true)
		}
	}
}

func (cp *cwtchPeer) storeMessage(handle string, message string, sent time.Time) (int, error) {
	// TODO maybe atomize this?
	ci, err := cp.FetchConversationInfo(handle)
	if err != nil {
		id, err := cp.NewContactConversation(handle, model.DefaultP2PAccessControl(), false)
		if err != nil {
			return -1, err
		}
		ci, err = cp.GetConversationInfo(id)
		if err != nil {
			return -1, err
		}
	}

	// Generate a random number and use it as the signature
	signature := event.GetRandNumber().String()
	return cp.storage.InsertMessage(ci.ID, 0, message, model.Attributes{constants.AttrAuthor: handle, constants.AttrAck: event.True, constants.AttrSentTimestamp: sent.Format(time.RFC3339Nano)}, signature, model.CalculateContentHash(handle, message))
}

// ShareFile begins hosting the given serialized manifest
func (cp *cwtchPeer) ShareFile(fileKey string, serializedManifest string) {
	tsStr, exists := cp.GetScopedZonedAttribute(attr.LocalScope, attr.FilesharingZone, fmt.Sprintf("%s.ts", fileKey))
	if exists {
		ts, err := strconv.ParseInt(tsStr, 10, 64)
		if err != nil || ts < time.Now().Unix()-2592000 {
			log.Errorf("ignoring request to download a file offered more than 30 days ago")
			return
		}
	}
	// set the filekey status to active
	cp.SetScopedZonedAttribute(attr.LocalScope, attr.FilesharingZone, fmt.Sprintf("%s.active", fileKey), constants.True)
	cp.eventBus.Publish(event.NewEvent(event.ShareManifest, map[event.Field]string{event.FileKey: fileKey, event.SerializedManifest: serializedManifest}))
}

// StopFileShare sends a message to the ProtocolEngine to cease sharing a particular file
func (cp *cwtchPeer) StopFileShare(fileKey string) {
	// set the filekey status to inactive
	cp.SetScopedZonedAttribute(attr.LocalScope, attr.FilesharingZone, fmt.Sprintf("%s.active", fileKey), constants.False)
	cp.eventBus.Publish(event.NewEvent(event.StopFileShare, map[event.Field]string{event.FileKey: fileKey}))
}

// StopAllFileShares sends a message to the ProtocolEngine to cease sharing all files
func (cp *cwtchPeer) StopAllFileShares() {
	cp.eventBus.Publish(event.NewEvent(event.StopAllFileShares, map[event.Field]string{}))
}

// eventHandler process events from other subsystems
func (cp *cwtchPeer) eventHandler() {
	for {
		ev := cp.queue.Next()
		switch ev.EventType {
		/***** Default auto handled events *****/
		case event.ProtocolEngineStopped:
			cp.mutex.Lock()
			cp.listenStatus = false
			onion, _ := cp.storage.LoadProfileKeyValue(TypeAttribute, attr.PublicScope.ConstructScopedZonedPath(attr.ProfileZone.ConstructZonedPath(constants.Onion)).ToString())
			log.Infof("Protocol engine for %s has stopped listening: %v", onion, ev.Data[event.Error])
			cp.mutex.Unlock()
		case event.EncryptedGroupMessage:

			// If successful, a side effect is the message is added to the group's timeline
			ciphertext, _ := base64.StdEncoding.DecodeString(ev.Data[event.Ciphertext])
			signature, _ := base64.StdEncoding.DecodeString(ev.Data[event.Signature])
			log.Debugf("received encrypted group message: %x", ev.Data[event.Signature])
			// SECURITY NOTE: A malicious server could insert posts such that everyone always has a different lastKnownSignature
			// However the server can always replace **all** messages in an attempt to track users
			// This is mitigated somewhat by resync events which do wipe things entire.
			// The security of cwtch groups are also not dependent on the servers inability to uniquely tag connections (as long as
			// it learns nothing else about each connection).
			// store the base64 encoded signature for later use

			// TODO Server Connections should send Connection ID
			ci, err := cp.FetchConversationInfo(ev.Data[event.GroupServer])
			if ci == nil || err != nil {
				log.Errorf("no server connection count")
				return
			}
			cp.SetConversationAttribute(ci.ID, attr.LocalScope.ConstructScopedZonedPath(attr.ProfileZone.ConstructZonedPath(lastReceivedSignature)), ev.Data[event.Signature])
			conversations, err := cp.FetchConversations()
			if err == nil {
				for _, conversationInfo := range conversations {
					if !tor.IsValidHostname(conversationInfo.Handle) {
						group, err := cp.constructGroupFromConversation(conversationInfo)
						if err == nil {
							success, dgm := group.AttemptDecryption(ciphertext, signature)
							if success {
								// Time to either acknowledge the message or insert a new message
								// Re-encode signature to base64
								cp.attemptInsertOrAcknowledgeLegacyGroupConversation(conversationInfo.ID, base64.StdEncoding.EncodeToString(signature), dgm)
								if serverState, exists := cp.state[ev.Data[event.GroupServer]]; exists && serverState == connections.AUTHENTICATED {
									// server is syncing, update it's most recent sync message time
									cp.SetConversationAttribute(ci.ID, attr.LocalScope.ConstructScopedZonedPath(attr.LegacyGroupZone.ConstructZonedPath(constants.SyncMostRecentMessageTime)), time.Unix(int64(dgm.Timestamp), 0).Format(time.RFC3339Nano))
								}
								break
							}
						}
					}
				}
			}
		case event.NewMessageFromPeerEngine: //event.TimestampReceived, event.RemotePeer, event.Data
			ts, _ := time.Parse(time.RFC3339Nano, ev.Data[event.TimestampReceived])
			id, err := cp.storeMessage(ev.Data[event.RemotePeer], ev.Data[event.Data], ts)
			if err == nil {
				// Republish as NewMessageFromPeer
				ev.EventType = event.NewMessageFromPeer
				ev.Data[event.Index] = strconv.Itoa(id)
				ev.Data[event.ContentHash] = model.CalculateContentHash(ev.Data[event.RemotePeer], ev.Data[event.Data])
				cp.eventBus.Publish(ev)
			}
		case event.PeerAcknowledgement:
			err := cp.attemptAcknowledgeP2PConversation(ev.Data[event.RemotePeer], ev.Data[event.EventID])
			if err != nil {
				// Note: This is not an Error because malicious peers can just send acks for random things
				// There is no point in polluting error logs with that mess.
				log.Debugf("failed to acknowledge acknowledgement: %v", err)
			}
		case event.SendMessageToGroupError:
			err := cp.attemptErrorConversationMessage(ev.Data[event.GroupID], ev.Data[event.Signature], ev.Data[event.Error])
			if err != nil {
				log.Errorf("failed to error group message: %s %v", ev.Data[event.GroupID], err)
			}
		case event.SendMessageToPeerError:
			context := ev.Data[event.EventContext]
			if context == string(event.SendMessageToPeer) {
				err := cp.attemptErrorConversationMessage(ev.Data[event.RemotePeer], ev.Data[event.EventID], ev.Data[event.Error])
				if err != nil {
					log.Errorf("failed to error p2p message: %s %v", ev.Data[event.RemotePeer], err)
				}
			}
		case event.RetryServerRequest:
			// Automated Join Server Request triggered by a plugin.
			log.Debugf("profile received an automated retry event for %v", ev.Data[event.GroupServer])
			err := cp.JoinServer(ev.Data[event.GroupServer])
			if err != nil {
				log.Errorf("error joining server... %v", err)
			}
		case event.NewGetValMessageFromPeer:
			onion := ev.Data[event.RemotePeer]
			scope := ev.Data[event.Scope]
			path := ev.Data[event.Path]

			log.Debugf("NewGetValMessageFromPeer for %v.%v from %v\n", scope, path, onion)

			conversationInfo, err := cp.FetchConversationInfo(onion)
			log.Debugf("confo info lookup newgetval %v %v %v", onion, conversationInfo, err)
			if conversationInfo != nil && conversationInfo.Accepted {
				scope := attr.IntoScope(scope)
				if scope.IsPublic() || scope.IsConversation() {
					zone, zpath := attr.ParseZone(path)
					val, exists := cp.GetScopedZonedAttribute(scope, zone, zpath)

					// NOTE: Temporary Override because UI currently wipes names if it can't find them...
					if !exists && zone == attr.UnknownZone && path == constants.Name {
						val, exists = cp.GetScopedZonedAttribute(attr.PublicScope, attr.ProfileZone, constants.Name)
					}

					resp := event.NewEvent(event.SendRetValMessageToPeer, map[event.Field]string{event.ConversationID: strconv.Itoa(conversationInfo.ID), event.RemotePeer: onion, event.Exists: strconv.FormatBool(exists)})
					resp.EventID = ev.EventID
					if exists {
						resp.Data[event.Data] = val
					} else {
						resp.Data[event.Data] = ""
					}
					log.Debugf("Responding with SendRetValMessageToPeer exists:%v data: %v\n", exists, val)

					cp.eventBus.Publish(resp)
				}
			}

		case event.ManifestReceived:
			log.Debugf("Manifest Received Event!: %v", ev)
			handle := ev.Data[event.Handle]
			fileKey := ev.Data[event.FileKey]
			serializedManifest := ev.Data[event.SerializedManifest]

			manifestFilePath, exists := cp.GetScopedZonedAttribute(attr.LocalScope, attr.FilesharingZone, fmt.Sprintf("%v.manifest", fileKey))
			if exists {
				downloadFilePath, exists := cp.GetScopedZonedAttribute(attr.LocalScope, attr.FilesharingZone, fmt.Sprintf("%v.path", fileKey))
				if exists {
					log.Debugf("downloading manifest to %v, file to %v", manifestFilePath, downloadFilePath)
					var manifest files.Manifest
					err := json.Unmarshal([]byte(serializedManifest), &manifest)

					if err == nil {
						// We only need to check the file size here, as manifest is sent to engine and the file created
						// will be bound to the size advertised in manifest.
						fileSizeLimitValue, fileSizeLimitExists := cp.GetScopedZonedAttribute(attr.LocalScope, attr.FilesharingZone, fmt.Sprintf("%v.limit", fileKey))
						if fileSizeLimitExists {
							fileSizeLimit, err := strconv.ParseUint(fileSizeLimitValue, 10, bits.UintSize)
							if err == nil {
								if manifest.FileSizeInBytes >= fileSizeLimit {
									log.Errorf("could not download file, size %v greater than limit %v", manifest.FileSizeInBytes, fileSizeLimitValue)
								} else {
									manifest.Title = manifest.FileName
									manifest.FileName = downloadFilePath
									log.Debugf("saving manifest")
									err = manifest.Save(manifestFilePath)
									if err != nil {
										log.Errorf("could not save manifest: %v", err)
									} else {
										tempFile := ""
										if runtime.GOOS == "android" {
											tempFile = manifestFilePath[0 : len(manifestFilePath)-len(".manifest")]
											log.Debugf("derived android temp path: %v", tempFile)
										}
										cp.eventBus.Publish(event.NewEvent(event.ManifestSaved, map[event.Field]string{
											event.FileKey:            fileKey,
											event.Handle:             handle,
											event.SerializedManifest: string(manifest.Serialize()),
											event.TempFile:           tempFile,
											event.NameSuggestion:     manifest.Title,
										}))
									}
								}
							}
						}
					} else {
						log.Errorf("error saving manifest: %v", err)
					}
				} else {
					log.Errorf("found manifest path but not download path for %v", fileKey)
				}
			} else {
				log.Errorf("no download path found for manifest: %v", fileKey)
			}
		case event.FileDownloaded:
			fileKey := ev.Data[event.FileKey]
			cp.SetScopedZonedAttribute(attr.LocalScope, attr.FilesharingZone, fmt.Sprintf("%s.complete", fileKey), "true")
		case event.NewRetValMessageFromPeer:
			onion := ev.Data[event.RemotePeer]
			scope := ev.Data[event.Scope]
			path := ev.Data[event.Path]
			val := ev.Data[event.Data]
			exists, _ := strconv.ParseBool(ev.Data[event.Exists])
			log.Debugf("NewRetValMessageFromPeer %v %v %v %v %v\n", onion, scope, path, exists, val)
			if exists {

				// Handle File Sharing Metadata
				// TODO This probably should be broken out to it's own code..
				zone, path := attr.ParseZone(path)
				if attr.Scope(scope).IsConversation() && zone == attr.FilesharingZone && strings.HasSuffix(path, ".manifest.size") {
					fileKey := strings.Replace(path, ".manifest.size", "", 1)
					size, err := strconv.Atoi(val)
					// if size is valid and below the maximum size for a manifest
					// this is to prevent malicious sharers from using large amounts of memory when distributing
					// a manifest as we reconstruct this in-memory
					if err == nil && size < files.MaxManifestSize {
						cp.eventBus.Publish(event.NewEvent(event.ManifestSizeReceived, map[event.Field]string{event.FileKey: fileKey, event.ManifestSize: val, event.Handle: onion}))
					} else {
						cp.eventBus.Publish(event.NewEvent(event.ManifestError, map[event.Field]string{event.FileKey: fileKey, event.Handle: onion}))
					}
				}

				// Allow public profile parameters to be added as peer specific attributes...
				if attr.Scope(scope).IsPublic() && zone == attr.ProfileZone {
					ci, err := cp.FetchConversationInfo(onion)
					log.Debugf("fetch conversation info %v %v", ci, err)
					if ci != nil && err == nil {
						err := cp.SetConversationAttribute(ci.ID, attr.Scope(scope).ConstructScopedZonedPath(zone.ConstructZonedPath(path)), val)
						if err != nil {
							log.Errorf("error setting conversation attribute %v", err)
						}
					}
				}
			}
		case event.PeerStateChange:
			handle := ev.Data[event.RemotePeer]
			if connections.ConnectionStateToType()[ev.Data[event.ConnectionState]] == connections.AUTHENTICATED {
				ci, err := cp.FetchConversationInfo(handle)
				var cid int
				if err != nil {
					// if it's a newly authenticated connection with no conversation storage, init
					cid, _ = cp.NewContactConversation(handle, model.DefaultP2PAccessControl(), false)
				} else {
					cid = ci.ID
				}

				timestamp := time.Now().Format(time.RFC3339Nano)
				cp.SetConversationAttribute(cid, attr.LocalScope.ConstructScopedZonedPath(attr.ProfileZone.ConstructZonedPath(constants.AttrLastConnectionTime)), timestamp)
			} else if connections.ConnectionStateToType()[ev.Data[event.ConnectionState]] == connections.DISCONNECTED {
				ci, err := cp.FetchConversationInfo(handle)
				if err == nil {
					cp.mutex.Lock()
					if cp.state[ev.Data[event.RemotePeer]] == connections.AUTHENTICATED {
						// If peer went offline, set last seen time to now
						timestamp := time.Now().Format(time.RFC3339Nano)
						cp.SetConversationAttribute(ci.ID, attr.LocalScope.ConstructScopedZonedPath(attr.ProfileZone.ConstructZonedPath(constants.AttrLastConnectionTime)), timestamp)
					}
					cp.mutex.Unlock()
				}
			}
			cp.mutex.Lock()
			cp.state[ev.Data[event.RemotePeer]] = connections.ConnectionStateToType()[ev.Data[event.ConnectionState]]
			cp.mutex.Unlock()
		case event.ServerStateChange:
			cp.mutex.Lock()
			prevState := cp.state[ev.Data[event.GroupServer]]
			state := connections.ConnectionStateToType()[ev.Data[event.ConnectionState]]
			cp.state[ev.Data[event.GroupServer]] = state
			cp.mutex.Unlock()

			// If starting to sync, determine last message from known groups on server so we can calculate sync progress
			if state == connections.AUTHENTICATED {
				conversations, err := cp.FetchConversations()
				mostRecentTime := event.CwtchEpoch
				if err == nil {
					for _, conversationInfo := range conversations {
						if server, exists := conversationInfo.GetAttribute(attr.LocalScope, attr.LegacyGroupZone, constants.GroupServer); exists && server == ev.Data[event.GroupServer] {
							lastMessage, _ := cp.GetMostRecentMessages(conversationInfo.ID, 0, 0, 1)
							if len(lastMessage) == 0 {
								continue
							}
							lastGroupMsgTime, err := time.Parse(time.RFC3339Nano, lastMessage[0].Attr[constants.AttrSentTimestamp])
							if err != nil {
								continue
							}
							if lastGroupMsgTime.After(mostRecentTime) {
								mostRecentTime = lastGroupMsgTime
							}
						}
					}
				}
				serverInfo, err := cp.FetchConversationInfo(ev.Data[event.GroupServer])
				if err == nil {
					cp.SetConversationAttribute(serverInfo.ID, attr.LocalScope.ConstructScopedZonedPath(attr.LegacyGroupZone.ConstructZonedPath(constants.SyncPreLastMessageTime)), mostRecentTime.Format(time.RFC3339Nano))
					cp.SetConversationAttribute(serverInfo.ID, attr.LocalScope.ConstructScopedZonedPath(attr.LegacyGroupZone.ConstructZonedPath(constants.SyncMostRecentMessageTime)), mostRecentTime.Format(time.RFC3339Nano))

					if connections.ConnectionStateToType()[ev.Data[event.ConnectionState]] == connections.AUTHENTICATED {
						timestamp := time.Now().Format(time.RFC3339Nano)
						cp.SetConversationAttribute(serverInfo.ID, attr.LocalScope.ConstructScopedZonedPath(attr.ProfileZone.ConstructZonedPath(constants.AttrLastConnectionTime)), timestamp)
					} else if connections.ConnectionStateToType()[ev.Data[event.ConnectionState]] == connections.DISCONNECTED && prevState == connections.AUTHENTICATED {
						// If peer went offline, set last seen time to now
						timestamp := time.Now().Format(time.RFC3339Nano)
						cp.SetConversationAttribute(serverInfo.ID, attr.LocalScope.ConstructScopedZonedPath(attr.ProfileZone.ConstructZonedPath(constants.AttrLastConnectionTime)), timestamp)
					}
				}
			}
		case event.TriggerAntispamCheck:
			conversations, _ := cp.FetchConversations()
			for _, conversation := range conversations {
				if conversation.IsServer() {
					cp.MakeAntispamPayment(conversation.Handle)
				}
			}
		default:
			if ev.EventType != "" {
				log.Errorf("peer event handler received an event it was not subscribed for: %v", ev.EventType)
			}
			return
		}
	}
}

// attemptInsertOrAcknowledgeLegacyGroupConversation is a convenience method that looks up the conversation
// by the given handle and attempts to mark the message as acknowledged. returns error on failure
// to either find the contact or the associated message
func (cp *cwtchPeer) attemptInsertOrAcknowledgeLegacyGroupConversation(conversationID int, signature string, dm *groups.DecryptedGroupMessage) error {
	log.Debugf("attempting to insert or ack group message %v %v", conversationID, signature)
	messageID, err := cp.GetChannelMessageBySignature(conversationID, 0, signature)
	// We have received our own message (probably), acknowledge and move on...
	if err == nil {
		_, attr, err := cp.GetChannelMessage(conversationID, 0, messageID)
		if err == nil && attr[constants.AttrAck] != constants.True {
			cp.mutex.Lock()
			attr[constants.AttrAck] = constants.True
			cp.mutex.Unlock()
			cp.storage.UpdateMessageAttributes(conversationID, 0, messageID, attr)
			cp.eventBus.Publish(event.NewEvent(event.IndexedAcknowledgement, map[event.Field]string{event.ConversationID: strconv.Itoa(conversationID), event.Index: strconv.Itoa(messageID)}))
			return nil
		}
	} else {
		contenthash := model.CalculateContentHash(dm.Onion, dm.Text)
		id, err := cp.storage.InsertMessage(conversationID, 0, dm.Text, model.Attributes{constants.AttrAck: constants.True, "PreviousSignature": base64.StdEncoding.EncodeToString(dm.PreviousMessageSig), constants.AttrAuthor: dm.Onion, constants.AttrSentTimestamp: time.Unix(int64(dm.Timestamp), 0).Format(time.RFC3339Nano)}, signature, contenthash)
		if err == nil {
			cp.eventBus.Publish(event.NewEvent(event.NewMessageFromGroup, map[event.Field]string{event.ConversationID: strconv.Itoa(conversationID), event.TimestampSent: time.Unix(int64(dm.Timestamp), 0).Format(time.RFC3339Nano), event.RemotePeer: dm.Onion, event.Index: strconv.Itoa(id), event.Data: dm.Text, event.ContentHash: contenthash}))
		}
		return err
	}
	return err
}

// attemptAcknowledgeP2PConversation is a convenience method that looks up the conversation
// by the given handle and attempts to mark the message as acknowledged. returns error on failure
// to either find the contact or the associated message
func (cp *cwtchPeer) attemptAcknowledgeP2PConversation(handle string, signature string) error {
	ci, err := cp.FetchConversationInfo(handle)
	// We should *never* received a peer acknowledgement for a conversation that doesn't exist...
	if ci != nil && err == nil {
		// for p2p messages the randomly generated event ID is the "signature"
		id, err := cp.GetChannelMessageBySignature(ci.ID, 0, signature)
		if err == nil {
			_, attr, err := cp.GetChannelMessage(ci.ID, 0, id)
			if err == nil {
				cp.mutex.Lock()
				attr[constants.AttrAck] = constants.True
				cp.mutex.Unlock()
				cp.storage.UpdateMessageAttributes(ci.ID, 0, id, attr)
				cp.eventBus.Publish(event.NewEvent(event.IndexedAcknowledgement, map[event.Field]string{event.ConversationID: strconv.Itoa(ci.ID), event.RemotePeer: handle, event.Index: strconv.Itoa(id)}))
				return nil
			}
			return err
		}
		return err
	}
	return err
}

// attemptErrorConversationMessage is a convenience method that looks up the conversation
// by the given handle and attempts to mark the message as errored. returns error on failure
// to either find the contact or the associated message
func (cp *cwtchPeer) attemptErrorConversationMessage(handle string, signature string, error string) error {

	ci, err := cp.FetchConversationInfo(handle)
	// We should *never* received an error for a conversation that doesn't exist...
	if ci != nil && err == nil {
		// "signature" here is event ID for peer messages...
		id, err := cp.GetChannelMessageBySignature(ci.ID, 0, signature)
		if err == nil {
			_, attr, err := cp.GetChannelMessage(ci.ID, 0, id)
			if err == nil {
				cp.mutex.Lock()
				attr[constants.AttrErr] = constants.True
				cp.storage.UpdateMessageAttributes(ci.ID, 0, id, attr)
				cp.mutex.Unlock()
				// Send a generic indexed failure...
				cp.eventBus.Publish(event.NewEvent(event.IndexedFailure, map[event.Field]string{event.ConversationID: strconv.Itoa(ci.ID), event.Handle: handle, event.Error: error, event.Index: strconv.Itoa(id)}))
				return nil
			}
			return err
		}
		return err
	}
	return err
}

func (cp *cwtchPeer) GetChannelMessageBySignature(conversationID int, channelID int, signature string) (int, error) {
	return cp.storage.GetChannelMessageBySignature(conversationID, channelID, signature)
}

func (cp *cwtchPeer) GetChannelMessageByContentHash(conversationID int, channelID int, contenthash string) (int, error) {
	messageID, err := cp.storage.GetChannelMessageByContentHash(conversationID, channelID, contenthash)
	if err == nil {
		return cp.storage.GetRowNumberByMessageID(conversationID, channelID, messageID)
	}
	return -1, err
}

// constructGroupFromConversation returns a model.Group wrapper around a database back groups. Useful for
// encrypting / decrypting messages to/from the group.
func (cp *cwtchPeer) constructGroupFromConversation(conversationInfo *model.Conversation) (*model.Group, error) {
	key := conversationInfo.Attributes[attr.LocalScope.ConstructScopedZonedPath(attr.LegacyGroupZone.ConstructZonedPath(constants.GroupKey)).ToString()]
	groupKey, err := base64.StdEncoding.DecodeString(key)
	if err != nil {
		return nil, errors.New("group key is malformed")
	}
	var groupKeyFixed [32]byte
	copy(groupKeyFixed[:], groupKey[:])
	group := model.Group{
		GroupID:     conversationInfo.Handle,
		GroupServer: conversationInfo.Attributes[attr.LocalScope.ConstructScopedZonedPath(attr.LegacyGroupZone.ConstructZonedPath(constants.GroupServer)).ToString()],
		GroupKey:    groupKeyFixed,
	}
	return &group, nil
}
