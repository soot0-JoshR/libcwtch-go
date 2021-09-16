package utils

import (
	"cwtch.im/cwtch/model"
	"cwtch.im/cwtch/model/attr"
	"cwtch.im/cwtch/peer"
	"cwtch.im/cwtch/protocol/connections"
	"errors"
	"git.openprivacy.ca/cwtch.im/libcwtch-go/constants"
	"git.openprivacy.ca/openprivacy/log"
	"strconv"
	"strings"
	"time"
)

type PeerHelper struct {
	peer peer.CwtchPeer
}

func NewPeerHelper(profile peer.CwtchPeer) *PeerHelper {
	return &PeerHelper{profile}
}

func (p *PeerHelper) IsGroup(id string) bool {
	return len(id) == 32 && !p.IsServer(id)
}

func (p *PeerHelper) IsPeer(id string) bool {
	return len(id) == 56 && !p.IsServer(id)
}

// Check if the id is associated with a contact with a KeyTypeServerOnion attribute (which indicates that this
// is a server, not a regular contact or a group
func (p *PeerHelper) IsServer(id string) bool {
	_, ok := p.peer.GetContactAttribute(id, string(model.KeyTypeServerOnion))
	return ok
}

// GetTimeline returns a pointer to the timeline associated with the conversation handle or nil if the handle
// does not exist (this can happen if the conversation has been deleted)
func (p *PeerHelper) GetTimeline(handle string) *model.Timeline {
	if p.IsServer(handle) {
		// This should *never* happen
		log.Errorf("server accessed as contact when getting timeline...")
		return &model.Timeline{}
	}
	// We return a pointer to the timeline to avoid copying, accessing Timeline is thread-safe
	if p.IsGroup(handle) {
		group :=  p.peer.GetGroup(handle)
		if group == nil {
			return nil
		}
		return &group.Timeline
	}
	contact :=  p.peer.GetContact(handle)
	if contact == nil {
		return nil
	}
	return &contact.Timeline
}

/*
func getOrDefault(id, key string, defaultVal string) string {
	var val string
	var ok bool
	if IsGroup(id) {
		val, ok = the.Peer.GetGroupAttribute(id, key)
	} else {
		val, ok = the.Peer.GetContactAttribute(id, key)
	}
	if ok {
		return val
	} else {
		return defaultVal
	}
}*/

func (p *PeerHelper) GetWithSetDefault(id string, key string, defaultVal string) string {
	var val string
	var ok bool
	if p.IsGroup(id) {
		val, ok = p.peer.GetGroupAttribute(id, key)
	} else {
		val, ok = p.peer.GetContactAttribute(id, key)
	}
	if !ok {
		val = defaultVal
		if p.IsGroup(id) {
			p.peer.SetGroupAttribute(id, key, defaultVal)
		} else {
			p.peer.SetContactAttribute(id, key, defaultVal)
		}
	}
	return val
}

func (p *PeerHelper) GetNick(id string) string {
	if p.IsGroup(id) {
		nick, exists := p.peer.GetGroupAttribute(id, attr.GetLocalScope(constants.Name))
		if !exists || nick == "" || nick == id {
			nick, exists = p.peer.GetGroupAttribute(id, attr.GetPeerScope(constants.Name))
			if !exists {
				nick = "[" + id + "]"
			}
		}
		return nick
	} else {
		nick, exists := p.peer.GetContactAttribute(id, attr.GetLocalScope(constants.Name))
		if !exists || nick == "" || nick == id {
			nick, exists = p.peer.GetContactAttribute(id, attr.GetPeerScope(constants.Name))
			if !exists {
				nick = "[" + id + "]"
				// re-request
				p.peer.SendGetValToPeer(id, attr.PublicScope, constants.Name)
			}
		}
		return nick
	}
}

// InitLastReadTime checks and gets the Attributable's LastRead time or sets it to now
func (p *PeerHelper) InitLastReadTime(id string) time.Time {
	nowStr, _ := time.Now().MarshalText()
	lastReadAttr := p.GetWithSetDefault(id, attr.GetLocalScope(constants.LastRead), string(nowStr))
	var lastRead time.Time
	lastRead.UnmarshalText([]byte(lastReadAttr))
	return lastRead
}

// GetProfilePic returns a string path to an image to display for hte given peer/group id
func (p *PeerHelper) GetProfilePic(id string) string {
	if p.IsGroup(id) {
		if picVal, exists := p.peer.GetGroupAttribute(id, attr.GetLocalScope(constants.Picture)); exists {
			pic, err := StringToImage(picVal)
			if err == nil {
				return GetPicturePath(pic)
			}
		}
		if picVal, exists := p.peer.GetGroupAttribute(id, attr.GetPeerScope(constants.Picture)); exists {
			pic, err := StringToImage(picVal)
			if err == nil {
				return GetPicturePath(pic)
			}
		}
		return GetPicturePath(NewImage(RandomGroupImage(id), TypeImageDistro))

	} else {
		if picVal, exists := p.peer.GetContactAttribute(id, attr.GetLocalScope(constants.Picture)); exists {
			pic, err := StringToImage(picVal)
			if err == nil {
				return GetPicturePath(pic)
			}
		}
		if picVal, exists := p.peer.GetContactAttribute(id, attr.GetPeerScope(constants.Picture)); exists {
			pic, err := StringToImage(picVal)
			if err == nil {
				return GetPicturePath(pic)
			}
		}
		return RandomProfileImage(id)
	}
}

// a lot of pics were stored full path + uri. remove all this to the relative path in images/
// fix for storing full paths introduced 2019.12
func profilePicRelativize(filename string) string {
	parts := strings.Split(filename, "qml/images")
	return parts[len(parts)-1]
}

func GetPicturePath(pic *image) string {
	switch pic.T {
	case TypeImageDistro:
		return profilePicRelativize(pic.Val)
	default:
		log.Errorf("Unhandled profile picture type of %v\n", pic.T)
		return ""
	}
}

func (p *PeerHelper) CountUnread(messages []model.Message, lastRead time.Time) int {
	count := 0
	for i := len(messages) - 1; i >= 0; i-- {
		if messages[i].Timestamp.After(lastRead) || messages[i].Timestamp.Equal(lastRead) {
			count++
		} else {
			break
		}
	}
	return count
}

func getLastMessageTime(tl *model.Timeline) int {
	if len(tl.Messages) == 0 {
		return 0
	}

	return int(tl.Messages[len(tl.Messages)-1].Timestamp.Unix())
}

/*
// AddProfile adds a new profile to the UI
func AddProfile(gcd *GrandCentralDispatcher, handle string) {
	p := the.CwtchApp.GetPeer(handle)
	if p != nil {
		nick, exists := p.GetAttribute(attr.GetPublicScope(constants.Name))
		if !exists {
			nick = handle
		}

		picVal, ok := p.GetAttribute(attr.GetPublicScope(constants.Picture))
		if !ok {
			picVal = ImageToString(NewImage(RandomProfileImage(handle), TypeImageDistro))
		}
		pic, err := StringToImage(picVal)
		if err != nil {
			pic = NewImage(RandomProfileImage(handle), TypeImageDistro)
		}
		picPath := getPicturePath(pic)

		tag, _ := p.GetAttribute(app.AttributeTag)

		online, _ := p.GetAttribute(attr.GetLocalScope(constants.PeerOnline))

		log.Debugf("AddProfile %v %v %v %v %v\n", handle, nick, picPath, tag, online)
		gcd.AddProfile(handle, nick, picPath, tag, online == event.True)
	}
}*/
/*
type manager struct {
	gcd     *GrandCentralDispatcher
	profile string
}

// Manager is a middleware helper for entities like peer event listeners wishing to trigger ui changes (via the gcd)
//   each manager is for one profile/peer
//   manager takes minimal arguments and builds the full struct of data (usually pulled from a cwtch peer) required to call the GCD to perform the ui action
//   manager also performs call filtering based on UI state: users of manager can safely always call it on events and not have to worry about weather the relevant ui is active
//   ie: you can always safely call AddMessage even if in the ui a different profile is selected. manager will check with gcd, and if the correct conditions are not met, it will not call on gcd to update the ui incorrectly
type Manager interface {
	Acknowledge(handle, mID string)
	AddContact(Handle string)
	AddSendMessageError(peer string, signature string, err string)
	AddMessage(handle string, from string, message string, fromMe bool, messageID string, timestamp time.Time, Acknowledged bool)

	ReloadProfiles()

	UpdateContactDisplayName(handle string)
	UpdateContactPicture(handle string)
	UpdateContactStatus(handle string, status int, loading bool)
	UpdateContactAttribute(handle, key, value string)

	ChangePasswordResponse(error bool)

	AboutToAddMessage()
	MessageJustAdded()
	StoreAndNotify(peer.CwtchPeer, string, string, time.Time, string)

	UpdateNetworkStatus(online bool)
}

// NewManager returns a new Manager interface for a profile to the gcd
func NewManager(profile string, gcd *GrandCentralDispatcher) Manager {
	return &manager{gcd: gcd, profile: profile}
}


*/
// EnrichNewPeer populates required data for use by frontend
//   uiManager.AddContact(onion)
//   (handle string, displayName string, image string, badge int, status int, authorization string, loading bool, lastMsgTime int)
func EnrichNewPeer(handle string, ph *PeerHelper, ev *EventProfileEnvelope) error {
	if ph.IsGroup(handle) {
		group := ph.peer.GetGroup(handle)
		if group != nil {
			lastRead := ph.InitLastReadTime(group.GroupID)
			ev.Event.Data["unread"] = strconv.Itoa(ph.CountUnread(group.Timeline.GetMessages(), lastRead))
			ev.Event.Data["picture"] = ph.GetProfilePic(handle)
			ev.Event.Data["numMessages"] = strconv.Itoa(group.Timeline.Len())
			ev.Event.Data["nick"] = ph.GetNick(handle)
			ev.Event.Data["status"] = group.State
			ev.Event.Data["authorization"] = string(model.AuthApproved)
			ev.Event.Data["loading"] = "false"
			ev.Event.Data["lastMsgTime"] = strconv.Itoa(getLastMessageTime(&group.Timeline))
		}
	} else if ph.IsPeer(handle) {
		contact := ph.peer.GetContact(handle)
		if contact != nil {
			lastRead := ph.InitLastReadTime(contact.Onion)
			ev.Event.Data["unread"] = strconv.Itoa(ph.CountUnread(contact.Timeline.GetMessages(), lastRead))
			ev.Event.Data["numMessages"] = strconv.Itoa(contact.Timeline.Len())
			ev.Event.Data["picture"] = ph.GetProfilePic(handle)

			ev.Event.Data["nick"] = ph.GetNick(handle)

			// TODO Replace this if with a better flow that separates New Contacts and Peering Updates
			if contact.State == "" {
				// Will be disconnected to start
				ev.Event.Data["status"] = connections.ConnectionStateName[connections.DISCONNECTED]
			} else {
				ev.Event.Data["status"] = contact.State
			}
			ev.Event.Data["authorization"] = string(contact.Authorization)
			ev.Event.Data["loading"] = "false"
			ev.Event.Data["lastMsgTime"] = strconv.Itoa(getLastMessageTime(&contact.Timeline))
		} else {
			log.Errorf("Failed to find contact: %v", handle)
		}
	} else {
		// could be a server?
		log.Debugf("sorry, unable to handle AddContact(%v)", handle)
		return errors.New("not a peer or group")
	}
	return nil
}

/*
// AddSendMessageError adds an error not and icon to a message in a conversation in the ui for the message identified by the peer/sig combo
func (this *manager) AddSendMessageError(peer string, signature string, err string) {
	this.gcd.DoIfProfile(this.profile, func() {
		this.gcd.DoIfConversation(peer, func() {
			log.Debugf("Received Error Sending Message: %v", err)
			// FIXME: Sometimes, for the first Peer message we send our error beats our message to the UI
			time.Sleep(time.Second * 1)
			this.gcd.GroupSendError(signature, err)
		})
	})
}

func (this *manager) AboutToAddMessage() {
	this.gcd.TimelineInterface.AddMessage(this.gcd.TimelineInterface.num())
}

func (this *manager) MessageJustAdded() {
	this.gcd.TimelineInterface.RequestEIR()
}*/

/*
// AddMessage adds a message to the message pane for the supplied conversation if it is active
func (this *manager) AddMessage(handle string, from string, message string, fromMe bool, messageID string, timestamp time.Time, Acknowledged bool) {
	this.gcd.DoIfProfile(this.profile, func() {
		this.gcd.DoIfConversation(handle, func() {
			updateLastReadTime(handle)
			// If the message is not from the user then add it, otherwise, just acknowledge.
			if !fromMe || !Acknowledged {
				this.gcd.TimelineInterface.AddMessage(this.gcd.TimelineInterface.num() - 1)
				this.gcd.TimelineInterface.RequestEIR()
			} else {
				this.gcd.Acknowledged(messageID)
			}
		})
		this.gcd.IncContactUnreadCount(handle)
	})
	if !fromMe {
		this.gcd.Notify(handle)
	}
}

func (this *manager) ReloadProfiles() {
	this.gcd.reloadProfileList()
}

// UpdateContactDisplayName updates a contact's display name in the contact list and conversations
func (this *manager) UpdateContactDisplayName(handle string) {
	this.gcd.DoIfProfile(this.profile, func() {
		this.gcd.UpdateContactDisplayName(handle, GetNick(handle))
	})
}

// UpdateContactPicture updates a contact's picture in the contact list and conversations
func (this *manager) UpdateContactPicture(handle string) {
	this.gcd.DoIfProfile(this.profile, func() {
		this.gcd.UpdateContactPicture(handle, GetProfilePic(handle))
	})
}

// UpdateContactAttribute update's a contacts attribute in the ui
func (this *manager) UpdateContactAttribute(handle, key, value string) {
	this.gcd.DoIfProfile(this.profile, func() {
		this.gcd.UpdateContactAttribute(handle, key, value)
	})
}

func (this *manager) ChangePasswordResponse(error bool) {
	this.gcd.ChangePasswordResponse(error)
}

func (this *manager) UpdateNetworkStatus(online bool) {
	this.gcd.UpdateProfileNetworkStatus(this.profile, online)
}
*/
