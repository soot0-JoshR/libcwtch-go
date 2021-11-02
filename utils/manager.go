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
		group := p.peer.GetGroup(handle)
		if group == nil {
			return nil
		}
		return &group.Timeline
	}
	contact := p.peer.GetContact(handle)
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
				// we do not have a canonical nick for this contact.
				// re-request if authenticated
				// TODO: This check probably doesn't belong here...
				if contact := p.peer.GetContact(id); contact != nil && contact.State == connections.ConnectionStateName[connections.AUTHENTICATED] {
					p.peer.SendScopedZonedGetValToContact(id, attr.PublicScope, attr.ProfileZone, constants.Name)
				}
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