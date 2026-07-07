package cwtchcore

import (
	"cwtch.im/cwtch/app"
	"cwtch.im/cwtch/functionality/filesharing"
	"cwtch.im/cwtch/model"
	"cwtch.im/cwtch/model/attr"
	"cwtch.im/cwtch/peer"
	"cwtch.im/cwtch/protocol/connections"
	"cwtch.im/cwtch/protocol/files"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"git.openprivacy.ca/cwtch.im/libcwtch-go/utils"
	"git.openprivacy.ca/openprivacy/connectivity"
	"git.openprivacy.ca/openprivacy/log"
	"regexp"
	"strings"
	"sync"
)

type AuthorizedBinding struct {
	ProfileOnion         string
	PeerOnion            string
	CwtchConversationID  int32
	StegmsConversationID int32
}

type MediaOffer struct {
	TransferID          string  `json:"transferId"`
	ProfileOnion        string  `json:"profileOnion"`
	PeerOnion           string  `json:"peerOnion"`
	CwtchConversationID int32   `json:"cwtchConversationId"`
	MessageIndex        int32   `json:"messageIndex"`
	SuggestedName       string  `json:"suggestedName"`
	ExpectedSize        int64   `json:"expectedSize"`
	State               string  `json:"state"`
	Progress            float64 `json:"progress"`
	MediaID             string  `json:"mediaId"`
	MimeType            string  `json:"mimeType"`
}

var (
	stateMutex    sync.RWMutex
	Application   app.Application
	EventHandler  *utils.EventHandler
	GlobalTorPath string
	GlobalAppDir  string
	GlobalACN     connectivity.ProxyACN

	authorizedBindings = make(map[string]AuthorizedBinding)
	authMutex          sync.Mutex

	mediaOffersMutex   sync.Mutex
	mediaOffers        = make(map[string]MediaOffer)
	ensureContactMutex sync.Mutex
)

type EnsureContactResult struct {
	Status         string `json:"status"`
	ConversationID int    `json:"conversationId,omitempty"`
	Created        bool   `json:"created"`
	Reason         string `json:"reason,omitempty"`
}

var validOnionAddress = regexp.MustCompile(`^[a-z2-7]{56}$`)

func normalizeOnion(value string) string {
	return strings.TrimSuffix(strings.ToLower(strings.TrimSpace(value)), ".onion")
}

func ensureContactJSON(result EnsureContactResult) string {
	encoded, _ := json.Marshal(result)
	return string(encoded)
}

func EnsureContactForProfile(profile peer.CwtchPeer, profileOnionRaw string, peerOnionRaw string) string {
	ensureContactMutex.Lock()
	defer ensureContactMutex.Unlock()

	profileOnion := normalizeOnion(profileOnionRaw)
	peerOnion := normalizeOnion(peerOnionRaw)
	if !validOnionAddress.MatchString(profileOnion) || !validOnionAddress.MatchString(peerOnion) {
		return ensureContactJSON(EnsureContactResult{Status: "error", Reason: "invalid_onion"})
	}
	if profileOnion == peerOnion {
		return ensureContactJSON(EnsureContactResult{Status: "error", Reason: "self_onion"})
	}

	if conversation, err := profile.FetchConversationInfo(peerOnion); err == nil && conversation != nil {
		if err := profile.AcceptConversation(conversation.ID); err != nil {
			log.Errorf("EnsureContact accept error: %v", err)
			return ensureContactJSON(EnsureContactResult{Status: "error", Reason: "storage_error"})
		}
		return ensureContactJSON(EnsureContactResult{
			Status: "existing", ConversationID: conversation.ID,
		})
	}

	conversationID, err := profile.NewContactConversation(
		peerOnion, model.DefaultP2PAccessControl(), true,
	)
	if err != nil {
		// Another caller or Cwtch event may have created it concurrently.
		if conversation, fetchErr := profile.FetchConversationInfo(peerOnion); fetchErr == nil && conversation != nil {
			return ensureContactJSON(EnsureContactResult{
				Status: "existing", ConversationID: conversation.ID,
			})
		}
		log.Errorf("EnsureContact storage error: %v", err)
		return ensureContactJSON(EnsureContactResult{Status: "error", Reason: "storage_error"})
	}
	// NewContactConversation persists the contact but does not initiate a
	// connection. Match Cwtch's normal contact-import behavior.
	profile.PeerWithOnion(peerOnion)
	return ensureContactJSON(EnsureContactResult{
		Status: "created", ConversationID: conversationID, Created: true,
	})
}

func EnsureContact(profileOnionRaw string, peerOnionRaw string) string {
	stateMutex.RLock()
	defer stateMutex.RUnlock()

	if Application != nil {
		if profile := Application.GetPeer(normalizeOnion(profileOnionRaw)); profile != nil {
			return EnsureContactForProfile(profile, profileOnionRaw, peerOnionRaw)
		}
	}
	return ensureContactJSON(EnsureContactResult{
		Status: "error", Reason: "application_not_initialized",
	})
}

func init() {
	utils.OnFileOfferReceived = func(profileOnion string, peerOnion string, conversationID int, messageIndex int, name string, size int64, fileKey string) {
		mediaOffersMutex.Lock()
		mediaOffers[fileKey] = MediaOffer{
			TransferID:          fileKey,
			ProfileOnion:        profileOnion,
			PeerOnion:           peerOnion,
			CwtchConversationID: int32(conversationID),
			MessageIndex:        int32(messageIndex),
			SuggestedName:       name,
			ExpectedSize:        size,
			State:               "offered",
			Progress:            0.0,
			MimeType:            "application/octet-stream",
		}
		mediaOffersMutex.Unlock()
	}

	utils.OnFileProgressUpdated = func(fileKey string, progress float64, state string) {
		mediaOffersMutex.Lock()
		if offer, exists := mediaOffers[fileKey]; exists {
			offer.State = state
			offer.Progress = progress
			mediaOffers[fileKey] = offer
		}
		mediaOffersMutex.Unlock()
	}
}

func StartCwtch(appDir string, torPath string) int32 {
	stateMutex.Lock()
	defer stateMutex.Unlock()
	return 0
}

func ShutdownCwtch() {
	stateMutex.Lock()
	defer stateMutex.Unlock()
	if Application != nil {
		Application.Shutdown()
		Application = nil
	}

	// Mandatory safeguard: Clear media offers and auth bindings on shutdown
	mediaOffersMutex.Lock()
	mediaOffers = make(map[string]MediaOffer)
	mediaOffersMutex.Unlock()

	authMutex.Lock()
	authorizedBindings = make(map[string]AuthorizedBinding)
	authMutex.Unlock()
}

func CreateProfile(nick string, password string) {
	stateMutex.RLock()
	defer stateMutex.RUnlock()
	if Application != nil {
		Application.CreatePeer(nick, password, map[attr.ZonedPath]string{
			attr.ProfileZone.ConstructZonedPath("tag"):       "v1-password",
			attr.ProfileZone.ConstructZonedPath("autostart"): "true",
		})
	}
}

func LoadProfiles(password string) {
	stateMutex.RLock()
	defer stateMutex.RUnlock()
	if Application != nil {
		Application.LoadProfiles(password)
	}
}

func GetLoadedProfiles() string {
	stateMutex.RLock()
	defer stateMutex.RUnlock()
	if Application != nil {
		profiles := Application.ListProfiles()
		bytes, _ := json.Marshal(profiles)
		return string(bytes)
	}
	return "[]"
}

func SignChallenge(profileOnion string, challenge string) string {
	stateMutex.RLock()
	defer stateMutex.RUnlock()
	if Application != nil {
		profile := Application.GetPeer(profileOnion)
		if profile != nil {
			message := []byte("StegMS-Auth-v1:" + challenge)
			sig, err := profile.SignMessage(message)
			if err == nil {
				return base64.StdEncoding.EncodeToString(sig)
			}
		}
	}
	return ""
}

func GetOnionAddress(profileOnion string) string {
	stateMutex.RLock()
	defer stateMutex.RUnlock()
	if Application != nil {
		profile := Application.GetPeer(profileOnion)
		if profile != nil {
			return profile.GetOnion()
		}
	}
	return ""
}

func SendMessage(profileOnion string, peerOnion string, message string) string {
	stateMutex.RLock()
	defer stateMutex.RUnlock()
	if Application != nil {
		profile := Application.GetPeer(profileOnion)
		if profile != nil {
			conversation, err := profile.FetchConversationInfo(peerOnion)
			if err == nil && conversation != nil {
				if profile.GetPeerState(peerOnion) != connections.AUTHENTICATED {
					return `{"status":"error","reason":"peer_not_connected"}`
				}
				id, err := profile.SendMessage(conversation.ID, message)
				if err == nil {
					return fmt.Sprintf(`{"id":%d,"status":"sent"}`, id)
				}
				log.Errorf("SendMessage error: %v", err)
			}
		}
	}
	return `{"status":"error","reason":"send_failed"}`
}

func SendInvitation(profileOnion string, peerOnion string, message string) string {
	stateMutex.RLock()
	defer stateMutex.RUnlock()
	if Application != nil {
		profile := Application.GetPeer(profileOnion)
		if profile != nil {
			conversation, err := profile.FetchConversationInfo(peerOnion)
			if err == nil && conversation != nil {
				id, err := profile.SendMessage(conversation.ID, message)
				if err == nil {
					return fmt.Sprintf(`{"id":%d,"status":"sent"}`, id)
				}
				log.Errorf("SendInvitation error: %v", err)
			}
		}
	}
	return ""
}

func SendFile(profileOnion string, peerOnion string, filePath string) {
	stateMutex.RLock()
	defer stateMutex.RUnlock()
	if Application != nil {
		profile := Application.GetPeer(profileOnion)
		if profile != nil {
			conversation, err := profile.FetchConversationInfo(peerOnion)
			if err == nil && conversation != nil {
				fh, err := filesharing.FunctionalityGate(utils.ReadGlobalSettings().Experiments)
				if err != nil {
					log.Errorf("file sharing error: %v", err)
					return
				}
				fileKey, overlay, err := fh.ShareFile(filePath, profile)
				if err != nil {
					log.Errorf("error sharing file: %v", err)
					return
				}
				profile.SetConversationAttribute(conversation.ID, attr.ConversationScope.ConstructScopedZonedPath(attr.FilesharingZone.ConstructZonedPath(fileKey)), "")
				_, err = profile.SendMessage(conversation.ID, overlay)
				if err != nil {
					log.Errorf("error sending sharing message: %v", err)
				}
			}
		}
	}
}

func GetTorState() string {
	stateMutex.RLock()
	defer stateMutex.RUnlock()
	if Application != nil {
		prog, status := GlobalACN.GetBootstrapStatus()
		return fmt.Sprintf(`{"progress":%d,"status":"%s"}`, prog, status)
	}
	return `{"progress":0,"status":"Offline"}`
}

func GetPeerStates() string {
	stateMutex.RLock()
	defer stateMutex.RUnlock()
	states := make(map[string]string)
	if Application != nil {
		for _, onion := range Application.ListProfiles() {
			profile := Application.GetPeer(onion)
			if profile != nil {
				conversations, err := profile.FetchConversations()
				if err == nil {
					for _, conv := range conversations {
						state := profile.GetPeerState(conv.Handle)
						states[conv.Handle] = connections.ConnectionStateName[state]
					}
				}
			}
		}
	}
	bytes, _ := json.Marshal(states)
	return string(bytes)
}

func GetConversationMap() string {
	stateMutex.RLock()
	defer stateMutex.RUnlock()
	convMap := make(map[string]int)
	if Application != nil {
		for _, onion := range Application.ListProfiles() {
			profile := Application.GetPeer(onion)
			if profile != nil {
				conversations, err := profile.FetchConversations()
				if err == nil {
					for _, conv := range conversations {
						convMap[conv.Handle] = conv.ID
					}
				}
			}
		}
	}
	bytes, _ := json.Marshal(convMap)
	return string(bytes)
}

func GetMediaOffers() string {
	mediaOffersMutex.Lock()
	defer mediaOffersMutex.Unlock()
	list := make([]MediaOffer, 0, len(mediaOffers))
	for _, offer := range mediaOffers {
		list = append(list, offer)
	}
	bytes, _ := json.Marshal(list)
	return string(bytes)
}

func RequestMedia(transferID string) {
	// Mandatory safeguard: Hold stateMutex.RLock() throughout RequestMedia
	stateMutex.RLock()
	defer stateMutex.RUnlock()

	appInst := Application
	if appInst == nil {
		return
	}

	mediaOffersMutex.Lock()
	offer, exists := mediaOffers[transferID]
	if exists {
		offer.State = "downloading"
		mediaOffers[transferID] = offer
	}
	mediaOffersMutex.Unlock()

	for _, onion := range appInst.ListProfiles() {
		profile := appInst.GetPeer(onion)
		if profile == nil {
			continue
		}
		manifestFilePath, exists := profile.GetScopedZonedAttribute(attr.LocalScope, attr.FilesharingZone, fmt.Sprintf("%s.manifest", transferID))
		if exists && manifestFilePath != "" {
			conversations, err := profile.FetchConversations()
			if err == nil {
				for _, conv := range conversations {
					_, err := profile.GetConversationAttribute(conv.ID, attr.ConversationScope.ConstructScopedZonedPath(attr.FilesharingZone.ConstructZonedPath(transferID)))
					if err == nil {
						fh, err := filesharing.FunctionalityGate(utils.ReadGlobalSettings().Experiments)
						if err == nil {
							_ = fh.DownloadFile(profile, conv.ID, manifestFilePath, manifestFilePath, transferID, files.MaxManifestSize*files.DefaultChunkSize)
						}
						return
					}
				}
			}
		}
	}
}

func AuthorizeConversation(profileOnion string, peerOnion string, cwtchConversationID int32, stegmsConversationID int32) {
	stateMutex.RLock()
	defer stateMutex.RUnlock()
	if Application != nil {
		profile := Application.GetPeer(profileOnion)
		if profile != nil {
			profile.AcceptConversation(int(cwtchConversationID))
			authMutex.Lock()
			// Mandatory safeguard: Key by both profile and peer to prevent cross-profile collisions
			bindingKey := fmt.Sprintf("%s:%s", profileOnion, peerOnion)
			authorizedBindings[bindingKey] = AuthorizedBinding{
				ProfileOnion:         profileOnion,
				PeerOnion:            peerOnion,
				CwtchConversationID:  cwtchConversationID,
				StegmsConversationID: stegmsConversationID,
			}
			authMutex.Unlock()
		}
	}
}

func GetAppBusEvent() string {
	// Mandatory safeguard: Hold stateMutex.RLock() throughout GetAppBusEvent
	stateMutex.RLock()
	defer stateMutex.RUnlock()
	handler := EventHandler
	if handler == nil {
		return ""
	}
	return handler.TryNextEvent()
}
