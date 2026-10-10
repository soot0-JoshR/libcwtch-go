package cwtchcore

import (
	"crypto/sha256"
	"cwtch.im/cwtch/app"
	"cwtch.im/cwtch/event"
	"cwtch.im/cwtch/functionality/filesharing"
	"cwtch.im/cwtch/model"
	"cwtch.im/cwtch/model/attr"
	constants2 "cwtch.im/cwtch/model/constants"
	"cwtch.im/cwtch/peer"
	"cwtch.im/cwtch/protocol/connections"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	lcgconstants "git.openprivacy.ca/cwtch.im/libcwtch-go/constants"
	"git.openprivacy.ca/cwtch.im/libcwtch-go/utils"
	"git.openprivacy.ca/openprivacy/connectivity"
	"git.openprivacy.ca/openprivacy/log"
	"mime"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"time"
)

type AuthorizedBinding struct {
	ProfileOnion         string
	PeerOnion            string
	CwtchConversationID  int32
	StegmsConversationID string
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
	LocalPath           string  `json:"localPath,omitempty"`
	ErrorMessage        string  `json:"errorMessage,omitempty"`
}

type MediaRequestResult struct {
	MediaOffer
	Status string `json:"status"`
	Reason string `json:"reason,omitempty"`
}

type ProfileMetadata struct {
	Onion      string `json:"onion"`
	Name       string `json:"name"`
	Lifetime   string `json:"lifetime"`
	Storage    string `json:"storage"`
	Source     string `json:"source"`
	CanPromote bool   `json:"canPromote"`
}

type ConversationMetadata struct {
	PeerOnion      string `json:"peerOnion"`
	ConversationID int    `json:"conversationId"`
	Name           string `json:"name"`
	Blocked        bool   `json:"blocked"`
	Accepted       bool   `json:"accepted"`
}

type ContactMutationResult struct {
	Status         string `json:"status"`
	Reason         string `json:"reason,omitempty"`
	ConversationID int    `json:"conversationId,omitempty"`
}

var (
	stateMutex    sync.RWMutex
	Application   app.Application
	EventHandler  *utils.EventHandler
	GlobalTorPath string
	GlobalAppDir  string
	GlobalACN     *connectivity.ProxyACN

	authorizedBindings = make(map[string]AuthorizedBinding)
	authMutex          sync.Mutex

	mediaOffersMutex   sync.Mutex
	mediaOffers        = make(map[string]MediaOffer)
	ensureContactMutex sync.Mutex
)

const (
	profileLifetimeAttribute  = "stegms_lifetime"
	profileLifetimePersistent = "persistent"
	profileLifetimeEphemeral  = "ephemeral"
	maxStegmsMediaBytes       = int64(100 * 1024 * 1024)
)

type EnsureContactResult struct {
	Status         string `json:"status"`
	ConversationID int    `json:"conversationId,omitempty"`
	Created        bool   `json:"created"`
	Reason         string `json:"reason,omitempty"`
}

type SendMessageResult struct {
	Status         string `json:"status"`
	ID             int    `json:"id,omitempty"`
	ConversationID int    `json:"conversationId,omitempty"`
	Reason         string `json:"reason,omitempty"`
	PeerState      string `json:"peerState,omitempty"`
}

type EnhancedMessage struct {
	model.Message
	ID           int
	LocalIndex   int
	ContentHash  string
	ContactImage string
	Attributes   map[string]string
}

var validOnionAddress = regexp.MustCompile(`^[a-z2-7]{56}$`)
var unsafeMediaName = regexp.MustCompile(`[^A-Za-z0-9._-]+`)

func normalizeOnion(value string) string {
	return strings.TrimSuffix(strings.ToLower(strings.TrimSpace(value)), ".onion")
}

func normalizeProfileLifetime(value string) string {
	if strings.EqualFold(strings.TrimSpace(value), profileLifetimeEphemeral) {
		return profileLifetimeEphemeral
	}
	return profileLifetimePersistent
}

func normalizeStegmsConversationID(value string) (string, bool) {
	normalized := strings.TrimSpace(value)
	return normalized, normalized != "" && len(normalized) <= 256
}

func connectionStateName(state connections.ConnectionState) string {
	index := int(state)
	if index >= 0 && index < len(connections.ConnectionStateName) {
		if name := connections.ConnectionStateName[index]; name != "" {
			return name
		}
	}
	return "Disconnected"
}

func ensureContactJSON(result EnsureContactResult) string {
	encoded, _ := json.Marshal(result)
	return string(encoded)
}

func contactMutationJSON(result ContactMutationResult) string {
	encoded, _ := json.Marshal(result)
	return string(encoded)
}

func conversationBlocked(conversation *model.Conversation) bool {
	if conversation == nil {
		return false
	}
	access, exists := conversation.ACL[conversation.Handle]
	return exists && access.Blocked
}

func sendMessageJSON(result SendMessageResult) string {
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
		if conversationBlocked(conversation) {
			return ensureContactJSON(EnsureContactResult{Status: "error", Reason: "peer_blocked"})
		}
		if conversation.Accepted {
			// An accepted database row does not imply its peer socket survived
			// suspension, so requeue one connection attempt.
			profile.PeerWithOnion(peerOnion)
		} else if err := profile.AcceptConversation(conversation.ID); err != nil {
			log.Errorf("EnsureContact accept error: %v", err)
			return ensureContactJSON(EnsureContactResult{Status: "error", Reason: "storage_error"})
		}
		if err := profile.SetConversationAttribute(
			conversation.ID,
			attr.LocalScope.ConstructScopedZonedPath(attr.ProfileZone.ConstructZonedPath(event.SaveHistoryKey)),
			event.SaveHistoryConfirmed,
		); err != nil {
			log.Errorf("EnsureContact save history error: %v", err)
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
			if conversation.Accepted {
				profile.PeerWithOnion(peerOnion)
			} else if acceptErr := profile.AcceptConversation(conversation.ID); acceptErr != nil {
				log.Errorf("EnsureContact concurrent accept error: %v", acceptErr)
				return ensureContactJSON(EnsureContactResult{Status: "error", Reason: "storage_error"})
			}
			if saveErr := profile.SetConversationAttribute(
				conversation.ID,
				attr.LocalScope.ConstructScopedZonedPath(attr.ProfileZone.ConstructZonedPath(event.SaveHistoryKey)),
				event.SaveHistoryConfirmed,
			); saveErr != nil {
				log.Errorf("EnsureContact concurrent save history error: %v", saveErr)
				return ensureContactJSON(EnsureContactResult{Status: "error", Reason: "storage_error"})
			}
			return ensureContactJSON(EnsureContactResult{
				Status: "existing", ConversationID: conversation.ID,
			})
		}
		log.Errorf("EnsureContact storage error: %v", err)
		return ensureContactJSON(EnsureContactResult{Status: "error", Reason: "storage_error"})
	}
	if err := profile.SetConversationAttribute(
		conversationID,
		attr.LocalScope.ConstructScopedZonedPath(attr.ProfileZone.ConstructZonedPath(event.SaveHistoryKey)),
		event.SaveHistoryConfirmed,
	); err != nil {
		log.Errorf("EnsureContact new save history error: %v", err)
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

	if Application == nil {
		return ensureContactJSON(EnsureContactResult{
			Status: "error", Reason: "application_not_initialized",
		})
	}
	if profile := Application.GetPeer(normalizeOnion(profileOnionRaw)); profile != nil {
		return EnsureContactForProfile(profile, profileOnionRaw, peerOnionRaw)
	}
	return ensureContactJSON(EnsureContactResult{
		Status: "error", Reason: "profile_not_found",
	})
}

func mutateContact(profileOnionRaw string, peerOnionRaw string, block bool) string {
	stateMutex.RLock()
	defer stateMutex.RUnlock()
	ensureContactMutex.Lock()
	defer ensureContactMutex.Unlock()

	profileOnion := normalizeOnion(profileOnionRaw)
	peerOnion := normalizeOnion(peerOnionRaw)
	if !validOnionAddress.MatchString(profileOnion) || !validOnionAddress.MatchString(peerOnion) {
		return contactMutationJSON(ContactMutationResult{Status: "error", Reason: "invalid_onion"})
	}
	if Application == nil {
		return contactMutationJSON(ContactMutationResult{Status: "error", Reason: "application_not_initialized"})
	}
	profile := Application.GetPeer(profileOnion)
	if profile == nil {
		return contactMutationJSON(ContactMutationResult{Status: "error", Reason: "profile_not_found"})
	}
	conversation, err := profile.FetchConversationInfo(peerOnion)
	if err != nil || conversation == nil {
		return contactMutationJSON(ContactMutationResult{Status: "error", Reason: "contact_not_found"})
	}

	if block {
		if err := profile.BlockConversation(conversation.ID); err != nil {
			log.Errorf("BlockContact storage error: %v", err)
			return contactMutationJSON(ContactMutationResult{Status: "error", Reason: "storage_error"})
		}
		return contactMutationJSON(ContactMutationResult{
			Status: "blocked", ConversationID: conversation.ID,
		})
	}

	if err := profile.DeleteConversation(conversation.ID); err != nil {
		log.Errorf("DeleteContact storage error: %v", err)
		return contactMutationJSON(ContactMutationResult{Status: "error", Reason: "storage_error"})
	}
	authMutex.Lock()
	delete(authorizedBindings, fmt.Sprintf("%s:%s", profileOnion, peerOnion))
	authMutex.Unlock()
	return contactMutationJSON(ContactMutationResult{
		Status: "deleted", ConversationID: conversation.ID,
	})
}

func BlockContact(profileOnionRaw string, peerOnionRaw string) string {
	return mutateContact(profileOnionRaw, peerOnionRaw, true)
}

func DeleteContact(profileOnionRaw string, peerOnionRaw string) string {
	return mutateContact(profileOnionRaw, peerOnionRaw, false)
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

	utils.OnFileProgressUpdated = func(fileKey string, progress float64, state string, localPath string, errorMessage string) {
		mediaOffersMutex.Lock()
		if offer, exists := mediaOffers[fileKey]; exists {
			offer.State = state
			offer.Progress = progress
			if localPath != "" {
				if state == "available" {
					downloadRoot := filepath.Join(
						GlobalAppDir,
						"media",
						normalizeOnion(offer.ProfileOnion),
					)
					info, statErr := os.Stat(localPath)
					if !pathInsideRoot(downloadRoot, localPath) ||
						statErr != nil ||
						!info.Mode().IsRegular() ||
						info.Size() != offer.ExpectedSize ||
						info.Size() > maxStegmsMediaBytes {
						offer.State = "failed"
						offer.Progress = 0
						offer.ErrorMessage = "downloaded media failed path or size validation"
					} else {
						offer.LocalPath = localPath
						offer.MimeType = sniffMediaType(localPath)
					}
				} else {
					offer.LocalPath = localPath
				}
			}
			if errorMessage != "" {
				offer.ErrorMessage = errorMessage
			}
			mediaOffers[fileKey] = offer
		}
		mediaOffersMutex.Unlock()
	}
}

func sniffMediaType(filePath string) string {
	file, err := os.Open(filePath)
	if err == nil {
		defer func() {
			if closeErr := file.Close(); closeErr != nil {
				log.Warnf("unable to close media file after MIME inspection: %v", closeErr)
			}
		}()
		header := make([]byte, 512)
		bytesRead, readErr := file.Read(header)
		if readErr == nil || bytesRead > 0 {
			detected := http.DetectContentType(header[:bytesRead])
			if detected != "application/octet-stream" {
				return detected
			}
		}
	}
	if extensionType := mime.TypeByExtension(strings.ToLower(filepath.Ext(filePath))); extensionType != "" {
		return strings.SplitN(extensionType, ";", 2)[0]
	}
	return "application/octet-stream"
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
	// Application shutdown tears down profiles and protocol engines, but it
	// does not own the global ACN. Close it independently so partial startup and
	// repeated shutdown paths cannot retain a stale Tor runtime.
	if GlobalACN != nil {
		GlobalACN.Close()
		GlobalACN = nil
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
	CreateProfileWithLifetime(nick, password, profileLifetimePersistent)
}

func CreateEphemeralProfile(nick string, password string) {
	tagVal := lcgconstants.ProfileTypeV1Password
	if password == lcgconstants.DefactoPasswordForUnencryptedProfiles {
		tagVal = lcgconstants.ProfileTypeV1DefaultPassword
	}

	Application.CreateEphemeralPeer(nick, password, map[attr.ZonedPath]string{
		attr.ProfileZone.ConstructZonedPath(constants2.Tag):             tagVal,
		attr.ProfileZone.ConstructZonedPath(lcgconstants.PeerAutostart): constants2.True,
	})
}

func PromoteEphemeralProfile(onion string, password string) error {
	if Application == nil {
		return fmt.Errorf("application_not_initialized")
	}
	return Application.PromoteEphemeralProfile(onion, password)
}

// ProfileHasPassword reports, as JSON {"status":"ok","hasPassword":bool},
// whether a loaded profile has a password other than blankPassword (the
// caller's stand-in for "none"). StegMS addition (2026-10-10).
func ProfileHasPassword(profileOnion string, blankPassword string) string {
	stateMutex.RLock()
	defer stateMutex.RUnlock()
	result := map[string]interface{}{"status": "ok"}
	if Application == nil {
		result = map[string]interface{}{"status": "error", "reason": "application_not_initialized"}
	} else if profile := Application.GetPeer(normalizeOnion(profileOnion)); profile == nil {
		result = map[string]interface{}{"status": "error", "reason": "profile_not_found"}
	} else {
		result["hasPassword"] = profile.HasPassword(blankPassword)
	}
	bytes, _ := json.Marshal(result)
	return string(bytes)
}

// ExportProfileWithPassword writes a standard Cwtch backup of a loaded profile,
// encrypted with backupPassword, after checking its current password. The
// result is JSON: {"status":"exported"} or {"status":"error","reason":...}.
// StegMS addition (2026-10-09): identity backup.
func ExportProfileWithPassword(profileOnion string, file string, currentPassword string, backupPassword string) string {
	stateMutex.RLock()
	defer stateMutex.RUnlock()
	result := map[string]string{"status": "exported"}
	if Application == nil {
		result = map[string]string{"status": "error", "reason": "application_not_initialized"}
	} else if profile := Application.GetPeer(normalizeOnion(profileOnion)); profile == nil {
		result = map[string]string{"status": "error", "reason": "profile_not_found"}
	} else if err := profile.ExportWithPassword(file, currentPassword, backupPassword); err != nil {
		result = map[string]string{"status": "error", "reason": err.Error()}
	}
	bytes, _ := json.Marshal(result)
	return string(bytes)
}

// ImportProfileWithNewPassword restores a Cwtch backup opened with
// backupPassword, then sets the restored profile's password on this device to
// newPassword (often blank, so it loads at startup like other password-less
// identities). Without that it would keep the backup password and stay hidden
// after the next restart until loaded with it. StegMS addition (2026-10-09).
func ImportProfileWithNewPassword(exportedCwtchFile string, backupPassword string, newPassword string) string {
	stateMutex.RLock()
	defer stateMutex.RUnlock()
	encode := func(result map[string]string) string {
		bytes, _ := json.Marshal(result)
		return string(bytes)
	}
	if Application == nil {
		return encode(map[string]string{"status": "error", "reason": "application_not_initialized"})
	}
	profile, err := Application.ImportProfile(exportedCwtchFile, backupPassword)
	if err != nil || profile == nil {
		reason := "import_failed"
		if err != nil {
			reason = err.Error()
		}
		return encode(map[string]string{"status": "error", "reason": reason})
	}
	if newPassword != backupPassword {
		if err := profile.ChangePassword(backupPassword, newPassword, newPassword); err != nil {
			// Imported, but still under the backup password.
			return encode(map[string]string{"status": "imported", "onion": profile.GetOnion(), "passwordChanged": "false", "reason": err.Error()})
		}
	}
	return encode(map[string]string{"status": "imported", "onion": profile.GetOnion(), "passwordChanged": "true"})
}

func ImportProfile(exportedCwtchFile string, pass string) string {
	_, err := Application.ImportProfile(exportedCwtchFile, pass)
	if err == nil {
		return `{"status":"ok"}`
	}
	return fmt.Sprintf(`{"status":"error","reason":"%s"}`, err.Error())
}

func CreateProfileWithLifetime(nick string, password string, lifetime string) {
	stateMutex.RLock()
	defer stateMutex.RUnlock()
	if Application != nil {
		Application.CreatePeer(nick, password, map[attr.ZonedPath]string{
			attr.ProfileZone.ConstructZonedPath("tag"):                    "v1-password",
			attr.ProfileZone.ConstructZonedPath("autostart"):              "true",
			attr.ProfileZone.ConstructZonedPath(profileLifetimeAttribute): normalizeProfileLifetime(lifetime),
		})
	}
}

func SetProfileLifetime(profileOnion string, lifetime string) string {
	stateMutex.RLock()
	defer stateMutex.RUnlock()
	if Application == nil {
		return `{"status":"error","reason":"application_not_initialized"}`
	}
	profile := Application.GetPeer(normalizeOnion(profileOnion))
	if profile == nil {
		return `{"status":"error","reason":"profile_not_found"}`
	}
	profile.SetScopedZonedAttribute(attr.LocalScope, attr.ProfileZone, profileLifetimeAttribute, normalizeProfileLifetime(lifetime))
	return `{"status":"ok"}`
}

func DeleteProfile(profileOnion string, password string) string {
	stateMutex.RLock()
	defer stateMutex.RUnlock()
	if Application == nil {
		return `{"status":"error","reason":"application_not_initialized"}`
	}
	profile := Application.GetPeer(normalizeOnion(profileOnion))
	if profile == nil {
		return `{"status":"error","reason":"profile_not_found"}`
	}
	if !profile.CheckPassword(password) {
		return `{"status":"error","reason":"invalid_password"}`
	}
	purgeGuestMediaLocked(profile.GetOnion())
	Application.DeletePeer(profile.GetOnion(), password)
	return `{"status":"deleted"}`
}

// LockProfile unloads one profile from the running application without
// deleting its encrypted database. Tor and every other loaded profile remain
// online, and the profile can be loaded again with its password.
func LockProfile(profileOnion string) string {
	stateMutex.RLock()
	defer stateMutex.RUnlock()
	if Application == nil {
		return `{"status":"error","reason":"application_not_initialized"}`
	}
	onion := normalizeOnion(profileOnion)
	if onion == "" || Application.GetPeer(onion) == nil {
		return `{"status":"error","reason":"profile_not_found"}`
	}
	if EventHandler != nil {
		EventHandler.ForgetProfileState(onion)
	}
	Application.ShutdownPeer(onion)
	return `{"status":"locked"}`
}

func profileMetadataFor(profile peer.CwtchPeer) ProfileMetadata {
	name, ok := profile.GetScopedZonedAttribute(attr.PublicScope, attr.ProfileZone, "name")
	if !ok || name == "" {
		name = "Unnamed"
	}
	lifetime, ok := profile.GetScopedZonedAttribute(attr.LocalScope, attr.ProfileZone, profileLifetimeAttribute)
	if !ok || lifetime == "" {
		lifetime = profileLifetimePersistent
	}
	storage, ok := profile.GetScopedZonedAttribute(attr.LocalScope, attr.ProfileZone, "stegms_storage")
	if !ok || storage == "" {
		storage = "disk"
	}
	source, ok := profile.GetScopedZonedAttribute(attr.LocalScope, attr.ProfileZone, "stegms_source")
	if !ok || source == "" {
		source = "stegms"
	}
	return ProfileMetadata{
		Onion:      profile.GetOnion(),
		Name:       name,
		Lifetime:   normalizeProfileLifetime(lifetime),
		Storage:    storage,
		Source:     source,
		CanPromote: storage == "memory",
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

func GetProfileMetadata() string {
	stateMutex.RLock()
	defer stateMutex.RUnlock()
	metadata := make([]ProfileMetadata, 0)
	if Application != nil {
		for _, onion := range Application.ListProfiles() {
			if profile := Application.GetPeer(onion); profile != nil {
				metadata = append(metadata, profileMetadataFor(profile))
			}
		}
	}
	bytes, _ := json.Marshal(metadata)
	return string(bytes)
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

	cleanProfile := normalizeOnion(profileOnion)
	cleanPeer := normalizeOnion(peerOnion)
	if !validOnionAddress.MatchString(cleanProfile) || !validOnionAddress.MatchString(cleanPeer) {
		return sendMessageJSON(SendMessageResult{Status: "error", Reason: "invalid_onion"})
	}
	if Application == nil {
		return sendMessageJSON(SendMessageResult{Status: "error", Reason: "application_not_initialized"})
	}
	profile := Application.GetPeer(cleanProfile)
	if profile == nil {
		log.Errorf("SendMessage profile not found: %s", cleanProfile)
		return sendMessageJSON(SendMessageResult{Status: "error", Reason: "profile_not_found"})
	}

	conversation, err := profile.FetchConversationInfo(cleanPeer)
	if err != nil || conversation == nil {
		log.Errorf("SendMessage conversation not found for peer %s: %v", cleanPeer, err)
		return sendMessageJSON(SendMessageResult{Status: "error", Reason: "conversation_not_found"})
	}

	peerState := connectionStateName(profile.GetPeerState(cleanPeer))
	if peerState != "Authenticated" {
		return sendMessageJSON(SendMessageResult{
			Status:         "error",
			Reason:         "peer_not_connected",
			PeerState:      peerState,
			ConversationID: conversation.ID,
		})
	}

	id, err := profile.SendMessage(conversation.ID, message)
	if err == nil {
		return sendMessageJSON(SendMessageResult{
			ID:             id,
			Status:         "sent",
			ConversationID: conversation.ID,
		})
	}
	log.Errorf("SendMessage native send error for conversation %d: %v", conversation.ID, err)
	return sendMessageJSON(SendMessageResult{
		Status:         "error",
		Reason:         "native_send_failed",
		PeerState:      peerState,
		ConversationID: conversation.ID,
	})
}

func SendInvitation(profileOnion string, peerOnion string, message string) string {
	stateMutex.RLock()
	defer stateMutex.RUnlock()
	if Application != nil {
		profile := Application.GetPeer(normalizeOnion(profileOnion))
		if profile != nil {
			conversation, err := profile.FetchConversationInfo(normalizeOnion(peerOnion))
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

func SendFile(profileOnion string, peerOnion string, filePath string) string {
	stateMutex.RLock()
	defer stateMutex.RUnlock()
	if Application != nil {
		profile := Application.GetPeer(normalizeOnion(profileOnion))
		if profile != nil {
			conversation, err := profile.FetchConversationInfo(normalizeOnion(peerOnion))
			if err == nil && conversation != nil {
				fh, err := filesharing.FunctionalityGate(utils.ReadGlobalSettings().Experiments)
				if err != nil {
					log.Errorf("file sharing error: %v", err)
					return ""
				}
				fileKey, overlay, err := fh.ShareFile(filePath, profile)
				if err != nil {
					log.Errorf("error sharing file: %v", err)
					return ""
				}
				profile.SetConversationAttribute(conversation.ID, attr.ConversationScope.ConstructScopedZonedPath(attr.FilesharingZone.ConstructZonedPath(fileKey)), "")
				_, err = profile.SendMessage(conversation.ID, overlay)
				if err != nil {
					log.Errorf("error sending sharing message: %v", err)
					return ""
				}
				return fileKey
			}
		}
	}
	return ""
}

func GetTorState() string {
	stateMutex.RLock()
	defer stateMutex.RUnlock()
	if Application != nil && GlobalACN != nil {
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
						states[conv.Handle] = connectionStateName(state)
					}
				}
			}
		}
	}
	bytes, _ := json.Marshal(states)
	return string(bytes)
}

func GetPeerStatesForProfile(profileOnion string) string {
	stateMutex.RLock()
	defer stateMutex.RUnlock()
	states := make(map[string]string)
	if Application != nil {
		profile := Application.GetPeer(normalizeOnion(profileOnion))
		if profile != nil {
			conversations, err := profile.FetchConversations()
			if err == nil {
				for _, conv := range conversations {
					states[normalizeOnion(conv.Handle)] = connectionStateName(profile.GetPeerState(conv.Handle))
				}
			}
		}
	}
	bytes, _ := json.Marshal(states)
	return string(bytes)
}

func GetPeerState(profileOnion string, peerOnion string) string {
	stateMutex.RLock()
	defer stateMutex.RUnlock()

	cleanProfile := normalizeOnion(profileOnion)
	cleanPeer := normalizeOnion(peerOnion)
	if Application != nil {
		if profile := Application.GetPeer(cleanProfile); profile != nil {
			return connectionStateName(profile.GetPeerState(cleanPeer))
		}
	}
	return "Disconnected"
}

// ReconnectCwtchForeground is called when the Android Activity resumes. A
// suspended Android process can retain the Tor ACN and protocol engines while
// their peer sockets time out. Requeueing accepted peer conversations avoids
// waiting for the contact-retry backoff (or requiring a new guest profile).
func ReconnectCwtchForeground() string {
	stateMutex.RLock()
	defer stateMutex.RUnlock()

	if Application == nil {
		return `{"status":"error","reason":"application_not_initialized"}`
	}

	profiles := Application.ListProfiles()
	for _, onion := range profiles {
		if profile := Application.GetPeer(onion); profile != nil {
			profile.StartPeersConnections()
		}
	}
	Application.QueryACNStatus()
	return fmt.Sprintf(`{"status":"ok","profiles":%d}`, len(profiles))
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

func GetConversationMapForProfile(profileOnionRaw string) string {
	stateMutex.RLock()
	defer stateMutex.RUnlock()
	convMap := make(map[string]int)
	profileOnion := normalizeOnion(profileOnionRaw)
	if Application != nil && validOnionAddress.MatchString(profileOnion) {
		if profile := Application.GetPeer(profileOnion); profile != nil {
			if conversations, err := profile.FetchConversations(); err == nil {
				for _, conv := range conversations {
					if conversationBlocked(conv) {
						continue
					}
					convMap[conv.Handle] = conv.ID
				}
			}
		}
	}
	bytes, _ := json.Marshal(convMap)
	return string(bytes)
}

func conversationDisplayName(conversation *model.Conversation) string {
	if conversation == nil {
		return ""
	}
	for _, scope := range []attr.Scope{attr.LocalScope, attr.PublicScope} {
		if name, exists := conversation.GetAttribute(scope, attr.ProfileZone, constants2.Name); exists {
			name = strings.TrimSpace(name)
			if name != "" && name != "Unnamed" && normalizeOnion(name) != normalizeOnion(conversation.Handle) {
				return name
			}
		}
	}
	return ""
}

func GetConversationMetadataForProfile(profileOnionRaw string) string {
	stateMutex.RLock()
	defer stateMutex.RUnlock()
	metadata := make([]ConversationMetadata, 0)
	profileOnion := normalizeOnion(profileOnionRaw)
	if Application != nil && validOnionAddress.MatchString(profileOnion) {
		if profile := Application.GetPeer(profileOnion); profile != nil {
			if conversations, err := profile.FetchConversations(); err == nil {
				for _, conversation := range conversations {
					metadata = append(metadata, ConversationMetadata{
						PeerOnion:      normalizeOnion(conversation.Handle),
						ConversationID: conversation.ID,
						Name:           conversationDisplayName(conversation),
						Blocked:        conversationBlocked(conversation),
						Accepted:       conversation.Accepted,
					})
				}
			}
		}
	}
	bytes, _ := json.Marshal(metadata)
	return string(bytes)
}

func GetMessages(profileOnionRaw string, conversationID int, messageIndex int, count int) string {
	stateMutex.RLock()
	defer stateMutex.RUnlock()
	emessages := make([]EnhancedMessage, 0)
	if count <= 0 || count > 100 || messageIndex < 0 || conversationID <= 0 || Application == nil {
		bytes, _ := json.Marshal(emessages)
		return string(bytes)
	}
	profile := Application.GetPeer(normalizeOnion(profileOnionRaw))
	if profile == nil {
		bytes, _ := json.Marshal(emessages)
		return string(bytes)
	}
	messages, err := profile.GetMostRecentMessages(conversationID, 0, messageIndex, count)
	if err == nil {
		for _, message := range messages {
			sentAt, _ := time.Parse(time.RFC3339Nano, message.Attr[constants2.AttrSentTimestamp])
			emessages = append(emessages, EnhancedMessage{
				Message: model.Message{
					Message:      message.Body,
					Acknowledged: message.Attr[constants2.AttrAck] == constants2.True,
					Error:        message.Attr[constants2.AttrErr],
					PeerID:       message.Attr[constants2.AttrAuthor],
					Timestamp:    sentAt,
				},
				ID:           message.ID,
				ContentHash:  model.CalculateContentHash(message.Attr[constants2.AttrAuthor], message.Body),
				ContactImage: utils.RandomProfileImage(message.Attr[constants2.AttrAuthor]),
				Attributes:   message.Attr,
			})
		}
	}
	bytes, _ := json.Marshal(emessages)
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

func mediaRequestJSON(offer MediaOffer, status string, reason string) string {
	encoded, _ := json.Marshal(MediaRequestResult{MediaOffer: offer, Status: status, Reason: reason})
	return string(encoded)
}

func safeMediaFilename(transferID string, suggestedName string) string {
	name := unsafeMediaName.ReplaceAllString(filepath.Base(strings.TrimSpace(suggestedName)), "_")
	name = strings.Trim(name, ".")
	if name == "" {
		name = "attachment.bin"
	}
	if len(name) > 96 {
		ext := filepath.Ext(name)
		stem := strings.TrimSuffix(name, ext)
		if len(ext) > 24 {
			ext = ""
			stem = name
		}
		stemLimit := 96 - len(ext)
		if len(stem) > stemLimit {
			stem = stem[:stemLimit]
		}
		name = stem + ext
	}
	rawPrefix := strings.SplitN(strings.TrimSpace(transferID), ".", 2)[0]
	prefix := unsafeMediaName.ReplaceAllString(rawPrefix, "_")
	for strings.Contains(prefix, "..") {
		prefix = strings.ReplaceAll(prefix, "..", "_")
	}
	prefix = strings.Trim(prefix, "._-")
	if prefix == "" {
		// Keep malformed or entirely punctuation-based transfer IDs isolated
		// from one another without allowing any of their path syntax through.
		digest := sha256.Sum256([]byte(transferID))
		prefix = hex.EncodeToString(digest[:8])
	}
	if len(prefix) > 32 {
		prefix = prefix[:32]
	}
	return prefix + "-" + name
}

func pathInsideRoot(root string, candidate string) bool {
	if root == "" || candidate == "" {
		return false
	}
	absoluteRoot, rootErr := filepath.Abs(root)
	absoluteCandidate, candidateErr := filepath.Abs(candidate)
	if rootErr != nil || candidateErr != nil {
		return false
	}
	relative, err := filepath.Rel(absoluteRoot, absoluteCandidate)
	return err == nil &&
		relative != "." &&
		relative != ".." &&
		!strings.HasPrefix(relative, ".."+string(os.PathSeparator)) &&
		!filepath.IsAbs(relative)
}

func RequestMedia(transferID string) string {
	// Mandatory safeguard: Hold stateMutex.RLock() throughout RequestMedia
	stateMutex.RLock()
	defer stateMutex.RUnlock()

	appInst := Application
	if appInst == nil {
		return mediaRequestJSON(MediaOffer{TransferID: transferID}, "error", "application_not_initialized")
	}

	mediaOffersMutex.Lock()
	offer, exists := mediaOffers[transferID]
	mediaOffersMutex.Unlock()
	if !exists {
		return mediaRequestJSON(MediaOffer{TransferID: transferID}, "error", "unknown_transfer")
	}
	if offer.ExpectedSize <= 0 || offer.ExpectedSize > maxStegmsMediaBytes {
		return mediaRequestJSON(offer, "error", "media_exceeds_size_policy")
	}

	profileOnion := normalizeOnion(offer.ProfileOnion)
	peerOnion := normalizeOnion(offer.PeerOnion)
	authMutex.Lock()
	binding, authorized := authorizedBindings[fmt.Sprintf("%s:%s", profileOnion, peerOnion)]
	authMutex.Unlock()
	if !authorized || binding.CwtchConversationID != offer.CwtchConversationID {
		return mediaRequestJSON(offer, "error", "conversation_not_authorized")
	}

	profile := appInst.GetPeer(profileOnion)
	if profile == nil {
		return mediaRequestJSON(offer, "error", "profile_not_found")
	}
	downloadDir := filepath.Join(GlobalAppDir, "media", profileOnion)
	if GlobalAppDir == "" {
		return mediaRequestJSON(offer, "error", "media_directory_unavailable")
	}
	if offer.State == "complete" || offer.State == "available" {
		if pathInsideRoot(downloadDir, offer.LocalPath) {
			if info, err := os.Stat(offer.LocalPath); err == nil &&
				info.Mode().IsRegular() &&
				info.Size() == offer.ExpectedSize &&
				info.Size() <= maxStegmsMediaBytes {
				offer.State = "available"
				offer.Progress = 100
				return mediaRequestJSON(offer, "available", "")
			}
		}
		return mediaRequestJSON(offer, "error", "completed_media_missing")
	}

	if err := os.MkdirAll(downloadDir, 0700); err != nil {
		return mediaRequestJSON(offer, "error", "media_directory_unavailable")
	}
	downloadFilePath, hasDownloadPath := profile.GetScopedZonedAttribute(
		attr.LocalScope, attr.FilesharingZone, fmt.Sprintf("%s.path", transferID),
	)
	manifestFilePath, hasManifestPath := profile.GetScopedZonedAttribute(
		attr.LocalScope, attr.FilesharingZone, fmt.Sprintf("%s.manifest", transferID),
	)
	if !hasDownloadPath ||
		!hasManifestPath ||
		!pathInsideRoot(downloadDir, downloadFilePath) ||
		!pathInsideRoot(downloadDir, manifestFilePath) {
		downloadFilePath = filepath.Join(downloadDir, safeMediaFilename(transferID, offer.SuggestedName))
		manifestFilePath = downloadFilePath + ".manifest"
	}

	fh, err := filesharing.FunctionalityGate(utils.ReadGlobalSettings().Experiments)
	if err != nil {
		return mediaRequestJSON(offer, "error", "filesharing_unavailable")
	}
	if err := fh.DownloadFile(
		profile,
		int(offer.CwtchConversationID),
		downloadFilePath,
		manifestFilePath,
		transferID,
		uint64(maxStegmsMediaBytes+1),
	); err != nil {
		offer.State = "failed"
		offer.ErrorMessage = err.Error()
		mediaOffersMutex.Lock()
		mediaOffers[transferID] = offer
		mediaOffersMutex.Unlock()
		return mediaRequestJSON(offer, "error", "download_start_failed")
	}

	offer.State = "downloading"
	offer.Progress = 0
	offer.LocalPath = downloadFilePath
	offer.ErrorMessage = ""
	mediaOffersMutex.Lock()
	mediaOffers[transferID] = offer
	mediaOffersMutex.Unlock()
	return mediaRequestJSON(offer, "requested", "")
}

func purgeGuestMediaLocked(profileOnionRaw string) {
	profileOnion := normalizeOnion(profileOnionRaw)
	if GlobalAppDir == "" || !validOnionAddress.MatchString(profileOnion) {
		return
	}
	mediaRoot := filepath.Join(GlobalAppDir, "media")
	profileRoot := filepath.Join(mediaRoot, profileOnion)

	mediaOffersMutex.Lock()
	for fileKey, offer := range mediaOffers {
		if normalizeOnion(offer.ProfileOnion) != profileOnion {
			continue
		}
		// Clean legacy downloads that predate profile-scoped directories, but
		// never remove a path outside StegMS's private media root.
		if offer.LocalPath != "" {
			if relative, err := filepath.Rel(mediaRoot, filepath.Clean(offer.LocalPath)); err == nil &&
				relative != "." && relative != ".." && !strings.HasPrefix(relative, ".."+string(os.PathSeparator)) {
				_ = os.Remove(offer.LocalPath)
				_ = os.Remove(offer.LocalPath + ".manifest")
			}
		}
		delete(mediaOffers, fileKey)
	}
	mediaOffersMutex.Unlock()
	_ = os.RemoveAll(profileRoot)

	authMutex.Lock()
	for bindingKey, binding := range authorizedBindings {
		if normalizeOnion(binding.ProfileOnion) == profileOnion {
			delete(authorizedBindings, bindingKey)
		}
	}
	authMutex.Unlock()
}

func PurgeGuestMedia(profileOnionRaw string) string {
	stateMutex.RLock()
	defer stateMutex.RUnlock()
	profileOnion := normalizeOnion(profileOnionRaw)
	if !validOnionAddress.MatchString(profileOnion) {
		return `{"status":"error","reason":"invalid_onion"}`
	}
	purgeGuestMediaLocked(profileOnion)
	return `{"status":"ok"}`
}

func AuthorizeConversation(profileOnion string, peerOnion string, cwtchConversationID int32, stegmsConversationID string) string {
	stateMutex.RLock()
	defer stateMutex.RUnlock()
	if Application == nil {
		return `{"status":"error","reason":"application_not_initialized"}`
	}
	cleanProfile := normalizeOnion(profileOnion)
	cleanPeer := normalizeOnion(peerOnion)
	cleanStegmsID, validStegmsID := normalizeStegmsConversationID(stegmsConversationID)
	if !validOnionAddress.MatchString(cleanProfile) ||
		!validOnionAddress.MatchString(cleanPeer) ||
		cwtchConversationID <= 0 ||
		!validStegmsID {
		return `{"status":"error","reason":"invalid_conversation_binding"}`
	}
	profile := Application.GetPeer(cleanProfile)
	if profile == nil {
		return `{"status":"error","reason":"profile_not_found"}`
	}
	conversation, err := profile.FetchConversationInfo(cleanPeer)
	if err != nil || conversation == nil || conversation.ID != int(cwtchConversationID) {
		return `{"status":"error","reason":"conversation_mismatch"}`
	}
	if err := profile.AcceptConversation(int(cwtchConversationID)); err != nil {
		return `{"status":"error","reason":"conversation_accept_failed"}`
	}
	if err := profile.SetConversationAttribute(
		int(cwtchConversationID),
		attr.LocalScope.ConstructScopedZonedPath(attr.ProfileZone.ConstructZonedPath(event.SaveHistoryKey)),
		event.SaveHistoryConfirmed,
	); err != nil {
		return `{"status":"error","reason":"conversation_history_failed"}`
	}
	authMutex.Lock()
	// Mandatory safeguard: Key by both profile and peer to prevent cross-profile collisions
	bindingKey := fmt.Sprintf("%s:%s", cleanProfile, cleanPeer)
	authorizedBindings[bindingKey] = AuthorizedBinding{
		ProfileOnion:         cleanProfile,
		PeerOnion:            cleanPeer,
		CwtchConversationID:  cwtchConversationID,
		StegmsConversationID: cleanStegmsID,
	}
	authMutex.Unlock()
	return `{"status":"authorized"}`
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
