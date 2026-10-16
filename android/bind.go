package cwtch

import (
	"cwtch.im/cwtch/app"
	modelconstants "cwtch.im/cwtch/model/constants"
	lcgconstants "git.openprivacy.ca/cwtch.im/libcwtch-go/constants"
	"git.openprivacy.ca/cwtch.im/libcwtch-go/cwtchcore"
	"git.openprivacy.ca/cwtch.im/libcwtch-go/utils"
	"git.openprivacy.ca/openprivacy/connectivity"
	"git.openprivacy.ca/openprivacy/connectivity/tor"
	"git.openprivacy.ca/openprivacy/log"
	_ "github.com/mutecomm/go-sqlcipher/v4"

	"crypto/rand"
	"encoding/base64"
	mrand "math/rand"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"
)

var lastStartupError string

func startupFailure(code int32, message string) int32 {
	lastStartupError = message
	log.Errorf("Android Cwtch startup failed (%d): %s", code, message)
	return code
}

// GetLastStartupError returns diagnostic detail for the most recent failed
// StartCwtch call. The Android bridge reads it immediately after a non-zero
// startup result so users receive the real Tor/storage failure.
func GetLastStartupError() string {
	return lastStartupError
}

// StartCwtch initializes the Cwtch application instance for Android and assigns it to cwtchcore.
func StartCwtch(appDir string, torPath string, noLoadProfiles bool) int32 {
	if cwtchcore.Application != nil {
		lastStartupError = ""
		return 0
	}
	if runtime.GOARCH != "arm64" {
		return startupFailure(2, "unsupported Android Cwtch architecture: "+runtime.GOARCH)
	}
	if appDir == "" || torPath == "" {
		return startupFailure(3, "Cwtch startup requires app and Tor paths")
	}
	if info, err := os.Stat(torPath); err != nil || info.IsDir() {
		return startupFailure(4, "invalid bundled Tor path: "+torPath)
	}
	if err := os.MkdirAll(appDir, 0700); err != nil {
		return startupFailure(5, "failed to create Cwtch directory: "+err.Error())
	}
	torDataDir := filepath.Join(appDir, "tor")
	if err := os.MkdirAll(torDataDir, 0700); err != nil {
		return startupFailure(6, "failed to create Tor data directory: "+err.Error())
	}
	if err := utils.InitGlobalSettingsFile(appDir, lcgconstants.DefactoPasswordForUnencryptedProfiles); err != nil {
		return startupFailure(7, "failed to initialize Cwtch settings: "+err.Error())
	}

	api := utils.LCG_API_Handler{
		LaunchServers: func() {},
		StopServers:   func() {},
	}
	cwtchcore.EventHandler = utils.NewEventHandler(api)
	log.ExcludeFromPattern("service.go")

	settings := utils.ReadGlobalSettings()
	// StegMS media transport is built on Cwtch's file-sharing overlay. Fresh
	// installs default that experiment off, which makes SendFile return an empty
	// result and prevents RequestMedia from starting. Enable it before profiles
	// and their protocol engines are loaded, and persist the setting.
	if settings.Experiments == nil {
		settings.Experiments = make(map[string]bool)
	}
	settings.ExperimentsEnabled = true
	settings.Experiments[modelconstants.FileSharingExperiment] = true
	utils.WriteGlobalSettings(*settings)
	cwtchcore.GlobalAppDir = appDir
	cwtchcore.GlobalTorPath = torPath

	mrand.Seed(int64(time.Now().Nanosecond()))
	socksPort := mrand.Intn(1000) + 9600
	controlPort := socksPort + 1
	key := make([]byte, 64)
	if _, err := rand.Read(key); err != nil {
		return startupFailure(8, "failed to generate Tor authentication key: "+err.Error())
	}

	if settings.AllowAdvancedTorConfig {
		controlPort = settings.CustomControlPort
		socksPort = settings.CustomSocksPort
	}

	torrc := tor.NewTorrc().WithSocksPort(socksPort).WithOnionTrafficOnly().WithControlPort(controlPort).WithHashedPassword(base64.StdEncoding.EncodeToString(key))

	if settings.UseCustomTorrc {
		customTorrc := settings.CustomTorrc
		torrc.WithCustom(strings.Split(customTorrc, "\n"))
	} else {
		settings.CustomTorrc = torrc.Preview()
		settings.CustomControlPort = controlPort
		settings.CustomSocksPort = socksPort
		utils.WriteGlobalSettings(*settings)
	}

	if err := torrc.Build(filepath.Join(torDataDir, "torrc")); err != nil {
		return startupFailure(9, "failed to build torrc: "+err.Error())
	}
	acn, err := tor.NewTorACNWithAuth(appDir, cwtchcore.GlobalTorPath, torDataDir, controlPort, tor.HashedPasswordAuthenticator{Password: base64.StdEncoding.EncodeToString(key)})
	if err != nil || acn == nil {
		if err == nil {
			return startupFailure(10, "Tor connectivity provider returned no runtime")
		}
		return startupFailure(10, "failed to construct Tor connectivity provider: "+err.Error())
	}
	proxyACN := connectivity.NewProxyACN(acn)
	cwtchcore.GlobalACN = &proxyACN
	cwtchcore.Application = app.NewApp(cwtchcore.GlobalACN, appDir)

	cwtchcore.EventHandler.HandleApp(cwtchcore.Application)
	if !noLoadProfiles {
		cwtchcore.Application.LoadProfiles(lcgconstants.DefactoPasswordForUnencryptedProfiles)
	}

	lastStartupError = ""
	return 0
}

func ShutdownCwtch() {
	cwtchcore.ShutdownCwtch()
}

func CreateProfile(nick string, password string, lifetime string) {
	cwtchcore.CreateProfileWithLifetime(nick, password, lifetime)
}

func LoadProfiles(password string) {
	cwtchcore.LoadProfiles(password)
}

func CreateEphemeralProfile(nick string, password string) {
	cwtchcore.CreateEphemeralProfile(nick, password)
}

func PromoteEphemeralProfile(profileOnion string, password string) string {
	err := cwtchcore.PromoteEphemeralProfile(profileOnion, password)
	if err != nil {
		return `{"status":"error","reason":"` + err.Error() + `"}`
	}
	return `{"status":"ok"}`
}

// ProfileHasPassword reports whether a loaded profile has a password ("" = none).
func ProfileHasPassword(profileOnion string) string {
	return cwtchcore.ProfileHasPassword(profileOnion, "")
}

// ExportProfile writes an identity backup encrypted with backupPassword.
func ExportProfile(profileOnion string, file string, currentPassword string, backupPassword string) string {
	return cwtchcore.ExportProfileWithPassword(profileOnion, file, currentPassword, backupPassword, "")
}

// RestoreProfileBackup restores an identity backup as it was ("" = no password).
func RestoreProfileBackup(file string, backupPassword string) string {
	return cwtchcore.RestoreProfileBackup(file, backupPassword, "")
}

func GetDuplicateProfiles() string {
	return cwtchcore.GetDuplicateProfiles()
}

func ExportDuplicateProfile(id string, side string, file string, currentPassword string, backupPassword string) string {
	return cwtchcore.ExportDuplicateProfile(id, side, file, currentPassword, backupPassword, "")
}

func ConfirmDuplicateBackup(id string, side string, file string, backupPassword string) string {
	return cwtchcore.ConfirmDuplicateBackup(id, side, file, backupPassword)
}

func ResolveDuplicateProfile(id string, action string, currentPassword string, duplicatePassword string) string {
	return cwtchcore.ResolveDuplicateProfile(id, action, currentPassword, duplicatePassword, "")
}

func ImportProfile(file string, password string) string {
	return cwtchcore.ImportProfile(file, password)
}

func GetLoadedProfiles() string {
	return cwtchcore.GetLoadedProfiles()
}

func GetProfileMetadata() string {
	return cwtchcore.GetProfileMetadata()
}

func SetProfileLifetime(profileOnion string, lifetime string) string {
	return cwtchcore.SetProfileLifetime(profileOnion, lifetime)
}

func DeleteProfile(profileOnion string, password string) string {
	return cwtchcore.DeleteProfile(profileOnion, password)
}

func SignChallenge(profileOnion string, challenge string) string {
	return cwtchcore.SignChallenge(profileOnion, challenge)
}

func GetOnionAddress(profileOnion string) string {
	return cwtchcore.GetOnionAddress(profileOnion)
}

func SendMessage(profileOnion string, peerOnion string, message string) string {
	return cwtchcore.SendMessage(profileOnion, peerOnion, message)
}

func SendInvitation(profileOnion string, peerOnion string, message string) string {
	return cwtchcore.SendInvitation(profileOnion, peerOnion, message)
}

func EnsureContact(profileOnion string, peerOnion string) string {
	return cwtchcore.EnsureContact(profileOnion, peerOnion)
}

func BlockContact(profileOnion string, peerOnion string) string {
	return cwtchcore.BlockContact(profileOnion, peerOnion)
}

func DeleteContact(profileOnion string, peerOnion string) string {
	return cwtchcore.DeleteContact(profileOnion, peerOnion)
}

func SendFile(profileOnion string, peerOnion string, filePath string) string {
	return cwtchcore.SendFile(profileOnion, peerOnion, filePath)
}

func GetTorState() string {
	return cwtchcore.GetTorState()
}

func GetPeerStates() string {
	return cwtchcore.GetPeerStates()
}

func GetPeerStatesForProfile(profileOnion string) string {
	return cwtchcore.GetPeerStatesForProfile(profileOnion)
}

func GetPeerState(profileOnion string, peerOnion string) string {
	return cwtchcore.GetPeerState(profileOnion, peerOnion)
}

func LockProfile(profileOnion string) string {
	return cwtchcore.LockProfile(profileOnion)
}

func ReconnectCwtchForeground() string {
	return cwtchcore.ReconnectCwtchForeground()
}

func GetConversationMap() string {
	return cwtchcore.GetConversationMap()
}

func GetConversationMapForProfile(profileOnion string) string {
	return cwtchcore.GetConversationMapForProfile(profileOnion)
}

func GetConversationMetadataForProfile(profileOnion string) string {
	return cwtchcore.GetConversationMetadataForProfile(profileOnion)
}

func GetMessages(profileOnion string, conversationID int32, messageIndex int32, count int32) string {
	return cwtchcore.GetMessages(profileOnion, int(conversationID), int(messageIndex), int(count))
}

func GetMediaOffers() string {
	return cwtchcore.GetMediaOffers()
}

func RequestMedia(transferID string) string {
	return cwtchcore.RequestMedia(transferID)
}

func PurgeGuestMedia(profileOnion string) string {
	return cwtchcore.PurgeGuestMedia(profileOnion)
}

func AuthorizeConversation(profileOnion string, peerOnion string, cwtchConversationID int32, stegmsConversationID string) string {
	return cwtchcore.AuthorizeConversation(profileOnion, peerOnion, cwtchConversationID, stegmsConversationID)
}

func GetAppBusEvent() string {
	return cwtchcore.GetAppBusEvent()
}
