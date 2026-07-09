package cwtch

import (
	"cwtch.im/cwtch/app"
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

// StartCwtch initializes the Cwtch application instance for Android and assigns it to cwtchcore.
func StartCwtch(appDir string, torPath string) int32 {
	if cwtchcore.Application != nil {
		return 0
	}
	if runtime.GOARCH != "arm64" {
		log.Errorf("unsupported Android Cwtch architecture: %s", runtime.GOARCH)
		return 2
	}
	if appDir == "" || torPath == "" {
		log.Errorf("Cwtch startup requires app and Tor paths")
		return 3
	}
	if info, err := os.Stat(torPath); err != nil || info.IsDir() {
		log.Errorf("invalid bundled Tor path %q: %v", torPath, err)
		return 4
	}
	if err := os.MkdirAll(appDir, 0700); err != nil {
		log.Errorf("failed to create Cwtch directory: %v", err)
		return 5
	}
	torDataDir := filepath.Join(appDir, "tor")
	if err := os.MkdirAll(torDataDir, 0700); err != nil {
		log.Errorf("failed to create Tor data directory: %v", err)
		return 6
	}
	if err := utils.InitGlobalSettingsFile(appDir, lcgconstants.DefactoPasswordForUnencryptedProfiles); err != nil {
		log.Errorf("failed to initialize Cwtch settings: %v", err)
		return 7
	}

	api := utils.LCG_API_Handler{
		LaunchServers: func() {},
		StopServers:   func() {},
	}
	cwtchcore.EventHandler = utils.NewEventHandler(api)
	log.ExcludeFromPattern("service.go")

	settings := utils.ReadGlobalSettings()
	cwtchcore.GlobalAppDir = appDir
	cwtchcore.GlobalTorPath = torPath

	mrand.Seed(int64(time.Now().Nanosecond()))
	socksPort := mrand.Intn(1000) + 9600
	controlPort := socksPort + 1
	key := make([]byte, 64)
	if _, err := rand.Read(key); err != nil {
		log.Errorf("failed to generate Tor authentication key: %v", err)
		return 8
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
		log.Errorf("failed to build torrc: %v", err)
		return 9
	}
	acn, err := tor.NewTorACNWithAuth(appDir, cwtchcore.GlobalTorPath, torDataDir, controlPort, tor.HashedPasswordAuthenticator{Password: base64.StdEncoding.EncodeToString(key)})
	if err != nil || acn == nil {
		log.Errorf("failed to construct Tor ACN: %v", err)
		if err == nil {
			log.Errorf("Tor ACN was nil")
		}
		return 10
	}
	cwtchcore.GlobalACN = connectivity.NewProxyACN(acn)
	cwtchcore.Application = app.NewApp(&cwtchcore.GlobalACN, appDir)

	cwtchcore.EventHandler.HandleApp(cwtchcore.Application)
	cwtchcore.Application.LoadProfiles(lcgconstants.DefactoPasswordForUnencryptedProfiles)

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

func ImportProfile(file string, password string) string {
	errStr := cwtchcore.ImportProfile(file, password)
	if errStr != "" {
		return `{"status":"error","reason":"` + errStr + `"}`
	}
	return `{"status":"ok"}`
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

func SendFile(profileOnion string, peerOnion string, filePath string) {
	cwtchcore.SendFile(profileOnion, peerOnion, filePath)
}

func GetTorState() string {
	return cwtchcore.GetTorState()
}

func GetPeerStates() string {
	return cwtchcore.GetPeerStates()
}

func GetPeerState(profileOnion string, peerOnion string) string {
	return cwtchcore.GetPeerState(profileOnion, peerOnion)
}

func GetConversationMap() string {
	return cwtchcore.GetConversationMap()
}

func GetMediaOffers() string {
	return cwtchcore.GetMediaOffers()
}

func RequestMedia(transferID string) {
	cwtchcore.RequestMedia(transferID)
}

func AuthorizeConversation(profileOnion string, peerOnion string, cwtchConversationID int32, stegmsConversationID int32) {
	cwtchcore.AuthorizeConversation(profileOnion, peerOnion, cwtchConversationID, stegmsConversationID)
}

func GetAppBusEvent() string {
	return cwtchcore.GetAppBusEvent()
}
