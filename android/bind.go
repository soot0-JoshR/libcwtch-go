package cwtch

import (
	"git.openprivacy.ca/cwtch.im/libcwtch-go/cwtchcore"
	"git.openprivacy.ca/cwtch.im/libcwtch-go/utils"
	lcgconstants "git.openprivacy.ca/cwtch.im/libcwtch-go/constants"
	"git.openprivacy.ca/openprivacy/connectivity"
	"git.openprivacy.ca/openprivacy/connectivity/tor"
	"git.openprivacy.ca/openprivacy/log"
	"cwtch.im/cwtch/app"
	
	"crypto/rand"
	"encoding/base64"
	"os"
	"path/filepath"
	"time"
	mrand "math/rand"
	"strings"
)

// StartCwtch initializes the Cwtch application instance for Android and assigns it to cwtchcore.
func StartCwtch(appDir string, torPath string) int32 {
	if cwtchcore.Application != nil {
		return 0
	}

	api := utils.LCG_API_Handler{
		LaunchServers: func() {},
		StopServers:   func() {},
	}
	cwtchcore.EventHandler = utils.NewEventHandler(api)
	log.ExcludeFromPattern("service.go")

	os.MkdirAll(appDir, 0700)
	utils.InitGlobalSettingsFile(appDir, lcgconstants.DefactoPasswordForUnencryptedProfiles)
	os.MkdirAll(filepath.Join(appDir, "tor"), 0700)

	settings := utils.ReadGlobalSettings()
	cwtchcore.GlobalAppDir = appDir
	cwtchcore.GlobalTorPath = torPath

	mrand.Seed(int64(time.Now().Nanosecond()))
	socksPort := mrand.Intn(1000) + 9600
	controlPort := socksPort + 1
	key := make([]byte, 64)
	rand.Read(key)

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

	torrc.Build(filepath.Join(appDir, "tor", "torrc"))
	acn, _ := tor.NewTorACNWithAuth(appDir, cwtchcore.GlobalTorPath, filepath.Join(appDir, "tor"), controlPort, tor.HashedPasswordAuthenticator{Password: base64.StdEncoding.EncodeToString(key)})
	cwtchcore.GlobalACN = connectivity.NewProxyACN(acn)
	cwtchcore.Application = app.NewApp(&cwtchcore.GlobalACN, appDir)

	cwtchcore.EventHandler.HandleApp(cwtchcore.Application)
	cwtchcore.Application.LoadProfiles(lcgconstants.DefactoPasswordForUnencryptedProfiles)

	return 0
}

func ShutdownCwtch() {
	cwtchcore.ShutdownCwtch()
}

func CreateProfile(nick string, password string) {
	cwtchcore.CreateProfile(nick, password)
}

func LoadProfiles(password string) {
	cwtchcore.LoadProfiles(password)
}

func GetLoadedProfiles() string {
	return cwtchcore.GetLoadedProfiles()
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

func SendFile(profileOnion string, peerOnion string, filePath string) {
	cwtchcore.SendFile(profileOnion, peerOnion, filePath)
}

func GetTorState() string {
	return cwtchcore.GetTorState()
}

func GetPeerStates() string {
	return cwtchcore.GetPeerStates()
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
