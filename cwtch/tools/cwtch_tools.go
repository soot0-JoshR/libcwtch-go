package main

import (
	"crypto/rand"
	"cwtch.im/cwtch/model"
	"cwtch.im/cwtch/model/constants"
	"cwtch.im/cwtch/protocol/connections"
	"cwtch.im/cwtch/protocol/groups"
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"git.openprivacy.ca/cwtch.im/tapir/primitives/privacypass"
	"git.openprivacy.ca/openprivacy/connectivity/tor"
	"git.openprivacy.ca/openprivacy/log"
	"github.com/gtank/ristretto255"
	mrand "math/rand"
	"os"
	path "path/filepath"
	"strings"
	"time"
)

var tool = flag.String("tool", "", "the tool to use")
var bundle = flag.String("bundle", "", "a server bundle to parse")

func main() {
	flag.Parse()

	if *tool == "" {
		fmt.Fprintf(os.Stderr, "usage: cwtch_tools -tool <tool>\n")
		flag.PrintDefaults()
	}

	switch *tool {
	case "bundleparse":
		bundle, err := bundleParse(*bundle)
		if err == nil {
			fmt.Printf("bundle: %s\n", bundle.Serialize())
		} else {
			fmt.Printf("error parsing bundle: %v", err)
		}
	case "gettokens":
		getTokens(*bundle)
	default:
		fmt.Fprintf(os.Stderr, "unknown tool: %s \n", *tool)
	}

}

func bundleParse(bundle string) (*model.KeyBundle, error) {
	if strings.HasPrefix(bundle, constants.ServerPrefix) {
		bundle, err := base64.StdEncoding.DecodeString(bundle[len(constants.ServerPrefix):])
		if err != nil {
			fmt.Printf("invalid server bundle: %v\n", err)
		}
		keyBundle, err := model.DeserializeAndVerify([]byte(bundle))
		return keyBundle, err
	} else {
		return nil, fmt.Errorf("unknown bundle prefix")
	}
}

func getTokens(bundle string) {
	log.SetLevel(log.LevelDebug)
	keyBundle, err := bundleParse(bundle)
	if err != nil {
		log.Errorf("error parsing keybundle: %v", err)
		return
	}

	privacyPassKey, err := keyBundle.GetKey(model.KeyTypePrivacyPass)
	if err != nil {
		log.Errorf("error parsing keybundle: %v", err)
		return
	}

	tokenServiceKey, err := keyBundle.GetKey(model.KeyTypeTokenOnion)
	if err != nil {
		log.Errorf("error parsing keybundle: %v", err)
		return
	}

	os.Mkdir("tordir", 0700)
	dataDir := path.Join("tordir", "tor")
	os.MkdirAll(dataDir, 0700)

	// we don't need real randomness for the port, just to avoid a possible conflict...
	mrand.Seed(int64(time.Now().Nanosecond()))
	socksPort := mrand.Intn(1000) + 9051
	controlPort := mrand.Intn(1000) + 9052

	// generate a random password
	key := make([]byte, 64)
	_, err = rand.Read(key)
	if err != nil {
		log.Errorf("insufficient randomness: %v", err)
		return
	}

	torDataDir := "./data-dir-cwtchtool"
	if err = os.MkdirAll(torDataDir, 0700); err != nil {
		log.Errorf("could not create data dir")
		return
	}

	tor.NewTorrc().WithSocksPort(socksPort).WithOnionTrafficOnly().WithHashedPassword(base64.StdEncoding.EncodeToString(key)).WithControlPort(controlPort).Build("tordir/tor/torrc")
	acn, err := tor.NewTorACNWithAuth("./tordir", path.Join("..", "tor"), torDataDir, controlPort, tor.HashedPasswordAuthenticator{Password: base64.StdEncoding.EncodeToString(key)})
	if err != nil {
		log.Errorf("Could not start Tor: %v", err)
		return
	}
	acn.WaitTillBootstrapped()
	defer acn.Close()

	Y := new(ristretto255.Element)
	Y.UnmarshalText([]byte(privacyPassKey))

	tokenServer := privacypass.NewTokenServer()
	tokenServer.Y = Y

	err = connections.MakePayment(string(tokenServiceKey), tokenServer, acn, Handler{})
	if err != nil {
		log.Errorf("timed out trying to get payments")
	}
}

type Handler struct {
}

func (h Handler) PostingFailed(server string, sig []byte) {

}

func (h Handler) GroupMessageHandler(server string, gm *groups.EncryptedGroupMessage) {
}

func (h Handler) ServerAuthedHandler(server string) {
}

func (h Handler) ServerSyncedHandler(server string) {
}

func (h Handler) ServerClosedHandler(server string) {
}

func (h Handler) NewTokenHandler(tokenService string, tokens []*privacypass.Token) {
	data, _ := json.Marshal(tokens)
	os.WriteFile("tokens", data, 0600)
}

func (h Handler) FetchToken(tokenService string) (*privacypass.Token, int, error) {
	return nil, 0, nil
}
