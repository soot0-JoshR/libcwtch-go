package filesharing

import (
	"crypto/rand"
	app2 "cwtch.im/cwtch/app"
	"cwtch.im/cwtch/event"
	"cwtch.im/cwtch/functionality/filesharing"
	"cwtch.im/cwtch/model"
	"cwtch.im/cwtch/model/attr"
	"cwtch.im/cwtch/model/constants"
	"cwtch.im/cwtch/peer"
	"cwtch.im/cwtch/protocol/connections"
	"cwtch.im/cwtch/protocol/files"
	utils2 "cwtch.im/cwtch/utils"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"git.openprivacy.ca/openprivacy/connectivity/tor"
	"git.openprivacy.ca/openprivacy/log"

	// Import SQL Cipher
	mrand "math/rand"
	"os"
	"os/user"
	"path"
	"runtime"
	"runtime/pprof"
	"testing"
	"time"

	_ "github.com/mutecomm/go-sqlcipher/v4"
)

func waitForPeerPeerConnection(t *testing.T, peera peer.CwtchPeer, peerb peer.CwtchPeer) {
	for {
		state := peera.GetPeerState(peerb.GetOnion())
		if state == connections.FAILED {
			t.Fatalf("%v could not connect to %v", peera.GetOnion(), peerb.GetOnion())
		}
		if state != connections.AUTHENTICATED {
			fmt.Printf("peer %v waiting connect to peer %v, currently: %v\n", peera.GetOnion(), peerb.GetOnion(), connections.ConnectionStateName[state])
			time.Sleep(time.Second * 5)
			continue
		} else {
			peerAName, _ := peera.GetScopedZonedAttribute(attr.PublicScope, attr.ProfileZone, constants.Name)
			peerBName, _ := peerb.GetScopedZonedAttribute(attr.PublicScope, attr.ProfileZone, constants.Name)
			fmt.Printf("%v CONNECTED and AUTHED to %v\n", peerAName, peerBName)
			break
		}
	}
}

func TestFileSharing(t *testing.T) {
	numGoRoutinesStart := runtime.NumGoroutine()
	os.RemoveAll("cwtch.out.png")
	os.RemoveAll("cwtch.out.png.manifest")

	log.SetLevel(log.LevelInfo)

	os.Mkdir("tordir", 0700)
	dataDir := path.Join("tordir", "tor")
	os.MkdirAll(dataDir, 0700)

	// we don't need real randomness for the port, just to avoid a possible conflict...
	mrand.Seed(int64(time.Now().Nanosecond()))
	socksPort := mrand.Intn(1000) + 9051
	controlPort := mrand.Intn(1000) + 9052

	// generate a random password
	key := make([]byte, 64)
	_, err := rand.Read(key)
	if err != nil {
		panic(err)
	}

	torDataDir := ""
	if torDataDir, err = os.MkdirTemp(dataDir, "data-dir-"); err != nil {
		t.Fatalf("could not create data dir")
	}

	tor.NewTorrc().WithSocksPort(socksPort).WithOnionTrafficOnly().WithHashedPassword(base64.StdEncoding.EncodeToString(key)).WithControlPort(controlPort).Build("tordir/tor/torrc")
	acn, err := tor.NewTorACNWithAuth("./tordir", path.Join("..", "..", "tor"), torDataDir, controlPort, tor.HashedPasswordAuthenticator{Password: base64.StdEncoding.EncodeToString(key)})
	if err != nil {
		t.Fatalf("Could not start Tor: %v", err)
	}
	acn.WaitTillBootstrapped()
	defer acn.Close()

	app := app2.NewApp(acn, "./storage")

	usr, _ := user.Current()
	cwtchDir := path.Join(usr.HomeDir, ".cwtch")
	os.Mkdir(cwtchDir, 0700)
	os.RemoveAll(path.Join(cwtchDir, "testing"))
	os.Mkdir(path.Join(cwtchDir, "testing"), 0700)

	t.Logf("Creating Alice...")
	app.CreateTaggedPeer("alice", "asdfasdf", "testing")

	t.Logf("Creating Bob...")
	app.CreateTaggedPeer("bob", "asdfasdf", "testing")

	t.Logf("** Waiting for Alice, Bob...")
	alice := app2.WaitGetPeer(app, "alice")
	app.ActivatePeerEngine(alice.GetOnion(), true, true, true)
	bob := app2.WaitGetPeer(app, "bob")
	app.ActivatePeerEngine(bob.GetOnion(), true, true, true)

	alice.AutoHandleEvents([]event.Type{event.PeerStateChange, event.NewRetValMessageFromPeer})
	bob.AutoHandleEvents([]event.Type{event.PeerStateChange, event.NewRetValMessageFromPeer, event.ManifestReceived})

	queueOracle := event.NewQueue()
	app.GetEventBus(bob.GetOnion()).Subscribe(event.FileDownloaded, queueOracle)

	t.Logf("** Launching Peers...")

	waitTime := time.Duration(30) * time.Second
	t.Logf("** Waiting for Alice, Bob  to connect with onion network... (%v)\n", waitTime)
	time.Sleep(waitTime)

	bob.NewContactConversation(alice.GetOnion(), model.DefaultP2PAccessControl(), true)
	alice.NewContactConversation(bob.GetOnion(), model.DefaultP2PAccessControl(), true)
	alice.PeerWithOnion(bob.GetOnion())

	t.Logf("Waiting for alice and Bob to peer...")
	waitForPeerPeerConnection(t, alice, bob)

	t.Logf("Alice and Bob are Connected!!")

	filesharingFunctionality, _ := filesharing.FunctionalityGate(map[string]bool{constants.FileSharingExperiment: true})

	_, fileSharingMessage, err := filesharingFunctionality.ShareFile("cwtch.png", alice)
	alice.SendMessage(1, fileSharingMessage)

	if err != nil {
		t.Fatalf("Error!: %v", err)
	}

	// Wait for the messages to arrive...
	time.Sleep(time.Second * 10)

	// test that bob can download and verify the file
	testBobDownloadFile(t, bob, filesharingFunctionality, queueOracle)

	// Test stopping and restarting file shares
	t.Logf("Stopping File Share")
	alice.StopAllFileShares()

	// Allow time for the stop request to filter through Engine
	time.Sleep(time.Second * 5)

	// Restart
	t.Logf("Restarting File Share")
	filesharingFunctionality.ReShareFiles(alice)

	// run the same download test again...to check that we can actually download the file
	testBobDownloadFile(t, bob, filesharingFunctionality, queueOracle)

	// test that we can delete bob...
	app.DeletePeer(bob.GetOnion(), "asdfasdf")

	queueOracle.Shutdown()
	app.Shutdown()
	acn.Close()
	time.Sleep(5 * time.Second)
	numGoRoutinesPostACN := runtime.NumGoroutine()

	// Printing out the current goroutines
	// Very useful if we are leaking any.
	pprof.Lookup("goroutine").WriteTo(os.Stdout, 1)

	if numGoRoutinesStart != numGoRoutinesPostACN {
		t.Errorf("Number of GoRoutines at start (%v) does not match number of goRoutines after cleanup of peers and servers (%v), clean up failed, leak detected!", numGoRoutinesStart, numGoRoutinesPostACN)
	}

}

func testBobDownloadFile(t *testing.T, bob peer.CwtchPeer, filesharingFunctionality *filesharing.Functionality, queueOracle event.Queue) {

	os.RemoveAll("cwtch.out.png")
	os.RemoveAll("cwtch.out.png.manifest")

	message, _, err := bob.GetChannelMessage(1, 0, 1)
	if err != nil {
		t.Fatalf("could not find file sharing message: %v", err)
	}

	var messageWrapper model.MessageWrapper
	json.Unmarshal([]byte(message), &messageWrapper)

	if messageWrapper.Overlay == model.OverlayFileSharing {
		var fileMessageOverlay filesharing.OverlayMessage
		err := json.Unmarshal([]byte(messageWrapper.Data), &fileMessageOverlay)

		if err == nil {

			// try downloading with invalid download dir
			err = filesharingFunctionality.DownloadFile(bob, 1, "/do/not/download/this/file/cwtch.out.png", "./cwtch.out.png.manifest", fmt.Sprintf("%s.%s", fileMessageOverlay.Hash, fileMessageOverlay.Nonce), constants.ImagePreviewMaxSizeInBytes)
			if err == nil {
				t.Fatalf("should not download file with invalid download dir")
			}

			// try downloading with invalid manifest dir
			err = filesharingFunctionality.DownloadFile(bob, 1, "./cwtch.out.png", "/do/not/download/this/file/cwtch.out.png.manifest", fmt.Sprintf("%s.%s", fileMessageOverlay.Hash, fileMessageOverlay.Nonce), constants.ImagePreviewMaxSizeInBytes)
			if err == nil {
				t.Fatalf("should not download file with invalid manifest dir")
			}

			err = filesharingFunctionality.DownloadFile(bob, 1, "./cwtch.out.png", "./cwtch.out.png.manifest", fmt.Sprintf("%s.%s", fileMessageOverlay.Hash, fileMessageOverlay.Nonce), constants.ImagePreviewMaxSizeInBytes)
			if err != nil {
				t.Fatalf("could not download file: %v", err)
			}
		}
	}

	// Wait for the file downloaded event
	ClientTimeout := utils2.TimeoutPolicy(time.Second * 120)
	err = ClientTimeout.ExecuteAction(func() error {
		ev := queueOracle.Next()
		if ev.EventType != event.FileDownloaded {
			t.Fatalf("Expected file download event")
		}

		manifest, _ := files.CreateManifest("cwtch.out.png")
		if hex.EncodeToString(manifest.RootHash) != "8f0ed73bbb30db45b6a740b1251cae02945f48e4f991464d5f3607685c45dcd136a325dab2e5f6429ce2b715e602b20b5b16bf7438fb6235fefe912adcedb5fd" {
			t.Fatalf("file hash does not match expected %x: ", manifest.RootHash)
		}
		return nil
	})

	if err != nil {
		t.Fatalf("timeout when attempting to download a file")
	}
}
