package testing

import (
	"crypto/rand"
	app2 "cwtch.im/cwtch/app"
	"cwtch.im/cwtch/event"
	"cwtch.im/cwtch/model"
	"cwtch.im/cwtch/model/attr"
	"cwtch.im/cwtch/model/constants"
	"cwtch.im/cwtch/peer"
	"cwtch.im/cwtch/protocol/connections"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"git.openprivacy.ca/cwtch.im/tapir/primitives/privacypass"
	"git.openprivacy.ca/openprivacy/connectivity/tor"
	"git.openprivacy.ca/openprivacy/log"
	_ "github.com/mutecomm/go-sqlcipher/v4"
	mrand "math/rand"
	"os"
	"os/user"
	"path"
	"path/filepath"
	"runtime"
	"runtime/pprof"
	"strconv"
	"testing"
	"time"
)

var (
	aliceLines = []string{"Hello, I'm Alice", "bye"}
	bobLines   = []string{"Hi, my name is Bob.", "toodles", "welcome"}
	carolLines = []string{"Howdy, thanks!"}
)

func waitForConnection(t *testing.T, peer peer.CwtchPeer, addr string, target connections.ConnectionState) {
	peerName, _ := peer.GetScopedZonedAttribute(attr.LocalScope, attr.ProfileZone, constants.Name)
	for {
		log.Infof("%v checking connection...\n", peerName)
		state := peer.GetPeerState(addr)
		log.Infof("Waiting for Peer %v to %v - state: %v\n", peerName, addr, connections.ConnectionStateName[state])
		if state == connections.FAILED {
			t.Fatalf("%v could not connect to %v", peer.GetOnion(), addr)
		}
		if state != target {
			log.Infof("peer %v  %v waiting connect  %v, currently: %v\n", peerName, peer.GetOnion(), addr, connections.ConnectionStateName[state])
			time.Sleep(time.Second * 5)
			continue
		} else {
			log.Infof("peer %v  %v CONNECTED to %v\n", peerName, peer.GetOnion(), addr)
			break
		}
	}
}

func waitForRetVal(peer peer.CwtchPeer, convId int, szp attr.ScopedZonedPath) {
	for {
		_, err := peer.GetConversationAttribute(convId, szp)
		if err == nil {
			return
		}
		time.Sleep(time.Second * 5)
	}
}

func checkAndLoadTokens() []*privacypass.Token {
	var tokens []*privacypass.Token
	data, err := os.ReadFile("../tokens")
	if err == nil {
		err := json.Unmarshal(data, &tokens)
		if err != nil {
			log.Errorf("could not load tokens from file")
		}
	}
	return tokens
}

func TestCwtchPeerIntegration(t *testing.T) {

	// Goroutine Monitoring Start..
	numGoRoutinesStart := runtime.NumGoroutine()

	log.AddEverythingFromPattern("connectivity")
	log.SetLevel(log.LevelDebug)
	log.ExcludeFromPattern("connection/connection")
	log.ExcludeFromPattern("outbound/3dhauthchannel")
	log.ExcludeFromPattern("event/eventmanager")
	log.ExcludeFromPattern("tapir")

	// checking if we should use the token cache
	cachedTokens := checkAndLoadTokens()
	if len(cachedTokens) > 7 {
		log.Infof("using cached tokens")
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
	_, err := rand.Read(key)
	if err != nil {
		panic(err)
	}

	useCache := os.Getenv("TORCACHE") == "true"

	torDataDir := ""
	if useCache {
		log.Infof("using tor cache")
		torDataDir = filepath.Join(dataDir, "data-dir-torcache")
		os.MkdirAll(torDataDir, 0700)
	} else {
		log.Infof("using clean tor data dir")
		if torDataDir, err = os.MkdirTemp(dataDir, "data-dir-"); err != nil {
			t.Fatalf("could not create data dir")
		}
	}

	tor.NewTorrc().WithSocksPort(socksPort).WithOnionTrafficOnly().WithHashedPassword(base64.StdEncoding.EncodeToString(key)).WithControlPort(controlPort).Build("tordir/tor/torrc")
	acn, err := tor.NewTorACNWithAuth("./tordir", path.Join("..", "tor"), torDataDir, controlPort, tor.HashedPasswordAuthenticator{Password: base64.StdEncoding.EncodeToString(key)})
	if err != nil {
		t.Fatalf("Could not start Tor: %v", err)
	}
	log.Infof("Waiting for tor to bootstrap...")
	acn.WaitTillBootstrapped()
	defer acn.Close()

	// ***** Cwtch Server management *****

	const ServerKeyBundleBase64 = "eyJLZXlzIjp7ImJ1bGxldGluX2JvYXJkX29uaW9uIjoibmZoeHp2enhpbnJpcGdkaDR0Mm00eGN5M2NyZjZwNGNiaGVjdGdja3VqM2lkc2pzYW90Z293YWQiLCJwcml2YWN5X3Bhc3NfcHVibGljX2tleSI6IjVwd2hQRGJ0c0EvdFI3ZHlUVUkzakpZZnM1L3Jaai9iQ1ZWZEpTc0Jtbk09IiwidG9rZW5fc2VydmljZV9vbmlvbiI6ImVvd25mcTRsNTZxMmU0NWs0bW03MjdsanJod3Z0aDZ5ZWN0dWV1bXB4emJ5cWxnbXVhZm1qdXFkIn0sIlNpZ25hdHVyZSI6IlY5R3NPMHNZWFJ1bGZxdzdmbGdtclVxSTBXS0JlSFIzNjIvR3hGbWZPekpEZjJaRks2ck9jNVRRR1ZxVWIrbXIwV2xId0pwdXh0UW1JRU9KNkplYkNRPT0ifQ=="
	const ServerAddr = "nfhxzvzxinripgdh4t2m4xcy3crf6p4cbhectgckuj3idsjsaotgowad"
	serverKeyBundle, _ := base64.StdEncoding.DecodeString(ServerKeyBundleBase64)

	app := app2.NewApp(acn, "./storage")

	usr, _ := user.Current()
	cwtchDir := path.Join(usr.HomeDir, ".cwtch")
	os.Mkdir(cwtchDir, 0700)
	os.RemoveAll(path.Join(cwtchDir, "testing"))
	os.Mkdir(path.Join(cwtchDir, "testing"), 0700)

	numGoRoutinesPostAppStart := runtime.NumGoroutine()

	// ***** cwtchPeer setup *****

	log.Infoln("Creating Alice...")
	app.CreateTaggedPeer("Alice", "asdfasdf", "test")

	log.Infoln("Creating Bob...")
	app.CreateTaggedPeer("Bob", "asdfasdf", "test")

	log.Infoln("Creating Carol...")
	app.CreateTaggedPeer("Carol", "asdfasdf", "test")

	alice := app2.WaitGetPeer(app, "Alice")
	aliceBus := app.GetEventBus(alice.GetOnion())
	app.ActivatePeerEngine(alice.GetOnion(), true, true, true)
	log.Infoln("Alice created:", alice.GetOnion())
	alice.SetScopedZonedAttribute(attr.PublicScope, attr.ProfileZone, constants.Name, "Alice")
	alice.AutoHandleEvents([]event.Type{event.PeerStateChange, event.ServerStateChange, event.NewGroupInvite, event.NewRetValMessageFromPeer})

	bob := app2.WaitGetPeer(app, "Bob")
	bobBus := app.GetEventBus(bob.GetOnion())
	app.ActivatePeerEngine(bob.GetOnion(), true, true, true)
	log.Infoln("Bob created:", bob.GetOnion())
	bob.SetScopedZonedAttribute(attr.PublicScope, attr.ProfileZone, constants.Name, "Bob")
	bob.AutoHandleEvents([]event.Type{event.PeerStateChange, event.ServerStateChange, event.NewGroupInvite, event.NewRetValMessageFromPeer})

	carol := app2.WaitGetPeer(app, "Carol")
	carolBus := app.GetEventBus(carol.GetOnion())
	app.ActivatePeerEngine(carol.GetOnion(), true, true, true)
	log.Infoln("Carol created:", carol.GetOnion())
	carol.SetScopedZonedAttribute(attr.PublicScope, attr.ProfileZone, constants.Name, "Carol")
	carol.AutoHandleEvents([]event.Type{event.PeerStateChange, event.ServerStateChange, event.NewGroupInvite, event.NewRetValMessageFromPeer})

	waitTime := time.Duration(60) * time.Second
	log.Infof("** Waiting for Alice, Bob, and Carol to register their onion hidden service on the network... (%v)\n", waitTime)
	time.Sleep(waitTime)
	numGoRoutinesPostPeerStart := runtime.NumGoroutine()
	log.Infof("** Wait Done!")

	// ***** Peering, server joining, group creation / invite *****

	log.Infoln("Alice and Bob creating conversations...")
	// Simulate Alice Adding Bob
	log.Infof("  alice.NewConvo(bob)...")
	alice2bobConversationID, err := alice.NewContactConversation(bob.GetOnion(), model.DefaultP2PAccessControl(), true)
	if err != nil {
		t.Fatalf("error adding conversaiton %v", alice2bobConversationID)
	}
	log.Infof("  bob.NewConvo(alice)...")
	bob2aliceConversationID, err := bob.NewContactConversation(alice.GetOnion(), model.DefaultP2PAccessControl(), true)
	if err != nil {
		t.Fatalf("error adding conversaiton %v", bob2aliceConversationID)
	}

	log.Infof("Alice and Carol creating conversations...")
	// Simulate Alice Adding Carol
	alice2carolConversationID, err := alice.NewContactConversation(carol.GetOnion(), model.DefaultP2PAccessControl(), true)
	if err != nil {
		t.Fatalf("error adding conversaiton %v", alice2carolConversationID)
	}
	carol2aliceConversationID, err := carol.NewContactConversation(alice.GetOnion(), model.DefaultP2PAccessControl(), true)
	if err != nil {
		t.Fatalf("error adding conversaiton %v", carol2aliceConversationID)
	}

	log.Infof("Alice peering with Bob...")
	alice.PeerWithOnion(bob.GetOnion())
	log.Infof("Alice Peering with Carol...")
	alice.PeerWithOnion(carol.GetOnion())

	// Test that we can rekey alice without issues...
	err = alice.ChangePassword("asdfasdf", "password 1 2 3", "password 1 2 3")

	if err != nil {
		t.Fatalf("error changing password for Alice: %v", err)
	}

	if !alice.CheckPassword("password 1 2 3") {
		t.Fatalf("Alice password did not change...")
	}

	waitForConnection(t, alice, bob.GetOnion(), connections.AUTHENTICATED)
	waitForConnection(t, alice, carol.GetOnion(), connections.AUTHENTICATED)
	waitForConnection(t, bob, alice.GetOnion(), connections.AUTHENTICATED)
	waitForConnection(t, carol, alice.GetOnion(), connections.AUTHENTICATED)

	log.Infof("Alice and Bob getVal public.name...")

	alice.SendScopedZonedGetValToContact(alice2bobConversationID, attr.PublicScope, attr.ProfileZone, constants.Name)
	bob.SendScopedZonedGetValToContact(bob2aliceConversationID, attr.PublicScope, attr.ProfileZone, constants.Name)

	alice.SendScopedZonedGetValToContact(alice2carolConversationID, attr.PublicScope, attr.ProfileZone, constants.Name)
	carol.SendScopedZonedGetValToContact(carol2aliceConversationID, attr.PublicScope, attr.ProfileZone, constants.Name)

	// This used to be 10, but increasing it to 30 because this is now causing frequent issues
	// Probably related to latency/throughput problems in the underlying tor network.
	time.Sleep(30 * time.Second)

	waitForRetVal(bob, bob2aliceConversationID, attr.PublicScope.ConstructScopedZonedPath(attr.ProfileZone.ConstructZonedPath(constants.Name)))
	aliceName, err := bob.GetConversationAttribute(bob2aliceConversationID, attr.PublicScope.ConstructScopedZonedPath(attr.ProfileZone.ConstructZonedPath(constants.Name)))
	if err != nil || aliceName != "Alice" {
		t.Fatalf("Bob: alice GetKeyVal error on alice peer.name %v: %v\n", aliceName, err)
	}
	log.Infof("Bob has alice's name as '%v'\n", aliceName)

	waitForRetVal(alice, alice2bobConversationID, attr.PublicScope.ConstructScopedZonedPath(attr.ProfileZone.ConstructZonedPath(constants.Name)))
	bobName, err := alice.GetConversationAttribute(alice2bobConversationID, attr.PublicScope.ConstructScopedZonedPath(attr.ProfileZone.ConstructZonedPath(constants.Name)))
	if err != nil || bobName != "Bob" {
		t.Fatalf("Alice: bob GetKeyVal error on bob peer.name %v: %v \n", bobName, err)
	}
	log.Infof("Alice has bob's name as '%v'\n", bobName)

	waitForRetVal(carol, carol2aliceConversationID, attr.PublicScope.ConstructScopedZonedPath(attr.ProfileZone.ConstructZonedPath(constants.Name)))
	aliceName, err = carol.GetConversationAttribute(carol2aliceConversationID, attr.PublicScope.ConstructScopedZonedPath(attr.ProfileZone.ConstructZonedPath(constants.Name)))
	if err != nil || aliceName != "Alice" {
		t.Fatalf("carol GetKeyVal error for alice peer.name %v: %v\n", aliceName, err)
	}

	waitForRetVal(alice, alice2carolConversationID, attr.PublicScope.ConstructScopedZonedPath(attr.ProfileZone.ConstructZonedPath(constants.Name)))
	carolName, err := alice.GetConversationAttribute(alice2carolConversationID, attr.PublicScope.ConstructScopedZonedPath(attr.ProfileZone.ConstructZonedPath(constants.Name)))
	if err != nil || carolName != "Carol" {
		t.Fatalf("alice GetKeyVal error, carol peer.name: %v: %v\n", carolName, err)
	}
	log.Infof("Alice has carol's name as '%v'\n", carolName)

	// Group Testing
	usedTokens := len(aliceLines)
	// Simulate Alice Creating a Group
	log.Infoln("Alice joining server...")
	if serverOnion, err := alice.AddServer(string(serverKeyBundle)); err != nil {
		if len(cachedTokens) > len(aliceLines) {
			alice.StoreCachedTokens(serverOnion, cachedTokens[0:len(aliceLines)])
		}

		t.Fatalf("Failed to Add Server Bundle %v", err)
	}

	// Creating a Group
	log.Infof("Creating group on %v...", ServerAddr)
	aliceGroupConversationID, err := alice.StartGroup("Our Cool Testing Group", ServerAddr)
	log.Infof("Created group: %v!\n", aliceGroupConversationID)
	if err != nil {
		t.Errorf("Failed to init group: %v", err)
		return
	}

	// Invites
	log.Infoln("Alice inviting Bob to group...")
	_, err = alice.SendInviteToConversation(alice2bobConversationID, aliceGroupConversationID)
	if err != nil {
		t.Fatalf("Error for Alice inviting Bob to group: %v", err)
	}
	time.Sleep(time.Second * 5)

	// Alice invites Bob to the Group...
	message, _, err := bob.GetChannelMessage(bob2aliceConversationID, 0, 1)
	log.Infof("Alice message to Bob %v %v", message, err)
	var overlayMessage model.MessageWrapper
	json.Unmarshal([]byte(message), &overlayMessage)
	log.Infof("Parsed Overlay Message: %v", overlayMessage)
	err = bob.ImportBundle(overlayMessage.Data)
	log.Infof("Result of Bob Importing the Bundle from Alice: %v", err)
	if len(cachedTokens) > (usedTokens + len(bobLines)) {
		bob.StoreCachedTokens(ServerAddr, cachedTokens[usedTokens:usedTokens+len(bobLines)])
		usedTokens += len(bobLines)
	}

	log.Infof("Waiting for alice to join server...")
	waitForConnection(t, alice, ServerAddr, connections.SYNCED)
	log.Infof("Waiting for Bob to join connect to group server...")
	waitForConnection(t, bob, ServerAddr, connections.SYNCED)

	// 1 = Alice
	// 2 = Server
	// 3 = Group...
	bobGroupConversationID := 3

	numGoRoutinesPostServerConnect := runtime.NumGoroutine()

	// ***** Conversation *****
	log.Infof("Starting conversation in group...")
	checkSendMessageToGroup(t, alice, aliceBus, aliceGroupConversationID, aliceLines[0])
	checkSendMessageToGroup(t, bob, bobBus, bobGroupConversationID, bobLines[0])
	checkSendMessageToGroup(t, alice, aliceBus, aliceGroupConversationID, aliceLines[1])
	checkSendMessageToGroup(t, bob, bobBus, bobGroupConversationID, bobLines[1])

	// Pretend that Carol Acquires the Overlay Message through some other means...
	json.Unmarshal([]byte(message), &overlayMessage)
	log.Infof("Parsed Overlay Message: %v", overlayMessage)
	err = carol.ImportBundle(overlayMessage.Data)
	log.Infof("Result of Carol Importing the Bundle from Alice: %v", err)
	log.Infof("Waiting for Carol to join connect to group server...")
	carolGroupConversationID := 3
	if len(cachedTokens) > (usedTokens + len(carolLines)) {
		carol.StoreCachedTokens(ServerAddr, cachedTokens[usedTokens:usedTokens+len(carolLines)])
	}
	waitForConnection(t, carol, ServerAddr, connections.SYNCED)
	numGoRoutinesPostCarolConnect := runtime.NumGoroutine()

	// Check Alice Timeline
	log.Infof("Checking Alice's Timeline...")
	checkMessage(t, alice, aliceGroupConversationID, 1, aliceLines[0])
	checkMessage(t, alice, aliceGroupConversationID, 2, bobLines[0])
	checkMessage(t, alice, aliceGroupConversationID, 3, aliceLines[1])
	checkMessage(t, alice, aliceGroupConversationID, 4, bobLines[1])

	log.Infof("Shutting down Alice...")
	app.ShutdownPeer(alice.GetOnion())
	time.Sleep(time.Second * 3)
	numGoRoutinesPostAlice := runtime.NumGoroutine()

	checkSendMessageToGroup(t, carol, carolBus, carolGroupConversationID, carolLines[0])
	checkSendMessageToGroup(t, bob, bobBus, bobGroupConversationID, bobLines[2])

	// Time to Sync
	time.Sleep(time.Second * 10)

	// Check Bob Timeline
	log.Infof("Checking Bob's Timeline...")
	checkMessage(t, bob, bobGroupConversationID, 1, aliceLines[0])
	checkMessage(t, bob, bobGroupConversationID, 2, bobLines[0])
	checkMessage(t, bob, bobGroupConversationID, 3, aliceLines[1])
	checkMessage(t, bob, bobGroupConversationID, 4, bobLines[1])
	checkMessage(t, bob, bobGroupConversationID, 5, carolLines[0])
	checkMessage(t, bob, bobGroupConversationID, 6, bobLines[2])

	// Check Carol Timeline
	log.Infof("Checking Carols's Timeline...")
	checkMessage(t, carol, carolGroupConversationID, 1, aliceLines[0])
	checkMessage(t, carol, carolGroupConversationID, 2, bobLines[0])
	checkMessage(t, carol, carolGroupConversationID, 3, aliceLines[1])
	checkMessage(t, carol, carolGroupConversationID, 4, bobLines[1])
	checkMessage(t, carol, carolGroupConversationID, 5, carolLines[0])
	checkMessage(t, carol, carolGroupConversationID, 6, bobLines[2])

	log.Infof("Shutting down Bob...")
	app.ShutdownPeer(bob.GetOnion())
	time.Sleep(time.Second * 3)
	numGoRoutinesPostBob := runtime.NumGoroutine()

	log.Infof("Shutting down Carol...")
	app.ShutdownPeer(carol.GetOnion())
	time.Sleep(time.Second * 3)
	numGoRoutinesPostCarol := runtime.NumGoroutine()

	log.Infof("Shutting down apps...")
	log.Infof("app Shutdown: %v\n", runtime.NumGoroutine())
	app.Shutdown()

	time.Sleep(2 * time.Second)

	log.Infof("Done shutdown: %v\n", runtime.NumGoroutine())

	log.Infof("Shutting down ACN...")
	acn.Close()
	time.Sleep(time.Second * 30) // the network status plugin might keep goroutines alive for a minute before killing them

	numGoRoutinesPostAppShutdown := runtime.NumGoroutine()

	// Printing out the current goroutines
	// Very useful if we are leaking any.
	pprof.Lookup("goroutine").WriteTo(os.Stdout, 1)
	fmt.Println("")
	log.Infof("numGoRoutinesStart: %v\nnumGoRoutinesPostAppStart: %v\nnumGoRoutinesPostPeerStart: %v\nnumGoRoutinesPostPeerAndServerConnect: %v\n"+
		"numGoRoutinesPostAlice: %v\nnumGoRoutinesPostCarolConnect: %v\nnumGoRoutinesPostBob: %v\nnumGoRoutinesPostCarol: %v\nnumGoRoutinesPostAppShutdown: %v",
		numGoRoutinesStart, numGoRoutinesPostAppStart, numGoRoutinesPostPeerStart, numGoRoutinesPostServerConnect,
		numGoRoutinesPostAlice, numGoRoutinesPostCarolConnect, numGoRoutinesPostBob, numGoRoutinesPostCarol, numGoRoutinesPostAppShutdown)

	if numGoRoutinesStart != numGoRoutinesPostAppShutdown {
		t.Errorf("Number of GoRoutines at start (%v) does not match number of goRoutines after cleanup of peers and servers (%v), clean up failed, v detected!", numGoRoutinesStart, numGoRoutinesPostAppShutdown)
	}
}

// Utility function for sending a message from a peer to a group
func checkSendMessageToGroup(t *testing.T, profile peer.CwtchPeer, bus event.Manager, id int, message string) {
	name, _ := profile.GetScopedZonedAttribute(attr.PublicScope, attr.ProfileZone, constants.Name)
	log.Infof("%v> %v\n", name, message)
	queue := event.NewQueue()
	bus.Subscribe(event.IndexedAcknowledgement, queue)
	mid, err := profile.SendMessage(id, message)
	if err != nil {
		log.Errorf("Alice failed to send a message to the group: %v", err)
		t.Fatalf("Alice failed to send a message to the group: %v\n", err)
	}
	log.Infof("Sent message with mid: %v, waiting for ack...", mid)
	ev := queue.Next()
	switch ev.EventType {
	case event.IndexedAcknowledgement:
		if evid, err := strconv.Atoi(ev.Data[event.Index]); err == nil && evid == mid {
			log.Infof("Message mid acked!")
			break
		}
	}
	queue.Shutdown()
	time.Sleep(time.Second * 10)
}

// Utility function for testing that a message in a conversation is as expected
func checkMessage(t *testing.T, profile peer.CwtchPeer, id int, messageID int, expected string) {
	message, _, err := profile.GetChannelMessage(id, 0, messageID)
	log.Debugf("  checking if expected: %v is actual: %v", expected, message)
	if err != nil {
		log.Errorf("unexpected message %v expected: %v got error: %v", profile.GetOnion(), expected, err)
		t.Fatalf("unexpected message %v expected: %v got error: %v\n", profile.GetOnion(), expected, err)
	}
	if message != expected {
		log.Errorf("unexpected message %v expected: %v got: [%v]", profile.GetOnion(), expected, message)
		t.Fatalf("unexpected message %v expected: %v got: [%v]\n", profile.GetOnion(), expected, message)
	}
}
