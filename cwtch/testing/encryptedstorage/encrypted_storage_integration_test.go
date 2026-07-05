package encryptedstorage

import (
	// Import SQL Cipher
	"crypto/rand"
	app2 "cwtch.im/cwtch/app"
	"cwtch.im/cwtch/model"
	"cwtch.im/cwtch/model/constants"
	"cwtch.im/cwtch/peer"
	"encoding/base64"
	"fmt"
	"git.openprivacy.ca/openprivacy/connectivity/tor"
	"git.openprivacy.ca/openprivacy/log"
	_ "github.com/mutecomm/go-sqlcipher/v4"
	mrand "math/rand"
	"os"
	"path"
	"path/filepath"
	"testing"
	"time"
)

func TestEncryptedStorage(t *testing.T) {

	log.SetLevel(log.LevelDebug)

	os.Mkdir("tordir", 0700)
	dataDir := filepath.Join("tordir", "tor")
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

	cwtchDir := path.Join(".", "encrypted_storage_profiles")
	os.RemoveAll(cwtchDir)
	os.Mkdir(cwtchDir, 0700)

	fmt.Println("Creating Alice...")

	defer acn.Close()
	acn.WaitTillBootstrapped()
	app := app2.NewApp(acn, cwtchDir)
	app.CreateTaggedPeer("alice", "password", constants.ProfileTypeV1Password)
	app.CreateTaggedPeer("bob", "password", constants.ProfileTypeV1Password)

	alice := app2.WaitGetPeer(app, "alice")
	bob := app2.WaitGetPeer(app, "bob")

	alice.Listen()
	bob.Listen()

	// To keep this large test organized, we will break it down into sub tests...
	subTestAliceAddAndDeleteBob(t, alice, bob)

	conversations, err := alice.FetchConversations()
	if err != nil || len(conversations) != 1 {
		t.Fatalf("unexpected issue when fetching all of alices conversations. Expected 1 got : %v %v", conversations, err)
	}

	aliceOnion := alice.GetOnion()
	alice.PeerWithOnion(bob.GetOnion())

	time.Sleep(time.Second * 40)

	alice.SendMessage(2, "Hello Bob")
	if err != nil {
		t.Fatalf("alice should have been able to fetch her own message")
	}
	_, attr, _ := alice.GetChannelMessage(2, 0, 1)
	if attr[constants.AttrAck] != "false" {
		t.Fatalf("Alices message should have been acknowledged...yet")
	}

	time.Sleep(time.Second * 30)

	ci, err := bob.FetchConversationInfo(alice.GetOnion())
	for err != nil {
		time.Sleep(time.Second * 5)
		ci, err = bob.FetchConversationInfo(alice.GetOnion())
	}

	body, _, err := bob.GetChannelMessage(ci.ID, 0, 1)
	if body != "Hello Bob" || err != nil {
		t.Fatalf("unexpected message in conversation channel %v %v", body, err)
	} else {
		t.Logf("succesfully found message in conversation channel %v", body)
	}

	// Check that we received an ACk...
	_, attr, err = alice.GetChannelMessage(2, 0, 1)
	if err != nil {
		t.Fatalf("alice should have been able to fetch her own message")
	}

	if attr[constants.AttrAck] != "true" {
		t.Fatalf("Alices message should have been acknowledged.")
	}

	if count, err := alice.GetChannelMessageCount(2, 0); err != nil || count != 1 {
		t.Fatalf("Channel should have a single message in it. Instead returned %v %v", count, err)
	}

	messages, err := alice.GetMostRecentMessages(2, 0, 0, 10)

	if err != nil {
		t.Fatalf("fetching messages over offset should not result in error: %v", err)
	}

	if len(messages) != 1 || len(messages) > 0 && messages[0].Body != "Hello Bob" {
		t.Fatalf("expeced GetMostRecentMessages to return 1, instead returned: %v %v", len(messages), messages)
	}

	err = alice.Export("alice.tar.gz")
	if err != nil {
		t.Fatalf("could not export profile: %v", err)
	}

	_, err = app.ImportProfile("alice.tar.gz", "password")
	if err == nil {
		t.Fatal("profile is already imported...this should fail")
	}

	app.DeletePeer(alice.GetOnion(), "password")
	alice, err = app.ImportProfile("alice.tar.gz", "password")
	if err != nil {
		t.Fatalf("profile should have successfully imported: %s", err)
	}

	if alice.GetOnion() != aliceOnion {
		t.Fatalf("profile is not Alice...%s != %s", aliceOnion, alice.GetOnion())
	}

	app.Shutdown()

}

// Sub Test testing that Alice can add Bob, delete the conversation associated with Bob, and then add Bob again
// Under a different conversation identifier.
func subTestAliceAddAndDeleteBob(t *testing.T, alice peer.CwtchPeer, bob peer.CwtchPeer) {

	t.Logf("Starting Sub Test AliceAddAndDeleteBob")

	alice.NewContactConversation(bob.GetOnion(), model.AccessControl{Read: true, Append: true, Blocked: false}, true)

	// Test Basic Fetching
	bobCI, err := alice.FetchConversationInfo(bob.GetOnion())
	if bobCI == nil || err != nil {
		t.Fatalf("alice should have been able to fetch bobs conversationf info ci:%v err:%v", bobCI, err)
	} else {
		t.Logf("Bobs Conversation Info fetched successfully: %v", bobCI)
	}

	oldID := bobCI.ID

	alice.DeleteConversation(oldID)

	// Test Basic Fetching
	bobCI, err = alice.FetchConversationInfo(bob.GetOnion())
	if bobCI != nil {
		t.Fatalf("alice should **not** have been able to fetch bobs conversationf info ci:%v err:%v", bobCI, err)
	} else {
		t.Logf("expected error fetching deleted conversation info: %v", err)
	}

	alice.NewContactConversation(bob.GetOnion(), model.AccessControl{Read: true, Append: true, Blocked: false}, true)

	// Test Basic Fetching
	bobCI, err = alice.FetchConversationInfo(bob.GetOnion())
	if bobCI == nil || err != nil {
		t.Fatalf("alice should have been able to fetch bobs conversationf info ci:%v err:%v", bobCI, err)
	} else {
		t.Logf("Bobs Conversation Info fetched successfully: %v", bobCI)
	}

	if oldID == bobCI.ID {
		t.Fatalf("bob should have a different conversation ID. Instead it is the same as the old conversation id, meaning something has gone wrong in the storage engine.")
	}

}
