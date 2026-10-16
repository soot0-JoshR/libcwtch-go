package peer

import (
	"errors"
	"os"
	"path/filepath"
	"testing"

	"cwtch.im/cwtch/model"
	"cwtch.im/cwtch/model/constants"
	_ "github.com/mutecomm/go-sqlcipher/v4"
)

func cloneProfileForMergeTest(t *testing.T, source CwtchPeer, destination string, password string) CwtchPeer {
	t.Helper()
	key, _, err := initV2Directory(destination, password)
	if err != nil {
		t.Fatal(err)
	}
	if err := source.(*cwtchPeer).storage.cloneEncryptedDatabase(filepath.Join(destination, dbFile), key); err != nil {
		t.Fatal(err)
	}
	cloned, err := FromEncryptedDatabase(destination, password)
	if err != nil {
		t.Fatal(err)
	}
	return cloned
}

func TestMergeEncryptedProfileDirectories(t *testing.T) {
	root := t.TempDir()
	primaryDirectory := filepath.Join(root, "primary")
	secondaryDirectory := filepath.Join(root, "secondary")
	primary, err := CreateEncryptedStorePeer(primaryDirectory, "primary", "primary-password")
	if err != nil {
		t.Fatal(err)
	}
	peerOne := "peer-one"
	historyAttributes := model.Attributes{}
	conversationOne, err := primary.(*cwtchPeer).storage.NewConversation(peerOne, historyAttributes, model.AccessControlList{peerOne: model.DefaultP2PAccessControl()}, true)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := primary.(*cwtchPeer).storage.InsertMessage(conversationOne, 0, "in both", model.Attributes{constants.AttrAuthor: peerOne}, "same-signature", "same-hash"); err != nil {
		t.Fatal(err)
	}
	secondary := cloneProfileForMergeTest(t, primary, secondaryDirectory, "secondary-password")
	if _, err := secondary.(*cwtchPeer).storage.InsertMessage(conversationOne, 0, "secondary only", model.Attributes{constants.AttrAuthor: peerOne}, "secondary-signature", "secondary-hash"); err != nil {
		t.Fatal(err)
	}
	peerTwo := "peer-two"
	conversationTwo, err := secondary.(*cwtchPeer).storage.NewConversation(peerTwo, model.Attributes{}, model.AccessControlList{peerTwo: model.DefaultP2PAccessControl()}, true)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := secondary.(*cwtchPeer).storage.InsertMessage(conversationTwo, 0, "new conversation", model.Attributes{constants.AttrAuthor: peerTwo}, "new-conversation-signature", "new-conversation-hash"); err != nil {
		t.Fatal(err)
	}
	// Neither side of a recovery join is a normal active-session shutdown: its
	// currently stored no-save history must remain available for the merge.
	primary.ShutdownWithoutPurgingMessages()
	secondary.ShutdownWithoutPurgingMessages()

	merged, summary, err := MergeEncryptedProfileDirectories(primaryDirectory, "primary-password", secondaryDirectory, "secondary-password")
	if err != nil {
		t.Fatal(err)
	}
	defer merged.Shutdown()
	if summary.ConversationsAdded != 1 || summary.MessagesAdded != 2 {
		t.Fatalf("unexpected merge summary: %+v", summary)
	}
	if _, err := os.Stat(secondaryDirectory); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("secondary directory remains after merge: %v", err)
	}
	conversation, err := merged.FetchConversationInfo(peerOne)
	if err != nil {
		t.Fatal(err)
	}
	if count, err := merged.GetChannelMessageCount(conversation.ID, 0); err != nil || count != 2 {
		t.Fatalf("merged first conversation count=%d err=%v", count, err)
	}
	conversation, err = merged.FetchConversationInfo(peerTwo)
	if err != nil {
		t.Fatal(err)
	}
	if count, err := merged.GetChannelMessageCount(conversation.ID, 0); err != nil || count != 1 {
		t.Fatalf("merged second conversation count=%d err=%v", count, err)
	}
}

func TestMergeRejectsDifferentIdentitiesWithoutChangingEither(t *testing.T) {
	root := t.TempDir()
	primaryDirectory := filepath.Join(root, "primary")
	secondaryDirectory := filepath.Join(root, "secondary")
	primary, err := CreateEncryptedStorePeer(primaryDirectory, "primary", "primary-password")
	if err != nil {
		t.Fatal(err)
	}
	secondary, err := CreateEncryptedStorePeer(secondaryDirectory, "secondary", "secondary-password")
	if err != nil {
		t.Fatal(err)
	}
	primary.Shutdown()
	secondary.Shutdown()
	if _, _, err := MergeEncryptedProfileDirectories(primaryDirectory, "primary-password", secondaryDirectory, "secondary-password"); err == nil {
		t.Fatal("different identities were merged")
	}
	for _, directory := range []string{primaryDirectory, secondaryDirectory} {
		if _, err := os.Stat(filepath.Join(directory, dbFile)); err != nil {
			t.Fatalf("original profile was changed or removed: %s: %v", directory, err)
		}
	}
}
