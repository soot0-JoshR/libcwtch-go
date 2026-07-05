package model

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha512"
	"cwtch.im/cwtch/protocol/groups"
	"encoding/base32"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"git.openprivacy.ca/cwtch.im/tapir/primitives"
	"git.openprivacy.ca/openprivacy/connectivity/tor"
	"git.openprivacy.ca/openprivacy/log"
	"golang.org/x/crypto/nacl/secretbox"
	"golang.org/x/crypto/pbkdf2"
	"io"
	"strings"
	"time"
)

// CurrentGroupVersion is used to set the version of newly created groups and make sure group structs stored are correct and up to date
const CurrentGroupVersion = 4

// GroupInvitePrefix identifies a particular string as being a serialized group invite.
const GroupInvitePrefix = "torv3"

// Group defines and encapsulates Cwtch's conception of group chat. Which are sessions
// tied to a server under a given group key. Each group has a set of Messages.
type Group struct {
	// GroupID is now derived from the GroupKey and the GroupServer
	GroupID     string
	GroupName   string
	GroupKey    [32]byte
	GroupServer string
	Attributes  map[string]string //legacy to not use
	Version     int
	Timeline    Timeline `json:"-"`
	LocalID     string
}

// NewGroup initializes a new group associated with a given CwtchServer
func NewGroup(server string) (*Group, error) {
	group := new(Group)
	if !tor.IsValidHostname(server) {
		return nil, errors.New("server is not a valid v3 onion")
	}

	group.GroupServer = server

	var groupKey [32]byte
	if _, err := io.ReadFull(rand.Reader, groupKey[:]); err != nil {
		log.Errorf("Error: Cannot read from random: %v\n", err)
		return nil, err
	}
	copy(group.GroupKey[:], groupKey[:])

	// Derive Group ID from the group key and the server public key. This binds the group to a particular server
	// and key.
	group.GroupID = deriveGroupID(groupKey[:], server)
	return group, nil
}

// CheckGroup returns true only if the ID of the group is cryptographically valid.
func (g *Group) CheckGroup() bool {
	return g.GroupID == deriveGroupID(g.GroupKey[:], g.GroupServer)
}

// deriveGroupID hashes together the key and the hostname to create a bound identifier that can later
// be referenced and checked by profiles when they receive invites and messages.
func deriveGroupID(groupKey []byte, serverHostname string) string {
	data, _ := base32.StdEncoding.DecodeString(strings.ToUpper(serverHostname))
	pubkey := data[0:ed25519.PublicKeySize]
	return hex.EncodeToString(pbkdf2.Key(groupKey, pubkey, 4096, 16, sha512.New))
}

// Invite generates a invitation that can be sent to a cwtch peer
func (g *Group) Invite() (string, error) {

	gci := &groups.GroupInvite{
		GroupID:    g.GroupID,
		GroupName:  g.GroupName,
		SharedKey:  g.GroupKey[:],
		ServerHost: g.GroupServer,
	}

	invite, err := json.Marshal(gci)
	serializedInvite := fmt.Sprintf("%v%v", GroupInvitePrefix, base64.StdEncoding.EncodeToString(invite))
	return serializedInvite, err
}

// EncryptMessage takes a message and encrypts the message under the group key.
func (g *Group) EncryptMessage(message *groups.DecryptedGroupMessage) ([]byte, error) {
	var nonce [24]byte
	if _, err := io.ReadFull(rand.Reader, nonce[:]); err != nil {
		log.Errorf("Cannot read from random: %v\n", err)
		return nil, err
	}
	wire, err := json.Marshal(message)
	if err != nil {
		return nil, err
	}
	encrypted := secretbox.Seal(nonce[:], []byte(wire), &nonce, &g.GroupKey)
	return encrypted, nil
}

// DecryptMessage takes a ciphertext and returns true and the decrypted message if the
// cipher text can be successfully decrypted,else false.
func (g *Group) DecryptMessage(ciphertext []byte) (bool, *groups.DecryptedGroupMessage) {
	if len(ciphertext) > 24 {
		var decryptNonce [24]byte
		copy(decryptNonce[:], ciphertext[:24])
		decrypted, ok := secretbox.Open(nil, ciphertext[24:], &decryptNonce, &g.GroupKey)
		if ok {
			dm := &groups.DecryptedGroupMessage{}
			err := json.Unmarshal(decrypted, dm)
			if err == nil {
				return true, dm
			}
		}
	}
	return false, nil
}

// ValidateInvite takes in a serialized invite and returns the invite structure if it is cryptographically valid
// and an error if it is not
func ValidateInvite(invite string) (*groups.GroupInvite, error) {
	// We prefix invites for groups with torv3
	if strings.HasPrefix(invite, GroupInvitePrefix) {
		data, err := base64.StdEncoding.DecodeString(invite[len(GroupInvitePrefix):])
		if err == nil {
			// First attempt to unmarshal the json...
			var gci groups.GroupInvite
			err := json.Unmarshal(data, &gci)
			if err == nil {

				// Validate the Invite by first checking that the server is a valid v3 onion
				if !tor.IsValidHostname(gci.ServerHost) {
					return nil, errors.New("server is not a valid v3 onion")
				}

				// Validate the length of the shared key...
				if len(gci.SharedKey) != 32 {
					return nil, errors.New("key length is not 32 bytes")
				}

				// Derive the servers public key (we can ignore the error checking here because it's already been
				// done by IsValidHostname, and check that we derive the same groupID...
				derivedGroupID := deriveGroupID(gci.SharedKey, gci.ServerHost)
				if derivedGroupID != gci.GroupID {
					return nil, errors.New("group id is invalid")
				}

				// Replace the original with the derived, this should be a no-op at this point but defense in depth...
				gci.GroupID = derivedGroupID
				return &gci, nil
			}
		}
	}
	return nil, errors.New("invite has invalid structure")
}

// AttemptDecryption takes a ciphertext and signature and attempts to decrypt it under known groups.
// If successful, adds the message to the group's timeline
func (g *Group) AttemptDecryption(ciphertext []byte, signature []byte) (bool, *groups.DecryptedGroupMessage) {
	success, dgm := g.DecryptMessage(ciphertext)
	if success {

		// Attempt to serialize this message
		serialized, err := json.Marshal(dgm)

		// Someone send a message that isn't a valid Decrypted Group Message. Since we require this struct in orer
		// to verify the message, we simply ignore it.
		if err != nil {
			return false, nil
		}

		// This now requires knowledge of the Sender, the Onion and the Specific Decrypted Group Message (which should only
		// be derivable from the cryptographic key) which contains many unique elements such as the time and random padding
		verified := g.VerifyGroupMessage(dgm.Onion, g.GroupID, base64.StdEncoding.EncodeToString(serialized), signature)

		if !verified {
			// An earlier version of this protocol mistakenly signed the ciphertext of the message
			// instead of the serialized decrypted group message.
			// This has 2 issues:
			// 1. A server with knowledge of group members public keys AND the Group ID would be able to detect valid messages
			// 2. It made the metadata-security of a group dependent on keeping the cryptographically derived Group ID secret.
			// While not awful, it also isn't good. For Version 3 groups only we permit Cwtch to check this older signature
			// structure in a backwards compatible way for the duration of the Groups Experiment.
			// TODO: Delete this check when Groups are no long Experimental
			if g.Version == 3 {
				verified = g.VerifyGroupMessage(dgm.Onion, g.GroupID, string(ciphertext), signature)
			}
		}

		// So we have a message that has a valid group key, but the signature can't be verified.
		// The most obvious explanation for this is that the group key has been compromised (or we are in an open group and the server is being malicious)
		// Either way, someone who has the private key is being detectably bad so we are just going to throw this message away and mark the group as Compromised.
		if !verified {
			return false, nil
		}
		return true, dgm
	}

	// If we couldn't find a group to decrypt the message with we just return false. This is an expected case
	return false, nil
}

// VerifyGroupMessage confirms the authenticity of a message given an sender onion, message and signature.
// The goal of this function is 2-fold:
//  1. We confirm that the sender referenced in the group text is the actual sender of the message (or at least
//     knows the senders private key)
//  2. Secondly, we confirm that the sender sent the message to a particular group id on a specific server (it doesn't
//     matter if we actually received this message from the server or from a hybrid protocol, all that matters is
//     that the sender and receivers agree that this message was intended for the group
//
// The 2nd point is important as it prevents an attack documented in the original Cwtch paper (and later at
// https://docs.openprivacy.ca/cwtch-security-handbook/groups.html) in which a malicious profile sets up 2 groups
// on two different servers with the same key and then forwards messages between them to convince the parties in
// each group that they are actually in one big group (with the intent to later censor and/or selectively send messages
// to each group).
func (g *Group) VerifyGroupMessage(onion string, groupID string, message string, signature []byte) bool {
	// We use our group id, a known reference server and the ciphertext of the message.
	m := groupID + g.GroupServer + message

	// Otherwise we derive the public key from the sender and check it against that.
	decodedPub, err := base32.StdEncoding.DecodeString(strings.ToUpper(onion))
	if err == nil && len(decodedPub) >= 32 {
		return ed25519.Verify(decodedPub[:32], []byte(m), signature)
	}
	return false
}

// EncryptMessageToGroup when given a message and a group, encrypts and signs the message under the group and
// profile
func EncryptMessageToGroup(message string, author primitives.Identity, group *Group, prevSig string) ([]byte, []byte, *groups.DecryptedGroupMessage, error) {
	if len(message) > MaxGroupMessageLength {
		return nil, nil, nil, errors.New("group message is too long")
	}
	timestamp := time.Now().Unix()

	lenPadding := MaxGroupMessageLength - len(message)
	padding := make([]byte, lenPadding)
	getRandomness(&padding)
	hexGroupID, err := hex.DecodeString(group.GroupID)
	if err != nil {
		return nil, nil, nil, err
	}

	prevSigBytes, err := base64.StdEncoding.DecodeString(prevSig)
	if err != nil {
		return nil, nil, nil, err
	}

	dm := &groups.DecryptedGroupMessage{
		Onion:              author.Hostname(),
		Text:               message,
		SignedGroupID:      hexGroupID,
		Timestamp:          uint64(timestamp),
		PreviousMessageSig: prevSigBytes,
		Padding:            padding[:],
	}

	ciphertext, err := group.EncryptMessage(dm)
	if err != nil {
		return nil, nil, nil, err
	}
	serialized, _ := json.Marshal(dm)
	signature := author.Sign([]byte(group.GroupID + group.GroupServer + base64.StdEncoding.EncodeToString(serialized)))
	return ciphertext, signature, dm, nil
}
