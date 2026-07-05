package model

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"golang.org/x/crypto/ed25519"
	"io"
	"sync"
)

// Authorization is a type determining client assigned authorization to a peer
// Deprecated - Only used for Importing legacy profile formats
// Still used in some APIs in UI but will be replaced prior to full deprecation
type Authorization string

const (
	// AuthUnknown is an initial state for a new unseen peer
	AuthUnknown Authorization = "unknown"
	// AuthApproved means the client has approved the peer, it can send messages to us, perform GetVals, etc
	AuthApproved Authorization = "approved"
	// AuthBlocked means the client has blocked the peer, it's messages and connections should be rejected
	AuthBlocked Authorization = "blocked"
)

// PublicProfile is a local copy of a CwtchIdentity
// Deprecated - Only used for Importing legacy profile formats
type PublicProfile struct {
	Name                   string
	Ed25519PublicKey       ed25519.PublicKey
	Authorization          Authorization
	DeprecatedBlocked      bool `json:"Blocked"`
	Onion                  string
	Attributes             map[string]string
	Timeline               Timeline `json:"-"`
	LocalID                string   // used by storage engine
	State                  string   `json:"-"`
	lock                   sync.Mutex
	UnacknowledgedMessages map[string]int
}

// Profile encapsulates all the attributes necessary to be a Cwtch Peer.
// Deprecated - Only used for Importing legacy profile formats
type Profile struct {
	PublicProfile
	Contacts          map[string]*PublicProfile
	Ed25519PrivateKey ed25519.PrivateKey
	Groups            map[string]*Group
}

// MaxGroupMessageLength is the maximum length of a message posted to a server group.
// TODO: Should this be per server?
const MaxGroupMessageLength = 1800

func getRandomness(arr *[]byte) {
	if _, err := io.ReadFull(rand.Reader, (*arr)[:]); err != nil {
		if err != nil {
			// If we can't do randomness, just crash something is very very wrong and we are not going
			// to resolve it here....
			panic(err.Error())
		}
	}
}

// GenerateRandomID generates a random 16 byte hex id code
func GenerateRandomID() string {
	randBytes := make([]byte, 16)
	rand.Read(randBytes)
	return hex.EncodeToString(randBytes)
}

// GetCopy returns a full deep copy of the Profile struct and its members (timeline inclusion control by arg)
func (p *Profile) GetCopy(timeline bool) *Profile {
	p.lock.Lock()
	defer p.lock.Unlock()

	newp := new(Profile)
	bytes, _ := json.Marshal(p)
	json.Unmarshal(bytes, &newp)

	if timeline {
		for groupID := range newp.Groups {
			newp.Groups[groupID].Timeline = *p.Groups[groupID].Timeline.GetCopy()
		}

		for peerID := range newp.Contacts {
			newp.Contacts[peerID].Timeline = *p.Contacts[peerID].Timeline.GetCopy()
		}
	}

	return newp
}
