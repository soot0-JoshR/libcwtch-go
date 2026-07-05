package model

import (
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"sort"
	"sync"
	"time"
)

// Timeline encapsulates a collection of ordered Messages, and a mechanism to access them
// in a threadsafe manner.
type Timeline struct {
	Messages      []Message
	SignedGroupID []byte
	lock          sync.Mutex

	// a cache to allow quick checks for existing messages...
	signatureCache map[string]int

	// a cache to allowing looking up messages by content hash
	// we need this for features like reply-to message, and other self
	// referential applications.
	// note: that the index stored here is not global as different peers may have difference views of the timeline
	// depending on if they save history, and when the last time they purged their timeline was, as such we can't
	// simply send the index of the message.
	hashCache map[string][]int
}

// LocallyIndexedMessage is a type wrapper around a Message and a TimeLine Index that is local to this
// instance of the timeline.
type LocallyIndexedMessage struct {
	Message
	LocalIndex int
}

// Message is a local representation of a given message sent over a group chat channel.
type Message struct {
	Timestamp          time.Time
	Received           time.Time
	PeerID             string
	Message            string
	Signature          []byte
	PreviousMessageSig []byte
	ReceivedByServer   bool   // messages sent to a server
	Acknowledged       bool   // peer to peer
	Error              string `json:",omitempty"`
	// Application specific flags, useful for storing small amounts of metadata
	Flags uint64
}

// MessageBaseSize 2021.06 byte size of an *empty* message json serialized
const MessageBaseSize float64 = 463

// compareSignatures checks if a and b are equal. Note: this function does
// not need to be constant time - in fact it is better that it is not as it's only main use
// is in sorting timeline state consistently.
func compareSignatures(a []byte, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// GetMessages returns a copy of the entire timeline
func (t *Timeline) GetMessages() []Message {
	t.lock.Lock()
	messages := make([]Message, len(t.Messages))
	copy(messages[:], t.Messages[:])
	t.lock.Unlock()
	return messages
}

// GetCopy returns a duplicate of the Timeline
func (t *Timeline) GetCopy() *Timeline {
	t.lock.Lock()
	defer t.lock.Unlock()
	newt := &Timeline{}
	// initialize the timeline and copy the message over...
	newt.SetMessages(t.Messages)
	return newt
}

// SetMessages sets the Messages of this timeline. Only to be used in loading/initialization
func (t *Timeline) SetMessages(messages []Message) {
	t.lock.Lock()
	t.init()
	t.lock.Unlock()
	for _, m := range messages {
		t.Insert(&m)
	}
}

// GetMessagesByHash attempts to find messages that match the given
// content hash in the timeline. If successful it returns a list of messages as well as their local index
// , on failure it returns an error.
// We return a list of messages because content hashes are not guaranteed to be unique from a given Peer. This allows
// us to do things like: ensure that reply-to and quotes reference the last seen message from the message they are quoted
// in or detect duplicate messages from a peer.
func (t *Timeline) GetMessagesByHash(contentHash string) ([]LocallyIndexedMessage, error) {
	t.lock.Lock()
	defer t.lock.Unlock()
	t.init()
	if idxs, exists := t.hashCache[contentHash]; exists {
		var messages []LocallyIndexedMessage
		for _, idx := range idxs {
			messages = append(messages, LocallyIndexedMessage{LocalIndex: idx, Message: t.Messages[idx]})
		}
		return messages, nil
	}
	return nil, errors.New("cannot find message by hash")
}

// calculateHash calculates the content hash of a given message
// the content used is the sender of the message, the body of the message
//
// content hashes must be calculable across timeline views so that different participants can
// calculate the same hash for the same message - as such we cannot use timestamps from peers or groups
// as they are mostly fuzzy.
//
// As a reminder: for p2p messages PeerID is authenticated by the initial 3DH handshake, for groups
// each message is signed by the sender, and this signature is checked prior to inclusion in the timeline.
//
// Multiple messages from the same peer can result in the same hash (where the same user sends the same message more
// than once) - in this case we will only store the idx of the most recent message - and use that for reference lookups.
func (t *Timeline) calculateHash(message Message) string {
	content := []byte(message.PeerID + message.Message)
	contentBasedHash := sha256.Sum256(content)
	return base64.StdEncoding.EncodeToString(contentBasedHash[:])
}

// Len gets the length of the timeline
func (t *Timeline) Len() int {
	return len(t.Messages)
}

// Swap swaps 2 Messages on the timeline.
func (t *Timeline) Swap(i, j int) {
	t.Messages[i], t.Messages[j] = t.Messages[j], t.Messages[i]
}

// Less checks 2 Messages (i and j) in the timeline and returns true if i occurred before j, else false
func (t *Timeline) Less(i, j int) bool {

	if t.Messages[i].Timestamp.Before(t.Messages[j].Timestamp) {
		return true
	}

	// Short circuit false if j is before i, signature checks will give a wrong order in this case.
	if t.Messages[j].Timestamp.Before(t.Messages[i].Timestamp) {
		return false
	}

	if compareSignatures(t.Messages[i].PreviousMessageSig, t.SignedGroupID) {
		return true
	}

	if compareSignatures(t.Messages[i].Signature, t.Messages[j].PreviousMessageSig) {
		return true
	}

	return false
}

// Sort sorts the timeline in a canonical order.
func (t *Timeline) Sort() {
	t.lock.Lock()
	defer t.lock.Unlock()

	sort.Sort(t)
}

// Insert a message into the timeline in a thread safe way.
func (t *Timeline) Insert(mi *Message) int {
	t.lock.Lock()
	defer t.lock.Unlock()

	// assert timeline is initialized
	t.init()

	// check that we haven't seen this message before (this has no impact on p2p messages, but is essential for
	// group messages)
	// FIXME: The below code now checks if the message has a signature. If it doesn't then skip duplication check.
	// We do this because p2p messages right now do not have a signature, and so many p2p messages are not stored
	// with a signature. In the future in hybrid groups this check will go away as all timelines will use the same
	// underlying protocol.
	// This is currently safe to do because p2p does not rely on signatures and groups will verify the signature of
	// messages prior to generating an event to include them in the timeline.
	if len(mi.Signature) != 0 {
		idx, exists := t.signatureCache[base64.StdEncoding.EncodeToString(mi.Signature)]
		if exists {
			t.Messages[idx].Acknowledged = true
			return idx
		}
	}

	// update the message store
	t.Messages = append(t.Messages, *mi)
	// add to signature cache for fast checking of group messages...
	t.signatureCache[base64.StdEncoding.EncodeToString(mi.Signature)] = len(t.Messages) - 1
	// content based addressing index
	contentHash := t.calculateHash(*mi)
	t.hashCache[contentHash] = append(t.hashCache[contentHash], len(t.Messages)-1)
	return len(t.Messages) - 1
}

func (t *Timeline) init() {
	// only allow this setting once...
	if t.signatureCache == nil {
		t.signatureCache = make(map[string]int)
	}

	if t.hashCache == nil {
		t.hashCache = make(map[string][]int)
	}
}

// SetSendError marks a message has having some kind of application specific error.
// Note: The message here is indexed by signature.
func (t *Timeline) SetSendError(sig []byte, e string) bool {
	t.lock.Lock()
	defer t.lock.Unlock()

	idx, exists := t.signatureCache[base64.StdEncoding.EncodeToString(sig)]
	if !exists {
		return false
	}

	t.Messages[idx].Error = e
	return true
}
