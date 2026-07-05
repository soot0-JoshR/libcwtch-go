package model

import (
	"bytes"
	"errors"
)

// PeerMessage is an encapsulation that can be used by higher level applications
type PeerMessage struct {
	// ID **must** only contain alphanumeric characters separated by period.
	ID string // A unique Message ID (primarily used for acknowledgments)

	// Context **must** only contain alphanumeric characters separated by period.
	Context string // A unique context identifier i.e. im.cwtch.chat

	// Data can contain anything
	Data []byte // A data packet.
}

// Serialize constructs an efficient serialized representation
// Format: [ID String] | [Context String] | Binary Data
func (m *PeerMessage) Serialize() []byte {
	return append(append([]byte(m.ID+"|"), []byte(m.Context+"|")...), m.Data...)
}

// ParsePeerMessage returns either a deserialized PeerMessage or an error if it is malformed
func ParsePeerMessage(message []byte) (*PeerMessage, error) {

	// find the identifier prefix
	idTerminator := bytes.IndexByte(message, '|')
	if idTerminator != -1 && idTerminator+1 < len(message) {
		// find the context terminator prefix
		contextbegin := idTerminator + 1
		contextTerminator := bytes.IndexByte(message[contextbegin:], '|')
		if contextTerminator != -1 {

			// check that we have data
			dataBegin := contextbegin + contextTerminator + 1
			var data []byte
			if dataBegin < len(message) {
				data = message[dataBegin:]
			}

			// compile the message
			return &PeerMessage{
				ID:      string(message[0:idTerminator]),
				Context: string(message[contextbegin : contextbegin+contextTerminator]),
				Data:    data,
			}, nil
		}
	}
	return nil, errors.New("invalid message")
}
