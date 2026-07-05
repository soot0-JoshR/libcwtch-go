package connections

import (
	"cwtch.im/cwtch/event"
	model2 "cwtch.im/cwtch/protocol/model"
	"encoding/json"
	"git.openprivacy.ca/cwtch.im/tapir"
	"git.openprivacy.ca/cwtch.im/tapir/applications"
	"git.openprivacy.ca/openprivacy/log"
	"sync/atomic"
)

const cwtchCapability = tapir.Capability("cwtchCapability")

// PeerApp encapsulates the behaviour of a Cwtch Peer
type PeerApp struct {
	applications.AuthApp
	connection        tapir.Connection
	MessageHandler    func(string, string, string, []byte)
	IsBlocked         func(string) bool
	IsAllowed         func(string) bool
	OnAcknowledgement func(string, string)
	OnAuth            func(string)
	OnClose           func(string)
	OnConnecting      func(string)
	version           atomic.Value
}

type peerGetVal struct {
	Scope, Path string
}

type peerRetVal struct {
	Val    string
	Exists bool
}

const Version1 = 0x01
const Version2 = 0x02

// NewInstance should always return a new instantiation of the application.
func (pa *PeerApp) NewInstance() tapir.Application {
	newApp := new(PeerApp)
	newApp.MessageHandler = pa.MessageHandler
	newApp.IsBlocked = pa.IsBlocked
	newApp.IsAllowed = pa.IsAllowed
	newApp.OnAcknowledgement = pa.OnAcknowledgement
	newApp.OnAuth = pa.OnAuth
	newApp.OnClose = pa.OnClose
	newApp.OnConnecting = pa.OnConnecting
	newApp.version.Store(Version1)
	return newApp
}

// Init is run when the connection is first started.
func (pa *PeerApp) Init(connection tapir.Connection) {
	// First run the Authentication App
	pa.AuthApp.Init(connection)

	if connection.HasCapability(applications.AuthCapability) {

		pa.connection = connection
		connection.SetCapability(cwtchCapability)

		if pa.IsBlocked(connection.Hostname()) {
			pa.connection.Close()
			pa.OnClose(connection.Hostname())
		} else {

			// we are authenticated
			// attempt to negotiate a more efficient packet format...
			// we are abusing the context here slightly by sending a "malformed" GetVal request.
			// as a rule cwtch ignores getval requests that it cannot deserialize so older clients will ignore this
			// message.
			// version *must* be the first message sent to prevent race conditions for other events fired after-auth
			// (e.g. getVal requests)
			// as such, we send this message before we update the rest of the system
			pa.SendMessage(model2.PeerMessage{
				ID:      event.ContextVersion,
				Context: event.ContextGetVal,
				Data:    []byte{Version2},
			})

			pa.OnAuth(connection.Hostname())
			go pa.listen()
		}
	} else {
		// The auth protocol wasn't completed, we can safely shutdown the connection
		// send an onclose here because we *may* have triggered this and we want to retry later...
		pa.OnClose(connection.Hostname())
		connection.Close()
	}
}

func (pa *PeerApp) listen() {
	for {
		message := pa.connection.Expect()
		if len(message) == 0 {
			log.Debugf("0 byte read, socket has likely failed. Closing the listen goroutine")
			pa.OnClose(pa.connection.Hostname())
			return
		}

		var packet model2.PeerMessage
		var err error

		if pa.version.Load() == Version1 {
			err = json.Unmarshal(message, &packet)
		} else if pa.version.Load() == Version2 {
			parsePacket, parseErr := model2.ParsePeerMessage(message)
			// if all else fails...attempt to process this message as a version 1 message
			if parseErr != nil {
				err = json.Unmarshal(message, &packet)
			} else {
				packet = *parsePacket
			}

		} else {
			log.Errorf("invalid version")
			pa.OnClose(pa.connection.Hostname())
			return
		}

		if err == nil {
			if pa.IsAllowed(pa.connection.Hostname()) {
				// we don't expose im.cwtch.version messages outside of PeerApp (ideally at some point in the future we
				// can remove this check all together)
				if packet.ID == event.ContextVersion {
					if pa.version.Load() == Version1 && len(packet.Data) == 1 && packet.Data[0] == Version2 {
						log.Debugf("switching to protocol version 2")
						pa.version.Store(Version2)
					}
				} else {
					pa.MessageHandler(pa.connection.Hostname(), packet.ID, packet.Context, []byte(packet.Data))
				}
			}
		} else {
			log.Errorf("Error unmarshalling PeerMessage package: %x %v", message, err)
		}
	}
}

// SendMessage sends the peer a preformatted message
// NOTE: This is a stub, we will likely want to extend this to better reflect the desired protocol
func (pa *PeerApp) SendMessage(message model2.PeerMessage) error {
	var serialized []byte
	var err error

	if pa.version.Load() == Version2 {
		// treat data as a pre-serialized string, not as a byte array (which will be base64 encoded and bloat the packet size)
		serialized = message.Serialize()
	} else {
		serialized, err = json.Marshal(message)
	}

	if err == nil {
		err = pa.connection.Send(serialized)

		// at this point we have tried to send a message to a peer only to find that something went wrong.
		// we don't know *what* went wrong - the most likely explanation is the peer went offline in the time between
		// sending the message and it arriving in the engine to be sent. Other explanations include problems with Tor,
		// a dropped wifi connection.
		// Regardless, we error out this message and close this peer app assuming it cannot be used again.
		// We expect that cwtch will eventually recreate this connection and the app.
		if err != nil {
			// close any associated sockets
			pa.connection.Close()
			// tell cwtch this connection is no longer valid
			pa.OnClose(err.Error())
		}
		return err
	}
	return err
}
