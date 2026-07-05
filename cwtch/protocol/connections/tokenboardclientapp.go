package connections

import (
	"cwtch.im/cwtch/protocol/groups"
	"encoding/json"
	"git.openprivacy.ca/cwtch.im/tapir"
	"git.openprivacy.ca/cwtch.im/tapir/applications"
	"git.openprivacy.ca/cwtch.im/tapir/primitives/privacypass"
	"git.openprivacy.ca/openprivacy/connectivity"
	"git.openprivacy.ca/openprivacy/log"
	"github.com/gtank/ristretto255"
	"sync"
)

// TokenBoardHandler encapsulates all the various handlers a client needs to interact with a token board
// this includes handlers to receive new messages, as well as handlers to manage tokens.
type TokenBoardHandler interface {
	GroupMessageHandler(server string, gm *groups.EncryptedGroupMessage)
	ServerAuthedHandler(server string)
	ServerSyncedHandler(server string)
	ServerClosedHandler(server string)
	NewTokenHandler(tokenService string, tokens []*privacypass.Token)
	PostingFailed(server string, sig []byte)
	FetchToken(tokenService string) (*privacypass.Token, int, error)
}

// NewTokenBoardClient generates a new Client for Token Board
func NewTokenBoardClient(acn connectivity.ACN, Y *ristretto255.Element, tokenServiceOnion string, lastKnownSignature []byte, tokenBoardHandler TokenBoardHandler) tapir.Application {
	tba := new(TokenBoardClient)
	tba.acn = acn
	tba.tokenService = privacypass.NewTokenServer()
	tba.tokenService.Y = Y
	tba.tokenServiceOnion = tokenServiceOnion
	tba.tokenBoardHandler = tokenBoardHandler
	tba.lastKnownSignature = lastKnownSignature
	return tba
}

// TokenBoardClient defines a client for the TokenBoard server
type TokenBoardClient struct {
	applications.AuthApp
	connection        tapir.Connection
	tokenBoardHandler TokenBoardHandler

	// Token service handling
	acn connectivity.ACN

	tokenService       *privacypass.TokenServer
	tokenServiceOnion  string
	lastKnownSignature []byte

	postLock  sync.Mutex
	postQueue []groups.CachedEncryptedGroupMessage
}

// NewInstance Client a new TokenBoardApp
func (ta *TokenBoardClient) NewInstance() tapir.Application {
	tba := new(TokenBoardClient)
	tba.tokenBoardHandler = ta.tokenBoardHandler
	tba.acn = ta.acn
	tba.tokenService = ta.tokenService
	tba.tokenServiceOnion = ta.tokenServiceOnion
	tba.lastKnownSignature = ta.lastKnownSignature
	return tba
}

// Init initializes the cryptographic TokenBoardApp
func (ta *TokenBoardClient) Init(connection tapir.Connection) {
	// connection.Hostname is always valid because we are ALWAYS the initiating party
	log.Debugf("connecting to server: %v", connection.Hostname())
	ta.AuthApp.Init(connection)
	log.Debugf("server protocol complete: %v", connection.Hostname())
	if connection.HasCapability(applications.AuthCapability) {
		log.Debugf("Successfully Initialized Connection to %v", connection.Hostname())
		ta.connection = connection
		ta.tokenBoardHandler.ServerAuthedHandler(connection.Hostname())
		go ta.Listen()
		// Optimistically acquire many tokens for this server...
		go ta.PurchaseTokens()
		go ta.PurchaseTokens()
		ta.Replay()
	} else {
		log.Debugf("Error Connecting to %v", connection.Hostname())
		ta.tokenBoardHandler.ServerClosedHandler(connection.Hostname())
		connection.Close()
	}
}

// Listen processes the messages for this application
func (ta *TokenBoardClient) Listen() {
	for {
		log.Debugf("Client waiting...")
		data := ta.connection.Expect()
		if len(data) == 0 {
			log.Debugf("Server closed the connection...")
			ta.tokenBoardHandler.ServerClosedHandler(ta.connection.Hostname())
			return // connection is closed
		}

		// We always expect the server to follow protocol, and the second it doesn't we close the connection
		var message groups.Message
		if err := json.Unmarshal(data, &message); err != nil {
			log.Debugf("Server sent an unexpected message, closing the connection: %v", err)
			ta.tokenBoardHandler.ServerClosedHandler(ta.connection.Hostname())
			ta.connection.Close()
			return
		}

		switch message.MessageType {
		case groups.NewMessageMessage:
			if message.NewMessage != nil {
				ta.tokenBoardHandler.GroupMessageHandler(ta.connection.Hostname(), &message.NewMessage.EGM)
			} else {
				log.Debugf("Server sent an unexpected NewMessage, closing the connection: %s", data)
				ta.tokenBoardHandler.ServerClosedHandler(ta.connection.Hostname())
				ta.connection.Close()
				return
			}
		case groups.PostResultMessage:
			ta.postLock.Lock()
			egm := ta.postQueue[0]
			ta.postQueue = ta.postQueue[1:]
			ta.postLock.Unlock()
			if !message.PostResult.Success {
				log.Debugf("post result message: %v", message.PostResult)
				// Retry using another token
				posted, _ := ta.Post(egm.Group, egm.Ciphertext, egm.Signature)
				// if posting failed...
				if !posted {
					log.Errorf("error posting message")
					ta.tokenBoardHandler.PostingFailed(egm.Group, egm.Signature)
				}
			}
		case groups.ReplayResultMessage:
			if message.ReplayResult != nil {
				log.Debugf("Replaying %v Messages...", message.ReplayResult.NumMessages)
				for i := 0; i < message.ReplayResult.NumMessages; i++ {
					data := ta.connection.Expect()

					if len(data) == 0 {
						log.Debugf("Server sent an unexpected EncryptedGroupMessage, closing the connection")
						ta.tokenBoardHandler.ServerClosedHandler(ta.connection.Hostname())
						ta.connection.Close()
						return
					}

					egm := &groups.EncryptedGroupMessage{}
					if err := json.Unmarshal(data, egm); err == nil {
						ta.tokenBoardHandler.GroupMessageHandler(ta.connection.Hostname(), egm)
						ta.lastKnownSignature = egm.Signature
					} else {
						log.Debugf("Server sent an unexpected EncryptedGroupMessage, closing the connection: %v", err)
						ta.tokenBoardHandler.ServerClosedHandler(ta.connection.Hostname())
						ta.connection.Close()
						return
					}
				}
				ta.tokenBoardHandler.ServerSyncedHandler(ta.connection.Hostname())
				ta.connection.SetCapability(groups.CwtchServerSyncedCapability)
			}
		}
	}
}

// Replay posts a Replay Message to the server.
func (ta *TokenBoardClient) Replay() {
	data, _ := json.Marshal(groups.Message{MessageType: groups.ReplayRequestMessage, ReplayRequest: &groups.ReplayRequest{LastCommit: ta.lastKnownSignature}})
	ta.connection.Send(data)
}

// PurchaseTokens purchases the given number of tokens from the server (using the provided payment handler)
func (ta *TokenBoardClient) PurchaseTokens() {
	MakePayment(ta.tokenServiceOnion, ta.tokenService, ta.acn, ta.tokenBoardHandler)
}

// Post sends a Post Request to the server
func (ta *TokenBoardClient) Post(group string, ct []byte, sig []byte) (bool, int) {
	egm := groups.EncryptedGroupMessage{Ciphertext: ct, Signature: sig}
	token, numTokens, err := ta.NextToken(egm.ToBytes(), ta.connection.Hostname())
	if err == nil {
		data, _ := json.Marshal(groups.Message{MessageType: groups.PostRequestMessage, PostRequest: &groups.PostRequest{EGM: egm, Token: token}})
		ta.postLock.Lock()
		// ONLY put group in the EGM as a cache / for error reporting...
		ta.postQueue = append(ta.postQueue, groups.CachedEncryptedGroupMessage{Group: group, EncryptedGroupMessage: egm})
		log.Debugf("Message Length: %s %v", data, len(data))
		err := ta.connection.Send(data)
		ta.postLock.Unlock()
		if err != nil {
			return false, numTokens
		}
		return true, numTokens
	}
	log.Debugf("No Valid Tokens: %v", err)
	return false, numTokens
}

// NextToken retrieves the next token
func (ta *TokenBoardClient) NextToken(data []byte, hostname string) (privacypass.SpentToken, int, error) {
	token, numtokens, err := ta.tokenBoardHandler.FetchToken(ta.tokenServiceOnion)
	if err != nil {
		return privacypass.SpentToken{}, numtokens, err
	}
	return token.SpendToken(append(data, hostname...)), numtokens, nil
}
