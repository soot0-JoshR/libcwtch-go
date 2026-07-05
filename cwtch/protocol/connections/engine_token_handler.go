package connections

import (
	"cwtch.im/cwtch/event"
	"cwtch.im/cwtch/protocol/groups"
	"encoding/base64"
	"git.openprivacy.ca/cwtch.im/tapir/primitives/privacypass"
	"strconv"
)

// Implement Token Service Handler for Engine

// GroupMessageHandler receives a server and an encrypted group message
func (e *engine) GroupMessageHandler(server string, gm *groups.EncryptedGroupMessage) {
	e.receiveGroupMessage(server, gm)
}

// PostingFailed notifies a peer that a message failed to post
func (e *engine) PostingFailed(group string, sig []byte) {
	e.eventManager.Publish(event.NewEvent(event.SendMessageToGroupError, map[event.Field]string{event.GroupID: group, event.Error: "failed to post message", event.Signature: base64.StdEncoding.EncodeToString(sig)}))
}

// ServerAuthedHandler is notified when a server has successfully authed
func (e *engine) ServerAuthedHandler(server string) {
	e.serverAuthed(server)
}

// ServerSyncedHandler is notified when a server has successfully synced
func (e *engine) ServerSyncedHandler(server string) {
	e.serverSynced(server)
}

// ServerClosedHandler is notified when a server connection has closed, the result is ignored during shutdown...
func (e *engine) ServerClosedHandler(server string) {
	e.ignoreOnShutdown(e.serverDisconnected)(server)
}

// NewTokenHandler is notified after a successful token acquisition
func (e *engine) NewTokenHandler(tokenService string, tokens []*privacypass.Token) {
	tokenManagerPointer, _ := e.tokenManagers.LoadOrStore(tokenService, NewTokenManager())
	tokenManager := tokenManagerPointer.(*TokenManager)
	tokenManager.StoreNewTokens(tokens)
	e.eventManager.Publish(event.NewEvent(event.TokenManagerInfo, map[event.Field]string{event.ServerTokenOnion: tokenService, event.ServerTokenCount: strconv.Itoa(tokenManager.NumTokens())}))
}

// FetchToken is notified when a server requires a new token from the client
func (e *engine) FetchToken(tokenService string) (*privacypass.Token, int, error) {
	tokenManagerPointer, _ := e.tokenManagers.LoadOrStore(tokenService, NewTokenManager())
	tokenManager := tokenManagerPointer.(*TokenManager)
	token, numTokens, err := tokenManager.FetchToken()
	e.eventManager.Publish(event.NewEvent(event.TokenManagerInfo, map[event.Field]string{event.ServerTokenOnion: tokenService, event.ServerTokenCount: strconv.Itoa(numTokens)}))
	return token, numTokens, err
}
