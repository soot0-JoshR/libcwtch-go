package connections

import (
	"encoding/json"
	"errors"
	"git.openprivacy.ca/cwtch.im/tapir/primitives/privacypass"
	"git.openprivacy.ca/openprivacy/log"
	"sync"
)

// TokenManager maintains a list of tokens associated with a single TokenServer
type TokenManager struct {
	lock   sync.Mutex
	tokens map[string]*privacypass.Token
}

func NewTokenManager() *TokenManager {
	tm := new(TokenManager)
	tm.tokens = make(map[string]*privacypass.Token)
	return tm
}

// StoreNewTokens adds tokens to the internal list managed by this TokenManager
func (tm *TokenManager) StoreNewTokens(tokens []*privacypass.Token) {
	tm.lock.Lock()
	defer tm.lock.Unlock()
	log.Debugf("acquired %v new tokens", tokens)
	for _, token := range tokens {
		serialized, _ := json.Marshal(token)
		tm.tokens[string(serialized)] = token
	}
}

// NumTokens returns the current number of tokens
func (tm *TokenManager) NumTokens() int {
	tm.lock.Lock()
	defer tm.lock.Unlock()
	return len(tm.tokens)
}

// FetchToken removes a token from the internal list and returns it, along with a count of the remaining tokens.
// Errors if no tokens available.
func (tm *TokenManager) FetchToken() (*privacypass.Token, int, error) {
	tm.lock.Lock()
	defer tm.lock.Unlock()
	if len(tm.tokens) == 0 {
		return nil, 0, errors.New("no more tokens")
	}
	for serializedToken, token := range tm.tokens {
		delete(tm.tokens, serializedToken)
		return token, len(tm.tokens), nil
	}
	return nil, 0, errors.New("no more tokens")
}
