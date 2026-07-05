package model

import (
	"crypto/ed25519"
	"encoding/base32"
	"encoding/json"
	"errors"
	"git.openprivacy.ca/cwtch.im/tapir/primitives"
	"strings"
)

// KeyType provides a wrapper for a generic public key type identifier (could be an onion address, a zcash address etc.)
type KeyType string

const (

	// BundleType - the attribute under which the signed server bundle is stored...
	BundleType = KeyType("server_key_bundle")

	// KeyTypeServerOnion - a cwtch address
	KeyTypeServerOnion = KeyType("bulletin_board_onion") // bulletin board

	// KeyTypeTokenOnion - a cwtch peer with a PoW based token protocol
	KeyTypeTokenOnion = KeyType("token_service_onion")

	//KeyTypePrivacyPass - a privacy pass based token server
	KeyTypePrivacyPass = KeyType("privacy_pass_public_key")
)

// Key provides a wrapper for a generic public key identifier (could be an onion address, a zcash address etc.)
type Key string

// KeyBundle manages a collection of related keys for various different services.
type KeyBundle struct {
	Keys      map[KeyType]Key
	Signature []byte
}

// NewKeyBundle creates a new KeyBundle initialized with no keys.
func NewKeyBundle() *KeyBundle {
	keyBundle := new(KeyBundle)
	keyBundle.Keys = make(map[KeyType]Key)
	return keyBundle
}

// HasKeyType returns true if the bundle has a public key of a given type.
func (kb *KeyBundle) HasKeyType(keytype KeyType) bool {
	_, exists := kb.Keys[keytype]
	return exists
}

// GetKey retrieves a key with a given type from the bundle
func (kb *KeyBundle) GetKey(keytype KeyType) (Key, error) {
	key, exists := kb.Keys[keytype]
	if exists {
		return key, nil
	}
	return "", errors.New("no such key")
}

// Serialize produces a json encoded byte array.
func (kb KeyBundle) Serialize() []byte {
	// json.Marshal sorts map keys
	bundle, _ := json.Marshal(kb)
	return bundle
}

// Sign allows a server to authenticate a key bundle by signing it (this uses the tapir identity interface)
func (kb *KeyBundle) Sign(identity primitives.Identity) {
	kb.Signature = identity.Sign(kb.Serialize())
}

// DeserializeAndVerify takes in a json formatted bundle and only returns a valid key bundle
// if it has been signed by the server.
func DeserializeAndVerify(bundle []byte) (*KeyBundle, error) {
	keyBundle := new(KeyBundle)
	err := json.Unmarshal(bundle, &keyBundle)
	if err == nil {
		signature := keyBundle.Signature
		keyBundle.Signature = nil
		serverKey, _ := keyBundle.GetKey(KeyTypeServerOnion)

		// We have to do convert the encoded key to a format that can be used to verify the signature
		var decodedPub []byte
		decodedPub, err = base32.StdEncoding.DecodeString(strings.ToUpper(string(serverKey)))
		if err == nil && len(decodedPub) == 35 {
			if ed25519.Verify(decodedPub[:32], keyBundle.Serialize(), signature) { // == true
				return keyBundle, nil
			}
		}
		err = InvalidEd25519PublicKey
	}
	return nil, err
}

// AttributeBundle returns a map that can be used as part of a peer attribute bundle
func (kb *KeyBundle) AttributeBundle() map[string]string {
	ab := make(map[string]string)
	for k, v := range kb.Keys {
		ab[string(k)] = string(v)
	}
	return ab
}
