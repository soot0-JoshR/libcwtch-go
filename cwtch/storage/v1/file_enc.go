package v1

import (
	"crypto/rand"
	"errors"
	"git.openprivacy.ca/openprivacy/log"
	"golang.org/x/crypto/nacl/secretbox"
	"golang.org/x/crypto/pbkdf2"
	"golang.org/x/crypto/sha3"
	"io"
	"os"
	path "path/filepath"
)

// CreateKeySalt derives a key and salt from a password: returns key, salt, err
func CreateKeySalt(password string) ([32]byte, [128]byte, error) {
	var salt [128]byte
	if _, err := io.ReadFull(rand.Reader, salt[:]); err != nil {
		log.Errorf("Cannot read from random: %v\n", err)
		return [32]byte{}, salt, err
	}
	dk := pbkdf2.Key([]byte(password), salt[:], 4096, 32, sha3.New512)

	var dkr [32]byte
	copy(dkr[:], dk)
	return dkr, salt, nil
}

// CreateKey derives a key from a password and salt
func CreateKey(password string, salt []byte) [32]byte {
	dk := pbkdf2.Key([]byte(password), salt, 4096, 32, sha3.New512)

	var dkr [32]byte
	copy(dkr[:], dk)
	return dkr
}

// EncryptFileData encrypts the data with the supplied key
func EncryptFileData(data []byte, key [32]byte) ([]byte, error) {
	var nonce [24]byte

	if _, err := io.ReadFull(rand.Reader, nonce[:]); err != nil {
		log.Errorf("Cannot read from random: %v\n", err)
		return nil, err
	}

	encrypted := secretbox.Seal(nonce[:], data, &nonce, &key)
	return encrypted, nil
}

// DecryptFile decrypts the passed ciphertext with the supplied key.
func DecryptFile(ciphertext []byte, key [32]byte) ([]byte, error) {
	var decryptNonce [24]byte
	copy(decryptNonce[:], ciphertext[:24])
	decrypted, ok := secretbox.Open(nil, ciphertext[24:], &decryptNonce, &key)
	if ok {
		return decrypted, nil
	}
	return nil, errors.New("failed to decrypt")
}

// ReadEncryptedFile reads data from an encrypted file in directory with key
func ReadEncryptedFile(directory, filename string, key [32]byte) ([]byte, error) {
	encryptedbytes, err := os.ReadFile(path.Join(directory, filename))
	if err == nil {
		return DecryptFile(encryptedbytes, key)
	}
	return nil, err
}
