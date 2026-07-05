package v1

import (
	"cwtch.im/cwtch/model"
	"encoding/json"
	"fmt"
	"git.openprivacy.ca/openprivacy/log"
	"math"
	"os"
	"path"
	"sync"
)

// This number is larger that the recommend chunk size of libsodium secretbox by an order of magnitude.
// Since this code is not performance-sensitive (and is unlikely to gain any significant performance benefit from
// cache-efficient chunking) this size isn’t currently a concern.
const (
	fileStorePartitions = 128
	bytesPerFile        = 128 * 1024
)

// streamStore is a file-backed implementation of StreamStore using an in memory buffer of ~16KB and a rotating set of files
type streamStore struct {
	key [32]byte

	storeDirectory string
	filenameBase   string

	// Buffer is used just for current file to write to
	messages        []model.Message
	bufferByteCount int

	lock sync.Mutex
}

// StreamStore provides a stream like interface to encrypted storage
type StreamStore interface {
	Write(message model.Message)
	WriteN(messages []model.Message)
	Read() []model.Message
	Delete()
}

// NewStreamStore returns an initialized StreamStore ready for reading and writing
func NewStreamStore(directory string, filenameBase string, key [32]byte) (store StreamStore) {
	ss := &streamStore{storeDirectory: directory, filenameBase: filenameBase, key: key}
	os.Mkdir(ss.storeDirectory, 0700)

	ss.initBuffer()
	ss.initBufferFromStorage()

	return ss
}

func (ss *streamStore) initBuffer() {
	ss.messages = []model.Message{}
	ss.bufferByteCount = 0
}

func (ss *streamStore) initBufferFromStorage() error {
	filename := fmt.Sprintf("%s.%d", ss.filenameBase, 0)

	bytes, _ := ReadEncryptedFile(ss.storeDirectory, filename, ss.key)

	msgs := []model.Message{}
	err := json.Unmarshal([]byte(bytes), &msgs)
	if err != nil {
		return err
	}

	for _, message := range msgs {
		ss.updateBuffer(message)
	}
	return nil
}

func (ss *streamStore) updateBuffer(m model.Message) {
	ss.messages = append(ss.messages, m)
	ss.bufferByteCount += int(math.Ceil(model.MessageBaseSize*1.5)) + len(m.Message)
}

func (ss *streamStore) updateFile() error {
	msgs, err := json.Marshal(ss.messages)
	if err != nil {
		log.Errorf("Failed to marshal group messages %v\n", err)
	}

	// ENCRYPT
	encryptedMsgs, err := EncryptFileData(msgs, ss.key)
	if err != nil {
		log.Errorf("Failed to encrypt messages: %v\n", err)
		return err
	}

	os.WriteFile(path.Join(ss.storeDirectory, fmt.Sprintf("%s.%d", ss.filenameBase, 0)), encryptedMsgs, 0600)
	return nil
}

func (ss *streamStore) rotateFileStore() {
	os.Remove(path.Join(ss.storeDirectory, fmt.Sprintf("%s.%d", ss.filenameBase, fileStorePartitions-1)))

	for i := fileStorePartitions - 2; i >= 0; i-- {
		os.Rename(path.Join(ss.storeDirectory, fmt.Sprintf("%s.%d", ss.filenameBase, i)), path.Join(ss.storeDirectory, fmt.Sprintf("%s.%d", ss.filenameBase, i+1)))
	}
}

// Delete deletes all the files associated with this streamStore
func (ss *streamStore) Delete() {
	for i := fileStorePartitions - 1; i >= 0; i-- {
		os.Remove(path.Join(ss.storeDirectory, fmt.Sprintf("%s.%d", ss.filenameBase, i)))
	}
}

// Read returns all messages from the backing file (not the buffer, for writing to the current file)
func (ss *streamStore) Read() (messages []model.Message) {
	ss.lock.Lock()
	defer ss.lock.Unlock()

	resp := []model.Message{}

	for i := fileStorePartitions - 1; i >= 0; i-- {
		filename := fmt.Sprintf("%s.%d", ss.filenameBase, i)

		bytes, err := ReadEncryptedFile(ss.storeDirectory, filename, ss.key)
		if err != nil {
			continue
		}

		msgs := []model.Message{}
		json.Unmarshal([]byte(bytes), &msgs)
		resp = append(resp, msgs...)
	}

	return resp
}

// Write adds a GroupMessage to the store
func (ss *streamStore) Write(m model.Message) {
	ss.lock.Lock()
	defer ss.lock.Unlock()
	ss.updateBuffer(m)
	ss.updateFile()

	if ss.bufferByteCount > bytesPerFile {
		log.Debugf("rotating log file")
		ss.rotateFileStore()
		ss.initBuffer()
	}
}

func (ss *streamStore) WriteN(messages []model.Message) {
	ss.lock.Lock()
	defer ss.lock.Unlock()

	log.Infof("WriteN %v messages\n", len(messages))
	i := 0
	for _, m := range messages {
		ss.updateBuffer(m)
		i++

		if ss.bufferByteCount > bytesPerFile {
			ss.updateFile()
			ss.rotateFileStore()
			ss.initBuffer()
		}
	}
	ss.updateFile()
}
