package v1

import (
	"cwtch.im/cwtch/model"
	"os"
	"testing"
)

const testingDir = "./testing"
const filenameBase = "testStream"
const password = "asdfqwer"
const line1 = "Hello from storage!"

func TestStreamStoreWriteRead(t *testing.T) {
	os.Remove(".test.json")
	os.RemoveAll(testingDir)
	os.Mkdir(testingDir, 0777)
	key, _, _ := CreateKeySalt(password)
	ss1 := NewStreamStore(testingDir, filenameBase, key)
	m := model.Message{Message: line1}
	ss1.Write(m)

	ss2 := NewStreamStore(testingDir, filenameBase, key)
	messages := ss2.Read()
	if len(messages) != 1 {
		t.Errorf("Read messages has wrong length. Expected: 1 Actual: %d\n", len(messages))
	}
	if messages[0].Message != line1 {
		t.Errorf("Read message has wrong content. Expected: '%v' Actual: '%v'\n", line1, messages[0].Message)
	}
}

func TestStreamStoreWriteReadRotate(t *testing.T) {
	os.Remove(".test.json")
	os.RemoveAll(testingDir)
	os.Mkdir(testingDir, 0777)
	key, _, _ := CreateKeySalt(password)
	ss1 := NewStreamStore(testingDir, filenameBase, key)
	m := model.Message{Message: line1}
	for i := 0; i < 400; i++ {
		ss1.Write(m)
	}

	ss2 := NewStreamStore(testingDir, filenameBase, key)
	messages := ss2.Read()
	if len(messages) != 400 {
		t.Errorf("Read messages has wrong length. Expected: 400 Actual: %d\n", len(messages))
	}
	if messages[0].Message != line1 {
		t.Errorf("Read message has wrong content. Expected: '%v' Actual: '%v'\n", line1, messages[0].Message)
	}
}
