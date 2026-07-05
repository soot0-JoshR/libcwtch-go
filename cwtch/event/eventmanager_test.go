package event

import (
	"git.openprivacy.ca/openprivacy/log"
	"testing"
	"time"
)

// Most basic Manager Test, Initialize, Subscribe, Publish, Receive
func TestEventManager(t *testing.T) {
	eventManager := NewEventManager()

	// We need to make this buffer at least 1, otherwise we will log an error!
	simpleQueue := NewQueue()
	eventManager.Subscribe("TEST", simpleQueue)
	eventManager.Publish(Event{EventType: "TEST", Data: map[Field]string{"Value": "Hello World"}})

	event := simpleQueue.Next()
	if event.EventType == "TEST" && event.Data["Value"] == "Hello World" {

	} else {
		t.Errorf("Received Invalid Event")
	}

	eventManager.Shutdown()
}

func TestEventManagerMultiple(t *testing.T) {
	log.SetLevel(log.LevelDebug)
	eventManager := NewEventManager()

	groupEventQueue := NewQueue()
	peerEventQueue := NewQueue()
	allEventQueue := NewQueue()

	eventManager.Subscribe("PeerEvent", peerEventQueue)
	eventManager.Subscribe("GroupEvent", groupEventQueue)
	eventManager.Subscribe("PeerEvent", allEventQueue)
	eventManager.Subscribe("GroupEvent", allEventQueue)
	eventManager.Subscribe("ErrorEvent", allEventQueue)

	eventManager.Publish(Event{EventType: "PeerEvent", Data: map[Field]string{"Value": "Hello World Peer"}})
	eventManager.Publish(Event{EventType: "GroupEvent", Data: map[Field]string{"Value": "Hello World Group"}})
	eventManager.Publish(Event{EventType: "PeerEvent", Data: map[Field]string{"Value": "Hello World Peer"}})
	eventManager.Publish(Event{EventType: "ErrorEvent", Data: map[Field]string{"Value": "Hello World Error"}})
	eventManager.Publish(Event{EventType: "NobodyIsSubscribedToThisEvent", Data: map[Field]string{"Value": "Noone should see this!"}})

	assertLength := func(len int, expected int, label string) {
		if len != expected {
			t.Errorf("Expected %s to be %v was %v", label, expected, len)
		}
	}

	time.Sleep(time.Second)

	assertLength(groupEventQueue.Len(), 1, "Group Event Queue Length")
	assertLength(peerEventQueue.Len(), 2, "Peer Event Queue Length")
	assertLength(allEventQueue.Len(), 4, "All Event Queue Length")

	checkEvent := func(eventType Type, expected Type, label string) {
		if eventType != expected {
			t.Errorf("Expected %s to be %v was %v", label, expected, eventType)
		}
	}

	event := groupEventQueue.Next()
	checkEvent(event.EventType, "GroupEvent", "First Group Event")

	event = peerEventQueue.Next()
	checkEvent(event.EventType, "PeerEvent", "First Peer Event")
	event = peerEventQueue.Next()
	checkEvent(event.EventType, "PeerEvent", "Second Peer Event")

	event = allEventQueue.Next()
	checkEvent(event.EventType, "PeerEvent", "ALL: First Peer Event")
	event = allEventQueue.Next()
	checkEvent(event.EventType, "GroupEvent", "ALL: First Group Event")
	event = allEventQueue.Next()
	checkEvent(event.EventType, "PeerEvent", "ALL: Second Peer Event")
	event = allEventQueue.Next()
	checkEvent(event.EventType, "ErrorEvent", "ALL: First Error Event")

	eventManager.Shutdown()
	groupEventQueue.Shutdown()
	peerEventQueue.Shutdown()
	allEventQueue.Shutdown()

	// Reading from a closed queue should result in an instant return and an empty event
	event = groupEventQueue.Next()
	checkEvent(event.EventType, "", "Test Next() on Empty Queue")
}
