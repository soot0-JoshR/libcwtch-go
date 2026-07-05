package event

import (
	"crypto/rand"
	"encoding/json"
	"fmt"
	"git.openprivacy.ca/openprivacy/log"
	"math"
	"math/big"
	"os"
	"runtime"
	"strings"
	"sync"
)

// Event is the core struct type passed around between various subsystems. Events consist of a type which can be
// filtered on, an event ID for tracing and a map of Fields to string values.
type Event struct {
	EventType Type
	EventID   string
	Data      map[Field]string
}

// GetRandNumber is a helper function which returns a random integer, this is
// currently mostly used to generate messageids
func GetRandNumber() *big.Int {
	num, err := rand.Int(rand.Reader, big.NewInt(math.MaxUint32))
	// If we can't generate random numbers then panicking is probably
	// the best option.
	if err != nil {
		panic(err.Error())
	}
	return num
}

// NewEvent creates a new event object with a unique ID and the given type and data.
func NewEvent(eventType Type, data map[Field]string) Event {
	return Event{EventType: eventType, EventID: GetRandNumber().String(), Data: data}
}

// NewEventList creates a new event object with a unique ID and the given type and data supplied in a list format and composed into a map of Type:string
func NewEventList(eventType Type, args ...interface{}) Event {
	data := map[Field]string{}
	for i := 0; i < len(args); i += 2 {
		key, kok := args[i].(Field)
		val, vok := args[i+1].(string)
		if kok && vok {
			data[key] = val
		}
	}
	return Event{EventType: eventType, EventID: GetRandNumber().String(), Data: data}
}

// Manager is an Event Bus which allows subsystems to subscribe to certain EventTypes and publish others.
type manager struct {
	subscribers map[Type][]Queue
	events      chan []byte
	mapMutex    sync.Mutex
	chanMutex   sync.Mutex
	internal    chan bool
	closed      bool
	trace       bool
}

// Manager is an interface for an event bus
type Manager interface {
	Subscribe(Type, Queue)
	Publish(Event)
	Shutdown()
}

// NewEventManager returns an initialized EventManager
func NewEventManager() Manager {
	em := &manager{}
	em.initialize()
	return em
}

// Initialize sets up the Manager.
func (em *manager) initialize() {
	em.subscribers = make(map[Type][]Queue)
	em.events = make(chan []byte)
	em.internal = make(chan bool)
	em.closed = false

	_, em.trace = os.LookupEnv("CWTCH_EVENT_SOURCE")

	go em.eventBus()
}

// Subscribe takes an eventType and an Channel and associates them in the eventBus. All future events of that type
// will be sent to the eventChannel.
func (em *manager) Subscribe(eventType Type, queue Queue) {
	em.mapMutex.Lock()
	defer em.mapMutex.Unlock()
	em.subscribers[eventType] = append(em.subscribers[eventType], queue)
}

// Publish takes an Event and sends it to the internal eventBus where it is distributed to all Subscribers
func (em *manager) Publish(event Event) {
	em.chanMutex.Lock()
	defer em.chanMutex.Unlock()
	if event.EventType != "" && !em.closed {

		// Debug Events for Tracing, locked behind an environment variable
		// for now.
		if em.trace {
			pc, _, _, _ := runtime.Caller(1)
			funcName := runtime.FuncForPC(pc).Name()
			lastSlash := strings.LastIndexByte(funcName, '/')
			if lastSlash < 0 {
				lastSlash = 0
			}
			lastDot := strings.LastIndexByte(funcName[lastSlash:], '.') + lastSlash
			event.Data[Source] = fmt.Sprintf("%v.%v", funcName[:lastDot], funcName[lastDot+1:])
		}

		// Deep Copy the Event...
		eventJSON, err := json.Marshal(event)
		if err != nil {
			log.Errorf("Error serializing event: %v", event)
		}
		em.events <- eventJSON
	}
}

// eventBus is an internal function that is used to distribute events to all subscribers
func (em *manager) eventBus() {
	for {
		eventJSON := <-em.events

		// In the case on an empty event. Teardown the Queue
		if len(eventJSON) == 0 {
			log.Errorf("Received zero length event")
			break
		}

		var event Event
		err := json.Unmarshal(eventJSON, &event)

		if err != nil {
			log.Errorf("Error on Deep Copy: %v %v", eventJSON, err)
		}

		// maps aren't thread safe
		em.mapMutex.Lock()
		subscribers := em.subscribers[event.EventType]
		em.mapMutex.Unlock()

		// Send the event to any subscribers to that event type
		for _, subscriber := range subscribers {
			// Deep Copy for Each Subscriber
			var eventCopy Event
			json.Unmarshal(eventJSON, &eventCopy)
			subscriber.Publish(eventCopy)
		}
	}

	// We are about to exit the eventbus thread, fire off an event internally
	em.internal <- true
}

// Shutdown triggers, and waits for, the internal eventBus goroutine to finish
func (em *manager) Shutdown() {
	em.events <- []byte{}
	em.chanMutex.Lock()
	em.closed = true
	em.chanMutex.Unlock()
	// wait for eventBus to finish
	<-em.internal
	close(em.events)
	close(em.internal)
}
