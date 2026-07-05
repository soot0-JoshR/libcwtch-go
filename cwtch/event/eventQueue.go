package event

import (
	"sync"
)

type queue struct {
	infChan infiniteChannel
	lock    sync.Mutex
	closed  bool
}

// Queue is a wrapper around a channel for handling Events in a consistent way across subsystems.
// The expectation is that each subsystem in Cwtch will manage a given an event.Queue fed from
// the event.Manager.
type Queue interface {
	Publish(event Event)
	Next() Event
	Shutdown()
	OutChan() <-chan Event
	Len() int
}

// NewQueue initializes an event.Queue
func NewQueue() Queue {
	queue := &queue{infChan: *newInfiniteChannel()}
	return queue
}

func (iq *queue) inChan() chan<- Event {
	return iq.infChan.In()
}

func (iq *queue) OutChan() <-chan Event {
	return iq.infChan.Out()
}

// Out returns the next available event from the front of the queue
func (iq *queue) Next() Event {
	event := <-iq.infChan.Out()
	return event
}

func (iq *queue) Len() int {
	return iq.infChan.Len()
}

// Shutdown closes our eventChannel
func (iq *queue) Shutdown() {
	iq.lock.Lock()
	if !iq.closed {
		iq.closed = true
		iq.infChan.Close()
	}
	iq.lock.Unlock()

}

func (iq *queue) Publish(event Event) {
	iq.lock.Lock()
	if !iq.closed {
		iq.inChan() <- event
	}
	iq.lock.Unlock()
}
