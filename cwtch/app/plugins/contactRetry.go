package plugins

import (
	"cwtch.im/cwtch/event"
	"cwtch.im/cwtch/protocol/connections"
	"git.openprivacy.ca/openprivacy/log"
	"math"
	"sync"
	"time"
)

// Todo: Move to protocol/connections
// This Plugin is now required and it makes more sense to run more integrated in engine

const tickTimeSec = 30
const tickTime = tickTimeSec * time.Second

const circutTimeoutSecs int = 120

const MaxBaseTimeoutSec = 5 * 60 // a max base time out of 5 min
const maxFailedBackoff = 6       // 2^6 = 64 -> 64 * [2m to 5m] = 2h8m to 5h20m

const PriorityQueueTimeSinceQualifierHours float64 = 168

type connectionType int

const (
	peerConn connectionType = iota
	serverConn
)

type contact struct {
	id    string
	state connections.ConnectionState
	ctype connectionType

	lastAttempt time.Time
	failedCount int

	lastSeen time.Time
	queued   bool
}

// compare a to b
// returns -1 if a < b
//
//	0 if a == b
//	+1 if a > b
//
// algo: sort by failedCount first favouring less attempts, then sort by lastSeen time favouring more recent connections
func (a *contact) compare(b *contact) int {
	if a.failedCount < b.failedCount {
		return -1
	} else if a.failedCount > b.failedCount {
		return +1
	}

	if a.lastSeen.After(b.lastSeen) {
		return -1
	} else if a.lastSeen.Before(b.lastSeen) {
		return +1
	}

	return 0
}

type connectionQueue struct {
	queue []*contact
}

func newConnectionQueue() *connectionQueue {
	return &connectionQueue{queue: []*contact{}}
}

func (cq *connectionQueue) insert(c *contact) {
	// find loc
	i := 0
	var b *contact
	for i, b = range cq.queue {
		if c.compare(b) >= 0 {
			break
		}
	}

	// insert
	if len(cq.queue) == i { // nil or empty slice or after last element
		cq.queue = append(cq.queue, c)
	} else {
		cq.queue = append(cq.queue[:i+1], cq.queue[i:]...) // index < len(a)
		cq.queue[i] = c
	}

	c.queued = true
}

func (cq *connectionQueue) dequeue() *contact {
	if len(cq.queue) == 0 {
		return nil
	}
	c := cq.queue[0]
	cq.queue = cq.queue[1:]
	c.queued = false
	return c
}

type contactRetry struct {
	bus            event.Manager
	queue          event.Queue
	ACNUp          bool
	ACNUpTime      time.Time
	protocolEngine bool
	running        bool
	breakChan      chan bool
	onion          string
	lastCheck      time.Time

	connections   sync.Map //[string]*contact
	connCount     int
	pendingQueue  *connectionQueue
	priorityQueue *connectionQueue
}

// NewConnectionRetry returns a Plugin that when started will retry connecting to contacts with a failedCount timing
func NewConnectionRetry(bus event.Manager, onion string) Plugin {
	cr := &contactRetry{bus: bus, queue: event.NewQueue(), breakChan: make(chan bool, 1), connections: sync.Map{}, connCount: 0, ACNUp: false, ACNUpTime: time.Now(), protocolEngine: false, onion: onion, pendingQueue: newConnectionQueue(), priorityQueue: newConnectionQueue()}
	return cr
}

// maxTorCircuitsPending a function to throttle access to tor network during start up
func (cr *contactRetry) maxTorCircuitsPending() int {
	timeSinceStart := time.Since(cr.ACNUpTime)
	if timeSinceStart < 30*time.Second {
		return 4
	} else if timeSinceStart < 4*time.Minute {
		return 8
	} else if timeSinceStart < 8*time.Minute {
		return 16
	}
	return connections.TorMaxPendingConns
}

func (cr *contactRetry) connectingCount() int {
	connecting := 0
	cr.connections.Range(func(k, v interface{}) bool {
		conn := v.(*contact)
		if conn.state == connections.CONNECTING {
			connecting++
		}
		return true
	})
	return connecting
}

func (cr *contactRetry) Start() {
	if !cr.running {
		go cr.run()
	} else {
		log.Errorf("Attempted to start Contact Retry plugin twice for %v", cr.onion)
	}
}

func (cr *contactRetry) Id() PluginID {
	return CONNECTIONRETRY
}

func (cr *contactRetry) run() {
	cr.running = true
	cr.bus.Subscribe(event.PeerStateChange, cr.queue)
	cr.bus.Subscribe(event.ACNStatus, cr.queue)
	cr.bus.Subscribe(event.ServerStateChange, cr.queue)
	cr.bus.Subscribe(event.PeerRequest, cr.queue)
	cr.bus.Subscribe(event.QueuePeerRequest, cr.queue)
	cr.bus.Subscribe(event.QueueJoinServer, cr.queue)
	cr.bus.Subscribe(event.ProtocolEngineShutdown, cr.queue)
	cr.bus.Subscribe(event.ProtocolEngineCreated, cr.queue)

	for {
		if cr.ACNUp {
			cr.requeueReady()
			connectingCount := cr.connectingCount()
			log.Debugf("checking queues (priority len: %v) (pending len: %v) of total conns watched: %v, with current connecingCount: %v", len(cr.priorityQueue.queue), len(cr.pendingQueue.queue), cr.connCount, connectingCount)

			// do priority connections first...
			for connectingCount < cr.maxTorCircuitsPending() && len(cr.priorityQueue.queue) > 0 {
				contact := cr.priorityQueue.dequeue()
				if contact == nil {
					break
				}
				// could have received incoming connection while in queue, make sure still disconnected before trying
				if contact.state == connections.DISCONNECTED {
					cr.publishConnectionRequest(contact)
					connectingCount++
				}
			}

			for connectingCount < cr.maxTorCircuitsPending() && len(cr.pendingQueue.queue) > 0 {
				contact := cr.pendingQueue.dequeue()
				if contact == nil {
					break
				}
				// could have received incoming connection while in queue, make sure still disconnected before trying
				if contact.state == connections.DISCONNECTED {
					cr.publishConnectionRequest(contact)
					connectingCount++
				}
			}
			cr.lastCheck = time.Now()
		}

		select {
		case e := <-cr.queue.OutChan():
			switch e.EventType {
			case event.PeerStateChange:
				state := connections.ConnectionStateToType()[e.Data[event.ConnectionState]]
				peer := e.Data[event.RemotePeer]
				cr.handleEvent(peer, state, peerConn)

			case event.ServerStateChange:
				state := connections.ConnectionStateToType()[e.Data[event.ConnectionState]]
				server := e.Data[event.GroupServer]
				cr.handleEvent(server, state, serverConn)

			case event.QueueJoinServer:
				fallthrough
			case event.QueuePeerRequest:
				lastSeen, err := time.Parse(time.RFC3339Nano, e.Data[event.LastSeen])
				if err != nil {
					lastSeen = event.CwtchEpoch
				}

				id := ""
				if peer, exists := e.Data[event.RemotePeer]; exists {
					id = peer
					cr.addConnection(peer, connections.DISCONNECTED, peerConn, lastSeen)
				} else if server, exists := e.Data[event.GroupServer]; exists {
					id = server
					cr.addConnection(server, connections.DISCONNECTED, serverConn, lastSeen)
				}

				if c, ok := cr.connections.Load(id); ok {
					contact := c.(*contact)
					if contact.state == connections.DISCONNECTED && !contact.queued {

						// prioritize connections made in the last week
						if time.Since(contact.lastSeen).Hours() < PriorityQueueTimeSinceQualifierHours {
							cr.priorityQueue.insert(contact)
						} else {
							cr.pendingQueue.insert(contact)
						}
					}
				}
			case event.ProtocolEngineCreated:
				cr.protocolEngine = true

			case event.ProtocolEngineShutdown:
				cr.ACNUp = false
				cr.protocolEngine = false
			case event.ACNStatus:
				prog := e.Data[event.Progress]
				if !cr.protocolEngine {
					continue
				}
				if prog == "100" && !cr.ACNUp {
					cr.ACNUp = true
					cr.ACNUpTime = time.Now()
					cr.connections.Range(func(k, v interface{}) bool {
						p := v.(*contact)
						p.failedCount = 0
						return true
					})
				} else if prog != "100" {
					cr.ACNUp = false
				}
			}

		case <-time.After(tickTime):
			continue

		case <-cr.breakChan:
			cr.running = false
			return
		}
	}
}

func (cr *contactRetry) requeueReady() {
	if !cr.ACNUp {
		return
	}

	retryable := []*contact{}

	throughPutPerMin := cr.maxTorCircuitsPending() / (circutTimeoutSecs / 60)
	adjustedBaseTimeout := cr.connCount / throughPutPerMin * 60
	if adjustedBaseTimeout < circutTimeoutSecs {
		adjustedBaseTimeout = circutTimeoutSecs
	} else if adjustedBaseTimeout > MaxBaseTimeoutSec {
		adjustedBaseTimeout = MaxBaseTimeoutSec
	}

	cr.connections.Range(func(k, v interface{}) bool {
		p := v.(*contact)
		if p.state == connections.DISCONNECTED && !p.queued {
			timeout := time.Duration((math.Pow(2, float64(p.failedCount)))*float64(adjustedBaseTimeout /*baseTimeoutSec*/)) * time.Second
			if time.Since(p.lastAttempt) > timeout {
				retryable = append(retryable, p)
			}
		}
		return true
	})
	for _, contact := range retryable {
		if time.Since(contact.lastSeen).Hours() < PriorityQueueTimeSinceQualifierHours {
			cr.priorityQueue.insert(contact)
		} else {
			cr.pendingQueue.insert(contact)
		}
	}
}

func (cr *contactRetry) publishConnectionRequest(contact *contact) {
	if contact.ctype == peerConn {
		cr.bus.Publish(event.NewEvent(event.RetryPeerRequest, map[event.Field]string{event.RemotePeer: contact.id}))
	}
	if contact.ctype == serverConn {
		cr.bus.Publish(event.NewEvent(event.RetryServerRequest, map[event.Field]string{event.GroupServer: contact.id}))
	}
	contact.state = connections.CONNECTING // Hacky but needed so we don't over flood waiting for PeerStateChange from engine
	contact.lastAttempt = time.Now()
}

func (cr *contactRetry) addConnection(id string, state connections.ConnectionState, ctype connectionType, lastSeen time.Time) {
	// don't handle contact retries for ourselves
	if id == cr.onion {
		return
	}

	if _, exists := cr.connections.Load(id); !exists {
		p := &contact{id: id, state: state, failedCount: 0, lastAttempt: event.CwtchEpoch, ctype: ctype, lastSeen: lastSeen, queued: false}
		cr.connections.Store(id, p)
		cr.connCount += 1
		return
	}
}

func (cr *contactRetry) handleEvent(id string, state connections.ConnectionState, ctype connectionType) {
	log.Debugf("cr.handleEvent state to %v on id %v", connections.ConnectionStateName[state], id)

	// don't handle contact retries for ourselves
	if id == cr.onion {
		return
	}

	if _, exists := cr.connections.Load(id); !exists {
		cr.addConnection(id, state, ctype, event.CwtchEpoch)
		return
	}

	pinf, _ := cr.connections.Load(id)
	p := pinf.(*contact)
	log.Debugf("  managing state change for %v %v to %v by self %v", id, connections.ConnectionStateName[p.state], connections.ConnectionStateName[state], cr.onion)
	if state == connections.DISCONNECTED || state == connections.FAILED || state == connections.KILLED {
		if p.state == connections.SYNCED || p.state == connections.AUTHENTICATED {
			p.lastSeen = time.Now()
		} else {
			p.failedCount += 1
		}
		p.state = connections.DISCONNECTED
		p.lastAttempt = time.Now()
		if p.failedCount > maxFailedBackoff {
			p.failedCount = maxFailedBackoff
		}
	} else if state == connections.CONNECTING || state == connections.CONNECTED {
		p.state = state
	} else if state == connections.AUTHENTICATED || state == connections.SYNCED {
		p.state = state
		p.lastSeen = time.Now()
		p.failedCount = 0
	}
}

func (cr *contactRetry) Shutdown() {
	cr.breakChan <- true
	cr.queue.Shutdown()
}
