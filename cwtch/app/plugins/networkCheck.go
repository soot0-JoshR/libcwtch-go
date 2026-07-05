package plugins

import (
	"cwtch.im/cwtch/event"
	"cwtch.im/cwtch/protocol/connections"
	"cwtch.im/cwtch/utils"
	"git.openprivacy.ca/openprivacy/connectivity"
	"git.openprivacy.ca/openprivacy/log"
	"sync"
	"time"
)

// NetworkCheckError is a status for when the NetworkCheck Plugin has had an error making an out going connection indicating it may be offline
const NetworkCheckError = "Error"

// NetworkCheckSuccess is a status for when the NetworkCheck Plugin has had a successful message from a peer, indicating it is online right now
const NetworkCheckSuccess = "Success"

const NetworkCheckPeriod = time.Minute

// networkCheck is a convenience plugin for testing high level availability of onion services
type networkCheck struct {
	bus         event.Manager
	queue       event.Queue
	onion       string
	acn         connectivity.ACN
	breakChan   chan bool
	running     bool
	offline     bool
	offlineLock sync.Mutex
}

// NewNetworkCheck returns a Plugin that when started will attempt various network tests
func NewNetworkCheck(onion string, bus event.Manager, acn connectivity.ACN) Plugin {
	nc := &networkCheck{onion: onion, bus: bus, acn: acn, queue: event.NewQueue(), breakChan: make(chan bool, 1)}
	return nc
}

func (nc *networkCheck) Start() {
	go nc.run()
}

func (cr *networkCheck) Id() PluginID {
	return NETWORKCHECK
}

func (nc *networkCheck) run() {
	nc.running = true
	nc.offline = true
	nc.bus.Subscribe(event.ProtocolEngineStartListen, nc.queue)
	nc.bus.Subscribe(event.NewMessageFromPeer, nc.queue)
	nc.bus.Subscribe(event.PeerAcknowledgement, nc.queue)
	nc.bus.Subscribe(event.EncryptedGroupMessage, nc.queue)
	nc.bus.Subscribe(event.PeerStateChange, nc.queue)
	nc.bus.Subscribe(event.ServerStateChange, nc.queue)
	nc.bus.Subscribe(event.NewGetValMessageFromPeer, nc.queue)
	nc.bus.Subscribe(event.NewRetValMessageFromPeer, nc.queue)
	var lastMessageReceived = time.Now()
	for {
		select {
		case <-nc.breakChan:
			nc.running = false
			return
		case e := <-nc.queue.OutChan():
			switch e.EventType {
			// On receipt of a Listen request for an onion service we will add the onion to our list
			// and then we will wait a minute and check the connection for the first time (the onion should be up)
			// under normal operating circumstances
			case event.ProtocolEngineStartListen:
				if nc.onion == (e.Data[event.Onion]) {
					log.Debugf("initiating connection check for %v", e.Data[event.Onion])
					if time.Since(lastMessageReceived) > time.Minute {
						nc.selfTest()
					}
				} else {
					log.Errorf("network check plugin received an event for a different profile than it was started with. Internal wiring is probably wrong.")
				}
			case event.PeerStateChange:
				fallthrough
			case event.ServerStateChange:
				// if we successfully connect / authenticated to a remote server / peer then we obviously have internet
				connectionState := e.Data[event.ConnectionState]
				nc.offlineLock.Lock()
				if connectionState == connections.ConnectionStateName[connections.AUTHENTICATED] || connectionState == connections.ConnectionStateName[connections.CONNECTED] {
					lastMessageReceived = time.Now()

					if nc.offline {
						nc.bus.Publish(event.NewEvent(event.NetworkStatus, map[event.Field]string{event.Error: "", event.Status: NetworkCheckSuccess}))
						nc.offline = false
					}
				}
				nc.offlineLock.Unlock()
			default:
				// if we receive either an encrypted group message or a peer acknowledgement we can assume the network
				// is up and running (our onion service might still not be available, but we would aim to detect that
				// through other actions
				// we reset out timer
				lastMessageReceived = time.Now()
				nc.offlineLock.Lock()
				if nc.offline {
					nc.bus.Publish(event.NewEvent(event.NetworkStatus, map[event.Field]string{event.Error: "", event.Status: NetworkCheckSuccess}))
					nc.offline = false
				}
				nc.offlineLock.Unlock()
			}
		case <-time.After(NetworkCheckPeriod):
			// if we haven't received an action in the last minute...kick off a set of testing
			if time.Since(lastMessageReceived) > time.Minute {
				nc.selfTest()
				lastMessageReceived = time.Now()
			}
		}
	}
}

func (nc *networkCheck) Shutdown() {
	if nc.running {
		nc.queue.Shutdown()
		log.Debugf("shutting down network status plugin")
		nc.breakChan <- true
	}
}

func (nc *networkCheck) selfTest() {
	go nc.checkConnection(nc.onion)
}

func (nc *networkCheck) checkConnection(onion string) {
	prog, _ := nc.acn.GetBootstrapStatus()
	if prog != 100 {
		return
	}

	// we want to definitively time these actions out faster than tor will, because these onions should definitely be
	// online
	ClientTimeout := utils.TimeoutPolicy(time.Second * 60)
	err := ClientTimeout.ExecuteAction(func() error {
		conn, _, err := nc.acn.Open(onion)
		if err == nil {
			conn.Close()
		}
		return err
	})
	nc.offlineLock.Lock()
	defer nc.offlineLock.Unlock()
	// regardless of the outcome we want to report a status to let anyone who might care know that we did do a check
	if err != nil {
		log.Debugf("publishing network error for %v -- %v\n", onion, err)
		nc.bus.Publish(event.NewEvent(event.NetworkStatus, map[event.Field]string{event.Onion: onion, event.Error: err.Error(), event.Status: NetworkCheckError}))
		nc.offline = true
	} else {
		log.Debugf("publishing network success for %v", onion)
		nc.bus.Publish(event.NewEvent(event.NetworkStatus, map[event.Field]string{event.Onion: onion, event.Error: "", event.Status: NetworkCheckSuccess}))
		nc.offline = false
	}
}
