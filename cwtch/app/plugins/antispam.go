package plugins

import (
	"cwtch.im/cwtch/event"
	"git.openprivacy.ca/openprivacy/log"
	"time"
)

const antispamTickTime = 30 * time.Second

type antispam struct {
	bus       event.Manager
	queue     event.Queue
	breakChan chan bool
}

func (a *antispam) Start() {
	go a.run()
}

func (cr *antispam) Id() PluginID {
	return ANTISPAM
}

func (a antispam) Shutdown() {
	a.breakChan <- true
}

func (a *antispam) run() {
	log.Infof("running antispam trigger plugin")
	for {
		select {
		case <-time.After(antispamTickTime):
			// no fuss, just trigger the check. Downstream will filter out superfluous actions
			a.bus.Publish(event.NewEvent(event.TriggerAntispamCheck, map[event.Field]string{}))
			continue
		case <-a.breakChan:
			return
		}
	}
}

// NewAntiSpam returns a Plugin that when started will trigger antispam payments on a regular interval
func NewAntiSpam(bus event.Manager) Plugin {
	cr := &antispam{bus: bus, queue: event.NewQueue(), breakChan: make(chan bool, 1)}
	return cr
}
