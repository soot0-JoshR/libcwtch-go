package servers

import (
	"cwtch.im/cwtch/event"
	"fmt"
	"git.openprivacy.ca/cwtch.im/server"
	"git.openprivacy.ca/openprivacy/connectivity"
	"git.openprivacy.ca/openprivacy/log"
	"os"
	"path/filepath"
	"strconv"
	"sync"
	"time"
)

const serversExperiment = "servers-experiment"

const (
	ZeroServersLoaded  = event.Type("ZeroServersLoaded")
	NewServer          = event.Type("NewServer")
	ServerIntentUpdate = event.Type("ServerIntentUpdate")
	ServerDeleted      = event.Type("ServerDeleted")
	ServerStatsUpdate  = event.Type("ServerStatsUpdate")
)

const (
	Intent        = event.Field("Intent")
	TotalMessages = event.Field("TotalMessages")
	Connections   = event.Field("Connections")
)

const (
	IntentRunning = "running"
	IntentStopped = "stopped"
)

// TODO: move into Cwtch model/attr

type ServerInfo struct {
	Onion        string
	ServerBundle string
	Autostart    bool
	Running      bool
	Description  string
	StorageType  string
}

type PublishFn func(event.Event)

var lock sync.Mutex
var appServers server.Servers
var publishFn PublishFn
var killStatsUpdate chan bool = make(chan bool, 1)
var enabled bool = false

func InitServers(acn connectivity.ACN, appdir string, pfn PublishFn) {
	lock.Lock()
	defer lock.Unlock()
	if appServers == nil {
		serversDir := filepath.Join(appdir, "servers")
		err := os.MkdirAll(serversDir, 0700)
		if err != nil {
			log.Errorf("Could not init servers directory: %s", err)
		}
		appServers = server.NewServers(acn, serversDir)
		publishFn = pfn
	}
}

func Disable() {
	lock.Lock()
	defer lock.Unlock()
	if appServers != nil {
		appServers.Stop()
	}
	if enabled {
		enabled = false
		killStatsUpdate <- true
	}
}

func Enabled() bool {
	lock.Lock()
	defer lock.Unlock()
	return enabled
}

// ServersFunctionality provides experiment gated server functionality
type ServersFunctionality struct {
}

// ExperimentGate returns ServersFunctionality if the experiment is enabled, and an error otherwise.
func ExperimentGate(experimentMap map[string]bool) (*ServersFunctionality, error) {
	if experimentMap[serversExperiment] {
		lock.Lock()
		defer lock.Unlock()
		return &ServersFunctionality{}, nil
	}
	return nil, fmt.Errorf("gated by %v", serversExperiment)
}

func (sf *ServersFunctionality) Enable() {
	lock.Lock()
	defer lock.Unlock()
	if appServers != nil && !enabled {
		enabled = true
		go cacheForwardServerMetricUpdates()
	}
}

func (sf *ServersFunctionality) LoadServers(password string) ([]string, error) {
	servers, err := appServers.LoadServers(password)
	// server:1.3/libcwtch-go:1.4 accidentally enabled monitor logging by default. make sure it's turned off
	for _, onion := range servers {
		server := appServers.GetServer(onion)
		server.SetMonitorLogging(false)
	}
	return servers, err
}

func (sf *ServersFunctionality) CreateServer(password string) (server.Server, error) {
	return appServers.CreateServer(password)
}

func (sf *ServersFunctionality) GetServer(onion string) server.Server {
	return appServers.GetServer(onion)
}

func (sf *ServersFunctionality) GetServerStatistics(onion string) server.Statistics {
	s := appServers.GetServer(onion)
	if s != nil {
		return s.GetStatistics()
	}
	return server.Statistics{}
}

func (sf *ServersFunctionality) ListServers() []string {
	return appServers.ListServers()
}

func (sf *ServersFunctionality) DeleteServer(onion string, currentPassword string) error {
	return appServers.DeleteServer(onion, currentPassword)
}

func (sf *ServersFunctionality) LaunchServer(onion string) {
	appServers.LaunchServer(onion)
	server := appServers.GetServer(onion)
	if server != nil {
		newStats := server.GetStatistics()
		publishFn(event.NewEventList(ServerStatsUpdate, event.Identity, onion, TotalMessages, strconv.Itoa(newStats.TotalMessages), Connections, strconv.Itoa(newStats.TotalConnections)))
	}
}

func (sf *ServersFunctionality) StopServer(onion string) {
	appServers.StopServer(onion)
}

func (sf *ServersFunctionality) DestroyServers() {
	appServers.Destroy()
}

func (sf *ServersFunctionality) GetServerInfo(onion string) *ServerInfo {
	s := sf.GetServer(onion)
	var serverInfo ServerInfo
	serverInfo.Onion = s.Onion()
	serverInfo.ServerBundle = s.ServerBundle()
	serverInfo.Autostart = s.GetAttribute(server.AttrAutostart) == "true"
	running, _ := s.CheckStatus()
	serverInfo.Running = running
	serverInfo.Description = s.GetAttribute(server.AttrDescription)
	serverInfo.StorageType = s.GetAttribute(server.AttrStorageType)
	return &serverInfo
}

func (si *ServerInfo) EnrichEvent(e *event.Event) {
	e.Data["Onion"] = si.Onion
	e.Data["ServerBundle"] = si.ServerBundle
	e.Data["Description"] = si.Description
	e.Data["StorageType"] = si.StorageType
	if si.Autostart {
		e.Data["Autostart"] = "true"
	} else {
		e.Data["Autostart"] = "false"
	}
	if si.Running {
		e.Data["Running"] = "true"
	} else {
		e.Data["Running"] = "false"
	}
}

// cacheForwardServerMetricUpdates every minute gets metrics for all servers, and if they have changed, sends events to the UI
func cacheForwardServerMetricUpdates() {
	var cache map[string]server.Statistics = make(map[string]server.Statistics)
	duration := time.Second // allow first load
	for {
		select {
		case <-time.After(duration):
			duration = time.Minute
			serverList := appServers.ListServers()
			for _, serverOnion := range serverList {
				server := appServers.GetServer(serverOnion)
				if running, err := server.CheckStatus(); running && err == nil {
					newStats := server.GetStatistics()
					if stats, ok := cache[serverOnion]; !ok || stats.TotalConnections != newStats.TotalConnections || stats.TotalMessages != newStats.TotalMessages {
						cache[serverOnion] = newStats
						publishFn(event.NewEventList(ServerStatsUpdate, event.Identity, serverOnion, TotalMessages, strconv.Itoa(newStats.TotalMessages), Connections, strconv.Itoa(newStats.TotalConnections)))
					}
				}
			}
		case <-killStatsUpdate:
			return
		}
	}
}

func Shutdown() {
	Disable()
	appServers.Destroy()
}
