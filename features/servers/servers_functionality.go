package servers

import (
	"cwtch.im/cwtch/event"
	"fmt"
	"git.openprivacy.ca/cwtch.im/libcwtch-go/constants"
	"git.openprivacy.ca/cwtch.im/server"
	"git.openprivacy.ca/openprivacy/connectivity"
	"path"
	"sync"
)

const serversExperiment = "servers-experiment"

const (
	ZeroServersLoaded = event.Type("ZeroServersLoaded")
	NewServer = event.Type("NewServer")
	ServerIntentUpdate = event.Type("ServerIntentUpdate")
)

const (
	Intent = event.Field("Intent")
)

const (
	IntentRunning = "running"
	IntentStopped = "stopped"
)

type ServerInfo struct {
	Onion string
	ServerBundle string
	Autostart bool
	Running bool
	Description string
	StorageType string
}

var lock sync.Mutex
var appServers server.Servers

func InitServers(acn connectivity.ACN, appdir string) {
	lock.Lock()
	defer lock.Unlock()
	if appServers == nil {
		appServers = server.NewServers(acn, path.Join(appdir, "servers"))
		appServers.LoadServers(constants.DefactoPasswordForUnencryptedProfiles)
	}
}

func DeactivateServers() {
	lock.Lock()
	defer lock.Unlock()
	if appServers != nil {
		appServers.Stop()
	}
}

// ServersFunctionality provides experiment gated server functionality
type ServersFunctionality struct {
}

// ExperimentGate returns ServersFunctionality if the experiment is enabled, and an error otherwise.
func ExperimentGate(experimentMap map[string]bool) (*ServersFunctionality, error) {
	if experimentMap[serversExperiment] {
		lock.Lock()
		defer  lock.Unlock()
		return &ServersFunctionality{}, nil
	}
	return nil, fmt.Errorf("gated by %v", serversExperiment)
}

func (sf *ServersFunctionality) LoadServers(password string) ([]string, error) {
	return appServers.LoadServers(password)
}

func (sf *ServersFunctionality) CreateServer(password string) (server.Server, error) {
	return appServers.CreateServer(password)
}

func (sf *ServersFunctionality) GetServer(onion string) server.Server {
	return appServers.GetServer(onion)
}

func (sf *ServersFunctionality) ListServers() []string {
	return appServers.ListServers()
}

func (sf *ServersFunctionality) DeleteServer(onion string, currentPassword string) error {
	return appServers.DeleteServer(onion, currentPassword)
}

func (sf *ServersFunctionality) LaunchServer(onion string) {
	appServers.LaunchServer(onion)
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