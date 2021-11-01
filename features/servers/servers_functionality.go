package servers

import (
	"cwtch.im/cwtch/event"
	"encoding/json"
	"fmt"
	"git.openprivacy.ca/openprivacy/connectivity"
	"path"
	"sync"
)
import "git.openprivacy.ca/cwtch.im/server"

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
	IntentEnabled = "enabled"
	IntentDisabled = "disabled"
)

var lock sync.Mutex
var appServers server.Servers

func InitServers(acn connectivity.ACN, appdir string) {
	lock.Lock()
	defer lock.Unlock()
	if appServers == nil {
		appServers = server.NewServers(acn, path.Join(appdir, "servers"))
	}
}

func DeactivateServers() {
	appServers.Shutdown()
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

func (sf *ServersFunctionality) ShutdownServer(onion string) {
	appServers.ShutdownServer(onion)
}

func (sf *ServersFunctionality) SeverToJson(onion string) string {
	s := sf.GetServer(onion)
	hash := make(map[string]string)
	hash["onion"] = s.Onion()
	hash["serverbundle"] = s.ServerBundle()
	hash[server.AttrAutostart] = s.GetAttribute(server.AttrAutostart)
	hash[server.AttrEnabled] = s.GetAttribute(server.AttrEnabled)
	hash[server.AttrDescription] = s.GetAttribute(server.AttrDescription)
	hash[server.AttrStorageType] = s.GetAttribute(server.AttrStorageType)
	json, _ := json.Marshal(hash)
	return string(json)
}