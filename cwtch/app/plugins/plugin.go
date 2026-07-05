package plugins

import (
	"cwtch.im/cwtch/event"
	"fmt"
	"git.openprivacy.ca/openprivacy/connectivity"
)

// PluginID is used as an ID for signaling plugin activities
type PluginID int

// These are the plugin IDs for the supplied plugins
const (
	CONNECTIONRETRY PluginID = iota
	NETWORKCHECK
	ANTISPAM
)

// Plugin is the interface for a plugin
type Plugin interface {
	Start()
	Shutdown()
	Id() PluginID
}

// Get is a plugin factory for the requested plugin
func Get(id PluginID, bus event.Manager, acn connectivity.ACN, onion string) (Plugin, error) {
	switch id {
	case CONNECTIONRETRY:
		return NewConnectionRetry(bus, onion), nil
	case NETWORKCHECK:
		return NewNetworkCheck(onion, bus, acn), nil
	case ANTISPAM:
		return NewAntiSpam(bus), nil
	}

	return nil, fmt.Errorf("plugin not defined %v", id)
}
