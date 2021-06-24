package constants

import "cwtch.im/cwtch/event"

// The server manager defines its own events, most should be self-explanatory:
const (
	NewServer = event.Type("NewServer")

	// Force  a UI update
	ListServers = event.Type("ListServers")

	// Takes an Onion, used to toggle off/on Server availability
	StartServer = event.Type("StartServer")
	StopServer  = event.Type("StopServer")

	// Takes an Onion and a AutoStartEnabled boolean
	AutoStart = event.Type("AutoStart")

	// Get the status of a particular server (takes an Onion)
	CheckServerStatus  = event.Type("CheckServerStatus")
	ServerStatusUpdate = event.Type("ServerStatusUpdate")
)

const (
	AutoStartEnabled = event.Field("AutoStartEnabled")
)
