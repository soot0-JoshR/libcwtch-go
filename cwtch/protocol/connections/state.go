package connections

// ConnectionState defines the various states a connection can be in from disconnected to authenticated
type ConnectionState int

// Connection States
// DISCONNECTED - No existing connection has been made, or all attempts have failed
// CONNECTING - We are in the process of attempting to connect to a given endpoint
// CONNECTED - We have connected but not yet authenticated
// AUTHENTICATED - im.ricochet.auth-hidden-server has succeeded on the connection.
// SYNCED - we have pulled all the messages for groups from the server and are ready to send
const (
	DISCONNECTED ConnectionState = iota
	CONNECTING
	CONNECTED
	AUTHENTICATED
	SYNCED
	FAILED
	KILLED
)

var (
	// ConnectionStateName allows conversion of states to their string representations
	ConnectionStateName = []string{"Disconnected", "Connecting", "Connected", "Authenticated", "Synced", "Failed", "Killed"}
)

// ConnectionStateToType allows conversion of strings to their state type
func ConnectionStateToType() map[string]ConnectionState {
	return map[string]ConnectionState{"Disconnected": DISCONNECTED, "Connecting": CONNECTING,
		"Connected": CONNECTED, "Authenticated": AUTHENTICATED, "Synced": SYNCED, "Failed": FAILED, "Killed": KILLED}
}
