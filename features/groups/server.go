package groups

type ServerKey struct {
	Type string `json:"type"`
	Key  string `json:"key"`
}

type SyncStatus struct {
	StartTime       string `json:"startTime"`
	LastMessageTime string `json:"lastMessageTime"`
}

type Server struct {
	Onion        string      `json:"onion"`
	Identifier   int         `json:"identifier"`
	Status       string      `json:"status"`
	Description  string      `json:"description"`
	Keys         []ServerKey `json:"keys"`
	SyncProgress SyncStatus  `json:"syncProgress"`
}
