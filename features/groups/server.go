package groups

type ServerKey struct {
	Type string `json:"type"`
	Key  string `json:"key"`
}

type Server struct {
	Onion  string      `json:"onion"`
	Status string      `json:"status"`
	Keys   []ServerKey `json:"keys"`
}
