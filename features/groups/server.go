package groups

type ServerKey struct {
	Type string `json:"type"`
	Key  string `json:"key"`
}

type Server struct {
	Onion  string      `json:"onion"`
	Status string      `json:"status"`
	Description string `json:"description"`
	Keys   []ServerKey `json:"keys"`
}
