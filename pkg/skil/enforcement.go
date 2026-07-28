package skil

type Operation struct {
	Capability   string   `json:"capability"`
	Target       string   `json:"target,omitempty"`
	Command      []string `json:"command,omitempty"`
	External     bool     `json:"external,omitempty"`
	Destructive  bool     `json:"destructive,omitempty"`
	Confirmed    bool     `json:"confirmed,omitempty"`
	NetworkBytes int64    `json:"network_bytes,omitempty"`
}
