package skil

type SkillContract struct {
	Version       int              `json:"version" yaml:"version"`
	Skill         SkillIdentity    `json:"skill" yaml:"skill"`
	Owner         string           `json:"owner,omitempty" yaml:"owner,omitempty"`
	Entrypoint    string           `json:"entrypoint,omitempty" yaml:"entrypoint,omitempty"`
	Compatibility *Compatibility   `json:"compatibility,omitempty" yaml:"compatibility,omitempty"`
	Security      *SecurityPosture `json:"security,omitempty" yaml:"security,omitempty"`
	Capabilities  Capabilities     `json:"capabilities" yaml:"capabilities"`
}

type SkillIdentity struct {
	Name        string `json:"name" yaml:"name"`
	Version     string `json:"version,omitempty" yaml:"version,omitempty"`
	Description string `json:"description" yaml:"description"`
}

type Compatibility struct {
	Agents     []string `json:"agents,omitempty" yaml:"agents,omitempty"`
	Platforms  []string `json:"platforms,omitempty" yaml:"platforms,omitempty"`
	MinVersion string   `json:"min_version,omitempty" yaml:"min_version,omitempty"`
}

// SecurityPosture is the portable security summary. Capabilities remains
// the enforceable least-privilege declaration and must be consistent with it.
type SecurityPosture struct {
	RequiresNetwork bool `json:"requires_network" yaml:"requires_network"`
	RequiresSecrets bool `json:"requires_secrets" yaml:"requires_secrets"`
	WritesFiles     bool `json:"writes_files" yaml:"writes_files"`
	RunsCommands    bool `json:"runs_commands" yaml:"runs_commands"`
}

type Capabilities struct {
	Filesystem  FilesystemCapability  `json:"filesystem" yaml:"filesystem"`
	Network     NetworkCapability     `json:"network" yaml:"network"`
	Commands    CommandCapability     `json:"commands" yaml:"commands"`
	Secrets     SecretCapability      `json:"secrets" yaml:"secrets"`
	Environment EnvironmentCapability `json:"environment" yaml:"environment"`
	Tools       ToolCapability        `json:"tools" yaml:"tools"`
	MCP         MCPCapability         `json:"mcp" yaml:"mcp"`
	Persistence bool                  `json:"persistence" yaml:"persistence"`
	Agent       AgentCapability       `json:"agent" yaml:"agent"`
	Resources   ResourceLimits        `json:"resources" yaml:"resources"`
}

type FilesystemCapability struct {
	Read   []string `json:"read,omitempty" yaml:"read,omitempty"`
	Write  []string `json:"write,omitempty" yaml:"write,omitempty"`
	Delete []string `json:"delete,omitempty" yaml:"delete,omitempty"`
}
type NetworkCapability struct {
	Inbound  bool     `json:"inbound" yaml:"inbound"`
	Outbound bool     `json:"outbound" yaml:"outbound"`
	Hosts    []string `json:"hosts,omitempty" yaml:"hosts,omitempty"`
}
type CommandCapability struct {
	Execute bool     `json:"execute" yaml:"execute"`
	Allow   []string `json:"allow,omitempty" yaml:"allow,omitempty"`
}
type SecretCapability struct {
	Read   []string `json:"read,omitempty" yaml:"read,omitempty"`
	Expose bool     `json:"expose" yaml:"expose"`
}
type EnvironmentCapability struct {
	Read []string `json:"read,omitempty" yaml:"read,omitempty"`
}
type ToolCapability struct {
	Allow []string `json:"allow,omitempty" yaml:"allow,omitempty"`
	Deny  []string `json:"deny,omitempty" yaml:"deny,omitempty"`
}
type MCPCapability struct {
	Servers []string `json:"servers,omitempty" yaml:"servers,omitempty"`
	Tools   []string `json:"tools,omitempty" yaml:"tools,omitempty"`
}
type AgentCapability struct {
	AutonomousActions   bool     `json:"autonomous_actions" yaml:"autonomous_actions"`
	ExternalSideEffects bool     `json:"external_side_effects" yaml:"external_side_effects"`
	ConfirmDestructive  bool     `json:"confirm_destructive" yaml:"confirm_destructive"`
	ConfirmExternal     bool     `json:"confirm_external" yaml:"confirm_external"`
	ExternalTargets     []string `json:"external_targets,omitempty" yaml:"external_targets,omitempty"`
}
type ResourceLimits struct {
	MaxRuntimeSeconds int64 `json:"max_runtime_seconds,omitempty" yaml:"max_runtime_seconds,omitempty"`
	MaxMemoryMB       int64 `json:"max_memory_mb,omitempty" yaml:"max_memory_mb,omitempty"`
	MaxNetworkBytes   int64 `json:"max_network_bytes,omitempty" yaml:"max_network_bytes,omitempty"`
	MaxToolCalls      int   `json:"max_tool_calls,omitempty" yaml:"max_tool_calls,omitempty"`
}

type ObservedCapabilities struct {
	FilesystemRead      bool     `json:"filesystem_read"`
	FilesystemWrite     bool     `json:"filesystem_write"`
	FilesystemDelete    bool     `json:"filesystem_delete"`
	FilesystemPaths     []string `json:"filesystem_paths,omitempty"`
	NetworkOutbound     bool     `json:"network_outbound"`
	NetworkHosts        []string `json:"network_hosts,omitempty"`
	CommandsExecute     bool     `json:"commands_execute"`
	Commands            []string `json:"commands,omitempty"`
	SecretsRead         bool     `json:"secrets_read"`
	Secrets             []string `json:"secrets,omitempty"`
	Persistence         bool     `json:"persistence"`
	ExternalSideEffects bool     `json:"external_side_effects"`
	EnvironmentRead     bool     `json:"environment_read"`
	Environment         []string `json:"environment,omitempty"`
	Tools               []string `json:"tools,omitempty"`
	MCPServers          []string `json:"mcp_servers,omitempty"`
	MCPTools            []string `json:"mcp_tools,omitempty"`
}
