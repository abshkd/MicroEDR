package model

type Event struct {
	SchemaVersion string         `json:"schema_version"`
	EventType     string         `json:"event_type"`
	EventID       string         `json:"event_id"`
	TsUnixNano    int64          `json:"ts_unix_nano"`
	Host          HostInfo       `json:"host"`
	Agent         AgentInfo      `json:"agent"`
	Container     ContainerInfo  `json:"container"`
	Process       ProcessInfo    `json:"process"`
	Payload       map[string]any `json:"payload"`
}

type HostInfo struct {
	HostID        string    `json:"host_id"`
	Hostname      string    `json:"hostname"`
	OS            string    `json:"os"`
	OSVersion     string    `json:"os_version"`
	KernelVersion string    `json:"kernel_version"`
	Cloud         CloudInfo `json:"cloud"`
}

type CloudInfo struct {
	Provider   string `json:"provider"`
	InstanceID string `json:"instance_id"`
	Region     string `json:"region"`
}

type AgentInfo struct {
	Version string `json:"version"`
	Build   string `json:"build"`
}

type ContainerInfo struct {
	Present     bool   `json:"present"`
	Runtime     string `json:"runtime"`
	ContainerID string `json:"container_id"`
	Pod         string `json:"pod"`
	Namespace   string `json:"namespace"`
	CgroupID    string `json:"cgroup_id"`
}

type ProcessInfo struct {
	PID             int32       `json:"pid"`
	PPID            int32       `json:"ppid"`
	StartTsUnixNano int64       `json:"start_ts_unix_nano"`
	Exe             string      `json:"exe"`
	Cmdline         string      `json:"cmdline"`
	CWD             string      `json:"cwd"`
	User            string      `json:"user"`
	UID             int32       `json:"uid"`
	GID             int32       `json:"gid"`
	EUID            int32       `json:"euid"`
	Hash            HashInfo    `json:"hash"`
	Signing         SigningInfo `json:"signing"`
}

type HashInfo struct {
	SHA256 string `json:"sha256"`
}

type SigningInfo struct {
	Trusted   bool   `json:"trusted"`
	Publisher string `json:"publisher"`
}

