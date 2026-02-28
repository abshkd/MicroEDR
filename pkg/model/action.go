package model

type Action struct {
	ActionID        string         `json:"action_id"`
	HostID          string         `json:"host_id"`
	TsUnixNano      int64          `json:"ts_unix_nano"`
	Type            string         `json:"type"`
	Params          map[string]any `json:"params"`
	Reason          string         `json:"reason"`
	ExpiresTsUnix   int64          `json:"expires_ts_unix_nano"`
	SignatureBase64 string         `json:"signature"`
}

