package config

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"time"
)

type Config struct {
	TenantID string `json:"tenant_id"`
	HostID   string `json:"host_id"`
	Ingest   struct {
		URL string `json:"url"`
	} `json:"ingest"`
	Spool struct {
		Dir            string `json:"dir"`
		MaxMB          int64  `json:"max_mb"`
		MaxSegmentMB   int64  `json:"max_segment_mb"`
		FlushEveryMSec int64  `json:"flush_interval_msec"`
	} `json:"spool"`
	Upload struct {
		BatchMaxEvents int  `json:"batch_max_events"`
		BatchMaxBytes  int  `json:"batch_max_bytes"`
		FlushInterval  int  `json:"flush_interval_sec"`
		Gzip           bool `json:"gzip"`
	} `json:"upload"`
	Actions struct {
		Enabled            bool     `json:"enabled"`
		Allow              []string `json:"allow"`
		PollIntervalSec    int      `json:"poll_interval_sec"`
		ServerPublicKeyB64 string   `json:"server_public_key_b64"`
	} `json:"actions"`
}

func DefaultPath() string {
	if runtime.GOOS == "windows" {
		return filepath.Join(os.Getenv("ProgramData"), "MicroEDR", "agent.yaml")
	}
	return "/etc/microedr/agent.yaml"
}

func Load(path string) (Config, error) {
	if path == "" {
		path = DefaultPath()
	}
	cfg := defaultConfig()
	b, err := os.ReadFile(path)
	if err != nil {
		return Config{}, err
	}
	// v0.1 accepts JSON-formatted config at the YAML path to avoid third-party deps.
	if err := json.Unmarshal(b, &cfg); err != nil {
		return Config{}, err
	}
	if cfg.TenantID == "" || cfg.HostID == "" || cfg.Ingest.URL == "" {
		return Config{}, errors.New("tenant_id, host_id and ingest.url are required")
	}
	return cfg, nil
}

func defaultConfig() Config {
	cfg := Config{}
	cfg.Spool.MaxMB = 2048
	cfg.Spool.MaxSegmentMB = 32
	cfg.Spool.FlushEveryMSec = int64((2 * time.Second).Milliseconds())
	cfg.Upload.BatchMaxEvents = 2000
	cfg.Upload.BatchMaxBytes = 1048576
	cfg.Upload.FlushInterval = 2
	cfg.Upload.Gzip = true
	cfg.Actions.PollIntervalSec = 5
	cfg.Actions.Allow = []string{"kill_process", "isolate_egress"}
	return cfg
}
