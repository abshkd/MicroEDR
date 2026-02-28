package detection

import (
	"crypto/rand"
	"encoding/hex"
	"time"

	"microedr/backend/internal/signing"
	"microedr/pkg/model"
)

type Config struct {
	Window              time.Duration
	MinWritesInWindow   int
	MinDistinctPaths    int
	ActionCooldown      time.Duration
	ActionExpiry        time.Duration
	DefaultReasonPrefix string
}

type Detector struct {
	cfg    Config
	signer *signing.Signer
	state  map[string]*hostState
}

type hostState struct {
	processes map[int32]*procState
}

type procState struct {
	events         []writeObs
	lastActionUnix int64
}

type writeObs struct {
	ts   int64
	path string
}

func DefaultConfig() Config {
	return Config{
		Window:              20 * time.Second,
		MinWritesInWindow:   120,
		MinDistinctPaths:    40,
		ActionCooldown:      2 * time.Minute,
		ActionExpiry:        3 * time.Minute,
		DefaultReasonPrefix: "heuristic:ransomware_file_write_spike",
	}
}

func NewRansomwareDetector(cfg Config, signer *signing.Signer) *Detector {
	if cfg.Window <= 0 {
		cfg.Window = 20 * time.Second
	}
	if cfg.MinWritesInWindow <= 0 {
		cfg.MinWritesInWindow = 120
	}
	if cfg.MinDistinctPaths <= 0 {
		cfg.MinDistinctPaths = 40
	}
	if cfg.ActionCooldown <= 0 {
		cfg.ActionCooldown = 2 * time.Minute
	}
	if cfg.ActionExpiry <= 0 {
		cfg.ActionExpiry = 3 * time.Minute
	}
	if cfg.DefaultReasonPrefix == "" {
		cfg.DefaultReasonPrefix = "heuristic:ransomware_file_write_spike"
	}
	return &Detector{
		cfg:    cfg,
		signer: signer,
		state:  make(map[string]*hostState, 64),
	}
}

func (d *Detector) Process(hostID string, events []model.Event) []model.Action {
	if hostID == "" || len(events) == 0 {
		return nil
	}
	hs := d.state[hostID]
	if hs == nil {
		hs = &hostState{processes: make(map[int32]*procState, 256)}
		d.state[hostID] = hs
	}

	actions := make([]model.Action, 0, 4)
	for _, ev := range events {
		if ev.EventType != "file.write" {
			continue
		}
		pid := ev.Process.PID
		if pid <= 0 {
			continue
		}
		path, _ := ev.Payload["path"].(string)
		if path == "" {
			continue
		}
		op, _ := ev.Payload["op"].(string)
		if op != "create" && op != "modify" && op != "rename" {
			continue
		}

		ps := hs.processes[pid]
		if ps == nil {
			ps = &procState{events: make([]writeObs, 0, 512)}
			hs.processes[pid] = ps
		}
		ts := ev.TsUnixNano
		if ts <= 0 {
			ts = time.Now().UnixNano()
		}

		ps.events = append(ps.events, writeObs{ts: ts, path: path})
		ps.events = trimWindow(ps.events, ts-int64(d.cfg.Window))
		count, distinct := summarize(ps.events)

		cooldownNs := int64(d.cfg.ActionCooldown)
		if ts-ps.lastActionUnix < cooldownNs {
			continue
		}
		if count < d.cfg.MinWritesInWindow || distinct < d.cfg.MinDistinctPaths {
			continue
		}
		action := model.Action{
			ActionID:      newID(),
			HostID:        hostID,
			TsUnixNano:    ts,
			Type:          "kill_process",
			Params:        map[string]any{"pid": int(pid)},
			Reason:        d.cfg.DefaultReasonPrefix,
			ExpiresTsUnix: ts + int64(d.cfg.ActionExpiry),
		}
		if d.signer != nil {
			if err := d.signer.SignAction(&action); err != nil {
				continue
			}
		}
		ps.lastActionUnix = ts
		actions = append(actions, action)
	}
	return actions
}

func trimWindow(events []writeObs, thresholdTs int64) []writeObs {
	i := 0
	for i < len(events) && events[i].ts < thresholdTs {
		i++
	}
	if i == 0 {
		return events
	}
	out := make([]writeObs, len(events)-i)
	copy(out, events[i:])
	return out
}

func summarize(events []writeObs) (count int, distinct int) {
	if len(events) == 0 {
		return 0, 0
	}
	seen := make(map[string]struct{}, len(events))
	for _, e := range events {
		seen[e.path] = struct{}{}
	}
	return len(events), len(seen)
}

func newID() string {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "00000000000000000000000000000000"
	}
	return hex.EncodeToString(b[:])
}
