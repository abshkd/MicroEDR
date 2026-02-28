package detection

import (
	"testing"
	"time"

	"microedr/backend/internal/signing"
	"microedr/pkg/model"
)

func TestRansomwareSpikeTriggersKillAction(t *testing.T) {
	s, _, err := signing.NewFromBase64("")
	if err != nil {
		t.Fatalf("new signer: %v", err)
	}
	d := NewRansomwareDetector(Config{
		Window:            10 * time.Second,
		MinWritesInWindow: 5,
		MinDistinctPaths:  3,
		ActionCooldown:    30 * time.Second,
		ActionExpiry:      1 * time.Minute,
	}, s)

	base := time.Now().UnixNano()
	events := []model.Event{
		fileWriteEvent(2001, base+1, `C:\x\a.txt`),
		fileWriteEvent(2001, base+2, `C:\x\b.txt`),
		fileWriteEvent(2001, base+3, `C:\x\c.txt`),
		fileWriteEvent(2001, base+4, `C:\x\d.txt`),
		fileWriteEvent(2001, base+5, `C:\x\e.txt`),
	}
	actions := d.Process("h1", events)
	if len(actions) != 1 {
		t.Fatalf("expected one action, got %d", len(actions))
	}
	a := actions[0]
	if a.Type != "kill_process" {
		t.Fatalf("expected kill_process, got %s", a.Type)
	}
	if a.SignatureBase64 == "" {
		t.Fatal("expected signed action")
	}

	// During cooldown, no extra action should be generated.
	again := d.Process("h1", []model.Event{
		fileWriteEvent(2001, base+6, `C:\x\f.txt`),
		fileWriteEvent(2001, base+7, `C:\x\g.txt`),
	})
	if len(again) != 0 {
		t.Fatalf("expected cooldown suppression, got %d actions", len(again))
	}
}

func fileWriteEvent(pid int32, ts int64, path string) model.Event {
	return model.Event{
		SchemaVersion: "1.0",
		EventType:     "file.write",
		EventID:       "e",
		TsUnixNano:    ts,
		Host:          model.HostInfo{HostID: "h1"},
		Process:       model.ProcessInfo{PID: pid},
		Payload: map[string]any{
			"path": path,
			"op":   "modify",
		},
	}
}
