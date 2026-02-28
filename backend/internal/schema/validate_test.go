package schema

import (
	"testing"
	"time"

	"microedr/pkg/model"
)

func TestValidateEvent(t *testing.T) {
	ev := model.Event{
		SchemaVersion: "1.0",
		EventType:     "proc.exec",
		EventID:       "e1",
		TsUnixNano:    time.Now().UnixNano(),
		Host:          model.HostInfo{HostID: "h1"},
	}
	if err := ValidateEvent(ev); err != nil {
		t.Fatalf("expected valid event, got: %v", err)
	}
	ev.EventType = "bad.type"
	if err := ValidateEvent(ev); err == nil {
		t.Fatal("expected invalid event_type")
	}
}

