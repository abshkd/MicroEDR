package rules

import (
	"strings"

	"microedr/pkg/model"
)

type Rule struct {
	ID        string
	EventType string
	ExeAny    []string
	CmdHasAny []string
}

func Match(ev model.Event, r Rule) bool {
	if ev.EventType != r.EventType {
		return false
	}
	exeMatch := len(r.ExeAny) == 0
	for _, exe := range r.ExeAny {
		if strings.EqualFold(ev.Process.Exe, exe) {
			exeMatch = true
			break
		}
	}
	if !exeMatch {
		return false
	}
	if len(r.CmdHasAny) == 0 {
		return true
	}
	for _, s := range r.CmdHasAny {
		if strings.Contains(ev.Process.Cmdline, s) {
			return true
		}
	}
	return false
}

