//go:build windows

package etw

import (
	"context"
	"time"

	"microedr/pkg/model"
)

// Collector is a Windows-first placeholder for ETW wiring in v0.1.
// It emits health events until full ETW provider subscriptions are added.
type Collector struct {
	hostID string
}

func New(hostID string) *Collector {
	return &Collector{hostID: hostID}
}

func (c *Collector) Run(ctx context.Context, out chan<- model.Event) error {
	t := time.NewTicker(30 * time.Second)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-t.C:
			out <- model.Event{
				SchemaVersion: "1.0",
				EventType:     "integrity.module_load",
				EventID:       newID(),
				TsUnixNano:    time.Now().UnixNano(),
				Host:          model.HostInfo{HostID: c.hostID, OS: "windows"},
				Container:     model.ContainerInfo{Present: false, Runtime: "none"},
				Payload: map[string]any{
					"collector": "windows.etw",
					"status":    "alive",
				},
			}
		}
	}
}

