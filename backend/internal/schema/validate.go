package schema

import (
	"errors"

	"microedr/pkg/model"
)

var allowedEventTypes = map[string]struct{}{
	"proc.exec":            {},
	"net.conn":             {},
	"dns.query":            {},
	"file.write":           {},
	"auth.sudo":            {},
	"container.lifecycle":  {},
	"integrity.module_load": {},
}

func ValidateEvent(ev model.Event) error {
	if ev.SchemaVersion != "1.0" {
		return errors.New("invalid schema_version")
	}
	if _, ok := allowedEventTypes[ev.EventType]; !ok {
		return errors.New("unsupported event_type")
	}
	if ev.EventID == "" || ev.TsUnixNano <= 0 || ev.Host.HostID == "" {
		return errors.New("missing required event fields")
	}
	return nil
}

