//go:build windows

package etw

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"

	goetw "github.com/secDre4mer/etw"
	ps "github.com/shirou/gopsutil/v3/process"
	"golang.org/x/sys/windows"

	"microedr/pkg/model"
)

type Collector struct {
	hostID   string
	hostname string
	hasher   *hashCache
}

type hashEntry struct {
	modUnix int64
	size    int64
	sum     string
}

type hashCache struct {
	mu    sync.Mutex
	byExe map[string]hashEntry
}

func New(hostID string) *Collector {
	hostname, _ := os.Hostname()
	return &Collector{
		hostID:   hostID,
		hostname: hostname,
		hasher: &hashCache{
			byExe: make(map[string]hashEntry, 1024),
		},
	}
}

func (c *Collector) Run(ctx context.Context, out chan<- model.Event) error {
	// ETW-first. If ETW cannot initialize (permissions/provider issues), keep
	// collecting with snapshot fallback for resilience.
	if err := c.runETW(ctx, out); err == nil {
		return nil
	}
	return c.runSnapshot(ctx, out)
}

func (c *Collector) runETW(ctx context.Context, out chan<- model.Event) error {
	session, err := goetw.NewSession(goetw.WithName("microedr-" + newID()[:8]))
	if err != nil {
		return err
	}

	providers := []struct {
		name string
		kind string
	}{
		{name: "Microsoft-Windows-Kernel-Process", kind: "proc"},
		{name: "Microsoft-Windows-Kernel-Network", kind: "net"},
		{name: "Microsoft-Windows-DNS-Client", kind: "dns"},
		{name: "Microsoft-Windows-Kernel-File", kind: "file"},
	}

	kindByProvider := make(map[string]string, len(providers))
	for _, p := range providers {
		provider, err := goetw.LookupProvider(p.name)
		if err != nil {
			continue
		}
		opts := []goetw.ProviderOption{goetw.WithLevel(goetw.TRACE_LEVEL_VERBOSE)}
		if p.kind == "dns" {
			// DNS query request event.
			opts = append(opts, goetw.WithFilter(goetw.EventIdFilter{
				EventIds:       []uint16{3006},
				PositiveFilter: true,
			}))
		}
		if err := session.AddProvider(provider.Guid, opts...); err != nil {
			continue
		}
		kindByProvider[guidKey(provider.Guid)] = p.kind
	}
	if len(kindByProvider) == 0 {
		_ = session.Close()
		return errors.New("no ETW providers attached")
	}

	errCh := make(chan error, 1)
	go func() {
		errCh <- session.Process(func(e *goetw.Event) {
			props, err := e.EventProperties()
			if err != nil {
				return
			}
			kind := kindByProvider[guidKey(e.Header.ProviderID)]
			var (
				ev model.Event
				ok bool
			)
			switch kind {
			case "proc":
				ev, ok = c.fromETWProcess(e, props)
			case "net":
				ev, ok = c.fromETWNetwork(e, props)
			case "dns":
				ev, ok = c.fromETWDNS(e, props)
			case "file":
				ev, ok = c.fromETWFile(e, props)
			default:
				return
			}
			if !ok {
				return
			}
			select {
			case out <- ev:
			default:
				// Drop on backpressure for lower value ETW events.
			}
		})
	}()

	select {
	case <-ctx.Done():
		_ = session.Close()
		err := <-errCh
		if err != nil && !errors.Is(err, windows.ERROR_CANCELLED) {
			return err
		}
		return nil
	case err := <-errCh:
		if err != nil && !errors.Is(err, windows.ERROR_CANCELLED) {
			return err
		}
		return nil
	}
}

func (c *Collector) fromETWProcess(e *goetw.Event, props map[string]interface{}) (model.Event, bool) {
	pid := firstInt32(props, "ProcessID", "ProcessId", "PID")
	if pid == 0 {
		pid = int32(e.Header.ProcessID)
	}
	if pid == 0 {
		return model.Event{}, false
	}

	ppid := firstInt32(props, "ParentProcessID", "ParentProcessId", "ParentID", "ParentId")
	exe := firstString(props, "ImageName", "ImageFileName", "ImagePathName", "ProcessName")
	cmdline := firstString(props, "CommandLine", "CmdLine")

	// Skip clear process-stop style records where no executable context exists.
	if exe == "" && cmdline == "" && ppid == 0 {
		return model.Event{}, false
	}

	parentExe := ""
	if ppid > 0 {
		if p, err := ps.NewProcess(int32(ppid)); err == nil {
			parentExe, _ = p.Exe()
		}
	}
	user := sidFromEvent(e)

	ev := c.baseEvent("proc.exec", e.Header.TimeStamp.UnixNano())
	ev.Process = model.ProcessInfo{
		PID:             pid,
		PPID:            ppid,
		StartTsUnixNano: e.Header.TimeStamp.UnixNano(),
		Exe:             exe,
		Cmdline:         cmdline,
		User:            user,
		Hash:            model.HashInfo{SHA256: c.hashExe(exe)},
		Signing:         model.SigningInfo{Trusted: false},
	}
	ev.Payload = map[string]any{
		"argv":         splitArgv(cmdline),
		"parent_exe":   parentExe,
		"etw_event_id": e.Header.ID,
		"source":       "windows.etw.kernel_process",
	}
	return ev, true
}

func (c *Collector) fromETWNetwork(e *goetw.Event, props map[string]interface{}) (model.Event, bool) {
	dstIP := firstString(props, "daddr", "DestAddress", "DestinationAddress", "RemoteAddress", "dIP")
	srcIP := firstString(props, "saddr", "SourceAddress", "LocalAddress", "sIP")
	dstPort := firstInt(props, "dport", "DestPort", "DestinationPort", "RemotePort")
	srcPort := firstInt(props, "sport", "SourcePort", "LocalPort")
	if dstIP == "" && dstPort == 0 {
		return model.Event{}, false
	}

	pid := firstInt32(props, "ProcessID", "ProcessId", "PID")
	if pid == 0 {
		pid = int32(e.Header.ProcessID)
	}
	exe := ""
	cmdline := ""
	if pid > 0 {
		if p, err := ps.NewProcess(pid); err == nil {
			exe, _ = p.Exe()
			cmdline, _ = p.Cmdline()
		}
	}

	ev := c.baseEvent("net.conn", e.Header.TimeStamp.UnixNano())
	ev.Process = model.ProcessInfo{
		PID:     pid,
		Exe:     exe,
		Cmdline: cmdline,
	}
	ev.Payload = map[string]any{
		"proto":        normalizeProto(firstString(props, "Protocol", "proto")),
		"direction":    "egress",
		"src_ip":       srcIP,
		"src_port":     srcPort,
		"dst_ip":       dstIP,
		"dst_port":     dstPort,
		"bytes_out":    firstInt(props, "size", "send_size", "BytesSent"),
		"bytes_in":     firstInt(props, "recv_size", "BytesReceived"),
		"etw_event_id": e.Header.ID,
		"source":       "windows.etw.kernel_network",
	}
	return ev, true
}

func (c *Collector) fromETWDNS(e *goetw.Event, props map[string]interface{}) (model.Event, bool) {
	qname := firstString(props, "QueryName", "Query", "Name")
	if qname == "" {
		return model.Event{}, false
	}
	pid := firstInt32(props, "ProcessId", "ProcessID", "PID")
	if pid == 0 {
		pid = int32(e.Header.ProcessID)
	}

	ev := c.baseEvent("dns.query", e.Header.TimeStamp.UnixNano())
	ev.Process = model.ProcessInfo{PID: pid}
	ev.Payload = map[string]any{
		"qname":        qname,
		"qtype":        normalizeQType(firstString(props, "QueryType", "Type")),
		"rcode":        normalizeRCode(firstString(props, "Status", "QueryStatus", "Result")),
		"etw_event_id": e.Header.ID,
		"source":       "windows.etw.dns_client",
	}
	return ev, true
}

func (c *Collector) fromETWFile(e *goetw.Event, props map[string]interface{}) (model.Event, bool) {
	path := firstString(props, "FileName", "FilePath", "Path", "OpenPath", "File")
	if path == "" {
		return model.Event{}, false
	}
	op := inferFileOp(e, props)
	if op == "" {
		return model.Event{}, false
	}

	pid := firstInt32(props, "ProcessID", "ProcessId", "PID")
	if pid == 0 {
		pid = int32(e.Header.ProcessID)
	}
	if pid == 0 {
		return model.Event{}, false
	}

	exe := ""
	cmdline := ""
	if p, err := ps.NewProcess(pid); err == nil {
		exe, _ = p.Exe()
		cmdline, _ = p.Cmdline()
	}

	ev := c.baseEvent("file.write", e.Header.TimeStamp.UnixNano())
	ev.Process = model.ProcessInfo{
		PID:     pid,
		Exe:     exe,
		Cmdline: cmdline,
	}
	ev.Payload = map[string]any{
		"path":          path,
		"op":            op,
		"bytes_written": firstInt(props, "IoSize", "TransferSize", "WriteSize", "Size", "Length"),
		"mode":          "",
		"inode":         0,
		"etw_event_id":  e.Header.ID,
		"source":        "windows.etw.kernel_file",
	}
	return ev, true
}

func (c *Collector) runSnapshot(ctx context.Context, out chan<- model.Event) error {
	seen := make(map[int32]int64, 2048)
	_ = c.scanSnapshot(seen, nil)

	t := time.NewTicker(2 * time.Second)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-t.C:
			_ = c.scanSnapshot(seen, out)
		}
	}
}

func (c *Collector) scanSnapshot(seen map[int32]int64, out chan<- model.Event) error {
	procs, err := ps.Processes()
	if err != nil {
		return err
	}
	current := make(map[int32]int64, len(procs))
	for _, p := range procs {
		startMs, err := p.CreateTime()
		if err != nil {
			continue
		}
		pid := int32(p.Pid)
		current[pid] = startMs
		if prev, ok := seen[pid]; ok && prev == startMs {
			continue
		}
		seen[pid] = startMs
		if out == nil {
			continue
		}
		ev, ok := c.fromSnapshotProcess(p, startMs)
		if !ok {
			continue
		}
		select {
		case out <- ev:
		default:
		}
	}
	for pid := range seen {
		if _, ok := current[pid]; !ok {
			delete(seen, pid)
		}
	}
	return nil
}

func (c *Collector) fromSnapshotProcess(p *ps.Process, startMs int64) (model.Event, bool) {
	ppid64, err := p.Ppid()
	if err != nil {
		return model.Event{}, false
	}
	exe, _ := p.Exe()
	cmdline, _ := p.Cmdline()
	user, _ := p.Username()

	parentExe := ""
	if ppid64 > 0 {
		if parent, err := ps.NewProcess(ppid64); err == nil {
			parentExe, _ = parent.Exe()
		}
	}

	startNano := time.UnixMilli(startMs).UnixNano()
	ev := c.baseEvent("proc.exec", time.Now().UnixNano())
	ev.Process = model.ProcessInfo{
		PID:             int32(p.Pid),
		PPID:            int32(ppid64),
		StartTsUnixNano: startNano,
		Exe:             exe,
		Cmdline:         cmdline,
		User:            user,
		Hash:            model.HashInfo{SHA256: c.hashExe(exe)},
		Signing:         model.SigningInfo{Trusted: false},
	}
	ev.Payload = map[string]any{
		"argv":       splitArgv(cmdline),
		"parent_exe": parentExe,
		"source":     "windows.process_snapshot",
	}
	return ev, true
}

func (c *Collector) baseEvent(eventType string, ts int64) model.Event {
	return model.Event{
		SchemaVersion: "1.0",
		EventType:     eventType,
		EventID:       newID(),
		TsUnixNano:    ts,
		Host: model.HostInfo{
			HostID:        c.hostID,
			Hostname:      c.hostname,
			OS:            "windows",
			OSVersion:     runtime.GOOS,
			KernelVersion: runtime.GOARCH,
			Cloud:         model.CloudInfo{Provider: "none"},
		},
		Agent: model.AgentInfo{
			Version: "0.1.0",
			Build:   "dev",
		},
		Container: model.ContainerInfo{
			Present: false,
			Runtime: "none",
		},
		Payload: map[string]any{},
	}
}

func sidFromEvent(e *goetw.Event) string {
	ext := e.ExtendedInfo()
	if ext.UserSID == nil {
		return ""
	}
	return ext.UserSID.String()
}

func splitArgv(cmdline string) []string {
	if cmdline == "" {
		return nil
	}
	return strings.Fields(cmdline)
}

func (c *Collector) hashExe(path string) string {
	if path == "" {
		return ""
	}
	fi, err := os.Stat(path)
	if err != nil {
		return ""
	}
	modUnix := fi.ModTime().UnixNano()
	size := fi.Size()

	c.hasher.mu.Lock()
	if entry, ok := c.hasher.byExe[path]; ok && entry.modUnix == modUnix && entry.size == size {
		c.hasher.mu.Unlock()
		return entry.sum
	}
	c.hasher.mu.Unlock()

	f, err := os.Open(path)
	if err != nil {
		return ""
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return ""
	}
	sum := hex.EncodeToString(h.Sum(nil))

	c.hasher.mu.Lock()
	c.hasher.byExe[path] = hashEntry{modUnix: modUnix, size: size, sum: sum}
	c.hasher.mu.Unlock()
	return sum
}

func firstString(props map[string]interface{}, keys ...string) string {
	for _, k := range keys {
		for pk, pv := range props {
			if strings.EqualFold(pk, k) {
				switch v := pv.(type) {
				case string:
					return strings.TrimSpace(v)
				case []string:
					if len(v) > 0 {
						return strings.TrimSpace(v[0])
					}
				default:
					return strings.TrimSpace(strings.TrimPrefix(strings.TrimSuffix(strings.TrimSpace(toString(v)), ","), ","))
				}
			}
		}
	}
	return ""
}

func firstInt(props map[string]interface{}, keys ...string) int {
	for _, k := range keys {
		for pk, pv := range props {
			if strings.EqualFold(pk, k) {
				if n, ok := toInt(pv); ok {
					return n
				}
			}
		}
	}
	return 0
}

func firstInt32(props map[string]interface{}, keys ...string) int32 {
	return int32(firstInt(props, keys...))
}

func toString(v interface{}) string {
	switch t := v.(type) {
	case string:
		return t
	case []string:
		if len(t) == 0 {
			return ""
		}
		return t[0]
	default:
		return fmt.Sprint(v)
	}
}

func toInt(v interface{}) (int, bool) {
	switch t := v.(type) {
	case int:
		return t, true
	case int32:
		return int(t), true
	case int64:
		return int(t), true
	case uint16:
		return int(t), true
	case uint32:
		return int(t), true
	case uint64:
		return int(t), true
	case float64:
		return int(t), true
	case string:
		s := strings.TrimSpace(t)
		s = strings.TrimSuffix(s, ",")
		if s == "" {
			return 0, false
		}
		if strings.HasPrefix(strings.ToLower(s), "0x") {
			n, err := strconv.ParseInt(s[2:], 16, 64)
			if err != nil {
				return 0, false
			}
			return int(n), true
		}
		n, err := strconv.ParseInt(s, 10, 64)
		if err != nil {
			return 0, false
		}
		return int(n), true
	default:
		return 0, false
	}
}

func normalizeProto(v string) string {
	switch strings.TrimSpace(strings.ToLower(v)) {
	case "6", "tcp":
		return "tcp"
	case "17", "udp":
		return "udp"
	default:
		if v == "" {
			return "tcp"
		}
		return strings.ToLower(v)
	}
}

func normalizeQType(v string) string {
	switch strings.TrimSpace(strings.ToUpper(v)) {
	case "1", "A":
		return "A"
	case "28", "AAAA":
		return "AAAA"
	case "16", "TXT":
		return "TXT"
	case "":
		return "A"
	default:
		return strings.ToUpper(strings.TrimSpace(v))
	}
}

func normalizeRCode(v string) string {
	s := strings.TrimSpace(strings.ToUpper(v))
	switch s {
	case "", "0", "SUCCESS":
		return "NOERROR"
	case "9003":
		return "NXDOMAIN"
	default:
		return s
	}
}

func inferFileOp(e *goetw.Event, props map[string]interface{}) string {
	operation := strings.ToLower(firstString(props, "Operation", "OpcodeName", "TaskName", "Irp"))
	infoClass := strings.ToLower(firstString(props, "FileInfoClass", "InfoClass"))

	switch {
	case strings.Contains(operation, "rename"), strings.Contains(infoClass, "rename"):
		return "rename"
	case strings.Contains(operation, "create"), strings.Contains(operation, "new"):
		return "create"
	case strings.Contains(operation, "write"), strings.Contains(operation, "setinfo"), strings.Contains(operation, "set information"):
		return "modify"
	}

	// Common kernel file event ids (best-effort mapping).
	switch e.Header.ID {
	case 12:
		return "create"
	case 16, 17:
		return "modify"
	case 26:
		return "rename"
	default:
		return ""
	}
}

func guidKey(g windows.GUID) string {
	return strings.ToLower(g.String())
}
