Micro-EDR for Servers & Containers (Win + Linux) — Coded Spec v0.1
0) Goals & Non-Goals
Goals

Server-first (cloud VMs + bare metal), container-aware

Collect high-signal telemetry with low overhead

Detect a focused set of behaviors:

suspicious process execution chains

network connections + DNS

file write spikes / suspicious paths

privilege & persistence attempts (best-effort on servers)

container escapes / unexpected host access

Support containment actions (safe, auditable, reversible):

kill process

isolate host (egress block)

quarantine artifact (rename/move + chmod) (Linux only at v0.1)

“Works” without kernel drivers: Linux eBPF, Windows ETW.

Non-Goals (v0.1)

Full AV scanning, kernel-mode Windows driver, full memory forensics

Complex ML. This is rules + heuristics + baselining.

Endpoint UX. Assume servers are headless.

1) High-Level Architecture
[Agent] ──HTTPS/mTLS──> [Ingest API] ──> [Stream/Queue] ──> [Detector] ──> [Alerts]
   │                        │                                │             │
   └── Local spool          └── AuthZ/RBAC                   └── Actions <─┘
           │                                                     │
           └── Health/metrics ────────> [Metrics/Logs] <─────────┘
Components

agentd (daemon/service)

collector-linux-ebpf (BPF programs + userspace reader)

collector-win-etw (ETW sessions + userspace parsing)

uploader (batching, compression, retry, disk spool)

ingest-api (auth, schema validation, rate limiting)

detector (rules + heuristics)

actioner (sends signed action requests to agent)

console (optional; API-first)

2) Repo Layout (monorepo)
microedr/
  agent/
    cmd/agentd/
    internal/
      common/
      spool/
      uploader/
      config/
      actions/
      collectors/
        linux/
          ebpf/
          userspace/
        windows/
          etw/
  backend/
    cmd/ingest-api/
    cmd/detector/
    cmd/actioner/
    internal/
      auth/
      schema/
      storage/
      rules/
      correlation/
      api/
  proto/
    microedr.proto
  rules/
    sigma-lite/
    builtin/
  deploy/
    docker/
    systemd/
    windows-service/

Languages:

Agent: Go (good services, cross-platform)

Linux eBPF: C + libbpf (or bpf2go)

Windows ETW collector: Go calling Windows APIs or C# sidecar (either is fine; spec assumes Go)

3) Data Model
3.1 Event Envelope (common)

All telemetry uses one envelope.

{
  "schema_version": "1.0",
  "event_type": "proc.exec|net.conn|dns.query|file.write|auth.sudo|container.lifecycle|integrity.module_load",
  "event_id": "uuid",
  "ts_unix_nano": 0,
  "host": {
    "host_id": "stable-guid",
    "hostname": "string",
    "os": "linux|windows",
    "os_version": "string",
    "kernel_version": "string",
    "cloud": { "provider": "aws|gcp|azure|none", "instance_id": "string", "region": "string" }
  },
  "agent": { "version": "string", "build": "string" },
  "container": {
    "present": true,
    "runtime": "docker|containerd|none",
    "container_id": "string",
    "pod": "string",
    "namespace": "string",
    "cgroup_id": "string"
  },
  "process": {
    "pid": 123,
    "ppid": 1,
    "start_ts_unix_nano": 0,
    "exe": "/usr/bin/curl",
    "cmdline": "curl http://...",
    "cwd": "/",
    "user": "root",
    "uid": 0,
    "gid": 0,
    "euid": 0,
    "hash": { "sha256": "..." },
    "signing": { "trusted": false, "publisher": "string" }   // best effort
  },
  "payload": { }
}
3.2 Event Types (minimum v0.1)
proc.exec

payload:

{
  "argv": ["curl","http://..."],
  "env_keys": ["PATH","HOME"],
  "parent_exe": "/bin/bash",
  "tty": "pts/0",
  "session_id": "string"
}
net.conn

payload:

{
  "proto": "tcp|udp",
  "direction": "egress|ingress",
  "src_ip": "ip",
  "src_port": 12345,
  "dst_ip": "ip",
  "dst_port": 443,
  "dst_domain": "optional",
  "bytes_out": 0,
  "bytes_in": 0
}
dns.query

payload:

{ "qname": "string", "qtype": "A|AAAA|TXT|...", "rcode": "NOERROR|NXDOMAIN|..." }
file.write

payload:

{
  "path": "/etc/cron.d/evil",
  "op": "create|modify|rename",
  "bytes_written": 1234,
  "mode": "octal",
  "inode": 0
}
container.lifecycle (Linux only v0.1)

payload:

{
  "action": "start|stop|exec",
  "image": "repo:tag",
  "labels": { "k": "v" }
}
4) Linux Implementation Spec (eBPF-first)
4.1 Telemetry sources

eBPF tracepoints/kprobes:

sched_process_exec → proc.exec

tcp_connect / inet_csk_accept (or sock tracepoints) → net.conn

file write: tracepoints on vfs_write / LSM hooks if available (fallback to tracepoints)

Container identity mapping:

Map pid → cgroup_id via BPF helper + userspace cache

Resolve cgroup_id → container_id/pod/ns by reading:

/proc/<pid>/cgroup

containerd/docker metadata sockets (best-effort)

DNS:

Option A: capture UDP/53 connects + parse in userspace from socket buffers (hard)

Option B (v0.1 recommended): read /var/log/syslog / systemd-resolved logs OR hook libc resolver via uprobes (later)

For v0.1: implement net.conn; DNS is optional.

4.2 BPF program constraints

Must be bounded, no loops unless verifier-safe

Emit fixed-size structs to a perf/ring buffer

Example structs (C):

struct exec_event {
  u64 ts;
  u32 pid;
  u32 ppid;
  u64 cgroup_id;
  char filename[256];
  char comm[16];
};

struct net_event {
  u64 ts;
  u32 pid;
  u64 cgroup_id;
  u8 proto;       // 6 tcp, 17 udp
  u8 direction;   // 0 egress, 1 ingress
  u32 saddr_v4;
  u32 daddr_v4;
  u16 sport;
  u16 dport;
};
4.3 Userspace reader

Reads ring buffer, enriches:

cmdline from /proc/<pid>/cmdline

exe path /proc/<pid>/exe

user/uid from /proc/<pid>/status

sha256 (async hashing worker; cache by inode+mtime)

Produces envelope JSON (or protobuf) into local spool

5) Windows Implementation Spec (ETW-first)
5.1 Telemetry sources

Use ETW providers:

Process:

Microsoft-Windows-Kernel-Process (process start)

Network:

Microsoft-Windows-Kernel-Network (TCP/IP connect)

DNS:

Microsoft-Windows-DNS-Client (query)

Optional later:

Sysmon support if installed (but don’t require)

5.2 Collection mechanics

Start ETW trace session(s) with admin privileges

Parse event payloads into the same envelope schema

Hash executable (async, cache)

Container mapping:

Windows containers exist but messy; v0.1: set container.present=false

If WSL2 present, treat as Linux host signals (future)

6) Agent Core (Cross-platform)
6.1 Config

/etc/microedr/agent.yaml (Linux) / C:\ProgramData\MicroEDR\agent.yaml (Win)

tenant_id: "t-123"
host_id: "stable-guid"
ingest:
  url: "https://ingest.example.com/v1/events"
  mTLS:
    cert_file: "..."
    key_file: "..."
    ca_file: "..."
spool:
  dir: "/var/lib/microedr/spool"
  max_mb: 2048
upload:
  batch_max_events: 2000
  batch_max_bytes: 1048576
  flush_interval_sec: 2
  gzip: true
collectors:
  linux:
    ebpf: true
  windows:
    etw: true
actions:
  enabled: true
  allow:
    - "kill_process"
    - "isolate_egress"
6.2 Spool format

Append-only segment files:

segment-000001.events.gz containing newline-delimited JSON OR protobuf frames

Index file for offsets (optional)

On successful upload ACK, delete segments

6.3 Uploader protocol

POST /v1/events:batch

Body: { "tenant_id":"...", "host_id":"...", "events":[...], "seq":123 }

Response: { "accepted": N, "rejected": M, "next_seq": 124 }

Auth:

mTLS + tenant cert mapping server-side

7) Backend APIs (Minimum)
7.1 Ingest API

Endpoints:

POST /v1/events:batch

GET /v1/health

POST /v1/actions:request (internal, from actioner only)

POST /v1/actions:result (agent posts result)

Validation:

enforce schema_version, event_type whitelist

size limits, rate limits per host_id

Storage (v0.1):

Write raw events to object storage OR time-series DB (ClickHouse is ideal, but you can start with Postgres+partitioning)

Alerts stored in Postgres

7.2 Action protocol

Action request (server → agent via polling or push; v0.1 polling):

Agent polls GET /v1/actions:poll?host_id=...&since=...

Server returns list of signed actions

Action object:

{
  "action_id": "uuid",
  "host_id": "h-123",
  "ts_unix_nano": 0,
  "type": "kill_process|isolate_egress",
  "params": { "pid": 123 },
  "reason": "alert:a-987",
  "expires_ts_unix_nano": 0,
  "signature": "ed25519..."
}

Agent must:

verify signature against pinned server key

execute with guardrails

POST /v1/actions:result

8) Detection Engine (Micro, high-signal)
8.1 Rule format (“sigma-lite”)

YAML rules with simple matching + thresholds.

Example:

id: R1001
name: Suspicious curl|wget to IP with bash
match:
  event_type: proc.exec
  any:
    - process.exe: "/usr/bin/curl"
    - process.exe: "/usr/bin/wget"
  contains:
    process.cmdline:
      - "| bash"
      - "| sh"
severity: high
actions:
  - type: kill_process
    when: auto_if_confidence_gte
    value: 0.90
8.2 Heuristics (built-in v0.1)

LOLBins on servers (Linux):

curl|wget|python|perl|bash -c with remote fetch + pipe

Suspicious outbound

new process making first-time egress to rare ASN / direct IP (no domain)

Write spike

a single process writing to many files rapidly (possible encryption / tampering)

Persistence

writes to /etc/cron.*, /etc/systemd/system, ~/.ssh/authorized_keys

Container escape indicators (best-effort)

container process touching /proc/1/root, /var/run/docker.sock, /run/containerd/containerd.sock

privileged container with host mounts writing to host paths

8.3 Correlation window

Keep 5–15 minutes in memory per host for:

process tree edges

recent net destinations

write counters

Alert schema:

{
  "alert_id": "uuid",
  "ts_unix_nano": 0,
  "host_id": "h-123",
  "rule_id": "R1001",
  "severity": "medium|high|critical",
  "confidence": 0.0,
  "title": "string",
  "summary": "string",
  "entities": {
    "pid": 123,
    "exe": "...",
    "dst_ip": "...",
    "container_id": "..."
  },
  "evidence_event_ids": ["..."]
}
9) Containment Actions (Safe Defaults)
9.1 kill_process

Linux: kill(SIGKILL) target pid

Windows: TerminateProcess
Guardrails:

never kill PID 1 (Linux) / system critical processes list (Windows)

allowlist processes by path/publisher/config

9.2 isolate_egress

Linux: add iptables/nftables rule blocking outbound except to ingest URL + DNS if needed

Windows: add Windows Firewall outbound block, allow ingest
Guardrails:

time-bound isolation (auto-revert after N minutes unless renewed)

always keep a management escape hatch list (config)

10) Security Requirements

mTLS everywhere; host_id bound to cert

Signed actions (ed25519) + pinned server public key on agent

Tamper-evident local spool (optional v0.1): hash chain per segment

No shelling out for actions (avoid command injection footguns)

Strict parsing, strict timeouts

11) Performance & Reliability Targets (v0.1)

CPU overhead:

Linux eBPF: < 2% average on typical server

Windows ETW: < 2% average

Memory: < 150MB agent

Disk spool: configurable, default 2GB

Offline tolerance: at least 24h spooling under moderate event volume

Backpressure: drop lowest-value events first (e.g., net.conn summaries) but never drop proc.exec

12) Test Plan (Codex should implement)
Unit tests

schema validation

rule matching

action signature verification

spool segment rotation and replay

Integration tests (dockerized)

Linux: spawn processes, generate net connects, verify events ingested

Windows: ETW session sanity + sample events

Load tests

5k events/sec on backend ingest (single node baseline)

Implementation Milestones (practical order)

Backend ingest + storage (accept events, store raw)

Agent core + spool + uploader (no collectors yet)

Linux proc.exec via eBPF + enrichment

Windows proc start via ETW + enrichment

net.conn collectors (both)

Detector with 5–10 rules + alert storage

Actioner + kill_process

Isolate egress

Container identity mapping & container escape rules (Linux)

What I need from you (no long back-and-forth)

Pick these defaults and I’ll tighten this into a v0.1 “build contract” Codex can execute directly:

Backend storage: ClickHouse or Postgres (ClickHouse is better for events)

Runtime: Docker compose for backend? (yes/no)

Cloud target: bare metal only or AWS/GCP/Azure too (for host_id + metadata)