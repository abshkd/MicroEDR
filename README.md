# MicroEDR (Windows-first v0.1 scaffold)

This repository now contains a Windows-first implementation slice from `plan.md`:

- Agent core with config loading, disk spool segments, and uploader.
- Windows collector (`collector/windows/etw`) using package-backed ETW sessions for process/network/DNS events.
- Ingest API with event schema validation and file-backed raw event storage.
- Action API endpoints for request/poll/result flow.
- Agent action poller with signature verification and guarded action execution.
- Auto detect-and-act heuristic: file-write spike => signed `kill_process` action.
- Tests for schema validation, rule matching, action signature verification, and spool replay/rotation.

## Run ingest API

```powershell
docker compose -f deploy/docker/docker-compose.yml up --build
```

or directly:

```powershell
go run ./backend/cmd/ingest-api
```

Ingest prints (and exposes) the action signing public key:

- `GET /v1/actions:public_key`

## Agent config

Use `deploy/windows-service/agent.windows.sample.json` as a template.

The loader currently accepts JSON content at the expected YAML path (`C:\ProgramData\MicroEDR\agent.yaml`) to keep the project dependency-free in v0.1.

To enable automated containment, set:

- `actions.enabled=true`
- `actions.server_public_key_b64=<value from /v1/actions:public_key>`

## Run agent

```powershell
go run ./agent/cmd/agentd -config C:\ProgramData\MicroEDR\agent.yaml
```

## Current ETW status

`agent/internal/collectors/windows/etw` now subscribes to ETW providers:

- `Microsoft-Windows-Kernel-Process`
- `Microsoft-Windows-Kernel-Network`
- `Microsoft-Windows-DNS-Client`

If ETW setup fails (provider lookup/permissions), it falls back to process snapshot collection so the agent keeps producing `proc.exec` telemetry.

## Ransomware heuristic

Backend ingest includes a built-in heuristic:

- If a process produces a high spike of `file.write` events with many distinct paths in a short window, ingest queues a signed `kill_process` action for that host.

Tune via env vars:

- `MICROEDR_RANSOM_WINDOW_SEC` (default `20`)
- `MICROEDR_RANSOM_WRITE_THRESHOLD` (default `120`)
- `MICROEDR_RANSOM_UNIQUE_PATH_THRESHOLD` (default `40`)
- `MICROEDR_RANSOM_COOLDOWN_SEC` (default `120`)
