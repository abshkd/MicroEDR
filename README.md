# MicroEDR (Windows-first v0.1 scaffold)

This repository now contains a Windows-first implementation slice from `plan.md`:

- Agent core with config loading, disk spool segments, and uploader.
- Windows collector entrypoint (`collector/windows/etw`) wired into agent runtime.
- Ingest API with event schema validation and file-backed raw event storage.
- Action API endpoints for request/poll/result flow.
- Tests for schema validation, rule matching, action signature verification, and spool replay/rotation.

## Run ingest API

```powershell
docker compose -f deploy/docker/docker-compose.yml up --build
```

or directly:

```powershell
go run ./backend/cmd/ingest-api
```

## Agent config

Use `deploy/windows-service/agent.windows.sample.json` as a template.

The loader currently accepts JSON content at the expected YAML path (`C:\ProgramData\MicroEDR\agent.yaml`) to keep the project dependency-free in v0.1.

## Run agent

```powershell
go run ./agent/cmd/agentd -config C:\ProgramData\MicroEDR\agent.yaml
```

## Current ETW status

`agent/internal/collectors/windows/etw` is wired and running, but still emits health heartbeat events. Full provider subscriptions for:

- `Microsoft-Windows-Kernel-Process`
- `Microsoft-Windows-Kernel-Network`
- `Microsoft-Windows-DNS-Client`

are the next implementation step.

