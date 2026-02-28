@echo off
setlocal

if exist build\events.ndjson del /f /q build\events.ndjson

start "" /b cmd /c "set MICROEDR_INGEST_ADDR=:18080&& set MICROEDR_EVENTS_FILE=D:\microedr\build\events.ndjson&& D:\microedr\build\ingest-api.exe"
timeout /t 2 /nobreak >nul

start "" /b D:\microedr\build\agentd.exe -config D:\microedr\build\agent.test.json
for /L %%i in (1,1,8) do (
  ping -n 2 127.0.0.1
  timeout /t 1 /nobreak >nul
)

taskkill /f /im agentd.exe >nul 2>&1
taskkill /f /im ingest-api.exe >nul 2>&1

if exist build\events.ndjson (
  for %%A in (build\events.ndjson) do @echo events_bytes=%%~zA
) else (
  echo events_bytes=0
)

endlocal
