$ErrorActionPreference = "Stop"

$env:MICROEDR_INGEST_ADDR = ":18081"
$env:MICROEDR_EVENTS_FILE = "D:\microedr\build\events.detect.ndjson"
$env:MICROEDR_RANSOM_WRITE_THRESHOLD = "5"
$env:MICROEDR_RANSOM_UNIQUE_PATH_THRESHOLD = "3"
$env:MICROEDR_RANSOM_WINDOW_SEC = "30"

Get-Process ingest-api -ErrorAction SilentlyContinue | Stop-Process -Force

if (Test-Path "D:\microedr\build\events.detect.ndjson") {
  Remove-Item "D:\microedr\build\events.detect.ndjson" -Force
}

$p = Start-Process -FilePath "D:\microedr\build\ingest-api.exe" -PassThru
Start-Sleep -Seconds 2

$pub = (Invoke-RestMethod -Uri "http://127.0.0.1:18081/v1/actions:public_key").public_key_base64

$events = @()
for ($i = 1; $i -le 6; $i++) {
  $events += @{
    schema_version = "1.0"
    event_type = "file.write"
    event_id = "e$i"
    ts_unix_nano = [DateTimeOffset]::UtcNow.ToUnixTimeMilliseconds() * 1000000 + $i
    host = @{
      host_id = "h-test"
      hostname = "vm"
      os = "windows"
      os_version = ""
      kernel_version = ""
      cloud = @{ provider = "none"; instance_id = ""; region = "" }
    }
    agent = @{ version = "0.1.0"; build = "dev" }
    container = @{ present = $false; runtime = "none"; container_id = ""; pod = ""; namespace = ""; cgroup_id = "" }
    process = @{
      pid = 4321
      ppid = 1
      start_ts_unix_nano = 0
      exe = "C:\evil.exe"
      cmdline = "evil"
      cwd = ""
      user = ""
      uid = 0
      gid = 0
      euid = 0
      hash = @{ sha256 = "" }
      signing = @{ trusted = $false; publisher = "" }
    }
    payload = @{
      path = "C:\data\f$i.txt"
      op = "modify"
      bytes_written = 1000
      mode = ""
      inode = 0
    }
  }
}

$body = @{
  tenant_id = "t-test"
  host_id = "h-test"
  seq = 1
  events = $events
} | ConvertTo-Json -Depth 8

Invoke-RestMethod -Method Post -Uri "http://127.0.0.1:18081/v1/events:batch" -ContentType "application/json" -Body $body | Out-Null
$poll = Invoke-RestMethod -Uri "http://127.0.0.1:18081/v1/actions:poll?host_id=h-test"

Write-Output ("actions_count=" + $poll.actions.Count)
if ($poll.actions.Count -gt 0) {
  Write-Output ("action_type=" + $poll.actions[0].type)
  Write-Output ("signature_present=" + [bool]$poll.actions[0].signature)
}
Write-Output ("public_key_base64_len=" + $pub.Length)

Stop-Process -Id $p.Id -Force
