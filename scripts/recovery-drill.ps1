param(
    [Parameter(Mandatory=$true)][string]$Archive,
    [string]$ComposeFile = "compose.production.yaml",
    [string]$ComposeEnvFile = ".env.production",
    [string]$DrillName = ("recovery-drill-" + (Get-Date -Format "yyyyMMdd-HHmmss"))
)
$ErrorActionPreference = "Stop"
if (-not (Test-Path $ComposeEnvFile -PathType Leaf)) { throw "Private Compose environment file not found: $ComposeEnvFile" }
if (-not (Test-Path $Archive -PathType Leaf)) { throw "Backup archive not found: $Archive" }
$manifest = "$Archive.manifest.json"
if (-not (Test-Path $manifest -PathType Leaf)) { throw "Backup sidecar manifest not found: $manifest" }
if ($DrillName -notmatch '^[A-Za-z0-9._-]+$' -or $DrillName.Contains("..")) { throw "DrillName must be a simple directory name." }
$containerArchive = "/data/recovery-input/" + [IO.Path]::GetFileName($Archive)

function Invoke-Compose([string[]]$Arguments) {
    & docker compose --env-file $ComposeEnvFile -f $ComposeFile @Arguments
    if ($LASTEXITCODE -ne 0) { throw "Docker Compose command failed: $($Arguments -join ' ')" }
}

Invoke-Compose @("exec", "-T", "cloudshield", "python", "-c", "from pathlib import Path; Path('/data/recovery-input').mkdir(parents=True, exist_ok=True); Path('/data/recovery-drill').mkdir(parents=True, exist_ok=True)")
Invoke-Compose @("cp", $Archive, "cloudshield:$containerArchive")
Invoke-Compose @("cp", $manifest, "cloudshield:$($containerArchive).manifest.json")
Invoke-Compose @("exec", "-T", "cloudshield", "python", "-m", "cloudshield.cli", "verify-workspaces", $containerArchive)
Invoke-Compose @("exec", "-T", "cloudshield", "python", "-m", "cloudshield.cli", "restore-workspaces", $containerArchive, "--destination", "/data/recovery-drill/$DrillName")
$check = "import sqlite3; from pathlib import Path; root=Path('/data/recovery-drill/$DrillName'); auth=sqlite3.connect(root/'auth.sqlite3'); users=auth.execute('SELECT COUNT(*) FROM users').fetchone()[0]; auth.close(); tenants=list((root/'tenants').glob('*.sqlite3')); assert users>0 and tenants; checks=[sqlite3.connect(p).execute('PRAGMA integrity_check').fetchone()[0] for p in tenants]; assert all(x=='ok' for x in checks); print('Recovered users:',users,'tenant databases:',len(tenants),'SQLite integrity: ok')"
Invoke-Compose @("exec", "-T", "cloudshield", "python", "-c", $check)
Write-Host "Restore drill completed to /data/recovery-drill/$DrillName."
Write-Host "This is an isolated recovery copy. Do not switch production traffic until application-level sign-off is recorded."
