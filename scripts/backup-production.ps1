param(
    [string]$ComposeFile = "compose.production.yaml",
    [string]$ComposeEnvFile = ".env.production",
    [string]$BackupName = ("cloudshield-workspaces-" + (Get-Date -Format "yyyyMMdd-HHmmss") + ".zip")
)
$ErrorActionPreference = "Stop"
if (-not (Test-Path $ComposeEnvFile -PathType Leaf)) { throw "Private Compose environment file not found: $ComposeEnvFile" }
if ($BackupName -notmatch '^[A-Za-z0-9._-]+\.zip$' -or $BackupName.Contains("..")) { throw "BackupName must be a simple .zip filename." }
$containerPath = "/data/backups/$BackupName"
$hostBackup = Join-Path "backups" $BackupName
$stoppedApp = $false
$stoppedWorker = $false
New-Item -ItemType Directory -Force -Path "backups" | Out-Null
if (Test-Path $hostBackup) { throw "Refusing to overwrite existing backup: $hostBackup" }
if (Test-Path "$hostBackup.manifest.json") { throw "Refusing to overwrite existing manifest: $hostBackup.manifest.json" }
function Invoke-Compose([string[]]$Arguments) {
    & docker compose --env-file $ComposeEnvFile -f $ComposeFile @Arguments
    if ($LASTEXITCODE -ne 0) { throw "Docker Compose command failed: $($Arguments -join ' ')" }
}
try {
    # Stop both writers to establish a consistent point-in-time snapshot of auth and tenant DBs.
    Invoke-Compose @("stop", "cloudshield-worker")
    $stoppedWorker = $true
    Invoke-Compose @("stop", "cloudshield")
    $stoppedApp = $true
    Invoke-Compose @("run", "--rm", "--no-deps", "cloudshield", "python", "-c", "from pathlib import Path; Path('/data/backups').mkdir(parents=True, exist_ok=True)")
    Invoke-Compose @("run", "--rm", "--no-deps", "cloudshield", "python", "-m", "cloudshield.cli", "backup-workspaces", "--auth-database", "/data/auth.sqlite3", "--tenant-directory", "/data/tenants", "--output", $containerPath)
    Invoke-Compose @("run", "--rm", "--no-deps", "cloudshield", "python", "-m", "cloudshield.cli", "verify-workspaces", $containerPath)
    Invoke-Compose @("cp", "cloudshield:$containerPath", $hostBackup)
    Invoke-Compose @("cp", "cloudshield:$($containerPath).manifest.json", "$hostBackup.manifest.json")
    $hash = (Get-FileHash $hostBackup -Algorithm SHA256).Hash
    Write-Host "Verified workspace backup copied to $hostBackup"
    Write-Host "SHA256: $hash"
    Write-Host "Copy the archive and manifest to independent protected storage."
}
finally {
    if ($stoppedApp) { Invoke-Compose @("start", "cloudshield") }
    if ($stoppedWorker) { Invoke-Compose @("start", "cloudshield-worker") }
    if ($stoppedApp -or $stoppedWorker) { Write-Host "Services restarted. Confirm /api/health and /api/health/ready before reopening operations." }
}
