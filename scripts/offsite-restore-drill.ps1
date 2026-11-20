param(
    [Parameter(Mandatory=$true)][string]$Bucket,
    [Parameter(Mandatory=$true)][string]$ArchiveKey,
    [Parameter(Mandatory=$true)][string]$RestoreDirectory,
    [string]$Profile = ""
)
$ErrorActionPreference = "Stop"
if ($ArchiveKey -notmatch '^cloudshield/[A-Za-z0-9._/-]+\.zip$' -or $ArchiveKey.Contains("..")) { throw "Invalid archive key." }
if (Test-Path $RestoreDirectory) { throw "Restore directory already exists; choose a new empty path." }
New-Item -ItemType Directory -Force -Path $RestoreDirectory | Out-Null
$archive = Join-Path $RestoreDirectory ([IO.Path]::GetFileName($ArchiveKey))
$manifest = "$archive.manifest.json"
$profileArgs = @()
if ($Profile) { $profileArgs = @("--profile",$Profile) }
$headRaw = & aws @profileArgs s3api head-object --bucket $Bucket --key $ArchiveKey
if ($LASTEXITCODE -ne 0) { throw "Cannot inspect the remote archive object." }
$head = $headRaw | ConvertFrom-Json
if ($head.ServerSideEncryption -ne "aws:kms" -or $head.ObjectLockMode -ne "COMPLIANCE" -or -not $head.ObjectLockRetainUntilDate) { throw "Remote archive is not protected by SSE-KMS and Object Lock COMPLIANCE." }
& aws @profileArgs s3 cp "s3://$Bucket/$ArchiveKey" $archive --only-show-errors
if ($LASTEXITCODE -ne 0) { throw "Archive download failed." }
& aws @profileArgs s3 cp "s3://$Bucket/$ArchiveKey.manifest.json" $manifest --only-show-errors
if ($LASTEXITCODE -ne 0) { throw "Manifest download failed." }
$python = Join-Path $PSScriptRoot "..\.verify-venv\Scripts\python.exe"
if (-not (Test-Path $python)) { $python = "python" }
& $python -m cloudshield.cli verify-workspaces $archive
if ($LASTEXITCODE -ne 0) { throw "Downloaded workspace archive failed verification." }
$restored = Join-Path $RestoreDirectory "restored"
& $python -m cloudshield.cli restore-workspaces $archive --destination $restored
if ($LASTEXITCODE -ne 0) { throw "Workspace restore failed." }
$authDb = Join-Path $restored "auth.sqlite3"
$tenantDir = Join-Path $restored "tenants"
if (-not (Test-Path $authDb -PathType Leaf) -or -not (Test-Path $tenantDir -PathType Container)) { throw "Restored workspace set is missing expected auth or tenant data." }
Write-Host "Offsite restore drill passed. Restored files are isolated at $restored"
Write-Host "This drill did not replace or modify the live CloudShield data volume."
