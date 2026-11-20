param(
    [Parameter(Mandatory=$true)][string]$ArchivePath,
    [Parameter(Mandatory=$true)][string]$Bucket,
    [Parameter(Mandatory=$true)][string]$KmsKeyArn,
    [string]$Prefix = "cloudshield/",
    [string]$Profile = ""
)
$ErrorActionPreference = "Stop"
$manifestPath = "$ArchivePath.manifest.json"
foreach ($file in @($ArchivePath,$manifestPath)) { if (-not (Test-Path $file -PathType Leaf)) { throw "Missing verified backup file: $file" } }
if ($Bucket -notmatch '^[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]$' -or $Prefix -notmatch '^cloudshield/[A-Za-z0-9._/-]*$' -or $Prefix.Contains("..")) { throw "Invalid bucket or backup prefix." }
if ($KmsKeyArn -notmatch '^arn:aws(-[a-z]+)?:kms:[a-z0-9-]+:[0-9]{12}:key/[A-Fa-f0-9-]+$') { throw "Provide a valid AWS KMS key ARN." }
$python = Join-Path $PSScriptRoot "..\.verify-venv\Scripts\python.exe"
if (-not (Test-Path $python)) { $python = "python" }
& $python -m cloudshield.cli verify-workspaces $ArchivePath
if ($LASTEXITCODE -ne 0) { throw "Local workspace backup verification failed." }
$stamp = (Get-Date).ToUniversalTime().ToString("yyyyMMddTHHmmssfffZ")
$archiveKey = "$Prefix$stamp/$([IO.Path]::GetFileName($ArchivePath))"
$manifestKey = "$archiveKey.manifest.json"
$profileArgs = @()
if ($Profile) { $profileArgs = @("--profile",$Profile) }
& aws @profileArgs s3 cp $ArchivePath "s3://$Bucket/$archiveKey" --sse aws:kms --sse-kms-key-id $KmsKeyArn --only-show-errors
if ($LASTEXITCODE -ne 0) { throw "S3 archive upload failed." }
& aws @profileArgs s3 cp $manifestPath "s3://$Bucket/$manifestKey" --sse aws:kms --sse-kms-key-id $KmsKeyArn --only-show-errors
if ($LASTEXITCODE -ne 0) { throw "S3 manifest upload failed." }
foreach ($key in @($archiveKey,$manifestKey)) {
    $raw = & aws @profileArgs s3api head-object --bucket $Bucket --key $key
    if ($LASTEXITCODE -ne 0) { throw "Cannot verify uploaded object: $key" }
    $head = $raw | ConvertFrom-Json
    if ($head.ServerSideEncryption -ne "aws:kms") { throw "Uploaded object is not SSE-KMS encrypted: $key" }
    if ($head.ObjectLockMode -ne "COMPLIANCE" -or -not $head.ObjectLockRetainUntilDate) { throw "Object Lock COMPLIANCE retention is not active: $key" }
}
Write-Host "Offsite archive and manifest uploaded and verified."
Write-Host "s3://$Bucket/$archiveKey"
Write-Host "Retention is governed by the bucket's COMPLIANCE Object Lock policy."
