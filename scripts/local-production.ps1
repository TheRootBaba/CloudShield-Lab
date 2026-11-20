[CmdletBinding()]
param(
    [Parameter(ValueFromRemainingArguments = $true)]
    [string[]]$ComposeArgs
)

$ErrorActionPreference = "Stop"
$repo = Split-Path -Parent $PSScriptRoot
$envFile = Join-Path $repo ".env.production.local"
$composeFile = Join-Path $repo "compose.production.yaml"
$privateDir = Join-Path $env:USERPROFILE ".config\cloudshield"
$overrideFile = Join-Path $privateDir "compose.loopback.override.yaml"

if (-not (Test-Path -LiteralPath $envFile)) {
    throw "Missing .env.production.local. Create it from .env.production.example and protect its ACL."
}
if (-not (Test-Path -LiteralPath $composeFile)) {
    throw "Missing compose.production.yaml."
}

New-Item -ItemType Directory -Force -Path $privateDir | Out-Null
$override = @'
services:
  caddy:
    ports: !override
      - "127.0.0.1:8088:80"
      - "127.0.0.1:8443:443"
      - "127.0.0.1:8443:443/udp"
'@
[IO.File]::WriteAllText($overrideFile, $override, [System.Text.UTF8Encoding]::new($false))

if (-not $ComposeArgs -or $ComposeArgs.Count -eq 0) {
    $ComposeArgs = @("up", "--detach")
}
# Prefer the long form: PowerShell can consume short -d as an abbreviated common parameter.
$ComposeArgs = @($ComposeArgs | ForEach-Object { if ($_ -eq "-d") { "--detach" } else { $_ } })

& docker compose --env-file $envFile -f $composeFile -f $overrideFile @ComposeArgs
if ($LASTEXITCODE -ne 0) {
    throw "Docker Compose failed with exit code $LASTEXITCODE."
}
