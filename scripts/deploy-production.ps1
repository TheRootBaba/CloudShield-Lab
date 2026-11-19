param(
    [string]$ComposeFile = "compose.production.yaml",
    [string]$ComposeEnvFile = ".env.production",
    [int]$HealthTimeoutSeconds = 300
)
$ErrorActionPreference = "Stop"
if (-not (Test-Path $ComposeEnvFile -PathType Leaf)) { throw "Private production environment file not found: $ComposeEnvFile" }

# Read only the three deployment values needed for preflight. Never print the bootstrap secret.
$settings = @{}
foreach ($line in Get-Content $ComposeEnvFile) {
    if ($line -match '^\s*([A-Z0-9_]+)=(.*)$') { $settings[$Matches[1]] = $Matches[2].Trim().Trim('"').Trim("'") }
}
$domain = [string]$settings["CLOUDSHIELD_DOMAIN"]
$email = [string]$settings["CLOUDSHIELD_TLS_EMAIL"]
$bootstrap = [string]$settings["CLOUDSHIELD_BOOTSTRAP_TOKEN"]
if ($domain -notmatch '^(?=.{1,253}$)([a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[A-Za-z]{2,63}$' -or $domain -eq "cloudshield.example.com") {
    throw "Set CLOUDSHIELD_DOMAIN to a real DNS name before deploying."
}
if ($email -notmatch '^[^\s@]+@[^\s@]+\.[^\s@]+$') { throw "Set CLOUDSHIELD_TLS_EMAIL to a valid certificate contact address." }
if ($bootstrap.Length -lt 32 -or $bootstrap.ToLowerInvariant().StartsWith("replace_")) {
    throw "Set a unique CLOUDSHIELD_BOOTSTRAP_TOKEN of at least 32 characters in the private environment file."
}

& docker info *> $null
if ($LASTEXITCODE -ne 0) { throw "Docker Engine is not reachable. Start Docker Desktop or the Linux Docker service." }
& docker compose --env-file $ComposeEnvFile -f $ComposeFile config --quiet
if ($LASTEXITCODE -ne 0) { throw "Production Compose configuration validation failed." }

Write-Host "Building the CloudShield production image (no push)..."
& docker compose --env-file $ComposeEnvFile -f $ComposeFile build
if ($LASTEXITCODE -ne 0) { throw "Production image build failed." }

Write-Host "Starting the private application and HTTPS ingress..."
& docker compose --env-file $ComposeEnvFile -f $ComposeFile up -d
if ($LASTEXITCODE -ne 0) { throw "Production Compose startup failed." }

$deadline = (Get-Date).AddSeconds($HealthTimeoutSeconds)
$appHealthy = $false
while ((Get-Date) -lt $deadline) {
    & docker compose --env-file $ComposeEnvFile -f $ComposeFile exec -T cloudshield python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8765/api/health', timeout=3).read()"
    if ($LASTEXITCODE -eq 0) { $appHealthy = $true; break }
    Start-Sleep -Seconds 5
}
if (-not $appHealthy) { throw "CloudShield application did not become healthy. Inspect service logs; do not open registration." }

$httpsHealthy = $false
$httpsDeadline = (Get-Date).AddSeconds($HealthTimeoutSeconds)
while ((Get-Date) -lt $httpsDeadline) {
    try {
        $health = Invoke-RestMethod -Uri "https://$domain/api/health" -TimeoutSec 10
        if ($health.ok -eq $true) { $httpsHealthy = $true; break }
    } catch {
        Start-Sleep -Seconds 5
    }
}
if (-not $httpsHealthy) {
    throw "The app is healthy internally but HTTPS through Caddy is not yet healthy. Check DNS A/AAAA, inbound 80/443, Caddy logs and certificate issuance."
}

& docker compose --env-file $ComposeEnvFile -f $ComposeFile ps
if ($LASTEXITCODE -ne 0) { throw "Could not read production service status." }
Write-Host "CloudShield HTTPS health check passed at https://$domain/api/health."
Write-Host "Complete the first-admin signup using CLOUDSHIELD_BOOTSTRAP_TOKEN from the private environment file. Do not share that token."
