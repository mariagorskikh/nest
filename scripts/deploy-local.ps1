#Requires -Version 5.1
<#
.SYNOPSIS
  One-command local deployment for Nanda Town (Python engine + Next.js dashboard).
.DESCRIPTION
  For /skills POST in production, set NEST_SKILLS_API_KEY in
  apps/nest-dashboard/.env.local (see .env.local.example).
  Distributed scenarios (workers > 1) require NEST_HTTP_SHARED_SECRET in the
  environment before nest run — see docs/distributed.md.
.EXAMPLE
  .\scripts\deploy-local.ps1 -Mode Dev
.EXAMPLE
  .\scripts\deploy-local.ps1 -Mode Prod -RunScenario -InitSkills `
    -DatabaseUrl "postgresql://user:pass@host/db?sslmode=require"
#>
param(
    [ValidateSet('Dev', 'Prod')]
    [string]$Mode = 'Dev',
    [switch]$RunScenario,
    [switch]$InitSkills,
    [string]$DatabaseUrl
)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$RepoRoot = Resolve-Path (Join-Path $PSScriptRoot '..')
$DashboardDir = Join-Path $RepoRoot 'apps\nest-dashboard'
$EnvLocal = Join-Path $DashboardDir '.env.local'
$Port = 3000
function Write-Step([string]$Message) {
    Write-Host ">>> $Message" -ForegroundColor Cyan
}
function Stop-PortListener([int]$ListenPort) {
    $connections = Get-NetTCPConnection -LocalPort $ListenPort -State Listen -ErrorAction SilentlyContinue
    if (-not $connections) {
        return
    }
    $pids = $connections | Select-Object -ExpandProperty OwningProcess -Unique
    foreach ($procId in $pids) {
        $proc = Get-Process -Id $procId -ErrorAction SilentlyContinue
        if ($proc) {
            Write-Host "Stopping process on port ${ListenPort}: $($proc.ProcessName) (PID $procId)" -ForegroundColor Yellow
            Stop-Process -Id $procId -Force -ErrorAction SilentlyContinue
        }
    }
    Start-Sleep -Seconds 1
}
function Test-DoctorPassed {
    $output = & uv run nest doctor 2>&1 | Out-String
    Write-Host $output
    return $output -match '7/7 checks passed'
}
Push-Location $RepoRoot
try {
    Write-Step 'uv sync'
    & uv sync
    if ($LASTEXITCODE -ne 0) { throw 'uv sync failed' }
    Write-Step 'nest doctor'
    if (-not (Test-DoctorPassed)) {
        throw 'nest doctor did not report 7/7 checks passed'
    }
    if ($RunScenario) {
        Write-Step 'nest run marketplace'
        & uv run nest run marketplace
        if ($LASTEXITCODE -ne 0) { throw 'nest run marketplace failed' }
    }
    if ($DatabaseUrl) {
        Write-Step 'writing apps/nest-dashboard/.env.local'
        $escaped = $DatabaseUrl.Replace('"', '\"')
        "DATABASE_URL=`"$escaped`"" | Set-Content -Path $EnvLocal -Encoding utf8
        Write-Host "Wrote $EnvLocal"
    }
    $hasEnvLocal = Test-Path $EnvLocal
    if ($InitSkills) {
        if (-not $hasEnvLocal) {
            throw 'InitSkills requires .env.local. Pass -DatabaseUrl or create apps/nest-dashboard/.env.local first.'
        }
        Write-Step 'initializing skills schema (db-init.mjs)'
        Push-Location $DashboardDir
        try {
            & node scripts/db-init.mjs
            if ($LASTEXITCODE -ne 0) { throw 'db-init.mjs failed' }
        }
        finally {
            Pop-Location
        }
    }
    Write-Step 'npm ci (nest-dashboard)'
    Push-Location $DashboardDir
    try {
        & npm ci
        if ($LASTEXITCODE -ne 0) { throw 'npm ci failed' }
        if (Get-NetTCPConnection -LocalPort $Port -State Listen -ErrorAction SilentlyContinue) {
            Write-Host "Port $Port is in use; stopping existing listener..." -ForegroundColor Yellow
            Stop-PortListener -ListenPort $Port
        }
        if ($Mode -eq 'Prod') {
            Write-Step 'npm run build'
            & npm run build
            if ($LASTEXITCODE -ne 0) { throw 'npm run build failed' }
            Write-Step "npm run start (http://localhost:${Port})"
            & npm run start
        }
        else {
            Write-Step "npm run dev (http://localhost:${Port})"
            & npm run dev
        }
    }
    finally {
        Pop-Location
    }
}
finally {
    Pop-Location
}
