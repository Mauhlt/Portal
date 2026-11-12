# Point current back at the known-good release. Idempotent: running it twice
# does not bounce back to the bad build.
$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'common.ps1')
$releases = Get-ReleasesDir
$kg = Read-Pointer (Join-Path $releases 'known-good.txt')
if (-not $kg) { Write-Host 'rollback: no known-good release recorded (run mark-good.ps1 on a working release).' -ForegroundColor Red; exit 1 }
if (-not (Test-Path (Join-Path $releases "$kg\portal.exe"))) { Write-Host "rollback: known-good $kg is missing its portal.exe." -ForegroundColor Red; exit 1 }
$cur = Read-Pointer (Join-Path $releases 'current.txt')
if ($cur -eq $kg) { Write-Host "rollback: already on known-good $kg."; exit 0 }
Write-Pointer (Join-Path $releases 'current.txt') $kg
Write-Host "rollback: current is now known-good $kg (was $cur). Restart portal to use it." -ForegroundColor Green
