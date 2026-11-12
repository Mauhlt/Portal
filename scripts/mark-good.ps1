# Mark the current release as known-good, after you have confirmed it works
# end to end (laptop login over WireGuard, viewing, answering a prompt).
# rollback.ps1 always returns to this release, and it is never pruned.
$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'common.ps1')
$releases = Get-ReleasesDir
$cur = Read-Pointer (Join-Path $releases 'current.txt')
if (-not $cur) { Write-Host 'mark-good: no valid current release.' -ForegroundColor Red; exit 1 }
if (-not (Test-Path (Join-Path $releases "$cur\portal.exe"))) { Write-Host "mark-good: $cur has no portal.exe." -ForegroundColor Red; exit 1 }
Write-Pointer (Join-Path $releases 'known-good.txt') $cur
Write-Host "mark-good: known-good is now $cur" -ForegroundColor Green
