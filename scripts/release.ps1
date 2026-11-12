# Build, test and promote a new Portal release, keeping a known-good fallback.
#
# Releases live OUTSIDE the repo (so `git clean` can't delete the safety copy):
#     %LOCALAPPDATA%\Portal\releases\
#         20261111-183000_zig-0.18.0-dev.4+5a23bf4b2\
#             portal.exe, portal.pdb, BUILD-INFO.txt, source\
#         current.txt     release bin\portal.cmd runs
#         known-good.txt  release you confirmed works (scripts\mark-good.ps1)
#         history.txt     every promotion, newest last
#
# Only a build that passes `zig build test` (unit tests + full exe compile in
# Debug and ReleaseSafe) with the installed compiler is promoted. A running
# portal.exe is never overwritten. Upgrading Zig can never break the binary
# you already use, and `rollback.ps1` always returns to known-good.
#
#   powershell -ExecutionPolicy Bypass -File scripts\release.ps1
#   powershell -ExecutionPolicy Bypass -File scripts\mark-good.ps1
#   powershell -ExecutionPolicy Bypass -File scripts\rollback.ps1

$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'common.ps1')
$root = Split-Path -Parent $PSScriptRoot
$releases = Get-ReleasesDir
$keep = 4   # extra releases kept besides current / known-good / newest-per-zig

function Fail($msg) {
    Write-Host "release: $msg" -ForegroundColor Red
    Write-Host 'release: current release left untouched.' -ForegroundColor Yellow
    exit 1
}

Push-Location $root
try {
    if (-not (Get-Command zig -ErrorAction SilentlyContinue)) { Fail 'zig not found on PATH' }
    $zigVersion = (& zig version).Trim()
    Write-Host "release: using zig $zigVersion"

    Write-Host 'release: running tests (unit tests + full compile)...'
    & zig build test --summary all
    if ($LASTEXITCODE -ne 0) { Fail "tests failed with zig $zigVersion" }

    $stamp = Get-Date -Format 'yyyyMMdd-HHmmss'
    $id = "${stamp}_zig-$zigVersion"
    if ($id -notmatch $ReleaseIdPattern) { Fail "unexpected release id '$id'" }
    $dest = Join-Path $releases $id
    if (Test-Path $dest) { Fail "release $id already exists; wait a second and retry" }
    $stage = Join-Path $releases '_staging'
    if (Test-Path $stage) { Remove-Item -Recurse -Force $stage }

    Write-Host 'release: building ReleaseSafe...'
    & zig build -Doptimize=ReleaseSafe --prefix $stage
    if ($LASTEXITCODE -ne 0) { Fail "build failed with zig $zigVersion" }

    $exe = Join-Path $stage 'bin\portal.exe'
    # Via cmd: Windows PowerShell 5.1 can turn a native exe's stderr into an error.
    $out = (cmd /c "`"$exe`" version 2>&1" | Out-String).Trim()
    if ($LASTEXITCODE -ne 0) { Fail "new binary does not run: $out" }

    $commit = 'none'
    if (Get-Command git -ErrorAction SilentlyContinue) {
        $c = (cmd /c "git -C `"$root`" rev-parse HEAD 2>nul" | Out-String).Trim()
        if ($c) {
            $dirty = (cmd /c "git -C `"$root`" status --porcelain 2>nul" | Out-String).Trim()
            $commit = $c + $(if ($dirty) { ' (uncommitted changes)' } else { '' })
        }
    }

    New-Item -ItemType Directory -Force -Path $dest | Out-Null
    Copy-Item $exe $dest
    $pdb = Join-Path $stage 'bin\portal.pdb'
    if (Test-Path $pdb) { Copy-Item $pdb $dest }
    $src = Join-Path $dest 'source'
    New-Item -ItemType Directory -Force -Path $src | Out-Null
    Copy-Item -Recurse (Join-Path $root 'src') $src
    Copy-Item (Join-Path $root 'build.zig'), (Join-Path $root 'build.zig.zon') $src
    $hash = (Get-FileHash (Join-Path $dest 'portal.exe') -Algorithm SHA256).Hash.ToLower()
    $zigExe = (Get-Command zig).Source
    @(
        "portal: $out"
        "zig: $zigVersion"
        "zig path: $zigExe"
        "git: $commit"
        "built: $(Get-Date -Format o)"
        "sha256(portal.exe): $hash"
    ) | Set-Content -Encoding utf8 (Join-Path $dest 'BUILD-INFO.txt')
    Remove-Item -Recurse -Force $stage

    Write-Pointer (Join-Path $releases 'current.txt') $id
    Add-Content -Encoding ascii -Path (Join-Path $releases 'history.txt') -Value $id

    # Prune, never touching current, known-good, or the newest release built
    # with each distinct zig version. Locked (running) releases are skipped.
    $protected = @($id)
    $kg = Read-Pointer (Join-Path $releases 'known-good.txt')
    if ($kg) { $protected += $kg }
    $all = Get-ChildItem $releases -Directory | Where-Object { $_.Name -match $ReleaseIdPattern } | Sort-Object Name -Descending
    $seenZig = @{}
    foreach ($d in $all) {
        $z = $d.Name.Substring($d.Name.IndexOf('_zig-') + 5)
        if (-not $seenZig.ContainsKey($z)) { $seenZig[$z] = $true; $protected += $d.Name }
    }
    $all | Where-Object { $_.Name -notin $protected } | Select-Object -Skip $keep | ForEach-Object {
        try {
            # Rename first: fails cleanly if portal.exe is running, leaving the folder intact.
            $tmp = "$($_.FullName).deleting"
            Rename-Item $_.FullName $tmp -ErrorAction Stop
            Remove-Item -Recurse -Force $tmp -ErrorAction Stop
            Write-Host "release: pruned $($_.Name)"
        } catch {
            Write-Host "release: could not prune $($_.Name) (in use?); skipping" -ForegroundColor Yellow
        }
    }

    Write-Host "release: promoted $id" -ForegroundColor Green
    if ($kg) { Write-Host "release: known-good fallback is $kg" }
    else { Write-Host 'release: no known-good release yet. After confirming this one works end to end, run scripts\mark-good.ps1' -ForegroundColor Yellow }
    Write-Host 'release: restart any running portal to pick it up (bin\portal.cmd).'
}
finally {
    Pop-Location
}
