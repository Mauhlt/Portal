# Shared helpers for release.ps1 / mark-good.ps1 / rollback.ps1.

$ReleaseIdPattern = '^\d{8}-\d{6}_zig-[0-9A-Za-z.+-]+$'

function Get-ReleasesDir {
    if (-not $env:LOCALAPPDATA) { throw 'LOCALAPPDATA is not set' }
    $d = Join-Path $env:LOCALAPPDATA 'Portal\releases'
    New-Item -ItemType Directory -Force -Path $d | Out-Null
    return $d
}

# Returns the release id stored in a pointer file, or $null if missing/invalid.
function Read-Pointer($path) {
    if (-not (Test-Path $path)) { return $null }
    $v = (Get-Content $path -Raw)
    if ($null -eq $v) { return $null }
    $v = $v.Trim()
    if ($v -notmatch $ReleaseIdPattern) { return $null }
    return $v
}

# Atomic pointer update: write a temp file, then replace.
function Write-Pointer($path, $id) {
    if ($id -notmatch $ReleaseIdPattern) { throw "refusing to write invalid release id '$id'" }
    $tmp = "$path.tmp"
    [IO.File]::WriteAllText($tmp, $id, [Text.Encoding]::ASCII)
    if (Test-Path $path) { [IO.File]::Replace($tmp, $path, $null) } else { [IO.File]::Move($tmp, $path) }
}
