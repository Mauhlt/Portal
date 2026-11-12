@echo off
rem Launches the currently promoted Portal release (see scripts\release.ps1).
setlocal
set "REL=%LOCALAPPDATA%\Portal\releases"
if not exist "%REL%\current.txt" (
  echo portal: no release yet. Run: powershell -ExecutionPolicy Bypass -File "%~dp0..\scripts\release.ps1"
  exit /b 1
)
rem Clear first: if current.txt is empty, set /p would keep an inherited CUR.
set "CUR="
set /p CUR=<"%REL%\current.txt"
if not defined CUR goto bad
echo %CUR%| findstr /r /x "[0-9]*-[0-9]*_zig-[0-9A-Za-z.+-]*" >nul || goto bad
if not exist "%REL%\%CUR%\portal.exe" goto bad
"%REL%\%CUR%\portal.exe" %*
exit /b %ERRORLEVEL%
:bad
echo portal: %REL%\current.txt is missing or invalid. Run scripts\rollback.ps1 or scripts\release.ps1.
exit /b 1
