@echo off
rem ---------------------------------------------------------------------------
rem  Start frida-server inside the LDPlayer 9 instance and verify the link.
rem
rem      <FRIDA_ROOT>\ld_frida_start.cmd                 (uses emulator-5554)
rem      <FRIDA_ROOT>\ld_frida_start.cmd 127.0.0.1:5555  (explicit adb target)
rem
rem  Requirements (all already prepared):
rem    * LDPlayer 9 instance booted, its adb exposed as emulator-5554 / 127.0.0.1:5555
rem    * ROOT enabled for the instance (otherwise `su -c` fails: "su: not found")
rem    * <FRIDA_ROOT>/server\frida-server-17.18.0-android-x86_64 (x86_64 = LDPlayer ABI)
rem
rem  frida CLI and frida-server MUST be the same version (17.18.0), otherwise you get
rem  "unable to communicate with remote frida-server".
rem ---------------------------------------------------------------------------
setlocal
set "FRIDA_DIR=<FRIDA_ROOT>"
set "PATH=%FRIDA_DIR%\.venv\Scripts;%FRIDA_DIR%\platform-tools;%PATH%"
set "SERVER=%FRIDA_DIR%\server\frida-server-17.18.0-android-x86_64"
set "DEV=%~1"
if "%DEV%"=="" set "DEV=emulator-5554"

echo [1/5] adb server / device
adb start-server >nul 2>&1
adb -s %DEV% get-state >nul 2>&1
if errorlevel 1 (
    echo     %DEV% not connected - trying adb connect 127.0.0.1:5555
    adb connect 127.0.0.1:5555 >nul 2>&1
    set "DEV=127.0.0.1:5555"
)
adb devices

echo [2/5] pushing frida-server ^(x86_64^) and the launcher script
adb -s %DEV% push "%SERVER%" /data/local/tmp/frida-server
if errorlevel 1 goto :fail
rem  The guest mksh dies on CRLF ("syntax error: unmatched 'if'"), so normalise first.
"%FRIDA_DIR%\.venv\Scripts\python.exe" -c "import pathlib; p = pathlib.Path(r'%FRIDA_DIR%\ld_start_frida.sh'); p.write_bytes(p.read_bytes().replace(b'\r\n', b'\n'))"
adb -s %DEV% push "%FRIDA_DIR%\ld_start_frida.sh" /data/local/tmp/ld_start_frida.sh
if errorlevel 1 goto :fail

echo [3/5] starting frida-server as root ^(su^)
adb -s %DEV% shell "su -c 'sh /data/local/tmp/ld_start_frida.sh'"
if errorlevel 1 goto :fail

echo [4/5] frida-server processes
adb -s %DEV% shell "su -c 'ps -A | grep frida-server'"

echo [5/5] frida-ps -U  ^(device process list = link works^)
frida-ps -U
echo.
echo [=] done. Next:
echo     <FRIDA_ROOT>/.venv/Scripts/python.exe <FRIDA_ROOT>\dump_dex.py --package com.example.targetapp --out <OUT_DIR>/unpacked
endlocal
exit /b 0

:fail
echo [!] a step failed - check the adb output above
endlocal
exit /b 1
