@echo off
rem  Put the frida venv + Android platform-tools on PATH for the current shell:
rem      call <FRIDA_ROOT>\env.cmd
rem  Then you can just run:  adb devices | frida-ps -U | frida -U -f <pkg> -l <script.js>
set "PATH=<FRIDA_ROOT>\.venv\Scripts;<FRIDA_ROOT>\platform-tools;%PATH%"
echo [frida] PATH ready:
echo    frida / frida-ps / frida-trace  -^> <FRIDA_ROOT>\.venv\Scripts
echo    adb                            -^> <FRIDA_ROOT>\platform-tools
