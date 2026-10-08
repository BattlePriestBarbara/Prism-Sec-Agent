@echo off
rem  Convenience wrapper: run the venv's frida CLI without activating the venv.
rem  Usage:  <FRIDA_ROOT>\frida.cmd -ps -U
"<FRIDA_ROOT>\.venv\Scripts\frida.exe" %*
