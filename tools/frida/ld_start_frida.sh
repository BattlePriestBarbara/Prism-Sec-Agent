#!/system/bin/sh
# Device-side launcher for frida-server on the LDPlayer 9 instance.
#
# Runs ON THE GUEST (pushed to /data/local/tmp). Invoked from the host as:
#     adb -s emulator-5554 shell "su -c 'sh /data/local/tmp/ld_start_frida.sh'"
#
# Why a script instead of one long `su -c "..."` line: the Windows->adb->su->sh quoting
# chain eats nested quotes, which silently turns `chmod 755 <path>` into a bare `chmod`.
# Keeping the quoting inside the file removes that whole class of failure.
# NOTE: this file must keep LF line endings - the guest mksh chokes on CRLF.
#
# Result: frida-server 17.18.0 listening on 0.0.0.0:27042 (so `frida -H 127.0.0.1:27042`
# works too), logging to /data/local/tmp/frida.log.

BIN=/data/local/tmp/frida-server
LOG=/data/local/tmp/frida.log

if [ ! -f "$BIN" ]; then
    echo "missing $BIN (push it first: adb push <host frida-server-...-android-x86_64> $BIN)"
    exit 1
fi

chmod 755 "$BIN"

# Kill an older instance so re-running this script is idempotent (busybox pkill may be
# absent on some images, hence the ps/grep fallback).
if command -v pkill >/dev/null 2>&1; then
    pkill -f "$BIN" 2>/dev/null
else
    for pid in $(ps -A 2>/dev/null | grep "$BIN" | awk '{print $2}'); do
        kill -9 "$pid" 2>/dev/null
    done
fi
sleep 1

nohup "$BIN" -l 0.0.0.0:27042 >"$LOG" 2>&1 &
sleep 3

echo "--- processes matching frida-server ---"
ps -A 2>/dev/null | grep frida-server | grep -v grep
echo "--- listening sockets (27042 = 0x69A2) ---"
grep -i "69A2" /proc/net/tcp /proc/net/tcp6 2>/dev/null
echo "--- tail of $LOG ---"
tail -n 5 "$LOG" 2>/dev/null
echo "[i] host-side check: frida-ps -U should now list the device processes"
exit 0
