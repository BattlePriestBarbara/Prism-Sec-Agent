"""Self-check for the <FRIDA_ROOT> installation.

Prints: python/frida versions, console scripts, the extracted frida-server binaries
(ABI, size, ELF magic, sha256) and whether a device/adb is reachable right now.

    <FRIDA_ROOT>/.venv/Scripts/python.exe <FRIDA_ROOT>\\check_setup.py
"""
from __future__ import annotations

import hashlib
import json
import shutil
import subprocess
from pathlib import Path

FRIDA_DIR = Path(__file__).resolve().parent
SERVER_DIR = FRIDA_DIR / "server"


def main() -> int:
    print("=" * 72)
    print("frida installation self-check")
    print("=" * 72)

    import frida
    print(f"frida python binding : {frida.__version__}")
    for name in ("frida.exe", "frida-ps.exe", "frida-trace.exe"):
        path = FRIDA_DIR / ".venv" / "Scripts" / name
        print(f"{name:<21}: {'ok' if path.is_file() else 'MISSING'} ({path})")

    print("\nfrida-server binaries:")
    for binary in sorted(SERVER_DIR.glob("frida-server-*")):
        if binary.suffix in (".xz",):
            continue
        head = binary.read_bytes()[:4]
        digest = hashlib.sha256(binary.read_bytes()).hexdigest()[:16]
        abi = binary.name.replace("frida-server-17.18.0-", "")
        is_elf = head == bytes([0x7F, 0x45, 0x4C, 0x46])
        print(f"  {abi:<12} {binary.stat().st_size / 1024 / 1024:7.2f} MB  "
              f"ELF={'yes' if is_elf else 'NO'}  sha256={digest}")

    print("\ndevice tooling:")
    local_adb = FRIDA_DIR / "platform-tools" / "adb.exe"
    adb = str(local_adb) if local_adb.is_file() else shutil.which("adb")
    print(f"  adb               : {adb or 'not found'}")
    if adb:
        try:
            version = subprocess.run([adb, "version"], capture_output=True, text=True,
                                     timeout=20).stdout.strip().splitlines()
            items = [line for line in version if "Android Debug Bridge" in line
                     or line.startswith("Version")]
            print(f"                      {' | '.join(items)}")
            devices = subprocess.run([adb, "devices"], capture_output=True, text=True,
                                     timeout=20).stdout.strip()
            print("  adb devices       : " + devices.replace("\r\n", " / ").replace("\n", " / "))
        except Exception as exc:  # noqa: BLE001
            print(f"  adb call failed   : {exc}")

    try:
        from frida_tools.application import ConsoleApplication  # noqa: F401
        device_list = frida.enumerate_devices()
        print("  frida devices     : " + ", ".join(f"{d.id}({d.type})" for d in device_list))
    except Exception as exc:  # noqa: BLE001
        print(f"  frida devices     : {type(exc).__name__}: {exc}")

    print("\nhook scripts:")
    for script in sorted((FRIDA_DIR / "hooks").glob("*.js")):
        print(f"  {script.name:<24} {script.stat().st_size:>6} bytes")

    info = {"frida": frida.__version__,
            "servers": [p.name for p in SERVER_DIR.glob("frida-server-*") if p.suffix != ".xz"],
            "hooks": [p.name for p in sorted((FRIDA_DIR / "hooks").glob("*.js"))]}
    print("\n" + json.dumps(info, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
