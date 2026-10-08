"""Host side of the shell DEX dump: spawns/attaches the app, runs hooks/dump_dex.js and
writes every DEX blob the JS side streams over.

    python dump_dex.py --package com.example.targetapp --out <OUT_DIR>/unpacked
    python dump_dex.py --attach 12345 --out <OUT_DIR>/unpacked        # by pid
    python dump_dex.py --package com.example.targetapp --device 127.0.0.1:27042

Requires: a running frida-server on the device (<FRIDA_ROOT>/server\\...) and adb for USB
devices. The DEX files land in <out>\\dex\\ and are validated (magic + declared size).
"""
from __future__ import annotations

import argparse
import hashlib
import time
from pathlib import Path

import frida

JS = Path(__file__).resolve().parent / "hooks" / "dump_dex.js"


def on_message(message, data, out_dir: Path, counter: list) -> None:
    if message.get("type") == "error":
        print(f"[!] script error: {message.get('description')}")
        return
    payload = message.get("payload") or {}
    kind = payload.get("type")
    if kind == "dex" and data:
        counter[0] += 1
        declared = payload.get("size", 0)
        digest = hashlib.sha256(data).hexdigest()[:8]
        classes = payload.get("classes", -1)
        source = str(payload.get("source", "scan")).replace("/", "_")
        name = (f"dump_{counter[0]:02d}_{source}_{payload.get('address', '?').replace('0x', '')}"
                f"_{digest}_cls{classes}.dex")
        target = out_dir / "dex" / name
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(data)
        magic = data[:4].decode("latin-1", "replace")
        real_size = int.from_bytes(data[0x20:0x24], "little") if len(data) >= 0x28 else 0
        print(f"[+] {name}: {len(data)} bytes, magic={magic!r}, declared={declared} "
              f"(header says {real_size}) version={payload.get('version')} "
              f"strings={payload.get('strings')} methods={payload.get('methods')} "
              f"classes={classes} endian=0x{(payload.get('endian') or 0) & 0xFFFFFFFF:08x}",
              flush=True)
    elif kind == "scan-done":
        print(f"[*] scan done: new={payload.get('hits')} total={payload.get('total')} "
              f"scanned={payload.get('scanned_mb')} MB", flush=True)
    elif payload:
        print(f"[*] {payload}")


def main() -> int:
    parser = argparse.ArgumentParser(description="Dump the decrypted DEX of a packed app.")
    parser.add_argument("--package", default="com.example.targetapp")
    parser.add_argument("--attach", type=int, default=None, help="pid to attach to")
    parser.add_argument("--device", default=None,
                        help="frida device id/address (default: USB). "
                             "Emulators: 127.0.0.1:27042")
    parser.add_argument("--out", default=r"<OUT_DIR>/unpacked")
    parser.add_argument("--js", default=str(JS))
    parser.add_argument("--seconds", type=int, default=None,
                        help="run for N seconds and detach automatically "
                             "(default: wait for Ctrl+C; use this in non-interactive shells "
                             "where sys.stdin is not a terminal)")
    args = parser.parse_args()

    if args.device:
        device = frida.get_device_manager().add_remote_device(args.device)
    else:
        device = frida.get_usb_device(timeout=10)
    print(f"[i] device: {device}")

    pid = None
    if args.attach:
        session = device.attach(args.attach)
        print(f"[i] attached to pid {args.attach}")
    else:
        pid = device.spawn([args.package])
        session = device.attach(pid)
        print(f"[i] spawned {args.package} -> pid {pid}")

    script = session.create_script(Path(args.js).read_text(encoding="utf-8"))
    counter = [0]
    script.on("message", lambda message, data: on_message(message, data, Path(args.out), counter))
    script.load()

    if pid is not None:
        device.resume(pid)
        print("[i] resumed; waiting for the packer to decrypt ...")

    if args.seconds:
        print(f"[i] attached for {args.seconds}s (non-interactive mode)")
        time.sleep(args.seconds)
    else:
        print("[i] press Ctrl+C to stop")
        try:
            import sys
            sys.stdin.read()
        except KeyboardInterrupt:
            pass
    session.detach()
    print(f"[=] dumps written to {Path(args.out) / 'dex'} ({counter[0]} blobs)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
