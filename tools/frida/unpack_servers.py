"""Verifies + extracts the frida-server .xz files in <FRIDA_ROOT>/server.

Windows has no built-in xz tool, but Python's lzma module handles the format, and
frida-server ships as .xz. Extraction produces the raw Android ELF binaries that get
pushed to the device with `adb push`.

    python unpack_servers.py [--dir <FRIDA_ROOT>/server]
"""
from __future__ import annotations

import argparse
import hashlib
import lzma
from pathlib import Path


def main() -> int:
    parser = argparse.ArgumentParser(description="Verify + extract frida-server .xz files.")
    parser.add_argument("--dir", default=r"<FRIDA_ROOT>/server")
    args = parser.parse_args()

    folder = Path(args.dir)
    archives = sorted(folder.glob("*.xz"))
    if not archives:
        print(f"[!] no .xz files in {folder}")
        return 1

    for archive in archives:
        raw = archive.read_bytes()
        target = archive.with_suffix("")
        try:
            data = lzma.decompress(raw)
        except Exception as exc:  # noqa: BLE001
            print(f"[!] {archive.name}: xz broken ({type(exc).__name__}: {exc}) "
                  f"- re-download needed ({len(raw)} bytes so far)")
            continue
        target.write_bytes(data)
        print(f"[+] {archive.name}")
        print(f"      xz size {len(raw)} bytes -> ELF {len(data)} bytes -> {target.name}")
        print(f"      ELF magic {data[:4].hex()} | sha256 {hashlib.sha256(data).hexdigest()[:32]}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
