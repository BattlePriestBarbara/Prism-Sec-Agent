"""Resumable frida-server / frida-gadget downloader with integrity checking.

GitHub is often flaky from here and mirrors sometimes truncate large assets, so this tool:
  * tries several mirrors (direct GitHub first, then common China-friendly proxies)
  * resumes with HTTP Range requests instead of restarting
  * verifies each attempt by xz-decompressing it (that is the real "did it finish?" test)
  * extracts the ELF only when the archive is provably complete

    python fetch_frida_asset.py --abi android-x86_64 --kind server
    python fetch_frida_asset.py --abi android-arm64  --kind gadget
"""
from __future__ import annotations

import argparse
import hashlib
import lzma
import urllib.request
from pathlib import Path

MIRRORS = [
    "https://github.com/frida/frida/releases/download/{v}/{name}",
    "https://ghfast.top/https://github.com/frida/frida/releases/download/{v}/{name}",
    "https://ghproxy.net/https://github.com/frida/frida/releases/download/{v}/{name}",
    "https://gh-proxy.com/https://github.com/frida/frida/releases/download/{v}/{name}",
]

ASSETS = {
    "server": "frida-server-{v}-{abi}.xz",
    "gadget": "frida-gadget-{v}-{abi}.so.xz",
}


def complete(path: Path) -> bytes | None:
    """Returns the decompressed payload if the .xz on disk is complete, else None."""
    try:
        return lzma.decompress(path.read_bytes())
    except (OSError, lzma.LZMAError):
        return None


def download(url: str, target: Path, timeout: int = 60) -> None:
    have = target.stat().st_size if target.exists() else 0
    request = urllib.request.Request(url)
    if have:
        request.add_header("Range", f"bytes={have}-")
    mode = "ab" if have else "wb"
    with urllib.request.urlopen(request, timeout=timeout) as response:
        chunk_size = 512 * 1024
        with target.open(mode) as handle:
            while True:
                chunk = response.read(chunk_size)
                if not chunk:
                    break
                handle.write(chunk)


def main() -> int:
    parser = argparse.ArgumentParser(description="Fetch a frida release asset (resumable).")
    parser.add_argument("--abi", required=True,
                        help="android-arm64 / android-x86_64 / android-arm / android-x86")
    parser.add_argument("--version", default="17.18.0")
    parser.add_argument("--kind", default="server", choices=sorted(ASSETS))
    parser.add_argument("--dir", default=r"<FRIDA_ROOT>/server")
    parser.add_argument("--rounds", type=int, default=6)
    args = parser.parse_args()

    folder = Path(args.dir)
    folder.mkdir(parents=True, exist_ok=True)
    name = ASSETS[args.kind].format(v=args.version, abi=args.abi)
    archive = folder / name
    partial = folder / (name + ".part")

    for round_index in range(1, args.rounds + 1):
        for template in MIRRORS:
            url = template.format(v=args.version, name=name)
            host = url.split("/")[2]
            try:
                if partial.exists():
                    partial.replace(archive) if not archive.exists() else None
                download(url, archive)
            except Exception as exc:  # noqa: BLE001
                print(f"  [{round_index}] {host}: {type(exc).__name__} "
                      f"({archive.stat().st_size if archive.exists() else 0} bytes)")
                continue
            data = complete(archive)
            size = archive.stat().st_size
            if data is None:
                print(f"  [{round_index}] {host}: incomplete ({size} bytes), resuming")
                continue
            payload = archive.with_suffix("")
            payload.write_bytes(data)
            print(f"[+] {name} complete after {round_index} round(s)")
            print(f"    archive {size} bytes -> {payload.name} {len(data)} bytes")
            print(f"    ELF magic {data[:4].hex()} | "
                  f"sha256 {hashlib.sha256(data).hexdigest()}")
            return 0
    print(f"[!] could not complete {name}; try another mirror or network")
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
