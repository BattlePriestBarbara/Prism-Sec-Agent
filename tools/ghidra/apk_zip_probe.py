"""Decide whether a .zip is really the *original* APK (just renamed) or a re-zipped tree.

Dynamic analysis (Frida attach / DEX unpack) needs an installable APK that still carries
the original signature, because the commercial packer shell verifies it at startup. A re-zipped
directory keeps META-INF/*.SF + *.RSA (v1) but loses the APK Signing Block that sits
between the last entry and the central directory (v2/v3), which is enough to tell them apart.

    python apk_zip_probe.py <SAMPLE_ZIP>
"""
from __future__ import annotations

import argparse
import struct
import sys
import zipfile
from pathlib import Path

try:
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
except Exception:  # noqa: BLE001
    pass

APK_SIG_MAGIC = b"APK Sig Block 42"
EOCD_MAGIC = b"PK\x05\x06"
ROOT_EXPECTED = ["AndroidManifest.xml", "classes.dex", "resources.arsc"]


def find_eocd(data: bytes) -> int | None:
    """Offset of the End Of Central Directory record (scan back over the comment)."""
    start = max(0, len(data) - (0xFFFF + 22))
    idx = data.rfind(EOCD_MAGIC, start)
    return idx if idx != -1 else None


def signing_block_info(data: bytes) -> tuple[bool, int, dict[str, int]]:
    """Return (has_signing_block, cd_offset, {scheme_name: block_size})."""
    eocd = find_eocd(data)
    if eocd is None:
        return False, -1, {}
    cd_offset = struct.unpack_from("<I", data, eocd + 16)[0]
    if cd_offset < 32:
        return False, cd_offset, {}
    magic_at = cd_offset - 16
    if data[magic_at:magic_at + 16] != APK_SIG_MAGIC:
        return False, cd_offset, {}
    block_size = struct.unpack_from("<Q", data, cd_offset - 24)[0]
    start = cd_offset - 8 - block_size
    found: dict[str, int] = {}
    pos = start + 8
    end = cd_offset - 24
    while pos + 12 <= end:
        pair_len = struct.unpack_from("<Q", data, pos)[0]
        if pair_len < 4 or pos + 8 + pair_len > end + 24:
            break
        pair_id = struct.unpack_from("<I", data, pos + 8)[0]
        found.setdefault({0x7109871A: "v2", 0xF05368C0: "v3",
                          0x1B93AD61: "v4(idsig)", 0x42726577: "padding"}.get(
                              pair_id, f"id 0x{pair_id:08x}"), pair_len)
        pos += 8 + pair_len
    return True, cd_offset, found


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("zip_path")
    args = parser.parse_args()

    path = Path(args.zip_path)
    if not path.is_file():
        print(f"[!] no such file: {path}")
        return 1

    data = path.read_bytes()
    print(f"file            : {path}")
    print(f"size            : {len(data)} bytes ({len(data) / 1024 / 1024:.2f} MB)")
    print(f"magic           : {data[:4]!r} "
          f"({'zip container' if data[:2] == b'PK' else 'NOT a zip'})")
    if data[:2] != b"PK":
        return 1

    with zipfile.ZipFile(path) as zf:
        names = zf.namelist()
        print(f"entries         : {len(names)}")
        print(f"first 8 entries : {names[:8]}")
        bad = zf.testzip()
        print(f"crc test        : {'all entries OK' if bad is None else 'CORRUPT -> ' + bad}")

        missing = [m for m in ROOT_EXPECTED if m not in names]
        print(f"root members    : present={[m for m in ROOT_EXPECTED if m in names]} "
              f"missing={missing}")
        print(f"top-level names : {sorted({n.split('/')[0] for n in names})[:20]}")

        meta = [n for n in names if n.startswith("META-INF/")]
        sf = [n for n in meta if n.upper().endswith(".SF")]
        rsa = [n for n in meta if n.upper().endswith((".RSA", ".DSA", ".EC"))]
        mf = [n for n in meta if n.upper().endswith("MANIFEST.MF")]
        print(f"META-INF        : {len(meta)} entries; MANIFEST.MF={mf} SF={sf} certs={rsa}")
        if meta:
            print(f"META-INF names  : {sorted(meta)[:12]}")

        info = zf.infolist()
        methods: dict[int, int] = {}
        for item in info:
            methods[item.compress_type] = methods.get(item.compress_type, 0) + 1
        print(f"compression     : {methods}  (0=stored, 8=deflate)")
        if info:
            print(f"first entry     : {info[0].filename} (method={info[0].compress_type}, "
                  f"date={info[0].date_time})")

    has_block, cd_offset, schemes = signing_block_info(data)
    print(f"central dir     : offset {cd_offset}")
    print(f"APK sign block  : {'yes' if has_block else 'no'}")
    print(f"sign schemes    : {schemes or '(none found)'}")

    print("\nverdict:")
    if has_block or schemes:
        print("  * APK Signing Block present -> almost certainly the ORIGINAL apk; "
              "copy it to <name>.apk and install directly.")
    elif sf and rsa:
        print("  * only v1 (META-INF) signature files -> the tree was re-zipped, the "
              "v2/v3 block is gone.")
        print("    Android 7+ still accepts v1-only when targetSdk < 30, but the sample's "
              "own signature check may reject a repack.")
        print("    -> prefer the untouched original .apk for dynamic work.")
    else:
        print("  * no signature material at all -> not installable as-is; you need the "
              "original apk.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
