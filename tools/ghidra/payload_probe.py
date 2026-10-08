"""Entropy / payload probe: detects encrypted or compressed regions and the size of the
"real" content inside suspicious containers (shell stub DEX, *_enc.so, 1-byte assets).

    python payload_probe.py [-o <OUT_DIR>\\payload_probe.json]
"""
from __future__ import annotations

import argparse
import json
import math
import zlib
from collections import Counter
from pathlib import Path

APK = Path(r"<SAMPLE_DIR>")
MAGIC = {b"\x7fELF": "ELF", b"dex\n": "DEX", b"\x1f\x8b": "gzip", b"PK\x03\x04": "zip",
         b"ANDROID!": "Android boot img", b"SQLite f": "SQLite", b"\x89PNG": "PNG",
         b"\xff\xd8\xff": "JPEG", b"<!DOCTYPE": "XML", b"<?xml": "XML"}


def entropy(blob: bytes) -> float:
    if not blob:
        return 0.0
    counts = Counter(blob)
    total = len(blob)
    return -sum((count / total) * math.log2(count / total) for count in counts.values())


def detect(blob: bytes) -> str:
    for magic, name in MAGIC.items():
        if blob.startswith(magic):
            return name
    return "unknown"


def probe_file(path: Path, chunk: int = 256 * 1024) -> dict:
    raw = path.read_bytes()
    if not raw:
        return {"path": str(path), "size": 0, "error": "empty"}
    peaks = []
    for start in range(0, len(raw), chunk):
        piece = raw[start:start + chunk]
        peaks.append({"offset": start, "size": len(piece),
                      "entropy": round(entropy(piece), 3),
                      "magic": detect(piece)})
    inflate_ok = False
    try:
        inflate_ok = len(zlib.decompress(raw)) > 0
    except Exception:  # noqa: BLE001
        inflate_ok = False
    return {
        "path": str(path), "size": len(raw),
        "head_hex": raw[:32].hex(),
        "head_ascii": "".join(chr(b) if 32 <= b < 127 else "." for b in raw[:32]),
        "magic": detect(raw),
        "overall_entropy": round(entropy(raw), 3),
        "zlib_decompressible": inflate_ok,
        "chunks": peaks[:12],
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="Entropy / payload probe.")
    parser.add_argument("-o", "--output", default=r"<OUT_DIR>\payload_probe.json")
    args = parser.parse_args()

    targets = [APK / "classes.dex", APK / "assets" / "libshell_vip_enc.so",
               APK / "assets" / "libshell.so", APK / "assets" / "libshell_vip_a64.so",
               APK / "resources.arsc", APK / "lib" / "arm64-v8a" / "libliveness.so"]
    targets += sorted(APK.glob("bttets/*"))[:4]
    targets += sorted(APK.glob("bttets/*/*"))[:6]

    results = []
    for path in targets:
        if path.is_file():
            record = probe_file(path)
            results.append(record)
            print(f"[+] {path.relative_to(APK)}  size={record.get('size')} "
                  f"magic={record.get('magic')} entropy={record.get('overall_entropy')} "
                  f"zlib={record.get('zlib_decompressible')} head={record.get('head_ascii')}")
            for chunk in record.get("chunks", [])[:4]:
                print(f"      @{chunk['offset']:<10} ent={chunk['entropy']:<6} "
                      f"{chunk['magic']}")

    output = Path(args.output)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(results, indent=2, ensure_ascii=False), encoding="utf-8")
    print(f"[=] wrote {output} ({len(results)} files)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
