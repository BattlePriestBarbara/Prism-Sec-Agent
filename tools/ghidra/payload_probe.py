"""Entropy / payload probe: detects encrypted or compressed regions and the size of the
"real" content inside suspicious containers (shell stub DEX, *_enc.so, 1-byte assets).

The containers are *discovered*, not hard-coded: the sample's own artefact names would leak
the target and would have to be edited for every new APK. The default set is

  * the structure files and entry points that always matter (classes*.dex, resources.arsc),
  * everything the shell keeps under `assets/` and one reference library per ABI,
  * every non-standard top-level directory of the unpacked APK - a shell typically ships a
    decoy twin of `assets/` under a scrambled name, with each file reduced to a placeholder.

Add paths with --target (repeatable) or scan another tree with --root.

    python payload_probe.py [-o <OUT_DIR>\\payload_probe.json]
    python payload_probe.py --root <SAMPLE_DIR> --target assets/libfoo_enc.so
"""
from __future__ import annotations

import argparse
import json
import math
import zlib
from collections import Counter
from pathlib import Path

DEFAULT_ROOT = r"<SAMPLE_DIR>"

#: Top-level names a normal APK has; anything else is treated as worth probing.
STANDARD_TOP_LEVEL = frozenset({
    "AndroidManifest.xml", "assets", "classes.dex", "com", "junit", "kotlin", "lib",
    "META-INF", "okhttp3", "org", "res", "resources.arsc",
})
#: Always probed, relative to --root (glob patterns).
DEFAULT_GLOBS = ("classes*.dex", "resources.arsc", "assets/*", "lib/*/*.so")
#: Caps, so one huge assets/ tree cannot flood a run.
PER_GLOB_LIMIT = 8
DECOY_DIR_LIMIT = 6
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


def collect_targets(root: Path, extra: list[str]) -> tuple[list[Path], int]:
    """Discovery for a default run: returns (files to probe, number skipped by the caps)."""
    found: list[Path] = []
    skipped = 0
    for pattern in DEFAULT_GLOBS:
        matches = [p for p in sorted(root.glob(pattern)) if p.is_file()]
        found += matches[:PER_GLOB_LIMIT]
        skipped += max(0, len(matches) - PER_GLOB_LIMIT)
    for child in sorted(root.iterdir()):
        if child.name in STANDARD_TOP_LEVEL or child.name.startswith("."):
            continue
        if child.is_file():
            found.append(child)  # e.g. a stray stub/tmp DEX next to classes.dex
            continue
        files = [p for p in sorted(child.rglob("*")) if p.is_file()]
        found += files[:DECOY_DIR_LIMIT]
        skipped += max(0, len(files) - DECOY_DIR_LIMIT)
    found += [Path(name) if Path(name).is_absolute() else root / name for name in extra]

    seen: set[Path] = set()
    targets: list[Path] = []
    for path in found:
        if not path.is_file():
            continue
        resolved = path.resolve()
        if resolved in seen:
            continue
        seen.add(resolved)
        targets.append(path)
    return targets, skipped


def _relative(path: Path, root: Path) -> str:
    try:
        return str(path.relative_to(root))
    except ValueError:
        return str(path)


def main() -> int:
    parser = argparse.ArgumentParser(description="Entropy / payload probe.")
    parser.add_argument("--root", default=DEFAULT_ROOT,
                        help="unpacked APK tree to scan (default: <SAMPLE_DIR>)")
    parser.add_argument("--target", action="append", default=[],
                        help="extra container to probe, relative to --root (repeatable)")
    parser.add_argument("--list", action="store_true",
                        help="only print the discovered containers and exit")
    parser.add_argument("-o", "--output", default=r"<OUT_DIR>\payload_probe.json")
    args = parser.parse_args()

    root = Path(args.root)
    if not root.is_dir():
        print(f"[!] not a directory: {root} - pass --root <SAMPLE_DIR>")
        return 1

    targets, skipped = collect_targets(root, args.target)
    print(f"[i] root={root} containers={len(targets)} (skipped {skipped} by the caps)")
    if args.list:
        for path in targets:
            print(f"    {_relative(path, root)}")
        return 0

    results = []
    for path in targets:
        record = probe_file(path)
        results.append(record)
        print(f"[+] {_relative(path, root)}  size={record.get('size')} "
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
