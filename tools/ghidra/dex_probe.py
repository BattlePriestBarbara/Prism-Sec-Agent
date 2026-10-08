"""Dumps the structural tables of a DEX file (header counts, classes, methods).

Used to prove whether `classes.dex` of the unpacked APK is real application code or a
(packer) shell: a real APK has thousands of classes / tens of thousands of methods,
a commercial packer stub has a handful.

    python dex_probe.py <SAMPLE_DIR>\\classes.dex [-o <OUT_DIR>\\dex_probe.json]
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path

HEADER_FIELDS = [
    ("string_ids_size", 0x38), ("string_ids_off", 0x3C),
    ("type_ids_size", 0x40), ("type_ids_off", 0x44),
    ("proto_ids_size", 0x48), ("proto_ids_off", 0x4C),
    ("field_ids_size", 0x50), ("field_ids_off", 0x54),
    ("method_ids_size", 0x58), ("method_ids_off", 0x5C),
    ("class_defs_size", 0x60), ("class_defs_off", 0x64),
    ("data_size", 0x68), ("data_off", 0x6C),
]


def u32(raw: bytes, off: int) -> int:
    return int.from_bytes(raw[off:off + 4], "little")


def uleb128(raw: bytes, off: int) -> tuple[int, int]:
    result = 0
    shift = 0
    while True:
        byte = raw[off]
        off += 1
        result |= (byte & 0x7F) << shift
        if not byte & 0x80:
            return result, off
        shift += 7


def mutf8_size(raw: bytes, off: int) -> int:
    size, _ = uleb128(raw, off)
    return size


def string_at(raw: bytes, data_off: int) -> str:
    """Reads one DEX string_data_item located at `data_off` (offset in file)."""
    _, cursor = uleb128(raw, data_off)
    end = raw.find(b"\x00", cursor)
    return raw[cursor:end].decode("utf-8", "replace")


def probe(path: Path) -> dict:
    raw = path.read_bytes()
    result: dict = {
        "path": str(path), "size_bytes": len(raw),
        "md5": hashlib.md5(raw).hexdigest(), "sha256": hashlib.sha256(raw).hexdigest(),
        "magic": raw[:4].decode("latin-1"), "version": raw[4:7].decode("latin-1"),
        "declared_file_size": u32(raw, 0x20), "header_size": u32(raw, 0x24),
        "endian_tag": hex(u32(raw, 0x28)),
        "checksum": hex(u32(raw, 0x08)), "signature": raw[0x0C:0x2C].hex(),
        "map_off": u32(raw, 0x34),
    }
    counts = {name: u32(raw, off) for name, off in HEADER_FIELDS}
    result["header_counts"] = counts

    # --- strings (first 400) ---
    strings: list[str] = []
    string_ids_off = counts["string_ids_off"]
    for index in range(min(counts["string_ids_size"], 4000)):
        item_off = u32(raw, string_ids_off + index * 4)
        if 0 < item_off < len(raw):
            strings.append(string_at(raw, item_off))
    result["strings_sampled"] = len(strings)
    result["strings_sample"] = strings[:400]

    # --- classes ---
    class_names: list[str] = []
    class_defs_off = counts["class_defs_off"]
    type_ids_off = counts["type_ids_off"]
    for index in range(counts["class_defs_size"]):
        base = class_defs_off + index * 32
        if base + 32 > len(raw):
            break
        class_idx = u32(raw, base)
        if class_idx < counts["type_ids_size"]:
            descriptor_idx = u32(raw, type_ids_off + class_idx * 4)
            if descriptor_idx < counts["string_ids_size"]:
                item_off = u32(raw, string_ids_off + descriptor_idx * 4)
                class_names.append(string_at(raw, item_off))
    result["class_names"] = class_names
    result["class_count"] = len(class_names)

    # Byte markers that identify the packer you are facing: edit for your target.
    markers = {"packer-marker-1": b"XXXX", "packer-marker-2": b"YYYY",
               "stub-class": b"ZZZZ"}
    result["markers"] = {name: raw.find(value) for name, value in markers.items()}
    return result


def main() -> int:
    parser = argparse.ArgumentParser(description="DEX structural probe.")
    parser.add_argument("dex")
    parser.add_argument("-o", "--output", default=None)
    args = parser.parse_args()
    path = Path(args.dex)
    result = probe(path)
    output = Path(args.output) if args.output else path.with_suffix(".dexprobe.json")
    output.write_text(json.dumps(result, indent=2, ensure_ascii=False), encoding="utf-8")

    counts = result["header_counts"]
    print(f"file            : {result['path']} ({result['size_bytes']} bytes)")
    print(f"magic/version   : {result['magic']} {result['version']}  "
          f"endian_tag={result['endian_tag']}")
    print(f"declared size   : {result['declared_file_size']} "
          f"(actual {result['size_bytes']})")
    print(f"strings         : {counts['string_ids_size']}")
    print(f"types           : {counts['type_ids_size']}")
    print(f"protos          : {counts['proto_ids_size']}")
    print(f"fields          : {counts['field_ids_size']}")
    print(f"methods         : {counts['method_ids_size']}")
    print(f"classes         : {counts['class_defs_size']}")
    print(f"markers         : {result['markers']}")
    print("class descriptors:")
    for name in result["class_names"][:60]:
        print(f"  {name}")
    print(f"[=] wrote {output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
