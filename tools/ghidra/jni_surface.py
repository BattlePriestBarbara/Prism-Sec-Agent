"""Extract the JNI surface of every ELF in the sample from ghidra_out/elf_triage.json.

Answers two questions that drive JNI-boundary work:
    * which libraries expose *statically named* JNI entry points (Java_com_*), and
    * which libraries expose none - i.e. they can only be reached through
      JNIEnv->RegisterNatives() at runtime, so a Frida trace of RegisterNatives is the
      only way to see (name, signature, function pointer) for them.

Outputs a markdown table on stdout plus a machine readable summary that
hooks/jni_boundary.js reads at run time.

    python jni_surface.py                      # markdown + refresh jni_surface.json
    python jni_surface.py --abi arm64-v8a      # restrict to one ABI directory
    python jni_surface.py --json-only
"""
from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path

try:
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
except Exception:  # noqa: BLE001
    pass

DEFAULT_TRIAGE = r"<OUT_DIR>/elf_triage.json"
DEFAULT_OUT = r"<OUT_DIR>/jni_surface.json"

# JNI_OnLoad / Java_* / _Java_* (some loaders prefix an underscore)
RE_JNI_DECL = re.compile(r"^_?(Java_[A-Za-z0-9_]+)$")
RE_ONLOAD = re.compile(r"JNI_On(Load|Unload)")

# Android::base / art internals that show up in exports but are not JNI endpoints
NOISE = re.compile(r"^(__|_Z|_Unwind|JavaVM)")


def abi_of(path: str) -> str:
    parts = Path(path).parts
    for candidate in ("arm64-v8a", "armeabi-v7a", "armeabi", "x86", "x86_64"):
        if candidate in parts:
            return candidate
    return "assets" if "assets" in parts else "?"


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--triage", default=DEFAULT_TRIAGE)
    parser.add_argument("--out", default=DEFAULT_OUT)
    parser.add_argument("--abi", default=None,
                        help="restrict to one ABI (e.g. arm64-v8a); default: all")
    parser.add_argument("--json-only", action="store_true")
    args = parser.parse_args()

    triage = json.loads(Path(args.triage).read_text(encoding="utf-8"))
    modules: dict[str, dict] = {}

    for entry in triage.get("files", []):
        if entry.get("error"):
            continue
        path = entry["path"]
        abi = abi_of(path)
        if args.abi and abi != args.abi:
            continue
        name = entry.get("soname") or Path(path).name
        exports = entry.get("exported_symbols") or []
        jni: list[str] = []
        onload: list[str] = []
        for symbol in exports:
            if RE_ONLOAD.search(symbol):
                onload.append(symbol)
                continue
            match = RE_JNI_DECL.match(symbol)
            if match and not NOISE.match(symbol):
                jni.append(match.group(1))
        record = modules.setdefault(name, {"abis": {}, "jni_exports": set(),
                                           "onload": set(), "export_count": {}})
        record["abis"][abi] = path
        record["jni_exports"].update(jni)
        record["onload"].update(onload)
        record["export_count"][abi] = entry.get("exported_function_count", 0)

    # ---- machine readable summary (consumed by hooks/jni_boundary.js) ----
    summary = {"modules": {}, "dynamic_only": [], "with_jni": []}
    for name in sorted(modules):
        record = modules[name]
        jni = sorted(record["jni_exports"])
        summary["modules"][name] = {
            "abis": record["abis"],
            "jni_exports": jni,
            "onload": sorted(record["onload"]),
            "exported_functions": record["export_count"],
        }
        if jni:
            summary["with_jni"].append(name)
        elif record["export_count"].get("arm64-v8a", 0) > 0:
            # has code but no statically named JNI entry -> RegisterNatives candidate
            summary["dynamic_only"].append(name)
    Path(args.out).write_text(json.dumps(summary, indent=2, ensure_ascii=False),
                              encoding="utf-8")

    if args.json_only:
        print(f"[=] wrote {args.out}")
        return 0

    total_jni = sum(len(v["jni_exports"]) for v in summary["modules"].values())
    print(f"# JNI surface (source: {Path(args.triage).name})\n")
    print(f"- libraries: {len(summary['modules'])}, statically named JNI entry points: {total_jni}")
    print(f"- libraries exposing Java_* exports: {len(summary['with_jni'])}, "
          f"RegisterNatives-only candidates: {len(summary['dynamic_only'])}")
    print(f"- machine readable summary: {args.out}\n")

    print("| library | ABI | exported funcs | JNI_OnLoad | static Java_* exports |")
    print("| --- | --- | --- | --- | --- |")
    for name in sorted(summary["modules"], key=lambda n: -len(summary["modules"][n]["jni_exports"])):
        record = summary["modules"][name]
        exports = "/".join(f"{abi}:{cnt}" for abi, cnt in sorted(record["exported_functions"].items()))
        onload = ",".join(record["onload"]) or "-"
        jni = ", ".join(f"`{j}`" for j in record["jni_exports"]) if record["jni_exports"] else "**none (dynamic registration only)**"
        print(f"| `{name}` | {'/'.join(sorted(record['abis']))} | {exports} | {onload} | {jni} |")

    if summary["dynamic_only"]:
        print("\n## RegisterNatives-only candidate libraries\n")
        for name in summary["dynamic_only"]:
            print(f"- `{name}` (exported functions "
                  f"{summary['modules'][name]['exported_functions'].get('arm64-v8a', 0)}, "
                  f"no `Java_*`)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
