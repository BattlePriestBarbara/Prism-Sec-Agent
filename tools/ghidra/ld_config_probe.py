"""Probe the LDPlayer 9 installation for its instance-config key names.

LDPlayer 9.1.50.60 ships without `ldconsole.exe`, so the only way to flip settings
(e.g. the ROOT permission / adb-debug switches) from the command line is to edit the
per-instance JSON at `vms\\config\\leidianN.config` with the *exact* key names the
player expects. The key names live as plain ASCII in the player binaries / Qt
resources, so we just scan for an anchor string and print its neighbourhood.

    python ld_config_probe.py --dir "<EMULATOR_HOME>" --anchor advancedSettings
    python ld_config_probe.py --anchor rootPermission --anchor adbDebug
"""
from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path

# PowerShell on a zh-CN Windows defaults stdout to GBK, which cannot encode the
# replacement characters produced by scanning binaries -> force UTF-8.
try:
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
except Exception:  # noqa: BLE001
    pass

SKIP_SUFFIX = {".vmdk", ".vdi", ".exe", ".dll", ".so", ".bin", ".img", ".apk", ".ogg", ".dat"}
MAX_SCAN_BYTES = 200 * 1024 * 1024
TEXT_CHUNK = 4 * 1024 * 1024


def scan_file(path: Path, anchors: list[bytes], window: int,
              encodings: tuple[str, ...] = ("utf-8",)) -> list[tuple[bytes, bytes]]:
    """Return (anchor, context) pairs found in `path`.

    Qt stores its UI strings as UTF-16, so callers can pass several encodings and each
    anchor is looked up in all of them; the winning encoding is used to decode the
    context so the output stays readable.
    """
    hits: list[tuple[bytes, bytes]] = []
    try:
        size = path.stat().st_size
        if size == 0 or size > MAX_SCAN_BYTES:
            return hits
        data = path.read_bytes()
    except OSError:
        return hits
    for anchor_text in anchors:
        for encoding in encodings:
            try:
                anchor = anchor_text.decode() if isinstance(anchor_text, bytes) else anchor_text
                needle = anchor.encode(encoding, "ignore")
            except (UnicodeDecodeError, LookupError):
                continue
            if not needle:
                continue
            for match in re.finditer(re.escape(needle), data):
                start = max(0, match.start() - window * len(needle) // max(len(anchor), 1))
                end = min(len(data), match.end() + window * 3)
                hits.append((encoding, anchor, data[start:end]))
                if len(hits) > 40:
                    return hits
    return hits


def printable(raw: bytes, encoding: str = "utf-8") -> str:
    """Keep printables + CJK-ish sequences, drop the rest."""
    text = raw.decode(encoding, "replace")
    return "".join(ch if ch.isprintable() else "." for ch in text)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--dir", default=r"<EMULATOR_HOME>")
    parser.add_argument("--anchor", action="append", default=None,
                        help="ASCII anchor to look for (repeatable)")
    parser.add_argument("--window", type=int, default=64)
    parser.add_argument("--include-exe", action="store_true",
                        help="also scan .exe/.dll (slower)")
    parser.add_argument("--dump-keys", default=None, metavar="OUT",
                        help="write every Settings.<key> name found to OUT (utf-8)")
    parser.add_argument("--utf16", action="store_true",
                        help="also search UTF-16LE/BE (needed for Qt UI strings)")
    args = parser.parse_args()

    anchors = args.anchor or ["advancedSettings", "rootPermission", "adbDebug"]
    encodings = ("utf-8", "utf-16le", "utf-16be") if args.utf16 else ("utf-8",)
    root = Path(args.dir)
    if root.is_file():
        targets = [root]
    elif root.is_dir():
        targets = [p for p in sorted(root.rglob("*")) if p.is_file()]
    else:
        print(f"[!] not a file or directory: {root}")
        return 1

    seen_keys: set[str] = set()
    all_keys: set[str] = set()
    contexts: list[str] = []
    for path in targets:
        if not args.include_exe and path.suffix.lower() in SKIP_SUFFIX:
            continue
        if path.suffix.lower() not in (".json", ".xml", ".rcc", ".ini", ".txt", ".exe",
                                       ".dll", ".so", ".dat", ".js", ""):
            continue
        for encoding, anchor, context in scan_file(path, anchors, args.window, encodings):
            text = printable(context, encoding)
            all_keys.update(re.findall(r"[A-Za-z][A-Za-z0-9_]{2,40}\.[A-Za-z][A-Za-z0-9_]{2,40}",
                                       text))
            # Config files use dotted keys: advancedSettings.foo
            for key in re.findall(r"[A-Za-z][A-Za-z0-9_.]{6,60}", text):
                if key.startswith(anchor) and key not in seen_keys:
                    seen_keys.add(key)
                    print(f"{path.name:<28} {anchor:<18} {key}")
            if not any(k.startswith(anchor) for k in
                       re.findall(r"[A-Za-z][A-Za-z0-9_.]{6,60}", text)):
                print(f"{path.name:<28} {anchor:<18} [{encoding}] <ctx> {text[:200]}")
                contexts.append(f"{path.name} [{encoding}] :: {text[:1500]}")

    if args.dump_keys:
        body = ["=== dotted keys ==="] + sorted(all_keys)
        body += ["", "=== contexts ==="] + contexts
        Path(args.dump_keys).write_text("\n".join(body), encoding="utf-8")
        print(f"[i] dumped {len(all_keys)} keys -> {args.dump_keys}")

    if not seen_keys:
        print("[i] no dotted keys matched; try --anchor root or --include-exe")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
