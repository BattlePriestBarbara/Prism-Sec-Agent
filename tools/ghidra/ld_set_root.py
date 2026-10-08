"""Flip a key in an LDPlayer 9 per-instance config (`vms\\config\\leidianN.config`).

Why not just json.load / json.dump: LDPlayer rewrites this file itself and we do not want
to re-serialise the whole document (key order, escape style and the non-ASCII shared-folder
paths). So we insert/replace the single member with a pure-text edit and keep a .bak.

The key names are the ones the player actually looks for, recovered from dnplayer.exe with
`tools/ld_config_probe.py`:

    basicSettings.rootMode   1 = enable ROOT (installs su / runs adbd as root)
    basicSettings.adbDebug   1 = enable ADB debugging
    advancedSettings.cpuCount / advancedSettings.memorySize / advancedSettings.resolution

The emulator must be shut down while editing, otherwise it overwrites the file on exit.

    python ld_set_root.py --config "<EMULATOR_HOME>\\vms\\config\\leidian0.config" \
        --set basicSettings.rootMode=1 --set basicSettings.adbDebug=1
    python ld_set_root.py --config ... --show
"""
from __future__ import annotations

import argparse
import json
import re
import shutil
import sys
from pathlib import Path

try:
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
except Exception:  # noqa: BLE001
    pass


def render(value: str) -> str:
    """Render a CLI value the way JSON would: 1 -> 1, true -> true, text -> "text"."""
    lowered = value.lower()
    if lowered in ("true", "false"):
        return lowered
    if re.fullmatch(r"-?\d+", value):
        return value
    if value.startswith(("{", "[")):
        return json.dumps(json.loads(value), ensure_ascii=False)
    return json.dumps(value, ensure_ascii=False)


def set_member(text: str, key: str, raw_value: str) -> tuple[str, str]:
    """Insert or replace `"key": raw_value`; returns (new_text, action)."""
    pattern = re.compile(r'("' + re.escape(key) + r'"\s*:\s*)(?:"(?:[^"\\]|\\.)*"|[^,\n}\]]+)')
    match = pattern.search(text)
    if match:
        return pattern.sub(lambda m: m.group(1) + raw_value, text, count=1), "updated"
    # insert as the first member so the diff stays local and readable
    brace = text.index("{")
    insert_at = text.find("\n", brace)
    if insert_at == -1:
        return text[: brace + 1] + f'"{key}": {raw_value}' + text[brace + 1:], "inserted"
    indent = "    "
    return (text[: insert_at + 1] + f'{indent}"{key}": {raw_value},\n'
            + text[insert_at + 1:]), "inserted"


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--config", required=True)
    parser.add_argument("--set", action="append", default=[], metavar="KEY=VALUE")
    parser.add_argument("--show", action="store_true", help="just print the current file")
    args = parser.parse_args()

    path = Path(args.config)
    if not path.is_file():
        print(f"[!] no such config: {path}")
        return 1
    text = path.read_text(encoding="utf-8")

    if args.show or not args.set:
        print(text)
        return 0

    backup = path.with_suffix(path.suffix + ".bak")
    if not backup.exists():
        shutil.copy2(path, backup)
        print(f"[i] backup -> {backup}")

    for item in args.set:
        key, _, value = item.partition("=")
        text, action = set_member(text, key.strip(), render(value.strip()))
        print(f"[+] {key.strip()} = {render(value.strip())}  ({action})")

    json.loads(text)  # fail loudly instead of leaving a broken config behind
    path.write_text(text, encoding="utf-8")
    print(f"[=] wrote {path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
