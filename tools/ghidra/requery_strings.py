"""Re-queries an already-analysed program (no re-import/re-analysis) to refresh only the
string tables of its <name>.ghidra.json.

Needed because the first pass capped string extraction; Ghidra's analysis is cached in the
project, so this costs seconds instead of minutes.

    python requery_strings.py --project apk_arm64 --target <WORK_DIR>/.../libliveness.so [--limit 200000]
"""
from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
GHIDRA_MCP = Path(r"<GHIDRA_MCP_ROOT>")
sys.path.insert(0, str(Path(__file__).resolve().parent))

from ghidra_batch import grep_strings  # noqa: E402


def main() -> int:
    parser = argparse.ArgumentParser(description="Refresh strings of an analysed program.")
    parser.add_argument("--target", action="append", default=[])
    parser.add_argument("--targets-file", default=None)
    parser.add_argument("--project", required=True)
    parser.add_argument("--out", default=str(ROOT / "ghidra_out"))
    parser.add_argument("--projects", default=str(ROOT / "ghidra_projects"))
    parser.add_argument("--limit", type=int, default=200000)
    parser.add_argument("--min-length", type=int, default=5)
    args = parser.parse_args()

    targets = [Path(p) for p in args.target]
    if args.targets_file:
        targets += [Path(line.strip()) for line in
                    Path(args.targets_file).read_text(encoding="utf-8").splitlines()
                    if line.strip() and not line.startswith("#")]

    os.environ["GHIDRA_MCP_INSTALL_DIR"] = r"<GHIDRA_INSTALL>"
    os.environ["GHIDRA_MCP_JAVA_HOME"] = r"<JDK_HOME>"
    os.environ["GHIDRA_MCP_PROJECTS"] = args.projects
    sys.path.insert(0, str(GHIDRA_MCP))

    from ghidra_mcp import tools                          # noqa: E402
    from ghidra_mcp.session import SESSION                # noqa: E402

    for target in targets:
        out_path = Path(args.out) / f"{target.name}.ghidra.json"
        if not out_path.exists():
            print(f"[!] {target.name}: no existing JSON, run ghidra_batch.py first")
            continue
        opened = json.loads(tools.ghidra_open_program(
            project_name=args.project, program_name=target.name,
            analyze_if_needed=False, timeout=60))
        if not opened.get("ok"):
            print(f"[!] {target.name}: open failed: {opened.get('error')}")
            continue
        payload = json.loads(tools.ghidra_list_strings(
            min_length=args.min_length, limit=args.limit))
        if not payload.get("ok"):
            print(f"[!] {target.name}: list_strings failed: {payload.get('error')}")
            continue
        record = json.loads(out_path.read_text(encoding="utf-8"))
        record["strings"] = payload["strings"]
        record["interesting_strings"] = grep_strings(payload["strings"])
        record["features"]["string_count"] = payload["matched"]
        record["features"]["strings_returned"] = len(payload["strings"])
        record["features"]["string_limit"] = args.limit
        out_path.write_text(json.dumps(record, indent=2, ensure_ascii=False),
                            encoding="utf-8")
        print(f"[+] {target.name}: {payload['matched']} strings matched, "
              f"{len(payload['strings'])} returned -> {out_path.name}")

    SESSION.close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
