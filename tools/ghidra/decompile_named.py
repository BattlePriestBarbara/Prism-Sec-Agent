"""Decompiles named functions of an already-analysed program (no re-analysis needed).

The generic batch ranks functions by caller count, which for C++-heavy libraries often
lands on libiberty/OpenCV helpers. This tool lets us ask for the interesting symbols
explicitly (license checks, JNI entry points, crypto routines, packer init).

    python decompile_named.py --project apk_arm64 --target <WORK_DIR>/.../libtransport.so `
        --match Java_com_openssl_md --match genECDHsharedsecret --match aes_256_cbc
"""
from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
GHIDRA_MCP = Path(os.environ.get("GHIDRA_MCP_ROOT", r"<GHIDRA_MCP_ROOT>"))


def main() -> int:
    parser = argparse.ArgumentParser(description="Decompile selected functions by name.")
    parser.add_argument("--target", action="append", default=[])
    parser.add_argument("--targets-file", default=None)
    parser.add_argument("--project", required=True)
    parser.add_argument("--match", action="append", default=[],
                        help="case-insensitive name substring (repeatable)")
    parser.add_argument("--per-match", type=int, default=4)
    parser.add_argument("--chars", type=int, default=9000)
    parser.add_argument("--out", default=str(ROOT / "ghidra_out"))
    parser.add_argument("--projects", default=str(ROOT / "ghidra_projects"))
    parser.add_argument("--suffix", default=".targeted")
    args = parser.parse_args()

    targets = [Path(p) for p in args.target]
    if args.targets_file:
        targets += [Path(line.strip()) for line in
                    Path(args.targets_file).read_text(encoding="utf-8").splitlines()
                    if line.strip() and not line.startswith("#")]
    if not args.match:
        raise SystemExit("at least one --match is required")

    os.environ["GHIDRA_MCP_INSTALL_DIR"] = os.environ.get(
        "GHIDRA_MCP_INSTALL_DIR", r"<GHIDRA_INSTALL>")
    os.environ["GHIDRA_MCP_JAVA_HOME"] = os.environ.get(
        "GHIDRA_MCP_JAVA_HOME", r"<JDK_HOME>")
    os.environ["GHIDRA_MCP_PROJECTS"] = args.projects
    sys.path.insert(0, str(GHIDRA_MCP))

    from ghidra_mcp import tools                          # noqa: E402
    from ghidra_mcp.session import SESSION                # noqa: E402

    out_dir = Path(args.out) / "decompiled"
    out_dir.mkdir(parents=True, exist_ok=True)

    for target in targets:
        opened = json.loads(tools.ghidra_open_program(
            project_name=args.project, program_name=target.name,
            analyze_if_needed=False, timeout=120))
        if not opened.get("ok"):
            print(f"[!] {target.name}: open failed: {opened.get('error')}")
            continue

        blocks: list[str] = []
        seen: set[str] = set()
        for pattern in args.match:
            listing = json.loads(tools.ghidra_list_functions(
                name_filter=pattern, limit=args.per_match, offset=0,
                include_external=True, include_thunks=True))
            if not listing.get("ok"):
                print(f"    [!] list_functions({pattern}): {listing.get('error')}")
                continue
            hits = listing.get("functions", [])
            print(f"    [.] {pattern}: {len(hits)} hit(s) "
                  f"(total matches {listing.get('matched', listing.get('total_functions'))})")
            for func in hits:
                if func["entry"] in seen:
                    continue
                seen.add(func["entry"])
                code = json.loads(tools.ghidra_decompile_function(
                    func["entry"], max_chars=args.chars))
                body = (code.get("code") or "// <decompilation unavailable>")
                blocks.append(
                    f"// ==== match '{pattern}' ====\n"
                    f"// {func['full_name']} @ {func['entry']} "
                    f"size={func.get('size_bytes')} signature: {func.get('signature')}\n"
                    + body.replace("\r\n", "\n").replace("\r", "\n") + "\n")

        out_path = out_dir / f"{target.name}{args.suffix}.c"
        with out_path.open("w", encoding="utf-8", newline="\n") as handle:
            handle.write(f"// Ghidra targeted decompilation - {target.name}\n")
            handle.write(f"// matches: {args.match}\n\n")
            handle.write("\n".join(blocks) if blocks else "// no matching functions\n")
        print(f"[+] {target.name}: {len(blocks)} function(s) -> {out_path.name}")

    SESSION.close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
