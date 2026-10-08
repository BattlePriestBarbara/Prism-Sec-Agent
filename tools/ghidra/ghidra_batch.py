"""Batch Ghidra (PyGhidra) analysis of the binaries inside <SAMPLE_DIR>.

Drives exactly the same Ghidra Java API that the <GHIDRA_MCP_ROOT> MCP server exposes
(ghidra_mcp.tools), but in batch: import + auto-analyse, then dump functions, imports,
strings, entry points, memory blocks, call-graph ranking and the decompiled pseudo-code
of the N most "core" functions.

Results are written per binary so a long run is resumable (an existing output file is
reused unless --force is given).

    python ghidra_batch.py --target <file> [--target ...] [--project NAME]
                           [--out DIR] [--top N] [--timeout SECONDS] [--force]
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent          # <WORK_DIR>
GHIDRA_MCP = Path(os.environ.get("GHIDRA_MCP_ROOT", r"<GHIDRA_MCP_ROOT>"))

#: Strings that usually point at keys, endpoints, crypto or anti-analysis logic.
INTERESTING_PATTERNS = [
    ("url", r"https?://[^\s\"'<>]{4,120}"),
    ("ipv4", r"\b(?:\d{1,3}\.){3}\d{1,3}(?::\d{2,5})?\b"),
    ("crypto/api-key", r"(?i)(api[_-]?key|secret|app[_-]?secret|access[_-]?key|"
                       r"token|password|passwd|aes|rsa|hmac|md5|sha1|sha256)"),
    ("cert/pem", r"(?i)(-----BEGIN|-{5}END|X509|certificate)"),
    ("java/jni", r"(?i)(Ljava/|Landroid/|JNI|RegisterNatives|GetEnv|jclass|jstring)"),
    ("packer/anti-debug", r"(?i)(shell|packer|stub|vendor|frida|ptrace|"
                          r"tracerpid|debugger|root|xposed|magisk|emulator|qemu)"),
    ("license/activation", r"(?i)(licen[cs]e|activ(?:ate|ation)|serial|expire|trial|"
                           r"device[_-]?id|imei|android[_-]?id)"),
    ("ocr/face/idcard", r"(?i)(ocr|face|idcard|id[_-]?card|liveness|recogniz|detect|"
                        r"quality|model|onnx|tflite|caffe|ncnn|mnn)"),
]


def sha256_of(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def call(label: str, func, *args, **kwargs):
    """Calls a tool function, returns its payload or None on failure."""
    started = time.time()
    payload = json.loads(func(*args, **kwargs))
    elapsed = round(time.time() - started, 1)
    if not payload.get("ok"):
        print(f"    [!] {label} FAILED after {elapsed}s: {payload.get('error')}",
              file=sys.stderr, flush=True)
        return None
    print(f"    [.] {label}: ok ({elapsed}s)", file=sys.stderr, flush=True)
    return payload


def rank_core_functions(tools, all_functions: list[dict], top_n: int,
                        candidate_pool: int = 30) -> list[dict]:
    """Same ranking rule as <GHIDRA_MCP_ROOT>\\extract_features.py."""
    pool = [f for f in all_functions
            if not f["is_external"] and not f["is_thunk"] and f.get("size_bytes")]
    pool.sort(key=lambda f: f["size_bytes"], reverse=True)
    candidates = {f["entry"]: f for f in pool[:candidate_pool]}
    entry_func = next((f for f in pool if f["name"] == "entry"), None)
    if entry_func is not None:
        candidates.setdefault(entry_func["entry"], entry_func)

    ranked = []
    for func in candidates.values():
        graph = json.loads(tools.ghidra_call_graph(func["entry"], limit=500))
        callers = len(graph.get("calling_functions", [])) if graph.get("ok") else 0
        callees = len(graph.get("called_functions", [])) if graph.get("ok") else 0
        ranked.append({**func, "callers": callers, "callees": callees,
                       "score": callers * 1000 + (func["size_bytes"] or 0)})
    ranked.sort(key=lambda f: (f["score"], f["size_bytes"] or 0), reverse=True)

    chosen = ranked[:top_n]
    if entry_func is not None and entry_func["entry"] not in {f["entry"] for f in chosen}:
        chosen = chosen[: max(top_n - 1, 0)] + [
            next(f for f in ranked if f["entry"] == entry_func["entry"])
        ]
    for index, func in enumerate(chosen, start=1):
        func["rank"] = index
    return chosen


def grep_strings(strings: list) -> dict:
    """Groups defined strings by the security-relevant patterns in INTERESTING_PATTERNS.

    `strings` is the raw ghidra_list_strings payload (dicts with address/length/value).
    """
    values = [entry["value"] if isinstance(entry, dict) else str(entry)
              for entry in strings]
    findings: dict[str, list[str]] = {}
    for label, pattern in INTERESTING_PATTERNS:
        regex = re.compile(pattern)
        hits = sorted({value for value in values if regex.search(value)})
        if hits:
            findings[label] = hits[:400]
    findings["_count"] = [f"{len(values)} strings scanned"]
    return findings


def analyze_one(tools, target: Path, program_name: str, project: str, out_dir: Path,
                top: int, timeout: int, strings_limit: int, decompile_chars: int,
                force: bool, name_suffix: str = "") -> dict:
    """Import + analyse one binary and write <name><suffix>.ghidra.json / .c."""
    json_out = out_dir / f"{target.name}{name_suffix}.ghidra.json"
    code_out = out_dir / "decompiled" / f"{target.name}{name_suffix}.c"
    if json_out.exists() and not force:
        print(f"[=] {target.name}: cached ({json_out})", flush=True)
        return json.loads(json_out.read_text(encoding="utf-8"))

    print(f"[>] {target.name}: import + analyse (timeout {timeout}s)", flush=True)
    record: dict = {"target": {"path": str(target), "name": target.name,
                               "size_bytes": target.stat().st_size,
                               "sha256": sha256_of(target)}}
    imported = call("import_and_analyze", tools.ghidra_import_and_analyze,
                    binary_path=str(target), project_name=project,
                    program_name=program_name, analyze=True, timeout=timeout,
                    force_reimport=force)
    if imported is None:
        record["error"] = "import/analysis failed"
        json_out.write_text(json.dumps(record, indent=2, ensure_ascii=False),
                            encoding="utf-8")
        return record

    summary = call("current_program", tools.ghidra_current_program)["program"]
    functions = call("list_functions", tools.ghidra_list_functions, limit=100000,
                     include_external=True, include_thunks=True) or {"functions": []}
    imports = call("list_imports", tools.ghidra_list_imports, limit=100000) or {"imports": []}
    strings = call("list_strings", tools.ghidra_list_strings, min_length=5,
                   limit=strings_limit) or {"strings": [], "matched": 0}
    entries = call("list_entry_points", tools.ghidra_list_entry_points, limit=500) or \
        {"entry_points": []}
    blocks = call("list_memory_blocks", tools.ghidra_list_memory_blocks) or {"blocks": []}

    core = rank_core_functions(tools, functions["functions"], top)
    for func in core:
        payload = json.loads(tools.ghidra_decompile_function(func["entry"],
                                                             max_chars=decompile_chars))
        func["decompile_completed"] = bool(payload.get("decompile_completed"))
        func["pseudo_code"] = payload.get("code", "")
        func["pseudo_code_truncated"] = bool(payload.get("truncated"))
        if not payload.get("ok") or not func["decompile_completed"]:
            func["decompile_error"] = payload.get("error", "decompilation incomplete")
        print(f"    [.] decompiled {func['name']} ({len(func['pseudo_code'])} chars)",
              flush=True)

    all_strings = strings.get("strings", [])
    record.update({
        "analysis": {"imported": imported.get("imported"), "analyzed": imported.get("analyzed"),
                     "elapsed_seconds": imported.get("elapsed_seconds"),
                     "program": imported.get("program")},
        "program": summary,
        "features": {
            "function_count": summary.get("function_count"),
            "internal_function_count": len([f for f in functions["functions"]
                                            if not f["is_external"] and not f["is_thunk"]]),
            "imported_api_count": len(imports.get("imports", [])),
            "imported_library_count": len(imports.get("libraries", [])),
            "string_count": strings.get("matched"),
            "strings_returned": len(all_strings),
            "symbol_count": summary.get("symbol_count"),
            "entry_point_count": len(entries.get("entry_points", [])),
            "memory_bytes": summary.get("memory_bytes"),
        },
        "imported_libraries": imports.get("libraries", []),
        "imported_apis": [entry["name"] for entry in imports.get("imports", [])],
        "entry_points": entries.get("entry_points", []),
        "memory_blocks": blocks.get("blocks", []),
        "strings": all_strings,
        "interesting_strings": grep_strings(all_strings),
        "core_functions": core,
        "ranking_method": (
            "Non-import, non-thunk functions with a body, sorted by caller count "
            "(in-degree from ghidra_call_graph, computed for the 30 largest functions), "
            "ties broken by body size; the entry point is always included."
        ),
    })
    json_out.write_text(json.dumps(record, indent=2, ensure_ascii=False), encoding="utf-8")

    code_out.parent.mkdir(parents=True, exist_ok=True)
    with code_out.open("w", encoding="utf-8", newline="\n") as handle:
        handle.write(f"// Ghidra decompiler output - {target.name}\n")
        handle.write(f"// sha256 {record['target']['sha256']}\n")
        handle.write(f"// language {summary.get('language')}  "
                     f"compiler {summary.get('compiler')}\n")
        handle.write(f"// functions {summary.get('function_count')}  "
                     f"strings {strings.get('matched')}\n\n")
        for func in core:
            handle.write(f"// ---- [{func['rank']}] {func['name']} @ {func['entry']} "
                         f"size={func['size_bytes']} callers={func['callers']}\n")
            handle.write(f"// signature: {func['signature']}\n")
            body = func["pseudo_code"] or "// <decompilation unavailable>\n"
            handle.write(body.replace("\r\n", "\n").replace("\r", "\n"))
            handle.write("\n\n")
    print(f"[+] {target.name}: {summary.get('function_count')} functions, "
          f"{strings.get('matched')} strings -> {json_out.name} / decompiled\\{code_out.name}",
          flush=True)
    return record


def main() -> int:
    parser = argparse.ArgumentParser(description="Batch Ghidra analysis of APK binaries.")
    parser.add_argument("--target", action="append", default=[],
                        help="binary to analyse (repeatable)")
    parser.add_argument("--targets-file", default=None,
                        help="text file with one binary path per line")
    parser.add_argument("--project", default="apk_arm64")
    parser.add_argument("--program-prefix", default="",
                        help="prefix for the program name inside the project")
    parser.add_argument("--name-suffix", default="",
                        help="suffix for the output file names (e.g. -arm32), useful when "
                             "several ABIs ship a library with the same file name")
    parser.add_argument("--out", default=str(ROOT / "ghidra_out"))
    parser.add_argument("--projects", default=str(ROOT / "ghidra_projects"))
    parser.add_argument("--top", type=int, default=5)
    parser.add_argument("--timeout", type=int, default=1800)
    parser.add_argument("--strings-limit", type=int, default=6000)
    parser.add_argument("--decompile-chars", type=int, default=12000)
    parser.add_argument("--force", action="store_true")
    args = parser.parse_args()

    targets = [Path(p) for p in args.target]
    if args.targets_file:
        targets += [Path(line.strip()) for line in
                    Path(args.targets_file).read_text(encoding="utf-8").splitlines()
                    if line.strip() and not line.startswith("#")]
    if not targets:
        raise SystemExit("no targets given (--target or --targets-file)")

    # Configure the Ghidra MCP harness BEFORE importing it.
    os.environ["GHIDRA_MCP_INSTALL_DIR"] = os.environ.get(
        "GHIDRA_MCP_INSTALL_DIR", r"<GHIDRA_INSTALL>")
    os.environ["GHIDRA_MCP_JAVA_HOME"] = os.environ.get(
        "GHIDRA_MCP_JAVA_HOME", r"<JDK_HOME>")
    os.environ["GHIDRA_MCP_PROJECTS"] = args.projects
    sys.path.insert(0, str(GHIDRA_MCP))

    from ghidra_mcp import tools                       # noqa: E402
    from ghidra_mcp.session import SESSION             # noqa: E402

    env = SESSION.environment()
    print(f"[i] ghidra={env.get('ghidra_version')} java={env.get('java_home_selected')} "
          f"projects={args.projects}", flush=True)

    out_dir = Path(args.out)
    out_dir.mkdir(parents=True, exist_ok=True)

    summary_path = out_dir / f"summary_{args.project}.json"
    summary: dict = {"project": args.project, "results": []}
    if summary_path.exists() and not args.force:
        summary = json.loads(summary_path.read_text(encoding="utf-8"))

    for target in targets:
        if not target.is_file():
            print(f"[!] missing: {target}", file=sys.stderr, flush=True)
            continue
        started = time.time()
        try:
            record = analyze_one(tools, target, args.program_prefix + target.name,
                                 args.project, out_dir, args.top, args.timeout,
                                 args.strings_limit, args.decompile_chars, args.force,
                                 args.name_suffix)
        except Exception as exc:  # noqa: BLE001
            print(f"[!] {target.name}: {type(exc).__name__}: {exc}", file=sys.stderr,
                  flush=True)
            record = {"target": {"path": str(target), "name": target.name},
                      "error": f"{type(exc).__name__}: {exc}"}
        elapsed = round(time.time() - started, 1)

        entry = {
            "name": target.name + args.name_suffix,
            "path": str(target),
            "elapsed_seconds": elapsed,
            "sha256": record.get("target", {}).get("sha256"),
            "error": record.get("error"),
            "language": (record.get("program") or {}).get("language"),
            "compiler": (record.get("program") or {}).get("compiler"),
            **(record.get("features") or {}),
            "core_functions": [f"{f['name']} @ {f['entry']}"
                               for f in record.get("core_functions", [])],
        }
        summary["results"] = [r for r in summary["results"]
                              if r["name"] != target.name + args.name_suffix]
        summary["results"].append(entry)
        summary_path.write_text(json.dumps(summary, indent=2, ensure_ascii=False),
                                encoding="utf-8")
        print(f"[=] {target.name}: done in {elapsed}s", flush=True)

    SESSION.close()
    done = [r for r in summary["results"] if not r.get("error")]
    print(f"\n[=] analysed {len(done)}/{len(summary['results'])} binaries; "
          f"summary -> {summary_path}", flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
