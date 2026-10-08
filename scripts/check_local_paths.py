#!/usr/bin/env python3
"""Local-path hygiene check for a public release of this repository.

A published repository must not ship absolute paths from the machine it was
developed on: the checkout directory the author cloned into, the author's user
profile directory, or installer directories such as a Ghidra / Frida install.
Those strings leak the author's filesystem layout, are meaningless to every
reader, and reappear whenever a live run writes a new crash report or probe
dump.

This script is the repository's *repeatable* version of "grep the whole tree for
absolute paths", so the check can be re-run after every experiment:

* **error** -- a path this tool knows how to redact: the checkout directory
  (see ``EXTRA_PROJECT_NAMES``), user profile directories, and the Ghidra /
  ghidra-mcp / Frida install directories. ``--fix`` rewrites them to a portable
  placeholder (``/path/to/workspace`` and friends); tail separators are
  normalised to ``/`` so the rewrite stays valid inside JSON, Markdown and
  Python string literals alike.
* **warning** -- any other drive-letter path. Synthetic fixtures such as a
  made-up ``parser.exe`` location leak nothing, so they are listed but do not
  fail the run unless ``--strict`` is passed.
* **info** -- binary artifacts (``.exe``, ``.png``, ...) are scanned read-only;
  a compiled binary can embed its build directory in debug info, which is
  reported but never rewritten (patching debug data would corrupt the file).
  Build such targets with ``-fdebug-prefix-map`` (GCC/Clang) or
  ``-pathmap`` (MSVC) to keep the debug info path-independent.

Exit codes: 0 = clean (or warnings without --strict), 1 = errors found
(``--strict``: warnings count too), 2 = the scan itself failed.

Usage:
    python scripts/check_local_paths.py            # audit, read-only
    python scripts/check_local_paths.py --fix      # redact in place
    python scripts/check_local_paths.py --strict   # warnings are errors too
    python scripts/check_local_paths.py --root DIR # scan another checkout
"""

from __future__ import annotations

import argparse
import re
import sys
from dataclasses import dataclass, field
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent

#: Portable placeholder every redacted path is rewritten to.
PLACEHOLDER = "/path/to/workspace"

#: Directories that never hold authored content.
SKIP_DIRS = frozenset(
    {".git", ".idea", ".mypy_cache", ".pytest_cache", ".ruff_cache", ".venv",
     ".vscode", "__pycache__", "build", "dist", "node_modules", "venv"}
)

#: Files that legitimately hold this machine's own paths and are git-ignored, so
#: they are never published: skipped by the audit (never counted as findings).
LOCAL_ONLY_FILES = ("config/local.json",)

#: Suffixes scanned as bytes (reported, never rewritten).
BINARY_SUFFIXES = frozenset({".dll", ".exe", ".jpg", ".pdf", ".pkl", ".png", ".pyd", ".so", ".zip"})

#: Extra names for the project root, e.g. an older checkout directory. Add the
#: directory name(s) you cloned into if the repository name is not enough, so a
#: stale path from a previous checkout is caught too.
EXTRA_PROJECT_NAMES: tuple[str, ...] = ()

#: One path element: anything but a separator, whitespace or string/quotes.
_ELEMENT = r"[^\\/\s\"'`|;,)\]}]*"
#: The remainder of a path (separator + element), repeated.
_TAIL = rf"(?:[\\/]+{_ELEMENT})*"


def _rules(project_names: tuple[str, ...]) -> tuple[tuple[str, re.Pattern[str], str], ...]:
    """(label, pattern, replacement) triples, applied in order."""
    roots = "|".join(re.escape(name) for name in sorted(set(project_names), key=len, reverse=True))
    return (
        ("project-root", re.compile(rf"[A-Za-z]:[\\/]+(?:{roots})(?P<tail>{_TAIL})"), PLACEHOLDER),
        ("user-profile",
         re.compile(rf"[A-Za-z]:[\\/]+Users[\\/]+{_ELEMENT}(?P<tail>{_TAIL})"), "/path/to/home"),
        ("ghidra-mcp", re.compile(rf"[A-Za-z]:[\\/]+ghidra-mcp(?P<tail>{_TAIL})"), "/path/to/ghidra-mcp"),
        ("ghidra", re.compile(rf"[A-Za-z]:[\\/]+ghidra[_\-]{_ELEMENT}(?P<tail>{_TAIL})"), "/path/to/ghidra"),
        ("frida", re.compile(rf"[A-Za-z]:[\\/]+frida(?P<tail>{_TAIL})"), "/path/to/frida"),
    )


#: Any remaining drive-letter path: reported as a warning, never rewritten.
#: The lookbehind keeps URL schemes (``http://``, ``file:/``) out of the report.
ABSOLUTE_RE = re.compile(rf"(?<![A-Za-z0-9:])[A-Za-z]:[\\/]+{_ELEMENT}")
#: The same thing inside a binary artifact.
BINARY_ABS_RE = re.compile(rb"(?<![A-Za-z0-9:])[A-Za-z]:[\\/]+[ -~]{3,90}")


def _to_posix(tail: str) -> str:
    """``\\a\\b`` -> ``/a/b`` so a rewrite is portable in every file format."""
    return re.sub(r"[\\/]+", "/", tail)


def apply_rules(text: str, rules: tuple[tuple[str, re.Pattern[str], str], ...]) -> tuple[str, dict[str, int]]:
    """Rewrite every redactable path in ``text``; return the new text and hit counts."""
    hits: dict[str, int] = {}
    for label, pattern, replacement in rules:

        def _sub(match: re.Match[str], _label: str = label, _repl: str = replacement) -> str:
            hits[_label] = hits.get(_label, 0) + 1
            return _repl + _to_posix(match.group("tail"))

        text = pattern.sub(_sub, text)
    return text, hits


@dataclass
class FileReport:
    """Audit result for one file (text file or binary artifact)."""

    path: Path
    errors: dict[str, int] = field(default_factory=dict)
    warnings: list[str] = field(default_factory=list)
    binary_leaks: list[str] = field(default_factory=list)
    binary_other: int = 0
    changed: bool = False

    @property
    def error_total(self) -> int:
        return sum(self.errors.values())

    @property
    def warning_total(self) -> int:
        return len(self.warnings) + len(self.binary_leaks)


def _iter_files(root: Path, skip: frozenset[Path]) -> list[Path]:
    """Every candidate file under ``root``, skipping build/tooling directories."""
    found: list[Path] = []
    for path in sorted(root.rglob("*")):
        if not path.is_file() or path in skip:
            continue
        if any(part in SKIP_DIRS for part in path.relative_to(root).parts):
            continue
        found.append(path)
    return found


def scan_text(
    path: Path,
    rules: tuple[tuple[str, re.Pattern[str], str], ...],
    *,
    fix: bool,
) -> FileReport:
    """Audit (and optionally redact) one text file, byte-exact about line endings."""
    report = FileReport(path=path)
    try:
        raw = path.read_bytes()
    except OSError:
        return report
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError:
        report.binary_other = 1  # not text after all: the caller treats it as binary
        return report

    redacted, hits = apply_rules(text, rules)
    report.errors = hits
    report.warnings = list(dict.fromkeys(m.group(0) for m in ABSOLUTE_RE.finditer(redacted)))
    if fix and hits and redacted != text:
        path.write_bytes(redacted.encode("utf-8"))
        report.changed = True
    return report


def scan_binary(path: Path, project_names: tuple[str, ...]) -> FileReport:
    """Read-only scan of a binary artifact (debug info can embed the build dir)."""
    report = FileReport(path=path)
    try:
        blob = path.read_bytes()
    except OSError:
        return report
    leaks: set[str] = set()
    other = 0
    for raw in {m.group(0) for m in BINARY_ABS_RE.finditer(blob)}:
        text = raw.decode("latin-1")
        if any(name in text for name in project_names):
            leaks.add(text)
        else:
            other += 1
    report.binary_leaks = sorted(leaks)
    report.binary_other = other
    return report


def _relative(path: Path, root: Path) -> str:
    try:
        return path.relative_to(root).as_posix()
    except ValueError:
        return str(path)


def _print_report(
    reports: list[FileReport],
    root: Path,
    rules: tuple[tuple[str, re.Pattern[str], str], ...],
    *,
    fix: bool,
    strict: bool,
) -> int:
    """Render the audit and return the exit code."""
    placeholders = {label: replacement for label, _pattern, replacement in rules}
    errors = [r for r in reports if r.error_total]
    warnings = [r for r in reports if r.warnings]
    binaries = [r for r in reports if r.binary_leaks or r.binary_other]

    print("local-path hygiene audit")
    print(f"  root : {root}")
    print(f"  mode : {'--fix (rewriting)' if fix else 'audit (read-only)'}"
          f"{' --strict' if strict else ''}")
    for name in LOCAL_ONLY_FILES:
        if (root / name).is_file():
            print(f"  skip : {name} (machine-local overlay, git-ignored by design)")
    print()

    print(f"ERRORS  redactable absolute paths ({len(errors)} file(s), "
          f"{sum(r.error_total for r in errors)} hit(s))")
    if not errors:
        print("  none")
    for report in errors:
        counts = ", ".join(f"{label} x{count}" for label, count in sorted(report.errors.items()))
        targets = ", ".join(sorted({placeholders[label] for label in report.errors}))
        action = " -> redacted" if report.changed else f" -> {targets}"
        print(f"  {_relative(report.path, root)}: {counts}{action}")
    print()

    shown = 0
    leftover = 0
    print("WARNINGS  other absolute paths (synthetic fixtures are harmless)")
    if not warnings and not binaries:
        print("  none")
    for report in warnings:
        for sample in report.warnings:
            if shown >= 40:
                leftover += 1
                continue
            print(f"  {_relative(report.path, root)}: {sample}")
            shown += 1
    for report in binaries:
        leaks = ", ".join(report.binary_leaks)
        detail = f"build-path leak(s): {leaks}" if leaks else "clean"
        if report.binary_other and not leaks:
            detail = f"clean (toolchain paths only: {report.binary_other})"
        if shown >= 40:
            leftover += 1
            continue
        print(f"  {_relative(report.path, root)}: {detail}")
        shown += 1
    if leftover:
        print(f"  ... {leftover} more")
    if strict and (warnings or binaries):
        print("  --strict: the entries above fail this run")
    print()

    unfixed = [r for r in errors if not r.changed]
    text_errors = sum(r.error_total for r in errors)
    fixed_files = [r for r in errors if r.changed]
    failed = bool(unfixed) if fix else bool(errors)
    if strict and (warnings or binaries):
        failed = True

    if fix:
        print(f"summary: redacted {sum(r.error_total for r in fixed_files)} path(s) in "
              f"{len(fixed_files)} file(s), {len(warnings)} file(s) with warnings, "
              f"{len(binaries)} binary artifact(s)")
        if unfixed:
            print("next   : some hits could not be rewritten - see the ERRORS list")
        else:
            print("status : re-run without --fix to verify the audit is clean")
    else:
        print(f"summary: {text_errors} error(s) in {len(errors)} file(s), "
              f"{len(warnings)} file(s) with warnings, {len(binaries)} binary artifact(s)")
        if errors:
            print("next   : python scripts/check_local_paths.py --fix")
        elif failed:
            print("next   : review the warnings above, or drop --strict")
        else:
            print("status : OK - no local paths to redact")
    return 1 if failed else 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Audit this repository for leaked local paths.")
    parser.add_argument("--root", default=str(REPO_ROOT), help="checkout to scan (default: repo root)")
    parser.add_argument("--fix", action="store_true", help="redact redactable paths in place")
    parser.add_argument("--strict", action="store_true", help="exit 1 on warnings as well")
    parser.add_argument("--extra-project-name", action="append", default=[],
                        help="additional checkout directory name to redact (repeatable)")
    args = parser.parse_args(argv)

    root = Path(args.root).resolve()
    if not root.is_dir():
        print(f"[ERROR] not a directory: {root}", file=sys.stderr)
        return 2

    names = tuple(dict.fromkeys((root.name, *EXTRA_PROJECT_NAMES, *args.extra_project_name)))
    rules = _rules(names)

    try:
        reports = []
        local_only = {(root / name).resolve() for name in LOCAL_ONLY_FILES}
        for path in _iter_files(root, frozenset(local_only)):
            if path.suffix.lower() in BINARY_SUFFIXES:
                reports.append(scan_binary(path, names))
                continue
            report = scan_text(path, rules, fix=args.fix)
            if report.binary_other:  # undecodable file (a binary without a known suffix)
                reports.append(scan_binary(path, names))
            else:
                reports.append(report)
    except OSError as exc:
        print(f"[ERROR] scan failed: {exc}", file=sys.stderr)
        return 2

    return _print_report(reports, root, rules, fix=args.fix, strict=args.strict)


if __name__ == "__main__":
    raise SystemExit(main())
