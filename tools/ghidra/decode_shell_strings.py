"""Decodes the commercial packer stub's obfuscated string literals from baksmali output.

The stub's Java layer decrypts its own const-strings with a per-character XOR 0x10
(found at `a.a(String)` in `a.smali`: `xor-int/lit8 v2, v2, 0x10`), so every obfuscated
literal can be recovered statically - no device and no Ghidra needed.

    python decode_shell_strings.py --smali <OUT_DIR>\\smali_stub `
        [-o <OUT_DIR>\\smali_stub\\decoded_strings.txt] [--key 0x10]
"""
from __future__ import annotations

import argparse
import re
from pathlib import Path

#: Substrings that make a decoded value obviously a real identifier/path/type.
HINTS = ("com.", "/data", "Landroid", "Ljava", "Lcom/", "android.", "java.",
         "/system", "libshell", "dtc", "ActivityThread", "Instrumentation",
         "ClassLoader", "DexFile", "assets", "lib/", ".so", "ro.", "getprop",
         "package", "signature", "cert", "isRoot", "xposed", "frida")


def unescape_smali(value: str) -> str:
    """baksmali escapes non-printable chars as \\uXXXX / \\n etc. - undo that first."""
    out: list[str] = []
    index = 0
    simple = {"n": "\n", "t": "\t", "r": "\r", "b": "\b", "f": "\f",
              '"': '"', "'": "'", "\\": "\\"}
    while index < len(value):
        char = value[index]
        if char == "\\" and index + 1 < len(value):
            nxt = value[index + 1]
            if nxt == "u" and index + 5 < len(value):
                try:
                    out.append(chr(int(value[index + 2:index + 6], 16)))
                    index += 6
                    continue
                except ValueError:
                    pass
            elif nxt in simple:
                out.append(simple[nxt])
                index += 2
                continue
        out.append(char)
        index += 1
    return "".join(out)


def decode(value: str, key: int) -> str:
    return "".join(chr(ord(ch) ^ key) for ch in value)


def looks_real(text: str) -> bool:
    if not text or not all(32 <= ord(ch) < 127 for ch in text):
        return False
    if any(hint in text for hint in HINTS):
        return True
    # identifier-shaped: only [A-Za-z0-9_$./:;<>\-()] and at least two words
    return bool(re.fullmatch(r"[A-Za-z0-9_$./:;<>\-()\[\]]{4,}", text)) and \
        len(re.findall(r"[A-Za-z]{3,}", text)) >= 2


def main() -> int:
    parser = argparse.ArgumentParser(description="Decode shell stub string literals.")
    parser.add_argument("--smali", default=r"<OUT_DIR>\smali_stub")
    parser.add_argument("--key", default="0x10")
    parser.add_argument("-o", "--output",
                        default=r"<OUT_DIR>\smali_stub\decoded_strings.txt")
    args = parser.parse_args()

    key = int(args.key, 16) if args.key.lower().startswith("0x") else int(args.key)
    root = Path(args.smali)
    pattern = re.compile(r'const-string(?:/jumbo)?\s+\w+,\s+"(.*)"\s*$')

    per_file: dict[str, list[tuple[str, str]]] = {}
    for smali in sorted(root.rglob("*.smali")):
        entries: list[tuple[str, str]] = []
        for line in smali.read_text(encoding="utf-8", errors="replace").splitlines():
            match = pattern.search(line.strip())
            if not match:
                continue
            cipher = unescape_smali(match.group(1))
            if cipher.startswith('"') and cipher.endswith('"'):
                cipher = cipher[1:-1]
            plain = decode(cipher, key)
            if looks_real(plain) and plain != cipher:
                entries.append((cipher, plain))
        if entries:
            per_file[smali.relative_to(root).as_posix()] = entries

    out_lines = [f"# shell stub strings decoded with XOR 0x{key:02x}", ""]
    total = 0
    for name, entries in per_file.items():
        out_lines.append(f"## {name}  ({len(entries)} strings)")
        for cipher, plain in entries:
            out_lines.append(f"  {cipher!r}  ->  {plain!r}")
            total += 1
        out_lines.append("")

    output = Path(args.output)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text("\n".join(out_lines), encoding="utf-8")
    print("\n".join(out_lines[:40]))
    print(f"...\n[=] decoded {total} strings from {len(per_file)} smali files -> {output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
