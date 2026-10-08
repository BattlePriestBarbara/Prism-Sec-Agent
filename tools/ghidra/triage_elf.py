"""Triage every ELF (Android .so) shipped in the unpacked APK at <SAMPLE_DIR>.

Pure-Python (no third-party deps): reads the ELF header, section headers, dynamic
section, dynamic symbol table and .comment so we can answer "which native library is
which, is it stripped, what does it need, where did it come from" BEFORE spending
Ghidra time on it.

    python triage_elf.py [--root <SAMPLE_DIR>] [-o <OUT_DIR>/elf_triage.json]
"""
from __future__ import annotations

import argparse
import hashlib
import json
import struct
from pathlib import Path

EM = {
    0x03: "x86", 0x08: "MIPS", 0x28: "ARM(32)", 0x3E: "x86-64", 0x8C: "MIPS64",
    0xB7: "AArch64(ARM64)", 0xF3: "RISC-V",
}
ETYPE = {1: "REL", 2: "EXEC", 3: "DYN(shared object / PIE)", 4: "CORE"}
STB = {0: "LOCAL", 1: "GLOBAL", 2: "WEAK"}
STT = {0: "NOTYPE", 1: "OBJECT", 2: "FUNC", 3: "SECTION", 4: "FILE", 5: "COMMON",
       6: "TLS"}


def cstr(blob: bytes, off: int) -> str:
    end = blob.find(b"\x00", off)
    if end < 0:
        end = len(blob)
    return blob[off:end].decode("utf-8", "replace")


class Elf:
    def __init__(self, raw: bytes):
        self.raw = raw
        if raw[:4] != b"\x7fELF":
            raise ValueError("not an ELF file")
        self.is64 = raw[4] == 2
        self.endian = "<" if raw[5] == 1 else ">"
        self.machine = struct.unpack_from(self.endian + "H", raw, 18)[0]
        self.etype = struct.unpack_from(self.endian + "H", raw, 16)[0]
        if self.is64:
            (self.entry, self.phoff, self.shoff, _flags, self.ehsize,
             self.phentsize, self.phnum, self.shentsize, self.shnum,
             self.shstrndx) = struct.unpack_from(self.endian + "QQQIHHHHHH", raw, 24)
        else:
            (self.entry, self.phoff, self.shoff, _flags, self.ehsize,
             self.phentsize, self.phnum, self.shentsize, self.shnum,
             self.shstrndx) = struct.unpack_from(self.endian + "IIIIHHHHHH", raw, 24)
        self.sections: list[dict] = []
        self._read_sections()
        self.dynamic: list[tuple[int, int]] = []
        self.needed: list[str] = []
        self.soname: str | None = None
        self.rpath: str | None = None
        self.dynsyms: list[dict] = []
        self._read_dynamic()
        self._read_dynsyms()

    # -- sections ---------------------------------------------------------
    def _read_sections(self) -> None:
        for index in range(self.shnum):
            off = self.shoff + index * self.shentsize
            if off + self.shentsize > len(self.raw):
                break
            if self.is64:
                name, stype, flags, addr, offset, size, link, info, align, entsize = \
                    struct.unpack_from(self.endian + "IIQQQQIIQQ", self.raw, off)
            else:
                name, stype, flags, addr, offset, size, link, info, align, entsize = \
                    struct.unpack_from(self.endian + "IIIIIIIIII", self.raw, off)
            self.sections.append({"name_idx": name, "type": stype, "flags": flags,
                                  "addr": addr, "offset": offset, "size": size,
                                  "link": link, "info": info, "entsize": entsize,
                                  "index": index})

        shstr_off = shstr_size = 0
        if 0 <= self.shstrndx < len(self.sections):
            shstr_off = self.sections[self.shstrndx]["offset"]
            shstr_size = self.sections[self.shstrndx]["size"]
        shstr = self.raw[shstr_off:shstr_off + shstr_size]
        for section in self.sections:
            section["name"] = cstr(shstr, section["name_idx"]) if shstr else ""
        self.by_name = {section["name"]: section for section in self.sections}

    # -- dynamic ----------------------------------------------------------
    def _read_dynamic(self) -> None:
        dynamic = self.by_name.get(".dynamic")
        if not dynamic:
            return
        strtab = self.by_name.get(".dynstr")
        dynstr = self.raw[strtab["offset"]:strtab["offset"] + strtab["size"]] \
            if strtab else b""
        step = 16 if self.is64 else 8
        fmt = self.endian + ("QQ" if self.is64 else "II")
        for off in range(dynamic["offset"], dynamic["offset"] + dynamic["size"], step):
            tag, val = struct.unpack_from(fmt, self.raw, off)
            self.dynamic.append((tag, val))
            if tag == 0:
                break
            if tag == 1 and dynstr:
                self.needed.append(cstr(dynstr, val))
            elif tag == 14 and dynstr:
                self.soname = cstr(dynstr, val)
            elif tag in (15, 29) and dynstr:
                self.rpath = cstr(dynstr, val)

    def _read_dynsyms(self) -> None:
        symtab = self.by_name.get(".dynsym")
        strtab = self.by_name.get(".dynstr")
        if not symtab or not strtab:
            return
        dynstr = self.raw[strtab["offset"]:strtab["offset"] + strtab["size"]]
        step = symtab["entsize"] or (24 if self.is64 else 16)
        count = symtab["size"] // step if step else 0
        for index in range(count):
            off = symtab["offset"] + index * step
            if self.is64:
                name, info, other, shndx, value, size = struct.unpack_from(
                    self.endian + "IBBHQQ", self.raw, off)
            else:
                name, value, size, info, other, shndx = struct.unpack_from(
                    self.endian + "IIIBBH", self.raw, off)
            bind, stype = info >> 4, info & 0xF
            self.dynsyms.append({
                "index": index, "name": cstr(dynstr, name) if name else "",
                "bind": STB.get(bind, str(bind)), "type": STT.get(stype, str(stype)),
                "defined": shndx != 0, "value": value, "size": size,
            })


def comment_text(elf: Elf) -> str | None:
    """Version banner left in .comment (compiler + NDK/IDE generation)."""
    section = elf.by_name.get(".comment")
    if not section:
        return None
    blob = elf.raw[section["offset"]:section["offset"] + section["size"]]
    parts = [p for p in blob.split(b"\x00") if p]
    return "; ".join(p.decode("utf-8", "replace") for p in parts)


def triage(path: Path) -> dict:
    raw = path.read_bytes()
    record: dict = {"path": str(path), "size_bytes": len(raw),
                    "md5": hashlib.md5(raw).hexdigest(),
                    "sha256": hashlib.sha256(raw).hexdigest()}
    try:
        elf = Elf(raw)
    except ValueError as exc:
        record["error"] = str(exc)
        return record

    defined = [s for s in elf.dynsyms if s["defined"] and s["name"]]
    exported_funcs = [s for s in defined if s["type"] == "FUNC"]
    imported = [s for s in elf.dynsyms if not s["defined"] and s["name"]]
    section_names = [s["name"] for s in elf.sections if s["name"]]

    record.update({
        "class": "ELF64" if elf.is64 else "ELF32",
        "endianness": "little" if elf.endian == "<" else "big",
        "machine": EM.get(elf.machine, hex(elf.machine)),
        "type": ETYPE.get(elf.etype, str(elf.etype)),
        "entry": hex(elf.entry),
        "soname": elf.soname,
        "rpath": elf.rpath,
        "needed": elf.needed,
        "comment": comment_text(elf),
        "stripped": ".symtab" not in elf.by_name,
        "has_debug_info": any(n.startswith(".debug") for n in section_names),
        "section_count": len(section_names),
        "section_names": section_names,
        "exported_symbol_count": len(defined),
        "exported_function_count": len(exported_funcs),
        "exported_symbols": [s["name"] for s in defined][:4000],
        "imported_symbol_count": len([s for s in imported if s["type"] == "FUNC"]),
        "imported_functions": sorted({s["name"] for s in imported if s["type"] == "FUNC"}),
        "bind_now": any(tag == 24 for tag, _ in elf.dynamic),
    })
    return record


def main() -> int:
    parser = argparse.ArgumentParser(description="ELF triage for the unpacked APK.")
    parser.add_argument("--root", default=r"<SAMPLE_DIR>")
    parser.add_argument("-o", "--output", default=r"<OUT_DIR>/elf_triage.json")
    args = parser.parse_args()

    root = Path(args.root)
    targets = sorted({*root.rglob("*.so"), *root.rglob("*.a")})
    records = []
    for path in targets:
        record = triage(path)
        records.append(record)
        rel = str(path.relative_to(root))
        if "error" in record:
            print(f"[!] {rel}: {record['error']}")
        else:
            print(f"[+] {rel:<46} {record['machine']:<15} "
                  f"funcs={record['exported_function_count']:<5} "
                  f"stripped={str(record['stripped']):<5} needed={len(record['needed'])}")

    print()
    for record in records:
        if "error" in record:
            continue
        print(f"--- {Path(record['path']).name}  soname={record['soname']}")
        print(f"    comment : {record['comment']}")
        print(f"    needed  : {record['needed']}")

    output = Path(args.output)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps({"root": str(root), "count": len(records),
                                  "files": records}, indent=2, ensure_ascii=False),
                      encoding="utf-8")
    print(f"\n[=] wrote {output} ({len(records)} files)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
