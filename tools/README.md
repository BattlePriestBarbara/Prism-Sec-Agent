# tools/ — the implementations behind the docs

Everything here is a **sanitized copy** of the tooling used for the workflow described in
`../docs/`. It is published as a working reference, not as a turnkey product: machine-specific
values were replaced by placeholders, and application/vendor identifiers by role names.

## Placeholder vocabulary

These strings appear in defaults, comments and command examples. Replace them before running
anything (or pass the real values on the command line / through environment variables).

| Placeholder | Means |
| --- | --- |
| `<WORK_DIR>` | the per-target analysis workspace (holds the sample, the Ghidra projects and the output) |
| `<SAMPLE_APK>` / `<SAMPLE_ZIP>` | the original APK (or a copy with a `.zip` extension) |
| `<SAMPLE_DIR>` | the APK unzipped for static work |
| `<OUT_DIR>` | analysis output: JSON evidence, decompiled C, smali, reports |
| `<PROJECTS_DIR>` | the Ghidra project store |
| `<TOOLS_DIR>` | this directory |
| `<GHIDRA_MCP_ROOT>` | checkout of the Ghidra MCP server |
| `<GHIDRA_INSTALL>` | the Ghidra installation |
| `<JDK_HOME>` | a JDK >= 21 |
| `<FRIDA_ROOT>` | the Frida environment (venv + platform-tools + server binaries) |
| `<PYTHON_EXE>` | the interpreter of the relevant virtual environment |
| `<EMULATOR_HOME>` | the Android emulator installation |
| `<SERIAL>` | one adb device serial |
| `<PACKAGE>` | the target package name (`com.example.targetapp` is the shipped placeholder) |
| `com.example.shell.ShellStub` | placeholder for the packer's stub entry class |
| `libshell*` | role name for the packer shell's own loader/decoy libraries (e.g. `libshell.so`, `libshell_*_enc.so`) — the vendor's real file names are not reproduced |
| `<TARGET_PIPELINE>` | the identifier of a pipeline whose default project name is `apk_arm64` |

Environment variables understood by the Ghidra-side scripts:
`GHIDRA_MCP_ROOT`, `GHIDRA_MCP_INSTALL_DIR`, `GHIDRA_MCP_JAVA_HOME` (same names as the MCP
configuration, so one set of values drives both).

What is deliberately **not** anonymised: the analysis tooling keeps its real product names —
Ghidra, PyGhidra, Frida/frida-server, Android platform-tools and the Android emulator used for
the dynamic pass (`ld_*.py`, `ld_*.cmd`, `ld_start_frida.sh`). That is public software the
reader installs anyway, and naming it is documentation rather than leakage. Only the *target*
was rewritten; where the originals hard-coded one sample's own artefact names (a decoy folder
name, a fixed list of packed loader libraries), the published scripts discover those
containers at run time instead — see `ghidra/payload_probe.py`.

## `ghidra/` — static side

| Script | What it does |
| --- | --- |
| `triage_elf.py` | Dependency-free ELF triage: ABI, type, entry, soname, needed libraries, `.comment` banner, stripped?, export counts and names. Run it *before* Ghidra. |
| `ghidra_batch.py` | Batch import + auto-analyse + evidence extraction through the same tools the MCP server exposes. Per-binary JSON, resumable. |
| `decompile_named.py` | Decompiles only the functions whose names match given substrings; the answer to "the automatic ranking keeps giving me library helpers". |
| `jni_surface.py` | Splits libraries into "has static `Java_*` exports" vs "RegisterNatives-only" and writes a JSON summary you use to aim the JNI hook. |
| `apk_zip_probe.py` | Decides whether a zip is the untouched original APK (APK Signing Block present) or a re-zipped tree (v1 only). |
| `dex_probe.py` | DEX structural probe: header counts, class list, packer marker bytes, whether the file is really a stub. |
| `payload_probe.py` | Inspects suspicious containers (stub DEX, `*_enc.so`, 1-byte assets) and reports header, size and block entropy. `--list` shows what it discovered; `--root`/`--target` override it. |
| `requery_strings.py` | Re-queries an analysed program for a string subset without re-running analysis. |
| `decode_shell_strings.py` | XOR-decodes obfuscated string literals out of baksmali output once the stub's key is recovered. |
| `DexSmali.java` | Tiny wrapper that invokes the smali disassembler bundled with Ghidra's file-format libraries (DEX -> smali with no extra download). |
| `ld_config_probe.py` | Extracts emulator instance-config key names from the player binary (they are not documented anywhere else). |
| `ld_set_root.py` | Flips emulator config keys with a text insert + backup, so the emulator's own parser keeps working. |

## `frida/` — dynamic side

| File | What it does |
| --- | --- |
| `dump_dex.py` | The driver every hook runs through: attach/spawn, load a JS file, stream blobs to the host, validate and name them. `--seconds` for non-interactive runs. |
| `check_setup.py` | Self-check: Python/Frida versions, console scripts, extracted server binaries, device reachability. |
| `unpack_servers.py` | Verifies and extracts the `.xz` frida-server archives (Windows has no xz tool; Python's `lzma` does). |
| `fetch_frida_asset.py` | Downloads a frida-server or frida-gadget build for a given ABI. |
| `env.cmd` / `frida.cmd` | Put the Frida venv and platform-tools on `PATH`; thin CLI wrapper. |
| `ld_start_frida.sh` | Device-side launcher for frida-server, pushed and run under `su` (avoids the quoting layers of `adb shell`). **Must keep LF newlines.** |
| `ld_frida_start.cmd` | Host-side orchestration: push, run, verify the link. |
| `hooks/api_probe.js` | Prints the GumJS API surface the hooks depend on — run after every Frida upgrade. |
| `hooks/anti_debug_probe.js` | Recon only: records which detection APIs the app/packer calls. Never alters behaviour. |
| `hooks/arm_hook_probe.js` | Reports which of the app's own modules are mapped, from which ABI, whether they export `JNI_OnLoad`, and whether instrumentation can reach them. |
| `hooks/dump_dex.js` | Memory scan for the DEX magic, streams what it finds to the host. |
| `hooks/dump_dex_art.js` | Hooks the runtime's own DEX openers (buffer + size), no scanning required. |
| `hooks/dump_dex_write.js` | Watches libc `write`/`pwrite`/`writev` and `open`/`openat` for plaintext DEX at the syscall boundary. |
| `hooks/trace_native.js` | Symbol-driven argument/return tracer for the entry points identified statically, plus a `dlopen` watcher for lazily loaded libraries. |
| `hooks/jni_boundary.js` | Traces the Java <-> native boundary without a Java bridge, by calling the JNI environment table by index and hooking `RegisterNatives`. |

## Notes before you run anything

* **Defaults are placeholders.** Anything left as `<...>` must be filled in, or overridden on the
  command line. `python tools/ghidra/triage_elf.py --help` shows the parameters.
* **Two interpreters.** Ghidra-side scripts need PyGhidra/jpype; Frida-side scripts need the
  `frida` package. They are deliberately separate environments (doc 01), and each side ships
  its own manifest: `ghidra/requirements.txt` and `frida/requirements.txt`. Every probe that
  does not drive Ghidra or Frida is stdlib-only on purpose, so it runs anywhere.
* **Hook scripts are templates.** Symbol lists, module focus/deny lists and the stub class name
  point at the *class* of target described in the docs; edit them for your own sample. That is
  why they contain `com.example.targetapp`, `libtransport.so` and similar placeholders.
* **Sanitization policy** (what was removed and why) is in `../docs/06-limitations-and-scope.md`,
  §5. Paths, application/package identity, SDK brands and hashes are gone; logic, numbers and
  outcomes are unchanged.

## Sanity checks

```powershell
# every Python file must compile (no third-party imports are needed for a syntax check)
Get-ChildItem -Recurse -Filter *.py <TOOLS_DIR> | ForEach-Object { python -m py_compile $_.FullName }

# every hook must parse (Frida's runtime is not needed for a syntax check)
Get-ChildItem -Recurse -Filter *.js <TOOLS_DIR> | ForEach-Object { node --check $_.FullName }

# no local paths / machine-specific values left behind
python <TOOLS_DIR>\..\scripts\check_local_paths.py --root <TOOLS_DIR>\..
```

Two scripts are meant to be edited before use and will report misleading results until you do:
`ghidra/dex_probe.py` (its marker byte sequences) and `ghidra/decode_shell_strings.py` (its
`HINTS` list). Everything else takes its sample-specific values from arguments.

The JavaScript hooks follow the same conventions as the originals: feature-detect the Frida 17
API changes instead of assuming them, never abort the whole script because the Java bridge is
missing, and print rather than patch unless a script is explicitly a "probe".
