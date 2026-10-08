# 01 — Environment setup

Everything below was assembled and verified on a single Windows workstation. Version
numbers are the ones that were actually exercised; the counts matter more than the exact
releases.

## 1. Host prerequisites

| Component | Version used | Why it is needed |
| --- | --- | --- |
| Ghidra | 12.1.3 PUBLIC | Disassembly, decompilation, project store |
| JDK | Temurin 25 (any JDK >= 21 works) | Ghidra 12 refuses to start on JDK 8/16 — the machine default was too old, so the MCP server gets a dedicated `JAVA_HOME` |
| PyGhidra | 3.1.0 (+ jpype 1.5.2) | In-process JVM from Python; ships as wheels inside the Ghidra install |
| Python | 3.12 | MCP server, probe/batch tooling |
| MCP SDK | 2.2.0 (`mcp.server.mcpserver`) | Typed tools over stdio for the assistant |
| Frida (Python binding + CLI) | 17.18.0 | Dynamic instrumentation of the target process |
| frida-server | 17.18.0, `android-x86_64` + `android-arm64` | On-device agent; **must match the CLI version exactly** |
| Android platform-tools | adb 1.0.41 / 37.0.1 | Device transport, package install, `su` shell |
| Android environment | emulator (x86_64, Android 9 / API 28, rooted) or a rooted arm64 device | Where the app and frida-server actually run |

Layout used throughout this repository (placeholders are defined in the top-level README):

```
<WORK_DIR>/            analysis workspace for one target
  <SAMPLE_APK>         the (untouched) original APK
  <SAMPLE_DIR>/        APK unzipped for static work
  <PROJECTS_DIR>/      Ghidra project store
  <OUT_DIR>/           analysis output: JSON, decompiled C, smali, report
<GHIDRA_MCP_ROOT>/     the Ghidra MCP server checkout
<FRIDA_ROOT>/          frida venv + platform-tools + server binaries
<EMULATOR_HOME>/       the Android emulator installation
```

## 2. Gotchas that cost real time

* **Keep the whole toolchain on an ASCII path.** PyGhidra/JVM start-up fails or misbehaves
  when the checkout lives under a non-ASCII path. The virtual environments are also
  machine-local (they embed absolute interpreter paths), so rebuild rather than copy them.
* **Two Python environments, deliberately isolated.** The Ghidra side needs PyGhidra +
  jpype; the Frida side needs the `frida`/`frida-tools` pair. Installing both into one
  interpreter invites version conflicts, so each side has its own venv.
* **Ghidra's bundled wheels work offline.** PyGhidra can be installed from the wheels that
  ship inside the Ghidra install (`Features/PyGhidra/pypkg/dist`), which avoids a slow or
  blocked PyPI route.
* **frida-server version = frida CLI version.** A mismatch shows up as
  `unable to communicate with remote frida-server`, which reads like a network problem and
  is not.

## 3. MCP wiring (Ghidra as tools)

The assistant talks to Ghidra over MCP, not over a GUI. The server is a small stdio
process; the assistant's settings file holds one entry per server:

```json
{
  "mcpServers": {
    "ghidra": {
      "command": "<PYTHON_EXE>",
      "args": ["<GHIDRA_MCP_ROOT>/server.py"],
      "env": {
        "GHIDRA_MCP_INSTALL_DIR": "<GHIDRA_INSTALL>",
        "GHIDRA_MCP_JAVA_HOME": "<JDK_HOME>",
        "GHIDRA_MCP_PROJECTS": "<GHIDRA_MCP_ROOT>/projects",
        "PYTHONIOENCODING": "utf-8",
        "PYTHONUNBUFFERED": "1"
      },
      "timeout": 900
    }
  }
}
```

A ready-to-edit copy lives in `config/cline_mcp_settings.example.json`.

Notes on the three environment variables: `GHIDRA_MCP_INSTALL_DIR` points at the Ghidra
install, `GHIDRA_MCP_JAVA_HOME` overrides a too-old system JDK for the JVM that PyGhidra
starts, and `GHIDRA_MCP_PROJECTS` keeps the project store out of the Ghidra installation
so analysed programs survive a server restart.

Two more fields are worth understanding before you copy the file:

* `timeout` is generous (900 s) because importing and auto-analysing a large binary is a
  multi-minute operation that must not be cut off mid-analysis.
* `autoApprove` lists the *read-only* tools; anything that mutates state (import/analyse,
  close program) is intentionally left out so it always needs an explicit approval.

## 4. Verifying the stack before trusting it

```powershell
# Ghidra side: environment report (JSON) + the tool list the assistant will see
& <PYTHON_EXE> <GHIDRA_MCP_ROOT>/server.py --check
& <PYTHON_EXE> <GHIDRA_MCP_ROOT>/server.py --tools

# Frida side: versions, console scripts, extracted server binaries, device state
& <FRIDA_ROOT>/.venv/Scripts/python.exe <FRIDA_ROOT>/check_setup.py
& <FRIDA_ROOT>/.venv/Scripts/python.exe <FRIDA_ROOT>/unpack_servers.py
```

`--check` exits non-zero when it finds a non-ASCII path problem, so it doubles as a
pre-flight gate. `unpack_servers.py` exists because frida-server ships as `.xz` and
Windows has no built-in xz tool; Python's `lzma` module handles it.

## 5. Device side

**Push and start frida-server** (root required; the `su` flavour on the emulator needs the
`su -c '...'` form — a bare `su <cmd>` is parsed as a user name):

```powershell
adb -s <SERIAL> push <FRIDA_ROOT>/server/frida-server-17.18.0-android-x86_64 /data/local/tmp/frida-server
adb -s <SERIAL> shell "su -c 'chmod 755 /data/local/tmp/frida-server'"
adb -s <SERIAL> shell "su -c '/data/local/tmp/frida-server &'"
& <FRIDA_ROOT>/.venv/Scripts/frida-ps.exe -U      # process list == link is up
```

**Emulator-specific preparation.** The emulator used here ships no scripting console, so
instances are launched by passing an index to the player binary. Root was off by default,
and the per-instance JSON uses key names that only exist inside the player binary:
`tools/ghidra/ld_config_probe.py` extracts them from the executable, and
`tools/ghidra/ld_set_root.py` flips them with a *text* insert plus a backup, because the
emulator rewrites that file itself and reserialising it can break its own parser. The two
keys that matter:

```
basicSettings.rootMode    -> 1 to enable root
basicSettings.adbDebug    -> 1 to keep adb usable
```

After a restart, `adb shell 'su -c id'` should report `uid=0(root)`.

**Serial discipline.** The same emulator instance can appear twice (as a transport serial
and as a `host:port` alias), which makes `adb wait-for-device` fail with
`more than one device/emulator`. Pin one serial (`-s <SERIAL>`) in every command and treat
the alias as a duplicate.

**Shell quoting.** PowerShell -> `adb shell` -> `su -c` -> `sh` strips quoting layers; a
pushed command can arrive mangled (`chmod` losing its argument). The reliable pattern is to
push a small shell script (`tools/frida/ld_start_frida.sh`) and run it on the device. That
script must use LF newlines — CRLF makes the device shell report `syntax error: unmatched
'if'`.

## 6. What the assistant can and cannot see

Worth stating explicitly, because it shapes how you write prompts:

* The MCP server exposes **programs, not files**: the assistant asks Ghidra for functions,
  strings, imports and decompiled C, and never sees the binary itself.
* Host-side tooling runs as ordinary commands, so anything a script can print is available
  to the assistant — that is how the triage/batch/probe scripts in `tools/` feed data back.
* Device-side state is only visible through `adb` output and the JSON the hook scripts
  `send()` back to the host. Anything the hooks do not report does not exist as far as the
  session is concerned; budget hook coverage accordingly.
