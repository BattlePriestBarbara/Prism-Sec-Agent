# 02 — Static analysis: driving Ghidra through MCP

## 1. Why the MCP design looks like this

* **MCP is the integration layer.** The assistant cannot drive Ghidra's GUI or its Java API
  directly; the protocol turns Ghidra operations into typed tools it can call, so a question
  like "decompile the function that parses `/proc/self/maps`" becomes a sequence of tool
  calls instead of a copy/paste loop.
* **PyGhidra is the primary engine.** One JVM is started lazily on the first call and kept
  warm; the analysed program stays open, so follow-up questions cost milliseconds instead of
  a JVM restart. Analysis results are persisted in a Ghidra project, so a session that ends
  can be resumed by opening the same program.
* **`analyzeHeadless` is the fallback/batch engine.** One tool shells out to Ghidra's own
  CLI for long or batch jobs. Both engines share the same project store, so a binary
  imported by headless can be queried through PyGhidra and vice versa. That interop is
  worth a smoke test of its own before you rely on it.

The companion server lives in its own repository:
<https://github.com/BattlePriestBarbara/Ghidra-MCP-tool>.

## 2. The tool surface

Roughly two dozen tools, in four families:

| Family | Tools | Use |
| --- | --- | --- |
| Session / environment | `ghidra_environment`, `ghidra_session_status`, `ghidra_list_projects`, `ghidra_list_programs`, `ghidra_current_program`, `ghidra_close_program` | Is the JVM alive, which program is open, what is cached |
| Ingestion | `ghidra_import_and_analyze`, `ghidra_open_program`, `ghidra_headless_import` | Import + auto-analyse, or reopen a cached program |
| Inventory | `ghidra_list_functions`, `ghidra_search_symbols`, `ghidra_list_strings`, `ghidra_list_imports`, `ghidra_list_entry_points`, `ghidra_list_memory_blocks`, `ghidra_list_data_types` | "What is in here" |
| Deep look | `ghidra_function_details`, `ghidra_decompile_function`, `ghidra_disassemble`, `ghidra_xrefs`, `ghidra_call_graph`, `ghidra_read_bytes`, `ghidra_search_bytes` | Per-function reasoning |

Function arguments accept a **name** (`FUN_140001008`, `KERNEL32.dll::CreateFileW`) or an
**address** (`0x140001008`); addresses come back 0x-prefixed. Tools return JSON and never
raise, so a failed call is data (`ok: false` + `error`) rather than a broken session.

If you have used another Ghidra MCP server, the names differ:

| Name used elsewhere | Tool in this server |
| --- | --- |
| `ghidra_get_functions` | `ghidra_list_functions` |
| `ghidra_get_symbols` | `ghidra_search_symbols` |
| `ghidra_get_imports` | `ghidra_list_imports` |
| `ghidra_get_strings` | `ghidra_list_strings` |
| `ghidra_decompile` | `ghidra_decompile_function` |

## 3. The static workflow that was actually used

**Step 0 — triage before you spend Ghidra time.** `tools/ghidra/triage_elf.py` is pure
Python (no dependencies) and reads ELF headers, section headers, the dynamic section, the
dynamic symbol table and `.comment`. It answers, per library and in seconds: which ABI,
which compiler/runtime banner, is it stripped, what does it need, how many exported
functions. That output decides where the decompilation budget goes.

```powershell
& <PYTHON_EXE> <TOOLS_DIR>/ghidra/triage_elf.py --root <SAMPLE_DIR> -o <OUT_DIR>/elf_triage.json
```

**Step 1 — split the sample into batches.** Group by ABI and by role (protection loaders,
crypto/licence modules, ML runtimes, storage, analytics). One Ghidra project per batch keeps
each analysis job bounded and lets you throw away a batch without losing the rest.

**Step 2 — import and auto-analyse per batch.**

```powershell
& <PYTHON_EXE> <TOOLS_DIR>/ghidra/ghidra_batch.py --project <BATCH_NAME> --target <LIB> [...]
```

`ghidra_batch.py` drives the same tool functions the MCP server exposes, but in batch: it
imports + analyses, then dumps functions, imports, strings, entry points, memory blocks, a
call-graph ranking and the decompiled pseudo-code of the N most "core" functions. Each
binary gets its own JSON file, so a long run is **resumable** — an existing output file is
reused unless `--force` is given.

**Step 3 — rank, then read what matters.** Automatic ranking by caller count tends to surface
library helpers rather than the interesting code in C++-heavy binaries, so the batch output is
a starting point, not the answer. Two rules that produced useful results:

* Rank non-import, non-thunk functions with a body by **in-degree from the call graph**
  (ties broken by body size), always pin the program entry point, and record the rule in the
  output (`ranking_method`) so the numbers stay interpretable later.
* Then jump by **symbol**, not by rank: `tools/ghidra/decompile_named.py` takes
  case-insensitive name substrings (`--match Java_com_...`, `--match genECDHsharedsecret`,
  `--match aes_256_cbc`) and decompiles only the matches, with an option to widen the
  character budget per function.

```powershell
& <PYTHON_EXE> <TOOLS_DIR>/ghidra/decompile_named.py --project <BATCH_NAME> `
    --target <LIB> --match <SYMBOL_SUBSTRING> --match <OTHER> --per-match 4
```

**Step 4 — mine strings for intent, keys and anti-analysis markers.** For obfuscated or
stripped loaders the string table is often the fastest path to what a binary *does*: paths it
manages, `ptrace`/`/proc/self/maps` parsing shapes, `inotify_*` usage, signature-check
reflection, transport keys, URLs. `requery_strings.py` re-queries a program for a string
subset without re-analysing; `payload_probe.py` inspects suspicious containers (a stub DEX,
`*_enc.so` assets, 1-byte placeholder assets) and reports header, size and block entropy;
`decode_shell_strings.py` XOR-decodes obfuscated string literals out of baksmali output once a
stub resolver can be recovered.

**Step 5 — extract the JNI surface before touching a device.**
`tools/ghidra/jni_surface.py` reads the triage JSON and splits libraries in two:

* libraries with statically named `Java_*` exports — hookable by symbol name;
* libraries with plenty of exports but **zero** `Java_*` symbols — reachable only through
  `JNIEnv->RegisterNatives()` at runtime, which changes the dynamic plan (see doc 03).

It also writes a machine-readable summary (`<OUT_DIR>/jni_surface.json`). A Frida script cannot
read host files, so the summary is meant to be read by *you* between the two stages: use it to
edit the hook's focus/deny patterns (`MODULE_FOCUS`, `MODULE_DENY` in `jni_boundary.js`) instead
of letting it trace the framework's own `Java_*` exports.

**Step 6 — keep evidence in JSON, not prose.** Every stage writes structured output with the
input hashes, the tool settings and the counts. A report written from a JSON contract can be
regenerated; a report written from memory cannot.

## 4. Practical notes and traps

* **Never name your own Python file `ghidra*.py`.** PyGhidra's import hook claims modules
  whose name starts with `ghidra`, and the failure mode is a `RecursionError` inside
  `find_spec` — confusing enough that it is worth making it a rule.
* **One program open at a time.** The session keeps the current program in memory; ask for
  `ghidra_current_program` when a prompt chain gets long, and reopen deliberately instead of
  assuming.
* **Projects are a cache, not an artefact to publish.** They are large, they embed the
  original bytes, and a project can be used to restore the file it was imported from
  (`OriginalFileExporter`, or "Export Original File" in the GUI). That is useful for
  integrity work and a good reason not to distribute `.gpr`/`.rep` directories.
* **Hashes are evidence, not identifiers to publish.** Record them locally; they are one-way
  functions, but they still fingerprint one specific sample.
* **Stripped is not the same as opaque.** A loader that exports nothing still decompiles into
  hundreds of functions with a readable string table — enough to describe behaviour even when
  the control flow is obfuscated.
* **Batch cost is dominated by auto-analysis, not by queries.** Shape batches so that one long
  import cannot invalidate an hour of work; that is exactly what the per-binary output files
  protect against.
* **Two engines, one store** is a feature worth testing early: import with the headless engine
  when you want a separate process, then query the same program through the warm PyGhidra
  session.
