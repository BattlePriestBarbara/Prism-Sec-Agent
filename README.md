# AI-assisted reverse engineering: Cline + MCP + Ghidra + Frida

A distilled, sanitized write-up of an end-to-end **Android reverse-engineering workflow** driven
from an AI coding assistant (Cline). Ghidra is used for static analysis through a custom **MCP
server**, Frida for dynamic instrumentation, and the two are combined to work out what a hardened
(packed) application actually does — including the case where the honest answer is "this build has
no complete plaintext payload to dump, and here is the evidence".

The repository is both a **method description** (`docs/`) and the **sanitized tooling** that
implements it (`tools/`). No machine-specific paths, application names, package names or sample
hashes appear anywhere; the placeholder vocabulary is defined once in `tools/README.md`.

## What it demonstrates

* **Ghidra as a tool surface, not a GUI.** A small stdio MCP server exposes ~24 typed tools
  (import/analyse, inventory, decompile, xrefs, call graph, byte search) so the assistant can ask
  questions about an analysed binary directly.
* **Frida driven from the same session.** Host-side drivers plus a catalogue of small hook
  scripts, each answering exactly one question, with results streamed back to the host.
* **A triage-first unpacking playbook.** Classify the protection, choose the cheapest extraction
  route, and treat each failure as information instead of retrying blindly.
* **Evidence as data.** Every stage emits structured JSON, so findings can be re-derived rather
  than remembered, and every claim in the case study traces back to a tool run.
* **The limits, written down.** Translated-emulator blind spots, version couplings, signature
  checks, and the protection class where unpacking is not the right goal.

## The pipeline at a glance

```
                 ┌───────────────────────────────────────────────┐
                 │              AI assistant (Cline)             │
                 └───────┬───────────────────────────┬───────────┘
             MCP (stdio) │                           │ shell commands
                         ▼                           ▼
        ┌────────────────────────────┐   ┌──────────────────────────────┐
        │  Ghidra MCP server         │   │  host tooling + Frida driver  │
        │  PyGhidra (warm JVM)       │   │  dump_dex.py + hook scripts   │
        │  analyzeHeadless (batch)   │   │  triage / probe / batch tools │
        └───────────┬────────────────┘   └───────────────┬──────────────┘
                    ▼                                    ▼
        ┌────────────────────────────┐   ┌──────────────────────────────┐
        │ Ghidra project store       │   │ Android device / emulator     │
        │ (functions, strings, C)    │   │ frida-server (root)           │
        └───────────┬────────────────┘   └───────────────┬──────────────┘
                    └───────────┬────────────────────────┘
                                ▼
                 ┌──────────────────────────────────────────────┐
                 │ JSON evidence  ->  decompiled C / smali  ->  report │
                 └──────────────────────────────────────────────┘
```

Static and dynamic passes feed each other: the JNI surface extractor (static) tells you which
libraries are only reachable through `RegisterNatives` (dynamic), and the dynamic `open()` trace
tells you which module to decompile next.

## Start here

| Document | Contents |
| --- | --- |
| [`docs/01-environment-setup.md`](docs/01-environment-setup.md) | Toolchain versions, the two virtual environments, MCP wiring, device preparation, the gotchas that cost real time |
| [`docs/02-static-analysis-ghidra.md`](docs/02-static-analysis-ghidra.md) | The tool surface, the six-step static workflow, ranking rules, and the traps (including PyGhidra's import hook) |
| [`docs/03-dynamic-analysis-frida.md`](docs/03-dynamic-analysis-frida.md) | Frida 17 breaking changes, the host driver, measured spawn-vs-attach, the hook catalogue, the JNI table technique |
| [`docs/04-unpacking-playbook.md`](docs/04-unpacking-playbook.md) | Protection taxonomy, four extraction strategies, decoy-vs-real DEX, APK signature verification, reconstruction |
| [`docs/05-case-study-anonymized.md`](docs/05-case-study-anonymized.md) | One complete run with real numbers: 48 libraries triaged, 21 decompiled, the payload evidence chain, three extraction routes and their outcomes |
| [`docs/06-limitations-and-scope.md`](docs/06-limitations-and-scope.md) | Environment and method limits, evidence hygiene, legal/ethical scope, and exactly what was removed before publication |
| [`tools/README.md`](tools/README.md) | Placeholder vocabulary and what every script does |
| [`config/cline_mcp_settings.example.json`](config/cline_mcp_settings.example.json) | Ready-to-edit MCP configuration |

## Repository layout

```
.
├── README.md                       this file
├── LICENSE                         MIT
├── docs/                           the method (01..06)
├── config/
│   └── cline_mcp_settings.example.json
├── tools/
│   ├── README.md                   placeholder vocabulary + script index
│   ├── ghidra/                     static side: triage, batch analysis, decompile-by-name,
│   │                               JNI surface, APK/DEX/payload probes, emulator helpers
│   └── frida/                      dynamic side: driver, environment helpers,
│       └── hooks/                  one script per question
└── scripts/
    └── check_local_paths.py        hygiene gate: fails if absolute paths sneak back in
```

## Sanitization

The published tree went through an audited rewrite, not a manual tidy-up:

| Removed | Replaced with |
| --- | --- |
| Absolute paths (workspace, Ghidra/Frida/JDK/emulator installs, user profile) | `<WORK_DIR>`, `<OUT_DIR>`, `<GHIDRA_MCP_ROOT>`, ... |
| Application name, package name, stub entry class, packer/vendor brand | `com.example.targetapp`, `com.example.shell.ShellStub`, "the commercial packer" |
| Third-party SDK brands | role names: `libtransport.so`, `libliveness.so`, `liblicense.so`, ... |
| File hashes, sample metadata, generated analysis output | nothing — the scripts that produce it are shipped instead |

Numbers, tables and outcome statements are **unchanged**; they are the transferable part. Run the
gate yourself:

```powershell
python scripts/check_local_paths.py --root .        # exit 0 = clean
```

## Design decisions worth copying

1. **Put the tool behind a protocol.** MCP turned "I need to look at three more functions" into a
   handful of typed calls, which is the difference between using an assistant and being one's own
   clipboard.
2. **Keep the engine warm, and cache the analysis.** A lazily started JVM plus a persistent project
   store make the tenth question cheap; re-analysis is what makes people stop asking questions.
3. **Triage before you decompile.** A dependency-free ELF pass over 48 libraries took seconds and
   decided where the decompilation budget went.
4. **Rank, then jump by symbol.** Call-graph ranking is a starting point; named-entry-point
   decompilation is what actually finds the licence check or the crypto routine.
5. **One hook, one question.** Small scripts with a clear hypothesis produce logs you can cite.
6. **Attach by default, spawn deliberately.** A stub that kills a freshly spawned process 0.4 s
   after resume turns a spawn-first workflow into lost time.
7. **Write failures into the evidence.** "Hooked, never called" and "zero DEX-magic writes" are
   findings that eliminate whole classes of protection.
8. **Decide the environment before the coverage.** On a translated emulator, part of your hook
   coverage is unreachable by construction — that is a planning constraint, not a bug to fix later.

## Quick start

```powershell
# 1) configure MCP (fill the placeholders with real paths)
#    copy config/cline_mcp_settings.example.json into the assistant's MCP settings

# 2) verify the stack
& <PYTHON_EXE> <GHIDRA_MCP_ROOT>/server.py --check
& <FRIDA_ROOT>/.venv/Scripts/python.exe <FRIDA_ROOT>/check_setup.py

# 3) static pass: triage, then analyse the libraries that matter
& <PYTHON_EXE> <TOOLS_DIR>/ghidra/triage_elf.py --root <SAMPLE_DIR> -o <OUT_DIR>/elf_triage.json
& <PYTHON_EXE> <TOOLS_DIR>/ghidra/ghidra_batch.py --project <BATCH_NAME> --target <LIB>

# 4) dynamic pass: start frida-server, attach, run one hook at a time
& <PYTHON_EXE> <FRIDA_ROOT>/dump_dex.py --attach <PID> --js <FRIDA_ROOT>/hooks/anti_debug_probe.js --seconds 60
```

## Results in the case study

One run, fully de-identified in [`docs/05`](docs/05-case-study-anonymized.md): 48 native libraries
triaged and 21 decompiled; a 12.2 MB main DEX that was 99.85% encrypted payload; three unpacking
routes that each failed *informatively* (decoy DEX only, loader hooks never called, zero DEX writes
across any fd); a `RegisterNatives`-only surface for the libraries that mattered; a packer class
(instruction-level + DEX-to-C) that explains why; and a stale 2010-era TLS library still shipping
in the app — found statically, without needing the protection defeated.

## Companion projects

* Ghidra MCP server used here: <https://github.com/BattlePriestBarbara/Ghidra-MCP-tool>
* An autonomous security-assessment framework with a different focus:
  <https://github.com/BattlePriestBarbara/AVA-Security-Toolkit>

## License

MIT — see [LICENSE](LICENSE). Copyright (c) 2026 Xinhang Yu.

## Disclaimer

This material describes a **defensive and academic** workflow: understanding how software and its
protections work. Use it on software you own or are authorised to test, respect licences and
applicable law, and read [`docs/06-limitations-and-scope.md`](docs/06-limitations-and-scope.md)
§4 before instrumenting anything.
