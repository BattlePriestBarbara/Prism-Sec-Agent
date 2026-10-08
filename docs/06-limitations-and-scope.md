# 06 — Limits, evidence hygiene and scope

A workflow write-up is only useful if it also says where it stops working.

## 1. Environment limits

**The translated-emulator blind spot.** If the app ships only ARM libraries and you run it on an
x86_64 emulator, those libraries execute inside the emulator's ARM translation layer and live in a
*different address space* from the one Frida sees. Consequences, all observed:

* `Process.enumerateModules()` shows only the app's host-ABI part plus system libraries; the app's
  own ARM libraries are missing, so `Interceptor.attach` cannot be pointed at them.
* The ARM libraries' `RegisterNatives` calls go through the translation bridge rather than the
  host-ABI JNI environment table the tracer hooks, so their bindings stay invisible.
* One process contains two address spaces (568 `.so` mappings in the observed case), which is the
  trap: the libraries *are* there, `maps` proves it, and instrumentation still cannot reach them.

Options: a rooted **arm64 device** (simplest, no translation), a **user-mode emulator harness** for
libraries you can call directly (no device at all, but it needs a runtime environment for
DEX-to-C modules), or accept the reduced coverage and work statically.

**Root.** Without root you cannot push and start frida-server the straightforward way; the
alternative is repackaging the app with an injected gadget, which invalidates the signature and
therefore tends to break precisely the signature self-check a hardened app performs. Decide this
early — several hours of hook work are wasted if the environment cannot deliver the ABI you need.

**Version pinning.** Three couplings to respect:

| Coupling | Failure if broken |
| --- | --- |
| Frida CLI == frida-server | `unable to communicate with remote frida-server` (looks like a network fault) |
| Hook scripts == Frida major | Frida 17 removed the bundled Java bridge and both export-lookup helpers; old scripts die or, worse, silently find nothing |
| Ghidra == PyGhidra/JDK >= 21 | The JVM will not start on an old JDK; the MCP server needs its own `JAVA_HOME` |

**Network.** Dependency downloads are the least predictable part of setup: a Maven-based build
route timed out against its default central repository while mirrors answered, and one
`frida-server` ABI downloaded far slower than the others. Where possible, install from artefacts
that ship with the tools you already have (for example PyGhidra's bundled wheels) and keep a
mirror configured.

**Emulator quirks** (all cost time at least once): no scripting console in some builds, root off
by default with key names discoverable only inside the player binary, the same instance
registered twice under different serials, and CRLF line endings breaking pushed shell scripts.

## 2. Method limits

* **Instruction-level/DEX-to-C protection may have no solvable artefact.** If methods are
  decrypted and translated on demand, there may be no complete plaintext image to capture.
  Evidence of *that* is the deliverable — see doc 05.
* **Static analysis of an obfuscated loader describes behaviour, not semantics.** You can prove
  what the loader touches (`ptrace`, maps parsing, file watches, signature checks) without reading
  its control flow exactly.
* **Encrypted models and keys need their decryptor.** A model file that is `*_secret.bin` is not
  going to open offline without reproducing the derivation path.
* **Hooks only see what they are pointed at.** A trace with nobody hitting a symbol proves nothing
  about a feature you never exercised, because libraries load lazily.
* **Time-boxed honesty.** Every route has a cost. Writing down "route 3 produced zero hits and the
  `open` trace explains why" is the result; continuing to rerun route 1 is not.

## 3. Evidence hygiene and reproducibility

What made the results in this repository checkable:

* **One log per experiment**, labelled with the hook set, the pid, the duration and the device.
  Hook output is the primary evidence; an unattributed log is nearly worthless.
* **A JSON contract per stage** (triage, batch analysis, JNI surface, probes) with counts, tool
  settings and local hashes, so a report can be regenerated rather than retyped.
* **Hashes stay local.** They are evidence for correlating your own copies; they are also a
  fingerprint of one specific sample, so they are deliberately not published here.
* **Deterministic inputs.** Untouched originals for dynamic work (verified with
  `apk_zip_probe.py`), and analysis projects that can be reopened instead of rebuilt.
* **Reproducibility caveats to state up front:** hardened apps change per build, emulator builds
  differ, and Frida behaviour changes across majors. Record versions, or the numbers mean nothing
  six months later.

## 4. Scope, ethics and legal

This repository documents a **defensive and academic** reverse-engineering workflow. The
conditions under which the work it describes is appropriate:

* **Authorised targets only** — software you own, software you are contracted to assess, or
  research targets where you have permission. Review the licence terms and the applicable law in
  your jurisdiction before instrumenting anything.
* **No circumvention for use.** Understanding how a protection works is not the same as shipping a
  bypass; do not redistribute extracted code, models, keys or modified builds.
* **Report, do not publish, exploitable detail.** Findings about a third party's app belong in a
  responsible disclosure channel, not in a public write-up with a reproducible payload.
* **Third-party data.** Instrumenting an app frequently surfaces personal data, credentials or
  proprietary models. Treat anything captured as sensitive: minimise, redact, delete.
* **Keep the toolchain honest.** Anti-analysis checks exist because people misuse this kind of
  tooling; the probes here record behaviour instead of patching it, and the neutralisation steps
  stay in the lab.

## 5. What this repository deliberately omits

To publish the method without publishing the target, the sanitisation pass removed:

* every absolute path, replaced by `<PLACEHOLDERS>` that are documented once in `tools/README.md`;
* the application name, package name, entry-class name and any vendor/packer brand;
* third-party SDK brands, replaced by role names (`libtransport.so`, `libliveness.so`, ...);
* file hashes, sample metadata and any artefact that would fingerprint one specific build;
* generated analysis output (decompiled C, smali trees, JSON evidence) — the scripts that produce
  it are shipped instead.

The numbers, tables and outcomes are untouched: they are what makes the write-up transferable.
