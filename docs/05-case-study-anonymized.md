# 05 — Case study (anonymised)

This is the run the rest of the repository is distilled from. **All identifiers have been
removed**: no application name, package name, file path, hash, or third-party brand survives.
Numbers, structure and outcomes are unchanged, because they are the part worth learning from.
Library names appear as role names (`libtransport.so`, `libliveness.so`, ...), and the packer is
described by class rather than by vendor.

## 1. Target profile

| Property | Value |
| --- | --- |
| Size | ~52 MB APK |
| SDK range | minSdk 21, targetSdk 30 |
| Native ABIs shipped | `arm64-v8a`, `armeabi-v7a`, `armeabi` — **no** x86/x86_64 |
| Protection | commercial packer, "instruction-level + DEX-to-C" class (see doc 04) |
| Static pass | Ghidra 12.1.3 headless/PyGhidra, 48 ELF libraries triaged, 21 fully decompiled |
| Dynamic pass | rooted x86_64 emulator (Android 9 / API 28, ARM translation), Frida 17.18.0 |

## 2. Static pass — what the corpus looked like

Triage of all 48 libraries produced a clear division of labour, and that division is the reason
to triage before decompiling:

| Category | Shape of the evidence | Value |
| --- | --- | --- |
| Packer loaders (2: arm32 + arm64) | Stripped, **0 exported symbols**, control-flow obfuscation; 722 and 307 functions recovered anyway; strings naming the encrypted DEX, a hash file, `ptrace`, `/proc/self/maps` parsing, `inotify_*`, a reflective signature check, and an obfuscated `JNI_OnLoad` reached through an indirect syscall | Describes the protection without needing to defeat it |
| Transport crypto module | **Not stripped**, full C++ symbols: ECDH shared-secret generation, ECDH public-key generation, AES-256-CBC encode/decode, PEM->EC key, plus its JNI entry points | Highest value per hour: logic readable from decompiled C alone |
| OCR SDK + licence module | Not stripped; licence activation/state machine, apikey/signature checks, MD5 helpers, JNI entry points visible | Explains the licence flow end to end |
| ID-quality SDK | ~1.4k functions; loads encrypted model binaries (`*_model_secret.bin`) | Models must be recovered at runtime or after the decryptor |
| Face/liveness SDK | ~3.5k exported functions, OpenCV + an inference runtime inside | Large attack surface, ML internals |
| Storage, inference, analytics, networking, crash reporters | Mixed; one KV store advertises AES-256 rekeying via ARMv8 AES instructions; one analytics/anti-cheat library probes for emulators, Xposed and substrate | Device-fingerprint and privacy review material |
| Legacy TLS/crypto library | Reports **OpenSSL 1.0.0a (2010)**, still containing SSLv2-era method code paths | A concrete, reportable hygiene finding |

Two takeaways that generalise: **the "hardest" binaries are often the least useful** (the packer
is obfuscated precisely because it is not the product), and **stripped does not mean silent** —
the loader's string table alone described its job.

## 3. Packer evidence chain (static)

* Main DEX: 12,218,952 bytes total, of which the declared DEX `data` section ends at offset
  17,876 — **0.15%** of the file is valid DEX structure; the rest is high-entropy payload.
  Header counts: 386 strings, 72 types, 135 protos, 23 fields, **215 methods, 5 classes**.
* The five classes are a stub entry point plus four shell classes (including configuration,
  a class loader and a "DTC loader"), several of them with byte-reversed names.
* String markers for the packer appear inside the file; other vendor markers do not.
* `assets/` contains the loaders; the same folder name also exists **spelled backwards** with
  every file reduced to a one-byte placeholder — a resource-protection fingerprint.
* Result: the shipped Java layer is a loader stub, and the Java business logic cannot be read
  statically without unpacking. That is a *finding*, not a failure.

## 4. Dynamic pass — what the process actually does

The app installed and started normally on the rooted emulator, and the stub's early checks did
not trip when the agent attached *after* start-up (see doc 03 for why attach was chosen).

**What the stub leaves behind** in its private data directory — all of it readable as root:

| Artefact | Size | Meaning |
| --- | --- | --- |
| Its own loader, 32-bit | 958,912 B | x86 loader the stub unpacks at run time |
| Its own loader, 64-bit | 1,063,424 B | the one actually loaded |
| `tmp.dex` | **284 B** | minimum legal DEX header, **0 classes** — a decoy, not the payload |
| `tmp.odex` / `tmp.vdex` | 17,024 B / 376 B | the runtime's compilation of that decoy |
| version-control file | small | the stub's own state |

**The `open()` trace** (from `dump_dex_write.js`) is the clearest narrative of the whole
unpacking sequence: the installed APK, its oat/vdex, the stub's own loaders, a lock file around
the decoy DEX, the decoy's vdex, the version-control file, then a **DTC module**, and only then
the app's own libraries.

**The three extraction routes, and what each failure meant:**

| Route | Outcome | Conclusion |
| --- | --- | --- |
| Memory magic scan | Only the 284-byte decoy, 0 classes, across all rounds | The plaintext image is not sitting in a readable mapping |
| Runtime loader hooks | Hooks attached, **never called** | The app does not use the runtime's in-memory DEX loader path |
| Syscall-boundary hooks | **0** writes carrying DEX magic; the `open` trace exposed the working directory, the decoy and the DTC module | Plaintext DEX never crosses an fd → likely no complete plaintext image exists |

Combined with the DTC module being loaded at start-up, the honest verdict was
**instruction-level decryption plus DEX-to-C**: methods are translated on demand, so a classic
"one dump = whole app" result does not exist on this build. Saying that with evidence is more
useful than another unsuccessful dumping run.

**The Java<->native surface.** Static JNI analysis (`jni_surface.py`) showed a handful of
libraries with static `Java_*` exports (4, 6, 6, 3, 5 and 4 of them), while the most interesting
one — a liveness/face library with **3,513 exports and zero `Java_*` symbols** — plus the KV
store, the analytics library and the networking library, expose none. Those bindings are only
visible by intercepting `RegisterNatives` (doc 03, §5), which is what `jni_boundary.js` does.

**Stability.** With attach, 11 hook rounds ran with zero script errors and a stable process.
With spawn, the framework reported the process dead and restarted it roughly **0.4 s** after
resume, taking the agent with it.

**The environment's hard limit.** The emulator ran the app's ARM-only libraries through an ARM
translation layer. The process ended up with 568 `.so` mappings in **two address spaces**
(host-ABI libraries at high addresses, translated ARM libraries at low addresses). Frida, running
in the host ABI, could enumerate and instrument the stub's host-ABI part and the system libraries
but could not reach the app's own ARM libraries at all — not a script bug, a property of
translation. Doc 06 covers what that means for planning.

## 5. What the case concluded, and what was recommended next

1. **Keep going on the native side.** The highest-value modules were not stripped; static
   single-point recovery (doc 02) plus `trace_native.js` on a real device is where the remaining
   progress is.
2. **Use a rooted arm64 device** if the Java/ARM logic must run under instrumentation — no
   translation layer, no emulator-detection interference.
3. **Consider a user-mode emulator harness** for unstripped, directly-callable libraries: it needs
   no device and sidesteps the translation problem entirely. It is a poor fit for DEX-to-C
   modules, which expect a full runtime environment.
4. **Do not chase full unpacking of this class.** Spend the same effort on the modules that carry
   the protocol, the licence logic and the crypto instead.

## 6. What I would do differently next time

* Run `triage_elf.py` and `jni_surface.py` **before** any Ghidra batch job: the triage decided the
  batches correctly but only after the first, less focused, import round.
* Budget deployable time for `spawn` experiments and treat `attach` as the default; the 0.4 s
  kill was diagnosable in the log but cost several attempts.
* Decide the device question (arm64 vs x86_64 emulator) **before** building hook coverage: on a
  translated environment, a large part of that coverage is unreachable by construction.
