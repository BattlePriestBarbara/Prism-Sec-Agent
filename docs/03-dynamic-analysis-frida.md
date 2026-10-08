# 03 — Dynamic analysis: driving Frida from the same session

## 1. Frida 17 changed the assumptions

Two changes broke most published scripts, and both fail *quietly* in the worst case:

| Change | Symptom | What to do instead |
| --- | --- | --- |
| The Java/ObjC bridges are no longer bundled in GumJS | `Java` is undefined, so a script that starts with `Java.perform(...)` dies with `ReferenceError` before doing anything | Feature-detect: `typeof Java !== "undefined" && Java.available`. For real Java-layer work, build an agent with `frida-compile` + `frida-java-bridge` |
| `Module.findExportByName` **and** `Module.getExportByName` were removed | `TypeError: not a function` — and inside a `try/catch` it degrades into a silent "symbol not found" | `Module.findGlobalExportByName(...)`, or resolve through the owner: `Process.getModuleByName('libc.so').getExportByName('write')` |

`tools/frida/hooks/api_probe.js` exists for exactly this reason: it prints the API surface the
scripts depend on, so a Frida upgrade can be re-validated in one 15-second run instead of by
reading release notes:

```powershell
& <PYTHON_EXE> <FRIDA_ROOT>/dump_dex.py --package <PACKAGE> --js <FRIDA_ROOT>/hooks/api_probe.js --seconds 15
```

Every hook in `tools/frida/hooks/` is written to work on both old and new releases: it prefers
the legacy lookup when present and falls back to the per-module form.

## 2. The host-side driver

`tools/frida/dump_dex.py` is the single entry point for all hook scripts. It attaches (or
spawns), loads a JS file, writes every blob the script streams over to disk, and prints a
one-line summary per blob and per scan round.

```
python dump_dex.py --package <PACKAGE> --out <OUT_DIR>/unpacked      # spawn
python dump_dex.py --attach <PID>    --out <OUT_DIR>/unpacked        # attach
python dump_dex.py --package <PACKAGE> --device <HOST:PORT>          # remote frida-server
python dump_dex.py --attach <PID> --js hooks/jni_boundary.js --seconds 120
```

Design points that matter in practice:

* **Blobs are streamed to the host, not written on the device.** `/data/local/tmp` is not
  writable from an unprivileged app process on modern Android, and the host side needs no root
  at all. The script validates each blob (magic, declared size, header counts) before naming it.
* **`--seconds N` makes runs non-interactive.** Without it the driver waits for Ctrl+C, which
  never arrives in a scripted or piped shell. Use `python -u` so progress is visible through
  `Tee-Object`/redirection.
* **One script at a time, one log per run.** Hook output is the primary evidence, so keeping a
  log file per experiment (hook set, pid, duration) is what makes the results reproducible.

## 3. Spawn or attach: a measured decision

Spawn gives you hooks before the first instruction, which is what a packer wants you to be
missing. In practice, on a target whose stub performs early self-checks, a freshly spawned
process was reported dead by the framework and restarted **about 0.4 s after resume** — the
new pid had no agent attached, and every timer in the script became meaningless.

The working pattern is therefore:

1. `am start` the activity and wait 5-8 s so the stub finishes its early self-checks;
2. resolve the pid (`pidof` under `su`);
3. `dump_dex.py --attach <PID> ...`.

With attach, repeated hook rounds ran cleanly (11 rounds, zero script errors, process stable).
Use spawn only when the earliest possible hook is unavoidable, and then expect to retry with
`am force-stop` between attempts.

Related: **app libraries are lazily loaded.** Attaching at the first activity, none of the
crypto/licence/ML libraries had been `dlopen`ed within 20 s. Either drive the matching feature
in the UI, or rely on the `dlopen`/`android_dlopen_ext` watcher in `trace_native.js`, which
hooks the library the moment it appears.

## 4. Hook catalogue

Each hook answers exactly one question. Run them in this order on a new target.

| Hook | Question it answers | Notes |
| --- | --- | --- |
| `api_probe.js` | Which GumJS APIs does this Frida release give me? | Run once per Frida upgrade |
| `anti_debug_probe.js` | Which detection APIs does the app/packer call? | **Recon only** — records, never alters behaviour |
| `arm_hook_probe.js` | Are the app's own modules mapped, from which ABI, and can `Interceptor.attach` reach them? | Decides the whole strategy on translated environments |
| `dump_dex.js` | Is there a plaintext DEX image in memory right now? | Range scan for `dex\n03x` magic, anon + app-owned mappings |
| `dump_dex_art.js` | Does the runtime's own DEX loader ever receive the decrypted image? | Hooks ART's dex openers, so no scanning |
| `dump_dex_write.js` | Does plaintext DEX cross a syscall boundary (file, pipe, socket)? | libc `write`/`pwrite`/`writev` + `open`/`openat` |
| `trace_native.js` | What do the identified crypto/licence entry points receive and return? | Symbol-driven; also watches `dlopen` for lazy libraries |
| `jni_boundary.js` | Which Java methods are bound to which native addresses, and with what arguments? | Works without the Java bridge (see §5) |

`anti_debug_probe.js` is the one to run first on anything hardened: its output is a list of
checks to neutralise (or avoid), taken from what the process actually calls rather than from a
generic checklist. On this class of target it recorded `ptrace` self-attach,
`/proc/self/maps` parsing, `dl_iterate_phdr` module walks, `inotify_*` file watching, a
reflective `getPackageInfo(...).signatures` check, and emulator/root probes
(`/dev/socket/qemu`, `XposedBridge.jar`, `libsubstrate.so`, `su`).

## 5. The Java <-> native boundary without a Java bridge

`hooks/jni_boundary.js` is the most reusable piece here, because it needs no Java bridge at all.
The idea: `JNIEnv*` points at a table of function pointers, so the n-th JNI function is
`env.readPointer().add(n * pointerSize).readPointer()`. Calling those through `NativeFunction` is
safe from an Interceptor callback because that callback already runs on a thread attached to the
runtime. Index 215 (`RegisterNatives`) is the one that matters:

* it is the only place where *(Java name, signature, native address)* appear together for
  libraries that export no `Java_*` symbols at all;
* Android 9's `libart.so` does not export `art::JNI::RegisterNatives`, so hooking the table entry
  is the only way in;
* getting there requires `JNI_GetCreatedJavaVMs()` first: `GetEnv` returns `-2`
  (`JNI_EDETACHED`) for a raw thread, so the script calls `AttachCurrentThread` (index 4 of the
  `JNIInvokeInterface`) before touching the environment.

Two filters keep the output usable: a **deny list** (ML runtimes, OpenSSL, `libc`, the runtime
itself) and a **focus list** (only the sample's own libraries, mapped from its own paths). Without
them the tracer explores the framework's own `Java_*` exports and produces mostly overhead.

## 6. Operational notes

* Read `jni_surface.json` (doc 02, step 5) before running `jni_boundary.js`: libraries with
  hundreds or thousands of exports and **no** `Java_*` symbols are exactly where a
  `RegisterNatives` trace pays off.
* Keep runs short and scripted (`--seconds 120`) and log each one; an unattended hook run
  produces a log nobody can attribute to a hypothesis.
* Coverage beats cleverness: a hook that reports arguments for the two functions you care about
  is worth more than a generic tracer that floods the log.
