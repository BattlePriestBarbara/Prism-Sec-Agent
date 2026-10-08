# 04 — Unpacking playbook for hardened Android apps

This is the part that generalises least and diagnoses most. The goal is not "run a dumper";
it is to find out **which class of protection** you are facing, because that determines whether
an unpacking attempt can work at all.

## 1. Classify the protection first

Use both sides at once — static evidence for the claim, dynamic evidence for the confirmation.

Static (cheap, no device needed):

* **Manifest:** the declared application class is a stub (`com.example.shell.ShellStub` in this
  write-up), not the app's real entry point.
* **The main DEX is mostly payload.** Compare the DEX header's declared `data` end against the
  file size. In the case study, 12.2 MB of `classes.dex` contained 17.9 KB (0.15%) of valid DEX
  structure and 5 classes / 215 methods — the rest was high-entropy payload.
* **An `assets/`-resident loader**: one or more `.so` files whose job is DEX decryption and
  loading, often with an empty export table, `ptrace`, `/proc/self/maps` parsing, `inotify_*`
  watches and a signature check.
* **Resources collapsed to placeholders** (a 1-byte file where a real asset used to be) and
  a suspiciously spelled duplicate of `assets/` (e.g. the same name reversed) — both are
  classic shell fingerprints.
* **Entropy:** a high-entropy region inside a file that is supposed to be structured.

Dynamic (needs the device; run `anti_debug_probe.js` first):

* what the stub writes to its private data directory while starting;
* which `dlopen`/`open` calls happen around decryption — this is what tells you whether a
  DTC-style module is in play.

## 2. The protection classes you will meet

| Class | Behaviour | Realistic approach |
| --- | --- | --- |
| A — dumpable | Decrypted DEX lands on disk, or the app uses a standard in-memory loader you can hook | Memory scan or loader hooks usually succeed |
| B — memory-loader | DEX exists only as a buffer handed to the runtime's in-memory loader | Hook the runtime's DEX openers (`ArtDexFileLoader::OpenCommon`, `Open(const uint8_t*, size_t)`) |
| C — instruction-level / DEX-to-C | Methods are decrypted and translated one by one; a complete plaintext image may **never** exist | Per-method or runtime-internal hooking; expect to work around it rather than through it |
| D — VM / bytecode virtualization | Original bytecode is interpreted by a custom native VM | Out of scope for this playbook; needs a dedicated devirtualisation effort |

Class C is the one that makes classic dumpers look "broken". It is not the tooling: the artefact
you are looking for is not produced.

## 3. The four extraction strategies, in cost order

1. **Memory magic scan** (`hooks/dump_dex.js`). Scan readable mappings for `dex\n03x`, read the
   declared size from the header, stream the blob to the host. Cheap to write, expensive to run:
   scanning hundreds of MB every second inside a translated process does not finish quickly.
   *Failure tells you:* the image is not in a readable mapping — or only a placeholder is.
2. **Runtime loader hooks** (`hooks/dump_dex_art.js`). Hook the exported ART entry points that
   receive `(buffer, size)`. Sharp and fast when the app uses the in-memory path.
   *Failure tells you:* that path is not used at all (hooks attach but are never called), which
   rules out a whole class of packers.
3. **Syscall-boundary hooks** (`hooks/dump_dex_write.js`). Watch libc `write`/`pwrite`/`writev`
   and `open`/`openat`: if plaintext DEX ever crosses a file, pipe or socket, the magic appears in
   the buffer. Even on failure this is the most informative run, because the `open` trace exposes
   the shell's working directory and its own extra modules.
4. **Java-layer tooling** (needs an agent built with `frida-java-bridge`, since Frida 17 no longer
   ships the bridge). Hook the class loaders and `DexFile` accessors. Most convenient when it
   works, most fragile across releases.

## 4. Telling a placeholder apart from a real dump

This is the single most useful check during unpacking, because shells do leave a decoy DEX behind
to keep the runtime happy:

| Signal | Placeholder | Real |
| --- | --- | --- |
| File size | ~284 bytes (minimum legal header, no classes) | kilobytes to megabytes |
| `class_defs_size` | 0 | hundreds to thousands |
| `method_ids_size` | 0 | thousands |
| Header `file_size` (offset `0x20`) | equals the tiny file size | equals the real image size |
| Where it lives | the shell's own working directory | a mapping handed to the runtime |

`--out` dumps from `dump_dex.py` carry the source, the address, the hash prefix, the version and
the class count in the filename, so a folder of dumps can be triaged at a glance instead of by
opening each one.

## 5. Verify the APK before you install it

Dynamic work needs an installable APK that still carries the **original signature**, because a
hardened app verifies its own signature at startup. A re-zipped directory keeps the v1
`META-INF` material but loses the APK Signing Block (v2/v3) that sits between the last entry and
the central directory — enough to distinguish the two:

```powershell
& <PYTHON_EXE> <TOOLS_DIR>/ghidra/apk_zip_probe.py <CANDIDATE_ZIP_OR_APK>
```

* APK Signing Block present -> almost certainly the original file, just renamed; copy it to
  `*.apk` and install it.
* Only v1 signature files -> the tree was re-zipped. Android 7+ may still install it, but the
  app's own signature check can reject it, which is why the untouched original is preferred.
* No signature material -> not installable as-is.

Repacking the app (for example to inject a gadget) invalidates the signature and therefore tends
to break exactly the check this workflow depends on; plan for that if you take the no-root route.

## 6. Reconstructing what you extracted

* **DEX -> smali.** No extra download is needed: a smali assembler/disassembler ships inside
  Ghidra's file-format libraries. `tools/ghidra/DexSmali.java` is the thin wrapper used to invoke
  it against a classpath built from the install's jars; the result is a readable smali tree that
  pairs with the decompiled C from the static pass.
* **DEX -> Java.** A Java decompiler (jadx) is the fastest way to read business logic once
  unpacking succeeded. Keep the smali tree too: it is closer to the runtime truth and survives
  where a decompiler gives up.
* **Native logic.** For stripped or DTC-heavy components, stay on the native side: the static
  decompilation from doc 02 plus targeted hooks (`trace_native.js`) usually gets further than
  trying to reconstruct Java that no longer exists in Java form.

## 7. Deciding when to stop

Write the decision down, with the evidence that produced it. "Unpacking did not succeed" is not a
result; "the image is never written to any fd, the runtime's loader never sees it, and a DTC
module is loaded at start-up, therefore no complete plaintext DEX exists on this build" is a
result — and it is what the case study in doc 05 looks like. From that point the useful moves are
static single-point recovery of the modules that matter and, where the algorithm must be executed,
a user-mode emulator harness or a real arm64 device.
