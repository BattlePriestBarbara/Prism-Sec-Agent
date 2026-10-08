// jni_boundary.js - trace the Java <-> Native boundary without the Java bridge.
//
// Why this is the right tool for this class of target (see docs/03-dynamic-analysis-frida.md):
//   tools/jni_surface.py shows that only a few libs expose statically named entry points
//   (libtransport.so: 4, liblicense.so: 6, libocr.so: 6, libidquality: 3,
//   libsocialsdk: 5, libdevicespy: 4) while the interesting ones - libliveness.so
//   (face/liveness, 3513 exports), libkvs.so, libcrashreporter.so, libnetwork.so - export
//   ZERO Java_* symbols and can only be reached through JNIEnv->RegisterNatives().
//   Hooking RegisterNatives is therefore the only place where
//   (java name, signature, native address) become visible at once - and those addresses
//   are exactly what we then instrument to capture arguments and return values.
//
// Frida 17 dropped the bundled Java bridge, so we talk to JNI ourselves: a JNIEnv* points
// to a table of function pointers (the C++ ABI layout of JNINativeInterface), hence the
// n-th JNI function is env.readPointer().add(n * pointerSize).readPointer(). Calling those
// pointers through NativeFunction is safe here because Interceptor callbacks run on the
// target thread, which is already attached to ART.
//
// Usage (attach, not spawn - this shell kills a freshly spawned process, see 4.5):
//   python dump_dex.py --attach <pid> --js hooks/jni_boundary.js --seconds 120

const PTR = Process.pointerSize;

// ---- JNINativeInterface table indices (jni.h order, Android API 28) ----
const JNI = {
    GetObjectClass: 31,
    GetStringUTFChars: 169,
    ReleaseStringUTFChars: 170,
    GetArrayLength: 171,
    GetObjectArrayElement: 173,
    GetByteArrayElements: 184,
    ReleaseByteArrayElements: 195,
    GetJavaVM: 219,
};

// Libraries whose Java_* exports are noise for us (3rd-party ML runtimes, OpenSSL, ART)
const MODULE_DENY = /tensorflowlite|infer|^libcrypto|^libssl|^libc\.so|^libart|^libandroid/;
// Only the sample's own libraries are hooked: they are mapped from /data/app/<pkg>/... or
// from the apk itself. Without this the tracer happily instruments the framework's ~157
// Java_* exports (libopenjdk.so, libmedia_jni.so, ...), which is pure overhead.
const APP_PATH_RE = /\/data\/(app|data)\/com\.example\.targetapp/;
// Libraries whose registered natives get per-call instrumentation (and whose dlopen we watch)
const MODULE_FOCUS = /libtransport|libliveness|liblicense|libocr|libchannel|libnetwork|libdtc|libshell|libkvs|libidquality|libsocialsdk|libdevicespy/i;

const hookedJava = new Set();
const hookedNative = new Set();
const fnCache = new Map();
const registered = [];
const MAX_CALLS_PER_FN = 30;

// ---- JNI access helpers ----------------------------------------------------
function jniFn(env, index) {
    let fn = fnCache.get(index);
    if (fn === undefined) {
        fn = env.readPointer().add(index * PTR).readPointer();
        fnCache.set(index, fn);
    }
    return fn;
}

function jniCall(env, index, ret, args) {
    try { return new NativeFunction(jniFn(env, index), ret, args); }
    catch (e) { return null; }
}

function readJString(env, jstr) {
    if (!jstr || jstr.isNull()) return null;
    const get = jniCall(env, JNI.GetStringUTFChars, "pointer", ["pointer", "pointer", "pointer"]);
    const rel = jniCall(env, JNI.ReleaseStringUTFChars, "void", ["pointer", "pointer", "pointer"]);
    if (!get) return null;
    try {
        const chars = get(env, jstr, ptr(0));
        if (chars.isNull()) return null;
        const value = chars.readCString();
        if (rel) { try { rel(env, jstr, chars); } catch (e) { } }
        return value;
    } catch (e) {
        return "<jstring read failed: " + e + ">";
    }
}

function readJByteArray(env, arr, maxBytes) {
    if (!arr || arr.isNull()) return null;
    const limit = maxBytes || 256;
    const lenFn = jniCall(env, JNI.GetArrayLength, "int", ["pointer", "pointer"]);
    const get = jniCall(env, JNI.GetByteArrayElements, "pointer", ["pointer", "pointer", "pointer"]);
    const rel = jniCall(env, JNI.ReleaseByteArrayElements, "void",
        ["pointer", "pointer", "pointer", "int"]);
    if (!lenFn || !get) return null;
    try {
        const length = lenFn(env, arr);
        const data = get(env, arr, ptr(0));
        if (data.isNull()) return { length: length, hex: null };
        const n = Math.min(length, limit);
        const bytes = new Uint8Array(data.readByteArray(n));
        const hex = Array.from(bytes).map(b => b.toString(16).padStart(2, "0")).join(" ");
        const ascii = Array.from(bytes)
            .map(b => (b >= 0x20 && b < 0x7f) ? String.fromCharCode(b) : ".").join("");
        if (rel) { try { rel(env, arr, data, 2); } catch (e) { } }   // JNI_ABORT
        return { length: length, hex: hex, ascii: ascii };
    } catch (e) {
        return { length: -1, hex: "<read failed: " + e + ">" };
    }
}

function readJStringArray(env, arr, maxItems) {
    if (!arr || arr.isNull()) return null;
    const lenFn = jniCall(env, JNI.GetArrayLength, "int", ["pointer", "pointer"]);
    const get = jniCall(env, JNI.GetObjectArrayElement, "pointer", ["pointer", "pointer", "int"]);
    if (!lenFn || !get) return null;
    const out = [];
    try {
        const length = lenFn(env, arr);
        const n = Math.min(length, maxItems || 16);
        for (let i = 0; i < n; i++) {
            out.push(readJString(env, get(env, arr, i)) || "<non-string>");
        }
        return { length: length, items: out };
    } catch (e) {
        return { length: -1, items: ["<read failed: " + e + ">"] };
    }
}

// ---- JNI signature handling -------------------------------------------------
// The signature handed to RegisterNatives tells us exactly how to decode every argument.
// That is precisely why the dynamic-registration path is worth more than guessing at raw
// pointers: it is the only place where the Java types are known.
function readOneType(sig, i) {
    const c = sig.charAt(i);
    if (c !== "L") return c;
    const end = sig.indexOf(";", i);
    return end === -1 ? sig.slice(i) : sig.slice(i, end + 1);
}

function parseSignature(sig) {
    const args = [];
    if (!sig || sig.charAt(0) !== "(") return { args: args, ret: "V" };
    let i = 1;
    while (i < sig.length && sig.charAt(i) !== ")") {
        let type = "";
        while (sig.charAt(i) === "[") { type += "["; i++; }
        const one = readOneType(sig, i);
        type += one;
        i += one.length;
        args.push(type);
    }
    return { args: args, ret: sig.slice(i + 1) || "V" };
}

function readArrayLength(env, ref) {
    const fn = jniCall(env, JNI.GetArrayLength, "int", ["pointer", "pointer"]);
    if (!fn) return -1;
    try { return fn(env, ref); } catch (e) { return -1; }
}

function decodeArg(env, raw, type) {
    try {
        switch (type) {
            case "Z": return raw.toInt32() !== 0;
            case "B": case "C": case "S": return raw.toInt32() & 0xffff;
            case "I": return raw.toInt32();
            case "J": return raw.toString();
            case "F": case "D": return String(raw) + " (fp)";
            case "Ljava/lang/String;": return readJString(env, raw);
            case "[B": return readJByteArray(env, raw, 256);
            case "[Ljava/lang/String;": return readJStringArray(env, raw, 16);
            default:
                if (type.charAt(0) === "[") return { array: type, length: readArrayLength(env, raw) };
                if (type.charAt(0) === "L") return String(raw);
                return String(raw);
        }
    } catch (e) {
        return "<decode failed: " + e + ">";
    }
}

function decodeArgs(env, args, argTypes) {
    const out = {};
    for (let i = 0; i < argTypes.length; i++) {
        out["a" + i] = decodeArg(env, args[i + 2], argTypes[i]);
    }
    return out;
}

// ---- instrumentation of one native -----------------------------------------
function describeModule(addr) {
    try {
        const module = Process.findModuleByAddress(addr);
        return module ? module.name + "+0x" + addr.sub(module.base).toString(16) : String(addr);
    } catch (e) {
        return String(addr);
    }
}

function instrumentFn(key, label, sig, fnPtr, argTypes) {
    if (hookedNative.has(key)) return false;
    hookedNative.add(key);
    const where = describeModule(fnPtr);
    const state = { calls: 0 };
    try {
        Interceptor.attach(fnPtr, {
            onEnter(args) {
                state.calls++;
                if (state.calls > MAX_CALLS_PER_FN) return;
                const env = args[0];
                let decoded;
                if (argTypes && argTypes.length) {
                    decoded = decodeArgs(env, args, argTypes);
                } else {
                    // No signature available (Java_* export names do not carry one), so report
                    // the raw refs and only treat a value as a C string when it really looks
                    // like one - a Java reference points at an ART object whose leading words
                    // are never a printable C string.
                    decoded = {};
                    for (let i = 2; i < 6; i++) {
                        const value = args[i];
                        if (value.isNull()) { decoded["a" + (i - 2)] = null; continue; }
                        let maybe = null;
                        try { maybe = value.readUtf8String(64); } catch (e) { }
                        decoded["a" + (i - 2)] = (maybe && /^[\x20-\x7e]{2,64}$/.test(maybe))
                            ? { cstr: maybe } : String(value);
                    }
                }
                console.log(("==> " + label + " @" + where + " " +
                    JSON.stringify(decoded)).slice(0, 600));
                send({ type: "jni-call", label: label, sig: sig, where: where, args: decoded });
            },
            onLeave(retval) {
                if (state.calls > MAX_CALLS_PER_FN) return;
                console.log("<== " + label + " ret=" + retval);
                send({ type: "jni-return", label: label, ret: String(retval) });
            }
        });
        console.log("[+] instrumented " + label + " -> " + where +
            (argTypes ? " (" + argTypes.join(",") + ")" : " (args unknown)"));
        return true;
    } catch (e) {
        console.log("[!] cannot instrument " + label + " @" + fnPtr + ": " + e);
        return false;
    }
}

// ---- strategy 1: statically named Java_* exports ---------------------------
function hookStaticJni() {
    let count = 0;
    Process.enumerateModules().forEach(function (module) {
        if (MODULE_DENY.test(module.name)) return;
        if (!APP_PATH_RE.test(module.path || "")) return;
        let exports = [];
        try { exports = module.enumerateExports(); } catch (e) { return; }
        exports.forEach(function (entry) {
            if (entry.type !== "function") return;
            const match = /^_?(Java_[A-Za-z0-9_]+)$/.exec(entry.name);
            if (!match) return;
            const javaName = match[1];
            const key = module.name + "!" + javaName;
            if (hookedJava.has(key)) return;
            hookedJava.add(key);
            count++;
            instrumentFn(key, javaName + " [" + module.name + "]", null, entry.address, null);
        });
    });
    if (count) console.log("[*] static Java_* hooks added this pass: " + count);
    return count;
}

// JNI's name mangling for RegisterNatives entries: _1 -> "_", _2 -> ";",
// _3 -> "[", _0 -> "." and a plain "_" separates the class/method parts, e.g.
// "getTokenFromLicense" stays as is, "native_1init" becomes "native_init".
function javaNameFromNative(name) {
    return name.replace(/_1/g, "_").replace(/_2/g, ";").replace(/_3/g, "[")
        .replace(/_0/g, ".").replace(/_/g, ".");
}

// ---- strategy 2: RegisterNatives -------------------------------------------
// libliveness.so (face/liveness), libkvs.so, libcrashreporter.so and libnetwork.so export no
// Java_* symbols at all (see tools/jni_surface.py), so this is the only place where their
// (java name, signature, native address) triple becomes visible.
function hookRegisterNatives() {
    const libart = Process.findModuleByName("libart.so");
    if (!libart) { console.log("[!] libart.so not loaded yet"); return 0; }
    let hooked = 0;
    libart.enumerateExports().forEach(function (entry) {
        if (!/RegisterNatives|UnregisterNatives/.test(entry.name)) return;
        const key = "art!" + entry.name;
        if (hookedNative.has(key)) return;
        hookedNative.add(key);
        try {
            Interceptor.attach(entry.address, {
                onEnter(args) {
                    if (/Unregister/.test(entry.name)) {
                        console.log("[JNI] UnregisterNatives(class=" + args[1] + ")");
                        return;
                    }
                    const methods = args[2];
                    const count = args[3].toInt32();
                    if (!methods || methods.isNull() || count <= 0 || count > 512) return;
                    console.log("[JNI] RegisterNatives(class=" + args[1] + ") -> " +
                        count + " methods");
                    for (let i = 0; i < count; i++) {
                        const entryPtr = methods.add(i * 3 * PTR);
                        let name = null, sig = null, fn = null;
                        try {
                            name = entryPtr.readPointer().readCString();
                            sig = entryPtr.add(PTR).readPointer().readCString();
                            fn = entryPtr.add(2 * PTR).readPointer();
                        } catch (e) { continue; }
                        if (!name || !fn || fn.isNull()) continue;
                        const javaName = javaNameFromNative(name);
                        const where = describeModule(fn);
                        registered.push({ java: javaName, signature: sig, native: where });
                        console.log("[JNI]   " + javaName + " " + sig + "  -> " + where);
                        send({ type: "jni-register", method: { java: javaName, signature: sig,
                                                               native: where } });
                        if (MODULE_FOCUS.test(where)) {
                            const parsed = parseSignature(sig);
                            instrumentFn("dyn!" + javaName + "@" + where, javaName + sig,
                                sig, fn, parsed.args);
                        }
                    }
                }
            });
            hooked++;
            console.log("[+] hooked libart " + entry.name);
        } catch (e) {
            console.log("[!] cannot hook " + entry.name + ": " + e);
        }
    });
    return hooked;
}

// ---- strategy 2b: hook the JNI function table directly ----------------------
// libart.so does not export art::JNI::RegisterNatives on Android 9, so the reliable route is
// to read the pointer out of the JNIEnv function table itself (index 215) and interceptor it.
// Any JNIEnv works - we obtain one from a JavaVM* by calling JNIInvokeInterface::GetEnv
// (index 6), and a JavaVM* is handed to every library's JNI_OnLoad as its first argument.
const JNI_TABLE_REGISTER_NATIVES = 215;
const JNI_INVOKE_GET_ENV = 6;
const JNI_VERSION_1_6 = 0x00010006;

let tableHooked = false;

function handleRegisterNatives(args) {
    const methods = args[2];
    const count = args[3].toInt32();
    if (!methods || methods.isNull() || count <= 0 || count > 512) return;
    console.log("[JNI] RegisterNatives(class=" + args[1] + ") -> " + count + " methods");
    for (let i = 0; i < count; i++) {
        const entryPtr = methods.add(i * 3 * PTR);
        let name = null, sig = null, fn = null;
        try {
            name = entryPtr.readPointer().readCString();
            sig = entryPtr.add(PTR).readPointer().readCString();
            fn = entryPtr.add(2 * PTR).readPointer();
        } catch (e) { continue; }
        if (!name || !fn || fn.isNull()) continue;
        const javaName = javaNameFromNative(name);
        const where = describeModule(fn);
        registered.push({ java: javaName, signature: sig, native: where });
        console.log("[JNI]   " + javaName + " " + sig + "  -> " + where);
        send({ type: "jni-register", method: { java: javaName, signature: sig, native: where } });
        if (MODULE_FOCUS.test(where)) {
            const parsed = parseSignature(sig);
            instrumentFn("dyn!" + javaName + "@" + where, javaName + sig, sig, fn, parsed.args);
        }
    }
}

function hookJniTableFromVm(jvm) {
    if (tableHooked || !jvm || jvm.isNull()) return false;
    try {
        const invoke = jvm.readPointer();                            // JNIInvokeInterface*
        const getEnv = invoke.add(JNI_INVOKE_GET_ENV * PTR).readPointer();
        const attachCurrent = invoke.add(4 * PTR).readPointer();     // AttachCurrentThread
        const envOut = Memory.alloc(PTR);
        let rc = new NativeFunction(getEnv, "int", ["pointer", "pointer", "int"])(
            jvm, envOut, JNI_VERSION_1_6);
        // -2 == JNI_EDETACHED: the Frida JS thread is not attached to the VM yet, which is the
        // normal situation for a plain attach. AttachCurrentThread then hands us a usable env.
        if (rc !== 0) {
            rc = new NativeFunction(attachCurrent, "int",
                ["pointer", "pointer", "pointer"])(jvm, envOut, ptr(0));
        }
        const env = envOut.readPointer();
        if (rc !== 0 || env.isNull()) {
            console.log("[!] GetEnv/AttachCurrentThread failed rc=" + rc);
            return false;
        }
        const table = env.readPointer();
        const registerNatives = table.add(JNI_TABLE_REGISTER_NATIVES * PTR).readPointer();
        const unregister = table.add(216 * PTR).readPointer();
        Interceptor.attach(registerNatives, { onEnter: handleRegisterNatives });
        Interceptor.attach(unregister, {
            onEnter(args) { console.log("[JNI] UnregisterNatives(class=" + args[1] + ")"); }
        });
        tableHooked = true;
        console.log("[+] hooked JNIEnv table RegisterNatives @" + registerNatives +
            " (via JavaVM " + jvm + ")");
        return true;
    } catch (e) {
        console.log("[!] cannot hook JNIEnv table: " + e);
        return false;
    }
}

// Every library that has native methods ends up calling JNI_OnLoad(JavaVM*, void*), so its
// onEnter is the cheapest place to pick up a JavaVM*.
const vmWatch = new Set();
function watchJniOnLoad() {
    let added = 0;
    Process.enumerateModules().forEach(function (module) {
        if (vmWatch.has(module.name)) return;
        let entry = null;
        try { entry = module.getExportByName("JNI_OnLoad"); } catch (e) { return; }
        vmWatch.add(module.name);
        added++;
        Interceptor.attach(entry, {
            onEnter(args) {
                console.log("[JNI_OnLoad] " + module.name);
                hookJniTableFromVm(args[0]);
            }
        });
    });
    return added;
}

// In attach mode every already-loaded library has called JNI_OnLoad long ago, so we need
// another way to a JavaVM*: the JNI invocation API's JNI_GetCreatedJavaVMs() is exported by
// libart.so and hands us the VM the process is already using.
function getJavaVm() {
    const libart = Process.findModuleByName("libart.so");
    if (!libart) return null;
    let addr = null;
    try { addr = libart.getExportByName("JNI_GetCreatedJavaVMs"); } catch (e) { }
    if (!addr) { console.log("[!] JNI_GetCreatedJavaVMs not exported"); return null; }
    try {
        const vmBuf = Memory.alloc(PTR);
        const nVms = Memory.alloc(4);
        const rc = new NativeFunction(addr, "int", ["pointer", "int", "pointer"])(vmBuf, 1, nVms);
        if (rc !== 0 || nVms.readInt() < 1) {
            console.log("[!] JNI_GetCreatedJavaVMs rc=" + rc + " n=" + nVms.readInt());
            return null;
        }
        return vmBuf.readPointer();
    } catch (e) {
        console.log("[!] JNI_GetCreatedJavaVMs call failed: " + e);
        return null;
    }
}

// ---- bootstrap -------------------------------------------------------------
// RegisterNatives fires very early (each library's JNI_OnLoad), which is why libart is
// hooked first. The app's own libraries are then dlopen()ed lazily, so we rescan the module
// list on a schedule and also watch dlopen to pick a new library up immediately.
let regHooked = false;
let bootPasses = 0;
function bootstrap() {
    bootPasses++;
    // libart's exported RegisterNatives does not exist on every ROM, so try it only early;
    // the JNIEnv-table route (hookJniTableFromVm) is the one that actually works here.
    if (!regHooked && bootPasses <= 2) regHooked = hookRegisterNatives() > 0;
    if (!tableHooked) hookJniTableFromVm(getJavaVm());
    const vmAdded = watchJniOnLoad();
    const staticAdded = hookStaticJni();
    // Keep the log honest - without this the tool looks dead while nothing has matched yet.
    console.log("[*] pass " + bootPasses + ": JNI_OnLoad watched=" + vmWatch.size +
        " (+" + vmAdded + "), JNIEnv table hooked=" + tableHooked +
        ", static Java_*=" + hookedJava.size + " (+" + staticAdded + ")" +
        ", registered=" + registered.length);
}

["android_dlopen_ext", "dlopen"].forEach(function (fnName) {
    let addr = null;
    try { addr = Process.getModuleByName("libdl.so").getExportByName(fnName); } catch (e) { }
    if (!addr) {
        try { addr = Process.getModuleByName("libc.so").getExportByName(fnName); } catch (e) { }
    }
    if (!addr) { console.log("[!] " + fnName + " not found"); return; }
    Interceptor.attach(addr, {
        onEnter(args) { try { this.path = args[0].readCString(); } catch (e) { } },
        onLeave() {
            if (!this.path || !MODULE_FOCUS.test(this.path)) return;
            console.log("[dlopen] " + this.path);
            setTimeout(bootstrap, 50);
        }
    });
    console.log("[+] watching " + fnName);
});

setImmediate(bootstrap);
[100, 400, 1000, 2000, 3500, 6000, 10000, 16000, 25000].forEach(function (delay) {
    setTimeout(bootstrap, delay);
});
setTimeout(function () {
    console.log("[*] summary: static Java_* hooked=" + hookedJava.size +
        ", registered natives seen=" + registered.length +
        ", instrumented=" + hookedNative.size);
    registered.forEach(function (record) {
        console.log("    " + record.java + " " + record.signature + " -> " + record.native);
    });
}, 26000);
