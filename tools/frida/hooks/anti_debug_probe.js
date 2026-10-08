// anti_debug_probe.js - RECON ONLY. Records which detection APIs the app / packer calls,
// so you know what has to be neutralised before a full unpack on this build.
//
// Everything we saw in the shell's native libraries suggests these checks:
//   * ptrace self-attach            (native: ptrace)
//   * /proc/self/maps parsing       (native: fopen/fgets, "0x%lx-0x%lx" scanf pattern)
//   * dl_iterate_phdr               (native: walks loaded modules -> finds frida/hook libs)
//   * inotify_* watching files      (native: detects tools that drop files)
//   * signing check via reflection  (Java: PackageManager.getPackageInfo(...).signatures + MessageDigest)
//   * emulator/root probes          (strings: /dev/socket/qemu, XposedBridge.jar, libsubstrate.so, su)
//
// Usage: <FRIDA_ROOT>\frida.cmd -U -f com.example.targetapp -l <FRIDA_ROOT>\hooks\anti_debug_probe.js
//
// FRIDA 17: the Java bridge is no longer bundled with GumJS, so `Java` is undefined
// unless you fed this script through frida-compile together with frida-java-bridge.
// The native half of the probe (ptrace / fopen / dl_iterate_phdr / inotify) always runs.

function log(tag, text) {
    console.log("[" + tag + "] " + text);
}

const hasJava = (typeof Java !== "undefined") && Java.available;

// Frida 17 removed both Module.findExportByName() and Module.getExportByName(); only the
// *Global* variants plus the per-Module instance methods remain. Resolve through the owning
// module, which also keeps this working on older frida releases.
function findExport(moduleName, symbol) {
    try {
        if (typeof Module.findExportByName === "function") {
            return Module.findExportByName(moduleName, symbol);
        }
        return Process.getModuleByName(moduleName).getExportByName(symbol);
    } catch (e) {
        return null;
    }
}

function hookJava() {
    const targets = [
        ["android.os.Debug", ["isDebuggerConnected", "waitingForDebugger"]],
        ["java.lang.System", ["getProperty", "getenv"]],
        ["java.io.File", ["exists"]],
        ["java.lang.Runtime", ["exec"]],
        ["java.lang.ProcessBuilder", ["start"]]
    ];
    targets.forEach(function ([className, methods]) {
        try {
            const clazz = Java.use(className);
            methods.forEach(function (methodName) {
                if (!clazz[methodName]) return;
                clazz[methodName].overloads.forEach(function (overload) {
                    overload.implementation = function () {
                        let out = null;
                        for (let i = 0; i < arguments.length; i++) {
                            out = (out === null ? "" : out + ", ") + arguments[i];
                        }
                        log(className + "." + methodName, out);
                        return overload.apply(this, arguments);
                    };
                });
            });
        } catch (e) { }
    });

    // signature check / package info read (the shell resolves getPackageInfo + signatures)
    try {
        const PM = Java.use("android.content.pm.PackageManager");
        PM.getPackageInfo.overloads.forEach(function (overload) {
            overload.implementation = function () {
                log("PackageManager.getPackageInfo", arguments[0] + " flags=" + arguments[1]);
                return overload.apply(this, arguments);
            };
        });
    } catch (e) { }
    try {
        const MD = Java.use("java.security.MessageDigest");
        MD.digest.overloads.forEach(function (overload) {
            overload.implementation = function () {
                const result = overload.apply(this, arguments);
                log("MessageDigest.digest", this.getAlgorithm() + " -> " +
                    (result ? Array.from(new Uint8Array(result)).map(b => b.toString(16).padStart(2, "0")).join("") : "null"));
                return result;
            };
        });
    } catch (e) { }
}

function hookNative() {
    // libc-level probe calls: logged only, behaviour is never altered.
    [["libc.so", "ptrace"], ["libc.so", "fopen"], ["libc.so", "open"],
     ["libc.so", "dl_iterate_phdr"], ["libc.so", "inotify_init"],
     ["libc.so", "inotify_add_watch"], ["libc.so", "__system_property_get"]].forEach(function ([mod, sym]) {
        let address = null;
        address = findExport(mod, sym);
        if (!address || address.isNull()) return;
        const interesting = (sym === "fopen" || sym === "open");
        Interceptor.attach(address, {
            onEnter(args) {
                let path = null;
                try { path = args[0].readCString(); } catch (e) { }
                if (!interesting || (path && (path.indexOf("/proc") === 0 || path.indexOf("su") >= 0 ||
                        path.indexOf("frida") >= 0 || path.indexOf("magisk") >= 0 ||
                        path.indexOf("xposed") >= 0 || path.indexOf("/system") === 0))) {
                    log("native:" + sym, path === null ? String(args[0]) : path);
                }
            }
        });
        console.log("[+] hooked native " + sym);
    });
}

setImmediate(function () {
    if (hasJava) {
        Java.perform(function () { hookJava(); hookNative(); });
    } else {
        console.log("[!] Java bridge unavailable (Frida 17) - native probes only");
        hookNative();
    }
    console.log("[*] probe active - exercise the app for ~30s, then read this log");
});
