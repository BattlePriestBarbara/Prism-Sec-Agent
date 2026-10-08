// trace_native.js - log the crypto/licence entry points we identified in the APK.
//
// libtransport.so is NOT stripped and exports its logic, so these names resolve directly:
//   _Z19genECDHsharedsecretP9ec_key_stPhj   (ECDH shared secret)
//   _Z13genECDHpubkeySsPhRj                 (ECDH public key gen)
//   _Z18aes_256_cbc_encodePKhRKSs / _decode (AES-256-CBC)
//   _Z13pemString2keySs                     (PEM -> EC key)
//   Java_com_example_transport_JniHand_*           (JNI entry points)
// the licence-check entry points of the OCR/licence modules can be hooked the same way.
//
// Usage:  <FRIDA_ROOT>\frida.cmd -U -f com.example.targetapp -l <FRIDA_ROOT>\hooks\trace_native.js

const TARGETS = [
    ["libtransport.so", "_Z19genECDHsharedsecretP9ec_key_stPhj"],
    ["libtransport.so", "_Z13genECDHpubkeySsPhRj"],
    ["libtransport.so", "_Z18aes_256_cbc_encodePKhRKSs"],
    ["libtransport.so", "_Z18aes_256_cbc_decodePKhRKSs"],
    ["libtransport.so", "_Z13pemString2keySs"],
    ["libtransport.so", "Java_com_example_transport_JniHand_getAppPubKey"],
    ["libtransport.so", "Java_com_example_transport_JniHand_paramJsonEncode"],
    ["libtransport.so", "Java_com_example_transport_JniHand_paramJsonDecode"],
    ["liblicense.so", "Java_com_example_license_License_initLicenseWithToken"],
    ["liblicense.so", "Java_com_example_license_License_getLicenseState"],
    ["libocr.so", "Java_com_example_ocr_jni_JniInterface_getToken"],
    ["libocr.so", "Java_com_example_ocr_jni_JniInterface_getTokenFromLicense"]
];

function hexdumpPtr(ptr, length) {
    try { return hexdump(ptr, { length: length, ansi: false }); }
    catch (e) { return "<unreadable>"; }
}

// Frida 17 removed both Module.findExportByName() and Module.getExportByName(); resolve
// through the owning module instead (see hooks/api_probe.js for the full API survey).
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

// The app's own libraries are ARM and only get dlopen()ed once the app starts touching its
// own classes, i.e. AFTER our script is loaded (frida loads the agent while the spawned
// process is still suspended). Hooking once at load time therefore finds nothing, so we
// retry on a schedule and hook whatever has appeared since the previous pass.
const hooked = new Set();

function hookTargets() {
    let pending = 0;
    TARGETS.forEach(([moduleName, symbol]) => {
        const key = moduleName + "!" + symbol;
        if (hooked.has(key)) return;
        const address = findExport(moduleName, symbol);
        if (!address || address.isNull()) {
            if (Process.findModuleByName(moduleName)) pending++;
            return; // module not loaded (yet) or symbol missing in this ABI
        }
        hooked.add(key);
        console.log("[+] hooked " + key + " @ " + address);
        Interceptor.attach(address, {
            onEnter(args) {
                this.tag = key;
                console.log("--> " + this.tag);
                for (let i = 0; i < 4; i++) {
                    const p = args[i];
                    if (p.isNull()) { console.log("      arg" + i + " = NULL"); continue; }
                    // numeric arguments print directly; pointers print their address, then up to 32 bytes
                    console.log("      arg" + i + " = " + p);
                    try {
                        const head = p.readByteArray(32);
                        if (head) console.log(hexdump(p, { length: 32, ansi: false }));
                    } catch (e) { }
                }
            },
            onLeave(retval) {
                console.log("<-- " + this.tag + " ret=" + retval);
                try {
                    const data = retval.readByteArray(32);
                    if (data) console.log(hexdump(retval, { length: 32, ansi: false }));
                } catch (e) { }
            }
        });
    });
    return { pending: pending, done: hooked.size, total: TARGETS.length };
}

// FRIDA 17: `Java` only exists when frida-java-bridge was compiled in, so feature-detect it first.
// Native hooking works either way; the flag only controls an extra Java-side hint.
const hasJava = (typeof Java !== "undefined") && Java.available;
if (!hasJava) {
    console.log("[!] Java bridge unavailable (Frida 17) - native tracing only");
}

// Scheduling: dense retries early (a shell dlopens its own libs ~0.5-3 s after resume), then slower.
[0, 200, 500, 1000, 1500, 2500, 4000, 6000, 9000, 14000, 20000].forEach(delay => {
    setTimeout(function () {
        const status = hookTargets();
        if (delay === 0 || status.pending || status.done < status.total) {
            console.log("[*] hook pass t+" + delay + "ms: hooked " + status.done + "/" +
                status.total + ", module loaded but symbol missing " + status.pending);
        }
        if (delay === 20000) {
            ["libtransport.so", "liblicense.so", "libocr.so", "libshell_vip_64.so"]
                .forEach(function (name) {
                    const module = Process.findModuleByName(name);
                    console.log((module ? "[*] loaded: " : "[*] not loaded: ") + name +
                        (module ? " base=" + module.base : ""));
                });
        }
    }, delay);
});

// App libraries are lazily loaded (dlopen only when the matching feature is used), so watch dlopen:
// hook the target library the moment it appears instead of waiting for the next poll round.
["android_dlopen_ext", "dlopen"].forEach(function (fn) {
    const addr = findExport("libdl.so", fn) || findExport("libc.so", fn);
    if (!addr) {
        console.log("[!] " + fn + " not found - relying on the polling passes");
        return;
    }
    Interceptor.attach(addr, {
        onEnter(args) {
            let path = null;
            try { path = args[0].readCString(); } catch (e) { }
            this.path = path;
        },
        onLeave(retval) {
            if (!this.path) return;
            if (/libtransport|liblicense|libocr|libliveness|libchannel/i.test(this.path)) {
                console.log("[dlopen] " + this.path + " -> " + retval);
                const status = hookTargets();
                console.log("[*] after dlopen: hooked " + status.done + "/" + status.total);
            }
        }
    });
    console.log("[+] watching " + fn);
});
