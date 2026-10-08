// dump_dex_write.js - catch the decrypted DEX at the syscall boundary.
//
// Third strategy after (1) brute-force range scanning - too slow in an ARM-translated
// process, and (2) hooking art::ArtDexFileLoader::Open* - never called for this shell:
// watch libc instead. If the shell hands the plaintext DEX to *anything* through write()/
// pwrite() (a file it drops, a pipe, a socket or /proc/self/mem) we see the "dex\n03x"
// magic in the buffer. open()/openat() are logged for dex/shell-looking paths so the
// on-disk side of the unpacking is visible too.
//
// Works without the Java bridge; pure libc hooks.

const MAGIC_BYTES = [0x64, 0x65, 0x78, 0x0a, 0x30, 0x33]; // "dex\n03"
const seen = new Set();
let writes = 0;

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

function isDex(ptr, len) {
    if (ptr.isNull() || len < 0x70) return false;
    let head = null;
    try { head = new Uint8Array(ptr.readByteArray(MAGIC_BYTES.length)); } catch (e) { return false; }
    if (head === null) return false;
    for (let i = 0; i < MAGIC_BYTES.length; i++) {
        if (head[i] !== MAGIC_BYTES[i]) return false;
    }
    return true;
}

function sendDex(ptr, len, where) {
    let declared = len, strings = -1, methods = -1, classes = -1;
    try {
        declared = ptr.add(0x20).readU32();
        strings = ptr.add(0x38).readU32();
        methods = ptr.add(0x58).readU32();
        classes = ptr.add(0x60).readU32();
    } catch (e) { }
    const key = where + ":" + ptr + ":" + declared;
    if (seen.has(key)) return;
    seen.add(key);
    const want = (declared >= 0x70 && declared <= 256 * 1024 * 1024) ? declared : len;
    const data = ptr.readByteArray(want);
    if (data === null) return;
    const version = Array.from(new Uint8Array(data, 4, 3))
        .map(c => String.fromCharCode(c)).join("");
    send({
        type: "dex", address: ptr.toString(), size: want, version: version,
        strings: strings, methods: methods, classes: classes, source: where,
    }, data);
    console.log("[+] captured DEX via " + where + " @ " + ptr + " size=" + want +
        " strings=" + strings + " methods=" + methods + " classes=" + classes);
}

function hookWrite(name) {
    const addr = findExport("libc.so", name);
    if (!addr) { console.log("[!] " + name + " not found"); return; }
    Interceptor.attach(addr, {
        onEnter(args) {
            writes++;
            const len = args[2].toInt32();
            if (len < 0x70 || len > 256 * 1024 * 1024) return;
            if (isDex(args[1], len)) {
                sendDex(args[1], len, name + "/fd" + args[0].toInt32());
            }
        }
    });
    console.log("[+] hooked " + name);
}

function hookOpen(name) {
    const addr = findExport("libc.so", name);
    if (!addr) { console.log("[!] " + name + " not found"); return; }
    Interceptor.attach(addr, {
        onEnter(args) {
            let path = null;
            try { path = args[0].readCString(); } catch (e) { }
            if (path && /dex|shell|targetapp|\.apk|\.odex|\.vdex|code_cache/i.test(path)) {
                console.log("[open] " + name + "(" + path + ")");
            }
        }
    });
    console.log("[+] hooked " + name);
}

setImmediate(function () {
    ["write", "pwrite", "pwrite64", "writev"].forEach(hookWrite);
    ["open", "openat", "openat64"].forEach(hookOpen);
    setTimeout(function () {
        console.log("[*] write() calls observed so far: " + writes);
    }, 15000);
});
