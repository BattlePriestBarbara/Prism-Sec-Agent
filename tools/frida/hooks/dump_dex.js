// dump_dex.js - memory-scan DEX dumper for packed apps.
//
// Strategy: after the packer has decrypted the real DEX it must exist in the process as
// a readable buffer starting with the DEX magic "dex\n03x\0" (either a mapped file for
// the on-disk copy or an anonymous region for the in-memory one). We scan readable
// ranges, read the declared DEX size from the header and stream the blob to the host
// (see dump_dex.py), which writes it next to this script's output dir.
//
// Why streaming instead of writing on-device: /data/local/tmp is not writable from an
// unprivileged app process on Android 9+, and the host side needs no root at all.
//
// FRIDA 17 NOTE: GumJS no longer bundles the Java/ObjC bridges (they are separate npm
// packages now), so `Java` is undefined unless you compiled a frida-java-bridge agent.
// The unpack itself needs no Java at all - we therefore feature-detect the bridge and
// degrade gracefully instead of aborting the whole script.
//
// Hooks for the shell stub interfaces found in this APK (com.example.shell.ShellStub) are attached
// best-effort: they tell us which assets are being decrypted and served from memory.

// "dex\n03" covers 035/036/037/038/039 - the header has the exact version at offset 4.
const MAGIC = "64 65 78 0a 30 33";
const seen = new Set();
const hasJava = (typeof Java !== "undefined") && Java.available;

function u32(buf, off) {
    return buf.add(off).readU32();
}

const DEX_HEADER = {
    file_size: 0x20, header_size: 0x24, endian_tag: 0x28,
    string_ids_size: 0x38, type_ids_size: 0x40, method_ids_size: 0x58,
    class_defs_size: 0x60,
};

function dexStats(base) {
    // Reading the counts from the header is how we tell the shell's 284-byte placeholder
    // (0 classes) apart from the real decrypted DEX (thousands of strings/methods).
    const stats = {};
    for (const [name, offset] of Object.entries(DEX_HEADER)) {
        try { stats[name] = u32(base, offset); } catch (e) { stats[name] = -1; }
    }
    return stats;
}

function dumpAt(base, declaredSize) {
    const stats = dexStats(base);
    // The DEX header stores file_size at 0x20; sanity-clamp it.
    let size = declaredSize;
    if (!size || size < 0x70 || size > 128 * 1024 * 1024) size = 16 * 1024 * 1024;
    const data = base.readByteArray(size);
    if (data === null) return;
    const version = Array.from(new Uint8Array(data, 4, 3))
        .map(c => String.fromCharCode(c)).join("");
    send({
        type: "dex", address: base.toString(), size: size, version: version,
        strings: stats.string_ids_size, methods: stats.method_ids_size,
        classes: stats.class_defs_size, endian: stats.endian_tag,
    }, data);
    console.log("[+] dumped DEX @ " + base + " size=" + size + " version=" + version +
        " strings=" + stats.string_ids_size + " methods=" + stats.method_ids_size +
        " classes=" + stats.class_defs_size + " endian=0x" +
        (stats.endian_tag >>> 0).toString(16));
}

// The decrypted DEX lives in memory only (the shell feeds it to InMemoryDexClassLoader),
// so we look at anonymous mappings. Scanning every mapping of a 4 GB guest inside an
// ARM-translated process is far too slow, hence: anon-only + a per-range size cap, plus
// byte progress so a stalled round is visible in the log.
function scanRanges(label) {
    let hits = 0;
    let bytes = 0;
    // Only this app's own /data mappings are considered interesting: the shell may hand the
    // decrypted DEX over as a file it wrote and mmapped. Everything else (apk/oat/boot
    // framework mappings) is either the unpacked stub or plain system code, and scanning
    // all of it every round is what made the earlier attempts stall.
    const interesting = /shell|com\.example\.targetapp/i;
    ["rw-", "r--", "r-x"].forEach(protection => {
        Process.enumerateRanges(protection).forEach(range => {
            const filePath = (range.file && range.file.path) || null;
            if (filePath !== null) {
                if (!interesting.test(filePath)) return;
                if (!filePath.startsWith("/data/")) return;
            }
            if (range.size < 0x70 || range.size > 64 * 1024 * 1024) return;
            bytes += range.size;
            if (filePath !== null) console.log("[*] " + label + " scanning app mapping: " +
                filePath + " size=" + (range.size / 1048576).toFixed(1) + " MB");
            try {
                Memory.scanSync(range.base, range.size, MAGIC).forEach(match => {
                    const key = match.address.toString();
                    if (seen.has(key)) return;
                    seen.add(key);
                    hits++;
                    let declared = 0;
                    try { declared = u32(match.address, 0x20); } catch (e) { }
                    dumpAt(match.address, declared);
                });
            } catch (e) { }
        });
    });
    console.log("[*] " + label + ": scanned " + (bytes / 1048576).toFixed(1) +
        " MB (anon + app file mappings), new hits: " + hits +
        " (total " + seen.size + ")");
    send({ type: "scan-done", hits: hits, total: seen.size, scanned_mb: +(bytes / 1048576).toFixed(1) });
}

function hookStub() {
    try {
        const ShellStub = Java.use("com.example.shell.ShellStub");
        console.log("[*] com.example.shell.ShellStub found: " + Object.getOwnPropertyNames(ShellStub).length + " members");
        // asset / resource decryption service point: shows which resource the shell feeds to the app.
        ["interface199", "interface19", "interface51"].forEach(name => {
            try {
                const method = ShellStub[name];
                if (!method) return;
                const overloads = method.overloads;
                overloads.forEach(ov => {
                    ov.implementation = function () {
                        const arg = arguments.length > 1 ? arguments[1] : arguments[0];
                        console.log("[asset] " + name + "(" + arg + ")");
                        if (ov.argumentTypes.length === 2) {
                            try {
                                const stream = ov.call(this, arguments[0], arguments[1]);
                                return stream;
                            } catch (e) { }
                        }
                        return ov.apply(this, arguments);
                    };
                });
            } catch (e) { }
        });
    } catch (e) {
        console.log("[!] com.example.shell.ShellStub not visible yet: " + e);
    }
}

setImmediate(function () {
    if (hasJava) {
        Java.perform(function () {
            hookStub();
            scanRanges("round t0 (app still suspended)");
        });
    } else {
        console.log("[!] Java bridge unavailable (Frida 17 dropped the built-in bridge) - "
            + "running the native-only memory scan");
        scanRanges("round t0 (app still suspended)");
    }
    // The shell decrypts the payload shortly after the app resumes, so the rounds are
    // front-loaded: small+cheap scans every ~1s early on, then a few late ones in case the
    // real DEX only shows up when the first Activity pulls its classes in.
    [300, 1000, 2000, 3000, 4500, 6000, 8000, 11000, 15000, 20000, 30000].forEach(delay =>
        setTimeout(() => scanRanges("round t+" + delay), delay));
});
