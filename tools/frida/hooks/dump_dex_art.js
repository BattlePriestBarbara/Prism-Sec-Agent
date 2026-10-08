// dump_dex_art.js - precise DEX capture by hooking ART's own dex openers.
//
// Why this beats memory scanning for the commercial packer (VIP tier): the shell never writes the real DEX to
// disk (all it leaves in /data/data/<pkg>/.shell/ is a 284-byte placeholder "tmp.dex" plus
// its own libshell_vip_64.so), so the decrypted image only exists as a buffer that gets
// handed to ART. Brute-force range scanning of a multi-hundred-MB address space is far too
// slow to run every second inside an ARM-translated process - but ART's entry points are
// exported symbols, so we can hook them and grab (buffer, size) directly.
//
// Works without the Java bridge (Frida 17 no longer bundles it) because libart.so is a
// normal ELF with a dynamic symbol table.
//
// Usage (host side): python dump_dex.py --js <FRIDA_ROOT>\hooks\dump_dex_art.js --package ...

const MAGIC = "64 65 78 0a 30 33"; // dex\n03x
const seen = new Set();
const hooked = new Set();

function u32(buf, off) {
    return buf.add(off).readU32();
}

function sendDex(base, size, where) {
    if (base.isNull() || size < 0x70 || size > 256 * 1024 * 1024) return;
    let magic = null;
    try { magic = base.readByteArray(7); } catch (e) { return; }
    if (!magic) return;
    const head = Array.from(new Uint8Array(magic))
        .map(b => b.toString(16).padStart(2, "0")).join(" ");
    if (!head.startsWith(MAGIC)) {
        console.log("[" + where + "] not a DEX (magic " + head + ")");
        return;
    }
    const key = base.toString() + ":" + size;
    if (seen.has(key)) return;
    seen.add(key);

    let declared = size, strings = -1, methods = -1, classes = -1;
    try {
        declared = u32(base, 0x20);
        strings = u32(base, 0x38);
        methods = u32(base, 0x58);
        classes = u32(base, 0x60);
    } catch (e) { }
    const want = (declared >= 0x70 && declared <= 256 * 1024 * 1024) ? declared : size;
    const data = base.readByteArray(want);
    if (data === null) {
        console.log("[" + where + "] read failed @ " + base + " size=" + want);
        return;
    }
    const version = Array.from(new Uint8Array(data, 4, 3))
        .map(c => String.fromCharCode(c)).join("");
    send({
        type: "dex", address: base.toString(), size: want, version: version,
        strings: strings, methods: methods, classes: classes, source: where,
    }, data);
    console.log("[" + where + "] captured DEX @ " + base + " size=" + want +
        " version=" + version + " strings=" + strings + " methods=" + methods +
        " classes=" + classes);
}

// Android 9 exposes the in-memory entry points through art::ArtDexFileLoader; the older
// art::DexFile::OpenMemory name is kept as a fallback for other API levels.
//   OpenCommon(const uint8_t* base, size_t size, const uint8_t* data_base, size_t data_size,
//              const std::string& location, uint32_t checksum, const OatDexFile*, bool, bool,
//              std::string*, std::unique_ptr<DexFileContainer>, VerifyResult*)
//   Open(const uint8_t* base, size_t size, const std::string& location, uint32_t checksum,
//        const OatDexFile*, bool verify, bool verify_checksum, std::string*)
// -> args[0] = base, args[1] = size in both cases.
const RE_INMEMORY = /ArtDexFileLoader(10OpenCommon|4Open)EPKhm|4OpenEPKhm|DexFile.*OpenMemory/;
const RE_PATHBASED = /ArtDexFileLoader4OpenEPKc|DexFile4OpenEPKc/;
const RE_ZIP = /ArtDexFileLoader7OpenZip|DexFile7OpenZip/;

function hookArt() {
    const mod = Process.findModuleByName("libart.so");
    if (!mod) {
        console.log("[!] libart.so not loaded yet");
        return;
    }
    const exports = mod.enumerateExports();
    const dexRelated = exports.map(e => e.name).filter(n => n.indexOf("Dex") !== -1);
    const openers = dexRelated.filter(n => /Open/.test(n));
    console.log("[*] libart.so: " + dexRelated.length + " dex-related exports, " +
        openers.length + " openers:");
    openers.forEach(n => console.log("      " + n));

    exports.filter(e => RE_INMEMORY.test(e.name)).forEach(e => {
        if (hooked.has("mem:" + e.address)) return;
        hooked.add("mem:" + e.address);
        try {
            Interceptor.attach(e.address, {
                onEnter(args) {
                    const size = args[1].toInt32();
                    console.log("--> IN-MEMORY dex: base=" + args[0] + " size=" + size);
                    sendDex(args[0], size, "OpenMemory");
                }
            });
            console.log("[+] hooked in-memory opener " + e.name + " @ " + e.address);
        } catch (err) { console.log("[!] hook failed for " + e.name + ": " + err); }
    });

    // File/zip based loaders: log only, so we can see whether anything was materialised on
    // disk after all (the shell writes a 284-byte placeholder into <data>/.shell/tmp.dex).
    exports.filter(e => RE_PATHBASED.test(e.name) || RE_ZIP.test(e.name)).forEach(e => {
        if (hooked.has("path:" + e.address)) return;
        hooked.add("path:" + e.address);
        try {
            Interceptor.attach(e.address, {
                onEnter(args) {
                    let where = String(args[0]);
                    try {
                        if (RE_ZIP.test(e.name)) where = "fd " + where;
                        else where = args[0].readCString();
                    } catch (err) { }
                    console.log("--> " + e.name.substring(0, 60) + " => " + where);
                }
            });
            console.log("[+] hooked path/zip opener " + e.name.substring(0, 60) + " @ " + e.address);
        } catch (err) { console.log("[!] hook failed for " + e.name + ": " + err); }
    });
}

setImmediate(hookArt);

// libart may finish loading slightly later on some images - retry a few times.
[500, 2000, 5000].forEach(delay => setTimeout(function () {
    try { hookArt(); } catch (e) { console.log("[!] retry failed: " + e); }
}, delay));
