// arm_hook_probe.js - can Frida instrument this app's ARM libraries at all?
//
// The sample ships only arm64-v8a/armeabi-v7a/armeabi (tools/jni_surface.py), so on the
// x86_64 LDPlayer instance everything it loads runs through the ARM translation layer
// (libnb.so). This probe answers three questions that decide the whole dynamic strategy:
//   1. which of the app's libraries are actually mapped, and from which ABI directory,
//   2. do they expose JNI_OnLoad (i.e. can we ever see their RegisterNatives),
//   3. does Interceptor.attach() accept an address inside such a library, and if it does,
//      are the arguments still meaningful?
//
// Usage: python dump_dex.py --attach <pid> --js hooks/arm_hook_probe.js --seconds 20

const APP_PATH_RE = /\/data\/(app|data)\/com\.example\.targetapp/;

function abiOf(path) {
    const match = /\/(arm64-v8a|armeabi-v7a|armeabi|x86_64|x86)\//.exec(path || "");
    return match ? match[1] : "?";
}

setImmediate(function () {
    console.log("[=] modules mapped from the app's own paths:");
    Process.enumerateModules().forEach(function (module) {
        if (!APP_PATH_RE.test(module.path || "")) return;
        const abi = abiOf(module.path);
        let onload = null;
        try { onload = module.getExportByName("JNI_OnLoad"); } catch (e) { }
        console.log("    " + module.name.padEnd(28) + " abi=" + abi.padEnd(12) +
            " base=" + module.base + " size=" + (module.size / 1024).toFixed(0) + "KB" +
            " JNI_OnLoad=" + (onload ? onload : "-"));
    });

    // Try to instrument something inside an ARM library: pick the first app module whose
    // path says arm64/armeabi and attach to any exported function of it.
    const candidates = Process.enumerateModules().filter(function (module) {
        if (!APP_PATH_RE.test(module.path || "")) return false;
        return /arm64-v8a|armeabi/.test(module.path || "");
    });
    if (!candidates.length) {
        console.log("[i] no ARM app module is mapped right now (nothing loaded yet)");
        return;
    }
    const target = candidates[0];
    console.log("[i] trying to instrument " + target.name + " (" + abiOf(target.path) + ")");
    let exports = [];
    try { exports = target.enumerateExports(); } catch (e) {
        console.log("[!] enumerateExports failed: " + e);
        return;
    }
    console.log("    exports: " + exports.length);

    let hooked = 0;
    exports.slice(0, 5).forEach(function (entry) {
        if (entry.type !== "function") return;
        try {
            Interceptor.attach(entry.address, {
                onEnter() { }
            });
            hooked++;
            console.log("    [ok]   attached to " + entry.name + " @" + entry.address);
        } catch (e) {
            console.log("    [fail] " + entry.name + " @" + entry.address + " -> " + e);
        }
    });
    console.log("[=] result: " + hooked + "/" + Math.min(exports.length, 5) +
        " attach attempts succeeded inside " + target.name);
});
