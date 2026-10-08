// api_probe.js - one-shot probe of the GumJS API surface we depend on.
//
// Frida 17 renamed/removed several lookup helpers (Module.findExportByName ->
// Module.getExportByName, etc.), and a wrong guess turns into a silent "not found".
// Run this once per new frida release:
//     python dump_dex.py --package <pkg> --js hooks/api_probe.js --seconds 15

function report(label, fn) {
    try {
        const value = fn();
        console.log("[ok]   " + label + " -> " + value);
    } catch (e) {
        console.log("[fail] " + label + " -> " + e);
    }
}

setImmediate(function () {
    console.log("frida " + Frida.version + "  runtime=" + Script.runtime);
    console.log("typeof Module.findExportByName : " + typeof Module.findExportByName);
    console.log("typeof Module.getExportByName  : " + typeof Module.getExportByName);
    console.log("typeof Module.findGlobalExportByName : " + typeof Module.findGlobalExportByName);
    console.log("typeof Module.getGlobalExportByName  : " + typeof Module.getGlobalExportByName);
    console.log("typeof Process.findModuleByName : " + typeof Process.findModuleByName);
    console.log("typeof Process.getModuleByName  : " + typeof Process.getModuleByName);

    report("Process.findModuleByName('libc.so')", function () {
        return Process.findModuleByName("libc.so").name;
    });
    report("Process.getModuleByName('libc.so')", function () {
        return Process.getModuleByName("libc.so").base;
    });
    report("Module.getExportByName('libc.so','write')", function () {
        return Module.getExportByName("libc.so", "write");
    });
    report("Module.findGlobalExportByName('write')", function () {
        return Module.findGlobalExportByName("write");
    });
    report("Module.getGlobalExportByName('write')", function () {
        return Module.getGlobalExportByName("write");
    });
    report("libc module .getExportByName('write')", function () {
        return Process.getModuleByName("libc.so").getExportByName("write");
    });
    report("libc module .findExportByName('write')", function () {
        return Process.getModuleByName("libc.so").findExportByName("write");
    });
    report("DebugSymbol.fromName('write')", function () {
        return DebugSymbol.fromName("write").address;
    });
});
