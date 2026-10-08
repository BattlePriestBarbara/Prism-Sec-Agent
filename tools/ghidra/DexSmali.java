import org.jf.baksmali.Baksmali;
import org.jf.baksmali.BaksmaliOptions;
import org.jf.dexlib2.DexFileFactory;
import org.jf.dexlib2.Opcodes;
import org.jf.dexlib2.dexbacked.DexBackedDexFile;
import org.jf.dexlib2.iface.MultiDexContainer;

import java.io.File;

/**
 * Disassembles a .dex (or every classesN.dex inside an .apk) into smali.
 *
 * Uses the baksmali + dexlib2 jars that ship with Ghidra, so no download is needed.
 * The baksmali *CLI* is unusable here (it needs jcommander, which Ghidra does not ship),
 * hence this tiny API driver.
 *
 *   javac -cp "baksmali-2.5.2.jar;dexlib2-2.5.2.jar;util-2.5.2.jar;guava-*.jar" DexSmali.java
 *   java  -cp "<classes>;baksmali-2.5.2.jar;dexlib2-2.5.2.jar;util-2.5.2.jar;guava-*.jar" \
 *         DexSmali <input.dex|input.apk> <outputDir> [apiLevel]
 */
public class DexSmali {
    public static void main(String[] args) throws Exception {
        if (args.length < 2) {
            System.err.println("usage: DexSmali <input.dex|input.apk> <outputDir> [apiLevel]");
            System.exit(2);
        }
        File input = new File(args[0]);
        File output = new File(args[1]);
        int api = args.length > 2 ? Integer.parseInt(args[2]) : 28;
        Opcodes opcodes = Opcodes.forApi(api);

        BaksmaliOptions options = new BaksmaliOptions();
        options.apiLevel = api;

        int entries = 0;
        if (input.getName().toLowerCase().endsWith(".apk")
                || input.getName().toLowerCase().endsWith(".jar")) {
            MultiDexContainer<? extends DexBackedDexFile> container =
                    DexFileFactory.loadDexContainer(input, opcodes);
            for (String name : container.getDexEntryNames()) {
                MultiDexContainer.DexEntry<? extends DexBackedDexFile> entry =
                        container.getEntry(name);
                File dir = new File(output, name.replace(".dex", ""));
                Baksmali.disassembleDexFile(entry.getDexFile(), dir, 1, options);
                System.out.println("disassembled " + name + " -> " + dir);
                entries++;
            }
        } else {
            DexBackedDexFile dex = DexFileFactory.loadDexFile(input, opcodes);
            Baksmali.disassembleDexFile(dex, output, 1, options);
            System.out.println("disassembled " + input.getName() + " -> " + output);
            entries++;
        }
        System.out.println("entries: " + entries);
    }
}
