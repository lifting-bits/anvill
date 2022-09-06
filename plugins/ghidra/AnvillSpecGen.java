//
//@author Trail of Bits, inc.
//@category 
//@keybinding
//@menupath
//@toolbar

import ghidra.app.script.GhidraScript;
import ghidra.program.model.lang.Processor;
import ghidra.util.exception.CancelledException;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Map;
import java.util.HashMap;
import java.util.Arrays;

import com.google.gson.*;

public class AnvillSpecGen extends GhidraScript {
    public class AnvillMemory {
        public long address;
        public boolean is_executable;
        public boolean is_writeable;
        public String data;

        public Map<String, Object> toSpec() {
            var map = new HashMap<String, Object>();
            map.put("address", address);
            map.put("is_executable", is_executable);
            map.put("is_writeable", is_writeable);
            map.put("data", data);
            return map;
        }
    }

    public class AnvillSpec {
        public String arch;
        public String os;
        public AnvillMemory[] memory;

        public Map<String, Object> toSpec() {
            var map = new HashMap<String, Object>();
            map.put("arch", arch);
            map.put("os", os);
            map.put("memory", Arrays.stream(memory).map(AnvillMemory::toSpec).toArray());
            return map;
        }
    }

    static final byte[] HEX_ARRAY = "0123456789ABCDEF".getBytes(StandardCharsets.US_ASCII);
    static String bytesToHex(byte[] bytes) {
        byte[] hexChars = new byte[bytes.length * 2];
        for (int j = 0; j < bytes.length; j++) {
            int v = bytes[j] & 0xFF;
            hexChars[j * 2] = HEX_ARRAY[v >>> 4];
            hexChars[j * 2 + 1] = HEX_ARRAY[v & 0x0F];
        }
        return new String(hexChars, StandardCharsets.UTF_8);
    }

    static String getRemillOSName(String format) {
        format = format.toLowerCase();
        if(format.indexOf("mac os") >= 0) {
            return "macos";
        }
        if(format.indexOf("win") >= 0) {
            return "windows";
        }
        if(format.indexOf("solaris") >= 0) {
            return "solaris";
        }
        if(format.indexOf("linux") >= 0) {
            return "linux";
        }
        return "invalid";
    }

    static String getRemillArchName(Processor proc) {
        var name = proc.toString().toLowerCase();
        if(name.indexOf("aarch64") >= 0) {
            return "aarch64";
        }
        if(name.indexOf("x86") >= 0) {
            return "x86";
        }
        return "invalid";
    }

    AnvillMemory[] getMemorySegments() throws IOException {
        var memory = currentProgram.getMemory();
        var blocks = memory.getBlocks();
        var list = new ArrayList<AnvillMemory>();
        for (int i = 0; i < blocks.length; ++i) {
            var block = blocks[i];
            if(!block.isRead()) {
                continue;
            }

            var data = block.getData().readAllBytes();
            if(data.length == 0) {
                continue;
            }

            var mem = new AnvillMemory();
            mem.address = block.getStart().getOffset();
            mem.is_executable = block.isExecute();
            mem.is_writeable = block.isWrite();
            mem.data = bytesToHex(data);

            list.add(mem);
        }
        return list.toArray(AnvillMemory[]::new);
    }

    @Override
    protected void run() throws Exception {
        var spec = new AnvillSpec();
        var language = currentProgram.getLanguage();
        var processor = language.getProcessor();
        spec.arch = getRemillArchName(processor);
        spec.os = getRemillOSName(currentProgram.getExecutableFormat());

        spec.memory = getMemorySegments();

        try {
            var file = askFile("Spec file path", "Save");
            var gson = new GsonBuilder().setPrettyPrinting().create();
            println(gson.toJson(spec));
            java.nio.file.Files.write(file.toPath(), gson.toJson(spec).getBytes());
        } catch(CancelledException ex) {

        }
    }
}
