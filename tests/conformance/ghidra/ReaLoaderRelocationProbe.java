//@category REA Verification

import com.google.gson.JsonArray;
import com.google.gson.JsonObject;
import generic.jar.ResourceFile;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.script.GhidraScript;
import ghidra.app.script.GhidraScriptProvider;
import ghidra.app.script.GhidraScriptUtil;
import ghidra.program.database.mem.FileBytes;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.mem.MemoryBlockSourceInfo;
import ghidra.program.model.reloc.Relocation;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.SymbolIterator;
import java.io.File;
import java.lang.reflect.Field;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.nio.file.Files;
import java.security.MessageDigest;
import java.util.HexFormat;
import java.util.Iterator;
import java.util.List;

/**
 * Exercises the production loader-relocation boundary on a real imported
 * Linux ELF Ghidra Program. The relocation and instruction reference must
 * come from the importer; the source file and its FileBytes are never changed.
 */
public final class ReaLoaderRelocationProbe extends GhidraScript {
    private record FileSnapshot(FileBytes source, byte[] original, byte[] modified) {}

    private final JsonArray checks = new JsonArray();

    private void require(String name, boolean condition) {
        if (!condition) throw new IllegalStateException("Loader relocation assertion failed: " + name);
        checks.add(name);
    }

    private Function function(String name) {
        FunctionIterator functions = currentProgram.getFunctionManager().getFunctions(true);
        Function found = null;
        while (functions.hasNext()) {
            Function candidate = functions.next();
            if (!candidate.getName().equals(name) && !candidate.getName().equals("_" + name)) continue;
            require("unique_function_" + name, found == null);
            found = candidate;
        }
        require("function_present_" + name, found != null);
        return found;
    }

    private static byte[] bytes(FileBytes fileBytes, boolean original) throws Exception {
        byte[] result = new byte[Math.toIntExact(fileBytes.getSize())];
        int read = original
            ? fileBytes.getOriginalBytes(0, result)
            : fileBytes.getModifiedBytes(0, result, 0, result.length);
        if (read != result.length) throw new IllegalStateException("Incomplete FileBytes capture");
        return result;
    }

    private static String digest(byte[] value) throws Exception {
        return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(value));
    }

    private static Method privateMethod(Class<?> owner, String name, Class<?>... types)
            throws Exception {
        Method method = owner.getDeclaredMethod(name, types);
        method.setAccessible(true);
        return method;
    }

    private static Object invoke(Method method, Object target, Object... arguments) throws Exception {
        try {
            return method.invoke(target, arguments);
        }
        catch (InvocationTargetException failure) {
            throw new IllegalStateException("Production bridge method failed: " + method.getName(), failure.getCause());
        }
    }

    private static void setField(Object target, String name, Object value) throws Exception {
        for (Class<?> owner = target.getClass(); owner != null; owner = owner.getSuperclass()) {
            try {
                Field field = owner.getDeclaredField(name);
                field.setAccessible(true);
                field.set(target, value);
                return;
            }
            catch (NoSuchFieldException ignored) {
                // Continue through HeadlessScript's inherited state.
            }
        }
        throw new IllegalStateException("Missing bridge field: " + name);
    }

    private static JsonObject procedureQuery(String document, String procedure) {
        JsonObject query = new JsonObject();
        query.addProperty("document", document);
        query.addProperty("procedure", procedure);
        return query;
    }

    private Address symbolAddress(String name) {
        SymbolIterator symbols = currentProgram.getSymbolTable().getSymbols(name);
        Address found = null;
        while (symbols.hasNext()) {
            Address address = symbols.next().getAddress();
            if (found != null && !found.equals(address))
                throw new IllegalStateException("Multiple addresses for fixture symbol " + name);
            found = address;
        }
        if (found == null) throw new IllegalStateException("Missing fixture symbol " + name);
        return found;
    }

    private Relocation relocationAt(Address address) {
        Iterator<Relocation> relocations = currentProgram.getRelocationTable().getRelocations();
        Relocation found = null;
        while (relocations.hasNext()) {
            Relocation candidate = relocations.next();
            if (!candidate.getAddress().equals(address)) continue;
            if (found != null) throw new IllegalStateException("Multiple relocations at " + canonical(address));
            found = candidate;
        }
        return found;
    }

    private static boolean targetBacked(MemoryBlock block, FileBytes target) {
        for (MemoryBlockSourceInfo source : block.getSourceInfos())
            if (source.getFileBytes().orElse(null) == target) return true;
        return false;
    }

    private Reference readerReference(Function reader, Address target) {
        for (Instruction instruction : currentProgram.getListing().getInstructions(reader.getBody(), true)) {
            for (Reference reference : instruction.getReferencesFrom()) {
                if (reference.getToAddress().equals(target) && reference.getReferenceType().isRead())
                    return reference;
            }
        }
        return null;
    }

    private Address pointerValue(Memory memory, Address pointer) throws Exception {
        long value = currentProgram.getDefaultPointerSize() == 8
            ? memory.getLong(pointer, memory.isBigEndian())
            : Integer.toUnsignedLong(memory.getInt(pointer, memory.isBigEndian()));
        return pointer.getAddressSpace().getAddress(value);
    }

    private static List<FileSnapshot> snapshotFileBytes(List<FileBytes> sources) throws Exception {
        List<FileSnapshot> snapshots = new java.util.ArrayList<>();
        for (FileBytes source : sources)
            snapshots.add(new FileSnapshot(source, bytes(source, true), bytes(source, false)));
        return snapshots;
    }

    private static boolean fileBytesUnchanged(List<FileSnapshot> snapshots) throws Exception {
        for (FileSnapshot snapshot : snapshots) {
            if (!java.util.Arrays.equals(snapshot.original(), bytes(snapshot.source(), true)) ||
                !java.util.Arrays.equals(snapshot.modified(), bytes(snapshot.source(), false))) return false;
        }
        return true;
    }

    private static boolean containsFileConstant(String pseudocode) {
        return pseudocode.contains("11111111") || pseudocode.contains("286331153");
    }

    private static void disposeDecompiler(Object bridge) throws Exception {
        Object value = getField(bridge, "decompiler");
        if (value instanceof DecompInterface interface_) {
            interface_.dispose();
            setField(bridge, "decompiler", null);
        }
    }

    private static String permissions(MemoryBlock block) {
        return "read=" + block.isRead() + ",write=" + block.isWrite() + ",execute=" + block.isExecute();
    }

    @Override
    public void run() throws Exception {
        String[] arguments = getScriptArgs();
        if (arguments.length != 1) throw new IllegalArgumentException("Expected exact bridge source path");
        File expectedBridge = new File(arguments[0]).getCanonicalFile();
        ResourceFile resource = GhidraScriptUtil.findScriptByName("ReaGhidraBridge.java");
        if (resource == null) throw new IllegalStateException("ReaGhidraBridge.java is absent from scriptPath");
        File actualBridge = new File(resource.getAbsolutePath()).getCanonicalFile();
        require("bridge_source_bound", expectedBridge.equals(actualBridge));
        String source = Files.readString(actualBridge.toPath());
        int protectionCall = source.indexOf("protectLoaderInitializedRelocations();");
        int decompilerCall = source.indexOf("initializeDecompiler();");
        require("relocation_protection_precedes_decompiler", protectionCall >= 0 && protectionCall < decompilerCall);

        GhidraScript bridge = GhidraScriptUtil.getProvider(resource).getScriptInstance(resource, errorWriter);
        bridge.set(getState(), getControls());
        setField(bridge, "sessionDefaultAddressSpace", currentProgram.getAddressFactory().getDefaultAddressSpace());
        setField(bridge, "admittedTargetSha256", currentProgram.getExecutableSHA256().toLowerCase());

        Memory memory = currentProgram.getMemory();
        List<FileBytes> sources = memory.getAllFileBytes();
        if (sources.isEmpty()) throw new IllegalStateException("Imported Program has no FileBytes");
        FileBytes targetSource = sources.get(0);
        List<FileSnapshot> sourceBefore = snapshotFileBytes(sources);

        Function reader = function("rea_loader_reader");
        Address pointer = symbolAddress("rea_loader_pointer");
        Relocation relocation = relocationAt(pointer);
        require("program_relocations_are_loader_relocations",
            !currentProgram.getRelocationTable().isRelocatable());
        require("importer_relocation_present",
            relocation != null && relocation.getBytes() != null && relocation.getBytes().length > 0 &&
            currentProgram.getRelocationTable().hasRelocation(pointer));
        if (relocation == null) throw new IllegalStateException("Importer did not create pointer relocation");

        require("relocation_targets_pointer_symbol",
            pointerValue(memory, pointer).equals(symbolAddress("rea_loader_value")));
        Reference reference = readerReference(reader, pointer);
        require("reader_references_relocation", reference != null);

        MemoryBlock block = memory.getBlock(pointer);
        if (block == null) throw new IllegalStateException("Pointer relocation has no loaded memory block");
        boolean readable = block.isRead();
        boolean writable = block.isWrite();
        boolean executable = block.isExecute();
        require("destination_is_loaded_initialized", block.isLoaded() && block.isInitialized());
        require("destination_is_file_backed", targetBacked(block, targetSource));
        require("destination_is_non_writable", !writable);
        require("destination_not_volatile_before_protection", !block.isVolatile());

        boolean decompilerAvailable = false;
        String baselinePseudocode = null;
        String protectedPseudocode = null;
        List<String> limitations = null;
        Method initialize = privateMethod(bridge.getClass(), "initializeDecompiler");
        Method pseudocodeMethod = privateMethod(bridge.getClass(), "procedurePseudocode", JsonObject.class);
        try {
            try {
                invoke(initialize, bridge);
                decompilerAvailable = true;
            }
            catch (IllegalStateException unavailable) {
                Throwable cause = unavailable.getCause();
                require("native_decompiler_unavailable_is_explicit",
                    cause instanceof IllegalStateException &&
                    cause.getMessage() != null && cause.getMessage().contains("could not open"));
            }
            if (decompilerAvailable) {
                JsonObject baseline = (JsonObject)invoke(
                    pseudocodeMethod,
                    bridge,
                    procedureQuery(currentProgram.getName(), reader.getName())
                );
                baselinePseudocode = baseline.get("value").getAsString();
                require("baseline_pseudocode_folds_file_constant", containsFileConstant(baselinePseudocode));
            }

            disposeDecompiler(bridge);
            Method protect = privateMethod(bridge.getClass(), "protectLoaderInitializedRelocations");
            invoke(protect, bridge);
            require("destination_block_is_volatile", block.isVolatile());
            require("destination_permissions_preserved",
                block.isRead() == readable && block.isWrite() == writable && block.isExecute() == executable);
            require("source_filebytes_unchanged", fileBytesUnchanged(sourceBefore));

            Method limitationsMethod = privateMethod(
                bridge.getClass(), "functionBoundaryLimitations", Function.class, Iterable.class
            );
            @SuppressWarnings("unchecked")
            List<String> observedLimitations = (List<String>)invoke(
                limitationsMethod,
                bridge,
                reader,
                currentProgram.getListing().getInstructions(reader.getBody(), true)
            );
            limitations = observedLimitations;
            require("evidence_limitation_represents_loader_uncertainty",
                limitations.stream().anyMatch(value ->
                    value.contains("non-writable block " + block.getName()) &&
                    value.contains("file-backed value may differ") &&
                    value.contains("not authoritative")));

            if (decompilerAvailable) {
                invoke(initialize, bridge);
                JsonObject protectedResult = (JsonObject)invoke(
                    pseudocodeMethod,
                    bridge,
                    procedureQuery(currentProgram.getName(), reader.getName())
                );
                protectedPseudocode = protectedResult.get("value").getAsString();
                require("pseudocode_does_not_use_file_constant", !containsFileConstant(protectedPseudocode));
                require("protected_pseudocode_is_not_baseline_constant",
                    !protectedPseudocode.equals(baselinePseudocode));
            }
        }
        finally {
            disposeDecompiler(bridge);
        }
        JsonObject report = new JsonObject();
        report.addProperty("status", "passed");
        report.addProperty("ghidra_version", ghidra.framework.Application.getApplicationVersion());
        report.addProperty("bridge_source_sha256", digest(Files.readAllBytes(actualBridge.toPath())));
        report.addProperty("target_source_sha256", digest(sourceBefore.get(0).original()));
        report.addProperty("relocation_address", canonical(pointer));
        report.addProperty("relocation_type", relocation.getType());
        report.addProperty("relocation_status", relocation.getStatus().toString());
        report.addProperty("block", block.getName());
        report.addProperty("reader_reference", canonical(reference.getFromAddress()));
        report.addProperty("source_filebytes_unchanged", fileBytesUnchanged(sourceBefore));
        report.addProperty("permissions", permissions(block));
        report.addProperty("decompiler_verified", decompilerAvailable);
        if (baselinePseudocode != null) report.addProperty("baseline_pseudocode", baselinePseudocode);
        if (protectedPseudocode != null) report.addProperty("protected_pseudocode", protectedPseudocode);
        if (limitations == null) throw new IllegalStateException("Loader limitation probe did not run");
        report.add("limitations", GSON_ARRAY(limitations));
        report.add("checks", checks);
        report.addProperty("scope", "real Linux ELF importer relocation and production bridge private methods; no target execution and no source FileBytes mutation");
        println("REA_LOADER_RELOCATION_PROBE_JSON " + report);
    }

    private static JsonArray GSON_ARRAY(List<String> values) {
        JsonArray result = new JsonArray();
        for (String value : values) result.add(value);
        return result;
    }

    private static Object getField(Object target, String name) throws Exception {
        for (Class<?> owner = target.getClass(); owner != null; owner = owner.getSuperclass()) {
            try {
                Field field = owner.getDeclaredField(name);
                field.setAccessible(true);
                return field.get(target);
            }
            catch (NoSuchFieldException ignored) { }
        }
        throw new IllegalStateException("Missing bridge field: " + name);
    }

    private static String canonical(Address address) {
        return address.getAddressSpace().getName() + ":0x" + Long.toUnsignedString(address.getOffset(), 16);
    }
}
