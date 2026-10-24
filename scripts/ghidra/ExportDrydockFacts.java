// Export static observations only. Never execute the imported program.
// @category Drydock
import ghidra.app.util.headless.HeadlessScript;
import ghidra.framework.Application;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;
import ghidra.program.model.symbol.ExternalLocation;
import ghidra.program.model.symbol.ExternalLocationIterator;
import com.google.gson.GsonBuilder;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Comparator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

public class ExportDrydockFacts extends HeadlessScript {
    private static final int MAX_FACTS = 1000;
    private boolean truncated = false;

    private String bounded(String value) {
        if (value == null) return "";
        if (value.length() > 256) {
            truncated = true;
            return value.substring(0, 256);
        }
        return value;
    }

    @Override
    protected void run() throws Exception {
        String[] args = getScriptArgs();
        if (args.length != 1 || currentProgram == null) throw new IllegalArgumentException("Invalid export request");
        List<Map<String, Object>> functions = new ArrayList<>();
        FunctionIterator iterator = currentProgram.getFunctionManager().getFunctions(true);
        while (iterator.hasNext()) {
            monitor.checkCancelled();
            if (functions.size() == MAX_FACTS) { truncated = true; break; }
            Function function = iterator.next();
            Map<String, Object> row = new LinkedHashMap<>();
            row.put("entry", function.getEntryPoint().toString(true));
            row.put("name", bounded(function.getName()));
            row.put("body_addresses", function.getBody().getNumAddresses());
            functions.add(row);
        }
        functions.sort(Comparator.comparing(row -> (String) row.get("entry")));
        List<Map<String, Object>> imports = new ArrayList<>();
        String[] libraries = currentProgram.getExternalManager().getExternalLibraryNames();
        Arrays.sort(libraries);
        outer: for (String library : libraries) {
            ExternalLocationIterator locations = currentProgram.getExternalManager().getExternalLocations(library);
            while (locations.hasNext()) {
                monitor.checkCancelled();
                if (imports.size() == MAX_FACTS) { truncated = true; break outer; }
                ExternalLocation location = locations.next();
                Map<String, Object> row = new LinkedHashMap<>();
                row.put("library", bounded(library));
                row.put("name", bounded(location.getLabel()));
                // EXTERNAL-space addresses are database locations, not runtime addresses.
                row.put("external_location", location.getExternalSpaceAddress().toString(true));
                imports.add(row);
            }
        }
        imports.sort(Comparator.comparing((Map<String, Object> row) -> (String) row.get("library"))
            .thenComparing(row -> (String) row.get("name"))
            .thenComparing(row -> (String) row.get("external_location")));
        Map<String, Object> result = new LinkedHashMap<>();
        result.put("version", 1);
        result.put("ghidra_version", Application.getApplicationVersion());
        result.put("executable_sha256", currentProgram.getExecutableSHA256());
        result.put("executable_format", currentProgram.getExecutableFormat());
        result.put("language_id", currentProgram.getLanguageID().toString());
        result.put("compiler_spec_id", currentProgram.getCompilerSpec().getCompilerSpecID().toString());
        result.put("image_base", currentProgram.getImageBase().toString(true));
        result.put("analysis_timed_out", analysisTimeoutOccurred());
        result.put("truncated", truncated);
        result.put("functions", functions);
        result.put("imports", imports);
        String json = new GsonBuilder().disableHtmlEscaping().create().toJson(result);
        Files.writeString(Path.of(args[0]), json + "\n", StandardOpenOption.CREATE_NEW);
    }
}
