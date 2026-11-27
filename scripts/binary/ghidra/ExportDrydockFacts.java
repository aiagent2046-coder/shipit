// Export static observations only. Never execute the imported program.
// @category Drydock
import ghidra.app.util.headless.HeadlessScript;
import ghidra.framework.Application;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressIterator;
import ghidra.program.model.block.BasicBlockModel;
import ghidra.program.model.block.CodeBlock;
import ghidra.program.model.block.CodeBlockIterator;
import ghidra.program.model.block.CodeBlockReferenceIterator;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.InstructionIterator;
import ghidra.program.model.symbol.ExternalLocation;
import ghidra.program.model.symbol.ExternalLocationIterator;
import ghidra.program.model.symbol.FlowType;
import ghidra.program.model.symbol.Reference;
import com.google.gson.GsonBuilder;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.Comparator;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

public class ExportDrydockFacts extends HeadlessScript {
    private static final int MAX_FACTS = 1000;
    private static final int MAX_EDGES = 4000;
    private static final int WL_ROUNDS = 3;
    private boolean truncated = false;

    private String bounded(String value) {
        if (value == null) return "";
        if (value.length() > 256) {
            truncated = true;
            return value.substring(0, 256);
        }
        return value;
    }

    private static String sha256Hex(String input) throws Exception {
        MessageDigest md = MessageDigest.getInstance("SHA-256");
        byte[] digest = md.digest(input.getBytes(StandardCharsets.UTF_8));
        StringBuilder sb = new StringBuilder(64);
        for (byte b : digest) {
            sb.append(String.format("%02x", b & 0xff));
        }
        return sb.toString();
    }

    private static int countBackEdgesDfs(int nodeCount, List<List<Integer>> succs) {
        if (nodeCount == 0) return 0;
        int[] state = new int[nodeCount];
        int backEdges = 0;
        for (int root = 0; root < nodeCount; root++) {
            if (state[root] != 0) continue;
            List<int[]> stack = new ArrayList<>();
            state[root] = 1;
            stack.add(new int[]{root, 0});
            while (!stack.isEmpty()) {
                int[] top = stack.get(stack.size() - 1);
                int u = top[0];
                List<Integer> children = succs.get(u);
                if (top[1] < children.size()) {
                    int v = children.get(top[1]++);
                    if (state[v] == 1) {
                        backEdges++;
                    } else if (state[v] == 0) {
                        state[v] = 1;
                        stack.add(new int[]{v, 0});
                    }
                } else {
                    state[u] = 2;
                    stack.remove(stack.size() - 1);
                }
            }
        }
        return backEdges;
    }

    private static int[] computeCyclicSccMetrics(int nodeCount, List<List<Integer>> succs) {
        if (nodeCount == 0) return new int[]{0, 0};
        int[] indices = new int[nodeCount];
        Arrays.fill(indices, -1);
        int[] lowlink = new int[nodeCount];
        boolean[] onStack = new boolean[nodeCount];
        int[] tarjanStack = new int[nodeCount];
        int tarjanTop = 0;
        int currentIndex = 0;
        int maxSccBlocks = 0;
        int maxSccHubIn = 0;

        for (int start = 0; start < nodeCount; start++) {
            if (indices[start] != -1) continue;
            List<int[]> callStack = new ArrayList<>();
            indices[start] = currentIndex;
            lowlink[start] = currentIndex;
            currentIndex++;
            tarjanStack[tarjanTop++] = start;
            onStack[start] = true;
            callStack.add(new int[]{start, 0});

            while (!callStack.isEmpty()) {
                int[] frame = callStack.get(callStack.size() - 1);
                int v = frame[0];
                int ci = frame[1];
                List<Integer> children = succs.get(v);
                if (ci < children.size()) {
                    frame[1] = ci + 1;
                    int w = children.get(ci);
                    if (indices[w] == -1) {
                        indices[w] = currentIndex;
                        lowlink[w] = currentIndex;
                        currentIndex++;
                        tarjanStack[tarjanTop++] = w;
                        onStack[w] = true;
                        callStack.add(new int[]{w, 0});
                    } else if (onStack[w]) {
                        if (indices[w] != -1) {
                            lowlink[v] = Math.min(lowlink[v], indices[w]);
                        }
                    }
                } else {
                    callStack.remove(callStack.size() - 1);
                    if (!callStack.isEmpty()) {
                        int parent = callStack.get(callStack.size() - 1)[0];
                        lowlink[parent] = Math.min(lowlink[parent], lowlink[v]);
                    }
                    if (lowlink[v] == indices[v]) {
                        List<Integer> comp = new ArrayList<>();
                        while (true) {
                            int w = tarjanStack[--tarjanTop];
                            onStack[w] = false;
                            comp.add(w);
                            if (w == v) break;
                        }
                        boolean cyclic = comp.size() != 1;
                        if (!cyclic && !comp.isEmpty()) {
                            int only = comp.get(0);
                            cyclic = succs.get(only).contains(only);
                        }
                        if (cyclic) {
                            Set<Integer> compSet = new HashSet<>(comp);
                            int hubIn = 0;
                            Map<Integer, Integer> inDeg = new HashMap<>();
                            for (int u : comp) {
                                for (int dst : succs.get(u)) {
                                    if (compSet.contains(dst)) {
                                        int nextIn = inDeg.getOrDefault(dst, 0) + 1;
                                        inDeg.put(dst, nextIn);
                                        if (nextIn > hubIn) hubIn = nextIn;
                                    }
                                }
                            }
                            if (comp.size() > maxSccBlocks || (comp.size() == maxSccBlocks && hubIn > maxSccHubIn)) {
                                maxSccBlocks = comp.size();
                                maxSccHubIn = hubIn;
                            }
                        }
                    }
                }
            }
        }
        return new int[]{maxSccBlocks, maxSccHubIn};
    }

    private String resolveTarget(FunctionManager manager, Address target, Set<String> outKind) {
        Function callee = manager.getFunctionAt(target);
        if (callee != null) {
            if (callee.isThunk()) {
                Function thunked = callee.getThunkedFunction(true);
                if (thunked != null && thunked.isExternal()) {
                    ExternalLocation ext = thunked.getExternalLocation();
                    if (ext != null) {
                        outKind.add("import");
                        return ext.getExternalSpaceAddress().toString(true);
                    }
                } else if (thunked != null) {
                    outKind.add("internal");
                    return thunked.getEntryPoint().toString(true);
                }
            }
            if (callee.isExternal()) {
                ExternalLocation ext = callee.getExternalLocation();
                if (ext != null) {
                    outKind.add("import");
                    return ext.getExternalSpaceAddress().toString(true);
                }
            }
            outKind.add("internal");
            return callee.getEntryPoint().toString(true);
        }
        if (target.isExternalAddress()) {
            outKind.add("import");
            return target.toString(true);
        }
        return null;
    }

    @Override
    protected void run() throws Exception {
        String[] args = getScriptArgs();
        if (args.length != 1 || currentProgram == null) throw new IllegalArgumentException("Invalid export request");

        FunctionManager functionManager = currentProgram.getFunctionManager();
        BasicBlockModel blockModel = new BasicBlockModel(currentProgram);

        Set<Address> entryPoints = new HashSet<>();
        AddressIterator epIter = currentProgram.getSymbolTable().getExternalEntryPointIterator();
        while (epIter.hasNext()) {
            entryPoints.add(epIter.next());
        }

        List<Map<String, Object>> functions = new ArrayList<>();
        List<Map<String, Object>> exports = new ArrayList<>();
        List<Map<String, Object>> callEdges = new ArrayList<>();
        Set<String> seenEdges = new HashSet<>();

        FunctionIterator iterator = functionManager.getFunctions(true);
        while (iterator.hasNext()) {
            monitor.checkCancelled();
            if (functions.size() == MAX_FACTS) { truncated = true; break; }
            Function function = iterator.next();
            String entry = function.getEntryPoint().toString(true);
            String name = bounded(function.getName());

            List<CodeBlock> rawBlocks = new ArrayList<>();
            CodeBlockIterator blockIter = blockModel.getCodeBlocksContaining(function.getBody(), monitor);
            while (blockIter.hasNext()) {
                monitor.checkCancelled();
                rawBlocks.add(blockIter.next());
            }
            rawBlocks.sort(Comparator.comparing(b -> b.getFirstStartAddress().toString(true)));
            for (int i = 1; i < rawBlocks.size(); i++) {
                if (rawBlocks.get(i).contains(function.getEntryPoint())) {
                    CodeBlock entryBlk = rawBlocks.remove(i);
                    rawBlocks.add(0, entryBlk);
                    break;
                }
            }

            int nBlocks = rawBlocks.size();
            Map<Address, Integer> startToIdx = new HashMap<>();
            for (int i = 0; i < nBlocks; i++) {
                startToIdx.put(rawBlocks.get(i).getFirstStartAddress(), i);
            }

            List<List<Integer>> succs = new ArrayList<>(nBlocks);
            List<List<Integer>> preds = new ArrayList<>(nBlocks);
            for (int i = 0; i < nBlocks; i++) {
                succs.add(new ArrayList<>());
                preds.add(new ArrayList<>());
            }

            int cfgEdges = 0;
            for (int i = 0; i < nBlocks; i++) {
                CodeBlock blk = rawBlocks.get(i);
                Set<Integer> seenLocalTargets = new HashSet<>();
                CodeBlockReferenceIterator dests = blk.getDestinations(monitor);
                while (dests.hasNext()) {
                    monitor.checkCancelled();
                    Address dest = dests.next().getDestinationAddress();
                    if (!function.getBody().contains(dest)) continue;
                    Integer targetIdx = startToIdx.get(dest);
                    if (targetIdx == null) {
                        for (int k = 0; k < nBlocks; k++) {
                            if (rawBlocks.get(k).contains(dest)) {
                                targetIdx = k;
                                break;
                            }
                        }
                    }
                    if (targetIdx != null && seenLocalTargets.add(targetIdx)) {
                        succs.get(i).add(targetIdx);
                        preds.get(targetIdx).add(i);
                        cfgEdges++;
                    }
                }
                Collections.sort(succs.get(i));
            }
            for (int i = 0; i < nBlocks; i++) {
                Collections.sort(preds.get(i));
            }

            int[] blockDirectCalls = new int[nBlocks];
            int[] blockIndirectCalls = new int[nBlocks];
            boolean[] blockHasReturn = new boolean[nBlocks];
            int indirectCalls = 0;

            InstructionIterator instructions = currentProgram.getListing().getInstructions(function.getBody(), true);
            while (instructions.hasNext()) {
                monitor.checkCancelled();
                Instruction insn = instructions.next();
                FlowType flow = insn.getFlowType();

                int ownerIdx = -1;
                Address insnAddr = insn.getAddress();
                for (int k = 0; k < nBlocks; k++) {
                    if (rawBlocks.get(k).contains(insnAddr)) {
                        ownerIdx = k;
                        break;
                    }
                }
                if (ownerIdx >= 0 && flow.isTerminal() && !flow.isCall()) {
                    blockHasReturn[ownerIdx] = true;
                }

                if (!flow.isCall()) continue;
                if (flow.isComputed()) {
                    indirectCalls++;
                    if (ownerIdx >= 0) blockIndirectCalls[ownerIdx]++;
                } else if (ownerIdx >= 0) {
                    blockDirectCalls[ownerIdx]++;
                }

                for (Reference ref : insn.getReferencesFrom()) {
                    if (!ref.getReferenceType().isCall()) continue;
                    Set<String> kindHolder = new HashSet<>(1);
                    String resolved = resolveTarget(functionManager, ref.getToAddress(), kindHolder);
                    if (resolved == null || kindHolder.isEmpty()) continue;
                    String kind = kindHolder.iterator().next();
                    String edgeKey = entry + "\0" + resolved + "\0" + kind;
                    if (seenEdges.contains(edgeKey)) continue;
                    if (callEdges.size() == MAX_EDGES) {
                        truncated = true;
                        continue;
                    }
                    seenEdges.add(edgeKey);
                    Map<String, Object> edge = new LinkedHashMap<>();
                    edge.put("caller", entry);
                    edge.put("target", resolved);
                    edge.put("target_kind", kind);
                    callEdges.add(edge);
                }
            }

            int branchBlocks = 0;
            String[] colors = new String[nBlocks];
            for (int i = 0; i < nBlocks; i++) {
                int outDeg = succs.get(i).size();
                int inDeg = preds.get(i).size();
                if (outDeg >= 2) branchBlocks++;
                boolean isEntry = rawBlocks.get(i).contains(function.getEntryPoint());
                String role = inDeg + ":" + outDeg + ":" + (isEntry ? 1 : 0) + ":"
                    + (blockHasReturn[i] ? 1 : 0) + ":" + blockDirectCalls[i] + ":" + blockIndirectCalls[i];
                colors[i] = sha256Hex("v0|" + role);
            }

            for (int round = 1; round <= WL_ROUNDS; round++) {
                String[] nextColors = new String[nBlocks];
                for (int i = 0; i < nBlocks; i++) {
                    List<String> inLabels = new ArrayList<>(preds.get(i).size());
                    for (int p : preds.get(i)) inLabels.add(colors[p]);
                    Collections.sort(inLabels);

                    List<String> outLabels = new ArrayList<>(succs.get(i).size());
                    for (int s : succs.get(i)) outLabels.add(colors[s]);
                    Collections.sort(outLabels);

                    String payload = "r" + round + "|" + colors[i]
                        + "|in:" + String.join(",", inLabels)
                        + "|out:" + String.join(",", outLabels);
                    nextColors[i] = sha256Hex(payload);
                }
                colors = nextColors;
            }

            List<String> finalMultiset = new ArrayList<>(Arrays.asList(colors));
            Collections.sort(finalMultiset);
            String wlHash = sha256Hex("wl1|n=" + nBlocks + "|" + String.join(",", finalMultiset));

            int backEdges = countBackEdgesDfs(nBlocks, succs);
            int[] sccMetrics = computeCyclicSccMetrics(nBlocks, succs);
            int cyclomatic = nBlocks > 0 ? Math.max(1, cfgEdges - nBlocks + 2) : 1;

            Map<String, Object> row = new LinkedHashMap<>();
            row.put("entry", entry);
            row.put("name", name);
            row.put("body_addresses", function.getBody().getNumAddresses());
            row.put("basic_blocks", nBlocks);
            row.put("cfg_edges", cfgEdges);
            row.put("back_edges", backEdges);
            row.put("branch_blocks", branchBlocks);
            row.put("cyclomatic", cyclomatic);
            row.put("indirect_calls", indirectCalls);
            row.put("max_scc_blocks", sccMetrics[0]);
            row.put("max_scc_hub_in", sccMetrics[1]);
            row.put("is_thunk", function.isThunk());
            row.put("wl_hash", wlHash);
            functions.add(row);

            if (!function.isThunk() && entryPoints.contains(function.getEntryPoint())) {
                if (exports.size() < MAX_FACTS) {
                    Map<String, Object> exp = new LinkedHashMap<>();
                    exp.put("entry", entry);
                    exp.put("name", name);
                    exports.add(exp);
                } else {
                    truncated = true;
                }
            }
        }

        functions.sort(Comparator.comparing(row -> (String) row.get("entry")));
        exports.sort(Comparator.comparing((Map<String, Object> row) -> (String) row.get("entry"))
            .thenComparing(row -> (String) row.get("name")));
        callEdges.sort(Comparator.comparing((Map<String, Object> row) -> (String) row.get("caller"))
            .thenComparing(row -> (String) row.get("target"))
            .thenComparing(row -> (String) row.get("target_kind")));

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
                row.put("external_location", location.getExternalSpaceAddress().toString(true));
                imports.add(row);
            }
        }
        imports.sort(Comparator.comparing((Map<String, Object> row) -> (String) row.get("library"))
            .thenComparing(row -> (String) row.get("name"))
            .thenComparing(row -> (String) row.get("external_location")));

        Map<String, Object> result = new LinkedHashMap<>();
        result.put("version", 2);
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
        result.put("exports", exports);
        result.put("call_edges", callEdges);
        String json = new GsonBuilder().disableHtmlEscaping().create().toJson(result);
        Files.writeString(Path.of(args[0]), json + "\n", StandardOpenOption.CREATE_NEW);
    }
}
