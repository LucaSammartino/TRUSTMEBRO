// Prototype: dump pseudocode + callees of EVERY function in one Ghidra session (one import, one analysis).
// Output: one JSON object per line: {"address","name","code","callees":["0x..."]}
import ghidra.app.script.GhidraScript;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionManager;
import java.io.*;
import java.util.*;

public class DumpAll extends GhidraScript {
  private static String hex(Function f) {
    String s = f.getEntryPoint().toString().toLowerCase().replaceFirst("^0+(?=.)", "");
    return "0x" + s;
  }

  private static String esc(String s) {
    StringBuilder b = new StringBuilder("\"");
    for (int i = 0; i < s.length(); i++) {
      char c = s.charAt(i);
      if (c == '"') b.append("\\\"");
      else if (c == '\\') b.append("\\\\");
      else if (c == '\n') b.append("\\n");
      else if (c == '\r') b.append("\\r");
      else if (c == '\t') b.append("\\t");
      else if (c < 0x20) b.append("\\u00").append(Character.forDigit(c >> 4, 16)).append(Character.forDigit(c & 15, 16));
      else b.append(c);
    }
    return b.append('"').toString();
  }

  @Override
  public void run() throws Exception {
    String out = getScriptArgs()[0];
    if (getScriptArgs().length > 1) {
      try (PrintWriter base = new PrintWriter(new OutputStreamWriter(new FileOutputStream(getScriptArgs()[1]), "UTF-8"))) {
        base.println("{\"imageBase\":\"0x" + Long.toUnsignedString(currentProgram.getImageBase().getOffset(), 16) + "\"}");
      }
    }
    long t0 = System.currentTimeMillis();
    DecompInterface di = new DecompInterface();
    di.openProgram(currentProgram);
    FunctionManager fm = currentProgram.getFunctionManager();
    int n = 0, failed = 0;
    try (PrintWriter w = new PrintWriter(new OutputStreamWriter(new FileOutputStream(out), "UTF-8"))) {
      for (Function f : fm.getFunctions(true)) {
        if (f.isExternal()) continue;
        String code = "";
        try {
          DecompileResults r = di.decompileFunction(f, 60, monitor);
          if (r.decompileCompleted()) code = r.getDecompiledFunction().getC();
          else failed++;
        } catch (Exception e) {
          failed++;
        }
        LinkedHashSet<String> callees = new LinkedHashSet<>();
        for (Function c : f.getCalledFunctions(monitor)) {
          if (c.isExternal()) continue;
          Function target = c.isThunk() ? c.getThunkedFunction(true) : c;
          if (target == null || target.isExternal()) continue;
          String a = hex(target);
          if (!a.equals(hex(f))) callees.add(a);
        }
        StringBuilder cs = new StringBuilder("[");
        boolean first = true;
        for (String a : callees) {
          if (!first) cs.append(',');
          cs.append('"').append(a).append('"');
          first = false;
        }
        cs.append(']');
        w.println("{\"address\":\"" + hex(f) + "\",\"name\":" + esc(f.getName()) + ",\"code\":" + esc(code) + ",\"callees\":" + cs + "}");
        n++;
      }
    }
    println("DUMPALL functions=" + n + " decompileFailed=" + failed + " ms=" + (System.currentTimeMillis() - t0));
  }
}
