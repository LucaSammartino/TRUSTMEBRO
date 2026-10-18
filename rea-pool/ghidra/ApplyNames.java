// Apply trusted pool results from names.json: function names and comments, plus (optional per entry)
//   structs    : "Name { type field; ... }"  -> added to the program's data type manager (skipped if the name exists)
//   signature  : "ret name(type a, type b)"  -> return type and parameters replaced (the prototype's function
//                name is ignored; the name comes from the function_name note)
//   variables  : [{from, to}]                -> decompiler variables (param_1, local_10, iVar2 ...) renamed
//
// Each step runs in its own try/catch, so one failure never stops the rest.
// Known limits (partial support, by design):
//   - a field whose type text cannot be resolved becomes a single undefined1 byte with the given name;
//     bitfields and nested anonymous structs/unions are not supported (the field is kept as undefined1)
//   - a signature with an unresolvable return or parameter type is skipped as a whole (warning printed)
//   - a variable rename is skipped if the symbol is not found in the decompiler output or the new name
//     is already used by another variable of that function
//   - calling convention and storage are left to Ghidra (dynamic storage), varargs ("...") is honoured
import ghidra.app.script.GhidraScript;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.program.model.data.ArrayDataType;
import ghidra.program.model.data.CategoryPath;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DataTypeConflictHandler;
import ghidra.program.model.data.DataTypeManager;
import ghidra.program.model.data.StructureDataType;
import ghidra.program.model.data.Undefined1DataType;
import ghidra.program.model.data.VoidDataType;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Function.FunctionUpdateType;
import ghidra.program.model.listing.Parameter;
import ghidra.program.model.listing.ParameterImpl;
import ghidra.program.model.pcode.HighFunction;
import ghidra.program.model.pcode.HighFunctionDBUtil;
import ghidra.program.model.pcode.HighSymbol;
import ghidra.program.model.pcode.LocalSymbolMap;
import ghidra.program.model.symbol.SourceType;
import ghidra.util.data.DataTypeParser;
import ghidra.util.exception.DuplicateNameException;
import com.google.gson.Gson;
import java.io.*;
import java.nio.charset.StandardCharsets;
import java.util.*;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class ApplyNames extends GhidraScript {
  private static class Var {
    String from;
    String to;
  }

  private static class Entry {
    String address;
    String name;
    String comment;
    String[] alternatives;
    Var[] variables;
    String signature;
    String[] structs;
  }

  private static class Bundle {
    Entry[] functions;
  }

  private static final Pattern IDENT_TAIL = Pattern.compile("^(.*?)([A-Za-z_][A-Za-z0-9_]*)\\s*$", Pattern.DOTALL);
  private static final Pattern IDENT = Pattern.compile("^[A-Za-z_][A-Za-z0-9_]*$");

  private int structsAdded = 0, signaturesApplied = 0, variablesRenamed = 0, failed = 0;
  private DataTypeParser typeParser;
  private DataTypeManager dtm;

  private DataType parseType(String text) {
    if (text == null) return null;
    String t = text.trim();
    if (t.isEmpty()) return null;
    try {
      return typeParser.parse(t);
    } catch (Exception e) {
      return null;
    }
  }

  private static List<String> splitTop(String s, char sep) {
    List<String> out = new ArrayList<>();
    int depth = 0, start = 0;
    for (int i = 0; i < s.length(); i++) {
      char c = s.charAt(i);
      if (c == '(' || c == '[' || c == '{') depth++;
      else if (c == ')' || c == ']' || c == '}') depth--;
      else if (c == sep && depth == 0) {
        out.add(s.substring(start, i));
        start = i + 1;
      }
    }
    out.add(s.substring(start));
    return out;
  }

  // "Name { type field; ... }"
  private void applyStruct(String def) {
    try {
      int open = def.indexOf('{');
      int close = def.lastIndexOf('}');
      if (open < 0 || close < open) {
        println("WARNING: bad struct definition: " + def);
        return;
      }
      String name = def.substring(0, open).trim().replaceFirst("^(struct|union)\\s+", "");
      if (!IDENT.matcher(name).matches()) {
        println("WARNING: bad struct name: " + name);
        return;
      }
      if (dtm.getDataType(CategoryPath.ROOT, name) != null) return;
      StructureDataType st = new StructureDataType(CategoryPath.ROOT, name, 0, dtm);
      int fields = 0;
      for (String raw : splitTop(def.substring(open + 1, close), ';')) {
        String field = raw.trim();
        if (field.isEmpty()) continue;
        String fname = null;
        String typeText = field;
        int count = 0;
        Matcher am = Pattern.compile("^(.*?)\\[\\s*(\\d+)\\s*\\]\\s*$", Pattern.DOTALL).matcher(field);
        if (am.matches()) {
          field = am.group(1).trim();
          typeText = field;
          count = Integer.parseInt(am.group(2));
        }
        Matcher m = IDENT_TAIL.matcher(field);
        DataType dt = null;
        if (m.matches() && !m.group(1).trim().isEmpty()) {
          fname = m.group(2);
          typeText = m.group(1).trim();
          dt = parseType(typeText);
        }
        if (fname == null) fname = "field" + fields;
        if (dt == null || dt.getLength() <= 0) {
          println("WARNING: struct " + name + ": unresolved field type '" + typeText + "' for " + fname + ", using undefined1");
          dt = new Undefined1DataType();
        }
        if (count > 0) dt = new ArrayDataType(dt, count, dt.getLength());
        try {
          st.add(dt, fname, null);
          fields++;
        } catch (Exception e) {
          println("WARNING: struct " + name + ": field " + fname + " skipped: " + e.getMessage());
        }
      }
      if (fields == 0) {
        println("WARNING: struct " + name + " has no usable fields");
        return;
      }
      dtm.addDataType(st, DataTypeConflictHandler.KEEP_HANDLER);
      structsAdded++;
    } catch (Exception e) {
      failed++;
      println("WARNING: could not add struct: " + e.getMessage());
    }
  }

  // "ret name(type a, type b)"
  private void applySignature(Function f, String proto) {
    try {
      int open = proto.indexOf('(');
      int close = proto.lastIndexOf(')');
      if (open < 0 || close < open) {
        println("WARNING: bad signature: " + proto);
        return;
      }
      Matcher head = IDENT_TAIL.matcher(proto.substring(0, open));
      if (!head.matches() || head.group(1).trim().isEmpty()) {
        println("WARNING: signature without return type: " + proto);
        return;
      }
      DataType ret = parseType(head.group(1));
      if (ret == null) {
        println("WARNING: unresolved return type in signature: " + proto);
        return;
      }
      List<Parameter> params = new ArrayList<>();
      boolean varargs = false;
      String body = proto.substring(open + 1, close).trim();
      if (!body.isEmpty() && !body.equals("void")) {
        int index = 0;
        for (String raw : splitTop(body, ',')) {
          String p = raw.trim();
          if (p.equals("...")) {
            varargs = true;
            continue;
          }
          DataType dt = parseType(p);
          String pname = null;
          if (dt == null) {
            Matcher m = IDENT_TAIL.matcher(p);
            if (m.matches()) {
              dt = parseType(m.group(1));
              pname = m.group(2);
            }
          }
          if (dt == null) {
            println("WARNING: unresolved parameter type '" + p + "' in signature: " + proto);
            return;
          }
          params.add(new ParameterImpl(pname, dt, currentProgram));
          index++;
        }
      }
      if (matches(f, ret, params, varargs)) return;
      f.setReturnType(ret, SourceType.USER_DEFINED);
      f.replaceParameters(params, FunctionUpdateType.DYNAMIC_STORAGE_ALL_PARAMS, true, SourceType.USER_DEFINED);
      f.setVarArgs(varargs);
      signaturesApplied++;
    } catch (Exception e) {
      failed++;
      println("WARNING: could not apply signature for " + f.getName() + ": " + e.getMessage());
    }
  }

  private boolean matches(Function f, DataType ret, List<Parameter> params, boolean varargs) {
    if (!f.getReturnType().isEquivalent(ret) || f.hasVarArgs() != varargs || f.getParameterCount() != params.size()) return false;
    for (int i = 0; i < params.size(); i++) {
      Parameter have = f.getParameter(i);
      Parameter want = params.get(i);
      if (!have.getDataType().isEquivalent(want.getDataType())) return false;
      if (want.getName() != null && !want.getName().equals(have.getName())) return false;
    }
    return true;
  }

  private HighFunction decompile(DecompInterface di, Function f) {
    DecompileResults r = di.decompileFunction(f, 60, monitor);
    return r != null && r.decompileCompleted() ? r.getHighFunction() : null;
  }

  private void applyVariables(DecompInterface di, Function f, Var[] vars) {
    for (Var v : vars) {
      try {
        if (v == null || v.from == null || v.to == null || !IDENT.matcher(v.to).matches()) continue;
        HighFunction hf = decompile(di, f);
        if (hf == null) {
          println("WARNING: decompile failed for " + f.getName());
          return;
        }
        HighSymbol target = null;
        boolean conflict = false;
        LocalSymbolMap map = hf.getLocalSymbolMap();
        Iterator<HighSymbol> it = map.getSymbols();
        while (it.hasNext()) {
          HighSymbol s = it.next();
          if (s.getName().equals(v.to)) conflict = true;
          if (s.getName().equals(v.from)) target = s;
        }
        if (target == null) {
          if (!conflict) println("WARNING: variable " + v.from + " not found in " + f.getName());
          continue;
        }
        if (conflict) {
          println("WARNING: variable name " + v.to + " already used in " + f.getName());
          continue;
        }
        HighFunctionDBUtil.updateDBVariable(target, v.to, null, SourceType.USER_DEFINED);
        variablesRenamed++;
      } catch (Exception e) {
        failed++;
        println("WARNING: could not rename variable " + (v == null ? "null" : v.from) + " in " + f.getName() + ": " + e.getMessage());
      }
    }
  }

  @Override
  public void run() throws Exception {
    String[] args = getScriptArgs();
    File input = args.length > 0 ? new File(args[0]) : askFile("Choose names.json", "Open");
    Bundle bundle;
    try (Reader reader = new InputStreamReader(new FileInputStream(input), StandardCharsets.UTF_8)) {
      bundle = new Gson().fromJson(reader, Bundle.class);
    }
    dtm = currentProgram.getDataTypeManager();
    typeParser = new DataTypeParser(dtm, dtm, null, DataTypeParser.AllowedDataTypes.ALL);
    DecompInterface di = new DecompInterface();
    di.openProgram(currentProgram);
    int renamed = 0, skipped = 0;
    for (Entry entry : bundle.functions) {
      Function f = null;
      try {
        f = getFunctionAt(toAddr(entry.address));
        if (f == null) {
          println("WARNING: no function at " + entry.address);
          skipped++;
          continue;
        }
        if (f.getName().equals(entry.name)) {
          skipped++;
        } else {
          try {
            f.setName(entry.name, SourceType.USER_DEFINED);
          } catch (DuplicateNameException e) {
            f.setName(entry.name + "_" + entry.address.replaceFirst("(?i)^0x", ""), SourceType.USER_DEFINED);
          }
          String comment = entry.comment;
          if (entry.alternatives != null && entry.alternatives.length > 0) {
            String other = "Other candidates: " + String.join(", ", entry.alternatives);
            comment = comment == null || comment.isEmpty() ? other : comment + "\n" + other;
          }
          if (comment != null) f.setComment(comment);
          renamed++;
        }
      } catch (Exception e) {
        failed++;
        println("WARNING: could not apply entry " + (entry == null ? "null" : entry.address) + ": " + e.getMessage());
        continue;
      }
      if (entry.structs != null) {
        for (String s : entry.structs) if (s != null) applyStruct(s);
      }
      if (entry.signature != null && !entry.signature.trim().isEmpty()) applySignature(f, entry.signature.trim());
      if (entry.variables != null && entry.variables.length > 0) {
        try {
          applyVariables(di, f, entry.variables);
        } catch (Exception e) {
          failed++;
          println("WARNING: variable renames failed for " + entry.address + ": " + e.getMessage());
        }
      }
    }
    di.dispose();
    println("APPLYNAMES renamed=" + renamed + " skipped=" + skipped + " failed=" + failed
        + " variables=" + variablesRenamed + " signatures=" + signaturesApplied + " structs=" + structsAdded);
  }
}
