// Apply trusted pool names and comments from names.json.
import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.Function;
import ghidra.program.model.symbol.SourceType;
import ghidra.util.exception.DuplicateNameException;
import com.google.gson.Gson;
import java.io.*;
import java.nio.charset.StandardCharsets;

public class ApplyNames extends GhidraScript {
  private static class Entry {
    String address;
    String name;
    String comment;
    String[] alternatives;
  }

  private static class Bundle {
    Entry[] functions;
  }

  @Override
  public void run() throws Exception {
    String[] args = getScriptArgs();
    File input = args.length > 0 ? new File(args[0]) : askFile("Choose names.json", "Open");
    Bundle bundle;
    try (Reader reader = new InputStreamReader(new FileInputStream(input), StandardCharsets.UTF_8)) {
      bundle = new Gson().fromJson(reader, Bundle.class);
    }
    int renamed = 0, skipped = 0, failed = 0;
    for (Entry entry : bundle.functions) {
      try {
        Function f = getFunctionAt(toAddr(entry.address));
        if (f == null) {
          println("WARNING: no function at " + entry.address);
          skipped++;
          continue;
        }
        if (f.getName().equals(entry.name)) {
          skipped++;
          continue;
        }
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
      } catch (Exception e) {
        failed++;
        println("WARNING: could not apply entry " + (entry == null ? "null" : entry.address) + ": " + e.getMessage());
      }
    }
    println("APPLYNAMES renamed=" + renamed + " skipped=" + skipped + " failed=" + failed);
  }
}
