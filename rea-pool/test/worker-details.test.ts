import { test } from "node:test";
import assert from "node:assert/strict";
import { DETAIL_KINDS, checkDetail, cleanDetails, detailsFromFlags, parseExtras, parseVariables, validateNote } from "../src/rules.ts";
import { analyzePrompt, detailsFromAnswer, reviewPrompt } from "../src/agent.ts";

const rules = { allowedKinds: ["function_name", "comment", ...DETAIL_KINDS], maxTextLength: 500, maxEvidenceItems: 5 } as any;
const ok = (kind: string, value: string) => validateNote({ kind, value }, rules).ok;

test("variable_name validator", () => {
  assert.ok(ok("variable_name", "param_1=packet"));
  assert.ok(ok("variable_name", "iVar2=index"));
  for (const bad of ["a=a", "a", "1a=b", "a=b c", "a=b;x", "=b", "a==b", "a=" + "b".repeat(65)]) assert.ok(!ok("variable_name", bad), bad);
});

test("signature validator", () => {
  assert.ok(ok("signature", "int parse_packet(char *buf, int len)"));
  assert.ok(ok("signature", "void f(void)"));
  for (const bad of ["int f(int a);", "int f(int a) { x", "int f", "int f(int (*cb)(void))", "int f)(", "http://x(a)", "int f(int a)\nrm"]) assert.ok(!ok("signature", bad), bad);
});

test("struct_def validator", () => {
  assert.ok(ok("struct_def", "packet_t { uint type; uint length; char *data; }"));
  assert.ok(ok("struct_def", "pair{int a[4];}"));
  for (const bad of ["packet_t", "packet_t {}", "1x { int a; }", "p { int a = 1; }", "p { int a; } extra", "p { " + "a;".repeat(250) + " }"]) assert.ok(!ok("struct_def", bad), bad);
});

test("detail values skip the free-text tripwire; unknown kinds stay rejected", () => {
  assert.equal(checkDetail("struct_def", "you_t { int must; }"), null);
  assert.ok(!validateNote({ kind: "variable_name", value: "a=b" }, { ...rules, allowedKinds: ["comment"] }).ok);
});

const reply = {
  name: "parse_packet",
  summary: "Parses a packet header.",
  confidence: "high",
  variables: { param_1: "packet", iVar2: "index", bad: "not valid!", same: "same", param_2: 5 },
  signature: "int parse_packet(char *buf, int len)",
  structs: ["packet_t { uint type; char *data; }", "junk", 7, "a { int x; }", "b { int y; }"],
};

test("details parsing keeps valid fields and drops malformed ones", () => {
  const d = cleanDetails(reply);
  assert.deepEqual(d.map((x) => x.value), ["param_1=packet", "iVar2=index", "int parse_packet(char *buf, int len)", "packet_t { uint type; char *data; }", "a { int x; }"]);
  assert.deepEqual(cleanDetails({ variables: [1], signature: 5, structs: "x" }), []);
  assert.deepEqual(cleanDetails({}), []);
  const many = Object.fromEntries(Array.from({ length: 15 }, (_, i) => [`param_${i}`, `p${i}`]));
  assert.equal(cleanDetails({ variables: many }).length, 10);
  assert.deepEqual(detailsFromAnswer(reply as any, ["function_name", "signature"]).map((x) => x.kind), ["signature"]);
});

test("prompt asks for detail fields only when the kinds are allowed", () => {
  const full = analyzePrompt("x");
  assert.ok(full.includes('"variables"') && full.includes('"signature"') && full.includes('"structs"'));
  assert.equal(analyzePrompt("x", [], {}, [], DETAIL_KINDS), full);
  const none = analyzePrompt("x", [], {}, [], ["function_name", "comment"]);
  assert.ok(!none.includes("variables") && !none.includes("signature") && !none.includes("structs") && !none.includes("Optional fields"));
  const sigOnly = analyzePrompt("x", [], {}, [], ["signature"]);
  assert.ok(sigOnly.includes('"signature"') && !sigOnly.includes('"variables"'));
});

test("review prompt shows detail notes one per line", () => {
  const p = reviewPrompt("x", [{ kind: "function_name", value: "foo" }, { kind: "variable_name", value: "param_1=packet" }, { kind: "signature", value: "int foo(int a)" }]);
  assert.ok(p.includes("function_name: foo\nvariable_name: param_1=packet\nsignature: int foo(int a)"));
});

test("cli flag helpers", () => {
  assert.deepEqual(parseVariables("param_1=packet, iVar2=index,bad").map((d) => d.value), ["param_1=packet", "iVar2=index"]);
  assert.deepEqual(parseVariables(["a=b", "a=b", 3]).map((d) => d.value), ["a=b"]);
  const d = detailsFromFlags({ var: "param_1=packet\u0001iVar2=index,x=y", sig: "int f(int a)", struct: "p { int a; }\u0001q { int b; }" });
  assert.deepEqual(d.map((x) => x.kind), ["variable_name", "variable_name", "variable_name", "signature", "struct_def", "struct_def"]);
  assert.deepEqual(detailsFromFlags({ var: "true", sig: "true" }), []);
  assert.deepEqual(parseExtras({ structs: "p { int a; }" }).length, 1);
});
