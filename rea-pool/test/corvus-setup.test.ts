import { test } from "node:test";
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { runCommand } from "../src/exec.ts";

const source = readFileSync(new URL("../setup.sh", import.meta.url), "utf8");
const requirements = JSON.parse(readFileSync(new URL("../requirements.json", import.meta.url), "utf8"));

test("all six optional assets have pinned SHA-256 values", () => {
  const hashes = [
    ["LinuxX64", "a70bfde1e744e301a110577ce75ee4041be26f111b8fe5803f4db0f7f5f4ef4b"],
    ["LinuxArm64", "476b99e14642d2fb9f122e4e49117b6f0a15454b795ea30631174672a2da5d85"],
    ["OsxX64", "1c0d7d09f1499f560b78b3c54b66b2643f6e1e18015e5f0f6943af29906b8b68"],
    ["OsxArm64", "973de460b4593bda2139b1899da0212874929a96f59ece572c6ef021b4a80313"],
    ["WinX64", "8ac90008fa8b880637ba0aac9f6ba5033d61521cfa837e0187fb62b6e2f84f35"],
    ["WinArm64", "64ddbaa881266db9598a23c872f50f879cf7317432482572d679e8e79f83e7f3"],
  ];
  assert.equal(requirements.corvusVersion, "2.4.0");
  for (const [key, hash] of hashes) {
    assert.match(hash, /^[a-f0-9]{64}$/);
    assert.equal(requirements[`corvus${key}Sha256`], hash);
    assert.match(requirements[`corvus${key}Asset`], /^corvus-.*\.(zip|tar\.gz)$/);
  }
});

test("optional shell installer verifies before extraction, honors skips, and only warns on failures", { skip: process.platform === "win32" }, () => {
  const root = mkdtempSync(join(tmpdir(), "corvus-setup-mock-"));
  try {
    // Exercise the actual function with a dummy archive and stubbed curl/tar. No network or installer is run.
    const fn = source.slice(source.indexOf("ensure_corvus() {"), source.indexOf("# ---- The AI"));
    const hash = createHash("sha256").update("fixture archive").digest("hex");
    const script = join(root, "test.sh");
    const harness = `set -u
TMP="$1/tmp"; TOOLS="$1/tools"; NEW_PATH=""; PROBLEMS=""; OSN=linux; ARCHN=x64; IGNORE_EXISTING=1
mkdir -p "$TMP" "$TOOLS"
say() { echo "$1"; }; ok() { echo "$1"; }
have() { [ "$1" = curl ]; }
ask() { [ "$CHECK_ONLY" = 0 ] && [ "$ASSUME_YES" = 1 ]; }
corvus_version() { echo 2.3.0; }
req() { case "$1" in *Sha256) echo "$EXPECTED" ;; *Asset) echo fixture.tar.gz ;; corvusVersion) echo 2.4.0 ;; esac; }
sha256_of() { echo "${hash}"; }
curl() { [ "$FAIL_DOWNLOAD" = 0 ] || return 1; printf 'fixture archive' > "$TMP/corvus-archive"; }
tar() { touch "$TMP/extracted"; [ "$FAIL_EXTRACT" = 0 ] || return 1; printf '#!/bin/sh\\nexit 99\\n' > "$TMP/corvus-unpack/corvus"; }
${fn}
ensure_corvus
[ -z "$PROBLEMS" ]
`;
    writeFileSync(script, harness);
    for (const mode of ["mismatch", "download", "extract", "skip", "check", "decline", "yes", "upgrade", "upgrade-mismatch"]) {
      rmSync(join(root, "tmp"), { recursive: true, force: true }); rmSync(join(root, "tools"), { recursive: true, force: true });
      if (mode.startsWith("upgrade")) {
        mkdirSync(join(root, "tools", "corvus"), { recursive: true });
        writeFileSync(join(root, "tools", "corvus", "old-marker"), "old version");
      }
      const result = runCommand("bash", [script, root], { env: { ...process.env, EXPECTED: mode.endsWith("mismatch") ? "0".repeat(64) : hash,
        FAIL_DOWNLOAD: mode === "download" ? "1" : "0", FAIL_EXTRACT: mode === "extract" ? "1" : "0", NO_CORVUS: mode === "skip" ? "1" : "0",
        CHECK_ONLY: mode === "check" ? "1" : "0", ASSUME_YES: mode === "decline" ? "0" : "1" } });
      assert.equal(result.status, 0, result.stderr);
      assert.equal(existsSync(join(root, "tools", "corvus", "corvus")), ["yes", "upgrade"].includes(mode), mode);
      if (["mismatch", "download", "skip", "check", "decline"].includes(mode)) assert.equal(existsSync(join(root, "tmp", "extracted")), false, mode);
      if (mode.startsWith("upgrade")) assert.equal(existsSync(join(root, "tools", "corvus", "old-marker")), mode === "upgrade-mismatch");
      if (["mismatch", "download", "extract", "upgrade-mismatch"].includes(mode)) assert.match(result.stdout, /WARNING/);
    }
  } finally { rmSync(root, { recursive: true, force: true }); }
});

const pwsh = runCommand("pwsh", ["-NoLogo", "-NoProfile", "-Command", "$PSVersionTable.PSVersion.ToString()"], { timeout: 10000 });
test("optional PowerShell installer verifies before extraction and keeps failures optional", { skip: pwsh.error !== undefined || pwsh.status !== 0 }, () => {
  const root = mkdtempSync(join(tmpdir(), "corvus-ps-mock-"));
  const setup = new URL("../setup.ps1", import.meta.url).pathname;
  try {
    const script = join(root, "test.ps1");
    writeFileSync(script, `param($Setup, $TempRoot, $TestMode)
. $Setup -Mode setup-only -Yes
$ToolsDir = Join-Path $TempRoot "tools"
$script:Problems = @()
$NoCorvus = $TestMode -eq "skip"
$CheckOnly = $TestMode -eq "check"
$Yes = $TestMode -ne "decline"
$Req.corvusWinX64Sha256 = "${createHash("sha256").update("fixture archive").digest("hex")}"
$Req.corvusWinArm64Sha256 = $Req.corvusWinX64Sha256
if ($TestMode -eq "mismatch") { $Req.corvusWinX64Sha256 = "0" * 64; $Req.corvusWinArm64Sha256 = "0" * 64 }
function Has-Command($name) { return $false }
function Get-CorvusVersion($program) { return "2.3.0" }
function Ask($question) { return (-not $CheckOnly -and $Yes) }
function Add-CorvusPath($dir) { }
function curl.exe {
  if ($TestMode -eq "download") { $global:LASTEXITCODE = 1; return }
  [IO.File]::WriteAllText((Join-Path $ToolsDir "corvus-download.zip"), "fixture archive")
  $global:LASTEXITCODE = 0
}
function Expand-Archive($Path, $DestinationPath, [switch]$Force) {
  New-Item -ItemType Directory -Path $DestinationPath -Force | Out-Null
  New-Item -ItemType File -Path (Join-Path $TempRoot "extracted") -Force | Out-Null
  if ($TestMode -eq "extract") { throw "fixture unpack error" }
  Set-Content (Join-Path $DestinationPath "corvus.exe") "fixture, never executed"
}
Ensure-Corvus
if ($script:Problems.Count -ne 0) { throw "optional failure made setup fail" }
`);
    for (const mode of ["mismatch", "download", "extract", "skip", "check", "decline", "yes"]) {
      rmSync(join(root, "tools"), { recursive: true, force: true }); rmSync(join(root, "extracted"), { force: true });
      const result = runCommand("pwsh", ["-NoLogo", "-NoProfile", "-File", script, setup, root, mode], { timeout: 15000 });
      assert.equal(result.status, 0, result.stdout + result.stderr);
      assert.equal(existsSync(join(root, "tools", "corvus", "corvus.exe")), mode === "yes", mode);
      if (["mismatch", "download", "skip", "check", "decline"].includes(mode)) assert.equal(existsSync(join(root, "extracted")), false, mode);
      if (["mismatch", "download", "extract"].includes(mode)) assert.match(result.stdout, /WARNING/);
    }
  } finally { rmSync(root, { recursive: true, force: true }); }
});
