# rea-pool setup for Windows.
# Checks that everything you need is installed, offers to install what is missing, then (in "friend" mode)
# helps you join a project and starts working.
#
#   -Mode friend       (default) set up, join if needed, then run
#   -Mode setup-only   just set up (for the leader)
#   -CheckOnly         only report what is missing; install nothing and ask nothing
param(
  [ValidateSet("friend", "setup-only")][string]$Mode = "friend",
  [switch]$CheckOnly
)

$ErrorActionPreference = "Stop"
$ProgressPreference = "SilentlyContinue"
$Root = Split-Path -Parent $MyInvocation.MyCommand.Path
$Req = Get-Content (Join-Path $Root "requirements.json") -Raw | ConvertFrom-Json
$ToolsDir = Join-Path $HOME $Req.toolsFolder
$script:Problems = @()

function Say($text, $color = "White") { Write-Host $text -ForegroundColor $color }
function Ok($text) { Say ("  [OK]       " + $text) Green }
function Missing($text) { Say ("  [MISSING]  " + $text) Yellow }
function Bad($text) { Say ("  [PROBLEM]  " + $text) Red; $script:Problems += $text }

function Ask($question) {
  if ($CheckOnly) { return $false }
  $answer = Read-Host ($question + " (Y/n)")
  return ($answer -eq "" -or $answer -match "^[yY]")
}

function Refresh-Path {
  $env:Path = [Environment]::GetEnvironmentVariable("Path", "Machine") + ";" + [Environment]::GetEnvironmentVariable("Path", "User")
}

function Set-UserEnv($name, $value) {
  [Environment]::SetEnvironmentVariable($name, $value, "User")
  Set-Item -Path ("Env:" + $name) -Value $value
}

function Has-Command($name) { return [bool](Get-Command $name -ErrorAction SilentlyContinue) }

function Free-SpaceGB { return [math]::Round((Get-PSDrive -Name ($HOME.Substring(0, 1))).Free / 1GB, 1) }

# ---- Node.js -----------------------------------------------------------------------------------

function Get-NodeMajor {
  try {
    $v = (& node --version) 2>$null
    if ($v -match "v(\d+)") { return [int]$Matches[1] }
  } catch { }
  return 0
}

function Ensure-Node {
  $major = Get-NodeMajor
  if ($major -ge $Req.node.minimumMajor) { Ok ("Node.js " + $major); return }
  if ($major -gt 0) { Missing ("Node.js is version " + $major + " but version " + $Req.node.minimumMajor + " or newer is needed") } else { Missing "Node.js (runs the pool tool)" }
  if (-not (Has-Command "winget")) { Bad ("Windows' installer (winget) is not available. Install Node.js from " + $Req.node.manualUrl + " then run this again."); return }
  if (Ask ("Install Node.js " + $Req.node.wingetVersion + " now? (small download; Windows may ask for permission)")) {
    & winget install --id $Req.node.wingetId --version $Req.node.wingetVersion --exact --silent --accept-package-agreements --accept-source-agreements
    Refresh-Path
    if ((Get-NodeMajor) -ge $Req.node.minimumMajor) { Ok "Node.js installed" } else { Bad ("Node.js did not install. Install it from " + $Req.node.manualUrl + ", then run this again.") }
  } else { Bad "Node.js is required." }
}

# ---- Java 21 -----------------------------------------------------------------------------------

function Get-JdkMajor($dir) {
  if (-not $dir) { return 0 }
  if (-not (Test-Path (Join-Path $dir "bin\javac.exe"))) { return 0 }
  $release = Join-Path $dir "release"
  if (Test-Path $release) {
    $line = Select-String -Path $release -Pattern '^JAVA_VERSION="?(\d+)' | Select-Object -First 1
    if ($line) { return [int]$line.Matches[0].Groups[1].Value }
  }
  return 0
}

function Find-Jdk {
  $want = [int]$Req.java.major
  $candidates = @($env:JAVA_HOME, [Environment]::GetEnvironmentVariable("JAVA_HOME", "User"))
  foreach ($base in @("C:\Program Files\Eclipse Adoptium", "C:\Program Files\Java", "C:\Program Files\Microsoft", "C:\Program Files\Amazon Corretto", "C:\Program Files\Zulu")) {
    if (Test-Path $base) { $candidates += (Get-ChildItem $base -Directory -ErrorAction SilentlyContinue | ForEach-Object { $_.FullName }) }
  }
  foreach ($dir in $candidates) { if ((Get-JdkMajor $dir) -eq $want) { return $dir } }
  return $null
}

function Ensure-Java {
  $jdk = Find-Jdk
  if (-not $jdk) {
    Missing ("Java " + $Req.java.major + " (the full 'JDK', needed by Ghidra)")
    if (-not (Has-Command "winget")) { Bad ("Install Java " + $Req.java.major + " (JDK) from " + $Req.java.manualUrl + " then run this again."); return }
    if (Ask ("Install Java " + $Req.java.major + " now? (about 200 MB; Windows may ask for permission; your other Java versions stay)")) {
      & winget install --id $Req.java.wingetId --exact --silent --accept-package-agreements --accept-source-agreements
      $jdk = Find-Jdk
    }
  }
  if (-not $jdk) { Bad ("Java " + $Req.java.major + " is required."); return }
  if ([Environment]::GetEnvironmentVariable("JAVA_HOME", "User") -ne $jdk) {
    if ($CheckOnly) { Missing ("JAVA_HOME should point at " + $jdk); return }
    Set-UserEnv "JAVA_HOME" $jdk
  }
  $env:JAVA_HOME = $jdk
  Ok ("Java " + $Req.java.major + " at " + $jdk)
}

# ---- Ghidra ------------------------------------------------------------------------------------

function Get-GhidraVersion($dir) {
  if (-not $dir) { return $null }
  $props = Join-Path $dir "Ghidra\application.properties"
  if (-not (Test-Path $props)) { return $null }
  $line = Select-String -Path $props -Pattern '^application\.version=(.+)$' | Select-Object -First 1
  if ($line) { return $line.Matches[0].Groups[1].Value.Trim() }
  return $null
}

function Ensure-Ghidra {
  $want = $Req.ghidra.version
  $default = Join-Path $ToolsDir $Req.ghidra.folderName
  $dir = $null
  foreach ($candidate in @($env:GHIDRA_INSTALL_DIR, [Environment]::GetEnvironmentVariable("GHIDRA_INSTALL_DIR", "User"), $default)) {
    if ((Get-GhidraVersion $candidate) -eq $want) { $dir = $candidate; break }
  }
  if (-not $dir) {
    Missing ("Ghidra " + $want + " (the program that reads the software; free, from the NSA)")
    $need = [math]::Ceiling($Req.ghidra.sizeMB * 3 / 1024)
    if ((Free-SpaceGB) -lt $need) { Bad ("Not enough free disk space: Ghidra needs about " + $need + " GB free."); return }
    if (Ask ("Download Ghidra " + $want + " (about " + $Req.ghidra.sizeMB + " MB) from github.com and unpack it into " + $ToolsDir + "?")) {
      New-Item -ItemType Directory -Force -Path $ToolsDir | Out-Null
      $zip = Join-Path $ToolsDir "ghidra-download.zip"
      Say "  Downloading... this can take several minutes." Cyan
      & curl.exe -L --fail --silent --show-error -o $zip $Req.ghidra.url
      if ($LASTEXITCODE -ne 0) { Bad "The Ghidra download failed. Check your internet connection and run this again."; return }
      $hash = (Get-FileHash $zip -Algorithm SHA256).Hash.ToLower()
      if ($hash -ne $Req.ghidra.sha256) {
        Remove-Item $zip -Force
        Bad "The downloaded Ghidra file did not match its published fingerprint, so it was deleted and NOT installed. Try again later."
        return
      }
      Ok "Download verified (fingerprint matches the published one)"
      Say "  Unpacking... (a few minutes)" Cyan
      & tar.exe -xf $zip -C $ToolsDir
      Remove-Item $zip -Force
      if ((Get-GhidraVersion $default) -eq $want) { $dir = $default } else { Bad "Ghidra did not unpack correctly."; return }
    } else { Bad "Ghidra is required."; return }
  }
  if ([Environment]::GetEnvironmentVariable("GHIDRA_INSTALL_DIR", "User") -ne $dir) {
    if ($CheckOnly) { Missing ("GHIDRA_INSTALL_DIR should point at " + $dir); return }
    Set-UserEnv "GHIDRA_INSTALL_DIR" $dir
  }
  $env:GHIDRA_INSTALL_DIR = $dir
  Ok ("Ghidra " + $want + " at " + $dir)
}

# ---- rea ---------------------------------------------------------------------------------------

function Get-ReaVersion {
  try {
    $v = (& rea --version) 2>$null
    if ($v -match "(\d+\.\d+\.\d+)") { return $Matches[1] }
  } catch { }
  return $null
}

function Ensure-Rea {
  $want = $Req.rea.version
  $have = Get-ReaVersion
  if ($have -eq $want) { Ok ("rea " + $want); }
  else {
    if ($have) { Missing ("rea is version " + $have + " but this project uses " + $want) } else { Missing "rea (the tool that lets an AI read the software)" }
    if (-not (Has-Command "npm")) { Bad "npm is missing (it comes with Node.js). Open a NEW window and run this again."; return }
    if (Ask ("Install rea " + $want + " now?")) {
      & npm install --global ($Req.rea.npmPackage + "@" + $want)
      Refresh-Path
      if ((Get-ReaVersion) -eq $want) { Ok ("rea " + $want + " installed") } else { Bad "rea did not install. Open a NEW window and run this again." }
    } else { Bad "rea is required."; return }
  }
  if ([Environment]::GetEnvironmentVariable("REA_ANALYSIS_PROVIDER", "User") -ne "ghidra" -or $env:REA_ANALYSIS_PROVIDER -ne "ghidra") {
    if (-not $CheckOnly) { Set-UserEnv "REA_ANALYSIS_PROVIDER" "ghidra" }
  }
}

# ---- The AI ------------------------------------------------------------------------------------

function Ensure-Ai {
  if (-not (Has-Command "claude")) {
    Missing "An AI to do the thinking (the Claude command line was not found)"
    Say "  If you have a Claude subscription: install Claude Code from https://claude.com/download, open a normal window, run  claude auth login  and sign in." Gray
    Say "  Using a different AI? That works too, but needs one extra setting; ask whoever invited you." Gray
    $script:Problems += "No AI found (install and sign in to the Claude command line)."
    return
  }
  Ok "Claude command line found"
  if ($CheckOnly) { return }
  if (Ask "Test that you are signed in? (sends one tiny message, costs almost nothing)") {
    $reply = ("Reply with the single word OK" | & claude -p --no-session-persistence 2>&1 | Out-String)
    if ($LASTEXITCODE -eq 0 -and $reply -match "OK") { Ok "Signed in and working" }
    else {
      Bad "Claude could not answer. Open a normal window, run  claude auth login , then run this again."
      Say ("  It said: " + $reply.Trim()) Gray
    }
  }
}

# ---- Joining -----------------------------------------------------------------------------------

function Parse-JoinLine($line) {
  if ($line -match "join\s+(\S+)\s+(\S+)") { return @{ Url = $Matches[1]; Code = $Matches[2] } }
  return $null
}

function Join-IfNeeded {
  $config = Join-Path $HOME ".rea-pool.json"
  if (Test-Path $config) { Ok "You have already joined a project"; return $true }
  Say ""
  Say "Now let's join the project. Your friend sent you a line that starts with 'pool join'." Cyan
  $joinLine = Read-Host "Paste that line here and press Enter"
  $parsed = Parse-JoinLine $joinLine
  if (-not $parsed) { Bad "That does not look like a join line. It should look like: pool join http://... jc_..."; return $false }
  Say ""
  Say "Your friend gave you a software file too. Drag that file into this window (or type its full path) and press Enter." Cyan
  $target = (Read-Host "Path to your copy of the software").Trim().Trim('"')
  if (-not (Test-Path $target)) { Bad ("I cannot find a file at " + $target); return $false }
  $joinArgs = @("join", $parsed.Url, $parsed.Code, "--target", $target)
  for ($try = 0; $try -lt 3; $try++) {
    $output = (& node (Join-Path $Root "src\cli.ts") @joinArgs 2>&1 | Out-String)
    Write-Host $output
    if ($LASTEXITCODE -eq 0) { return $true }
    if ($output -match "name is taken") {
      $name = (Read-Host "That name is taken. Pick another (letters and digits only)").Trim()
      $joinArgs = @("join", $parsed.Url, $parsed.Code, "--target", $target, "--name", $name)
    } else { break }
  }
  Bad "Could not join. Check the line with your friend and that their server is running."
  return $false
}

# ---- Main --------------------------------------------------------------------------------------

function Main {
  Say ""
  Say "rea-pool setup" Cyan
  Say "This checks what you need and offers to install anything missing. Nothing is installed without asking." Gray
  Say ("Programs go in standard places; Ghidra goes in " + $ToolsDir + ". Three user settings may be added: JAVA_HOME, GHIDRA_INSTALL_DIR, REA_ANALYSIS_PROVIDER.") Gray
  Say ""
  Ensure-Node
  Ensure-Java
  Ensure-Ghidra
  Ensure-Rea
  if ($Mode -eq "friend") { Ensure-Ai }

  if ($script:Problems.Count -gt 0) {
    Say ""
    Say "Setup is not finished:" Red
    foreach ($p in $script:Problems) { Say ("  - " + $p) Red }
    Say "Fix the above and run this again; it picks up where it left off." Yellow
    exit 1
  }
  if ($CheckOnly) { Say ""; Say "Everything is installed." Green; return }

  Say ""
  Say "Setup is complete." Green
  if ($Mode -eq "setup-only") {
    Say "Leaders: run  leader.cmd start <path to the software file> --name ""My project""" Cyan
    return
  }
  if (-not (Join-IfNeeded)) { exit 1 }
  Say ""
  Say "Starting. You can leave this window open and walk away. Press Ctrl+C to stop; run this again any time to continue." Cyan
  & node (Join-Path $Root "src\cli.ts") run
}

if ($MyInvocation.InvocationName -ne ".") { Main }
