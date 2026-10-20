#!/usr/bin/env bash
# rea-pool setup for Linux and macOS.
# Checks that everything you need is installed, offers to install what is missing (inside your own home
# folder, no administrator rights needed), then (in "friend" mode) helps you join a project and starts working.
#
#   ./setup.sh                      set up, join if needed, then run
#   ./setup.sh --mode setup-only    just set up (for the leader)
#   ./setup.sh --check-only         only report what is missing; install nothing and ask nothing
#   ./setup.sh --yes                do not ask, just install what is missing
#   ./setup.sh --no-corvus          skip the optional game reader
#   ./setup.sh --ignore-existing    pretend nothing is installed (for testing the installer)
#
# Works with the bash that ships with macOS (3.2).

set -u

ROOT="$(cd "$(dirname "$0")" && pwd)"
MODE="friend"
CHECK_ONLY=0
ASSUME_YES=0
IGNORE_EXISTING=0
NO_CORVUS=0

while [ $# -gt 0 ]; do
  case "$1" in
    --mode) MODE="${2:-friend}"; shift 2 ;;
    --check-only) CHECK_ONLY=1; shift ;;
    --yes) ASSUME_YES=1; shift ;;
    --no-corvus) NO_CORVUS=1; shift ;;
    --ignore-existing) IGNORE_EXISTING=1; shift ;;
    -h|--help) sed -n '2,14p' "$0"; exit 0 ;;
    *) echo "Unknown option: $1 (try --help)"; exit 2 ;;
  esac
done

case "$(uname -s)" in
  Linux) OSN=linux; ADOPT_OS=linux ;;
  Darwin) OSN=darwin; ADOPT_OS=mac ;;
  *) echo "This script is for Linux and macOS. On Windows, double-click START-HERE.cmd instead."; exit 2 ;;
esac
case "$(uname -m)" in
  x86_64|amd64) ARCHN=x64; ADOPT_ARCH=x64 ;;
  arm64|aarch64) ARCHN=arm64; ADOPT_ARCH=aarch64 ;;   # Node calls it arm64, the Java download site calls it aarch64
  *) echo "Unsupported processor type: $(uname -m)"; exit 2 ;;
esac

case "$OSN-$ARCHN" in
  linux-x64) PLAT=linux_x86_64 ;;
  linux-arm64) PLAT=linux_arm_64 ;;
  darwin-x64) PLAT=mac_x86_64 ;;
  darwin-arm64) PLAT=mac_arm_64 ;;
esac

HOME_DIR="$HOME/.rea-pool"
TOOLS="$HOME_DIR/tools"
ENVFILE="$HOME_DIR/env.sh"
PROBLEMS=""
NEW_PATH=""      # extra folders to put on PATH
NEW_JAVA_HOME=""
NEW_GHIDRA=""

# ---- small helpers -----------------------------------------------------------------------------

if [ -t 1 ]; then GREEN=$'\033[32m'; YELLOW=$'\033[33m'; RED=$'\033[31m'; CYAN=$'\033[36m'; GRAY=$'\033[90m'; OFF=$'\033[0m'; else GREEN=""; YELLOW=""; RED=""; CYAN=""; GRAY=""; OFF=""; fi
say() { printf '%s\n' "$1"; }
ok() { printf '%s  [OK]       %s%s\n' "$GREEN" "$1" "$OFF"; }
missing() { printf '%s  [MISSING]  %s%s\n' "$YELLOW" "$1" "$OFF"; }
bad() { printf '%s  [PROBLEM]  %s%s\n' "$RED" "$1" "$OFF"; PROBLEMS="$PROBLEMS
  - $1"; }

# req KEY: read one value from requirements.json (flat file, no tools needed)
req() { sed -n "s/.*\"$1\": *\"\{0,1\}\([^\",}]*\)\"\{0,1\}.*/\1/p" "$ROOT/requirements.json" | head -n 1; }

ask() {
  [ "$CHECK_ONLY" -eq 1 ] && return 1
  [ "$ASSUME_YES" -eq 1 ] && return 0
  printf '%s (Y/n) ' "$1"
  local answer=""
  read -r answer || answer=""
  case "$answer" in ""|y|Y|yes|YES) return 0 ;; *) return 1 ;; esac
}

have() { command -v "$1" >/dev/null 2>&1; }

sha256_of() {
  if have sha256sum; then sha256sum "$1" | awk '{print $1}'; else shasum -a 256 "$1" | awk '{print $1}'; fi
}

# download URL DEST
download() {
  have curl || { bad "curl is needed to download files. Install it (for example: sudo apt install curl) and run this again."; return 1; }
  curl -fL --retry 3 --silent --show-error -o "$2" "$1"
}

free_gb() { df -Pk "$HOME" | awk 'NR==2 {printf "%d", $4/1024/1024}'; }

TMP="$(mktemp -d 2>/dev/null || mktemp -d -t rea-pool)"
trap 'rm -rf "$TMP"' EXIT

# ---- Node.js -----------------------------------------------------------------------------------

node_major() {
  local v
  v="$(node --version 2>/dev/null)" || { echo 0; return; }
  v="${v#v}"; echo "${v%%.*}"
}

ensure_node() {
  local want_major want_ver
  want_major="$(req nodeMinimumMajor)"; want_ver="$(req nodeVersion)"
  if [ "$IGNORE_EXISTING" -eq 0 ] && [ "$(node_major)" -ge "$want_major" ]; then ok "Node.js $(node_major)"; return; fi
  if [ -x "$TOOLS/node/bin/node" ] && [ "$("$TOOLS/node/bin/node" --version | sed 's/^v//;s/\..*//')" -ge "$want_major" ]; then
    NEW_PATH="$TOOLS/node/bin:$NEW_PATH"; export PATH="$TOOLS/node/bin:$PATH"; ok "Node.js $(node_major) (installed by rea-pool)"; return
  fi
  missing "Node.js $want_major or newer (runs the pool tool)"
  if ask "Download Node.js $want_ver (about 40 MB) from nodejs.org into $TOOLS/node?"; then
    local file="node-v$want_ver-$OSN-$ARCHN.tar.gz" base="https://nodejs.org/dist/v$want_ver"
    download "$base/$file" "$TMP/$file" && download "$base/SHASUMS256.txt" "$TMP/SHASUMS256.txt" || { bad "Could not download Node.js."; return; }
    local expected; expected="$(grep " $file\$" "$TMP/SHASUMS256.txt" | awk '{print $1}')"
    if [ -z "$expected" ] || [ "$(sha256_of "$TMP/$file")" != "$expected" ]; then bad "The Node.js download did not match its published fingerprint, so it was NOT installed."; return; fi
    ok "Node.js download verified (fingerprint matches the published one)"
    mkdir -p "$TOOLS"; rm -rf "$TOOLS/node" "$TOOLS/node-v$want_ver-$OSN-$ARCHN"
    tar -xzf "$TMP/$file" -C "$TOOLS" && mv "$TOOLS/node-v$want_ver-$OSN-$ARCHN" "$TOOLS/node"
    NEW_PATH="$TOOLS/node/bin:$NEW_PATH"; export PATH="$TOOLS/node/bin:$PATH"
    [ "$(node_major)" -ge "$want_major" ] && ok "Node.js installed" || bad "Node.js did not install correctly."
  else bad "Node.js is required."; fi
}

# ---- Java 21 -----------------------------------------------------------------------------------

jdk_major() {   # jdk_major DIR -> major version, or 0
  local dir="$1" line
  [ -x "$dir/bin/javac" ] || { echo 0; return; }
  line="$(sed -n 's/^JAVA_VERSION="\{0,1\}\([0-9]\{1,\}\).*/\1/p' "$dir/release" 2>/dev/null | head -n 1)"
  echo "${line:-0}"
}

find_jdk() {
  local want="$1" dir candidates
  candidates="$TOOLS/jdk"
  if [ "$IGNORE_EXISTING" -eq 0 ]; then
    candidates="${JAVA_HOME:-} $candidates"
    if [ -x /usr/libexec/java_home ]; then candidates="$candidates $(/usr/libexec/java_home -v "$want" 2>/dev/null)"; fi
    for dir in /usr/lib/jvm/*; do candidates="$candidates $dir"; done
  fi
  for dir in $candidates; do
    [ -n "$dir" ] && [ "$(jdk_major "$dir")" = "$want" ] && { echo "$dir"; return; }
  done
}

ensure_java() {
  local want; want="$(req javaMajor)"
  local jdk; jdk="$(find_jdk "$want")"
  if [ -z "$jdk" ]; then
    missing "Java $want (the full 'JDK', needed by Ghidra)"
    if ask "Download Java $want (Eclipse Temurin, about 190 MB) into $TOOLS/jdk? Your other Java versions are untouched."; then
      have node || { bad "Node.js is needed first."; return; }
      local api="https://api.adoptium.net/v3/assets/latest/$want/hotspot?architecture=$ADOPT_ARCH&image_type=jdk&os=$ADOPT_OS&vendor=eclipse"
      download "$api" "$TMP/jdk.json" || { bad "Could not look up the Java download."; return; }
      local info; info="$(node -e 'const d=JSON.parse(require("fs").readFileSync(process.argv[1],"utf8"));const p=d[0].binary.package;console.log(p.link+" "+p.checksum)' "$TMP/jdk.json" 2>/dev/null)"
      local link="${info%% *}" sum="${info##* }"
      [ -n "$link" ] && [ -n "$sum" ] || { bad "Could not read the Java download details."; return; }
      download "$link" "$TMP/jdk.tar.gz" || { bad "Could not download Java."; return; }
      if [ "$(sha256_of "$TMP/jdk.tar.gz")" != "$sum" ]; then bad "The Java download did not match its published fingerprint, so it was NOT installed."; return; fi
      ok "Java download verified (fingerprint matches the published one)"
      mkdir -p "$TOOLS/jdk-unpack"; rm -rf "$TOOLS/jdk" "$TOOLS/jdk-unpack"/*
      tar -xzf "$TMP/jdk.tar.gz" -C "$TOOLS/jdk-unpack"
      local top; top="$(ls "$TOOLS/jdk-unpack" | head -n 1)"
      if [ -d "$TOOLS/jdk-unpack/$top/Contents/Home" ]; then mv "$TOOLS/jdk-unpack/$top/Contents/Home" "$TOOLS/jdk"; else mv "$TOOLS/jdk-unpack/$top" "$TOOLS/jdk"; fi
      rm -rf "$TOOLS/jdk-unpack"
      jdk="$(find_jdk "$want")"
    fi
  fi
  [ -n "$jdk" ] || { bad "Java $want is required."; return; }
  NEW_JAVA_HOME="$jdk"; export JAVA_HOME="$jdk"
  ok "Java $want at $jdk"
}

# ---- Ghidra ------------------------------------------------------------------------------------

ghidra_version() {
  sed -n 's/^application\.version=\(.*\)$/\1/p' "$1/Ghidra/application.properties" 2>/dev/null | head -n 1
}

ensure_ghidra() {
  local want folder dir="" default url sum size
  want="$(req ghidraVersion)"; folder="$(req ghidraFolderName)"; url="$(req ghidraUrl)"; sum="$(req ghidraSha256)"; size="$(req ghidraSizeMB)"
  default="$TOOLS/$folder"
  local candidate
  for candidate in $( [ "$IGNORE_EXISTING" -eq 0 ] && echo "${GHIDRA_INSTALL_DIR:-}" ) "$default"; do
    [ -n "$candidate" ] && [ "$(ghidra_version "$candidate")" = "$want" ] && { dir="$candidate"; break; }
  done
  if [ -z "$dir" ]; then
    missing "Ghidra $want (the program that reads the software; free, from the NSA)"
    have unzip || { bad "'unzip' is needed to unpack Ghidra. Install it (for example: sudo apt install unzip) and run this again."; return; }
    if [ "$(free_gb)" -lt 3 ]; then bad "Not enough free disk space: Ghidra needs about 3 GB free."; return; fi
    if ask "Download Ghidra $want (about $size MB) from github.com and unpack it into $TOOLS?"; then
      say "${CYAN}  Downloading... this can take several minutes.${OFF}"
      download "$url" "$TMP/ghidra.zip" || { bad "The Ghidra download failed. Check your internet connection and run this again."; return; }
      if [ "$(sha256_of "$TMP/ghidra.zip")" != "$sum" ]; then bad "The downloaded Ghidra file did not match its published fingerprint, so it was NOT installed."; return; fi
      ok "Ghidra download verified (fingerprint matches the published one)"
      say "${CYAN}  Unpacking...${OFF}"
      mkdir -p "$TOOLS"; unzip -q -o "$TMP/ghidra.zip" -d "$TOOLS" || { bad "Ghidra did not unpack correctly."; return; }
      # Make sure Ghidra's helper programs can run.
      chmod +x "$default"/support/* "$default"/ghidraRun 2>/dev/null
      find "$default/Ghidra/Features/Decompiler/os" -type f -name decompile -exec chmod +x {} \; 2>/dev/null
      [ "$(ghidra_version "$default")" = "$want" ] && dir="$default" || { bad "Ghidra did not unpack correctly."; return; }
    else bad "Ghidra is required."; return; fi
  fi
  NEW_GHIDRA="$dir"; export GHIDRA_INSTALL_DIR="$dir"
  ok "Ghidra $want at $dir"
}

# ---- Ghidra's decompiler program ---------------------------------------------------------------
# Ghidra ships a ready-made decompiler for most computers but not all (notably Apple Silicon Macs).
# When it is missing, the source code is inside the download and can be built in a few minutes.

ensure_decompiler() {
  [ -n "$NEW_GHIDRA" ] || return
  local base="$NEW_GHIDRA/Ghidra/Features/Decompiler"
  if [ -x "$base/os/$PLAT/decompile" ] || [ -x "$base/build/os/$PLAT/decompile" ]; then
    ok "Ghidra's decompiler program for this computer ($PLAT)"; return
  fi
  missing "Ghidra's decompiler program for this computer ($PLAT) is not in the download and has to be built (a few minutes)"
  local compiler=""
  for c in c++ g++ clang++; do have "$c" && { compiler="$c"; break; }; done
  if ! have make || [ -z "$compiler" ]; then
    if [ "$OSN" = "darwin" ]; then bad "Building needs Apple's developer tools. Run  xcode-select --install  in Terminal, then run this again."
    else bad "Building needs make and a C++ compiler. Install them (for example: sudo apt install build-essential bison flex) and run this again."; fi
    return
  fi
  # Homebrew's bison is newer than the one macOS ships; use it if present.
  if have brew && [ -d "$(brew --prefix bison 2>/dev/null)/bin" ]; then export PATH="$(brew --prefix bison)/bin:$PATH"; fi
  if ! have bison; then
    if [ "$OSN" = "darwin" ]; then bad "Building needs  bison.  Install it with:  brew install bison   (get Homebrew from https://brew.sh), then run this again."
    else bad "Building needs  bison.  Install it (for example: sudo apt install bison flex) and run this again."; fi
    return
  fi
  if ask "Build Ghidra's decompiler program now? (takes a few minutes, uses your computer's compiler)"; then
    say "${CYAN}  Building...${OFF}"
    local src="$base/src/decompile/cpp" built=1
    if [ "$PLAT" = "mac_arm_64" ]; then
      ( cd "$src" && make ghidra_opt ARCH_TYPE="-arch arm64" OSDIR="$PLAT" >"$TMP/build.log" 2>&1 ) && built=0
      # Some compilers reject an old setting in the makefile; retry quietly with warnings off.
      if [ "$built" -ne 0 ]; then ( cd "$src" && make clean >/dev/null 2>&1; make ghidra_opt ARCH_TYPE="-arch arm64" OSDIR="$PLAT" ADDITIONAL_FLAGS="-w" >"$TMP/build.log" 2>&1 ) && built=0; fi
    else
      ( cd "$src" && make ghidra_opt OSDIR="$PLAT" >"$TMP/build.log" 2>&1 ) && built=0
      if [ "$built" -ne 0 ]; then ( cd "$src" && make clean >/dev/null 2>&1; make ghidra_opt OSDIR="$PLAT" ADDITIONAL_FLAGS="-w" >"$TMP/build.log" 2>&1 ) && built=0; fi
    fi
    if [ "$built" -ne 0 ] || [ ! -f "$src/ghidra_opt" ]; then
      bad "Building the decompiler failed. The last lines of the log: $(tail -n 5 "$TMP/build.log" | tr '\n' ' ')"; return
    fi
    mkdir -p "$base/os/$PLAT" && install -m 755 "$src/ghidra_opt" "$base/os/$PLAT/decompile"
    [ -x "$base/os/$PLAT/decompile" ] && ok "Decompiler program built" || bad "The decompiler program could not be installed."
  else bad "The decompiler program is required."; fi
}

# ---- rea ---------------------------------------------------------------------------------------

rea_version() { rea --version 2>/dev/null | sed -n 's/.*\([0-9]\{1,\}\.[0-9]\{1,\}\.[0-9]\{1,\}\).*/\1/p' | head -n 1; }

ensure_rea() {
  local want pkg; want="$(req reaVersion)"; pkg="$(req reaNpmPackage)"
  if [ -x "$TOOLS/npm-global/bin/rea" ]; then NEW_PATH="$TOOLS/npm-global/bin:$NEW_PATH"; export PATH="$TOOLS/npm-global/bin:$PATH"; fi
  local have_v=""; [ "$IGNORE_EXISTING" -eq 1 ] && [ ! -x "$TOOLS/npm-global/bin/rea" ] || have_v="$(rea_version)"
  if [ "$have_v" = "$want" ]; then ok "rea $want"; return; fi
  if [ -n "$have_v" ]; then missing "rea is version $have_v but this project uses $want"; else missing "rea (the tool that lets an AI read the software)"; fi
  have npm || { bad "npm is missing (it comes with Node.js)."; return; }
  if ask "Install rea $want now?"; then
    mkdir -p "$TOOLS/npm-global"
    npm install --global --prefix "$TOOLS/npm-global" "$pkg@$want" >/dev/null 2>"$TMP/npm.err" || { bad "rea did not install: $(tail -n 2 "$TMP/npm.err" | tr '\n' ' ')"; return; }
    NEW_PATH="$TOOLS/npm-global/bin:$NEW_PATH"; export PATH="$TOOLS/npm-global/bin:$PATH"
    [ "$(rea_version)" = "$want" ] && ok "rea $want installed" || bad "rea did not install correctly."
  else bad "rea is required."; fi
}

# ---- Corvus (optional) -------------------------------------------------------------------------

corvus_version() { "$1" --version 2>/dev/null | sed -n 's/.*\([0-9]\{1,\}\.[0-9]\{1,\}\.[0-9]\{1,\}\).*/\1/p' | head -n 1; }

ensure_corvus() {
  [ "$NO_CORVUS" -eq 1 ] && return
  say "Corvus (extra reader for Unity/.NET games)"
  local dir="$TOOLS/corvus" key asset sum version
  version="$(req corvusVersion)"
  if [ "$IGNORE_EXISTING" -eq 0 ] && have corvus && [ "$(corvus_version corvus)" = "$version" ]; then ok "Corvus $version (optional) found"; return; fi
  if [ -x "$dir/corvus" ] && [ "$(corvus_version "$dir/corvus")" = "$version" ]; then
    NEW_PATH="$dir:$NEW_PATH"; export PATH="$dir:$PATH"; ok "Corvus (optional) found"; return
  fi
  if [ "$CHECK_ONLY" -eq 1 ]; then say "  Optional reader not installed; rea/Ghidra still works."; return; fi
  ask "Install Corvus (extra reader for Unity/.NET games)?" || return
  case "$OSN-$ARCHN" in
    linux-x64) key=LinuxX64 ;; linux-arm64) key=LinuxArm64 ;;
    darwin-x64) key=OsxX64 ;; darwin-arm64) key=OsxArm64 ;;
  esac
  asset="$(req "corvus${key}Asset")"; sum="$(req "corvus${key}Sha256")"; version="$(req corvusVersion)"
  # Do not use download(): optional failures must never add to PROBLEMS.
  if ! have curl || ! curl -fL --retry 3 --silent --show-error -o "$TMP/corvus-archive" "https://github.com/Albasha0x0/Corvus/releases/download/v$version/$asset"; then
    say "  [WARNING] Corvus could not be downloaded; continuing with rea/Ghidra."; return
  fi
  if [ -z "$sum" ] || [ "$(sha256_of "$TMP/corvus-archive")" != "$sum" ]; then
    rm -f "$TMP/corvus-archive"
    say "  [WARNING] Corvus fingerprint did not match; it was NOT unpacked or installed. Continuing with rea/Ghidra."; return
  fi
  if ! mkdir -p "$TMP/corvus-unpack" || ! tar -xzf "$TMP/corvus-archive" -C "$TMP/corvus-unpack" || [ ! -f "$TMP/corvus-unpack/corvus" ]; then
    say "  [WARNING] Corvus could not be unpacked; continuing with rea/Ghidra."; return
  fi
  if ! chmod +x "$TMP/corvus-unpack/corvus" || ! mkdir -p "$TOOLS"; then
    say "  [WARNING] Corvus could not be installed; continuing with rea/Ghidra."; return
  fi
  if [ -e "$dir" ] && ! mv "$dir" "$TMP/corvus-previous"; then
    say "  [WARNING] Could not replace the old Corvus; continuing with rea/Ghidra."; return
  fi
  if ! mv "$TMP/corvus-unpack" "$dir"; then
    [ -e "$TMP/corvus-previous" ] && mv "$TMP/corvus-previous" "$dir"
    say "  [WARNING] Corvus could not be installed; continuing with rea/Ghidra."; return
  fi
  NEW_PATH="$dir:$NEW_PATH"; export PATH="$dir:$PATH"
  ok "Corvus $version installed (fingerprint verified)"
}

# ---- The AI ------------------------------------------------------------------------------------

ensure_ai() {
  if ! have claude; then
    missing "An AI to do the thinking (the Claude command line was not found)"
    say "${GRAY}  If you have a Claude subscription: install Claude Code from https://claude.com/download, run  claude auth login  and sign in.${OFF}"
    say "${GRAY}  Using a different AI? That works too, but needs one extra setting; ask whoever invited you.${OFF}"
    PROBLEMS="$PROBLEMS
  - No AI found (install and sign in to the Claude command line)."
    return
  fi
  ok "Claude command line found"
  [ "$CHECK_ONLY" -eq 1 ] && return
  if ask "Test that you are signed in? (sends one tiny message, costs almost nothing)"; then
    local reply; reply="$(printf 'Reply with the single word OK' | claude -p --no-session-persistence 2>&1)"
    case "$reply" in *OK*) ok "Signed in and working" ;; *) bad "Claude could not answer. Run  claude auth login  in a normal window, then run this again."; say "${GRAY}  It said: $reply${OFF}" ;; esac
  fi
}

# ---- Saving the settings -----------------------------------------------------------------------

write_env() {
  mkdir -p "$HOME_DIR"
  {
    echo "# Written by rea-pool setup. The ./pool and ./leader commands read this."
    [ -n "$NEW_PATH" ] && echo "export PATH=\"${NEW_PATH%:}:\$PATH\""
    [ -n "$NEW_JAVA_HOME" ] && echo "export JAVA_HOME=\"$NEW_JAVA_HOME\""
    [ -n "$NEW_GHIDRA" ] && echo "export GHIDRA_INSTALL_DIR=\"$NEW_GHIDRA\""
    [ -n "$NEW_GHIDRA" ] && echo "export CORVUS_GHIDRA_DIR=\"$NEW_GHIDRA\""
    echo "export REA_ANALYSIS_PROVIDER=ghidra"
  } > "$ENVFILE"
}

# ---- Joining -----------------------------------------------------------------------------------

join_if_needed() {
  if [ -f "$HOME/.rea-pool.json" ]; then ok "You have already joined a project"; return 0; fi
  say ""
  say "${CYAN}Now let's join the project. Your friend sent you a line that starts with 'pool join'.${OFF}"
  printf 'Paste that line here and press Enter: '
  local line=""; read -r line
  local url code
  url="$(printf '%s' "$line" | sed -n 's/.*join[[:space:]]\{1,\}\([^[:space:]]\{1,\}\)[[:space:]]\{1,\}\([^[:space:]]\{1,\}\).*/\1/p')"
  code="$(printf '%s' "$line" | sed -n 's/.*join[[:space:]]\{1,\}\([^[:space:]]\{1,\}\)[[:space:]]\{1,\}\([^[:space:]]\{1,\}\).*/\2/p')"
  if [ -z "$url" ] || [ -z "$code" ]; then bad "That does not look like a join line. It should look like: pool join http://... jc_..."; return 1; fi
  say ""
  say "${CYAN}Your friend gave you a software file too. Drag that file into this window (or type its full path) and press Enter.${OFF}"
  printf 'Path to your copy of the software: '
  local target=""; read -r target
  target="$(printf '%s' "$target" | sed "s/^[[:space:]]*//;s/[[:space:]]*\$//;s/^['\"]//;s/['\"]\$//;s/\\\\ / /g")"
  [ -f "$target" ] || { bad "I cannot find a file at $target"; return 1; }
  local try=0 name_args=""
  while [ "$try" -lt 3 ]; do
    local output status
    # shellcheck disable=SC2086
    output="$("$ROOT/pool" join "$url" "$code" --target "$target" $name_args 2>&1)"; status=$?
    printf '%s\n' "$output"
    [ "$status" -eq 0 ] && return 0
    case "$output" in
      *"name is taken"*) printf 'That name is taken. Pick another (letters and digits only): '; local name=""; read -r name; name_args="--name $name" ;;
      *) break ;;
    esac
    try=$((try + 1))
  done
  bad "Could not join. Check the line with your friend and that their server is running."
  return 1
}

# ---- Main --------------------------------------------------------------------------------------

say ""
say "${CYAN}rea-pool setup${OFF}"
say "${GRAY}This checks what you need and offers to install anything missing. Nothing is installed without asking.${OFF}"
say "${GRAY}Everything goes inside $HOME_DIR; no administrator rights are used.${OFF}"
say ""

mkdir -p "$TOOLS" 2>/dev/null
ensure_node
ensure_java
ensure_ghidra
ensure_decompiler
ensure_rea
ensure_corvus
[ "$MODE" = "friend" ] && ensure_ai

if [ -n "$PROBLEMS" ]; then
  say ""; printf '%sSetup is not finished:%s%s\n' "$RED" "$PROBLEMS" "$OFF"
  say "${YELLOW}Fix the above and run this again; it picks up where it left off.${OFF}"
  exit 1
fi
if [ "$CHECK_ONLY" -eq 1 ]; then say ""; say "${GREEN}Everything is installed.${OFF}"; exit 0; fi

write_env
say ""; say "${GREEN}Setup is complete.${OFF}"
if [ "$MODE" = "setup-only" ]; then
  say "${CYAN}Leaders: run  ./leader start <path to the software file> --name \"My project\"${OFF}"
  exit 0
fi
join_if_needed || exit 1
say ""
say "${CYAN}Starting. You can leave this window open and walk away. Press Ctrl+C to stop; run this again any time to continue.${OFF}"
rm -rf "$TMP"
exec "$ROOT/pool" run
