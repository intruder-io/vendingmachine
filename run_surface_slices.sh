#!/usr/bin/env bash
# run_surface_slices.sh
#
# Generic, multi-language surface slicer. For each application it:
#   1. detects the language (or honours a LANGUAGE= override),
#   2. selects the Joern frontend + exclude pattern + slice script + triage skill,
#   3. prebuilds a CPG out-of-process with a big heap (avoids OOM on large trees),
#   4. concatenates  slicers/_prelude.sc + <lang>.sc + _postlude.sc  into one
#      temp script and runs it,
#   5. prints which Claude skill to invoke on the resulting slices.
#
# Supported languages: php, ruby (Rails + Sinatra), wordpress (php2cpg frontend
# + wp-security-analyst skill), java (javasrc2cpg for .java source / jimple2cpg
# for compiled .jar/.war/.class — auto-picked by input kind), javascript
# (jssrc2cpg; JS + TS — Express/Koa/Fastify, NestJS decorators, Next.js API routes).
#
# Usage:
#   # Batch — one subdir per app under APPS_DIR (default ./apps):
#   ./run_surface_slices.sh
#   JOBS=4 ./run_surface_slices.sh                  # 4 in parallel (needs GNU parallel)
#   APPS_DIR=/path/to/apps ./run_surface_slices.sh
#
#   # Single app:
#   SOURCE_ROOT=/path/to/app PROJECT=myapp ./run_surface_slices.sh
#   LANGUAGE=ruby SOURCE_ROOT=/path/to/app PROJECT=myapp ./run_surface_slices.sh
#
# Key env vars:
#   LANGUAGE      - force language (php|ruby|wordpress|javascript|java|java-source|
#                   java-bytecode); `js`/`ts`/`node` alias javascript; bare `java`
#                   resolves source-vs-bytecode by input; else auto-detect
#   EXCLUDE_EXTRA - extra regex ORed onto the language-default EXCLUDE_REGEX
#                   (e.g. EXCLUDE_EXTRA='(.*/)?(lib)/.*' to skip bundled libs
#                   in Moodle-style apps that don't use a vendor/ directory)
#   JVM_OPTS    - extra JVM flags passed to both the CPG frontend and joern
#                   (e.g. JVM_OPTS='-XX:+UseZGC' to test low-pause GC)
#   APPS_DIR      - batch mode: dir containing one subdir per app (default ./apps)
#   SOURCE_ROOT   - single-app mode: the app source dir
#   PROJECT       - single-app mode: project name (default: basename SOURCE_ROOT)
#   OUTPUT_BASE   - slice output base (default ./surface_slices)
#   HEAP          - joern (analysis) heap (default 13g)
#   BUILD_HEAP    - frontend (parse) heap (default 12g)
#   DOWNLOAD_DEPS - ruby only: 1 to pass --download-dependencies (network, slow)
#   JOBS          - parallel app count (default 1; >1 requires GNU parallel)

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SLICERS_DIR="$SCRIPT_DIR/slicers"
APPS_DIR="${APPS_DIR:-$SCRIPT_DIR/apps}"
OUTPUT_BASE="${OUTPUT_BASE:-$SCRIPT_DIR/surface_slices}"
LOG_DIR="${LOG_DIR:-$SCRIPT_DIR/surface_logs}"
# NOTE: the prelude resolves the CPG path as "cpgs/<project>.bin" relative to CWD,
# and we cd to SCRIPT_DIR before running joern — so CPG_DIR must be SCRIPT_DIR/cpgs.
CPG_DIR="$SCRIPT_DIR/cpgs"
MAX_DEPTH="${MAX_DEPTH:-10}"
JOERN="${JOERN:-joern}"
JOBS="${JOBS:-1}"
HEAP="${HEAP:-13g}"
BUILD_HEAP="${BUILD_HEAP:-12g}"
DOWNLOAD_DEPS="${DOWNLOAD_DEPS:-0}"
LANGUAGE_OVERRIDE="${LANGUAGE:-}"
EXCLUDE_EXTRA="${EXCLUDE_EXTRA:-}"
JVM_OPTS="${JVM_OPTS:-}"

# Frontend launchers live alongside joern.
JOERN_BIN_DIR="$(dirname "$(command -v "$JOERN" 2>/dev/null || echo /usr/bin/joern)")"

mkdir -p "$LOG_DIR" "$OUTPUT_BASE" "$CPG_DIR"

# ---------------------------------------------------------------------------
# Java sub-kind: given a Java project, decide whether to feed the SOURCE frontend
# (javasrc2cpg, readable bodies) or the BYTECODE frontend (jimple2cpg, best call
# graph). The split is driven by which artifacts actually exist: if there is .java
# to compile we prefer source; if the input is only compiled (.class/.jar/.war/.apk)
# we go bytecode. Echoes: java-source | java-bytecode
# ---------------------------------------------------------------------------
detect_java_kind() {
  local r="$1" njava nclass njar nwar napk
  njava=$(find "$r" -name '*.java'  -not -path '*/test/*' 2>/dev/null | head -500 | wc -l | tr -d ' ')
  nclass=$(find "$r" -name '*.class' 2>/dev/null | head -50  | wc -l | tr -d ' ')
  nwar=$(find "$r" -name '*.war' 2>/dev/null   | head -5   | wc -l | tr -d ' ')
  napk=$(find "$r" -name '*.apk' 2>/dev/null   | head -5   | wc -l | tr -d ' ')
  # Ignore build-system jars (wrappers / the gradle distribution) when judging
  # "is this a bag of bytecode?" — only app/dependency jars count.
  njar=$(find "$r" -name '*.jar' -not -name 'gradle-wrapper.jar' 2>/dev/null | head -50 | wc -l | tr -d ' ')
  if (( njava > 0 )); then echo java-source
  elif (( nclass + njar + nwar + napk > 0 )); then echo java-bytecode
  else echo java-source   # has pom/gradle but nothing compiled yet → expect source
  fi
}

# ---------------------------------------------------------------------------
# Language detection (read-only, weighted signals).
# Echoes: php|ruby|wordpress|java-source|java-bytecode|ambiguous
# ---------------------------------------------------------------------------
detect_language() {
  local r="$1" score_ruby=0 score_php=0 score_java=0 score_js=0
  # WordPress is a PHP sub-case with its own slicer/skill — short-circuit.
  if [[ -f "$r/wp-load.php" || -f "$r/wp-config.php" || -f "$r/wp-settings.php" ]]; then
    echo wordpress; return
  fi
  [[ -f "$r/config/routes.rb" ]] && score_ruby=$((score_ruby + 10))
  [[ -d "$r/app/controllers" ]] && score_ruby=$((score_ruby + 5))
  if [[ -f "$r/Gemfile" ]]; then
    score_ruby=$((score_ruby + 3))
    grep -qE "gem ['\"]rails['\"]" "$r/Gemfile" 2>/dev/null && score_ruby=$((score_ruby + 5))
  fi
  [[ -f "$r/Rakefile" || -f "$r/config.ru" ]] && score_ruby=$((score_ruby + 2))
  [[ -f "$r/composer.json" ]] && score_php=$((score_php + 5))
  [[ -f "$r/artisan" ]] && score_php=$((score_php + 5))
  # Java build systems / layout / packaging are strong signals.
  [[ -f "$r/pom.xml" ]] && score_java=$((score_java + 8))
  [[ -f "$r/build.gradle" || -f "$r/build.gradle.kts" ]] && score_java=$((score_java + 8))
  [[ -f "$r/settings.gradle" || -f "$r/settings.gradle.kts" ]] && score_java=$((score_java + 2))
  [[ -d "$r/src/main/java" ]] && score_java=$((score_java + 6))
  { [[ -d "$r/WEB-INF" ]] || find "$r" -maxdepth 4 -type d -name WEB-INF -print -quit 2>/dev/null | grep -q .; } && score_java=$((score_java + 4))
  # JavaScript / TypeScript (Node.js) build + framework signals. package.json alone
  # is weak (PHP/Ruby apps carry one for front-end asset tooling), so the strong
  # discriminator is a *server-side* framework listed as a dependency.
  [[ -f "$r/package.json" ]] && score_js=$((score_js + 2))
  [[ -f "$r/tsconfig.json" ]] && score_js=$((score_js + 3))
  if [[ -f "$r/package.json" ]]; then
    grep -qE '"(express|koa|@koa/router|fastify|@nestjs/core|@nestjs/common|next|restify|@hapi/hapi|hapi|sails|connect|polka|routing-controllers)"[[:space:]]*:' "$r/package.json" 2>/dev/null \
      && score_js=$((score_js + 8))
  fi
  local rb php jv js
  rb=$(find "$r" -name '*.rb'   -not -path '*/vendor/*' 2>/dev/null | head -2000 | wc -l | tr -d ' ')
  php=$(find "$r" -name '*.php' -not -path '*/vendor/*' 2>/dev/null | head -2000 | wc -l | tr -d ' ')
  # Java sources OR compiled artifacts both count toward the Java file signal.
  jv=$(find "$r" \( -name '*.java' -o -name '*.class' -o -name '*.jar' -o -name '*.war' \) -not -path '*/test/*' 2>/dev/null | head -2000 | wc -l | tr -d ' ')
  js=$(find "$r" \( -name '*.js' -o -name '*.mjs' -o -name '*.cjs' -o -name '*.ts' -o -name '*.tsx' -o -name '*.jsx' \) \
        -not -path '*/node_modules/*' -not -name '*.min.js' -not -name '*.d.ts' 2>/dev/null | head -2000 | wc -l | tr -d ' ')
  (( rb  > php && rb  > jv && rb  > js )) && score_ruby=$((score_ruby + 3))
  (( php > rb  && php > jv && php > js )) && score_php=$((score_php + 3))
  (( jv  > rb  && jv  > php && jv  > js )) && score_java=$((score_java + 3))
  (( js  > rb  && js  > php && js  > jv )) && score_js=$((score_js + 3))
  # Strict max: one language must beat ALL others, else ambiguous (don't guess —
  # a wrong frontend yields an empty CPG and silent zero findings).
  if   (( score_js   > score_ruby && score_js   > score_php  && score_js   > score_java && score_js   > 0 )); then echo javascript
  elif (( score_java > score_ruby && score_java > score_php  && score_java > score_js   && score_java > 0 )); then detect_java_kind "$r"
  elif (( score_ruby > score_php  && score_ruby > score_java && score_ruby > score_js )); then echo ruby
  elif (( score_php  > score_ruby && score_php  > score_java && score_php  > score_js )); then echo php
  else echo "ambiguous (ruby=$score_ruby php=$score_php java=$score_java js=$score_js)"
  fi
}

# ---------------------------------------------------------------------------
# Per-language registry. Sets globals: FRONTEND_NAME, SLICER, SKILL, EXCLUDE_REGEX,
# FRONTEND_EXTRA. Returns non-zero for an unknown language.
# ---------------------------------------------------------------------------
lang_config() {
  local lang="$1"
  FRONTEND_EXTRA=()
  case "$lang" in
    php)
      FRONTEND_NAME="php2cpg"
      SLICER="$SLICERS_DIR/php.sc"
      EXCLUDE_REGEX='(.*/)?(vendor|node_modules|tests|test|locales)/.*|.*schemaCache\.php'
      ;;
    wordpress)
      FRONTEND_NAME="php2cpg"
      SLICER="$SLICERS_DIR/wordpress.sc"
      EXCLUDE_REGEX='(.*/)?(vendor|node_modules|tests|test|locales)/.*|.*schemaCache\.php'
      ;;
    javascript)
      # jssrc2cpg handles BOTH .js and .ts. NB: this frontend's launcher is named
      # with a `.sh` suffix (unlike php2cpg/rubysrc2cpg/javasrc2cpg).
      FRONTEND_NAME="jssrc2cpg.sh"
      SLICER="$SLICERS_DIR/javascript.sc"
      # Exclude third-party + build output + minified/bundled/type-def files: none
      # hold app request surface and node_modules in particular is enormous. (As in
      # the ruby note, the `(.*/)?` prefix lets a bare segment match an ANCESTOR dir,
      # so we keep this list to names that won't plausibly be a checkout's parent.)
      EXCLUDE_REGEX='(.*/)?(node_modules|bower_components|dist|build|coverage|\.next|test|tests|__tests__|__mocks__|e2e|cypress)/.*|.*\.min\.js|.*\.bundle\.js|.*\.d\.ts'
      ;;
    ruby)
      FRONTEND_NAME="rubysrc2cpg"
      SLICER="$SLICERS_DIR/ruby.sc"
      # Do NOT exclude config/ wholesale — config/routes.rb is the route source.
      # NB: the exclude regex is matched (find-style) against the ABSOLUTE path, and
      # the `(.*/)?` prefix lets a bare segment match an ANCESTOR dir. So we must NOT
      # list common temp-root names like `tmp`/`log` here — a checkout under /tmp
      # would then match `(.*/)?tmp/.*` and exclude the whole tree (empty CPG, silent
      # zero findings). tmp/ and log/ hold no .rb request surface anyway.
      EXCLUDE_REGEX='(.*/)?(vendor/bundle|\.bundle|node_modules|coverage|spec|test|features|db/migrate|public/(assets|packs)|storage|config/locales)/.*'
      [[ "$DOWNLOAD_DEPS" == "1" ]] && FRONTEND_EXTRA=(--download-dependencies)
      ;;
    java-source)
      # Readable bodies: feed the .java tree to the source frontend.
      FRONTEND_NAME="javasrc2cpg"
      SLICER="$SLICERS_DIR/java.sc"
      EXCLUDE_REGEX='(.*/)?(src/test|test|tests|target|build/(classes|generated|tmp)|\.gradle|node_modules)/.*|.*[Tt]est\.java'
      ;;
    java-bytecode)
      # Best call graph: feed compiled artifacts to the Jimple frontend.
      # --recurse unpacks nested jars (WARs / Spring-Boot fat jars); --full-resolver
      # resolves transitive references for a more complete call graph. Exclude the
      # dependency jar dirs so we slice the APP, not all of Spring/Hibernate (point
      # at WEB-INF/classes or BOOT-INF/classes for a fat jar to narrow further, or
      # set INCLUDE_REGEX='com\.yourco\..*' to scope every pass to your packages).
      FRONTEND_NAME="jimple2cpg"
      SLICER="$SLICERS_DIR/java.sc"
      EXCLUDE_REGEX='(.*/)?(WEB-INF/lib|BOOT-INF/lib|META-INF|test|tests)/.*'
      FRONTEND_EXTRA=(--recurse --full-resolver)
      ;;
    *) return 1 ;;
  esac
  case "$lang" in
    wordpress)               SKILL="wp-security-analyst" ;;
    php)                     SKILL="php-security-analyst" ;;
    ruby)                    SKILL="ruby-security-analyst" ;;
    javascript)              SKILL="javascript-security-analyst" ;;
    java-source|java-bytecode) SKILL="java-security-analyst" ;;
  esac
  return 0
}

# Guard: a language fragment must not redefine the prelude's shared vals/buffers.
lint_fragment() {
  if grep -Eq 'val[[:space:]]+(cpg|manifest|emitted|usedSlugs)\b' "$1"; then
    echo "[!] Lint: $(basename "$1") redefines a prelude-owned val (cpg/manifest/emitted/usedSlugs)"
    return 1
  fi
  return 0
}

# Concatenate prelude + language fragment + postlude into a temp .sc. Echoes its
# path. We create a temp DIR (mktemp -d randomises reliably on macOS, which only
# substitutes TRAILING Xs) and put slice.sc inside it — joern's --script wants a
# .sc/.scala extension. Caller removes the dir on success, keeps it on failure.
build_script() {
  local frag="$1" tmpdir tmp
  tmpdir="$(mktemp -d "${TMPDIR:-/tmp}/surface_slice.XXXXXX")"
  tmp="$tmpdir/slice.sc"
  {
    cat "$SLICERS_DIR/_prelude.sc"
    printf '\n// === BEGIN %s ===\n' "$(basename "$frag")"
    cat "$frag"
    printf '\n// === BEGIN _postlude.sc ===\n'
    cat "$SLICERS_DIR/_postlude.sc"
  } > "$tmp"
  echo "$tmp"
}

# ---------------------------------------------------------------------------
# Process one app: detect -> prebuild CPG -> concat -> run -> report skill.
# ---------------------------------------------------------------------------
process_app() {
  local name="$1"
  local dir="$2"
  local log="$LOG_DIR/$name.log"
  local cpg="$CPG_DIR/$name.bin"

  # Prelude resolves cpgs/<project>.bin relative to CWD — run from SCRIPT_DIR.
  cd "$SCRIPT_DIR"

  # 1) Language.
  local lang
  if [[ -n "$LANGUAGE_OVERRIDE" ]]; then
    lang="$LANGUAGE_OVERRIDE"
    # Convenience aliases for the JS/TS frontend (one frontend serves both).
    case "$lang" in js|ts|typescript|node|nodejs) lang="javascript" ;; esac
    # Convenience: `LANGUAGE=java` resolves to java-source/java-bytecode by input.
    [[ "$lang" == "java" ]] && lang="$(detect_java_kind "$dir")"
  else
    lang="$(detect_language "$dir")"
  fi
  if [[ "$lang" == ambiguous* ]]; then
    echo "[!] Skip: $name — language $lang. Set LANGUAGE=ruby|php|wordpress."; return
  fi
  if ! lang_config "$lang"; then
    echo "[!] Skip: $name — unknown language '$lang'."; return
  fi
  [[ -n "$EXCLUDE_EXTRA" ]] && EXCLUDE_REGEX="$EXCLUDE_REGEX|$EXCLUDE_EXTRA"
  echo "[*] $name: language=$lang frontend=$FRONTEND_NAME skill=$SKILL"

  local frontend_bin="$JOERN_BIN_DIR/$FRONTEND_NAME"
  if [[ ! -x "$frontend_bin" ]]; then
    echo "[!] Failed: $name — frontend not found at '$frontend_bin' (set JOERN= or PATH)"; return
  fi

  # Convert raw JVM flags (e.g. "-XX:+UseZGC") to joern's -J- prefix form.
  # If the user selects a different GC, prepend -XX:-UseG1GC to negate the one
  # hardcoded in the joern/frontend launcher scripts, which would otherwise cause
  # "multiple garbage collectors selected".
  local jvm_j_opts=() has_gc_selector=false
  for opt in $JVM_OPTS; do
    [[ "$opt" =~ -XX:\+Use[A-Za-z]*GC ]] && has_gc_selector=true
    jvm_j_opts+=("-J$opt")
  done
  $has_gc_selector && jvm_j_opts=("-J-XX:-UseG1GC" "${jvm_j_opts[@]}")

  # 2) Prebuild the CPG out-of-process (big heap + non-surface excludes) unless present.
  if [[ ! -f "$cpg" ]]; then
    echo "[*] Building CPG: $name (heap $BUILD_HEAP, $FRONTEND_NAME${JVM_OPTS:+, $JVM_OPTS})"
    if ! "$frontend_bin" -J-Xmx"$BUILD_HEAP" "${jvm_j_opts[@]}" \
          --exclude-regex "$EXCLUDE_REGEX" \
          "${FRONTEND_EXTRA[@]}" \
          "$dir" -o "$cpg" > "$log" 2>&1; then
      echo "[!] Failed: $name — CPG build error (see $log)"; rm -f "$cpg"; return
    fi
  fi

  # 3) Lint + concatenate the slice script.
  if ! lint_fragment "$SLICER"; then
    echo "[!] Failed: $name — slicer lint error"; return
  fi
  local tmp_script
  tmp_script="$(build_script "$SLICER")"

  # 4) Run the slicer against the prebuilt CPG (semantic overlays only).
  #    NOTE: this joern's script runner exits non-zero ("No @main methods
  #    declared") even after running the body successfully, so we DON'T trust its
  #    exit code — success is judged by whether the manifest was (re)written. The
  #    manifest is the last thing the postlude writes, so its presence means the
  #    whole script ran. Clear any stale manifest first so a failed re-run can't
  #    look like a success.
  local manifest="$OUTPUT_BASE/$name/manifest.txt"
  rm -f "$manifest"
  PROJECT="$name" \
  SOURCE_ROOT="$dir" \
  OUTPUT_BASE="$OUTPUT_BASE" \
  MAX_DEPTH="$MAX_DEPTH" \
  LANGUAGE="$lang" \
  SKILL="$SKILL" \
    "$JOERN" -J-Xmx"$HEAP" "${jvm_j_opts[@]}" --script "$tmp_script" >> "$log" 2>&1 || true

  if [[ -f "$manifest" ]]; then
    rm -rf "$(dirname "$tmp_script")"
    local n_ok n_un
    # grep -c prints the count (0 when none) but exits 1 on zero matches; `|| true`
    # keeps the count and swallows the exit so it isn't doubled or tripped by set -e.
    n_ok=$(grep -c "^OK " "$manifest" 2>/dev/null || true)
    n_un=$(grep -c "^UNRESOLVED " "$manifest" 2>/dev/null || true)
    echo "[+] Done:   $name ($n_ok slices, $n_un unresolved)"
    echo "    Analyze with:  /$SKILL $OUTPUT_BASE/$name/ $dir"
  else
    echo "[!] Failed: $name — no manifest written (see $log)"
    echo "    Concatenated script kept for debugging: $tmp_script"
  fi
}
export -f detect_language detect_java_kind lang_config lint_fragment build_script process_app
export SCRIPT_DIR SLICERS_DIR OUTPUT_BASE LOG_DIR CPG_DIR MAX_DEPTH JOERN \
       HEAP BUILD_HEAP DOWNLOAD_DEPS LANGUAGE_OVERRIDE JOERN_BIN_DIR EXCLUDE_EXTRA JVM_OPTS

# ---------------------------------------------------------------------------
# Single-app mode (SOURCE_ROOT set) vs batch mode (iterate APPS_DIR).
# ---------------------------------------------------------------------------
if [[ -n "${SOURCE_ROOT:-}" ]]; then
  name="${PROJECT:-$(basename "$SOURCE_ROOT")}"
  echo "[*] Single-app mode: $name <- $SOURCE_ROOT"
  process_app "$name" "$SOURCE_ROOT"
  exit 0
fi

# Batch mode.
pending=()
for d in "$APPS_DIR"/*/; do
  [[ -d "$d" ]] || continue
  n="$(basename "$d")"
  if [[ -f "$OUTPUT_BASE/$n/manifest.txt" ]]; then
    echo "[~] Skip (done):   $n"
  elif [[ -f "$OUTPUT_BASE/$n/failed.txt" ]]; then
    echo "[~] Skip (failed): $n"
  else
    pending+=("$n")
  fi
done

total="${#pending[@]}"
echo ""
echo "[*] ${total} app(s) to process (parallel jobs: $JOBS)"
echo "[*] Apps    <- $APPS_DIR/"
echo "[*] Slices  -> $OUTPUT_BASE/"
echo "[*] Logs    -> $LOG_DIR/"
echo ""

if [[ $total -eq 0 ]]; then
  echo "[*] Nothing to do."
  exit 0
fi

if [[ $JOBS -gt 1 ]]; then
  if ! command -v parallel &>/dev/null; then
    echo "[!] GNU parallel not found. Install it or run with JOBS=1."
    exit 1
  fi
  printf '%s\n' "${pending[@]}" | parallel -j "$JOBS" --bar 'process_app {} "'"$APPS_DIR"'/{}"'
else
  done_count=0
  for name in "${pending[@]}"; do
    done_count=$((done_count + 1))
    echo "[*] [$done_count/$total] $name"
    process_app "$name" "$APPS_DIR/$name"
  done
fi

echo ""
echo "=== Done. Summary ==="
ok=$(grep -rl "^OK " "$OUTPUT_BASE"/*/manifest.txt 2>/dev/null | wc -l | tr -d ' ')
unresolved=$(grep -rl "^UNRESOLVED " "$OUTPUT_BASE"/*/manifest.txt 2>/dev/null | wc -l | tr -d ' ')
echo "  Apps with slices:        $ok"
echo "  Apps with unresolved:    $unresolved"
echo "  Logs:                    $LOG_DIR/"
