#!/usr/bin/env bash
# run_analyst_cost.sh — run a *-security-analyst skill on one app in headless mode
# and report the exact billed cost of the run (total + per entry point).
#
# This is an alternative to invoking the skill interactively: it runs the same
# skill non-interactively, captures the analyst's report, and reads the exact
# cost Anthropic billed for the session (total_cost_usd, which already accounts
# for input/output/cache-write/cache-read token tiers).
#
# Usage:
#   ./run_analyst_cost.sh <slices-dir> [source-root]
#   ./run_analyst_cost.sh surface_slices/limesurvey/ /path/to/limesurvey
#
# Env:
#   SKILL    override the skill (default: read from manifest's "# Skill:" line)
#   OUTDIR   where to write the report + raw JSON (default: ./cost_runs)
#   MODEL    pass a specific model to `claude` (default: account default)
#   STREAM   1 = stream the run live (play-by-play) instead of waiting silently.
#            Same cost; just shows progress as it happens. Raw events are saved
#            to <base>.stream.jsonl; report + cost are extracted from the final
#            result event exactly as in non-stream mode.

set -euo pipefail

SLICES="${1:?usage: $0 <slices-dir> [source-root]}"
SOURCE_ROOT="${2:-}"
SLICES="${SLICES%/}"                       # strip trailing slash
MANIFEST="$SLICES/manifest.txt"
OUTDIR="${OUTDIR:-./cost_runs}"

[ -f "$MANIFEST" ] || { echo "[!] no manifest at $MANIFEST" >&2; exit 1; }
command -v jq  >/dev/null || { echo "[!] jq is required" >&2; exit 1; }
command -v claude >/dev/null || { echo "[!] claude CLI not found" >&2; exit 1; }

# --- derive skill, project name, and entry-point count from the manifest ---
SKILL="${SKILL:-$(grep -m1 '^# Skill:' "$MANIFEST" | sed 's/^# Skill:[[:space:]]*//')}"
PROJECT="$(grep -m1 '^# Project:' "$MANIFEST" | sed 's/^# Project:[[:space:]]*//')"
PROJECT="${PROJECT:-$(basename "$SLICES")}"
OK_COUNT="$(grep -c '^OK ' "$MANIFEST" || true)"
[ -n "$SKILL" ] || { echo "[!] could not determine skill (no '# Skill:' line); set SKILL=" >&2; exit 1; }

# --- build the slash-command invocation (slice-only, or slices + source root) ---
CMD="/$SKILL $SLICES/"
[ -n "$SOURCE_ROOT" ] && CMD="$CMD $SOURCE_ROOT"

mkdir -p "$OUTDIR"
STAMP="$(date +%Y%m%d_%H%M%S)"
BASE="$OUTDIR/${PROJECT}_${STAMP}"

echo "[*] project   : $PROJECT"
echo "[*] skill     : $SKILL"
echo "[*] entry pts : $OK_COUNT  (OK lines in manifest)"
echo "[*] mode      : $([ -n "$SOURCE_ROOT" ] && echo "slices + source root ($SOURCE_ROOT)" || echo "slice-only")"
echo "[*] command   : claude -p \"$CMD\""
[ "$OK_COUNT" -gt 150 ] && echo "[!] $OK_COUNT entry points — this is a large run and may take a while / cost more."
echo "[*] running headless… (report -> $BASE.report.md, raw -> $BASE.json)"

# Read-only skill: pre-allow its tools so the headless run never blocks on a prompt.
MODEL_ARG=(); [ -n "${MODEL:-}" ] && MODEL_ARG=(--model "$MODEL")
ALLOW=(--allowedTools "Read" "Grep" "Glob")

if [ "${STREAM:-0}" = "1" ]; then
  # Live mode: stream every event, tee the raw JSONL to disk for the live view,
  # then distil the final result event into $BASE.json so extraction below is
  # identical to non-stream mode. stream-json requires --verbose.
  echo "[*] streaming live (raw events -> $BASE.stream.jsonl)…"
  echo "----------------------------------------------------------------"
  claude -p "$CMD" \
    --output-format stream-json --verbose \
    "${ALLOW[@]}" "${MODEL_ARG[@]}" \
    | tee "$BASE.stream.jsonl" \
    | jq -rj --unbuffered '
        if .type=="assistant" then
          (.message.content[]? |
            if .type=="text" then .text + "\n"
            elif .type=="tool_use" then "  → \(.name) \((.input|tojson)[0:140])\n"
            else empty end)
        elif .type=="result" then "\n----------------------------------------------------------------\n"
        else empty end' 2>/dev/null || true
  # Last result event carries total_cost_usd / usage / result, same shape as json mode.
  grep '"type":"result"' "$BASE.stream.jsonl" | tail -1 > "$BASE.json"
  [ -s "$BASE.json" ] || { echo "[!] no result event in stream; see $BASE.stream.jsonl" >&2; exit 1; }
else
  claude -p "$CMD" \
    --output-format json \
    "${ALLOW[@]}" "${MODEL_ARG[@]}" \
    > "$BASE.json"
fi

# --- extract the analyst's report and the cost figures ---
jq -r '.result // ""' "$BASE.json" > "$BASE.report.md"

jq -r --arg ok "$OK_COUNT" '
  ($ok|tonumber) as $n
  | "\n========== COST ==========",
    "total_cost_usd : \(.total_cost_usd)",
    (if $n > 0 then "per_entry_point: \(.total_cost_usd / $n)" else "per_entry_point: n/a (0 entries)" end),
    "turns          : \(.num_turns)",
    "duration       : \((.duration_ms/1000)|floor)s",
    "is_error       : \(.is_error)",
    "tokens         : in=\(.usage.input_tokens) out=\(.usage.output_tokens) cache_write=\(.usage.cache_creation_input_tokens) cache_read=\(.usage.cache_read_input_tokens)",
    "==========================",
    "report -> '"$BASE"'.report.md"
' "$BASE.json"
