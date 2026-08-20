#!/usr/bin/env python3
"""
analyze_run_cost.py — compute the exact $ cost of Claude Code analyst runs from a
session transcript, by summing per-message token usage and applying model pricing.

Why this exists: /cost and /usage are live UI counters — they reset (e.g. show $0
after a limit reset), so they're useless as a durable ledger. The session
transcript JSONL persists on disk permanently and records exact token usage per
assistant message. This reconstructs cost from that ground truth, so it works
retroactively and survives resets.

A single session often contains SEVERAL analyst runs (e.g. you invoked
/php-security-analyst on app A, then app B, in one conversation). Summing the
whole file would give one combined blob — the same figure no matter which app
you meant. So this segments the transcript at each `/<lang>-security-analyst`
invocation and reports cost PER RUN, pulling each run's slices dir from its
command args to also give $/entry-point.

It accounts for the four token tiers at their real rates, splitting cache writes
into 5-minute (1.25x) vs 1-hour (2x) buckets — Claude Code uses 1h caching.

Usage:
  ./analyze_run_cost.py <session.jsonl>     # per-run breakdown for one transcript
  ./analyze_run_cost.py --latest            # newest transcript that CONTAINS a run
  ./analyze_run_cost.py <session.jsonl> --json
  ./analyze_run_cost.py --list              # list this project's transcripts + run counts

Note on --latest: it skips transcripts with no analyst invocation (so it won't
pick the interactive session you're typing in). It still can't isolate a run
that shares a session with others perfectly across cache boundaries — for clean,
unambiguous per-run cost, run each skill headless (one run = one session) via
run_analyst_cost.sh and read total_cost_usd.

Transcripts for this project live in:
  ~/.claude/projects/-<cwd-with-slashes-replaced-by-dashes>/*.jsonl
"""
import argparse, glob, json, os, re, sys

# Per-million-token rates. cache_write_5m = 1.25x input, cache_write_1h = 2x input,
# cache_read = 0.1x input. Source: claude-api skill (pricing) + prompt-caching economics.
PRICING = {  # model_id: (input, output, cache_w_5m, cache_w_1h, cache_read)
    "claude-opus-4-8":   (5.0, 25.0, 6.25, 10.0, 0.50),
    "claude-opus-4-7":   (5.0, 25.0, 6.25, 10.0, 0.50),
    "claude-opus-4-6":   (5.0, 25.0, 6.25, 10.0, 0.50),
    "claude-sonnet-4-6": (3.0, 15.0, 3.75,  6.0, 0.30),
    "claude-haiku-4-5":  (1.0,  5.0, 1.25,  2.0, 0.10),
    "claude-fable-5":    (10.0, 50.0, 12.5, 20.0, 1.00),
}
PROJECT_DIR = os.path.join(
    os.path.expanduser("~/.claude/projects"),
    "-" + os.getcwd().replace("/", "-").lstrip("-"),
)
CMD_RE = re.compile(r"<command-name>/((?:php|javascript|java|ruby|wp)-security-analyst)</command-name>")
ARGS_RE = re.compile(r"<command-args>(.*?)</command-args>", re.S)


def new_acc():
    return dict(input=0, output=0, cache_read=0, cw5m=0, cw1h=0, msgs=0, model=None)


def add_usage(acc, msg):
    usage = msg["usage"]
    cc = usage.get("cache_creation") or {}
    acc["input"]      += usage.get("input_tokens", 0)
    acc["output"]     += usage.get("output_tokens", 0)
    acc["cache_read"] += usage.get("cache_read_input_tokens", 0)
    if cc:
        acc["cw5m"] += cc.get("ephemeral_5m_input_tokens", 0)
        acc["cw1h"] += cc.get("ephemeral_1h_input_tokens", 0)
    else:
        acc["cw5m"] += usage.get("cache_creation_input_tokens", 0)
    acc["msgs"] += 1
    # Ignore Claude Code's injected "<synthetic>" messages (interrupts, errors) —
    # they carry a fake model name that would otherwise clobber the real one and
    # void the run's price.
    m = msg.get("model")
    if m and m != "<synthetic>":
        acc["model"] = m


def cost_for(acc):
    m = acc["model"]
    if m not in PRICING:
        return None
    i, o, w5, w1, r = PRICING[m]
    return (acc["input"] * i + acc["output"] * o + acc["cw5m"] * w5
            + acc["cw1h"] * w1 + acc["cache_read"] * r) / 1_000_000


def text_of(content):
    """Flatten a message's content (string or list of blocks) to one string."""
    if isinstance(content, str):
        return content
    if isinstance(content, list):
        return "\n".join(
            b.get("text", "") for b in content if isinstance(b, dict))
    return ""


def ok_count(slices_dir):
    """Count OK lines in a slices dir's manifest; None if not resolvable."""
    if not slices_dir:
        return None
    cand = slices_dir.lstrip("./").rstrip("/")
    for base in (os.path.join(os.getcwd(), cand), cand):
        manifest = os.path.join(base, "manifest.txt")
        if os.path.isfile(manifest):
            with open(manifest) as f:
                return sum(1 for line in f if line.startswith("OK "))
    return None


def segment(path):
    """Return ordered list of run segments. Each run starts at an analyst
    command-name marker; assistant usage before the first run goes to a
    '(pre-run / other)' bucket. Dedup assistant messages by id across the file."""
    runs, seen = [], set()
    pre = {"label": "(pre-run / other)", "skill": None, "slices": None, "acc": new_acc()}
    current = pre
    with open(path) as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                obj = json.loads(line)
            except json.JSONDecodeError:
                continue
            t = obj.get("type")
            msg = obj.get("message", {}) or {}
            if t == "user":
                blob = text_of(msg.get("content"))
                m = CMD_RE.search(blob)
                if m:
                    args_m = ARGS_RE.search(blob)
                    args = args_m.group(1).strip() if args_m else ""
                    slices = args.split()[0] if args.split() else None
                    current = {"label": f"/{m.group(1)} {args}".strip(),
                               "skill": m.group(1), "slices": slices, "acc": new_acc()}
                    runs.append(current)
            elif t == "assistant" and msg.get("usage"):
                mid = msg.get("id") or obj.get("requestId")
                if mid in seen:
                    continue
                seen.add(mid)
                add_usage(current["acc"], msg)
    if pre["acc"]["msgs"]:
        runs.insert(0, pre)
    return runs


def pick_latest(require_run=True):
    files = sorted(glob.glob(os.path.join(PROJECT_DIR, "*.jsonl")),
                   key=os.path.getmtime, reverse=True)
    if not files:
        sys.exit(f"[!] no transcripts in {PROJECT_DIR}")
    if require_run:
        for f in files:
            with open(f) as fh:
                if CMD_RE.search(fh.read()):
                    return f
        print("[!] no transcript contains an analyst invocation; "
              "using newest (likely the live session)", file=sys.stderr)
    return files[0]


def list_transcripts():
    files = sorted(glob.glob(os.path.join(PROJECT_DIR, "*.jsonl")),
                   key=os.path.getmtime, reverse=True)
    for f in files:
        runs = [r for r in segment(f) if r["skill"]]
        labels = "; ".join(r["label"] for r in runs) or "(no analyst runs)"
        print(f"{os.path.basename(f)[:8]}  {len(runs)} run(s)  {labels[:100]}")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("transcript", nargs="?")
    ap.add_argument("--latest", action="store_true")
    ap.add_argument("--list", action="store_true")
    ap.add_argument("--slices", help="override entry-point source for ALL runs")
    ap.add_argument("--json", action="store_true", dest="as_json")
    args = ap.parse_args()

    if args.list:
        list_transcripts()
        return

    path = pick_latest() if args.latest else args.transcript
    if not path:
        ap.error("give a transcript path, --latest, or --list")
    if not os.path.isfile(path):
        sys.exit(f"[!] no such transcript: {path}")

    runs = segment(path)
    out = []
    file_total = 0.0
    for r in runs:
        c = cost_for(r["acc"])
        file_total += c or 0.0
        n = ok_count(args.slices or r["slices"])
        out.append((r, c, n))

    if args.as_json:
        print(json.dumps({
            "transcript": path,
            "file_total_cost_usd": round(file_total, 6),
            "runs": [{
                "label": r["label"], "skill": r["skill"], "slices": r["slices"],
                "cost_usd": round(c, 6) if c is not None else None,
                "entry_points": n,
                "per_entry_point_usd": round(c / n, 6) if (c and n) else None,
                **r["acc"],
            } for r, c, n in out],
        }, indent=2))
        return

    print(f"transcript : {path}\n")
    for r, c, n in out:
        a = r["acc"]
        cs = f"${c:.4f}" if c is not None else "UNPRICED"
        print(f"  {r['label']}")
        print(f"    model={a['model']}  msgs={a['msgs']}  "
              f"in={a['input']:,} out={a['output']:,} "
              f"cache_read={a['cache_read']:,} cw5m={a['cw5m']:,} cw1h={a['cw1h']:,}")
        line = f"    cost: {cs}"
        if c is not None and n:
            line += f"   entry_points={n}   per_entry=${c / n:.6f}"
        elif c is not None and r["skill"]:
            line += "   (slices dir not found — pass --slices for per-entry cost)"
        print(line + "\n")
    print("=" * 50)
    print(f"FILE TOTAL : ${file_total:.4f}  ({len([r for r,_,_ in out if r['skill']])} analyst run(s))")
    print("=" * 50)
    print("[!] ESTIMATE ONLY — validated ~8% LOW vs authoritative total_cost_usd.")
    print("    Transcripts undercount billed tokens (secondary-model/sidechain")
    print("    turns) and can't split 5m/1h cache. For real cost, run headless")
    print("    via run_analyst_cost.sh and read total_cost_usd.")


if __name__ == "__main__":
    main()
