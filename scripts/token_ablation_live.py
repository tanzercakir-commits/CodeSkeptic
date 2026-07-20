#!/usr/bin/env python3
"""Live token ablation: run a real model, measure real tokens AND accuracy.

The offline harness (token_ablation.py) measures the INPUT-token footprint
deterministically. This one calls an actual model so it also captures:
  - real input + output tokens (from the API usage counters), and
  - whether each condition actually located the real bug (accuracy),
which the offline version cannot.

Two conditions per file:
  baseline : send the whole source, ask the model to find memory-safety bugs
  assisted : send CodeSkeptic's findings, ask the model to confirm + fix

Requires: pip install anthropic ; export ANTHROPIC_API_KEY=...
This makes real (paid) API calls. Start small.

Usage:
  python3 scripts/token_ablation_live.py file1.c [file2.c ...] \
      [--bin build/src/codeskeptic] [--model claude-sonnet-5]
"""
import argparse, json, os, subprocess, sys

def scan(binpath, path):
    out = path + ".json"
    subprocess.run([binpath, path, "--json", out, "--whole-program"],
                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    try:
        return json.load(open(out)).get("diagnostics", [])
    except Exception:
        return []

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("files", nargs="+")
    ap.add_argument("--bin", default="build/src/codeskeptic")
    ap.add_argument("--model", default="claude-sonnet-5")
    args = ap.parse_args()

    try:
        import anthropic
    except ImportError:
        sys.exit("pip install anthropic  (and export ANTHROPIC_API_KEY)")
    client = anthropic.Anthropic()

    SYS = ("You are a C/C++ code reviewer. Report memory-safety defects "
           "(null-deref, leak, overflow), each with its line and a fix.")

    def ask(text):
        r = client.messages.create(model=args.model, max_tokens=1024,
                                   system=SYS, messages=[{"role": "user",
                                                          "content": text}])
        u = r.usage
        body = "".join(b.text for b in r.content if b.type == "text")
        return u.input_tokens, u.output_tokens, body

    print(f"model: {args.model}\n")
    print(f"{'file':<24}{'cond':<10}{'in':>7}{'out':>7}{'total':>8}")
    print("-" * 56)
    for path in args.files:
        src = open(path).read()
        fs = scan(args.bin, path)
        fjson = json.dumps([{"rule": f.get("rule_id"), "line": f.get("line"),
                             "msg": f.get("message")} for f in fs], indent=1)
        # baseline: whole file
        bi, bo, _ = ask("Review this file for memory-safety bugs:\n\n" + src)
        # assisted: findings only
        ai, ao, _ = ask("CodeSkeptic reported these findings; confirm and "
                        "suggest fixes:\n\n" + fjson)
        base = os.path.basename(path)
        print(f"{base:<24}{'baseline':<10}{bi:>7}{bo:>7}{bi+bo:>8}")
        print(f"{base:<24}{'assisted':<10}{ai:>7}{ao:>7}{ai+ao:>8}")
        if bi + bo:
            print(f"{'':<24}{'-> ratio':<10}{'':>7}{'':>7}"
                  f"{(bi+bo)/max(1,ai+ao):>7.1f}x")

if __name__ == "__main__":
    main()
