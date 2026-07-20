#!/usr/bin/env python3
"""Token-footprint ablation: LLM-only review vs CodeSkeptic-assisted review.

Measures how many INPUT tokens an LLM must process to reach actionable
memory-safety findings, on the SAME source, under two conditions:

  baseline : the whole source file is handed to the model ("find the bugs")
  assisted : CodeSkeptic's findings are handed to the model instead
             (detect = findings only; fix = findings + a small code window)

Deterministic and reproducible: no LLM is called here. This measures the
token FOOTPRINT of the context each approach needs. Accuracy (did the model
actually find the bug / did it hallucinate) needs a live model — see
token_ablation_live.py.

The scaling series holds the bug set constant while clean helper code grows,
so baseline tokens climb with LOC while CodeSkeptic's output stays flat:
its output is O(bugs), not O(lines).

Usage:
  python3 scripts/token_ablation.py [path/to/codeskeptic]
Real BPE counts (tiktoken) are used when available; otherwise a transparent
offline estimate is used. The reduction RATIO is tokenizer-insensitive.
"""
import json, os, re, subprocess, sys, tempfile

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
BIN = sys.argv[1] if len(sys.argv) > 1 else os.path.join(REPO, "build/src/codeskeptic")

try:
    import tiktoken
    _ENC = tiktoken.get_encoding("cl100k_base")
    def ntok(s): return len(_ENC.encode(s))
    TOKENIZER = "tiktoken/cl100k_base (real BPE)"
except Exception:
    _TOK = re.compile(r"\w+|[^\s\w]")
    def ntok(s):
        return round((len(_TOK.findall(s)) + len(s) / 4) / 2)
    TOKENIZER = "offline estimate (word+punct / chars-4 average)"

SYS = ("You are a C/C++ code reviewer. Report memory-safety defects "
       "(null-deref, leak, overflow) with the line and a fix.\n")

BUGGY = r'''
extern char *getenv(const char*);
extern void *malloc(unsigned long);
extern unsigned long strlen(const char*);
extern char *strcpy(char*, const char*);
extern int atoi(const char*);

char *load_setting(const char *name) {
    char *val = getenv(name);
    char *copy = (char*)malloc(strlen(val) + 1);
    strcpy(copy, val);
    return copy;
}
int buffer_size(const char *s) {
    int n = atoi(s);
    return n * 4096;
}
'''

def clean_helper(i):
    return (f"static int util_{i}(int a, int b) {{\n"
            f"    int r = a + b;\n"
            f"    if (r < 0) r = -r;\n"
            f"    return r * {i % 7 + 1};\n"
            f"}}\n")

def build(k):
    return BUGGY + "\n" + "\n".join(clean_helper(i) for i in range(k))

def scan(src, tmp):
    path = os.path.join(tmp, "in.c")
    open(path, "w").write(src)
    out = path + ".json"
    subprocess.run([BIN, path, "--json", out],
                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    try:
        return json.load(open(out)).get("diagnostics", [])
    except Exception:
        return []

def windows(src, findings, radius=3):
    lines = src.splitlines()
    out = []
    for f in findings:
        ln = int(f.get("line", 1)) - 1
        lo, hi = max(0, ln - radius), min(len(lines), ln + radius + 1)
        out.append("\n".join(lines[lo:hi]))
    return "\n---\n".join(out)

def measure(label, src, tmp):
    fs = scan(src, tmp)
    base = SYS + "Review this file for memory-safety bugs:\n\n" + src
    fjson = json.dumps([{"rule": f.get("rule_id"), "line": f.get("line"),
                         "msg": f.get("message"),
                         "trace": [t.get("message") for t in f.get("notes", [])]}
                        for f in fs], indent=1)
    detect = SYS + "CodeSkeptic reported these findings:\n\n" + fjson
    fix = detect + "\n\nRelevant lines:\n" + windows(src, fs)
    b, d, fx = ntok(base), ntok(detect), ntok(fix)
    loc = len(src.splitlines())
    return (label, loc, len(fs), b, d, fx,
            (b / d if d else 0), (b / fx if fx else 0))

def main():
    rows = []
    with tempfile.TemporaryDirectory() as tmp:
        for real in ["docs/demo.c", "docs/custom.c"]:
            p = os.path.join(REPO, real)
            if os.path.exists(p):
                rows.append(measure(os.path.basename(real), open(p).read(), tmp))
        for k in [0, 10, 40, 120, 400]:
            rows.append(measure(f"scaling k={k}", build(k), tmp))

    print(f"tokenizer: {TOKENIZER}   (bugs held constant, clean code grows)\n")
    print(f"{'input':<15}{'LOC':>6}{'bugs':>5}{'baseline':>10}"
          f"{'detect':>8}{'fix':>7}{'detect x':>10}{'fix x':>8}")
    print("-" * 69)
    for label, loc, nf, b, d, fx, rd, rf in rows:
        print(f"{label:<15}{loc:>6}{nf:>5}{b:>10}{d:>8}{fx:>7}{rd:>9.1f}x{rf:>7.1f}x")

if __name__ == "__main__":
    main()
