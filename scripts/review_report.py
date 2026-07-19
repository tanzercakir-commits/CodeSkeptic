#!/usr/bin/env python3
"""CodeSkeptic diff-review assembler (the c1 "semantic PR review" core).

Two subcommands, both invoked by scripts/review_diff.sh:

  remap-db   Rewrite a compile_commands.json so the HEAD tree's compile
             commands apply to the BASE worktree: every occurrence of the
             head root path (as a path prefix) in directory/file/command
             is rewritten to the base worktree root. This deliberately
             assumes the head revision's compile flags apply to the base
             revision — true for typical PR deltas, and the same
             pragmatic assumption CodeChecker-style local diffs make.

  assemble   Compute the finding DELTA between the base and head runs,
             fold in the contract diff (SUMMARY_DIFF lines) and the
             coverage honesty data, render a markdown review, and exit
             with the gate verdict.

Delta semantics — a faithful port of Baseline v2 (src/analyzer/
Baseline.cpp), because that file's keying is the project's one tested
definition of "the same finding":

  key = rule_id | repo-relative path | fnv1a64(trimmed line content) | message

The one deliberate difference: the file component is the REPO-RELATIVE
path (the C++ key uses the canonical absolute path, which can never
match across two checkouts of the same project). Renamed files map their
base path to the head path before keying, so a pure rename introduces no
"new" findings. Identical keys carry multiset COUNTS, and the filter
consumes budget exactly like Baseline::filter does. The end-to-end
fixture test (scripts/test_review_diff.sh) pins this parity — a finding
that merely SHIFTS lines must not resurface, and one whose line CHANGES
must (that is a feature: a changed line deserves re-review).

Soundness posture (matches the analyzer's discipline): definite findings
(error) gate; "may"-findings (warning) are reported but do not gate
unless --strict; everything not analyzed is LISTED, never silently
dropped.
"""

import argparse
import fnmatch
import json
import os
import re
import sys
from collections import Counter

# ---------------------------------------------------------------------------
# Baseline-v2 key parity (see src/analyzer/Baseline.cpp)
# ---------------------------------------------------------------------------

TRIM_BYTES = b" \t\r\n"


def fnv1a64_hex(data: bytes) -> str:
    """FNV-1a 64 over raw bytes — the same constants and byte-wise walk
    as Baseline.cpp's fnv1a64Hex (stable across platforms)."""
    h = 0xCBF29CE484222325  # 1469598103934665603
    for b in data:
        h ^= b
        h = (h * 0x100000001B3) & 0xFFFFFFFFFFFFFFFF  # 1099511628211
    return "%016x" % h


class LineCache:
    """Per-file line table, split on '\\n' only (std::getline parity;
    '\\r' survives into the line and is removed by trimming)."""

    def __init__(self):
        self._files = {}

    def line(self, path: str, lineno: int) -> bytes:
        lines = self._files.get(path)
        if lines is None:
            try:
                with open(path, "rb") as f:
                    lines = f.read().split(b"\n")
            except OSError:
                lines = []
            self._files[path] = lines
        if lineno < 1 or lineno > len(lines):
            return b""
        return lines[lineno - 1]


def finding_key(diag: dict, relpath: str, cache: LineCache) -> str:
    content = cache.line(diag["file"], diag["line"]).strip(TRIM_BYTES)
    return "%s|%s|%s|%s" % (
        diag["rule_id"], relpath, fnv1a64_hex(content), diag["message"])


# ---------------------------------------------------------------------------
# Inputs
# ---------------------------------------------------------------------------

def load_diags(path):
    """The analyzer's --json output; a missing/empty path is an empty run
    (e.g. a PR that only adds files has no base side)."""
    if not path or not os.path.exists(path):
        return []
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f).get("diagnostics", [])


def rel_to_root(abs_path: str, root: str) -> str:
    """Strip `root` as a path prefix; realpath both sides first (the
    analyzer canonicalizes diagnostic paths, and mktemp roots may be
    symlinked). A path outside the root stays absolute — visible, not
    wrong."""
    p = os.path.realpath(abs_path)
    r = os.path.realpath(root).rstrip(os.sep)
    if p == r:
        return ""
    if p.startswith(r + os.sep):
        return p[len(r) + 1:]
    return p


def load_renames(path):
    """old<TAB>new relative paths (git --find-renames R entries)."""
    renames = {}
    if path and os.path.exists(path):
        with open(path, "r", encoding="utf-8") as f:
            for line in f:
                parts = line.rstrip("\n").split("\t")
                if len(parts) == 2 and parts[0] and parts[1]:
                    renames[parts[0]] = parts[1]
    return renames


def parse_added_lines(diff_path):
    """Head-side added-line numbers per repo-relative path, from a
    unified diff (-U0 or otherwise; only +start,count of @@ headers is
    read). Used solely to MARK findings/trace steps that sit on changed
    lines — never to filter."""
    added = {}
    if not diff_path or not os.path.exists(diff_path):
        return added
    current = None
    hunk = re.compile(r"^@@ -\d+(?:,\d+)? \+(\d+)(?:,(\d+))? @@")
    with open(diff_path, "r", encoding="utf-8", errors="replace") as f:
        for line in f:
            if line.startswith("+++ "):
                target = line[4:].rstrip("\n").split("\t")[0]
                if target == "/dev/null":
                    current = None
                else:
                    current = target[2:] if target.startswith("b/") else target
            elif current is not None:
                m = hunk.match(line)
                if m:
                    start = int(m.group(1))
                    count = 1 if m.group(2) is None else int(m.group(2))
                    if count > 0:
                        added.setdefault(current, set()).update(
                            range(start, start + count))
    return added


def parse_summary_diff(path):
    """SUMMARY_DIFF <KIND> <key> <detail...> lines from the captured
    --summary-diff output. Returns (list of (kind, rest), available)."""
    if not path or not os.path.exists(path):
        return [], False
    changes = []
    with open(path, "r", encoding="utf-8", errors="replace") as f:
        for line in f:
            if line.startswith("SUMMARY_DIFF "):
                parts = line.rstrip("\n").split(" ", 2)
                if len(parts) >= 2:
                    changes.append((parts[1], parts[2] if len(parts) > 2 else ""))
    return changes, True


def parse_head_stderr(path):
    """Coverage honesty from the head run's stderr: processed-file count
    and the iteration-cap function list (CoverageIncomplete block)."""
    processed = 0
    capped = []
    if path and os.path.exists(path):
        in_coverage = False
        with open(path, "r", encoding="utf-8", errors="replace") as f:
            for line in f:
                if "Processing file" in line:
                    processed += 1
                    in_coverage = False
                elif "analysis coverage:" in line:
                    in_coverage = True
                elif in_coverage and line.startswith("  - "):
                    capped.append(line[4:].rstrip("\n"))
                else:
                    in_coverage = False
    return processed, capped


def parse_name_status(path):
    """git diff --name-status entries: (status, old_path, new_path)."""
    entries = []
    if path and os.path.exists(path):
        with open(path, "r", encoding="utf-8", errors="replace") as f:
            for line in f:
                parts = line.rstrip("\n").split("\t")
                if not parts or not parts[0]:
                    continue
                st = parts[0]
                if st[0] in ("R", "C") and len(parts) >= 3:
                    entries.append((st, parts[1], parts[2]))
                elif len(parts) >= 2:
                    entries.append((st, parts[1], parts[1]))
    return entries


SRC_EXT = (".c", ".cpp", ".cc", ".cxx")
HDR_EXT = (".h", ".hpp", ".hh", ".hxx", ".inl")


# ---------------------------------------------------------------------------
# Delta — Baseline::filter's consume-budget algorithm over two runs
# ---------------------------------------------------------------------------

def compute_delta(base_diags, head_diags, base_root, head_root, renames):
    cache = LineCache()

    base_keys = Counter()
    for d in base_diags:
        rel = rel_to_root(d["file"], base_root)
        rel = renames.get(rel, rel)  # align a renamed file with its head path
        base_keys[finding_key(d, rel, cache)] += 1

    budget = Counter(base_keys)
    new = []
    for d in head_diags:
        rel = rel_to_root(d["file"], head_root)
        k = finding_key(d, rel, cache)
        if budget[k] > 0:
            budget[k] -= 1
        else:
            new.append((d, rel))
    fixed = sum(budget.values())  # base findings nothing at head consumed
    return new, fixed


# ---------------------------------------------------------------------------
# Markdown
# ---------------------------------------------------------------------------

def render_finding(diag, rel, head_root, added_lines):
    mark = " *(on changed line)*" if diag["line"] in added_lines.get(rel, ()) else ""
    lines = ["- **[%s] %s** `%s:%d` in `%s` — %s%s" % (
        diag["severity"], diag["rule_id"], rel, diag["line"],
        diag.get("function", "?"), diag["message"], mark)]
    for note in diag.get("notes", []):
        nrel = rel_to_root(note["file"], head_root)
        nmark = " *(changed)*" if note["line"] in added_lines.get(nrel, ()) else ""
        lines.append("  - `%s:%d` %s%s" % (nrel, note["line"], note["message"], nmark))
    return lines


def cmd_assemble(args):
    base_diags = load_diags(args.base_json)
    head_diags = load_diags(args.head_json)
    renames = load_renames(args.renames)
    added_lines = parse_added_lines(args.diff)
    sum_changes, sum_available = parse_summary_diff(args.summary_diff)
    processed, capped = parse_head_stderr(args.head_stderr)
    name_status = parse_name_status(args.name_status)

    analyzed_rel = set()
    if args.head_files and os.path.exists(args.head_files):
        with open(args.head_files, "r", encoding="utf-8") as f:
            for line in f:
                p = line.strip()
                if p:
                    analyzed_rel.add(rel_to_root(p, args.head_root))

    new, fixed = compute_delta(base_diags, head_diags, args.base_root,
                               args.head_root, renames)
    new_errors = [(d, r) for d, r in new if d["severity"] == "error"]
    new_warnings = [(d, r) for d, r in new if d["severity"] != "error"]

    # Human label counts by ACTUAL severity (an assumption finding is
    # info, not warning); the REVIEW_RESULT machine line keeps its
    # stable two-bucket schema (new_warnings = everything non-error,
    # the "does not gate unless --strict" set).
    sev_counts = Counter(d["severity"] for d, _ in new)
    sev_label = ", ".join(
        "%d %s" % (sev_counts[s], s)
        for s in ("error", "warning", "info") if s in sev_counts) or "none"
    for s in sev_counts:
        if s not in ("error", "warning", "info"):
            sev_label += ", %d %s" % (sev_counts[s], s)

    weakened = [rest for kind, rest in sum_changes if kind == "WEAKENED"]
    other_changes = [(k, rest) for k, rest in sum_changes if k != "WEAKENED"]

    gate_fail = bool(new_errors) or bool(weakened) or \
        (args.strict and bool(new_warnings))

    # --- render -----------------------------------------------------------
    md = []
    md.append("# CodeSkeptic diff review")
    md.append("")
    md.append("Base `%s` -> head `%s`." % (args.base_label, args.head_label))
    if gate_fail:
        reasons = []
        if new_errors:
            reasons.append("%d new error(s)" % len(new_errors))
        if args.strict and new_warnings:
            reasons.append("%d new warning(s) (--strict)" % len(new_warnings))
        if weakened:
            reasons.append("%d weakened contract(s)" % len(weakened))
        md.append("**Verdict: FAIL** — " + ", ".join(reasons))
    else:
        md.append("**Verdict: PASS** — no new definite findings, "
                  "no weakened contracts")

    md.append("")
    md.append("## New findings (%s)" % sev_label)
    if new:
        for d, rel in new_errors + new_warnings:
            md.extend(render_finding(d, rel, args.head_root, added_lines))
    else:
        md.append("None — the change introduces no findings in the "
                  "analyzed files.")

    md.append("")
    md.append("## Fixed findings")
    md.append("%d finding(s) present at base are gone at head." % fixed
              if fixed else "None.")

    md.append("")
    md.append("## Contract changes")
    if not sum_available:
        md.append("Contract diff skipped (no base-side functions to "
                  "compare — e.g. an added-files-only change).")
    elif not sum_changes:
        md.append("None — inferred function contracts are unchanged.")
    else:
        # WEAKENED is the gate signal: always in full. The rest is
        # informational and easily macro-flooded (each gtest TEST()
        # expands to several generated symbols) — cap it, but SAY how
        # much was capped: hidden-but-counted, never silently dropped.
        for rest in weakened:
            md.append("- **WEAKENED** %s" % rest)
        cap = 8
        for kind, rest in other_changes[:cap]:
            md.append("- %s %s" % (kind, rest))
        if len(other_changes) > cap:
            md.append("- … and %d more non-gating contract change(s)" %
                      (len(other_changes) - cap))

    md.append("")
    md.append("## Coverage")
    src_changed = [e for e in name_status
                   if e[2].endswith(SRC_EXT) or e[1].endswith(SRC_EXT)]
    md.append("- Changed files: %d total, %d C/C++ source; analyzed %d "
              "(head side, whole file — not just hunks)." %
              (len(name_status), len(src_changed), len(analyzed_rel)))
    excludes = args.exclude or []

    def excluded(rel):
        return any(fnmatch.fnmatch(rel, pat) for pat in excludes)

    not_analyzed = []
    for st, old, new_p in name_status:
        if st.startswith("D"):
            not_analyzed.append("`%s` (deleted — base-only findings in it "
                                "are not counted as fixed)" % old)
        elif new_p.endswith(HDR_EXT):
            not_analyzed.append("`%s` (header — its own TU impact is only "
                                "seen through changed .c/.cpp files that "
                                "include it)" % new_p)
        elif not new_p.endswith(SRC_EXT):
            not_analyzed.append("`%s` (not a C/C++ source)" % new_p)
        elif excluded(new_p):
            not_analyzed.append("`%s` (excluded by --exclude)" % new_p)
        elif new_p not in analyzed_rel and not st.startswith("D"):
            not_analyzed.append("`%s` (not analyzed)" % new_p)
    if not_analyzed:
        md.append("- Not analyzed (\"no warning\" here means NOT CHECKED, "
                  "not \"correct\"):")
        for item in not_analyzed:
            md.append("  - %s" % item)
    if capped:
        md.append("- Functions that hit the iteration cap at head "
                  "(findings may be incomplete): %s" %
                  ", ".join("`%s`" % f for f in capped))
    else:
        md.append("- All analyzed head functions reached a dataflow "
                  "fixpoint.")
    if new_warnings and not args.strict:
        md.append("- New warnings are reported but do not gate; pass "
                  "--strict to gate them.")

    result_line = ("REVIEW_RESULT new_errors=%d new_warnings=%d fixed=%d "
                   "weakened=%d gate=%s" %
                   (len(new_errors), len(new_warnings), fixed,
                    len(weakened), "fail" if gate_fail else "pass"))
    md.append("")
    md.append("---")
    md.append("`%s`" % result_line)
    text = "\n".join(md) + "\n"

    if args.out:
        with open(args.out, "w", encoding="utf-8") as f:
            f.write(text)
        print(result_line)
    else:
        sys.stdout.write(text)

    if gate_fail and args.gate == "error":
        return 1
    return 0


# ---------------------------------------------------------------------------
# remap-db
# ---------------------------------------------------------------------------

def cmd_remap_db(args):
    src_root = os.path.realpath(args.from_root).rstrip(os.sep)
    dst_root = os.path.realpath(args.to_root).rstrip(os.sep)
    if not src_root or src_root == os.sep:
        print("[review] refusing to remap from root '%s'" % src_root,
              file=sys.stderr)
        return 2
    # Prefix-safe: /a/b must not rewrite inside /a/bc — require a
    # separator, whitespace, quote, or end after the match.
    pat = re.compile(re.escape(src_root) + r'(?=[/\s"\']|$)')

    # The BUILD directory is typically inside the repo root but is NOT in
    # git — a worktree has no build/. Paths under it (generated headers,
    # -Ibuild/_deps/...) must keep pointing at the HEAD build: protect
    # them with a sentinel through the root rewrite. Head build outputs
    # applied to base sources is the same pragmatic assumption as
    # reusing head compile flags at all.
    protect = None
    if args.protect:
        protect = os.path.realpath(args.protect).rstrip(os.sep)
        if not protect.startswith(src_root + os.sep):
            protect = None  # outside the root: the rewrite can't touch it
    sentinel = "\x00CS_PROTECTED\x00"
    prot_pat = re.compile(re.escape(protect) + r'(?=[/\s"\']|$)') \
        if protect else None

    def rw(s):
        if prot_pat is not None:
            s = prot_pat.sub(lambda _m: sentinel, s)
        s = pat.sub(lambda _m: dst_root, s)
        if prot_pat is not None:
            s = s.replace(sentinel, protect)
        return s

    with open(args.src, "r", encoding="utf-8") as f:
        entries = json.load(f)
    for e in entries:
        for field in ("directory", "file", "command", "output"):
            if field in e and isinstance(e[field], str):
                e[field] = rw(e[field])
        if isinstance(e.get("arguments"), list):
            e["arguments"] = [rw(a) if isinstance(a, str) else a
                              for a in e["arguments"]]
    os.makedirs(os.path.dirname(args.out) or ".", exist_ok=True)
    with open(args.out, "w", encoding="utf-8") as f:
        json.dump(entries, f, indent=1)
    return 0


# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="cmd", required=True)

    p_remap = sub.add_parser("remap-db")
    p_remap.add_argument("--src", required=True)
    p_remap.add_argument("--from-root", required=True)
    p_remap.add_argument("--to-root", required=True)
    p_remap.add_argument("--protect", help="path prefix to keep un-remapped "
                         "(the head build dir — absent from a worktree)")
    p_remap.add_argument("--out", required=True)

    p_asm = sub.add_parser("assemble")
    p_asm.add_argument("--base-json")
    p_asm.add_argument("--head-json")
    p_asm.add_argument("--base-root", required=True)
    p_asm.add_argument("--head-root", required=True)
    p_asm.add_argument("--renames")
    p_asm.add_argument("--diff")
    p_asm.add_argument("--name-status")
    p_asm.add_argument("--head-files")
    p_asm.add_argument("--head-stderr")
    p_asm.add_argument("--summary-diff")
    p_asm.add_argument("--gate", choices=["error", "warn"], default="error")
    p_asm.add_argument("--strict", action="store_true")
    p_asm.add_argument("--exclude", action="append",
                       help="glob over repo-relative paths whose changed "
                            "files were skipped (labeling only; the "
                            "actual skip happens in review_diff.sh)")
    p_asm.add_argument("--base-label", default="base")
    p_asm.add_argument("--head-label", default="head")
    p_asm.add_argument("--out")

    args = parser.parse_args()
    if args.cmd == "remap-db":
        return cmd_remap_db(args)
    return cmd_assemble(args)


if __name__ == "__main__":
    sys.exit(main())
