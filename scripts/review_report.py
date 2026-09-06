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

Delta semantics — Baseline v3's full identity (src/analyzer/Baseline.cpp):

  rule, path, function, AST signature, relative column, severity, source, message

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
import shlex
import sys
from collections import Counter

# ---------------------------------------------------------------------------
# Baseline-v3 identity parity (see src/analyzer/Baseline.cpp)
# ---------------------------------------------------------------------------

TRIM_BYTES = b" \t\r\n"


class LineCache:
    """Physical CR/LF/CRLF byte lines, matching compiler source coordinates."""

    def __init__(self):
        self._files = {}

    def line(self, path: str, lineno: int) -> bytes:
        lines = self._files.get(path)
        if lines is None:
            with open(path, "rb") as f:
                text = f.read()
            lines = re.split(b"\r\n|\r|\n", text)
            if not lines[-1]: lines.pop()
            self._files[path] = lines
        if lineno < 1 or lineno > len(lines):
            raise ValueError(f"finding line is outside its source: {path}:{lineno}")
        return lines[lineno - 1]


def finding_key(diag: dict, relpath: str, cache: LineCache):
    line = cache.line(diag["file"], diag["line"])
    leading = len(line) - len(line.lstrip(TRIM_BYTES))
    if not leading < diag["column"] <= len(line):
        raise ValueError("finding column is outside its source content")
    signature = diag["baseline_function"]
    if not signature or not diag["function"]:
        return None  # Explicitly unbound: never consume a baseline budget.
    if not signature.startswith("csb-fn1:") or len(signature) <= 8:
        raise ValueError("unsupported baseline function identity; refresh reports")
    return (diag["rule_id"], relpath, diag["function"], signature,
            diag["column"] - leading, diag["severity"], line.strip(TRIM_BYTES), diag["message"])


# ---------------------------------------------------------------------------
# Inputs
# ---------------------------------------------------------------------------

def load_diags(path, suppression_audit=None):
    """Omitted side is intentional; an explicit unreadable report is an error."""
    if not path:
        return []
    with open(path, "r", encoding="utf-8") as f:
        report = json.load(f)
    if (not isinstance(report, dict) or report.get("schema") != "codeskeptic-report/v1" or
            report.get("complete") is not True or type(report.get("exit_code")) is not int or
            report["exit_code"] not in (0, 1) or not isinstance(report.get("diagnostics"), list) or
            type(report.get("total")) is not int or report["total"] != len(report["diagnostics"])):
        raise ValueError("missing, malformed or incomplete report contract; regenerate both sides")
    baseline = report.get("baseline")
    if baseline is not None:
        if (not isinstance(baseline, dict) or type(baseline.get("matched_callbacks")) is not int or
                baseline["matched_callbacks"] != 0):
            raise ValueError("baseline-filtered evidence cannot establish a full diff; rerun without --baseline")
    audit = report.get("suppressions")
    if not isinstance(audit, list): raise ValueError("report requires a suppression audit array")
    for record in audit:
        if not isinstance(record, dict) or not isinstance(record.get("finding"), dict):
            raise ValueError("invalid suppression audit finding")
        for field in ("marker_line", "target_line", "occurrences"):
            if type(record.get(field)) is not int or record[field] <= 0:
                raise ValueError("invalid suppression audit coordinates/count")
        marker = record.get("marker")
        if marker not in ("codeskeptic-disable-line", "codeskeptic-disable-next-line"):
            raise ValueError("invalid suppression marker")
        if (record["target_line"] != record["marker_line"] + (marker == "codeskeptic-disable-next-line") or
                record["target_line"] != record["finding"].get("line") or
                record.get("file") != record["finding"].get("file")):
            raise ValueError("suppression audit scope disagrees with its finding")
        rules = record.get("rules")
        if (not isinstance(rules, list) or any(not isinstance(rule, str) or not rule for rule in rules) or
                type(record.get("all_rules")) is not bool or record["all_rules"] != (not rules) or
                (rules and record["finding"].get("rule_id") not in rules)):
            raise ValueError("invalid suppression rule scope")
        if record.get("reason_status") == "provided":
            if not isinstance(record.get("reason"), str) or not record["reason"].strip():
                raise ValueError("suppression reason is missing")
        elif record.get("reason_status") != "legacy-unspecified" or record.get("reason", "") is not None:
            raise ValueError("invalid legacy suppression reason state")
    for diag in report["diagnostics"] + [record["finding"] for record in audit]:
        if not isinstance(diag, dict): raise ValueError("finding must be an object")
        for field in ("rule_id", "file", "message", "function", "baseline_function"):
            if not isinstance(diag.get(field), str):
                raise ValueError(f"finding requires string {field}; refresh reports")
        signature = diag["baseline_function"]
        if signature and (not signature.startswith("csb-fn1:") or len(signature) <= 8):
            raise ValueError("unsupported baseline function identity; refresh reports")
        if (not diag["rule_id"] or not diag["file"] or diag.get("severity") not in ("info", "warning", "error") or
                type(diag.get("blocks_verdict")) is not bool):
            raise ValueError("invalid finding classification")
        for field in ("line", "column"):
            if type(diag.get(field)) is not int or not 0 < diag[field] <= 0xffffffff:
                raise ValueError(f"invalid finding {field}")
        if not isinstance(diag.get("notes"), list): raise ValueError("invalid finding notes")
        for note in diag["notes"]:
            if (not isinstance(note, dict) or not isinstance(note.get("file"), str) or
                    not isinstance(note.get("message"), str) or type(note.get("line")) is not int or
                    type(note.get("column")) is not int or note["line"] < 0 or note["column"] < 0):
                raise ValueError("invalid finding trace")
    if suppression_audit is not None: suppression_audit.extend(audit)
    return report["diagnostics"]


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
        # Git diffs and rename maps always use '/'. Native Windows relative
        # paths must use the same spelling or the honesty report says a TU was
        # both analyzed and not analyzed.
        return p[len(r) + 1:].replace(os.sep, "/")
    return p


def load_renames(path):
    """old<TAB>new relative paths (git --find-renames R entries)."""
    renames, old_names, new_names = {}, set(), set()
    if path:
        with open(path, "r", encoding="utf-8") as f:
            for line in f:
                parts = line.rstrip("\n").split("\t")
                if len(parts) != 2:
                    raise ValueError("rename map requires old<TAB>new paths")
                for name in parts:
                    if (not name or name.startswith(("/", "\\")) or "\\" in name or
                            re.match(r"^[A-Za-z]:", name) or any(ord(c) < 32 for c in name) or
                            any(part in ("", ".", "..") for part in name.split("/"))):
                        raise ValueError("rename paths must be contained repository-relative paths")
                old, new = parts
                if os.path.normcase(old) in old_names or os.path.normcase(new) in new_names:
                    raise ValueError("duplicate rename identity")
                old_names.add(os.path.normcase(old))
                new_names.add(os.path.normcase(new))
                renames[old] = new
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
    if not path:
        return [], False
    with open(path, "r", encoding="utf-8") as stream:
        lines = stream.read().splitlines()
    if not lines or not re.fullmatch(r"\[CodeSkeptic\] summary diff: .+ -> .+ \(\d+ functions\)", lines[0]):
        raise ValueError("missing or malformed contract-diff header")
    changes, index = [], 1
    kinds = ("WEAKENED", "STRENGTHENED", "CHANGED", "ADDED", "REMOVED")
    while index < len(lines) and lines[index].startswith("SUMMARY_DIFF "):
        fields = lines[index].split(" ", 2)
        if len(fields) != 3 or fields[1] not in kinds or not fields[2].strip():
            raise ValueError("invalid contract-diff change record")
        changes.append((fields[1], fields[2]))
        index += 1
    trailer = re.fullmatch(r"\[CodeSkeptic\] (\d+) weakened, (\d+) strengthened, (\d+) changed, (\d+) added, (\d+) removed",
                           lines[index] if index < len(lines) else "")
    if trailer is None: raise ValueError("missing or malformed contract-diff count trailer")
    counts = Counter(kind for kind, _ in changes)
    if tuple(map(int, trailer.groups())) != tuple(counts[kind] for kind in kinds):
        raise ValueError("contract-diff counts disagree with change records")
    expected_tail = (["[CodeSkeptic] weakened contracts: callers relying on them must be re-checked"]
                     if counts["WEAKENED"] else [])
    if lines[index + 1:] != expected_tail:
        raise ValueError("unexpected or truncated contract-diff ending")
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

def logical_findings(diagnostics):
    groups = {}
    for diagnostic in diagnostics:
        signature = diagnostic["baseline_function"]
        if signature and (not signature.startswith("csb-fn1:") or len(signature) <= 8):
            raise ValueError("unsupported baseline function identity; refresh reports")
        key = tuple(diagnostic[field] for field in ("severity", "file", "line", "column", "rule_id", "message"))
        if key not in groups:
            groups[key] = dict(diagnostic)
        else:
            if groups[key]["blocks_verdict"] != diagnostic["blocks_verdict"]:
                raise ValueError("equivalent finding rows disagree on verdict classification")
            if any(groups[key][field] != diagnostic[field] for field in ("function", "baseline_function")):
                groups[key]["baseline_function"] = ""
    return list(groups.values())


def compute_delta(base_diags, head_diags, base_root, head_root, renames, head_suppressed=()):
    base_diags, head_diags = logical_findings(base_diags), logical_findings(head_diags)
    cache = LineCache()

    base_keys = Counter()
    for d in base_diags:
        rel = rel_to_root(d["file"], base_root)
        rel = renames.get(rel, rel)  # align a renamed file with its head path
        key = finding_key(d, rel, cache)
        if key is not None: base_keys[key] += 1

    budget = Counter(base_keys)
    new = []
    for d in head_diags:
        rel = rel_to_root(d["file"], head_root)
        k = finding_key(d, rel, cache)
        if k is not None and budget[k] > 0:
            budget[k] -= 1
        else:
            new.append((d, rel))
    # A suppression can add text on the finding line itself. Do NOT weaken v3
    # matching to call it the same finding. Conservatively withhold fix claims
    # in that owner instead; new visible findings still use the full identity.
    suppressed_owners, unbound_suppressed_files = set(), set()
    for diagnostic in head_suppressed:
        rel = rel_to_root(diagnostic["file"], head_root)
        if diagnostic["function"] and diagnostic["baseline_function"]:
            suppressed_owners.add((diagnostic["rule_id"], rel, diagnostic["function"], diagnostic["baseline_function"]))
        else:
            unbound_suppressed_files.add((diagnostic["rule_id"], rel))
    fixed = sum(count for key, count in budget.items()
                if key[:4] not in suppressed_owners and key[:2] not in unbound_suppressed_files)
    return new, fixed


# ---------------------------------------------------------------------------
# Markdown
# ---------------------------------------------------------------------------

def render_finding(diag, rel, head_root, added_lines):
    mark = " *(on changed line)*" if diag["line"] in added_lines.get(rel, ()) else ""
    tier_mark = (
        " *(experimental, report-only)*"
        if not diag.get("blocks_verdict", True) else ""
    )
    lines = ["- **[%s] %s** `%s:%d` in `%s` — %s%s" % (
        diag["severity"], diag["rule_id"], rel, diag["line"],
        diag.get("function", "?"), diag["message"], mark + tier_mark)]
    for note in diag.get("notes", []):
        nrel = rel_to_root(note["file"], head_root)
        nmark = " *(changed)*" if note["line"] in added_lines.get(nrel, ()) else ""
        lines.append("  - `%s:%d` %s%s" % (nrel, note["line"], note["message"], nmark))
    return lines


def cmd_assemble(args):
    if args.base_json and args.head_json and not args.summary_diff:
        raise ValueError("two analyzed sides require a contract-diff artifact")
    # Explicitly named artifacts must exist. Absence is only valid when the
    # wrapper deliberately omitted that side/auxiliary result.
    for field in ("renames", "diff", "name_status", "head_files", "base_files", "head_stderr", "summary_diff"):
        path = getattr(args, field, None)
        if path:
            with open(path, "rb") as stream: stream.read(1)
    for side in ("base", "head"):
        manifest = getattr(args, side + "_files", None)
        if manifest:
            with open(manifest, encoding="utf-8") as stream:
                expected = any(line.rstrip("\r\n") for line in stream)
            if expected != bool(getattr(args, side + "_json")):
                raise ValueError(f"{side} source manifest disagrees with report presence")
    base_audit, head_audit = [], []
    base_diags = logical_findings(load_diags(args.base_json, base_audit))
    head_diags = logical_findings(load_diags(args.head_json, head_audit))
    renames = load_renames(args.renames)
    added_lines = parse_added_lines(args.diff)
    sum_changes, sum_available = parse_summary_diff(args.summary_diff)
    processed, capped = parse_head_stderr(args.head_stderr)
    name_status = parse_name_status(args.name_status)
    audit_sources = LineCache()
    for root, audit in ((args.base_root, base_audit), (args.head_root, head_audit)):
        for record in audit:
            diagnostic = record["finding"]
            finding_key(diagnostic, rel_to_root(diagnostic["file"], root), audit_sources)

    analyzed_rel = set()
    if args.head_files and os.path.exists(args.head_files):
        with open(args.head_files, "r", encoding="utf-8") as f:
            for line in f:
                p = line.strip()
                if p:
                    analyzed_rel.add(rel_to_root(p, args.head_root))

    new, fixed = compute_delta(base_diags, head_diags, args.base_root,
                               args.head_root, renames, [record["finding"] for record in head_audit])
    unbound_base = sum(not d["baseline_function"] or not d["function"] for d in base_diags)
    unbound_head = sum(not d["baseline_function"] or not d["function"] for d in head_diags)
    new_errors = [(d, r) for d, r in new if d["severity"] == "error"]
    new_warnings = [(d, r) for d, r in new if d["severity"] != "error"]
    blocking = [(d, r) for d, r in new
                if d.get("blocks_verdict", True)]
    blocking_errors = [(d, r) for d, r in blocking
                       if d["severity"] == "error"]
    blocking_warnings = [(d, r) for d, r in blocking
                         if d["severity"] != "error"]
    report_only = [(d, r) for d, r in new
                   if not d.get("blocks_verdict", True)]

    # Human label counts by ACTUAL severity (an assumption finding is
    # info, not warning); the REVIEW_RESULT machine line keeps its
    # stable two-bucket schema (new_warnings = everything non-error).
    # Verdict gating is independently determined by blocks_verdict.
    sev_counts = Counter(d["severity"] for d, _ in new)
    sev_label = ", ".join(
        "%d %s" % (sev_counts[s], s)
        for s in ("error", "warning", "info") if s in sev_counts) or "none"
    for s in sev_counts:
        if s not in ("error", "warning", "info"):
            sev_label += ", %d %s" % (sev_counts[s], s)

    weakened = [rest for kind, rest in sum_changes if kind == "WEAKENED"]
    other_changes = [(k, rest) for k, rest in sum_changes if k != "WEAKENED"]

    gate_fail = bool(blocking_errors) or bool(weakened) or \
        (args.strict and bool(blocking_warnings))

    # --- render -----------------------------------------------------------
    md = []
    md.append("# CodeSkeptic diff review")
    md.append("")
    md.append("Base `%s` -> head `%s`." % (args.base_label, args.head_label))
    md.append("Finding identity: baseline v3 (AST-bound function signatures, logical occurrence budgets).")
    if unbound_base or unbound_head:
        md.append("Unbound identity: %d base / %d head findings. Head findings remain new; "
                  "unbound base findings are not claimed fixed." % (unbound_base, unbound_head))
    if gate_fail:
        reasons = []
        if blocking_errors:
            reasons.append("%d new blocking error(s)" % len(blocking_errors))
        if args.strict and blocking_warnings:
            reasons.append("%d new blocking warning(s) (--strict)" %
                           len(blocking_warnings))
        if weakened:
            reasons.append("%d weakened contract(s)" % len(weakened))
        md.append("**Verdict: FAIL** — " + ", ".join(reasons))
    else:
        md.append("**Verdict: PASS** — no new blocking findings, "
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
    if base_audit or head_audit:
        md.extend(["", "## Applied suppressions", "",
                   "Suppression is a policy decision, not evidence of a fix. Fix claims for the same rule/function "
                   "are withheld where head findings are suppressed (same rule/file if ownership is unbound)."])
        for side, audit in (("Base", base_audit), ("Head", head_audit)):
            md.extend(["", "### %s (%d applied finding records)" % (side, len(audit)), ""])
            # Indented JSON retains exact reason/scope/finding evidence without
            # treating untrusted comment text as executable HTML or Markdown.
            md.extend("    " + json.dumps(record, ensure_ascii=False, sort_keys=True) for record in audit)

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
    if blocking_warnings and not args.strict:
        md.append("- New supported warnings are reported but do not gate; "
                  "pass --strict to gate them.")
    if report_only:
        md.append(
            "- %d experimental finding(s) are report-only and never gate, "
            "including under --strict." % len(report_only)
        )

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

def _path_pattern_body(path):
    """Return a regex body matching a path with either separator style."""
    path = path.rstrip("/\\")
    if not path:
        raise ValueError("path prefix must not be empty")
    pieces = re.split(r"([/\\]+)", path)
    return "".join(
        r"[/\\]+" if re.fullmatch(r"[/\\]+", piece) else re.escape(piece)
        for piece in pieces
        if piece
    )


def _path_prefix_pattern(path):
    return re.compile(
        _path_pattern_body(path) + r"(?=[/\\\s\"\']|$)",
        re.IGNORECASE,
    )


def _compile_path_prefixes(value):
    """Find actual identities in path-valued substrings, including -I.

    Roots supplied by the caller can use long Windows names while database
    flags use 8.3 names (or directory symlinks). Resolve prefixes only: never
    normalize an entire compiler argument and thereby change a flag's value.
    """
    prefixes = {}
    for start in re.finditer(r"(?:[A-Za-z]:)?[/\\]", value):
        for end in re.finditer(r"[/\\\s\"\']|$", value[start.end():]):
            prefix = value[start.start():start.end() + end.start()]
            if not os.path.isabs(prefix):
                continue
            try:
                prefixes[prefix] = os.path.realpath(prefix)
            except (OSError, ValueError):
                continue
    return prefixes


def _rewrite_compile_path(value, src_root, dst_root, protect=None):
    """Rewrite source paths while preserving build-only dependencies."""
    hidden = []

    def hide(match):
        token = f"\x00CS_PROTECTED_{len(hidden)}\x00"
        hidden.append((token, match.group(0)))
        return token

    prefixes = _compile_path_prefixes(value)
    roots = {src_root}
    protected = {protect} if protect else set()
    for prefix, canonical in prefixes.items():
        if os.path.normcase(canonical) == os.path.normcase(src_root):
            roots.add(prefix)
        if protect and os.path.normcase(canonical) == os.path.normcase(protect):
            protected.add(prefix)
        # Build aliases can occur below the root too (OUTGEN~1, BUILDO~1).
        # Compare identities before any replacement and keep original bytes.
        if (os.path.normcase(os.path.dirname(canonical)) == os.path.normcase(src_root) and
                re.fullmatch(r"(?:build|cmake-build)(?:[-_.].*)?",
                             os.path.basename(canonical), re.IGNORECASE)):
            protected.add(prefix)
    for prefix in sorted(protected, key=len, reverse=True):
        value = _path_prefix_pattern(prefix).sub(hide, value)

    # A compile DB may reuse dependencies from an older sibling build. Those
    # directories do not exist in a source-only base worktree and must retain
    # their HEAD paths just like the explicitly selected BUILD_PATH.
    # Keep lexical matching too: cross-host review fixtures can contain Windows
    # paths on POSIX, where native filesystem alias resolution cannot help.
    for root in roots:
        build_root = re.compile(
            _path_pattern_body(root)
            + r"[/\\]+(?:build|cmake-build)(?:[-_.][^/\\\s\"\']*)?"
            + r"(?=[/\\\s\"\']|$)", re.IGNORECASE)
        value = build_root.sub(hide, value)
    for root in sorted(roots, key=len, reverse=True):
        value = _path_prefix_pattern(root).sub(lambda _m: dst_root, value)
    for token, original in hidden:
        value = value.replace(token, original)
    return value


def _compile_renames(path, src_root, dst_root):
    """Strict HEAD-new -> BASE-old source identities, never basename edits."""
    if not path:
        return {}
    result, seen_old = {}, set()
    with open(path, encoding="utf-8") as stream:
        for line in stream:
            fields = line.rstrip("\n").split("\t")
            if len(fields) != 2:
                raise ValueError("rename map requires old<TAB>new paths")
            for name in fields:
                if (not name or name.startswith(("/", "\\")) or "\x00" in name or
                        "\\" in name or ":" in name.split("/")[0] or
                        any(part in ("", ".", "..") for part in name.split("/"))):
                    raise ValueError("rename paths must be contained repository-relative paths")
            old, new = fields
            target = _compile_identity(old, dst_root)
            identity = os.path.normcase(_compile_identity(new, src_root))
            if os.path.normcase(target) in seen_old or identity in result:
                raise ValueError("duplicate rename identity")
            seen_old.add(os.path.normcase(target))
            result[identity] = target
    return result


def _compile_identity(path, working):
    return os.path.realpath(path if os.path.isabs(path) else os.path.join(working, path))


def _remap_compile_arguments(arguments, source, working, target, renamed, rw):
    """Preserve argument values; move only an exact standalone source operand.

    This is not a driver parser. The real HEAD analyzer must validate the
    original command first. Ambiguous rename forms fail rather than inventing
    a valid BASE command from invalid or differently interpreted HEAD input.
    """
    if renamed and (os.path.basename(arguments[0]).lower() in ("cl", "cl.exe", "clang-cl", "clang-cl.exe") or
                    any(arg.startswith(("@", "-working-directory", "--working-directory", "/Tc", "/Tp")) or
                        arg == "--driver-mode=cl" for arg in arguments)):
        raise ValueError("rename requires standalone source arguments without response files or directory overrides")
    if any(arg in (";", "&&", "||", "|", "<", ">") for arg in arguments):
        raise ValueError("shell command chains are not compilation arguments")
    matching = [index for index, value in enumerate(arguments) if index and
                not value.startswith(("-", "@")) and
                os.path.normcase(_compile_identity(value, working)) == os.path.normcase(source)]
    if renamed and len(matching) != 1:
        raise ValueError("rename requires exactly one original declared source operand")
    if renamed:
        for index, value in enumerate(arguments):
            if index == 0 or index in matching or value.startswith(("-", "@")):
                continue
            if os.path.normcase(_compile_identity(rw(_compile_identity(value, working)), working)) == os.path.normcase(target):
                raise ValueError("rename would conflate another original argument with the BASE source")
    remapped = [rw(value) for value in arguments]
    # Absolute source operands remain correct when a protected build working
    # directory stays in HEAD, including originally relative source arguments.
    for index in matching:
        remapped[index] = target
    return remapped


def cmd_remap_db(args):
    src_root = os.path.realpath(args.from_root).rstrip(os.sep)
    dst_root = os.path.realpath(args.to_root).rstrip(os.sep)
    if not src_root or src_root == os.sep:
        print("[review] refusing to remap from root '%s'" % src_root,
              file=sys.stderr)
        return 2
    # The BUILD directory is typically inside the repo root but is NOT in
    # git — a worktree has no build/. Paths under it (generated headers,
    # -Ibuild/_deps/...) must keep pointing at the HEAD build: protect
    # them with a sentinel through the root rewrite. Head build outputs
    # applied to base sources is the same pragmatic assumption as
    # reusing head compile flags at all.
    protect = None
    if args.protect:
        protect = os.path.realpath(args.protect).rstrip(os.sep)
        try:
            common = os.path.commonpath((src_root, protect))
        except ValueError:
            common = ""
        if (os.path.normcase(common) != os.path.normcase(src_root) or
                os.path.normcase(protect) == os.path.normcase(src_root)):
            protect = None  # outside the root: the rewrite can't touch it

    def rw(s):
        return _rewrite_compile_path(s, src_root, dst_root, protect)

    with open(args.src, "r", encoding="utf-8") as f:
        entries = json.load(f)
    if not isinstance(entries, list):
        raise ValueError("compilation database must be an array")
    renames = _compile_renames(getattr(args, "renames", None), src_root, dst_root)
    for e in entries:
        if not isinstance(e, dict) or any(not isinstance(e.get(field), str) or
                not e[field] or "\x00" in e[field] for field in ("directory", "file")):
            raise ValueError("database entries require nonempty directory and file strings")
        if "arguments" in e and (not isinstance(e["arguments"], list) or not e["arguments"] or
                any(not isinstance(a, str) or "\x00" in a for a in e["arguments"]) or not e["arguments"][0]):
            raise ValueError("arguments must be a nonempty string array with a compiler")
        if "command" in e and (not isinstance(e["command"], str) or not e["command"] or "\x00" in e["command"]):
            raise ValueError("command must be a nonempty string")
        if "arguments" not in e and "command" not in e:
            raise ValueError("database entry requires arguments or command")
        if "output" in e and (not isinstance(e["output"], str) or "\x00" in e["output"]):
            raise ValueError("output must be a string")
        working = _compile_identity(e["directory"], os.path.dirname(os.path.abspath(args.src)))
        source = _compile_identity(e["file"], working)
        target = renames.get(os.path.normcase(source), rw(source))
        renamed = os.path.normcase(source) in renames
        if "arguments" in e:
            e["arguments"] = _remap_compile_arguments(e["arguments"], source, working, target, renamed, rw)
        if "command" in e:
            if os.name == "nt":
                if renamed:
                    raise ValueError("rename command-string remapping requires POSIX tokenization")
                e["command"] = rw(e["command"])
            else:
                arguments = shlex.split(e["command"])
                if not arguments:
                    raise ValueError("command has no compiler")
                e["command"] = shlex.join(_remap_compile_arguments(arguments, source, working, target, renamed, rw))
        e["directory"], e["file"] = rw(working), target
        if "output" in e:
            e["output"] = rw(e["output"])
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
    p_remap.add_argument("--renames", help="old<TAB>new repository-relative source names")

    p_asm = sub.add_parser("assemble")
    p_asm.add_argument("--base-json")
    p_asm.add_argument("--head-json")
    p_asm.add_argument("--base-root", required=True)
    p_asm.add_argument("--head-root", required=True)
    p_asm.add_argument("--renames")
    p_asm.add_argument("--diff")
    p_asm.add_argument("--name-status")
    p_asm.add_argument("--head-files")
    p_asm.add_argument("--base-files")
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
        try:
            return cmd_remap_db(args)
        except (OSError, ValueError) as error:
            print(f"[review] invalid compilation inputs: {error}", file=sys.stderr)
            return 2
    try:
        return cmd_assemble(args)
    except (OSError, ValueError, KeyError, TypeError) as error:
        print(f"[review] invalid review evidence: {error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
