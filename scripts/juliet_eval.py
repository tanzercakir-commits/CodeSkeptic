#!/usr/bin/env python3
"""Juliet evaluator.

Scores codeskeptic's --json output using the Juliet naming convention:
  - Finding in a function whose name contains 'bad'  -> TP (true positive)
  - Finding in a function whose name contains 'good' -> FP (false positive)
  - Everything else (helpers, main, etc.)            -> not counted (other)

Two views are reported:
  1. OVERALL: ALL findings in the files (the noise a user would see).
  2. RULE-MATCHED: only findings from the rule matching the CWE under
     test (the rule's true quality). Example: a memory-leak warning in a
     CWE416 file is not credited to the UAF rule.

Case-level metrics (the basis of F1): each file is one case — a matched
finding in a bad function makes the case a TP, one in a good function an
FP, and no finding in bad at all an FN (every Juliet file contains one
complete defect context). F1 is derived from case precision + recall.
For flow variants (54a..54e) the defect is split across files, so recall
is a lower bound.

DELIBERATELY NO ROC: the analyzer is evidence-based and binary, not
probabilistic — with no sweepable threshold, an AUC from a two-point
"curve" would be misleading. The honest counterpart is two operating
points: all findings vs errors only.

Expected baselines (4th argument, optional): line format
  <CWE-name> <min-rprecision> <min-rhitrate>
A baseline violation exits 1 → CI goes red (Juliet score guard).

Usage:
  juliet_eval.py <findings.json> <cwe-name> <file-list> [expected.txt]
"""

import json
import os
import sys

# Mapping that says "finding this defect is this rule's job" for the CWE
# under test. Key is a prefix of the CWE name; value is a set of rule_ids.
CWE_RULES = {
    "CWE476": {"null-deref"},
    "CWE401": {"memory-leak"},
    "CWE415": {"double-free"},
    "CWE416": {"use-after-free"},
    "CWE369": {"div-by-zero"},
    "CWE190": {"int-overflow"},
}


def relevant_rules(cwe: str) -> set:
    for prefix, rules in CWE_RULES.items():
        if cwe.startswith(prefix):
            return rules
    return set()


# --- FN classification (the recall map) ------------------------------
#
# Juliet file names encode the variant: CWE<n>_<name>__<source/sink
# description>_<flow-number><letter?>.c/.cpp. Classifying every MISSED
# case by name turns a bare recall number into a decision map:
#   float     — floating-point variants; deliberately silent (IEEE 754
#               division is defined behavior) — by design, not a gap
#   opaque    — rand()/socket/listen sources; an honest analyzer
#               cannot claim the value is zero/overflowing — by design
#   multifile — flow variants 54a..54e (chain across 5 files) and the
#               61 family (source and sink split across files): needs
#               --whole-program / summary-file analysis
#   baseline  — control-flow variants 01..34 in one function: if these
#               miss, the local engine itself has a gap (highest-value
#               targets)
#   flow      — single-TU dataflow variants (41..53: through calls/
#               pointers; 62..68: through structs/arrays/globals)
#   cpp       — C++ container/class variants (72..74, 81..84)
#   other     — anything the name does not place
import re

_FLOW_RE = re.compile(r"_(\d{2})[a-e]?\.(?:c|cpp)$")


def classify_fn(basename: str) -> str:
    name = basename.lower()
    if "float" in name:
        return "float"
    if "rand" in name or "socket" in name:
        return "opaque"
    m = _FLOW_RE.search(basename)
    flow = int(m.group(1)) if m else -1
    if flow in (54, 61):
        return "multifile"
    if 1 <= flow <= 34:
        return "baseline"
    if 41 <= flow <= 53 or 62 <= flow <= 68:
        return "flow"
    if 72 <= flow <= 74 or 81 <= flow <= 84:
        return "cpp"
    return "other"


def selftest() -> int:
    cases = {
        "CWE369_Divide_by_Zero__float_zero_divide_01.c": "float",
        "CWE369_Divide_by_Zero__int_rand_divide_02.c": "opaque",
        "CWE369_Divide_by_Zero__int_zero_divide_54c.c": "multifile",
        "CWE190_Integer_Overflow__int_max_multiply_61b.c": "multifile",
        "CWE369_Divide_by_Zero__int_zero_divide_09.c": "baseline",
        "CWE416_Use_After_Free__malloc_free_char_44.c": "flow",
        "CWE401_Memory_Leak__int64_t_calloc_67a.c": "flow",
        "CWE401_Memory_Leak__new_array_TwoIntsClass_72a.cpp": "cpp",
        "CWE190_weird_name.c": "other",
    }
    bad = {n: (classify_fn(n), want) for n, want in cases.items()
           if classify_fn(n) != want}
    if bad:
        print(f"FN-classifier selftest FAILED: {bad}")
        return 1
    print("FN-classifier selftest ok")
    return 0


# Known-lax-baseline exclusion (documented ground-truth correction).
#
# Juliet's CWE476 `null_check_after_deref` GOOD functions deliberately
# dereference a malloc result with NO null check — the source comment
# reads "FIX: Don't check for NULL since we wouldn't reach this line if
# the pointer was NULL", which is simply false (malloc can return NULL).
# Those good functions therefore CONTAIN a real unchecked-allocation
# defect (CWE-690/476); a null-deref finding in them is a TRUE positive
# by any strict reading. Juliet labels them "good" only w.r.t. the
# narrow flaw the class isolates (a redundant post-deref check), not as
# a claim of global correctness.
#
# So a null-deref finding here is neither a Juliet-TP (wrong function
# role) nor a genuine FP (the code IS buggy): it is EXCLUDED from
# precision, and the count is printed for audit. This corrects the
# ground truth instead of relaxing the precision floor — the floor
# stays fully sensitive to real regressions. Verified 2026-07-17: with
# the #92 alloc rule, 32/32 of the new CWE476 null-deref "FPs" fall
# exactly in this class; zero genuine FPs.
def isKnownLaxGood(d):
    func = d.get("function", "")
    base = d.get("file", "").split("/")[-1]
    return ("good" in func and d.get("rule_id") == "null-deref" and
            "null_check_after_deref" in base)


def score(diags):
    """(tp, fp, other) triple — per the Juliet function-name convention.
    Findings matching isKnownLaxGood are dropped (see its comment)."""
    tp, fp, other = [], [], []
    for d in diags:
        if isKnownLaxGood(d):
            continue
        func = d.get("function", "")
        if "bad" in func:
            tp.append(d)
        elif "good" in func:
            fp.append(d)
        else:
            other.append(d)
    return tp, fp, other


def precision(tp, fp):
    denom = len(tp) + len(fp)
    return (len(tp) / denom) if denom else 0.0


def load_expected(path, cwe):
    """Returns the expected baseline line as (min_rprec, min_rhit)."""
    if not path or not os.path.exists(path):
        return None
    with open(path) as f:
        for line in f:
            parts = line.split()
            if len(parts) >= 3 and not line.startswith("#") and \
                    cwe.startswith(parts[0]):
                return float(parts[1]), float(parts[2])
    return None


def main() -> int:
    if len(sys.argv) == 2 and sys.argv[1] == "--selftest":
        return selftest()
    if len(sys.argv) not in (4, 5):
        print(__doc__)
        return 2

    findings_path, cwe, filelist_path = sys.argv[1], sys.argv[2], sys.argv[3]
    expected_path = sys.argv[4] if len(sys.argv) == 5 else None

    with open(findings_path) as f:
        data = json.load(f)
    with open(filelist_path) as f:
        scanned_files = [line.strip() for line in f if line.strip()]

    diags = data.get("diagnostics", [])
    total_files = len(scanned_files)
    excluded = [d for d in diags if isKnownLaxGood(d)]
    if excluded:
        print(f"  excluded (known-lax good): {len(excluded)}"
              f"  [null_check_after_deref good functions deref malloc"
              f" unchecked — real CWE-690, not an FP]")

    # 1) Overall view: findings from all rules
    tp, fp, other = score(diags)
    files_with_tp = {d["file"] for d in tp}
    hit_rate = (len(files_with_tp) / total_files) if total_files else 0.0

    # 2) Rule-matched view: only the CWE's own rule
    rules = relevant_rules(cwe)
    matched = [d for d in diags if d.get("rule") in rules or
               d.get("rule_id") in rules]
    rtp, rfp, _ = score(matched)
    rfiles_with_tp = {d["file"] for d in rtp}
    rhit = (len(rfiles_with_tp) / total_files) if total_files else 0.0

    # Case-level (file = case): F1 is derived from this
    case_tp = len(rfiles_with_tp)
    case_fp = len({d["file"] for d in rfp})
    case_fn = total_files - case_tp
    case_prec = (case_tp / (case_tp + case_fp)) if (case_tp + case_fp) \
        else 0.0
    case_rec = (case_tp / (case_tp + case_fn)) if (case_tp + case_fn) \
        else 0.0
    f1 = (2 * case_prec * case_rec / (case_prec + case_rec)) \
        if (case_prec + case_rec) else 0.0

    # Second operating point: errors only (definite claims)
    err = [d for d in matched if d.get("severity") == "error"]
    etp, efp, _ = score(err)

    print(f"=== {cwe} ===")
    print(f"  files scanned              : {total_files}")
    print(f"  OVERALL TP/FP              : {len(tp)}/{len(fp)}"
          f"  precision={precision(tp, fp):.3f}  hitrate={hit_rate:.3f}")
    print(f"  RULE-MATCHED ({','.join(sorted(rules)) or '-'})")
    print(f"          TP/FP              : {len(rtp)}/{len(rfp)}"
          f"  precision={precision(rtp, rfp):.3f}  hitrate={rhit:.3f}")
    print(f"  case (file) level          : TP={case_tp} FP={case_fp}"
          f" FN={case_fn}"
          f"  precision={case_prec:.3f}  recall={case_rec:.3f}"
          f"  F1={f1:.3f}")
    print(f"  errors-only operating point: TP/FP {len(etp)}/{len(efp)}"
          f"  precision={precision(etp, efp):.3f}")
    print(f"  uncounted (other)          : {len(other)}")

    # Per-rule breakdown: make it visible which rule the FPs come from
    by_rule = {}
    for d in diags:
        rule = d.get("rule") or d.get("rule_id") or "?"
        t, f_, o = by_rule.setdefault(rule, [0, 0, 0])
        func = d.get("function", "")
        if "bad" in func:
            by_rule[rule][0] = t + 1
        elif "good" in func:
            by_rule[rule][1] = f_ + 1
        else:
            by_rule[rule][2] = o + 1
    for rule in sorted(by_rule):
        t, f_, o = by_rule[rule]
        tag = "*" if rule in rules else " "
        print(f"   {tag}{rule:<16} tp={t:<5} fp={f_:<5} other={o}")

    # FP samples: raw material for rule improvement. Since the suite
    # lives in CI, FP patterns can only be read from the logs —
    # first 12 samples per rule (deterministic: sorted by file+line).
    fp_by_rule = {}
    for d in fp:
        rule = d.get("rule") or d.get("rule_id") or "?"
        fp_by_rule.setdefault(rule, []).append(d)
    for rule in sorted(fp_by_rule):
        samples = sorted(fp_by_rule[rule],
                         key=lambda d: (d.get("file", ""), d.get("line", 0)))
        for d in samples[:12]:
            base = os.path.basename(d.get("file", "?"))
            print(f"FP_SAMPLE {cwe} {rule} {base}:{d.get('line', 0)} "
                  f"{d.get('function', '?')} :: {d.get('message', '')}")

    # FN classification: every missed case, bucketed by variant name —
    # the recall decision map (by-design vs addressable; see classify_fn).
    missed = sorted(set(scanned_files) - rfiles_with_tp)
    buckets = {}
    for path in missed:
        buckets.setdefault(classify_fn(os.path.basename(path)),
                           []).append(path)
    counts = " ".join(f"{k}={len(buckets.get(k, []))}"
                      for k in ("float", "opaque", "multifile",
                                "baseline", "flow", "cpp", "other"))
    print(f"JULIET_FN_CLASS {cwe} total={len(missed)} {counts}")
    for bucket in ("baseline", "flow", "multifile", "cpp", "other"):
        for path in buckets.get(bucket, [])[:5]:
            print(f"FN_SAMPLE {cwe} {bucket} {os.path.basename(path)}")

    # Machine-readable line (grep-friendly for trend tracking).
    # Legacy fields are preserved; r* fields are the rule-matched view.
    print(f"JULIET_RESULT {cwe} files={total_files} tp={len(tp)} "
          f"fp={len(fp)} precision={precision(tp, fp):.3f} "
          f"hitrate={hit_rate:.3f} rtp={len(rtp)} rfp={len(rfp)} "
          f"rprecision={precision(rtp, rfp):.3f} rhitrate={rhit:.3f} "
          f"rcaseprec={case_prec:.3f} rf1={f1:.3f} "
          f"eprecision={precision(etp, efp):.3f}")

    # Score guard: dropping below the pinned baselines = red.
    # Baselines are updated in the SAME PR for deliberate improvement PRs.
    bounds = load_expected(expected_path, cwe)
    if bounds:
        min_prec, min_hit = bounds
        rprec = precision(rtp, rfp)
        if rprec < min_prec or rhit < min_hit:
            print(f"JULIET_GUARD_FAIL {cwe} rprecision={rprec:.3f} "
                  f"(baseline {min_prec}) rhitrate={rhit:.3f} "
                  f"(baseline {min_hit})")
            return 1
        print(f"[juliet] {cwe}: score guard OK "
              f"(rprec>={min_prec}, rhit>={min_hit})")
    return 0


if __name__ == "__main__":
    sys.exit(main())
