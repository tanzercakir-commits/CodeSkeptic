#!/usr/bin/env python3
"""Juliet evaluator.

Scores zerodefect's --json output using the Juliet naming convention:
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
}


def relevant_rules(cwe: str) -> set:
    for prefix, rules in CWE_RULES.items():
        if cwe.startswith(prefix):
            return rules
    return set()


def score(diags):
    """(tp, fp, other) triple — per the Juliet function-name convention."""
    tp, fp, other = [], [], []
    for d in diags:
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
    # first 5 samples per rule (deterministic: sorted by file+line).
    fp_by_rule = {}
    for d in fp:
        rule = d.get("rule") or d.get("rule_id") or "?"
        fp_by_rule.setdefault(rule, []).append(d)
    for rule in sorted(fp_by_rule):
        samples = sorted(fp_by_rule[rule],
                         key=lambda d: (d.get("file", ""), d.get("line", 0)))
        for d in samples[:5]:
            base = os.path.basename(d.get("file", "?"))
            print(f"FP_SAMPLE {cwe} {rule} {base}:{d.get('line', 0)} "
                  f"{d.get('function', '?')} :: {d.get('message', '')}")

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
