#!/usr/bin/env python3
"""Juliet degerlendiricisi.

zerodefect'in --json ciktisini Juliet adlandirma sozlesmesiyle puanlar:
  - Bulgu, adi 'bad' iceren fonksiyondaysa  -> TP (dogru pozitif)
  - Bulgu, adi 'good' iceren fonksiyondaysa -> FP (yanlis pozitif)
  - Digerleri (yardimcilar, main vb.)       -> sayilmaz (other)

Iki gorunum raporlanir:
  1. GENEL: dosyalardaki TUM bulgular (kullanicinin gorecegi gurultu).
  2. ESLEMELI: yalnizca test edilen CWE'yle eslesen kuralin bulgulari
     (kuralin gercek kalitesi). Ornek: CWE416 dosyasindaki bir
     memory-leak uyarisi UAF kuralinin hanesine yazilmaz.

Recall paydasi yaklasik olarak "bad fonksiyon iceren dosya sayisi"dir:
her Juliet test dosyasi tam bir kusur baglami icerir. Dosya-bazli
isabet orani (hit rate) = en az bir TP bulgusu olan dosya / tum dosyalar.
Akis varyantlarinda (54a..54e gibi) kusur dosyalar arasi boldugu icin
bu oran alt sinirdir — kesin fonksiyon-bazli ground truth v2'de
(dokumante sinir).

Kullanim:
  juliet_eval.py <findings.json> <cwe-adi> <taranan-dosya-listesi>
"""

import json
import sys

# Test edilen CWE'ye "bu kusuru bulmak bu kuralin isi" diyen esleme.
# Anahtar CWE adinin on eki; deger rule_id kumesi.
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
    """(tp, fp, other) uclusu — Juliet fonksiyon-adi sozlesmesiyle."""
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


def main() -> int:
    if len(sys.argv) != 4:
        print(__doc__)
        return 2

    findings_path, cwe, filelist_path = sys.argv[1], sys.argv[2], sys.argv[3]

    with open(findings_path) as f:
        data = json.load(f)
    with open(filelist_path) as f:
        scanned_files = [line.strip() for line in f if line.strip()]

    diags = data.get("diagnostics", [])
    total_files = len(scanned_files)

    # 1) Genel gorunum: tum kurallarin bulgulari
    tp, fp, other = score(diags)
    files_with_tp = {d["file"] for d in tp}
    hit_rate = (len(files_with_tp) / total_files) if total_files else 0.0

    # 2) Eslemeli gorunum: yalnizca CWE'nin kurali
    rules = relevant_rules(cwe)
    matched = [d for d in diags if d.get("rule") in rules or
               d.get("rule_id") in rules]
    rtp, rfp, _ = score(matched)
    rfiles_with_tp = {d["file"] for d in rtp}
    rhit = (len(rfiles_with_tp) / total_files) if total_files else 0.0

    print(f"=== {cwe} ===")
    print(f"  taranan dosya       : {total_files}")
    print(f"  GENEL  TP/FP        : {len(tp)}/{len(fp)}"
          f"  precision={precision(tp, fp):.3f}  hitrate={hit_rate:.3f}")
    print(f"  ESLEMELI ({','.join(sorted(rules)) or '-'})")
    print(f"         TP/FP        : {len(rtp)}/{len(rfp)}"
          f"  precision={precision(rtp, rfp):.3f}  hitrate={rhit:.3f}")
    print(f"  sayilmayan (diger)  : {len(other)}")

    # Kural bazinda kirilim: FP'nin hangi kuraldan geldigi gorunur olsun
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
        print(f"   {tag}{rule:<16} tp={t:<5} fp={f_:<5} diger={o}")

    # Makine-okur satir (trend takibi icin grep-dostu).
    # Eski alanlar korunur; r* alanlari eslemeli gorunumdur.
    print(f"JULIET_RESULT {cwe} files={total_files} tp={len(tp)} "
          f"fp={len(fp)} precision={precision(tp, fp):.3f} "
          f"hitrate={hit_rate:.3f} rtp={len(rtp)} rfp={len(rfp)} "
          f"rprecision={precision(rtp, rfp):.3f} rhitrate={rhit:.3f}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
