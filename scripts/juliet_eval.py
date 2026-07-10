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

Vaka-bazli metrikler (F1'in temeli): her dosya bir vakadir — bad
fonksiyonda eslesen bulgu varsa vaka-TP, good fonksiyonda varsa vaka-FP,
bad'e hic bulgu yoksa FN (her Juliet dosyasi tam bir kusur baglami
icerir). Vaka-precision + recall'dan F1 turetilir. Akis varyantlarinda
(54a..54e) kusur dosyalar arasi bolundugu icin recall alt sinirdir.

ROC BILINCLI YOK: analizci olasiliksal degil, kanit-temelli ikili —
taranabilir esik olmadigi icin iki noktali "egri"den AUC yaniltici olur.
Durust karsiligi iki isletim noktasi: tum bulgular vs yalniz Error.

Beklenen tabanlar (4. arguman, opsiyonel): satir formati
  <CWE-adi> <min-rprecision> <min-rhitrate>
Taban ihlali exit 1 → CI kirmizi (Juliet skor bekcisi).

Kullanim:
  juliet_eval.py <findings.json> <cwe-adi> <dosya-listesi> [beklenen.txt]
"""

import json
import os
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


def load_expected(path, cwe):
    """Beklenen taban satirini (min_rprec, min_rhit) olarak dondurur."""
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

    # Vaka-bazli (dosya = vaka): F1 buradan turetilir
    case_tp = len(rfiles_with_tp)
    case_fp = len({d["file"] for d in rfp})
    case_fn = total_files - case_tp
    case_prec = (case_tp / (case_tp + case_fp)) if (case_tp + case_fp) \
        else 0.0
    case_rec = (case_tp / (case_tp + case_fn)) if (case_tp + case_fn) \
        else 0.0
    f1 = (2 * case_prec * case_rec / (case_prec + case_rec)) \
        if (case_prec + case_rec) else 0.0

    # Ikinci isletim noktasi: yalniz Error (kesin iddialar)
    err = [d for d in matched if d.get("severity") == "error"]
    etp, efp, _ = score(err)

    print(f"=== {cwe} ===")
    print(f"  taranan dosya       : {total_files}")
    print(f"  GENEL  TP/FP        : {len(tp)}/{len(fp)}"
          f"  precision={precision(tp, fp):.3f}  hitrate={hit_rate:.3f}")
    print(f"  ESLEMELI ({','.join(sorted(rules)) or '-'})")
    print(f"         TP/FP        : {len(rtp)}/{len(rfp)}"
          f"  precision={precision(rtp, rfp):.3f}  hitrate={rhit:.3f}")
    print(f"  vaka (dosya) bazli  : TP={case_tp} FP={case_fp} FN={case_fn}"
          f"  precision={case_prec:.3f}  recall={case_rec:.3f}"
          f"  F1={f1:.3f}")
    print(f"  yalniz-Error noktasi: TP/FP {len(etp)}/{len(efp)}"
          f"  precision={precision(etp, efp):.3f}")
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

    # FP ornekleri: kural iyilestirmesi icin ham malzeme. Suite CI'da
    # yasadigi icin FP kaliplari yalnizca loglardan okunabilir —
    # kural basina ilk 5 ornek (deterministik: dosya+satir sirali).
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

    # Makine-okur satir (trend takibi icin grep-dostu).
    # Eski alanlar korunur; r* alanlari eslemeli gorunumdur.
    print(f"JULIET_RESULT {cwe} files={total_files} tp={len(tp)} "
          f"fp={len(fp)} precision={precision(tp, fp):.3f} "
          f"hitrate={hit_rate:.3f} rtp={len(rtp)} rfp={len(rfp)} "
          f"rprecision={precision(rtp, rfp):.3f} rhitrate={rhit:.3f} "
          f"rcaseprec={case_prec:.3f} rf1={f1:.3f} "
          f"eprecision={precision(etp, efp):.3f}")

    # Skor bekcisi: sabitlenen tabanlarin altina dusus = kirmizi.
    # Tabanlar bilincli iyilestirme PR'larinda AYNI PR'da guncellenir.
    bounds = load_expected(expected_path, cwe)
    if bounds:
        min_prec, min_hit = bounds
        rprec = precision(rtp, rfp)
        if rprec < min_prec or rhit < min_hit:
            print(f"JULIET_GUARD_FAIL {cwe} rprecision={rprec:.3f} "
                  f"(taban {min_prec}) rhitrate={rhit:.3f} "
                  f"(taban {min_hit})")
            return 1
        print(f"[juliet] {cwe}: skor bekcisi OK "
              f"(rprec>={min_prec}, rhit>={min_hit})")
    return 0


if __name__ == "__main__":
    sys.exit(main())
