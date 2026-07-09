#!/usr/bin/env python3
"""Juliet degerlendiricisi.

zerodefect'in --json ciktisini Juliet adlandirma sozlesmesiyle puanlar:
  - Bulgu, adi 'bad' iceren fonksiyondaysa  -> TP (dogru pozitif)
  - Bulgu, adi 'good' iceren fonksiyondaysa -> FP (yanlis pozitif)
  - Digerleri (yardimcilar, main vb.)       -> sayilmaz (other)

Recall paydasi yaklasik olarak "bad fonksiyon iceren dosya sayisi"dir:
her Juliet test dosyasi tam bir kusur baglami icerir. Dosya-bazli
isabet orani (hit rate) = en az bir TP bulgusu olan dosya / tum dosyalar.
Bu, literaturdeki dosya-bazli Juliet puanlamasinin sade halidir —
kesin fonksiyon-bazli ground truth v2'de (dokumante sinir).

Kullanim:
  juliet_eval.py <findings.json> <cwe-adi> <taranan-dosya-listesi>
"""

import json
import sys


def main() -> int:
    if len(sys.argv) != 4:
        print(__doc__)
        return 2

    findings_path, cwe, filelist_path = sys.argv[1], sys.argv[2], sys.argv[3]

    with open(findings_path) as f:
        data = json.load(f)
    with open(filelist_path) as f:
        scanned_files = [line.strip() for line in f if line.strip()]

    tp, fp, other = [], [], []
    for d in data.get("diagnostics", []):
        func = d.get("function", "")
        if "bad" in func:
            tp.append(d)
        elif "good" in func:
            fp.append(d)
        else:
            other.append(d)

    files_with_tp = {d["file"] for d in tp}
    total_files = len(scanned_files)
    hit_rate = (len(files_with_tp) / total_files) if total_files else 0.0
    denom = len(tp) + len(fp)
    precision = (len(tp) / denom) if denom else 0.0

    print(f"=== {cwe} ===")
    print(f"  taranan dosya       : {total_files}")
    print(f"  TP bulgu ('bad')    : {len(tp)}")
    print(f"  FP bulgu ('good')   : {len(fp)}")
    print(f"  sayilmayan (diger)  : {len(other)}")
    print(f"  precision (TP/TP+FP): {precision:.3f}")
    print(f"  dosya isabet orani  : {hit_rate:.3f}"
          f"  ({len(files_with_tp)}/{total_files})")

    # Makine-okur satir (trend takibi icin grep-dostu)
    print(f"JULIET_RESULT {cwe} files={total_files} tp={len(tp)} "
          f"fp={len(fp)} precision={precision:.3f} hitrate={hit_rate:.3f}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
