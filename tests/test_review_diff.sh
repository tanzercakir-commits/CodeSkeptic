#!/usr/bin/env bash
# Focused compile-only baseline/suppression regressions, called by the existing
# ReviewDiffFlow CTest harness. No downloads, execution of fixtures or Git writes.
set -euo pipefail
task_script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
python3 -B - "${1:?codeskeptic binary required}" "$task_script_dir/../scripts/review_report.py" <<'PY'
import importlib.util
import json
from pathlib import Path
import subprocess
import sys
import tempfile

binary, module_path = Path(sys.argv[1]).resolve(), Path(sys.argv[2]).resolve()
spec = importlib.util.spec_from_file_location("review_report", module_path)
review = importlib.util.module_from_spec(spec)
spec.loader.exec_module(review)

with tempfile.TemporaryDirectory(prefix="codeskeptic-baseline-contract-") as directory:
    root = Path(directory)
    source = root / "input.cpp"
    sequence = 0

    def scan(code, *args):
        global sequence
        sequence += 1
        source.write_bytes(code.encode())
        output = root / f"report-{sequence}.json"
        process = subprocess.run([str(binary), str(source), "--lang", "en", "--json", str(output), *map(str, args)],
                                 cwd=root, capture_output=True, text=True, timeout=45)
        assert not process.stdout, process.stdout
        report = json.loads(output.read_text()) if output.exists() else None
        return process, report

    original = "int f(int x){\nint zero=0;\nreturn 1/zero;\n}\n"
    process, raw = scan(original)
    assert process.returncode == 1 and raw["total"] == 1, (process.stderr, raw)
    diagnostic = raw["diagnostics"][0]
    assert diagnostic["baseline_function"].startswith("csb-fn1:")
    baseline = root / "baseline.txt"
    process, report = scan(original, "--write-baseline", baseline)
    assert process.returncode == 0 and report is None
    assert baseline.read_text().startswith("# codeskeptic-baseline v3\n")
    assert "unbound_records=0" in process.stderr
    for label, code, count in [
        ("same", original, 0),
        ("shift", "// inserted\n\n" + original, 0),
        ("overload", original.replace("int x", "long x"), 1),
        ("new-function", original.replace("f(int", "g(int"), 1),
        ("legacy-volume", original + "\n" + original.replace("f(int", "g(int"), 1),
    ]:
        process, report = scan(code, "--baseline", baseline)
        assert (process.returncode, report["total"]) == (count, count), (label, process.stderr, report)
        assert report["coverage"] == raw["coverage"]
        assert report["baseline"]["version"] == 3 and not report["baseline"]["legacy_weak_identity"]
        if label == "overload":
            assert report["diagnostics"][0]["fingerprint"] == diagnostic["fingerprint"]
            assert report["diagnostics"][0]["baseline_function"] != diagnostic["baseline_function"]

    for newline in ("\n", "\r", "\r\n"):
        process, report = scan("int f(){int z=0;return 1/z;}" + newline +
                               "// codeskeptic-disable-line div-by-zero" + newline)
        assert process.returncode == 1 and report["total"] == 1 and not report["suppressions"]
    for label, code, count in [
        ("reason", "// codeskeptic-disable-next-line div-by-zero -- fixture rationale\nint f(){int z=0;return 1/z;}\n", 0),
        ("legacy", "int f(){int z=0;return 1/z;} // codeskeptic-disable-line\n", 0),
        ("string", 'int f(){const char*s="// codeskeptic-disable-line";int z=0;return 1/z;}\n', 1),
        ("raw", 'int f(){const char*s=R"tag(// codeskeptic-disable-line)tag";int z=0;return 1/z;}\n', 1),
        ("malformed", "int f(){int z=0;return 1/z;} // codeskeptic-disable-line !!!\n", 1),
        ("prefix", "int f(){int z=0;return 1/z;} // not-codeskeptic-disable-line\n", 1),
    ]:
        process, report = scan(code)
        assert (process.returncode, report["total"]) == (count, count), (label, process.stderr, report)
        assert report["coverage"] == raw["coverage"]
        if count:
            assert report["suppressions"] == []
        else:
            assert len(report["suppressions"]) == 1
            record = report["suppressions"][0]
            assert record["finding"]["rule_id"] == "div-by-zero" and record["finding"]["fingerprint"]
            assert record["reason_status"] == ("provided" if label == "reason" else "legacy-unspecified")
            assert record["reason"] == ("fixture rationale" if label == "reason" else None)
            assert record["target_line"] == (2 if label == "reason" else 1)
            process, report = scan(code, "--write-baseline", root / (label + ".baseline"))
            assert process.returncode == 0 and report is None
            records = [json.loads(line.removeprefix("[CodeSkeptic] suppressions: ")) for line in process.stderr.splitlines()
                       if line.startswith("[CodeSkeptic] suppressions: ")]
            assert records == [[record]]

    for label, text in [("unknown", "# codeskeptic-baseline v999\n"),
                        ("malformed", "# codeskeptic-baseline v3\nv3|not-valid\n")]:
        malformed = root / (label + ".baseline")
        malformed.write_text(text)
        process, report = scan(original, "--baseline", malformed)
        assert process.returncode == 2 and report["evidence"]["baseline_load_failed"]
        assert report["total"] == 1

    # Two real compile variants agree on the public finding but not its AST
    # signature. Neither baseline nor the post-dedup report may invent consensus.
    variant_code = "int f(ARG x){int z=0;return 1/z;}\n"
    database = root / "compile_commands.json"
    def variants(types):
        database.write_text(json.dumps([
            {"directory": str(root), "file": str(source),
             "arguments": ["clang++", "-std=c++17", "-DARG=" + kind, "-c", str(source)]}
            for kind in types]))
    variants(["int", "long"])
    process, report = scan(variant_code, "--build-path", root)
    assert process.returncode == 1 and report["total"] == 1, (process.stderr, report)
    assert report["coverage"]["sources"][0]["commands"] == 2
    assert report["diagnostics"][0]["baseline_function"] == ""
    process, report = scan(variant_code, "--build-path", root, "--write-baseline", baseline)
    assert process.returncode == 0 and "unbound_records=1" in process.stderr
    assert "unbound|" in baseline.read_text()
    process, report = scan(variant_code, "--build-path", root, "--baseline", baseline)
    assert process.returncode == 1 and report["total"] == 1
    variants(["int"])
    process, report = scan(variant_code, "--build-path", root, "--write-baseline", baseline)
    assert process.returncode == 0 and "unbound_records=0" in process.stderr
    variants(["int", "int", "int"])
    process, report = scan(variant_code, "--build-path", root, "--baseline", baseline)
    assert process.returncode == 0 and report["total"] == 0
    database.unlink()  # only this fixture's generated database

    for label, code in [
        ("template", "template<class T> int f(T x){int z=0;return 1/z;} int g(){return f(1);}\n"),
        ("macro", "#define DEF int f(){int z=0;return 1/z;}\nDEF\n"),
        ("lambda", "int g(){auto f=[](){int z=0;return 1/z;};return f();}\n"),
    ]:
        process, report = scan(code)
        findings = [d for d in report["diagnostics"] if d["rule_id"] == "div-by-zero"]
        assert process.returncode == 1 and findings, (label, process.stderr, report)
        assert all(not d["baseline_function"] for d in findings), (label, findings)

    # Pure identity checks pin review parity independently of the C++ encoder.
    source.write_text("return 1/z;\nreturn 1/z;\n")
    base = dict(diagnostic, file=str(source), line=1, column=1)
    for field, value in [("function", "g"), ("baseline_function", "csb-fn1:int (long)"),
                         ("severity", "warning"), ("column", 2)]:
        changed = dict(base, **{field: value})
        new, fixed = review.compute_delta([base], [changed], str(root), str(root), {})
        assert (len(new), fixed) == (1, 1), (field, new, fixed)
    second = dict(base, line=2)
    new, fixed = review.compute_delta([base, base], [base, base, second], str(root), str(root), {})
    assert (len(new), fixed) == (1, 0)
    unbound = dict(base, baseline_function="")
    new, fixed = review.compute_delta([unbound], [unbound], str(root), str(root), {})
    assert (len(new), fixed) == (1, 0)
    assert len(review.logical_findings([unbound, unbound])) == 1
    conflict = dict(base, baseline_function="csb-fn1:int (long)")
    assert review.logical_findings([base, conflict])[0]["baseline_function"] == ""
    try:
        review.compute_delta([], [dict(base, blocks_verdict=False), base], str(root), str(root), {})
    except ValueError:
        pass
    else:
        raise AssertionError("conflicting duplicate classification must not become report-only")
    try:
        review.logical_findings([base, dict(base, baseline_function="unknown-signature")])
    except ValueError:
        pass
    else:
        raise AssertionError("malformed signature must not disappear during normalization")
    renamed = root / "renamed.cpp"
    renamed.write_text("return 1/z;\n")
    new, fixed = review.compute_delta([base], [dict(base, file=str(renamed))], str(root), str(root),
                                      {"input.cpp": "renamed.cpp"})
    assert (len(new), fixed) == (0, 0)
    expected_key = review.finding_key(base, "input.cpp", review.LineCache())
    source.write_bytes(b"// shift\r\n\r    return 1/z;\r")
    assert review.finding_key(dict(base, line=3, column=5), "input.cpp", review.LineCache()) == expected_key

    source.write_text("return 1/z;\n")
    valid = dict(raw, diagnostics=[base], total=1)
    report_path = root / "valid.json"
    report_path.write_text(json.dumps(valid))
    process = subprocess.run([sys.executable, "-B", str(module_path), "assemble", "--head-json", str(report_path),
        "--base-json", str(report_path), "--head-root", str(root), "--base-root", str(root), "--gate", "warn"],
        capture_output=True, text=True)
    assert process.returncode == 2 and "Verdict: PASS" not in process.stdout
    manifest = root / "head-files.txt"
    for contents, expected in [("", 0), (str(source) + "\n", 2)]:
        manifest.write_text(contents)
        process = subprocess.run([sys.executable, "-B", str(module_path), "assemble", "--head-files", str(manifest),
            "--head-root", str(root), "--base-root", str(root), "--gate", "warn"], capture_output=True, text=True)
        assert process.returncode == expected, (process.stdout, process.stderr)
    renames = root / "renames.txt"
    for contents in ["malformed\n", "a.cpp\tb.cpp\na.cpp\tc.cpp\n", "a.cpp\tb.cpp\nc.cpp\tb.cpp\n",
                     "../a.cpp\tb.cpp\n", "/absolute.cpp\tb.cpp\n"]:
        renames.write_text(contents)
        process = subprocess.run([sys.executable, "-B", str(module_path), "assemble", "--head-json", str(report_path),
            "--head-root", str(root), "--base-root", str(root), "--renames", str(renames), "--gate", "warn"],
            capture_output=True, text=True)
        assert process.returncode == 2 and "Verdict: PASS" not in process.stdout
    broken_path = root / "broken.json"
    invalid_documents = [None, "{}", '{"diagnostics":{}}', "not-json"]
    for contents in invalid_documents:
        if contents is not None: broken_path.write_text(contents)
        for gate in ("error", "warn"):
            process = subprocess.run([sys.executable, "-B", str(module_path), "assemble", "--head-json", str(broken_path),
                "--head-root", str(root), "--base-root", str(root), "--gate", gate], capture_output=True, text=True)
            assert process.returncode == 2 and "Verdict: PASS" not in process.stdout, (process.stdout, process.stderr)
    for arguments in [["--summary-diff", str(root / "missing.summary")], ["--head-files", str(root / "missing.manifest")]]:
        process = subprocess.run([sys.executable, "-B", str(module_path), "assemble", "--head-json", str(report_path),
            "--head-root", str(root), "--base-root", str(root), "--gate", "warn", *arguments], capture_output=True, text=True)
        assert process.returncode == 2 and "Verdict: PASS" not in process.stdout
    for changed in [dict(base, file=str(root / "missing.cpp")), dict(base, line=999), dict(base, column=999)]:
        report_path.write_text(json.dumps(dict(valid, diagnostics=[changed])))
        process = subprocess.run([sys.executable, "-B", str(module_path), "assemble", "--head-json", str(report_path),
            "--head-root", str(root), "--base-root", str(root), "--gate", "warn"], capture_output=True, text=True)
        assert process.returncode == 2 and "Verdict: PASS" not in process.stdout
    print("PASS: baseline v3 / lexical suppression / AST variants / review identity and input integrity")
PY
