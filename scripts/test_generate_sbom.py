#!/usr/bin/env python3
"""Synthetic provenance contract checks; these do not execute/qualify a binary."""
import contextlib
import copy
import io
import json
from pathlib import Path
import tarfile
import tempfile
import unittest
from unittest.mock import patch

import generate_sbom as sbom


class ProvenanceTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="sbom fixtures ")
        self.addCleanup(self.temporary.cleanup)
        self.work = Path(self.temporary.name)
        self.source = sbom.git(sbom.REPO, "rev-parse", "HEAD").decode().strip()
        self.version = "0.4.9-dev+g" + self.source[:12]
        self.name = "codeskeptic-v" + self.version + "-linux-x86_64"
        self.root = self.work / self.name
        self.root.mkdir()
        self.put("bin/codeskeptic", b"synthetic binary: never executed\n")
        (self.root / "bin/codeskeptic").chmod(0o755)
        self.put("LICENSE", sbom.git(sbom.REPO, "show", self.source + ":LICENSE"))
        self.put("README.md", b"synthetic package\n")
        self.put("lib/libLLVM.so.20.1", b"synthetic library\n")
        self.put("lib/clang/20/include/stddef.h", b"synthetic header\n")
        self.put("licenses/llvm-20/copyright", b"Synthetic notice; /usr/share/common-licenses/MIT\n")
        self.put("licenses/common/MIT", b"Synthetic common license text\n")
        self.put("licenses/INDEX.tsv", (
            "component\tpackage\tversion\tnotice\n"
            "lib/libLLVM.so.20.1\tllvm-20\t20.1.2\tlicenses/llvm-20/copyright\n"
            "lib/clang/20/include\tllvm-20\t20.1.2\tlicenses/llvm-20/copyright\n").encode())
        self.put("DEPENDENCIES.txt", ("CodeSkeptic " + self.version + "\nClang resource major: 20\n"
                 "Synthetic fixture\n\nbundled lib/libLLVM.so.20.1\nhost libc.so.6\n").encode())
        self.report = self.work / "report.json"
        self.report.write_bytes(sbom.canonical({"tool": "CodeSkeptic", "tool_version": self.version,
                                              "schema": "codeskeptic-report/v1"}))
        self.caps = self.work / "capabilities.json"
        self.caps.write_bytes(sbom.canonical({"product": "CodeSkeptic", "version": self.version,
                                            "schema_version": 2}))
        self.log = self.work / "build.log"
        self.log.write_bytes(b"synthetic build receipt, not an actual build\n")
        self.archive = self.work / (self.name + ".tar.gz")
        self.manifest = self.work / "build-evidence.json"
        self.output = self.work / "sidecars"
        self.evidence = {"schema": "codeskeptic-build-evidence/v1", "source_sha": self.source,
                         "archive_sha256": "0" * 64,
                         "binary_sha256": sbom.file_hash(self.root / "bin/codeskeptic"),
                         "report": self.record(self.report), "capabilities": self.record(self.caps),
                         "recipe": {"source_sha": self.source,
                                    "toolchain": {"profile": "synthetic; not executed"},
                                    "commands": ["cmake --build build"],
                                    "inputs": [dict(name="build.log", **self.record(self.log))]}}

    def put(self, path, data):
        target = self.root / path
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(data)

    @staticmethod
    def record(path):
        return {"path": str(path), "sha256": sbom.file_hash(path)}

    def pack(self):
        with tarfile.open(self.archive, "w:gz") as archive:
            archive.add(self.root, arcname=self.name)
        self.evidence["archive_sha256"] = sbom.file_hash(self.archive)

    def run_generator(self):
        self.manifest.write_bytes(sbom.canonical(self.evidence))
        # Unit fixtures do not claim to be a committed generator qualification.
        # The exact unmocked generator is measured separately on the real package.
        identity = {"head": "1" * 40, "files": {
            "scripts/" + name: sbom.file_hash(sbom.REPO / "scripts" / name)
            for name in ("generate_sbom.py", "action_acquire.py", "action_run.py")}}
        with patch.object(sbom, "generator_identity", return_value=identity):
            with contextlib.redirect_stdout(io.StringIO()):
                return sbom.generate(self.archive, self.manifest, self.output)

    def verify(self, pending_checksums=False):
        original_git = sbom.git
        def fixture_git(repo, *args):
            if args[0] == "show" and args[1].startswith("1" * 40 + ":scripts/"):
                return (sbom.REPO / args[1].split(":", 1)[1]).read_bytes()
            return original_git(repo, *args)
        with patch.object(sbom, "git", side_effect=fixture_git), contextlib.redirect_stdout(io.StringIO()):
            sbom.verify_sidecars(self.archive, self.output, self.source, self.version,
                                pending_checksums=pending_checksums)

    def update_provenance(self, change):
        path = self.output / (self.archive.name + ".provenance.json")
        value = json.loads(path.read_bytes())
        change(value)
        path.write_bytes(sbom.canonical(value))

    def rejected(self, message):
        with self.assertRaisesRegex((ValueError, RuntimeError, OSError), message):
            self.run_generator()
        self.assertFalse(self.output.exists())

    def test_complete_inventory_digests_not_complete_static_dependency_claim(self):
        self.pack()
        bom, provenance = self.run_generator()
        self.assertEqual(bom["bomFormat"], "CycloneDX")
        self.assertEqual(bom["specVersion"], "1.6")
        self.assertEqual(bom["compositions"], [{"aggregate": "incomplete"}])
        self.assertEqual(len(provenance["files"]), 9)
        self.assertEqual(len(provenance["licenses"]), 2)
        self.assertEqual(provenance["source"]["sha"], self.source)
        self.assertNotEqual(provenance["generator"]["head"], self.source)
        self.assertFalse(provenance["signed"])
        host = next(c for c in bom["components"] if c["bom-ref"] == "host:libc.so.6")
        self.assertNotIn("version", host)
        self.assertNotIn("licenses", host)
        for row in provenance["files"]:
            self.assertEqual(row["sha256"], sbom.file_hash(self.root / row["path"]))
        sums = (self.output / "sha256sums.txt").read_text().splitlines()
        self.assertEqual(len(sums), 3)
        for line in sums:
            digest, name = line.split("  ")
            target = self.archive if name == self.archive.name else self.output / name
            self.assertEqual(digest, sbom.file_hash(target))

    def test_deterministic_bytes(self):
        self.pack()
        self.run_generator()
        first = {p.name: p.read_bytes() for p in self.output.iterdir()}
        self.output = self.work / "second"
        self.run_generator()
        self.assertEqual(first, {p.name: p.read_bytes() for p in self.output.iterdir()})

    def test_generated_sidecars_verify_against_archive(self):
        self.pack()
        self.run_generator()
        self.verify()

    def test_sidecar_inventory_corruption_rejected(self):
        self.pack()
        self.run_generator()
        self.update_provenance(lambda p: p["files"].pop())
        with self.assertRaisesRegex(ValueError, "inventory mismatch"):
            self.verify()

    def test_sidecar_sbom_corruption_even_with_updated_hash_rejected(self):
        self.pack()
        self.run_generator()
        path = self.output / (self.archive.name + ".sbom.json")
        value = json.loads(path.read_bytes())
        value["components"].pop()
        path.write_bytes(sbom.canonical(value))
        self.update_provenance(lambda p: p["sbom"].update(sha256=sbom.file_hash(path)))
        with self.assertRaisesRegex(ValueError, "SBOM content"):
            self.verify()

    def test_sidecar_metadata_corruption_rejected(self):
        self.pack()
        self.run_generator()
        path = self.output / (self.archive.name + ".provenance.json")
        original = path.read_bytes()
        for change, message in (
            (lambda p: p.update(signed=True), "signed"),
            (lambda p: p["source"].update(tool_version="invented"), "source/version"),
            (lambda p: p["recipe"].update(source_sha="0" * 40), "recipe source"),
            (lambda p: p["recipe"].update(commands=[]), "commands"),
            (lambda p: p["generator"]["files"].update({"scripts/generate_sbom.py": "0" * 64}), "generator source"),
            (lambda p: p["sbom"].update(sha256="0" * 64), "SBOM checksum")):
            with self.subTest(message=message):
                path.write_bytes(original)
                self.update_provenance(change)
                with self.assertRaisesRegex(ValueError, message):
                    self.verify()

    def test_unverified_trust_claim_rejected(self):
        self.pack()
        self.run_generator()
        self.update_provenance(lambda p: p.update(trust="Cryptographically authenticated independent producer attestation"))
        with self.assertRaisesRegex(ValueError, "trust"):
            self.verify()

    def test_existing_checksum_companion_must_agree(self):
        self.pack()
        self.run_generator()
        (self.output / "sha256sums.txt").write_bytes(b"inconsistent checksum companion\n")
        with self.assertRaisesRegex(ValueError, "checksum companion"):
            self.verify()
        with self.assertRaisesRegex(ValueError, "checksum companion"):
            self.verify(pending_checksums=True)

    def test_missing_checksum_companion_needs_explicit_aggregation(self):
        self.pack()
        self.run_generator()
        (self.output / "sha256sums.txt").unlink()
        with self.assertRaisesRegex(ValueError, "checksum companion missing"):
            self.verify()
        self.verify(pending_checksums=True)

    def test_changed_archive_rejected(self):
        self.pack()
        self.evidence["archive_sha256"] = "0" * 64
        self.rejected("checksum")

    def test_changed_binary_rejected(self):
        self.pack()
        self.evidence["binary_sha256"] = "0" * 64
        self.rejected("binary checksum")

    def test_source_and_recipe_must_agree(self):
        self.pack()
        self.evidence["recipe"]["source_sha"] = "0" * 40
        self.rejected("recipe source")

    def test_source_must_be_full_commit(self):
        self.pack()
        self.evidence["source_sha"] = self.source[:12]
        self.rejected("full source SHA")

    def test_native_report_version_mismatch(self):
        self.pack()
        self.report.write_bytes(sbom.canonical({"tool": "CodeSkeptic", "schema": "codeskeptic-report/v1",
                                              "tool_version": "0.4.8"}))
        self.evidence["report"] = self.record(self.report)
        self.rejected("report/source identity")

    def test_native_report_schema_mismatch(self):
        self.pack()
        value = json.loads(self.report.read_bytes())
        value["schema"] = "invented"
        self.report.write_bytes(sbom.canonical(value))
        self.evidence["report"] = self.record(self.report)
        self.rejected("report/source identity")

    def test_capabilities_version_and_schema_mismatch(self):
        self.pack()
        original = self.caps.read_bytes()
        for key, value in (("version", "0.4.8"), ("schema_version", True), ("schema_version", 99)):
            with self.subTest(key=key, value=value):
                changed = json.loads(original)
                changed[key] = value
                self.caps.write_bytes(sbom.canonical(changed))
                self.evidence["capabilities"] = self.record(self.caps)
                self.rejected("capabilities/source identity")

    def test_native_evidence_digest_mismatch(self):
        self.pack()
        self.report.write_bytes(b"changed\n")
        self.rejected("evidence file checksum")

    def test_build_input_digest_mismatch(self):
        self.pack()
        self.log.write_bytes(b"changed\n")
        self.rejected("evidence file checksum")

    def test_missing_component_notice(self):
        (self.root / "licenses/llvm-20/copyright").unlink()
        self.pack()
        self.rejected("No such file")

    def test_missing_common_license(self):
        (self.root / "licenses/common/MIT").unlink()
        self.pack()
        self.rejected("common license missing")

    def test_license_index_must_cover_exact_components(self):
        index = self.root / "licenses/INDEX.tsv"
        original = index.read_bytes()
        variants = [b"\n".join(original.splitlines()[:2]) + b"\n",
                    original + original.splitlines()[1] + b"\n",
                    original + b"lib/not-shipped.so\tllvm-20\t20.1.2\tlicenses/llvm-20/copyright\n",
                    original.replace(b"lib/clang/20/include\tllvm-20\t20.1.2", b"lib/clang/20/include\tllvm-20\t19.0")]
        for variant in variants:
            with self.subTest(index=variant[:20]):
                index.write_bytes(variant)
                self.pack()
                self.rejected("component|closure|conflicting package")

    def test_extra_file_rejected(self):
        self.put("unexpected-file", b"unclassified\n")
        self.pack()
        self.rejected("unclassified")

    def test_llvm_resource_major_mismatch(self):
        (self.root / "lib/libLLVM.so.20.1").rename(self.root / "lib/libLLVM.so.19.1")
        self.pack()
        self.rejected("LLVM/resource major")

    def test_dependency_closure_must_agree(self):
        path = self.root / "DEPENDENCIES.txt"
        original = path.read_bytes()
        for changed in (original.replace(b"bundled lib/libLLVM.so.20.1\n", b""),
                        original + b"host libLLVM.so.20.1\n", original + b"host libc.so.6\n",
                        original.replace(b"Clang resource major: 20", b"Clang resource major: 19")):
            with self.subTest(value=changed[-30:]):
                path.write_bytes(changed)
                self.pack()
                self.rejected("closure|also declared|duplicate|identity")

    def test_project_license_source_mismatch(self):
        self.put("LICENSE", b"different license\n")
        self.pack()
        self.rejected("LICENSE/source mismatch")

    def test_recipe_requires_nonempty_commands_tools_and_inputs(self):
        self.pack()
        original = copy.deepcopy(self.evidence)
        for key, empty in (("commands", []), ("toolchain", {}), ("inputs", [])):
            with self.subTest(key=key):
                self.evidence = copy.deepcopy(original)
                self.evidence["recipe"][key] = empty
                self.rejected("required|invalid toolchain")

    def test_duplicate_input_names_rejected(self):
        self.pack()
        self.evidence["recipe"]["inputs"] *= 2
        self.rejected("duplicate recipe input")

    def test_json_duplicates_nonfinite_and_unknown_fields_rejected(self):
        for data in (b'{"key":1,"key":2}', b'{"key":NaN}'):
            with self.subTest(data=data), self.assertRaises(ValueError):
                sbom.parse_json(data)
        self.pack()
        self.evidence["signed"] = True
        self.rejected("build evidence fields")

    def test_unsafe_archive_paths_and_links_rejected(self):
        for name, kind in ((self.name + "/../escape", tarfile.REGTYPE),
                           (self.name + "/link", tarfile.SYMTYPE)):
            with self.subTest(kind=kind):
                with tarfile.open(self.archive, "w:gz") as archive:
                    entry = tarfile.TarInfo(name)
                    entry.type = kind
                    if kind == tarfile.SYMTYPE:
                        entry.linkname = "LICENSE"
                    archive.addfile(entry, io.BytesIO())
                self.evidence["archive_sha256"] = sbom.file_hash(self.archive)
                self.rejected("unsafe|unsupported|links")

    def test_existing_output_and_symlink_preserved(self):
        self.pack()
        self.output.mkdir()
        sentinel = self.output / "sentinel"
        sentinel.write_bytes(b"preserve")
        with self.assertRaisesRegex(ValueError, "output exists"):
            self.run_generator()
        self.assertEqual(sentinel.read_bytes(), b"preserve")
        self.output = self.work / "link"
        self.output.symlink_to(self.work / "sidecars", target_is_directory=True)
        with self.assertRaisesRegex(ValueError, "output exists"):
            self.run_generator()
        self.assertEqual(sentinel.read_bytes(), b"preserve")

    def test_symlink_evidence_input_rejected(self):
        self.pack()
        link = self.work / "report-link"
        link.symlink_to(self.report)
        self.evidence["report"]["path"] = str(link)
        self.rejected("symbolic links")

    def test_dirty_generator_bytes_rejected(self):
        with patch.object(sbom, "git", side_effect=[(self.source + "\n").encode(), b"different"]):
            with self.assertRaisesRegex(ValueError, "not committed"):
                sbom.generator_identity(sbom.REPO)

    def test_wrong_source_version_rejected(self):
        with self.assertRaisesRegex(ValueError, "package/source version"):
            sbom.source_identity(sbom.REPO, self.source, "0.4.9-dev+g000000000000")

    def test_wrapper_and_hosted_sidecars_are_explicit_and_checksum_bound(self):
        wrapper = (sbom.REPO / "scripts/package_release.sh").read_text()
        workflow = (sbom.REPO / ".github/workflows/release.yml").read_text()
        self.assertIn('"${1:-}" = --provenance', wrapper)
        self.assertIn('generate "$2" "$3" "$4"', wrapper)
        self.assertIn('exec python3 -B scripts/package_linux.py "$BIN" "$OUT" "$CLANG"', wrapper)
        self.assertIn('dist/provenance/*.sbom.json dist/provenance/*.provenance.json', workflow)
        self.assertIn("-p '*.sbom.json' -p '*.provenance.json'", workflow)
        self.assertIn('sha256sum *.tar.gz *.zip *.sbom.json *.provenance.json', workflow)
        self.assertEqual(workflow.count('scripts/generate_sbom.py verify'), 2)
        self.assertIn('--source-sha "$GITHUB_SHA" --version "${GITHUB_REF_NAME#v}"', workflow)


if __name__ == "__main__":
    unittest.main()
