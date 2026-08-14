#!/usr/bin/env python3
"""Contract tests for the bounded Phase 10 parser-fuzz campaign."""

from __future__ import annotations

import hashlib
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "run_fuzz_campaign.py"
SPEC = importlib.util.spec_from_file_location("run_fuzz_campaign", SCRIPT)
assert SPEC and SPEC.loader
CAMPAIGN = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(CAMPAIGN)


class FuzzingContractTest(unittest.TestCase):
    def test_campaign_is_bounded_and_covers_exact_plan_surfaces(self) -> None:
        campaign = CAMPAIGN.load_campaign()
        self.assertEqual(
            [target["id"] for target in campaign["targets"]],
            ["config", "compile_database", "summary", "mcp_json_rpc"],
        )
        self.assertEqual(campaign["max_input_bytes"], 65536)
        self.assertEqual(campaign["input_timeout_seconds"], 5)
        self.assertEqual(campaign["rss_limit_mb"], 2048)
        self.assertEqual(campaign["modes"], CAMPAIGN.EXPECTED_MODES)
        self.assertEqual(campaign["targets"], CAMPAIGN.EXPECTED_TARGETS)
        for target in campaign["targets"]:
            command = CAMPAIGN.normalized_command(
                target, campaign["modes"]["smoke"])
            joined = " ".join(command)
            self.assertIn(f"-seed={target['seed']}", joined)
            self.assertIn("-runs=256", joined)
            self.assertIn("-max_len=$MAX_INPUT_BYTES", joined)
            self.assertIn("-timeout=$INPUT_TIMEOUT_SECONDS", joined)
            self.assertIn("-rss_limit_mb=$RSS_LIMIT_MB", joined)
            self.assertIn("-artifact_prefix=$ARTIFACT_DIR/", joined)

    def test_seed_corpus_is_exactly_checksummed(self) -> None:
        entries = CAMPAIGN.load_corpus_checksums()
        self.assertEqual(len(entries), 9)
        self.assertEqual(
            {Path(path).parts[0] for path in entries},
            {"config", "compile_database", "summary", "mcp_json_rpc"},
        )

    def test_real_fuzzer_targets_use_production_entry_points(self) -> None:
        expected = {
            "FuzzConfig.cpp": "loadFromText",
            "FuzzCompileDatabase.cpp": "validateCompilationDatabaseText",
            "FuzzSummary.cpp": "parseSummaryText",
            "FuzzMcpJsonRpc.cpp": "validateMcpMessage",
        }
        cmake = (ROOT / "fuzz" / "CMakeLists.txt").read_text(encoding="utf-8")
        for source, entry in expected.items():
            text = (ROOT / "fuzz" / source).read_text(encoding="utf-8")
            self.assertIn(entry, text)
            self.assertIn("LLVMFuzzerTestOneInput", text)
            self.assertIn(source, cmake)

    def test_source_manifest_binds_uncommitted_parser_and_fuzz_bytes(self) -> None:
        first = CAMPAIGN.source_manifest()
        second = CAMPAIGN.source_manifest()
        self.assertEqual(first, second)
        self.assertGreater(first["file_count"], 40)
        self.assertRegex(first["digest"], r"^[0-9a-f]{64}$")

    def test_ci_invokes_smoke_campaign_and_retains_receipt(self) -> None:
        workflow = (ROOT / ".github" / "workflows" / "ci.yml").read_text(
            encoding="utf-8")
        self.assertIn("python3 scripts/run_fuzz_campaign.py", workflow)
        self.assertIn("--mode smoke", workflow)
        self.assertIn("fuzz-smoke-receipt", workflow)
        self.assertIn("actions/upload-artifact@v4", workflow)

    def test_checksum_bound_fuzz_bytes_disable_line_ending_conversion(self) -> None:
        attributes = (ROOT / ".gitattributes").read_text(encoding="utf-8")
        self.assertIn("docs/evidence/phase10/fuzz/** -text\n", attributes)
        self.assertIn("fuzz/corpus/** -text\n", attributes)

    def test_receipt_writer_uses_canonical_bytes_and_checksum(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary)
            payload = {"schema": CAMPAIGN.RECEIPT_SCHEMA, "status": "accepted"}
            CAMPAIGN.write_receipt(output, payload)
            receipt = output / "receipt.json"
            expected = hashlib.sha256(receipt.read_bytes()).hexdigest()
            self.assertEqual(
                (output / "receipt.json.sha256").read_text(encoding="utf-8"),
                f"{expected}  receipt.json\n",
            )
            self.assertEqual(json.loads(receipt.read_text(encoding="utf-8")),
                             payload)

    def test_compiler_identity_accepts_cmake_cache_value_types(self) -> None:
        for cache_type in ("FILEPATH", "STRING", "UNINITIALIZED"):
            with self.subTest(cache_type=cache_type), \
                    tempfile.TemporaryDirectory() as temporary:
                build = Path(temporary)
                compiler = build / "clang++"
                compiler.write_text("binary-placeholder", encoding="utf-8")
                (build / "CMakeCache.txt").write_text(
                    f"CMAKE_CXX_COMPILER:{cache_type}={compiler}\n",
                    encoding="utf-8",
                )
                completed = mock.Mock(
                    returncode=0,
                    stdout="clang version test\nTarget: fixture\n",
                )
                with mock.patch.object(CAMPAIGN.subprocess, "run",
                                       return_value=completed):
                    identity = CAMPAIGN.compiler_identity(build)
                self.assertEqual(identity["path"], str(compiler))
                self.assertEqual(identity["version_first_line"],
                                 "clang version test")

    def test_receipt_verifier_rejects_tampering(self) -> None:
        retained = (ROOT / "docs" / "evidence" / "phase10" / "fuzz" /
                    "2026-08-13-macos-arm64")
        if not retained.is_dir():
            self.skipTest("extended receipt is not materialized")
        build = ROOT / "build-fuzz"
        if not build.is_dir():
            self.skipTest("fuzz build is not materialized")
        CAMPAIGN.verify_receipt(retained, build)
        with tempfile.TemporaryDirectory() as temporary:
            import shutil
            copied = Path(temporary) / "receipt"
            shutil.copytree(retained, copied)
            log = copied / "logs" / "config.log"
            log.write_bytes(b"fabricated success log\n")
            receipt_path = copied / "receipt.json"
            receipt = json.loads(receipt_path.read_text(encoding="utf-8"))
            receipt["targets"][0]["log_sha256"] = hashlib.sha256(
                log.read_bytes()).hexdigest()
            CAMPAIGN.write_receipt(copied, receipt)
            with self.assertRaisesRegex(CAMPAIGN.CampaignError,
                                        "completion evidence"):
                CAMPAIGN.verify_receipt(
                    copied, build, require_current_source=False)

    def test_receipt_verifier_rejects_appended_failure_after_done(self) -> None:
        retained = (ROOT / "docs" / "evidence" / "phase10" / "fuzz" /
                    "2026-08-13-macos-arm64")
        build = ROOT / "build-fuzz"
        if not retained.is_dir() or not build.is_dir():
            self.skipTest("extended receipt/build is not materialized")
        with tempfile.TemporaryDirectory() as temporary:
            import shutil
            copied = Path(temporary) / "receipt"
            shutil.copytree(retained, copied)
            log = copied / "logs" / "config.log"
            log.write_bytes(log.read_bytes() + b"CAMPAIGN WALL TIMEOUT\n")
            receipt_path = copied / "receipt.json"
            receipt = json.loads(receipt_path.read_text(encoding="utf-8"))
            receipt["targets"][0]["log_sha256"] = hashlib.sha256(
                log.read_bytes()).hexdigest()
            CAMPAIGN.write_receipt(copied, receipt)
            with self.assertRaisesRegex(CAMPAIGN.CampaignError,
                                        "completion evidence"):
                CAMPAIGN.verify_receipt(
                    copied, build, require_current_source=False)

    def test_receipt_verifier_binds_current_fuzzer_binaries(self) -> None:
        retained = (ROOT / "docs" / "evidence" / "phase10" / "fuzz" /
                    "2026-08-13-macos-arm64")
        build = ROOT / "build-fuzz"
        if not retained.is_dir() or not build.is_dir():
            self.skipTest("extended receipt/build is not materialized")
        original_resolver = CAMPAIGN.resolve_binary
        with tempfile.TemporaryDirectory() as temporary:
            fake = Path(temporary) / "codeskeptic_fuzz_config"
            fake.write_bytes(b"not the retained fuzzer binary")

            def resolve(build_dir: Path, name: str) -> Path:
                if name == "codeskeptic_fuzz_config":
                    return fake
                return original_resolver(build_dir, name)

            with mock.patch.object(CAMPAIGN, "resolve_binary",
                                   side_effect=resolve):
                with self.assertRaisesRegex(CAMPAIGN.CampaignError,
                                            "binary checksum mismatch"):
                    CAMPAIGN.verify_receipt(
                        retained, build, require_current_source=False)

    def test_receipt_source_base_can_precede_head_but_must_be_ancestor(self) -> None:
        retained = (ROOT / "docs" / "evidence" / "phase10" / "fuzz" /
                    "2026-08-13-macos-arm64")
        build = ROOT / "build-fuzz"
        if not retained.is_dir() or not build.is_dir():
            self.skipTest("extended receipt/build is not materialized")
        receipt = json.loads(
            (retained / "receipt.json").read_text(encoding="utf-8"))
        base = receipt["source"]["commit"]
        descendant = "f" * 40
        with mock.patch.object(CAMPAIGN, "git_commit",
                               return_value=descendant), \
                mock.patch.object(CAMPAIGN, "source_manifest",
                                  return_value=receipt["source"]["manifest"]), \
                mock.patch.object(CAMPAIGN, "git_commit_is_ancestor",
                                  return_value=True) as ancestry:
            CAMPAIGN.verify_receipt(retained, build)
            ancestry.assert_called_once_with(base, descendant)

        with mock.patch.object(CAMPAIGN, "git_commit",
                               return_value=descendant), \
                mock.patch.object(CAMPAIGN, "source_manifest",
                                  return_value=receipt["source"]["manifest"]), \
                mock.patch.object(CAMPAIGN, "git_commit_is_ancestor",
                                  return_value=False):
            with self.assertRaisesRegex(CAMPAIGN.CampaignError,
                                        "not an ancestor"):
                CAMPAIGN.verify_receipt(retained, build)

    def test_retained_extended_evidence_has_external_git_manifest(self) -> None:
        evidence = ROOT / "docs" / "evidence" / "phase10" / "fuzz"
        manifest = evidence / "SHA256SUMS"
        entries = {}
        for line in manifest.read_text(encoding="utf-8").splitlines():
            digest, separator, relative = line.partition("  ")
            self.assertTrue(separator)
            self.assertRegex(digest, r"^[0-9a-f]{64}$")
            self.assertNotIn(relative, entries)
            entries[relative] = digest
        expected = {
            path.relative_to(evidence).as_posix()
            for path in (evidence / "2026-08-13-macos-arm64").rglob("*")
            if path.is_file() and path.name != "receipt.json.sha256"
        }
        self.assertEqual(set(entries), expected)
        for relative, digest in entries.items():
            self.assertEqual(
                hashlib.sha256((evidence / relative).read_bytes()).hexdigest(),
                digest,
            )


if __name__ == "__main__":
    unittest.main()
