#!/usr/bin/env python3
"""Contract tests for release-triggered Docker source and version identity."""

from __future__ import annotations

import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
WORKFLOW = ROOT / ".github" / "workflows" / "docker.yml"
DOCKERFILE = ROOT / "Dockerfile"


class DockerWorkflowTest(unittest.TestCase):
    def test_one_time_legacy_cleanup_is_exact_and_fail_closed(self) -> None:
        workflow = WORKFLOW.read_text(encoding="utf-8")

        self.assertIn("Remove exact legacy v0.4.9 package version", workflow)
        self.assertIn("LEGACY_TAG: v0.4.9", workflow)
        self.assertIn(
            "LEGACY_DIGEST: sha256:03b346e66f1b292a5c2a1ddd1b5cb9190d21899077b6d646eee115f320d6197c",
            workflow,
        )
        self.assertNotIn("CURRENT_DIGEST:", workflow)
        self.assertIn("current_digest=$(jq -r '.[0].name'", workflow)
        self.assertIn('[[ "$current_digest" =~ ^sha256:[0-9a-f]{64}$ ]]', workflow)
        self.assertIn('test "$current_digest" != "$LEGACY_DIGEST"', workflow)
        self.assertIn('--arg digest "$current_digest"', workflow)
        self.assertIn("current_before", workflow)
        self.assertIn("current_after", workflow)
        self.assertIn(
            "if: github.event_name == 'workflow_dispatch' && "
            "inputs.release_tag == 'v0.4.8'",
            workflow,
        )
        self.assertIn(".metadata.container.tags | length", workflow)
        for name in ("current_before", "matches", "current_after"):
            with self.subTest(singleton=name):
                self.assertIn(f'<<<"${name}")" -eq 1', workflow)
        self.assertIn('test "$tag_count" -eq 1', workflow)
        self.assertIn('test "$digest" = "$LEGACY_DIGEST"', workflow)
        self.assertIn("gh api --method DELETE", workflow)
        self.assertIn('test "$remaining" -eq 0', workflow)

    def test_release_rebuild_uses_current_recipe_with_exact_tag_source(self) -> None:
        workflow = WORKFLOW.read_text(encoding="utf-8")

        self.assertGreaterEqual(workflow.count("uses: actions/checkout@v4"), 2)
        self.assertIn("Checkout workflow source", workflow)
        self.assertIn("Checkout exact release source", workflow)
        self.assertIn("path: release-source", workflow)
        self.assertIn('context="release-source"', workflow)
        self.assertIn('-f "$PWD/Dockerfile"', workflow)

    def test_release_build_is_pinned_to_triggering_source_and_tag(self) -> None:
        workflow = WORKFLOW.read_text(encoding="utf-8")
        dockerfile = DOCKERFILE.read_text(encoding="utf-8")

        self.assertIn("github.event.workflow_run.head_sha", workflow)
        self.assertIn("github.event.workflow_run.head_branch", workflow)
        self.assertIn(
            '--build-arg "CODESKEPTIC_VERSION_OVERRIDE=${RELEASE_TAG#v}"',
            workflow,
        )
        self.assertIn('test "$RELEASE_TAG" = "v$VER"', workflow)
        self.assertIn('docker push "$IMG:$RELEASE_TAG"', workflow)
        self.assertNotIn("[docker-publish]", workflow)

        self.assertIn("workflow_dispatch:", workflow)
        self.assertIn("release_tag:", workflow)
        self.assertIn("inputs.release_tag", workflow)
        self.assertIn('gh release view "$RELEASE_TAG" --json isDraft', workflow)
        self.assertIn('test "$draft" = "false"', workflow)

        self.assertIn('ARG CODESKEPTIC_VERSION_OVERRIDE=""', dockerfile)
        self.assertIn(
            '-DCODESKEPTIC_VERSION_OVERRIDE="$CODESKEPTIC_VERSION_OVERRIDE"',
            dockerfile,
        )


if __name__ == "__main__":
    unittest.main()
