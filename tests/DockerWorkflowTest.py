#!/usr/bin/env python3
"""Contract tests for release-triggered Docker source and version identity."""

from __future__ import annotations

import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
WORKFLOW = ROOT / ".github" / "workflows" / "docker.yml"
DOCKERFILE = ROOT / "Dockerfile"


class DockerWorkflowTest(unittest.TestCase):
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
