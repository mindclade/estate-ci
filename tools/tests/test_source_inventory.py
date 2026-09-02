from __future__ import annotations

import json
import shutil
import sys
import tempfile
import unittest
from pathlib import Path


TOOLS = Path(__file__).resolve().parents[1]
ROOT = TOOLS.parent
sys.path.insert(0, str(TOOLS))

from verify_source_inventory import VerificationError, verify  # noqa: E402


class SourceInventoryTest(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        shutil.copytree(ROOT / "generated", self.root / "generated")
        (self.root / "ci").mkdir()
        shutil.copy2(ROOT / "ci/source-inventory.json", self.root / "ci/source-inventory.json")
        shutil.copy2(ROOT / "ci/required-workflow-profile.json", self.root / "ci/required-workflow-profile.json")
        inventory = json.loads((ROOT / "ci/source-inventory.json").read_text())
        for name in inventory["required_sources"]:
            source = ROOT / name
            destination = self.root / name
            if destination.exists():
                continue
            destination.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(source, destination)

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def test_approved_inventory_verifies(self) -> None:
        verify(self.root)

    def test_modified_artifact_fails_closed(self) -> None:
        path = self.root / "generated/bazelrc.common"
        path.write_text(path.read_text() + "# drift\n")
        with self.assertRaisesRegex(VerificationError, "digest drift"):
            verify(self.root)

    def test_unexpected_generated_artifact_fails_closed(self) -> None:
        (self.root / "generated/unreviewed.txt").write_text("unexpected")
        with self.assertRaisesRegex(VerificationError, "directory drift"):
            verify(self.root)

    def test_local_required_workflow_fails_closed(self) -> None:
        workflow_dir = self.root / ".github/workflows"
        workflow_dir.mkdir(parents=True)
        with self.assertRaisesRegex(VerificationError, "forbidden"):
            verify(self.root)

    def test_local_required_workflow_file_fails_closed(self) -> None:
        workflow = self.root / ".github/workflows/required.yml"
        workflow.parent.mkdir(parents=True)
        workflow.write_text("name: Pull request\n")
        with self.assertRaisesRegex(VerificationError, "forbidden"):
            verify(self.root)


if __name__ == "__main__":
    unittest.main()
