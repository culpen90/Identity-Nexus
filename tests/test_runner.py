import sys
import tempfile
import tomllib
import unittest
from pathlib import Path

from identity_nexus.config import DEFAULT_CONFIG
from identity_nexus.models import (
    RESULT_DRY_RUN,
    RESULT_NOT_APPLICABLE,
    RESULT_OK,
    RESULT_SKIPPED,
    ScanRequest,
)
from identity_nexus.runner import AuthorizationRequired, NexusRunner


def fake_config(command, accepts=None, enabled=True, data_dir=None):
    config = tomllib.loads(DEFAULT_CONFIG)
    config["service"]["data_dir"] = data_dir or tempfile.mkdtemp(prefix="identity-nexus-test-")
    config["tools"] = {
        "fake": {
            "name": "Fake Tool",
            "enabled": enabled,
            "accepts": accepts or ["email"],
            "risk": "passive",
            "command": command,
            "timeout_seconds": 10,
        }
    }
    return config


class RunnerTests(unittest.TestCase):
    def test_requires_authorization_attestation(self):
        runner = NexusRunner(config=fake_config([sys.executable, "-c", "print('ok')"]))
        with self.assertRaises(AuthorizationRequired):
            runner.run(ScanRequest(target="person@example.com"))

    def test_executes_fake_email_tool_and_parses_json(self):
        command = [
            sys.executable,
            "-c",
            "import json, sys; print(json.dumps({'target': sys.argv[1]}))",
            "{email}",
        ]
        runner = NexusRunner(config=fake_config(command))
        record = runner.run(ScanRequest(target="Person@Example.com", authorized=True))

        self.assertEqual(record.results[0].status, RESULT_OK)
        self.assertEqual(record.results[0].parsed["stdout_json"]["target"], "person@example.com")

    def test_dry_run_uses_derived_username_for_email_targets(self):
        command = [sys.executable, "-c", "print('unused')", "{username}"]
        runner = NexusRunner(config=fake_config(command, accepts=["username"]))
        record = runner.run(
            ScanRequest(target="first.last+tag@example.com", authorized=True, dry_run=True)
        )

        self.assertEqual(record.results[0].status, RESULT_DRY_RUN)
        self.assertEqual(record.results[0].command[-1], "first.last")

    def test_explicit_incompatible_module_reports_not_applicable(self):
        runner = NexusRunner(config=fake_config([sys.executable, "-c", "print('unused')"]))
        record = runner.run(
            ScanRequest(target="+12125550100", authorized=True, modules=["fake"], dry_run=True)
        )

        self.assertEqual(record.results[0].status, RESULT_NOT_APPLICABLE)
        self.assertIn("not phone", record.results[0].message)

    def test_explicit_disabled_module_reports_skipped(self):
        runner = NexusRunner(
            config=fake_config([sys.executable, "-c", "print('unused')"], enabled=False)
        )
        record = runner.run(
            ScanRequest(target="person@example.com", authorized=True, modules=["fake"])
        )

        self.assertEqual(record.results[0].status, RESULT_SKIPPED)

    def test_artifacts_are_persistent(self):
        data_dir = tempfile.mkdtemp(prefix="identity-nexus-test-")
        command = [
            sys.executable,
            "-c",
            "from pathlib import Path; import sys; Path(sys.argv[1]).write_text('{\"ok\": true}')",
            "{output_json}",
        ]
        runner = NexusRunner(config=fake_config(command, data_dir=data_dir))
        record = runner.run(ScanRequest(target="person@example.com", authorized=True))

        artifact = Path(record.results[0].artifacts[0])
        self.assertTrue(artifact.exists())
        self.assertTrue(str(artifact).startswith(data_dir))


if __name__ == "__main__":
    unittest.main()
