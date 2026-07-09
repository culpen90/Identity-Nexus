import sys
import tempfile
import tomllib
import unittest

from identity_nexus.config import DEFAULT_CONFIG

try:
    from fastapi.testclient import TestClient
    from identity_nexus.api import create_app
except (ImportError, RuntimeError) as exc:  # pragma: no cover - optional dependency guard
    raise unittest.SkipTest(str(exc))


def api_config():
    config = tomllib.loads(DEFAULT_CONFIG)
    config["service"]["data_dir"] = tempfile.mkdtemp(prefix="identity-nexus-api-test-")
    config["tools"] = {
        "fake": {
            "name": "Fake Tool",
            "enabled": True,
            "accepts": ["email"],
            "risk": "passive",
            "command": [sys.executable, "-c", "print('ok')", "{email}"],
            "timeout_seconds": 10,
        }
    }
    return config


class ApiTests(unittest.TestCase):
    def test_scan_requires_authorization(self):
        client = TestClient(create_app(api_config()))
        response = client.post("/api/scans", json={"target": "person@example.com"})

        self.assertEqual(response.status_code, 403)

    def test_creates_and_runs_dry_scan(self):
        client = TestClient(create_app(api_config()))
        response = client.post(
            "/api/scans",
            json={"target": "person@example.com", "authorized": True, "dry_run": True},
        )

        self.assertEqual(response.status_code, 200)
        scan_id = response.json()["scan_id"]
        saved = client.get(f"/api/scans/{scan_id}").json()
        self.assertEqual(saved["status"], "complete")
        self.assertEqual(saved["results"][0]["status"], "dry_run")


if __name__ == "__main__":
    unittest.main()
