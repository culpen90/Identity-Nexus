import tomllib
import unittest
from pathlib import Path

from identity_nexus.config import DEFAULT_CONFIG


class ConfigTests(unittest.TestCase):
    def test_example_config_matches_built_in_defaults(self):
        example = Path("configs/identity-nexus.example.toml").read_text(encoding="utf-8")

        self.assertEqual(tomllib.loads(example), tomllib.loads(DEFAULT_CONFIG))


if __name__ == "__main__":
    unittest.main()
