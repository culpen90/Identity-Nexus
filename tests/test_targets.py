import unittest

from identity_nexus.models import EMAIL, PHONE, USERNAME
from identity_nexus.targets import derive_username_from_email, detect_target_kind, normalize_target


class TargetTests(unittest.TestCase):
    def test_detects_email_phone_and_username(self):
        self.assertEqual(detect_target_kind("Person@example.com"), EMAIL)
        self.assertEqual(detect_target_kind("+1 (212) 555-0100"), PHONE)
        self.assertEqual(detect_target_kind("example_user"), USERNAME)

    def test_normalizes_email_and_phone(self):
        self.assertEqual(normalize_target(" Person@Example.com "), ("person@example.com", EMAIL))
        self.assertEqual(normalize_target("+1 (212) 555-0100"), ("+12125550100", PHONE))

    def test_derives_username_from_email_local_part(self):
        self.assertEqual(derive_username_from_email("First.Last+tag@example.com"), "First.Last")


if __name__ == "__main__":
    unittest.main()
