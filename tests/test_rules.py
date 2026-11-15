"""Unit tests for rules.py in SENTINEL."""

import unittest

from rules import (
    PASSWORD_MIN_THRESHOLD,
    check_api_auth_dependency,
    check_firewall,
    check_password_length,
    evaluate_rules,
)


class TestSecurityRules(unittest.TestCase):
    """Test suite covering the three predefined security rules."""

    def test_firewall_enabled_passes(self) -> None:
        """Rule 1: Firewall Check passes when firewall_enabled is True."""
        config = {"firewall_enabled": True}
        result = check_firewall(config)
        self.assertTrue(result.passed)
        self.assertEqual(result.rule_id, "RULE_FIREWALL")
        self.assertEqual(result.rule_name, "Firewall Check")
        self.assertIn("enabled", result.details.lower())

    def test_firewall_disabled_fails(self) -> None:
        """Rule 1: Firewall Check fails when firewall_enabled is False."""
        config = {"firewall_enabled": False}
        result = check_firewall(config)
        self.assertFalse(result.passed)
        self.assertEqual(result.rule_id, "RULE_FIREWALL")
        self.assertIn("disabled", result.details.lower())

    def test_password_length_above_threshold_passes(self) -> None:
        """Rule 2: Password Length Check passes when password_min_length > 8."""
        config = {"password_min_length": 12}
        result = check_password_length(config)
        self.assertTrue(result.passed)
        self.assertEqual(result.rule_id, "RULE_PASSWORD_LENGTH")
        self.assertIn("meeting the security threshold", result.details.lower())

    def test_password_length_equal_threshold_passes(self) -> None:
        """Rule 2: Password Length Check passes when password_min_length == 8."""
        config = {"password_min_length": PASSWORD_MIN_THRESHOLD}
        result = check_password_length(config)
        self.assertTrue(result.passed)
        self.assertEqual(result.rule_id, "RULE_PASSWORD_LENGTH")

    def test_password_length_below_threshold_fails(self) -> None:
        """Rule 2: Password Length Check fails when password_min_length < 8."""
        config = {"password_min_length": 7}
        result = check_password_length(config)
        self.assertFalse(result.passed)
        self.assertEqual(result.rule_id, "RULE_PASSWORD_LENGTH")
        self.assertIn("below the required security threshold", result.details.lower())

    def test_internal_api_with_auth_disabled_passes(self) -> None:
        """Rule 3: API Auth Dependency Check passes when API is internal and auth is False."""
        config = {"api_exposure": "internal", "authentication_required": False}
        result = check_api_auth_dependency(config)
        self.assertTrue(result.passed)
        self.assertEqual(result.rule_id, "RULE_API_AUTH_DEPENDENCY")

    def test_internal_api_with_auth_enabled_passes(self) -> None:
        """Rule 3: API Auth Dependency Check passes when API is internal and auth is True."""
        config = {"api_exposure": "internal", "authentication_required": True}
        result = check_api_auth_dependency(config)
        self.assertTrue(result.passed)
        self.assertEqual(result.rule_id, "RULE_API_AUTH_DEPENDENCY")

    def test_public_api_with_auth_enabled_passes(self) -> None:
        """Rule 3: API Auth Dependency Check passes when API is public and auth is True."""
        config = {"api_exposure": "public", "authentication_required": True}
        result = check_api_auth_dependency(config)
        self.assertTrue(result.passed)
        self.assertEqual(result.rule_id, "RULE_API_AUTH_DEPENDENCY")

    def test_public_api_with_auth_disabled_fails(self) -> None:
        """Rule 3: API Auth Dependency Check fails when API is public and auth is False."""
        config = {"api_exposure": "public", "authentication_required": False}
        result = check_api_auth_dependency(config)
        self.assertFalse(result.passed)
        self.assertEqual(result.rule_id, "RULE_API_AUTH_DEPENDENCY")
        self.assertIn("authentication is disabled", result.details.lower())

    def test_evaluate_rules_returns_all_results(self) -> None:
        """evaluate_rules must evaluate all 3 rules independently."""
        config = {
            "firewall_enabled": True,
            "password_min_length": 10,
            "api_exposure": "internal",
            "authentication_required": False,
        }
        results = evaluate_rules(config)
        self.assertEqual(len(results), 3)
        self.assertIn("RULE_FIREWALL", results)
        self.assertIn("RULE_PASSWORD_LENGTH", results)
        self.assertIn("RULE_API_AUTH_DEPENDENCY", results)
        self.assertTrue(results["RULE_FIREWALL"].passed)
        self.assertTrue(results["RULE_PASSWORD_LENGTH"].passed)
        self.assertTrue(results["RULE_API_AUTH_DEPENDENCY"].passed)


if __name__ == "__main__":
    unittest.main()
