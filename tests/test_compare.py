"""Unit and integration tests for compare.py and complete SENTINEL workflow."""

import unittest
from pathlib import Path

from compare import (
    CLASSIFICATION_EXISTING_WEAKNESS,
    CLASSIFICATION_NEW_WEAKNESS,
    CLASSIFICATION_NO_WEAKNESS,
    CLASSIFICATION_RESOLVED_WEAKNESS,
    classify_outcome,
    compare_rule_results,
)
from config import load_config
from rules import evaluate_rules


class TestChangeImpactComparison(unittest.TestCase):
    """Test suite covering the 2x2 comparison matrix and dependency break detection."""

    def test_classify_outcome_pass_to_pass(self) -> None:
        """Original Pass, Proposed Pass -> No weakness detected."""
        outcome = classify_outcome(orig_passed=True, prop_passed=True)
        self.assertEqual(outcome, CLASSIFICATION_NO_WEAKNESS)

    def test_classify_outcome_pass_to_fail(self) -> None:
        """Original Pass, Proposed Fail -> New weakness."""
        outcome = classify_outcome(orig_passed=True, prop_passed=False)
        self.assertEqual(outcome, CLASSIFICATION_NEW_WEAKNESS)

    def test_classify_outcome_fail_to_pass(self) -> None:
        """Original Fail, Proposed Pass -> Resolved weakness."""
        outcome = classify_outcome(orig_passed=False, prop_passed=True)
        self.assertEqual(outcome, CLASSIFICATION_RESOLVED_WEAKNESS)

    def test_classify_outcome_fail_to_fail(self) -> None:
        """Original Fail, Proposed Fail -> Existing weakness."""
        outcome = classify_outcome(orig_passed=False, prop_passed=False)
        self.assertEqual(outcome, CLASSIFICATION_EXISTING_WEAKNESS)

    def test_firewall_pass_to_fail_new_weakness(self) -> None:
        """Disabling firewall should be classified as a New weakness with recommendation."""
        orig_cfg = {
            "firewall_enabled": True,
            "password_min_length": 10,
            "api_exposure": "internal",
            "authentication_required": False,
        }
        prop_cfg = {
            "firewall_enabled": False,
            "password_min_length": 10,
            "api_exposure": "internal",
            "authentication_required": False,
        }

        orig_res = evaluate_rules(orig_cfg)
        prop_res = evaluate_rules(prop_cfg)
        report = compare_rule_results(orig_cfg, prop_cfg, orig_res, prop_res)

        firewall_finding = next(f for f in report.findings if f.rule_id == "RULE_FIREWALL")
        self.assertEqual(firewall_finding.classification, CLASSIFICATION_NEW_WEAKNESS)
        self.assertTrue(firewall_finding.original_passed)
        self.assertFalse(firewall_finding.proposed_passed)
        self.assertIsNotNone(firewall_finding.recommendation)
        self.assertEqual(report.new_weaknesses_count, 1)

    def test_password_fail_to_pass_resolved_weakness(self) -> None:
        """Increasing password length from 6 to 12 should resolve weakness."""
        orig_cfg = {
            "firewall_enabled": True,
            "password_min_length": 6,
            "api_exposure": "internal",
            "authentication_required": False,
        }
        prop_cfg = {
            "firewall_enabled": True,
            "password_min_length": 12,
            "api_exposure": "internal",
            "authentication_required": False,
        }

        orig_res = evaluate_rules(orig_cfg)
        prop_res = evaluate_rules(prop_cfg)
        report = compare_rule_results(orig_cfg, prop_cfg, orig_res, prop_res)

        pwd_finding = next(f for f in report.findings if f.rule_id == "RULE_PASSWORD_LENGTH")
        self.assertEqual(pwd_finding.classification, CLASSIFICATION_RESOLVED_WEAKNESS)
        self.assertFalse(pwd_finding.original_passed)
        self.assertTrue(pwd_finding.proposed_passed)
        self.assertEqual(report.resolved_weaknesses_count, 1)

    def test_existing_weakness_persisting(self) -> None:
        """Weakness present in both configurations should be classified as Existing weakness."""
        orig_cfg = {
            "firewall_enabled": False,
            "password_min_length": 10,
            "api_exposure": "internal",
            "authentication_required": False,
        }
        prop_cfg = {
            "firewall_enabled": False,
            "password_min_length": 10,
            "api_exposure": "internal",
            "authentication_required": False,
        }

        orig_res = evaluate_rules(orig_cfg)
        prop_res = evaluate_rules(prop_cfg)
        report = compare_rule_results(orig_cfg, prop_cfg, orig_res, prop_res)

        firewall_finding = next(f for f in report.findings if f.rule_id == "RULE_FIREWALL")
        self.assertEqual(firewall_finding.classification, CLASSIFICATION_EXISTING_WEAKNESS)
        self.assertFalse(firewall_finding.original_passed)
        self.assertFalse(firewall_finding.proposed_passed)
        self.assertEqual(report.existing_weaknesses_count, 1)


class TestIntegrationSampleConfigurations(unittest.TestCase):
    """Integration test suite executing the complete pipeline against sample input files."""

    def test_sample_files_silent_dependency_break(self) -> None:
        """Integration test using original.json and proposed.json.

        Expected outcomes:
        - Firewall: PASS in original, PASS in proposed -> No weakness detected
        - Password length: PASS in original, PASS in proposed -> No weakness detected
        - API auth dependency: PASS in original, FAIL in proposed -> New weakness
        - New weaknesses: 1
        - Resolved weaknesses: 0
        - Existing weaknesses: 0
        - Silent dependency break correctly identified:
          * api_exposure changed from 'internal' to 'public'
          * authentication_required remained False
        """
        orig_path = Path("original.json")
        prop_path = Path("proposed.json")

        self.assertTrue(orig_path.exists(), "original.json must exist")
        self.assertTrue(prop_path.exists(), "proposed.json must exist")

        orig_cfg = load_config(orig_path)
        prop_cfg = load_config(prop_path)

        orig_res = evaluate_rules(orig_cfg)
        prop_res = evaluate_rules(prop_cfg)

        # Rule evaluation assertions
        self.assertTrue(orig_res["RULE_FIREWALL"].passed)
        self.assertTrue(prop_res["RULE_FIREWALL"].passed)

        self.assertTrue(orig_res["RULE_PASSWORD_LENGTH"].passed)
        self.assertTrue(prop_res["RULE_PASSWORD_LENGTH"].passed)

        self.assertTrue(orig_res["RULE_API_AUTH_DEPENDENCY"].passed)
        self.assertFalse(prop_res["RULE_API_AUTH_DEPENDENCY"].passed)

        # Comparison assertions
        report = compare_rule_results(orig_cfg, prop_cfg, orig_res, prop_res)

        self.assertEqual(report.new_weaknesses_count, 1)
        self.assertEqual(report.resolved_weaknesses_count, 0)
        self.assertEqual(report.existing_weaknesses_count, 0)
        self.assertEqual(report.no_weakness_count, 2)

        api_finding = next(f for f in report.findings if f.rule_id == "RULE_API_AUTH_DEPENDENCY")
        self.assertEqual(api_finding.classification, CLASSIFICATION_NEW_WEAKNESS)
        self.assertTrue(api_finding.original_passed)
        self.assertFalse(api_finding.proposed_passed)
        self.assertIsNotNone(api_finding.recommendation)

        # Silent dependency break assertions
        self.assertEqual(len(report.silent_dependency_breaks), 1)
        break_info = report.silent_dependency_breaks[0]
        self.assertTrue(break_info.is_silent_break)
        self.assertEqual(break_info.changed_setting, "api_exposure")
        self.assertEqual(break_info.changed_from, "internal")
        self.assertEqual(break_info.changed_to, "public")
        self.assertEqual(break_info.affected_unchanged_setting, "authentication_required")
        self.assertEqual(break_info.affected_unchanged_value, False)
        self.assertIn("authentication", break_info.why_unsafe.lower())
        self.assertIn("authentication_required", break_info.corrective_action)


if __name__ == "__main__":
    unittest.main()
