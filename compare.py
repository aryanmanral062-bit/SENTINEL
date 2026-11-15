"""Change Impact Analysis Module for SENTINEL.

Compares security evaluation results of original and proposed configurations,
classifies outcomes into standard security impact categories, detects
silent dependency breaks between interacting settings, and generates
clear explanations and corrective recommendations.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, List, Optional

from rules import RuleResult


# Classification Constants
CLASSIFICATION_NO_WEAKNESS = "No weakness detected"
CLASSIFICATION_NEW_WEAKNESS = "New weakness"
CLASSIFICATION_RESOLVED_WEAKNESS = "Resolved weakness"
CLASSIFICATION_EXISTING_WEAKNESS = "Existing weakness"


@dataclass(frozen=True)
class DependencyBreakInfo:
    """Detailed information regarding a detected silent dependency break."""

    is_silent_break: bool
    changed_setting: str
    changed_from: Any
    changed_to: Any
    affected_unchanged_setting: str
    affected_unchanged_value: Any
    why_unsafe: str
    corrective_action: str


@dataclass(frozen=True)
class Finding:
    """Security finding comparing original and proposed evaluation for a single rule."""

    rule_id: str
    rule_name: str
    original_passed: bool
    proposed_passed: bool
    classification: str
    explanation: str
    recommendation: Optional[str]
    dependency_break: Optional[DependencyBreakInfo] = None


@dataclass(frozen=True)
class ComparisonReport:
    """Aggregated analysis report summarizing findings across all rules."""

    findings: List[Finding]
    new_weaknesses_count: int
    resolved_weaknesses_count: int
    existing_weaknesses_count: int
    no_weakness_count: int
    silent_dependency_breaks: List[DependencyBreakInfo]


def classify_outcome(orig_passed: bool, prop_passed: bool) -> str:
    """Classify the comparison outcome according to the 2x2 security matrix.

    | Original | Proposed | Classification         |
    |----------|----------|------------------------|
    | Pass     | Pass     | No weakness detected   |
    | Pass     | Fail     | New weakness           |
    | Fail     | Pass     | Resolved weakness      |
    | Fail     | Fail     | Existing weakness      |
    """
    if orig_passed and prop_passed:
        return CLASSIFICATION_NO_WEAKNESS
    elif orig_passed and not prop_passed:
        return CLASSIFICATION_NEW_WEAKNESS
    elif not orig_passed and prop_passed:
        return CLASSIFICATION_RESOLVED_WEAKNESS
    else:
        return CLASSIFICATION_EXISTING_WEAKNESS


def analyze_dependency_break(
    original_config: Dict[str, Any],
    proposed_config: Dict[str, Any],
    orig_passed: bool,
    prop_passed: bool,
) -> Optional[DependencyBreakInfo]:
    """Analyze API authentication dependency to identify silent dependency breaks.

    A silent dependency break occurs when a setting (e.g., api_exposure) changes,
    while another setting (e.g., authentication_required) remains unchanged,
    causing the unchanged setting to become inadequate and creating a new vulnerability.
    """
    # Only relevant when rule went from passing to failing
    if not (orig_passed and not prop_passed):
        return None

    orig_exposure = original_config.get("api_exposure")
    prop_exposure = proposed_config.get("api_exposure")
    orig_auth = original_config.get("authentication_required")
    prop_auth = proposed_config.get("authentication_required")

    # Scenario: api_exposure changed from internal to public, while authentication_required was left false
    if orig_exposure != prop_exposure and prop_exposure == "public" and orig_auth == prop_auth:
        return DependencyBreakInfo(
            is_silent_break=True,
            changed_setting="api_exposure",
            changed_from=orig_exposure,
            changed_to=prop_exposure,
            affected_unchanged_setting="authentication_required",
            affected_unchanged_value=prop_auth,
            why_unsafe=(
                f"Setting 'api_exposure' changed from '{orig_exposure}' to '{prop_exposure}', "
                f"but 'authentication_required' remained unchanged as '{prop_auth}'. "
                "Exposing services to the public internet without requiring authentication permits "
                "unauthorized and anonymous external requests."
            ),
            corrective_action=(
                "Enable authentication by setting 'authentication_required': true, "
                "or revert 'api_exposure' to 'internal' if external access is not intended."
            ),
        )

    return None


def compare_rule_results(
    original_config: Dict[str, Any],
    proposed_config: Dict[str, Any],
    original_results: Dict[str, RuleResult],
    proposed_results: Dict[str, RuleResult],
) -> ComparisonReport:
    """Compare evaluation results produced by rules.py for original and proposed configurations.

    Args:
        original_config: Validated original configuration dictionary.
        proposed_config: Validated proposed configuration dictionary.
        original_results: Rule evaluation results for original configuration.
        proposed_results: Rule evaluation results for proposed configuration.

    Returns:
        A ComparisonReport containing structured findings and statistics.
    """
    findings: List[Finding] = []
    silent_breaks: List[DependencyBreakInfo] = []

    for rule_id, orig_res in original_results.items():
        prop_res = proposed_results[rule_id]
        orig_passed = orig_res.passed
        prop_passed = prop_res.passed
        classification = classify_outcome(orig_passed, prop_passed)

        explanation = ""
        recommendation: Optional[str] = None
        dep_break: Optional[DependencyBreakInfo] = None

        if rule_id == "RULE_FIREWALL":
            orig_val = original_config["firewall_enabled"]
            prop_val = proposed_config["firewall_enabled"]
            if classification == CLASSIFICATION_NO_WEAKNESS:
                explanation = "Firewall remains enabled in both configurations. Active perimeter defense maintained."
            elif classification == CLASSIFICATION_NEW_WEAKNESS:
                explanation = (
                    f"Firewall state changed from enabled ({orig_val}) to disabled ({prop_val}). "
                    "This removes network perimeter protection and introduces a critical vulnerability."
                )
                recommendation = "Re-enable the firewall by setting 'firewall_enabled': true."
            elif classification == CLASSIFICATION_RESOLVED_WEAKNESS:
                explanation = (
                    f"Firewall state changed from disabled ({orig_val}) to enabled ({prop_val}). "
                    "Perimeter defense has been successfully restored."
                )
            else:  # Existing weakness
                explanation = "Firewall is disabled in both configurations. Persistent perimeter exposure."
                recommendation = "Enable the firewall by setting 'firewall_enabled': true."

        elif rule_id == "RULE_PASSWORD_LENGTH":
            orig_len = original_config["password_min_length"]
            prop_len = proposed_config["password_min_length"]
            if classification == CLASSIFICATION_NO_WEAKNESS:
                if orig_len != prop_len:
                    explanation = (
                        f"Password minimum length changed from {orig_len} to {prop_len}, "
                        "both meeting or exceeding the minimum requirement of 8 characters."
                    )
                else:
                    explanation = (
                        f"Password minimum length remains {orig_len} characters (threshold is 8)."
                    )
            elif classification == CLASSIFICATION_NEW_WEAKNESS:
                explanation = (
                    f"Password minimum length was reduced from {orig_len} to {prop_len}, "
                    "which is below the required security threshold of 8 characters."
                )
                recommendation = (
                    f"Increase 'password_min_length' to at least 8 characters (currently {prop_len})."
                )
            elif classification == CLASSIFICATION_RESOLVED_WEAKNESS:
                explanation = (
                    f"Password minimum length increased from {orig_len} to {prop_len}, "
                    "satisfying the minimum security threshold of 8 characters."
                )
            else:  # Existing weakness
                explanation = (
                    f"Password minimum length remains non-compliant ({orig_len} -> {prop_len}; required >= 8)."
                )
                recommendation = (
                    f"Increase 'password_min_length' to at least 8 characters (currently {prop_len})."
                )

        elif rule_id == "RULE_API_AUTH_DEPENDENCY":
            orig_exp = original_config["api_exposure"]
            prop_exp = proposed_config["api_exposure"]
            orig_auth = original_config["authentication_required"]
            prop_auth = proposed_config["authentication_required"]

            # Perform dependency break inspection
            dep_break = analyze_dependency_break(
                original_config, proposed_config, orig_passed, prop_passed
            )

            if dep_break and dep_break.is_silent_break:
                silent_breaks.append(dep_break)
                explanation = (
                    f"Silent dependency break detected: 'api_exposure' changed from '{orig_exp}' to '{prop_exp}' "
                    f"while 'authentication_required' remained unchanged as {prop_auth}. "
                    "A public API without authentication creates an unauthorized entry point."
                )
                recommendation = dep_break.corrective_action
            elif classification == CLASSIFICATION_NO_WEAKNESS:
                if orig_exp == prop_exp and orig_auth == prop_auth:
                    explanation = (
                        f"API policy remains unchanged (exposure: '{prop_exp}', auth_required: {prop_auth}). "
                        "Security requirements are satisfied."
                    )
                else:
                    explanation = (
                        f"API configuration updated safely (exposure: '{orig_exp}' -> '{prop_exp}', "
                        f"auth_required: {orig_auth} -> {prop_auth})."
                    )
            elif classification == CLASSIFICATION_NEW_WEAKNESS:
                # Direct downgrade (e.g. was public+auth=true -> public+auth=false)
                explanation = (
                    f"API exposure is '{prop_exp}' but authentication requirement changed from {orig_auth} to {prop_auth}. "
                    "Disabling authentication on a public endpoint exposes it to unauthorized access."
                )
                recommendation = "Re-enable authentication by setting 'authentication_required': true."
            elif classification == CLASSIFICATION_RESOLVED_WEAKNESS:
                explanation = (
                    f"API configuration security weakness resolved (exposure: '{orig_exp}' -> '{prop_exp}', "
                    f"auth_required: {orig_auth} -> {prop_auth})."
                )
            else:  # Existing weakness
                explanation = (
                    f"API remains publicly exposed without authentication ({prop_exp}, auth: {prop_auth}). "
                    "Unrestricted anonymous access persists."
                )
                recommendation = "Enforce authentication by setting 'authentication_required': true."

        findings.append(
            Finding(
                rule_id=rule_id,
                rule_name=orig_res.rule_name,
                original_passed=orig_passed,
                proposed_passed=prop_passed,
                classification=classification,
                explanation=explanation,
                recommendation=recommendation,
                dependency_break=dep_break,
            )
        )

    # Compute summary counts
    new_count = sum(1 for f in findings if f.classification == CLASSIFICATION_NEW_WEAKNESS)
    resolved_count = sum(1 for f in findings if f.classification == CLASSIFICATION_RESOLVED_WEAKNESS)
    existing_count = sum(1 for f in findings if f.classification == CLASSIFICATION_EXISTING_WEAKNESS)
    no_weakness_count = sum(1 for f in findings if f.classification == CLASSIFICATION_NO_WEAKNESS)

    return ComparisonReport(
        findings=findings,
        new_weaknesses_count=new_count,
        resolved_weaknesses_count=resolved_count,
        existing_weaknesses_count=existing_count,
        no_weakness_count=no_weakness_count,
        silent_dependency_breaks=silent_breaks,
    )
