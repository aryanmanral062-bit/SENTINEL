"""Security Rules and Dependency Analysis Module for SENTINEL.

Evaluates simulated system configurations independently against three predefined
security rules:
1. Firewall Check
2. Password Length Check
3. API Authentication Dependency Check

This module evaluates configurations in isolation without classifying changes.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict


PASSWORD_MIN_THRESHOLD = 8


@dataclass(frozen=True)
class RuleResult:
    """Represents the structured outcome of a single security rule evaluation."""

    rule_id: str
    rule_name: str
    passed: bool
    details: str
    evaluated_values: Dict[str, Any]


def check_firewall(config: Dict[str, Any]) -> RuleResult:
    """Evaluate Rule 1: Firewall Check.

    Rule definition:
    - Firewall must be enabled.
    - If firewall_enabled is false, report a security failure.
    """
    is_enabled = config["firewall_enabled"]
    passed = bool(is_enabled)
    if passed:
        details = "Firewall is enabled, providing active network perimeter defense."
    else:
        details = "Firewall is disabled. System perimeter is exposed to unmonitored network traffic."

    return RuleResult(
        rule_id="RULE_FIREWALL",
        rule_name="Firewall Check",
        passed=passed,
        details=details,
        evaluated_values={"firewall_enabled": is_enabled},
    )


def check_password_length(config: Dict[str, Any]) -> RuleResult:
    """Evaluate Rule 2: Password Length Check.

    Rule definition:
    - Minimum password length must be at least 8.
    - If the value is below 8, report a security failure.
    """
    length = config["password_min_length"]
    passed = length >= PASSWORD_MIN_THRESHOLD
    if passed:
        details = (
            f"Minimum password length is set to {length}, "
            f"meeting the security threshold (minimum {PASSWORD_MIN_THRESHOLD} characters)."
        )
    else:
        details = (
            f"Minimum password length is set to {length}, "
            f"which is below the required security threshold ({PASSWORD_MIN_THRESHOLD} characters)."
        )

    return RuleResult(
        rule_id="RULE_PASSWORD_LENGTH",
        rule_name="Password Length Check",
        passed=passed,
        details=details,
        evaluated_values={"password_min_length": length},
    )


def check_api_auth_dependency(config: Dict[str, Any]) -> RuleResult:
    """Evaluate Rule 3: API Authentication Dependency Check.

    Rule definition:
    - If api_exposure is 'public', authentication_required must be true.
    - If api is public and authentication is disabled, report a security failure.
    - If api is internal, this dependency rule passes.
    """
    api_exposure = config["api_exposure"]
    auth_required = config["authentication_required"]

    if api_exposure == "public":
        passed = bool(auth_required)
        if passed:
            details = "API is exposed publicly with mandatory authentication enforced."
        else:
            details = (
                "API is exposed publicly while authentication is disabled, "
                "allowing unrestricted anonymous external access."
            )
    else:
        # internal api
        passed = True
        if auth_required:
            details = "API exposure is internal and authentication is enforced."
        else:
            details = "API exposure is internal; external unauthenticated access rule satisfied."

    return RuleResult(
        rule_id="RULE_API_AUTH_DEPENDENCY",
        rule_name="API Authentication Dependency Check",
        passed=passed,
        details=details,
        evaluated_values={
            "api_exposure": api_exposure,
            "authentication_required": auth_required,
        },
    )


def evaluate_rules(config: Dict[str, Any]) -> Dict[str, RuleResult]:
    """Evaluate all predefined security rules against a configuration dictionary.

    Args:
        config: Validated configuration dictionary.

    Returns:
        A dictionary mapping rule_id to RuleResult.
    """
    firewall_res = check_firewall(config)
    password_res = check_password_length(config)
    api_auth_res = check_api_auth_dependency(config)

    return {
        firewall_res.rule_id: firewall_res,
        password_res.rule_id: password_res,
        api_auth_res.rule_id: api_auth_res,
    }
