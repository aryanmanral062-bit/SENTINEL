"""Configuration Management Module for SENTINEL.

Responsible for loading JSON configuration files, converting them into
Python dictionaries, validating required keys, types, and permitted values,
and providing informative validation errors.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict


REQUIRED_KEYS = {
    "firewall_enabled",
    "password_min_length",
    "api_exposure",
    "authentication_required",
}

PERMITTED_API_EXPOSURE = {"internal", "public"}


class ConfigError(Exception):
    """Base exception for configuration errors."""


class ConfigFileNotFoundError(ConfigError):
    """Raised when a configuration file cannot be found."""


class ConfigJSONDecodeError(ConfigError):
    """Raised when a configuration file contains invalid JSON syntax."""


class ConfigValidationError(ConfigError):
    """Raised when a configuration fails schema or value validation."""


def load_config(file_path: str | Path) -> Dict[str, Any]:
    """Load and validate a simulated system configuration from a JSON file.

    Args:
        file_path: File system path to the JSON configuration file.

    Returns:
        A validated dictionary containing the four required configuration settings.

    Raises:
        ConfigFileNotFoundError: If the file does not exist or is not a file.
        ConfigJSONDecodeError: If the file contains malformed JSON.
        ConfigValidationError: If the configuration structure, keys, types, or values are invalid.
    """
    path = Path(file_path)

    if not path.exists():
        raise ConfigFileNotFoundError(f"Configuration file not found: '{path}'")

    if not path.is_file():
        raise ConfigFileNotFoundError(f"Specified path is not a regular file: '{path}'")

    try:
        content = path.read_text(encoding="utf-8")
    except OSError as err:
        raise ConfigError(f"Unable to read configuration file '{path}': {err}") from err

    try:
        data = json.loads(content)
    except json.JSONDecodeError as err:
        raise ConfigJSONDecodeError(
            f"Invalid JSON syntax in '{path}': line {err.lineno}, column {err.colno} ({err.msg})"
        ) from err

    return validate_config(data, source_name=str(path))


def validate_config(data: Any, source_name: str = "Configuration") -> Dict[str, Any]:
    """Validate the structure, types, and values of a configuration dictionary.

    Args:
        data: The deserialized data to validate.
        source_name: An optional identifier for the configuration source (used in error messages).

    Returns:
        The validated configuration dictionary.

    Raises:
        ConfigValidationError: If validation fails.
    """
    if not isinstance(data, dict):
        raise ConfigValidationError(
            f"{source_name} must be a JSON object (dictionary), got {type(data).__name__}."
        )

    # Check for missing keys
    missing_keys = REQUIRED_KEYS - set(data.keys())
    if missing_keys:
        missing_sorted = sorted(missing_keys)
        raise ConfigValidationError(
            f"{source_name} is missing required key(s): {', '.join(missing_sorted)}."
        )

    # Check for unexpected/extra keys
    extra_keys = set(data.keys()) - REQUIRED_KEYS
    if extra_keys:
        extra_sorted = sorted(extra_keys)
        raise ConfigValidationError(
            f"{source_name} contains unexpected key(s): {', '.join(extra_sorted)}. "
            f"Only the following keys are permitted: {', '.join(sorted(REQUIRED_KEYS))}."
        )

    # 1. Validate firewall_enabled (Boolean)
    firewall_enabled = data["firewall_enabled"]
    if not isinstance(firewall_enabled, bool):
        raise ConfigValidationError(
            f"Invalid type for 'firewall_enabled' in {source_name}: "
            f"expected boolean (true/false), got {type(firewall_enabled).__name__}."
        )

    # 2. Validate password_min_length (Integer, non-negative)
    password_min_length = data["password_min_length"]
    # In Python, bool is a subclass of int, so explicitly disallow bool
    if isinstance(password_min_length, bool) or not isinstance(password_min_length, int):
        raise ConfigValidationError(
            f"Invalid type for 'password_min_length' in {source_name}: "
            f"expected integer, got {type(password_min_length).__name__}."
        )
    if password_min_length < 0:
        raise ConfigValidationError(
            f"Invalid value for 'password_min_length' in {source_name}: "
            f"must be non-negative, got {password_min_length}."
        )

    # 3. Validate api_exposure (String: 'internal' or 'public')
    api_exposure = data["api_exposure"]
    if not isinstance(api_exposure, str):
        raise ConfigValidationError(
            f"Invalid type for 'api_exposure' in {source_name}: "
            f"expected string ('internal' or 'public'), got {type(api_exposure).__name__}."
        )
    if api_exposure not in PERMITTED_API_EXPOSURE:
        raise ConfigValidationError(
            f"Invalid value for 'api_exposure' in {source_name}: '{api_exposure}'. "
            f"Permitted values are: {', '.join(sorted(PERMITTED_API_EXPOSURE))}."
        )

    # 4. Validate authentication_required (Boolean)
    authentication_required = data["authentication_required"]
    if not isinstance(authentication_required, bool):
        raise ConfigValidationError(
            f"Invalid type for 'authentication_required' in {source_name}: "
            f"expected boolean (true/false), got {type(authentication_required).__name__}."
        )

    return {
        "firewall_enabled": firewall_enabled,
        "password_min_length": password_min_length,
        "api_exposure": api_exposure,
        "authentication_required": authentication_required,
    }
