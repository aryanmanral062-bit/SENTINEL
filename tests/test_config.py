"""Unit tests for config.py in SENTINEL."""

import json
import tempfile
import unittest
from pathlib import Path

from config import (
    ConfigFileNotFoundError,
    ConfigJSONDecodeError,
    ConfigValidationError,
    load_config,
    validate_config,
)


class TestConfigManagement(unittest.TestCase):
    """Test suite covering configuration loading, parsing, and validation."""

    def setUp(self) -> None:
        self.valid_data = {
            "firewall_enabled": True,
            "password_min_length": 12,
            "api_exposure": "internal",
            "authentication_required": False,
        }

    def test_valid_configuration_dictionary(self) -> None:
        """Valid dictionary should validate cleanly and return exact typed values."""
        validated = validate_config(self.valid_data)
        self.assertEqual(validated["firewall_enabled"], True)
        self.assertEqual(validated["password_min_length"], 12)
        self.assertEqual(validated["api_exposure"], "internal")
        self.assertEqual(validated["authentication_required"], False)

    def test_valid_json_file_loading(self) -> None:
        """Valid JSON file should be correctly loaded and parsed."""
        with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as f:
            json.dump(self.valid_data, f)
            temp_path = Path(f.name)

        try:
            loaded = load_config(temp_path)
            self.assertEqual(loaded, self.valid_data)
        finally:
            temp_path.unlink(missing_ok=True)

    def test_missing_required_key(self) -> None:
        """Missing any required configuration key should raise ConfigValidationError."""
        for key in self.valid_data:
            incomplete = dict(self.valid_data)
            del incomplete[key]
            with self.assertRaises(ConfigValidationError) as ctx:
                validate_config(incomplete)
            self.assertIn("missing required key", str(ctx.exception).lower())
            self.assertIn(key, str(ctx.exception))

    def test_unexpected_extra_key(self) -> None:
        """Configurations with extra, unauthorized keys should raise ConfigValidationError."""
        data_with_extra = dict(self.valid_data)
        data_with_extra["unauthorized_setting"] = "danger"
        with self.assertRaises(ConfigValidationError) as ctx:
            validate_config(data_with_extra)
        self.assertIn("unexpected key", str(ctx.exception).lower())

    def test_invalid_firewall_type(self) -> None:
        """firewall_enabled must be a boolean; integers or strings are rejected."""
        invalid_types = ["true", 1, 0, None, [True]]
        for val in invalid_types:
            bad_data = dict(self.valid_data, firewall_enabled=val)
            with self.assertRaises(ConfigValidationError) as ctx:
                validate_config(bad_data)
            self.assertIn("firewall_enabled", str(ctx.exception))

    def test_invalid_password_length_type(self) -> None:
        """password_min_length must be an integer, not a boolean, string, or float."""
        invalid_types = [True, False, "12", 12.5, None, []]
        for val in invalid_types:
            bad_data = dict(self.valid_data, password_min_length=val)
            with self.assertRaises(ConfigValidationError) as ctx:
                validate_config(bad_data)
            self.assertIn("password_min_length", str(ctx.exception))

    def test_negative_password_length(self) -> None:
        """Negative password lengths must be rejected."""
        bad_data = dict(self.valid_data, password_min_length=-5)
        with self.assertRaises(ConfigValidationError) as ctx:
            validate_config(bad_data)
        self.assertIn("non-negative", str(ctx.exception).lower())

    def test_invalid_api_exposure_type(self) -> None:
        """api_exposure must be a string."""
        bad_data = dict(self.valid_data, api_exposure=123)
        with self.assertRaises(ConfigValidationError) as ctx:
            validate_config(bad_data)
        self.assertIn("api_exposure", str(ctx.exception))

    def test_invalid_api_exposure_value(self) -> None:
        """api_exposure must only be 'internal' or 'public'."""
        invalid_values = ["external", "dmz", "INTERNAL", "public_access", ""]
        for val in invalid_values:
            bad_data = dict(self.valid_data, api_exposure=val)
            with self.assertRaises(ConfigValidationError) as ctx:
                validate_config(bad_data)
            self.assertIn("permitted values", str(ctx.exception).lower())

    def test_invalid_authentication_required_type(self) -> None:
        """authentication_required must be a boolean."""
        invalid_types = ["true", 1, 0, None]
        for val in invalid_types:
            bad_data = dict(self.valid_data, authentication_required=val)
            with self.assertRaises(ConfigValidationError) as ctx:
                validate_config(bad_data)
            self.assertIn("authentication_required", str(ctx.exception))

    def test_root_not_a_dictionary(self) -> None:
        """JSON payload whose root is a list or scalar must be rejected."""
        with self.assertRaises(ConfigValidationError):
            validate_config(["firewall_enabled", True])

    def test_malformed_json_file(self) -> None:
        """Malformed JSON files must raise ConfigJSONDecodeError with syntax details."""
        with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as f:
            f.write('{"firewall_enabled": true, "password_min_length": 12, ')  # incomplete JSON
            temp_path = Path(f.name)

        try:
            with self.assertRaises(ConfigJSONDecodeError) as ctx:
                load_config(temp_path)
            self.assertIn("invalid json syntax", str(ctx.exception).lower())
        finally:
            temp_path.unlink(missing_ok=True)

    def test_missing_file(self) -> None:
        """Non-existent file paths must raise ConfigFileNotFoundError."""
        non_existent = Path("non_existent_config_file_xyz_123.json")
        with self.assertRaises(ConfigFileNotFoundError) as ctx:
            load_config(non_existent)
        self.assertIn("not found", str(ctx.exception).lower())


if __name__ == "__main__":
    unittest.main()
