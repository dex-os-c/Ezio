"""Tests for config.py"""

import os
import sys
import unittest
import logging
from unittest.mock import patch


class TestConfigOTXKey(unittest.TestCase):
    """Test that OTX_API_KEY is correctly loaded from environment."""

    def test_otx_api_key_from_environment(self):
        """OTX_API_KEY should be loaded from environment, not overwritten."""
        test_key = "test-key-123"

        for mod_name in list(sys.modules.keys()):
            if mod_name == "ezio.config" or mod_name.startswith("ezio.config."):
                sys.modules.pop(mod_name)

        env = {
            "JWT_SECRET": "test-secret-for-validation",
            "OTX_API_KEY": test_key,
        }

        with patch.dict(os.environ, env, clear=True):
            import ezio.config as config
            import importlib
            importlib.reload(config)

            self.assertEqual(config.OTX_API_KEY, test_key)


class TestConfigValidation(unittest.TestCase):
    """Test config validation."""

    def test_validate_config_logs_warning_for_missing_optional(self):
        """validate_config should log warning for missing optional keys."""
        for mod_name in list(sys.modules.keys()):
            if mod_name == "ezio.config" or mod_name.startswith("ezio.config."):
                sys.modules.pop(mod_name)

        with patch.dict(os.environ, {"JWT_SECRET": "test-secret-key-123"}, clear=True):
            import ezio.config as config_module
            import importlib
            importlib.reload(config_module)

            with patch("ezio.config.logger") as mock_logger:
                config_module.validate_config()

                self.assertTrue(mock_logger.warning.called)
                warning_calls = str(mock_logger.warning.call_args_list)
                self.assertIn("OPENAI_API_KEY", warning_calls)

    def test_optional_config_warning_is_once_per_process(self):
        """Repeated validation must not spam the same process with warnings."""
        import config

        with patch.dict(os.environ, {"JWT_SECRET": "test-secret-key-123"}, clear=True):
            # The guard intentionally lives on logging so compatibility-module
            # reloads cannot reset it; reset it explicitly for this isolated
            # regression test.
            setattr(logging, "_ezio_optional_config_warning_shown", False)
            try:
                with patch.object(config, "logger") as mock_logger:
                    config.validate_config()
                    config.validate_config()

                    warning_calls = [
                        call for call in mock_logger.warning.call_args_list
                        if call.args and "Optional configuration keys not set" in str(call.args[0])
                    ]
                    self.assertEqual(len(warning_calls), 1)
            finally:
                setattr(logging, "_ezio_optional_config_warning_shown", False)


if __name__ == "__main__":
    unittest.main()
