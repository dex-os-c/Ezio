"""Compatibility wrapper for the project-level configuration module."""

from importlib import import_module, reload

# Reload the compatibility target so explicit `importlib.reload` calls keep
# reflecting a test/application environment change. The warning guard itself
# lives on the process-wide logging module, so this reload cannot reintroduce
# warning spam.
_config = reload(import_module("config"))

for _name in dir(_config):
    if not _name.startswith("__"):
        globals()[_name] = getattr(_config, _name)


def validate_config():
    _config.logger = logger
    return _config.validate_config()
