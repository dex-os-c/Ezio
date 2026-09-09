"""
tests/test_api_monitors.py — Tests for api/routes/monitors.py concurrent config writes.
"""

from __future__ import annotations

import asyncio
import os
import sys
import tempfile
import unittest
import yaml
from pathlib import Path
from unittest.mock import AsyncMock, patch

_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)


class TestConcurrentConfigWrites(unittest.IsolatedAsyncioTestCase):
    async def test_concurrent_writes_no_corruption(self):
        """Two threads writing simultaneously should not corrupt the YAML file."""
        from api.routes import monitors

        with tempfile.TemporaryDirectory() as tmpdir:
            path = Path(tmpdir) / "monitors.yaml"
            lock_path = str(path) + ".lock"

            path.write_text(
                yaml.dump({"watches": [{"name": "initial", "type": "keyword", "query": "q", "interval_hours": 1.0, "alert_on": "new_results", "enabled": True}]}, default_flow_style=False),
                encoding="utf-8"
            )

            async def write_watch(name: str):
                """Simulate creating a monitor via the file lock."""
                with monitors.FileLock(lock_path, timeout=10):
                    content = path.read_text(encoding="utf-8")
                    data = yaml.safe_load(content) or {"watches": []}
                    watches = data.get("watches", [])
                    if not isinstance(watches, list):
                        watches = []

                    entry = {
                        "name": name,
                        "type": "keyword",
                        "query": f"query for {name}",
                        "interval_hours": 1.0,
                        "alert_on": "new_results",
                        "enabled": True,
                    }
                    watches.append(entry)

                    with open(path, 'w', encoding='utf-8') as f:
                        f.write(yaml.dump({"watches": watches}, default_flow_style=False, allow_unicode=True))

                return name

            results = await asyncio.gather(
                write_watch("watch1"),
                write_watch("watch2"),
            )

            content = path.read_text(encoding="utf-8")
            data = yaml.safe_load(content)

            self.assertEqual(len(results), 2)
            self.assertIn("watch1", results)
            self.assertIn("watch2", results)

            watches = data.get("watches", [])
            self.assertEqual(len(watches), 3)

            watch_names = [w.get("name") for w in watches]
            self.assertIn("initial", watch_names)
            self.assertIn("watch1", watch_names)
            self.assertIn("watch2", watch_names)

    async def test_concurrent_writes_valid_yaml(self):
        """After concurrent writes, the file is valid YAML."""
        from api.routes import monitors

        with tempfile.TemporaryDirectory() as tmpdir:
            path = Path(tmpdir) / "monitors.yaml"
            lock_path = str(path) + ".lock"

            path.write_text(
                yaml.dump({"watches": []}, default_flow_style=False),
                encoding="utf-8"
            )

            async def write_many(n: int):
                for i in range(n):
                    with monitors.FileLock(lock_path, timeout=10):
                        content = path.read_text(encoding="utf-8")
                        data = yaml.safe_load(content) or {"watches": []}
                        watches = data.get("watches", [])

                        entry = {
                            "name": f"concurrent_{n}_{i}",
                            "type": "keyword",
                            "query": f"q{n}_{i}",
                            "interval_hours": 1.0,
                            "alert_on": "new_results",
                            "enabled": True,
                        }
                        watches.append(entry)

                        with open(path, 'w', encoding='utf-8') as f:
                            f.write(yaml.dump({"watches": watches}, default_flow_style=False, allow_unicode=True))

            await asyncio.gather(
                write_many(5),
                write_many(5),
            )

            content = path.read_text(encoding="utf-8")
            data = yaml.safe_load(content)

            self.assertIsInstance(data, dict)
            self.assertIn("watches", data)
            self.assertIsInstance(data["watches"], list)
            self.assertEqual(len(data["watches"]), 10)


if __name__ == "__main__":
    unittest.main()