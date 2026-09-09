"""Command-line wrapper for the v2.0.3 legacy-data backfill."""

import sys
from pathlib import Path

# When invoked as ``python scripts/backfill_legacy_data.py``, Python puts the
# scripts directory—not the repository root—on sys.path.
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from ezio.backfill import main  # noqa: E402


if __name__ == "__main__":
    raise SystemExit(main())
