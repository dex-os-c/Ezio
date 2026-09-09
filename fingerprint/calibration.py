"""Calibration helpers for stylometric decisions.

Calibration is intentionally data-driven.  The application must not invent a
same-author threshold: an artifact produced by ``scripts/evaluate_stylometry``
is required before a result can be labelled a match.
"""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any


def load_calibration(path: str | None = None) -> dict[str, Any] | None:
    """Load a validated calibration artifact, or return ``None``."""
    path = path or os.getenv("STYLOMETRY_CALIBRATION_FILE")
    if not path:
        return None
    try:
        artifact = json.loads(Path(path).read_text(encoding="utf-8"))
        if artifact.get("method") != "burrows_delta_zscore":
            return None
        threshold = float(artifact["threshold"])
        false_match_rate = float(artifact["false_match_rate"])
        if not 0.0 <= threshold <= 1.0 or not 0.0 <= false_match_rate <= 1.0:
            return None
        return artifact
    except (OSError, ValueError, TypeError, KeyError):
        return None


def calibration_summary() -> dict[str, Any]:
    artifact = load_calibration()
    if not artifact:
        return {
            "status": "uncalibrated",
            "method": "burrows_delta_zscore",
            "message": "No labeled calibration artifact is configured; similarity is descriptive only.",
        }
    return {
        "status": "calibrated",
        "method": artifact.get("method"),
        "threshold": artifact.get("threshold"),
        "false_match_rate": artifact.get("false_match_rate"),
        "validation_pairs": artifact.get("validation_pairs"),
        "dataset": artifact.get("dataset"),
    }


def calibrated_threshold() -> float | None:
    artifact = load_calibration()
    return float(artifact["threshold"]) if artifact else None

