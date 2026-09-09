"""Tests for OPSEC analysis (PGP reuse and full pipeline entrypoint)."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

from analysis.opsec import (
    detect_timezone_leak,
    detect_pgp_reuse,
    run_full_opsec_analysis,
)


def test_timezone_detection_uses_utc_not_host_timezone():
    """Equivalent instants expressed with different offsets yield same result."""
    utc_entries = [
        {"text": "x", "timestamp": datetime(2024, 1, 1, 12 + i % 2, tzinfo=timezone.utc)}
        for i in range(10)
    ]
    offset_entries = [
        {"text": "x", "timestamp": entry["timestamp"].astimezone(timezone(timedelta(hours=5, minutes=30)))}
        for entry in utc_entries
    ]
    assert detect_timezone_leak(utc_entries) == detect_timezone_leak(offset_entries)


def test_detect_pgp_reuse_multiple_keys():
    """Same PGP fingerprint appearing twice in the list should trigger."""
    fingerprints = [
        "C1D5DA871E6F6A0D73220256E357ABCDEF12345678",
        "C1D5DA871E6F6A0D73220256E357ABCDEF12345678",
        "ABCDEF1234567890ABCDEF1234567890ABCDEF12",
    ]
    result = detect_pgp_reuse(fingerprints)
    assert result.get("detected") is True


def test_detect_pgp_reuse_unique_keys():
    """All unique PGP keys should not trigger duplicate detection."""
    fingerprints = ["KEY123456789012345678901234567890ABCD1234", "KEY567890123456789012345678901234EFGH5678"]
    result = detect_pgp_reuse(fingerprints)
    assert result.get("detected") is False


def test_opsec_score_perfect_empty():
    """No text and no PGP issues should yield a perfect score and LOW risk."""
    result = run_full_opsec_analysis("actor", [], pgp_fingerprints=None)
    assert result["opsec_score"] == 100
    assert result["risk_level"] == "LOW"
    assert len(result["findings"]) == 0
