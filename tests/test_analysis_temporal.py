"""Tests for temporal analysis helpers and HTML post timestamp extraction."""

from __future__ import annotations

from datetime import date, timedelta

from analysis.temporal import detect_anomalies, detect_silence_breaks


def _make_timeline(counts: list[int]) -> list[dict]:
    base = date(2024, 1, 1)
    return [
        {"date": base + timedelta(days=i), "count": c} for i, c in enumerate(counts)
    ]


def test_detect_anomalies_spike():
    """A burst of activity should be flagged as anomaly."""
    counts = [1] * 9 + [100]
    tl = _make_timeline(counts)
    result = detect_anomalies(tl, z_threshold=2.0)
    assert len(result) > 0
    assert any(a["type"] == "spike" for a in result)
    assert result[0]["poisson_p_value"] <= 0.01


def test_poisson_model_does_not_flag_small_low_rate_uptick():
    """Three events after a stable one-event baseline are ordinary Poisson variation."""
    result = detect_anomalies(_make_timeline([1] * 9 + [3]))
    assert result == []


def test_poisson_model_flags_large_high_rate_spike():
    """A 30-event day is rare against a stable ten-event baseline."""
    result = detect_anomalies(_make_timeline([10] * 9 + [30]))
    assert len(result) == 1
    assert result[0]["type"] == "spike"
    assert result[0]["expected_rate"] == 10.0


def test_detect_silence_breaks_gap():
    """A multi-week gap between active days should be detected."""
    tl = [
        {"date": date(2024, 1, 1), "count": 1},
        {"date": date(2024, 1, 2), "count": 1},
        {"date": date(2024, 1, 3), "count": 1},
        {"date": date(2024, 1, 4), "count": 1},
        {"date": date(2024, 1, 5), "count": 1},
        {"date": date(2024, 2, 1), "count": 1},
        {"date": date(2024, 2, 2), "count": 1},
        {"date": date(2024, 2, 3), "count": 1},
        {"date": date(2024, 2, 4), "count": 1},
        {"date": date(2024, 2, 5), "count": 1},
    ]
    result = detect_silence_breaks(tl, silence_days=14)
    assert len(result) > 0
    assert result[0]["gap_days"] >= 14


def test_no_anomalies_in_uniform_daily_counts():
    """Uniform daily counts produce no z-score anomalies (std > 0 required for spikes)."""
    tl = _make_timeline([5] * 10)
    result = detect_anomalies(tl)
    assert result == []


def test_extract_post_timestamp_from_html():
    """Timestamp extraction from HTML."""
    from scraper.scrape import extract_post_timestamp

    html = '<time datetime="2024-03-15T14:23:00">March 15</time>'
    result = extract_post_timestamp(html)
    assert result is not None
    assert result.year == 2024
    assert result.month == 3
    assert result.hour == 14


def test_extract_post_timestamp_returns_none_for_no_match():
    """Should return None when no timestamp found."""
    from scraper.scrape import extract_post_timestamp

    result = extract_post_timestamp("<div>No date here</div>")
    assert result is None
