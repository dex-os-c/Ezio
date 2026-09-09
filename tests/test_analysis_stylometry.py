"""Tests for stylometry fingerprinting."""

from __future__ import annotations

from fingerprint.stylometry import extract_style_vector

SAMPLE_TEXT = """
The threat actor demonstrated sophisticated understanding of network protocols.
Using advanced techniques, they bypassed multiple security layers.
The attack vector leveraged a previously unknown vulnerability in the target system.
"""


def test_extract_style_vector_returns_features():
    """Should return dict with expected feature keys."""
    result = extract_style_vector(SAMPLE_TEXT)
    assert isinstance(result, dict)
    assert result is not None
    assert "avg_word_length" in result
    assert "avg_sentence_length" in result
    assert "punctuation_density" in result
    assert "vocabulary_richness" in result


def test_extract_style_vector_values_in_range():
    """Feature values should be in expected ranges."""
    result = extract_style_vector(SAMPLE_TEXT)
    assert result is not None
    assert 3.0 <= result["avg_word_length"] <= 12.0
    assert 5.0 <= result["avg_sentence_length"] <= 50.0
    assert 0.0 <= result["punctuation_density"] <= 1.0
    assert 0.0 <= result["vocabulary_richness"] <= 1.0


def test_extract_style_vector_different_texts():
    """Different writing styles should produce different vectors."""
    technical = extract_style_vector(
        "The CVE-2024-1234 vulnerability affects kernel versions 5.4 through 6.1. "
        "Exploitation requires local privilege escalation via the mmap syscall."
    )
    casual = extract_style_vector(
        "hey guys check this out its really cool lol gonna post more soon. "
        "this is casual text with enough length for stylometry to work properly. "
        "we need at least one hundred characters in this sample paragraph here."
    )
    assert technical is not None and casual is not None
    # Technical CVE-style prose vs casual chat should differ on multiple axes
    assert technical["avg_word_length"] != casual["avg_word_length"] or abs(
        technical["vocabulary_richness"] - casual["vocabulary_richness"]
    ) > 0.01
