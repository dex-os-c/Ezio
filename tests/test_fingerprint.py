"""
tests/test_fingerprint.py — Tests for Phase 6 fingerprint module.

Test classes
------------
TestStylometry  — fingerprint/stylometry.py
TestProfiler    — fingerprint/profiler.py
"""

from __future__ import annotations

import os
import sys
import unittest
from unittest.mock import MagicMock, patch

_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)

# Ensure DATABASE_URL is unset for DB-free tests
os.environ.pop("DATABASE_URL", None)

from fingerprint.stylometry import (
    are_likely_same_author,
    compute_similarity,
    extract_style_vector,
)


# ---------------------------------------------------------------------------
# Shared test text samples
# ---------------------------------------------------------------------------

_SHORT_TEXT = "Too short."

_SAMPLE_A = (
    "The quick brown fox jumps over the lazy dog. "
    "This is a fairly standard piece of English text that demonstrates "
    "a wide variety of common words and sentence structures. "
    "Furthermore, the use of function words like 'the', 'and', 'is' "
    "and 'are' gives us insight into the writing style of the author. "
    "People tend to use function words habitually and unconsciously, "
    "which makes them excellent stylometric markers for identification."
)

_SAMPLE_B = (
    "I believe that this market will soon experience significant volatility. "
    "The administrators have been quiet for two weeks now, which is unusual. "
    "Several vendors have reported withdrawal delays and that concerns me. "
    "If you are holding funds on this platform you should consider moving them. "
    "Historical patterns suggest that silence from admins precedes an exit. "
    "Be careful and do not leave money on any centralized dark web market."
)

# Long enough text that looks very similar to _SAMPLE_A
_SAMPLE_A2 = (
    "The quick brown fox jumps over the lazy dog very quickly! "
    "This is another piece of English text demonstrating various common words "
    "and sentence structures written in the same style. "
    "Furthermore, using function words like 'the', 'and', 'is' and 'are' "
    "consistently helps identify the writing style of a particular person. "
    "People use function words habitually and unconsciously at all times."
)


# ===========================================================================
# TestStylometry
# ===========================================================================

class TestStylometry(unittest.TestCase):

    # --- extract_style_vector ---

    def test_returns_none_for_short_text(self):
        result = extract_style_vector(_SHORT_TEXT)
        self.assertIsNone(result)

    def test_returns_none_for_text_exactly_99_chars(self):
        text = "a" * 99
        self.assertIsNone(extract_style_vector(text))

    def test_returns_dict_for_valid_text(self):
        result = extract_style_vector(_SAMPLE_A)
        self.assertIsInstance(result, dict)

    def test_all_required_keys_present(self):
        result = extract_style_vector(_SAMPLE_A)
        self.assertIsNotNone(result)
        required_keys = {
            "avg_word_length",
            "avg_sentence_length",
            "vocabulary_richness",
            "punctuation_density",
            "uppercase_ratio",
            "digit_ratio",
            "function_word_freq",
            "avg_paragraph_length",
            "exclamation_ratio",
            "question_ratio",
            "char_ngram_freq",
        }
        self.assertEqual(required_keys, set(result.keys()))

    def test_avg_word_length_is_positive_float(self):
        result = extract_style_vector(_SAMPLE_A)
        self.assertIsNotNone(result)
        self.assertIsInstance(result["avg_word_length"], float)
        self.assertGreater(result["avg_word_length"], 0.0)

    def test_vocabulary_richness_in_range(self):
        result = extract_style_vector(_SAMPLE_A)
        self.assertIsNotNone(result)
        self.assertGreaterEqual(result["vocabulary_richness"], 0.0)
        self.assertLessEqual(result["vocabulary_richness"], 1.0)

    def test_function_word_freq_is_dict(self):
        result = extract_style_vector(_SAMPLE_A)
        self.assertIsNotNone(result)
        self.assertIsInstance(result["function_word_freq"], dict)
        self.assertIn("the", result["function_word_freq"])

    def test_function_word_freq_has_20_words(self):
        result = extract_style_vector(_SAMPLE_A)
        self.assertIsNotNone(result)
        self.assertEqual(len(result["function_word_freq"]), 20)

    def test_char_ngram_freq_is_dict_max_50(self):
        result = extract_style_vector(_SAMPLE_A)
        self.assertIsNotNone(result)
        self.assertIsInstance(result["char_ngram_freq"], dict)
        self.assertLessEqual(len(result["char_ngram_freq"]), 50)

    def test_returns_none_for_empty_string(self):
        self.assertIsNone(extract_style_vector(""))

    def test_returns_none_for_none_equivalent(self):
        self.assertIsNone(extract_style_vector(None))  # type: ignore

    def test_never_raises(self):
        for val in [None, "", "x", 42, [], {}]:
            try:
                extract_style_vector(val)  # type: ignore
            except Exception as exc:
                self.fail(f"extract_style_vector raised {exc} for input {val!r}")

    # --- compute_similarity ---

    def test_identical_vectors_return_1(self):
        vec = extract_style_vector(_SAMPLE_A)
        self.assertIsNotNone(vec)
        score = compute_similarity(vec, vec)
        self.assertAlmostEqual(score, 1.0, places=5)

    def test_orthogonal_vectors_return_near_zero(self):
        # Construct two clearly orthogonal minimal vectors
        vec_a = {
            "avg_word_length": 1.0,
            "avg_sentence_length": 0.0,
            "vocabulary_richness": 0.0,
            "punctuation_density": 0.0,
            "uppercase_ratio": 0.0,
            "digit_ratio": 0.0,
            "function_word_freq": {"the": 1.0, "a": 0.0},
            "avg_paragraph_length": 0.0,
            "exclamation_ratio": 0.0,
            "question_ratio": 0.0,
            "char_ngram_freq": {"abc": 1.0, "xyz": 0.0},
        }
        vec_b = {
            "avg_word_length": 0.0,
            "avg_sentence_length": 1.0,
            "vocabulary_richness": 0.0,
            "punctuation_density": 0.0,
            "uppercase_ratio": 0.0,
            "digit_ratio": 0.0,
            "function_word_freq": {"the": 0.0, "a": 1.0},
            "avg_paragraph_length": 0.0,
            "exclamation_ratio": 0.0,
            "question_ratio": 0.0,
            "char_ngram_freq": {"abc": 0.0, "xyz": 1.0},
        }
        score = compute_similarity(vec_a, vec_b)
        self.assertAlmostEqual(score, 0.0, places=5)

    def test_handles_none_input_gracefully(self):
        self.assertEqual(compute_similarity(None, None), 0.0)  # type: ignore

    def test_handles_none_a(self):
        vec = extract_style_vector(_SAMPLE_A)
        self.assertEqual(compute_similarity(None, vec), 0.0)  # type: ignore

    def test_handles_none_b(self):
        vec = extract_style_vector(_SAMPLE_A)
        self.assertEqual(compute_similarity(vec, None), 0.0)  # type: ignore

    def test_handles_empty_dict(self):
        self.assertEqual(compute_similarity({}, {}), 0.0)

    def test_score_between_0_and_1(self):
        vec_a = extract_style_vector(_SAMPLE_A)
        vec_b = extract_style_vector(_SAMPLE_B)
        self.assertIsNotNone(vec_a)
        self.assertIsNotNone(vec_b)
        score = compute_similarity(vec_a, vec_b)
        self.assertGreaterEqual(score, 0.0)
        self.assertLessEqual(score, 1.0)

    # --- are_likely_same_author ---

    def test_above_threshold_returns_true(self):
        vec = extract_style_vector(_SAMPLE_A)
        self.assertIsNotNone(vec)
        result, score = are_likely_same_author(vec, vec, threshold=0.85)
        self.assertTrue(result)
        self.assertGreaterEqual(score, 0.85)

    def test_below_threshold_returns_false(self):
        vec_a = extract_style_vector(_SAMPLE_A)
        vec_b = extract_style_vector(_SAMPLE_B)
        self.assertIsNotNone(vec_a)
        self.assertIsNotNone(vec_b)
        # Use a very high threshold to force False
        result, score = are_likely_same_author(vec_a, vec_b, threshold=0.9999)
        self.assertFalse(result)
        self.assertLess(score, 0.9999)

    def test_returns_tuple(self):
        vec = extract_style_vector(_SAMPLE_A)
        self.assertIsNotNone(vec)
        result = are_likely_same_author(vec, vec)
        self.assertIsInstance(result, tuple)
        self.assertEqual(len(result), 2)

    def test_score_is_float(self):
        vec = extract_style_vector(_SAMPLE_A)
        self.assertIsNotNone(vec)
        _, score = are_likely_same_author(vec, vec)
        self.assertIsInstance(score, float)


# ===========================================================================
# TestProfiler
# ===========================================================================

from fingerprint.profiler import (
    build_actor_profile,
    load_profiles_from_db,
    match_against_profiles,
    save_profile_to_db,
    update_profile,
)


class TestProfiler(unittest.TestCase):

    # --- build_actor_profile ---

    def test_filters_short_texts(self):
        texts = ["short", _SAMPLE_A]
        profile = build_actor_profile(texts)
        self.assertIsNotNone(profile)
        # Only one valid text, so sample count should be 1
        self.assertEqual(profile.get("_sample_count"), 1)

    def test_returns_none_if_all_short(self):
        texts = ["hi", "yo", "short text"]
        profile = build_actor_profile(texts)
        self.assertIsNone(profile)

    def test_returns_none_for_empty_list(self):
        profile = build_actor_profile([])
        self.assertIsNone(profile)

    def test_mean_vector_has_same_keys(self):
        texts = [_SAMPLE_A, _SAMPLE_B]
        profile = build_actor_profile(texts)
        self.assertIsNotNone(profile)
        single_vec = extract_style_vector(_SAMPLE_A)
        self.assertIsNotNone(single_vec)
        # All stylometric keys should be present (plus _handle, _sample_count)
        for key in single_vec.keys():
            self.assertIn(key, profile)

    def test_sample_count_correct(self):
        texts = [_SAMPLE_A, _SAMPLE_B, _SAMPLE_A2]
        profile = build_actor_profile(texts)
        self.assertIsNotNone(profile)
        self.assertEqual(profile.get("_sample_count"), 3)

    def test_profile_metadata_stored(self):
        profile = build_actor_profile([_SAMPLE_A])
        self.assertIsNotNone(profile)
        self.assertEqual(profile.get("_sample_count"), 1)

    # --- update_profile ---

    def test_update_changes_profile(self):
        original = build_actor_profile([_SAMPLE_A])
        self.assertIsNotNone(original)
        updated = update_profile(original, [_SAMPLE_B])
        # The updated profile should differ from the original
        self.assertNotEqual(
            original.get("avg_word_length"),
            updated.get("avg_word_length"),
        )

    def test_update_with_no_valid_texts_returns_unchanged(self):
        original = build_actor_profile([_SAMPLE_A])
        self.assertIsNotNone(original)
        updated = update_profile(original, ["too short"])
        self.assertEqual(
            original.get("avg_word_length"),
            updated.get("avg_word_length"),
        )

    def test_update_increments_sample_count(self):
        original = build_actor_profile([_SAMPLE_A])
        self.assertIsNotNone(original)
        original_count = original.get("_sample_count", 1)
        updated = update_profile(original, [_SAMPLE_B])
        self.assertEqual(updated.get("_sample_count"), original_count + 1)

    # --- match_against_profiles (mocked DB) ---

    def test_match_against_profiles_returns_sorted(self):
        vec_a = extract_style_vector(_SAMPLE_A)
        vec_b = extract_style_vector(_SAMPLE_B)
        self.assertIsNotNone(vec_a)
        self.assertIsNotNone(vec_b)
        
        mock_profile_a = MagicMock()
        mock_profile_a.canonical_value = "actor_a"
        mock_profile_a.entity_type = "THREAT_ACTOR"
        mock_profile_a.style_vector = vec_a
        mock_profile_a.sample_count = 1
        mock_profile_a.total_chars = 100

        mock_profile_b = MagicMock()
        mock_profile_b.canonical_value = "actor_b"
        mock_profile_b.entity_type = "THREAT_ACTOR"
        mock_profile_b.style_vector = vec_b
        mock_profile_b.sample_count = 1
        mock_profile_b.total_chars = 100

        mock_session = MagicMock()
        mock_session.query.return_value.filter.return_value.all.return_value = [mock_profile_a, mock_profile_b]
        mock_session.query.return_value.all.return_value = [mock_profile_a, mock_profile_b]

        results = match_against_profiles(vec_a, mock_session, threshold=0.0)
        self.assertIsInstance(results, list)
        self.assertGreaterEqual(len(results), 2)
        # Results should be sorted by similarity (descending)
        self.assertGreaterEqual(results[0]["similarity"], results[1]["similarity"])

    # --- load_profiles_from_db (no DATABASE_URL) ---

    def test_load_returns_empty_without_db(self):
        mock_session = MagicMock()
        mock_session.query.side_effect = Exception("DB Fail")
        result = load_profiles_from_db(mock_session)
        self.assertEqual(result, {})

    def test_load_with_session_success(self):
        mock_row = MagicMock()
        mock_row.canonical_value = "actor1"
        mock_row.style_vector = {"test": 1.0}
        mock_session = MagicMock()
        mock_session.query.return_value.all.return_value = [mock_row]
        result = load_profiles_from_db(mock_session)
        self.assertEqual(result, {"actor1": {"test": 1.0}})

    # --- save_profile_to_db (no DATABASE_URL) ---

    def test_save_returns_false_on_exception(self):
        mock_session = MagicMock()
        mock_session.query.side_effect = Exception("DB Fail")
        vec = extract_style_vector(_SAMPLE_A)
        self.assertIsNotNone(vec)
        result = save_profile_to_db(vec, "test_handle", "THREAT_ACTOR", mock_session)
        self.assertFalse(result)

    def test_save_success(self):
        mock_session = MagicMock()
        mock_session.query.return_value.filter.return_value.first.return_value = None
        vec = {"test": 1.0, "_sample_count": 1}
        result = save_profile_to_db(vec, "handle", "THREAT_ACTOR", mock_session)
        self.assertTrue(result)
        self.assertTrue(mock_session.add.called)


if __name__ == "__main__":
    unittest.main()
