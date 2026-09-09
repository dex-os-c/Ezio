"""
tests/test_i18n.py — Tests for Phase 6 i18n module.

Test classes
------------
TestDetect       — i18n/detect.py
TestTranslate    — i18n/translate.py
TestQueryExpand  — i18n/query_expand.py
"""

from __future__ import annotations

import importlib
import os
import sys
import types
import unittest
from unittest.mock import MagicMock, patch

_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)

os.environ.pop("DEEPL_API_KEY", None)


# ===========================================================================
# TestDetect
# ===========================================================================

class TestDetect(unittest.TestCase):

    def _make_langdetect_mock(self, return_value: str) -> types.ModuleType:
        mock = MagicMock()
        mock.detect = MagicMock(return_value=return_value)
        mock.LangDetectException = Exception
        return mock

    def test_returns_correct_iso_code(self):
        """detect_language returns the mocked langdetect result."""
        mock_ld = self._make_langdetect_mock("en")
        with patch.dict("sys.modules", {"langdetect": mock_ld}):
            import i18n.detect as det_mod
            importlib.reload(det_mod)
            result = det_mod.detect_language("This is a long enough English text for proper detection now.")
        self.assertEqual(result, "en")

    def test_returns_none_for_short_text(self):
        """detect_language returns None for text < 50 chars regardless of library."""
        mock_ld = self._make_langdetect_mock("en")
        with patch.dict("sys.modules", {"langdetect": mock_ld}):
            import i18n.detect as det_mod
            importlib.reload(det_mod)
            result = det_mod.detect_language("short")
        self.assertIsNone(result)

    def test_returns_none_exactly_49_chars(self):
        mock_ld = self._make_langdetect_mock("en")
        with patch.dict("sys.modules", {"langdetect": mock_ld}):
            import i18n.detect as det_mod
            importlib.reload(det_mod)
            result = det_mod.detect_language("a" * 49)
        self.assertIsNone(result)

    def test_returns_none_when_langdetect_not_installed(self):
        """detect_language returns None when langdetect cannot be imported."""
        saved = sys.modules.pop("langdetect", None)
        # Inject ImportError
        sys.modules["langdetect"] = None  # type: ignore
        try:
            import i18n.detect as det_mod
            importlib.reload(det_mod)
            result = det_mod.detect_language("This is a long enough text to trigger detection here.")
        finally:
            if saved is not None:
                sys.modules["langdetect"] = saved
            else:
                sys.modules.pop("langdetect", None)
        self.assertIsNone(result)

    def test_returns_none_on_langdetect_exception(self):
        mock_ld = MagicMock()
        mock_ld.detect = MagicMock(side_effect=Exception("detect failed"))
        mock_ld.LangDetectException = Exception
        with patch.dict("sys.modules", {"langdetect": mock_ld}):
            import i18n.detect as det_mod
            importlib.reload(det_mod)
            result = det_mod.detect_language("This is a long enough text to trigger detection.")
        self.assertIsNone(result)

    def test_never_raises(self):
        import i18n.detect as det_mod
        importlib.reload(det_mod)
        for val in [None, "", "x", "a" * 200]:
            try:
                det_mod.detect_language(val)  # type: ignore
            except Exception as exc:
                self.fail(f"detect_language raised {exc} for input {val!r}")

    def test_is_non_english_true_for_ru(self):
        mock_ld = self._make_langdetect_mock("ru")
        with patch.dict("sys.modules", {"langdetect": mock_ld}):
            import i18n.detect as det_mod
            importlib.reload(det_mod)
            result = det_mod.is_non_english("x" * 60)
        self.assertTrue(result)

    def test_is_non_english_false_for_en(self):
        mock_ld = self._make_langdetect_mock("en")
        with patch.dict("sys.modules", {"langdetect": mock_ld}):
            import i18n.detect as det_mod
            importlib.reload(det_mod)
            result = det_mod.is_non_english("x" * 60)
        self.assertFalse(result)

    def test_detect_batch_returns_same_length(self):
        mock_ld = self._make_langdetect_mock("en")
        with patch.dict("sys.modules", {"langdetect": mock_ld}):
            import i18n.detect as det_mod
            importlib.reload(det_mod)
            texts = ["hello world " * 5, "hola mundo " * 5, "x"]
            results = det_mod.detect_language_batch(texts)
        self.assertEqual(len(results), len(texts))

    def test_detect_batch_none_for_short(self):
        mock_ld = self._make_langdetect_mock("en")
        with patch.dict("sys.modules", {"langdetect": mock_ld}):
            import i18n.detect as det_mod
            importlib.reload(det_mod)
            results = det_mod.detect_language_batch(["short"])
        self.assertIsNone(results[0])


# ===========================================================================
# TestTranslate
# ===========================================================================

class TestTranslate(unittest.TestCase):

    def setUp(self):
        os.environ.pop("DEEPL_API_KEY", None)

    def tearDown(self):
        os.environ.pop("DEEPL_API_KEY", None)

    def test_uses_deepl_when_api_key_set(self):
        """translate_to_english calls DeepL when DEEPL_API_KEY is configured."""
        os.environ["DEEPL_API_KEY"] = "test-key-123"

        mock_response = MagicMock()
        mock_response.json.return_value = {
            "translations": [{"text": "Hello world"}]
        }
        mock_response.raise_for_status = MagicMock()

        with patch("requests.post", return_value=mock_response) as mock_post:
            import i18n.translate as tr_mod
            importlib.reload(tr_mod)
            result = tr_mod.translate_to_english("Hola mundo", source_lang="es")

        mock_post.assert_called_once()
        self.assertEqual(result, "Hello world")

    def test_falls_back_when_deepl_fails(self):
        """translate_to_english falls back gracefully when DeepL request fails."""
        os.environ["DEEPL_API_KEY"] = "invalid-key"

        with patch("requests.post", side_effect=Exception("network error")):
            import i18n.translate as tr_mod
            importlib.reload(tr_mod)
            # No transformers available → should return None
            result = tr_mod.translate_to_english(
                "Hola mundo y algo más para hacer el texto suficientemente largo.",
                source_lang="es",
            )
        self.assertIsNone(result)

    def test_returns_none_when_no_method_available(self):
        """translate_to_english returns None when neither DeepL nor transformers work."""
        os.environ.pop("DEEPL_API_KEY", None)

        # Ensure transformers not available
        saved = sys.modules.get("transformers")
        sys.modules["transformers"] = None  # type: ignore
        try:
            import i18n.translate as tr_mod
            importlib.reload(tr_mod)
            result = tr_mod.translate_to_english("Bonjour le monde.", source_lang="fr")
        finally:
            if saved is not None:
                sys.modules["transformers"] = saved
            else:
                sys.modules.pop("transformers", None)
        self.assertIsNone(result)

    def test_translate_batch_skips_english(self):
        """translate_batch returns English texts as-is without translating."""
        mock_ld = MagicMock()
        mock_ld.detect = MagicMock(return_value="en")
        mock_ld.LangDetectException = Exception

        with patch.dict("sys.modules", {"langdetect": mock_ld}):
            import i18n.detect as det_mod
            importlib.reload(det_mod)
            import i18n.translate as tr_mod
            importlib.reload(tr_mod)

            english_text = "This is already in English and long enough to detect."
            results = tr_mod.translate_batch([english_text])

        self.assertEqual(len(results), 1)
        self.assertEqual(results[0], english_text)

    def test_translate_batch_same_length(self):
        """translate_batch always returns list of same length as input."""
        os.environ.pop("DEEPL_API_KEY", None)
        import i18n.translate as tr_mod
        importlib.reload(tr_mod)
        texts = ["text one " * 10, "text two " * 10, "text three " * 10]
        results = tr_mod.translate_batch(texts)
        self.assertEqual(len(results), len(texts))

    def test_translate_empty_list(self):
        import i18n.translate as tr_mod
        importlib.reload(tr_mod)
        results = tr_mod.translate_batch([])
        self.assertEqual(results, [])

    def test_never_raises(self):
        import i18n.translate as tr_mod
        importlib.reload(tr_mod)
        try:
            tr_mod.translate_to_english(None)  # type: ignore
        except Exception as exc:
            self.fail(f"translate_to_english raised: {exc}")


# ===========================================================================
# TestQueryExpand
# ===========================================================================

class TestQueryExpand(unittest.TestCase):

    def test_en_key_always_present(self):
        """expand_query always includes the original English query."""
        with patch("i18n.translate._translate_from_english", return_value=None):
            import i18n.query_expand as qe_mod
            importlib.reload(qe_mod)
            result = qe_mod.expand_query("ransomware payment")
        self.assertIn("en", result)
        self.assertEqual(result["en"], "ransomware payment")

    def test_skips_languages_where_translation_fails(self):
        """expand_query skips a language if translation returns None."""
        call_count = 0

        def mock_translate(text, lang):
            nonlocal call_count
            call_count += 1
            if lang in ("ru", "zh"):
                return f"translated_{lang}"
            return None

        with patch("i18n.translate._translate_from_english", side_effect=mock_translate):
            import i18n.query_expand as qe_mod
            importlib.reload(qe_mod)
            result = qe_mod.expand_query("test query", target_languages=["ru", "zh", "ar"])

        self.assertIn("en", result)
        self.assertIn("ru", result)
        self.assertIn("zh", result)
        self.assertNotIn("ar", result)
        # All returned values should be non-None strings
        for lang, val in result.items():
            self.assertIsNotNone(val)
            self.assertIsInstance(val, str)

    def test_returns_dict_of_strings(self):
        with patch("i18n.translate._translate_from_english", return_value="translated"):
            import i18n.query_expand as qe_mod
            importlib.reload(qe_mod)
            result = qe_mod.expand_query("test", target_languages=["ru"])
        self.assertIsInstance(result, dict)
        for val in result.values():
            self.assertIsInstance(val, str)

    def test_get_multilingual_search_terms_includes_original(self):
        """get_multilingual_search_terms returns flat list including original English."""
        with patch("i18n.translate._translate_from_english", return_value="translated"):
            import i18n.query_expand as qe_mod
            importlib.reload(qe_mod)
            terms = qe_mod.get_multilingual_search_terms("ransomware", ["ru", "es"])
        self.assertIn("ransomware", terms)
        self.assertIsInstance(terms, list)

    def test_get_multilingual_search_terms_no_none_values(self):
        """get_multilingual_search_terms never contains None values."""
        def mock_translate(text, lang):
            return f"t_{lang}" if lang != "zh" else None

        with patch("i18n.translate._translate_from_english", side_effect=mock_translate):
            import i18n.query_expand as qe_mod
            importlib.reload(qe_mod)
            terms = qe_mod.get_multilingual_search_terms("test", ["ru", "zh"])
        for term in terms:
            self.assertIsNotNone(term)

    def test_default_targets_when_none_specified(self):
        """expand_query uses default languages when target_languages is None."""
        with patch("i18n.translate._translate_from_english", return_value="translated"):
            import i18n.query_expand as qe_mod
            importlib.reload(qe_mod)
            result = qe_mod.expand_query("test query")
        # Should have "en" plus some translated languages
        self.assertIn("en", result)
        self.assertGreater(len(result), 1)


if __name__ == "__main__":
    unittest.main()
