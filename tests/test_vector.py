"""
tests/test_vector.py — Phase 4 vector module (embedder, store, search).
"""

from __future__ import annotations

import os
import sys
import time
import unittest
from unittest.mock import MagicMock, patch

_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)


class TestEmbedder(unittest.TestCase):
    def tearDown(self):
        import vector.embedder as emb

        emb._EMBEDDER = None

    def test_embed_text_returns_floats(self):
        import numpy as np
        import vector.embedder as emb

        mock_model = MagicMock()
        mock_model.tokenizer.encode = MagicMock(return_value=[1, 2, 3])
        mock_model.tokenizer.decode = MagicMock(return_value="hello")
        mock_model.encode = MagicMock(
            return_value=np.array([0.1] * 384, dtype=np.float32)
        )
        emb._EMBEDDER = mock_model
        out = emb.embed_text("hello world")
        self.assertIsNotNone(out)
        assert out is not None
        self.assertEqual(len(out), 384)
        self.assertIsInstance(out[0], float)

    def test_embed_text_empty_returns_none(self):
        import vector.embedder as emb

        emb._EMBEDDER = MagicMock()
        self.assertIsNone(emb.embed_text(""))
        self.assertIsNone(emb.embed_text("   "))

    def test_embed_text_unavailable_returns_none(self):
        import vector.embedder as emb

        with patch.object(emb, "get_embedder", return_value=None):
            self.assertIsNone(emb.embed_text("x"))

    def test_embed_batch_same_length(self):
        import numpy as np
        import vector.embedder as emb

        mock_model = MagicMock()
        mock_model.tokenizer.encode = MagicMock(return_value=[1, 2])
        mock_model.tokenizer.decode = MagicMock(return_value="x")
        mock_model.encode = MagicMock(
            return_value=np.array([[0.0] * 384, [0.1] * 384], dtype=np.float32)
        )
        emb._EMBEDDER = mock_model
        batch = emb.embed_batch(["a", "", "b"])
        self.assertEqual(len(batch), 3)
        self.assertIsNone(batch[1])
        self.assertIsNotNone(batch[0])
        self.assertIsNotNone(batch[2])

    def test_get_embedder_singleton(self):
        import vector.embedder as emb

        m = MagicMock()
        emb._EMBEDDER = m
        self.assertIs(emb.get_embedder(), m)
        self.assertIs(emb.get_embedder(), m)


class TestStore(unittest.TestCase):
    def test_upsert_success(self):
        import vector.store as store

        mock_col = MagicMock()
        with patch.object(store, "get_collection", return_value=mock_col):
            with patch.object(store.embedder, "embed_text", return_value=[0.0] * 384):
                ok = store.upsert_page(
                    "http://test.onion/p",
                    "body text",
                    metadata={"k": "v"},
                    page_id=42,
                )
        self.assertTrue(ok)
        mock_col.upsert.assert_called_once()

    def test_upsert_false_without_embedder(self):
        import vector.store as store

        mock_col = MagicMock()
        with patch.object(store, "get_collection", return_value=mock_col):
            with patch.object(store.embedder, "embed_text", return_value=None):
                self.assertFalse(
                    store.upsert_page("http://x.onion", "t"),
                )

    def test_search_similar_structure(self):
        import vector.store as store

        mock_col = MagicMock()
        mock_col.query.return_value = {
            "ids": [["id1"]],
            "distances": [[0.12]],
            "metadatas": [[{"url": "http://a.onion", "page_id": "7"}]],
        }
        with patch.object(store, "get_collection", return_value=mock_col):
            with patch.object(store.embedder, "embed_text", return_value=[0.0] * 384):
                rows = store.search_similar("q", n_results=5)
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["url"], "http://a.onion")
        self.assertEqual(rows[0]["page_id"], 7)
        self.assertAlmostEqual(rows[0]["distance"], 0.12)

    def test_is_duplicate_below_threshold(self):
        import vector.store as store

        with patch.object(
            store,
            "search_similar",
            return_value=[{"distance": 0.01, "url": "u", "page_id": None, "metadata": {}}],
        ):
            self.assertTrue(store.is_duplicate("text", threshold=0.05))

    def test_is_duplicate_no_collection(self):
        import vector.store as store

        with patch.object(store, "get_collection", return_value=None):
            self.assertFalse(store.is_duplicate("x"))

    def test_get_collection_stats(self):
        import vector.store as store

        mock_col = MagicMock()
        mock_col.count.return_value = 3
        with patch.object(store, "get_collection", return_value=mock_col):
            with patch.object(store, "_persist_dir", MagicMock(return_value="/tmp/c")):
                stats = store.get_collection_stats()
        self.assertEqual(stats["total_documents"], 3)
        self.assertIn("persist_directory", stats)

    def test_bulk_check_cache_performance(self):
        import vector.store as store

        num_cached = 10000
        num_query = 1000

        cached_urls = [f"http://cached{i}.onion" for i in range(num_cached)]
        query_urls = [cached_urls[i * 10] for i in range(num_query)]

        cached_ids = [store._stable_id(url) for url in cached_urls]
        query_ids = [store._stable_id(url) for url in query_urls]

        from datetime import datetime, timezone
        fresh_ts = datetime.now(timezone.utc).isoformat()
        cached_metas = [
            {"url": url, "timestamp": fresh_ts}
            for url in cached_urls
        ]
        cached_docs = ["x" * 200] * num_cached

        mock_col = MagicMock()
        mock_col.get.return_value = {
            "ids": cached_ids,
            "metadatas": cached_metas,
            "documents": cached_docs,
        }

        with patch.object(store, "get_collection", return_value=mock_col):
            start = time.perf_counter()
            cached, uncached = store.bulk_check_cache(query_urls, max_age_hours=24)
            elapsed = time.perf_counter() - start

        self.assertLess(elapsed, 0.1, f"bulk_check_cache took {elapsed*1000:.1f}ms, expected <100ms")
        self.assertEqual(len(cached), num_query)
        self.assertEqual(len(uncached), 0)


class TestSearch(unittest.TestCase):
    def test_find_related_pages_delegates(self):
        import vector.search as vsearch

        with patch.object(
            vsearch.store,
            "search_similar",
            return_value=[{"url": "u"}],
        ) as m:
            out = vsearch.find_related_pages("q", n_results=3)
        m.assert_called_once_with("q", n_results=3)
        self.assertEqual(out, [{"url": "u"}])

    def test_find_pages_similar_unknown(self):
        import vector.search as vsearch

        mock_col = MagicMock()
        mock_col.get.return_value = {"embeddings": [None]}
        with patch.object(vsearch.store, "get_collection", return_value=mock_col):
            self.assertEqual(
                vsearch.find_pages_similar_to("http://missing.onion"),
                [],
            )

    def test_cross_investigation_excludes(self):
        import vector.search as vsearch

        with patch.object(
            vsearch.store,
            "search_similar",
            return_value=[],
        ) as m:
            vsearch.cross_investigation_recall("q", exclude_investigation_id=99)
        m.assert_called_once_with(
            "q",
            n_results=10,
            where={"investigation_id": {"$ne": "99"}},
        )


if __name__ == "__main__":
    unittest.main()
