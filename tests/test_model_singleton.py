"""Tests for vector.model_singleton module."""

from __future__ import annotations

import threading
import time

import pytest


class TestModelSingleton:
    """Test suite for the embedding model singleton."""

    def test_same_instance_returned_from_multiple_calls(self):
        """Multiple calls to get_embedding_model return the same instance."""
        from vector.model_singleton import get_embedding_model

        model1 = get_embedding_model()
        model2 = get_embedding_model()

        assert model1 is model2
        assert id(model1) == id(model2)

    def test_parallel_threads_get_same_instance(self):
        """Threads calling get_embedding_model concurrently get the same instance."""
        from vector.model_singleton import get_embedding_model

        results: dict[int, int] = {}
        barrier = threading.Barrier(3)
        start_event = threading.Event()

        def worker(thread_id: int):
            barrier.wait()
            start_event.wait()
            model = get_embedding_model()
            results[thread_id] = id(model)

        threads = [
            threading.Thread(target=worker, args=(i,))
            for i in range(3)
        ]

        for t in threads:
            t.start()

        start_event.set()

        for t in threads:
            t.join()

        ids = list(results.values())
        assert len(set(ids)) == 1, f"Expected same instance, got ids: {ids}"

    def test_model_has_encode_method(self):
        """Returned model has the encode method needed for embeddings."""
        from vector.model_singleton import get_embedding_model

        model = get_embedding_model()
        assert model is not None
        assert hasattr(model, "encode")
        assert callable(model.encode)

    def test_model_produces_valid_embedding(self):
        """Model can encode text and produce valid embedding vector."""
        from vector.model_singleton import get_embedding_model

        model = get_embedding_model()
        if model is None:
            pytest.skip("Model not available")

        embedding = model.encode("test query", convert_to_numpy=True)
        assert embedding.shape == (384,)
        assert embedding.dtype == float