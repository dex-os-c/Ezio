"""
Thread-safe singleton for the SentenceTransformer embedding model.

Loads all-MiniLM-L6-v2 lazily on first use, then reuses the same instance
across all consumers. This eliminates the ~80 MB duplicate model weight
problem when multiple modules each instantiate their own model at load time.

Import torch and SentenceTransformer INSIDE the getter function to avoid
the 2-5 second startup delay from torch enumerating CUDA devices.
"""

from __future__ import annotations

import logging
import hashlib
import os
import threading

logger = logging.getLogger(__name__)

_model: "SentenceTransformer | None" = None
_lock = threading.Lock()


class _FallbackEmbeddingModel:
    """Small deterministic encoder used when sentence-transformers cannot load."""

    def encode(self, text, convert_to_numpy: bool = True, **_kwargs):
        import numpy as np

        payload = text if isinstance(text, str) else "\n".join(map(str, text))
        digest = hashlib.sha256(payload.encode("utf-8", errors="ignore")).digest()
        values = [((digest[i % len(digest)] / 255.0) * 2.0) - 1.0 for i in range(384)]
        arr = np.array(values, dtype=float)
        if isinstance(text, list):
            arr = np.vstack([arr for _ in text])
        return arr if convert_to_numpy else arr.tolist()


class _EmbeddingModelWrapper:
    def __init__(self, model):
        self._model = model

    def __getattr__(self, name):
        return getattr(self._model, name)

    def encode(self, *args, **kwargs):
        result = self._model.encode(*args, **kwargs)
        try:
            import numpy as np

            if isinstance(result, np.ndarray):
                return result.astype(float)
        except Exception:
            pass
        return result


def get_embedding_model() -> "SentenceTransformer | None":
    """
    Return the shared SentenceTransformer instance.

    Lazy-loads the model on first call, then caches it for all subsequent calls.
    Thread-safe: uses a lock to prevent race conditions during init.
    """
    global _model

    if _model is not None:
        return _model

    with _lock:
        if _model is not None:
            return _model

        os.environ.setdefault("TRANSFORMERS_NO_TF", "1")
        os.environ.setdefault("USE_TF", "0")

        try:
            import torch  # noqa: PLC0415,F401 - imported inside function per M-6
            from sentence_transformers import SentenceTransformer  # noqa: PLC0415
            _model = _EmbeddingModelWrapper(SentenceTransformer("all-MiniLM-L6-v2"))
            logger.info("Loaded embedding model all-MiniLM-L6-v2 (singleton)")
        except Exception as exc:
            logger.warning("Failed to load embedding model: %s", exc)
            logger.warning(
                "Deterministic embedding fallback is active; install "
                "ezio[nlp] (torch + sentence-transformers) for full "
                "vector embeddings."
            )
            _model = _FallbackEmbeddingModel()

    return _model
