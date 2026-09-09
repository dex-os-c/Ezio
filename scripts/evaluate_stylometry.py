"""Evaluate stylometry calibration data.

Input JSONL records must contain ``text_a``, ``text_b`` and ``same_author``.
The output is a calibration artifact consumed through
``STYLOMETRY_CALIBRATION_FILE``.  Threshold selection maximizes balanced
accuracy, with false-match rate used as the tie-breaker.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from fingerprint.stylometry import compute_similarity, extract_style_vector, fit_reference_stats


def evaluate(path: str) -> dict:
    pairs: list[tuple[dict, dict, bool]] = []
    vectors: list[dict] = []
    for line in Path(path).read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        row = json.loads(line)
        a, b = extract_style_vector(row["text_a"]), extract_style_vector(row["text_b"])
        if a is not None and b is not None:
            pairs.append((a, b, bool(row["same_author"])))
            vectors.extend((a, b))
    reference_stats = fit_reference_stats(vectors)
    scores = [(compute_similarity(a, b, reference_stats), label) for a, b, label in pairs]
    if not scores or not any(label for _, label in scores) or not any(not label for _, label in scores):
        raise ValueError("calibration data needs valid same-author and different-author pairs")

    candidates = sorted({score for score, _ in scores})
    best = None
    for threshold in candidates:
        tp = sum(score >= threshold and label for score, label in scores)
        fn = sum(score < threshold and label for score, label in scores)
        fp = sum(score >= threshold and not label for score, label in scores)
        tn = sum(score < threshold and not label for score, label in scores)
        tpr = tp / (tp + fn) if tp + fn else 0.0
        tnr = tn / (tn + fp) if tn + fp else 0.0
        fmr = fp / (fp + tn) if fp + tn else 0.0
        candidate = ( (tpr + tnr) / 2, -fmr, threshold, fmr, tpr, tnr )
        if best is None or candidate > best:
            best = candidate
    assert best is not None
    _, _, threshold, fmr, tpr, tnr = best
    return {
        "method": "burrows_delta_zscore",
        "threshold": threshold,
        "false_match_rate": fmr,
        "true_match_rate": tpr,
        "true_negative_rate": tnr,
        "validation_pairs": len(scores),
        "dataset": str(path),
        "reference_stats": reference_stats,
    }


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("input_jsonl")
    parser.add_argument("output_json")
    args = parser.parse_args()
    Path(args.output_json).write_text(json.dumps(evaluate(args.input_jsonl), indent=2) + "\n", encoding="utf-8")
