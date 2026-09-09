"""Contract tests for the structured, cluster-aware threat gazetteer."""

from __future__ import annotations

import json
from pathlib import Path

from extractor import gazetteer


DATA_PATH = Path(__file__).parents[1] / "data" / "threat_gazetteer.json"


def test_snapshot_uses_structured_cluster_records() -> None:
    data = json.loads(DATA_PATH.read_text(encoding="utf-8"))

    for category in ("threat_actors", "malware", "ransomware"):
        assert data[category]
        assert all(
            set(record) == {"canonical", "synonyms", "uuid"}
            and isinstance(record["canonical"], str)
            and isinstance(record["synonyms"], list)
            and isinstance(record["uuid"], str)
            for record in data[category]
        )


def test_alias_round_trips_to_blackcat_cluster() -> None:
    record = gazetteer.lookup("ALPHV", "ransomware")

    assert record is not None
    assert record["canonical"] == "BlackCat"
    assert set(record["synonyms"]) == {"ALPHV", "Noberus"}
    assert record["uuid"] == "e6c09b63-a424-4d9e-b7f7-b752cbbca02a"
    assert gazetteer.lookup("Noberus", "ransomware") == record


def test_existing_membership_category_and_suffix_matching_remain_available() -> None:
    assert gazetteer.is_known_ransomware("ALPHV")
    assert gazetteer.is_known("ALPHV", "RANSOMWARE_GROUP")
    assert gazetteer.category_of("ALPHV") == "ransomware"
    assert gazetteer.is_known_ransomware("BlackCat Ransomware Group")


def test_stats_expose_alias_index_and_source_coverage() -> None:
    stats = gazetteer.stats()
    data = json.loads(DATA_PATH.read_text(encoding="utf-8"))

    assert set(stats) == {"actors", "malware", "ransomware", "generated_at"}
    assert stats["actors"] > 0
    assert stats["malware"] > 0
    assert stats["ransomware"] > 0
    assert data["coverage"]["source_entries"] == 8933
    assert data["coverage"]["source_entries_with_synonyms"] == 2757
    assert data["coverage"]["sources"]["ransomware.json"]["synonym_coverage_pct"] == 9.7
