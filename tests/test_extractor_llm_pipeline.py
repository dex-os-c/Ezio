"""Regression tests for LLM extraction and normalization provenance."""

import pytest


class _Response:
    content = (
        '{"crypto_wallets": ["0x0000000000000000000000000000000000000000"], '
        '"urls": ["https://example.com/report"], "threat_actor_handles": [], '
        '"malware_names": [], "dates": [], "cve_identifiers": [], '
        '"mitre_techniques": [], "file_hashes_md5": [], "file_hashes_sha1": [], '
        '"file_hashes_sha256": []}'
    )


class _FakeLLM:
    calls = 0

    def bind(self, **_kwargs):
        return self

    async def ainvoke(self, _prompt):
        self.calls += 1
        return _Response()


@pytest.mark.asyncio
async def test_llm_runs_when_regex_and_ner_found_nothing():
    from extractor.llm_extract import extract_with_llm

    llm = _FakeLLM()
    result = await extract_with_llm(
        "A prose-only incident report with no structured indicators.",
        llm,
        {},
        disable_cache=True,
    )

    assert llm.calls == 1
    assert result["ETHEREUM_ADDRESS"] == ["0x0000000000000000000000000000000000000000"]
    assert result["URL"] == ["https://example.com/report"]


def test_llm_provenance_and_wallet_validation():
    from extractor.normalizer import normalize_entities

    entities = normalize_entities(
        {
            "ETHEREUM_ADDRESS": ["0x0000000000000000000000000000000000000000"],
            "URL": ["https://example.com/report"],
        },
        "https://source.example/report",
        extraction_method_overrides={
            ("ETHEREUM_ADDRESS", "0x0000000000000000000000000000000000000000"): "LLM",
            ("URL", "https://example.com/report"): "LLM",
        },
    )

    by_type = {entity.entity_type: entity for entity in entities}
    assert by_type["ETHEREUM_ADDRESS"].extraction_method == "LLM"
    assert by_type["ETHEREUM_ADDRESS"].confidence < 1.0
    assert by_type["URL"].extraction_method == "LLM"


def test_wallet_checksum_and_hash_context_validation():
    from extractor.normalizer import normalize_entities
    from extractor.regex_patterns import extract_all

    assert normalize_entities(
        {"BITCOIN_ADDRESS": ["1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa"]},
        "https://source.example",
    )
    assert not normalize_entities(
        {"BITCOIN_ADDRESS": ["1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNb"]},
        "https://source.example",
    )

    bare_hash = "a" * 64
    assert bare_hash not in extract_all(bare_hash)["FILE_HASH_SHA256"]
    assert bare_hash in extract_all(f"sha256: {bare_hash}")["FILE_HASH_SHA256"]
