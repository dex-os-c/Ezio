import pytest

from extractor.relationship_extract import (
    _COMPATIBILITY_GUIDE,
    extract_relationships_for_page,
    extract_relationships_from_results,
)


class _Response:
    content = '{"relationships": [{"source": 0, "target": 1, "type": "uses", "confidence": 0.9}, {"source": 0, "target": 2, "type": "uses", "confidence": 0.9}]}'


class _LLM:
    def __init__(self):
        self.prompt = ""

    def with_config(self, _config):
        return self

    async def ainvoke(self, prompt):
        self.prompt = prompt
        return _Response()


@pytest.mark.asyncio
async def test_prompt_contains_shared_compatibility_guide_and_invalid_pair_is_dropped():
    llm = _LLM()
    entities = [
        {"id": "actor", "type": "THREAT_ACTOR_HANDLE", "value": "@actor"},
        {"id": "tool", "type": "TOOL", "value": "Rclone"},
        {"id": "hash", "type": "FILE_HASH_SHA256", "value": "abc"},
    ]

    relationships = await extract_relationships_for_page("actor uses rclone", entities, llm)

    assert relationships == [
        {
            "entity_a_id": "actor",
            "entity_b_id": "tool",
            "relationship_type": "USES",
            "confidence": 0.9,
        }
    ]
    assert _COMPATIBILITY_GUIDE in llm.prompt


@pytest.mark.asyncio
async def test_relationship_provenance_uses_page_manifest_id():
    class _Result:
        page_url = "https://example.test/page"
        entity_ids = ["actor", "org"]
        entities = [
            type("Entity", (), {"entity_type": "THREAT_ACTOR_HANDLE", "value": "@actor", "confidence": 1.0})(),
            type("Entity", (), {"entity_type": "ORGANIZATION_NAME", "value": "Acme", "confidence": 1.0})(),
        ]

    class _TargetLLM(_LLM):
        async def ainvoke(self, prompt):
            self.prompt = prompt
            return type(
                "Response",
                (),
                {"content": '{"relationships": [{"source": 0, "target": 1, "type": "targets", "confidence": 0.8}]}'},
            )()

    relationships = await extract_relationships_from_results(
        [_Result()],
        {"https://example.test/page": "actor targets Acme"},
        {"https://example.test/page": "page-123"},
        _TargetLLM(),
    )

    assert relationships[0]["source_page_id"] == "page-123"
