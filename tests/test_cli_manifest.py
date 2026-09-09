from ezio_cli.commands.investigate import _append_enrichment_pages_to_manifest


def test_enrichment_pages_are_added_once_to_manifest():
    scraped = [{"url": "https://example.test/core", "source": "rss_feed"}]
    enrichment = [
        {"url": "https://example.test/core", "source": "enrichment"},
        {"url": "https://example.test/ransomware", "source": "ransomware_live"},
    ]

    result = _append_enrichment_pages_to_manifest(scraped, enrichment)

    assert [page["url"] for page in result] == [
        "https://example.test/core",
        "https://example.test/ransomware",
    ]
    assert result[1]["source"] == "ransomware_live"
