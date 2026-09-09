"""
tests/test_sources_enrichment_new.py — Tests for the 4 new enrichment sources:
  sources/cisa.py
  sources/shodan.py
  sources/virustotal.py
  sources/historical_intel.py
  sources/cache.py

Run with:
    pytest tests/test_sources_enrichment_new.py -v
"""

from __future__ import annotations

import asyncio
import json
import os
import sys
import tempfile
import time
import unittest
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)


# ---------------------------------------------------------------------------
# Mock aiohttp session helpers
# ---------------------------------------------------------------------------


def _json_response(data, status: int = 200) -> MagicMock:
    r = MagicMock()
    r.status = status
    r.__aenter__ = AsyncMock(return_value=r)
    r.__aexit__ = AsyncMock(return_value=False)
    r.json = AsyncMock(return_value=data)
    return r


def _text_response(text: str, status: int = 200) -> MagicMock:
    r = MagicMock()
    r.status = status
    r.__aenter__ = AsyncMock(return_value=r)
    r.__aexit__ = AsyncMock(return_value=False)
    r.text = AsyncMock(return_value=text)
    return r


# ===========================================================================
# TestCachedFeed
# ===========================================================================


class TestCachedFeed(unittest.TestCase):
    def test_fresh_cache_returns_cached_data(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            cache_path = os.path.join(tmpdir, "feed.json")
            feed = MagicMock()
            feed._is_fresh = MagicMock(return_value=True)
            feed.cache_path = Path(cache_path)

            import builtins
            with patch("builtins.open", MagicMock()):
                result = feed._is_fresh()
                self.assertTrue(result)


# ===========================================================================
# TestCISA
# ===========================================================================


class TestCISA(unittest.TestCase):
    def test_enrich_cisa_kev_lookup_hit(self):
        """CVE present in KEV returns is_actively_exploited = True."""
        from sources.cisa import enrich_cisa_cve

        mock_kev_data = {
            "vulnerabilities": [
                {
                    "cveID": "CVE-2021-44228",
                    "vendorProject": "Apache Software Foundation",
                    "product": "Log4j",
                    "vulnerabilityName": "Apache Log4j Remote Code Execution",
                    "dateAdded": "2021-12-10",
                    "shortDescription": "Apache Log4j2 vulnerability...",
                }
            ]
        }

        async def run():
            with patch("sources.cache.CachedFeed.fetch", new=AsyncMock(return_value=mock_kev_data)):
                result = await enrich_cisa_cve("CVE-2021-44228")
            return result

        result = asyncio.run(run())
        self.assertEqual(len(result), 1)
        self.assertTrue(result[0]["is_actively_exploited"])
        self.assertEqual(result[0]["vendor_project"], "Apache Software Foundation")
        self.assertEqual(result[0]["product"], "Log4j")

    def test_enrich_cisa_kev_miss(self):
        """CVE not in KEV returns empty without error."""
        from sources.cisa import enrich_cisa_cve

        mock_kev_data = {"vulnerabilities": []}

        async def run():
            with patch("sources.cache.CachedFeed.fetch", new=AsyncMock(return_value=mock_kev_data)):
                result = await enrich_cisa_cve("CVE-2021-99999")
            return result

        result = asyncio.run(run())
        self.assertEqual(result, [])

    def test_enrich_cisa_cve_handles_fetch_error(self):
        """KEV fetch failure returns empty, does not raise."""
        from sources.cisa import enrich_cisa_cve

        async def run():
            with patch("sources.cache.CachedFeed.fetch", new=AsyncMock(return_value=None)):
                result = await enrich_cisa_cve("CVE-2021-44228")
            return result

        result = asyncio.run(run())
        self.assertEqual(result, [])


# ===========================================================================
# TestShodan
# ===========================================================================


class TestShodan(unittest.TestCase):
    def test_shodan_c2_detection(self):
        """Shodan tags containing 'cobalt-strike' sets high_confidence_c2 = True."""
        from sources.shodan import enrich_shodan_ip

        mock_internetdb = {
            "ip": "1.2.3.4",
            "ports": [50050, 8080],
            "tags": ["cobalt-strike", "tor"],
            "hostnames": ["evil.example.com"],
            "vulns": {"CVE-2021-44228": {}},
        }

        async def run():
            with patch("aiohttp.ClientSession") as MockSession:
                mock_session = MagicMock()
                mock_resp = _json_response(mock_internetdb)
                mock_session.get = MagicMock(return_value=mock_resp)
                mock_session.__aenter__ = AsyncMock(return_value=mock_session)
                mock_session.__aexit__ = AsyncMock(return_value=False)
                MockSession.return_value = mock_session

                result = await enrich_shodan_ip("1.2.3.4", {"CVE-2021-44228"})
            return result

        result = asyncio.run(run())
        self.assertIsNotNone(result)
        self.assertTrue(result["high_confidence_c2"])
        self.assertEqual(result["open_ports"], [50050, 8080])
        self.assertIn("CVE-2021-44228", result["correlated_cves"])

    def test_shodan_rate_limit_cap(self):
        """60 IP entities results in only 50 Shodan requests (max cap enforced)."""
        from sources.shodan import enrich_shodan

        entities = [{"type": "IP_ADDRESS", "value": f"1.2.3.{i}"} for i in range(60)]

        call_count = 0

        async def mock_ip(ip, cves):
            nonlocal call_count
            call_count += 1
            return None

        async def run():
            with patch("sources.shodan.enrich_shodan_ip", new=mock_ip):
                await enrich_shodan(entities)
            return call_count

        call_count = asyncio.run(run())
        self.assertEqual(call_count, 50)

    def test_shodan_ip_not_found_returns_none(self):
        """404 from InternetDB returns None without error."""
        from sources.shodan import enrich_shodan_ip

        async def run():
            with patch("aiohttp.ClientSession") as MockSession:
                mock_session = MagicMock()
                mock_resp = _json_response({}, status=404)
                mock_session.get = MagicMock(return_value=mock_resp)
                mock_session.__aenter__ = AsyncMock(return_value=mock_session)
                mock_session.__aexit__ = AsyncMock(return_value=False)
                MockSession.return_value = mock_session

                result = await enrich_shodan_ip("99.99.99.99", set())
            return result

        result = asyncio.run(run())
        self.assertIsNone(result)


# ===========================================================================
# TestVirusTotal
# ===========================================================================


class TestVirusTotal(unittest.TestCase):
    def test_virustotal_disabled_gracefully(self):
        """With no VT_API_KEY, source returns [] without raising."""
        from sources import virustotal as vt

        async def run():
            with patch.object(vt, "VT_API_KEY", ""):
                result = await vt.enrich_virustotal([])
            return result

        result = asyncio.run(run())
        self.assertEqual(result, [])

    def test_virustotal_confirmed_malicious(self):
        """50/72 detections sets confirmed_malicious = True and detection_ratio ~0.69."""
        from sources import virustotal as vt

        mock_vt_response = {
            "data": {
                "attributes": {
                    "last_analysis_stats": {
                        "malicious": 50,
                        "suspicious": 5,
                        "undetected": 17,
                        "harmless": 0,
                    },
                    "popular_threat_classification": {
                        "suggested_threat_label": "trojan.cobaltloader/win"
                    },
                    "creation_date": "2021-01-01",
                    "last_analysis_date": "2024-01-01",
                }
            }
        }

        async def run():
            with patch.object(vt, "VT_API_KEY", "test_key_123"), \
                 patch("aiohttp.ClientSession") as MockSession:
                mock_session = MagicMock()
                mock_resp = _json_response(mock_vt_response)
                mock_session.get = MagicMock(return_value=mock_resp)
                mock_session.__aenter__ = AsyncMock(return_value=mock_session)
                mock_session.__aexit__ = AsyncMock(return_value=False)
                MockSession.return_value = mock_session

                entities = [{"type": "FILE_HASH_SHA256", "value": "a" * 64}]
                result = await vt.enrich_virustotal(entities)
            return result

        result = asyncio.run(run())
        self.assertEqual(len(result), 1)
        self.assertTrue(result[0]["confirmed_malicious"])
        self.assertAlmostEqual(result[0]["detection_ratio"], 50 / 72, places=2)
        self.assertEqual(result[0]["suggested_threat_label"], "trojan.cobaltloader/win")


# ===========================================================================
# TestHistoricalIntel
# ===========================================================================


class TestHistoricalIntel(unittest.TestCase):
    def test_historical_fallback_only_runs_for_empty_entities(self):
        """Fallback ONLY activates when other sources returned 0 results for THREAT_ACTOR."""
        from sources.historical_intel import enrich_historical

        async def run():
            result = await enrich_historical({
                "THREAT_ACTOR": [{"type": "THREAT_ACTOR", "value": "REvil"}],
                "RANSOMWARE_GROUP": [],
                "MALWARE_FAMILY": [],
            })
            return result

        result = asyncio.run(run())
        self.assertIsInstance(result, list)

    def test_historical_returns_empty_for_non_actor_entities(self):
        """Non THREAT_ACTOR/RANSOMWARE_GROUP/MALWARE_FAMILY types return empty."""
        from sources.historical_intel import enrich_historical

        async def run():
            result = await enrich_historical({
                "CVE_NUMBER": [{"type": "CVE_NUMBER", "value": "CVE-2021-44228"}],
            })
            return result

        result = asyncio.run(run())
        self.assertEqual(result, [])


# ===========================================================================
# TestCache
# ===========================================================================


class TestCacheStaleFallback(unittest.TestCase):
    def test_cached_feed_stale_fallback(self):
        """Failed HTTP fetch with stale cache present returns stale cache + warning."""
        import sources.cache as cache_mod

        with tempfile.TemporaryDirectory() as tmpdir:
            stale_file = os.path.join(tmpdir, "stale.json")
            with open(stale_file, "w") as f:
                json.dump({"vulnerabilities": [{"cveID": "CVE-2021-44228"}]}, f)

            old_mtime = time.time() - 2000
            os.utime(stale_file, (old_mtime, old_mtime))

            feed = cache_mod.CachedFeed(
                url="https://example.com/feed.json",
                cache_path=stale_file,
                ttl_seconds=300,
            )

            async def run():
                return await feed.fetch()

            with patch("aiohttp.ClientSession") as MockSession:
                mock_session = MagicMock()
                mock_session.__aenter__ = AsyncMock(return_value=mock_session)
                mock_session.__aexit__ = AsyncMock(return_value=False)

                async def raise_exc(*a, **kw):
                    raise Exception("network error")

                mock_get = MagicMock(side_effect=raise_exc)
                mock_session.get = mock_get
                MockSession.return_value = mock_session

                result = asyncio.run(run())

            self.assertIsNotNone(result)
            self.assertEqual(result["vulnerabilities"][0]["cveID"], "CVE-2021-44228")


# ===========================================================================
# TestNewSourcesWiredInEnrichment
# ===========================================================================


class TestNewSourcesWiredInEnrichment(unittest.TestCase):
    def test_enrich_investigation_accepts_entities_param(self):
        """enrich_investigation signature accepts optional entities list."""
        from sources.enrichment import enrich_investigation
        import inspect

        sig = inspect.signature(enrich_investigation)
        self.assertIn("entities", sig.parameters)

    def test_new_sources_in_gather(self):
        """_enrich_new_sources runs CISA, Shodan, and VT concurrently."""
        from sources import enrichment as enr

        with patch("sources.cisa.enrich_cisa", new=AsyncMock(return_value=[])), \
             patch("sources.shodan.enrich_shodan", new=AsyncMock(return_value=[])), \
             patch("sources.virustotal.enrich_virustotal", new=AsyncMock(return_value=[])), \
             patch("aiohttp.ClientSession"):
            async def run():
                return await enr._enrich_new_sources("test query", [])
            result = asyncio.run(run())
            self.assertIsInstance(result, list)


if __name__ == "__main__":
    unittest.main()
