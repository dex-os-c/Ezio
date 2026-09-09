from __future__ import annotations

import os
import sys
import unittest
from unittest.mock import AsyncMock, MagicMock, patch

from fastapi.testclient import TestClient

_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)


class TestMonitorIntegration(unittest.IsolatedAsyncioTestCase):
    async def test_keyword_watch_creates_investigation_and_rebuilds_graph(self):
        import monitor.jobs as jobs

        watch = {"name": "keyword-watch", "query": "alpha beta", "type": "keyword"}
        inv = MagicMock()
        inv.id = "inv-1"
        mock_er = MagicMock()
        mock_er.entity_count = 2
        mock_er.errors = []
        graph_obj = MagicMock()

        with patch("db.session.get_session") as get_session:
            session = MagicMock()
            session_inv = MagicMock()
            session.get.return_value = session_inv
            get_session.return_value.__enter__.return_value = session
            with patch.object(jobs.search, "get_search_results", return_value=[{"link": "http://a.onion", "title": "A"}]):
                with patch.object(jobs.scrape, "scrape_multiple", return_value={"http://a.onion": "body"}):
                    with patch.object(jobs.vector, "bulk_check_cache", return_value=([], ["http://a.onion"])):
                        with patch.object(jobs.vector, "is_duplicate", return_value=False):
                            with patch.object(jobs.vector, "upsert_page", return_value=True):
                                with patch.object(jobs, "get_investigation_by_query", return_value=None) as get_inv:
                                    with patch.object(jobs, "create_investigation", return_value=inv) as create_inv:
                                        with patch.object(jobs, "extract_entities_from_pages", new_callable=AsyncMock, return_value=[mock_er]) as extract:
                                            with patch.object(jobs.graph, "build_graph_from_db", return_value=graph_obj) as build:
                                                with patch.object(jobs.graph, "infer_relationships", return_value=graph_obj) as infer:
                                                    with patch.object(jobs.graph, "persist_graph_edges", create=True, return_value={"status": "written"}) as persist:
                                                        result = await jobs.run_keyword_watch(watch, llm=None)

        self.assertEqual(result["new_entities"], 2)
        get_inv.assert_called_once()
        create_inv.assert_called_once()
        extract.assert_awaited_once()
        build.assert_called_once_with(investigation_id="inv-1")
        infer.assert_called_once_with(graph_obj)
        persist.assert_called_once_with(graph_obj, "inv-1")
        self.assertTrue(session.commit.called)

    async def test_url_watch_associates_with_investigation(self):
        import monitor.jobs as jobs

        watch = {"name": "url-watch", "url": "http://u.onion", "type": "url"}
        inv = MagicMock()
        inv.id = "inv-2"
        mock_er = MagicMock()
        mock_er.entity_count = 3

        with patch("db.session.get_session") as get_session:
            session = MagicMock()
            session.get.return_value = None
            get_session.return_value.__enter__.return_value = session
            with patch.object(jobs._db, "get_last_cleaned_text_for_url", return_value="old"):
                with patch.object(jobs.scrape, "scrape_multiple", return_value={"http://u.onion": "new"}):
                    with patch.object(jobs.vector, "upsert_page", return_value=True):
                        with patch.object(jobs, "get_investigation_by_query", return_value=None):
                            with patch.object(jobs, "create_investigation", return_value=inv):
                                with patch.object(jobs, "extract_entities_from_page", new_callable=AsyncMock, return_value=mock_er) as extract:
                                    result = await jobs.run_url_watch(watch, llm=object())

        self.assertTrue(result["changed"])
        extract.assert_awaited_once()
        kwargs = extract.await_args.kwargs
        self.assertEqual(kwargs["investigation_id"], "inv-2")

    async def test_crawler_checks_cache_before_fetching(self):
        import crawler.spider as spider

        cached = {"link": "http://cached.onion", "content": "cached body"}
        spider_obj = spider.Spider(["http://cached.onion", "http://fresh.onion"], "q", max_pages=2)
        spider_obj._process_url = AsyncMock()

        # run() no longer builds a connector or a ClientSession — sessions come
        # from the shared Tor pool, acquired inside _process_url, which is
        # mocked out entirely here.  The connector/session patches this test
        # used to need are therefore gone rather than retargeted.
        with patch.object(spider, "is_valid_onion", return_value=True):
            with patch.object(spider, "bulk_check_cache", return_value=([cached], ["http://fresh.onion"])):
                with patch.object(spider, "upsert_page", return_value=True) as upsert:
                    result = await spider_obj.run()

        self.assertEqual(result.pages_crawled, 1)
        spider_obj._process_url.assert_awaited_once()
        upsert.assert_called_once()


class TestSearchEndpoints(unittest.TestCase):
    def setUp(self):
        import api.main as main

        self.app = main.app
        self.app.dependency_overrides.clear()
        from api.auth import get_current_user

        self.app.dependency_overrides[get_current_user] = lambda: MagicMock(user=MagicMock(id=1))
        self.client = TestClient(self.app)

    def tearDown(self):
        self.app.dependency_overrides.clear()

    def test_semantic_search_schema(self):
        with patch("vector.search_similar", return_value=[{"url": "http://x.onion", "distance": 0.1, "metadata": {}}]):
            resp = self.client.get("/search/semantic", params={"q": "alpha", "n": 5})
        self.assertEqual(resp.status_code, 200)
        body = resp.json()
        self.assertIn("results", body)
        self.assertEqual(body["results"][0]["url"], "http://x.onion")

    def test_similar_to_schema(self):
        with patch("vector.find_pages_similar_to", return_value=[{"url": "http://x.onion", "distance": 0.2, "metadata": {}}]):
            resp = self.client.get("/search/similar-to", params={"url": "http://ref.onion"})
        self.assertEqual(resp.status_code, 200)
        self.assertIn("results", resp.json())

    def test_cross_investigation_schema(self):
        with patch("vector.cross_investigation_recall", return_value=[{"url": "http://x.onion", "distance": 0.3, "metadata": {}}]):
            resp = self.client.get("/search/cross-investigation", params={"q": "alpha"})
        self.assertEqual(resp.status_code, 200)
        self.assertIn("results", resp.json())

    def test_stats_schema(self):
        with patch("vector.get_collection_stats", return_value={"total_documents": 7, "persist_directory": "/tmp/chroma"}):
            with patch("vector.count_pages", return_value=7):
                with patch("vector.get_collection", return_value=MagicMock()):
                    resp = self.client.get("/search/stats")
        self.assertEqual(resp.status_code, 200)
        body = resp.json()
        self.assertEqual(body["total_documents"], 7)
        self.assertTrue(body["chromadb_available"])


if __name__ == "__main__":
    unittest.main()
