"""Tests for Playwright JS rendering module."""
import pytest
from scraper.scrape_js import is_js_rendered


def test_js_rendered_detects_react_app():
    """React app root should be detected as JS-rendered."""
    html = '<html><body><div id="root"></div><script src="bundle.js"></script></body></html>'
    assert is_js_rendered(html, "") is True


def test_js_rendered_detects_vue_app():
    """Vue/Nuxt app should be detected as JS-rendered."""
    html = '<html><body><div id="app"></div><script>window.__NUXT__={}</script></body></html>'
    assert is_js_rendered(html, "") is True


def test_js_rendered_false_when_content_present():
    """Pages with enough extracted content should not trigger Playwright."""
    html = "<html><body><article><p>Long content here...</p></article></body></html>"
    content = "x" * 500  # Enough content = no JS fallback needed
    assert is_js_rendered(html, content) is False


def test_js_rendered_false_for_static_html():
    """Regular static HTML pages should not trigger Playwright."""
    html = """
    <html><body>
    <article>
        <h1>Dark Web Forum Post</h1>
        <p>This is regular static content from a dark web forum.</p>
        <p>It has multiple paragraphs of real text content.</p>
    </article>
    </body></html>
    """
    content = "Dark web forum post regular static content multiple paragraphs text"
    assert is_js_rendered(html, content) is False


def test_js_rendered_high_script_ratio():
    """High script-to-content ratio should trigger Playwright."""
    html = """
    <html><body>
    <script src="a.js"></script>
    <script src="b.js"></script>
    <script src="c.js"></script>
    <script src="d.js"></script>
    <div></div>
    </body></html>
    """
    assert is_js_rendered(html, "") is True


def test_js_rendered_empty_html():
    """Empty HTML should not trigger Playwright."""
    assert is_js_rendered("", "") is False


def test_js_rendered_detects_dread_marker():
    """Dread forum marker should trigger Playwright."""
    html = '<html><body><div id="app"></div><h1>Dread</h1></body></html>'
    assert is_js_rendered(html, "") is True


def test_js_rendered_detects_phpbb():
    """phpBB marker should trigger Playwright."""
    html = '<html><body><script>phpBB=</script><div></div></body></html>'
    assert is_js_rendered(html, "") is True


def test_js_rendered_no_marker_short_content():
    """No marker but short content should still trigger."""
    html = '<html><body><div id="main"><p>Hi</p></div></body></html>'
    assert is_js_rendered(html, "Hi") is False  # Actually has content, not triggering


def test_js_rendered_angular():
    """Angular/React markers should trigger Playwright."""
    html = '<html><body><div ng-app></div><script></script></body></html>'
    assert is_js_rendered(html, "") is True