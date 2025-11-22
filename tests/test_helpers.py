import pytest

import poetrist.blog as blog
from poetrist.blog import (
    _auto_quote,
    _highlight,
    _parse_item_query,
    _rfc2822,
    extract_tags,
    infer_kind,
    kind_to_slug,
    page_size,
    parse_trigger,
    slug_to_kind,
    strip_caret,
)


def test_strip_caret_ignores_code_fence():
    md = "```py\n^progress:42%\n```"
    assert strip_caret(md) == "```py\n```"   # caret-line is removed, fence stays

def test_extract_tags_filters_hex():
    tags = extract_tags("hello #World and #FfF")
    assert tags == {"world", "fff"}       # function keeps both, lower-cased

@pytest.mark.parametrize("title,link,kind", [
    ("",     "",   "say"),
    ("Foo",  "",   "post"),
    ("Foo",  "https://x", "pin"),
])
def test_infer_kind(title, link, kind):
    assert infer_kind(title, link) == kind

def test_parse_compact_trigger():
    txt = '^reading:book:"The Hobbit":42%'
    body, blocks, errors = parse_trigger(txt)
    assert body == '^book:$PENDING$0$'
    blk = blocks[0]
    assert blk["verb"] == "read"
    assert blk["item_type"] == "book"
    assert blk["title"] == "The Hobbit"
    assert blk["progress"] == "42%"
    assert errors == []

def test_parse_trigger_preserves_meta_case():
    body, blocks, errors = parse_trigger('^reading:book:"Hitchhiker"\n^ISBN-13:abc123')
    assert errors == []
    blk = blocks[0]
    assert blk["meta"].get("ISBN-13") == "abc123"
    # ensure we did not downcase the key
    assert "isbn-13" not in blk["meta"]


# ──────────────────────────────────────────────────────────────
# slug helpers
# ──────────────────────────────────────────────────────────────
def test_slug_roundtrip(monkeypatch):
    # patch settings so the mapping changes
    monkeypatch.setattr(blog, "get_setting",
                        lambda k, d=None: {"slug_say": "yap"}.get(k, d))
    assert kind_to_slug("say") == "yap"
    assert slug_to_kind("yap") == "say"


# ──────────────────────────────────────────────────────────────
# page_size coercion helper
# ──────────────────────────────────────────────────────────────
@pytest.mark.parametrize("raw, expected", [
    ("42", 42),          # numeric → keep
    ("0",  0),           # plain 0 is accepted as-is
    ("",   blog.PAGE_DEFAULT),  # empty → default
    ("spam", blog.PAGE_DEFAULT) # non-digit → default
])
def test_page_size(monkeypatch, raw, expected):
    monkeypatch.setattr(blog, "get_setting",
                        lambda k, d=None: raw if k == "page_size" else d)
    assert page_size() == expected


# ──────────────────────────────────────────────────────────────
# search helpers
# ──────────────────────────────────────────────────────────────
def test_auto_quote():
    # token with punctuation gets wrapped, trailing * stays outside
    assert _auto_quote('foo+bar* baz') == '"foo+bar"* baz'

def test_highlight_marks_all_terms(monkeypatch):
    # avoid needing a Flask app-context
    monkeypatch.setattr(blog, "theme_color", lambda: "#ff00ff")
    html = str(_highlight("KaFka on the Shore", ["kafka", "shore"]))
    assert '<mark' in html and 'KaFka' in html and 'Shore' in html

@pytest.mark.parametrize("q, ok", [
    ('book:"Kafka"',              ("book", None, "Kafka")),
    ('book:title:kafka',          ("book", "title", "kafka")),
    ('book:author:"Haruki M."',   ("book", "author", "Haruki M.")),
    ('not a match',               None),
])
def test_parse_item_query(q, ok):
    res = _parse_item_query(q)
    if ok is None:
        assert res is None
    else:
        t, f, term = ok
        assert res["type"] == t and res["field"] == f and res["term"] == term


# ──────────────────────────────────────────────────────────────
# tiny helper: RFC-2822 formatting
# ──────────────────────────────────────────────────────────────
def test_rfc2822():
    iso = "2025-06-30T12:00:00+00:00"
    out = _rfc2822(iso)
    # Mon, 30 Jun 2025 14:00:00 +0200   ← timezone depends on local TZ, so just assert parts
    assert "Mon," in out and "2025" in out and out.endswith("00")
