import pytest

from poetrist.blog import extract_tags, infer_kind, parse_trigger, strip_caret


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
    body, blocks = parse_trigger(txt)
    assert body == '^book:$PENDING$0$'
    blk = blocks[0]
    assert blk["verb"] == "read"
    assert blk["item_type"] == "book"
    assert blk["title"] == "The Hobbit"
    assert blk["progress"] == "42%"
