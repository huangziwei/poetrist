"""
tests/test_tags_code.py
"""
from poetrist.blog import extract_tags


def test_tags_ignore_inline_code():
    text = "Normal #tag but `#not_a_tag` stays literal."
    assert extract_tags(text) == {"tag"}


def test_tags_ignore_fenced_code():
    text = """
Outside #tag
```
#inside_fence
```
    """.strip()
    assert extract_tags(text) == {"tag"}
