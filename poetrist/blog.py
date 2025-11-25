#!/usr/bin/env python3
"""
A single-file minimal blog.
"""

import ipaddress
import json
import re
import secrets
import socket
import sqlite3
import uuid
from collections import defaultdict, deque
from datetime import datetime, timezone
from functools import wraps
from html import escape, unescape
from importlib.metadata import PackageNotFoundError, version
from pathlib import Path
from time import time
from typing import DefaultDict
from urllib.parse import urlencode, urlparse
from zoneinfo import ZoneInfo, available_timezones

import click
import latex2mathml.converter as _l2m
import markdown
import requests
from flask import (
    Flask,
    Response,
    abort,
    flash,
    g,
    redirect,
    render_template_string,
    request,
    session,
    url_for,
)
from itsdangerous import BadSignature, SignatureExpired, TimestampSigner
from markdown.extensions import Extension
from markupsafe import Markup
from webauthn import (
    generate_authentication_options,
    generate_registration_options,
    verify_authentication_response,
    verify_registration_response,
)
from webauthn.helpers import base64url_to_bytes, options_to_json
from webauthn.helpers.structs import (
    AttestationConveyancePreference,
    PublicKeyCredentialDescriptor,
    UserVerificationRequirement,
)
from werkzeug.middleware.proxy_fix import ProxyFix
from werkzeug.security import check_password_hash as verify_token
from werkzeug.security import generate_password_hash as hash_token

################################################################################
# Imports & constants
################################################################################

ROOT = Path(__file__).parent
DB_FILE = ROOT / "blog.sqlite3"

SECRET_FILE = ROOT / ".secret_key"
SECRET_KEY = (
    SECRET_FILE.read_text().strip() if SECRET_FILE.exists() else secrets.token_hex(32)
)
SECRET_FILE.write_text(SECRET_KEY)
TOKEN_LEN = 48
signer = TimestampSigner(SECRET_KEY, salt="login-token")

SLUG_DEFAULTS = {"say": "says", "post": "posts", "pin": "pins"}
VERB_MAP = {
    "read": [
        "to-read",
        "to read",
        "reading",
        "read",
        "to reread",
        "rereading",
        "reread",
        "finished",
        "skimmed",
        "abandoned",
    ],
    "watch": [
        "to-watch",
        "to watch",
        "watching",
        "watched",
        "to rewatch",
        "rewatching",
        "rewatched",
        "abandoned",
    ],
    "listen": [
        "to-listen",
        "to listen",
        "listening",
        "listened",
        "to relisten",
        "relistening",
        "relistened",
        "abandoned",
    ],
    "play": [
        "to-play",
        "to play",
        "playing",
        "played",
        "to replay",
        "replaying",
        "replayed",
        "abandoned",
    ],
    "visit": [
        "to-visit",
        "to visit",
        "visiting",
        "visited",
        "to revisit",
        "revisiting",
        "revisited",
        "regular",
    ],
    "use": [
        "to-use",
        "to use",
        "using",
        "used",
        "to reuse",
        "reusing",
        "reused",
        "retired",
        "replaced",
    ],
}
ALIASES = {
    "p": "progress",
    "pg": "progress",
    "i": "item_type",
    "it": "item_type",
    "a": "action",
    "at": "action",
    "v": "verb",
    "vb": "verb",
    "t": "title",
    "tt": "title",
}


def canon(k: str) -> str:  # helper: ^pg → progress
    return ALIASES.get(k.lower(), k.lower())


def canon_meta_key(k: str) -> str:
    """Map aliases, otherwise preserve the original casing."""
    return ALIASES.get(k.lower(), k)


GENRE_SPLIT_RE = re.compile(r"\s*/\s*")


def normalize_genre(value: str) -> str:
    return re.sub(r"\s+", " ", value.strip()).lower()


KINDS = ("say", "post", "pin") + tuple(VERB_MAP.keys()) + ("page",)
PAGE_DEFAULT = 100
RFC2822_FMT = "%a, %d %b %Y %H:%M:%S %z"
_TOKEN_CHARS = r"0-9A-Za-z\u0080-\uFFFF_"
TOKEN_RE = re.compile(f"[{_TOKEN_CHARS}]+")
TAG_CHARS = r"[\w./-]+"
TAG_RE = re.compile(rf"(?<!\w)#({TAG_CHARS})")
PROJECT_RE = re.compile(r"^\s*~project:([A-Za-z0-9_-]+)(?:\|(.*))?$")
HASH_LINK_RE = re.compile(
    rf"""
    (?<![A-Za-z0-9_="'&]) \#
    (?!x?[0-9A-Fa-f]+;)
    (?![0-9A-Fa-f]{{3,8}}\b)
    ({TAG_CHARS})
""",
    re.X,
)
ARITH_RE = re.compile(
    r'<(?P<tag>span|div) class="arithmatex">(.*?)</(?P=tag)>',
    re.S,
)
_FOOTNOTE_DIV_RE = re.compile(r'<div class="footnote">.*?</div>', re.S)
_FOOT_LI_RE = re.compile(r'<li id="fn:([^"]+)">(.*?)</li>', re.S)
_PARA_RE = re.compile(r"<p[^>]*>(.*?)</p>", re.S)
_BACKREF_RE = re.compile(r"<a[^>]+footnote-backref[^>]*>.*?</a>", re.S)
_SUP_RE = re.compile(
    r'<sup id="fnref:([^"]+)"><a class="footnote-ref" href="#fn:[^"]+"[^>]*>.*?</a></sup>'
)
_HEADING_RE = re.compile(r"^(#{1,6})\s+(.*)$")

try:
    __version__ = version("poetrist")
except PackageNotFoundError:
    __version__ = "0.1.0-dev"


################################################################################
# App + template filters
################################################################################
app = Flask(__name__)
app.url_map.strict_slashes = False
app.config.update(SECRET_KEY=SECRET_KEY, DATABASE=str(DB_FILE))
app.config.update(
    SESSION_COOKIE_SAMESITE="Lax",  # blocks most CSRF on simple links
    SESSION_COOKIE_HTTPONLY=True,  # mitigate XSS → cookie theft
    SESSION_COOKIE_SECURE=True,  # only if you serve over HTTPS
)
app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1)

EMBED_MAX_DEPTH = 2
EMBED_MAX_COUNT = 10
_EMBED_RE = re.compile(r"^@entry:(\S+?)(?:#([A-Za-z0-9._-]+))?\s*$")

MD_EXTENSION_CONFIGS = {
    "pymdownx.highlight": {
        "guess_lang": True,
        "noclasses": True,
        "pygments_style": "nord",
    },
    "pymdownx.arithmatex": {"generic": True},
}
BASE_MD_EXTENSIONS = [
    "pymdownx.extra",
    "pymdownx.magiclink",
    "pymdownx.tilde",
    "pymdownx.mark",
    "pymdownx.superfences",
    "pymdownx.highlight",
    "pymdownx.betterem",
    "pymdownx.saneheaders",
    "pymdownx.arithmatex",
]


def _slugify_heading(text: str) -> str:
    """Simplistic slugify to match headings for partial embeds."""
    slug = re.sub(r"[^\w\s-]", "", text or "").strip().lower()
    slug = re.sub(r"\s+", "-", slug)
    return slug


def _new_embed_ctx(source_slug: str | None) -> dict:
    """Per-render context for embed depth/loop tracking."""
    return {"root": source_slug, "stack": set(), "depth": 0, "count": 0}


def _get_embed_ctx() -> dict:
    ctx = getattr(g, "_embed_ctx", None)
    if ctx is None:
        ctx = _new_embed_ctx(None)
    return ctx


def _set_embed_ctx(ctx):
    g._embed_ctx = ctx


def _drop_caret_meta(text: str) -> str:
    """
    Remove ^meta lines **except** when they are inside a fenced
    code-block (``` … ``` or ~~~ … ~~~).
    """
    out, in_code, fence = [], False, ""
    for ln in (text or "").splitlines():
        m = _CODE_FENCE_RE.match(ln)
        if m:  # toggle fence status
            tok = m.group(1)
            if not in_code:
                in_code, fence = True, tok
            elif tok == fence:  # matching closer
                in_code, fence = False, ""
            out.append(ln)
            continue

        if in_code or not ln.lstrip().startswith("^"):
            out.append(ln)  # keep line
    return "\n".join(out)


def _render_markdown(text: str, *, ctx: dict | None = None, renderer=None) -> str:
    """Convert Markdown text to HTML with a dedicated renderer."""
    ctx = ctx or _new_embed_ctx(None)
    prev = getattr(g, "_embed_ctx", None)
    _set_embed_ctx(ctx)
    try:
        rnd = renderer or md
        rnd.reset()
        return rnd.convert(text)
    finally:
        if prev is None:
            g.pop("_embed_ctx", None)
        else:
            _set_embed_ctx(prev)


def _popup_footnotes(html: str) -> str:
    div_m = _FOOTNOTE_DIV_RE.search(html)
    if not div_m:
        return html

    notes = {}
    for m in _FOOT_LI_RE.finditer(div_m.group(0)):
        num, raw = m.group(1), m.group(2)
        raw = _BACKREF_RE.sub("", raw)
        paras = [p.strip() for p in _PARA_RE.findall(raw)]
        notes[num] = "<br><br>".join(paras)
    html = html.replace(div_m.group(0), "")

    # ensure the global “none” radio exists once per request
    if "fn_none_added" not in g:
        g.fn_none_added = True
        html = (
            '<input type="radio" hidden id="fn-none" name="fn-set" '
            'class="fn-none" checked>'
        ) + html

    def repl(m: re.Match) -> str:
        num = m.group(1)
        body = notes.get(num, "")
        rid = f"fn-{num}-{uuid.uuid4().hex[:4]}"
        return (
            f'<sup class="fn" id="fnref:{num}">'
            f'  <input hidden type="radio" id="{rid}" name="fn-set" '
            f'         class="fn-toggle">'
            f'  <label for="{rid}" class="fn-ref">{num}</label>'
            f'  <span  class="fn-popup">{body}</span>'
            f'  <label for="fn-none" class="fn-overlay"></label>'
            f"</sup>"
        )

    html = _SUP_RE.sub(repl, html)
    all_notes = "".join(
        f'<li id="fn:{k}"><a href="#fnref:{k}" class="fn-badge" style="font-size:0.85rem;text-decoration:none;">{k}</a> {v}</li>'
        for k, v in notes.items()
    )
    html += (
        '<details class="fn-all" style="margin-bottom:1.5rem;font-size:1rem;">'
        f'  <summary style="cursor:pointer;font-weight:bold;">'
        f"    Footnotes&nbsp;({len(notes)})"
        "  </summary>"
        '  <ol style="list-style:none;margin:0.5rem 0">'
        f"{all_notes}"
        "  </ol>"
        "</details>"
    )
    return html


def _postprocess_html(html: str, *, theme_col: str) -> str:
    """
    Apply hashtag links, mark styling, MathML conversion, footnote popups,
    and add u-photo class to images.
    """

    def _hashtag_repl(match):
        orig_tag = match.group(1)
        tag_lc = orig_tag.lower()
        href = tags_href(tag_lc)
        return f'<a href="{href}" style="text-decoration:none;color:{theme_col};border-bottom:0.1px dotted currentColor;">#{orig_tag}</a>'

    html = HASH_LINK_RE.sub(_hashtag_repl, html)
    html = re.sub(
        r"(<mark)(>)",
        rf'\1 style="background:{theme_col};color:#000;padding:0 .15em;"\2',
        html,
    )

    def _undelimit(tex: str) -> str:
        tex = tex.strip()
        for left, right in [("$$", "$$"), (r"\[", r"\]"), (r"\(", r"\)"), ("$", "$")]:
            if tex.startswith(left) and tex.endswith(right):
                return tex[len(left) : -len(right)].strip()
        return tex

    def _to_mathml(m: re.Match) -> str:
        try:
            mathml = _l2m.convert(
                unescape(_undelimit(m.group(2))),
                display="inline" if m.group("tag") == "span" else "block",
            )
            if m.group("tag") == "div":
                return f'<div class="math-scroll" tabindex="0">{mathml}</div>'
            return mathml
        except Exception:
            return f'<pre class="tex">{escape(m.group(2))}</pre>'

    html = ARITH_RE.sub(_to_mathml, html)
    html = _popup_footnotes(html)

    def _add_u_photo(m):
        tag = m.group(0)
        return (
            tag if "u-photo" in tag else tag.replace("<img", '<img class="u-photo"', 1)
        )

    return re.sub(r"<img\b[^>]*>", _add_u_photo, html)


def _extract_section(body: str, section: str) -> str | None:
    """
    Return the Markdown text for a heading-matched section.

    Uses a simple slugify to match '# Title' → 'title' and captures until the
    next heading (same or deeper level number).
    """
    if not section:
        return body

    lines = body.splitlines()
    in_code, fence = False, ""
    start_idx, end_idx = None, None
    for idx, ln in enumerate(lines):
        m_f = _CODE_FENCE_RE.match(ln)
        if m_f:
            tok = m_f.group(1)
            if not in_code:
                in_code, fence = True, tok
            elif tok == fence:
                in_code, fence = False, ""
            continue

        if in_code:
            continue

        h = _HEADING_RE.match(ln)
        if not h:
            continue

        if start_idx is not None:
            end_idx = idx
            break

        slug = _slugify_heading(h.group(2))
        if slug == section:
            start_idx = idx

    if start_idx is None:
        return None
    if end_idx is None:
        end_idx = len(lines)
    return "\n".join(lines[start_idx:end_idx]).strip()


def _embed_error(msg: str) -> str:
    return f'<div class="entry-embed entry-embed--error"><strong>Embed error:</strong> {escape(msg)}</div>'


def _parse_embed_target(
    raw: str, section_hint: str | None
) -> tuple[str | None, str | None, str | None]:
    """
    Accept a slug OR an absolute/relative URL and return (slug, section, error).
    """
    raw = (raw or "").strip()
    if not raw:
        return None, section_hint, "embed target missing"

    parsed = urlparse(raw)
    section = section_hint

    if not section and parsed.fragment:
        section = parsed.fragment

    if parsed.scheme or parsed.netloc:
        parts = [p for p in parsed.path.split("/") if p]
        if not parts:
            return None, section, "embed URL missing slug"
        return parts[-1].rstrip("/"), section, None

    if raw.startswith("/"):
        parts = [p for p in raw.split("/") if p]
        if not parts:
            return None, section, "embed path missing slug"
        return parts[-1].rstrip("/"), section, None

    return raw, section, None


def render_entry_embed(
    slug: str, section: str | None, *, ctx: dict | None = None
) -> str:
    """
    Resolve @entry:slug embeds, optionally scoped to a heading section.
    """
    slug, section, parse_err = _parse_embed_target(slug, section)
    if parse_err:
        return _embed_error(parse_err)

    section_key = section.lower() if section else None
    ctx = ctx or _get_embed_ctx()
    ctx.setdefault("stack", set())
    ctx.setdefault("depth", 0)
    ctx.setdefault("count", 0)
    if ctx["count"] >= EMBED_MAX_COUNT:
        return _embed_error("too many embeds in one entry")

    if slug == ctx.get("root") or slug in ctx["stack"]:
        return _embed_error("circular embed detected")

    if ctx["depth"] >= EMBED_MAX_DEPTH:
        return _embed_error("embed depth limit reached")

    row = (
        get_db()
        .execute(
            "SELECT id, title, body, created_at, slug, kind FROM entry WHERE slug=?",
            (slug,),
        )
        .fetchone()
    )
    if not row:
        return _embed_error(f"entry '{slug}' not found")

    body = row["body"] or ""
    if section_key:
        part = _extract_section(body, section_key)
        if not part:
            return _embed_error(f"section '{section}' not found in entry")
        body = part

    clean = _drop_caret_meta(body)
    ctx["stack"].add(slug)
    ctx["depth"] += 1
    ctx["count"] += 1
    try:
        inner_html = _render_markdown(clean, ctx=ctx, renderer=_markdown_renderer())
    finally:
        ctx["stack"].discard(slug)
        ctx["depth"] -= 1

    url = url_for(
        "entry_detail", kind_slug=kind_to_slug(row["kind"]), entry_slug=row["slug"]
    )
    view_url = f"{url}#{section_key}" if section_key else url
    ts = ts_filter(row["created_at"])
    section_label = ""
    kind_url = url_for("by_kind", slug=kind_to_slug(row["kind"]))

    title_html = ""
    if row["title"]:
        title_html = (
            f'<div style="font-weight:700;">'
            f'<a href="{view_url}" style="color:inherit;border-bottom:none;">'
            f"{escape(row['title'])}"
            "</a>"
            "</div>"
        )

    footer_html = (
        '  <div class="entry-embed__footer" style="color:#aaa;">'
        '    <span class="entry-embed__pill">'
        f'      <a href="{kind_url}" style="text-decoration:none; color:inherit;border-bottom:none;">{escape(row["kind"])}</a>'
        "    </span>"
        f'    <a class="u-url u-uid" href="{view_url}" style="text-decoration:none; color:inherit; vertical-align:middle; font-variant-numeric:tabular-nums; white-space:nowrap;">'
        f'      <time class="dt-published" datetime="{escape(row["created_at"])}">{escape(ts)}</time>'
        "    </a>"
        f"    {section_label}"
        "  </div>"
    )

    return (
        f'<div class="entry-embed" data-slug="{escape(slug)}">\n'
        f"{title_html}\n"
        f'  <div class="entry-embed__body">{inner_html}</div>\n'
        f"{footer_html}\n"
        f"</div>"
    )


def render_markdown_html(
    text: str | None,
    *,
    source_slug: str | None = None,
    renderer=None,
) -> str:
    """
    Shared Markdown renderer used across filters and RSS.
    """
    clean = _drop_caret_meta((text or ""))
    ctx = _new_embed_ctx(source_slug)
    html = _render_markdown(clean, ctx=ctx, renderer=renderer)
    return _postprocess_html(html, theme_col=theme_color())


class EntryEmbedPreprocessor(markdown.preprocessors.Preprocessor):
    """Replace @entry:slug references with embedded entry HTML blocks."""

    def run(self, lines: list[str]) -> list[str]:
        ctx = _get_embed_ctx()
        out, in_code, fence = [], False, ""
        for ln in lines:
            m_f = _CODE_FENCE_RE.match(ln)
            if m_f:
                tok = m_f.group(1)
                if not in_code:
                    in_code, fence = True, tok
                elif tok == fence:
                    in_code, fence = False, ""
                out.append(ln)
                continue

            if in_code:
                out.append(ln)
                continue

            m = _EMBED_RE.match(ln.strip())
            if not m:
                out.append(ln)
                continue

            slug, section = m.group(1), m.group(2)
            out.append(render_entry_embed(slug, section, ctx=ctx))
        return out


class EntryEmbedExtension(Extension):
    def extendMarkdown(self, md_inst):
        md_inst.preprocessors.register(
            EntryEmbedPreprocessor(md_inst), "entry_embed", 27
        )


def _markdown_extensions():
    return [*BASE_MD_EXTENSIONS, EntryEmbedExtension()]


def _markdown_renderer():
    return markdown.Markdown(
        extensions=_markdown_extensions(),
        extension_configs=MD_EXTENSION_CONFIGS,
    )


md = _markdown_renderer()


@app.template_filter("md")
def md_filter(text: str | None, source_slug: str | None = None) -> Markup:
    """
    Render Markdown and turn every #tag into a link to the tag view.
    """
    return Markup(render_markdown_html(text, source_slug=source_slug))


@app.template_filter("mdinline")
def md_inline_filter(text: str | None, source_slug: str | None = None) -> Markup:
    """
    Render Markdown like `md`, but if the result is exactly one
    <p>…</p> block, unwrap it so we get pure inline HTML.
    """
    html = md_filter(text, source_slug)  # reuse the existing logic
    # Markup -> str for inspection, but keep it safe afterwards
    s = str(html)

    if s.startswith("<p>") and s.endswith("</p>"):
        s = s[3:-4].strip()  # drop the wrapper

    return Markup(s)


@app.template_filter("smartcap")
def smartcap(s: str | None) -> str:
    """
    • If the whole token is already uppercase (discounting digits / punctuation)
      → return it verbatim  (ISBN-13, URL, ID, …).

    • Otherwise → normal str.capitalize()  (author → Author).
    """
    if not s:
        return ""
    # at least one cased char and no lowercase letters  → treat as ALL-CAPS
    return s if any(c.isalpha() for c in s) and s.upper() == s else s.capitalize()


@app.template_filter("ts")
def ts_filter(iso: str | None) -> str:
    if not iso:
        return ""
    try:
        dt = datetime.fromisoformat(iso)
    except ValueError:
        return iso
    return dt.astimezone(ZoneInfo(tz_name())).strftime("%Y.%m.%d %H:%M:%S")


@app.template_filter("url")
def url_filter(url: str | None) -> str:
    if not url:
        return ""
    try:
        p = urlparse(url)
        return f"{p.scheme}://{p.netloc}/"
    except Exception:
        return url


###############################################################################
# Database helpers
###############################################################################
def get_db():
    if "db" not in g:
        g.db = sqlite3.connect(app.config["DATABASE"])
        g.db.execute("PRAGMA foreign_keys = ON;")
        g.db.row_factory = sqlite3.Row
        g.db.create_function("strip_caret", 1, strip_caret)
    return g.db


@app.teardown_appcontext
def close_db(error=None):
    db = g.pop("db", None)
    if db is not None:
        db.close()


def init_db():
    db = get_db()
    db.executescript(
        """
        ------------------------------------------------------------
        -- 1.  Accounts
        ------------------------------------------------------------
        CREATE TABLE IF NOT EXISTS user (
            id          INTEGER PRIMARY KEY,
            username    TEXT UNIQUE NOT NULL,
            token_hash  TEXT NOT NULL
        );

        ------------------------------------------------------------
        -- 2.  Objects  (one row per distinct work / place / tool …)
        ------------------------------------------------------------
        CREATE TABLE object (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            itype       TEXT NOT NULL,               
            title       TEXT NOT NULL,
            slug        TEXT UNIQUE NOT NULL         
        );


        ------------------------------------------------------------
        -- 3. Entries
        ------------------------------------------------------------
        CREATE TABLE IF NOT EXISTS entry (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            title       TEXT,
            body        TEXT NOT NULL,
            link        TEXT,
            created_at  TEXT NOT NULL,
            updated_at  TEXT,                           
            slug        TEXT UNIQUE NOT NULL,
            kind        TEXT NOT NULL                  -- say | post | pin | page
        );

        ------------------------------------------------------------
        -- 3.  Site-wide key/value settings
        ------------------------------------------------------------
        CREATE TABLE IF NOT EXISTS settings (
            key   TEXT PRIMARY KEY,
            value TEXT
        );
        INSERT OR IGNORE INTO settings (key, value)
            VALUES ('site_name', 'po.etr.ist'),
                   ('theme_color','#A5BA93'),
                   ('timezone','{TZ_DFLT}');

        ------------------------------------------------------------
        -- 4.  Projects (post collections)
        ------------------------------------------------------------
        CREATE TABLE IF NOT EXISTS project (
            id    INTEGER PRIMARY KEY AUTOINCREMENT,
            slug  TEXT UNIQUE NOT NULL,
            title TEXT
        );

        CREATE TABLE IF NOT EXISTS project_entry (
            project_id INTEGER NOT NULL,
            entry_id   INTEGER NOT NULL,
            created_at TEXT NOT NULL,
            PRIMARY KEY (project_id, entry_id),
            FOREIGN KEY (project_id) REFERENCES project(id) ON DELETE CASCADE,
            FOREIGN KEY (entry_id)   REFERENCES entry(id)   ON DELETE CASCADE
        );

        CREATE INDEX IF NOT EXISTS idx_project_entry_entry ON project_entry(entry_id);

        ------------------------------------------------------------
        -- 4.  Tags
        ------------------------------------------------------------
        CREATE TABLE IF NOT EXISTS tag (
            id   INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT UNIQUE NOT NULL
        );

        CREATE TABLE IF NOT EXISTS entry_tag (
            entry_id INTEGER NOT NULL,
            tag_id   INTEGER NOT NULL,
            PRIMARY KEY (entry_id, tag_id),
            FOREIGN KEY (entry_id) REFERENCES entry(id) ON DELETE CASCADE,
            FOREIGN KEY (tag_id)   REFERENCES tag(id)   ON DELETE CASCADE
        );

        ------------------------------------------------------------
        -- 5.  Full-text search 
        ------------------------------------------------------------
        CREATE VIRTUAL TABLE IF NOT EXISTS entry_fts USING fts5(
            title, body, link,
            content='entry',
            content_rowid='id',
            tokenize = 'trigram'
        );

        CREATE TRIGGER IF NOT EXISTS entry_ai AFTER INSERT ON entry BEGIN
            INSERT INTO entry_fts(rowid,title,body,link)
                VALUES (new.id,
                        COALESCE(new.title,''),
                        strip_caret(new.body),
                        COALESCE(new.link,''));
        END;

        CREATE TRIGGER IF NOT EXISTS entry_au AFTER UPDATE ON entry BEGIN
            INSERT INTO entry_fts(entry_fts, rowid)
                VALUES('delete', old.id);

            INSERT INTO entry_fts(rowid, title, body, link)
                VALUES(
                    new.id,
                    COALESCE(new.title,''),
                    strip_caret(new.body),
                    COALESCE(new.link,'')
                );
        END;

        CREATE TRIGGER IF NOT EXISTS entry_ad AFTER DELETE ON entry BEGIN
            INSERT INTO entry_fts(entry_fts, rowid)
                VALUES('delete', old.id);
        END;

        ------------------------------------------------------------
        -- 6.  Re-usable media / places / etc. (“items”)
        ------------------------------------------------------------
        CREATE TABLE IF NOT EXISTS item (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            uuid        TEXT UNIQUE NOT NULL,        
            slug        TEXT UNIQUE NOT NULL,        
            item_type   TEXT NOT NULL,               
            title       TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS item_meta (       
            item_id INTEGER NOT NULL,
            k       TEXT NOT NULL,
            v       TEXT,
            ord     INTEGER NOT NULL,
            PRIMARY KEY (item_id, k),
            FOREIGN KEY (item_id) REFERENCES item(id) ON DELETE CASCADE
        );

        CREATE INDEX IF NOT EXISTS idx_item_type      ON item(item_type);
        CREATE INDEX IF NOT EXISTS idx_item_meta_kv   ON item_meta(k, v)
             WHERE k NOT IN ('cover','img','poster')
               AND length(v) < 500;

        ------------------------------------------------------------
        -- 8.  Links “which entry talks about which item”
        ------------------------------------------------------------
        CREATE TABLE IF NOT EXISTS entry_item (
            entry_id INTEGER NOT NULL,
            item_id  INTEGER NOT NULL,
            verb     TEXT NOT NULL,      -- read / watch / visit / …
            action   TEXT NOT NULL,      -- reading / reread / …
            progress TEXT,
            PRIMARY KEY (entry_id, item_id),
            FOREIGN KEY (entry_id) REFERENCES entry(id) ON DELETE CASCADE,
            FOREIGN KEY (item_id)  REFERENCES item(id)  ON DELETE CASCADE
        );

        ------------------------------------------------------------
        --  9. Passkeys  (multiple per account)
        ------------------------------------------------------------
        CREATE TABLE IF NOT EXISTS passkey (
            id            INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id       INTEGER NOT NULL,
            cred_id       BLOB    UNIQUE NOT NULL,   
            pub_key       BLOB    NOT NULL,
            sign_count    INTEGER NOT NULL,
            nickname      TEXT,
            created_at    TEXT    NOT NULL,
            FOREIGN KEY (user_id) REFERENCES user(id) ON DELETE CASCADE
        );
        """
    )
    db.commit()


# -------------------------------------------------------------------------
# Time helpers
# -------------------------------------------------------------------------
def utc_now() -> datetime:
    """Return an *aware* datetime in UTC."""
    return datetime.now(timezone.utc)


###############################################################################
# CLI – create admin + token
###############################################################################
def _create_admin(db, *, username: str) -> str:
    handle = secrets.token_urlsafe(TOKEN_LEN)
    token = signer.sign(handle).decode()
    db.execute(
        "INSERT INTO user (username, token_hash) VALUES (?,?)",
        (username, hash_token(handle)),
    )
    db.commit()
    return token


def _rotate_token(db) -> str:
    """Generate + store a *new* one-time token, return it for display."""
    handle = secrets.token_urlsafe(TOKEN_LEN)
    token = signer.sign(handle).decode()
    db.execute("UPDATE user SET token_hash=? WHERE id=1", (hash_token(handle),))
    db.commit()
    return token


@app.cli.command("init")
@click.option(
    "--username", prompt=True, help="Admin username (will be created if DB empty)"
)
def cli_init(username: str):
    """Initialise DB *and* create the first admin account."""
    init_db()  # no-op if already there
    db = get_db()
    token = _create_admin(db, username=username.strip())

    click.secho("\n✅  Admin created.", fg="green")
    click.echo(f"\nOne-time login token:\n\n{token}\n")
    click.echo("Paste it into the login form at /login within 1 minute.")


@app.cli.command("token")
def cli_token():
    """Rotate the admin’s one-time login token."""
    db = get_db()
    token = _rotate_token(db)

    click.secho("\n🔑  Fresh login token generated.\n", fg="yellow")
    click.echo(f"{token}\n")
    click.echo("Paste it into the login form at /login within 1 minute.")


###############################################################################
# Content helpers
###############################################################################
def strip_caret(text: str | None) -> str:
    """
    Drop every line that starts with “^something:”
    (Used for both FTS indexing and LIKE-fallback searches.)
    """
    if not text:
        return ""
    return "\n".join(ln for ln in text.splitlines() if not ln.lstrip().startswith("^"))


def infer_kind(title, link):
    if not title and not link:
        return "say"
    if link and title:
        return "pin"
    return "post"


def current_username() -> str:
    """Return the (only) account’s username, falling back to 'admin'."""
    row = get_db().execute("SELECT username FROM user LIMIT 1").fetchone()
    return row["username"] if row else "admin"


def get_setting(key, default=None):
    row = get_db().execute("SELECT value FROM settings WHERE key=?", (key,)).fetchone()
    return row["value"] if row else default


def set_setting(key, value):
    db = get_db()
    db.execute(
        "INSERT INTO settings (key,value) VALUES (?,?) "
        "ON CONFLICT(key) DO UPDATE SET value=excluded.value",
        (key, value),
    )
    db.commit()


def is_b64_image(k: str, v: str) -> bool:
    return k.lower() in {"cover", "img", "poster"} and len(v) > 100


# Slug helpers
def slug_map() -> dict[str, str]:
    """
    Return slug mappings for core kinds plus verbs, with fall-back defaults.
    Settings keys follow slug_<kind>, e.g. slug_read.
    """
    slugs = {k: get_setting(f"slug_{k}", v) or v for k, v in SLUG_DEFAULTS.items()}
    slugs.update(
        {v: get_setting(f"slug_{v}", v) or v for v in VERB_KINDS}
    )  # verbs default to themselves
    return slugs


def kind_to_slug(kind: str) -> str:
    return slug_map().get(kind, kind)


def slug_to_kind(slug: str) -> str | None:
    rev = {v: k for k, v in slug_map().items()}
    return rev.get(slug, slug)


def tags_slug() -> str:
    """Current base slug for the tags view."""
    s = (get_setting("slug_tags", "tags") or "tags").strip("/") or "tags"
    return s


def settings_slug() -> str:
    """Current base slug for the settings page."""
    s = (get_setting("slug_settings", "settings") or "settings").strip(
        "/"
    ) or "settings"
    return s


def tags_href(tag_list: str = "", **params) -> str:
    """
    Build a path for the tags view that respects the custom slug.
    Example: tags_href("foo+bar", sort="new") → /tags/foo+bar?sort=new
    """
    base = f"/{tags_slug()}"
    path = f"{base}/{tag_list}" if tag_list else base
    if params:
        path += "?" + urlencode(params)
    return path


def settings_href() -> str:
    """Path to the Settings page (customizable slug)."""
    return f"/{settings_slug()}"


# Pagination helpers
def page_size() -> int:
    try:
        return int(get_setting("page_size", PAGE_DEFAULT))
    except (TypeError, ValueError):
        return PAGE_DEFAULT


def paginate(base_sql: str, params: tuple, *, page: int, per_page: int, db):
    total = db.execute(f"SELECT COUNT(*) FROM ({base_sql})", params).fetchone()[0]
    pages = (total + per_page - 1) // per_page
    rows = db.execute(
        f"{base_sql} LIMIT ? OFFSET ?", params + (per_page, (page - 1) * per_page)
    ).fetchall()
    return rows, pages


def extract_tags(text: str) -> set[str]:
    """Return a **lower-cased** set of #tags found in *text*."""
    return {m.lower() for m in TAG_RE.findall(text or "")}


def sync_tags(entry_id: int, tags: set[str], *, db):
    """
    Bring `entry_tag` + `tag` tables in sync with *tags* for *entry_id*.
    Removes orphaned tags automatically.
    """
    # current tags on that entry
    cur = {
        r["name"]
        for r in db.execute(
            "SELECT t.name FROM tag t JOIN entry_tag et ON t.id=et.tag_id "
            "WHERE et.entry_id=?",
            (entry_id,),
        )
    }
    add = tags - cur
    remove = cur - tags

    # -- add new ones ------------------------------------------------------
    for t in add:
        db.execute("INSERT OR IGNORE INTO tag(name) VALUES(?)", (t,))
        tag_id = db.execute("SELECT id FROM tag WHERE name=?", (t,)).fetchone()["id"]
        db.execute("INSERT OR IGNORE INTO entry_tag VALUES (?,?)", (entry_id, tag_id))

    # -- drop unneeded -----------------------------------------------------
    for t in remove:
        tag_id = db.execute("SELECT id FROM tag WHERE name=?", (t,)).fetchone()["id"]
        db.execute(
            "DELETE FROM entry_tag WHERE entry_id=? AND tag_id=?", (entry_id, tag_id)
        )

    # -- garbage-collect unused tags --------------------------------------
    db.execute(
        "DELETE FROM tag WHERE id NOT IN (SELECT DISTINCT tag_id FROM entry_tag)"
    )
    db.commit()


def parse_projects(text: str) -> tuple[str, list[dict[str, str]]]:
    """
    Extract ~project:slug|Title lines from *text* and return (clean_body, projects).
    Projects are deduped by slug (first title wins).
    """
    projects: dict[str, str] = {}
    clean_lines: list[str] = []
    for ln in (text or "").splitlines():
        m = PROJECT_RE.match(ln)
        if not m:
            clean_lines.append(ln)
            continue
        slug = m.group(1).lower()
        title = (m.group(2) or "").strip()
        projects.setdefault(slug, title)
    return "\n".join(clean_lines), [
        {"slug": s, "title": t} for s, t in projects.items()
    ]


def sync_projects(entry_id: int, projects: list[dict[str, str]], *, db):
    """
    Bring project ↔ entry links in sync (many-to-many). Creates projects on demand.
    """
    # current projects for this entry
    cur = {
        r["slug"]: r["project_id"]
        for r in db.execute(
            """SELECT p.id AS project_id, p.slug
                 FROM project p
                 JOIN project_entry pe ON pe.project_id = p.id
                WHERE pe.entry_id = ?""",
            (entry_id,),
        )
    }

    wanted = {p["slug"]: p.get("title", "") for p in projects if p.get("slug")}
    add = set(wanted) - set(cur)
    remove = set(cur) - set(wanted)

    # ensure projects exist + link
    created_at = db.execute(
        "SELECT created_at FROM entry WHERE id=?", (entry_id,)
    ).fetchone()["created_at"] or utc_now().isoformat(timespec="seconds")

    for slug in add:
        title = wanted[slug] or slug
        db.execute(
            "INSERT OR IGNORE INTO project (slug, title) VALUES (?, ?)",
            (slug, title),
        )
        # backfill title if it was empty
        if title:
            db.execute(
                "UPDATE project SET title=? WHERE slug=? AND (title IS NULL OR title='')",
                (title, slug),
            )
        proj_id = db.execute("SELECT id FROM project WHERE slug=?", (slug,)).fetchone()[
            "id"
        ]
        db.execute(
            "INSERT OR IGNORE INTO project_entry (project_id, entry_id, created_at) VALUES (?,?,?)",
            (proj_id, entry_id, created_at),
        )

    # remove stale links
    for slug in remove:
        proj_id = cur[slug]
        db.execute(
            "DELETE FROM project_entry WHERE project_id=? AND entry_id=?",
            (proj_id, entry_id),
        )

    # garbage-collect unused projects
    db.execute(
        "DELETE FROM project WHERE id NOT IN (SELECT DISTINCT project_id FROM project_entry)"
    )
    db.commit()


def entry_projects(entry_id: int, *, db):
    """Return sorted list of (slug, title) mappings for one entry."""
    rows = db.execute(
        """SELECT p.slug, COALESCE(p.title, p.slug) AS title
             FROM project p
             JOIN project_entry pe ON pe.project_id = p.id
            WHERE pe.entry_id=?
            ORDER BY LOWER(COALESCE(p.title, p.slug))""",
        (entry_id,),
    )
    return rows.fetchall()


def project_filters(*, db):
    """Projects with post counts, sorted by count desc then title."""
    return db.execute(
        """SELECT p.slug,
                  COALESCE(p.title, p.slug) AS title,
                  COUNT(pe.entry_id)        AS cnt
             FROM project p
             JOIN project_entry pe ON pe.project_id = p.id
             JOIN entry e         ON e.id = pe.entry_id
            WHERE e.kind='post'
         GROUP BY p.id
           HAVING cnt > 0
         ORDER BY cnt DESC, LOWER(COALESCE(p.title, p.slug))"""
    ).fetchall()


def entry_tags(entry_id: int, *, db) -> list[str]:
    """Return a *sorted* list of tag names for one entry."""
    rows = db.execute(
        "SELECT t.name FROM tag t JOIN entry_tag et ON t.id=et.tag_id "
        "WHERE et.entry_id=? ORDER BY LOWER(t.name)",
        (entry_id,),
    )
    return [r["name"] for r in rows]


def nav_pages():
    """List of dicts: [{'title':'About', 'slug':'about'}, …] sorted A-Z."""
    db = get_db()
    return db.execute(
        "SELECT title, slug FROM entry WHERE kind='page' ORDER BY LOWER(title)"
    ).fetchall()


# ── compact one-liner (verb:item:identifier[:progress]) ──────────────
CARET_COMPACT_RE = re.compile(
    r"""
    ^\^
    (?:"([^"]+)"|([a-z0-9_-]+)) :      # ➊ action  (grp 1 if quoted, grp 2 plain)
    (?:"([^"]+)"|([a-z0-9_-]+)) :      # ➋ item_type (grp 3 or grp 4)
    (?:
        "([^"]+)"                      # ➌ title — quoted         (grp 5)
      | ([^":\s]+)                     #     title — **un-quoted** (grp 6)
      | ([0-9a-f-]{36}|[a-z0-9_-]+)    #     slug/uuid             (grp 7)
    )
    (?:\s*:\s*(?:"([^"]+)"|([^":\s]+)))?  # ➍ progress (grp 8/9)
""",
    re.X | re.I | re.U,
)
# ── “long” meta lines ─────────────────────────
META_RE = re.compile(r'^\^([^\s:]+):"?(.*?)"?$', re.U)
UUID4_RE = re.compile(
    r"^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$", re.I
)
IMPORT_RE = re.compile(
    r"""
    ^\^
    (?:"([^"]+)"|([0-9A-Za-z_-]+))   # action (grp1 if quoted, else grp2)
    :
    (https?://\S+)                   # absolute URL (grp3)
""",
    re.X | re.I,
)
_CODE_FENCE_RE = re.compile(r"^\s*(```|~~~)")


def parse_trigger(text: str) -> tuple[str, list[dict], list[str]]:
    """
    Parse caret-trigger lines from free text and return a tuple of
    (rewritten_body, blocks, errors).

    Invalid or incomplete caret snippets are treated as plain text and
    ignored for block extraction, but a message noting the validation
    error is collected so callers can surface it to the user. A valid
    block must include:
    - item_type (non-empty)
    - action and a verb that maps to one of VERB_KINDS
    - either a title or a slug/uuid (so an item can be resolved/created)
    """
    errors: list[str] = []

    def _block_error(blk: dict) -> str | None:
        # item_type present
        if not blk.get("item_type"):
            return "caret block is missing an item type"

        # action present → derive verb the same way parse does
        action_lc = (blk.get("action") or "").lower()
        verb = (blk.get("verb") or "").lower() or next(
            (vb for vb, acts in VERB_MAP.items() if action_lc in acts),
            action_lc,
        )
        if not verb or verb not in VERB_MAP:
            return "caret block has an unknown action/verb"

        # need at least a title or an identifier
        if not (blk.get("title") or blk.get("slug")):
            return "caret block needs a title or identifier"
        return None

    out_blocks, new_lines = [], []
    lines = text.splitlines()
    in_code = False
    fence = ""
    i = 0
    while i < len(lines):
        ln = lines[i]

        # ── enter / leave fenced code ───────────────────────────────
        m_f = _CODE_FENCE_RE.match(ln)
        if m_f:
            tok = m_f.group(1)
            if not in_code:  # start of a fence
                in_code, fence = True, tok
            elif tok == fence:  # matching closing fence
                in_code, fence = False, ""
            new_lines.append(ln)
            i += 1
            continue

        if in_code:
            new_lines.append(ln)  # inside a code block → leave untouched
            i += 1
            continue

        line = ln.strip()

        # ───────────────────────── 1) import block  (NEW) ──────────────────
        m = IMPORT_RE.match(line)
        if m:
            action = m.group(1) or m.group(2)
            url = m.group(3)

            try:
                blk = import_item_json(url, action=action)
            except ValueError as exc:
                new_lines.append(line + f"   ← {exc}")
                i += 1
                continue

            out_blocks.append(blk)
            new_lines.append(f"^{blk['item_type']}:$PENDING${len(out_blocks) - 1}$")
            i += 1
            continue

        # ── try compact form first ────────────────────────────────
        m = CARET_COMPACT_RE.match(line)
        if m:
            start_idx = i
            action = m.group(1) or m.group(2)
            item_type = m.group(3) or m.group(4)
            title = m.group(5) or m.group(6)  # quoted OR un-quoted
            slug = m.group(7)  # stays the same meaning
            prog = m.group(8) or m.group(9)  # quoted OR un-quoted

            action_lc = (action or "").lower()
            verb = next(
                (vb for vb, acts in VERB_MAP.items() if action_lc in acts), action_lc
            )
            blk = {
                "verb": verb,
                "action": action_lc,
                "item_type": item_type,
                "title": title,
                "slug": slug,
                "progress": prog,
                "meta": {},
            }

            j = i + 1
            while j < len(lines):
                nxt = lines[j].strip()
                if not nxt.startswith("^") or CARET_COMPACT_RE.match(nxt):
                    break
                km = META_RE.match(nxt)
                if km:
                    k, v = km.groups()
                    k = canon_meta_key(k)
                    if k == "progress":
                        blk["progress"] = v
                    elif k not in {
                        "action",
                        "verb",
                        "item",
                        "item_type",
                        "title",
                        "uuid",
                        "slug",
                    }:
                        blk["meta"][k] = v
                j += 1

            i = j
            err = _block_error(blk)
            if not err:
                out_blocks.append(blk)
                new_lines.append(f"^{item_type}:$PENDING${len(out_blocks) - 1}$")
            else:
                errors.append(f"{err} (line {start_idx + 1})")
                # treat as plain text if incomplete/invalid
                new_lines.extend(lines[start_idx:i])
                continue

            continue

        # ── otherwise: collect verbose caret-meta lines ───────────
        if line.startswith("^"):
            tmp = {
                "verb": None,
                "action": None,
                "item_type": None,
                "title": None,
                "slug": None,
                "progress": None,
                "meta": {},
            }
            start = i
            while i < len(lines) and lines[i].lstrip().startswith("^"):
                ln = lines[i].strip()
                m2 = META_RE.match(ln)
                if not m2:
                    new_lines.append(lines[i])
                    i += 1
                    continue
                k, v = m2.groups()
                k = canon_meta_key(k)
                if k == "action":
                    tmp["action"] = v
                elif k == "verb":
                    tmp["verb"] = v
                elif k in ("item", "item_type"):
                    tmp["item_type"] = v
                elif k == "title":
                    tmp["title"] = v
                elif k in ("uuid", "slug"):
                    tmp["slug"] = v
                elif k == "progress":
                    tmp["progress"] = v
                elif tmp["item_type"] is None:
                    tmp["item_type"] = k
                    # decide whether the value is a slug/uuid or a title
                    if UUID4_RE.fullmatch(v) or TOKEN_RE.fullmatch(v):
                        tmp["slug"] = v
                    else:
                        tmp["title"] = v
                else:
                    tmp["meta"][k] = v
                i += 1

            if "verb" not in tmp or not tmp["verb"]:
                action_lc = (tmp["action"] or "").lower()
                tmp["verb"] = next(
                    (vb for vb, acts in VERB_MAP.items() if action_lc in acts),
                    action_lc,
                )
            err = _block_error(tmp)
            if not err:
                out_blocks.append(tmp)
                new_lines.append(f"^{tmp['item_type']}:$PENDING${len(out_blocks) - 1}$")
            else:
                # put the original caret lines back unchanged
                errors.append(f"{err} (line {start + 1})")
                new_lines.extend(lines[start:i])
            continue

        # ── a normal, non-caret line ──────────────────────────────
        new_lines.append(lines[i])
        i += 1

    return "\n".join(new_lines), out_blocks, errors


def get_or_create_item(
    *, item_type, title, meta, slug: str | None = None, db, update_meta: bool = True
):
    if slug:
        row = db.execute(
            "SELECT id, slug, uuid FROM item WHERE slug=?", (slug,)
        ).fetchone()
        if row:
            return row["id"], row["slug"], row["uuid"]
        if UUID4_RE.fullmatch(slug):
            row = db.execute(
                "SELECT id, slug, uuid FROM item WHERE uuid=?", (slug,)
            ).fetchone()
            if row:
                return row["id"], row["slug"], row["uuid"]

    if title is None:
        raise ValueError("slug not found and no title given → cannot create item")

    uuid_ = str(uuid.uuid4())
    slug = slug or uuid_
    db.execute(
        "INSERT INTO item (uuid, slug, item_type, title) VALUES (?,?,?,?)",
        (uuid_, slug, item_type, title),
    )
    item_id = db.execute("SELECT last_insert_rowid()").fetchone()[0]

    if update_meta:
        for ord, (k, v) in enumerate(meta.items(), start=1):
            db.execute(
                "INSERT OR REPLACE INTO item_meta (item_id,k,v,ord) VALUES (?,?,?,?)",
                (item_id, k, v, ord),
            )
    return item_id, slug, uuid_


def has_kind(kind: str) -> bool:
    """True if at least one entry of this kind exists."""
    row = (
        get_db().execute("SELECT 1 FROM entry WHERE kind=? LIMIT 1", (kind,)).fetchone()
    )
    return bool(row)


VERB_KINDS = tuple(VERB_MAP.keys())


def active_verbs() -> list[str]:
    """All verbs that actually occur in the DB, in the declared order."""
    rows = (
        get_db()
        .execute(
            f"SELECT DISTINCT kind FROM entry "
            f"WHERE kind IN ({','.join('?' * len(VERB_KINDS))})",
            VERB_KINDS,
        )
        .fetchall()
    )
    present = {r["kind"] for r in rows}
    return [v for v in VERB_KINDS if v in present]


def _verbose_block(blk, uuid_):
    """Return the 5-line caret block​ string for one check-in."""

    def q(s):
        return f'"{s}"' if " " in s else s  # quote if it contains spaces

    parts = [
        f"^uuid:{uuid_}",
        f"^item_type:{blk['item_type']}",
        f"^title:{q(blk['title'])}" if blk["title"] else "",
        f"^action:{blk['action']}",
        f"^progress:{q(blk['progress'])}" if blk["progress"] else "",
    ]
    return "\n".join(p for p in parts if p)


def _csrf_token() -> str:
    """One token per session (rotates when the cookie does)."""
    return session.get("csrf", "")


# Expose helpers to templates
app.jinja_env.globals.update(kind_to_slug=kind_to_slug, get_setting=get_setting)
app.jinja_env.globals["external_icon"] = lambda: Markup("""
    <svg xmlns="http://www.w3.org/2000/svg"
        viewBox="0 0 20 20"
        width="11" height="11"
        style="vertical-align:baseline; margin-left:.2em; fill:currentColor"
        aria-hidden="true" focusable="false">
    <path d="M14 2h4v4h-2V4.41L9.41 11 8 9.59 14.59 3H14V2z"/>
    <path d="M15 9v7H4V4h7V2H4a2 2 0 0 0-2 2v12a2 2 0 0 0 2 2h12a2
            2 0 0 0 2-2V9h-3z"/>
    </svg>""")
app.jinja_env.globals["PAGE_DEFAULT"] = PAGE_DEFAULT
app.jinja_env.globals["entry_tags"] = lambda eid: entry_tags(eid, db=get_db())
app.jinja_env.globals["entry_projects"] = lambda eid: entry_projects(eid, db=get_db())
app.jinja_env.globals["nav_pages"] = nav_pages
app.jinja_env.globals["version"] = __version__
app.jinja_env.globals.update(
    has_kind=has_kind,
    active_verbs=active_verbs,
    verb_kinds=VERB_KINDS,
    tags_slug=tags_slug,
    tags_href=tags_href,
    settings_href=settings_href,
)
app.jinja_env.globals["csrf_token"] = _csrf_token
app.jinja_env.globals["is_b64_image"] = is_b64_image


def backlinks(entries, *, db) -> dict[int, list]:
    """
    Accepts *one sqlite Row* or *an iterable of rows* that each have
    `id` and `slug`.
    Returns {entry_id: [backlink rows …]}.

    • One SQL MATCH that covers all slugs.
    • Results are sorted oldest → newest.
    """
    # ── normalise to a list --------------------------------------------------
    if entries is None:
        return {}
    if not isinstance(entries, (list, tuple, set)):
        entries = [entries]  # single Row → list of 1

    if not entries:
        return {}

    slug_to_id = {e["slug"]: e["id"] for e in entries}
    q_marks = ",".join("?" * len(slug_to_id))

    sql = f"""
        SELECT target.slug      AS target_slug,
               src.id, src.slug, src.kind,
               src.title, src.created_at
          FROM entry_fts                      -- trigram index
          JOIN entry src    ON src.id = entry_fts.rowid
          JOIN entry target ON target.slug IN ({q_marks})
         WHERE entry_fts MATCH ('\"' || target.slug || '\"')
           AND src.id != target.id
    """
    rows = db.execute(sql, tuple(slug_to_id)).fetchall()

    out: dict[int, list] = {e["id"]: [] for e in entries}
    for r in rows:
        out[slug_to_id[r["target_slug"]]].append(r)

    # sort each bucket oldest → newest
    for lst in out.values():
        lst.sort(key=lambda r: r["created_at"])
    return out


# ── Default settings ────────────────────────────────────────────────
THEME_PRESETS = {
    "萌木": "#9ccf70",
    "浅縹": "#95bbec",
    "退紅": "#fda3a5",
    "薄色": "#c386c2",
    "浅緋": "#d3250c",
    "朱祓": "#f1884f",
    "欵冬": "#fed410",
    "木蘭": "#b1a277",
}


def theme_color() -> str:
    return get_setting("theme_color", THEME_PRESETS["浅縹"])  # default to 浅縹


TZ_DFLT = "Europe/Berlin"


def tz_name() -> str:
    tz = get_setting("timezone", TZ_DFLT)
    return tz if tz in available_timezones() else TZ_DFLT


app.jinja_env.globals.update(
    {
        "theme_color": theme_color,
        "theme_presets": THEME_PRESETS,
        "tz_name": tz_name,
        "available_timezones": available_timezones,
    }
)

###############################################################################
# Templates + Views
###############################################################################


def wrap(body: str) -> str:
    """Glue prolog + page-specific body + epilog."""
    return TEMPL_PROLOG + body + TEMPL_EPILOG


TEMPL_PROLOG = """
<!doctype html>
<html lang="en" style="scroll-behavior:smooth;">
<title>{{title or 'po.etr.ist'}}</title>
<meta name="viewport" content="width=device-width, initial-scale=1, shrink-to-fit=no"> 
<meta charset="utf-8">
<meta name="description" content="po.etr.ist – a minimal blog">
<link rel="icon" type="image/svg+xml" href="/favicon.svg">
<link rel="alternate" type="application/rss+xml"
      href="{{ url_for('global_rss') }}" title="{{ title }} – RSS">
<style>
html{font-size:62.5%;font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,"Helvetica Neue",Arial,"Noto Sans",sans-serif}body{font-size:1.8rem;line-height:1.618;max-width:38em;margin:auto;color:#c9c9c9;background-color:#222222;padding:13px}@media (max-width:684px){body{font-size:1.75rem}}@media (max-width:382px)@media (max-width:560px){.meta {flex:0 0 100%;order:1;margin-left:0;text-align:left;}}{body{font-size:1.35rem}}h1,h2,h3,h4,h5,h6{line-height:1.1;font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,"Helvetica Neue",Arial,"Noto Sans",sans-serif;font-weight:700;margin-top:3rem;margin-bottom:1.5rem;overflow-wrap:break-word;word-wrap:break-word;-ms-word-break:break-all;word-break:break-word}h1{font-size:2.35em}h2{font-size:1.7em}h3{font-size:1.55em}h4{font-size:1.4em}h5{font-size:1.25em}h6{font-size:1.1em}p{margin-top:0px;margin-bottom:2.5rem;hyphens:auto}small,sub,sup{font-size:75%}hr{border-color:#ffffff}a{text-decoration:none;color:#ffffff}a:hover{color:#c9c9c9;border-bottom:2px solid #c9c9c9}p>a{text-decoration:none;border-bottom:0.1px dotted #ffffff}ul{padding-left:1.4em;margin-top:0px;margin-bottom:2.5rem}li{margin-bottom:0.4em}blockquote{margin-left:0px;margin-right:0px;padding-left:1em;padding-top:0.8em;padding-bottom:0.8em;padding-right:0.8em;border-left:5px solid #ffffff;margin-bottom:2.5rem;background-color:#4a4a4a}blockquote p{margin-bottom:0.75em}img,video{height:auto;max-width:100%;margin-top:0px;margin-bottom:0px}pre{background-color:#4a4a4a;display:block;padding:1em;overflow-x:auto;margin-top:0px;margin-bottom:2.5rem;font-size:0.9em}code,kbd,samp{font-size:0.9em;padding:0 0.5em;background-color:#4a4a4a;white-space:pre-wrap}pre>code{padding:0;background-color:transparent;white-space:pre;font-size:1em}table{text-align:justify;width:100%;border-collapse:collapse;margin-bottom:2rem}td,th{padding:0.5em;border-bottom:1px solid #4a4a4a}input,textarea{border:1px solid #c9c9c9}input:focus,textarea:focus{border:1px solid #ffffff}textarea{width:100%}.button,button,input[type=submit],input[type=reset],input[type=button],input[type=file]::file-selector-button{display:inline-block;padding:5px 10px;text-align:center;text-decoration:none;white-space:nowrap;background-color:#ffffff;color:#222222;border-radius:1px;border:1px solid #ffffff;cursor:pointer;box-sizing:border-box}.button[disabled],button[disabled],input[type=submit][disabled],input[type=reset][disabled],input[type=button][disabled],input[type=file]::file-selector-button[disabled]{cursor:default;opacity:0.5}.button:hover,button:hover,input[type=submit]:hover,input[type=reset]:hover,input[type=button]:hover,input[type=file]::file-selector-button:hover{background-color:#c9c9c9;color:#222222;outline:0}.button:focus-visible,button:focus-visible,input[type=submit]:focus-visible,input[type=reset]:focus-visible,input[type=button]:focus-visible,input[type=file]::file-selector-button:focus-visible{outline-style:solid;outline-width:2px}textarea,select,input{color:#c9c9c9;padding:6px 10px;margin-bottom:10px;background-color:#4a4a4a;border:1px solid #4a4a4a;border-radius:4px;box-shadow:none;box-sizing:border-box}textarea:focus,select:focus,input:focus{border:1px solid #ffffff;outline:0}input[type=checkbox]:focus{outline:1px dotted #ffffff}label,legend,fieldset{display:block;margin-bottom:0.5rem;font-weight:600}p>math[display="block"]{display: block;margin: 1em 0}math[display="block"]:not(:first-child){margin-top: 1.2em}sup.fn{position:relative;display:inline-block;}sup.fn>.fn-ref,.fn-badge{position:relative;z-index:2500;display:inline-flex;align-items:center;justify-content:center;min-width:1rem;max-width:25em;padding:0.2em .4em;min-height:1.5rem;margin:0 0.25em;vertical-align:top;border-radius:.75em;white-space:normal;background:var(--fn-badge-bg,#666); color:#fff;font-size:.65em;line-height:1;cursor:pointer;transition:background .2s ease;text-decoration:none;}sup.fn>.fn-ref:hover{background:var(--fn-badge-bg-hover,#888);text-decoration:none !important;}.fn-popup{position:fixed;left:50%; bottom:0;transform:translate(-50%,100%);width:90vw;max-width:60rem; z-index:3000;max-height:40vh; overflow:auto;background:#222; color:#fff; line-height:1.45;padding:1rem 1.25rem;border:1px solid #444;transition:transform .25s ease;will-change:transform;}.fn-overlay{position:fixed; inset:0;background:transparent;opacity:0; visibility:hidden; pointer-events:none;transition:opacity .25s ease;touch-action:none;-webkit-tap-highlight-color:transparent;z-index:2000}sup.fn .fn-toggle:checked + .fn-ref + .fn-popup{transform:translate(-50%,0);box-shadow:0 -4px 12px rgba(0,0,0,.4);}sup.fn .fn-toggle:checked ~ .fn-overlay{opacity:1; visibility:visible; pointer-events:auto}.math-scroll{overflow-x:auto;overflow-y:hidden;max-width:auto;white-space:nowrap;-webkit-overflow-scrolling:touch}.jump-btn{position:fixed;bottom:1.25rem;right:1.25rem;width:3rem;height:3rem;display:flex;align-items:center;justify-content:center;font-size:1.5rem;line-height:1;border-radius:50%;background:#aaa;color:#000;text-decoration:none;border-bottom:none;box-shadow:0 2px 6px rgba(0,0,0,.3);z-index:1000;opacity:.15;transition:opacity .3s}.jump-btn:hover{opacity:.8;text-decoration:none}.jump-up{display:none}#page-bottom:target~.jump-up{display:flex}#page-bottom:target~.jump-down{display:none}#page-top:target~.jump-down{display:flex}#page-top:target~.jump-up{display:none}a.fn-badge,a.fn-badge:hover,a.fn-badge:focus{border-bottom:none !important;text-decoration:none !important}.entry-embed{border:1px solid #444;border-radius:6px;padding:1rem;margin:1.5rem 0;background:#2a2a2a}.entry-embed__body{margin-top:.5rem}.entry-embed__footer{color:#aaa;font-size:.75em;display:flex;align-items:center;gap:.35rem;flex-wrap:wrap;margin-top:.25rem}.entry-embed__footer a{color:inherit;text-decoration:none;border-bottom:0.1px dotted currentColor}.entry-embed__pill{display:inline-block;padding:.1em .6em;margin-right:.4em;background:#444;color:#fff;border-radius:1em;font-size:.75em;text-transform:capitalize;vertical-align:middle;line-height:1.6}.entry-embed--error{border-color:#b33;background:#331414;color:#f9c0c0}
.skip-link{position:absolute;left:-999px;top:auto;width:1px;height:1px;overflow:hidden}
.skip-link:focus{left:1.5rem;top:1.5rem;width:auto;height:auto;padding:.5rem .85rem;background:#fff;color:#000;border-radius:.25rem;z-index:1100;text-decoration:none;border-bottom:none}
</style>
<body>
<a class="skip-link" href="#main-content">Skip to main content</a>
{% macro backlinks_panel(blist) -%}
    {% if blist %}
    <details class="backlinks" style="margin-bottom:1.5rem;font-size:1rem;">
    <summary style="cursor:pointer;font-weight:bold;">
        Backlinks&nbsp;({{ blist|length }})
    </summary>
    <ol style="margin:1rem 0 0 1.5rem;">
        {%- for b in blist %}
        <li>
            <a href="{{ url_for('entry_detail',
                                kind_slug=kind_to_slug(b.kind),
                                entry_slug=b.slug) }}">
            {{ b.title or b.slug }}
            </a>
        </li>
        {%- endfor %}
    </ol>
    </details>
    {% endif %}
{%- endmacro %}
<div class="container h-feed" style="max-width: 60rem; margin: 3rem auto;">
    <h1 id="page-top" style="margin-top:0;"><a href="{{ url_for('index') }}" style="color:{{ theme_color() }};">{{title or 'po.etr.ist'}}</a></h1>
    <nav aria-label="Primary" style="margin-bottom:1rem;display:flex;align-items:flex-end;font-size:.9em;">
        <!-- LEFT : two stacked rows -->
        <div style="display:flex; flex-direction:column; gap:.25rem;">
            <div>
                <a href="{{ url_for('by_kind', slug=kind_to_slug('say')) }}"
                {% if kind=='say' %}style="text-decoration:none;border-bottom:.33rem solid #aaa;" aria-current="page"{% endif %}>
                Says</a>&nbsp;&nbsp;
                <a href="{{ url_for('by_kind', slug=kind_to_slug('post')) }}"
                {% if kind=='post' %}style="text-decoration:none;border-bottom:.33rem solid #aaa;" aria-current="page"{% endif %}>
                Posts</a>&nbsp;&nbsp;
                <a href="{{ url_for('by_kind', slug=kind_to_slug('pin')) }}"
                {% if kind=='pin' %}style="text-decoration:none;border-bottom:.33rem solid #aaa;" aria-current="page"{% endif %}>
                Pins</a>&nbsp;&nbsp;
                <a href="{{ tags_href() }}"
                {% if kind=='tags' %}style="text-decoration:none;border-bottom:.33rem solid #aaa;" aria-current="page"{% endif %}>
                Tags</a>&nbsp;&nbsp;
            </div>
            {% if active_verbs() %}
            <div>
                {% for v in active_verbs() %}
                    {% set label = {'read':'Read','watch':'Watch','listen':'Listen','play':'Play','visit':'Visit', "use": "Use"}[v] %}
                    <a href="{{ url_for('by_kind', slug=kind_to_slug(v)) }}"
                    {% if verb==v %}style="text-decoration:none;border-bottom:.33rem solid #aaa;" aria-current="page"{% endif %}>
                    {{ label }}</a>{% if not loop.last %}&nbsp;&nbsp;{% endif %}
                {% endfor %}
            </div>
            {% endif %}
        </div>

        <!-- RIGHT : two stacked rows (auth button, search) -->
        <div style="margin-left:auto; display:flex; flex-direction:column; gap:.25rem;align-items:flex-end;">
            <div style="white-space:nowrap;">
                {% if session.get('logged_in') %}
                    <a href="{{ settings_href() }}"
                    {% if request.path==settings_href() %}style="text-decoration:none;border-bottom:.33rem solid #aaa;" aria-current="page"{% endif %}>
                    Settings</a>
                {% else %}
                    <a href="{{ url_for('login') }}"
                    {% if request.endpoint=='login' %}style="text-decoration:none;border-bottom:.33rem solid #aaa;" aria-current="page"{% endif %}>
                    Login</a>
                {% endif %}
            </div>
            <div>
                <form action="{{ url_for('search') }}" method="get" style="margin:0;">
                    <input type="search" name="q" aria-label="Search entries" placeholder="Search" value="{{ request.args.get('q','') }}"
                        style="width:13rem;font-size:.8em; padding:.2em .6em; margin:0;">
                </form>
            </div>
        </div>
    </nav>
    <a class="p-author h-card u-url" href="{{ url_for('index') }}" rel="me" style="display:none;">
        <span class="p-name">{{ username }}</span>
    </a>
    {% with msgs = get_flashed_messages() %}
    {% if msgs %}
        {# --- toast ----------------------------------------------------------- #}
        <div role="status" aria-live="polite" aria-atomic="true" style="position:fixed;top:1rem; right:1rem;background:#323232; color:#fff;padding:.75rem 1rem;border-radius:.4rem;font-size:.9rem; line-height:1.3;box-shadow:0 2px 6px rgba(0,0,0,.4);max-width:24rem; z-index:999;">
        {{ msgs|join('<br>')|safe }}
        </div>
    {% endif %}
    {% endwith %}
    <main id="main-content" role="main" tabindex="-1">
"""

TEMPL_EPILOG = """
    </main>
    <footer id="page-bottom" style="margin-top:1.875em;padding-top:1.5em;font-size:.8em;color:#888;display:flex;align-items:center;justify-content:space-between;border-top:1px solid #444;">
        <!-- left-hand side -->
        <span style="font-weight:normal;color:#aaa;">
            Built with
            <a href="https://github.com/huangziwei/poetrist"
               style="color:{{ theme_color() }};text-decoration:none;border-bottom:0.1px dotted currentColor;">
               poetrist</a>
               <span style="font-weight:normal;color:#aaa">v{{ version }}</span>
        </span>

        <!-- right-hand side – extra pages -->
        <nav aria-label="Footer" style="display:inline-block;">
            {% if has_today() %}
                <a href="{{ url_for('today') }}"
                {% if request.endpoint == 'today' %}
                    style="text-decoration:none;border-bottom:.33rem solid #aaa;" aria-current="page"
                {% endif %}>
                Today</a>&nbsp;
            {% endif %}
            {% for p in nav_pages() %}
                <a href="{{ '/' ~ p['slug'] }}"
                {% if request.path|trim('/') == p['slug'] %}
                    style="text-decoration:none;border-bottom:.33rem solid #aaa;align-items:center;" aria-current="page"
                {% endif %}>
                    {{ p['title'] }}</a>{% if not loop.last %}&nbsp;{% endif %}
            {% endfor %}
        </nav>
    </footer>
    <a href="#page-bottom" aria-label="Jump to footer" class="jump-btn jump-down">↓</a>
    <a href="#page-top" aria-label="Jump to top" class="jump-btn jump-up">↑</a>
</div> <!-- container -->
</body>
</html>
"""


###############################################################################
# Authentication
###############################################################################
def validate_token(token: str, max_age: int = 60) -> bool:
    """
    • Unsigned  age-check in *one* step (`max_age` seconds).
    • Compare the payload (“handle”) against the hashed copy in the DB.
    """
    try:
        handle = signer.unsign(token, max_age=max_age).decode()
    except SignatureExpired:
        return False  # too old ➜ invalid
    except BadSignature:
        return False  # forged ➜ invalid

    row = get_db().execute("SELECT token_hash FROM user LIMIT 1").fetchone()
    return row and verify_token(row["token_hash"], handle)


def login_required() -> None:
    if not session.get("logged_in"):
        abort(403)


def rate_limit(max_requests: int, window: int = 60):
    hits: DefaultDict[str, deque] = defaultdict(deque)

    def decorator(view):
        @wraps(view)
        def wrapped(*args, **kwargs):
            now = time()
            # left-most entry after ProxyFix = real client
            ip = (
                request.access_route[0] if request.access_route else request.remote_addr
            ) or "unknown"

            dq = hits[ip]
            while dq and now - dq[0] > window:
                dq.popleft()

            if len(dq) >= max_requests:
                retry_after = int(window - (now - dq[0]))
                return Response(
                    "Too many requests – try again later.",
                    status=429,
                    headers={"Retry-After": str(retry_after)},
                )

            dq.append(now)
            return view(*args, **kwargs)

        return wrapped

    return decorator


@app.route("/login", methods=["GET", "POST"])
@rate_limit(max_requests=5, window=60)  # 3 attempts per minute
def login():
    # ── read token only from the form ──────────────────────────────
    token = request.form.get("token", "").strip()

    if request.method == "POST" and token and validate_token(token):
        # ── token matched → burn it right away ─────────────────────
        db = get_db()
        db.execute(
            "UPDATE user SET token_hash=? WHERE id=1",
            (hash_token(secrets.token_hex(16)),),
        )
        db.commit()

        session.clear()
        session.permanent = True
        session["logged_in"] = True
        session["csrf"] = secrets.token_hex(16)
        return redirect(url_for("index"))

    return render_template_string(
        TEMPL_LOGIN, title=get_setting("site_name", "po.etr.ist")
    )


TEMPL_LOGIN = wrap("""
{% block body %}
<hr>
<form method="post" id="token-form">
  {% if csrf_token() %}
  <input type="hidden" name="csrf" value="{{ csrf_token() }}">
  {% endif %}

  <div style="position:relative;">
      <input id="token" name="token" type="password" autocomplete="current-password"
             style="width:100%;padding-right:7rem;">
      <label for="token" style="position:absolute;right:.5rem;top:40%;transform:translateY(-50%);
                    pointer-events:none;font-size:.75em;color:#aaa;">token</label>
  </div>
    <div style="margin-top:1rem;display:flex;gap:.6rem;">
    <!-- traditional token login -->
    <button
        type="submit"
        style="
        flex:1 1 auto;
        padding:.55rem 1rem;
        font-size:.95em;
        "
    >
        Sign&nbsp;in&nbsp;with&nbsp;Token
    </button>

    <!-- passkey login (revealed by JS) -->
    <button
        id="pk-btn"
        type="button"
        style="display:none;flex:1 1 auto;padding:.55rem 1rem;font-size:.95em;background:{{ theme_color() }};color:#000;border:1px solid #666;box-shadow:0 2px 4px rgba(0,0,0,.25);cursor:pointer;">
        <span style="white-space:nowrap;">Sign&nbsp;in&nbsp;with&nbsp;Passkey</span>
    </button>
    </div>
</form>

<script>
(async () => {
  if (!('credentials' in navigator)) return;          // WebAuthn unsupported

  // 1)  ask the server for options
  const optRes = await fetch("/webauthn/begin_login");
  if (!optRes.ok) return;
  const opts = await optRes.json();
  if (!opts.allowCredentials.length) return;          // no keys stored

  // 2)  convert Base64-URL → Uint8Array
  const b2u = s => Uint8Array.from(atob(s.replace(/-/g,'+').replace(/_/g,'/')),
                                   c=>c.charCodeAt(0));
  opts.challenge        = b2u(opts.challenge);
  opts.allowCredentials = opts.allowCredentials.map(c => ({...c, id: b2u(c.id)}));

  // 3)  show the button
  const btn = document.getElementById('pk-btn');
  btn.style.display = 'block';
  btn.onclick = async () => {
    try {
      const cred = await navigator.credentials.get({publicKey: opts});

      // 4)  send to the server
      const toB64 = a => btoa(String.fromCharCode(...new Uint8Array(a)));
      const headers = {"Content-Type": "application/json"};
      const csrf = document.querySelector('input[name=\"csrf\"]');
      if (csrf) headers["X-CSRFToken"] = csrf.value;

      const res = await fetch("/webauthn/complete_login", {
        method:"POST",
        headers,
        body: JSON.stringify({
          id: cred.id,
          type: cred.type,
          rawId: toB64(cred.rawId),
          response: {
            authenticatorData: toB64(cred.response.authenticatorData),
            clientDataJSON:    toB64(cred.response.clientDataJSON),
            signature:         toB64(cred.response.signature),
            userHandle: cred.response.userHandle ?
                         toB64(cred.response.userHandle) : null
          },
          clientExtensionResults: cred.getClientExtensionResults()
        })
      });
      if (res.ok) location.href = "/";
      else alert("Passkey sign-in failed");
    } catch (err) {
      console.log("passkey login failed", err);
    }
  };
})();
</script>
{% endblock %}
""")


@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("index"))


# ──── WebAuthn / Passkey constants ──────────────────────────────
RP_NAME = "po.etr.ist"


# ──── tiny utils ────────────────────────────────────────────────
def _u():
    return get_db().execute("SELECT id FROM user LIMIT 1").fetchone()["id"]


def _passkeys():
    return (
        get_db()
        .execute(
            """SELECT id, cred_id, nickname, created_at
                               FROM passkey WHERE user_id=?""",
            (_u(),),
        )
        .fetchall()
    )


app.jinja_env.globals["_passkeys"] = _passkeys


def _add_passkey(cred_id, pub_key, sign_count, nick):
    db = get_db()
    db.execute(
        """INSERT INTO passkey
                  (user_id, cred_id, pub_key, sign_count, nickname, created_at)
                  VALUES (?,?,?,?,?,?)""",
        (
            _u(),
            cred_id,
            pub_key,
            sign_count,
            nick,
            utc_now().isoformat(timespec="seconds"),
        ),
    )
    db.commit()


def _rp_id() -> str:
    return request.host.partition(":")[0]


@app.route("/webauthn/begin_login")
def webauthn_begin_login():
    # 1. pull the raw bytes straight from the DB
    cred_bytes = [r["cred_id"] for r in _passkeys()]  #  <-- changed line
    if not cred_bytes:
        return {"allowCredentials": []}

    # 2. wrap every blob in a PublicKeyCredentialDescriptor
    allow = [PublicKeyCredentialDescriptor(id=b) for b in cred_bytes]

    # 3. generate options with the **current** host as rp_id
    opts = generate_authentication_options(
        rp_id=_rp_id(),
        allow_credentials=allow,
        user_verification=UserVerificationRequirement.PREFERRED,
    )
    session["wa_chal"] = opts.challenge
    return options_to_json(opts)


@app.route("/webauthn/complete_login", methods=["POST"])
def webauthn_complete_login():
    data = request.get_json(force=True)
    cred_id = base64url_to_bytes(data["id"])
    pk = (
        get_db().execute("SELECT * FROM passkey WHERE cred_id=?", (cred_id,)).fetchone()
    )
    if not pk:
        abort(400)
    try:
        ver = verify_authentication_response(
            credential=data,
            expected_challenge=session.pop("wa_chal", ""),
            expected_rp_id=_rp_id(),  # "localhost"
            expected_origin=f"{request.scheme}://{request.host}",
            credential_public_key=pk["pub_key"],
            credential_current_sign_count=pk["sign_count"],
            require_user_verification=True,
        )
        # update the stored sign-count that WebAuthn uses for replay protection
        get_db().execute(
            "UPDATE passkey SET sign_count=? WHERE id=?", (ver.new_sign_count, pk["id"])
        )
        get_db().commit()
    except Exception:
        abort(400)

    session.clear()
    session.permanent = True
    session["logged_in"] = True
    session["csrf"] = secrets.token_hex(16)
    return {"ok": True}


@app.route("/webauthn/begin_register")
def webauthn_begin_register():
    login_required()
    exclude = [PublicKeyCredentialDescriptor(id=r["cred_id"]) for r in _passkeys()]
    options = generate_registration_options(
        rp_id=_rp_id(),
        rp_name=get_setting("site_name", RP_NAME),
        user_id=str(_u()).encode(),
        user_name=current_username(),
        exclude_credentials=exclude,
        attestation=AttestationConveyancePreference.NONE,
    )
    session["wa_chal"] = options.challenge
    return options_to_json(options)


@app.route("/webauthn/complete_register", methods=["POST"])
def webauthn_complete_register():
    login_required()
    data = request.get_json(force=True)

    rp_id = request.host.split(":", 1)[0]
    origin = f"{request.scheme}://{request.host}"

    try:
        ver = verify_registration_response(
            credential=data,
            expected_challenge=session.pop("wa_chal", ""),  # ← note default
            expected_rp_id=rp_id,
            expected_origin=origin,
            require_user_verification=True,
        )
    except Exception as e:
        print("webauthn register failed")  # prints stack in terminal
        return {"error": str(e)}, 400  # visible in JS

    _add_passkey(
        cred_id=base64url_to_bytes(data["id"]),
        pub_key=ver.credential_public_key,
        sign_count=ver.sign_count,
        nick=request.args.get("nickname") or "Passkey",
    )
    return {"ok": True}


@app.route("/webauthn/delete/<int:pkid>", methods=["POST"])
def webauthn_delete_passkey(pkid):
    """
    Delete one stored passkey and return the user to the Settings page.
    The request is already CSRF-guarded and the user is authenticated.
    """
    login_required()

    db = get_db()
    db.execute("DELETE FROM passkey WHERE id=? AND user_id=?", (pkid, _u()))
    db.commit()

    flash("Passkey deleted.")  # nice feedback for the toast
    return redirect(settings_href(), code=303)  # PRG pattern


@app.route("/webauthn/rename/<int:pkid>", methods=["POST"])
def webauthn_rename_passkey(pkid):
    """
    Rename one stored passkey.
    Body: {"nickname": "<new name>"}  (JSON)
    Headers: X-CSRFToken (same token you already use)
    """
    login_required()

    data = request.get_json(force=True)
    nickname = (data.get("nickname") or "").strip()
    if not nickname:
        return {"error": "empty nickname"}, 400

    db = get_db()
    db.execute(
        "UPDATE passkey SET nickname=? WHERE id=? AND user_id=?",
        (nickname, pkid, _u()),
    )
    db.commit()
    return {"ok": True}


###############################################################################
# Resources
###############################################################################
@app.route("/favicon.svg")
def favicon():
    """Return a 64 px SVG favicon whose color follows the current theme."""
    # ── background = theme color ───────────────────────────────────────────
    bg = theme_color().lstrip("#")
    if len(bg) == 3:  # allow #abc shorthand
        bg = "".join(c * 2 for c in bg)
    r, g, b = (int(bg[i : i + 2], 16) for i in (0, 2, 4))

    # ── foreground = simple RGB complement (#RRGGBB → #ʀ̅ ɢ̅ ʙ̅) ───────────
    fg = "#FFFFFF" if (r + g + b) < 384 else "#000000"  # light/dark

    # ── pick a letter: “P” by default, or 1st character of Site name ───────
    letter = (get_setting("site_name", "") or "P")[0].upper()

    svg = f'''<svg xmlns="http://www.w3.org/2000/svg"
                    width="64" height="64" viewBox="0 0 64 64">
      <rect width="64" height="64" rx="8" ry="8" fill="#{bg}"/>
      <text x="32" y="46" text-anchor="middle"
            font-family="Arial,Helvetica,sans-serif"
            font-size="42" font-weight="800"
            fill="{fg}">{letter}</text>
    </svg>'''

    # 1-day cache so browsers don’t keep hammering the route
    return Response(
        svg,
        mimetype="image/svg+xml",
        headers={"Cache-Control": "public, max-age=86400"},
    )


@app.route("/robots.txt")
def robots():
    """
    Allow selected well-behaved crawlers, nudge everyone else away.
    """
    rules = (
        "User-agent: GPTBot\n"
        "Allow: /\n\n"
        "User-agent: Googlebot\n"
        "Allow: /\n\n"
        "User-agent: Bingbot\n"
        "Allow: /\n\n"
        "User-agent: Applebot\n"
        "Allow: /\n\n"
        "User-agent: *\n"
        "Disallow: /\n"
    )
    return (
        Response(rules, mimetype="text/plain", direct_passthrough=True),
        200,
        {"Cache-Control": "public, max-age=86400"},
    )  # 1 day cache


SAFE_METHODS = {"GET", "HEAD", "OPTIONS", "TRACE"}


@app.before_request
def csrf_protect():
    # ➊ read-only verbs ⇒ always allowed
    if request.method in SAFE_METHODS:
        return

    # ➋ no logged-in flag yet ⇒ allow (covers /login POST)
    if not session.get("logged_in"):
        return

    # ➌ for authenticated users we REQUIRE a valid token
    token = session.get("csrf", "")
    sent = request.form.get("csrf") or request.headers.get("X-CSRFToken", "")
    if not token or not secrets.compare_digest(token, sent):
        abort(403)


@app.after_request
def sec_headers(resp):
    resp.headers.update(
        {
            "X-Frame-Options": "DENY",
            "X-Content-Type-Options": "nosniff",
            "Referrer-Policy": "strict-origin-when-cross-origin",
            "Permissions-Policy": "interest-cohort=()",  # opt-out of FLoC etc.
        }
    )
    return resp


###############################################################################
# Settings
###############################################################################
@app.route("/settings", methods=["GET", "POST"])
def settings():
    login_required()

    db = get_db()

    if request.method == "POST" and request.form.get("action") == "rotate_token":
        session["one_time_token"] = _rotate_token(db)  # store once
        return redirect(
            settings_href() + "#new-token", code=303
        )  # PRG; 303 = “See Other”

    if request.method == "POST":
        site_name = request.form["site_name"].strip()
        username = request.form["username"].strip()
        col = request.form["theme_color"].strip()
        tz = request.form.get("timezone", "").strip()
        if tz in available_timezones():
            set_setting("timezone", tz)

        if site_name:
            set_setting("site_name", site_name)

        if username:
            db.execute("UPDATE user SET username=? WHERE id=1", (username,))
            db.commit()

        if col:
            if re.fullmatch(r"#?[0-9A-Fa-f]{6}", col):
                if not col.startswith("#"):
                    col = "#" + col
                set_setting("theme_color", col)
            else:
                flash("Invalid color – please use 6-digit hex.")

        for kind, default_slug in SLUG_DEFAULTS.items():
            raw = request.form.get(f"slug_{kind}", "").strip()
            set_setting(f"slug_{kind}", raw or default_slug)
        for verb in active_verbs():
            raw = request.form.get(f"slug_{verb}", "").strip()
            set_setting(f"slug_{verb}", raw or verb)
        set_setting("slug_tags", request.form.get("slug_tags", "").strip() or "tags")
        set_setting(
            "slug_settings", request.form.get("slug_settings", "").strip() or "settings"
        )

        size = (
            max(1, int(raw))
            if (raw := request.form.get("page_size", "").strip()).isdigit()
            else PAGE_DEFAULT
        )
        set_setting("page_size", size)

        flash("Settings saved.")
        return redirect(settings_href())

    new_token = session.pop("one_time_token", None)  # use-and-forget
    cur_username = db.execute("SELECT username FROM user LIMIT 1").fetchone()[
        "username"
    ]
    active_verb_list = active_verbs()
    slug_settings = slug_map()
    slug_settings["tags"] = tags_slug()
    slug_settings["settings"] = settings_slug()
    verb_slugs = [(v, slug_settings.get(v, v)) for v in active_verb_list]
    return render_template_string(
        TEMPL_SETTINGS,
        site_name=get_setting("site_name", "po.etr.ist"),
        username=cur_username,
        new_token=new_token,
        title=get_setting("site_name", "po.etr.ist"),
        slug_settings=slug_settings,
        verb_slugs=verb_slugs,
    )


TEMPL_SETTINGS = wrap("""
    {% block body %}
    <hr>
    <h2>Site Settings</h2>
    <form method="post" style="max-width:36rem">
        {% if csrf_token() %}
            <input type="hidden" name="csrf" value="{{ csrf_token() }}">
            {% endif %}
        <!-- ──────────── site info ──────────── -->
        <fieldset style="margin:0 0 1.5rem 0; border:0; padding:0">
            <label style="display:block; margin:.5rem 0">
                <span style="font-size:.8em; color:#aaa">Site name</span><br>
                <input name="site_name" value="{{ site_name }}" style="width:100%">
            </label>

            <label style="display:block; margin:.5rem 0">
                <span style="font-size:.8em; color:#aaa">Username</span><br>
                <input name="username" value="{{ username }}" style="width:100%">
            </label>
                      
            <label style="display:block;margin:.5rem 0">
                <span style="font-size:.8em;color:#aaa">Timezone</span><br>
                <input list="tz-list" name="timezone" value="{{ tz_name() }}"
                    style="width:100%">
            </label>
                      
            <label style="display:flex; margin:.5rem 0">
                <span style="font-size:.8em; color:#aaa;margin-right:1rem">Theme color</span><br>
                <input name="theme_color"
                    value="{{ get_setting('theme_color', '#A5BA93') }}"
                    placeholder="#A5BA93"
                    style="width:8rem">
            </label>
            <details style="margin:.25rem 0 1rem 0;">
                <summary style="font-size:1rem;color:#aaa;">
                    Presets
                </summary>
                <div style="display:flex;flex-wrap:wrap;gap:.6rem 1.2rem;align-items:center;margin:.75rem 0 0 0;font-size:.8em;">
                    {% for name, col in theme_presets.items() %}
                        <span style="display:flex;align-items:center;gap:.4rem;">
                            <span style="width:1.25rem; height:1.25rem;border:1px solid #555;border-radius:.15rem;background:{{ col }};">
                            </span>
                            <code>{{ col }}</code>
                            <small style="color:#888;">{{ name }}</small>
                        </span>
                    {% endfor %}
                </div>
            </details>
        </fieldset>

        <!-- ──────────── slugs ──────────── -->
        <fieldset style="margin:0 0 1.5rem 0; border:0; padding:0">
            <legend style="font-weight:bold; margin-bottom:.5rem;">URL slugs</legend>
                <div style="display:grid; grid-template-columns:repeat(auto-fit,minmax(10rem,1fr)); gap:.75rem;">
                    <label>
                        <span style="font-size:.8em; color:#aaa">Says</span><br>
                        <input name="slug_say"  value="{{ slug_settings['say'] }}" style="width:100%">
                    </label>
                    <label>
                        <span style="font-size:.8em; color:#aaa">Posts</span><br>
                        <input name="slug_post" value="{{ slug_settings['post'] }}" style="width:100%">
                    </label>
                    <label>
                        <span style="font-size:.8em; color:#aaa">Pins</span><br>
                        <input name="slug_pin" value="{{ slug_settings['pin'] }}" style="width:100%">
                    </label>
            </div>
            <div style="margin-top:1rem;">
                <span style="font-size:.8em; color:#aaa">Other</span>
                <div style="display:grid; grid-template-columns:repeat(auto-fit,minmax(10rem,1fr)); gap:.75rem; margin-top:.4rem;">
                    <label>
                        <span style="font-size:.8em; color:#aaa">Tags</span><br>
                        <input name="slug_tags" value="{{ slug_settings['tags'] }}" style="width:100%">
                    </label>
                    <label>
                        <span style="font-size:.8em; color:#aaa">Settings</span><br>
                        <input name="slug_settings" value="{{ slug_settings['settings'] }}" style="width:100%">
                    </label>
                </div>
            </div>
            <div style="margin-top:1rem;">
                {% if verb_slugs %}
                    <span style="font-size:.8em; color:#aaa">Verbs</span>
                    <div style="display:grid; grid-template-columns:repeat(auto-fit,minmax(10rem,1fr)); gap:.75rem; margin-top:.4rem;">
                        {% for verb, slug in verb_slugs %}
                        <label>
                            <span style="font-size:.8em; color:#aaa">{{ verb|capitalize }}</span><br>
                            <input name="slug_{{ verb }}" value="{{ slug }}" style="width:100%">
                        </label>
                        {% endfor %}
                    </div>
                {% endif %}
            </div>
        </fieldset>

        <!-- ──────────── display ──────────── -->
        <fieldset style="margin:0 0 1.5rem 0; border:0; padding:0">
            <legend style="font-weight:bold; margin-bottom:.5rem;">Pagination</legend>
            <label style="display:block; margin:.5rem 0">
                <span style="font-size:.8em; color:#aaa">Entries per page</span><br>
                <input name="page_size"
                    value="{{ get_setting('page_size', PAGE_DEFAULT) }}"
                    style="width:8rem">
            </label>
        </fieldset>
        <button style="margin-top:.5rem;">Save settings</button>
    </form>
    <br>
    <hr>
          
    <h2>Authentication</h2>
                      
    <h3>Token</h3>
    <div style="display:flex; gap:1rem; max-width:36rem; margin-top:2rem;">
        <!-- token button in its own tiny form -->
        <form method="post" style="margin:0;">
            {% if csrf_token() %}
            <input type="hidden" name="csrf" value="{{ csrf_token() }}">
            {% endif %}
            <button name="action" value="rotate_token" style="color:{{ theme_color() }}; background:#333;">
                Get new token
            </button>
        </form>
    </div>

    {% if new_token %}
        <div id="new-token" style="margin-top:1.5rem; padding:1rem; border:1px solid #555;
                    background:#222; font-family:monospace; word-break:break-all;font-size:1.2rem;">
            {{ new_token }}
        </div>
    {% endif %}
         
    <!-- ─────────── Passkeys ─────────── -->
    <h3>Passkeys</h3>
    <ul id="pk-list" style="list-style:none;padding:0;margin:0;">
        {% for p in _passkeys() %}
        <li class="pk-row"
            data-pkid="{{ p.id }}"
            style="display:flex;align-items:start;gap:.5rem;margin:.6rem 0;">

            <!-- left: nickname + timestamp stacked in a mini-column -->
            <div style="flex:1;display:flex;flex-direction:column;gap:.15rem;">
                <span  class="pk-name">{{ p.nickname or 'Passkey' }}</span>
                <small class="pk-date" style="color:#888;font-size:.75em;">
                    {{ p.created_at|ts }}
                </small>
            </div>

            <!-- edit / save toggle -->
            <div style="margin:0;display:inline-block;">
            <button type="button"
                    class="pk-edit-btn">
                Edit
            </button>
            </div>

            <!-- delete -->
            <form class="pk-del-form"
                data-pkid="{{ p.id }}"
                method="post"
                action="{{ url_for('webauthn_delete_passkey', pkid=p.id) }}"
                style="margin:0;display:inline-block;">
                <input type="hidden" name="csrf"     value="{{ csrf_token() }}">
                <input type="hidden" name="assertion">
                <button type="submit"
                        onclick="return confirm('Delete this passkey?');"
                        style="color:#fff;background:#c00;border-color:#c00;">
                    Delete
                </button>
            </form>
        </li>
        {% else %}
        <li>No passkeys yet.</li>
        {% endfor %}

    <button id="add-pk">Add&nbsp;Passkey</button>

    <script>
    /*  settings → passkeys
        ───────────────────────────────────────────────────────────
        • create new passkey  (existing code, untouched)
        • rename / delete without leaving the page  (new)
        • wrapped in an IIFE to avoid globals
    */
    (() => {
    /* csrf token: take the first one we find on the page */
    const CSRF = document.querySelector('input[name="csrf"]')?.value || '';

    /* ---------- tiny helpers ------------------------------------------- */
    const b2u   = s => Uint8Array.from(atob(s.replace(/-/g,'+').replace(/_/g,'/')), c => c.charCodeAt(0));
    const u2b64 = b => btoa(String.fromCharCode(...new Uint8Array(b)));

    function getBrowserName () {
        if (navigator.userAgentData?.brands?.length) {
        const real = navigator.userAgentData.brands
                        .map(b => b.brand)
                        .filter(b => !/^Chromium$/i.test(b) && !/^Not.*Brand$/i.test(b));
        if (real.length) return real[0];
        }
        const ua = navigator.userAgent;
        if (/Firefox\\/\\d+/i.test(ua)) return 'Firefox';
        if (/Edg\\/\\d+/i.test(ua))     return 'Edge';
        if (/OPR\\/\\d+/i.test(ua))     return 'Opera';
        if (/Chrome\\/\\d+/i.test(ua))  return 'Chrome';
        if (/Safari\\/\\d+/i.test(ua))  return 'Safari';
        return 'Passkey';
    }

    /* ====================================================================
        A)  “Add passkey”  (original behaviour, left intact)
        ================================================================== */
    const addBtn = document.getElementById('add-pk');
    if (addBtn) addBtn.onclick = async () => {
        const optRes = await fetch('/webauthn/begin_register');
        if (!optRes.ok) return alert('Server error');

        const opts = await optRes.json();
        opts.challenge           = b2u(opts.challenge);
        opts.user.id             = b2u(opts.user.id);
        opts.excludeCredentials  = opts.excludeCredentials.map(c => ({...c,id:b2u(c.id)}));

        let cred;
        try { cred = await navigator.credentials.create({publicKey:opts}); }
        catch (e) { console.log('Passkey creation aborted', e); return; }

        const body = {
        id: cred.id,
        rawId: u2b64(cred.rawId),
        type: cred.type,
        response: {
            attestationObject: u2b64(cred.response.attestationObject),
            clientDataJSON:    u2b64(cred.response.clientDataJSON)
        },
        clientExtensionResults: cred.getClientExtensionResults()
        };

        const nn   = encodeURIComponent(getBrowserName());
        const res  = await fetch(`/webauthn/complete_register?nickname=${nn}`, {
        method:'POST',
        headers:{'Content-Type':'application/json','X-CSRFToken':CSRF},
        body:JSON.stringify(body)
        });

        if (res.ok) location.reload();
        else        alert('Passkey registration failed');
    };

    /* ====================================================================
        B)  Rename an existing passkey in-place
        ================================================================== */
    document.querySelectorAll('.pk-edit-btn').forEach(btn => {
        btn.addEventListener('click', async () => {
        const row   = btn.closest('.pk-row');
        const pkid  = row.dataset.pkid;
        console.log('pkid', pkid);
                      
        /* —— enter edit mode ——————————————————————————— */
        if (btn.textContent.trim() === 'Edit') {
            const span   = row.querySelector('.pk-name');
            const input  = document.createElement('input');
            input.type   = 'text';
            input.value  = span.textContent.trim();
            input.style.maxWidth = '25rem';
            input.style.flex = '1';                 // keep column width
            input.className  = 'pk-name-edit';      // easy selector

            span.replaceWith(input);
            btn.textContent = 'Save';
            input.focus();
            return;
        }
                      

        /* —— save nickname ———————————————————————————— */
        if (btn.textContent.trim() !== 'Save') return;   // should never happen
        const input    = row.querySelector('.pk-name-edit');
        if (!input) return;
        const nickname = input.value.trim();

        try {
            const res = await fetch(`/webauthn/rename/${pkid}`, {
            method :'POST',
            headers:{'Content-Type':'application/json','X-CSRFToken':CSRF},
            body   :JSON.stringify({nickname})
            });
            if (!res.ok) throw new Error();
        } catch {
            alert('Rename failed – please try again.');
            return;
        }

        /* —— update UI on success ——————————————————— */
        const newSpan = document.createElement('span');
        newSpan.className = 'pk-name';
        newSpan.textContent = nickname || 'Passkey';
        input.replaceWith(newSpan);
        btn.textContent = 'Edit';
        });
    });
    })();
    </script>
    <br>
    <hr style="margin:2rem 0">
    <!-- logout link, vertically centered -->
    <div style="display:flex; gap:1rem; max-width:36rem; margin-top:2rem;">
        <a href="{{ url_for('logout') }}"
            style="align-self:center; color:{{ theme_color() }}; text-decoration:none;">
        ⎋ Log&nbsp;out
        </a>
    </div>
    {% endblock %}
""")


###############################################################################
# Index + Listings
###############################################################################
@app.route("/", methods=["GET", "POST"])
def index():
    db = get_db()

    # Quick-add “Say” for logged-in admin
    form_body = ""
    if request.method == "POST":
        login_required()
        form_body = request.form.get("body", "")
        body_input = form_body.strip()

        if not body_input:
            flash("Text is required.")
        else:
            body_parsed, blocks, errors = parse_trigger(body_input)
            if errors:
                flash("Errors in caret blocks found. Entry was not saved.")
                for err in errors:
                    flash(err)
            else:
                kind = blocks[0]["verb"] if blocks else infer_kind("", "")
                now_dt = utc_now()
                now = now_dt.isoformat(timespec="seconds")
                slug = now_dt.strftime("%Y%m%d%H%M%S")

                db.execute(
                    """INSERT INTO entry (body, created_at, slug, kind)
                              VALUES (?,?,?,?)""",
                    (body_parsed, now, slug, kind),
                )
                entry_id = db.execute("SELECT last_insert_rowid()").fetchone()[0]

                sync_tags(entry_id, extract_tags(body_parsed), db=db)

                for idx, blk in enumerate(blocks):
                    item_id, slug_i, uuid_i = get_or_create_item(
                        item_type=blk["item_type"],
                        title=blk["title"],
                        meta=blk["meta"],
                        slug=blk["slug"],
                        db=db,
                        update_meta=True,  # only on creation
                    )

                    db.execute(
                        """INSERT OR IGNORE INTO entry_item
                                    (entry_id, item_id, verb, action, progress)
                                VALUES (?,?,?,?,?)""",
                        (
                            entry_id,
                            item_id,
                            blk["verb"],
                            blk["action"],
                            blk["progress"],
                        ),
                    )

                    # patch placeholder in the *local* variable
                    body_parsed = body_parsed.replace(
                        f"^{blk['item_type']}:$PENDING${idx}$",
                        _verbose_block(blk, uuid_i),
                    )

                # 🔑  NOW write the patched body back ↓↓↓
                db.execute(
                    "UPDATE entry SET body=? WHERE id=?", (body_parsed, entry_id)
                )
                db.commit()
                return redirect(url_for("index"))

    # pagination
    page = max(int(request.args.get("page", 1)), 1)
    ps = page_size()
    BASE_SQL = """
        SELECT  e.*,

                ei.action,
                ei.progress,
                i.title       AS item_title,
                i.slug        AS item_slug,
                i.item_type   AS item_type,
                MIN(CASE
                        WHEN im.k = 'date' AND LENGTH(im.v) >= 4
                        THEN SUBSTR(im.v, 1, 4)
                    END)      AS item_year,
                EXISTS (SELECT 1 FROM entry_item ei2
                        WHERE ei2.entry_id = e.id
                    )         AS had_item
        FROM entry e
        LEFT JOIN entry_item ei ON ei.entry_id = e.id
        LEFT JOIN item       i  ON i.id        = ei.item_id
        LEFT JOIN item_meta  im ON im.item_id  = i.id 
        WHERE e.kind!='page'
        GROUP BY e.id
        ORDER BY e.created_at DESC
    """

    entries, total_pages = paginate(BASE_SQL, (), page=page, per_page=ps, db=db)

    pages = list(range(1, total_pages + 1))
    back_map = backlinks(entries, db=db)
    return render_template_string(
        TEMPL_INDEX,
        entries=entries,
        page=page,
        pages=pages,
        backlinks=back_map,
        title=get_setting("site_name", "po.etr.ist"),
        username=current_username(),
        form_body=form_body,
    )


TEMPL_INDEX = wrap("""{% block body %}
    {% if session.get('logged_in') %}
        <hr style="margin:10px 0">
        <form method="post"
              style="display:flex;
                     flex-direction:column;
                     gap:10px;
                     align-items:flex-start;">
            {% if csrf_token() %}
            <input type="hidden" name="csrf" value="{{ csrf_token() }}">
            {% endif %}
            <textarea name="body"
                      rows="3"
                      style="width:100%;margin:0"
                      placeholder="What's on your mind?">{{ form_body or '' }}</textarea>
            <button>Add&nbsp;Say</button>
        </form>
    {% endif %}
    <hr>
    {% for e in entries %}
    <article class="h-entry" {% if not loop.last %}style="padding-bottom:1.5em; border-bottom:1px solid #444;"{% endif %}>
        {% if e['kind']=='pin' %}
            <h2>
                <a class="u-bookmark-of p-name" href="{{ e['link'] }}" target="_blank" rel="noopener">
                    {{ e['title'] }}
                </a>
                {{ external_icon() }} 
            </h2>
        {% elif e['kind']=='post' and e['title'] %}
            <h2 class="p-name">{{e['title']}}</h2>
        {% endif %}
        <div class="e-content" style="margin-top:1.5em;">{{ e['body']|md(e['slug']) }}</div>

        {{ backlinks_panel(backlinks[e.id]) }}

        <small style="color:#aaa;">
            {% if e.item_title %} 
                <span style="
                    display:inline-block;padding:.1em .6em;margin-right:.4em;background:#444;
                    color:#fff;border-radius:1em;font-size:.75em;text-transform:capitalize;
                    vertical-align:middle;">
                   {{ e.action | smartcap }}
                </span>
                {% if e.item_type %}
                <span style="
                    display:inline-block;padding:.1em .6em;margin-right:.4em;background:#444;
                    color:#fff;border-radius:1em;font-size:.75em;vertical-align:middle;">
                    {{ e.item_type | smartcap }}
                </span>
                {% endif %}
                {% if e.progress %}
                <span style="
                    display:inline-block;padding:.1em .6em;margin-right:.4em;background:#444;
                    color:#fff;border-radius:1em;font-size:.75em;vertical-align:middle;">
                    {{ e.progress }}
                </span>
                {% endif %}
                <a href="{{ url_for('item_detail', verb=kind_to_slug(e.kind), item_type=e.item_type, slug=e.item_slug) }}"
                    style="text-decoration:none;margin-right:.4em;color:{{ theme_color() }};vertical-align:middle;">
                    {{ e.item_title }}{% if e.item_year %} ({{ e.item_year }}){% endif %}
                </a>
                <br>
            {% endif %}
            <span style="
                display:inline-block;
                padding:.1em .6em;
                margin-right:.4em;
                background:#444;
                color:#fff;
                border-radius:1em;
                font-size:.75em;
                text-transform:capitalize;
                vertical-align:middle;
            ">
                <a href="{{ url_for('by_kind', slug=kind_to_slug(e['kind'])) }}"
                   style="text-decoration:none; color:inherit;border-bottom:none;">
                   {{ e['kind'] }}
                </a>
            </span>
            <a class="u-url u-uid" href="{{ url_for('entry_detail', kind_slug=kind_to_slug(e['kind']), entry_slug=e['slug']) }}"
                style="text-decoration:none; color:inherit;vertical-align:middle;font-variant-numeric:tabular-nums;white-space:nowrap;">
                <time class="dt-published" datetime="{{ e['created_at'] }}">{{ e['created_at']|ts }}</time>
            </a>&nbsp;
            {% if session.get('logged_in') %}
                <a href="{{ url_for('edit_entry', kind_slug=kind_to_slug(e['kind']), entry_slug=e['slug']) }}" style="vertical-align:middle;">Edit</a>&nbsp;&nbsp;
                <a href="{{ url_for('delete_entry', kind_slug=kind_to_slug(e['kind']), entry_slug=e['slug']) }}" style="vertical-align:middle;">Delete</a>
            {% endif %}
            {% set tags = entry_tags(e.id) %}
            {% if tags %}
                &nbsp;·&nbsp;
                {% for tag in tags %}
                    <a class="p-category" rel="tag" href="{{ tags_href(tag) }}"
                       style="text-decoration:none;margin-right:.35em;color:{{ theme_color() }};vertical-align:middle;">
                        #{{ tag }}
                    </a>
                {% endfor %}
            {% endif %}
        </small>
    </article>
    {% else %}
        <p>No entries yet.</p>
    {% endfor %}

    {% if pages|length > 1 %}
    <nav style="margin-top:2em;padding-top:2em;font-size:.75em;border-top:1px solid #444;">
        {% for p in pages %}
            {% if p == page %}
                <span style="border-bottom:0.33rem solid #aaa;">{{ p }}</span>
            {% else %}
                <a href="{{ request.path }}?page={{ p }}">{{ p }}</a>
            {% endif %}
            {% if not loop.last %}&nbsp;{% endif %}
        {% endfor %}
    </nav>
    {% endif %}
{% endblock %}
""")


@app.route("/<slug>", methods=["GET", "POST"])
def by_kind(slug):
    # Special-case custom slugs for tags/settings before kind detection
    if slug == tags_slug():
        return tags("")  # base tags view
    if slug == settings_slug():
        return settings()

    db = get_db()

    page = db.execute(
        "SELECT * FROM entry WHERE kind='page' AND slug=?", (slug,)
    ).fetchone()
    if page:
        return render_template_string(
            TEMPL_PAGE,
            e=page,
            username=current_username(),
            title=get_setting("site_name", "po.etr.ist"),
            kind="page",
        )

    kind = slug_to_kind(slug)
    if kind == "page":
        abort(404)

    # ---------- create new entry when the admin submits the inline form ----
    form_title = ""
    form_link = ""
    form_body = ""
    if request.method == "POST":
        login_required()

        form_title = request.form.get("title", "").strip()
        form_link = request.form.get("link", "").strip()
        form_body = request.form.get("body", "")
        body_input = form_body.strip()

        project_specs: list[dict[str, str]] = []
        body_for_parse = body_input
        if kind == "post":
            body_for_parse, project_specs = parse_projects(body_input)

        body_parsed, blocks, errors = parse_trigger(body_for_parse)

        # final kind used for insertion: caret verb wins, then explicit page
        entry_kind = kind
        if request.form.get("is_page") == "1":
            entry_kind = "page"
        elif blocks:
            entry_kind = blocks[0]["verb"]

        if errors:
            flash("Errors in caret blocks found. Entry was not saved.")
            for err in errors:
                flash(err)
        else:
            missing = []

            if entry_kind == "say":
                if not body_input:
                    missing.append("body")

            elif entry_kind == "post":
                if not form_title:
                    missing.append("title")
                if not body_input:
                    missing.append("body")

            elif entry_kind == "pin":  # body is OPTIONAL here
                if not form_title:
                    missing.append("title")
                if not form_link:
                    missing.append("link")

            if missing:
                nice = " and ".join(missing)
                flash(
                    f"{nice.capitalize()} {'is' if len(missing) == 1 else 'are'} required."
                )
            else:
                now_dt = utc_now()
                now = now_dt.isoformat(timespec="seconds")
                entry_slug = now_dt.strftime("%Y%m%d%H%M%S")
                db.execute(
                    """INSERT INTO entry
                                (title, body, link, created_at, slug, kind)
                             VALUES (?,?,?,?,?,?)""",
                    (
                        form_title or None,
                        body_parsed,
                        form_link or None,
                        now,
                        entry_slug,
                        entry_kind,
                    ),
                )
                entry_id = db.execute("SELECT last_insert_rowid()").fetchone()[0]
                sync_tags(entry_id, extract_tags(body_parsed), db=db)
                if entry_kind == "post":
                    sync_projects(entry_id, project_specs, db=db)
                else:
                    sync_projects(entry_id, [], db=db)

                for idx, blk in enumerate(blocks):
                    item_id, slug_i, uuid_i = get_or_create_item(
                        item_type=blk["item_type"],
                        title=blk["title"],
                        meta=blk["meta"],
                        slug=blk["slug"],
                        db=db,
                        update_meta=True,  # only on creation
                    )

                    db.execute(
                        """INSERT OR IGNORE INTO entry_item
                                    (entry_id, item_id, verb, action, progress)
                                VALUES (?,?,?,?,?)""",
                        (
                            entry_id,
                            item_id,
                            blk["verb"],
                            blk["action"],
                            blk["progress"],
                        ),
                    )

                    body_parsed = body_parsed.replace(
                        f"^{blk['item_type']}:$PENDING${idx}$",
                        _verbose_block(blk, uuid_i),
                    )

                db.execute(
                    "UPDATE entry SET body=? WHERE id=?", (body_parsed, entry_id)
                )
                db.commit()

                if entry_kind == "page":
                    return redirect(url_for("by_kind", slug=entry_slug))

                return redirect(url_for("by_kind", slug=kind_to_slug(entry_kind or "")))

    # --- pagination -------------------------------------------------------
    page = max(int(request.args.get("page", 1)), 1)
    ps = page_size()

    if kind in VERB_KINDS:
        sel_type = request.args.get("type", "").strip()  # e.g. “book”
        selected = sel_type.lower() if sel_type else ""  # empty → “All”

        canonical_actions = [a.lower() for a in VERB_MAP.get(kind, ())]
        canonical_set = set(canonical_actions)
        action_placeholders = ",".join("?" * len(canonical_actions))
        sub_latest_filter = (
            f" AND LOWER(ei2.action) IN ({action_placeholders})"
            if canonical_actions
            else ""
        )

        sel_action = request.args.get("action", "").strip()
        selected_action = sel_action.lower() if sel_action else ""
        if selected_action and selected_action not in canonical_set:
            selected_action = ""

        raw_genre = request.args.get("genre", "").strip()
        selected_genre = normalize_genre(raw_genre) if raw_genre else ""

        params_facets = [kind, *canonical_actions, kind]
        facet_rows = db.execute(
            f"""
            WITH latest AS (
                SELECT i.id,
                       i.item_type,
                       LOWER((
                           SELECT ei2.action
                             FROM entry_item ei2
                             JOIN entry      e2 ON e2.id = ei2.entry_id
                            WHERE ei2.item_id = i.id
                              AND ei2.verb    = ?{sub_latest_filter}
                            ORDER BY e2.created_at DESC
                            LIMIT 1
                       )) AS last_action
                  FROM item i
                  JOIN entry_item ei ON ei.item_id = i.id
                 WHERE ei.verb = ?
                 GROUP BY i.id
            )
            SELECT l.id,
                   l.item_type,
                   l.last_action,
                   im.v AS genre_value
              FROM latest l
              LEFT JOIN item_meta im
                     ON im.item_id = l.id
                    AND LOWER(im.k) IN ('genre','genres')
        """,
            tuple(params_facets),
        )

        items_data: dict[int, dict] = {}
        genre_labels: dict[str, str] = {}
        for row in facet_rows:
            item_id = row["id"]
            rec = items_data.setdefault(
                item_id,
                {
                    "id": item_id,
                    "item_type": row["item_type"],
                    "last_action": row["last_action"],
                    "genres": set(),
                },
            )
            val = row["genre_value"]
            if val:
                for raw in GENRE_SPLIT_RE.split(val):
                    norm = normalize_genre(raw)
                    if not norm:
                        continue
                    rec["genres"].add(norm)
                    genre_labels.setdefault(norm, raw.strip())

        def _matches(
            rec: dict,
            *,
            type_filter: str | None,
            action_filter: str | None,
            genre_filter: str | None,
        ) -> bool:
            if type_filter and rec["item_type"] != type_filter:
                return False
            if action_filter and rec["last_action"] != action_filter:
                return False
            if genre_filter and genre_filter not in rec["genres"]:
                return False
            return True

        type_counts: DefaultDict[str, int] = defaultdict(int)
        for rec in items_data.values():
            if not _matches(
                rec,
                type_filter=None,
                action_filter=selected_action or None,
                genre_filter=selected_genre or None,
            ):
                continue
            type_counts[rec["item_type"]] += 1
        type_rows = sorted(
            ({"item_type": t, "cnt": cnt} for t, cnt in type_counts.items()),
            key=lambda r: -r["cnt"],
        )
        type_total_cnt = sum(type_counts.values())

        base_items_for_action = [
            rec
            for rec in items_data.values()
            if _matches(
                rec,
                type_filter=selected or None,
                action_filter=None,
                genre_filter=selected_genre or None,
            )
        ]
        filtered_total_cnt = len(base_items_for_action)

        action_counts: DefaultDict[str, int] = defaultdict(int)
        for rec in base_items_for_action:
            act = rec["last_action"]
            if act in canonical_set:
                action_counts[act] += 1
        action_rows = [
            {"last_action": act, "cnt": cnt}
            for act, cnt in sorted(action_counts.items(), key=lambda kv: -kv[1])
        ]

        items_for_genres = [
            rec
            for rec in items_data.values()
            if _matches(
                rec,
                type_filter=selected or None,
                action_filter=selected_action or None,
                genre_filter=None,
            )
        ]
        genre_total_cnt = len(items_for_genres)

        genre_counts: DefaultDict[str, int] = defaultdict(int)
        for rec in items_for_genres:
            for g in rec["genres"]:
                genre_counts[g] += 1
        genre_rows = [
            {"key": g, "label": genre_labels.get(g, g), "cnt": cnt}
            for g, cnt in sorted(genre_counts.items(), key=lambda kv: -kv[1])
        ]

        genre_item_ids: set[int] | None = None
        if selected_genre:
            genre_item_ids = {
                rec["id"]
                for rec in items_data.values()
                if selected_genre in rec["genres"]
            }
        more_filters = bool(action_rows or genre_rows)

        def items_for_verb(
            verb: str,
            *,
            item_type: str | None,
            last_action: str | None,
            genre_ids: set[int] | None,
            page: int,
            per: int,
            db,
        ):
            if genre_ids is not None and not genre_ids:
                return [], 0

            params = [verb, *canonical_actions, verb]
            type_filter_sql = ""
            if item_type:
                type_filter_sql = " AND i.item_type = ?"
                params.append(item_type)

            genre_filter_sql = ""
            if genre_ids:
                placeholders = ",".join("?" * len(genre_ids))
                genre_filter_sql = f" AND i.id IN ({placeholders})"
                params.extend(sorted(genre_ids))

            base_sql = f"""
                WITH item_rows AS (
                    SELECT i.id, i.title, i.item_type, i.slug,
                        MIN(CASE WHEN im.k='date' AND LENGTH(im.v)>=4
                                    THEN SUBSTR(im.v,1,4) END)         AS year,
                        COUNT(DISTINCT e.id)                           AS cnt,
                        MAX(e.created_at)                              AS last_at,
                        LOWER((SELECT ei2.action
                            FROM entry_item ei2
                            JOIN entry      e2 ON e2.id = ei2.entry_id
                            WHERE ei2.item_id = i.id
                            AND ei2.verb    = ?{sub_latest_filter}
                            ORDER BY e2.created_at DESC
                            LIMIT 1))                                   AS last_action
                    FROM item        i
                    LEFT JOIN item_meta  im ON im.item_id = i.id
                    JOIN  entry_item  ei ON ei.item_id  = i.id
                    JOIN  entry       e  ON e.id        = ei.entry_id
                    WHERE ei.verb = ?{type_filter_sql}{genre_filter_sql}
                    GROUP BY i.id
                )
                SELECT * FROM item_rows
            """
            if last_action:
                base_sql += " WHERE last_action = ?"
                params.append(last_action)

            base_sql += " ORDER BY last_at DESC"
            return paginate(base_sql, tuple(params), page=page, per_page=per, db=db)

        rows, total_pages = items_for_verb(
            kind,
            item_type=selected or None,
            last_action=selected_action or None,
            genre_ids=genre_item_ids,
            page=page,
            per=ps,
            db=db,
        )
        pages = list(range(1, total_pages + 1))
        return render_template_string(
            TEMPL_ITEM_LIST,
            rows=rows,
            pages=pages,
            page=page,
            verb=kind,
            types=type_rows,
            selected=selected,
            actions=action_rows,
            selected_action=selected_action,
            genres=genre_rows,
            selected_genre=selected_genre,
            genre_total_cnt=genre_total_cnt,
            more_filters=more_filters,
            type_total_cnt=type_total_cnt,
            filtered_total_cnt=filtered_total_cnt,
            username=current_username(),
            title=get_setting("site_name", "po.etr.ist"),
        )

    project_filters_list = []
    selected_project = request.args.get("project", "").strip().lower()
    total_posts = None
    project_join = ""
    project_where = ""
    params: list[str] = [kind]

    if kind == "post":
        project_filters_list = project_filters(db=db)
        valid_slugs = {p["slug"] for p in project_filters_list}
        if selected_project and selected_project not in valid_slugs:
            selected_project = ""
        total_posts = db.execute(
            "SELECT COUNT(*) AS c FROM entry WHERE kind='post'"
        ).fetchone()["c"]
        if selected_project:
            project_join = (
                " JOIN project_entry pe ON pe.entry_id = e.id"
                " JOIN project p ON p.id = pe.project_id"
            )
            project_where = " AND p.slug=?"
            params.append(selected_project)

    BASE_SQL = f"""
        SELECT e.*, ei.action
          FROM entry e
          LEFT JOIN entry_item ei ON ei.entry_id = e.id
          {project_join}
         WHERE e.kind = ?{project_where}
         ORDER BY e.created_at DESC
    """

    entries, total_pages = paginate(
        BASE_SQL, tuple(params), page=page, per_page=ps, db=db
    )
    pages = list(range(1, total_pages + 1))

    back_map = backlinks(entries, db=db)
    return render_template_string(
        TEMPL_LIST,
        rows=entries,
        pages=pages,
        page=page,
        heading=(kind or "").capitalize() + "s",
        kind=kind,
        username=current_username(),
        title=get_setting("site_name", "po.etr.ist"),
        form_title=form_title,
        form_link=form_link,
        form_body=form_body,
        backlinks=back_map,
        project_filters=project_filters_list,
        selected_project=selected_project,
        total_posts=total_posts,
    )


TEMPL_LIST = wrap("""
    {% block body %}
        {% if session.get('logged_in') %}
        <hr style="margin:10px 0">
        <form method="post" 
                  style="display:flex;flex-direction:column;gap:10px;align-items:flex-start;">
            {% if csrf_token() %}
            <input type="hidden" name="csrf" value="{{ csrf_token() }}">
            {% endif %}
            {# Title field for Posts & Pins #}
            {% if kind in ('post', 'pin') %}
                <input name="title" style="width:100%;margin:0" placeholder="Title" value="{{ form_title or '' }}">
            {% endif %}
            {# Link field only for Pins #}
            {% if kind == 'pin' %}
                <input name="link" style="width:100%;margin:0" placeholder="Link" value="{{ form_link or '' }}">
            {% endif %}
            <textarea name="body" rows="3" style="width:100%;margin:0" placeholder="What's on your mind?">{{ form_body or '' }}</textarea>
            
            <div style="display:flex;gap:.75rem;justify-content:space-between;width:100%;">
                <button style="width:">Add&nbsp;{{ kind.capitalize() }}</button>      
                {% if kind=='post' %}
                <button name="is_page" value="1"
                        style="background:#444;color:#ffffff;border:1px solid #888;">
                    Add Page
                </button>
                {% endif %}  
            </div>
        </form>
        {% endif %}
        <hr>
        {% if kind == 'post' %}
            {% if project_filters %}
            <div style="display:flex; flex-wrap:wrap; gap:.25rem .5rem; margin-bottom:.75rem;">
                <a href="{{ url_for('by_kind', slug=kind_to_slug('post')) }}"
                   style="text-decoration:none !important;
                          border-bottom:none!important;
                          display:inline-flex;
                          margin:.15rem 0;
                          padding:.15rem .6rem;
                          border-radius:1rem;
                          white-space:nowrap;
                          font-size:.8em;
                          {% if not selected_project %}
                              background:{{ theme_color() }}; color:#000;
                          {% else %}
                              background:#444;   color:{{ theme_color() }};
                          {% endif %}">
                    All
                    <sup style="font-size:.5em;">{{ total_posts }}</sup>
                </a>
                {% for pr in project_filters %}
                <a href="{{ url_for('by_kind', slug=kind_to_slug('post'), project=pr['slug']) }}"
                   style="text-decoration:none !important;
                          border-bottom:none!important;
                          display:inline-flex;
                          margin:.15rem 0;
                          padding:.15rem .6rem;
                          border-radius:1rem;
                          white-space:nowrap;
                          font-size:.8em;
                          {% if selected_project == pr['slug'] %}
                              background:{{ theme_color() }}; color:#000;
                          {% else %}
                              background:#444;   color:{{ theme_color() }};
                          {% endif %}">
                    {{ pr['title'] }}
                    <sup style="font-size:.5em;">{{ pr['cnt'] }}</sup>
                </a>
                {% endfor %}
            </div>
            {% endif %}
            <ul style="list-style:none; padding:0; margin:0;">
            {% for e in rows %}
                <li class="h-entry" style="margin:1em 0;">
                    <a class="p-name u-url u-uid"
                       href="{{ url_for('entry_detail', kind_slug=kind_to_slug(e['kind']), entry_slug=e['slug']) }}"
                       style="display:inline-block;
                              font-weight:normal;
                              line-height:1.25;">
                        {{ e['title'] or e['slug'] }}
                    </a>
                    <div style="display:flex;
                                flex-wrap:wrap;
                                align-items:center;
                                margin-top:.25rem;
                                gap:.35rem;
                                font-size:1rem;
                                color:#888;">
                        <span style="white-space:nowrap;font-size:1rem;">
                            {{ e['created_at']|ts }}
                        </span>
                        {% set projects = entry_projects(e.id) %}
                        {% if projects %}
                            <span aria-hidden="true">•</span>
                            {% for pr in projects %}
                                <a href="{{ url_for('project_detail', project_slug=pr['slug']) }}"
                                   style="text-decoration:none; color:{{ theme_color() }}; border-bottom:0.1px dotted currentColor;">
                                    {{ pr['title'] }}
                                </a>{% if not loop.last %}<span aria-hidden="true"> / </span>{% endif %}
                            {% endfor %}
                        {% endif %}
                        {% if session.get('logged_in') %}
                            <span aria-hidden="true">•</span>
                            <a href="{{ url_for('edit_entry', kind_slug=kind_to_slug(e['kind']), entry_slug=e['slug']) }}"
                               style="text-decoration:none;">Edit</a>
                            <a href="{{ url_for('delete_entry', kind_slug=kind_to_slug(e['kind']), entry_slug=e['slug']) }}"
                               style="text-decoration:none;">Delete</a>
                        {% endif %}
                    </div>
                </li>
            {% else %}
                <p>No {{ heading.lower() }} yet.</p>
            {% endfor %}
            </ul>
        {% else %}
            {% for e in rows %}
            <article class="h-entry" style="{% if not loop.last %}padding-bottom:1.5em; border-bottom:1px solid #444;{% endif %}">
                {% if e['kind'] == 'pin' %}
                    <h2>
                        <a class="u-bookmark-of p-name" href="{{ e['link'] }}" target="_blank" rel="noopener">
                            {{ e['title'] }}
                        </a>
                        {{ external_icon() }} 
                    </h2>            
                {% elif e['title'] %}
                    <h2 class="p-name">{{ e['title'] }}</h2>
                {% endif %}
                <div class="e-content" style="margin-top:1.5em;">{{ e['body']|md(e['slug']) }}</div>
                {{ backlinks_panel(backlinks[e.id]) }}
                {% if e['link'] and e['kind'] != 'pin' %}
                    <p>🔗 <a href="{{ e['link'] }}" target="_blank" rel="noopener">{{ e['link'] }}</a></p>
                {% endif %}
                <small style="color:#aaa;">
                    <span style="
                        display:inline-block;
                        padding:.1em .6em;
                        margin-right:.4em;
                        background:#444;
                        color:#fff;
                        border-radius:1em;
                        font-size:.75em;
                        text-transform:capitalize;
                        vertical-align:middle;
                    ">
                        <a href="{{ url_for('by_kind', slug=kind_to_slug(e['kind'])) }}"
                            style="text-decoration:none; color:inherit;border-bottom:none;">
                            {{ e['action'] or e['kind'] }}
                        </a>
                    </span>
                    <a class="u-url u-uid" href="{{ url_for('entry_detail', kind_slug=kind_to_slug(e['kind']), entry_slug=e['slug']) }}"
                        style="text-decoration:none; color:inherit;vertical-align:middle;font-variant-numeric:tabular-nums;white-space:nowrap;">
                        <time class="dt-published" datetime="{{ e['created_at'] }}">{{ e['created_at']|ts }}</time>
                    </a>&nbsp;
                    {% if session.get('logged_in') %}
                        <a href="{{ url_for('edit_entry', kind_slug=kind_to_slug(e['kind']), entry_slug=e['slug']) }}" style="vertical-align:middle;">Edit</a>&nbsp;&nbsp;
                        <a href="{{ url_for('delete_entry', kind_slug=kind_to_slug(e['kind']), entry_slug=e['slug']) }}" style="vertical-align:middle;">Delete</a>
                    {% endif %}
                    {% set tags = entry_tags(e.id) %}
                    {% if tags %}
                        &nbsp;·&nbsp;
                        {% for tag in tags %}
                            <a class="p-category" rel="tag" href="{{ tags_href(tag) }}"
                               style="text-decoration:none;margin-right:.35em;color:{{ theme_color() }};vertical-align:middle;">
                                #{{ tag }}
                            </a>
                        {% endfor %}
                    {% endif %}
                </small>
            </article>
            {% else %}
                <p>No {{ heading.lower() }} yet.</p>
            {% endfor %}
        {% endif %}

        {% if pages|length > 1 %}
            <nav style="margin-top:2em;padding-top:2em;font-size:.75em;border-top:1px solid #444;">
                {% for p in pages %}
                    {% if p == page %}
                        <span style="border-bottom:0.33rem solid #aaa;">{{ p }}</span>
                    {% else %}
                        <a href="{% if kind == 'post' %}{{ url_for('by_kind', slug=kind_to_slug('post'), project=selected_project or None, page=p) }}{% else %}{{ request.path }}?page={{ p }}{% endif %}">{{ p }}</a>
                    {% endif %}
                    {# add thin spacing between numbers #}
                    {% if not loop.last %}&nbsp;{% endif %}
                {% endfor %}
            </nav>
        {% endif %}
    {% endblock %}
""")


TEMPL_PAGE = wrap("""
{% block body %}
<hr>
<article class="h-entry">
  <span class="p-name" style="position:absolute;left:-9999px;">{{ e['title'] or e['slug'] }}</span>
  <a class="u-url u-uid" href="{{ '/' ~ e['slug'] }}" style="display:none;">{{ '/' ~ e['slug'] }}</a>
  <time class="dt-published" datetime="{{ e['created_at'] }}" style="display:none;">{{ e['created_at'] }}</time>
  <div class="e-content" style="margin-top:1.5em;">{{ e['body']|md(e['slug']) }}</div>
  {% if session.get('logged_in') %}
      <small>
        <a href="{{ url_for('edit_entry',
                            kind_slug=kind_to_slug(e['kind']),
                            entry_slug=e['slug']) }}">Edit</a>
        <a href="{{ url_for('delete_entry',
                            kind_slug=kind_to_slug(e['kind']),
                            entry_slug=e['slug']) }}">Delete</a>
      </small>
  {% endif %}
</article>
{% endblock %}
""")


TEMPL_ITEM_LIST = wrap("""
{% block body %}
<hr>

<style>
.filter-grid details.more-toggle + .more-panel { display: none; }
.filter-grid details.more-toggle[open] + .more-panel { display: flex; flex-direction:column; gap:.35rem; }
</style>

<div class="filter-grid" style="display:grid; grid-template-columns:1fr auto; grid-template-rows:auto auto; column-gap:.75rem; row-gap:.35rem; align-items:start;">
    <div style="display:flex; flex-wrap:wrap; gap:.25rem .5rem;">
        <a href="{{ url_for('by_kind',
                            slug=kind_to_slug(verb),
                            action=selected_action or None,
                            genre=selected_genre or None) }}"
           style="text-decoration:none !important;
                  border-bottom:none!important;
                  display:inline-flex;
                  margin:.15rem 0;
                  padding:.15rem .6rem;
                  border-radius:1rem;
                  white-space:nowrap;
                  font-size:.8em;
                  {% if not selected %}
                      background:{{ theme_color() }}; color:#000;
                  {% else %}
                      background:#444;   color:{{ theme_color() }};
                  {% endif %}">
            All
            <sup style="font-size:.5em;">{{ type_total_cnt }}</sup>
        </a>

        {% for t in types %}
        <a href="{{ url_for('by_kind',
                            slug=kind_to_slug(verb),
                            type=t.item_type,
                            action=selected_action or None,
                            genre=selected_genre or None) }}"
           style="text-decoration:none !important;
                  border-bottom:none!important;
                  display:inline-flex;
                  margin:.15rem 0;
                  padding:.15rem .6rem;
                  border-radius:1rem;
                  white-space:nowrap;
                  font-size:.8em;
                  {% if selected == t.item_type %}
                      background:{{ theme_color() }}; color:#000;
                  {% else %}
                      background:#444;   color:{{ theme_color() }};
                  {% endif %}">
            {{ t.item_type | smartcap }}
            <sup style="font-size:.5em;">{{ t.cnt }}</sup>
        </a>
        {% endfor %}
    </div>

    {% if more_filters %}
    <details class="more-toggle"
             style="justify-self:end;"
             {% if selected_action or selected_genre %}open{% endif %}>
        <summary style="list-style:none;
                        display:inline-flex;
                        align-items:center;
                        gap:.25rem;
                        margin:0;
                        padding:.15rem .6rem;
                        border-radius:1rem;
                        border:1px solid #555;
                        background:#333;
                        color:{{ theme_color() }};
                        font-size:.8em;
                        cursor:pointer;">
            More
            <span aria-hidden="true" style="font-size:.75em;">▾</span>
        </summary>
    </details>

    <div class="more-panel" style="grid-column:1 / span 2;">
        {% if actions %}
        <div style="display:flex; flex-wrap:wrap; gap:.25rem .5rem;">
            <a href="{{ url_for('by_kind',
                                slug=kind_to_slug(verb),
                                type=selected or None,
                                genre=selected_genre or None) }}"
               style="text-decoration:none !important;
                      border-bottom:none!important;
                      display:inline-flex;
                      margin:.15rem 0;
                      padding:.15rem .6rem;
                      border-radius:1rem;
                      white-space:nowrap;
                      font-size:.8em;
                      {% if not selected_action %}
                          background:{{ theme_color() }}; color:#000;
                      {% else %}
                          background:#444;   color:{{ theme_color() }};
                      {% endif %}">
                All
                <sup style="font-size:.5em;">{{ filtered_total_cnt }}</sup>
            </a>

            {% for a in actions %}
            <a href="{{ url_for('by_kind',
                                slug=kind_to_slug(verb),
                                type=selected or None,
                                action=a.last_action,
                                genre=selected_genre or None) }}"
               style="text-decoration:none !important;
                      border-bottom:none!important;
                      display:inline-flex;
                      margin:.15rem 0;
                      padding:.15rem .6rem;
                      border-radius:1rem;
                      white-space:nowrap;
                      font-size:.8em;
                      {% if selected_action == a.last_action %}
                          background:{{ theme_color() }}; color:#000;
                      {% else %}
                          background:#444;   color:{{ theme_color() }};
                      {% endif %}">
                {{ a.last_action | smartcap }}
                <sup style="font-size:.5em;">{{ a.cnt }}</sup>
            </a>
            {% endfor %}
        </div>
        {% endif %}

        {% if genres %}
        <div style="display:flex; flex-wrap:wrap; gap:.25rem .5rem;">
            <a href="{{ url_for('by_kind',
                                slug=kind_to_slug(verb),
                                type=selected or None,
                                action=selected_action or None) }}"
               style="text-decoration:none !important;
                      border-bottom:none!important;
                      display:inline-flex;
                      margin:.15rem 0;
                      padding:.15rem .6rem;
                      border-radius:1rem;
                      white-space:nowrap;
                      font-size:.8em;
                      {% if not selected_genre %}
                          background:{{ theme_color() }}; color:#000;
                      {% else %}
                          background:#444;   color:{{ theme_color() }};
                      {% endif %}">
                All
                <sup style="font-size:.5em;">{{ genre_total_cnt }}</sup>
            </a>

            {% for g in genres %}
            <a href="{{ url_for('by_kind',
                                slug=kind_to_slug(verb),
                                type=selected or None,
                                action=selected_action or None,
                                genre=g.key) }}"
               style="text-decoration:none !important;
                      border-bottom:none!important;
                      display:inline-flex;
                      margin:.15rem 0;
                      padding:.15rem .6rem;
                      border-radius:1rem;
                      white-space:nowrap;
                      font-size:.8em;
                      {% if selected_genre == g.key %}
                          background:{{ theme_color() }}; color:#000;
                      {% else %}
                          background:#444;   color:{{ theme_color() }};
                      {% endif %}">
                {{ g.label | smartcap }}
                <sup style="font-size:.5em;">{{ g.cnt }}</sup>
            </a>
            {% endfor %}
        </div>
        {% endif %}
    </div>
    {% endif %}
</div>

<!-- —— Item list ——————————————————————————————— -->
{% if rows %}
  <hr>
  <ul style="list-style:none; padding:0; margin:0;">
  {% for r in rows %}
    <li style="margin:1em 0;">

      {# ─────────── ROW 1 – title ─────────── #}
      <a href="{{ url_for('item_detail',
                          verb=kind_to_slug(verb),
                          item_type=r.item_type,
                          slug=r.slug) }}"
         style="display:inline-block;               
                font-weight:normal;
                line-height:1.25;">
        {{ r.title }}{% if r.year %} ({{ r.year }}){% endif %}
      </a>

      {# ─────────── ROW 2 – meta ─────────── #}
      <div style="display:flex;
                  flex-wrap:wrap;
                  align-items:center;
                  margin-top:.25rem;
                  gap:.35rem;
                  font-size:1rem;
                  color:#888;">

        {% if r.last_action %}
        <span style="display:inline-block;padding:.1em .6em;background:#444;color:#fff;border-radius:1em;text-transform:capitalize;">
        {{ r.last_action | smartcap }}
        </span>
        {% endif %}
        <span style="display:inline-block;padding:.1em .6em;background:#444;color:#fff;border-radius:1em;text-transform:capitalize;">
        {{ r.item_type | smartcap }}
        </span>
        <span style="white-space:nowrap;font-size:1rem;">
           • {{ r.cnt }}× • {{ r.last_at|ts }}
        </span>
      </div>
    </li>
  {% endfor %}
  </ul>

  {% if pages|length > 1 %}
    <nav style="margin-top:2em;padding-top:2em;font-size:.75em;border-top:1px solid #444;">
      {% for p in pages %}
        {% if p == page %}
          <span style="border-bottom:.33rem solid #aaa;">{{ p }}</span>
        {% else %}
          <a href="{{ url_for('by_kind',
                               slug=kind_to_slug(verb),
                               type=selected or None,
                               action=selected_action or None,
                               genre=selected_genre or None,
                               page=p) }}">{{ p }}</a>
        {% endif %}
        {% if not loop.last %}&nbsp;{% endif %}
      {% endfor %}
    </nav>
  {% endif %}
{% else %}
  <p>No items{% if selected %} for this type{% endif %} yet.</p>
{% endif %}
{% endblock %}
""")


TEMPL_PROJECT_PAGE = wrap("""
{% block body %}
<hr>
<div style="display:flex;align-items:center;justify-content:space-between;gap:1rem;flex-wrap:wrap;">
    <h2 style="margin:0;">{{ project['title'] or project['slug'] }}</h2>
    <div style="display:flex; gap:.5rem; font-size:.9em;">
        <a href="{{ url_for('project_detail', project_slug=project['slug'], sort='old') }}"
           style="text-decoration:none; padding:.15rem .6rem; border-radius:1rem; border:1px solid #555;
                  {% if sort != 'new' %}background:{{ theme_color() }};color:#000;{% else %}color:#fff;{% endif %}">
           Oldest
        </a>
        <a href="{{ url_for('project_detail', project_slug=project['slug'], sort='new') }}"
           style="text-decoration:none; padding:.15rem .6rem; border-radius:1rem; border:1px solid #555;
                  {% if sort == 'new' %}background:{{ theme_color() }};color:#000;{% else %}color:#fff;{% endif %}">
           Newest
        </a>
    </div>
</div>

<ul style="list-style:none; padding:0; margin:1rem 0 0;">
{% for e in rows %}
  <li class="h-entry" style="margin:1em 0;">
    <a class="p-name u-url u-uid"
       href="{{ url_for('entry_detail', kind_slug=kind_to_slug(e['kind']), entry_slug=e['slug']) }}"
       style="display:inline-block; font-weight:normal; line-height:1.25;">
        {{ e['title'] or e['slug'] }}
    </a>
    <div style="display:flex;
                flex-wrap:wrap;
                align-items:center;
                margin-top:.25rem;
                gap:.35rem;
                font-size:1rem;
                color:#888;">
        <span style="white-space:nowrap;font-size:1rem;">
            {{ e['created_at']|ts }}
        </span>
        {% set projects = entry_projects(e.id) %}
        {% if projects %}
            <span aria-hidden="true">•</span>
            {% for pr in projects %}
                <a href="{{ url_for('project_detail', project_slug=pr['slug']) }}"
                   style="text-decoration:none;color:{{ theme_color() }};border-bottom:0.1px dotted currentColor;">
                    {{ pr['title'] }}
                </a>{% if not loop.last %}<span aria-hidden="true"> / </span>{% endif %}
            {% endfor %}
        {% endif %}
    </div>
  </li>
{% else %}
  <p>No posts in this project yet.</p>
{% endfor %}
</ul>

{% if pages|length > 1 %}
    <nav style="margin-top:2em;padding-top:2em;font-size:.75em;border-top:1px solid #444;">
      {% for p in pages %}
        {% if p == page %}
          <span style="border-bottom:.33rem solid #aaa;">{{ p }}</span>
        {% else %}
          <a href="{{ url_for('project_detail', project_slug=project['slug'], sort=sort, page=p) }}">{{ p }}</a>
        {% endif %}
        {% if not loop.last %}&nbsp;{% endif %}
      {% endfor %}
    </nav>
{% endif %}
{% endblock %}
""")


@app.route("/projects/<project_slug>")
def project_detail(project_slug):
    db = get_db()
    proj = db.execute("SELECT * FROM project WHERE slug=?", (project_slug,)).fetchone()
    if not proj:
        abort(404)

    sort = request.args.get("sort", "old").lower()
    order = "DESC" if sort == "new" else "ASC"
    page = max(int(request.args.get("page", 1)), 1)
    ps = page_size()

    base_sql = f"""
        SELECT e.*
          FROM project_entry pe
          JOIN entry e ON e.id = pe.entry_id
         WHERE pe.project_id=? AND e.kind='post'
         ORDER BY e.created_at {order}
    """
    rows, total_pages = paginate(base_sql, (proj["id"],), page=page, per_page=ps, db=db)
    pages = list(range(1, total_pages + 1))

    return render_template_string(
        TEMPL_PROJECT_PAGE,
        project=proj,
        rows=rows,
        page=page,
        pages=pages,
        sort="new" if sort == "new" else "old",
        title=get_setting("site_name", "po.etr.ist"),
    )


###############################################################################
# Entries (Say, Post, Pin)
###############################################################################
@app.route("/<kind_slug>/<entry_slug>")
def entry_detail(kind_slug, entry_slug):
    if kind_slug == tags_slug():
        return tags(entry_slug)
    kind = slug_to_kind(kind_slug)
    if kind == "page":
        abort(404)

    db = get_db()

    # grab one action (the first, if there are several entry_item rows)
    row = db.execute(
        """
        SELECT  e.*,
                MIN(ei.action)                 AS action,
                MIN(ei.progress)               AS progress,
                MIN(i.title)                   AS item_title,
                MIN(i.slug)                    AS item_slug,
                MIN(i.item_type)               AS item_type,
                MIN(CASE                     
                    WHEN im.k = 'date'
                        AND LENGTH(im.v) >= 4
                    THEN SUBSTR(im.v,1,4)
                END)                           AS item_year
            FROM entry           e
            LEFT JOIN entry_item ei ON ei.entry_id = e.id
            LEFT JOIN item       i  ON i.id        = ei.item_id
            LEFT JOIN item_meta  im ON im.item_id  = i.id
        WHERE e.kind = ? AND e.slug = ?
        GROUP BY e.id
        LIMIT 1
    """,
        (kind, entry_slug),
    ).fetchone()

    if kind not in (*KINDS, *VERB_KINDS) or row is None:
        abort(404)

    backs = backlinks(row, db=db)[row["id"]]
    return render_template_string(
        TEMPL_ENTRY_DETAIL,
        e=row,
        backlinks=backs,
        title=get_setting("site_name", "po.etr.ist"),
        username=current_username(),
        kind=row["kind"],
    )


TEMPL_ENTRY_DETAIL = wrap("""
    {% block body %}
        <hr>
        <article class="h-entry">
            {% if e['kind']=='pin' %}
                <h2 style="margin-top:0">
                    <a class="u-bookmark-of p-name" href="{{ e['link'] }}" target="_blank" rel="noopener" title="{{ e['link'] }}"
                    style="word-break:break-all; overflow-wrap:anywhere;">
                    {{ e['title'] }} 
                    </a>
                    {{ external_icon() }}
                </h2>
            {% elif e['title'] %}
                <h2 class="p-name">{{ e['title'] }}</h2>
            {% endif %}

            <div class="e-content" style="margin-top:1.5em;">{{ e['body']|md(e['slug']) }}</div>    
            {{ backlinks_panel(backlinks) }}
                                     
            <small style="color:#aaa;">

            {# —— item info (if any) ———————————————————————— #}
            {% if e.item_title %}
                <span style="
                      display:inline-block;padding:.1em .6em;margin-right:.4em;
                      background:#444;color:#fff;border-radius:1em;font-size:.75em;
                      text-transform:capitalize;vertical-align:middle;">
                    {{ e.action|smartcap }}
                </span>
                {% if e.item_type %}
                    <span style="
                          display:inline-block;padding:.1em .6em;margin-right:.4em;
                          background:#444;color:#fff;border-radius:1em;font-size:.75em;
                          vertical-align:middle;">
                        {{ e.item_type | smartcap }}
                    </span>
                {% endif %}           
                {% if e.progress %}
                    <span style="
                          display:inline-block;padding:.1em .6em;margin-right:.4em;
                          background:#444;color:#fff;border-radius:1em;font-size:.75em;
                          vertical-align:middle;">
                        {{ e.progress }}
                    </span>
                {% endif %}
                <a href="{{ url_for('item_detail',
                                    verb=kind_to_slug(e.kind),
                                    item_type=e.item_type,
                                    slug=e.item_slug) }}"
                   style="text-decoration:none;margin-right:.4em;
                          color:{{ theme_color() }};vertical-align:middle;">
                   {{ e.item_title }} {% if e.item_year %} ({{ e.item_year }}) {% endif %}
                </a><br>
            {% endif %}

            {# —— kind pill ———————————————————————————————— #}
            <span style="
                  display:inline-block;padding:.1em .6em;margin-right:.4em;
                  background:#444;color:#fff;border-radius:1em;font-size:.75em;
                  text-transform:capitalize;vertical-align:middle;">
                <a href="{{ url_for('by_kind', slug=kind_to_slug(e['kind'])) }}"
                   style="text-decoration:none;color:inherit;border-bottom:none;">
                   {{ e.kind }}
                </a>
            </span>

            {# —— timestamp & author ———————————————————————— #}
            <a class="u-url u-uid" href="{{ url_for('entry_detail',
                                 kind_slug=kind_to_slug(e['kind']),
                                 entry_slug=e['slug']) }}"
               style="text-decoration:none; color:inherit;vertical-align:middle;font-variant-numeric:tabular-nums;white-space:nowrap;">
               <time class="dt-published" datetime="{{ e['created_at'] }}">{{ e['created_at']|ts }}</time>
            </a>
            <span style="vertical-align:middle;">&nbsp;by&nbsp;{{ username }}</span>&nbsp;&nbsp;

            {# —— admin links ———————————————————————————————— #}
            {% if session.get('logged_in') %}
                <a href="{{ url_for('edit_entry',
                                    kind_slug=kind_to_slug(e['kind']),
                                    entry_slug=e['slug']) }}"
                   style="vertical-align:middle;">Edit</a>&nbsp;&nbsp;
                <a href="{{ url_for('delete_entry',
                                    kind_slug=kind_to_slug(e['kind']),
                                    entry_slug=e['slug']) }}"
                   style="vertical-align:middle;">Delete</a>
            {% endif %}
            {% set projects = entry_projects(e.id) %}
            {% if projects %}
                &nbsp;·&nbsp;
                {% for pr in projects %}
                    <a href="{{ url_for('project_detail', project_slug=pr['slug']) }}"
                       style="text-decoration:none;margin-right:.35em;color:{{ theme_color() }};vertical-align:middle;">
                        {{ pr['title'] }}
                    </a>{% if not loop.last %}<span aria-hidden="true"> / </span>{% endif %}
                {% endfor %}
            {% endif %}
            </small>
        </article>
    {% endblock %}
""")


@app.route("/<kind_slug>/<entry_slug>/edit", methods=["GET", "POST"])
def edit_entry(kind_slug, entry_slug):
    login_required()
    kind = slug_to_kind(kind_slug)
    db = get_db()

    row = db.execute(
        "SELECT * FROM entry WHERE kind=? AND slug=?", (kind, entry_slug)
    ).fetchone()
    if not row:
        abort(404)

    if request.method == "POST":
        title = request.form.get("title", "").strip() or None
        raw_body = request.form["body"]
        body_trimmed = raw_body.strip()
        link = request.form.get("link", "").strip() or None
        new_slug = request.form.get("slug", "").strip() or row["slug"]

        body_for_parse, project_specs = parse_projects(body_trimmed)

        # ── single pass ───────────────────────────────────────────────
        body_parsed, blocks, errors = parse_trigger(body_for_parse)  # ← only call once

        if errors:
            flash("Errors in caret blocks found. Entry was not saved.")
            for err in errors:
                flash(err)
            filled = dict(row)
            filled.update(
                {
                    "title": request.form.get("title", ""),
                    "body": raw_body,
                    "link": request.form.get("link", ""),
                    "slug": new_slug,
                }
            )
            return render_template_string(
                TEMPL_EDIT_ENTRY, e=filled, title=get_setting("site_name", "po.etr.ist")
            )

        # decide the final kind
        is_page_flag = request.form.get("is_page")  # None, '1' or '0'

        if is_page_flag == "1" or (is_page_flag is None and row["kind"] == "page"):
            # keep / promote to page
            new_kind = "page"
        elif is_page_flag == "0" and row["kind"] == "page":
            # explicit demotion → become a post (or whatever is inferred)
            new_kind = blocks[0]["verb"] if blocks else infer_kind(title, link)
        else:
            # normal post / pin / say workflow
            new_kind = blocks[0]["verb"] if blocks else infer_kind(title, link)

        if not body_parsed:
            flash("Body is required.")
            filled = dict(row)
            filled.update(
                {
                    "title": request.form.get("title", ""),
                    "body": raw_body,
                    "link": request.form.get("link", ""),
                    "slug": new_slug,
                    "kind": new_kind,
                }
            )
            return render_template_string(
                TEMPL_EDIT_ENTRY, e=filled, title=get_setting("site_name", "po.etr.ist")
            )

        # 2️⃣  Synchronise entry_item & item_meta
        db.execute("DELETE FROM entry_item WHERE entry_id=?", (row["id"],))
        for idx, blk in enumerate(blocks):
            item_id, slug_i, uuid_i = get_or_create_item(
                item_type=blk["item_type"],
                title=blk["title"],
                meta=blk["meta"],
                slug=blk["slug"],
                db=db,
                update_meta=False,
            )
            db.execute(
                """INSERT OR REPLACE INTO entry_item
                            (entry_id, item_id, verb, action, progress)
                          VALUES (?,?,?,?,?)""",
                (row["id"], item_id, blk["verb"], blk["action"], blk["progress"]),
            )

            body_parsed = body_parsed.replace(
                f"^{blk['item_type']}:$PENDING${idx}$", _verbose_block(blk, uuid_i)
            )

        # 3️⃣  Store the (possibly rewritten) entry itself
        db.execute(
            """UPDATE entry
                         SET title=?, body=?, link=?, slug=?, kind=?, updated_at=?
                       WHERE id=?""",
            (
                title,
                body_parsed,
                link,
                new_slug,
                new_kind,
                utc_now().isoformat(timespec="seconds"),
                row["id"],
            ),
        )

        # 4️⃣  Tags
        sync_tags(row["id"], extract_tags(body_parsed), db=db)
        if new_kind == "post":
            sync_projects(row["id"], project_specs, db=db)
        else:
            sync_projects(row["id"], [], db=db)
        db.commit()

        if new_kind == "page":
            return redirect(url_for("by_kind", slug=new_slug))

        return redirect(
            url_for(
                "entry_detail", kind_slug=kind_to_slug(new_kind), entry_slug=new_slug
            )
        )

    return render_template_string(
        TEMPL_EDIT_ENTRY,
        e=(
            (
                lambda r: {
                    **r,
                    "body": "\n".join(
                        filter(
                            None,
                            [
                                (r["body"] or "").rstrip("\n"),
                                *[
                                    f"~project:{pr['slug']}"
                                    + (f"|{pr['title']}" if pr["title"] else "")
                                    for pr in entry_projects(r["id"], db=db)
                                ],
                            ],
                        )
                    ).rstrip("\n")
                    if r["kind"] == "post"
                    else r["body"],
                }
            )(dict(row))
        ),
        title=get_setting("site_name", "po.etr.ist"),
    )


TEMPL_EDIT_ENTRY = wrap("""
{% block body %}
<hr>
<h2>Edit {{ e['kind']|smartcap }}</h2>
<form method="post">
    {% if csrf_token() %}
            <input type="hidden" name="csrf" value="{{ csrf_token() }}">
            {% endif %}
    {% if e['kind'] in ('post','pin', 'page') %}
        <div style="position:relative;">
            <input id="title"
                name="title"
                value="{{ e['title'] or '' }}"
                style="width:100%; padding-right:7rem;">
            <label for="title"
                style="position:absolute;
                right:.5rem;
                top:40%;
                transform:translateY(-50%);
                pointer-events:none;
                font-size:.75em;
                color:#aaa;">
                    Title
            </label>
        </div>
    {% endif %}

    {% if e['kind'] == 'pin' %}
    <div style="position:relative;">
        <input id="link"
                name="link"
                value="{{ e['link'] or '' }}"
                style="width:100%; padding-right:7rem;">
        <label for="link" 
                style="position:absolute; right:.5rem; top:40%;
                        transform:translateY(-50%);
                        pointer-events:none; font-size:.75em; color:#aaa;">
            Link
        </label>
    </div>
    {% endif %}

    <div style="position:relative;">
        <input name="slug" value="{{ e['slug'] }}"
            style="width:100%; padding-right:7rem;">
        <label for="slug"
                style="position:absolute;
                        right:.5rem;
                        top:40%;
                        transform:translateY(-50%);
                        pointer-events:none;
                        font-size:.75em;
                        color:#aaa;">
                    Slug
        </label>
    </div>

    <textarea name="body" rows="8" style="width:100%;">{{ e['body'] }}</textarea><br>
    <div style="display:flex;gap:.75rem;justify-content:space-between;width:100%;">
        <button>Save</button>

        {% if e['kind']=='page' %}
            <button name="is_page" value="0"
                    style="background:#444;color:#ffffff;border:1px solid #888;">
                Demote to Post
            </button>
        {% else %}
            {% if e['kind']=='post' %}
            <button name="is_page" value="1"
                    style="background:#444;color:#ffffff;border:1px solid #888;">
                Promote to Page
            </button>
            {% endif %}  
        {% endif %}
    </div>
</form>

{% if e['updated_at'] %}
  <small>Last edited {{ e['updated_at']|ts }}</small>
  <br>
  <small>First published {{ e['created_at']|ts }}</small>
{% else %}
  <small>Published {{ e['created_at']|ts }}</small>
{% endif %}
{% endblock %}
""")


@app.route("/<kind_slug>/<entry_slug>/delete", methods=["GET", "POST"])
def delete_entry(kind_slug, entry_slug):
    login_required()
    kind = slug_to_kind(kind_slug)
    db = get_db()

    row = db.execute(
        "SELECT * FROM entry WHERE kind=? AND slug=?", (kind, entry_slug)
    ).fetchone()
    if not row:
        abort(404)

    if request.method == "POST":
        db.execute("DELETE FROM entry WHERE id=?", (row["id"],))
        db.commit()
        db.execute(
            "DELETE FROM tag WHERE id NOT IN (SELECT DISTINCT tag_id FROM entry_tag)"
        )
        db.commit()
        return redirect(url_for("index"))

    return render_template_string(
        TEMPL_DELETE_ENTRY, e=row, title=get_setting("site_name", "po.etr.ist")
    )


TEMPL_DELETE_ENTRY = wrap("""
{% block body %}
    <hr>
    <h2>Delete entry?</h2>
    <article style="border-left:3px solid #c00; padding-left:1rem;">
        {% if e['title'] %}<h3>{{ e['title'] }}</h3>{% endif %}
        <div class="e-content" style="margin-top:1.5em;">{{ e['body']|md(e['slug']) }}</div>
        <small style="color:#aaa;">{{ e['created_at']|ts }}</small>
    </article>
    <form method="post" style="margin-top:1rem;">
        {% if csrf_token() %}
            <input type="hidden" name="csrf" value="{{ csrf_token() }}">
            {% endif %}
        <button style="background:#c00; color:#fff;">Yes – delete it</button>
        <a href="{{ url_for('index') }}" style="margin-left:1rem;">Cancel</a>
    </form>
    {% endblock %}
</div>
""")


###############################################################################
# Tags
###############################################################################
def _render_tags(tag_list: str):
    """
    Show a tag cloud.  Pills can be selected / deselected; the current
    selection is encoded in the path as  /<tags_slug>/foo+bar+baz
    """
    db = get_db()

    # ---------- tag statistics for the cloud --------------------------------
    cur = db.execute("""SELECT t.name, COUNT(et.entry_id) AS cnt
                         FROM tag t
                         LEFT JOIN entry_tag et ON t.id = et.tag_id
                         GROUP BY t.id
                         ORDER BY LOWER(t.name)""")
    rows = [dict(r) for r in cur]  # make mutable dicts

    # ---------- which is currently selected? ----------------------------------
    selected = {t.lower() for t in tag_list.split("+") if t}

    # ---------- scale counts → font-size (same as before) -------------------
    counts = [r["cnt"] for r in rows]
    lo, hi = (min(counts), max(counts)) if counts else (0, 0)
    span = max(1, hi - lo)
    for r in rows:
        weight = (r["cnt"] - lo) / span if counts else 0
        r["size"] = f"{0.75 + weight * 1.2:.2f}em"
        r["active"] = r["name"] in selected

        # ── URL that would result from clicking the pill ────────────────────
        new_sel = (selected - {r["name"]}) if r["active"] else (selected | {r["name"]})
        r["href"] = tags_href("+".join(sorted(new_sel))) if new_sel else tags_href()

    # ---------- fetch entries if something is selected ----------------------
    sort = request.args.get("sort", "new")
    page = max(int(request.args.get("page", 1)), 1)
    per = page_size()
    if selected:
        order_sql = "e.created_at DESC" if sort == "new" else "e.created_at ASC"
        q_marks = ",".join("?" * len(selected))
        base_sql = f"""
            SELECT  e.*,
                    ei.action,
                    ei.progress,
                    i.title      AS item_title,
                    i.slug       AS item_slug,
                    i.item_type  AS item_type,
                    MIN(CASE
                            WHEN im.k = 'date' AND LENGTH(im.v) >= 4
                            THEN SUBSTR(im.v, 1, 4)
                        END)     AS item_year
            FROM entry        e
            JOIN entry_tag    et ON et.entry_id = e.id
            JOIN tag          t  ON t.id       = et.tag_id
            LEFT JOIN entry_item ei ON ei.entry_id = e.id
            LEFT JOIN item       i  ON i.id        = ei.item_id
            LEFT JOIN item_meta  im ON im.item_id  = i.id
            WHERE t.name IN ({q_marks})
        GROUP BY e.id
            HAVING COUNT(DISTINCT t.name)=?
        ORDER BY {order_sql}
        """
        entries, total_pages = paginate(
            base_sql, (*selected, len(selected)), page=page, per_page=per, db=db
        )
        pages = list(range(1, total_pages + 1))
    else:
        entries, pages = None, []  # nothing selected → no list

    back_map = backlinks(entries, db=db)

    return render_template_string(
        TEMPL_TAGS,
        tags=rows,
        entries=entries,
        selected=selected,
        page=page,
        pages=pages,
        sort=sort,
        kind="tags",
        username=current_username(),
        title=get_setting("site_name", "po.etr.ist"),
        backlinks=back_map,
    )


@app.route("/tags", defaults={"tag_list": ""})
@app.route("/tags/<path:tag_list>")
def tags(tag_list: str):
    return _render_tags(tag_list)


@app.route("/<custom_tags_slug>/<path:tag_list>")
def tags_custom(custom_tags_slug: str, tag_list: str):
    if custom_tags_slug != tags_slug():
        abort(404)
    return _render_tags(tag_list)


TEMPL_TAGS = wrap("""
{% block body %}
<hr>
<!-- —— Tag-cloud as selectable pills ——————————————— -->
<div style="display:flex; flex-wrap:wrap; gap:.25rem .5rem;">
{% for t in tags %}
    <a class="p-category" rel="tag" href="{{ t.href }}"
        style="text-decoration:none !important;
                border-bottom:none!important;
                display:inline-flex;  
                margin:.15rem 0;
                padding:.15rem .6rem;
                border-radius:1rem;
                white-space:nowrap;
                font-size:.8em;
                {% if t.active %}
                    background:{{ theme_color() }}; color:#000;
                {% else %}
                    background:#444; color:{{ theme_color() }};
                {% endif %}">
        {{ t.name }}
        <sup style="font-size:.5em;">{{ t.cnt }}</sup>
    </a>
{% else %}
    <span>No tags yet.</span>
{% endfor %}
</div>

<!-- —— Entry list (only if sth. is selected) ————————— -->
{% if entries is not none %}
    <hr>
    {% if entries|length > 1 %}
    <div style="padding:1rem 0;
                font-size:.8em;color:#888;
                display:flex;align-items:center;
                justify-content:space-between;">
        <span style="display:inline-flex;
                border:1px solid #555;
                border-radius:4px;
                overflow:hidden;
                font-size:.8em;">
        {% for val,label in [('new','Newest'),('old','Oldest')] %}
            <a href="{{ tags_href('+'.join(selected), sort=val) }}"
               style="display:flex;align-items:center;padding:.35em 1em;
                      text-decoration:none;border-bottom:none;
                      {% if not loop.first %}border-left:1px solid #555;{% endif %}
                      {% if sort==val %}
                          background:{{ theme_color() }};color:#000;
                      {% else %}
                          background:#333;color:#eee;
                      {% endif %}">
                {{ label }}
            </a>
        {% endfor %}
        </span>
    </div>
    {% endif %}
    {% for e in entries %}
        <article class="h-entry" {% if not loop.last %}style="padding-bottom:1.5em;border-bottom:1px solid #444;"{% endif %}>
            {% if e['title'] %}
                <h3 style="margin:.25rem 0 .5rem 0;">{{ e['title'] }}</h3>
            {% endif %}
            <div class="e-content" style="margin-top:1.5em;">{{ e['body']|md(e['slug']) }}</div>
            {{ backlinks_panel(backlinks[e.id]) }}
            <small style="color:#aaa;">
                {# —— item info (if any) ———————————————————————— #}
                {% if e.item_title %}
                    <span style="
                        display:inline-block;padding:.1em .6em;margin-right:.4em;
                        background:#444;color:#fff;border-radius:1em;font-size:.75em;
                        text-transform:capitalize;vertical-align:middle;">
                        {{ e.action | smartcap }}
                    </span>
                    {% if e.item_type %}
                        <span style="
                            display:inline-block;padding:.1em .6em;margin-right:.4em;
                            background:#444;color:#fff;border-radius:1em;font-size:.75em;
                            vertical-align:middle;">
                            {{ e.item_type | smartcap }}
                        </span>
                    {% endif %}
                    {% if e.progress %}
                        <span style="
                            display:inline-block;padding:.1em .6em;margin-right:.4em;
                            background:#444;color:#fff;border-radius:1em;font-size:.75em;
                            vertical-align:middle;">
                            {{ e.progress }}
                        </span>
                    {% endif %}
                    <a href="{{ url_for('item_detail',
                                        verb=kind_to_slug(e.kind),
                                        item_type=e.item_type,
                                        slug=e.item_slug) }}"
                    style="text-decoration:none;margin-right:.4em;
                            color:{{ theme_color() }};vertical-align:middle;">
                    {{ e.item_title }}{% if e.item_year %} ({{ e.item_year }}){% endif %}
                    </a><br>
                {% endif %}

                <span style="
                    display:inline-block;
                    padding:.1em .6em;
                    margin-right:.4em;
                    background:#444;
                    color:#fff;
                    border-radius:1em;
                    font-size:.75em;
                    text-transform:capitalize;
                    vertical-align:middle;
                ">
                    {{ e['kind'] }}
                </span>
                <a class="u-url u-uid" href="{{ url_for('entry_detail', kind_slug=kind_to_slug(e['kind']), entry_slug=e['slug']) }}"
                    style="text-decoration:none; color:inherit;vertical-align:middle;">
                    <time class="dt-published" datetime="{{ e['created_at'] }}">{{ e['created_at']|ts }}</time>
                </a>&nbsp;
                {% if session.get('logged_in') %}
                    <a href="{{ url_for('edit_entry', kind_slug=kind_to_slug(e['kind']), entry_slug=e['slug']) }}" style="vertical-align:middle;">Edit</a>&nbsp;&nbsp;
                    <a href="{{ url_for('delete_entry', kind_slug=kind_to_slug(e['kind']), entry_slug=e['slug']) }}" style="vertical-align:middle;">Delete</a>
                {% endif %}
                {% set tags = entry_tags(e.id) %}
                {% if tags %}
                    &nbsp;·&nbsp;
                    {% for tag in tags %}
                        <a class="p-category" rel="tag" href="{{ tags_href(tag) }}"
                           style="text-decoration:none;margin-right:.35em;color:{{ theme_color() }};vertical-align:middle;">
                            #{{ tag }}
                        </a>
                    {% endfor %}
                {% endif %}
            </small>
        </article>
    {% else %}
        <p>No entries for this combination.</p>
    {% endfor %}
                  
    {% if pages|length > 1 %}
        <nav style="margin-top:2em;padding-top:2em;font-size:.75em;border-top:1px solid #444;">
            {% for p in pages %}
                {% if p == page %}
                    <span style="border-bottom:0.33rem solid #aaa;">{{ p }}</span>
                {% else %}
                    <a href="{{ tags_href('+'.join(selected), page=p) }}">{{ p }}</a>
                {% endif %}
                {% if not loop.last %}&nbsp;{% endif %}
            {% endfor %}
        </nav>
    {% endif %}
{% endif %}
{% endblock %}
""")


###############################################################################
# RSS feed
###############################################################################
def _rfc2822(dt_str: str) -> str:
    """ISO-8601 → RFC 2822 (Tue, 24 Jun 2025 09:22:20 +0200)."""
    try:
        return datetime.fromisoformat(dt_str).astimezone().strftime(RFC2822_FMT)
    except Exception:
        return dt_str


def _rss(entries, *, title, feed_url, site_url, feed_kind: str | None = None):
    """
    Build a valid RSS 2.0 document (single string).
    `entries` is an iterable of rows from the `entry` table.
    """
    items = []
    for e in entries:
        if e["kind"] == "page":
            continue

        link = url_for(
            "entry_detail",
            kind_slug=kind_to_slug(e["kind"]),
            entry_slug=e["slug"],
            _external=True,  # absolute URL
        )

        # choose the most recent timestamp we have
        ts_iso = e["updated_at"] or e["created_at"]
        ts_rfc = _rfc2822(ts_iso)
        guid = f"{link}#{ts_iso}"

        body_html = render_markdown_html(e["body"], source_slug=e["slug"])
        rss_title = e["title"] if e["title"] else e["slug"]
        if feed_kind:
            kind_slug = kind_to_slug(feed_kind)
            if not rss_title.lower().startswith(kind_slug.lower()):
                rss_title = f"{kind_slug}/{rss_title}"
        items.append(
            f"""
        <item>
          <title>{escape(rss_title)}</title>
          <link>{link}</link>
          <guid isPermaLink="false">{guid}</guid>
          <pubDate>{ts_rfc}</pubDate>
          <description><![CDATA[{body_html}]]></description>
        </item>"""
        )

    return f"""<?xml version="1.0" encoding="utf-8"?>
<rss version="2.0"
     xmlns:atom="http://www.w3.org/2005/Atom">
  <channel>
    <title>{escape(title)}</title>
    <link>{site_url}</link>
    <description>{escape(title)} – RSS</description>
    <generator>po.etr.ist</generator>
    <docs>https://validator.w3.org/feed/docs/rss2.html</docs>
    <lastBuildDate>{_rfc2822(datetime.now(timezone.utc).isoformat())}</lastBuildDate>
    <atom:link href="{feed_url}"
               rel="self"
               type="application/rss+xml" />

    {"".join(items)}
  </channel>
</rss>"""


# ------------------------------------------------------------------
#  ✨  RSS feeds
# ------------------------------------------------------------------
@app.route("/rss")
def global_rss():
    db = get_db()
    rows = db.execute(
        "SELECT * FROM entry ORDER BY created_at DESC LIMIT 50"
    ).fetchall()
    xml = _rss(
        rows,
        title=get_setting("site_name", "po.etr.ist"),
        feed_url=url_for("global_rss", _external=True),
        site_url=request.url_root.rstrip("/"),
        feed_kind=None,
    )
    return app.response_class(xml, mimetype="application/rss+xml")


@app.route("/<slug>/rss")
def kind_rss(slug):
    kind = slug_to_kind(slug)
    if kind == "page":  # pages don't have an RSS feed
        abort(404)
    db = get_db()
    rows = db.execute(
        "SELECT * FROM entry WHERE kind=? ORDER BY created_at DESC LIMIT 50", (kind,)
    ).fetchall()
    xml = _rss(
        rows,
        title=f"{(kind or '').capitalize()} – {get_setting('site_name', 'po.etr.ist')}",
        feed_url=request.url,  # already correct
        site_url=request.url_root.rstrip("/"),
        feed_kind=kind,
    )
    return app.response_class(xml, mimetype="application/rss+xml")


def _render_tags_rss(tag_list: str):
    tags = [t.lower() for t in re.split(r"[,+/]", tag_list) if t]
    if not tags:
        abort(404)

    q_marks = ",".join("?" * len(tags))
    sql = f"""SELECT e.* FROM entry e
              JOIN entry_tag et ON et.entry_id = e.id
              JOIN tag t        ON t.id        = et.tag_id
              WHERE t.name IN ({q_marks})
              GROUP BY e.id HAVING COUNT(DISTINCT t.name)=?
              ORDER BY e.created_at DESC LIMIT 50"""
    rows = get_db().execute(sql, (*tags, len(tags))).fetchall()

    pretty = " + ".join(tags)
    xml = _rss(
        rows,
        title=f"#{pretty} – {get_setting('site_name', 'po.etr.ist')}",
        feed_url=request.url,  # already correct
        site_url=request.url_root.rstrip("/"),
        feed_kind=None,
    )
    return app.response_class(xml, mimetype="application/rss+xml")


@app.route("/tags/<path:tag_list>/rss")
def tags_rss(tag_list):
    return _render_tags_rss(tag_list)


@app.route("/<custom_tags_slug>/<path:tag_list>/rss")
def tags_rss_custom(custom_tags_slug: str, tag_list: str):
    if custom_tags_slug != tags_slug():
        abort(404)
    return _render_tags_rss(tag_list)


###############################################################################
# Check-ins / Items
###############################################################################
@app.route("/<verb>/<item_type>/<slug>", methods=["GET", "POST"])
def item_detail(verb, item_type, slug):
    # Prevent custom tag slugs with 2 segments (e.g., /tagging/foo/bar) from
    # being misrouted here; hand them to the tag view instead.
    if verb == tags_slug():
        return _render_tags(f"{item_type}/{slug}")

    verb = slug_to_kind(verb)
    if verb not in VERB_KINDS:
        abort(404)
    db = get_db()
    itm = db.execute(
        "SELECT id, uuid, slug, item_type, title "
        "FROM item WHERE slug=? AND item_type=?",
        (slug, item_type),
    ).fetchone()
    if not itm:
        abort(404)

    # ──────────────────────────────── POST: quick “check-in” ──────────────
    if request.method == "POST":
        login_required()

        # ❶ ── turn the user input into a {key: value} dict -----------------
        raw = request.form["meta"].rstrip()

        meta_dict: dict[str, str] = {}
        body_lines: list[str] = []

        for ln in raw.splitlines():
            stripped = ln.strip()

            if stripped.startswith("^") and ":" in stripped:  # looks like “^key: val”
                k, v = [p.strip() for p in stripped.split(":", 1)]
                meta_dict[canon(k)] = v
            else:  # free text → body
                body_lines.append(ln.rstrip())

        # ❷ ── ensure we have an *action* (may be inferred) ------------------
        if "action" not in meta_dict:
            # most-recent action for the same item / verb
            r = db.execute(
                """SELECT ei.action
                               FROM entry_item ei
                               JOIN entry       e ON e.id = ei.entry_id
                              WHERE ei.item_id=? AND ei.verb=?
                              ORDER BY e.created_at DESC
                              LIMIT 1""",
                (itm["id"], verb),
            ).fetchone()
            if r:
                meta_dict["action"] = r["action"]
            else:  # fall-back: 2nd word in map
                meta_dict["action"] = (
                    VERB_MAP[verb][1]
                    if verb in VERB_MAP and len(VERB_MAP[verb]) > 1
                    else verb
                )

        # ❸ ── build the caret block ----------------------------------------
        caret_lines = [
            f"^uuid:{itm['uuid']}",
            f"^item_type:{itm['item_type']}",
            f"^action:{meta_dict.pop('action')}",
            f"^verb:{verb}",
        ]
        for k, v in meta_dict.items():  # any remaining keys (progress, …)
            caret_lines.append(f"{k}:{v}")

        # put user text (if any) underneath the caret block
        if body_lines:
            caret_lines.append("")  # blank line → separates meta/body
            caret_lines.extend(body_lines)

        body_raw = "\n".join(caret_lines)

        body, blocks, errors = parse_trigger(body_raw)  # normal pipeline
        if errors:
            raise ValueError(f"Generated caret block invalid: {errors}")

        now_dt = utc_now()
        now_iso = now_dt.isoformat(timespec="seconds")
        slug_ent = now_dt.strftime("%Y%m%d%H%M%S")

        # ➊  create the *entry* itself
        db.execute(
            """INSERT INTO entry (body, created_at, slug, kind)
                    VALUES (?,?,?,?)""",
            (body, now_iso, slug_ent, verb),
        )
        entry_id = db.execute("SELECT last_insert_rowid()").fetchone()[0]

        # ➋  link entry ↔ item   (only one block here, but keep the loop)
        for idx, blk in enumerate(blocks):
            db.execute(
                """INSERT INTO entry_item
                            (entry_id, item_id, verb, action, progress)
                        VALUES (?,?,?,?,?)""",
                (entry_id, itm["id"], blk["verb"], blk["action"], blk["progress"]),
            )

            # replace placeholder with the finished verbose block
            body = body.replace(
                f"^{blk['item_type']}:$PENDING${idx}$", _verbose_block(blk, itm["uuid"])
            )

        db.execute("UPDATE entry SET body=? WHERE id=?", (body, entry_id))
        db.commit()

        flash("Check-in added.")
        return redirect(request.url)

    meta = db.execute(
        """
            SELECT k, v
              FROM item_meta
             WHERE item_id=?
             ORDER BY ord, LOWER(k)         
        """,
        (itm["id"],),
    ).fetchall()

    sort = request.args.get("sort", "old")  # ➊  new | old

    if sort == "old":
        order_sql = "e.created_at ASC"
    else:  # newest (default)
        order_sql = "e.created_at DESC"

    rows = db.execute(
        f"""
            SELECT e.*, ei.action, ei.progress
              FROM entry      e
              JOIN entry_item ei ON ei.entry_id = e.id
             WHERE ei.item_id=? AND ei.verb=?
             ORDER BY {order_sql}
        """,
        (itm["id"], verb),
    ).fetchall()

    back_map = backlinks(rows, db=db)

    return render_template_string(
        TEMPL_ITEM_DETAIL,
        item=itm,
        meta=meta,
        entries=rows,
        verb=verb,
        verb_slug=kind_to_slug(verb),
        sort=sort,
        username=current_username(),
        title=get_setting("site_name", "po.etr.ist"),
        backlinks=back_map,
    )


TEMPL_ITEM_DETAIL = wrap("""
{% block body %}
<hr>
{% set _dates = meta | selectattr('k', 'equalto', 'date') | map(attribute='v') | list %}
{% set _year  = _dates[0][:4] if _dates else '' %}
<h2 style="margin-top:0">
    {{ item['title'] }}{% if _year %} ({{ _year }}){% endif %}
</h2>
            
{% if meta %}
<ul  style="display:flex;align-items:flex-start;gap:1rem;         
            list-style:none;padding:0;margin:0;font-size:.9em;color:#aaa;">

    {# ─────── cover column ─────── #}
    {% for r in meta if is_b64_image(r.k, r.v) %}
    <li style="float:left;margin:.65em .75rem .75rem 0;">
        <img src="data:image/webp;base64,{{ r.v }}"
             alt="{{ item.title }}"
             style="width:135px;max-width:100%;
                    border:1px solid #555;margin:0;">
    </li>
    {% endfor %}

    {# ─────── details column ─────── #}
    <li style="flex:1;">                                           
        <ul style="list-style:none;padding:0;margin:0;">
        {% for r in meta if not is_b64_image(r.k, r.v) %}
            <li style="margin:.2em 0;">
                <strong>{{ r.k|smartcap }}:</strong>
                {{ r.v|mdinline }}
            </li>
        {% endfor %}
        </ul>
    </li>
</ul>
{% endif %}


{% if session.get('logged_in') %}
<a href="{{ url_for('edit_item',
                verb=verb_slug, item_type=item['item_type'], slug=item['slug']) }}">Edit</a>   
<a href="{{ url_for('delete_item',
                verb=verb_slug, item_type=item['item_type'], slug=item['slug']) }}">&nbsp;&nbsp;Delete</a>   
{% endif %}
           

{% if session.get('logged_in') %}
<hr style="margin:1.25rem 0 .75rem 0">
<form method="post"
        style="display:flex;
            flex-direction:column;
            gap:10px;
            align-items:flex-start;">
    {% if csrf_token() %}
            <input type="hidden" name="csrf" value="{{ csrf_token() }}">
            {% endif %}
    <textarea name="meta"
            rows="3"
            style="width:100%;margin:0;"
        placeholder="^action:reading&#10;^progress:42%"></textarea>
    <button>Add&nbsp;Check-in</button>
</form>
{% endif %}

<hr>
{% if entries|length > 1 %}                
<div style="padding:1rem 0;font-size:.8em;color:#888;
                         display:flex;align-items:center;justify-content:space-between;">
        {# ─── sort pills ────────────────────────────────────────────── #}
        <span style="display:inline-flex;
                    border:1px solid #555;
                    border-radius:4px;
                    overflow:hidden;
                    font-size:.8em;">
            {% for val, label in [('old','Oldest'), ('new','Newest')] %}
            <a href="{{ url_for('item_detail',
                            verb=verb_slug,
                            item_type=item.item_type,
                            slug=item.slug,
                            sort=val) }}"
        style="display:flex; align-items:center;
                padding:.35em 1em;
                text-decoration:none; border-bottom:none;
                {% if not loop.first %}border-left:1px solid #555;{% endif %}
                {% if sort==val %}background:{{ theme_color() }};color:#000;
                {% else %}background:#333;color:#eee;{% endif %}">
            {{ label }}
        </a>
        {% endfor %}
    </span>
</div>
{% endif %}
{% for e in entries %}    
<article style="padding-bottom:1rem; {% if not loop.last %}border-bottom:1px solid #444;{% endif %}">
    <div class="e-content" style="margin-top:1.5em;">{{ e['body']|md(e['slug']) }}</div>
    {{ backlinks_panel(backlinks[e.id]) }}
    <small style="color:#aaa;">

        {# —— action pill ——————————————————————————————— #}
        <span style="
            display:inline-block;padding:.1em .6em;margin-right:.4em;
            background:#444;color:#fff;border-radius:1em;font-size:.75em;
            text-transform:capitalize;vertical-align:middle;">
            {{ e.action | smartcap }}
        </span>

        {# —— progress pill (optional) ———————————————— #}
        {% if e.progress %}
        <span style="
                display:inline-block;padding:.1em .6em;margin-right:.4em;
                background:#444;color:#fff;border-radius:1em;font-size:.75em;
                vertical-align:middle;">
            {{ e.progress }}
        </span>
        {% endif %}

        {# —— timestamp & author ———————————————————————— #}
        <a class="u-url u-uid" href="{{ url_for('entry_detail',
                                kind_slug=kind_to_slug(e['kind']),
                                entry_slug=e['slug']) }}"
            style="text-decoration:none;color:inherit;vertical-align:middle;">
            <time class="dt-published" datetime="{{ e['created_at'] }}">{{ e['created_at']|ts }}</time>
        </a>&nbsp;

        {# —— admin links ———————————————————————————————— #}
        {% if session.get('logged_in') %}
        <a href="{{ url_for('edit_entry',
                            kind_slug=kind_to_slug(e['kind']),
                            entry_slug=e['slug']) }}"
            style="vertical-align:middle;">Edit</a>&nbsp;&nbsp;
        <a href="{{ url_for('delete_entry',
                            kind_slug=kind_to_slug(e['kind']),
                            entry_slug=e['slug']) }}"
            style="vertical-align:middle;">Delete</a>
        {% endif %}
        {% set tags = entry_tags(e.id) %}
        {% if tags %}
            &nbsp;·&nbsp;
            {% for tag in tags %}
                <a class="p-category" rel="tag" href="{{ tags_href(tag) }}"
                   style="text-decoration:none;margin-right:.35em;color:{{ theme_color() }};vertical-align:middle;">
                    #{{ tag }}
                </a>
            {% endfor %}
        {% endif %}
    </small>
</article>
{% else %}
<p>No entries yet.</p>
{% endfor %}
{% endblock %}
""")


@app.route("/<verb>/<item_type>/<slug>/edit", methods=["GET", "POST"])
def edit_item(verb, item_type, slug):
    verb = slug_to_kind(verb)
    if verb not in VERB_KINDS:
        abort(404)
    login_required()
    db = get_db()
    itm = db.execute(
        "SELECT * FROM item WHERE slug=? AND item_type=?", (slug, item_type)
    ).fetchone()
    if not itm:
        abort(404)

    if request.method == "POST":
        title = request.form["title"].strip()
        new_slug = request.form["slug"].strip() or itm["slug"]
        new_type = request.form["item_type"].strip() or itm["item_type"]

        # ➊ update main row ---------------------------------------------------
        db.execute(
            """UPDATE item SET title=?, slug=?, item_type=? WHERE id=?""",
            (title, new_slug, new_type, itm["id"]),
        )

        # ➋ meta – collect paired lists -------------------------------
        keys = request.form.getlist("meta_k")
        vals = request.form.getlist("meta_v")
        orders = request.form.getlist("meta_o")

        triples = [
            (k.strip(), v.strip(), int(o) if o.strip().isdigit() else idx)
            for idx, (k, v, o) in enumerate(zip(keys, vals, orders), 1)
            if k.strip()
        ]
        db.execute("DELETE FROM item_meta WHERE item_id=?", (itm["id"],))
        for k, v, o in triples:
            db.execute(
                """INSERT INTO item_meta (item_id,k,v,ord)
                        VALUES (?,?,?,?)""",
                (itm["id"], k, v, o),
            )

        db.commit()
        flash("Item saved.")
        return redirect(
            url_for(
                "item_detail",
                verb=kind_to_slug(verb),
                item_type=new_type,
                slug=new_slug,
            )
        )

    # → GET – render form -----------------------------------------------------
    meta_rows = db.execute(
        "SELECT k, v, ord FROM item_meta WHERE item_id=? ORDER BY ord, LOWER(k)",
        (itm["id"],),
    ).fetchall()

    return render_template_string(
        TEMPL_EDIT_ITEM,
        item=itm,
        meta=meta_rows,
        verb=verb,
        username=current_username(),
        title=get_setting("site_name", "po.etr.ist"),
    )


TEMPL_EDIT_ITEM = wrap("""
{% block body %}
<hr>
<h2 style="margin-top:0">Edit item</h2>

<form method="post" style="max-width:32rem;display:flex;flex-direction:column;gap:1rem;">
  {% if csrf_token() %}
            <input type="hidden" name="csrf" value="{{ csrf_token() }}">
            {% endif %}
  {# ────────── title / slug / type ────────── #}
  <label>
    <span style="font-size:.8em;color:#888">Title</span><br>
    <input name="title" value="{{ item['title'] }}" style="width:100%">
  </label>

  <label>
    <span style="font-size:.8em;color:#888">Slug</span><br>
    <input name="slug"  value="{{ item['slug']  }}" style="width:100%">
  </label>

  <label>
    <span style="font-size:.8em;color:#888">Item type</span><br>
    <input name="item_type" value="{{ item['item_type'] }}" style="width:100%">
  </label>

  {# ────────── key / value rows ────────── #}
  <fieldset style="border:0;padding:0;">
    <legend style="font-weight:bold;margin-bottom:.25rem;font-size:.9em;">Meta data</legend>

    <div style="display:grid;
                grid-template-columns:3rem 1fr 2fr;
                gap:.5rem; align-items:center;">

    {# header row #}
    <span style="font-size:.75em;color:#888;">#</span>
    <span style="font-size:.75em;color:#888;">Key</span>
    <span style="font-size:.75em;color:#888;">Value</span>

    {# existing pairs #}
    {% for r in meta %}
        <input name="meta_o" value="{{ r['ord'] }}" style="width:3rem;text-align:right;">
        <input name="meta_k" value="{{ r['k'] }}"  placeholder="key">
        <input name="meta_v" value="{{ r['v'] }}"  placeholder="value">
    {% endfor %}

    {# ten blank rows for new data #}
    {% for _ in range(10) %}
        <input name="meta_o" placeholder="">
        <input name="meta_k" placeholder="key">
        <input name="meta_v" placeholder="value">
    {% endfor %}
    </div>

  </fieldset>

  <div>
    <button>Save</button>
    <a href="{{ url_for('item_detail', verb=kind_to_slug(verb),
                         item_type=item['item_type'], slug=item['slug']) }}"
       style="margin-left:1rem;">Cancel</a>
  </div>
</form>
{% endblock %}
""")


@app.route("/<verb>/<item_type>/<slug>/delete", methods=["GET", "POST"])
def delete_item(verb, item_type, slug):
    verb = slug_to_kind(verb)
    if verb not in VERB_KINDS:
        abort(404)
    login_required()
    db = get_db()
    itm = db.execute(
        "SELECT * FROM item WHERE slug=? AND item_type=?", (slug, item_type)
    ).fetchone()
    if not itm:
        abort(404)

    if request.method == "POST":
        db.execute("DELETE FROM item WHERE id=?", (itm["id"],))
        db.commit()
        flash("Item deleted.")
        return redirect(url_for("by_kind", slug=kind_to_slug(verb)))

    return render_template_string(
        TEMPL_DELETE_ITEM,
        item=itm,
        verb=verb,
        username=current_username(),
        title=get_setting("site_name", "po.etr.ist"),
    )


TEMPL_DELETE_ITEM = wrap("""
{% block body %}
  <hr>
  <h2 style="margin-top:0">Delete item?</h2>
  <p><strong>{{ item['title'] }}</strong> <em>({{ item['item_type'] }})</em></p>
  <form method="post" style="margin-top:1rem;">
    {% if csrf_token() %}
            <input type="hidden" name="csrf" value="{{ csrf_token() }}">
            {% endif %}
    <button style="background:#c00;color:#fff;">Yes – delete it</button>
    <a href="{{ url_for('item_detail',
                        verb=kind_to_slug(verb),
                        item_type=item['item_type'],
                        slug=item['slug']) }}"
       style="margin-left:1rem;">Cancel</a>
  </form>
{% endblock %}
""")

###############################################################################
# Search
###############################################################################

_SAFE_TOKEN_RE = re.compile(r"^\w+$", re.UNICODE)


def _auto_quote(q: str) -> str:
    """Wrap every token that contains punctuation in double quotes."""
    out = []
    for tok in q.split():
        # leave trailing * outside the quotes so prefix-search still works
        star = tok.endswith("*")
        core = tok[:-1] if star else tok
        if not _SAFE_TOKEN_RE.fullmatch(core):
            core = core.replace('"', '""')  # escape embedded quotes
            tok = f'"{core}"' + ("*" if star else "")
        out.append(tok)
    return " ".join(out)


# ------------------------------------------------------------------
# Full-text / LIKE search
# ------------------------------------------------------------------
def search_entries(
    q: str,
    *,
    db,
    page: int = 1,
    per_page: int = PAGE_DEFAULT,
    sort: str = "rel",  #  rel | new | old
):
    """
    Return (rows_on_page, total_hits, removed_chars_set).

    * “rel” = relevance (bm25 rank) – default
    * “new” = newest first
    * “old” = oldest first
    """
    # q, removed = _sanitize(q)
    q = _auto_quote(q)
    removed = set()  # no-op for now, but could be useful later
    q = q.strip().lower()
    if not q:
        return [], 0, removed

    # ─── 1-2 characters → simple LIKE ---------------------------------
    if len(q) < 3:
        like = f"%{q}%"
        order_sql = {"new": "e.created_at DESC", "old": "e.created_at ASC"}.get(
            sort, "e.created_at DESC"
        )
        base_sql = f"""
            SELECT e.*,
                   ei.action, ei.progress,
                   i.title       AS item_title,
                   i.slug        AS item_slug,
                   i.item_type   AS item_type,
                   MIN(CASE
                         WHEN im.k='date' AND LENGTH(im.v)>=4
                         THEN SUBSTR(im.v,1,4)
                       END)       AS item_year
              FROM entry e
              LEFT JOIN entry_item ei ON ei.entry_id = e.id
              LEFT JOIN item       i  ON i.id        = ei.item_id
              LEFT JOIN item_meta  im ON im.item_id  = i.id
             WHERE e.title LIKE ? OR strip_caret(e.body) LIKE ?
          GROUP BY e.id
            ORDER BY {order_sql}
        """
        total = db.execute(
            f"SELECT COUNT(*) FROM ({base_sql})", (like, like)
        ).fetchone()[0]
        rows = db.execute(
            f"{base_sql} LIMIT ? OFFSET ?",
            (like, like, per_page, (page - 1) * per_page),
        ).fetchall()
        return rows, total, removed

    # ─── ≥3 chars → FTS5 trigram index --------------------------------
    order_sql = {"new": "e.created_at DESC", "old": "e.created_at ASC"}.get(
        sort, "rank"
    )

    rows = db.execute(
        f"""
        SELECT
            e.*,
            bm25(entry_fts) AS rank,
            snippet(entry_fts, -1,
                    '<mark>', '</mark>', ' … ', 12) AS snippet,

            /* one representative action / progress */
            (SELECT ei.action   FROM entry_item ei
                WHERE ei.entry_id = e.id LIMIT 1)                AS action,
            (SELECT ei.progress FROM entry_item ei
                WHERE ei.entry_id = e.id LIMIT 1)                AS progress,

            /* item-related fields from the *first* linked item, if any */
            (SELECT i.title     FROM entry_item ei
                                JOIN item i ON i.id = ei.item_id
                WHERE ei.entry_id = e.id LIMIT 1)                AS item_title,
            (SELECT i.slug      FROM entry_item ei
                                JOIN item i ON i.id = ei.item_id
                WHERE ei.entry_id = e.id LIMIT 1)                AS item_slug,
            (SELECT i.item_type FROM entry_item ei
                                JOIN item i ON i.id = ei.item_id
                WHERE ei.entry_id = e.id LIMIT 1)                AS item_type,
            (SELECT SUBSTR(im.v,1,4)
                FROM entry_item ei
                JOIN item       i  ON i.id = ei.item_id
                JOIN item_meta  im ON im.item_id = i.id
                WHERE ei.entry_id = e.id
                AND im.k = 'date' AND LENGTH(im.v) >= 4
                LIMIT 1)                                          AS item_year

        FROM entry_fts
        JOIN entry e ON e.id = entry_fts.rowid
        WHERE entry_fts MATCH ?
        ORDER BY {order_sql}
        LIMIT ? OFFSET ?
    """,
        (q, per_page, (page - 1) * per_page),
    ).fetchall()

    total = db.execute(
        "SELECT COUNT(*) FROM entry_fts WHERE entry_fts MATCH ?", (q,)
    ).fetchone()[0]

    return rows, total, removed


_ITEM_Q_RE = re.compile(
    r"""
    ^\s*
    (?P<type>[^\s:]+)                 # track / book / …
    (?:\s*:\s*(?P<field>[^\s:]+))?    # 演唱 / 作者 / …
    \s*:\s*
    (?P<term>".+?"|[^"].*?)           # ← fixed here
    \s*$
""",
    re.X | re.I | re.U,
)


def _parse_item_query(q: str):
    """
    Return dict(type, field, term) *or* None if *q* is not an item query.
    Quotes around the term are stripped.
    """
    m = _ITEM_Q_RE.match(q)
    if not m:
        return None
    d = m.groupdict()
    term = d["term"].strip()
    if term.startswith('"') and term.endswith('"'):
        term = term[1:-1]
    d["term"] = term
    d["type"] = d["type"].lower()
    d["field"] = d["field"].lower() if d["field"] else None
    return d


def search_items(q: str, *, db, page=1, per_page=PAGE_DEFAULT):
    """
    LIKE-based search in item.title and item_meta.v, **excluding**
    large base-64 image blobs (cover/img/poster).

    Query forms supported
        book:"Kafka"          ← any field
        book:title:kafka      ← title only
        book:author:kafka     ← specific meta field

    Returns (rows_on_page, total_hits)
    """
    spec = _parse_item_query(q)
    if not spec:
        return [], 0  # not an item query → let caller fall back

    # ------------------------------------------------------------------
    # Build WHERE-clause and parameter list
    # ------------------------------------------------------------------
    conds, params = ["i.item_type = ?"], [spec["type"]]
    like = f"%{spec['term'].lower()}%"

    # --- helper fragment: exclude base64 images -----------------------
    _no_b64 = (
        "im.k NOT IN ('cover','img','poster') "
        "AND LENGTH(im.v) < 500"  # >≈300 chars → almost always an image
    )

    if spec["field"] is None:  #   book:"Kafka"
        conds.append(f"""
           (
             LOWER(i.title) LIKE ?
             OR EXISTS (SELECT 1 FROM item_meta im
                          WHERE im.item_id = i.id
                            AND {_no_b64}
                            AND LOWER(im.v) LIKE ?)
           )
        """)
        params.extend([like, like])

    elif spec["field"] == "title":  #   book:title:kafka
        conds.append("LOWER(i.title) LIKE ?")
        params.append(like)

    else:  #   book:author:kafka
        conds.append(f"""
            EXISTS (SELECT 1 FROM item_meta im
                     WHERE im.item_id = i.id
                       AND LOWER(im.k) = ?
                       AND {_no_b64}
                       AND LOWER(im.v) LIKE ?)
        """)
        params.extend([spec["field"], like])

    where_sql = " AND ".join(conds)

    # ------------------------------------------------------------------
    # Final query (unchanged apart from the new WHERE)
    # ------------------------------------------------------------------
    base_sql = f"""
        SELECT i.*,
               MIN(CASE
                     WHEN im.k='date' AND LENGTH(im.v)>=4
                     THEN SUBSTR(im.v,1,4)
                   END) AS year,
               COUNT(DISTINCT ei.entry_id) AS cnt,
               MAX(e.created_at)           AS last_at,
               MIN(ei.verb)                AS verb
          FROM item        i
          LEFT JOIN item_meta  im ON im.item_id = i.id
          LEFT JOIN entry_item ei ON ei.item_id = i.id
          LEFT JOIN entry      e  ON e.id       = ei.entry_id
         WHERE {where_sql}
         GROUP BY i.id
         ORDER BY cnt DESC, last_at DESC
    """

    total = db.execute(f"SELECT COUNT(*) FROM ({base_sql})", tuple(params)).fetchone()[
        0
    ]
    rows = db.execute(
        f"{base_sql} LIMIT ? OFFSET ?",
        tuple(params) + (per_page, (page - 1) * per_page),
    ).fetchall()
    return rows, total


def _highlight(text: str | None, terms: list[str]) -> Markup:
    """
    Wrap every *term* that occurs in *text* in a <mark> tag that mimics the
    FTS-snippet style.  Returns a Jinja-safe `Markup` object.
    """
    if not text:
        return Markup("")
    col = theme_color()
    pattern = re.compile("|".join(re.escape(t) for t in terms), re.I)
    return Markup(
        pattern.sub(
            lambda m: (
                f'<mark style="background:transparent;'
                f'color:{col};border-bottom:2px solid {col};">'
                f"{m.group(0)}</mark>"
            ),
            text,
        )
    )


@app.route("/search")
def search():
    q_raw = request.args.get("q", "").strip()
    page = max(int(request.args.get("page", 1)), 1)

    # ── ①  try item‑search first ─────────────────────────────────────
    if ":" in q_raw:  # quick pre‑filter
        rows, total = search_items(q_raw, db=get_db(), page=page, per_page=page_size())
        if total or _parse_item_query(q_raw):  # valid pattern
            pages = list(range(1, (total + page_size() - 1) // page_size() + 1))
            return render_template_string(
                TEMPL_SEARCH_ITEMS,
                rows=rows,
                total=total,
                query=q_raw,
                page=page,
                pages=pages,
                kind="search",
                username=current_username(),
                title=get_setting("site_name", "po.etr.ist"),
            )

    # ── ②  fall back to the existing entry search ───────────────────
    sort = request.args.get("sort", "rel")
    rows, total, removed = search_entries(
        q_raw, db=get_db(), page=page, per_page=page_size(), sort=sort
    )

    terms = [q_raw]  # q here is your original short token
    rows = [dict(r) for r in rows]  # make mutable copies
    for r in rows:
        r["snippet"] = _highlight(strip_caret(r["body"]), terms)
        r["title"] = _highlight(r["title"], terms)

    pages = list(range(1, (total + page_size() - 1) // page_size() + 1))

    return render_template_string(
        TEMPL_SEARCH_ENTRIES,
        rows=rows,
        query=q_raw,
        sort=sort,
        page=page,
        pages=pages,
        removed="".join(sorted(removed)),
        kind="search",
        username=current_username(),
        title=get_setting("site_name", "po.etr.ist"),
    )


TEMPL_SEARCH_ENTRIES = wrap("""
{% block body %}
    <hr>
    <div style="padding:1rem 0;
                
                font-size:.8em;
                color:#888;
                display:flex;
                align-items:center;      
                justify-content:space-between;">
        {# ─── sort pills ────────────────────────────────────────────── #}
        <span style="display:inline-flex;
                 border:1px solid #555;
                 border-radius:4px;
                 overflow:hidden;
                 font-size:.8em;">
            {% for val, label in [('rel','Relevance'),
                                ('new','Newest'),
                                ('old','Oldest')] %}
            <a href="{{ url_for('search', q=query, sort=val) }}"
            style="display:flex; align-items:center;              /* centre text */
                    padding:.35em 1em;                             /* same height as input */
                    text-decoration:none; border-bottom:none;
                    {% if not loop.first %}border-left:1px solid #555;{% endif %}
                    {% if sort==val %}background:{{ theme_color() }};color:#000;
                    {% else %}background:#333;color:#eee;{% endif %}">
            {{ label }}
            </a>
            {% endfor %}
        </span>
    </div>

    {% if removed %}
        <p style="color:{{ theme_color() }}; font-size:.8em;">
            Note: characters <code>{{ removed }}</code> were ignored in the search.
        </p>
    {% endif %}

    {% if query and not rows %}
        <p>No results for <strong>{{ query }}</strong>.</p>
    {% endif %}

    {% for e in rows %}
        <article style="padding-bottom:1.5em;
                        {% if not loop.last %}border-bottom:1px solid #444;{% endif %}">
            {% if e['title'] %}
                <h3 style="margin:.4rem 0;">{{ e['title'] }}</h3>
            {% endif %}
            <p>{{ e['snippet']|md(e['slug']) }}</p>
            <small style="color:#aaa;">
                {% if e.item_title %}
                    <span style="display:inline-block;padding:.1em .6em;margin-right:.4em;
                                background:#444;color:#fff;border-radius:1em;font-size:.75em;
                                text-transform:capitalize;vertical-align:middle;">
                    {{ e.action | smartcap }}
                    </span>
                    {% if e.item_type %}
                    <span style="display:inline-block;padding:.1em .6em;margin-right:.4em;
                                background:#444;color:#fff;border-radius:1em;font-size:.75em;
                                vertical-align:middle;">
                        {{ e.item_type | smartcap }}
                    </span>
                    {% endif %}
                    {% if e.progress %}
                    <span style="display:inline-block;padding:.1em .6em;margin-right:.4em;
                                background:#444;color:#fff;border-radius:1em;font-size:.75em;
                                vertical-align:middle;">
                        {{ e.progress }}
                    </span>
                    {% endif %}
                    <a href="{{ url_for('item_detail', verb=kind_to_slug(e.kind), item_type=e.item_type, slug=e.item_slug) }}"
                    style="text-decoration:none;margin-right:.4em;
                            color:{{ theme_color() }};vertical-align:middle;">
                    {{ e.item_title }}{% if e.item_year %} ({{ e.item_year }}){% endif %}
                    </a><br>
                {% endif %}
                <span style="display:inline-block;padding:.1em .6em;margin-right:.4em;background:#444;color:#fff;border-radius:1em;font-size:.75em;text-transform:capitalize;vertical-align:middle;">
                    {{ e['kind'] | smartcap }}
                </span>
                {% if e['kind'] == 'page' %}
                    <a class="u-url u-uid" href="{{ '/' ~ e['slug'] }}"
                        style="text-decoration:none; color:inherit;vertical-align:middle;">
                        <time class="dt-published" datetime="{{ e['created_at'] }}">{{ e['created_at']|ts }}</time>
                    </a>&nbsp;
                {% else %}
                <a class="u-url u-uid" href="{{ url_for('entry_detail', kind_slug=kind_to_slug(e['kind']), entry_slug=e['slug']) }}"
                    style="text-decoration:none; color:inherit;vertical-align:middle;">
                    <time class="dt-published" datetime="{{ e['created_at'] }}">{{ e['created_at']|ts }}</time>
                </a>&nbsp;
                {% endif %}
                {% if session.get('logged_in') %}
                    <a href="{{ url_for('edit_entry', kind_slug=kind_to_slug(e['kind']), entry_slug=e['slug']) }}" 
                        style="vertical-align:middle;">Edit</a>&nbsp;&nbsp;
                    <a href="{{ url_for('delete_entry', kind_slug=kind_to_slug(e['kind']), entry_slug=e['slug']) }}" 
                        style="vertical-align:middle;">Delete</a>
                {% endif %}
                {% set tags = entry_tags(e.id) %}
                {% if tags %}
                    &nbsp;·&nbsp;
                    {% for tag in tags %}
                        <a class="p-category" rel="tag" href="{{ tags_href(tag) }}"
                           style="text-decoration:none;margin-right:.35em;color:{{ theme_color() }};vertical-align:middle;">
                            #{{ tag }}
                        </a>
                    {% endfor %}
                {% endif %}
            </small>
        </article>
    {% endfor %}
                    
    {% if pages|length > 1 %}
    <nav style="margin-top:2em;padding-top:2em;font-size:.75em;border-top:1px solid #444;">
        {% for p in pages %}
            {% if p == page %}
                <span style="border-bottom:0.33rem solid #aaa;">{{ p }}</span>
            {% else %}
                <a href="{{ url_for('search', q=query, sort=sort, page=p) }}">{{ p }}</a>
            {% endif %}
            {% if not loop.last %}&nbsp;{% endif %}
        {% endfor %}
    </nav>
    {% endif %}
{% endblock %}
""")

TEMPL_SEARCH_ITEMS = wrap("""
{% block body %}
  <hr>
  <p style="font-size:.8em;color:#888;">
    {{ total }} item{{ '' if total==1 else 's' }} for <strong>{{ query }}</strong>
  </p>

  {% if rows %}
    <ul style="list-style:none;padding:0;">
    {% for r in rows %}
      <li style="margin:.6rem 0;">
        <a href="{{ url_for('item_detail', verb=kind_to_slug(r.verb), item_type=r.item_type, slug=r.slug) }}">
          {{ r.title|safe }}
        </a>
        {% if r.year %}<small style="color:#888;">({{ r.year }})</small>{% endif %}
        <br>
        <small style="color:#888;">{{ r.item_type }} • {{ r.cnt }} check‑in{{ '' if r.cnt==1 else 's' }}</small>
      </li>
    {% endfor %}
    </ul>

    {% if pages|length > 1 %}
      <nav style="margin-top:2em;padding-top:2em;font-size:.75em;border-top:1px solid #444;">
        {% for p in pages %}
          {% if p == page %}
            <span style="border-bottom:.33rem solid #aaa;">{{ p }}</span>
          {% else %}
            <a href="{{ url_for('search', q=query, page=p) }}">{{ p }}</a>
          {% endif %}
          {% if not loop.last %}&nbsp;{% endif %}
        {% endfor %}
      </nav>
    {% endif %}
  {% else %}
      <p>No items.</p>
  {% endif %}
{% endblock %}
""")


###############################################################################
# On This Day
###############################################################################
def _today_md() -> tuple[str, str]:
    now = datetime.now(ZoneInfo(tz_name()))
    return now.strftime("%m"), now.strftime("%d")


def _today_stats(*, db):
    """
    Return a list of dicts [{y:'2023', cnt:4}, …] for today’s month-day,
    ordered newest-year first.
    """
    mm, dd = _today_md()
    rows = db.execute(
        """
        SELECT substr(created_at,1,4) AS y,
               COUNT(*)               AS cnt
          FROM entry
         WHERE substr(created_at,6,2)=?
           AND substr(created_at,9,2)=?
           AND kind!='page'
         GROUP BY y
         ORDER BY y DESC
        """,
        (mm, dd),
    ).fetchall()
    # sqlite Row supports attribute access – convert to regular dict for safety
    return [dict(r) for r in rows]


def today_years(*, db) -> list[str]:
    """Helper so other parts of the code (or templates) can reuse the years list."""
    return [r["y"] for r in _today_stats(db=db)]


def has_today() -> bool:
    """Show the link only when ≥ 2 different years match today."""
    return len(today_years(db=get_db())) >= 2


app.jinja_env.globals.update(has_today=has_today)


@app.route("/today", defaults={"year": None})
@app.route("/today/<int:year>")
def today(year):
    db = get_db()
    stats = _today_stats(db=db)  # [{y, cnt}, …]
    years = [r["y"] for r in stats]  # plain list for convenience
    counts = {r["y"]: r["cnt"] for r in stats}  # {'2024':3, …}
    total_cnt = sum(counts.values())
    selected = str(year) if year else ""
    mm, dd = _today_md()

    cond = ""
    params = [mm, dd]
    if year:
        cond = " AND substr(e.created_at,1,4)=?"
        params.append(f"{year:04d}")

    BASE_SQL = f"""
        SELECT  e.*,
                ei.action,
                ei.progress,
                i.title       AS item_title,
                i.slug        AS item_slug,
                i.item_type   AS item_type,
                MIN(CASE
                        WHEN im.k='date' AND LENGTH(im.v)>=4
                        THEN SUBSTR(im.v,1,4)
                    END)      AS item_year
        FROM entry e
        LEFT JOIN entry_item ei ON ei.entry_id = e.id
        LEFT JOIN item       i  ON i.id        = ei.item_id
        LEFT JOIN item_meta  im ON im.item_id  = i.id
        WHERE substr(e.created_at,6,2)=? AND substr(e.created_at,9,2)=? {cond}
          AND e.kind!='page'
        GROUP BY e.id
        ORDER BY e.created_at DESC
    """

    page = max(int(request.args.get("page", 1)), 1)
    per_page = page_size()
    entries, pages_t = paginate(
        BASE_SQL, tuple(params), page=page, per_page=per_page, db=db
    )
    pages = list(range(1, pages_t + 1))

    return render_template_string(
        TEMPL_TODAY,
        rows=entries,
        stats=stats,  # [{y, cnt}, …] for pills
        years=years,  # simple list if you still need it
        total_cnt=total_cnt,
        selected=selected,
        page=page,
        pages=pages,
        title=get_setting("site_name", "po.etr.ist"),
        kind="today",
        username=current_username(),
    )


TEMPL_TODAY = wrap("""
{% block body %}
<hr>

<!-- —— Year-pills ———————————————————————————————————————— -->
<div style="display:flex; flex-wrap:wrap; gap:.25rem .5rem;">
  <!-- All-years pill -->
  <a href="{{ url_for('today') }}"
     style="text-decoration:none;border-bottom:none;
            display:inline-flex;margin:.15rem 0;padding:.15rem .6rem;
            border-radius:1rem;font-size:.8em;
            {% if not selected %}
              background:{{ theme_color() }};color:#000;
            {% else %}
              background:#444;color:{{ theme_color() }};
            {% endif %}">
     All
     <sup style="font-size:.5em;">{{ total_cnt }}</sup>
  </a>

  <!-- One pill per year -->
  {% for y in stats %}
    <a href="{{ url_for('today', year=y.y) }}"
       style="text-decoration:none;border-bottom:none;
              display:inline-flex;margin:.15rem 0;padding:.15rem .6rem;
              border-radius:1rem;font-size:.8em;
              {% if selected == y.y %}
                background:{{ theme_color() }};color:#000;
              {% else %}
                background:#444;color:{{ theme_color() }};
              {% endif %}">
       {{ y.y }}
       <sup style="font-size:.5em;">{{ y.cnt }}</sup>
    </a>
  {% endfor %}
</div>

<!-- —— Entry list ———————————————————————————————————————— -->
{% if rows %}
  <hr>
  {% for e in rows %}
    <article style="padding-bottom:1.5em;
                    {% if not loop.last %}border-bottom:1px solid #444;{% endif %}">
      {% if e.title %}
        <h3 style="margin:.4rem 0;">{{ e.title }}</h3>
      {% endif %}
      <p>{{ e.body|md(e.slug) }}</p>
      <small style="color:#aaa;">

        {# —— Item-related pills & link (if any) ———————————————— #}
        {% if e.item_title %}
          <span style="display:inline-block;padding:.1em .6em;margin-right:.4em;
                       background:#444;color:#fff;border-radius:1em;font-size:.75em;
                       text-transform:capitalize;vertical-align:middle;">
            {{ e.action|smartcap }}
          </span>

          {% if e.item_type %}
            <span style="display:inline-block;padding:.1em .6em;margin-right:.4em;
                         background:#444;color:#fff;border-radius:1em;font-size:.75em;
                         vertical-align:middle;">
              {{ e.item_type|smartcap }}
            </span>
          {% endif %}

          {% if e.progress %}
            <span style="display:inline-block;padding:.1em .6em;margin-right:.4em;
                         background:#444;color:#fff;border-radius:1em;font-size:.75em;
                         vertical-align:middle;">
              {{ e.progress }}
            </span>
          {% endif %}

          <a href="{{ url_for('item_detail',
                              verb=kind_to_slug(e.kind),
                              item_type=e.item_type,
                              slug=e.item_slug) }}"
             style="text-decoration:none;margin-right:.4em;
                    color:{{ theme_color() }};vertical-align:middle;">
             {{ e.item_title }}{% if e.item_year %} ({{ e.item_year }}){% endif %}
          </a><br>
        {% endif %}

        {# —— Kind pill ———————————————————————————————— #}
        <span style="display:inline-block;padding:.1em .6em;margin-right:.4em;
                     background:#444;color:#fff;border-radius:1em;font-size:.75em;
                     text-transform:capitalize;vertical-align:middle;">
          {{ e.kind }}
        </span>

        {# —— Timestamp ———————————————————————————————— #}
        <a href="{{ url_for('entry_detail',
                             kind_slug=kind_to_slug(e.kind),
                             entry_slug=e.slug) }}"
           style="text-decoration:none;color:inherit;vertical-align:middle;font-variant-numeric:tabular-nums;">
           {{ e.created_at|ts }}
        </a>

        {# —— Admin links ———————————————————————————————— #}
        {% if session.get('logged_in') %}
          &nbsp;
          <a href="{{ url_for('edit_entry',
                               kind_slug=kind_to_slug(e.kind),
                               entry_slug=e.slug) }}"
             style="vertical-align:middle;">Edit</a>&nbsp;&nbsp;
          <a href="{{ url_for('delete_entry',
                               kind_slug=kind_to_slug(e.kind),
                               entry_slug=e.slug) }}"
             style="vertical-align:middle;">Delete</a>
        {% endif %}

      </small>
    </article>
  {% endfor %}

  {% if pages|length > 1 %}
    <nav style="margin-top:2em;padding-top:2em;font-size:.75em;border-top:1px solid #444;">
      {% for p in pages %}
        {% if p == page %}
          <span style="border-bottom:.33rem solid #aaa;">{{ p }}</span>
        {% else %}
          <a href="{{ url_for('today',
                              year=selected if selected else None,
                              page=p) }}">{{ p }}</a>
        {% endif %}
        {% if not loop.last %}&nbsp;{% endif %}
      {% endfor %}
    </nav>
  {% endif %}
{% else %}
  <hr>
  <p>No entries for today yet.</p>
{% endif %}
{% endblock %}
""")

###############################################################################
# Error pages
###############################################################################


@app.route("/.well-known")
@app.route("/.well-known/<path:path>")
@app.route("/users/<path:path>")
@app.route("/nodeinfo")
@app.route("/nodeinfo/<path:path>")
@app.route("/api/nodeinfo")
@app.route("/api/nodeinfo/<path:path>")
@app.route("/inbox", methods=["GET", "POST"])
def gone(path=None):
    return ("", 410)


@app.errorhandler(404)
def not_found(exc):
    """Site-wide “Not Found” page."""
    return render_template_string(
        TEMPL_404, title=get_setting("site_name", "po.etr.ist")
    ), 404


@app.errorhandler(500)
def internal_error(exc):
    """
    Generic 500 page for production.
    • In development (`FLASK_ENV=development`) the Werkzeug debugger
      still shows the interactive traceback, because Flask bypasses
      this handler while debug is on.
    """
    # Optional: log the traceback here if you like
    return render_template_string(
        TEMPL_500, title=get_setting("site_name", "po.etr.ist")
    ), 500


TEMPL_404 = wrap("""
{% block body %}
  <hr>
  <h2 style="margin-top:0">Page not found</h2>
  <p>The URL you asked for doesn’t exist.
     <a href="{{ url_for('index') }}" style="color:{{ theme_color() }};">Back to the front page</a>
     or use the search box below.</p>
{% endblock %}
""")

TEMPL_500 = wrap("""
{% block body %}
  <hr>
  <h2 style="margin-top:0">Internal Server Error</h2>
  <p>Our fault, not yours.  
     Please try again in a minute or
     <a href="https://github.com/huangziwei/poetrist/issues/new"
        style="color:{{ theme_color() }};">report the bug</a>.</p>
{% endblock %}
""")

###############################################################################
# Import /Export Items data
###############################################################################


@app.route("/<verb>/<item_type>/<slug>/json")
@rate_limit(max_requests=30, window=60)
def export_item_json(verb, item_type, slug):
    verb = slug_to_kind(verb)
    if verb not in VERB_KINDS:
        abort(404)
    db = get_db()
    itm = db.execute(
        """SELECT id, uuid, slug, item_type, title
                          FROM item
                         WHERE item_type=? AND slug=?""",
        (item_type, slug),
    ).fetchone()
    if not itm:
        abort(404)

    meta = db.execute(
        """SELECT k, v, ord
                           FROM item_meta
                          WHERE item_id=?
                          ORDER BY ord""",
        (itm["id"],),
    ).fetchall()

    return {
        "title": itm["title"],
        "item_type": itm["item_type"],
        "slug": itm["slug"],
        "uuid": itm["uuid"],
        "meta": [{"k": m["k"], "v": m["v"], "ord": m["ord"]} for m in meta],
    }


_BAD_NETS = [
    ipaddress.ip_network(n)
    for n in (
        "0.0.0.0/8",
        "10.0.0.0/8",
        "127.0.0.0/8",
        "169.254.0.0/16",
        "172.16.0.0/12",
        "192.0.0.0/24",
        "192.168.0.0/16",
        "198.18.0.0/15",
        "224.0.0.0/4",
        "240.0.0.0/4",
        "::/128",
        "::1/128",
        "fc00::/7",
        "fe80::/10",
        "ff00::/8",
    )
]


def _is_private(host: str) -> bool:
    """True ⇢ *host* resolves **only** to private / reserved addresses."""
    # Fast-path literal IPs (no DNS resolution needed)
    try:
        ip_obj = ipaddress.ip_address(host)
    except ValueError:
        ip_obj = None
    else:
        return any(ip_obj in net for net in _BAD_NETS)

    try:
        infos = socket.getaddrinfo(host, None, proto=socket.IPPROTO_TCP)
    except socket.gaierror:
        return False  # unable to resolve (e.g. offline) ⇒ treat as non-private

    for fam, *_rest, sockaddr in infos:
        ip = sockaddr[0]
        try:
            ip_obj = ipaddress.ip_address(ip)
        except ValueError:
            continue  # skip unparsable addresses and try the next one
        if not any(ip_obj in net for net in _BAD_NETS):
            return False  # at least one public address
    return True


def import_item_json(url: str, *, action: str):
    """
    Securely fetch another poetrist instance’s item-JSON.

    • HTTPS is mandatory unless the *remote* host is localhost / 127.0.0.1 / ::1
    • Reject hosts that resolve only to private / reserved IP blocks
      (prevents SSRF to internal services)
    • Enforce < 1 MiB payload & `Content-Type: application/json`
    • Keep the existing verb / action consistency check
    """
    # ------------------------------------------------------------------ #
    # 0 . normalise URL and pull out components
    # ------------------------------------------------------------------ #
    parsed = urlparse(url)
    host = parsed.hostname or ""
    scheme = parsed.scheme or "https"
    if not host:
        raise ValueError("Malformed URL – host missing")

    # “/json” endpoint is canonical – append if caller omitted it
    if not parsed.path.rstrip("/").endswith("/json"):
        url = url.rstrip("/") + "/json"

    # ------------------------------------------------------------------ #
    # 1 . basic network-level guards
    # ------------------------------------------------------------------ #
    localhost_hosts = {"localhost", "127.0.0.1", "::1"}
    if host not in localhost_hosts and _is_private(host):
        raise ValueError("Refusing to fetch from a private/reserved address")

    if scheme != "https" and host not in localhost_hosts:
        raise ValueError("Remote imports must use HTTPS")

    # ------------------------------------------------------------------ #
    # 2 . HTTP fetch with tight limits
    # ------------------------------------------------------------------ #
    try:
        with requests.get(
            url,
            timeout=5,
            stream=True,  # we want to cap download
            verify=(
                host not in localhost_hosts
            ),  # allow self-signed *only* for localhost
            headers={"Accept": "application/json"},
        ) as resp:
            resp.raise_for_status()

            ctype = resp.headers.get("Content-Type", "")
            if "application/json" not in ctype:
                raise ValueError(f"Unexpected Content-Type “{ctype}”")

            raw = b""
            max_bytes = 1 * 1024 * 1024  # 1 MiB should be plenty
            for chunk in resp.iter_content(8192):
                raw += chunk
                if len(raw) > max_bytes:
                    raise ValueError("Remote JSON too large (>1 MiB)")
            data = json.loads(raw.decode(resp.encoding or "utf-8"))
    except (requests.RequestException, json.JSONDecodeError) as exc:
        raise ValueError(f"Cannot fetch remote item – {exc}") from None

    # ------------------------------------------------------------------ #
    # 3 . sanity-check payload
    # ------------------------------------------------------------------ #
    required = {"uuid", "slug", "item_type", "title"}
    if not required.issubset(data):
        raise ValueError("Remote item is missing mandatory fields")

    # ---- verb consistency (unchanged) -------------------------------- #
    path_parts = urlparse(url).path.strip("/").split("/")
    if len(path_parts) < 3:
        raise ValueError("Malformed URL")

    verb_from_url = path_parts[0].lower()
    verb_from_action = next(
        (v for v, acts in VERB_MAP.items() if action.lower() in acts), action.lower()
    )
    if verb_from_url != verb_from_action:
        raise ValueError("Verb/action mismatch")

    # ------------------------------------------------------------------ #
    # 4 . craft block-dict for caller
    # ------------------------------------------------------------------ #
    return {
        "verb": verb_from_action,
        "action": action.lower(),
        "item_type": data["item_type"],
        "title": data["title"],
        "slug": data["slug"],
        "progress": None,
        "meta": {m["k"]: m["v"] for m in data.get("meta", [])},
    }


###############################################################################
# main
###############################################################################
if __name__ == "__main__":
    import sys

    if len(sys.argv) > 1 and sys.argv[1] == "init":
        with app.app_context():
            cli_init()
    else:
        app.run(debug=True)
