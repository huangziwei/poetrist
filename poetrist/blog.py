#!/usr/bin/env python3
"""
A single-file minimal blog.
"""

import ipaddress
import json
import os
import re
import secrets
import socket
import sqlite3
import tempfile
import uuid
from collections import Counter, defaultdict, deque
from datetime import datetime, timedelta, timezone
from functools import wraps
from html import escape, unescape
from importlib.metadata import PackageNotFoundError, version
from pathlib import Path
from time import time
from typing import DefaultDict
from urllib.parse import urlencode, urlparse
from zoneinfo import ZoneInfo, available_timezones

import boto3
import click
import latex2mathml.converter as _l2m
import markdown
import requests
from botocore.exceptions import BotoCoreError, ClientError
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
from werkzeug.utils import secure_filename

################################################################################
# Imports & constants
################################################################################

ROOT = Path(__file__).parent
DB_FILE = ROOT / "blog.sqlite3"

ENV_FILE = ROOT / ".env"
SECRET_FILE = ROOT / ".secret_key"
SECRET_KEY = (
    SECRET_FILE.read_text().strip() if SECRET_FILE.exists() else secrets.token_hex(32)
)
SECRET_FILE.write_text(SECRET_KEY)
TOKEN_LEN = 48
signer = TimestampSigner(SECRET_KEY, salt="login-token")

SLUG_DEFAULTS = {"say": "says", "photo": "photos", "post": "posts", "pin": "pins"}
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
    "item": "item_type",
    "a": "action",
    "at": "action",
    "v": "verb",
    "vb": "verb",
    "t": "title",
    "tt": "title",
}

R2_ENV_KEYS = (
    "R2_ACCOUNT_ID",
    "R2_ACCESS_KEY_ID",
    "R2_SECRET_ACCESS_KEY",
    "R2_BUCKET",
    "R2_PUBLIC_BASE",
    "R2_ENDPOINT",
)
R2_REQUIRED_KEYS = (
    "R2_ACCOUNT_ID",
    "R2_ACCESS_KEY_ID",
    "R2_SECRET_ACCESS_KEY",
    "R2_BUCKET",
)
UPLOAD_MAX_BYTES = 32 * 1024 * 1024  # cap uploads to 8 MiB
IMAGE_MIMES = {
    "image/png",
    "image/jpeg",
    "image/webp",
    "image/gif",
    "image/svg+xml",
}
UPLOAD_ICON_SVG = """
<svg xmlns="http://www.w3.org/2000/svg"
     viewBox="0 -3 32 32"
     width="14" height="14"
     fill="currentColor" stroke="currentColor"
     preserveAspectRatio="xMidYMid"
     aria-hidden="true" focusable="false">
    <path d="M29.000,26.000 L3.000,26.000 C1.346,26.000 -0.000,24.654 -0.000,23.000 L-0.000,7.000 C-0.000,5.346 1.346,4.000 3.000,4.000 L7.381,4.000 L9.102,0.554 C9.270,0.214 9.617,0.000 9.996,0.000 L22.006,0.000 C22.385,0.000 22.731,0.214 22.901,0.554 L24.619,4.000 L29.000,4.000 C30.654,4.000 32.000,5.346 32.000,7.000 L32.000,23.000 C32.000,24.654 30.654,26.000 29.000,26.000 ZM30.000,7.000 C30.000,6.449 29.551,6.000 29.000,6.000 L24.000,6.000 C23.950,6.000 23.907,5.979 23.859,5.972 C23.788,5.961 23.717,5.955 23.649,5.929 C23.588,5.906 23.537,5.869 23.482,5.834 C23.428,5.801 23.373,5.773 23.326,5.729 C23.273,5.680 23.235,5.620 23.194,5.560 C23.166,5.520 23.127,5.491 23.105,5.446 L21.387,2.000 L10.615,2.000 L8.895,5.446 C8.848,5.541 8.785,5.623 8.715,5.695 C8.701,5.710 8.684,5.719 8.669,5.733 C8.597,5.798 8.518,5.851 8.432,5.892 C8.403,5.907 8.375,5.919 8.344,5.931 C8.234,5.971 8.120,5.999 8.002,6.000 C8.001,6.000 8.001,6.000 8.000,6.000 L3.000,6.000 C2.449,6.000 2.000,6.449 2.000,7.000 L2.000,23.000 C2.000,23.551 2.449,24.000 3.000,24.000 L29.000,24.000 C29.551,24.000 30.000,23.551 30.000,23.000 L30.000,7.000 ZM16.000,21.000 C12.140,21.000 9.000,17.860 9.000,14.000 C9.000,10.140 12.140,7.000 16.000,7.000 C19.860,7.000 23.000,10.140 23.000,14.000 C23.000,17.860 19.860,21.000 16.000,21.000 ZM16.000,9.000 C13.243,9.000 11.000,11.243 11.000,14.000 C11.000,16.757 13.243,19.000 16.000,19.000 C18.757,19.000 21.000,16.757 21.000,14.000 C21.000,11.243 18.757,9.000 16.000,9.000 Z"></path>
</svg>
"""

TRAFFIC_LOG_DIR_DEFAULT = Path(
    os.environ.get(
        "TRAFFIC_LOG_DIR", str(Path(tempfile.gettempdir()) / "poetrist-traffic")
    )
)
TRAFFIC_LOG_ENABLED = os.environ.get("TRAFFIC_LOG_ENABLED", "1") != "0"
TRAFFIC_LOG_RETENTION_DAYS = int(os.environ.get("TRAFFIC_LOG_RETENTION_DAYS", "14"))
TRAFFIC_BURST_WINDOW_SEC = int(os.environ.get("TRAFFIC_BURST_WINDOW", "5"))
TRAFFIC_BURST_LIMIT = int(os.environ.get("TRAFFIC_BURST_LIMIT", "50"))
TRAFFIC_GLOBAL_LIMIT = int(os.environ.get("TRAFFIC_GLOBAL_LIMIT", "60"))
TRAFFIC_GLOBAL_WINDOW_SEC = int(os.environ.get("TRAFFIC_GLOBAL_WINDOW_SEC", "60"))
TRAFFIC_SUSPICIOUS_MIN_HITS = int(os.environ.get("TRAFFIC_SUSPICIOUS_MIN_HITS", "10"))
TRAFFIC_NOTFOUND_SHARE = float(os.environ.get("TRAFFIC_NOTFOUND_SHARE", "0.4"))
TRAFFIC_READ_MAX_LINES = int(os.environ.get("TRAFFIC_READ_MAX_LINES", "5000"))
TRAFFIC_HIGH_HITS = int(os.environ.get("TRAFFIC_HIGH_HITS", "30"))
TRAFFIC_BOT_KEYWORDS = tuple(
    s.strip().lower()
    for s in os.environ.get(
        "TRAFFIC_BOT_KEYWORDS", "bot,crawler,spider,gptbot,baiduspider"
    ).split(",")
    if s.strip()
)
TRAFFIC_BLOCK_UA_KEYWORDS = tuple(
    s.strip().lower()
    for s in os.environ.get(
        "TRAFFIC_BLOCK_UA_KEYWORDS",
        "thinkbot,gptbot,perplexitybot,duckassistbot,archive.org_bot,meta-externalfetcher",
    ).split(",")
    if s.strip()
)
TRAFFIC_SUSPICIOUS_PATH_LEN = int(os.environ.get("TRAFFIC_SUSPICIOUS_PATH_LEN", "160"))
TRAFFIC_SUSPICIOUS_TOKEN_THRESHOLD = int(
    os.environ.get("TRAFFIC_SUSPICIOUS_TOKEN_THRESHOLD", "7")
)
TRAFFIC_SUSPICIOUS_MIN_UA_LEN = int(
    os.environ.get("TRAFFIC_SUSPICIOUS_MIN_UA_LEN", "14")
)
TRAFFIC_SUSPICIOUS_UA_KEYWORDS = tuple(
    s.strip().lower()
    for s in os.environ.get(
        "TRAFFIC_SUSPICIOUS_UA_KEYWORDS",
        "curl,wget,python-requests,httpclient,okhttp,aiohttp,libwww,scrapy,go-http-client,http.rb,java/,postmanruntime,guzzlehttp,restsharp,insomnia",
    ).split(",")
    if s.strip()
)
TRAFFIC_SUSPICIOUS_CHURN_MIN_HITS = int(
    os.environ.get("TRAFFIC_SUSPICIOUS_CHURN_MIN_HITS", "8")
)
TRAFFIC_SUSPICIOUS_SCORE = int(os.environ.get("TRAFFIC_SUSPICIOUS_SCORE", "3"))
TRAFFIC_SUSPICIOUS_NET_HITS = int(os.environ.get("TRAFFIC_SUSPICIOUS_NET_HITS", "80"))
TRAFFIC_SUSPICIOUS_NET_UNIQUE = int(
    os.environ.get("TRAFFIC_SUSPICIOUS_NET_UNIQUE", "20")
)
TRAFFIC_SUSPICIOUS_NET_NOTFOUND_SHARE = float(
    os.environ.get("TRAFFIC_SUSPICIOUS_NET_NOTFOUND_SHARE", "0.8")
)
TRAFFIC_SUSPICIOUS_NET_ERROR_SHARE = float(
    os.environ.get("TRAFFIC_SUSPICIOUS_NET_ERROR_SHARE", "0.8")
)
TRAFFIC_SUSPICIOUS_NET_LOW_HITS = int(
    os.environ.get("TRAFFIC_SUSPICIOUS_NET_LOW_HITS", "12")
)
TRAFFIC_SUSPICIOUS_NET_LOW_UNIQUE = int(
    os.environ.get("TRAFFIC_SUSPICIOUS_NET_LOW_UNIQUE", "10")
)
TRAFFIC_SUSPICIOUS_NET_LOW_NF_SHARE = float(
    os.environ.get("TRAFFIC_SUSPICIOUS_NET_LOW_NF_SHARE", "0.9")
)
TRAFFIC_SWARM_CORR_WINDOW_SEC = int(
    os.environ.get("TRAFFIC_SWARM_CORR_WINDOW_SEC", "3")
)
TRAFFIC_SWARM_TOKEN_MIN = int(os.environ.get("TRAFFIC_SWARM_TOKEN_MIN", "6"))
TRAFFIC_SWARM_MIN_CORR_HITS = int(os.environ.get("TRAFFIC_SWARM_MIN_CORR_HITS", "1"))
TRAFFIC_SWARM_REQUIRE_4XX = str(
    os.environ.get("TRAFFIC_SWARM_REQUIRE_4XX", "1")
).strip().lower() in {"1", "true", "yes", "on"}
TRAFFIC_SWARM_AUTOBLOCK = str(
    os.environ.get("TRAFFIC_SWARM_AUTOBLOCK", "1")
).strip().lower() in {"1", "true", "yes", "on"}
TRAFFIC_SWARM_AUTOBLOCK_EXPIRES_DAYS = int(
    os.environ.get("TRAFFIC_SWARM_AUTOBLOCK_EXPIRES_DAYS", "0")
)
TRAFFIC_SWARM_AUTOBLOCK_ON_REQUEST = str(
    os.environ.get("TRAFFIC_SWARM_AUTOBLOCK_ON_REQUEST", "1")
).strip().lower() in {"1", "true", "yes", "on"}
TRAFFIC_SWARM_AUTOBLOCK_SCAN_HOURS = int(
    os.environ.get("TRAFFIC_SWARM_AUTOBLOCK_SCAN_HOURS", "6")
)
TRAFFIC_SWARM_AUTOBLOCK_INTERVAL_SEC = int(
    os.environ.get("TRAFFIC_SWARM_AUTOBLOCK_INTERVAL_SEC", "30")
)
TRAFFIC_SWARM_AUTOBLOCK_UA_ALLOWLIST = tuple(
    s.strip().lower()
    for s in os.environ.get(
        "TRAFFIC_SWARM_AUTOBLOCK_UA_ALLOWLIST",
        "googlebot,bingbot,duckduckbot,slurp,linkedinbot",
    ).split(",")
    if s.strip()
)
CLOUDFLARE_IP_RANGES_DEFAULT = (
    "173.245.48.0/20",
    "103.21.244.0/22",
    "103.22.200.0/22",
    "103.31.4.0/22",
    "141.101.64.0/18",
    "108.162.192.0/18",
    "190.93.240.0/20",
    "188.114.96.0/20",
    "197.234.240.0/22",
    "198.41.128.0/17",
    "162.158.0.0/15",
    "104.16.0.0/13",
    "104.24.0.0/14",
    "172.64.0.0/13",
    "131.0.72.0/22",
    "2400:cb00::/32",
    "2606:4700::/32",
    "2803:f800::/32",
    "2405:b500::/32",
    "2405:8100::/32",
    "2a06:98c0::/29",
    "2c0f:f248::/32",
)
CLOUDFLARE_IP_RANGES = tuple(
    s.strip()
    for s in os.environ.get(
        "CLOUDFLARE_IP_RANGES", ",".join(CLOUDFLARE_IP_RANGES_DEFAULT)
    ).split(",")
    if s.strip()
)
TRAFFIC_SKIP_PATHS = {"/favicon.ico", "/robots.txt"}
IP_BLOCK_DEFAULT_DAYS = int(os.environ.get("IP_BLOCK_DEFAULT_DAYS", "0") or 0)


def canon(k: str) -> str:  # helper: ^pg → progress
    return ALIASES.get(k.lower(), k.lower())


def canon_meta_key(k: str) -> str:
    """Map aliases, otherwise preserve the original casing."""
    return ALIASES.get(k.lower(), k)


def normalize_item_type(value: str | None) -> str:
    """Canonicalise user-provided item types (trim + collapse case/whitespace)."""
    if not value:
        return ""
    return re.sub(r"\s+", " ", value).strip().casefold()


GENRE_SPLIT_RE = re.compile(r"\s*/\s*")


def normalize_genre(value: str) -> str:
    return re.sub(r"\s+", " ", value.strip()).lower()


PHOTO_TAGS = ("photo", "photos")
PHOTO_TAG_SET = set(PHOTO_TAGS)
KINDS = ("say", "photo", "post", "pin") + tuple(VERB_MAP.keys()) + ("page",)
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
IMG_TAG_RE = re.compile(
    r'<img\b(?=[^>]*\bsrc=["\'](?P<src>[^"\']+)["\'])(?=[^>]*\balt=["\'](?P<alt>[^"\']*)["\'])?[^>]*>',
    re.I,
)
_HEADING_RE = re.compile(r"^(#{1,6})\s+(.*)$")
WORD_COUNT_SQL = (
    "CASE WHEN body IS NULL OR LENGTH(TRIM(body))=0 THEN 0 "
    "ELSE LENGTH(REPLACE(REPLACE(body, char(10), ' '), char(13), ' ')) "
    "     - LENGTH(REPLACE(REPLACE(REPLACE(body, char(10), ' '), char(13), ' '), ' ', '')) "
    "     + 1 "
    "END"
)
_IP_BLOCKLIST_CHECKED = False

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
    TRAFFIC_LOG_DIR=str(TRAFFIC_LOG_DIR_DEFAULT),
    TRAFFIC_LOG_ENABLED=TRAFFIC_LOG_ENABLED,
    TRAFFIC_LOG_RETENTION_DAYS=TRAFFIC_LOG_RETENTION_DAYS,
    TRAFFIC_BURST_WINDOW=TRAFFIC_BURST_WINDOW_SEC,
    TRAFFIC_BURST_LIMIT=TRAFFIC_BURST_LIMIT,
    TRAFFIC_GLOBAL_LIMIT=TRAFFIC_GLOBAL_LIMIT,
    TRAFFIC_GLOBAL_WINDOW_SEC=TRAFFIC_GLOBAL_WINDOW_SEC,
    TRAFFIC_READ_MAX_LINES=TRAFFIC_READ_MAX_LINES,
    TRAFFIC_NOTFOUND_SHARE=TRAFFIC_NOTFOUND_SHARE,
    TRAFFIC_HIGH_HITS=TRAFFIC_HIGH_HITS,
    TRAFFIC_SUSPICIOUS_PATH_LEN=TRAFFIC_SUSPICIOUS_PATH_LEN,
    TRAFFIC_SUSPICIOUS_TOKEN_THRESHOLD=TRAFFIC_SUSPICIOUS_TOKEN_THRESHOLD,
    TRAFFIC_SUSPICIOUS_MIN_UA_LEN=TRAFFIC_SUSPICIOUS_MIN_UA_LEN,
    TRAFFIC_SUSPICIOUS_UA_KEYWORDS=TRAFFIC_SUSPICIOUS_UA_KEYWORDS,
    TRAFFIC_SUSPICIOUS_CHURN_MIN_HITS=TRAFFIC_SUSPICIOUS_CHURN_MIN_HITS,
    TRAFFIC_SUSPICIOUS_SCORE=TRAFFIC_SUSPICIOUS_SCORE,
    TRAFFIC_SUSPICIOUS_NET_HITS=TRAFFIC_SUSPICIOUS_NET_HITS,
    TRAFFIC_SUSPICIOUS_NET_UNIQUE=TRAFFIC_SUSPICIOUS_NET_UNIQUE,
    TRAFFIC_SUSPICIOUS_NET_NOTFOUND_SHARE=TRAFFIC_SUSPICIOUS_NET_NOTFOUND_SHARE,
    TRAFFIC_SUSPICIOUS_NET_ERROR_SHARE=TRAFFIC_SUSPICIOUS_NET_ERROR_SHARE,
    TRAFFIC_SUSPICIOUS_NET_LOW_HITS=TRAFFIC_SUSPICIOUS_NET_LOW_HITS,
    TRAFFIC_SUSPICIOUS_NET_LOW_UNIQUE=TRAFFIC_SUSPICIOUS_NET_LOW_UNIQUE,
    TRAFFIC_SUSPICIOUS_NET_LOW_NF_SHARE=TRAFFIC_SUSPICIOUS_NET_LOW_NF_SHARE,
    TRAFFIC_SWARM_CORR_WINDOW_SEC=TRAFFIC_SWARM_CORR_WINDOW_SEC,
    TRAFFIC_SWARM_TOKEN_MIN=TRAFFIC_SWARM_TOKEN_MIN,
    TRAFFIC_SWARM_MIN_CORR_HITS=TRAFFIC_SWARM_MIN_CORR_HITS,
    TRAFFIC_SWARM_REQUIRE_4XX=TRAFFIC_SWARM_REQUIRE_4XX,
    TRAFFIC_SWARM_AUTOBLOCK=TRAFFIC_SWARM_AUTOBLOCK,
    TRAFFIC_SWARM_AUTOBLOCK_EXPIRES_DAYS=TRAFFIC_SWARM_AUTOBLOCK_EXPIRES_DAYS,
    TRAFFIC_SWARM_AUTOBLOCK_ON_REQUEST=TRAFFIC_SWARM_AUTOBLOCK_ON_REQUEST,
    TRAFFIC_SWARM_AUTOBLOCK_SCAN_HOURS=TRAFFIC_SWARM_AUTOBLOCK_SCAN_HOURS,
    TRAFFIC_SWARM_AUTOBLOCK_INTERVAL_SEC=TRAFFIC_SWARM_AUTOBLOCK_INTERVAL_SEC,
    TRAFFIC_SWARM_AUTOBLOCK_UA_ALLOWLIST=TRAFFIC_SWARM_AUTOBLOCK_UA_ALLOWLIST,
    TRAFFIC_BLOCK_UA_KEYWORDS=TRAFFIC_BLOCK_UA_KEYWORDS,
    CLOUDFLARE_IP_RANGES=CLOUDFLARE_IP_RANGES,
)
app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1)

EMBED_MAX_DEPTH = 2
EMBED_MAX_COUNT = 10
_EMBED_RE = re.compile(r"^@(entry|item):(\S+?)(?:#([A-Za-z0-9._-]+))?\s*$")

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
        '  <ol style="list-style:none;margin:0.5rem 0;padding-inline-start:0;">'
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
    code_spans = {}

    def _extract_code(m):
        key = f"__CODE{len(code_spans)}__"
        code_spans[key] = m.group(0)
        return key

    # temporarily mask inline code so hashtags inside are untouched
    html = re.sub(r"<code[^>]*>.*?</code>", _extract_code, html, flags=re.S)

    def _hashtag_repl(match):
        orig_tag = match.group(1)
        tag_lc = orig_tag.lower()
        href = tags_href(tag_lc)
        return f'<a href="{href}" style="text-decoration:none;color:{theme_col};border-bottom:0.1px dotted currentColor;">#{orig_tag}</a>'

    html = HASH_LINK_RE.sub(_hashtag_repl, html)
    for k, v in code_spans.items():
        html = html.replace(k, v, 1)
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


def _strip_embed_lines(text: str | None) -> str:
    """
    Drop lines that are pure embed markers (@entry:… / @item:…).
    """
    if not text:
        return ""
    out = []
    for ln in (text or "").splitlines():
        if _EMBED_RE.match(ln.strip()):
            continue
        out.append(ln)
    return "\n".join(out)


def _non_code_lines(text: str | None):
    """Yield lines outside fenced code blocks."""
    in_code, fence = False, ""
    for ln in (text or "").splitlines():
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
        yield ln


def _strip_code_blocks(text: str | None) -> str:
    """
    Remove fenced + inline code spans so backlink detection ignores them.
    """
    if not text:
        return ""
    return "\n".join(_CODE_SPAN_RE.sub("", ln) for ln in _non_code_lines(text))


def _contains_slug_outside_code(text: str | None, slug: str) -> bool:
    """True if slug remains after dropping fenced/inline code."""
    if not text or not slug:
        return False
    return slug in _strip_code_blocks(text)


def _has_item_embed(body: str | None, slug: str) -> bool:
    """True if body contains an @item:slug embed outside code fences."""
    for ln in _non_code_lines(body):
        m = _EMBED_RE.match(ln.strip())
        if not m or m.group(1) != "item":
            continue
        target_slug, _, parse_err = _parse_embed_target(m.group(2), m.group(3))
        if not parse_err and target_slug == slug:
            return True
    return False


TEMPL_ITEM_EMBED = """
<div class="entry-embed entry-embed--item" data-item="{{ item['slug'] }}">
  <div style="display:flex;align-items:center;gap:.75rem;flex-wrap:wrap;">
    <div style="display:flex;align-items:center;gap:.5rem;flex-wrap:wrap;font-weight:700;">
      {% if item_url %}
      <a href="{{ item_url }}" style="color:inherit;border-bottom:none;display:inline-flex;align-items:center;gap:.35rem;">
        <span>{{ item['title'] }}{% if year %} ({{ year }}){% endif %}</span>
      </a>
      {% else %}
      <span>{{ item['title'] }}{% if year %} ({{ year }}){% endif %}</span>
      {% endif %}
      {% if rating_value %}
        <span aria-label="Score {{ rating_value }} of 5"
              style="display:inline-flex;align-items:center;color:{{ theme_color() }};font-size:1.2rem;letter-spacing:1px;white-space:nowrap;">
            {{ "★" * rating_value }}
        </span>
      {% endif %}
    </div>
  </div>

  {% if meta %}
  <div class="entry-embed__body">
    <ul  style="display:flex;align-items:flex-start;gap:1rem;
                list-style:none;padding:0;margin:0;font-size:.9em;color:#aaa;">
      {% for r in meta if is_b64_image(r.k, r.v) or is_url_image(r.k, r.v) %}
      <li style="float:left;margin:.65em .75rem .75rem 0;">
        <img src="{% if is_b64_image(r.k, r.v) %}data:image/webp;base64,{{ r.v }}{% else %}{{ r.v }}{% endif %}"
             alt="{{ item['title'] }}"
             style="width:135px;max-width:100%;
                    border:1px solid #555;margin:0;">
      </li>
      {% endfor %}

      <li style="flex:1;">
        <ul style="list-style:none;padding:0;margin:0;">
        {% for r in meta if not is_b64_image(r.k, r.v) and not is_url_image(r.k, r.v) %}
          <li style="margin:.2em 0;">
            <strong>{{ r.k|smartcap }}:</strong>
            {% set tokens = meta_search_tokens(item['item_type'], r.k, r.v) %}
            {% if tokens %}
              {% for tok in tokens %}
                <a href="{{ url_for('search', q=tok.query) }}"
                   style="color:#ccc;border-bottom:0.1px dotted currentColor;text-decoration:none;">
                  {{ tok.label|mdinline }}
                </a>{% if not loop.last %}<span aria-hidden="true"> / </span>{% endif %}
              {% endfor %}
            {% else %}
              {{ r.v|mdinline }}
            {% endif %}
          </li>
        {% endfor %}
        </ul>
      </li>
    </ul>
  </div>
  {% endif %}

  <div class="entry-embed__footer" style="color:#aaa;">
    {% if verb %}
      <span class="entry-embed__pill">{{ verb|smartcap }}</span>
    {% endif %}
    <span class="entry-embed__pill">{{ item['item_type']|smartcap }}</span>
  </div>
</div>
"""


def render_item_embed(slug: str, *, ctx: dict | None = None) -> str:
    """
    Resolve @item:slug embeds into item metadata cards.
    """
    slug, section, parse_err = _parse_embed_target(slug, None)
    if parse_err:
        return _embed_error(parse_err)
    if section:
        return _embed_error("item embeds do not support sections")

    use_external = bool(getattr(g, "_absolute_links", False))
    ctx = ctx or _get_embed_ctx()
    ctx.setdefault("stack", set())
    ctx.setdefault("depth", 0)
    ctx.setdefault("count", 0)

    if ctx["count"] >= EMBED_MAX_COUNT:
        return _embed_error("too many embeds in one entry")

    target_key = f"item:{slug}"
    if target_key in ctx["stack"]:
        return _embed_error("circular embed detected")
    if ctx["depth"] >= EMBED_MAX_DEPTH:
        return _embed_error("embed depth limit reached")

    db = get_db()
    ensure_item_rating_column(db)
    row = db.execute(
        "SELECT id, title, slug, item_type, rating FROM item WHERE slug=?", (slug,)
    ).fetchone()
    if not row:
        return _embed_error(f"item '{slug}' not found")

    meta = db.execute(
        """
        SELECT k, v
          FROM item_meta
         WHERE item_id=?
         ORDER BY ord, LOWER(k)
        """,
        (row["id"],),
    ).fetchall()

    verb_row = db.execute(
        """
        SELECT ei.verb
          FROM entry_item ei
          JOIN entry e ON e.id = ei.entry_id
         WHERE ei.item_id=?
         ORDER BY e.created_at DESC
         LIMIT 1
        """,
        (row["id"],),
    ).fetchone()
    verb = verb_row["verb"] if verb_row else None
    verb_slug = kind_to_slug(verb) if verb else None
    item_url = (
        url_for(
            "item_detail",
            verb=verb_slug,
            item_type=row["item_type"],
            slug=row["slug"],
            _external=use_external,
        )
        if verb_slug
        else None
    )
    rating_value = int(row["rating"]) if row["rating"] is not None else 0
    year = ""
    for r in meta:
        if (r["k"] or "").lower() == "date" and r["v"]:
            year = (r["v"] or "")[:4]
            break

    ctx["stack"].add(target_key)
    ctx["depth"] += 1
    ctx["count"] += 1
    try:
        return render_template_string(
            TEMPL_ITEM_EMBED,
            item=row,
            meta=meta,
            rating_value=rating_value,
            item_url=item_url,
            year=year,
            verb=verb,
        )
    finally:
        ctx["stack"].discard(target_key)
        ctx["depth"] -= 1


def render_entry_embed(
    slug: str, section: str | None, *, ctx: dict | None = None
) -> str:
    """
    Resolve @entry:slug embeds, optionally scoped to a heading section.
    """
    use_external = bool(getattr(g, "_absolute_links", False))
    is_rss = use_external  # treat absolute-link renders as feed/rich preview

    def _item_ctx(entry_id: int):
        return (
            get_db()
            .execute(
                """
                SELECT i.title   AS item_title,
                       i.slug    AS item_slug,
                       i.item_type,
                       ei.action AS item_action,
                       ei.progress,
                       MIN(CASE
                            WHEN im.k = 'date'
                                 AND LENGTH(im.v) >= 4
                            THEN SUBSTR(im.v, 1, 4)
                       END)      AS item_year
                  FROM entry_item ei
                  JOIN item      i  ON i.id = ei.item_id
                  LEFT JOIN item_meta im ON im.item_id = i.id
                 WHERE ei.entry_id=?
              GROUP BY i.id, ei.action, ei.progress
                 LIMIT 1
                """,
                (entry_id,),
            )
            .fetchone()
        )

    def _checkin_title(kind: str, itm) -> str:
        label = smartcap(itm["item_action"] or kind)
        base = f"{label}: {itm['item_title'] or itm['item_slug']}"
        extras = [p for p in (itm["progress"], itm["item_year"]) if p]
        if extras:
            base += f" ({' · '.join(extras)})"
        return base

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

    target_key = f"entry:{slug}"
    root_key = f"entry:{ctx.get('root')}" if ctx.get("root") else None
    if target_key == root_key or target_key in ctx["stack"]:
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
    ctx["stack"].add(target_key)
    ctx["depth"] += 1
    ctx["count"] += 1
    try:
        inner_html = _render_markdown(clean, ctx=ctx, renderer=_markdown_renderer())
    finally:
        ctx["stack"].discard(target_key)
        ctx["depth"] -= 1

    url = url_for(
        "entry_detail",
        kind_slug=kind_to_slug(row["kind"]),
        entry_slug=row["slug"],
        _external=use_external,
    )
    view_url = f"{url}#{section_key}" if section_key else url
    ts = ts_filter(row["created_at"])
    section_label = ""
    kind_url = url_for(
        "by_kind", slug=kind_to_slug(row["kind"]), _external=use_external
    )

    title_html = ""
    if row["title"]:
        title_html = (
            f'<div style="font-weight:700;">'
            f'<a href="{view_url}" style="color:inherit;border-bottom:none;">'
            f"{escape(row['title'])}"
            "</a>"
            "</div>"
        )

    if is_rss:
        # keep feed embeds lightweight and clearly marked
        itm = _item_ctx(row["id"])
        if row["kind"] in VERB_KINDS and itm:
            label = _checkin_title(row["kind"], itm)
        else:
            label = row["title"] or row["slug"]
        return (
            '<blockquote class="entry-embed-rss" '
            'style="border-left:4px solid #666;padding-left:.75em;margin:1em 0;">'
            f'<div style="font-weight:700;"><a href="{view_url}">{escape(label)}</a></div>'
            f"<div>{inner_html}</div>"
            f'<div style="font-size:.85em;color:#888;">Published {escape(ts)}</div>'
            "</blockquote>"
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
    absolute_links: bool = False,
) -> str:
    """
    Shared Markdown renderer used across filters and RSS.
    """
    clean = _drop_caret_meta((text or ""))
    ctx = _new_embed_ctx(source_slug)
    prev_abs = getattr(g, "_absolute_links", False)
    g._absolute_links = absolute_links
    try:
        html = _render_markdown(clean, ctx=ctx, renderer=renderer)
    finally:
        g._absolute_links = prev_abs
    return _postprocess_html(html, theme_col=theme_color())


def entry_images(body: str | None, slug: str | None = None) -> list[dict[str, str]]:
    """Return list of image dicts (src, alt) from rendered markdown/html."""
    html = render_markdown_html(body, source_slug=slug)
    imgs: list[dict[str, str]] = []
    for m in IMG_TAG_RE.finditer(html):
        src = m.group("src")
        if not src:
            continue
        imgs.append({"src": src, "alt": m.group("alt") or ""})
    return imgs


class EntryEmbedPreprocessor(markdown.preprocessors.Preprocessor):
    """Replace @entry:slug / @item:slug references with embed HTML blocks."""

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

            kind, slug, section = m.group(1), m.group(2), m.group(3)
            if kind == "item":
                out.append(render_item_embed(slug, ctx=ctx))
            else:
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
_RATING_COL_CHECKED = False


def get_db():
    if "db" not in g:
        g.db = sqlite3.connect(app.config["DATABASE"])
        g.db.execute("PRAGMA busy_timeout = 2000;")  # reduce transient lock errors
        g.db.execute("PRAGMA foreign_keys = ON;")
        g.db.row_factory = sqlite3.Row
        g.db.create_function("strip_caret", 1, strip_caret)
        g.db.create_function("link_host", 1, link_host)
        g.photo_kind_normalized = False
        ensure_ip_blocklist_table(db=g.db)
    if not getattr(g, "photo_kind_normalized", False):
        normalize_photo_kinds(db=g.db)
        g.photo_kind_normalized = True
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
            kind        TEXT NOT NULL                  -- say | photo | post | pin | page
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
                   ('site_tagline',''),
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
            title       TEXT NOT NULL,
            rating      INTEGER                      -- personal 0–5 score
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

        ------------------------------------------------------------
        -- 10. IP blocklist
        ------------------------------------------------------------
        CREATE TABLE IF NOT EXISTS ip_blocklist (
            ip         TEXT PRIMARY KEY,
            reason     TEXT,
            created_at TEXT NOT NULL,
            expires_at TEXT
        );
        """
    )
    db.commit()


def ensure_item_rating_column(db) -> None:
    """
    Add the item.rating column if it does not exist (older DBs).
    """
    global _RATING_COL_CHECKED
    if _RATING_COL_CHECKED:
        return

    cols = {row["name"] for row in db.execute("PRAGMA table_info(item)")}
    if "rating" not in cols:
        db.execute("ALTER TABLE item ADD COLUMN rating INTEGER")
        db.commit()
    _RATING_COL_CHECKED = True


def ensure_ip_blocklist_table(db) -> None:
    """Create ip_blocklist table if missing (upgrade path)."""
    global _IP_BLOCKLIST_CHECKED
    if _IP_BLOCKLIST_CHECKED:
        return
    cols = {
        row["name"]
        for row in db.execute(
            "SELECT name FROM sqlite_master WHERE type='table' AND name='ip_blocklist'"
        )
    }
    if "ip_blocklist" not in cols:
        db.execute(
            """
            CREATE TABLE IF NOT EXISTS ip_blocklist (
                ip         TEXT PRIMARY KEY,
                reason     TEXT,
                created_at TEXT NOT NULL,
                expires_at TEXT
            )
            """
        )
        db.commit()
    _IP_BLOCKLIST_CHECKED = True


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


def apply_photo_kind(kind: str, tags: set[str]) -> str:
    """
    Treat #photo-like tags as a hint to promote plain says to the photo kind.
    """
    if kind not in ("say", "photo"):
        return kind
    return "photo" if tags & PHOTO_TAG_SET else "say"


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


def _read_env_file() -> dict[str, str]:
    env = {}
    if not ENV_FILE.exists():
        return env
    for ln in ENV_FILE.read_text().splitlines():
        ln = ln.strip()
        if not ln or ln.startswith("#") or "=" not in ln:
            continue
        k, v = ln.split("=", 1)
        env[k.strip()] = v.strip()
    return env


def _write_env_file(env: dict[str, str]) -> None:
    if env:
        lines = [f"{k}={v}" for k, v in sorted(env.items()) if v]
        ENV_FILE.write_text("\n".join(lines) + "\n")
    elif ENV_FILE.exists():
        ENV_FILE.write_text("")
    try:
        ENV_FILE.chmod(0o600)
    except OSError:
        pass


def merge_env(updates: dict[str, str]) -> dict[str, str]:
    """Merge *updates* into both the process env and the .env file."""
    env = _read_env_file()
    changed = False
    for k, v in updates.items():
        if not v:
            continue
        if env.get(k) != v:
            env[k] = v
            changed = True
        if os.environ.get(k) != v:
            os.environ[k] = v
    if changed:
        _write_env_file(env)
    return env


def r2_config() -> dict[str, str]:
    env_file = _read_env_file()
    cfg = {k: (os.environ.get(k) or env_file.get(k) or "").strip() for k in R2_ENV_KEYS}
    return {k: v for k, v in cfg.items() if v}


def r2_is_configured(cfg: dict[str, str] | None = None) -> bool:
    cfg = cfg or r2_config()
    return all(cfg.get(k) for k in R2_REQUIRED_KEYS)


def _r2_client(cfg: dict[str, str]):
    endpoint = (
        cfg.get("R2_ENDPOINT")
        or f"https://{cfg['R2_ACCOUNT_ID']}.r2.cloudflarestorage.com"
    )
    return boto3.client(
        "s3",
        endpoint_url=endpoint,
        region_name="auto",
        aws_access_key_id=cfg["R2_ACCESS_KEY_ID"],
        aws_secret_access_key=cfg["R2_SECRET_ACCESS_KEY"],
    )


def r2_object_url(cfg: dict[str, str], key: str) -> str:
    base = cfg.get("R2_PUBLIC_BASE")
    if base:
        base = base.rstrip("/")
        return f"{base}/{key.lstrip('/')}"
    return f"https://{cfg['R2_BUCKET']}.{cfg['R2_ACCOUNT_ID']}.r2.cloudflarestorage.com/{key.lstrip('/')}"


def _is_urlish(val: str) -> bool:
    val = val.strip().lower()
    return val.startswith(("http://", "https://", "//"))


def is_b64_image(k: str, v: str) -> bool:
    if k.lower() not in {"cover", "img", "poster"}:
        return False
    val = (v or "").strip()
    if _is_urlish(val):
        return False
    if val.startswith("data:image/"):
        return True
    return len(val) > 100


def is_url_image(k: str, v: str) -> bool:
    if k.lower() not in {"cover", "img", "poster"}:
        return False
    return _is_urlish(v or "")


def linkable_meta(k: str | None, v: str | None) -> bool:
    """
    Heuristic: only auto-link short, human-name fields (authors, publishers, …)
    while skipping dates, identifiers, and URL-ish values.
    """
    key = (k or "").strip().lower()
    val = (v or "").strip()
    if not key or not val:
        return False
    if key in {"date", "year", "link", "url", "href"}:
        return False
    if key.startswith(("date", "year")):
        return False
    if any(
        token in key
        for token in (
            "isbn",
            "issn",
            "asin",
            "ean",
            "upc",
            "gtin",
            "doi",
            "uuid",
            "guid",
            "id",
        )
    ):
        return False
    if key in {"cover", "img", "poster"}:
        return False
    if _is_urlish(val) or "](" in val:  # already a link/markdown link
        return False
    if "\n" in val or len(val) > 120:  # avoid long notes/paragraphs
        return False
    if not any(ch.isalpha() for ch in val):  # skip number-only values
        return False
    return True


def meta_search_query(
    item_type: str | None, key: str | None, val: str | None, *, validate: bool = True
) -> str | None:
    """
    Build `<item>:<meta_key>:"<meta_val>"` search query when linkable, else None.
    """
    if validate and not linkable_meta(key, val):
        return None
    itype = (item_type or "").strip().lower()
    if not itype:
        return None
    k = (key or "").strip().lower()
    term = " ".join((val or "").split())
    term = term.replace('"', "")  # keep parser simple
    if not term:
        return None
    return f'{itype}:{k}:"{term}"'


def meta_search_tokens(
    item_type: str | None, key: str | None, val: str | None
) -> list[dict[str, str]]:
    """
    Split multi-value meta fields (e.g., "A / B / C") into individual search links.
    """
    if not linkable_meta(key, val):
        return []
    itype = (item_type or "").strip().lower()
    if not itype:
        return []
    key_norm = (key or "").strip().lower()
    tokens = []
    for part in re.split(r"\s*/\s*", val or ""):
        part = part.strip()
        if not part or not linkable_meta(key_norm, part):
            continue
        q = meta_search_query(itype, key_norm, part, validate=False)
        if q:
            tokens.append({"label": part, "query": q})
    return tokens


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
    """
    Return a **lower-cased** set of #tags found in *text*, ignoring code blocks.
    """
    if not text:
        return set()

    out_lines: list[str] = []
    in_code, fence = False, ""
    for ln in text.splitlines():
        m_f = _CODE_FENCE_RE.match(ln)
        if m_f:
            tok = m_f.group(1)
            if not in_code:
                in_code, fence = True, tok
            elif tok == fence:
                in_code, fence = False, ""
            continue  # skip fence lines

        if in_code:
            continue  # skip content inside fenced code

        # strip inline `code` spans so hashtags inside are ignored
        out_lines.append(re.sub(r"`[^`]*`", "", ln))

    clean = "\n".join(out_lines)
    return {m.lower() for m in TAG_RE.findall(clean)}


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


def normalize_photo_kinds(*, db):
    """
    Keep entry.kind in sync with photo-tag hints:
    - promote says that carry a photo tag → photo
    - demote photos that lost all photo tags → say
    """
    if not PHOTO_TAGS:
        return

    placeholders = ",".join("?" * len(PHOTO_TAGS))
    tag_params = PHOTO_TAGS

    try:
        promote = db.execute(
            f"""
            UPDATE entry
               SET kind='photo'
             WHERE kind='say'
               AND id IN (
                   SELECT et.entry_id
                     FROM entry_tag et
                     JOIN tag t ON t.id = et.tag_id
                    WHERE LOWER(t.name) IN ({placeholders})
               )
            """,
            tag_params,
        )

        demote = db.execute(
            f"""
            UPDATE entry
               SET kind='say'
             WHERE kind='photo'
               AND id NOT IN (
                   SELECT et.entry_id
                     FROM entry_tag et
                     JOIN tag t ON t.id = et.tag_id
                    WHERE LOWER(t.name) IN ({placeholders})
               )
            """,
            tag_params,
        )
    except sqlite3.OperationalError:
        return

    if promote.rowcount or demote.rowcount:
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


# ── compact one-liner ([verb:]action:item:identifier[:progress]) ─────
CARET_COMPACT_RE = re.compile(
    r"""
    ^\^
    (?:(?:"([^"]+)"|([a-z0-9_-]+))\:)?    # ➊ verb (optional; grp 1 quoted, 2 plain)
    (?:"([^"]+)"|([a-z0-9_-]+)) :         # ➋ action (grp 3/4)
    (?:"([^"]+)"|([a-z0-9_-]+)) :         # ➌ item_type (grp 5/6)
    (?:
        "([^"]+)"                         # ➍ title — quoted          (grp 7)
      | ([^":\s]+)                        #     title — **un-quoted** (grp 8)
      | ([0-9a-f-]{36}|[a-z0-9_-]+)       #     slug/uuid             (grp 9)
    )
    (?:\s*:\s*(?:"([^"]+)"|([^":\s]+)))?  # ➎ progress (grp 10/11)
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
_CODE_SPAN_RE = re.compile(r"`+[^`]*`+")


def _resolve_verb(
    action_lc: str,
    *,
    explicit: str | None = None,
    verb_hint: str | None = None,
    allow_unknown_actions: bool = False,
) -> tuple[str | None, str | None]:
    """
    Return (verb, error_msg). If the action maps to multiple verbs and no
    disambiguation is available, verb is None and error_msg explains why.
    """
    explicit_lc = (explicit or "").lower()
    if explicit_lc:
        if explicit_lc not in VERB_MAP:
            return None, f"verb '{explicit_lc}' is not supported"
        matches = [vb for vb, acts in VERB_MAP.items() if action_lc in acts]
        if allow_unknown_actions:
            return explicit_lc, None
        if matches and explicit_lc not in matches:
            return (
                None,
                f"action '{action_lc}' is not valid for verb '{explicit_lc}'",
            )
        if not matches:
            return (
                None,
                f"action '{action_lc}' is unknown for verb '{explicit_lc}'",
            )
        return explicit_lc, None

    hint_lc = (verb_hint or "").lower()
    matches = [vb for vb, acts in VERB_MAP.items() if action_lc in acts]

    if allow_unknown_actions and hint_lc in VERB_MAP:
        return hint_lc, None

    if hint_lc in VERB_MAP:
        if not matches or hint_lc in matches:
            return hint_lc, None

    if len(matches) == 1:
        return matches[0], None
    if len(matches) > 1:
        verb_list = ", ".join(matches)
        return (
            None,
            f"action '{action_lc}' exists for multiple verbs ({verb_list}); "
            "prefix with a verb, e.g., ^verb:action:…",
        )

    if hint_lc in VERB_MAP:
        return hint_lc, None
    return None, None


def parse_trigger(
    text: str, *, verb_hint: str | None = None, allow_unknown_actions: bool = False
) -> tuple[str, list[dict], list[str]]:
    """
    Parse caret-trigger lines from free text and return a tuple of
    (rewritten_body, blocks, errors).

    Invalid or incomplete caret snippets are treated as plain text and
    ignored for block extraction, but a message noting the validation
    error is collected so callers can surface it to the user. A valid
    block must include:
    - item_type (non-empty)
    - action and a verb from VERB_KINDS (explicit, inferred from the action,
      or provided via *verb_hint*)
    - either a title or a slug/uuid (so an item can be resolved/created)
    The compact syntax also accepts an optional leading verb to disambiguate
    actions that are shared across verbs (e.g., ^watch:abandoned:movie:"Foo").
    """
    errors: list[str] = []
    verb_hint_lc = (verb_hint or "").lower()

    def _block_error(blk: dict) -> str | None:
        # item_type present
        if not blk.get("item_type"):
            return "caret block is missing an item type"

        # action present → derive verb the same way parse does
        action_lc = (blk.get("action") or "").lower()
        verb, err_msg = _resolve_verb(
            action_lc,
            explicit=blk.get("_explicit_verb"),
            verb_hint=verb_hint_lc,
            allow_unknown_actions=allow_unknown_actions,
        )
        if not verb:
            return err_msg or "caret block has an unknown action/verb"

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
            first_tok = m.group(1) or m.group(2)
            action_tok = m.group(3) or m.group(4)
            item_tok = m.group(5) or m.group(6)
            title_tok = m.group(7) or m.group(8)  # quoted OR un-quoted
            slug_tok = m.group(9)  # stays the same meaning
            prog = m.group(10) or m.group(11)  # quoted OR un-quoted

            # Decide mapping based on whether the first token is a known verb
            is_explicit_verb = first_tok and first_tok.lower() in VERB_MAP
            if is_explicit_verb:
                explicit_verb = first_tok
                action = action_tok
                item_type = item_tok
                title = title_tok or None
                slug = slug_tok
                progress_val = prog
            elif first_tok:
                explicit_verb = None
                action = first_tok or action_tok
                item_type = action_tok
                title = item_tok or None
                slug = slug_tok
                progress_val = prog or title_tok
            else:
                explicit_verb = None
                action = action_tok
                item_type = item_tok
                title = title_tok or None
                slug = slug_tok
                progress_val = prog

            item_type_norm = normalize_item_type(item_type)
            action_lc = (action or "").lower()
            verb, err_msg = _resolve_verb(
                action_lc,
                explicit=explicit_verb,
                verb_hint=verb_hint_lc,
                allow_unknown_actions=allow_unknown_actions,
            )
            blk = {
                "verb": verb,
                "_explicit_verb": explicit_verb,
                "action": action_lc,
                "item_type": item_type_norm,
                "title": title,
                "slug": slug,
                "progress": progress_val,
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
            err = err_msg or _block_error(blk)
            if not err:
                out_blocks.append(blk)
                new_lines.append(f"^{item_type_norm}:$PENDING${len(out_blocks) - 1}$")
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
                "_explicit_verb": None,
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
                    tmp["_explicit_verb"] = v
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

            tmp["item_type"] = normalize_item_type(tmp["item_type"]) or None
            action_lc = (tmp["action"] or "").lower()
            tmp["verb"], verb_err = _resolve_verb(
                action_lc,
                explicit=tmp["verb"],
                verb_hint=verb_hint_lc,
                allow_unknown_actions=allow_unknown_actions,
            )
            err = verb_err or _block_error(tmp)
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
    item_type_norm = normalize_item_type(item_type)
    if not item_type_norm:
        raise ValueError("item_type missing or empty")

    if slug:
        row = db.execute(
            "SELECT id, slug, uuid, item_type FROM item WHERE slug=?", (slug,)
        ).fetchone()
        if row:
            if row["item_type"] != item_type_norm:
                db.execute(
                    "UPDATE item SET item_type=? WHERE id=?", (item_type_norm, row["id"])
                )
            return row["id"], row["slug"], row["uuid"]
        if UUID4_RE.fullmatch(slug):
            row = db.execute(
                "SELECT id, slug, uuid, item_type FROM item WHERE uuid=?", (slug,)
            ).fetchone()
            if row:
                if row["item_type"] != item_type_norm:
                    db.execute(
                        "UPDATE item SET item_type=? WHERE id=?",
                        (item_type_norm, row["id"]),
                    )
                return row["id"], row["slug"], row["uuid"]

    if title is None:
        raise ValueError("slug not found and no title given → cannot create item")

    uuid_ = str(uuid.uuid4())
    slug = slug or uuid_
    db.execute(
        "INSERT INTO item (uuid, slug, item_type, title) VALUES (?,?,?,?)",
        (uuid_, slug, item_type_norm, title),
    )
    item_id = db.execute("SELECT last_insert_rowid()").fetchone()[0]

    if update_meta:
        for ord, (k, v) in enumerate(meta.items(), start=1):
            db.execute(
                "INSERT OR REPLACE INTO item_meta (item_id,k,v,ord) VALUES (?,?,?,?)",
                (item_id, k, v, ord),
            )
    return item_id, slug, uuid_


def is_completed_action(action: str | None) -> bool:
    """
    True if an action represents a completed state (e.g., read, watched).
    """
    if not action:
        return False
    raw = action.strip().lower()
    if not raw:
        return False

    compact = re.sub(r"[\s_-]+", "", raw)
    if compact in {"read", "reread"}:
        return True
    if raw == "finished":
        return True
    return compact.endswith("ed")


def has_kind(kind: str) -> bool:
    """True if at least one entry of this kind exists."""
    row = (
        get_db().execute("SELECT 1 FROM entry WHERE kind=? LIMIT 1", (kind,)).fetchone()
    )
    return bool(row)


def has_stats() -> bool:
    """True if there is at least one non-page entry (for nav visibility)."""
    row = get_db().execute("SELECT 1 FROM entry WHERE kind!='page' LIMIT 1").fetchone()
    return bool(row)


VERB_KINDS = tuple(VERB_MAP.keys())
VERB_KINDS_LOWER = tuple(k.lower() for k in VERB_KINDS)


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
    """Return the verbose caret block string for one check-in."""

    def q(s):
        return f'"{s}"' if " " in s else s  # quote if it contains spaces

    parts = [
        f"^uuid:{uuid_}",
        f"^item:{blk['item_type']}",
        f"^title:{q(blk['title'])}" if blk["title"] else "",
        f"^action:{blk['action']}",
        f"^verb:{blk['verb']}",
        f"^progress:{q(blk['progress'])}" if blk["progress"] else "",
    ]
    return "\n".join(p for p in parts if p)


def upload_icon() -> Markup:
    """Inline camera icon used on upload buttons."""
    return Markup(UPLOAD_ICON_SVG)


def link_host(url: str | None) -> str:
    """Return the hostname (sans www) for display next to external links."""
    if not url:
        return ""
    try:
        parsed = urlparse(url if "://" in url else f"//{url}", scheme="https")
        host = parsed.netloc
    except ValueError:
        return ""
    if host.startswith("www."):
        host = host[4:]
    return host.lower()


def pins_from_href(host: str | None = "") -> str:
    """Build a filter URL for pins by source host."""
    norm = link_host(host or "")
    tag_param = (request.args.get("tag", "") or "").strip()
    params: dict[str, str] = {}
    if not norm:
        if tag_param:
            params["tag"] = tag_param
        return url_for("by_kind", slug=kind_to_slug("pin"), **params)
    params["from"] = norm
    if tag_param:
        params["tag"] = tag_param
    return url_for("by_kind", slug=kind_to_slug("pin"), **params)


def _csrf_token() -> str:
    """One token per session (rotates when the cookie does)."""
    return session.get("csrf", "")


# Expose helpers to templates
app.jinja_env.globals.update(kind_to_slug=kind_to_slug, get_setting=get_setting)
app.jinja_env.globals["upload_icon"] = upload_icon
app.jinja_env.globals["PAGE_DEFAULT"] = PAGE_DEFAULT
app.jinja_env.globals["entry_tags"] = lambda eid: entry_tags(eid, db=get_db())
app.jinja_env.globals["entry_projects"] = lambda eid: entry_projects(eid, db=get_db())
app.jinja_env.globals["nav_pages"] = nav_pages
app.jinja_env.globals["version"] = __version__
app.jinja_env.globals.update(
    has_kind=has_kind,
    has_stats=has_stats,
    pins_from_href=pins_from_href,
    active_verbs=active_verbs,
    verb_kinds=VERB_KINDS,
    tags_slug=tags_slug,
    tags_href=tags_href,
    settings_href=settings_href,
)
app.jinja_env.globals["csrf_token"] = _csrf_token
app.jinja_env.globals["is_b64_image"] = is_b64_image
app.jinja_env.globals["link_host"] = link_host
app.jinja_env.globals["linkable_meta"] = linkable_meta
app.jinja_env.globals["meta_search_query"] = meta_search_query
app.jinja_env.globals["meta_search_tokens"] = meta_search_tokens


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
               src.title, src.created_at, src.body
          FROM entry_fts                      -- trigram index
          JOIN entry src    ON src.id = entry_fts.rowid
          JOIN entry target ON target.slug IN ({q_marks})
         WHERE entry_fts MATCH ('\"' || target.slug || '\"')
           AND src.id != target.id
    """
    rows = db.execute(sql, tuple(slug_to_id)).fetchall()

    out: dict[int, list] = {e["id"]: [] for e in entries}
    for r in rows:
        if not _contains_slug_outside_code(r["body"], r["target_slug"]):
            continue
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
        "r2_enabled": r2_is_configured,
        "is_url_image": is_url_image,
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
html{font-size:62.5%;font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,"Helvetica Neue",Arial,"Noto Sans",sans-serif}body{font-size:1.8rem;line-height:1.618;max-width:38em;margin:auto;color:#c9c9c9;background-color:#222222;padding:13px}@media (max-width:684px){body{font-size:1.75rem}pre,pre>code{white-space:pre-wrap;word-break:break-word;}}@media (max-width:382px)@media (max-width:560px){.meta {flex:0 0 100%;order:1;margin-left:0;text-align:left;}}{body{font-size:1.35rem}}h1,h2,h3,h4,h5,h6{line-height:1.1;font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,"Helvetica Neue",Arial,"Noto Sans",sans-serif;font-weight:700;margin-top:3rem;margin-bottom:1.5rem;overflow-wrap:break-word;word-wrap:break-word;-ms-word-break:break-all;word-break:break-word}h1{font-size:2.35em}h2{font-size:1.7em}h3{font-size:1.55em}h4{font-size:1.4em}h5{font-size:1.25em}h6{font-size:1.1em}p{margin-top:0px;margin-bottom:2.5rem;hyphens:auto}small,sub,sup{font-size:75%}hr{border-color:#ffffff}a{color:#ffffff;text-decoration:underline;text-decoration-color:transparent;text-decoration-thickness:2px;text-underline-offset:0.18em;}a:hover{color:#c9c9c9;text-decoration-color:#c9c9c9;}.e-content p>a,.e-content li>a{color:inherit;text-decoration-thickness:1px;text-underline-offset:0.18em;text-decoration-color:inherit!important;text-decoration-style:dotted!important;}.e-content p>a:hover,.e-content li>a:hover{text-decoration-color:#fff!important;}}ul{padding-left:1.4em;margin-top:0px;margin-bottom:2.5rem}li{margin-bottom:0.4em}blockquote{margin-left:0px;margin-right:0px;padding-left:1em;padding-top:0.8em;padding-bottom:0.8em;padding-right:0.8em;border-left:5px solid #ffffff;margin-bottom:2.5rem;background-color:#4a4a4a}blockquote p{margin-bottom:0.75em}img,video{height:auto;max-width:100%;margin-top:0px;margin-bottom:0px}pre{background-color:#4a4a4a;display:block;padding:1em;overflow-x:auto;margin-top:0px;margin-bottom:2.5rem;font-size:0.9em}code,kbd,samp{font-size:0.9em;padding:0 0.5em;background-color:#4a4a4a;white-space:pre-wrap;word-break:break-word}pre>code{padding:0;background-color:transparent;white-space:pre;font-size:1em}table{text-align:justify;width:100%;border-collapse:collapse;margin-bottom:2rem}td,th{padding:0.5em;border-bottom:1px solid #4a4a4a}input,textarea{border:1px solid #c9c9c9}input:focus,textarea:focus{border:1px solid #ffffff}textarea{width:100%}.button,button,input[type=submit],input[type=reset],input[type=button],input[type=file]::file-selector-button{display:inline-block;padding:5px 10px;text-align:center;text-decoration:none;white-space:nowrap;background-color:#ffffff;color:#222222;border-radius:1px;border:1px solid #ffffff;cursor:pointer;box-sizing:border-box}.button[disabled],button[disabled],input[type=submit][disabled],input[type=reset][disabled],input[type=button][disabled],input[type=file]::file-selector-button[disabled]{cursor:default;opacity:0.5}.button:hover,button:hover,input[type=submit]:hover,input[type=reset]:hover,input[type=button]:hover,input[type=file]::file-selector-button:hover{background-color:#c9c9c9;color:#222222;outline:0}.button:focus-visible,button:focus-visible,input[type=submit]:focus-visible,input[type=reset]:focus-visible,input[type=button]:focus-visible,input[type=file]::file-selector-button:focus-visible{outline-style:solid;outline-width:2px}textarea,select,input{color:#c9c9c9;padding:6px 10px;margin-bottom:10px;background-color:#4a4a4a;border:1px solid #4a4a4a;border-radius:4px;box-shadow:none;box-sizing:border-box}textarea:focus,select:focus,input:focus{border:1px solid #ffffff;outline:0}input[type=checkbox]:focus{outline:1px dotted #ffffff}label,legend,fieldset{display:block;margin-bottom:0.5rem;font-weight:600}p>math[display="block"]{display: block;margin: 1em 0}math[display="block"]:not(:first-child){margin-top: 1.2em}sup.fn{position:relative;display:inline-block;}sup.fn>.fn-ref,.fn-badge{position:relative;z-index:2500;display:inline-flex;align-items:center;justify-content:center;min-width:1rem;max-width:25em;padding:0.2em .4em;min-height:1.5rem;margin:0 0.25em;vertical-align:top;border-radius:.75em;white-space:normal;background:var(--fn-badge-bg,#666); color:#fff;font-size:.65em;line-height:1;cursor:pointer;transition:background .2s ease;text-decoration:none;}sup.fn>.fn-ref:hover{background:var(--fn-badge-bg-hover,#888);text-decoration:none !important;}.fn-popup{position:fixed;left:50%; bottom:0;transform:translate(-50%,100%);width:90vw;max-width:60rem; z-index:3000;max-height:40vh; overflow:auto;background:#222; color:#fff; line-height:1.45;padding:1rem 1.25rem;border:1px solid #444;transition:transform .25s ease;will-change:transform;}.fn-overlay{position:fixed; inset:0;background:transparent;opacity:0; visibility:hidden; pointer-events:none;transition:opacity .25s ease;touch-action:none;-webkit-tap-highlight-color:transparent;z-index:2000}sup.fn .fn-toggle:checked + .fn-ref + .fn-popup{transform:translate(-50%,0);box-shadow:0 -4px 12px rgba(0,0,0,.4);}sup.fn .fn-toggle:checked ~ .fn-overlay{opacity:1; visibility:visible; pointer-events:auto}.math-scroll{overflow-x:auto;overflow-y:hidden;max-width:auto;white-space:nowrap;-webkit-overflow-scrolling:touch}.jump-btn{position:fixed;bottom:1.25rem;right:1.25rem;width:3rem;height:3rem;display:flex;align-items:center;justify-content:center;font-size:1.5rem;line-height:1;border-radius:50%;background:#aaa;color:#000;text-decoration:none;border-bottom:none;box-shadow:0 2px 6px rgba(0,0,0,.3);z-index:1000;opacity:.15;transition:opacity .3s}.jump-btn:hover{opacity:.8;text-decoration:none}.jump-up{display:none}#page-bottom:target~.jump-up{display:flex}#page-bottom:target~.jump-down{display:none}#page-top:target~.jump-down{display:flex}#page-top:target~.jump-up{display:none}a.fn-badge,a.fn-badge:hover,a.fn-badge:focus{border-bottom:none !important;text-decoration:none !important}.entry-embed{border:1px solid #444;border-radius:6px;padding:1rem;margin:1.5rem 0;background:#2a2a2a}.entry-embed__body{margin-top:.5rem}.entry-embed__footer{color:#aaa;font-size:.75em;display:flex;align-items:center;gap:.35rem;flex-wrap:wrap;margin-top:.25rem}.entry-embed__footer a{color:inherit;text-decoration:none;border-bottom:0.1px dotted currentColor}.entry-embed__pill{display:inline-block;padding:.1em .6em;margin-right:.4em;background:#444;color:#fff;border-radius:1em;font-size:.75em;text-transform:capitalize;vertical-align:middle;line-height:1.6}.entry-embed--error{border-color:#b33;background:#331414;color:#f9c0c0}
.skip-link{position:absolute;left:-999px;top:auto;width:1px;height:1px;overflow:hidden}
.skip-link:focus{left:1.5rem;top:1.5rem;width:auto;height:auto;padding:.5rem .85rem;background:#fff;color:#000;border-radius:.25rem;z-index:1100;text-decoration:none;border-bottom:none}
/* Primary nav layout */
.nav-primary{margin-bottom:1rem;display:grid;grid-template-columns:1fr auto;grid-template-areas:"primary auth" "secondary search";align-items:flex-start;column-gap:1.5rem;row-gap:.35rem;font-size:.9em;}
.nav-row{display:flex;align-items:center;gap:1.25rem;flex-wrap:nowrap;white-space:nowrap;overflow-x:auto;padding-bottom:2px;-webkit-overflow-scrolling:touch;}
.nav-row::-webkit-scrollbar{display:none;}
.nav-primary-links{grid-area:primary;}
.nav-secondary-links{grid-area:secondary;}
.nav-auth{grid-area:auth;justify-content:flex-end;align-self:flex-start;}
.nav-search{grid-area:search;justify-content:flex-end;}
.nav-auth,.nav-search{display:flex;}
.nav-row a{display:inline-block;padding-bottom:.08em;text-decoration:underline;text-decoration-color:transparent;text-decoration-thickness:2px;text-underline-offset:.2em;border-bottom:none;}
.nav-row a:hover,.nav-row a:focus-visible{color:#c9c9c9;text-decoration-color:#c9c9c9;}
nav a[aria-current=page]{color:#c9c9c9;text-decoration-color:currentColor;text-decoration-thickness:2px;text-underline-offset:.2em;}
nav a[aria-current=page]:hover,nav a[aria-current=page]:focus-visible{text-decoration-color:currentColor;}
.nav-search form{margin:0;width:auto;}
.nav-search input{width:13rem;margin:0;font-size:.8em;padding:.25em .6em;line-height:1.2;background:#2b2b2b;border:1px solid #555;border-radius:6px;color:#c9c9c9;box-shadow:0 2px 4px rgba(0,0,0,.18);transition:border-color .15s ease,box-shadow .2s ease,background .2s ease;}
.nav-search input:focus{border-color:{{ theme_color() }};background:#242424;box-shadow:0 4px 10px rgba(0,0,0,.3),0 0 0 2px rgba(255,255,255,.04);outline:0;}
.pin-title{font-size:1.3em;margin-bottom:.75rem;}
.pin-host{font-size:.75em;color:#888;margin-left:.35em;white-space:nowrap;}
.pin-host a{color:inherit;text-decoration:none;border-bottom:0.1px dotted currentColor;}
.pin-host a:hover,.pin-host a:focus-visible{color:#c9c9c9;text-decoration-color:currentColor;}
@media (max-width:720px){
.nav-primary{grid-template-columns:1fr auto;grid-template-areas:"primary auth" "secondary secondary" "search search";}
.nav-search{justify-content:flex-start;}
.nav-search form{width:100%;}
.nav-search input{width:100%;}
}
/* writing surfaces */
.writing-area{font-size:1.05em;line-height:1.6;padding:12px 14px;width:100%;min-height:7.5rem;max-height:60vh;background:#2b2b2b;border:1px solid #555;border-radius:8px;box-shadow:0 2px 6px rgba(0,0,0,.18);transition:border-color .15s ease,box-shadow .2s ease,background .2s ease;resize:vertical;overflow:auto;letter-spacing:.01em;caret-color:{{ theme_color() }};}
.writing-area:focus{border-color:{{ theme_color() }};background:#242424;box-shadow:0 4px 12px rgba(0,0,0,.35),0 0 0 2px rgba(255,255,255,.04);}
.writing-area::placeholder{color:#9a9a9a;}
.writing-input{font-size:1.02em;line-height:1.5;padding:10px 12px;width:100%;background:#2b2b2b;border:1px solid #555;border-radius:8px;box-shadow:0 2px 6px rgba(0,0,0,.18);transition:border-color .15s ease,box-shadow .2s ease,background .2s ease;letter-spacing:.01em;}
.writing-input:focus{border-color:{{ theme_color() }};background:#242424;box-shadow:0 4px 12px rgba(0,0,0,.35),0 0 0 2px rgba(255,255,255,.04);outline:0;}
.writing-input::placeholder{color:#9a9a9a;}
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
    <div style="margin-bottom:1rem; font-size:1.9rem; line-height:1.2;">
        <h1 id="page-top" style="display:inline; margin:0; line-height:1;font-size:2.25em">
            <a href="{{ url_for('index') }}" style="color:{{ theme_color() }}; text-decoration:none; border-bottom:none;">{{title or 'po.etr.ist'}}</a>
        </h1>
        {% set tagline = get_setting('site_tagline','').strip() %}
        {% if tagline %}
            <span style="margin-left:.1rem; color:#bcbcbc;">{{ tagline|mdinline('tagline') }}</span>
        {% endif %}
    </div>
    <nav aria-label="Primary" class="nav-primary">
        <div class="nav-row nav-primary-links">
            <a href="{{ url_for('by_kind', slug=kind_to_slug('say')) }}"
            {% if kind=='say' %}aria-current="page"{% endif %}>
            Says</a>
            <a href="{{ url_for('by_kind', slug=kind_to_slug('post')) }}"
            {% if kind=='post' %}aria-current="page"{% endif %}>
            Posts</a>
            <a href="{{ url_for('by_kind', slug=kind_to_slug('pin')) }}"
            {% if kind=='pin' %}aria-current="page"{% endif %}>
            Pins</a>
            <a href="{{ url_for('by_kind', slug=kind_to_slug('photo')) }}"
            {% if kind=='photo' %}aria-current="page"{% endif %}>
            Photos</a>
            <a href="{{ tags_href() }}"
            {% if kind=='tags' %}aria-current="page"{% endif %}>
            Tags</a>
        </div>
        {% if active_verbs() %}
        <div class="nav-row nav-secondary-links">
            {% for v in active_verbs() %}
                {% set label = {'read':'Read','watch':'Watch','listen':'Listen','play':'Play','visit':'Visit', "use": "Use"}[v] %}
                <a href="{{ url_for('by_kind', slug=kind_to_slug(v)) }}"
                {% if verb==v %}aria-current="page"{% endif %}>
                {{ label }}</a>
            {% endfor %}
        </div>
        {% endif %}
        <div class="nav-row nav-auth">
            {% if session.get('logged_in') %}
                <a href="{{ settings_href() }}"
                {% if request.path==settings_href() %}aria-current="page"{% endif %}>
                Settings</a>
            {% else %}
                <a href="{{ url_for('login') }}"
                {% if request.endpoint=='login' %}aria-current="page"{% endif %}>
                Login</a>
            {% endif %}
        </div>
        <div class="nav-row nav-search">
            <form action="{{ url_for('search') }}" method="get">
                <input type="search"
                       name="q"
                       aria-label="Search entries"
                       placeholder="Search"
                       value="{{ request.args.get('q','') }}">
            </form>
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
            {% if session.get('logged_in') and has_stats() %}
                <a href="{{ url_for('stats') }}"
                {% if request.endpoint == 'stats' %}
                    aria-current="page"
                {% endif %}>
                Stats</a>&nbsp;
            {% endif %}
            {% if has_today() %}
                <a href="{{ url_for('today') }}"
                {% if request.endpoint == 'today' %}
                    aria-current="page"
                {% endif %}>
                Today</a>&nbsp;
            {% endif %}
            {% for p in nav_pages() %}
                <a href="{{ '/' ~ p['slug'] }}"
                {% if request.path|trim('/') == p['slug'] %}
                    aria-current="page"
                {% endif %}>
                    {{ p['title'] }}</a>{% if not loop.last %}&nbsp;{% endif %}
            {% endfor %}
        </nav>
    </footer>
    <a href="#page-bottom" aria-label="Jump to footer" class="jump-btn jump-down">↓</a>
    <a href="#page-top" aria-label="Jump to top" class="jump-btn jump-up">↑</a>
    {% if session.get('logged_in') %}
    <script>
    (() => {
        const areas = Array.from(document.querySelectorAll('textarea[data-autogrow]'));
        const raf = window.requestAnimationFrame || ((fn) => setTimeout(fn, 16));
        if (!areas.length || !window.getComputedStyle) return;

        const resize = (ta) => {
            const styles = getComputedStyle(ta);
            const fontSize = parseFloat(styles.fontSize) || 16;
            const lh = parseFloat(styles.lineHeight);
            const lineHeight = Number.isFinite(lh) ? lh : fontSize * 1.4;
            const minRows = parseInt(ta.dataset.minRows || ta.getAttribute('rows') || '3', 10);
            const minHeight = Math.max(1, minRows) * lineHeight;
            const maxVh = parseFloat(ta.dataset.maxVh || '60') || 60;
            const maxHeight = Math.max(minHeight, Math.floor(window.innerHeight * (maxVh / 100)));

            ta.style.height = 'auto';
            const needed = Math.min(Math.max(minHeight, ta.scrollHeight), maxHeight);
            ta.style.height = `${needed}px`;
            ta.style.overflowY = ta.scrollHeight > needed ? 'auto' : 'hidden';
        };

        const refreshAll = () => areas.forEach(resize);

        areas.forEach((ta) => {
            resize(ta);
            ta.addEventListener('input', () => resize(ta));
            ta.addEventListener('change', () => resize(ta));
        });

        window.addEventListener('resize', () => raf(refreshAll), {passive: true});
    })();
    </script>
    {% endif %}
    {% if session.get('logged_in') and r2_enabled() %}
    <script>
    (() => {
        const csrf = document.querySelector('input[name="csrf"]')?.value || '';
        document.querySelectorAll('.img-upload-btn').forEach(btn => {
            const form = btn.closest('form');
            if (!form) return;
            const input = form.querySelector('.img-upload-input');
            const status = form.querySelector('.img-upload-status');
            const ta = form.querySelector('textarea[name="body"]');
            if (!input || !ta) return;

            btn.addEventListener('click', () => input.click());
            input.multiple = true;

            btn.addEventListener('dragover', ev => {
                ev.preventDefault();
                btn.style.outline = '2px dashed #888';
            });
            btn.addEventListener('dragleave', () => {
                btn.style.outline = '';
            });
            btn.addEventListener('drop', async ev => {
                ev.preventDefault();
                btn.style.outline = '';
                if (!ev.dataTransfer?.files?.length) return;
                await handleFiles([...ev.dataTransfer.files]);
            });

            input.addEventListener('change', async () => {
                if (!input.files || !input.files.length) return;
                await handleFiles([...input.files]);
                input.value = '';
            });

            async function handleFiles(files) {
                const headers = csrf ? {'X-CSRFToken': csrf} : {};
                for (const file of files) {
                    if (status) status.textContent = `Uploading ${file.name}...`;
                    const fd = new FormData();
                    fd.append('file', file);

                    try {
                        const res = await fetch('/upload-image', {
                            method: 'POST',
                            headers,
                            body: fd,
                        });
                        const data = await res.json();
                        if (!res.ok || !data?.url) {
                            throw new Error(data?.error || 'Upload failed');
                        }
                        const alt = (file.name || 'image').replace(/\\.[^.]+$/, '') || 'image';
                        const snippet = `![${alt}](${data.url})\n`;
                        insertSnippet(ta, snippet);
                        if (status) status.textContent = 'Inserted image link.';
                    } catch (err) {
                        if (status) status.textContent = err?.message || 'Upload failed.';
                        break;
                    }
                }
            }
        });

        document.querySelectorAll('.cover-upload-btn').forEach(btn => {
            const uploadUrl = btn.dataset.uploadUrl;
            const form = btn.closest('form') || document;
            const input = form.querySelector('.cover-upload-input');
            const status = form.querySelector('.cover-upload-status');
            if (!uploadUrl || !input) return;

            btn.addEventListener('click', () => input.click());
            input.multiple = false;

            btn.addEventListener('dragover', ev => {
                ev.preventDefault();
                btn.style.outline = '2px dashed #888';
            });
            btn.addEventListener('dragleave', () => {
                btn.style.outline = '';
            });
            btn.addEventListener('drop', async ev => {
                ev.preventDefault();
                btn.style.outline = '';
                if (!ev.dataTransfer?.files?.length) return;
                await handleCover(ev.dataTransfer.files[0]);
            });

            input.addEventListener('change', async () => {
                if (!input.files || !input.files.length) return;
                await handleCover(input.files[0]);
                input.value = '';
            });

            async function handleCover(file) {
                if (status) status.textContent = 'Uploading...';
                const fd = new FormData();
                fd.append('file', file);
                const headers = csrf ? {'X-CSRFToken': csrf} : {};

                try {
                    const res = await fetch(uploadUrl, {
                        method: 'POST',
                        headers,
                        body: fd,
                    });
                    const data = await res.json();
                    if (!res.ok || !data?.url) {
                        throw new Error(data?.error || 'Upload failed');
                    }
                    if (status) status.textContent = 'Cover updated.';
                    location.reload();
                } catch (err) {
                    if (status) status.textContent = err?.message || 'Upload failed.';
                }
            }
        });

        function insertSnippet(ta, snippet) {
            const start = ta.selectionStart || 0;
            const end = ta.selectionEnd || 0;
            const before = ta.value.slice(0, start);
            const after = ta.value.slice(end);
            ta.value = before + snippet + after;
            const pos = before.length + snippet.length;
            ta.setSelectionRange(pos, pos);
            ta.focus();
        }
    })();
    </script>
    {% endif %}
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


###############################################################################
# Traffic logging + blocklist
###############################################################################
_global_hits: DefaultDict[str, deque] = defaultdict(deque)
_traffic_hits: DefaultDict[str, deque] = defaultdict(deque)
_traffic_pruned_once = False
_last_swarm_autoblock_run = 0.0


def client_ip() -> str:
    """Return best-effort client IP after ProxyFix."""
    return (
        request.access_route[0] if request.access_route else request.remote_addr
    ) or "unknown"


def _request_host_info() -> tuple[str, str]:
    """Return normalized host and a simple classification for logging."""
    raw_host = (request.headers.get("Host") or request.host or "").strip()
    if not raw_host:
        return "", "unknown"
    host = raw_host.split(",", 1)[0].split(":", 1)[0].strip().lower()
    if host.endswith(".fly.dev") or host == "fly.dev":
        kind = "fly_dev"
    elif host.endswith(".flycast") or host == "flycast":
        kind = "flycast"
    else:
        kind = "custom"
    return host, kind


def _normalize_ip(ip: str) -> str:
    try:
        return str(ipaddress.ip_address((ip or "").strip()))
    except ValueError:
        return (ip or "").strip()


def _first_header_value(raw: str | None) -> str | None:
    if not raw:
        return None
    head = str(raw).split(",", 1)[0].strip()
    return head or None


def _cloudflare_networks() -> list[ipaddress.IPv4Network | ipaddress.IPv6Network]:
    ranges_cfg = app.config.get("CLOUDFLARE_IP_RANGES", CLOUDFLARE_IP_RANGES)
    if isinstance(ranges_cfg, (list, tuple, set)):
        raw_ranges = ranges_cfg
    else:
        raw_ranges = str(ranges_cfg or "").split(",")
    nets: list[ipaddress.IPv4Network | ipaddress.IPv6Network] = []
    for raw in raw_ranges:
        cidr = str(raw or "").strip()
        if not cidr:
            continue
        try:
            nets.append(ipaddress.ip_network(cidr, strict=False))
        except ValueError:
            continue
    return nets


def _cloudflare_info() -> dict[str, object]:
    cf_ray = _first_header_value(request.headers.get("CF-Ray"))
    cf_connecting_ip = _first_header_value(request.headers.get("CF-Connecting-IP"))
    cf_ip = _normalize_ip(cf_connecting_ip) if cf_connecting_ip else None
    edge_ip_raw = (
        request.environ.get("werkzeug.proxy_fix.orig_remote_addr")
        or request.remote_addr
        or ""
    )
    edge_ip = _normalize_ip(edge_ip_raw) if edge_ip_raw else ""
    nets = _cloudflare_networks()
    from_cf_ip = bool(edge_ip and nets and _ip_in_blocked(edge_ip, nets))
    via_cf = bool(cf_ray or cf_ip or from_cf_ip)
    info: dict[str, object] = {"cf": via_cf}
    if cf_ray:
        info["cfray"] = cf_ray[:64]
    if cf_ip:
        info["cfip"] = cf_ip
    if edge_ip and via_cf:
        info["edge"] = edge_ip
    if via_cf:
        if cf_ray or cf_ip:
            info["cf_src"] = "header+edge" if from_cf_ip else "header"
        else:
            info["cf_src"] = "ip_range"
    return info


def _normalize_block_value(value: str) -> str:
    raw = (value or "").strip()
    if not raw:
        raise ValueError("empty IP")
    if "/" in raw:
        try:
            return str(ipaddress.ip_network(raw, strict=False))
        except ValueError:
            raise ValueError("invalid CIDR")
    return _normalize_ip(raw)


def _parse_block_target(raw: str):
    val = (raw or "").strip()
    try:
        net = ipaddress.ip_network(val, strict=False)
        return net
    except ValueError:
        try:
            addr = ipaddress.ip_address(val)
            return ipaddress.ip_network(f"{addr}/{addr.max_prefixlen}", strict=False)
        except ValueError:
            return None


def _ip_in_blocked(ip: str, blocked_networks: list) -> bool:
    try:
        addr = ipaddress.ip_address((ip or "").strip())
    except ValueError:
        return False
    for net in blocked_networks:
        try:
            if addr.version != net.version:
                continue
            if addr in net:
                return True
        except Exception:
            continue
    return False


def _net_bucket(ip: str) -> str | None:
    try:
        addr = ipaddress.ip_address((ip or "").strip())
    except ValueError:
        return None
    if isinstance(addr, ipaddress.IPv4Address):
        return str(ipaddress.IPv4Network(f"{addr}/16", strict=False))
    return str(ipaddress.IPv6Network(f"{addr}/32", strict=False))


def _should_skip_traffic_log(path: str) -> bool:
    if path in TRAFFIC_SKIP_PATHS:
        return True
    if path.startswith("/static/"):
        return True
    return False


def _mark_burst(ip: str, now: float) -> bool:
    window = int(app.config.get("TRAFFIC_BURST_WINDOW", TRAFFIC_BURST_WINDOW_SEC))
    limit = int(app.config.get("TRAFFIC_BURST_LIMIT", TRAFFIC_BURST_LIMIT))
    dq = _traffic_hits[ip]
    while dq and now - dq[0] > window:
        dq.popleft()
    dq.append(now)
    return len(dq) >= limit


def _maybe_autoblock_synchronized(*, db) -> None:
    if not app.config.get(
        "TRAFFIC_SWARM_AUTOBLOCK_ON_REQUEST", TRAFFIC_SWARM_AUTOBLOCK_ON_REQUEST
    ):
        return
    if not app.config.get("TRAFFIC_SWARM_AUTOBLOCK", TRAFFIC_SWARM_AUTOBLOCK):
        return
    interval = int(
        app.config.get(
            "TRAFFIC_SWARM_AUTOBLOCK_INTERVAL_SEC",
            TRAFFIC_SWARM_AUTOBLOCK_INTERVAL_SEC,
        )
    )
    now = time()
    global _last_swarm_autoblock_run
    if _last_swarm_autoblock_run and now - _last_swarm_autoblock_run < max(interval, 1):
        return
    _last_swarm_autoblock_run = now
    try:
        hours = int(
            app.config.get(
                "TRAFFIC_SWARM_AUTOBLOCK_SCAN_HOURS",
                TRAFFIC_SWARM_AUTOBLOCK_SCAN_HOURS,
            )
        )
    except (TypeError, ValueError):
        hours = TRAFFIC_SWARM_AUTOBLOCK_SCAN_HOURS
    try:
        traffic_snapshot(db=db, hours=hours)
    except Exception:
        pass


def _is_bot_ua(ua: str | None) -> bool:
    ua_l = (ua or "").lower()
    return any(k in ua_l for k in TRAFFIC_BOT_KEYWORDS)


def _keyword_tuple(value) -> tuple[str, ...]:
    if isinstance(value, str):
        raw_items = value.split(",")
    else:
        raw_items = value or []
    return tuple(str(item).strip().lower() for item in raw_items if str(item).strip())


def _path_token_burst(path: str) -> int:
    if not path:
        return 0
    return path.count("+") + path.count("%20") + path.count(",") + path.count(";")


def _ua_suspicious(
    ua: str, *, min_len: int, keywords: tuple[str, ...]
) -> tuple[bool, str]:
    ua_clean = (ua or "").strip()
    if not ua_clean:
        return True, "Missing UA"
    ua_l = ua_clean.lower()
    if len(ua_clean) < min_len:
        return True, "Tiny UA"
    for kw in keywords:
        if kw and kw in ua_l:
            return True, f"UA contains {kw}"
    return False, ""


def is_ip_blocked(ip: str, *, db) -> bool:
    if not ip:
        return False
    now = utc_now().isoformat()
    try:
        rows = db.execute(
            "SELECT ip, expires_at FROM ip_blocklist WHERE (expires_at IS NULL OR expires_at > ?)",
            (now,),
        ).fetchall()
    except sqlite3.OperationalError:
        return True  # fail closed if the table is locked
    except Exception:
        return False
    nets = []
    for row in rows:
        net = _parse_block_target(row["ip"])
        if net:
            nets.append(net)
    blocked = _ip_in_blocked(ip, nets)
    return blocked


def block_ip_addr(ip: str, *, reason: str, expires_at: str | None, db) -> None:
    norm = _normalize_block_value(ip)
    db.execute(
        "INSERT OR REPLACE INTO ip_blocklist (ip, reason, created_at, expires_at) VALUES (?,?,?,?)",
        (norm, reason, utc_now().isoformat(timespec="seconds"), expires_at),
    )
    db.commit()


def unblock_ip_addr(ip: str, *, db) -> None:
    norm = _normalize_block_value(ip)
    db.execute("DELETE FROM ip_blocklist WHERE ip=?", (norm,))
    db.commit()


def _append_traffic_event(event: dict) -> None:
    if not app.config.get("TRAFFIC_LOG_ENABLED", True):
        return
    log_dir = Path(app.config.get("TRAFFIC_LOG_DIR") or TRAFFIC_LOG_DIR_DEFAULT)
    try:
        log_dir.mkdir(parents=True, exist_ok=True)
    except OSError:
        return

    try:
        ts = datetime.fromisoformat(event["ts"])
    except Exception:
        ts = utc_now()
    log_path = log_dir / f"traffic-{ts:%Y%m%d}.log"
    try:
        with log_path.open("a", encoding="utf-8") as fh:
            fh.write(json.dumps(event, separators=(",", ":")) + "\n")
    except OSError:
        return

    retention_days = int(
        app.config.get("TRAFFIC_LOG_RETENTION_DAYS", TRAFFIC_LOG_RETENTION_DAYS)
    )
    global _traffic_pruned_once
    if retention_days <= 0 or _traffic_pruned_once:
        return
    cutoff = (utc_now() - timedelta(days=retention_days)).date()
    for p in log_dir.glob("traffic-*.log"):
        stem = p.stem.replace("traffic-", "")
        try:
            dt = datetime.strptime(stem, "%Y%m%d").date()
        except ValueError:
            continue
        if dt < cutoff:
            try:
                p.unlink(missing_ok=True)
            except OSError:
                continue
    _traffic_pruned_once = True


@app.before_request
def traffic_gate():
    ip = client_ip()
    g.client_ip = ip
    now = time()
    path = request.path or ""
    db = None
    testing = bool(app.config.get("TESTING"))

    if not session.get("logged_in"):
        ua_raw = request.user_agent.string or ""
        ua = ua_raw.lower()
        block_ua_kw = next(
            (kw for kw in app.config.get("TRAFFIC_BLOCK_UA_KEYWORDS", ()) if kw in ua),
            None,
        )
        if block_ua_kw:
            db = get_db()
            if not is_ip_blocked(ip, db=db):
                try:
                    days = int(
                        app.config.get(
                            "TRAFFIC_SWARM_AUTOBLOCK_EXPIRES_DAYS",
                            TRAFFIC_SWARM_AUTOBLOCK_EXPIRES_DAYS,
                        )
                    )
                except (TypeError, ValueError):
                    days = TRAFFIC_SWARM_AUTOBLOCK_EXPIRES_DAYS
                expires_at = None
                if days > 0:
                    expires_at = (utc_now() + timedelta(days=days)).isoformat(
                        timespec="seconds"
                    )
                try:
                    block_ip_addr(
                        ip,
                        reason=f"Auto-block UA: {block_ua_kw}",
                        expires_at=expires_at,
                        db=db,
                    )
                except Exception:
                    pass
            abort(403)
        db = db or get_db()
        if is_ip_blocked(ip, db=db):
            abort(403)

    global_limit = int(app.config.get("TRAFFIC_GLOBAL_LIMIT", TRAFFIC_GLOBAL_LIMIT))
    global_window = int(
        app.config.get("TRAFFIC_GLOBAL_WINDOW_SEC", TRAFFIC_GLOBAL_WINDOW_SEC)
    )
    if testing and global_limit == TRAFFIC_GLOBAL_LIMIT:
        global_limit = 0  # opt-in only for tests that explicitly set a value
    if global_limit > 0 and global_window > 0 and not _should_skip_traffic_log(path):
        dq = _global_hits[ip]
        while dq and now - dq[0] > global_window:
            dq.popleft()
        if len(dq) >= global_limit:
            db = db or get_db()
            try:
                block_ip_addr(
                    ip,
                    reason="Auto-block: rate limit exceeded",
                    expires_at=None,
                    db=db,
                )
            except Exception:
                pass
            return Response(
                "Forbidden",
                status=403,
            )
        dq.append(now)

    if not app.config.get("TRAFFIC_LOG_ENABLED", True):
        return
    if _should_skip_traffic_log(path):
        g.skip_traffic_log = True
        return

    g._traffic_started_at = now
    flags: list[str] = list(getattr(g, "_traffic_flags", []))
    if _mark_burst(ip, now):
        flags.append("burst_suspect")
    g._traffic_flags = flags


@app.after_request
def log_traffic(resp):
    if not app.config.get("TRAFFIC_LOG_ENABLED", True):
        return resp
    if getattr(g, "skip_traffic_log", False):
        return resp

    try:
        started = getattr(g, "_traffic_started_at", None)
        dur_ms = int((time() - started) * 1000) if started else None
        flags = list(getattr(g, "_traffic_flags", []))
        if resp.status_code == 404:
            flags.append("nonexistent_path")

        ua = request.user_agent.string or ""
        if _is_bot_ua(ua):
            flags.append("bot_ua")
        if session.get("logged_in"):
            flags.append("admin_view")
        host, host_type = _request_host_info()
        cf_meta = _cloudflare_info()

        event = {
            "ts": utc_now().isoformat(),
            "ip": _normalize_ip(getattr(g, "client_ip", client_ip())),
            "host": host,
            "host_type": host_type,
            "path": request.path,
            "m": request.method,
            "st": resp.status_code,
            "ua": ua[:200],
            "dur": dur_ms,
            "flags": flags,
        }
        event.update(cf_meta)
        _append_traffic_event(event)
        _maybe_autoblock_synchronized(db=get_db())
    except Exception:
        pass

    return resp


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
        site_tagline = request.form.get("site_tagline", "").strip()
        username = request.form["username"].strip()
        col = request.form["theme_color"].strip()
        tz = request.form.get("timezone", "").strip()
        if tz in available_timezones():
            set_setting("timezone", tz)

        if site_name:
            set_setting("site_name", site_name)
        set_setting("site_tagline", site_tagline)

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

        r2_updates = {}
        for env_key, form_key in (
            ("R2_ACCOUNT_ID", "r2_account_id"),
            ("R2_ACCESS_KEY_ID", "r2_access_key_id"),
            ("R2_SECRET_ACCESS_KEY", "r2_secret_access_key"),
            ("R2_BUCKET", "r2_bucket"),
            ("R2_PUBLIC_BASE", "r2_public_base"),
            ("R2_ENDPOINT", "r2_endpoint"),
        ):
            raw = request.form.get(form_key, "").strip()
            if raw:
                r2_updates[env_key] = raw
        if r2_updates:
            merge_env(r2_updates)

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
    r2_cfg = r2_config()
    r2_status = {
        "account": bool(r2_cfg.get("R2_ACCOUNT_ID")),
        "key": bool(r2_cfg.get("R2_ACCESS_KEY_ID")),
        "secret": bool(r2_cfg.get("R2_SECRET_ACCESS_KEY")),
        "bucket": bool(r2_cfg.get("R2_BUCKET")),
        "public_base": bool(r2_cfg.get("R2_PUBLIC_BASE")),
        "endpoint": bool(r2_cfg.get("R2_ENDPOINT")),
    }
    return render_template_string(
        TEMPL_SETTINGS,
        site_name=get_setting("site_name", "po.etr.ist"),
        site_tagline=get_setting("site_tagline", ""),
        username=cur_username,
        new_token=new_token,
        title=get_setting("site_name", "po.etr.ist"),
        slug_settings=slug_settings,
        verb_slugs=verb_slugs,
        r2_status=r2_status,
        r2_configured=r2_is_configured(r2_cfg),
    )


TEMPL_SETTINGS = wrap("""
    {% block body %}
    <hr>
    <h2>Site Settings</h2>
    <form method="post" style="max-width:100%">
        {% if csrf_token() %}
            <input type="hidden" name="csrf" value="{{ csrf_token() }}">
            {% endif %}
        <!-- ──────────── site info ──────────── -->
        <fieldset style="margin:0 0 1.5rem 0; border:0; padding:0">
            <label style="display:block; margin:.5rem 0">
                <span style="font-size:.8em; color:#aaa">Site name</span><br>
                <input name="site_name"
                       class="writing-input"
                       value="{{ site_name }}"
                       style="width:100%">
            </label>
            <label style="display:block; margin:.5rem 0">
                <span style="font-size:.8em; color:#aaa">Tagline (optional)</span><br>
                <input name="site_tagline"
                       class="writing-input"
                       value="{{ site_tagline }}"
                       style="width:100%"
                       placeholder="A short subtitle under the site name">
            </label>

            <label style="display:block; margin:.5rem 0">
                <span style="font-size:.8em; color:#aaa">Username</span><br>
                <input name="username"
                       class="writing-input"
                       value="{{ username }}"
                       style="width:100%">
            </label>
                      
            <label style="display:block;margin:.5rem 0">
                <span style="font-size:.8em;color:#aaa">Timezone</span><br>
                <input list="tz-list"
                       name="timezone"
                       class="writing-input"
                       value="{{ tz_name() }}"
                       style="width:100%">
            </label>
                      
            <label style="display:flex; align-items:center; gap:.8rem; margin:.5rem 0;">
                <span style="font-size:.8em; color:#aaa; white-space:nowrap;">Theme color</span>
                <input name="theme_color"
                    class="writing-input"
                    value="{{ get_setting('theme_color', '#A5BA93') }}"
                    placeholder="#A5BA93"
                    style="width:10rem">
                <span data-color-chip
                      aria-hidden="true"
                      style="width:1.5rem;height:1.5rem;border:1px solid #555;border-radius:.15rem;background:{{ get_setting('theme_color', '#A5BA93') }};">
                </span>
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
            <script>
            (() => {
                const input = document.querySelector('input[name="theme_color"]');
                const chip = document.querySelector('[data-color-chip]');
                if (!input || !chip) return;
                const sync = () => {
                    const v = input.value.trim();
                    chip.style.background = /^#?[0-9a-fA-F]{6}$/.test(v) ? (v.startsWith('#') ? v : '#' + v) : '#444';
                };
                input.addEventListener('input', sync);
                sync();
            })();
            </script>
        </fieldset>

        <!-- ──────────── slugs ──────────── -->
        <fieldset style="margin:0 0 1.5rem 0; border:0; padding:0">
            <legend style="font-weight:bold; margin-bottom:.5rem;">URL slugs</legend>
                <div style="display:grid; grid-template-columns:repeat(2,minmax(14rem,1fr)); gap:.75rem; width:100%;">
                    <label>
                        <span style="font-size:.8em; color:#aaa">Says</span><br>
                        <input name="slug_say"
                               class="writing-input"
                               value="{{ slug_settings['say'] }}"
                               style="width:100%">
                    </label>
                    <label>
                        <span style="font-size:.8em; color:#aaa">Posts</span><br>
                        <input name="slug_post"
                               class="writing-input"
                               value="{{ slug_settings['post'] }}"
                               style="width:100%">
                    </label>
                    <label>
                        <span style="font-size:.8em; color:#aaa">Photos</span><br>
                        <input name="slug_photo"
                               class="writing-input"
                               value="{{ slug_settings['photo'] }}"
                               style="width:100%">
                    </label>
                    <label>
                        <span style="font-size:.8em; color:#aaa">Pins</span><br>
                        <input name="slug_pin"
                               class="writing-input"
                               value="{{ slug_settings['pin'] }}"
                               style="width:100%">
                    </label>
            </div>
            <div style="margin-top:1rem;">
                <span style="font-size:.8em; color:#aaa">Other</span>
                <div style="display:grid; grid-template-columns:repeat(2,minmax(14rem,1fr)); gap:.75rem; margin-top:.4rem; width:100%;">
                    <label>
                        <span style="font-size:.8em; color:#aaa">Tags</span><br>
                        <input name="slug_tags"
                               class="writing-input"
                               value="{{ slug_settings['tags'] }}"
                               style="width:100%">
                    </label>
                    <label>
                        <span style="font-size:.8em; color:#aaa">Settings</span><br>
                        <input name="slug_settings"
                               class="writing-input"
                               value="{{ slug_settings['settings'] }}"
                               style="width:100%">
                    </label>
                </div>
            </div>
            <div style="margin-top:1rem;">
                {% if verb_slugs %}
                    <span style="font-size:.8em; color:#aaa">Verbs</span>
                    <div style="display:grid; grid-template-columns:repeat(2,minmax(14rem,1fr)); gap:.75rem; margin-top:.4rem; width:100%;">
                        {% for verb, slug in verb_slugs %}
                        <label>
                            <span style="font-size:.8em; color:#aaa">{{ verb|capitalize }}</span><br>
                            <input name="slug_{{ verb }}"
                                   class="writing-input"
                                   value="{{ slug }}"
                                   style="width:100%">
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
                    class="writing-input"
                    value="{{ get_setting('page_size', PAGE_DEFAULT) }}"
                    style="width:8rem">
            </label>
        </fieldset>

        <!-- ──────────── uploads ──────────── -->
        <fieldset style="margin:0 0 1.5rem 0; border:0; padding:0">
            <legend style="font-weight:bold; margin-bottom:.5rem;">Image uploads (Cloudflare R2)</legend>
            <div style="font-size:.9em;color:#888;margin:.25rem 0 .75rem 0;">
                Status:
                {% if r2_configured %}
                    <span style="color:{{ theme_color() }};">ready</span>
                {% else %}
                    missing required values
                {% endif %}
                · leave fields blank to keep existing values
            </div>
            <div style="display:grid; grid-template-columns:repeat(2, minmax(14rem,1fr)); gap:.75rem; width:100%;">
                <label>
                    <span style="font-size:.8em; color:#aaa">Account ID
                        <small style="color:#777;">{% if r2_status.account %}saved{% else %}missing{% endif %}</small>
                    </span><br>
                    <input name="r2_account_id"
                           class="writing-input"
                           autocomplete="off"
                           placeholder="xxxxxxxxxxxxxxxxxxx"
                           style="width:100%">
                </label>
                <label>
                    <span style="font-size:.8em; color:#aaa">Access key ID
                        <small style="color:#777;">{% if r2_status.key %}saved{% else %}missing{% endif %}</small>
                    </span><br>
                    <input name="r2_access_key_id"
                           class="writing-input"
                           autocomplete="off"
                           placeholder="K123..."
                           style="width:100%">
                </label>
                <label>
                    <span style="font-size:.8em; color:#aaa">Secret access key
                        <small style="color:#777;">{% if r2_status.secret %}saved{% else %}missing{% endif %}</small>
                    </span><br>
                    <input type="text"
                           name="r2_secret_access_key"
                           class="writing-input"
                           autocomplete="off"
                           placeholder="••••••••"
                           style="width:100%">
                </label>
                <label>
                    <span style="font-size:.8em; color:#aaa">Bucket
                        <small style="color:#777;">{% if r2_status.bucket %}saved{% else %}missing{% endif %}</small>
                    </span><br>
                    <input name="r2_bucket"
                           class="writing-input"
                           autocomplete="off"
                           placeholder="poetrist-assets"
                           style="width:100%">
                </label>
                <label>
                    <span style="font-size:.8em; color:#aaa">Public base URL
                        <small style="color:#777;">{% if r2_status.public_base %}saved{% else %}optional{% endif %}</small>
                    </span><br>
                    <input name="r2_public_base"
                           class="writing-input"
                           autocomplete="off"
                           placeholder="https://cdn.example.com"
                           style="width:100%">
                </label>
                <label>
                    <span style="font-size:.8em; color:#aaa">Endpoint override
                        <small style="color:#777;">{% if r2_status.endpoint %}saved{% else %}optional{% endif %}</small>
                    </span><br>
                    <input name="r2_endpoint"
                           class="writing-input"
                           autocomplete="off"
                           placeholder="https://<account>.r2.cloudflarestorage.com"
                           style="width:100%">
                </label>
            </div>
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
            input.className  = 'pk-name-edit writing-input';      // easy selector + styling

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


@app.route("/upload-image", methods=["POST"])
def upload_image():
    login_required()

    cfg = r2_config()
    if not r2_is_configured(cfg):
        return {"error": "Image uploads are not configured."}, 400

    if "file" not in request.files:
        return {"error": "No file received."}, 400

    f = request.files["file"]
    if not f.filename:
        return {"error": "No file selected."}, 400

    mime = (f.mimetype or "").lower()
    if mime not in IMAGE_MIMES:
        return {"error": "Only image uploads are allowed."}, 415

    clen = request.content_length
    if clen and clen > UPLOAD_MAX_BYTES:
        return {"error": "File too large (8 MiB max)."}, 413

    ext = Path(secure_filename(f.filename)).suffix.lower()
    key = f"uploads/{utc_now().strftime('%Y/%m/%d')}/{uuid.uuid4().hex}{ext}"

    try:
        client = _r2_client(cfg)
        f.stream.seek(0)
        client.upload_fileobj(
            f.stream,
            cfg["R2_BUCKET"],
            key,
            ExtraArgs={"ContentType": mime},
        )
    except (BotoCoreError, ClientError):
        app.logger.exception("R2 upload failed")
        return {"error": "Upload failed – check R2 credentials."}, 502

    return {"url": r2_object_url(cfg, key), "key": key}, 201


@app.route("/<verb>/<item_type>/<slug>/upload-cover", methods=["POST"])
def upload_cover(verb, item_type, slug):
    login_required()
    cfg = r2_config()
    if not r2_is_configured(cfg):
        return {"error": "Image uploads are not configured."}, 400

    verb = slug_to_kind(verb)
    if verb not in VERB_KINDS:
        abort(404)

    item_type_norm = normalize_item_type(item_type)
    if not item_type_norm:
        abort(404)

    db = get_db()
    itm = db.execute(
        "SELECT id, uuid, item_type FROM item WHERE slug=? AND LOWER(item_type)=?",
        (slug, item_type_norm),
    ).fetchone()
    if not itm:
        abort(404)
    if itm["item_type"] != item_type_norm:
        db.execute("UPDATE item SET item_type=? WHERE id=?", (item_type_norm, itm["id"]))

    if "file" not in request.files:
        return {"error": "No file received."}, 400
    f = request.files["file"]
    if not f.filename:
        return {"error": "No file selected."}, 400

    mime = (f.mimetype or "").lower()
    if mime not in IMAGE_MIMES:
        return {"error": "Only image uploads are allowed."}, 415

    clen = request.content_length
    if clen and clen > UPLOAD_MAX_BYTES:
        return {"error": "File too large (8 MiB max)."}, 413

    ext = Path(secure_filename(f.filename)).suffix.lower()
    key = f"covers/{item_type}/{slug}/{itm['uuid']}-{uuid.uuid4().hex}{ext}"

    try:
        client = _r2_client(cfg)
        f.stream.seek(0)
        client.upload_fileobj(
            f.stream,
            cfg["R2_BUCKET"],
            key,
            ExtraArgs={"ContentType": mime},
        )
    except (BotoCoreError, ClientError):
        app.logger.exception("R2 upload failed")
        return {"error": "Upload failed – check R2 credentials."}, 502

    url = r2_object_url(cfg, key)
    # update or insert cover meta (preserve order if it existed)
    cur = db.execute(
        "SELECT ord FROM item_meta WHERE item_id=? AND k='cover'", (itm["id"],)
    ).fetchone()
    ord_val = (
        cur["ord"]
        if cur
        else (
            db.execute(
                "SELECT COALESCE(MAX(ord),0)+1 AS o FROM item_meta WHERE item_id=?",
                (itm["id"],),
            ).fetchone()["o"]
        )
    )
    db.execute(
        """INSERT INTO item_meta (item_id,k,v,ord)
                VALUES (?,?,?,?)
           ON CONFLICT(item_id,k) DO UPDATE SET v=excluded.v, ord=excluded.ord""",
        (itm["id"], "cover", url, ord_val),
    )
    db.commit()

    return {"url": url, "key": key}, 201


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
                tags = extract_tags(body_parsed)
                kind = (
                    blocks[0]["verb"]
                    if blocks
                    else apply_photo_kind(infer_kind("", ""), tags)
                )
                now_dt = utc_now()
                now = now_dt.isoformat(timespec="seconds")
                slug = now_dt.strftime("%Y%m%d%H%M%S")

                db.execute(
                    """INSERT INTO entry (body, created_at, slug, kind)
                              VALUES (?,?,?,?)""",
                    (body_parsed, now, slug, kind),
                )
                entry_id = db.execute("SELECT last_insert_rowid()").fetchone()[0]

                sync_tags(entry_id, tags, db=db)

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
        <form method="post" id="quick-add-form"
              style="display:flex;
                     flex-direction:column;
                     gap:10px;
                     align-items:flex-start;">
            {% if csrf_token() %}
            <input type="hidden" name="csrf" value="{{ csrf_token() }}">
            {% endif %}
            <textarea name="body"
                      class="writing-area"
                      rows="3"
                      data-autogrow="true"
                      style="margin:0"
                      placeholder="What's on your mind?">{{ form_body or '' }}</textarea>
            <div style="display:flex; gap:.5rem; align-items:center; flex-wrap:wrap;">
                <button>Add&nbsp;Say</button>
                {% if r2_enabled() %}
                    <input type="file" class="img-upload-input" accept="image/*" style="display:none">
                    <button type="button"
                            class="img-upload-btn"
                            aria-label="Upload images"
                            title="Upload images"
                            style="background:#333;color:#FFF;border:1px solid #666;display:inline-flex;align-items:center;justify-content:center;vertical-align:middle;padding:5px 10px;">
                        {{ upload_icon() }}
                    </button>
                    <span class="img-upload-status" style="font-size:.85em;color:#888;"></span>
                {% endif %}
            </div>
        </form>
    {% endif %}
    <hr>
    {% for e in entries %}
    <article class="h-entry" {% if not loop.last %}style="padding-bottom:1.5em; border-bottom:1px solid #444;"{% endif %}>
        {% if e['kind']=='pin' %}
            {% set host = link_host(e['link']) %}
            <h2 class="pin-title">
                <a class="u-bookmark-of p-name" href="{{ e['link'] }}" target="_blank" rel="noopener">
                    {{ e['title'] }}
                </a>
                {% if host %}
                    <span class="pin-host">(<a href="{{ pins_from_href(host) }}">{{ host }}</a>)</span>
                {% endif %}
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
            {% if e['kind'] == 'post' %}
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

        kind_hint = kind if kind in VERB_KINDS else None
        body_parsed, blocks, errors = parse_trigger(body_for_parse, verb_hint=kind_hint)

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
            tag_set = extract_tags(body_parsed)
            entry_kind = apply_photo_kind(entry_kind, tag_set)
            missing = []

            if entry_kind in ("say", "photo"):
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
                sync_tags(entry_id, tag_set, db=db)
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
                        i.rating,
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

        ensure_item_rating_column(db)
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
    selected_site = link_host(request.args.get("from", "").strip())
    selected_photo_tags_raw = (request.args.get("tag", "") or "").strip().lower()
    selected_photo_tags = {
        t for t in selected_photo_tags_raw.split("+") if t and t not in PHOTO_TAG_SET
    }
    selected_photo_tags_param = "+".join(sorted(selected_photo_tags))
    selected_say_tags_raw = (
        (request.args.get("tag", "") or "").strip().lower() if kind == "say" else ""
    )
    selected_say_tags = {t for t in selected_say_tags_raw.split("+") if t}
    selected_say_tags_list = sorted(selected_say_tags)
    selected_say_tags_param = "+".join(selected_say_tags_list)
    selected_post_tags_raw = (
        (request.args.get("tag", "") or "").strip().lower() if kind == "post" else ""
    )
    selected_post_tags = {t for t in selected_post_tags_raw.split("+") if t}
    selected_post_tags_list = sorted(selected_post_tags)
    selected_post_tags_param = "+".join(selected_post_tags_list)
    selected_pin_tags_raw = (
        (request.args.get("tag", "") or "").strip().lower() if kind == "pin" else ""
    )
    selected_pin_tags = {t for t in selected_pin_tags_raw.split("+") if t}
    selected_pin_tags_list = sorted(selected_pin_tags)
    selected_pin_tags_param = "+".join(selected_pin_tags_list)
    total_posts = None
    site_filters: list[dict[str, str]] = []
    total_pins = None
    total_photos = None
    total_says = None
    post_tag_filters: list[dict[str, str | int | bool]] = []
    photo_tag_filters: list[dict[str, str | int | bool]] = []
    say_tag_filters: list[dict[str, str | int | bool]] = []
    pin_tag_filters: list[dict[str, str | int | bool]] = []
    tag_join = ""
    tag_group_having = ""
    project_join = ""
    project_where = ""
    site_where = ""
    params: list[str] = [kind]

    if kind == "photo":
        # derive photo page size from configured page_size, but force a 3-wide grid
        ps_raw = page_size()
        per_photos = max(12, (ps_raw // 3) * 3 or 3)
        all_entries = db.execute(
            "SELECT * FROM entry WHERE kind='photo' ORDER BY created_at DESC"
        ).fetchall()

        tag_counts: dict[str, int] = defaultdict(int)
        co_occurring: set[str] = set()
        all_cards: list[dict[str, str | list[str]]] = []

        for e in all_entries:
            entry_tags_lower = [t.lower() for t in entry_tags(e["id"], db=db)]
            imgs = entry_images(e["body"], e["slug"])
            all_cards.extend(
                {
                    "src": img["src"],
                    "alt": img["alt"],
                    "slug": e["slug"],
                    "kind": e["kind"],
                    "tags": entry_tags_lower,
                }
                for img in imgs
            )

        def matches_selection(card: dict[str, str | list[str]]) -> bool:
            return not selected_photo_tags or selected_photo_tags.issubset(
                set(card["tags"])
            )

        cards = [c for c in all_cards if matches_selection(c)]

        for card in cards:
            for t in card["tags"]:
                if t in PHOTO_TAG_SET:
                    continue
                tag_counts[t] += 1
                co_occurring.add(t)

        all_filter_tags = set(tag_counts) | set(selected_photo_tags)

        def tag_href(new_sel: set[str]) -> str:
            tag_param = "+".join(sorted(new_sel))
            return (
                url_for("by_kind", slug=kind_to_slug("photo"), tag=tag_param)
                if tag_param
                else url_for("by_kind", slug=kind_to_slug("photo"))
            )

        photo_tag_filters = [
            {
                "tag": t,
                "cnt": tag_counts.get(t, 0),
                "active": t in selected_photo_tags,
                "hint": bool(
                    selected_photo_tags
                    and t not in selected_photo_tags
                    and t in co_occurring
                ),
                "href": tag_href(
                    (selected_photo_tags - {t})
                    if t in selected_photo_tags
                    else (selected_photo_tags | {t})
                ),
            }
            for t in sorted(
                all_filter_tags, key=lambda kv: (-tag_counts.get(kv, 0), kv)
            )
        ]

        total_cards = len(cards)
        total_photos = len(all_cards)
        total_pages = (total_cards + per_photos - 1) // per_photos
        start = (page - 1) * per_photos
        end = start + per_photos
        photo_cards = cards[start:end]
        pages = list(range(1, total_pages + 1))

        return render_template_string(
            TEMPL_LIST,
            rows=[],
            pages=pages,
            page=page,
            heading=(kind or "").capitalize() + "s",
            kind=kind,
            username=current_username(),
            title=get_setting("site_name", "po.etr.ist"),
            form_title=form_title,
            form_link=form_link,
            form_body=form_body,
            backlinks={},
            project_filters=[],
            selected_project="",
            total_posts=None,
            photo_tags=photo_tag_filters,
            selected_photo_tags=selected_photo_tags,
            selected_photo_tags_param=selected_photo_tags_param,
            total_photos=total_photos,
            say_tags=say_tag_filters,
            selected_say_tags=selected_say_tags,
            selected_say_tags_param=selected_say_tags_param,
            total_says=total_says,
            pin_tags=pin_tag_filters,
            selected_pin_tags=selected_pin_tags,
            selected_pin_tags_param=selected_pin_tags_param,
            photo_cards=photo_cards,
            site_filters=[],
            selected_site="",
            total_pins=None,
        )

    if kind == "say":
        total_says = db.execute(
            "SELECT COUNT(*) AS c FROM entry WHERE kind='say'"
        ).fetchone()["c"]
        q_marks_say = (
            ",".join("?" * len(selected_say_tags_list))
            if selected_say_tags_list
            else ""
        )
        co_occurring_say: set[str] = set()
        say_count_rows = []
        if selected_say_tags_list:
            matching_entries_sql = f"""
                SELECT et2.entry_id
                  FROM entry_tag et2
                  JOIN tag t2 ON t2.id = et2.tag_id
                  JOIN entry e2 ON e2.id = et2.entry_id
                 WHERE e2.kind='say' AND t2.name IN ({q_marks_say})
              GROUP BY et2.entry_id
                HAVING COUNT(DISTINCT t2.name)=?
            """
            say_count_rows = db.execute(
                f"""
                SELECT t.name, COUNT(*) AS cnt
                  FROM tag t
                  JOIN entry_tag et ON et.tag_id = t.id
                 WHERE et.entry_id IN ({matching_entries_sql})
              GROUP BY t.name
                """,
                (*selected_say_tags_list, len(selected_say_tags_list)),
            ).fetchall()
            co_occurring_say = {r["name"].lower() for r in say_count_rows}
        else:
            say_count_rows = db.execute(
                """
                SELECT t.name, COUNT(*) AS cnt
                  FROM tag t
                  JOIN entry_tag et ON et.tag_id = t.id
                  JOIN entry e ON e.id = et.entry_id
                 WHERE e.kind='say'
              GROUP BY t.name
                """
            ).fetchall()

        say_tag_counts = {r["name"].lower(): r["cnt"] for r in say_count_rows}
        for t in selected_say_tags:
            say_tag_counts.setdefault(t, 0)
        all_filter_tags = set(say_tag_counts) | set(selected_say_tags)

        def say_tag_href(new_sel: set[str]) -> str:
            tag_param = "+".join(sorted(new_sel))
            return (
                url_for("by_kind", slug=kind_to_slug("say"), tag=tag_param)
                if tag_param
                else url_for("by_kind", slug=kind_to_slug("say"))
            )

        say_tag_filters = [
            {
                "tag": t,
                "cnt": say_tag_counts.get(t, 0),
                "active": t in selected_say_tags,
                "hint": bool(
                    selected_say_tags
                    and t not in selected_say_tags
                    and t in co_occurring_say
                ),
                "href": say_tag_href(
                    (selected_say_tags - {t})
                    if t in selected_say_tags
                    else (selected_say_tags | {t})
                ),
            }
            for t in sorted(
                all_filter_tags, key=lambda kv: (-say_tag_counts.get(kv, 0), kv)
            )
        ]

        if selected_say_tags_list:
            tag_join = (
                " JOIN entry_tag et_filter ON et_filter.entry_id = e.id"
                " JOIN tag t_filter ON t_filter.id = et_filter.tag_id"
            )
            tag_group_having = f"""
            GROUP BY e.id
              HAVING COUNT(
                  DISTINCT CASE WHEN t_filter.name IN ({q_marks_say})
                                THEN t_filter.name END
              )=?
            """
            params.extend(selected_say_tags_list)
            params.append(len(selected_say_tags_list))

    if kind == "post":
        q_marks_post = (
            ",".join("?" * len(selected_post_tags_list))
            if selected_post_tags_list
            else ""
        )
        total_posts = db.execute(
            "SELECT COUNT(*) AS c FROM entry WHERE kind='post'"
        ).fetchone()["c"]

        # --- project filters (counts respect current tag selection) ----------
        if selected_post_tags_list:
            matching_entries_sql = f"""
                SELECT et2.entry_id
                  FROM entry_tag et2
                  JOIN tag t2 ON t2.id = et2.tag_id
                  JOIN entry e2 ON e2.id = et2.entry_id
                 WHERE e2.kind='post' AND t2.name IN ({q_marks_post})
              GROUP BY et2.entry_id
                HAVING COUNT(DISTINCT t2.name)=?
            """
            project_rows = db.execute(
                f"""
                SELECT p.slug, p.title, COUNT(*) AS cnt
                  FROM project p
                  JOIN project_entry pe ON pe.project_id = p.id
                 WHERE pe.entry_id IN ({matching_entries_sql})
              GROUP BY p.id
              ORDER BY cnt DESC, LOWER(p.title)
                """,
                (*selected_post_tags_list, len(selected_post_tags_list)),
            ).fetchall()
        else:
            project_rows = db.execute(
                """
                SELECT p.slug, p.title, COUNT(*) AS cnt
                  FROM project p
                  JOIN project_entry pe ON pe.project_id = p.id
                  JOIN entry e ON e.id = pe.entry_id
                 WHERE e.kind='post'
              GROUP BY p.id
              ORDER BY cnt DESC, LOWER(p.title)
                """
            ).fetchall()

        project_filters_list = [dict(r) for r in project_rows]
        valid_slugs = {p["slug"] for p in project_filters_list}
        if selected_project and selected_project not in valid_slugs:
            selected_project = ""
        if selected_project:
            project_join = (
                " JOIN project_entry pe ON pe.entry_id = e.id"
                " JOIN project p ON p.id = pe.project_id"
            )
            project_where = " AND p.slug=?"
            params.append(selected_project)

        # --- tag filters for posts (respect current project selection) -------
        post_tag_base_where = "WHERE e2.kind='post'"
        post_tag_params: list[str] = []
        post_tag_join = ""
        if selected_project:
            post_tag_join = (
                " JOIN project_entry pe2 ON pe2.entry_id = e2.id"
                " JOIN project p2 ON p2.id = pe2.project_id"
            )
            post_tag_base_where += " AND p2.slug=?"
            post_tag_params.append(selected_project)

        if selected_post_tags_list:
            matching_entries_sql = f"""
                SELECT et2.entry_id
                  FROM entry_tag et2
                  JOIN tag t2 ON t2.id = et2.tag_id
                  JOIN entry e2 ON e2.id = et2.entry_id
                  {post_tag_join}
                 {post_tag_base_where} AND t2.name IN ({q_marks_post})
              GROUP BY et2.entry_id
                HAVING COUNT(DISTINCT t2.name)=?
            """
            match_params = (
                *post_tag_params,
                *selected_post_tags_list,
                len(selected_post_tags_list),
            )
        else:
            matching_entries_sql = f"""
                SELECT e2.id AS entry_id
                  FROM entry e2
                  {post_tag_join}
                 {post_tag_base_where}
            """
            match_params = tuple(post_tag_params)

        post_tag_count_rows = db.execute(
            f"""
            SELECT t.name, COUNT(*) AS cnt
              FROM tag t
              JOIN entry_tag et ON et.tag_id = t.id
             WHERE et.entry_id IN ({matching_entries_sql})
          GROUP BY t.name
            """,
            match_params,
        ).fetchall()
        co_occurring_post = {r["name"].lower() for r in post_tag_count_rows}
        post_tag_counts = {r["name"].lower(): r["cnt"] for r in post_tag_count_rows}
        for t in selected_post_tags_list:
            post_tag_counts.setdefault(t, 0)
        all_post_tags = set(post_tag_counts) | set(selected_post_tags_list)

        def post_tag_href(new_sel: set[str]) -> str:
            tag_param = "+".join(sorted(new_sel))
            params_dict = {}
            if selected_project:
                params_dict["project"] = selected_project
            if tag_param:
                params_dict["tag"] = tag_param
            return url_for("by_kind", slug=kind_to_slug("post"), **params_dict)

        post_tag_filters = [
            {
                "tag": t,
                "cnt": post_tag_counts.get(t, 0),
                "active": t in selected_post_tags,
                "hint": bool(
                    selected_post_tags
                    and t not in selected_post_tags
                    and t in co_occurring_post
                ),
                "href": post_tag_href(
                    (selected_post_tags - {t})
                    if t in selected_post_tags
                    else (selected_post_tags | {t})
                ),
            }
            for t in sorted(
                all_post_tags, key=lambda kv: (-post_tag_counts.get(kv, 0), kv)
            )
        ]

        if selected_post_tags_list:
            tag_join = (
                " JOIN entry_tag et_filter ON et_filter.entry_id = e.id"
                " JOIN tag t_filter ON t_filter.id = et_filter.tag_id"
            )
            tag_group_having = f"""
            GROUP BY e.id
              HAVING COUNT(
                  DISTINCT CASE WHEN t_filter.name IN ({q_marks_post})
                                THEN t_filter.name END
              )=?
            """
            params.extend(selected_post_tags_list)
            params.append(len(selected_post_tags_list))
    elif kind == "pin":
        q_marks_pin = (
            ",".join("?" * len(selected_pin_tags_list))
            if selected_pin_tags_list
            else ""
        )
        # host filters, respecting current tag selection so counts stay accurate
        site_rows = db.execute(
            f"""
            SELECT host, COUNT(*) AS cnt
              FROM (
                SELECT link_host(e2.link) AS host
                  FROM entry e2
                  {"JOIN entry_tag et2 ON et2.entry_id = e2.id JOIN tag t2 ON t2.id = et2.tag_id" if selected_pin_tags_list else ""}
                 WHERE e2.kind='pin' AND link_host(e2.link)!=''
                   {"AND t2.name IN (" + q_marks_pin + ")" if selected_pin_tags_list else ""}
              GROUP BY e2.id, host
                {"HAVING COUNT(DISTINCT t2.name)=?" if selected_pin_tags_list else ""}
              ) sub
          GROUP BY host
          ORDER BY cnt DESC, host ASC
            """,
            (*selected_pin_tags_list, len(selected_pin_tags_list))
            if selected_pin_tags_list
            else (),
        ).fetchall()
        site_filters = [
            {
                "host": r["host"],
                "cnt": r["cnt"],
                "href": pins_from_href(r["host"]),
                "active": r["host"] == selected_site,
            }
            for r in site_rows
            if r["host"]
        ]
        total_pins = db.execute(
            "SELECT COUNT(*) AS c FROM entry WHERE kind='pin'"
        ).fetchone()["c"]

        # tag filters for pins (respect current host selection)
        pin_tag_base_where = "WHERE e2.kind='pin'"
        pin_tag_params: list[str] = []
        if selected_site:
            pin_tag_base_where += " AND link_host(e2.link)=?"
            pin_tag_params.append(selected_site)

        if selected_pin_tags_list:
            matching_entries_sql = f"""
                SELECT et2.entry_id
                  FROM entry_tag et2
                  JOIN tag t2 ON t2.id = et2.tag_id
                  JOIN entry e2 ON e2.id = et2.entry_id
                 {pin_tag_base_where} AND t2.name IN ({q_marks_pin})
              GROUP BY et2.entry_id
                HAVING COUNT(DISTINCT t2.name)=?
            """
            match_params = (
                *pin_tag_params,
                *selected_pin_tags_list,
                len(selected_pin_tags_list),
            )
        else:
            matching_entries_sql = f"""
                SELECT e2.id AS entry_id
                  FROM entry e2
                 {pin_tag_base_where}
            """
            match_params = tuple(pin_tag_params)

        pin_tag_count_rows = db.execute(
            f"""
            SELECT t.name, COUNT(*) AS cnt
              FROM tag t
              JOIN entry_tag et ON et.tag_id = t.id
             WHERE et.entry_id IN ({matching_entries_sql})
          GROUP BY t.name
            """,
            match_params,
        ).fetchall()
        co_occurring_pin = {r["name"].lower() for r in pin_tag_count_rows}
        pin_tag_counts = {r["name"].lower(): r["cnt"] for r in pin_tag_count_rows}
        for t in selected_pin_tags_list:
            pin_tag_counts.setdefault(t, 0)
        all_pin_tags = set(pin_tag_counts) | set(selected_pin_tags_list)

        def pin_tag_href(new_sel: set[str]) -> str:
            tag_param = "+".join(sorted(new_sel))
            params_dict = {}
            if selected_site:
                params_dict["from"] = selected_site
            if tag_param:
                params_dict["tag"] = tag_param
            return url_for("by_kind", slug=kind_to_slug("pin"), **params_dict)

        pin_tag_filters = [
            {
                "tag": t,
                "cnt": pin_tag_counts.get(t, 0),
                "active": t in selected_pin_tags,
                "hint": bool(
                    selected_pin_tags
                    and t not in selected_pin_tags
                    and t in co_occurring_pin
                ),
                "href": pin_tag_href(
                    (selected_pin_tags - {t})
                    if t in selected_pin_tags
                    else (selected_pin_tags | {t})
                ),
            }
            for t in sorted(
                all_pin_tags, key=lambda kv: (-pin_tag_counts.get(kv, 0), kv)
            )
        ]

        if selected_site:
            site_where = " AND link_host(e.link)=?"
            params.append(selected_site)
        if selected_pin_tags_list:
            tag_join = (
                " JOIN entry_tag et_filter ON et_filter.entry_id = e.id"
                " JOIN tag t_filter ON t_filter.id = et_filter.tag_id"
            )
            tag_group_having = f"""
            GROUP BY e.id
              HAVING COUNT(
                  DISTINCT CASE WHEN t_filter.name IN ({q_marks_pin})
                                THEN t_filter.name END
              )=?
            """
            params.extend(selected_pin_tags_list)
            params.append(len(selected_pin_tags_list))

    BASE_SQL = f"""
        SELECT e.*, ei.action
          FROM entry e
          LEFT JOIN entry_item ei ON ei.entry_id = e.id
          {project_join}
          {tag_join}
         WHERE e.kind = ?{project_where}{site_where}
         {tag_group_having}
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
        selected_site=selected_site,
        total_posts=total_posts,
        post_tags=post_tag_filters,
        selected_post_tags=selected_post_tags,
        selected_post_tags_param=selected_post_tags_param,
        photo_tags=photo_tag_filters,
        selected_photo_tags=selected_photo_tags,
        selected_photo_tags_param=selected_photo_tags_param,
        say_tags=say_tag_filters,
        selected_say_tags=selected_say_tags,
        selected_say_tags_param=selected_say_tags_param,
        total_says=total_says,
        total_photos=total_photos,
        photo_cards=[],
        site_filters=site_filters,
        pin_tags=pin_tag_filters,
        selected_pin_tags=selected_pin_tags,
        selected_pin_tags_param=selected_pin_tags_param,
        total_pins=total_pins,
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
                <input name="title"
                       class="writing-input"
                       style="margin:0"
                       placeholder="Title"
                       value="{{ form_title or '' }}">
            {% endif %}
            {# Link field only for Pins #}
            {% if kind == 'pin' %}
                <input name="link"
                       class="writing-input"
                       style="margin:0"
                       placeholder="Link"
                       value="{{ form_link or '' }}">
            {% endif %}
            <textarea name="body"
                      class="writing-area"
                      rows="3"
                      data-autogrow="true"
                      style="margin:0"
                      placeholder="What's on your mind?">{{ form_body or '' }}</textarea>
            
            <div style="display:flex;gap:.5rem;align-items:center;flex-wrap:wrap;width:100%;">
                <button style="width:">Add&nbsp;{{ kind.capitalize() }}</button>
                {% if r2_enabled() %}
                    <input type="file" class="img-upload-input" accept="image/*" style="display:none">
                    <button type="button"
                            class="img-upload-btn"
                            aria-label="Upload images"
                            title="Upload images"
                            style="background:#333;color:#FFF;border:1px solid #666;display:inline-flex;align-items:center;justify-content:center;vertical-align:middle;padding:5px 10px;">
                        {{ upload_icon() }}
                    </button>
                    <span class="img-upload-status" style="font-size:.85em;color:#888;"></span>
                {% endif %}
                {% if kind=='post' %}
                <span style="margin-left:auto;"></span>
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
            {% if project_filters or post_tags %}
            <style>
            .post-filter-grid details.more-toggle + .more-panel{display:none;}
            .post-filter-grid details.more-toggle[open] + .more-panel{display:flex;flex-wrap:wrap;gap:.25rem .5rem;margin-top:.35rem;grid-column:1 / span 2;}
            </style>
            {% set active_project = (project_filters|selectattr('slug','equalto',selected_project)|list|first) %}
            {% set active_post_tags = post_tags|selectattr('active')|list %}
            <div class="post-filter-grid" style="display:grid; grid-template-columns:1fr auto; grid-template-rows:auto auto; column-gap:.75rem; row-gap:.35rem; align-items:start; margin-bottom:.75rem;">
                <div style="display:flex; flex-wrap:wrap; gap:.25rem .5rem;">
                    <a href="{{ url_for('by_kind', slug=kind_to_slug('post')) }}"
                       style="text-decoration:none !important;
                              border-bottom:none!important;
                              display:inline-flex;
                              margin:.15rem 0;
                              padding:.15rem .6rem;
                              border-radius:1rem;
                              white-space:nowrap;
                              font-size:.8em;
                              {% if not selected_project and not selected_post_tags %}
                                  background:{{ theme_color() }}; color:#000;
                              {% else %}
                                  background:#444;   color:{{ theme_color() }};
                              {% endif %}">
                        All
                        <sup style="font-size:.5em;">{{ total_posts }}</sup>
                    </a>
                    {% if active_project %}
                    <a href="{{ url_for('by_kind', slug=kind_to_slug('post'), **({'tag': selected_post_tags_param} if selected_post_tags_param else {})) }}"
                       style="text-decoration:none !important;
                              border-bottom:none!important;
                              display:inline-flex;
                              margin:.15rem 0;
                              padding:.15rem .6rem;
                              border-radius:1rem;
                              white-space:nowrap;
                              font-size:.8em;
                              background:{{ theme_color() }}; color:#000;">
                        {{ active_project.title }}
                        <sup style="font-size:.5em;">{{ active_project.cnt }}</sup>
                    </a>
                    {% endif %}
                    {% for t in active_post_tags %}
                    <a href="{{ t.href }}"
                       style="text-decoration:none !important;
                              border-bottom:none!important;
                              display:inline-flex;
                              margin:.15rem 0;
                              padding:.15rem .6rem;
                              border-radius:1rem;
                              white-space:nowrap;
                              font-size:.8em;
                              background:{{ theme_color() }}; color:#000;">
                        #{{ t.tag }}
                        <sup style="font-size:.5em;">{{ t.cnt }}</sup>
                    </a>
                    {% endfor %}
                </div>
                <details class="more-toggle" style="justify-self:end;">
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
                        Filter
                        <span aria-hidden="true" style="font-size:.75em;">▾</span>
                    </summary>
                </details>
                <div class="more-panel" style="grid-column:1 / span 2;">
                    {% for pr in project_filters if pr.slug != selected_project %}
                    <a href="{{ url_for('by_kind', slug=kind_to_slug('post'), project=pr['slug'], **({'tag': selected_post_tags_param} if selected_post_tags_param else {})) }}"
                       style="text-decoration:none !important;
                              border-bottom:none!important;
                              display:inline-flex;
                              margin:.15rem 0;
                              padding:.15rem .6rem;
                              border-radius:1rem;
                              white-space:nowrap;
                              font-size:.8em;
                              background:#444;   color:{{ theme_color() }};">
                        {{ pr['title'] }}
                        <sup style="font-size:.5em;">{{ pr['cnt'] }}</sup>
                    </a>
                    {% endfor %}
                    {% if project_filters and post_tags %}<div style="width:100%; height:1px; background:#333; margin:.25rem 0;"></div>{% endif %}
                    {% for t in post_tags if not t.active %}
                    <a href="{{ t.href }}"
                       style="text-decoration:none !important;
                              border-bottom:none!important;
                              display:inline-flex;
                              margin:.15rem 0;
                              padding:.15rem .6rem;
                              border-radius:1rem;
                              white-space:nowrap;
                              font-size:.8em;
                              background:#444;   color:{{ theme_color() }};">
                        #{{ t.tag }}
                        <sup style="font-size:.5em;">{{ t.cnt }}</sup>
                    </a>
                    {% endfor %}
                </div>
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
        {% elif kind == 'say' %}
            {% if say_tags %}
            <style>
            .say-tag-grid details.more-toggle + .more-panel{display:none;}
            .say-tag-grid details.more-toggle[open] + .more-panel{display:flex;flex-wrap:wrap;gap:.25rem .5rem;margin-top:.35rem;grid-column:1 / span 2;}
            </style>
            {% set active_say_tags = say_tags|selectattr('active')|list %}
            <div class="say-tag-grid" style="display:grid; grid-template-columns:1fr auto; grid-template-rows:auto auto; column-gap:.75rem; row-gap:.35rem; align-items:start; margin-bottom:.75rem;">
                <div style="display:flex; flex-wrap:wrap; gap:.25rem .5rem;">
                    <a href="{{ url_for('by_kind', slug=kind_to_slug('say')) }}"
                       style="text-decoration:none !important;
                              border-bottom:none!important;
                              display:inline-flex;
                              margin:.15rem 0;
                              padding:.15rem .6rem;
                              border-radius:1rem;
                              white-space:nowrap;
                              font-size:.8em;
                              {% if not selected_say_tags %}
                                  background:{{ theme_color() }}; color:#000;
                              {% else %}
                                  background:#444;   color:{{ theme_color() }};
                              {% endif %}">
                        All
                        <sup style="font-size:.5em;">{{ total_says }}</sup>
                    </a>
                    {% for t in active_say_tags %}
                    <a href="{{ t.href }}"
                       style="text-decoration:none !important;
                              border-bottom:none!important;
                              display:inline-flex;
                              margin:.15rem 0;
                              padding:.15rem .6rem;
                              border-radius:1rem;
                              white-space:nowrap;
                              font-size:.8em;
                              background:{{ theme_color() }}; color:#000;">
                        #{{ t.tag }}
                        <sup style="font-size:.5em;">{{ t.cnt }}</sup>
                    </a>
                    {% endfor %}
                </div>
                <details class="more-toggle" style="justify-self:end;">
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
                        Filter
                        <span aria-hidden="true" style="font-size:.75em;">▾</span>
                    </summary>
                </details>
                <div class="more-panel" style="grid-column:1 / span 2;">
                    {% for t in say_tags if not t.active %}
                    <a href="{{ t.href }}"
                       style="text-decoration:none !important;
                              border-bottom:none!important;
                              display:inline-flex;
                              margin:.15rem 0;
                              padding:.15rem .6rem;
                              border-radius:1rem;
                              white-space:nowrap;
                              font-size:.8em;
                              background:#444;   color:{{ theme_color() }};">
                        #{{ t.tag }}
                        <sup style="font-size:.5em;">{{ t.cnt }}</sup>
                    </a>
                    {% endfor %}
                </div>
            </div>
            {% endif %}
            {% for e in rows %}
            <article class="h-entry" style="{% if not loop.last %}padding-bottom:1.5em; border-bottom:1px solid #444;{% endif %}">
                {% if e['title'] %}
                    <h2 class="p-name">{{ e['title'] }}</h2>
                {% endif %}
                <div class="e-content" style="margin-top:1.5em;">{{ e['body']|md(e['slug']) }}</div>
                {{ backlinks_panel(backlinks[e.id]) }}
                <small style="color:#aaa;">
                    <a class="u-url u-uid" href="{{ url_for('entry_detail', kind_slug=kind_to_slug(e['kind']), entry_slug=e['slug']) }}"
                        style="text-decoration:none; color:inherit;vertical-align:middle;font-variant-numeric:tabular-nums;white-space:nowrap;">
                        <time class="dt-published" datetime="{{ e['created_at'] }}">{{ e['created_at']|ts }}</time>
                    </a>&nbsp;
                    {% if session.get('logged_in') %}
                        <a href="{{ url_for('edit_entry', kind_slug=kind_to_slug(e['kind']), entry_slug=e['slug']) }}" style="vertical-align:middle;">Edit</a>&nbsp;&nbsp;
                        <a href="{{ url_for('delete_entry', kind_slug=kind_to_slug(e['kind']), entry_slug=e['slug']) }}" style="vertical-align:middle;">Delete</a>
                    {% endif %}
                </small>
            </article>
            {% else %}
                <p>No {{ heading.lower() }} yet.</p>
            {% endfor %}
        {% elif kind == 'photo' %}
            {% if photo_tags %}
            <style>
            .photo-tag-grid details.more-toggle + .more-panel{display:none;}
            .photo-tag-grid details.more-toggle[open] + .more-panel{display:flex;flex-wrap:wrap;gap:.25rem .5rem;margin-top:.35rem;grid-column:1 / span 2;}
            </style>
            {% set active_photo_tags = photo_tags|selectattr('active')|list %}
            <div class="photo-tag-grid" style="display:grid; grid-template-columns:1fr auto; grid-template-rows:auto auto; column-gap:.75rem; row-gap:.35rem; align-items:start; margin-bottom:.75rem;">
                <div style="display:flex; flex-wrap:wrap; gap:.25rem .5rem;">
                    <a href="{{ url_for('by_kind', slug=kind_to_slug('photo')) }}"
                       style="text-decoration:none !important;
                              border-bottom:none!important;
                              display:inline-flex;
                              margin:.15rem 0;
                              padding:.15rem .6rem;
                              border-radius:1rem;
                              white-space:nowrap;
                              font-size:.8em;
                              {% if not selected_photo_tags %}
                                  background:{{ theme_color() }}; color:#000;
                              {% else %}
                                  background:#444;   color:{{ theme_color() }};
                              {% endif %}">
                        All
                        <sup style="font-size:.5em;">{{ total_photos }}</sup>
                    </a>
                    {% for t in active_photo_tags %}
                    <a href="{{ t.href }}"
                       style="text-decoration:none !important;
                              border-bottom:none!important;
                              display:inline-flex;
                              margin:.15rem 0;
                              padding:.15rem .6rem;
                              border-radius:1rem;
                              white-space:nowrap;
                              font-size:.8em;
                              background:{{ theme_color() }}; color:#000;">
                        #{{ t.tag }}
                        <sup style="font-size:.5em;">{{ t.cnt }}</sup>
                    </a>
                    {% endfor %}
                </div>
                <details class="more-toggle" style="justify-self:end;">
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
                        Filter
                        <span aria-hidden="true" style="font-size:.75em;">▾</span>
                    </summary>
                </details>
                <div class="more-panel" style="grid-column:1 / span 2;">
                    {% for t in photo_tags if not t.active %}
                    <a href="{{ t.href }}"
                       style="text-decoration:none !important;
                              border-bottom:none!important;
                              display:inline-flex;
                              margin:.15rem 0;
                              padding:.15rem .6rem;
                              border-radius:1rem;
                              white-space:nowrap;
                              font-size:.8em;
                              background:#444;   color:{{ theme_color() }};">
                        #{{ t.tag }}
                        <sup style="font-size:.5em;">{{ t.cnt }}</sup>
                    </a>
                    {% endfor %}
                </div>
            </div>
            {% endif %}
            <div class="photo-grid" style="display:grid; grid-template-columns:repeat(auto-fit, minmax(160px, 1fr)); gap:.75rem; align-items:start;">
                {% for p in photo_cards %}
                    <a class="h-entry" href="{{ url_for('entry_detail', kind_slug=kind_to_slug(p.kind), entry_slug=p.slug) }}"
                       style="display:block; background:#111; border:1px solid #333; border-radius:8px; overflow:hidden;">
                        <img class="u-photo" src="{{ p.src }}" alt="{{ p.alt or 'Photo' }}"
                             style="width:100%; height:100%; display:block; object-fit:cover; aspect-ratio:1;">
                    </a>
                {% else %}
                    <p>No {{ heading.lower() }} yet.</p>
                {% endfor %}
            </div>
        {% else %}
            {% if kind == 'pin' and site_filters %}
            <style>
            .pin-filter-grid details.more-toggle + .more-panel{display:none;}
            .pin-filter-grid details.more-toggle[open] + .more-panel{display:flex;flex-wrap:wrap;gap:.25rem .5rem;margin-top:.35rem;grid-column:1 / span 2;}
            </style>
            {% set active_site = (site_filters|selectattr('active')|list|first) %}
            {% set active_pin_tags = pin_tags|selectattr('active')|list %}
            <div class="pin-filter-grid" style="display:grid; grid-template-columns:1fr auto; grid-template-rows:auto auto; column-gap:.75rem; row-gap:.35rem; align-items:start; margin-bottom:.75rem;">
                <div style="display:flex; flex-wrap:wrap; gap:.25rem .5rem;">
                    <a href="{{ url_for('by_kind', slug=kind_to_slug('pin')) }}"
                       style="text-decoration:none !important;
                              border-bottom:none!important;
                              display:inline-flex;
                              margin:.15rem 0;
                              padding:.15rem .6rem;
                              border-radius:1rem;
                              white-space:nowrap;
                              font-size:.8em;
                              {% if not selected_site and not selected_pin_tags %}
                                  background:{{ theme_color() }}; color:#000;
                              {% else %}
                                  background:#444;   color:{{ theme_color() }};
                              {% endif %}">
                        All
                        <sup style="font-size:.5em;">{{ total_pins }}</sup>
                    </a>
                    {% if active_site %}
                    <a href="{{ pins_from_href('') }}"
                       style="text-decoration:none !important;
                              border-bottom:none!important;
                              display:inline-flex;
                              margin:.15rem 0;
                              padding:.15rem .6rem;
                              border-radius:1rem;
                              white-space:nowrap;
                              font-size:.8em;
                              background:{{ theme_color() }}; color:#000;">
                        {{ active_site.host }}
                        <sup style="font-size:.5em;">{{ active_site.cnt }}</sup>
                    </a>
                    {% endif %}
                    {% for t in active_pin_tags %}
                    <a href="{{ t.href }}"
                       style="text-decoration:none !important;
                              border-bottom:none!important;
                              display:inline-flex;
                              margin:.15rem 0;
                              padding:.15rem .6rem;
                              border-radius:1rem;
                              white-space:nowrap;
                              font-size:.8em;
                              background:{{ theme_color() }}; color:#000;">
                        #{{ t.tag }}
                        <sup style="font-size:.5em;">{{ t.cnt }}</sup>
                    </a>
                    {% endfor %}
                </div>
                <details class="more-toggle" style="justify-self:end;">
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
                        Filter
                        <span aria-hidden="true" style="font-size:.75em;">▾</span>
                    </summary>
                </details>

                <div class="more-panel" style="grid-column:1 / span 2;">
                    {% for s in site_filters if not s.active %}
                    <a href="{{ s.href }}"
                       style="text-decoration:none !important;
                              border-bottom:none!important;
                              display:inline-flex;
                              margin:.15rem 0;
                              padding:.15rem .6rem;
                              border-radius:1rem;
                              white-space:nowrap;
                              font-size:.8em;
                              background:#444; color:{{ theme_color() }};">
                        {{ s.host }}
                        <sup style="font-size:.5em;">{{ s.cnt }}</sup>
                    </a>
                    {% endfor %}
                    {% if site_filters and pin_tags %}<div style="width:100%; height:1px; background:#333; margin:.25rem 0;"></div>{% endif %}
                    {% for t in pin_tags if not t.active %}
                    <a href="{{ t.href }}"
                       style="text-decoration:none !important;
                              border-bottom:none!important;
                              display:inline-flex;
                              margin:.15rem 0;
                              padding:.15rem .6rem;
                              border-radius:1rem;
                              white-space:nowrap;
                              font-size:.8em;
                              background:#444;   color:{{ theme_color() }};">
                        #{{ t.tag }}
                        <sup style="font-size:.5em;">{{ t.cnt }}</sup>
                    </a>
                    {% endfor %}
                </div>
            </div>
            {% endif %}
            {% for e in rows %}
            <article class="h-entry" style="{% if not loop.last %}padding-bottom:1.5em; border-bottom:1px solid #444;{% endif %}">
                {% if e['kind'] == 'pin' %}
                    {% set host = link_host(e['link']) %}
                    <h2 class="pin-title">
                        <a class="u-bookmark-of p-name" href="{{ e['link'] }}" target="_blank" rel="noopener">
                            {{ e['title'] }}
                        </a>
                        {% if host %}
                            <span class="pin-host">(<a href="{{ pins_from_href(host) }}">{{ host }}</a>)</span>
                        {% endif %}
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
                        <a href="{% if kind == 'post' %}
                                    {{ url_for('by_kind', slug=kind_to_slug('post'), project=selected_project or None, page=p, **({'tag': selected_post_tags_param} if selected_post_tags_param else {})) }}
                                 {% elif kind == 'pin' %}
                                    {{ request.path }}?page={{ p }}{% if selected_site %}&from={{ selected_site }}{% endif %}{% if selected_pin_tags_param %}&tag={{ selected_pin_tags_param }}{% endif %}
                                 {% elif kind == 'say' %}
                                    {{ request.path }}?page={{ p }}{% if selected_say_tags_param %}&tag={{ selected_say_tags_param }}{% endif %}
                                 {% elif kind == 'photo' %}
                                    {{ request.path }}?page={{ p }}{% if selected_photo_tags_param %}&tag={{ selected_photo_tags_param }}{% endif %}
                                 {% else %}
                                    {{ request.path }}?page={{ p }}
                                 {% endif %}">{{ p }}</a>
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
        {% if r.rating %}
        <span aria-label="{{ r.rating }} of 5"
              style="color:{{ theme_color() }};font-size:1.2rem;letter-spacing:1px;vertical-align:middle;">
            {{ "★" * r.rating }}
        </span>
        {% endif %}
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
<div style="display:flex;align-items:flex-end;justify-content:space-between;gap:1rem;flex-wrap:wrap;">
    <div style="display:flex; align-items:flex-end; gap:.5rem; flex-wrap:wrap;">
        <h2 style="margin:0;">{{ project['title'] or project['slug'] }}</h2>
        {% if session.get('logged_in') %}
            <a href="{{ url_for('project_edit', project_slug=project['slug']) }}"
               style="font-size:.85em; color:#aaa; text-decoration:none;">
               Edit
            </a>
        {% endif %}
    </div>
    <span style="display:inline-flex;
                border:1px solid #555;
                border-radius:4px;
                overflow:hidden;
                font-size:.75em;">
        <a href="{{ url_for('project_detail', project_slug=project['slug'], sort='old') }}"
           style="display:flex; align-items:center;
                  padding:.25em .85em;
                  text-decoration:none; border-bottom:none;
                  {% if sort != 'new' %}background:{{ theme_color() }};color:#000;
                  {% else %}background:#333;color:#eee;{% endif %}">
        Oldest
        </a>
        <a href="{{ url_for('project_detail', project_slug=project['slug'], sort='new') }}"
           style="display:flex; align-items:center;
                  padding:.25em .85em;
                  text-decoration:none; border-bottom:none;
                  border-left:1px solid #555;
                  {% if sort == 'new' %}background:{{ theme_color() }};color:#000;
                  {% else %}background:#333;color:#eee;{% endif %}">
        Newest
        </a>
    </span>
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


TEMPL_PROJECT_EDIT = wrap("""
{% block body %}
<hr>
<h2>Edit project</h2>
<form method="post" style="display:flex; flex-direction:column; gap:.75rem; max-width:28rem;">
    {% if csrf_token() %}
        <input type="hidden" name="csrf" value="{{ csrf_token() }}">
    {% endif %}
    <label>
        <div style="font-size:.85em;color:#aaa;">Title</div>
        <input name="title"
               class="writing-input"
               value="{{ project['title'] or '' }}"
               style="width:100%;">
    </label>
    <label>
        <div style="font-size:.85em;color:#aaa;">Slug</div>
        <input name="slug"
               class="writing-input"
               value="{{ project['slug'] }}"
               style="width:100%;">
        <div style="font-size:.8em;color:#777;">Allowed: letters, numbers, hyphen, underscore.</div>
    </label>
    <div style="display:flex; gap:.75rem;">
        <button>Save</button>
        <a href="{{ url_for('project_detail', project_slug=project['slug']) }}" style="align-self:center;">Cancel</a>
    </div>
</form>
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


@app.route("/projects/<project_slug>/edit", methods=["GET", "POST"])
def project_edit(project_slug):
    login_required()
    db = get_db()
    proj = db.execute("SELECT * FROM project WHERE slug=?", (project_slug,)).fetchone()
    if not proj:
        abort(404)

    if request.method == "POST":
        new_title = request.form.get("title", "").strip() or None
        new_slug = (request.form.get("slug", "") or project_slug).strip().strip("/")
        # allow broad Unicode slugs (match creation behavior), just collapse whitespace to dashes
        new_slug = re.sub(r"\s+", "-", new_slug).strip("-")
        if not new_slug:
            flash("Slug is required.")
        elif db.execute(
            "SELECT 1 FROM project WHERE slug=? AND id!=?", (new_slug, proj["id"])
        ).fetchone():
            flash("Slug already exists.")
        else:
            db.execute(
                "UPDATE project SET title=?, slug=? WHERE id=?",
                (new_title or new_slug, new_slug, proj["id"]),
            )
            db.commit()
            return redirect(url_for("project_detail", project_slug=new_slug))

    return render_template_string(
        TEMPL_PROJECT_EDIT,
        project=proj,
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
                {% set host = link_host(e['link']) %}
                <h2 class="pin-title">
                    <a class="u-bookmark-of p-name" href="{{ e['link'] }}" target="_blank" rel="noopener" title="{{ e['link'] }}"
                    style="word-break:break-all; overflow-wrap:anywhere;">
                    {{ e['title'] }} 
                    </a>
                    {% if host %}
                        <span class="pin-host">(<a href="{{ pins_from_href(host) }}">{{ host }}</a>)</span>
                    {% endif %}
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
        verb_hint = row["kind"] if row["kind"] in VERB_KINDS else None
        body_parsed, blocks, errors = parse_trigger(
            body_for_parse, verb_hint=verb_hint
        )  # ← only call once

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

        tags = extract_tags(body_parsed)
        new_kind = apply_photo_kind(new_kind, tags)

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
        sync_tags(row["id"], tags, db=db)
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
                class="writing-input"
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
                class="writing-input"
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
            class="writing-input"
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

    <textarea name="body"
              class="writing-area"
              data-autogrow="true"
              rows="8">{{ e['body'] }}</textarea><br>
    <div style="display:flex;gap:.5rem;align-items:center;flex-wrap:wrap;width:100%;margin-bottom:.5rem;">
        <button>Save</button>
        {% if r2_enabled() %}
            <input type="file" class="img-upload-input" accept="image/*" style="display:none">
            <button type="button"
                    class="img-upload-btn"
                    aria-label="Upload images"
                    title="Upload images"
                    style="background:#333;color:#FFF;border:1px solid #666;display:inline-flex;align-items:center;justify-content:center;vertical-align:middle;padding:5px 10px;">
                {{ upload_icon() }}
            </button>
            <span class="img-upload-status" style="font-size:.85em;color:#888;"></span>
        {% endif %}
        <span style="flex:1;"></span>
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
    q_marks = ",".join("?" * len(selected)) if selected else ""

    # ---------- tags that would still return results if added -----------------
    co_occurring: set[str] = set()
    if selected:
        co_sql = f"""
            SELECT DISTINCT t.name
              FROM entry_tag et
              JOIN tag t ON t.id = et.tag_id
             WHERE et.entry_id IN (
                SELECT et2.entry_id
                  FROM entry_tag et2
                  JOIN tag t2 ON t2.id = et2.tag_id
                 WHERE t2.name IN ({q_marks})
              GROUP BY et2.entry_id
                HAVING COUNT(DISTINCT t2.name)=?
             )
        """
        co_occurring = {
            r["name"].lower() for r in db.execute(co_sql, (*selected, len(selected)))
        }

    # ---------- scale counts → font-size (same as before) -------------------
    counts = [r["cnt"] for r in rows]
    lo, hi = (min(counts), max(counts)) if counts else (0, 0)
    span = max(1, hi - lo)
    for r in rows:
        r_name_lower = r["name"].lower()
        weight = (r["cnt"] - lo) / span if counts else 0
        r["size"] = f"{0.75 + weight * 1.2:.2f}em"
        r["active"] = r_name_lower in selected
        r["hint"] = bool(selected and not r["active"] and r_name_lower in co_occurring)

        # ── URL that would result from clicking the pill ────────────────────
        new_sel = (
            (selected - {r_name_lower}) if r["active"] else (selected | {r_name_lower})
        )
        r["href"] = tags_href("+".join(sorted(new_sel))) if new_sel else tags_href()

    # ---------- fetch entries if something is selected ----------------------
    sort = request.args.get("sort", "new")
    page = max(int(request.args.get("page", 1)), 1)
    per = page_size()
    if selected:
        order_sql = "e.created_at DESC" if sort == "new" else "e.created_at ASC"
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
                box-shadow:{% if t.hint %}0 0 0 1px {{ theme_color() }}{% else %}none{% endif %};
                opacity:{% if selected and not t.active and not t.hint %}0.45{% else %}1{% endif %};
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
                {% if e['kind']=='post' %}
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
    db = get_db()

    def _item_ctx(entry_id: int):
        """
        Return one linked item row (if any) with minimal metadata.
        """
        return db.execute(
            """
            SELECT i.title   AS item_title,
                   i.slug    AS item_slug,
                   i.item_type,
                   ei.action AS item_action,
                   ei.progress,
                   MIN(CASE
                        WHEN im.k = 'date'
                             AND LENGTH(im.v) >= 4
                        THEN SUBSTR(im.v, 1, 4)
                   END)      AS item_year
              FROM entry_item ei
              JOIN item      i  ON i.id = ei.item_id
              LEFT JOIN item_meta im ON im.item_id = i.id
             WHERE ei.entry_id=?
          GROUP BY i.id, ei.action, ei.progress
             LIMIT 1
            """,
            (entry_id,),
        ).fetchone()

    def _body_excerpt(text: str | None, limit: int = 80) -> str:
        clean = strip_caret(text)
        # strip markdown/HTML images entirely (leave alt text if present)
        clean = re.sub(r"!\[([^\]]*)\]\([^)]+\)", r"\1", clean)
        clean = re.sub(r"<img[^>]*alt=['\"]([^'\"]+)['\"][^>]*>", r"\1", clean)
        clean = re.sub(r"<img\b[^>]*>", "", clean)
        clean = re.sub(r"@(entry|item):[^\s]+", "", clean)  # drop inline embed markers
        clean = re.sub(r"\s+", " ", clean).strip()
        if not clean:
            return ""
        return clean if len(clean) <= limit else clean[:limit].rstrip() + "…"

    def _checkin_title(kind: str, itm) -> str:
        label = smartcap(itm["item_action"] or kind)
        base = f"{label}: {itm['item_title'] or itm['item_slug']}"
        extras = [p for p in (itm["progress"], itm["item_year"]) if p]
        if extras:
            base += f" ({' · '.join(extras)})"
        return base

    def _pin_title(e) -> str:
        if e["title"]:
            core = e["title"]
        elif e["link"]:
            core = urlparse(e["link"]).netloc or e["slug"]
        else:
            core = e["slug"]
        return f"Pin: {core}"

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

        itm = _item_ctx(e["id"])
        tags = entry_tags(e["id"], db=db) if "id" in e.keys() else []

        # ── title crafting ─────────────────────────────────────────────
        if e["kind"] in VERB_KINDS and itm:
            rss_title = _checkin_title(e["kind"], itm)
        elif e["kind"] == "pin":
            rss_title = _pin_title(e)
        elif e["title"]:
            rss_title = e["title"]
        else:
            excerpt = _body_excerpt(e["body"])
            rss_title = f"{smartcap(e['kind'])}: {excerpt}" if excerpt else e["slug"]

        # ── description preamble ───────────────────────────────────────
        body_html = render_markdown_html(
            e["body"], source_slug=e["slug"], absolute_links=True
        )
        preamble = ""
        if e["kind"] == "pin" and e["link"]:
            pin_label = e["title"] or urlparse(e["link"]).netloc or e["slug"]
            preamble = (
                f"<p><strong>Pin</strong>: "
                f'<a href="{escape(e["link"])}">{escape(pin_label)}</a></p>'
            )

        desc_html = preamble + body_html if preamble else body_html
        cat_xml = "".join(f"<category>{escape(t)}</category>" for t in tags)

        items.append(
            f"""
        <item>
          <title>{escape(rss_title)}</title>
          <link>{link}</link>
          <guid isPermaLink="false">{guid}</guid>
          <pubDate>{ts_rfc}</pubDate>
          {cat_xml}
          <description><![CDATA[{desc_html}]]></description>
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

    db = get_db()

    q_marks = ",".join("?" * len(tags))
    sql = f"""SELECT e.* FROM entry e
              JOIN entry_tag et ON et.entry_id = e.id
              JOIN tag t        ON t.id        = et.tag_id
              WHERE t.name IN ({q_marks})
              GROUP BY e.id HAVING COUNT(DISTINCT t.name)=?
              ORDER BY e.created_at DESC LIMIT 50"""
    rows = db.execute(sql, (*tags, len(tags))).fetchall()

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

    item_type_norm = normalize_item_type(item_type)
    if not item_type_norm:
        abort(404)

    verb = slug_to_kind(verb)
    if verb not in VERB_KINDS:
        abort(404)
    db = get_db()
    ensure_item_rating_column(db)
    itm = db.execute(
        "SELECT id, uuid, slug, item_type, title, rating "
        "FROM item WHERE slug=? AND LOWER(item_type)=?",
        (slug, item_type_norm),
    ).fetchone()
    if not itm:
        abort(404)
    if itm["item_type"] != item_type_norm:
        db.execute("UPDATE item SET item_type=? WHERE id=?", (item_type_norm, itm["id"]))
        db.commit()
        itm = dict(itm)
        itm["item_type"] = item_type_norm

    actions_for_item = db.execute(
        "SELECT action FROM entry_item WHERE item_id=? AND verb=?", (itm["id"], verb)
    ).fetchall()
    finished_actions = [
        r["action"] for r in actions_for_item if is_completed_action(r["action"])
    ]
    rating_ready = bool(finished_actions)

    # ──────────────────────────────── POST: quick “check-in” ──────────────
    if request.method == "POST":
        login_required()

        if "rating" in request.form:
            rating_raw = (request.form.get("rating") or "").strip()
            if not rating_ready:
                flash("Add a finished check-in before scoring.")
                return redirect(request.url)
            try:
                rating_val = int(rating_raw)
            except ValueError:
                flash("Score must be a number between 0 and 5.")
                return redirect(request.url)

            if not 0 <= rating_val <= 5:
                flash("Score must be between 0 and 5.")
                return redirect(request.url)

            if rating_val == 0:
                db.execute("UPDATE item SET rating=NULL WHERE id=?", (itm["id"],))
                flash("Score cleared.")
            else:
                db.execute(
                    "UPDATE item SET rating=? WHERE id=?", (rating_val, itm["id"])
                )
                flash(f"Score saved ({rating_val}/5).")
            db.commit()
            return redirect(request.url)

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

        body, blocks, errors = parse_trigger(
            body_raw, verb_hint=verb, allow_unknown_actions=True
        )  # normal pipeline
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
        # make hashtags searchable immediately (skip requires manual re-edit)
        sync_tags(entry_id, extract_tags(body), db=db)
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

    embed_rows = db.execute(
        """
            SELECT id, slug, kind, title, created_at, body, link
              FROM entry
             WHERE body LIKE ?
               AND kind!='page'
               AND id NOT IN (SELECT entry_id FROM entry_item WHERE item_id=?)
             ORDER BY created_at DESC
        """,
        (f"%@item:{itm['slug']}%", itm["id"]),
    ).fetchall()

    embed_rows = [r for r in embed_rows if _has_item_embed(r["body"], itm["slug"])]
    embed_ids = {r["id"] for r in embed_rows}

    mention_rows = db.execute(
        """
            SELECT id, slug, kind, title, created_at, body, link
              FROM entry
             WHERE body LIKE ?
               AND kind!='page'
               AND id NOT IN (SELECT entry_id FROM entry_item WHERE item_id=?)
        """,
        (f"%{itm['slug']}%", itm["id"]),
    ).fetchall()
    mention_rows = [
        r
        for r in mention_rows
        if r["id"] not in embed_ids
        and _contains_slug_outside_code(r["body"], itm["slug"])
    ]

    def _row_dict(r, *, is_embed: bool = False):
        d = dict(r)
        d.setdefault("action", None)
        d.setdefault("progress", None)
        d["is_mention"] = is_embed
        body = r["body"] or ""
        d["timeline_body"] = _strip_embed_lines(body) if is_embed else body
        return d

    timeline_rows = [_row_dict(r) for r in rows]
    timeline_rows += [_row_dict(r, is_embed=True) for r in embed_rows]
    timeline_rows += [_row_dict(r, is_embed=True) for r in mention_rows]
    if sort == "old":
        timeline_rows.sort(key=lambda r: r["created_at"])
    else:
        timeline_rows.sort(key=lambda r: r["created_at"], reverse=True)

    back_map = backlinks(timeline_rows, db=db)
    rating_value = int(itm["rating"]) if itm["rating"] is not None else 0

    return render_template_string(
        TEMPL_ITEM_DETAIL,
        item=itm,
        meta=meta,
        entries=timeline_rows,
        can_rate=rating_ready,
        rating_value=rating_value,
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
<div style="margin-top:0;display:flex;align-items:center;gap:.75rem;flex-wrap:wrap;">
    <h2 style="margin:0;min-width:0;flex:1 1 auto;display:flex;align-items:center;gap:.5rem;flex-wrap:wrap;">
        <span>{{ item['title'] }}{% if _year %} ({{ _year }}){% endif %}</span>
        {% if rating_value and not session.get('logged_in') %}
            <span aria-label="Score {{ rating_value }} of 5"
                style="display:inline-flex;align-items:center;color:{{ theme_color() }};font-size:1.2rem;letter-spacing:1px;white-space:nowrap;">
                {{ "★" * rating_value }}
            </span>
        {% endif %}
    </h2>
</div>
            
{% if meta %}
<ul  style="display:flex;align-items:flex-start;gap:1rem;         
            list-style:none;padding:0;margin:0;font-size:.9em;color:#aaa;">

    {# ─────── cover column ─────── #}
    {% for r in meta if is_b64_image(r.k, r.v) or is_url_image(r.k, r.v) %}
    <li style="float:left;margin:.65em .75rem .75rem 0;">
        <img src="{% if is_b64_image(r.k, r.v) %}data:image/webp;base64,{{ r.v }}{% else %}{{ r.v }}{% endif %}"
             alt="{{ item.title }}"
             style="width:135px;max-width:100%;
                    border:1px solid #555;margin:0;">
    </li>
    {% endfor %}

    {# ─────── details column ─────── #}
    <li style="flex:1;">                                           
        <ul style="list-style:none;padding:0;margin:0;">
        {% for r in meta if not is_b64_image(r.k, r.v) and not is_url_image(r.k, r.v) %}
            <li style="margin:.2em 0;">
                <strong>{{ r.k|smartcap }}:</strong>
                {% set tokens = meta_search_tokens(item['item_type'], r.k, r.v) %}
                {% if tokens %}
                    {% for tok in tokens %}
                    <a href="{{ url_for('search', q=tok.query) }}"
                       style="color:#ccc;border-bottom:0.1px dotted currentColor;text-decoration:none;">
                        {{ tok.label|mdinline }}
                    </a>{% if not loop.last %}<span aria-hidden="true"> / </span>{% endif %}
                    {% endfor %}
                {% else %}
                    {{ r.v|mdinline }}
                {% endif %}
            </li>
        {% endfor %}
        </ul>
    </li>
</ul>
{% endif %}


{% if session.get('logged_in') %}
<div style="display:flex;align-items:center;gap:1rem;flex-wrap:wrap;margin:.35rem 0;">
    <div style="display:flex;align-items:center;gap:.75rem;flex-wrap:wrap;">
        {% if r2_enabled() %}
        <input type="file" class="cover-upload-input" accept="image/*" style="display:none">
        <button type="button"
                class="cover-upload-btn"
                data-upload-url="{{ url_for('upload_cover', verb=verb_slug, item_type=item['item_type'], slug=item['slug']) }}"
                aria-label="Upload cover image"
                title="Upload cover image"
                style="background:#333;color:#FFF;border:1px solid #666;display:inline-flex;align-items:center;justify-content:center;vertical-align:middle;padding:5px 10px;">
            {{ upload_icon() }}
        </button>
        <span class="cover-upload-status" style="font-size:.85em;color:#888;"></span>
        {% endif %}
        <a href="{{ url_for('edit_item',
                        verb=verb_slug, item_type=item['item_type'], slug=item['slug']) }}">Edit</a>
        <a href="{{ url_for('delete_item',
                        verb=verb_slug, item_type=item['item_type'], slug=item['slug']) }}">Delete</a>
    </div>

    {% if can_rate %}
    <style>
    .score-stars {
        display:inline-flex;
        flex-direction:row-reverse;
        gap:.35rem;
    }
    .score-star {
        appearance:none;
        background:none;
        border:0;
        padding:0;
        margin:0;
        color:#555;
        font-size:1.5rem;
        line-height:1;
        cursor:pointer;
        transition:color 120ms ease;
    }
    .score-star:hover,
    .score-star:hover ~ .score-star {
        color:{{ theme_color() }};
        background-color:transparent;
    }
    .score-stars[data-score="1"] .score-star:nth-last-child(-n+1),
    .score-stars[data-score="2"] .score-star:nth-last-child(-n+2),
    .score-stars[data-score="3"] .score-star:nth-last-child(-n+3),
    .score-stars[data-score="4"] .score-star:nth-last-child(-n+4),
    .score-stars[data-score="5"] .score-star:nth-last-child(-n+5) {
        color:{{ theme_color() }};
    }
    .score-star:focus-visible {
        outline:2px solid {{ theme_color() }};
        outline-offset:2px;
    }
    .score-clear {
        background:none;
        border:0;
        padding:0 .35rem;
        color:#888;
        cursor:pointer;
        font-size:.9rem;
        text-decoration:underline dotted;
    }
    </style>
    <form method="post"
          aria-label="Your score for this item"
          style="display:flex;align-items:center;gap:.4rem;flex-wrap:wrap;">
        {% if csrf_token() %}
            <input type="hidden" name="csrf" value="{{ csrf_token() }}">
        {% endif %}
        <div class="score-stars"
             data-score="{{ rating_value }}"
             role="group"
             aria-label="Your score for this item">
            {% for n in range(5,0,-1) %}
            <button type="submit"
                    name="rating"
                    value="{{ n }}"
                    class="score-star"
                    aria-label="{{ n }} of 5">
                ★</button>
            {% endfor %}
        </div>
        {% if rating_value %}
        <button type="submit" name="rating" value="0" class="score-clear" aria-label="Clear score">
            Clear
        </button>
        {% endif %}
    </form>
    {% endif %}
</div>
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
            class="writing-area"
            data-autogrow="true"
            rows="3"
            style="margin:0;"
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
    {% if e.is_mention %}
        {% if e.kind == 'pin' and e.link %}
            {% set host = link_host(e.link) %}
            <h2 class="pin-title">
                <a class="u-bookmark-of p-name" href="{{ e.link }}" target="_blank" rel="noopener"
                   title="{{ e.link }}"
                   style="word-break:break-all; overflow-wrap:anywhere; text-decoration:none; border-bottom:0.1px dotted currentColor; color:inherit;">
                    {{ e['title'] or e['slug'] }}
                </a>
                {% if host %}
                    <span class="pin-host">(<a href="{{ pins_from_href(host) }}">{{ host }}</a>)</span>
                {% endif %}
            </h2>
        {% elif e['title'] %}
            <h2 class="p-name" style="margin:0;">{{ e['title'] }}</h2>
        {% endif %}
        <div class="e-content" style="margin-top:1.5em;">{{ e['timeline_body']|md(e['slug']) }}</div>
    {% else %}
        <div class="e-content" style="margin-top:1.5em;">{{ e['timeline_body']|md(e['slug']) }}</div>
    {% endif %}
    {{ backlinks_panel(backlinks[e.id]) }}
    <small style="color:#aaa;">

        {# —— action pill ——————————————————————————————— #}
        {% if e.is_mention %}
        <span style="
            display:inline-block;padding:.1em .6em;margin-right:.4em;
            background:#555;color:#fff;border-radius:1em;font-size:.75em;
            text-transform:capitalize;vertical-align:middle;">
            mentioned
        </span>
        <span style="
            display:inline-block;padding:.1em .6em;margin-right:.4em;
            background:#444;color:#fff;border-radius:1em;font-size:.75em;
            text-transform:capitalize;vertical-align:middle;">
            <a href="{{ url_for('by_kind', slug=kind_to_slug(e['kind'])) }}"
               style="text-decoration:none;color:inherit;border-bottom:none;">
               {{ e.kind }}
            </a>
        </span>
        {% else %}
        <span style="
            display:inline-block;padding:.1em .6em;margin-right:.4em;
            background:#444;color:#fff;border-radius:1em;font-size:.75em;
            text-transform:capitalize;vertical-align:middle;">
            {{ e.action | smartcap }}
        </span>
        {% if e.progress %}
        <span style="
                display:inline-block;padding:.1em .6em;margin-right:.4em;
                background:#444;color:#fff;border-radius:1em;font-size:.75em;
                vertical-align:middle;">
            {{ e.progress }}
        </span>
        {% endif %}
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
    </small>
</article>
{% else %}
<p>No entries yet.</p>
{% endfor %}

{% endblock %}
""")


@app.route("/<verb>/<item_type>/<slug>/edit", methods=["GET", "POST"])
def edit_item(verb, item_type, slug):
    item_type_norm = normalize_item_type(item_type)
    if not item_type_norm:
        abort(404)

    verb = slug_to_kind(verb)
    if verb not in VERB_KINDS:
        abort(404)
    login_required()
    db = get_db()
    itm = db.execute(
        "SELECT * FROM item WHERE slug=? AND LOWER(item_type)=?",
        (slug, item_type_norm),
    ).fetchone()
    if not itm:
        abort(404)
    if itm["item_type"] != item_type_norm:
        db.execute("UPDATE item SET item_type=? WHERE id=?", (item_type_norm, itm["id"]))
        db.commit()
        itm = dict(itm)
        itm["item_type"] = item_type_norm

    if request.method == "POST":
        title = request.form["title"].strip()
        new_slug = request.form["slug"].strip() or itm["slug"]
        new_type_raw = request.form["item_type"].strip() or itm["item_type"]
        new_type = normalize_item_type(new_type_raw) or itm["item_type"]

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

<form method="post" style="max-width:100%;display:flex;flex-direction:column;gap:1rem;">
  {% if csrf_token() %}
            <input type="hidden" name="csrf" value="{{ csrf_token() }}">
            {% endif %}
  {# ────────── title / slug / type ────────── #}
  <label>
    <span style="font-size:.8em;color:#888">Title</span><br>
    <input name="title"
           class="writing-input"
           value="{{ item['title'] }}"
           style="width:100%">
  </label>

  <label>
    <span style="font-size:.8em;color:#888">Slug</span><br>
    <input name="slug"
           class="writing-input"
           value="{{ item['slug']  }}"
           style="width:100%">
  </label>

  <label>
    <span style="font-size:.8em;color:#888">Item type</span><br>
    <input name="item_type"
           class="writing-input"
           value="{{ item['item_type'] }}"
           style="width:100%">
  </label>

  {# ────────── key / value rows ────────── #}
  <fieldset style="border:0;padding:0;">
    <legend style="font-weight:bold;margin-bottom:.25rem;font-size:.9em;">Meta data</legend>

    <div style="display:grid;
                grid-template-columns:5rem 1fr 2fr;
                gap:.5rem; align-items:center;">

    {# header row #}
    <span style="font-size:.75em;color:#888;text-align:right;">#</span>
    <span style="font-size:.75em;color:#888;">Key</span>
    <span style="font-size:.75em;color:#888;">Value</span>

    {# existing pairs #}
    {% for r in meta %}
        <input name="meta_o"
               class="writing-input"
               value="{{ r['ord'] }}"
               style="width:5rem;text-align:right;">
        <input name="meta_k"
               class="writing-input"
               value="{{ r['k'] }}"
               placeholder="key">
        <input name="meta_v"
               class="writing-input"
               value="{{ r['v'] }}"
               placeholder="value">
    {% endfor %}

    {# ten blank rows for new data #}
    {% for _ in range(10) %}
        <input name="meta_o"
               class="writing-input"
               placeholder=""
               style="width:5rem;text-align:right;">
        <input name="meta_k"
               class="writing-input"
               placeholder="key">
        <input name="meta_v"
               class="writing-input"
               placeholder="value">
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
    item_type_norm = normalize_item_type(item_type)
    if not item_type_norm:
        abort(404)

    verb = slug_to_kind(verb)
    if verb not in VERB_KINDS:
        abort(404)
    login_required()
    db = get_db()
    itm = db.execute(
        "SELECT * FROM item WHERE slug=? AND LOWER(item_type)=?",
        (slug, item_type_norm),
    ).fetchone()
    if not itm:
        abort(404)
    if itm["item_type"] != item_type_norm:
        db.execute("UPDATE item SET item_type=? WHERE id=?", (item_type_norm, itm["id"]))
        db.commit()
        itm = dict(itm)
        itm["item_type"] = item_type_norm

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
    (?P<type>[^:]+?)               # track / short story / …
    \s*:\s*
    (?: (?P<field>[^:]+?) \s*:\s* )?   # 演唱 / 作者 / …
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
    d["type"] = (d["type"] or "").strip().lower()
    d["field"] = d["field"].strip().lower() if d["field"] else None
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
    conds, params = ["LOWER(i.item_type) = ?"], [spec["type"]]
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
# Statistics
###############################################################################
def _order_kinds(used: set[str]) -> list[str]:
    """Stable ordering for kind pills: core kinds first, then the rest."""
    base = [k for k in KINDS if k != "page" and k in used]
    for k in sorted(used):
        if k not in base and k != "page":
            base.append(k)
    return base


def _stats_yearly(*, db, limit: int | None = None):
    """
    Aggregate entries per year with per-kind counts, words, and tag breadth.
    """
    rows = db.execute(
        f"""
        SELECT substr(created_at,1,4) AS y,
               LOWER(kind)            AS kind,
               COUNT(*)                AS cnt,
               SUM({WORD_COUNT_SQL})   AS words
          FROM entry
         WHERE kind!='page'
      GROUP BY y, LOWER(kind)
      ORDER BY y DESC
        """
    ).fetchall()

    buckets: dict[str, dict] = {}
    used: set[str] = set()
    for r in rows:
        year = r["y"]
        bucket = buckets.setdefault(
            year, {"year": year, "total": 0, "words": 0, "kinds": {}, "tags": 0}
        )
        bucket["kinds"][r["kind"]] = r["cnt"]
        bucket["total"] += r["cnt"]
        bucket["words"] += int(r["words"] or 0)
        used.add(r["kind"])

    tag_rows = db.execute(
        """
        SELECT substr(e.created_at,1,4) AS y,
               COUNT(DISTINCT et.tag_id) AS tags
          FROM entry e
          JOIN entry_tag et ON et.entry_id = e.id
         WHERE e.kind!='page'
      GROUP BY y
      ORDER BY y DESC
        """
    ).fetchall()

    for r in tag_rows:
        bucket = buckets.setdefault(
            r["y"], {"year": r["y"], "total": 0, "words": 0, "kinds": {}, "tags": 0}
        )
        bucket["tags"] = r["tags"]

    yearly = sorted(buckets.values(), key=lambda d: d["year"], reverse=True)
    return yearly if limit is None else yearly[:limit], used


def _stats_monthly(*, db, months: int = 12):
    """
    Last *months* (newest first) grouped as YYYY-MM with per-kind counts.
    """
    rows = db.execute(
        """
        SELECT substr(created_at,1,7) AS ym,
               LOWER(kind)            AS kind,
               COUNT(*)               AS cnt
          FROM entry
         WHERE kind!='page'
      GROUP BY ym, LOWER(kind)
      ORDER BY ym DESC
        """
    ).fetchall()

    buckets: dict[str, dict] = {}
    used: set[str] = set()
    for r in rows:
        month = r["ym"]
        bucket = buckets.setdefault(month, {"month": month, "total": 0, "kinds": {}})
        bucket["kinds"][r["kind"]] = r["cnt"]
        bucket["total"] += r["cnt"]
        used.add(r["kind"])

    ordered = sorted(buckets.values(), key=lambda d: d["month"], reverse=True)
    return ordered[:months], used


def _stats_tags(*, db, limit: int = 12) -> tuple[list[dict], int]:
    """
    Top tags plus the total count of distinct tags used.
    """
    rows = db.execute(
        """
        SELECT t.name,
               COUNT(*) AS cnt
          FROM tag t
          JOIN entry_tag et ON et.tag_id = t.id
          JOIN entry e      ON e.id      = et.entry_id
         WHERE e.kind!='page'
      GROUP BY t.id
      ORDER BY cnt DESC, LOWER(t.name)
         LIMIT ?
        """,
        (limit,),
    ).fetchall()

    total_used = (
        db.execute(
            """
            SELECT COUNT(DISTINCT et.tag_id) AS c
              FROM entry_tag et
              JOIN entry e ON e.id = et.entry_id
             WHERE e.kind!='page'
            """
        ).fetchone()[0]
        or 0
    )

    return [dict(name=r["name"], cnt=r["cnt"]) for r in rows], total_used


def _stats_items(*, db) -> dict:
    """Check-in stats derived from entry_item with a fallback to verb-only entries."""
    rows = db.execute("SELECT action, progress FROM entry_item").fetchall()
    total_with_items = len(rows)
    completed = sum(1 for r in rows if is_completed_action(r["action"]))
    with_progress = sum(1 for r in rows if (r["progress"] or "").strip())

    action_counts: DefaultDict[str, int] = defaultdict(int)
    for r in rows:
        act = (r["action"] or "").strip().lower()
        if not act:
            continue
        action_counts[act] += 1

    fallback = db.execute(
        f"""
        SELECT LOWER(kind) AS kind,
               COUNT(*) AS cnt
          FROM entry e
         WHERE LOWER(kind) IN ({",".join("?" * len(VERB_KINDS_LOWER))})
           AND NOT EXISTS (SELECT 1 FROM entry_item ei WHERE ei.entry_id = e.id)
      GROUP BY LOWER(kind)
        """,
        VERB_KINDS_LOWER,
    ).fetchall()

    fallback_total = 0
    for r in fallback:
        action_counts[r["kind"]] += r["cnt"]
        fallback_total += r["cnt"]

    total = total_with_items + fallback_total

    unique_items = (
        db.execute("SELECT COUNT(DISTINCT item_id) FROM entry_item").fetchone()[0] or 0
    )

    by_action = sorted(
        [{"action": k, "cnt": v} for k, v in action_counts.items()],
        key=lambda d: (-d["cnt"], d["action"]),
    )

    return {
        "checkins": total,
        "unique_items": unique_items,
        "completed": completed,
        "open": max(total - completed, 0),
        "with_progress": with_progress,
        "by_action": by_action,
    }


def _traffic_log_files(start: datetime, end: datetime, *, log_dir: Path) -> list[Path]:
    files: list[Path] = []
    day = start.date()
    while day <= end.date():
        cand = log_dir / f"traffic-{day:%Y%m%d}.log"
        if cand.exists():
            files.append(cand)
        day += timedelta(days=1)
    return files


def _recent_traffic_events(hours: int) -> list[dict]:
    if not app.config.get("TRAFFIC_LOG_ENABLED", True):
        return []

    now = utc_now()
    start = now - timedelta(hours=hours)
    log_dir = Path(app.config.get("TRAFFIC_LOG_DIR") or TRAFFIC_LOG_DIR_DEFAULT)
    files = _traffic_log_files(start, now, log_dir=log_dir)
    max_lines = int(app.config.get("TRAFFIC_READ_MAX_LINES", TRAFFIC_READ_MAX_LINES))

    buf: deque[dict] = deque(maxlen=max_lines)
    for path in files:
        try:
            with path.open("r", encoding="utf-8") as fh:
                for line in fh:
                    try:
                        obj = json.loads(line)
                    except json.JSONDecodeError:
                        continue
                    ts_raw = obj.get("ts")
                    if not ts_raw:
                        continue
                    try:
                        ts = datetime.fromisoformat(ts_raw)
                    except ValueError:
                        continue
                    if ts < start:
                        continue
                    obj["_ts"] = ts
                    buf.append(obj)
        except OSError:
            continue
    return list(buf)


def traffic_snapshot(*, db, hours: int = 24) -> dict:
    enabled = app.config.get("TRAFFIC_LOG_ENABLED", True)
    log_dir = Path(app.config.get("TRAFFIC_LOG_DIR") or TRAFFIC_LOG_DIR_DEFAULT)
    if not enabled:
        return {
            "enabled": False,
            "log_dir": str(log_dir),
            "suspicious": [],
            "blocklist": [],
            "total": 0,
            "unique_ips": 0,
        }

    blocklist_rows = db.execute(
        "SELECT ip, reason, created_at, expires_at FROM ip_blocklist ORDER BY created_at DESC"
    ).fetchall()
    blocklist = [dict(r) for r in blocklist_rows]
    now_iso = utc_now().isoformat()
    blocked_networks = []
    for row in blocklist:
        exp = row.get("expires_at")
        if exp and exp <= now_iso:
            continue
        net = _parse_block_target(row["ip"])
        if net:
            blocked_networks.append(net)

    events = _recent_traffic_events(hours)
    filtered_events: list[dict] = []
    blocked_times: list[datetime] = []
    for ev in events:
        flags = ev.get("flags") or []
        ip = _normalize_ip(ev.get("ip") or "unknown")
        ts_val = ev.get("_ts") if isinstance(ev.get("_ts"), datetime) else None
        if "admin_view" in flags:
            continue
        if _ip_in_blocked(ip, blocked_networks):
            if ts_val:
                blocked_times.append(ts_val)
            continue
        ev_copy = dict(ev)
        ev_copy["ip"] = ip
        filtered_events.append(ev_copy)

    blocked_times.sort()
    swarm_window = float(
        app.config.get("TRAFFIC_SWARM_CORR_WINDOW_SEC", TRAFFIC_SWARM_CORR_WINDOW_SEC)
    )

    def _near_blocked(ts: datetime | None) -> bool:
        if not blocked_times or ts is None:
            return False
        lo, hi = 0, len(blocked_times) - 1
        while lo <= hi:
            mid = (lo + hi) // 2
            delta = (ts - blocked_times[mid]).total_seconds()
            if abs(delta) <= swarm_window:
                return True
            if delta > 0:
                lo = mid + 1
            else:
                hi = mid - 1
        for idx in (lo, hi):
            if 0 <= idx < len(blocked_times):
                if abs((ts - blocked_times[idx]).total_seconds()) <= swarm_window:
                    return True
        return False

    ip_stats: dict[str, dict] = {}
    net_stats: dict[str, dict] = {}
    notfound_share = float(
        app.config.get("TRAFFIC_NOTFOUND_SHARE", TRAFFIC_NOTFOUND_SHARE)
    )
    path_len_threshold = int(
        app.config.get("TRAFFIC_SUSPICIOUS_PATH_LEN", TRAFFIC_SUSPICIOUS_PATH_LEN)
    )
    token_threshold = int(
        app.config.get(
            "TRAFFIC_SUSPICIOUS_TOKEN_THRESHOLD", TRAFFIC_SUSPICIOUS_TOKEN_THRESHOLD
        )
    )
    churn_min_hits = int(
        app.config.get(
            "TRAFFIC_SUSPICIOUS_CHURN_MIN_HITS", TRAFFIC_SUSPICIOUS_CHURN_MIN_HITS
        )
    )
    suspicious_score_min = int(
        app.config.get("TRAFFIC_SUSPICIOUS_SCORE", TRAFFIC_SUSPICIOUS_SCORE)
    )
    ua_min_len = int(
        app.config.get("TRAFFIC_SUSPICIOUS_MIN_UA_LEN", TRAFFIC_SUSPICIOUS_MIN_UA_LEN)
    )
    ua_kw_cfg = app.config.get(
        "TRAFFIC_SUSPICIOUS_UA_KEYWORDS", TRAFFIC_SUSPICIOUS_UA_KEYWORDS
    )
    ua_keywords = _keyword_tuple(ua_kw_cfg)
    net_hits_threshold = int(
        app.config.get("TRAFFIC_SUSPICIOUS_NET_HITS", TRAFFIC_SUSPICIOUS_NET_HITS)
    )
    net_unique_threshold = int(
        app.config.get("TRAFFIC_SUSPICIOUS_NET_UNIQUE", TRAFFIC_SUSPICIOUS_NET_UNIQUE)
    )
    net_nf_share = float(
        app.config.get(
            "TRAFFIC_SUSPICIOUS_NET_NOTFOUND_SHARE",
            TRAFFIC_SUSPICIOUS_NET_NOTFOUND_SHARE,
        )
    )
    net_err_share = float(
        app.config.get(
            "TRAFFIC_SUSPICIOUS_NET_ERROR_SHARE", TRAFFIC_SUSPICIOUS_NET_ERROR_SHARE
        )
    )
    net_low_hits = int(
        app.config.get(
            "TRAFFIC_SUSPICIOUS_NET_LOW_HITS", TRAFFIC_SUSPICIOUS_NET_LOW_HITS
        )
    )
    net_low_unique = int(
        app.config.get(
            "TRAFFIC_SUSPICIOUS_NET_LOW_UNIQUE", TRAFFIC_SUSPICIOUS_NET_LOW_UNIQUE
        )
    )
    net_low_nf_share = float(
        app.config.get(
            "TRAFFIC_SUSPICIOUS_NET_LOW_NF_SHARE",
            TRAFFIC_SUSPICIOUS_NET_LOW_NF_SHARE,
        )
    )

    for ev in filtered_events:
        ip = ev.get("ip") or "unknown"
        stat = ip_stats.setdefault(
            ip,
            {
                "hits": 0,
                "admin_hits": 0,
                "errors": 0,
                "not_found": 0,
                "flags": set(),
                "paths": Counter(),
                "status_counts": Counter(),
                "ua_samples": Counter(),
                "ua_suspicious": 0,
                "ua_reasons": Counter(),
                "max_path_len": 0,
                "max_token_like": 0,
            },
        )
        stat["hits"] += 1
        net = _net_bucket(ip)
        if net:
            nstat = net_stats.setdefault(
                net,
                {
                    "hits": 0,
                    "errors": 0,
                    "not_found": 0,
                    "paths": Counter(),
                    "status_counts": Counter(),
                    "ips": set(),
                    "max_path_len": 0,
                    "max_token_like": 0,
                },
            )
            nstat["hits"] += 1
            nstat["ips"].add(ip)
        is_admin_view = "admin_view" in (ev.get("flags") or [])
        if is_admin_view:
            stat["admin_hits"] += 1
        status = int(ev.get("st") or 0)
        if status >= 400:
            stat["errors"] += 1
            if net:
                nstat["errors"] += 1
        if status == 404:
            stat["not_found"] += 1
            if net:
                nstat["not_found"] += 1
        if status:
            bucket = f"{(status // 100)}xx"
            stat["status_counts"][bucket] += 1
            if net:
                nstat["status_counts"][bucket] += 1
        for f in ev.get("flags") or []:
            stat["flags"].add(f)
        path = ev.get("path") or ""
        if path:
            stat["paths"][path] += 1
            stat["max_path_len"] = max(stat["max_path_len"], len(path))
            stat["max_token_like"] = max(
                stat["max_token_like"], _path_token_burst(path)
            )
            if net:
                nstat["paths"][path] += 1
                nstat["max_path_len"] = max(nstat["max_path_len"], len(path))
                nstat["max_token_like"] = max(
                    nstat["max_token_like"], _path_token_burst(path)
                )
        ua_val = ev.get("ua") or ""
        if ua_val:
            stat["ua_samples"][ua_val] += 1
        bad_ua, bad_reason = _ua_suspicious(
            ua_val, min_len=ua_min_len, keywords=ua_keywords
        )
        if bad_ua:
            stat["ua_suspicious"] += 1
            if bad_reason:
                stat["ua_reasons"][bad_reason] += 1
        if _near_blocked(ev.get("_ts")):
            stat["correlated_hits"] = stat.get("correlated_hits", 0) + 1
            if status >= 400:
                stat["correlated_4xx"] = stat.get("correlated_4xx", 0) + 1

    suspicious: list[dict] = []
    min_hits = int(
        app.config.get("TRAFFIC_SUSPICIOUS_MIN_HITS", TRAFFIC_SUSPICIOUS_MIN_HITS)
    )
    high_hits = int(app.config.get("TRAFFIC_HIGH_HITS", TRAFFIC_HIGH_HITS))
    swarm_token_min = int(
        app.config.get("TRAFFIC_SWARM_TOKEN_MIN", TRAFFIC_SWARM_TOKEN_MIN)
    )
    swarm_min_corr_hits = int(
        app.config.get("TRAFFIC_SWARM_MIN_CORR_HITS", TRAFFIC_SWARM_MIN_CORR_HITS)
    )
    swarm_require_4xx = bool(
        app.config.get("TRAFFIC_SWARM_REQUIRE_4XX", TRAFFIC_SWARM_REQUIRE_4XX)
    )
    auto_block_enabled = bool(
        app.config.get("TRAFFIC_SWARM_AUTOBLOCK", TRAFFIC_SWARM_AUTOBLOCK)
    )
    auto_block_expires_days = int(
        app.config.get(
            "TRAFFIC_SWARM_AUTOBLOCK_EXPIRES_DAYS", TRAFFIC_SWARM_AUTOBLOCK_EXPIRES_DAYS
        )
    )
    ua_allowlist_raw = app.config.get(
        "TRAFFIC_SWARM_AUTOBLOCK_UA_ALLOWLIST", TRAFFIC_SWARM_AUTOBLOCK_UA_ALLOWLIST
    )
    ua_allowlist = tuple(
        (ua_allowlist_raw or [])
        if isinstance(ua_allowlist_raw, (list, tuple))
        else [s.strip().lower() for s in str(ua_allowlist_raw).split(",") if s.strip()]
    )

    def _ua_allowlisted(stat: dict) -> bool:
        if not ua_allowlist:
            return False
        for ua_val, _cnt in stat.get("ua_samples", {}).most_common(3):
            ua_l = (ua_val or "").lower()
            if any(kw and kw in ua_l for kw in ua_allowlist):
                return True
        return False

    auto_blocked_ips: set[str] = set()

    for ip, stat in ip_stats.items():
        hits = stat["hits"]
        nf_rate = (stat["not_found"] / hits) if hits else 0
        err_rate = (stat["errors"] / hits) if hits else 0
        unique_paths = len(stat["paths"])
        churn_ratio = (unique_paths / hits) if hits else 0
        reasons: list[str] = []
        score = 0
        if stat["admin_hits"] >= hits * 0.8:
            continue  # mostly admin/owner traffic → ignore
        if "burst_suspect" in stat["flags"]:
            reasons.append("High rate")
            score += 2
        if hits >= high_hits:
            reasons.append("High volume")
            score += 3
        elif hits >= min_hits:
            reasons.append("Elevated volume")
            score += 1
        if nf_rate >= notfound_share and stat["not_found"] >= 3:
            reasons.append("Many missing pages")
            score += 2
        if err_rate >= 0.5 and stat["errors"] >= 3:
            reasons.append("Lots of errors")
            score += 2
        if hits >= churn_min_hits and churn_ratio >= 0.9:
            reasons.append("High URL churn")
            score += 1
        if stat["max_path_len"] >= path_len_threshold:
            reasons.append("Very long paths")
            score += 1
        if stat["max_token_like"] >= token_threshold:
            reasons.append("Tokenized paths")
            score += 2
        if stat.get("ua_suspicious"):
            reasons.append("Suspicious UA")
            score += 2
        if "bot_ua" in stat["flags"]:
            reasons.append("Bot user-agent")
            score += 1
        if hits >= min_hits and nf_rate >= 0.25 and "Elevated volume" not in reasons:
            reasons.append("Heavy traffic")
        corr_hits = stat.get("correlated_hits", 0)
        corr_4xx = stat.get("correlated_4xx", 0)
        if (
            corr_hits >= swarm_min_corr_hits
            and stat["max_token_like"] >= swarm_token_min
            and (not swarm_require_4xx or corr_4xx >= corr_hits)
        ):
            reasons.append("Synchronized with blocked swarm")
            score = max(score, suspicious_score_min)
            if (
                auto_block_enabled
                and stat["status_counts"].get("2xx", 0) == 0
                and not _ua_allowlisted(stat)
                and ip not in auto_blocked_ips
            ):
                try:
                    expires_at = None
                    if auto_block_expires_days > 0:
                        expires_at = (
                            utc_now() + timedelta(days=auto_block_expires_days)
                        ).isoformat(timespec="seconds")
                    block_ip_addr(
                        ip,
                        reason="Auto-block: synchronized with blocked swarm",
                        expires_at=expires_at,
                        db=db,
                    )
                    auto_blocked_ips.add(ip)
                except Exception:
                    pass
        if score < suspicious_score_min or not reasons:
            continue
        deduped_reasons = list(dict.fromkeys(reasons))
        suspicious.append(
            {
                "ip": ip,
                "hits": hits,
                "errors": stat["errors"],
                "not_found": stat["not_found"],
                "flags": sorted(stat["flags"]),
                "top_paths": [p for p, _ in stat["paths"].most_common(3)],
                "status_counts": stat["status_counts"],
                "reason": "; ".join(deduped_reasons),
                "score": score,
                "blockable": True,
            }
        )

    for net, stat in net_stats.items():
        hits = stat["hits"]
        unique_ips = len(stat["ips"])
        nf_rate = (stat["not_found"] / hits) if hits else 0
        err_rate = (stat["errors"] / hits) if hits else 0
        meets_primary = (
            hits >= net_hits_threshold
            and unique_ips >= net_unique_threshold
            and (nf_rate >= net_nf_share or err_rate >= net_err_share)
        )
        meets_low_volume = (
            hits >= net_low_hits
            and unique_ips >= net_low_unique
            and nf_rate >= net_low_nf_share
            and stat["status_counts"].get("2xx", 0) == 0
        )
        if not (meets_primary or meets_low_volume):
            continue
        reasons = [f"Network swarm ({unique_ips} IPs)"]
        if nf_rate >= net_nf_share:
            reasons.append("High 404 share")
        if err_rate >= net_err_share and err_rate >= nf_rate:
            reasons.append("High error share")
        if stat["max_path_len"] >= path_len_threshold:
            reasons.append("Very long paths")
        if stat["max_token_like"] >= token_threshold:
            reasons.append("Tokenized paths")
        score = max(suspicious_score_min, 3)
        entry = {
            "ip": net,
            "hits": hits,
            "errors": stat["errors"],
            "not_found": stat["not_found"],
            "flags": ["net_aggregate"],
            "top_paths": [p for p, _ in stat["paths"].most_common(3)],
            "status_counts": stat["status_counts"],
            "reason": "; ".join(dict.fromkeys(reasons)),
            "score": score,
            "blockable": True,
            "unique_ips": unique_ips,
        }
        suspicious.append(entry)
        if (
            auto_block_enabled
            and stat["status_counts"].get("2xx", 0) == 0
            and stat["status_counts"].get("5xx", 0) > 0
            and net not in auto_blocked_ips
        ):
            try:
                expires_at = None
                if auto_block_expires_days > 0:
                    expires_at = (
                        utc_now() + timedelta(days=auto_block_expires_days)
                    ).isoformat(timespec="seconds")
                block_ip_addr(
                    net,
                    reason="Auto-block: network swarm errors",
                    expires_at=expires_at,
                    db=db,
                )
                auto_blocked_ips.add(net)
            except Exception:
                pass

    suspicious.sort(key=lambda r: (-r["hits"], -r["not_found"], r["ip"]))

    events_out = []
    for ev in filtered_events:
        ev_copy = {
            "ts": ev.get("ts"),
            "ip": ev.get("ip"),
            "path": ev.get("path"),
            "m": ev.get("m"),
            "st": ev.get("st"),
            "flags": ev.get("flags") or [],
            "dur": ev.get("dur"),
        }
        events_out.append(ev_copy)

    return {
        "enabled": True,
        "log_dir": str(log_dir),
        "suspicious": suspicious,
        "blocklist": blocklist,
        "total": len(filtered_events),
        "unique_ips": len(ip_stats),
        "events": events_out,
    }


def stats_snapshot(*, db, months: int = 12) -> dict:
    """Compose a reusable stats payload for HTML and JSON views."""
    yearly, kinds_y = _stats_yearly(db=db)
    monthly, kinds_m = _stats_monthly(db=db, months=months)
    tag_top, total_tags = _stats_tags(db=db)
    items = _stats_items(db=db)

    kinds_used = kinds_y | kinds_m
    kind_order = _order_kinds(kinds_used)

    overview = {
        "total_entries": sum(y["total"] for y in yearly),
        "total_words": sum(y["words"] for y in yearly),
        "years": len(yearly),
        "first_year": yearly[-1]["year"] if yearly else None,
        "latest_year": yearly[0]["year"] if yearly else None,
        "total_tags": total_tags,
    }

    today_rows = _today_stats(db=db)
    today_total = sum(r["cnt"] for r in today_rows)

    return {
        "yearly": yearly,
        "monthly": monthly,
        "tags": tag_top,
        "items": items,
        "today": {"rows": today_rows, "total": today_total},
        "overview": overview,
        "kinds": kind_order,
        "generated_at": utc_now().isoformat(),
    }


@app.route("/stats")
def stats():
    login_required()

    db = get_db()
    try:
        months_window = int(request.args.get("months", 12))
    except (TypeError, ValueError):
        months_window = 12
    months_window = min(max(months_window, 3), 36)

    snapshot = stats_snapshot(db=db, months=months_window)
    try:
        traffic_hours = int(request.args.get("traffic_hours", 24))
    except (TypeError, ValueError):
        traffic_hours = 24
    traffic_hours = min(max(traffic_hours, 1), 168)
    traffic = traffic_snapshot(db=db, hours=traffic_hours)
    snapshot["traffic"] = traffic
    if request.args.get("format") == "json":
        return snapshot
    if request.args.get("format") == "traffic-json":
        return traffic

    max_year_total = max((y["total"] for y in snapshot["yearly"]), default=0)
    max_month_total = max((m["total"] for m in snapshot["monthly"]), default=0)

    return render_template_string(
        TEMPL_STATS,
        stats=snapshot,
        kinds=snapshot["kinds"],
        max_year_total=max_year_total,
        max_month_total=max_month_total,
        months_window=months_window,
        traffic_hours=traffic_hours,
        title=get_setting("site_name", "po.etr.ist"),
        username=current_username(),
        IP_BLOCK_DEFAULT_DAYS=IP_BLOCK_DEFAULT_DAYS,
        kind="stats",
    )


TEMPL_STATS = wrap("""
{% block body %}
  <hr>
  <header style="display:flex;align-items:center;justify-content:space-between;gap:.5rem;flex-wrap:wrap;">
    <div>
      <h2 style="margin:1rem 0;">Statistics</h2>
      {% if stats.overview.first_year %}
        <small style="color:#888;">
          {{ stats.overview.first_year }} – {{ stats.overview.latest_year }}
          ({{ stats.overview.years }} year{{ 's' if stats.overview.years!=1 else '' }})
        </small>
      {% endif %}
    </div>
    <a href="{{ url_for('today') }}"
       style="color:{{ theme_color() }};font-size:.9em;text-decoration:none;border-bottom:0.1px dotted currentColor;">
       On this day →
    </a>
  </header>

  {% if not stats.yearly %}
    <p>No entries yet.</p>
  {% else %}
    {% set items = stats['items'] %}
    <!-- Summary cards -->
    <section style="margin:1.5rem 0;">
      <div style="display:grid;grid-template-columns:repeat(auto-fit,minmax(13rem,1fr));gap:1rem;">
        <div style="padding:1rem;border:1px solid #444;border-radius:.4rem;background:#2a2a2a;">
          <div style="font-size:.9em;color:#888;">Entries</div>
          <div style="font-size:2.1rem;line-height:1;">{{ '{:,}'.format(stats.overview.total_entries) }}</div>
          <div style="font-size:.85em;color:#888;">{{ stats.overview.years }} year{{ 's' if stats.overview.years!=1 else '' }}</div>
        </div>
        <div style="padding:1rem;border:1px solid #444;border-radius:.4rem;background:#2a2a2a;">
          <div style="font-size:.9em;color:#888;">Words</div>
          <div style="font-size:2.1rem;line-height:1;">{{ '{:,}'.format(stats.overview.total_words) }}</div>
          <div style="font-size:.85em;color:#888;">approximate count</div>
        </div>
        <div style="padding:1rem;border:1px solid #444;border-radius:.4rem;background:#2a2a2a;">
          <div style="font-size:.9em;color:#888;">Tags used</div>
          <div style="font-size:2.1rem;line-height:1;">{{ stats.overview.total_tags }}</div>
          {% if stats.tags %}
            <div style="font-size:.85em;color:#888;">Top {{ stats.tags|length }} shown below</div>
          {% else %}
            <div style="font-size:.85em;color:#888;">No tags yet</div>
          {% endif %}
        </div>
        <div style="padding:1rem;border:1px solid #444;border-radius:.4rem;background:#2a2a2a;">
          <div style="font-size:.9em;color:#888;">Check-ins</div>
          <div style="font-size:2.1rem;line-height:1;">{{ items.checkins }}</div>
          <div style="font-size:.85em;color:#888;">{{ items.unique_items }} unique item{{ '' if items.unique_items==1 else 's' }}</div>
        </div>
      </div>
    </section>

    <!-- Yearly cadence -->
    <section style="margin:1.5rem 0;">
      <h3 style="margin-bottom:.35rem;">Yearly cadence</h3>
      <div style="display:flex;flex-direction:column;gap:.65rem;">
        {% for y in stats.yearly %}
          <article style="border:1px solid #444;border-radius:.35rem;padding:.75rem 1rem;background:#2a2a2a;">
            <div style="display:flex;align-items:center;justify-content:space-between;gap:1rem;flex-wrap:wrap;font-variant-numeric:tabular-nums;">
              <strong>{{ y.year }}</strong>
              <span style="color:#ccc;font-size:.95em;">{{ y.total }} entr{{ 'y' if y.total==1 else 'ies' }}</span>
            </div>
            <div style="margin:.45rem 0 .35rem;height:8px;background:#333;border-radius:999px;overflow:hidden;">
              {% set pct = (y.total / max_year_total * 100) if max_year_total else 0 %}
              <span style="display:block;height:100%;width:{{ '%.1f' % pct }}%;background:{{ theme_color() }};"></span>
            </div>
            <div style="font-size:.85em;color:#bbb;display:flex;flex-wrap:wrap;gap:.6rem;">
              {% for k in kinds %}
                {% if y.kinds.get(k) %}
                  <span>{{ k|smartcap }} {{ y.kinds[k] }}</span>
                {% endif %}
              {% endfor %}
              <span style="color:#888;">{{ '{:,}'.format(y.words) }} words</span>
              <span style="color:#888;">{{ y.tags or 0 }} tags</span>
            </div>
          </article>
        {% endfor %}
      </div>
    </section>

    <!-- Monthly trend -->
    <section style="margin:1.5rem 0;">
      <h3 style="margin-bottom:.35rem;">Last {{ months_window }} month{{ '' if months_window==1 else 's' }}</h3>
      {% if stats.monthly %}
        <div style="display:flex;flex-direction:column;gap:.35rem;">
          {% for m in stats.monthly %}
            <div style="display:grid;grid-template-columns:7ch 1fr auto;align-items:center;gap:.65rem;font-variant-numeric:tabular-nums;">
              <span>{{ m.month }}</span>
              <div style="background:#333;border-radius:999px;overflow:hidden;height:8px;">
                {% set pct = (m.total / max_month_total * 100) if max_month_total else 0 %}
                <span style="display:block;height:100%;width:{{ '%.1f' % pct }}%;background:{{ theme_color() }};"></span>
              </div>
              <span style="color:#ccc;font-size:.9em;">{{ m.total }}</span>
            </div>
            <div style="font-size:.8em;color:#bbb; margin-left:7ch; display:flex; flex-wrap:wrap; gap:.5rem 1rem;">
              {% for k in kinds %}
                {% if m.kinds.get(k) %}
                  <span>{{ k|smartcap }} {{ m.kinds[k] }}</span>
                {% endif %}
              {% endfor %}
            </div>
          {% endfor %}
        </div>
      {% else %}
        <p>No recent months yet.</p>
      {% endif %}
    </section>

    <!-- Tags -->
    <section style="margin:1.5rem 0;">
      <h3 style="margin-bottom:.35rem;">Top tags</h3>
      {% if stats.tags %}
        <ul style="list-style:none;padding:0;display:flex;flex-wrap:wrap;gap:.5rem 1rem;font-size:.95em;">
          {% for t in stats.tags %}
            <li>
              <a href="{{ tags_href(t.name) }}"
                 style="color:{{ theme_color() }};text-decoration:none;border-bottom:0.1px dotted currentColor;">
                #{{ t.name }}
              </a>
              <small style="color:#888;">{{ t.cnt }}</small>
            </li>
          {% endfor %}
        </ul>
      {% else %}
        <p>No tags yet.</p>
      {% endif %}
    </section>

    <!-- Items -->
    <section style="margin:1.5rem 0;">
      <h3 style="margin-bottom:.35rem;">Items & check-ins</h3>
      {% if items.checkins %}
        <p style="margin:.4rem 0;color:#bbb;font-size:.95em;">
          {{ items.checkins }} check-in{{ '' if items.checkins==1 else 's' }},
          {{ items.unique_items }} item{{ '' if items.unique_items==1 else 's' }},
          {{ items.completed }} completed,
          {{ items.open }} open,
          {{ items.with_progress }} with progress.
        </p>
        {% if items.by_action %}
          <div style="display:flex;flex-wrap:wrap;gap:.45rem 1rem;font-size:.9em;color:#bbb;">
            {% for a in items.by_action %}
              <span style="display:inline-flex;align-items:center;gap:.35rem;">
                <span style="display:inline-block;padding:.1em .55em;border-radius:1em;background:#444;color:#fff;text-transform:capitalize;">
                  {{ a.action }}
                </span>
                <small style="color:#888;">{{ a.cnt }}</small>
              </span>
            {% endfor %}
          </div>
        {% endif %}
      {% else %}
        <p>No check-ins yet.</p>
      {% endif %}
    </section>
  {% endif %}

  <!-- Traffic -->
  <section id="traffic" style="margin:1.5rem 0;">
    <div style="display:flex;align-items:center;justify-content:space-between;gap:1rem;flex-wrap:wrap;">
      <h3>Traffic (last {{ traffic_hours }}h)</h3>
      <div style="font-size:.85em;color:#888;">
        Log dir: <code>{{ stats.traffic.log_dir }}</code>
      </div>
    </div>

    {% if not stats.traffic.enabled %}
      <p style="color:#888;">Traffic logging is disabled.</p>
    {% else %}
      <p style="margin:.4rem 0;color:#bbb;font-size:.95em;">
        {{ stats.traffic.total }} events, {{ stats.traffic.unique_ips }} unique IPs.
        <a href="{{ url_for('stats', format='traffic-json', traffic_hours=traffic_hours) }}"
           style="color:{{ theme_color() }};text-decoration:none;border-bottom:0.1px dotted currentColor;">
          Download JSON
        </a>
      </p>

      <h4 style="margin:.75rem 0 .35rem;">Suspicious</h4>
      {% if stats.traffic.suspicious %}
        <div style="overflow-x:auto;">
          <table style="width:100%;border-collapse:collapse;font-size:.9em;">
            <thead>
              <tr style="text-align:left;border-bottom:1px solid #444;">
              <th style="padding:.35rem;">IP</th>
              <th style="padding:.35rem;">Hits</th>
              <th style="padding:.35rem;">Status mix</th>
              <th style="padding:.35rem;">Reason</th>
              <th style="padding:.35rem;">Top paths</th>
              <th style="padding:.35rem;">Action</th>
            </tr>
            </thead>
            <tbody>
            {% for s in stats.traffic.suspicious %}
              <tr style="border-bottom:1px solid #333;">
                <td style="padding:.35rem;">{{ s.ip }}</td>
                <td style="padding:.35rem;">{{ s.hits }}</td>
                <td style="padding:.35rem;font-size:.85em;color:#aaa;">
                  {% set sc = s.status_counts %}
                  2xx {{ sc.get('2xx',0) }} · 3xx {{ sc.get('3xx',0) }} · 4xx {{ sc.get('4xx',0) }} · 5xx {{ sc.get('5xx',0) }}
                </td>
                <td style="padding:.35rem;">{{ s.reason }}</td>
                <td style="padding:.35rem;color:#aaa;font-size:.85em;">
                  {% if s.top_paths %}{{ s.top_paths|join(', ') }}{% else %}—{% endif %}
                </td>
                <td style="padding:.35rem;">
                  {% set can_block = s.blockable is not defined or s.blockable %}
                  {% if can_block %}
                    <form method="post" action="{{ url_for('ip_blocklist_action') }}" style="display:inline;">
                      {% if csrf_token() %}
                        <input type="hidden" name="csrf" value="{{ csrf_token() }}">
                      {% endif %}
                      <input type="hidden" name="action" value="block">
                      <input type="hidden" name="ip" value="{{ s.ip }}">
                      <input type="hidden" name="reason" value="{{ s.reason }}">
                      <button type="submit" style="background:#c0392b;color:#fff;border:1px solid #922b21;padding:.3rem .6rem;border-radius:.35rem;cursor:pointer;">
                        Block
                      </button>
                    </form>
                  {% else %}
                    <span style="color:#888;">—</span>
                  {% endif %}
                </td>
              </tr>
            {% endfor %}
            </tbody>
          </table>
        </div>
      {% else %}
        <p style="color:#888;">No suspicious IPs in this window.</p>
      {% endif %}

      <p style="margin-top:.75rem;font-size:.9em;">
        <a href="{{ url_for('blocklist', traffic_hours=traffic_hours) }}"
           style="color:{{ theme_color() }};text-decoration:none;border-bottom:0.1px dotted currentColor;">
           Manage blocklist →
        </a>
      </p>
    {% endif %}
  </section>
{% endblock %}
""")


TEMPL_BLOCKLIST = wrap("""
{% block body %}
  <hr>
  <header style="display:flex;align-items:center;justify-content:space-between;gap:.5rem;flex-wrap:wrap;">
    <div>
      <h2 style="margin:1rem 0;">Blocklist</h2>
      <small style="color:#888;">Last {{ traffic_hours }}h · log dir {{ data.log_dir }}</small>
    </div>
    <a href="{{ url_for('stats', format='traffic-json', traffic_hours=traffic_hours) }}"
       style="color:{{ theme_color() }};font-size:.9em;text-decoration:none;border-bottom:0.1px dotted currentColor;">
       Download JSON →
    </a>
  </header>

  {% if not data.enabled %}
    <p>Traffic logging is disabled.</p>
  {% else %}
    <section style="margin:1rem 0;">
      <div style="display:flex;gap:1rem;flex-wrap:wrap;">
        <div style="padding:1rem;border:1px solid #444;border-radius:.4rem;background:#2a2a2a;min-width:12rem;">
          <div style="font-size:.9em;color:#888;">Suspicious IPs</div>
          <div style="font-size:1.8rem;">{{ data.suspicious|length }}</div>
        </div>
        <div style="padding:1rem;border:1px solid #444;border-radius:.4rem;background:#2a2a2a;min-width:12rem;">
          <div style="font-size:.9em;color:#888;">Blocked</div>
          <div style="font-size:1.8rem;">{{ data.blocklist|length }}</div>
        </div>
        <div style="padding:1rem;border:1px solid #444;border-radius:.4rem;background:#2a2a2a;min-width:12rem;">
          <div style="font-size:.9em;color:#888;">Events</div>
          <div style="font-size:1.8rem;">{{ data.total }}</div>
          <div style="font-size:.85em;color:#888;">{{ data.unique_ips }} IPs</div>
        </div>
      </div>
    </section>

    <section style="margin:1.5rem 0;">
      <h3 style="margin-bottom:.5rem;">Suspicious</h3>
      {% if data.suspicious %}
        <div style="overflow-x:auto;">
          <table style="width:100%;border-collapse:collapse;font-size:.9em;">
            <thead>
              <tr style="text-align:left;border-bottom:1px solid #444;">
                <th style="padding:.35rem;">IP</th>
                <th style="padding:.35rem;">Hits</th>
                <th style="padding:.35rem;">Reason</th>
                <th style="padding:.35rem;">Top paths</th>
                <th style="padding:.35rem;">Action</th>
              </tr>
            </thead>
            <tbody>
            {% for s in data.suspicious %}
              <tr style="border-bottom:1px solid #333;">
                <td style="padding:.35rem;">{{ s.ip }}</td>
                <td style="padding:.35rem;">{{ s.hits }}</td>
                <td style="padding:.35rem;">{{ s.reason }}</td>
                <td style="padding:.35rem;color:#aaa;font-size:.85em;">
                  {% if s.top_paths %}{{ s.top_paths|join(', ') }}{% else %}—{% endif %}
                </td>
                <td style="padding:.35rem;">
                  <form method="post" action="{{ url_for('ip_blocklist_action') }}" style="display:inline;">
                    {% if csrf_token() %}<input type="hidden" name="csrf" value="{{ csrf_token() }}">{% endif %}
                    <input type="hidden" name="action" value="block">
                    <input type="hidden" name="ip" value="{{ s.ip }}">
                    <input type="hidden" name="reason" value="{{ s.reason }}">
                    <button type="submit" style="background:#c0392b;color:#fff;border:1px solid #922b21;padding:.3rem .6rem;border-radius:.35rem;cursor:pointer;">
                      Block
                    </button>
                  </form>
                </td>
              </tr>
            {% endfor %}
            </tbody>
          </table>
        </div>
      {% else %}
        <p style="color:#888;">No suspicious IPs in this window.</p>
      {% endif %}
    </section>

    <section style="margin:1.5rem 0;">
      <h3 style="margin-bottom:.5rem;">Blocked IPs <small style="color:#888;">({{ blocklist_total }})</small></h3>
      <section style="margin:1rem 0;">
        <h4 style="margin-bottom:.35rem;">Manually add IP</h4>
        <form method="post" action="{{ url_for('ip_blocklist_action') }}" style="display:flex;flex-wrap:wrap;gap:.5rem;align-items:flex-end;">
            {% if csrf_token() %}<input type="hidden" name="csrf" value="{{ csrf_token() }}">{% endif %}
            <input type="hidden" name="action" value="block">
            <label style="flex:1 1 12rem;display:flex;flex-direction:column;gap:.2rem;font-size:.9em;color:#bbb;">
            IP address
            <input name="ip" type="text" required placeholder="203.0.113.42" style="padding:.45rem;border:1px solid #444;border-radius:.3rem;background:#1f1f1f;color:#fff;">
            </label>
            <label style="flex:2 1 18rem;display:flex;flex-direction:column;gap:.2rem;font-size:.9em;color:#bbb;">
            Reason
            <input name="reason" type="text" placeholder="(optional)" style="padding:.45rem;border:1px solid #444;border-radius:.3rem;background:#1f1f1f;color:#fff;">
            </label>
            <label style="flex:0 0 9rem;display:flex;flex-direction:column;gap:.2rem;font-size:.9em;color:#bbb;">
            Expired after x days
            <input name="days" type="number" min="1" placeholder="blank = forever (add days to set expiry)" style="padding:.45rem;border:1px solid #444;border-radius:.3rem;background:#1f1f1f;color:#fff;">
            </label>
            <button type="submit" style="padding:.55rem 1rem;background:#c0392b;color:#fff;border:1px solid #922b21;border-radius:.35rem;cursor:pointer;flex:0 0 auto;">
            Add to blocklist
            </button>
        </form>
      </section>
      <details style="border:1px solid #333;border-radius:.4rem;padding:0;background:#1e1e1e;" {% if request.args.get('open') %}open{% endif %}>
        <summary style="cursor:pointer;padding:.75rem 1rem;font-weight:600;display:flex;align-items:center;justify-content:space-between;gap:.75rem;">
          <span>Show blocked IPs</span>
          <span style="color:#888;font-size:.9em;">Page {{ blocklist_page }} / {{ blocklist_pages }}</span>
        </summary>
        <div style="padding:0 1rem 1rem;">
          {% if data.blocklist_page %}
            <div style="overflow-x:auto;">
              <table style="width:100%;border-collapse:collapse;font-size:.9em;">
                <thead>
                  <tr style="text-align:left;border-bottom:1px solid #444;">
                    <th style="padding:.35rem;">IP</th>
                    <th style="padding:.35rem;">Reason</th>
                    <th style="padding:.35rem;">Created</th>
                    <th style="padding:.35rem;">Expires</th>
                    <th style="padding:.35rem;">Action</th>
                  </tr>
                </thead>
                <tbody>
                {% for b in data.blocklist_page %}
                  <tr style="border-bottom:1px solid #333;">
                    <td style="padding:.35rem;">{{ b.ip }}</td>
                    <td style="padding:.35rem;">{{ b.reason or '—' }}</td>
                    <td style="padding:.35rem;">{{ b.created_at }}</td>
                    <td style="padding:.35rem;">{{ b.expires_at or '—' }}</td>
                    <td style="padding:.35rem;">
                      <form method="post" action="{{ url_for('ip_blocklist_action') }}" style="display:inline;">
                        {% if csrf_token() %}<input type="hidden" name="csrf" value="{{ csrf_token() }}">{% endif %}
                        <input type="hidden" name="action" value="unblock">
                        <input type="hidden" name="ip" value="{{ b.ip }}">
                        <button type="submit" style="background:#444;color:#fff;border:1px solid #666;padding:.3rem .6rem;border-radius:.35rem;cursor:pointer;">
                          Unblock
                        </button>
                      </form>
                    </td>
                  </tr>
                {% endfor %}
                </tbody>
              </table>
            </div>
            {% if blocklist_pages > 1 %}
              <div style="margin-top:.75rem;display:flex;align-items:center;gap:.75rem;flex-wrap:wrap;font-size:.9em;">
                <span style="color:#888;">Page {{ blocklist_page }} of {{ blocklist_pages }}</span>
                <div style="display:flex;gap:.35rem;flex-wrap:wrap;">
                  {% if blocklist_page > 1 %}
                    <a href="{{ url_for('blocklist', page=blocklist_page-1, page_size=blocklist_page_size, traffic_hours=traffic_hours, open=1) }}" style="padding:.3rem .6rem;border:1px solid #444;border-radius:.3rem;color:{{ theme_color() }};text-decoration:none;">Previous</a>
                  {% endif %}
                  {% if blocklist_page < blocklist_pages %}
                    <a href="{{ url_for('blocklist', page=blocklist_page+1, page_size=blocklist_page_size, traffic_hours=traffic_hours, open=1) }}" style="padding:.3rem .6rem;border:1px solid #444;border-radius:.3rem;color:{{ theme_color() }};text-decoration:none;">Next</a>
                  {% endif %}
                </div>
              </div>
            {% endif %}
          {% else %}
            <p style="color:#888;">No IPs are blocked.</p>
          {% endif %}
        </div>
      </details>
    </section>
  {% endif %}
{% endblock %}
""")


@app.route("/ip-blocklist", methods=["POST"])
def ip_blocklist_action():
    login_required()
    ip = (request.form.get("ip") or "").strip()
    if not ip:
        abort(400)
    action = (request.form.get("action") or "block").strip().lower()
    db = get_db()

    if action == "block":
        reason = (
            request.form.get("reason") or "manual block"
        ).strip() or "manual block"
        days_raw = (request.form.get("days") or "").strip()
        expires_at = None
        if days_raw:
            try:
                days_int = int(days_raw)
                if days_int > 0:
                    expires_at = (utc_now() + timedelta(days=days_int)).isoformat()
            except ValueError:
                expires_at = None
        try:
            block_ip_addr(ip, reason=reason, expires_at=expires_at, db=db)
            flash(f"Blocked {ip}")
        except ValueError:
            flash("Invalid IP or CIDR", "error")
    elif action == "unblock":
        try:
            unblock_ip_addr(ip, db=db)
            flash(f"Unblocked {ip}")
        except ValueError:
            flash("Invalid IP or CIDR", "error")
    else:
        abort(400)
    return redirect(url_for("blocklist"))


@app.route("/blocklist")
def blocklist():
    login_required()
    try:
        traffic_hours = int(request.args.get("traffic_hours", 24))
    except (TypeError, ValueError):
        traffic_hours = 24
    traffic_hours = min(max(traffic_hours, 1), 168)
    try:
        page = int(request.args.get("page", 1))
    except (TypeError, ValueError):
        page = 1
    try:
        page_size = int(request.args.get("page_size", 50))
    except (TypeError, ValueError):
        page_size = 50
    page_size = min(max(page_size, 10), 200)
    snap = traffic_snapshot(db=get_db(), hours=traffic_hours)
    total_blocks = len(snap.get("blocklist") or [])
    total_pages = max((total_blocks + page_size - 1) // page_size, 1)
    page = min(max(page, 1), total_pages)
    start = (page - 1) * page_size
    end = start + page_size
    paged_blocklist = (snap.get("blocklist") or [])[start:end]
    snap["blocklist_page"] = paged_blocklist
    return render_template_string(
        TEMPL_BLOCKLIST,
        title=get_setting("site_name", "po.etr.ist"),
        username=current_username(),
        traffic_hours=traffic_hours,
        data=snap,
        blocklist_total=total_blocks,
        blocklist_page=page,
        blocklist_pages=total_pages,
        blocklist_page_size=page_size,
        IP_BLOCK_DEFAULT_DAYS=IP_BLOCK_DEFAULT_DAYS,
        kind="blocklist",
    )


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
    item_type_norm = normalize_item_type(item_type)
    if not item_type_norm:
        abort(404)

    verb = slug_to_kind(verb)
    if verb not in VERB_KINDS:
        abort(404)
    db = get_db()
    itm = db.execute(
        """SELECT id, uuid, slug, item_type, title
                          FROM item
                         WHERE LOWER(item_type)=? AND slug=?""",
        (item_type_norm, slug),
    ).fetchone()
    if not itm:
        abort(404)
    if itm["item_type"] != item_type_norm:
        db.execute("UPDATE item SET item_type=? WHERE id=?", (item_type_norm, itm["id"]))
        db.commit()
        itm = dict(itm)
        itm["item_type"] = item_type_norm

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
    verb_from_action, err_msg = _resolve_verb(action.lower(), verb_hint=verb_from_url)
    if verb_from_action != verb_from_url:
        reason = err_msg or "Verb/action mismatch"
        raise ValueError(reason)

    item_type_norm = normalize_item_type(data["item_type"])
    if not item_type_norm:
        raise ValueError("Remote item is missing an item_type")

    # ------------------------------------------------------------------ #
    # 4 . craft block-dict for caller
    # ------------------------------------------------------------------ #
    return {
        "verb": verb_from_action,
        "action": action.lower(),
        "item_type": item_type_norm,
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
