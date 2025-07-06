#!/usr/bin/env python3
"""
A single-file minimal blog.
"""
import os
import re
import secrets
import shlex
import sqlite3
import uuid
from collections import defaultdict, deque
from datetime import datetime, timezone
from email.utils import format_datetime
from functools import wraps
from html import escape
from importlib.metadata import PackageNotFoundError, version
from pathlib import Path
from time import time
from typing import DefaultDict
from urllib.parse import urlparse
from zoneinfo import ZoneInfo

import click
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
    send_from_directory,
    session,
    url_for,
)
from itsdangerous import BadSignature, SignatureExpired, TimestampSigner
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
from werkzeug.security import check_password_hash, generate_password_hash

################################################################################
# Imports & constants
################################################################################

ROOT        = Path(__file__).parent
DB_FILE     = ROOT / "blog.sqlite3"

SECRET_FILE = ROOT / ".secret_key"
SECRET_KEY  = SECRET_FILE.read_text().strip() if SECRET_FILE.exists() \
              else secrets.token_hex(32)
SECRET_FILE.write_text(SECRET_KEY)
TOKEN_LEN = 48
signer = TimestampSigner(SECRET_KEY, salt='login-token')

SLUG_DEFAULTS = {"say": "says", "post": "posts", "pin": "pins"}
VERB_MAP = {
    "read"   : ["to-read", "to read", "reading", "read", "rereading", "reread", "finished reading"],
    "watch"  : ["to-watch", "to watch" , "watching", "watched", "rewatching", "rewatched"],
    "listen" : ["to-listen", "to listen", "listening", "listened", "relistening", "relistened"],
    "play"   : ["to-play", "to play", "playing", "played", "replaying", "replayed"],
    "visit"  : ["to-visit", "to visit", "visiting", "visited", "revisiting", "revisited"],
    "use": ["to-use", "to use", "using", "used", "reusing", "reused"],
    "buy": ["to-buy", "to buy", "buying", "bought", "rebuying", "rebought"],
}
KINDS = ("say", "post", "pin") + tuple(VERB_MAP.keys()) + ("page",)
PAGE_DEFAULT = 100
TAG_RE = re.compile(r'(?<!\w)#([\w\-]+)')
RFC2822_FMT = "%a, %d %b %Y %H:%M:%S %z"
_TOKEN_CHARS = r"0-9A-Za-z\u0080-\uFFFF_"          # what unicode61 keeps
TOKEN_RE     = re.compile(f"[{_TOKEN_CHARS}]+")
HASH_LINK_RE = re.compile(
    r'''
    (?<![A-Za-z0-9_="'&])        # no word char, quote, = or & right before
    \#                           # literal “#”
    (?!x?[0-9A-Fa-f]+;)          # NOT an HTML entity  (e.g. &#x1F60A;)
    (?![0-9A-Fa-f]{3,8}\b)       # ★ NEW: NOT a 3- to 8-digit hex colour
    ([\w\-]+)                    # the actual tag
    ''',
    re.X
)

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
    SESSION_COOKIE_SAMESITE="Lax",   # blocks most CSRF on simple links
    SESSION_COOKIE_HTTPONLY=True,    # mitigate XSS → cookie theft
    SESSION_COOKIE_SECURE=True,      # only if you serve over HTTPS
)
app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1)

md = markdown.Markdown(
    extensions=[
        "pymdownx.extra",       # tables, fenced-code…
        "pymdownx.magiclink",   # auto-link bare URLs
        "pymdownx.tilde",       # ~~strike~~
        "pymdownx.mark",        # ==mark==
        "pymdownx.superfences", # improved ``` code fences
        "pymdownx.highlight",   # pygments highlighting
        "pymdownx.betterem",
        "pymdownx.saneheaders"
    ],
    extension_configs={
        "pymdownx.highlight": {"guess_lang": True, "noclasses": True, "pygments_style": "nord"},
    },
)

@app.template_filter("md")
def md_filter(text: str | None) -> Markup:
    """
    Render Markdown and turn every #tag into
    <a href="/tags/<tag>">#tag</a>.
    """
    theme_col = theme_color()  # get the current theme color

    # ➊ drop every line that starts with ^something:   (= caret meta)
    clean = "\n".join(
        ln for ln in (text or "").splitlines()
        if not ln.lstrip().startswith("^")
    )

    html = md.reset().convert(clean)

    # post-process the generated HTML
    def hashtag_repl(match):
        orig_tag = match.group(1)
        tag_lc   = orig_tag.lower() 
        href     = url_for("tags", tag_list=tag_lc)
        return f'<a href="{href}" style="text-decoration:none;color:{ theme_col };border-bottom:0.1px dotted currentColor;">#{orig_tag}</a>'

    html = HASH_LINK_RE.sub(hashtag_repl, html)

    # change <mark> to have a custom style
    html = re.sub(
            r'(<mark)(>)',
            rf'\1 style="background:{ theme_col };color:#000;padding:0 .15em;"\2',
            html
        )

    return Markup(html)

@app.template_filter("mdinline")
def md_inline_filter(text: str | None) -> Markup:
    """
    Render Markdown like `md`, but if the result is exactly one
    <p>…</p> block, unwrap it so we get pure inline HTML.
    """
    html = md_filter(text)          # reuse the existing logic
    # Markup -> str for inspection, but keep it safe afterwards
    s = str(html)

    if s.startswith("<p>") and s.endswith("</p>"):
        s = s[3:-4].strip()         # drop the wrapper

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
    """
    Convert an ISO-8601 string like '2025-06-24T09:22:20+00:00'
    to '2025.06.24 09:22:20'.  Falls back to the original value
    if parsing fails.
    """
    if not iso:
        return ""
    try:
        dt = datetime.fromisoformat(iso)
    except ValueError:
        return iso

    return dt.astimezone(ZoneInfo("Europe/Berlin")).strftime("%Y.%m.%d %H:%M:%S")

@app.template_filter("url")
def url_filter(url: str | None) -> str:
    """
    https://psyche.co/ideas/foo → https://psyche.co/
    Returns the original string if it can’t be parsed.
    """
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
    if 'db' not in g:
        g.db = sqlite3.connect(app.config['DATABASE'])
        g.db.execute("PRAGMA foreign_keys = ON;")
        g.db.row_factory = sqlite3.Row
        g.db.create_function("strip_caret", 1, strip_caret)
    return g.db

@app.teardown_appcontext
def close_db(error=None):
    db = g.pop('db', None)
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
            pwd_hash    TEXT NOT NULL,
            token_hash  TEXT NOT NULL
        );

        ------------------------------------------------------------
        -- 2.  Objects  (one row per distinct work / place / tool …)
        ------------------------------------------------------------
        CREATE TABLE object (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            itype       TEXT NOT NULL,               -- book, movie, …
            title       TEXT NOT NULL,
            slug        TEXT UNIQUE NOT NULL         -- never-let-me-go-2005
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
            updated_at  TEXT,                           -- NEW: seeded now
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
                   ('theme_color','#A5BA93');

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
        /* the index itself */
        CREATE VIRTUAL TABLE IF NOT EXISTS entry_fts USING fts5(
            title, body, link,
            content='entry',
            content_rowid='id',
            tokenize = 'trigram'
        );

        /* keep mirror in sync */
        CREATE TRIGGER IF NOT EXISTS entry_ai AFTER INSERT ON entry BEGIN
            INSERT INTO entry_fts(rowid,title,body,link)
                VALUES (new.id,
                        COALESCE(new.title,''),
                        strip_caret(new.body),
                        COALESCE(new.link,''));
        END;

        CREATE TRIGGER IF NOT EXISTS entry_au AFTER UPDATE ON entry BEGIN
            /* ① drop the stale version */
            INSERT INTO entry_fts(entry_fts, rowid)
                VALUES('delete', old.id);

            /* ② add the fresh version */
            INSERT INTO entry_fts(rowid, title, body, link)
                VALUES(
                    new.id,
                    COALESCE(new.title,''),
                    strip_caret(new.body),
                    COALESCE(new.link,'')
                );
        END;

        /* AFTER DELETE: just remove it from the index */
        CREATE TRIGGER IF NOT EXISTS entry_ad AFTER DELETE ON entry BEGIN
            INSERT INTO entry_fts(entry_fts, rowid)
                VALUES('delete', old.id);
        END;

        ------------------------------------------------------------
        -- 6.  Re-usable media / places / etc. (“items”)
        ------------------------------------------------------------
        CREATE TABLE IF NOT EXISTS item (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            uuid        TEXT UNIQUE NOT NULL,        -- canonical id (always)
            slug        TEXT UNIQUE NOT NULL,        -- user-changeable
            item_type   TEXT NOT NULL,               -- book / film / …
            title       TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS item_meta (       -- arbitrary key/value
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
            cred_id       BLOB    UNIQUE NOT NULL,   -- raw bytes
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
def load_simple_env(path=".env"):
    p = Path(path)
    if not p.exists():        # ── silently ignore if the file is absent
        return

    for line in p.read_text().splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        k, v = line.split("=", 1)
        os.environ.setdefault(k, shlex.split(v)[0])   # unquote if needed

load_simple_env()

def _create_admin(db, *, username: str, password: str) -> str:
    """Insert admin user and return the one-time token."""
    handle = secrets.token_urlsafe(TOKEN_LEN)          # random payload
    token  = signer.sign(handle).decode()              # handle.timestamp.sig
    db.execute(
        "INSERT INTO user (username, pwd_hash, token_hash) VALUES (?,?,?)",
        (username,
         generate_password_hash(password),
         generate_password_hash(handle))
    )
    db.commit()
    return token


def _rotate_token(db) -> str:
    """Generate + store a *new* one-time token, return it for display."""
    handle = secrets.token_urlsafe(TOKEN_LEN)
    token  = signer.sign(handle).decode()
    db.execute(
        "UPDATE user SET token_hash=? WHERE id=1",
        (generate_password_hash(handle),)
    )
    db.commit()
    return token

@app.cli.command("init")
@click.option("--username", envvar="ADMIN_USERNAME", prompt=True,
              help="Admin username (will be created if DB empty)")
@click.option("--password", envvar="ADMIN_PASSWORD", prompt=True, hide_input=True,
              confirmation_prompt=True,
              help="Admin password")
def cli_init(username: str, password: str):
    """Initialise DB *and* create the first admin account."""
    init_db()                           # no-op if already there
    db = get_db()
    token = _create_admin(db,
                          username=username.strip(),
                          password=password.strip())

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
    return "\n".join(
        ln for ln in text.splitlines()
        if not ln.lstrip().startswith("^")
    )

def infer_kind(title, link):
    if not title and not link:
        return 'say'
    if link and title:
        return 'pin'
    return 'post'

def current_username() -> str:
    """Return the (only) account’s username, falling back to 'admin'."""
    row = get_db().execute('SELECT username FROM user LIMIT 1').fetchone()
    return row['username'] if row else 'admin'

def get_setting(key, default=None):
    row = get_db().execute('SELECT value FROM settings WHERE key=?', (key,)).fetchone()
    return row['value'] if row else default


def set_setting(key, value):
    db = get_db()
    db.execute(
        'INSERT INTO settings (key,value) VALUES (?,?) '
        'ON CONFLICT(key) DO UPDATE SET value=excluded.value',
        (key, value))
    db.commit()

def is_b64_image(k: str, v: str) -> bool:
    return k.lower() in {"cover", "img", "poster"} and len(v) > 100

# Slug helpers
def slug_map() -> dict[str, str]:
    """Return {'say':'saying', 'post':'post', …} with fall-back defaults."""
    return {
        k: get_setting(f"slug_{k}", v) or v
        for k, v in SLUG_DEFAULTS.items()
    }

def kind_to_slug(kind: str) -> str:
    return slug_map().get(kind, kind)          

def slug_to_kind(slug: str) -> str | None:
    rev = {v: k for k, v in slug_map().items()}
    return rev.get(slug, slug)      

# Pagination helpers
def page_size() -> int:
    try:
        return int(get_setting('page_size', PAGE_DEFAULT))
    except (TypeError, ValueError):
        return PAGE_DEFAULT
    
def paginate(base_sql: str, params: tuple, *, page: int, per_page: int, db):
    total = db.execute(f"SELECT COUNT(*) FROM ({base_sql})", params).fetchone()[0]
    pages = (total + per_page - 1) // per_page
    rows  = db.execute(f"{base_sql} LIMIT ? OFFSET ?", params + (per_page, (page-1)*per_page)).fetchall()
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
    cur = {r['name'] for r in db.execute(
        "SELECT t.name FROM tag t JOIN entry_tag et ON t.id=et.tag_id "
        "WHERE et.entry_id=?", (entry_id,))}
    add    = tags - cur
    remove = cur - tags

    # -- add new ones ------------------------------------------------------
    for t in add:
        db.execute("INSERT OR IGNORE INTO tag(name) VALUES(?)", (t,))
        tag_id = db.execute("SELECT id FROM tag WHERE name=?", (t,)).fetchone()['id']
        db.execute("INSERT OR IGNORE INTO entry_tag VALUES (?,?)",  (entry_id, tag_id))
        
    # -- drop unneeded -----------------------------------------------------
    for t in remove:
        tag_id = db.execute("SELECT id FROM tag WHERE name=?", (t,)).fetchone()['id']
        db.execute("DELETE FROM entry_tag WHERE entry_id=? AND tag_id=?", (entry_id, tag_id))

    # -- garbage-collect unused tags --------------------------------------
    db.execute("DELETE FROM tag WHERE id NOT IN (SELECT DISTINCT tag_id FROM entry_tag)")
    db.commit()

def entry_tags(entry_id: int, *, db) -> list[str]:
    """Return a *sorted* list of tag names for one entry."""
    rows = db.execute(
        "SELECT t.name FROM tag t JOIN entry_tag et ON t.id=et.tag_id "
        "WHERE et.entry_id=? ORDER BY LOWER(t.name)", (entry_id,))
    return [r['name'] for r in rows]

def nav_pages():
    """List of dicts: [{'title':'About', 'slug':'about'}, …] sorted A-Z."""
    db = get_db()
    return db.execute(
        "SELECT title, slug FROM entry WHERE kind='page' ORDER BY LOWER(title)"
    ).fetchall()

# ── compact one-liner (verb:item:identifier[:progress]) ──────────────
CARET_COMPACT_RE = re.compile(r'''
    ^\^
    (?:"([^"]+)"|([a-z0-9_-]+)) :      # ➊ action  (grp 1 if quoted, grp 2 plain)
    (?:"([^"]+)"|([a-z0-9_-]+)) :      # ➋ item_type (grp 3 or grp 4)
    (?:
        "([^"]+)"                      # ➌ title — quoted         (grp 5)
      | ([^":\s]+)                     #     title — **un-quoted** (grp 6)
      | ([0-9a-f-]{36}|[a-z0-9_-]+)    #     slug/uuid             (grp 7)
    )
    (?:\s*:\s*(?:"([^"]+)"|([^":\s]+)))?  # ➍ progress (grp 8/9)
''', re.X | re.I | re.U)
# ── “long” meta lines ─────────────────────────
META_RE = re.compile(r'^\^([^\s:]+):"?(.*?)"?$', re.U)
UUID4_RE = re.compile(r'^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$', re.I)
IMPORT_RE = re.compile(r'''
    ^\^
    (?:"([^"]+)"|([0-9A-Za-z_-]+))   # action (grp1 if quoted, else grp2)
    :
    (https?://\S+)                   # absolute URL (grp3)
''', re.X | re.I)

def parse_trigger(text: str) -> tuple[str, list[dict]]:
    out_blocks, new_lines = [], []
    lines = text.splitlines()
    i = 0
    while i < len(lines):
        line = lines[i].strip()

        # ───────────────────────── 1) import block  (NEW) ──────────────────
        m = IMPORT_RE.match(line)
        if m:
            action = m.group(1) or m.group(2)
            url    = m.group(3)

            try:
                blk = import_item_json(url, action=action)
            except ValueError as exc:
                # Re-emit the original line so the user sees what failed,
                # and record nothing.
                new_lines.append(line + f"   ← {exc}")
                i += 1
                continue

            out_blocks.append(blk)
            new_lines.append(f'^{blk["item_type"]}:$PENDING${len(out_blocks)-1}$')
            i += 1
            continue


        # ── try compact form first ────────────────────────────────
        m = CARET_COMPACT_RE.match(line)
        if m:
            action    = m.group(1) or m.group(2)
            item_type = m.group(3) or m.group(4)
            title = m.group(5) or m.group(6)      # quoted OR un-quoted
            slug  = m.group(7)                    # stays the same meaning
            prog  = m.group(8) or m.group(9)      # quoted OR un-quoted

            verb = next(
                (vb for vb, acts in VERB_MAP.items() if action in acts),
                action
            )
            blk = {
                "verb"      : verb,
                "action"    : action,
                "item_type" : item_type,
                "title"     : title,
                "slug"      : slug,
                "progress"  : prog,
                "meta"      : {},
            }

            # ── NEW: hoover up following '^key:value' lines ──────────────────
            j = i + 1
            while j < len(lines):
                nxt = lines[j].strip()
                if not nxt.startswith('^') or CARET_COMPACT_RE.match(nxt):
                    break                       # stop on blank / non-caret / new block
                km = META_RE.match(nxt)
                if km:
                    k, v = km.groups()
                    k = k.lower()
                    if k == "progress":
                        blk["progress"] = v
                    elif k not in {          # core fields already set above
                            "action", "verb", "item", "item_type",
                            "title", "uuid", "slug"}:
                        blk["meta"][k] = v
                j += 1

            i = j                              # skip the absorbed lines
            out_blocks.append(blk)
            new_lines.append(f'^{item_type}:$PENDING${len(out_blocks)-1}$')
            continue

        # ── otherwise: collect verbose caret-meta lines ───────────
        if line.startswith('^'):
            tmp = {"verb":None,"action":None,"item_type":None,
                   "title":None,"slug":None,"progress":None,"meta":{}}
            while i < len(lines) and lines[i].lstrip().startswith('^'):
                ln = lines[i].strip()
                m2 = META_RE.match(ln)
                if not m2:
                    new_lines.append(lines[i])
                    i += 1
                    continue
                k, v = m2.groups()
                k = k.lower()
                if k in ("action", "verb"):      
                    tmp["action"]    = v
                elif k in ("item", "item_type"): 
                    tmp["item_type"] = v
                elif k == "title":               
                    tmp["title"]     = v
                elif k in ("uuid","slug"):       
                    tmp["slug"]      = v
                elif k == "progress":            
                    tmp["progress"]  = v
                elif tmp["item_type"] is None:
                    tmp["item_type"] = k               
                    # decide whether the value is a slug/uuid or a title
                    if UUID4_RE.fullmatch(v) or TOKEN_RE.fullmatch(v):
                        tmp["slug"] = v
                    else:
                        tmp["title"] = v
                else:                            
                    tmp["meta"][k]   = v
                i += 1

            tmp["verb"] = next(
                (vb for vb, acts in VERB_MAP.items() if tmp["action"] in acts),
                tmp["action"]
            )
            out_blocks.append(tmp)
            new_lines.append(f'^{tmp["item_type"]}:$PENDING${len(out_blocks)-1}$')
            continue

        # ── a normal, non-caret line ──────────────────────────────
        new_lines.append(lines[i])
        i += 1

    return '\n'.join(new_lines), out_blocks

def get_or_create_item(*, item_type, title, meta,
                       slug: str | None = None,
                       db,
                       update_meta: bool = True):
    # ➊ look up by slug first (if given)  --------------------------
    if slug:
        row = db.execute("SELECT id, slug, uuid FROM item WHERE slug=?", (slug,)).fetchone()
        if row:
            return row["id"], row["slug"], row["uuid"]
        if UUID4_RE.fullmatch(slug):
            row = db.execute("SELECT id, slug, uuid FROM item WHERE uuid=?", (slug,)).fetchone()
            if row:
                return row["id"], row["slug"], row["uuid"]

    # ➋ no slug/uuid → **always** create a new item
    #     (titles are allowed to repeat)

    # ➌ …or create a fresh item ------------------------------------
    if title is None:
        raise ValueError("slug not found and no title given → cannot create item")
    
    uuid_ = str(uuid.uuid4())
    slug  = slug or uuid_
    db.execute(
        "INSERT INTO item (uuid, slug, item_type, title) VALUES (?,?,?,?)",
        (uuid_, slug, item_type, title)
    )
    item_id = db.execute("SELECT last_insert_rowid()").fetchone()[0]

    if update_meta:
        for ord, (k, v) in enumerate(meta.items(), start=1):
            db.execute(
                "INSERT OR REPLACE INTO item_meta (item_id,k,v,ord) VALUES (?,?,?,?)",
                (item_id, k, v, ord)
            )
    return item_id, slug, uuid_

def has_kind(kind: str) -> bool:
    """True if at least one entry of this kind exists."""
    row = get_db().execute(
        "SELECT 1 FROM entry WHERE kind=? LIMIT 1", (kind,)
    ).fetchone()
    return bool(row)

VERB_KINDS = tuple(VERB_MAP.keys())
def active_verbs() -> list[str]:
    """All verbs that actually occur in the DB, in the declared order."""
    rows = get_db().execute(
        f"SELECT DISTINCT kind FROM entry "
        f"WHERE kind IN ({','.join('?'*len(VERB_KINDS))})",
        VERB_KINDS
    ).fetchall()
    present = {r['kind'] for r in rows}
    return [v for v in VERB_KINDS if v in present]

def _verbose_block(blk, uuid_):
    """Return the 5-line caret block​ string for one check-in."""
    def q(s):
        return f'"{s}"' if ' ' in s else s      # quote if it contains spaces
    parts = [
        f'^uuid:{uuid_}',
        f'^item_type:{blk["item_type"]}',
        f'^title:{q(blk["title"])}'   if blk["title"] else '',
        f'^action:{blk["action"]}',
        f'^progress:{q(blk["progress"])}' if blk["progress"] else ''
    ]
    return '\n'.join(p for p in parts if p)


def _csrf_token() -> str:
    """One token per session (rotates when the cookie does)."""
    return session.get("csrf", "")

# Expose helpers to templates
app.jinja_env.globals.update(kind_to_slug=kind_to_slug, get_setting=get_setting)
app.jinja_env.globals['external_icon'] = lambda: Markup("""
    <svg xmlns="http://www.w3.org/2000/svg"
        viewBox="0 0 20 20"
        width="11" height="11"
        style="vertical-align:baseline; margin-left:.2em; fill:currentColor"
        aria-hidden="true" focusable="false">
    <path d="M14 2h4v4h-2V4.41L9.41 11 8 9.59 14.59 3H14V2z"/>
    <path d="M15 9v7H4V4h7V2H4a2 2 0 0 0-2 2v12a2 2 0 0 0 2 2h12a2
            2 0 0 0 2-2V9h-3z"/>
    </svg>""")
app.jinja_env.globals['PAGE_DEFAULT'] = PAGE_DEFAULT
app.jinja_env.globals['entry_tags'] = lambda eid: entry_tags(eid, db=get_db())
app.jinja_env.globals['nav_pages'] = nav_pages
app.jinja_env.globals['version'] = __version__
app.jinja_env.globals.update(has_kind=has_kind,
                             active_verbs=active_verbs,
                             verb_kinds=VERB_KINDS)
app.jinja_env.globals["csrf_token"] = _csrf_token
app.jinja_env.globals['is_b64_image'] = is_b64_image

def theme_color() -> str:
    """Current theme colour (hex), falling back to the original green."""
    return get_setting('theme_color', '#A5BA93')
app.jinja_env.globals["theme_color"] = theme_color

THEME_PRESETS = {
    "Fern"   : "#A5BA93", 
    "Ocean"  : "#70C0E8",
    "Sunset" : "#F28C6B",
    "Lavender": "#BC9CFF",
    "Cherry" : "#EF476F",
    "Gold"   : "#F0A202",
}
app.jinja_env.globals["theme_presets"] = THEME_PRESETS

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
<link rel="stylesheet" href="{{ url_for('sakura_dark') }}">
<link rel="icon" href="{{ url_for('favicon') }}">
<link rel="alternate" type="application/rss+xml"
      href="{{ url_for('global_rss') }}" title="{{ title }} – RSS">
<style>
@media (max-width:560px){
    .meta {flex:0 0 100%;order:1;margin-left:0;text-align:left;}
}
</style>
<a href="#page-bottom" aria-label="Jump to footer"
   style="
        position:fixed;
        bottom:1.25rem;
        right:1.25rem;
        width:3rem; height:3rem;
        display:flex; align-items:center; justify-content:center;
        font-size:1.5rem; line-height:1;
        text-decoration:none;
        border-bottom:none;
        border-radius:50%;
        background:#aaa;
        color:#000;
        box-shadow:0 2px 6px rgba(0,0,0,.3);
        z-index:1000;
        opacity:.15;
   ">
    ↓
</a>
<div class="container" style="max-width: 60rem; margin: 3rem auto;">
    <h1 style="margin-top:0;"><a href="{{ url_for('index') }}" style="color:{{ theme_color() }};">{{title or 'po.etr.ist'}}</a></h1>
    <nav style="margin-bottom:1rem;
                display:flex;
                align-items:flex-end;
                font-size:.9em;">

        <!-- LEFT : two stacked rows -->
        <div style="display:flex; flex-direction:column; gap:.25rem;">

            <!-- row 1 – legacy kinds -->
            <div>
                <a href="{{ url_for('by_kind', slug=kind_to_slug('say')) }}"
                {% if kind=='say' %}style="text-decoration:none;border-bottom:.33rem solid #aaa;"{% endif %}>
                Says</a>&nbsp;&nbsp;

                <a href="{{ url_for('by_kind', slug=kind_to_slug('post')) }}"
                {% if kind=='post' %}style="text-decoration:none;border-bottom:.33rem solid #aaa;"{% endif %}>
                Posts</a>&nbsp;&nbsp;

                <a href="{{ url_for('by_kind', slug=kind_to_slug('pin')) }}"
                {% if kind=='pin' %}style="text-decoration:none;border-bottom:.33rem solid #aaa;"{% endif %}>
                Pins</a>&nbsp;&nbsp;

                <a href="{{ url_for('tags') }}"
                {% if kind=='tags' %}style="text-decoration:none;border-bottom:.33rem solid #aaa;"{% endif %}>
                Tags</a>&nbsp;&nbsp;
            </div>

            <!-- row 2 – verbs (shown only if at least one exists) -->
            {% if active_verbs() %}
            <div>
                {% for v in active_verbs() %}
                    {% set label = {'read':'Read','watch':'Watch',
                                    'listen':'Listen','play':'Play','visit':'Visit', "use": "Use"}[v] %}
                    <a href="{{ url_for('by_kind', slug=kind_to_slug(v)) }}"
                    {% if verb==v %}style="text-decoration:none;border-bottom:.33rem solid #aaa;"{% endif %}>
                    {{ label }}</a>{% if not loop.last %}&nbsp;&nbsp;{% endif %}
                {% endfor %}
            </div>
            {% endif %}
        </div>

        <!-- RIGHT : two stacked rows (auth button, search) -->
        <div style="margin-left:auto; display:flex; flex-direction:column; gap:.25rem;align-items:flex-end;">

            <!-- row 1 – Settings OR Login -->
            <div style="white-space:nowrap;">
                {% if session.get('logged_in') %}
                    <a href="{{ url_for('settings') }}"
                    {% if request.endpoint=='settings' %}style="text-decoration:none;border-bottom:.33rem solid #aaa;"{% endif %}>
                    Settings</a>
                {% else %}
                    <a href="{{ url_for('login') }}"
                    {% if request.endpoint=='login' %}style="text-decoration:none;border-bottom:.33rem solid #aaa;"{% endif %}>
                    Login</a>
                {% endif %}
            </div>

            <!-- row 2 – search box -->
            <div>
                <form action="{{ url_for('search') }}" method="get" style="margin:0;">
                    <input type="search" name="q" placeholder="Search"
                        value="{{ request.args.get('q','') }}"
                        style="width:13rem;font-size:.8em; padding:.2em .6em; margin:0;">
                </form>
            </div>
        </div>
    </nav>
    {% with msgs = get_flashed_messages() %}
    {% if msgs %}
        {# --- toast ----------------------------------------------------------- #}
        <div style="position:fixed;
                    top:1rem; right:1rem;
                    background:#323232; color:#fff;
                    padding:.75rem 1rem;
                    border-radius:.4rem;
                    font-size:.9rem; line-height:1.3;
                    box-shadow:0 2px 6px rgba(0,0,0,.4);
                    max-width:24rem; z-index:999;">
        {{ msgs|join('<br>')|safe }}
        </div>
    {% endif %}
    {% endwith %}
"""

TEMPL_EPILOG = """
    <footer id="page-bottom" style="margin-top:1rem;
                padding-top:1rem;
                font-size:.8em;
                color:#888;
                display:flex;              
                align-items:center;        
                justify-content:space-between;  
                border-top:1px solid #444;">
        <!-- left-hand side -->
        <span style="font-weight:normal;color:#aaa;">
            Built with
            <a href="https://github.com/huangziwei/poetrist"
               style="color:{{ theme_color() }};text-decoration:none;border-bottom:0.1px dotted currentColor;">
               poetrist</a>
               <span style="font-weight:normal;color:#aaa">v{{ version }}</span>
        </span>

        <!-- right-hand side – extra pages -->
        <nav style="display:inline-block;">
            {% for p in nav_pages() %}
                <a href="{{ '/' ~ p['slug'] }}"
                {% if request.path|trim('/') == p['slug'] %}
                    style="text-decoration:none;border-bottom:.33rem solid #aaa;align-items:center;"
                {% endif %}>
                    {{ p['title'] }}
                </a>
            {% endfor %}
        </nav>
    </footer>
</div> <!-- container -->
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
        return False                        # too old ➜ invalid
    except BadSignature:
        return False                        # forged ➜ invalid

    row = get_db().execute(
            'SELECT token_hash FROM user LIMIT 1').fetchone()
    return row and check_password_hash(row['token_hash'], handle)

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
            ip = (request.access_route[0] if request.access_route else request.remote_addr) or "unknown"

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

@app.route('/login', methods=['GET', 'POST'])
@rate_limit(max_requests=5, window=60)  # 3 attempts per minute
def login():
    # ── read token only from the form ──────────────────────────────
    token = request.form.get('token', '').strip()

    if request.method == 'POST' and token and validate_token(token):
        # ── token matched → burn it right away ─────────────────────
        db = get_db()
        db.execute(
            'UPDATE user SET token_hash=? WHERE id=1',
            (generate_password_hash(secrets.token_hex(16)),)
        )
        db.commit()

        session.clear()
        session.permanent = True
        session['logged_in'] = True
        session['csrf'] = secrets.token_hex(16)
        return redirect(url_for('index'))

    return render_template_string(TEMPL_LOGIN)

TEMPL_LOGIN = wrap("""
{% block body %}
<hr>
<form method="post" id="token-form">
  {% if csrf_token() %}
  <input type="hidden" name="csrf" value="{{ csrf_token() }}">
  {% endif %}

  <div style="position:relative;">
      <input name="token" type="password" autocomplete="current-password"
             style="width:100%;padding-right:7rem;">
      <label style="position:absolute;right:.5rem;top:40%;transform:translateY(-50%);
                    pointer-events:none;font-size:.75em;color:#aaa;">token</label>
  </div>
    <div style="
            margin-top:1rem;
            display:flex;
            gap:.6rem;                 
    ">
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
        style="
        display:none;                
        flex:1 1 auto;
        padding:.55rem 1rem;
        font-size:.95em;

        background:{{ theme_color() }};
        color:#000;
        border:1px solid #666;
        box-shadow:0 2px 4px rgba(0,0,0,.25);
        cursor:pointer;
        "
    >
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

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('index'))

# ──── WebAuthn / Passkey constants ──────────────────────────────
RP_NAME = "po.etr.ist"

# ──── tiny utils ────────────────────────────────────────────────
def _u(): return get_db().execute("SELECT id FROM user LIMIT 1").fetchone()["id"]

def _passkeys():
    return get_db().execute("""SELECT id, cred_id, nickname, created_at
                               FROM passkey WHERE user_id=?""", (_u(),)).fetchall()
app.jinja_env.globals['_passkeys'] = _passkeys

def _add_passkey(cred_id, pub_key, sign_count, nick):
    db = get_db()
    db.execute("""INSERT INTO passkey
                  (user_id, cred_id, pub_key, sign_count, nickname, created_at)
                  VALUES (?,?,?,?,?,?)""",
               (_u(), cred_id, pub_key, sign_count, nick,
                utc_now().isoformat(timespec="seconds")))
    db.commit()

def _rp_id() -> str:
    return request.host.partition(":")[0]


@app.route("/webauthn/begin_login")
def webauthn_begin_login():
    # 1. pull the raw bytes straight from the DB
    cred_bytes = [r["cred_id"] for r in _passkeys()]     #  <-- changed line
    if not cred_bytes:
        return {"allowCredentials": []}

    # 2. wrap every blob in a PublicKeyCredentialDescriptor
    allow = [PublicKeyCredentialDescriptor(id=b) for b in cred_bytes]

    # 3. generate options with the **current** host as rp_id
    opts = generate_authentication_options(
        rp_id             = _rp_id(),
        allow_credentials = allow,
        user_verification = UserVerificationRequirement.PREFERRED,
    )
    session["wa_chal"] = opts.challenge
    return options_to_json(opts)

@app.route("/webauthn/complete_login", methods=["POST"])
def webauthn_complete_login():
    data = request.get_json(force=True)
    cred_id = base64url_to_bytes(data["id"])
    pk      = get_db().execute("SELECT * FROM passkey WHERE cred_id=?", (cred_id,)).fetchone()
    if not pk:
        abort(400)
    try:
        ver = verify_authentication_response(
            credential                       = data,
            expected_challenge               = session.pop("wa_chal", ""),
            expected_rp_id                   = _rp_id(),                      # "localhost"
            expected_origin                  = f"{request.scheme}://{request.host}",
            credential_public_key            = pk["pub_key"],
            credential_current_sign_count    = pk["sign_count"],
            require_user_verification        = True,
        )
        # update the stored sign-count that WebAuthn uses for replay protection
        get_db().execute("UPDATE passkey SET sign_count=? WHERE id=?",
                        (ver.new_sign_count, pk["id"]))
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
    exclude = [
        PublicKeyCredentialDescriptor(id=r["cred_id"])
        for r in _passkeys()
    ]
    options = generate_registration_options(
        rp_id   = _rp_id(),  
        rp_name = get_setting("site_name", RP_NAME),
        user_id = str(_u()).encode(),
        user_name = current_username(),
        exclude_credentials = exclude,
        attestation = AttestationConveyancePreference.NONE,
    )
    session["wa_chal"] = options.challenge
    return options_to_json(options)

@app.route("/webauthn/complete_register", methods=["POST"])
def webauthn_complete_register():
    login_required()
    data = request.get_json(force=True)

    rp_id  = request.host.split(":", 1)[0]
    origin = f"{request.scheme}://{request.host}"

    try:
        ver = verify_registration_response(
            credential                = data,
            expected_challenge        = session.pop("wa_chal", ""),  # ← note default
            expected_rp_id            = rp_id,
            expected_origin           = origin,
            require_user_verification = True,
        )
    except Exception as e:
        print("webauthn register failed")        # prints stack in terminal
        return {"error": str(e)}, 400                    # visible in JS

    _add_passkey(
        cred_id    = base64url_to_bytes(data["id"]),
        pub_key    = ver.credential_public_key,
        sign_count = ver.sign_count,
        nick       = request.args.get("nickname") or "Passkey"
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
    db.execute(
        "DELETE FROM passkey WHERE id=? AND user_id=?", (pkid, _u())
    )
    db.commit()

    flash("Passkey deleted.")                   # nice feedback for the toast
    return redirect(url_for("settings"), code=303)  # PRG pattern

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
@app.route("/sakura-dark.min.css")
def sakura_dark():
    """Serve the local Sakura stylesheet with long-term caching."""
    return send_from_directory(
        Path(__file__).parent,          # directory where blog.py lives
        "sakura-dark.min.css",          # the file you downloaded
        mimetype="text/css",
        max_age=60*60*24*365            # 1-year cache header
    )

@app.route('/favicon.ico')
def favicon():
    return send_from_directory(
        Path(__file__).parent,          # directory where blog.py lives
        "favicon.ico",                  # the file you downloaded
        mimetype='image/x-icon',
        max_age=60*60*24*365            # 1-year cache header
    )

@app.route('/robots.txt')
def robots():
    """
    Block every crawler – search engines, AI spiders, everything.
    """
    rules = (
        "User-agent: *\n"
        "Disallow: /\n"
    )
    # Cache it for a year – the file never changes
    return Response(rules, mimetype='text/plain', direct_passthrough=True), 200, {
        "Cache-Control": "public, max-age=31536000"
    }

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
    sent  = request.form.get("csrf") or request.headers.get("X-CSRFToken", "")
    if not token or not secrets.compare_digest(token, sent):
        abort(403)

@app.after_request
def sec_headers(resp):
    resp.headers.update({
        "X-Frame-Options": "DENY",
        "X-Content-Type-Options": "nosniff",
        "Referrer-Policy": "strict-origin-when-cross-origin",
        "Permissions-Policy": "interest-cohort=()",   # opt-out of FLoC etc.
    })
    return resp

###############################################################################
# Settings
###############################################################################
@app.route('/settings', methods=['GET', 'POST'])
def settings():
    login_required()

    db = get_db()

    if request.method == 'POST' and request.form.get('action') == 'rotate_token':
        session['one_time_token'] = _rotate_token(db)   # store once
        return redirect(url_for('settings') + '#new-token', code=303)  # PRG; 303 = “See Other”


    if request.method == 'POST':
        site_name = request.form['site_name'].strip()
        username  = request.form['username'].strip()
        col = request.form['theme_color'].strip()

        if site_name:
            set_setting('site_name', site_name)

        if username:
            db.execute('UPDATE user SET username=? WHERE id=1', (username,))
            db.commit()

        if col:
            if re.fullmatch(r'#?[0-9A-Fa-f]{6}', col):
                if not col.startswith('#'):
                    col = '#' + col
                set_setting('theme_color', col)
            else:
                flash('Invalid colour – please use 6-digit hex.')

        set_setting('slug_say',  request.form.get('slug_say',  '').strip() or 'say')
        set_setting('slug_post', request.form.get('slug_post', '').strip() or 'post')
        set_setting('slug_pin',  request.form.get('slug_pin',  '').strip() or 'pin')

        size = max(1, int(raw)) if (raw := request.form.get('page_size','').strip()).isdigit() else PAGE_DEFAULT
        set_setting('page_size', size)

        flash('Settings saved.')
        return redirect(url_for('settings'))

    new_token = session.pop('one_time_token', None)     # use-and-forget
    cur_username = db.execute('SELECT username FROM user LIMIT 1') \
                       .fetchone()['username']
    return render_template_string(
        TEMPL_SETTINGS,
        site_name  = get_setting('site_name', 'po.etr.ist'),
        username   = cur_username,
        new_token  = new_token
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
                      
            <label style="display:block; margin:.5rem 0">
                <span style="font-size:.8em; color:#aaa">Theme colour</span><br>
                <input name="theme_color"
                    value="{{ get_setting('theme_color', '#A5BA93') }}"
                    placeholder="#A5BA93"
                    style="width:8rem">
            </label>
        </fieldset>

        <!-- ──────────── slugs ──────────── -->
        <fieldset style="margin:0 0 1.5rem 0; border:0; padding:0">
            <legend style="font-weight:bold; margin-bottom:.5rem;">URL slugs</legend>
                <div style="display:grid; grid-template-columns:repeat(auto-fit,minmax(10rem,1fr)); gap:.75rem;">
                    <label>
                        <span style="font-size:.8em; color:#aaa">Says</span><br>
                        <input name="slug_say"  value="{{ get_setting('slug_say',  'say')  }}" style="width:100%">
                    </label>
                    <label>
                        <span style="font-size:.8em; color:#aaa">Posts</span><br>
                        <input name="slug_post" value="{{ get_setting('slug_post', 'post') }}" style="width:100%">
                    </label>
                    <label>
                        <span style="font-size:.8em; color:#aaa">Pins</span><br>
                        <input name="slug_pin" value="{{ get_setting('slug_pin',  'pin')  }}" style="width:100%">
                    </label>
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
@app.route('/', methods=['GET', 'POST'])
def index():
    db = get_db()

    # Quick-add “Say” for logged-in admin
    if request.method == 'POST':
        login_required()
        body = request.form['body'].strip()

        if not body:
            flash('Text is required.')
            return redirect(request.url)

        if body:
            body, blocks = parse_trigger(body)
            kind  = blocks[0]['verb'] if blocks else infer_kind('', '')
            now_dt  = utc_now()
            now = now_dt.isoformat(timespec='seconds')
            slug = now_dt.strftime("%Y%m%d%H%M%S")

            db.execute("""INSERT INTO entry (body, created_at, slug, kind)
                          VALUES (?,?,?,?)""",
                       (body, now, slug, kind))
            entry_id = db.execute("SELECT last_insert_rowid()").fetchone()[0]

            sync_tags(entry_id, extract_tags(body), db=db)

            for idx, blk in enumerate(blocks):
                item_id, slug_i, uuid_i = get_or_create_item(
                    item_type = blk['item_type'],
                    title     = blk['title'],
                    meta      = blk['meta'],
                    slug      = blk['slug'],
                    db        = db,
                    update_meta=True        # only on creation
                )

                db.execute("""INSERT OR IGNORE INTO entry_item
                                (entry_id, item_id, verb, action, progress)
                            VALUES (?,?,?,?,?)""",
                        (entry_id, item_id,
                            blk['verb'], blk['action'], blk['progress']))

                # patch placeholder in the *local* variable
                body = body.replace(
                    f'^{blk["item_type"]}:$PENDING${idx}$',
                    _verbose_block(blk, uuid_i)
                )

            # 🔑  NOW write the patched body back ↓↓↓
            db.execute("UPDATE entry SET body=? WHERE id=?", (body, entry_id))
            db.commit()
            return redirect(url_for('index'))


    # pagination
    page = max(int(request.args.get('page', 1)), 1)
    ps   = page_size()
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

    pages = list(range(1, total_pages+1))

    return render_template_string(
        TEMPL_INDEX,
        entries = entries,
        page    = page,
        pages   = pages,          
        username= current_username(),
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
                      placeholder="What's on your mind?"></textarea>
            <button>Add&nbsp;Say</button>
        </form>
    {% endif %}
    <hr>
    {% for e in entries %}
    <article style="padding-bottom:1.5rem; {% if not loop.last %}border-bottom:1px solid #444;{% endif %}">
        {% if e['kind']=='pin' %}
            <h2>
                <a href="{{ e['link'] }}" target="_blank" rel="noopener">
                    {{ e['title'] }}
                </a>
                {{ external_icon() }} 
            </h2>
        {% elif e['kind']=='post' and e['title'] %}
            <h2>{{e['title']}}</h2>
        {% endif %}
        <p>{{e['body']|md}}</p>

        <small style="color:#aaa;">
            {% if e.item_title %} 
                <span style="
                    display:inline-block;padding:.1em .6em;margin-right:.4em;background:#444;
                    color:#fff;border-radius:1em;font-size:.75em;text-transform:capitalize;
                    vertical-align:middle;">
                   {{ e['action'] }}
                </span>
                {% if e.item_type %}
                <span style="
                    display:inline-block;padding:.1em .6em;margin-right:.4em;background:#444;
                    color:#fff;border-radius:1em;font-size:.75em;vertical-align:middle;">
                    {{ e.item_type|capitalize }}
                </span>
                {% endif %}
                {% if e.progress %}
                <span style="
                    display:inline-block;padding:.1em .6em;margin-right:.4em;background:#444;
                    color:#fff;border-radius:1em;font-size:.75em;vertical-align:middle;">
                    {{ e.progress }}
                </span>
                {% endif %}
                <a href="{{ url_for('item_detail', verb=e.kind, item_type=e.item_type, slug=e.item_slug) }}"
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
            <a href="{{ url_for('entry_detail', kind_slug=kind_to_slug(e['kind']), entry_slug=e['slug']) }}"
                style="text-decoration:none; color:inherit;vertical-align:middle;font-variant-numeric:tabular-nums;white-space:nowrap;">
                {{ e['created_at']|ts }}
            </a>&nbsp;
            {% if session.get('logged_in') %}
                <a href="{{ url_for('edit_entry', kind_slug=kind_to_slug(e['kind']), entry_slug=e['slug']) }}" style="vertical-align:middle;">Edit</a>&nbsp;&nbsp;
                <a href="{{ url_for('delete_entry', kind_slug=kind_to_slug(e['kind']), entry_slug=e['slug']) }}" style="vertical-align:middle;">Delete</a>
            {% endif %}
        </small>
    </article>
    {% else %}
        <p>No entries yet.</p>
    {% endfor %}

    {% if pages|length > 1 %}
    <nav style="margin-top:1rem;font-size:.75em;">
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



@app.route('/<slug>', methods=['GET', 'POST'])
def by_kind(slug):
    db = get_db()

    page = db.execute("SELECT * FROM entry WHERE kind='page' AND slug=?", (slug,)).fetchone()
    if page:
        return render_template_string(
            TEMPL_PAGE,
            e        = page,
            username = current_username(),
            kind     = 'page',
        )

    kind = slug_to_kind(slug)
    if kind == 'page':
        abort(404)

    # ---------- create new entry when the admin submits the inline form ----
    if request.method == 'POST':
        login_required()

        title = request.form.get('title', '').strip()
        body  = request.form.get('body',  '').strip()
        link  = request.form.get('link',  '').strip()

        body, blocks = parse_trigger(body)

        # final kind:  1st verb if any caret block, otherwise the URL kind
        if request.form.get("is_page") == "1":
            kind = "page"
        elif blocks:
            kind = blocks[0]['verb'] if blocks else kind

        missing = []

        if kind == 'say':
            if not body:
                missing.append('body')

        elif kind == 'post':
            if not title:
                missing.append('title')
            if not body:
                missing.append('body')

        elif kind == 'pin':                # body is OPTIONAL here
            if not title:
                missing.append('title')
            if not link:
                missing.append('link')

        if missing:
            nice = ' and '.join(missing)
            flash(f'{nice.capitalize()} {"is" if len(missing)==1 else "are"} required.')
            return redirect(url_for('by_kind', slug=kind_to_slug(kind or "")))

        now_dt = utc_now()
        now = now_dt.isoformat(timespec='seconds')
        slug = now_dt.strftime("%Y%m%d%H%M%S")
        db.execute("""INSERT INTO entry
                        (title, body, link, created_at, slug, kind)
                     VALUES (?,?,?,?,?,?)""",
                   (title or None, body, link or None, now, slug, kind))
        entry_id = db.execute("SELECT last_insert_rowid()").fetchone()[0]
        sync_tags(entry_id, extract_tags(body), db=db)
        db.commit()
        
        if kind == "page":
            return redirect(url_for("by_kind", slug=slug))

        return redirect(url_for('by_kind', slug=kind_to_slug(kind or "")))

    # --- pagination -------------------------------------------------------
    page = max(int(request.args.get('page', 1)), 1)
    ps   = page_size()

    if kind in VERB_KINDS:

        # --- ➊ collect the “pills” -------------------------------------------------
        cur = db.execute("""
            SELECT i.item_type, COUNT(DISTINCT i.id) AS cnt
            FROM item        i
            JOIN entry_item  ei ON ei.item_id = i.id
            WHERE ei.verb = ?
            GROUP BY i.item_type
        """, (kind,))
        type_rows = sorted((dict(r) for r in cur),          # [{item_type, cnt}, …]
                        key=lambda r: -r['cnt'])          # sort by cnt DESC

        # --- ➋ what filter (if any) is active? ------------------------------------
        sel_type = request.args.get('type', '').strip()      # e.g. “book”
        selected = sel_type.lower() if sel_type else ''      # empty → “All”

        def items_for_verb(verb: str, *, item_type: str | None,
                        page: int, per: int, db):
            base_sql = """
                SELECT i.id, i.title, i.item_type, i.slug,
                    MIN(CASE WHEN im.k='date' AND LENGTH(im.v)>=4
                                THEN SUBSTR(im.v,1,4) END)         AS year,
                    COUNT(DISTINCT e.id)                           AS cnt,
                    MAX(e.created_at)                              AS last_at,
                    (SELECT ei2.action
                        FROM entry_item ei2
                        JOIN entry      e2 ON e2.id = ei2.entry_id
                        WHERE ei2.item_id = i.id
                        AND ei2.verb    = ?
                        ORDER BY e2.created_at DESC
                        LIMIT 1)                                   AS last_action
                FROM item        i
                LEFT JOIN item_meta  im ON im.item_id = i.id
                JOIN  entry_item  ei ON ei.item_id  = i.id
                JOIN  entry       e  ON e.id        = ei.entry_id
                WHERE ei.verb = ?
            """
            params = [verb, verb]
            if item_type:
                base_sql += " AND i.item_type = ?"
                params.append(item_type)

            base_sql += """
                GROUP BY i.id
                ORDER BY last_at DESC
            """
            return paginate(base_sql, tuple(params),
                            page=page, per_page=per, db=db)

        rows, total_pages = items_for_verb(kind,
                                        item_type=selected or None,
                                        page=page, per=ps, db=db)
        pages = list(range(1, total_pages + 1))
        total_cnt = sum(r['cnt'] for r in type_rows)

        return render_template_string(
            TEMPL_ITEM_LIST,
            rows     = rows,
            pages    = pages,
            page     = page,
            verb     = kind,
            types    = type_rows,        
            selected = selected,  
            total_cnt= total_cnt,
            username = current_username(),
        )


    BASE_SQL = """
        SELECT e.*, ei.action
          FROM entry e
          LEFT JOIN entry_item ei ON ei.entry_id = e.id
         WHERE e.kind = ?
         ORDER BY e.created_at DESC
    """

    entries, total_pages = paginate(BASE_SQL, (kind,), page=page, per_page=ps, db=db)
    pages = list(range(1, total_pages+1))

    return render_template_string(
        TEMPL_LIST,
        rows     = entries,
        pages    = pages,
        page     = page,
        heading  = (kind or '').capitalize()+'s',
        kind     = kind,
        username = current_username(),
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
                <input name="title" style="width:100%;margin:0" placeholder="Title">
            {% endif %}
            {# Link field only for Pins #}
            {% if kind == 'pin' %}
                <input name="link" style="width:100%;margin:0" placeholder="Link">
            {% endif %}
            <textarea name="body" rows="3" style="width:100%;margin:0" placeholder="What's on your mind?"></textarea>
            
            <div style="display:flex;gap:.75rem;">
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
        {% for e in rows %}
        <article style="padding-bottom:1.5rem; {% if not loop.last %}border-bottom:1px solid #444;{% endif %}">
            {% if e['kind'] == 'pin' %}
                <h2>
                    <a href="{{ e['link'] }}" target="_blank" rel="noopener">
                        {{ e['title'] }}
                    </a>
                    {{ external_icon() }} 
                </h2>            
            {% elif e['title'] %}
                <h2>{{ e['title'] }}</h2>
            {% endif %}
            <p>{{ e['body']|md }}</p>
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
                <a href="{{ url_for('entry_detail', kind_slug=kind_to_slug(e['kind']), entry_slug=e['slug']) }}"
                    style="text-decoration:none; color:inherit;vertical-align:middle;font-variant-numeric:tabular-nums;white-space:nowrap;">
                    {{ e['created_at']|ts }}
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

        {% if pages|length > 1 %}
            <nav style="margin-top:1rem;font-size:.75em;">
                {% for p in pages %}
                    {% if p == page %}
                        <span style="border-bottom:0.33rem solid #aaa;">{{ p }}</span>
                    {% else %}
                        <a href="{{ request.path }}?page={{ p }}">{{ p }}</a>
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
<article>
  <p>{{ e['body']|md }}</p>
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

<!-- —— Type-cloud as selectable pills ——————————————— -->
<div style="display:flex; flex-wrap:wrap; gap:.25rem .5rem;">

    <!-- “All” pill -->
    <a href="{{ url_for('by_kind', slug=kind_to_slug(verb)) }}"
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
        <sup style="font-size:.5em;">{{ total_cnt }}</sup>
    </a>

    <!-- one pill per item_type -->
    {% for t in types %}
    <a href="{{ url_for('by_kind', slug=kind_to_slug(verb), type=t.item_type) }}"
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
        {{ t.item_type | capitalize }}
        <sup style="font-size:.5em;">{{ t.cnt }}</sup>
    </a>
    {% endfor %}
</div>

<!-- —— Item list ——————————————————————————————— -->
{% if rows %}
  <hr>
  <ul style="list-style:none; padding:0; margin:0;">
  {% for r in rows %}
    <li style="margin:1.5rem 0;">

      {# ─────────── ROW 1 – title ─────────── #}
      <a href="{{ url_for('item_detail',
                          verb=verb,
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
        {{ r.last_action }}
        </span>
        {% endif %}
        <span style="display:inline-block;padding:.1em .6em;background:#444;color:#fff;border-radius:1em;text-transform:capitalize;">
        {{ r.item_type|capitalize }}
        </span>
        <span style="white-space:nowrap;font-size:1rem;">
           • {{ r.cnt }}× • {{ r.last_at|ts }}
        </span>
      </div>
    </li>
  {% endfor %}
  </ul>

  {# — pagination unchanged — #}
  {% if pages|length > 1 %}
    <nav style="margin-top:1rem; font-size:.75em;">
      {% for p in pages %}
        {% if p == page %}
          <span style="border-bottom:.33rem solid #aaa;">{{ p }}</span>
        {% else %}
          <a href="{{ request.path }}?{% if selected %}type={{ selected }}&{% endif %}page={{ p }}">{{ p }}</a>
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


###############################################################################
# Entries (Say, Post, Pin)
###############################################################################

@app.route('/<kind_slug>/<entry_slug>')
def entry_detail(kind_slug, entry_slug):
    kind = slug_to_kind(kind_slug)
    if kind == 'page':
        abort(404)

    db = get_db()

    # grab one action (the first, if there are several entry_item rows)
    row = db.execute("""
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
    """, (kind, entry_slug)).fetchone()

    return render_template_string(
        TEMPL_ENTRY_DETAIL,
        e=row,
        title=get_setting('site_name', 'po.etr.ist'),
        username=current_username(),
        kind=row['kind'],
    )

TEMPL_ENTRY_DETAIL = wrap("""
    {% block body %}
        <hr>
        <article style="padding-bottom:1.5rem;">
            {% if e['kind']=='pin' %}
                <h2 style="margin-top:0">
                    <a href="{{ e['link'] }}" target="_blank" rel="noopener" title="{{ e['link'] }}"
                    style="word-break:break-all; overflow-wrap:anywhere;">
                    {{ e['title'] }} 
                    </a>
                    {{ external_icon() }}
                </h2>

            {% elif e['title'] %}
                <h2>{{ e['title'] }}</h2>
            {% endif %}

            <p>{{ e['body']|md }}</p>                
            <small style="color:#aaa;">

            {# —— item info (if any) ———————————————————————— #}
            {% if e.item_title %}
                <span style="
                      display:inline-block;padding:.1em .6em;margin-right:.4em;
                      background:#444;color:#fff;border-radius:1em;font-size:.75em;
                      text-transform:capitalize;vertical-align:middle;">
                    {{ e.action }}
                </span>
                {% if e.item_type %}
                    <span style="
                          display:inline-block;padding:.1em .6em;margin-right:.4em;
                          background:#444;color:#fff;border-radius:1em;font-size:.75em;
                          vertical-align:middle;">
                        {{ e.item_type | capitalize }}
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
                                    verb=e.kind,
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
            <a href="{{ url_for('entry_detail',
                                 kind_slug=kind_to_slug(e['kind']),
                                 entry_slug=e['slug']) }}"
               style="text-decoration:none; color:inherit;vertical-align:middle;font-variant-numeric:tabular-nums;white-space:nowrap;">
               {{ e['created_at']|ts }}
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
            </small>
        </article>
    {% endblock %}
""")


@app.route('/<kind_slug>/<entry_slug>/edit', methods=['GET', 'POST'])
def edit_entry(kind_slug, entry_slug):
    login_required()
    kind = slug_to_kind(kind_slug)
    db   = get_db()

    row  = db.execute("SELECT * FROM entry WHERE kind=? AND slug=?",
                      (kind, entry_slug)).fetchone()
    if not row:
        abort(404)

    if request.method == 'POST':
        title = request.form.get('title','').strip() or None
        body  = request.form['body'].strip()
        link  = request.form.get('link','').strip() or None
        new_slug = request.form.get('slug','').strip() or row['slug']

        # ── single pass ───────────────────────────────────────────────
        body, blocks = parse_trigger(body)            # ← only call once

        # decide the final kind
        if request.form.get('is_page') == '1' or row["kind"] == "page":
            new_kind = 'page'
        else:
            new_kind = blocks[0]['verb'] if blocks else infer_kind(title, link)

        if not body:
            flash('Body is required.')
            return redirect(request.url)

        # 2️⃣  Synchronise entry_item & item_meta
        db.execute("DELETE FROM entry_item WHERE entry_id=?", (row['id'],))
        for idx, blk in enumerate(blocks):
            item_id, slug_i, uuid_i = get_or_create_item(
                item_type = blk['item_type'],
                title     = blk['title'],
                meta      = blk['meta'],
                slug      = blk['slug'],
                db        = db,
                update_meta=False
            )
            db.execute("""INSERT OR REPLACE INTO entry_item
                            (entry_id, item_id, verb, action, progress)
                          VALUES (?,?,?,?,?)""",
                       (row['id'], item_id,
                        blk['verb'], blk['action'], blk['progress']))

            body = body.replace(
                f'^{blk["item_type"]}:$PENDING${idx}$',
                _verbose_block(blk, uuid_i)
            )

        # 3️⃣  Store the (possibly rewritten) entry itself
        db.execute("""UPDATE entry
                         SET title=?, body=?, link=?, slug=?, kind=?, updated_at=?
                       WHERE id=?""",
                   (title, body, link, new_slug, new_kind,
                    utc_now().isoformat(timespec='seconds'),
                    row['id']))

        # 4️⃣  Tags
        sync_tags(row['id'], extract_tags(body), db=db)
        db.commit()

        if new_kind == "page":
            return redirect(url_for('by_kind', slug=new_slug))        

        return redirect(url_for('entry_detail',
                                kind_slug=kind_to_slug(new_kind),
                                entry_slug=new_slug))

    return render_template_string(TEMPL_EDIT_ENTRY,
                                  e=row,
                                  title=get_setting('site_name', 'po.etr.ist'))


TEMPL_EDIT_ENTRY = wrap("""
{% block body %}
<hr>
<h2>Edit {{ e['kind']|capitalize }}</h2>
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
            <input id="Link"
                name="Link"
                value="{{ e['link'] or '' }}"
                style="width:100%; padding-right:7rem;">
            <label for="Link"
                style="position:absolute;
                right:.5rem;
                top:40%;
                transform:translateY(-50%);
                pointer-events:none;
                font-size:.75em;
                color:#aaa;">
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
    <div style="display:flex;gap:.75rem;">
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


@app.route('/<kind_slug>/<entry_slug>/delete', methods=['GET', 'POST'])
def delete_entry(kind_slug, entry_slug):
    login_required()
    kind = slug_to_kind(kind_slug)
    db   = get_db()

    row = db.execute("SELECT * FROM entry WHERE kind=? AND slug=?",
                     (kind, entry_slug)).fetchone()
    if not row:
        abort(404)

    if request.method == 'POST':
        db.execute('DELETE FROM entry WHERE id=?', (row['id'],))
        db.commit()
        db.execute("DELETE FROM tag WHERE id NOT IN "
                   "(SELECT DISTINCT tag_id FROM entry_tag)")
        db.commit()
        return redirect(url_for('index'))

    return render_template_string(TEMPL_DELETE_ENTRY,
                                  e=row,
                                  title=get_setting('site_name', 'po.etr.ist'))

TEMPL_DELETE_ENTRY = wrap("""
{% block body %}
    <hr>
    <h2>Delete entry?</h2>
    <article style="border-left:3px solid #c00; padding-left:1rem;">
        {% if e['title'] %}<h3>{{ e['title'] }}</h3>{% endif %}
        <p>{{ e['body']|md }}</p>
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
@app.route('/tags', defaults={'tag_list': ''})
@app.route('/tags/<path:tag_list>')
def tags(tag_list: str):
    """
    Show a tag cloud.  Pills can be selected / deselected; the current
    selection is encoded in the path as  /tags/foo+bar+baz
    """
    db = get_db()

    # ---------- tag statistics for the cloud --------------------------------
    cur  = db.execute("""SELECT t.name, COUNT(et.entry_id) AS cnt
                         FROM tag t
                         LEFT JOIN entry_tag et ON t.id = et.tag_id
                         GROUP BY t.id
                         ORDER BY LOWER(t.name)""")
    rows = [dict(r) for r in cur]           # make mutable dicts

    # ---------- who is currently selected? ----------------------------------
    selected = {t.lower() for t in tag_list.split('+') if t}

    # ---------- scale counts → font-size (same as before) -------------------
    counts = [r["cnt"] for r in rows]
    lo, hi = (min(counts), max(counts)) if counts else (0, 0)
    span   = max(1, hi - lo)
    for r in rows:
        weight     = (r["cnt"] - lo) / span if counts else 0
        r["size"]  = f"{0.75 + weight * 1.2:.2f}em"
        r["active"] = r["name"] in selected

        # ── URL that would result from clicking the pill ────────────────────
        new_sel = (selected - {r["name"]}) if r["active"] else (selected | {r["name"]})
        r["href"] = url_for('tags', tag_list='+'.join(sorted(new_sel))) if new_sel else url_for('tags')

    # ---------- fetch entries if something is selected ----------------------
    sort = request.args.get('sort', 'new') 
    page = max(int(request.args.get('page', 1)), 1)
    per  = page_size()
    if selected:
        order_sql = "e.created_at DESC" if sort == "new" else "e.created_at ASC"
        q_marks = ','.join('?' * len(selected))
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
        entries, total_pages = paginate(base_sql,
                                        (*selected, len(selected)),
                                        page=page, per_page=per, db=db)
        pages = list(range(1, total_pages + 1))
    else:
        entries, pages = None, []                       # nothing selected → no list

    return render_template_string(
        TEMPL_TAGS,
        tags     = rows,
        entries  = entries,
        selected = selected,
        page     = page,
        pages    = pages,
        sort     = sort,
        kind     = 'tags',
        username = current_username(),
    )

TEMPL_TAGS = wrap("""
{% block body %}
<hr>
<!-- —— Tag-cloud as selectable pills ——————————————— -->
<div style="display:flex; flex-wrap:wrap; gap:.25rem .5rem;">
{% for t in tags %}
    <a href="{{ t.href }}"
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
            <a href="{{ url_for('tags',
                                tag_list='+'.join(selected),
                                sort=val) }}"
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
        <article style="padding-bottom:1.5rem;
                        {% if not loop.last %}border-bottom:1px solid #444;{% endif %}">
            {% if e['title'] %}
                <h3 style="margin:.25rem 0 .5rem 0;">{{ e['title'] }}</h3>
            {% endif %}
            <p>{{ e['body']|md }}</p>
            <small style="color:#aaa;">
                {# —— item info (if any) ———————————————————————— #}
                {% if e.item_title %}
                    <span style="
                        display:inline-block;padding:.1em .6em;margin-right:.4em;
                        background:#444;color:#fff;border-radius:1em;font-size:.75em;
                        text-transform:capitalize;vertical-align:middle;">
                        {{ e.action }}
                    </span>
                    {% if e.item_type %}
                        <span style="
                            display:inline-block;padding:.1em .6em;margin-right:.4em;
                            background:#444;color:#fff;border-radius:1em;font-size:.75em;
                            vertical-align:middle;">
                            {{ e.item_type | capitalize }}
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
                                        verb=e.kind,
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
                <a href="{{ url_for('entry_detail', kind_slug=kind_to_slug(e['kind']), entry_slug=e['slug']) }}"
                    style="text-decoration:none; color:inherit;vertical-align:middle;">
                    {{ e['created_at']|ts }}
                </a>&nbsp;
                {% if session.get('logged_in') %}
                    <a href="{{ url_for('edit_entry', kind_slug=kind_to_slug(e['kind']), entry_slug=e['slug']) }}" style="vertical-align:middle;">Edit</a>&nbsp;&nbsp;
                    <a href="{{ url_for('delete_entry', kind_slug=kind_to_slug(e['kind']), entry_slug=e['slug']) }}" style="vertical-align:middle;">Delete</a>
                {% endif %}
            </small>
        </article>
    {% else %}
        <p>No entries for this combination.</p>
    {% endfor %}
                  
    {% if pages|length > 1 %}
        <nav style="margin-top:1rem;font-size:.75em;">
            {% for p in pages %}
                {% if p == page %}
                    <span style="border-bottom:0.33rem solid #aaa;">{{ p }}</span>
                {% else %}
                    <a href="{{ url_for('tags',
                                        tag_list='+'.join(selected),
                                        page=p) }}">{{ p }}</a>
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

def _rss(entries, *, title, feed_url, site_url):
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
            _external=True,            # absolute URL
        )

        body_html = md.reset().convert(strip_caret(e["body"]) if e["body"] else "")

        items.append(
            f"""
        <item>
          <title>{escape(e['title'] or (strip_caret(e["body"][:120]) + '…'))}</title>
          <link>{link}</link>
          <guid>{link}</guid>
          <pubDate>{_rfc2822(e['created_at'])}</pubDate>
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
    <lastBuildDate>{format_datetime(datetime.now().astimezone())}</lastBuildDate>
    <atom:link href="{feed_url}"
               rel="self"
               type="application/rss+xml" />

    {''.join(items)}
  </channel>
</rss>"""

# ------------------------------------------------------------------
#  ✨  RSS feeds
# ------------------------------------------------------------------
@app.route('/rss')
def global_rss():
    db  = get_db()
    rows = db.execute("SELECT * FROM entry ORDER BY created_at DESC LIMIT 50").fetchall()
    xml  = _rss(rows,
                title = get_setting('site_name', 'po.etr.ist'),
                feed_url = url_for('global_rss', _external=True),
                site_url = request.url_root.rstrip('/'))
    return app.response_class(xml, mimetype='application/rss+xml')


@app.route('/<slug>/rss')
def kind_rss(slug):
    kind = slug_to_kind(slug)
    if kind == 'page':  # pages don't have an RSS feed
        abort(404)
    db   = get_db()
    rows = db.execute("SELECT * FROM entry WHERE kind=? ORDER BY created_at DESC LIMIT 50",
                      (kind,)).fetchall()
    xml  = _rss(rows,
                title = f"{(kind or "").capitalize()} – {get_setting('site_name','po.etr.ist')}",
                feed_url = request.url,                 # already correct
                site_url = request.url_root.rstrip('/'))
    return app.response_class(xml, mimetype='application/rss+xml')


@app.route('/tags/<path:tag_list>/rss')
def tags_rss(tag_list):
    tags = [t.lower() for t in re.split(r'[,+/]', tag_list) if t]
    if not tags:
        abort(404)

    q_marks = ','.join('?' * len(tags))
    sql = f"""SELECT e.* FROM entry e
              JOIN entry_tag et ON et.entry_id = e.id
              JOIN tag t        ON t.id        = et.tag_id
              WHERE t.name IN ({q_marks})
              GROUP BY e.id HAVING COUNT(DISTINCT t.name)=?
              ORDER BY e.created_at DESC LIMIT 50"""
    rows = get_db().execute(sql, (*tags, len(tags))).fetchall()

    pretty = ' + '.join(tags)
    xml    = _rss(rows,
                  title   = f"#{pretty} – {get_setting('site_name','po.etr.ist')}",
                  feed_url = request.url,               # already correct
                  site_url = request.url_root.rstrip('/'))
    return app.response_class(xml, mimetype='application/rss+xml')

###############################################################################
# Check-ins / Items
###############################################################################
@app.route('/<verb>/<item_type>/<slug>', methods=['GET', 'POST'])
def item_detail(verb, item_type, slug):
    db   = get_db()
    itm = db.execute("SELECT id, uuid, slug, item_type, title "
                     "FROM item WHERE slug=? AND item_type=?",
                     (slug, item_type)).fetchone()
    if not itm:
        abort(404)

    # ──────────────────────────────── POST: quick “check-in” ──────────────
    if request.method == 'POST':
        login_required()

        # ❶ ── turn the user input into a {key: value} dict -----------------
        raw = request.form['meta'].rstrip()

        meta_dict: dict[str, str] = {}
        body_lines: list[str] = []

        for ln in raw.splitlines():
            ln = ln.strip()
            if not ln:
                continue
            if ln.startswith('^') and ':' in ln:        # looks like “^key: val”
                k, v = [p.strip() for p in ln.split(':', 1)]
                meta_dict[k.lower()] = v
            else:                                       # free text → body
                body_lines.append(ln + '\n')  # keep line breaks

        # ❷ ── ensure we have an *action* (may be inferred) ------------------
        if 'action' not in meta_dict:
            # most-recent action for the same item / verb
            r = db.execute("""SELECT ei.action
                               FROM entry_item ei
                               JOIN entry       e ON e.id = ei.entry_id
                              WHERE ei.item_id=? AND ei.verb=?
                              ORDER BY e.created_at DESC
                              LIMIT 1""",
                           (itm['id'], verb)).fetchone()
            if r:
                meta_dict['action'] = r['action']
            else:                                   # fall-back: 2nd word in map
                meta_dict['action'] = VERB_MAP[verb][1] \
                                   if verb in VERB_MAP and len(VERB_MAP[verb]) > 1 \
                                   else verb

        # ❸ ── build the caret block ----------------------------------------
        caret_lines = [
            f'^uuid:{itm["uuid"]}',
            f'^item_type:{itm["item_type"]}',
            f'^action:{meta_dict.pop("action")}',
        ]
        for k, v in meta_dict.items():          # any remaining keys (progress, …)
            caret_lines.append(f'{k}:{v}')

        # put user text (if any) underneath the caret block
        if body_lines:
            caret_lines.append('')          # blank line → separates meta/body
            caret_lines.extend(body_lines)

        body_raw = '\n'.join(caret_lines)

        body, blocks = parse_trigger(body_raw)        # normal pipeline

        now_dt   = utc_now()
        now_iso  = now_dt.isoformat(timespec='seconds')
        slug_ent = now_dt.strftime('%Y%m%d%H%M%S')

        # ➊  create the *entry* itself
        db.execute("""INSERT INTO entry (body, created_at, slug, kind)
                    VALUES (?,?,?,?)""",
                (body, now_iso, slug_ent, verb))
        entry_id = db.execute("SELECT last_insert_rowid()").fetchone()[0]

        # ➋  link entry ↔ item   (only one block here, but keep the loop)
        for idx, blk in enumerate(blocks):
            db.execute("""INSERT INTO entry_item
                            (entry_id, item_id, verb, action, progress)
                        VALUES (?,?,?,?,?)""",
                    (entry_id, itm['id'],
                        blk['verb'], blk['action'], blk['progress']))

            # replace placeholder with the finished verbose block
            body = body.replace(
                f'^{blk["item_type"]}:$PENDING${idx}$',
                _verbose_block(blk, itm['uuid'])
            )

        db.execute("UPDATE entry SET body=? WHERE id=?", (body, entry_id))
        db.commit()

        flash('Check-in added.')
        return redirect(request.url)

    meta = db.execute("""
            SELECT k, v
              FROM item_meta
             WHERE item_id=?
             ORDER BY ord, LOWER(k)         
        """, (itm['id'],)).fetchall()


    sort = request.args.get("sort", "new")          # ➊  new | old 

    if sort == "old":
        order_sql = "e.created_at ASC"
    else:                                           # newest (default)
        order_sql = "e.created_at DESC"

    rows = db.execute(f"""
            SELECT e.*, ei.action, ei.progress
              FROM entry      e
              JOIN entry_item ei ON ei.entry_id = e.id
             WHERE ei.item_id=? AND ei.verb=?
             ORDER BY {order_sql}
        """, (itm["id"], verb)).fetchall()

    return render_template_string(TEMPL_ITEM_DETAIL, 
                                  item   = itm,
                                  meta   = meta,
                                  entries= rows,
                                  verb   = verb,
                                  sort   = sort,
                                  username=current_username())

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
                verb=verb, item_type=item['item_type'], slug=item['slug']) }}">Edit</a>   
<a href="{{ url_for('delete_item',
                verb=verb, item_type=item['item_type'], slug=item['slug']) }}">&nbsp;&nbsp;Delete</a>   
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
        {% for val, label in [('new','Newest'),
                            ('old','Oldest')] %}
        <a href="{{ url_for('item_detail',
                            verb=verb,
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
    <p>{{ e['body']|md }}</p>
    <small style="color:#aaa;">

        {# —— action pill ——————————————————————————————— #}
        <span style="
            display:inline-block;padding:.1em .6em;margin-right:.4em;
            background:#444;color:#fff;border-radius:1em;font-size:.75em;
            text-transform:capitalize;vertical-align:middle;">
            {{ e.action }}
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
        <a href="{{ url_for('entry_detail',
                                kind_slug=kind_to_slug(e['kind']),
                                entry_slug=e['slug']) }}"
            style="text-decoration:none;color:inherit;vertical-align:middle;">
            {{ e['created_at']|ts }}
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

@app.route('/<verb>/<item_type>/<slug>/edit', methods=['GET', 'POST'])
def edit_item(verb, item_type, slug):
    login_required()
    db   = get_db()
    itm  = db.execute("SELECT * FROM item WHERE slug=? AND item_type=?",
                      (slug, item_type)).fetchone()
    if not itm:
        abort(404)

    if request.method == 'POST':
        title      = request.form['title'].strip()
        new_slug   = request.form['slug'].strip() or itm['slug']
        new_type   = request.form['item_type'].strip() or itm['item_type']

        # ➊ update main row ---------------------------------------------------
        db.execute("""UPDATE item SET title=?, slug=?, item_type=? WHERE id=?""",
                   (title, new_slug, new_type, itm['id']))

        # ➋ meta – collect paired lists -------------------------------
        keys  = request.form.getlist('meta_k')
        vals  = request.form.getlist('meta_v')
        orders = request.form.getlist('meta_o')

        triples = [
            (k.strip(), v.strip(), int(o) if o.strip().isdigit() else idx)
            for idx, (k, v, o) in enumerate(zip(keys, vals, orders), 1)
            if k.strip()
        ]
        db.execute("DELETE FROM item_meta WHERE item_id=?", (itm['id'],))
        for k, v, o in triples:
            db.execute("""INSERT INTO item_meta (item_id,k,v,ord)
                        VALUES (?,?,?,?)""", (itm['id'], k, v, o))

        db.commit()
        flash('Item saved.')
        return redirect(url_for('item_detail',
                                verb=verb, item_type=new_type, slug=new_slug))

    # → GET – render form -----------------------------------------------------
    meta_rows = db.execute(
        "SELECT k, v, ord FROM item_meta WHERE item_id=? ORDER BY ord, LOWER(k)", (itm['id'],)
    ).fetchall()

    return render_template_string(TEMPL_EDIT_ITEM,
                                  item      = itm,
                                  meta      = meta_rows,
                                  verb      = verb,
                                  username  = current_username())

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
    <a href="{{ url_for('item_detail', verb=verb,
                         item_type=item['item_type'], slug=item['slug']) }}"
       style="margin-left:1rem;">Cancel</a>
  </div>
</form>
{% endblock %}
""")


@app.route('/<verb>/<item_type>/<slug>/delete', methods=['GET', 'POST'])
def delete_item(verb, item_type, slug):
    login_required()
    db   = get_db()
    itm  = db.execute("SELECT * FROM item WHERE slug=? AND item_type=?",
                      (slug, item_type)).fetchone()
    if not itm:
        abort(404)

    if request.method == 'POST':
        db.execute("DELETE FROM item WHERE id=?", (itm['id'],))
        db.commit()
        flash('Item deleted.')
        return redirect(url_for('by_kind', slug=kind_to_slug(verb)))

    return render_template_string(TEMPL_DELETE_ITEM,
                                  item     = itm,
                                  verb     = verb, 
                                  username = current_username())

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
                        verb=verb,
                        item_type=item['item_type'],
                        slug=item['slug']) }}"
       style="margin-left:1rem;">Cancel</a>
  </form>
{% endblock %}
""")

###############################################################################
# Search
###############################################################################

_SAFE_TOKEN_RE = re.compile(r'^\w+$', re.UNICODE)

def _auto_quote(q: str) -> str:
    """Wrap every token that contains punctuation in double quotes."""
    out = []
    for tok in q.split():
        # leave trailing * outside the quotes so prefix-search still works
        star = tok.endswith('*')
        core = tok[:-1] if star else tok
        if not _SAFE_TOKEN_RE.fullmatch(core):
            core = core.replace('"', '""')         # escape embedded quotes
            tok = f'"{core}"' + ('*' if star else '')
        out.append(tok)
    return ' '.join(out)

# ------------------------------------------------------------------
# Full-text / LIKE search
# ------------------------------------------------------------------
def search_entries(q: str,
                   *,
                   db,
                   page: int = 1,
                   per_page: int = PAGE_DEFAULT,
                   sort: str = "rel"      #  rel | new | old
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
        order_sql = {"new": "e.created_at DESC",
                     "old": "e.created_at ASC"}.get(sort, "e.created_at DESC")
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
        total = db.execute(f"SELECT COUNT(*) FROM ({base_sql})",
                           (like, like)).fetchone()[0]
        rows  = db.execute(f"{base_sql} LIMIT ? OFFSET ?",
                           (like, like, per_page, (page-1)*per_page)).fetchall()
        return rows, total, removed

    # ─── ≥3 chars → FTS5 trigram index --------------------------------
    order_sql = {"new": "e.created_at DESC",
                    "old": "e.created_at ASC"}.get(sort, "rank")

    rows = db.execute(f"""
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
    """, (q, per_page, (page - 1) * per_page)).fetchall()

    total = db.execute(
        "SELECT COUNT(*) FROM entry_fts WHERE entry_fts MATCH ?", (q,)
    ).fetchone()[0]

    return rows, total, removed

_ITEM_Q_RE = re.compile(r"""
    ^\s*
    (?P<type>[^\s:]+)                 # track / book / …
    (?:\s*:\s*(?P<field>[^\s:]+))?    # 演唱 / 作者 / …
    \s*:\s*
    (?P<term>".+?"|[^"].*?)           # ← fixed here
    \s*$
""", re.X | re.I | re.U)

def _parse_item_query(q: str):
    """
    Return dict(type, field, term) *or* None if *q* is not an item query.
    Quotes around the term are stripped.
    """
    m = _ITEM_Q_RE.match(q)
    if not m:
        return None
    d = m.groupdict()
    term = d['term'].strip()
    if term.startswith('"') and term.endswith('"'):
        term = term[1:-1]
    d['term'] = term
    d['type'] = d['type'].lower()
    d['field'] = d['field'].lower() if d['field'] else None
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
        return [], 0           # not an item query → let caller fall back

    # ------------------------------------------------------------------ 
    # Build WHERE-clause and parameter list
    # ------------------------------------------------------------------
    conds, params = ["i.item_type = ?"], [spec['type']]
    like = f"%{spec['term'].lower()}%"

    # --- helper fragment: exclude base64 images -----------------------
    _no_b64 = (
        "im.k NOT IN ('cover','img','poster') "
        "AND LENGTH(im.v) < 500"              # >≈300 chars → almost always an image
    )

    if spec['field'] is None:                           #   book:"Kafka"
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

    elif spec['field'] == 'title':                      #   book:title:kafka
        conds.append("LOWER(i.title) LIKE ?")
        params.append(like)

    else:                                               #   book:author:kafka
        conds.append(f"""
            EXISTS (SELECT 1 FROM item_meta im
                     WHERE im.item_id = i.id
                       AND LOWER(im.k) = ?
                       AND {_no_b64}
                       AND LOWER(im.v) LIKE ?)
        """)
        params.extend([spec['field'], like])

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

    total = db.execute(f"SELECT COUNT(*) FROM ({base_sql})", tuple(params)).fetchone()[0]
    rows  = db.execute(f"{base_sql} LIMIT ? OFFSET ?",
                       tuple(params) + (per_page, (page-1)*per_page)).fetchall()
    return rows, total

def _make_like_snippet(title, body, terms):
    """
    Cheap LIKE-search snippet.
    - Strips caret meta.
    - Escapes HTML.
    - Highlights every term with <mark>.
    """
    body = strip_caret(body)
    pattern = re.compile('|'.join(re.escape(t) for t in terms), re.I)
    col = theme_color()
    return Markup(pattern.sub(lambda m: f'<mark style="background:transparent;color:{col};border-bottom:2px solid {col};">{m.group(0)}</mark>', body))

@app.route('/search')
def search():
    q_raw = request.args.get('q','').strip()
    page  = max(int(request.args.get('page',1)), 1)

    # ── ①  try item‑search first ─────────────────────────────────────
    if ':' in q_raw:                                      # quick pre‑filter
        rows, total = search_items(q_raw, db=get_db(),
                                   page=page, per_page=page_size())
        if total or _parse_item_query(q_raw):             # valid pattern
            pages = list(range(1, (total + page_size() - 1)//page_size() + 1))
            return render_template_string(
                TEMPL_SEARCH_ITEMS,
                rows   = rows,
                total  = total,
                query  = q_raw,
                page   = page,
                pages  = pages,
                kind   = 'search',
                username = current_username(),
            )
    
    # ── ②  fall back to the existing entry search ───────────────────
    sort  = request.args.get('sort','rel')
    rows, total, removed = search_entries(q_raw,
                db=get_db(),
                page=page,
                per_page=page_size(),
                sort=sort)
    
    terms = [q_raw]                              # q here is your original short token
    rows = [dict(r) for r in rows]           # make mutable copies
    for r in rows:
        r['snippet'] = _make_like_snippet(r['title'], r['body'], terms)


    pages = list(range(1, (total + page_size() - 1)//page_size() + 1))

    return render_template_string(
        TEMPL_SEARCH_ENTRIES,
        rows     = rows,
        query    = q_raw,
        sort     = sort,
        page     = page,
        pages    = pages,
        removed  = ''.join(sorted(removed)),
        kind     = 'search',
        username = current_username(),
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
        <article style="padding-bottom:1.5rem;
                        {% if not loop.last %}border-bottom:1px solid #444;{% endif %}">
            {% if e['title'] %}
                <h3 style="margin:.4rem 0;">{{ e['title'] }}</h3>
            {% endif %}
            <p>{{ e['snippet']|md }}</p>
            <small style="color:#aaa;">
                {% if e.item_title %}
                    <span style="display:inline-block;padding:.1em .6em;margin-right:.4em;
                                background:#444;color:#fff;border-radius:1em;font-size:.75em;
                                text-transform:capitalize;vertical-align:middle;">
                    {{ e.action }}
                    </span>
                    {% if e.item_type %}
                    <span style="display:inline-block;padding:.1em .6em;margin-right:.4em;
                                background:#444;color:#fff;border-radius:1em;font-size:.75em;
                                vertical-align:middle;">
                        {{ e.item_type|capitalize }}
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
                                        verb=e.kind,               
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
                {% if e['kind'] == 'page' %}
                    <a href="{{ '/' ~ e['slug'] }}"
                        style="text-decoration:none; color:inherit;vertical-align:middle;">
                        {{ e['created_at']|ts }}
                    </a>&nbsp;
                {% else %}
                <a href="{{ url_for('entry_detail', kind_slug=kind_to_slug(e['kind']), entry_slug=e['slug']) }}"
                    style="text-decoration:none; color:inherit;vertical-align:middle;">
                    {{ e['created_at']|ts }}
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
    <nav style="margin-top:1rem;font-size:.75em;">
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
        <a href="{{ url_for('item_detail',
                            verb=r.verb,          
                            item_type=r.item_type,
                            slug=r.slug) }}">
          {{ r.title }}
        </a>
        {% if r.year %}<small style="color:#888;">({{ r.year }})</small>{% endif %}
        <br>
        <small style="color:#888;">{{ r.item_type }} • {{ r.cnt }} check‑in{{ '' if r.cnt==1 else 's' }}</small>
      </li>
    {% endfor %}
    </ul>

    {% if pages|length > 1 %}
      <nav style="margin-top:1rem;font-size:.75em;">
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
# Error pages
###############################################################################

@app.route('/.well-known')
@app.route('/.well-known/<path:path>')
@app.route('/users/<path:path>')
@app.route('/nodeinfo')
@app.route('/nodeinfo/<path:path>')
@app.route('/api/nodeinfo')
@app.route('/api/nodeinfo/<path:path>')
@app.route('/inbox', methods=['GET','POST'])
def gone(path=None):
    return ('', 410)


@app.errorhandler(404)
def not_found(exc):
    """Site-wide “Not Found” page."""
    return render_template_string(TEMPL_404), 404

@app.errorhandler(500)
def internal_error(exc):
    """
    Generic 500 page for production.
    • In development (`FLASK_ENV=development`) the Werkzeug debugger
      still shows the interactive traceback, because Flask bypasses
      this handler while debug is on.
    """
    # Optional: log the traceback here if you like
    return render_template_string(TEMPL_500), 500

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

@app.route('/<verb>/<item_type>/<slug>/json')
@rate_limit(max_requests=30, window=60)
def export_item_json(verb, item_type, slug):
    db  = get_db()
    itm = db.execute("""SELECT id, uuid, slug, item_type, title
                          FROM item
                         WHERE item_type=? AND slug=?""",
                     (item_type, slug)).fetchone()
    if not itm:
        abort(404)

    meta = db.execute("""SELECT k, v, ord
                           FROM item_meta
                          WHERE item_id=?
                          ORDER BY ord""",
                      (itm['id'],)).fetchall()

    return {
        'title'    : itm['title'],
        'item_type': itm['item_type'],
        'slug'     : itm['slug'],
        'uuid'     : itm['uuid'],
        'meta'     : [{'k': m['k'], 'v': m['v'], 'ord': m['ord']} for m in meta]
    }

def import_item_json(url: str, *, action: str):
    """
    • Appends '/json' if missing.
    • Verifies that the verb in the URL matches the action/verb that the
      user wrote (so we don't attach a ^reading: …/watch/… item, etc.).
    • Returns a *block-dict* ready for get_or_create_item().
    """
    jurl = url if url.rstrip('/').endswith('/json') else url.rstrip('/') + '/json'
    parsed = urlparse(jurl)
    insecure_host = parsed.hostname in {"localhost", "127.0.0.1", "::1"}
    try:
        r = requests.get(jurl, timeout=5, verify=not insecure_host)
        r.raise_for_status()
        data = r.json()
    except Exception as exc:
        raise ValueError(f"Cannot fetch remote item → {exc}") from None

    # -------- sanity checks --------------------------------------------------
    need = {'uuid', 'slug', 'item_type', 'title'}
    if not need.issubset(data):
        raise ValueError("Remote item is missing mandatory fields")

    # -------- verb consistency ----------------------------------------------
    # 1) derive verb from URL  → '/read/book/kafka'   → 'read'
    path_parts = urlparse(url).path.strip('/').split('/')
    if len(path_parts) < 3:
        raise ValueError("Malformed URL")

    verb_from_url = path_parts[0]         # 'read', 'watch', …

    # 2) derive verb from action  ('reading' → 'read', 'to-read' → 'read', …)
    verb_from_action = next((v for v, acts in VERB_MAP.items()
                             if action in acts), action)

    if verb_from_url != verb_from_action:
        raise ValueError("Verb/action mismatch")

    # -------- craft the block dict ------------------------------------------
    return {
        "verb"      : verb_from_action,
        "action"    : action,
        "item_type" : data["item_type"],
        "title"     : data["title"],
        "slug"      : data["slug"],       # keep their nice slug
        "progress"  : None,
        "meta"      : {m["k"]: m["v"] for m in data.get("meta", [])},
    }


###############################################################################
# main
###############################################################################
if __name__ == '__main__':
    import sys
    if len(sys.argv) > 1 and sys.argv[1] == 'init':
        with app.app_context():
            cli_init()
    else:
        app.run(debug=True)
