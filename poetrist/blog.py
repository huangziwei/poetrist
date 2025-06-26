#!/usr/bin/env python3
"""
A single-file minimal blog.

blog.py
│
├─ 1  Imports & constants
├─ 2  App + Markdown filter
├─ 3  DB helpers
├─ 4  CLI (grouped)
├─ 5  Auth helpers + routes
├─ 6  Content helpers
├─ 7  Views (/  /<kind>  /edit  /settings)
├─ 8  Embedded templates (dict)
└─ 9  __main__
"""

import re
import secrets
import sqlite3
from datetime import datetime
from email.utils import format_datetime
from html import escape
from importlib.metadata import PackageNotFoundError, version
from pathlib import Path
from urllib.parse import urlparse

import click
import markdown
from flask import (
    Flask,
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
from markupsafe import Markup
from werkzeug.security import check_password_hash, generate_password_hash

################################################################################
# Imports & constants
################################################################################

ROOT        = Path(__file__).parent
DB_FILE     = ROOT / "blog.sqlite3"
TOKEN_LEN = 48
SECRET_FILE = ROOT / ".secret_key"
SECRET_KEY  = SECRET_FILE.read_text().strip() if SECRET_FILE.exists() \
              else secrets.token_hex(32)
SECRET_FILE.write_text(SECRET_KEY)
SLUG_DEFAULTS = {"say": "says", "post": "posts", "pin": "pins"}
KINDS = ("say", "post", "pin", "page")
PAGE_DEFAULT = 100 
TAG_RE = re.compile(r'(?<!\w)#([\w\-]+)')
HASH_LINK_RE = re.compile(r'(?<![A-Za-z0-9_])#([\w\-]+)')
RFC2822_FMT = "%a, %d %b %Y %H:%M:%S %z"
_TOKEN_CHARS = r"0-9A-Za-z\u0080-\uFFFF_"          # what unicode61 keeps
TOKEN_RE     = re.compile(f"[{_TOKEN_CHARS}]+")


try:
    __version__ = version("poetrist")
except PackageNotFoundError:
    __version__ = "0.1.0-dev"


################################################################################
# App + template filters
################################################################################
app = Flask(__name__)
app.config.update(SECRET_KEY=SECRET_KEY, DATABASE=str(DB_FILE))

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
        "pymdownx.highlight": {"guess_lang": True},
    },
)

@app.template_filter("md")
def md_filter(text: str | None) -> Markup:
    """
    Render Markdown and turn every #tag into
    <a href="/tags/<tag>">#tag</a>.
    """
    html = md.reset().convert(text or "")

    # post-process the generated HTML
    def repl(match):
        tag = match.group(1).lower()
        href = url_for("tags", tag_list=tag)
        return f'<a href="{href}" style="text-decoration:none;color:#F8B500">#{tag}</a>'

    html = HASH_LINK_RE.sub(repl, html)
    return Markup(html)

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

    return dt.astimezone().strftime("%Y.%m.%d %H:%M:%S")

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

        # one-time, lazy migrations
        ensure_updated_at()
        ensure_slug()
        ensure_fts()          
        ensure_fts_trigram()

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
            CREATE TABLE IF NOT EXISTS user (
                id INTEGER PRIMARY KEY,
                username TEXT UNIQUE NOT NULL,
                pwd_hash TEXT NOT NULL,
                token_hash TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS entry (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                title TEXT,
                body TEXT NOT NULL,
                link TEXT,
                created_at TEXT NOT NULL,
                updated_at TEXT,
                slug TEXT UNIQUE NOT NULL,
                kind TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS settings (
                key   TEXT PRIMARY KEY,
                value TEXT
            );
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
            INSERT OR IGNORE INTO settings (key, value)
                VALUES ('site_name', 'po.etr.ist');
            CREATE VIRTUAL TABLE IF NOT EXISTS entry_fts USING fts5(
                title,
                body,
                link,
                content='entry', -- auto-sync = simpler triggers
                content_rowid='id'
            );

            /* One-off back-fill for existing rows */
            INSERT OR IGNORE INTO entry_fts(rowid, title, body, link)
                SELECT id,
                    COALESCE(title,''),
                    body,
                    COALESCE(link,'')
                FROM entry;

            /* Keep FTS mirror in sync */
            CREATE TRIGGER IF NOT EXISTS entry_ai AFTER INSERT ON entry BEGIN
                INSERT INTO entry_fts(rowid, title, body, link)
                VALUES (new.id, new.title, new.body, new.link);
            END;
            CREATE TRIGGER IF NOT EXISTS entry_au AFTER UPDATE ON entry BEGIN
                UPDATE entry_fts
                SET title = new.title,
                    body  = new.body,
                    link  = new.link
                WHERE rowid = new.id;
            END;
            CREATE TRIGGER IF NOT EXISTS entry_ad AFTER DELETE ON entry BEGIN
                DELETE FROM entry_fts WHERE rowid = old.id;
            END;
            """
    )
    db.commit()

def ensure_updated_at():
    db = get_db()
    col = db.execute("PRAGMA table_info(entry);").fetchall()
    if not any(c["name"] == "updated_at" for c in col):
        db.execute("ALTER TABLE entry ADD COLUMN updated_at TEXT;")
        db.commit()

def ensure_slug():
    """Add slug and generate it for legacy rows once."""
    db = get_db()
    col = db.execute("PRAGMA table_info(entry);").fetchall()
    if not any(c["name"] == "slug" for c in col):
        db.execute("ALTER TABLE entry ADD COLUMN slug TEXT;")
        # fill historic rows
        for row in db.execute("SELECT id, created_at FROM entry WHERE slug IS NULL"):
            ts = datetime.fromisoformat(row["created_at"]).strftime("%Y%m%d%H%M%S")
            db.execute("UPDATE entry SET slug=? WHERE id=?", (ts, row["id"]))
        db.commit()

def ensure_fts():
    """
    Create the entry_fts virtual table + sync triggers if they are missing,
    then back-fill it with the current `entry` rows.
    Run once at start-up, no effect afterwards (“idempotent”).
    """
    db = get_db()

    # does the FTS table already exist?
    row = db.execute(
        "SELECT name FROM sqlite_master "
        "WHERE type='table' AND name='entry_fts'").fetchone()
    if row:                       # nothing to do
        return

    db.executescript("""
        /* 1. Table -------------------------------------------------------- */
        CREATE VIRTUAL TABLE entry_fts USING fts5(
            title,
            body,
            link,
            content='entry',
            content_rowid='id'
        );

        /* 2. Back-fill ---------------------------------------------------- */
        INSERT INTO entry_fts(rowid, title, body, link)
            SELECT id,
                   COALESCE(title,''),
                   body,
                   COALESCE(link,'')
            FROM entry;

        /* 3. Triggers to stay in sync ------------------------------------ */
        CREATE TRIGGER entry_ai AFTER INSERT ON entry BEGIN
            INSERT INTO entry_fts(rowid, title, body, link)
            VALUES (new.id, new.title, new.body, new.link);
        END;
        CREATE TRIGGER entry_au AFTER UPDATE ON entry BEGIN
            UPDATE entry_fts
               SET title=new.title,
                   body =new.body,
                   link =new.link
             WHERE rowid = new.id;
        END;
        CREATE TRIGGER entry_ad AFTER DELETE ON entry BEGIN
            DELETE FROM entry_fts WHERE rowid = old.id;
        END;
    """)
    db.commit()

def ensure_fts_trigram():
    """
    Add entry_fts3 (trigram tokenizer) + sync triggers if missing,
    then back-fill it.  Runs once per startup – idempotent.
    """
    db = get_db()
    row = db.execute(
        "SELECT name FROM sqlite_master "
        "WHERE type='table' AND name='entry_fts3'").fetchone()
    if row:
        return                                    # already there

    db.executescript("""
        /* -------- 1. table -------------------------------------- */
        CREATE VIRTUAL TABLE entry_fts3 USING fts5(
            title,
            body,
            link,
            content='entry',
            content_rowid='id',
            tokenize = 'trigram'
        );

        /* -------- 2. back-fill ---------------------------------- */
        INSERT INTO entry_fts3(rowid, title, body, link)
            SELECT id,
                   COALESCE(title,''),
                   body,
                   COALESCE(link,'')
            FROM entry;

        /* -------- 3. sync triggers ------------------------------ */
        CREATE TRIGGER entry_ai3 AFTER INSERT ON entry BEGIN
            INSERT INTO entry_fts3(rowid, title, body, link)
            VALUES (new.id, new.title, new.body, new.link);
        END;
        CREATE TRIGGER entry_au3 AFTER UPDATE ON entry BEGIN
            UPDATE entry_fts3
               SET title=new.title,
                   body =new.body,
                   link =new.link
             WHERE rowid = new.id;
        END;
        CREATE TRIGGER entry_ad3 AFTER DELETE ON entry BEGIN
            DELETE FROM entry_fts3 WHERE rowid = old.id;
        END;
    """)
    db.commit()

# -------------------------------------------------------------------------
# Time helpers
# -------------------------------------------------------------------------
def local_now() -> datetime:
    """
    Return an *aware* datetime that is already converted to the server’s
    local time-zone.  (Equivalent to datetime.now().astimezone())
    """
    return datetime.now().astimezone()


###############################################################################
# CLI – create admin + token
###############################################################################
def _create_admin(db, *, username: str, password: str) -> str:
    """Insert admin user and return the one-time token."""
    token = secrets.token_urlsafe(TOKEN_LEN)
    db.execute(
        "INSERT INTO user (username, pwd_hash, token_hash) VALUES (?,?,?)",
        (username,
         generate_password_hash(password),
         generate_password_hash(token))
    )
    db.commit()
    return token


def _rotate_token(db) -> str:
    """Generate + store a *new* one-time token, return it for display."""
    token = secrets.token_urlsafe(TOKEN_LEN)
    db.execute(
        "UPDATE user SET token_hash=? WHERE id=1",
        (generate_password_hash(token),)
    )
    db.commit()
    return token

@app.cli.command("init")
@click.option("--username", prompt=True,
              help="Admin username (will be created if DB empty)")
@click.option("--password", prompt=True, hide_input=True,
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
    click.echo("Use it at /login?token=<token> or paste it into the form.")


@app.cli.command("token")
def cli_token():
    """Rotate the admin’s one-time login token."""
    db = get_db()
    token = _rotate_token(db)

    click.secho("\n🔑  Fresh login token generated.\n", fg="yellow")
    click.echo(f"{token}\n")
    click.echo("Valid until first use → /login?token=<token>")

###############################################################################
# Authentication + routes
###############################################################################
def validate_token(token: str) -> bool:
    db = get_db()
    row = db.execute('SELECT token_hash FROM user LIMIT 1').fetchone()
    return row and check_password_hash(row['token_hash'], token)


def login_required() -> None:         
    if not session.get("logged_in"):
        abort(403)

@app.route('/login', methods=['GET', 'POST'])
def login():
    # ── read token from form or query string ──────────────────────────────
    token = (request.form['token'] if request.method == 'POST'
             else request.args.get('token', '')).strip()

    if token and validate_token(token):
        # ── token matched → burn it right away ────────────────────────
        db = get_db()
        db.execute('UPDATE user SET token_hash=? WHERE id=1',
                   (generate_password_hash(secrets.token_hex(16)),))
        db.commit()

        session.permanent = True      # keep user logged in across browser restarts
        session['logged_in'] = True
        return redirect(url_for('index'))

    return render_template_string(TEMPL_LOGIN)

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('index'))

@app.route("/sakura-dark.css")
def sakura_dark():
    """Serve the local Sakura stylesheet with long-term caching."""
    return send_from_directory(
        Path(__file__).parent,          # directory where blog.py lives
        "sakura-dark.css",              # the file you downloaded
        mimetype="text/css",
        max_age=60*60*24*365            # 1-year cache header
    )

@app.route('/favicon.ico')
def favicon():
    return send_from_directory(
        Path(__file__).parent,          # directory where blog.py lives
        "favicon.ico",                  # the file you downloaded
        mimetype='image/vnd.microsoft.icon',
        max_age=60*60*24*365            # 1-year cache header
    )

###############################################################################
# Tags (cloud + filter)  ─────────────────────────────────────────────────────
###############################################################################
@app.route('/tags',               defaults={'tag_list': ''})
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
    page = max(int(request.args.get('page', 1)), 1)
    per  = page_size()
    if selected:
        q_marks = ','.join('?' * len(selected))
        base_sql = f"""SELECT e.*
                  FROM entry  e
                  JOIN entry_tag et ON et.entry_id = e.id
                  JOIN tag       t  ON t.id        = et.tag_id
                  WHERE t.name IN ({q_marks})
                  GROUP BY e.id
                  HAVING COUNT(DISTINCT t.name)=?
                  ORDER BY e.created_at DESC"""
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
        title    = get_setting('site_name', 'po.etr.ist'),
        kind     = 'tags',
        username = current_username(),
    )


###############################################################################
# Content helpers
###############################################################################
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
    return rev.get(slug)         

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

###############################################################################
# Views
###############################################################################
@app.route('/', methods=['GET', 'POST'])
def index():
    db = get_db()

    # Quick-add “Say” for logged-in admin
    if request.method == 'POST':
        login_required()
        body = request.form['body'].strip()
        if body:
            kind  = infer_kind('', '')
            now_dt  = local_now()
            now = now_dt.isoformat(timespec='seconds')
            slug = now_dt.strftime("%Y%m%d%H%M%S")

            db.execute("""INSERT INTO entry (body, created_at, slug, kind)
                          VALUES (?,?,?,?)""",
                       (body, now, slug, kind))
            entry_id = db.execute("SELECT last_insert_rowid()").fetchone()[0]
            sync_tags(entry_id, extract_tags(body), db=db)
            db.commit()
            return redirect(url_for('index'))


    # pagination
    page = max(int(request.args.get('page', 1)), 1)
    ps   = page_size()

    BASE_SQL = "SELECT * FROM entry WHERE kind!='page' ORDER BY created_at DESC"
    entries, total_pages = paginate(BASE_SQL, (), page=page, per_page=ps, db=db)

    pages = list(range(1, total_pages+1))

    return render_template_string(
        TEMPL_INDEX,
        entries = entries,
        page    = page,
        pages   = pages,          
        title   = get_setting('site_name', 'po.etr.ist'),
        username= current_username(),
    )

@app.route('/<slug>', methods=['GET', 'POST'])
def by_kind(slug):
    db = get_db()

    page = db.execute("SELECT * FROM entry WHERE kind='page' AND slug=?", (slug,)).fetchone()
    if page:
        return render_template_string(
            TEMPL_PAGE,
            e        = page,
            title    = get_setting('site_name', 'po.etr.ist'),
            username = current_username(),
            kind     = 'page',
        )

    kind = slug_to_kind(slug)
    if kind not in KINDS[:-1]:
        abort(404)

    # ---------- create new entry when the admin submits the inline form ----
    if request.method == 'POST':
        login_required()

        title = request.form.get('title', '').strip()
        body  = request.form.get('body',  '').strip()
        link  = request.form.get('link',  '').strip()

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
            return redirect(url_for('by_kind', slug=kind_to_slug(kind)))

        now_dt = local_now()
        now = now_dt.isoformat(timespec='seconds')
        slug = now_dt.strftime("%Y%m%d%H%M%S")
        db.execute("""INSERT INTO entry
                        (title, body, link, created_at, slug, kind)
                     VALUES (?,?,?,?,?,?)""",
                   (title or None, body, link or None, now, slug, kind))
        entry_id = db.execute("SELECT last_insert_rowid()").fetchone()[0]
        sync_tags(entry_id, extract_tags(body), db=db)
        db.commit()
        
        return redirect(url_for('by_kind', slug=kind_to_slug(kind)))

    # --- pagination -------------------------------------------------------
    page = max(int(request.args.get('page', 1)), 1)
    ps   = page_size()

    entries, total_pages = paginate('SELECT * FROM entry WHERE kind=? ORDER BY created_at DESC', (kind,), page=page, per_page=ps, db=db)
    pages = list(range(1, total_pages+1))

    return render_template_string(
        TEMPL_LIST,
        rows     = entries,
        pages    = pages,
        page     = page,
        heading  = kind.capitalize()+'s',
        kind     = kind,
        title    = get_setting('site_name', 'po.etr.ist'),
        username = current_username(),
    )

@app.route('/settings', methods=['GET', 'POST'])
def settings():
    login_required()

    db = get_db()

    if request.method == 'POST' and request.form.get('action') == 'rotate_token':
        session['one_time_token'] = _rotate_token(db)   # store once
        return redirect(url_for('settings'), code=303)  # PRG; 303 = “See Other”


    if request.method == 'POST':
        site_name = request.form['site_name'].strip()
        username  = request.form['username'].strip()

        if site_name:
            set_setting('site_name', site_name)

        if username:
            db.execute('UPDATE user SET username=? WHERE id=1', (username,))
            db.commit()

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
        title      = get_setting('site_name', 'po.etr.ist'),
        site_name  = get_setting('site_name', 'po.etr.ist'),
        username   = cur_username,
        new_token  = new_token
    )

@app.route('/<slug>/<ts>')
def entry_detail(slug, ts):
    kind = slug_to_kind(slug)
    if kind not in ('say', 'post', 'pin'):
        abort(404)

    row = get_db().execute(
        "SELECT * FROM entry WHERE kind=? AND slug=?",
        (kind, ts)
    ).fetchone()

    if not row:
        abort(404)

    return render_template_string(
        TEMPL_DETAIL,
        e=row,
        title=get_setting('site_name', 'po.etr.ist'),
        username=current_username(),
        kind=row['kind']
    )

@app.route('/edit/<int:entry_id>', methods=['GET', 'POST'])
def edit_entry(entry_id):
    login_required()

    db  = get_db()
    row = db.execute('SELECT * FROM entry WHERE id=?', (entry_id,)).fetchone()
    if not row:
        abort(404)

    if request.method == 'POST':
        title = request.form.get('title','').strip() or None
        body  = request.form['body'].strip()
        link  = request.form.get('link','').strip() or None
        new_slug = request.form.get('slug', '').strip() or row['slug']

        if not body:
            flash('Body is required.')
            return redirect(url_for('edit_entry', entry_id=entry_id))

        form_flag = request.form.get('is_page')          

        if form_flag is None:            
            new_kind = row['kind']
        elif form_flag == "1":              
            new_kind = 'page'
        else:                   
            new_kind = infer_kind(title, link)

        # --- update live row ---
        db.execute("""UPDATE entry
                         SET title=?,
                             body=?,
                             link=?,
                             slug=?,
                             kind=?,
                             updated_at=?
                       WHERE id=?""",
                   (title, body, link, new_slug, new_kind,
                    local_now().isoformat(timespec='seconds'),
                    entry_id))
        sync_tags(entry_id, extract_tags(body), db=db)
        db.commit()
        return redirect(url_for('index'))

    # GET → render form
    return render_template_string(TEMPL_EDIT,
                                  e=row,
                                  title=get_setting('site_name', 'po.etr.ist'),
                                )

@app.route('/delete/<int:entry_id>', methods=['GET', 'POST'])
def delete_entry(entry_id):
    login_required()
    db  = get_db()

    # ── Step 2: POST → actually delete ───────────────────────────────────────
    if request.method == 'POST':
        db.execute('DELETE FROM entry WHERE id=?', (entry_id,))
        db.commit()
        db.execute("DELETE FROM tag WHERE id NOT IN (SELECT DISTINCT tag_id FROM entry_tag)")
        db.commit()
        return redirect(url_for('index'))

    # ── Step 1: GET  → show lightweight confirm page ─────────────────────────
    row = db.execute('SELECT * FROM entry WHERE id=?', (entry_id,)).fetchone()
    if not row:
        abort(404)

    return render_template_string(TEMPL_DELETE,
                                  e=row,
                                  title=get_setting('site_name', 'po.etr.ist'),
                                  )

###############################################################################
# Embedde​d templates
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
    <h1 style="margin-top:0"><a href="{{ url_for('index') }}">{{title or 'po.etr.ist'}}</a></h1>
    <nav style="margin-bottom:1rem;display:flex;">
        <div>
            <a href="{{ url_for('by_kind', slug=kind_to_slug('say')) }}"
                {% if kind|default('')=='say'  %}style="text-decoration:none;border-bottom:0.33rem solid #aaa;"{% endif %}>
                Says</a>&nbsp;&nbsp;
            <a href="{{ url_for('by_kind', slug=kind_to_slug('post')) }}"
                {% if kind|default('')=='post' %}style="text-decoration:none;border-bottom:0.33rem solid #aaa;"{% endif %}>
                Posts</a>&nbsp;&nbsp;
            <a href="{{ url_for('by_kind', slug=kind_to_slug('pin')) }}"
                {% if kind|default('')=='pin'  %}style="text-decoration:none;border-bottom:0.33rem solid #aaa;"{% endif %}>
                Pins</a>&nbsp;&nbsp;
            <a href="{{ url_for('tags') }}"
                {% if kind|default('')=='tags' %}style="text-decoration:none;border-bottom:0.33rem solid #aaa;"{% endif %}>
                Tags</a>&nbsp;&nbsp;
            {% for p in nav_pages() %}
                <a href="{{ '/' ~ p['slug'] }}"
                {% if request.path|trim('/') == p['slug'] %}style="text-decoration:none;border-bottom:0.33rem solid #aaa;"{% endif %}>
                {{ p['title'] }}</a>
                {% if not loop.last %}&nbsp;&nbsp;{% endif %}
            {% endfor %}
        </div>
        <div style="margin-left:auto; white-space:nowrap;">
            {% if session.get('logged_in') %}
                &nbsp;&nbsp;
                <a href="{{ url_for('settings') }}"
                {% if request.endpoint == 'settings' %}
                    style="text-decoration:none;border-bottom:0.33rem solid #aaa;"
                {% endif %}>
                Settings</a>
            {% else %}
                &nbsp;&nbsp;
                <a href="{{ url_for('login') }}"
                {% if request.endpoint == 'login' %}
                    style="font-weight:bold; text-decoration:none;"
                {% endif %}>
                Login
                </a>
            {% endif %}
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
        <span>
            Built with
            <a href="https://github.com/huangziwei/poetrist"
               style="color:#F8B500; text-decoration:none;">
               poetrist 
            </a><span style="font-weight:normal;">v{{ version }}</span>
        </span>

        <!-- right-hand side -->
        <form action="{{ url_for('search') }}" method="get" style="margin:0;">
            <input type="search" name="q" placeholder="Search"
                   value="{{ request.args.get('q','') }}"
                   style="font-size:.8em; padding:.2em .6em;">
        </form>
    </footer>
</div> <!-- container -->
"""


TEMPL_LOGIN = wrap("""
    {% block body %}
    <hr>
    <form method=post>
    <div style="position:relative;">
        <input  name="token"
            type="password"          
            autocomplete="current-password"
            style="width:100%; padding-right:7rem;">
        <label for="token"
                style="position:absolute;
                        right:.5rem;
                        top:40%;
                        transform:translateY(-50%);
                        pointer-events:none;
                        font-size:.75em;
                        color:#aaa;">
                    token
        </label>
    </div>
    <button>Log&nbsp;in</button>
    </form>
    {% endblock %}
""")

TEMPL_INDEX = wrap("""{% block body %}
    {% if session.get('logged_in') %}
    <hr>
    <form method=post>
        <textarea name=body rows=3 style="width:100%;margin-bottom:0rem;" placeholder="What's on your mind?"></textarea>
        <button>Add Say</button>
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
            <a href="{{ url_for('entry_detail', slug=kind_to_slug(e['kind']), ts=e['slug']) }}"
                style="text-decoration:none; color:inherit;vertical-align:middle;">
                {{ e['created_at']|ts }}
            </a>&nbsp;
            {% if session.get('logged_in') %}
                <a href="{{ url_for('edit_entry', entry_id=e['id']) }}" style="vertical-align:middle;">Edit</a>&nbsp;&nbsp;
                <a href="{{ url_for('delete_entry', entry_id=e['id']) }}" style="vertical-align:middle;">Delete</a>
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



TEMPL_LIST = wrap("""
    {% block body %}
        {% if session.get('logged_in') %}
        <hr style="margin:10px 0">
        <form method="post" 
                  style="display:flex;flex-direction:column;gap:10px;align-items:flex-start;">
            {# Title field for Posts & Pins #}
            {% if kind in ('post', 'pin') %}
                <input name="title" style="width:100%;margin:0" placeholder="Title">
            {% endif %}
            {# Link field only for Pins #}
            {% if kind == 'pin' %}
                <input name="link" style="width:100%;margin:0" placeholder="Link">
            {% endif %}
            <textarea name="body" rows="3" style="width:100%;margin:0" placeholder="What's on your mind?"></textarea>
            <button style="width:">Add&nbsp;{{ kind.capitalize() }}</button>
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
                    {{ e['kind'] }}
                    </a>
                </span>
                <a href="{{ url_for('entry_detail', slug=kind_to_slug(e['kind']), ts=e['slug']) }}"
                    style="text-decoration:none; color:inherit;vertical-align:middle;">
                    {{ e['created_at']|ts }}
                </a>&nbsp;
                {% if session.get('logged_in') %}
                    <a href="{{ url_for('edit_entry', entry_id=e['id']) }}" style="vertical-align:middle;">Edit</a>&nbsp;&nbsp;
                    <a href="{{ url_for('delete_entry', entry_id=e['id']) }}" style="vertical-align:middle;">Delete</a>
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

TEMPL_SETTINGS = wrap("""
    {% block body %}
    <hr>
    <form method="post" style="max-width:36rem">

        <!-- ──────────── site info ──────────── -->
        <fieldset style="margin:0 0 1.5rem 0; border:0; padding:0">
            <legend style="font-weight:bold; margin-bottom:.5rem;">Site</legend>

            <label style="display:block; margin:.5rem 0">
                <span style="font-size:.8em; color:#aaa">Site name</span><br>
                <input name="site_name" value="{{ site_name }}" style="width:100%">
            </label>

            <label style="display:block; margin:.5rem 0">
                <span style="font-size:.8em; color:#aaa">Username</span><br>
                <input name="username" value="{{ username }}" style="width:100%">
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
            <legend style="font-weight:bold; margin-bottom:.5rem;">Display</legend>
            <label style="display:block; margin:.5rem 0">
                <span style="font-size:.8em; color:#aaa">Entries per page</span><br>
                <input name="page_size"
                    value="{{ get_setting('page_size', PAGE_DEFAULT) }}"
                    style="width:8rem">
            </label>
        </fieldset>
        <button style="margin-top:.5rem;">Save settings</button>
    </form>
    <div style="display:flex; gap:1rem; max-width:36rem; margin-top:2rem;">
        <!-- token button in its own tiny form -->
        <form method="post" style="margin:0;">
            <button name="action" value="rotate_token" style="color:#F8B500; background:#333;">
                Get new token
            </button>
        </form>
    </div>

    {% if new_token %}
        <div style="margin-top:1.5rem; padding:1rem; border:1px solid #555;
                    background:#222; font-family:monospace; word-break:break-all;font-size:1.2rem;">
            {{ new_token }}
        </div>
    {% endif %}

    
    <!-- logout link, vertically centered -->
    <div style="display:flex; gap:1rem; max-width:36rem; margin-top:2rem;">
        <a href="{{ url_for('logout') }}"
            style="align-self:center; color:#F8B500; text-decoration:none;">
        ⎋ Log&nbsp;out
        </a>
    </div>
    
    {% endblock %}
""")

TEMPL_DETAIL = wrap("""
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
            {# — kind pill — #}
            <span style="
                display:inline-block;
                padding:.1em .6em;
                margin-right:.4em;
                background:#444;
                color:#fff;
                border-radius:1em;
                font-size:.75em;
                text-transform:capitalize;
                vertical-align:middle;">
                <a href="{{ url_for('by_kind', slug=kind_to_slug(e['kind'])) }}"
                style="text-decoration:none; color:inherit; border-bottom:none;">
                {{ e['kind'] }}
                </a>
            </span>
            {# — timestamp — #}
            <a href="{{ url_for('entry_detail',
                                slug=kind_to_slug(e['kind']),
                                ts=e['slug']) }}"
                style="text-decoration:none; color:inherit; vertical-align:middle;">
                {{ e['created_at']|ts }}
            </a>
            {# — author — #}
            <span style="vertical-align:middle;">&nbsp;by&nbsp;{{ username }}</span>&nbsp;&nbsp;
            {# — edit/delete (admin only) — #}
            {% if session.get('logged_in') %}
                <a href="{{ url_for('edit_entry', entry_id=e['id']) }}"
                    style="vertical-align:middle;">Edit</a>&nbsp;&nbsp;
                <a href="{{ url_for('delete_entry', entry_id=e['id']) }}"
                    style="vertical-align:middle;">Delete</a>
            {% endif %}
            </small>
        </article>
    {% endblock %}
""")

TEMPL_EDIT = wrap("""
{% block body %}
<form method="post">
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

TEMPL_DELETE = wrap("""
{% block body %}
  <h2>Delete entry?</h2>
  <article style="border-left:3px solid #c00; padding-left:1rem;">
      {% if e['title'] %}<h3>{{ e['title'] }}</h3>{% endif %}
      <p>{{ e['body']|md }}</p>
      <small style="color:#aaa;">{{ e['created_at']|ts }}</small>
  </article>
  <form method="post" style="margin-top:1rem;">
      <button style="background:#c00; color:#fff;">Yes – delete it</button>
      <a href="{{ url_for('index') }}" style="margin-left:1rem;">Cancel</a>
  </form>
{% endblock %}
</div>
""")

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
                align-items:center;
                margin:.15rem 0;
                padding:.15rem .6rem;
                border-radius:1rem;
                white-space:nowrap;
                font-size:.8em;
                {% if t.active %}
                    background:#F8B500; color:#000;
                {% else %}
                    background:#444; color:#F8B500;
                {% endif %}">
        {{ t.name }}
        <small style="color:#888;">({{ t.cnt }})</small>
    </a>
{% else %}
    <span>No tags yet.</span>
{% endfor %}
</div>

<!-- —— Entry list (only if sth. is selected) ————————— -->
{% if entries is not none %}
    <hr>
    {% for e in entries %}
        <article style="padding-bottom:1.5rem;
                        {% if not loop.last %}border-bottom:1px solid #444;{% endif %}">
            {% if e['title'] %}
                <h3 style="margin:.25rem 0 .5rem 0;">{{ e['title'] }}</h3>
            {% endif %}
            <p>{{ e['body']|md }}</p>
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
                    {{ e['kind'] }}
                </span>
                <a href="{{ url_for('entry_detail', slug=kind_to_slug(e['kind']), ts=e['slug']) }}"
                    style="text-decoration:none; color:inherit;vertical-align:middle;">
                    {{ e['created_at']|ts }}
                </a>&nbsp;
                {% if session.get('logged_in') %}
                    <a href="{{ url_for('edit_entry', entry_id=e['id']) }}" style="vertical-align:middle;">Edit</a>&nbsp;&nbsp;
                    <a href="{{ url_for('delete_entry', entry_id=e['id']) }}" style="vertical-align:middle;">Delete</a>
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

TEMPL_PAGE = wrap("""
{% block body %}
<hr>
<article>
  <p>{{ e['body']|md }}</p>
  {% if session.get('logged_in') %}
      <small>
          <a href="{{ url_for('edit_entry', entry_id=e['id']) }}">Edit</a> |
          <a href="{{ url_for('delete_entry', entry_id=e['id']) }}">Delete</a>
      </small>
  {% endif %}
</article>
{% endblock %}
""")

TEMPL_SEARCH = wrap("""
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
                    {% if sort==val %}background:#F8B500;color:#000;
                    {% else %}background:#333;color:#eee;{% endif %}">
            {{ label }}
            </a>
            {% endfor %}
        </span>

        {# ─── search box ────────────────────────────────────────────── #}
        <form action="{{ url_for('search') }}" method="get"
            style="margin:0;
                    display:inline-flex;   /* <── collapses to input’s height */
                    align-items:center;">
            <input type="search" name="q" placeholder="Search"
                value="{{ request.args.get('q','') }}"
                style="font-size:.8em;
                        padding:.35em .6em;
                        border:1px solid #555;
                        border-radius:4px;
                        margin:0;">  
        </form>
    </div>

    {% if removed %}
        <p style="color:#F8B500; font-size:.8em;">
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
            <p>{{ e['body']|md }}</p>
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
                    {{ e['kind'] }}
                </span>
                <a href="{{ url_for('entry_detail', slug=kind_to_slug(e['kind']), ts=e['slug']) }}"
                    style="text-decoration:none; color:inherit;vertical-align:middle;">
                    {{ e['created_at']|ts }}
                </a>&nbsp;
                {% if session.get('logged_in') %}
                    <a href="{{ url_for('edit_entry', entry_id=e['id']) }}" style="vertical-align:middle;">Edit</a>&nbsp;&nbsp;
                    <a href="{{ url_for('delete_entry', entry_id=e['id']) }}" style="vertical-align:middle;">Delete</a>
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
            slug=kind_to_slug(e["kind"]),
            ts=e["slug"],
            _external=True,            # absolute URL
        )

        body_html = md.reset().convert(e["body"] or "")

        items.append(
            f"""
        <item>
          <title>{escape(e['title'] or (e['body'][:60] + '…'))}</title>
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
    if kind not in ('say', 'post', 'pin'):
        abort(404)
    db   = get_db()
    rows = db.execute("SELECT * FROM entry WHERE kind=? ORDER BY created_at DESC LIMIT 50",
                      (kind,)).fetchall()
    xml  = _rss(rows,
                title = f"{kind.capitalize()}s – {get_setting('site_name','po.etr.ist')}",
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
# Search
###############################################################################

_OP_CHARS = r'-+:"*()@%<>=#'

def _sanitize(q: str) -> tuple[str, set[str]]:
    # if we have an odd number of quotes → replace them, too
    has_unmatched_quote = q.count('"') % 2 == 1

    op_chars = _OP_CHARS + ('"' if has_unmatched_quote else '')
    escape_re = re.compile(f'([{re.escape(op_chars)}])')

    removed: set[str] = set()
    def repl(m):
        removed.add(m.group(1))
        return ' '

    return escape_re.sub(repl, q), removed

def _needs_quotes(token: str) -> bool:
    """
    Return True if *token* contains any char that sqlite's unicode61
    tokenizer would drop (punctuation, symbols, etc.).
    """
    return TOKEN_RE.fullmatch(token) is None

def _expand_fuzzy(q: str) -> str:
    """
    • unquoted plain words  -> prefix search  (word*)
    • words with punctuation-> exact match   ("word%")
    • words in "quotes"     -> left untouched
    • Boolean ops AND/OR/NOT are preserved (case-insensitive)
    """
    parts = re.findall(r'"[^"]*"|\S+', q)
    out   = []

    for p in parts:
        if p.startswith('"') and p.endswith('"'):        # already quoted
            out.append(p)

        elif p.upper() in {"AND", "OR", "NOT"}:          # boolean op
            out.append(p.upper())

        elif _needs_quotes(p):                           # has % or other symbols
            out.append(f'"{p}"')                         # quote, no *

        else:                                            # simple word → prefix
            out.append(p + '*')

    return ' '.join(out)

def _has_quotes(q: str) -> bool:
    return '"' in q

def search_entries(query: str, *, db,
                   page: int        = 1,
                   per_page: int    = PAGE_DEFAULT,
                   sort: str        = "rel"):             # rel | new | old
    """Return (rows_on_page, total_hits, removed_chars)."""
    if not query:
        return [], 0, set()

    if _has_quotes(query):              # user wants an exact phrase
        clean_q, removed = query, set() # keep punctuation intact
    else:
        clean_q, removed = _sanitize(query)
        clean_q = clean_q.strip()
        if not clean_q:
            return [], 0, removed

    if '"' in clean_q:                   # user typed quotes → exact phrase
        tbl   = "entry_fts"
        match = clean_q
    else:
        if len(clean_q) >= 3 and '*' not in clean_q:
            tbl   = "entry_fts3"         # fast trigram if ≥3 chars, no *
            match = clean_q
        else:
            tbl   = "entry_fts"
            match = _expand_fuzzy(clean_q)   # add '*' for short/fuzzy search
            if match == '*':                 # ← optional extra guard
                return [], 0, removed
            
    order_sql = {
        "new": "ORDER BY e.created_at DESC",
        "old": "ORDER BY e.created_at ASC",
        "rel": "ORDER BY rank"
    }.get(sort, "ORDER BY rank")

    BASE_SQL = f"""
        SELECT e.*, bm25({tbl}) AS rank
          FROM {tbl}
          JOIN entry e ON e.id = {tbl}.rowid
         WHERE {tbl} MATCH ?
    """

    total = db.execute(f"SELECT COUNT(*) FROM ({BASE_SQL})", (match,)).fetchone()[0]
    rows  = db.execute(
                f"{BASE_SQL} {order_sql} LIMIT ? OFFSET ?",
                (match, per_page, (page-1)*per_page)
            ).fetchall()

    return rows, total, removed


@app.route('/search')
def search():
    q     = request.args.get('q',   '').strip()
    sort  = request.args.get('sort','rel')
    page  = max(int(request.args.get('page',1)), 1)
    per   = page_size()

    rows, total, removed = search_entries(q,
                db=get_db(),
                page=page,
                per_page=per,
                sort=sort)

    pages = list(range(1, (total + per - 1)//per + 1))

    return render_template_string(
        TEMPL_SEARCH,
        rows     = rows,
        query    = q,
        sort     = sort,
        page     = page,
        pages    = pages,
        removed  = ''.join(sorted(removed)),   # e.g. '@%-"'
        title    = get_setting('site_name', 'po.etr.ist'),
        kind     = 'search',
        username = current_username(),
    )

###############################################################################
# Error pages
###############################################################################

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
     <a href="{{ url_for('index') }}" style="color:#F8B500;">Back to the front page</a>
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
        style="color:#F8B500;">report the bug</a>.</p>
{% endblock %}
""")


###############################################################################
if __name__ == '__main__':     # Allow `python blog.py` to run the server, too
    import sys
    if len(sys.argv) > 1 and sys.argv[1] == 'init':
        # mirror `flask init` to make it easy without FLASK_APP
        with app.app_context():
            cli_init()
    else:
        app.run(debug=True)
