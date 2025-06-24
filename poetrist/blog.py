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
PAGE_DEFAULT = 100 
TAG_RE = re.compile(r'(?<!\w)#([\w\-]+)')
HASH_LINK_RE = re.compile(r'(?<![A-Za-z0-9_])#([\w\-]+)')
RFC2822_FMT = "%a, %d %b %Y %H:%M:%S %z"

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
        href = url_for("tags_detail", tag_list=tag)
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

@app.route('/tags')
def tags():
    cur = get_db().execute(
        """SELECT t.name, COUNT(et.entry_id) AS cnt
           FROM tag t LEFT JOIN entry_tag et ON t.id = et.tag_id
           GROUP BY t.id ORDER BY LOWER(t.name)"""
    )

    rows = [dict(r) for r in cur]             # ← make them mutable dicts

    # ── scale count → font-size ------------------------------------------------
    counts = [r["cnt"] for r in rows]
    if counts:
        lo, hi = min(counts), max(counts)
        span   = max(1, hi - lo)
        for r in rows:
            weight = (r["cnt"] - lo) / span      # 0‥1
            size   = 0.75 + weight * 1.2          # 0.75 em – 1.95 em
            r["size"] = f"{size:.2f}em"
    else:
        for r in rows:
            r["size"] = "1em"

    return render_template_string(
        TEMPL_TAGS,
        tags  = rows,
        title = get_setting('site_name', 'po.etr.ist'),
        kind  = 'tags',
        username = current_username(),
    )

@app.route('/tags/<path:tag_list>')
def tags_detail(tag_list):
    tags = [t.lower() for t in re.split(r'[,+/]', tag_list) if t]  # foo+bar/baz
    if not tags:
        abort(404)

    q_marks   = ','.join('?' * len(tags))
    sql = f"""SELECT e.*
              FROM entry e
              JOIN entry_tag et ON et.entry_id = e.id
              JOIN tag t        ON t.id = et.tag_id
              WHERE t.name IN ({q_marks})
              GROUP BY e.id
              HAVING COUNT(DISTINCT t.name)=?      -- AND-filter
              ORDER BY e.created_at DESC"""
    rows = get_db().execute(sql, (*tags, len(tags))).fetchall()

    return render_template_string(TEMPL_TAG_LIST,
                                  entries=rows,
                                  tag='+'.join(tags),
                                  selected=tags, 
                                  title=get_setting("site_name","po.etr.ist"),
                                  kind='tags',
                                  username=current_username())

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

    cur = db.execute('SELECT * FROM entry ORDER BY created_at DESC')
    entries = cur.fetchall()

    # pagination
    page = max(int(request.args.get('page', 1)), 1)
    ps   = page_size()

    entries, total_pages = paginate("SELECT * FROM entry ORDER BY created_at DESC", (), page=page, per_page=ps, db=db)

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
    kind = slug_to_kind(slug)
    if kind not in ('say', 'post', 'pin'):
        abort(404)

    db = get_db()
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

    cur_username = db.execute('SELECT username FROM user LIMIT 1').fetchone()['username']
    return render_template_string(
        TEMPL_SETTINGS,
        title = get_setting('site_name', 'po.etr.ist'),
        site_name = get_setting('site_name', 'po.etr.ist'),
        username = cur_username
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

        # --- update live row ---
        db.execute("""UPDATE entry
                         SET title=?,
                             body=?,
                             link=?,
                             slug=?,
                             updated_at=?
                       WHERE id=?""",
                   (title, body, link, new_slug,
                    local_now().isoformat(timespec='seconds'),
                    entry_id))
        sync_tags(entry_id, extract_tags(body), db=db)
        db.commit()
        return redirect(url_for('index'))

    # GET → render form
    return render_template_string(TEMPL_EDIT,
                                  e=row,
                                  title='Edit')

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
                                  title='Delete',
                                  )

###############################################################################
# Embedde​d templates
###############################################################################

TEMPL_BASE = """
<!doctype html>
<html lang="en">
<title>{{title or 'po.etr.ist'}}</title>
<meta name="viewport" content="width=device-width, initial-scale=1, shrink-to-fit=no"> 
<meta charset="utf-8">
<meta name="description" content="po.etr.ist – a minimal blog">
<link rel="stylesheet" href="{{ url_for('sakura_dark') }}">
<link rel="icon" href="{{ url_for('favicon') }}">
<link rel="alternate" type="application/rss+xml"
      href="{{ url_for('global_rss') }}" title="{{ title }} – RSS">

<div class="container" style="max-width: 60rem; margin: 3rem auto;">
    <h1 style="margin-top:0"><a href="{{ url_for('index') }}">{{title or 'po.etr.ist'}}</a></h1>
    <nav style="margin-bottom:1rem;display:flex;">
        <div>
            <a href="{{ url_for('by_kind', slug=kind_to_slug('say')) }}"
                {% if kind|default('')=='say'  %}style="font-weight:bold;text-decoration:none;"{% endif %}>
                Says
            </a>&nbsp;&nbsp;
            <a href="{{ url_for('by_kind', slug=kind_to_slug('post')) }}"
                {% if kind|default('')=='post' %}style="font-weight:bold;text-decoration:none;"{% endif %}>
                Posts
            </a>&nbsp;&nbsp;
            <a href="{{ url_for('by_kind', slug=kind_to_slug('pin')) }}"
                {% if kind|default('')=='pin'  %}style="font-weight:bold;text-decoration:none;"{% endif %}>
                Pins
            </a>&nbsp;&nbsp;
            <a href="{{ url_for('tags') }}"
                {% if kind|default('')=='tags' %}style="font-weight:bold;text-decoration:none"{% endif %}>
                Tags
            </a>
        </div>
        <div style="margin-left:auto; white-space:nowrap;">
            {% if session.get('logged_in') %}
                <a href="{{ url_for('settings') }}">Settings</a>&nbsp;&nbsp;
                <a href="{{url_for('logout')}}">Logout</a>
            {% else %}
                <a href="{{url_for('login')}}">Login</a>
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

        {# --- auto-dismiss: reload current URL after 3 s ---------------------- #}
        <meta http-equiv="refresh"
            content="3;url={{ request.path }}">
    {% endif %}
    {% endwith %}

<!-- the closing div is in other templates -->
"""

TEMPL_INDEX = TEMPL_BASE + """
    {% block body %}
        {% if session.get('logged_in') %}
        <form method=post>
        <textarea name=body rows=3 style="width:100%;margin-bottom:0rem;" placeholder="What's on your mind?"></textarea>
        <button>Add Say</button>
        </form>
        {% endif %}
        <hr>

        {% for e in entries %}
            <article style="padding-bottom:1rem; ;border-bottom:1px solid #444;"">
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
                    <a href="{{ url_for('entry_detail', slug=kind_to_slug(e['kind']), ts=e['slug']) }}"
                        style="text-decoration:none; color:inherit;">
                        {{ e['kind']|capitalize }} — {{ e['created_at']|ts }}
                    </a>
                    {% if session.get('logged_in') %}
                        | <a href="{{ url_for('edit_entry', entry_id=e['id']) }}">Edit</a>
                        | <a href="{{ url_for('delete_entry', entry_id=e['id']) }}">Delete</a>
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
                    <strong>{{ p }}</strong>
                {% else %}
                    <a href="{{ request.path }}?page={{ p }}">{{ p }}</a>
                {% endif %}
                {% if not loop.last %}&nbsp;{% endif %}
            {% endfor %}
        </nav>
        {% endif %}

    {% endblock body %}
</div>
"""

TEMPL_LOGIN = TEMPL_BASE + """
{% block body %}
<form method=post>
  <label>Token:<br>
    <input  name="token"
            type="password"          
            autocomplete="current-password"
            style="width:100%">
  </label>
  <br>
  <button>Log&nbsp;in</button>
</form>
{% endblock %}
"""


TEMPL_LIST = TEMPL_BASE + """
    {% block body %}
        {% if session.get('logged_in') %}
            <form method="post">
                {# Title field for Posts & Pins #}
                {% if kind in ('post', 'pin') %}
                    <input name="title" style="width:100%" placeholder="Title"><br>
                {% endif %}
                {# Link field only for Pins #}
                {% if kind == 'pin' %}
                    <input name="link" style="width:100%" placeholder="Link">
                {% endif %}
                <textarea name="body" rows="3" style="width:100%;margin-bottom:0rem;" placeholder="what's on your mind?"></textarea>
                <button>Add&nbsp;{{ kind.capitalize() }}</button>
            </form>
        {% endif %}
        <hr>
        {% for e in rows %}
        <article style="padding-bottom:1rem; border-bottom:1px solid #444;">
            {% if e['kind'] == 'pin' %}
                <h3>
                    <a href="{{ e['link'] }}" target="_blank" rel="noopener">
                        {{ e['title'] }}
                    </a>
                    {{ external_icon() }} 
                </h3>            
            {% elif e['title'] %}
                <h3>{{ e['title'] }}</h3>
            {% endif %}
            <p>{{ e['body']|md }}</p>
            {% if e['link'] and e['kind'] != 'pin' %}
                <p>🔗 <a href="{{ e['link'] }}" target="_blank" rel="noopener">{{ e['link'] }}</a></p>
            {% endif %}
            <small style="color:#aaa;">
                <a href="{{ url_for('entry_detail', slug=kind_to_slug(e['kind']), ts=e['slug']) }}"
                   style="text-decoration:none; color:inherit;">
                   {{ e['kind']|capitalize }} — {{ e['created_at']|ts }}
                </a>
                {% if session.get('logged_in') %}
                    | <a href="{{ url_for('edit_entry', entry_id=e['id']) }}">Edit</a>
                    | <a href="{{ url_for('delete_entry', entry_id=e['id']) }}">Delete</a>
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
                        <strong>{{ p }}</strong>
                    {% else %}
                        <a href="{{ request.path }}?page={{ p }}">{{ p }}</a>
                    {% endif %}
                    {# add thin spacing between numbers #}
                    {% if not loop.last %}&nbsp;{% endif %}
                {% endfor %}
            </nav>
        {% endif %}


    {% endblock %}
</div>
"""

TEMPL_SETTINGS = TEMPL_BASE + """
    {% block body %}
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
    {% endblock %}
</div>
"""

TEMPL_DETAIL = TEMPL_BASE + """
{% block body %}
<hr>
<article>

  {% if e['kind']=='pin' %}
      <h3 style="margin-top:0">
        <a href="{{ e['link'] }}" target="_blank" rel="noopener"
           style="word-break:break-all; overflow-wrap:anywhere;">
           {{ e['title'] }} 
        </a>
        {{ external_icon() }}
      </h3>
      <small>({{ e['link']|url }})</small> 

  {% elif e['title'] %}
      <h3>{{ e['title'] }}</h3>
  {% endif %}

  <p>{{ e['body']|md }}</p>
  
  <small style="color:#aaa;">
      <a href="{{ url_for('by_kind', slug=kind_to_slug(e['kind'])) }}"
         style="text-decoration:none; color:inherit;">
         {{ e['created_at']|ts }}
      </a>
      {% if e['updated_at'] %}
        <span title="Updated {{ e['updated_at']|ts }}">
            (updated)
        </span>
      {% endif %}
      by {{ username }}
      {% if session.get('logged_in') %}
          | <a href="{{ url_for('edit_entry', entry_id=e['id']) }}">Edit</a>
          | <a href="{{ url_for('delete_entry', entry_id=e['id']) }}">Delete</a>
      {% endif %}
  </small>
</article>
{% endblock %}
</div>
"""

TEMPL_EDIT = TEMPL_BASE + """
{% block body %}
<form method="post">
    {% if e['kind'] in ('post','pin') %}
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
    <button>Save</button>
    <small style="color:#aaa;"><a href="{{ url_for('index') }}">Cancel</a></small>
</form>

{% if e['updated_at'] %}
  <p><em>First published {{ e['created_at']|ts }}</em></p>
  <p>Last edited {{ e['updated_at']|ts }}</p>
{% else %}
  <p><em>Published {{ e['created_at']|ts }}</em></p>
{% endif %}
{% endblock %}
</div>
"""

TEMPL_DELETE = TEMPL_BASE + """
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
"""

TEMPL_TAGS = TEMPL_BASE + """
    {% block body %}
    <hr>
    <!-- flex row that wraps automatically -->
    <div>
        {% for t in tags %}
            <a href="{{ url_for('tags_detail', tag_list=t['name']) }}"
                style="text-decoration:none;
                        white-space:nowrap;
                        color:#F8B500;
                        font-size:{{ t['size'] }};">
                {{ t['name'] }}
                
            </a><small>({{ t['cnt'] }})</small> &nbsp
        {% else %}
            <span>No tags yet.</span>
        {% endfor %}
    </div>
    {% endblock %}
</div>
"""

TEMPL_TAG_LIST = TEMPL_BASE + """
{% block body %}
    <hr>
    <h3>#{{ tag }}</h3>
    {% for e in entries %}
        <article style="border-bottom:1px solid #444; padding-bottom:1rem;">
        {% if e['title'] %}
            <h4 style="margin:.25rem 0 .5rem 0;">{{ e['title'] }}</h4>
        {% endif %}

        <p>{{ e['body']|md }}</p>

        <small style="color:#aaa;">
            <a href="{{ url_for('entry_detail', slug=kind_to_slug(e['kind']), ts=e['slug']) }}"
            style="text-decoration:none; color:inherit;">
            {{ e['kind']|capitalize }} — {{ e['created_at']|ts }}
            </a>
            {% if session.get('logged_in') %}
            | <a href="{{ url_for('edit_entry', entry_id=e['id']) }}">Edit</a>
            | <a href="{{ url_for('delete_entry', entry_id=e['id']) }}">Delete</a>
            {% endif %}
        </small>
        </article>
    {% else %}
        <p>No entries for this tag.</p>
    {% endfor %}
    {% endblock %}
</div>
"""

###############################################################################
# RSS feed
###############################################################################
def _rfc2822(dt_str: str) -> str:
    """ISO-8601 → RFC 2822 (Tue, 24 Jun 2025 09:22:20 +0200)."""
    try:
        return datetime.fromisoformat(dt_str).astimezone().strftime(RFC2822_FMT)
    except Exception:
        return dt_str                           # fall back unchanged

def _rss(entries, *, title, feed_url, site_url):
    """
    Build a minimal RSS 2.0 document in **one** string.
    `entries` must be an iterable of rows from the `entry` table.
    """
    items = []
    for e in entries:
        link = url_for('entry_detail',
                       slug=kind_to_slug(e['kind']),
                       ts=e['slug'],
                       _external=True)          # absolute URL
        # Markdown → HTML (already safe; we escape around CDATA)
        body_html = md.reset().convert(e['body'] or "")
        items.append(f"""
        <item>
          <title>{escape(e['title'] or (e['body'][:60] + '…'))}</title>
          <link>{link}</link>
          <guid>{link}</guid>
          <pubDate>{_rfc2822(e['created_at'])}</pubDate>
          <description><![CDATA[{body_html}]]></description>
        </item>""")

    return f"""<?xml version="1.0" encoding="utf-8"?>
<rss version="2.0">
  <channel>
    <title>{escape(title)}</title>
    <link>{site_url}</link>
    <description>{escape(title)} – RSS</description>
    <generator>po.etr.ist</generator>
    <docs>https://validator.w3.org/feed/docs/rss2.html</docs>
    <lastBuildDate>{format_datetime(datetime.now().astimezone())}</lastBuildDate>
    <atom:link xmlns:atom href="{feed_url}" rel="self" type="application/rss+xml"/>
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
if __name__ == '__main__':     # Allow `python blog.py` to run the server, too
    import sys
    if len(sys.argv) > 1 and sys.argv[1] == 'init':
        # mirror `flask init` to make it easy without FLASK_APP
        with app.app_context():
            cli_init()
    else:
        app.run(debug=True)
