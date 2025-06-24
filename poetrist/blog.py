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

import secrets
import sqlite3
from datetime import datetime, timezone
from pathlib import Path

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
TOKEN_BYTES = 48
SECRET_FILE = ROOT / ".secret_key"
SECRET_KEY  = SECRET_FILE.read_text().strip() if SECRET_FILE.exists() \
              else secrets.token_hex(32)
SECRET_FILE.write_text(SECRET_KEY)



################################################################################
# App + Markdown filter
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
    ],
    extension_configs={
        "pymdownx.highlight": {"guess_lang": True},
    },
)

@app.template_filter("md")
def md_filter(text: str | None) -> Markup:
    """Render Markdown; raw HTML is already escaped by pymdownx.escapeall."""
    return Markup(md.reset().convert(text or ""))


###############################################################################
# Database helpers
###############################################################################
def get_db():
    if 'db' not in g:
        g.db = sqlite3.connect(app.config['DATABASE'])
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
                kind TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS entry_version (
                id           INTEGER PRIMARY KEY AUTOINCREMENT,
                entry_id     INTEGER NOT NULL,
                title        TEXT,
                body         TEXT,
                link         TEXT,
                saved_at     TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS settings (
                key   TEXT PRIMARY KEY,
                value TEXT
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

###############################################################################
# CLI – create admin + token
###############################################################################
def _create_admin(db, *, username: str, password: str) -> str:
    """Insert admin user and return the one-time token."""
    token = secrets.token_urlsafe(TOKEN_BYTES)
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
    token = secrets.token_urlsafe(TOKEN_BYTES)
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
        # ── ✅  token matched → burn it right away ────────────────────────
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

###############################################################################
# Content helpers
###############################################################################
def classify(title, link):
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
            kind  = classify('', '')
            now   = datetime.now(timezone.utc).isoformat(timespec='seconds')
            db.execute("""INSERT INTO entry (body, created_at, kind)
                          VALUES (?,?,?)""",
                       (body, now, kind))
            db.commit()
            return redirect(url_for('index'))

    cur = db.execute('SELECT * FROM entry ORDER BY created_at DESC')
    entries = cur.fetchall()
    title = get_setting('site_name', 'po.etr.ist')
    return render_template_string(TEMPL_INDEX, entries=entries, title=title, username=current_username())


@app.route('/<kind>', methods=['GET', 'POST'])
def by_kind(kind):
    if kind not in ('say', 'post', 'pin'):
        abort(404)
    db = get_db()
    # ---------- create new entry when the admin submits the inline form ----
    if request.method == 'POST':
        login_required()

        title = request.form.get('title', '').strip()
        body  = request.form.get('body',  '').strip()
        link  = request.form.get('link',  '').strip()

        if not body:
            flash('Body is required.')
            return redirect(url_for('by_kind', kind=kind))

        real_kind = classify(title, link)
        if real_kind != kind:
            flash(f'This form can only add {kind}s.')
            return redirect(url_for('by_kind', kind=kind))

        now = datetime.now(timezone.utc).isoformat(timespec='seconds')
        db.execute("""INSERT INTO entry
                        (title, body, link, created_at, kind)
                     VALUES (?,?,?,?,?)""",
                   (title or None, body, link or None, now, kind))
        db.commit()
        
        return redirect(url_for('by_kind', kind=kind))

    rows = db.execute('SELECT * FROM entry WHERE kind=? ORDER BY created_at DESC', (kind,)).fetchall()

    return render_template_string(TEMPL_LIST, 
                                  rows=rows, 
                                  heading=kind.capitalize()+"s", 
                                  kind=kind, 
                                  title=get_setting('site_name', 'po.etr.ist'), username=current_username())

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
        
        flash('Settings saved.')
        return redirect(url_for('settings'))

    cur_username = db.execute('SELECT username FROM user LIMIT 1').fetchone()['username']
    return render_template_string(
        TEMPL_SETTINGS,
        title = get_setting('site_name', 'po.etr.ist'),
        site_name = get_setting('site_name', 'po.etr.ist'),
        username = cur_username
    )

###############################################################################
# Edit / Versioning
###############################################################################
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

        if not body:
            flash('Body is required.')
            return redirect(url_for('edit_entry', entry_id=entry_id))

        # --- store old version before overwriting ---
        db.execute("""INSERT INTO entry_version
                         (entry_id, title, body, link, saved_at)
                      VALUES (?,?,?,?,?)""",
                   (row['id'], row['title'], row['body'], row['link'],
                    datetime.now(timezone.utc).isoformat(timespec='seconds')))

        # --- update live row ---
        db.execute("""UPDATE entry
                         SET title=?,
                             body=?,
                             link=?,
                             updated_at=?
                       WHERE id=?""",
                   (title, body, link,
                    datetime.now(timezone.utc).isoformat(timespec='seconds'),
                    entry_id))
        db.commit()
        return redirect(url_for('index'))

    # GET → render form
    return render_template_string(TEMPL_EDIT,
                                  e=row,
                                  title='Edit')


###############################################################################
# Embedde​d templates
###############################################################################

TEMPL_BASE = """
<!doctype html><title>{{title or 'po.etr.ist'}}</title>
<link rel=stylesheet href="https://unpkg.com/sakura.css/css/sakura-dark.css">
<div class="container" style="max-width: 60rem; margin: 3rem auto;">
    <h1 style="margin-top:0">{{title or 'po.etr.ist'}}</h1>
    <nav style="margin-bottom:1rem;">
      <a href="{{url_for('index')}}">Home</a> |
      <a href="{{ url_for('by_kind', kind='say')  }}">Says</a> |
      <a href="{{ url_for('by_kind', kind='post') }}">Posts</a> |
      <a href="{{ url_for('by_kind', kind='pin')  }}">Pins</a> |
      {% if session.get('logged_in') %}
          <a href="{{ url_for('settings') }}">Settings</a> | 
          <a href="{{url_for('logout')}}">Logout</a>
      {% else %}
          <a href="{{url_for('login')}}">Login</a>
      {% endif %}
    </nav>
    {% with msgs = get_flashed_messages() %}
      {% if msgs %}
        <ul>{% for m in msgs %}<li>{{m}}</li>{% endfor %}</ul>
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
        <hr>
        {% endif %}
        {% for e in entries %}
            <article style="padding-bottom:1rem; ;border-bottom:1px solid #444;"">
                {% if e['kind']=='pin' %}
                <h3><a href="{{e['link']}}" target=_blank rel=noopener>{{e['title']}}</a></h3>
                {% elif e['kind']=='post' and e['title'] %}
                <h3>{{e['title']}}</h3>
                {% endif %}
                <p>{{e['body']|md}}</p>
                <small>{{e['kind']|capitalize}} — {{e['created_at']}} by {{ username }}
                {% if session.get('logged_in') %}
                    | <a href="{{ url_for('edit_entry', entry_id=e['id']) }}">Edit</a>
                {% endif %}
                </small>
            </article>
        {% else %}
            <p>No entries yet.</p>
        {% endfor %}
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
            <hr>
        {% endif %}

        {% for e in rows %}
        <article>
            {% if e['kind'] == 'pin' %}
            <h3><a href="{{ e['link'] }}" target="_blank" rel="noopener">{{ e['title'] }}</a></h3>
            {% elif e['title'] %}
            <h3>{{ e['title'] }}</h3>
            {% endif %}
            <p>{{ e['body']|md }}</p>
            {% if e['link'] and e['kind'] != 'pin' %}
            <p>🔗 <a href="{{ e['link'] }}" target="_blank" rel="noopener">{{ e['link'] }}</a></p>
            {% endif %}
            <small>{{ e['created_at'] }} by {{  username  }}
            {% if session.get('logged_in') %}
                | <a href="{{ url_for('edit_entry', entry_id=e['id']) }}">Edit</a>
            {% endif %}
            </small>
        </article><hr>
        {% else %}
        <p>No {{ heading.lower() }} yet.</p>
        {% endfor %}

    {% endblock %}
</div>
"""

TEMPL_SETTINGS = TEMPL_BASE + """
    {% block body %}
    <form method="post">
    <!-- Site name field -->
    <div style="position:relative;">
        <input id="site_name"
            name="site_name"
            value="{{ site_name }}"
            style="width:100%; padding-right:7rem;">
        <label for="site_name"
            style="position:absolute;
                    right:.5rem;
                    top:40%;
                    transform:translateY(-50%);
                    pointer-events:none;
                    font-size:.75em;
                    color:#888;">Site&nbsp;name</label>
    </div>

    <!-- Username field -->
    <div style="position:relative; margin-top:1rem;">
        <input id="username"
            name="username"
            value="{{ username }}"
            style="width:100%; padding-right:6rem;">
        <label for="username"
            style="position:absolute;
                    right:.5rem;
                    top:40%;
                    transform:translateY(-50%);
                    pointer-events:none;
                    font-size:.75em;
                    color:#888;">Username</label>
    </div>

    <button style="margin-top:1rem;">Save</button>
    </form>

    {% endblock %}
</div>
"""

TEMPL_EDIT = TEMPL_BASE + """
{% block body %}
<form method="post">
  {% if e['kind'] in ('post','pin') %}
    <input name="title" value="{{ e['title'] or '' }}" style="width:100%" placeholder="Title"><br>
  {% endif %}

  {% if e['kind'] == 'pin' %}
    <input name="link"  value="{{ e['link'] or '' }}"  style="width:100%" placeholder="Link"><br>
  {% endif %}

  <textarea name="body" rows="8" style="width:100%;">{{ e['body'] }}</textarea><br>
  <button>Save</button>
  <small><a href="{{ url_for('index') }}">Cancel</a></small>
</form>

{% if e['updated_at'] %}
  <p><em>First published {{ e['created_at'] }}</em></p>
  <p>Last edited {{ e['updated_at'] }}</p>
{% else %}
  <p><em>Published {{ e['created_at'] }}</em></p>
{% endif %}
{% endblock %}
</div>
"""

T = {
    "base":   TEMPL_BASE,
    "index":  TEMPL_INDEX,
    "login":  TEMPL_LOGIN,
    "list":   TEMPL_LIST,
    "edit":   TEMPL_EDIT,
    "settings": TEMPL_SETTINGS,
}


###############################################################################
if __name__ == '__main__':     # Allow `python blog.py` to run the server, too
    import sys
    if len(sys.argv) > 1 and sys.argv[1] == 'init':
        # mirror `flask init` to make it easy without FLASK_APP
        with app.app_context():
            cli_init()
    else:
        app.run(debug=True)
