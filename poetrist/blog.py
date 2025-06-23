#!/usr/bin/env python3
"""
A minimal micro-, link- and long-form blog in one file.

  $ pip install flask werkzeug        # the only external deps
  $ python blog.py init               # one-time setup, creates DB + admin
  $ FLASK_APP=blog.py flask run
"""

import getpass
import os
import secrets
import sqlite3
from datetime import datetime, timezone

###############################################################################
# Configuration
###############################################################################
from pathlib import Path

import click
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
from werkzeug.security import check_password_hash, generate_password_hash

_secret_file = Path('.secret_key')

if _secret_file.exists():
    SECRET_KEY = _secret_file.read_text().strip()
else:
    SECRET_KEY = secrets.token_hex(32)
    _secret_file.write_text(SECRET_KEY)


DATABASE = os.path.join(os.path.dirname(__file__), 'blog.sqlite3')
# SECRET_KEY = secrets.token_hex(16)          # session signing
# SECRET_KEY = os.getenv("SECRET_KEY") or secrets.token_hex(32)
TOKEN_BYTES = 48                            # length of login token

app = Flask(__name__)
app.config.from_mapping(SECRET_KEY=SECRET_KEY, DATABASE=DATABASE)

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
                published_at TEXT NOT NULL,
                author TEXT,
                kind TEXT NOT NULL
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

###############################################################################
# CLI – create admin + token
###############################################################################
@app.cli.command('init')
def cli_init():
    """Initialise DB and create the only account."""
    init_db()
    db = get_db()

    username = input("Admin username: ").strip()
    password = getpass.getpass("Admin password (will not echo): ").strip()
    token    = secrets.token_urlsafe(TOKEN_BYTES)

    db.execute(
        'INSERT INTO user (username, pwd_hash, token_hash) VALUES (?,?,?)',
        (username,
         generate_password_hash(password),
         generate_password_hash(token))
    )
    db.commit()
    click.echo(f"\n✅  Admin created. Save this **one-time** login token:\n\n{token}\n")
    click.echo("Use it at /login?token=<token>  (or paste into the login form).")

###############################################################################
# Authentication
###############################################################################
def validate_token(token: str) -> bool:
    db = get_db()
    row = db.execute('SELECT token_hash FROM user LIMIT 1').fetchone()
    return row and check_password_hash(row['token_hash'], token)

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        token = request.form['token'].strip()
    else:
        token = request.args.get('token', '').strip()

    if token and validate_token(token):
        session.permanent = True 
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

###############################################################################
# Views
###############################################################################
@app.route('/', methods=['GET', 'POST'])
def index():
    db = get_db()

    # Quick-add “Say” for logged-in admin
    if request.method == 'POST':
        if not session.get('logged_in'):
            abort(403)
        body = request.form['body'].strip()
        if body:
            kind  = classify('', '')
            now   = datetime.now(timezone.utc).isoformat(timespec='seconds')
            db.execute("""INSERT INTO entry (body, published_at, author, kind)
                          VALUES (?,?,?,?)""",
                       (body, now, 'admin', kind))
            db.commit()
            return redirect(url_for('index'))

    cur = db.execute('SELECT * FROM entry ORDER BY published_at DESC')
    entries = cur.fetchall()
    title = get_setting('site_name', 'po.etr.ist')
    return render_template_string(TEMPL_INDEX, entries=entries, title=title)


@app.route('/<kind>', methods=['GET', 'POST'])
def by_kind(kind):
    if kind not in ('say', 'post', 'pin'):
        abort(404)
    db = get_db()
    # ---------- create new entry when the admin submits the inline form ----
    if request.method == 'POST':
        if not session.get('logged_in'):
            abort(403)

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
                         (title, body, link, published_at, author, kind)
                      VALUES (?,?,?,?,?,?)""",
                   (title or None, body, link or None, now, 'admin', kind))
        db.commit()
        
        return redirect(url_for('by_kind', kind=kind))

    rows = db.execute('SELECT * FROM entry WHERE kind=? ORDER BY published_at DESC', (kind,)).fetchall()
    title = get_setting('site_name', 'po.etr.ist')

    return render_template_string(TEMPL_LIST, rows=rows, heading=kind.capitalize()+"s", kind=kind, title=title)

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

@app.route('/settings', methods=['GET', 'POST'])
def settings():
    if not session.get('logged_in'):
        abort(403)

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
        title='Settings',
        site_name=get_setting('site_name', 'po.etr.ist'),
        username=cur_username
    )


###############################################################################
# Embedde​d templates – drop into separate files later if you like
###############################################################################
TEMPL_BASE = """
<!doctype html><title>{{title or 'po.etr.ist'}}</title>
<link rel=stylesheet href="https://unpkg.com/sakura.css/css/sakura-dark.css">
<div class="container" style="max-width: 60rem; margin: 3rem auto;">
    <h1 style="margin-top:0">{{title or 'po.etr.ist'}}</h1>
    <nav>
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
    <hr>
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
    <textarea name=body rows=3 style="width:100%;" placeholder="What's on your mind?"></textarea>
    <button>Add Say</button>
    </form>
    <hr>
    {% endif %}
    {% for e in entries %}
    <article>
        {% if e['kind']=='pin' %}
        <h3><a href="{{e['link']}}" target=_blank rel=noopener>{{e['title']}}</a></h3>
        {% elif e['kind']=='post' and e['title'] %}
        <h3>{{e['title']}}</h3>
        {% endif %}
        <p>{{e['body']|safe}}</p>
        <small>{{e['kind']}} — {{e['published_at']}} by {{e['author']}}</small>
    </article><hr>
    {% else %}
    <p>No entries yet.</p>
    {% endfor %}
    {% endblock %}
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
            <textarea name="body" rows="3" style="width:100%;" placeholder="what's on your mind?"></textarea>
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
            <p>{{ e['body']|safe }}</p>
            {% if e['link'] and e['kind'] != 'pin' %}
            <p>🔗 <a href="{{ e['link'] }}" target="_blank" rel="noopener">{{ e['link'] }}</a></p>
            {% endif %}
            <small>{{ e['published_at'] }} by {{ e['author'] }}</small>
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


###############################################################################
if __name__ == '__main__':     # Allow `python blog.py` to run the server, too
    import sys
    if len(sys.argv) > 1 and sys.argv[1] == 'init':
        # mirror `flask init` to make it easy without FLASK_APP
        with app.app_context():
            cli_init()
    else:
        app.run(debug=True)
