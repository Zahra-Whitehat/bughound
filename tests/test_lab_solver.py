"""Tests for the 0.7.1 lab-objective solver (bughound.solving).

Covers the three fixes that let the agent COMPLETE an exploit instead of
stopping at detection:

1. ``union_payloads`` ordering -- the unquoted variant used to be tried
   first and, on string contexts, stayed *inside* the SQL string literal
   (no error, HTTP 200 for every column count), so shape discovery locked
   onto bogus candidates and UNION extraction silently bailed.
2. ``_marker_match`` -- pages that reflect the raw payload (search-term
   echo) made non-greedy marker regexes capture SQL syntax
   ("'||version()||'") instead of the evaluated UNION result.
3. ``_cred_pairs_from_columns`` fuzzy pairing -- labs randomize credential
   column names (username_kd9fj2 / password_m4x0qa); exact-name-only
   pairing found nothing and row extraction returned zero rows.

Plus the solver itself: ``run_solve_phase`` drives the full chain (extract
admin password -> log in) against a mock Academy lab until the platform's
own status banner flips to ``is-solved``.
"""

from __future__ import annotations

import socket
import sqlite3
import threading
import time
from urllib.parse import urlparse

import pytest
import uvicorn
from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse, RedirectResponse

from bughound.exploits.sqli import (
    ROWS_RE,
    _cred_pairs_from_columns,
    _marker_match,
    union_payloads,
)
from bughound.http_client import HttpClient
from bughound.models import Category, Finding, ScanConfig, ScanResult, Severity, Target
from bughound.modules.base import RequestTarget, ScanContext
from bughound.solving import (
    check_lab_status,
    detect_lab_html,
    run_solve_phase,
)

# ---------------------------------------------------------------------------
# Pure-function regressions
# ---------------------------------------------------------------------------


def test_union_payloads_try_quoted_variants_first():
    payloads = union_payloads("Acc", "NULL,NULL")
    assert payloads[0] == "Acc' UNION SELECT NULL,NULL-- -"
    assert payloads[1] == "Acc') UNION SELECT NULL,NULL-- -"
    assert payloads[-1] == "Acc UNION SELECT NULL,NULL-- -"


def test_marker_match_skips_reflected_expression():
    # A page reflecting the raw payload: the FIRST marker span is the
    # expression itself, the second is the evaluated result.
    text = (
        "Refine: <a>' UNION SELECT 'bhrows='||string_agg(u||':'||p, ';')||'~bhEND~'--</a>"
        "<div>bhrows=administrator:s3cret;wiener:hunter2~bhEND~</div>"
    )
    m = _marker_match(ROWS_RE, text)
    assert m is not None
    assert m.group(1) == "administrator:s3cret;wiener:hunter2"


def test_marker_match_falls_back_to_last_when_all_polluted():
    text = "bhrows='||string_agg(x)||'~bhEND~"
    m = _marker_match(ROWS_RE, text)
    assert m is not None  # never lose data silently


def test_cred_pairs_exact_names():
    assert _cred_pairs_from_columns(["username", "password", "id"]) == [("username", "password")]


def test_cred_pairs_fuzzy_randomized_names():
    pairs = _cred_pairs_from_columns(["username_kd9fj2", "password_m4x0qa", "email"])
    assert ("username_kd9fj2", "password_m4x0qa") in pairs
    # username-ish columns before email
    assert pairs[0][0] == "username_kd9fj2"


# ---------------------------------------------------------------------------
# Lab markup detection
# ---------------------------------------------------------------------------

LAB_HTML_UNSOLVED = """
<html><head><title>SQL injection attack, listing the database contents</title></head>
<body><div id="academyLabHeader"><section class='academyLabBanner'><div class=container>
<div class=title-container>
    <h2>SQL injection attack, listing the database contents</h2>
</div>
<div class='widgetcontainer-lab-status is-notsolved'>
    <span>LAB</span>
    <p>Not solved</p>
</div>
</div></section></div></body></html>
"""

LAB_HTML_SOLVED = LAB_HTML_UNSOLVED.replace("is-notsolved", "is-solved").replace(
    "<p>Not solved</p>", "<p>Solved</p>"
)


def test_detect_lab_html_unsolved():
    lab = detect_lab_html(LAB_HTML_UNSOLVED)
    assert lab is not None
    assert lab["title"] == "SQL injection attack, listing the database contents"
    assert lab["solved"] is False


def test_detect_lab_html_solved():
    lab = detect_lab_html(LAB_HTML_SOLVED)
    assert lab is not None
    assert lab["solved"] is True


def test_detect_lab_html_no_lab():
    assert detect_lab_html("<html><body>ordinary site</body></html>") is None


def test_is_academy_url_matches_host_with_trailing_slash_or_path():
    from bughound.solving import is_academy_url

    assert is_academy_url("https://0a3b0085.web-security-academy.net/")
    assert is_academy_url("https://0a3b0085.web-security-academy.net/filter?category=x")
    assert is_academy_url("https://0a3b0085.web-security-academy.net")
    assert not is_academy_url("https://example.net/")
    assert not is_academy_url("https://web-security-academy.net.evil.io/")


# ---------------------------------------------------------------------------
# Mock Academy lab: real SQLi, real login, real status flip
# ---------------------------------------------------------------------------

lab_app = FastAPI()
_solved = {"flag": False}
_DB_FILE = "/tmp/bh_lab_test.db"


def _db() -> sqlite3.Connection:
    return sqlite3.connect(_DB_FILE)


def _init_db() -> None:
    conn = sqlite3.connect(_DB_FILE)
    conn.execute("DROP TABLE IF EXISTS products")
    conn.execute("DROP TABLE IF EXISTS users_tz8qva")
    conn.execute("CREATE TABLE products (name TEXT, category TEXT, price TEXT)")
    conn.executemany(
        "INSERT INTO products VALUES (?,?,?)",
        [("Leather Gloves", "Accessories", "$18"), ("Sunglasses", "Accessories", "$42")],
    )
    # Randomized credential table/column names, like the Academy does.
    conn.execute(
        "CREATE TABLE users_tz8qva (username_kd9fj2 TEXT, password_m4x0qa TEXT, email TEXT)"
    )
    conn.executemany(
        "INSERT INTO users_tz8qva VALUES (?,?,?)",
        [
            ("administrator", "h4ck3dth3lab", "admin@lab.test"),
            ("wiener", "peter123", "wiener@lab.test"),
        ],
    )
    conn.commit()
    conn.close()


_init_db()


def _lab_page(solved: bool) -> str:
    status = "is-solved" if solved else "is-notsolved"
    text = "Solved" if solved else "Not solved"
    return f"""
<html><head><title>SQL injection attack, listing the database contents on non-Oracle databases</title></head>
<body><div id="academyLabHeader"><section class='academyLabBanner'><div class=container>
<div class=title-container>
    <h2>SQL injection attack, listing the database contents on non-Oracle databases</h2>
</div>
<div class='widgetcontainer-lab-status {status}'>
    <span>LAB</span>
    <p>{text}</p>
</div>
</div></section></div></body></html>
"""


@lab_app.get("/", response_class=HTMLResponse)
def lab_home():
    return _lab_page(_solved["flag"])


@lab_app.get("/filter", response_class=HTMLResponse)
def lab_filter(category: str = ""):
    conn = _db()
    # Vulnerable: string-concatenated query, columns (name, category).
    sql = f"SELECT name, category FROM products WHERE category = '{category}'"
    try:
        rows = conn.execute(sql).fetchall()
    except sqlite3.Error:
        conn.close()
        raise
    conn.close()
    # The page reflects the raw search term (like the Academy's
    # "refine your search" link) -- this is what poisons naive
    # marker regexes.
    parts = [f"<a class=filter href='/filter?category={category}'>{category}</a>"]
    parts += [f"<div>{n} -- {c}</div>" for n, c in rows]
    return HTMLResponse("<html><body>" + "".join(parts) + "</body></html>")


@lab_app.get("/login", response_class=HTMLResponse)
def lab_login_form():
    return (
        "<html><body><form method=POST action=/login>"
        "<input name=csrf value=token123><input name=username><input name=password>"
        "<button type=submit>Log in</button></form></body></html>"
    )


@lab_app.post("/login")
async def lab_login(request: Request):
    form = await request.form()
    user = str(form.get("username", ""))
    pwd = str(form.get("password", ""))
    conn = _db()
    try:
        row = conn.execute(
            "SELECT password_m4x0qa FROM users_tz8qva WHERE username_kd9fj2 = ?",
            (user,),
        ).fetchone()
    finally:
        conn.close()
    if row and row[0] == pwd:
        if user == "administrator":
            _solved["flag"] = True
        resp = RedirectResponse("/", status_code=303)
        resp.set_cookie("session", f"owned-by-{user}")
        return resp
    return HTMLResponse("<html><body>Invalid username or password.</body></html>", status_code=401)


def _free_port() -> int:
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


@pytest.fixture(scope="module")
def lab_server():
    _solved["flag"] = False
    port = _free_port()
    config = uvicorn.Config(lab_app, host="127.0.0.1", port=port, log_level="warning")
    srv = uvicorn.Server(config)
    thread = threading.Thread(target=srv.run, daemon=True)
    thread.start()
    for _ in range(50):
        if srv.started:
            break
        time.sleep(0.1)
    yield f"http://127.0.0.1:{port}/"
    srv.should_exit = True
    thread.join(timeout=5)


def _make_ctx(server: str, seed: str, aggressive: bool = True):
    client = HttpClient(timeout=10)
    port = urlparse(server).port or 80
    config = ScanConfig(
        target_url=server, aggressive=aggressive, exploit=aggressive, use_external_tools=False
    )
    target = Target(url=server, scheme="http", host="127.0.0.1", port=port, authorized=True)
    rt_filter = RequestTarget(
        url=server + "filter", method="GET", params={"category": "Accessories"}, source="direct"
    )
    rt_login = RequestTarget(
        url=server + "login",
        method="POST",
        params={"username": "", "password": "", "csrf": ""},
        source="form",
    )
    ctx = ScanContext(
        client=client,
        config=config,
        target=target,
        base_url=server,
        urls=[server],
        request_targets=[rt_filter, rt_login],
        seed_html=seed,
    )
    return ctx, client


def _sqli_finding(server: str) -> Finding:
    return Finding(
        category=Category.SQLI,
        title="Possible boolean-based SQL injection in 'category'",
        severity=Severity.CRITICAL,
        url=server + "filter",
        module="sqli",
        verified=True,
    )


@pytest.mark.asyncio
async def test_solve_phase_completes_lab(lab_server):
    """The full objective: detect open lab -> exploit -> platform says SOLVED."""
    ctx, client = _make_ctx(lab_server, LAB_HTML_UNSOLVED)
    result = ScanResult(
        target=Target(url=lab_server, scheme="http", host="127.0.0.1",
                      port=urlparse(lab_server).port or 80),
        config=ctx.config,
    )
    result.add(_sqli_finding(lab_server))

    await run_solve_phase(ctx, result, print)

    obj = result.objective
    assert obj.get("title"), "lab objective should be detected"
    assert obj.get("solved_after") is True, f"lab should be solved: {obj}"
    assert obj.get("solved_before") is False
    attempts = obj.get("attempts") or []
    assert attempts and attempts[-1]["lab_solved"] is True
    assert any(a["strategy"] == "sqli-extraction-login" for a in attempts)
    # The solver records an objective-completed finding.
    assert any("Lab objective completed" in f.title for f in result.findings)
    # ...and the platform's own banner really flipped.
    status = await check_lab_status(ctx)
    assert status and status["solved"] is True
    await client.aclose()


@pytest.mark.asyncio
async def test_solve_phase_noop_without_lab(lab_server):
    ctx, client = _make_ctx(lab_server, "<html><body>plain site</body></html>")
    result = ScanResult(
        target=Target(url=lab_server, scheme="http", host="127.0.0.1", port=80),
        config=ctx.config,
    )
    await run_solve_phase(ctx, result, print)
    assert result.objective == {}
    await client.aclose()


@pytest.mark.asyncio
async def test_solve_phase_safe_mode_does_not_exploit(lab_server):
    ctx, client = _make_ctx(lab_server, LAB_HTML_UNSOLVED, aggressive=False)
    result = ScanResult(
        target=Target(url=lab_server, scheme="http", host="127.0.0.1",
                      port=urlparse(lab_server).port or 80),
        config=ctx.config,
    )
    result.add(_sqli_finding(lab_server))
    await run_solve_phase(ctx, result, print)
    assert result.objective.get("solved_after") is not True
    assert any("skipped" in (a.get("strategy") or "") for a in result.objective.get("attempts", []))
    # finding untouched by the solver
    assert result.findings[0].exploit_status == "not_attempted"
    await client.aclose()


@pytest.mark.asyncio
async def test_solve_phase_reports_already_solved(lab_server):
    _solved["flag"] = True
    ctx, client = _make_ctx(lab_server, LAB_HTML_SOLVED)
    result = ScanResult(
        target=Target(url=lab_server, scheme="http", host="127.0.0.1",
                      port=urlparse(lab_server).port or 80),
        config=ctx.config,
    )
    await run_solve_phase(ctx, result, print)
    assert result.objective.get("solved_after") is True
    assert result.objective.get("attempts") == []
    assert any("Lab objective completed" in f.title for f in result.findings)
    await client.aclose()
