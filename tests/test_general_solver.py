"""Mock Academy labs for the 0.9.0 GENERALIZED objective engine.

v0.7.1 solved exactly one objective shape (SQLi -> creds -> admin login).
v0.9.0 replaces that single ladder with a goal-driven strategy engine. These
mocks lock the generalization in: each one is a small Academy lookalike whose
objective is completed by a DIFFERENT technique -- admin panel discovery,
robots.txt disclosure, X-Original-URL bypass, 2FA skip, NoSQL operator
injection, stored XSS via comment, SSRF into an internal admin, path
traversal, OS command injection, JWT forgery and bounded credential
stuffing -- and each mock flips its own ``is-solved`` banner only when the
platform's intended objective is truly achieved.

If the solver ever regresses to lab-specific or SQLi-only behaviour, these
tests fail loudly -- the exact "worked for that lab, not for this one"
complaint that motivated 0.9.0.
"""

from __future__ import annotations

import base64
import json
import socket
import threading
import time
from contextlib import contextmanager
from urllib.parse import parse_qs, urlparse

import pytest
import uvicorn
from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse, RedirectResponse

from bughound.exploits.auth import COMMON_PASSWORDS
from bughound.http_client import HttpClient
from bughound.models import Category, Finding, ScanConfig, ScanResult, Severity, Target
from bughound.modules.base import RequestTarget, ScanContext
from bughound.solving import check_lab_status, run_solve_phase

# ---------------------------------------------------------------------------
# Shared harness
# ---------------------------------------------------------------------------


def academy_html(title: str, body: str, solved: bool) -> str:
    cls = "is-solved" if solved else "is-notsolved"
    status = "Solved" if solved else "Not solved"
    return (
        "<html><head><title>" + title + "</title></head><body>"
        "<div id=academyLabHeader><section class=academyLabBanner>"
        "<div class=title-container><h2>" + title + "</h2></div>"
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
    for _ in range(80):
        if srv.started:
            break
        time.sleep(0.05)
    try:
        yield f"http://127.0.0.1:{port}"
    finally:
        srv.should_exit = True
        thread.join(timeout=5)


def _finding(category: Category, title: str, url: str, severity: Severity = Severity.CRITICAL) -> Finding:
    return Finding(
        category=category,
        title=title,
        severity=severity,
        confidence="firm",
        url=url,
        description="mock finding",
        evidence="mock evidence",
        verified=True,
    )


def _make_ctx(server: str, seed: str, request_targets, findings, urls=None):
    client = HttpClient(timeout=10)
    config = ScanConfig(
        target_url=server, aggressive=True, exploit=True, use_external_tools=False
    )
    parsed = urlparse(server)
    target = Target(
        url=server,
        scheme="http",
        host=parsed.hostname or "127.0.0.1",
        port=parsed.port or 80,
        authorized=True,
    )
    return ScanContext(
        client=client,
        config=config,
        target=target,
        base_url=server,
        urls=urls if urls is not None else [server],
        request_targets=list(request_targets),
        seed_html=seed,
    )


async def solve_and_report(server: str, seed: str, targets, findings, urls=None, prime: bool = False):
    ctx = _make_ctx(server + "/", seed, targets, findings, urls)
    result = ScanResult(target=ctx.target, config=ctx.config)
    for f in findings:
        result.add(f)
    if prime:
        # Mimic the crawler: the scan session has already visited the site,
        # so any cookie the seed page issues (e.g. a JWT session) is in the
        # client's jar when the solve phase runs.
        await ctx.client.get(ctx.base_url)
    await run_solve_phase(ctx, result, lambda msg: None)
    status = await check_lab_status(ctx)
    await ctx.client.aclose()
    return result, status


def rt_get(url: str, **params) -> RequestTarget:
    return RequestTarget(url=url, method="GET", params=params, source="direct")


def rt_post(url: str, **params) -> RequestTarget:
    return RequestTarget(url=url, method="POST", params=params, source="form")


# ---------------------------------------------------------------------------
# Lab 1 + 2: admin panel completion (linked / robots.txt-disclosed)
# ---------------------------------------------------------------------------


def _admin_panel_app(admin_path: str, disclose_in_robots: bool):
    state = {"solved": False}
    app = FastAPI()

    panel = (
        f"<html><body><h1>Admin panel</h1><table>"
        f"<tr><td>wiener</td><td><a href='{admin_path}/delete?username=wiener'>Delete</a></td></tr>"
        f"<tr><td>carlos</td><td><a href='{admin_path}/delete?username=carlos'>Delete</a></td></tr>"
        f"</table></body></html>"
    )

    @app.get("/")
    async def home():
        link = f"<a href='{admin_path}'>Admin panel</a>" if not disclose_in_robots else ""
        return HTMLResponse(academy_html("Unprotected admin function", link, state["solved"]))

    @app.get("/robots.txt")
    async def robots():
        if disclose_in_robots:
            return HTMLResponse(f"User-agent: *\nDisallow: {admin_path}\n")
        return HTMLResponse("User-agent: *\nDisallow: /nothing-here\n")

    @app.get(admin_path)
    async def admin():
        return HTMLResponse(panel, status_code=200)

    @app.get(admin_path + "/delete")
    async def delete(username: str = ""):
        if username == "carlos":
            state["solved"] = True
        return RedirectResponse(admin_path, status_code=302)

    return app, state


@pytest.mark.parametrize("disclose_in_robots", [False, True])
async def test_admin_panel_deleted_carlos_solves_lab(disclose_in_robots):
    admin_path = "/kibana-manage-x9k2" if disclose_in_robots else "/admin"
    app, state = _admin_panel_app(admin_path, disclose_in_robots)
    with lab_server(app) as base:
        title = (
            "Unprotected admin function with unpredictable URL"
            if disclose_in_robots
            else "Unprotected admin function"
        )
        seed = academy_html(title, "", False)
        result, status = await solve_and_report(base, seed, [], [])
        assert state["solved"] is True
        assert status and status["solved"] is True
        assert result.objective["solved_after"] is True
        assert any(
            a["strategy"] == "admin-panel-action" and a["lab_solved"]
            for a in result.objective["attempts"]
        )


# ---------------------------------------------------------------------------
# Lab 3: X-Original-URL access-control bypass
# ---------------------------------------------------------------------------


def _original_url_app():
    state = {"solved": False}
    app = FastAPI()
    panel = (
        "<html><body><h1>Admin panel</h1><table>"
        "<tr><td>carlos</td><td><a href='/admin/delete?username=carlos'>Delete</a></td></tr>"
        "</table></body></html>"
    )

    @app.get("/")
    async def home(request: Request):
        if request.headers.get("x-original-url") == "/admin":
            return HTMLResponse(panel)
        return HTMLResponse(academy_html("URL-based access control can be circumvented", "Home", state["solved"]))

    @app.get("/admin")
    async def admin():
        return HTMLResponse("Access denied", status_code=403)

    @app.get("/admin/delete")
    async def delete(username: str = ""):
        if username == "carlos":
            state["solved"] = True
        return HTMLResponse("deleted")

    return app, state


async def test_x_original_url_bypass_reaches_panel():
    app, state = _original_url_app()
    with lab_server(app) as base:
        seed = academy_html("URL-based access control can be circumvented", "", False)
        result, status = await solve_and_report(base, seed, [], [])
        assert state["solved"] is True
        assert status and status["solved"] is True


# ---------------------------------------------------------------------------
# Lab 4: 2FA simple bypass
# ---------------------------------------------------------------------------


def _twofa_app():
    state = {"solved": False}
    app = FastAPI()

    @app.get("/")
    async def home():
        body = "<a href='/login'>Log in</a><a href='/my-account'>My account</a>"
        return HTMLResponse(academy_html("2FA simple bypass", body, state["solved"]))

    @app.get("/login")
    async def login_page():
        return HTMLResponse(
            "<form method='post' action='/login'>"
            "<input name='username'><input name='password'></form>"
        )

    @app.post("/login")
    async def login(request: Request):
        form = await request.form()
        if form.get("username") == "wiener" and form.get("password") == "peter":
            resp = RedirectResponse("/login2", status_code=302)
            resp.set_cookie("session", "half-auth-123")
            return resp
        return HTMLResponse("Invalid username or password", status_code=401)

    @app.get("/login2")
    async def login2():
        return HTMLResponse("<form method='post' action='/login2'>"
                            "<input name='mfa-code'></form>")

    @app.post("/login2")
    async def login2_post(request: Request):
        return HTMLResponse("Invalid verification code", status_code=401)

    @app.get("/my-account")
    async def my_account(request: Request):
        if "half-auth-123" in request.headers.get("cookie", ""):
            state["solved"] = True  # the 2FA step was skipped entirely
            return HTMLResponse(
                "<html><body>My Account — wiener — <a href='/logout'>log out</a></body></html>"
            )
        return RedirectResponse("/login", status_code=302)

    return app, state


async def test_2fa_bypass_solves_lab():
    app, state = _twofa_app()
    with lab_server(app) as base:
        seed = academy_html("2FA simple bypass", "", False)
        targets = [
            rt_post(base + "/login", username="", password=""),
        ]
        result, status = await solve_and_report(base, seed, targets, [])
        assert state["solved"] is True
        assert status and status["solved"] is True


# ---------------------------------------------------------------------------
# Lab 5: NoSQL operator-injection login bypass
# ---------------------------------------------------------------------------


def _nosql_app():
    state = {"solved": False}
    app = FastAPI()

    @app.get("/")
    async def home():
        return HTMLResponse(
            academy_html("NoSQL injection", "<form method='post' action='/login'>"
                         "<input name='username'><input name='password'></form>", state["solved"])
        )

    @app.post("/login")
    async def login(request: Request):
        ctype = request.headers.get("content-type", "")
        if "json" in ctype:
            try:
                body = await request.json()
            except Exception:  # noqa: BLE001
                body = {}
            user, pwd = body.get("username"), body.get("password")
            operator_bypass = (
                isinstance(user, dict) and "$ne" in user
                and isinstance(pwd, dict) and "$ne" in pwd
            )
        else:
            form = await request.form()
            keys = set(form.keys())
            operator_bypass = "username[$ne]" in keys and "password[$ne]" in keys
            user, pwd = form.get("username"), form.get("password")
        if operator_bypass or (user == "administrator" and pwd == "admin123"):
            state["solved"] = True
            resp = RedirectResponse("/", status_code=303)
            resp.set_cookie("session", "admin-session")
            return resp
        return HTMLResponse("Invalid username or password", status_code=401)

    return app, state


async def test_nosql_operator_bypass_solves_lab():
    app, state = _nosql_app()
    with lab_server(app) as base:
        seed = academy_html("NoSQL injection", "", False)
        targets = [rt_post(base + "/login", username="", password="")]
        result, status = await solve_and_report(base, seed, targets, [])
        assert state["solved"] is True
        assert status and status["solved"] is True


# ---------------------------------------------------------------------------
# Lab 6: stored XSS via blog comment
# ---------------------------------------------------------------------------


def _stored_xss_app():
    state = {"solved": False}
    app = FastAPI()
    comments: list[str] = []

    @app.get("/")
    async def home():
        rendered = "".join(f"<p>{c}</p>" for c in comments)
        return HTMLResponse(
            academy_html("Stored XSS into HTML context", rendered + "<a href='/post?postId=1'>blog</a>", state["solved"])
        )

    @app.get("/post")
    async def post(postId: str = "1"):
        rendered = "".join(f"<p>{c}</p>" for c in comments)
        return HTMLResponse(
            academy_html(
                "Stored XSS into HTML context",
                "<h1>Blog post</h1>" + rendered + (
                    "<form method='post' action='/post/comment'>"
                    "<input name='csrf' value='tok123'>"
                    f"<input name='postId' value='{postId}'>"
                    "<textarea name='comment'></textarea>"
                    "<input name='name'><input name='email'>"
                    "</form>"
                ),
                state["solved"],
            )
        )

    @app.post("/post/comment")
    async def comment(request: Request):
        form = await request.form()
        comments.append(str(form.get("comment", "")))
        if "<script>alert(1)</script>" in comments[-1]:
            state["solved"] = True
        return RedirectResponse("/post?postId=1", status_code=302)

    return app, state


async def test_stored_xss_comment_solves_lab():
    app, state = _stored_xss_app()
    with lab_server(app) as base:
        seed = academy_html("Stored XSS into HTML context", "", False)
        targets = [
            rt_post(
                base + "/post/comment",
                **{"csrf": "tok123", "postId": "1", "comment": "", "name": "", "email": ""},
            )
        ]
        urls = [base + "/post?postId=1"]
        result, status = await solve_and_report(base, seed, targets, [], urls=urls)
        assert state["solved"] is True
        assert status and status["solved"] is True


# ---------------------------------------------------------------------------
# Lab 7: SSRF into the internal admin panel
# ---------------------------------------------------------------------------


def _ssrf_admin_app(port: int):
    state = {"solved": False}
    app = FastAPI()
    panel = (
        "<html><body><h1>Admin panel</h1><table>"
        "<tr><td>carlos</td><td><a href='/admin/delete?username=carlos'>Delete</a></td></tr>"
        "</table></body></html>"
    )

    def internal_fetch(url: str) -> str:
        p = urlparse(url)
        if p.hostname not in ("localhost", "127.0.0.1"):
            return "<html><body>Blocked: only internal fetches allowed</body></html>"
        if p.path == "/admin":
            return panel
        if p.path == "/admin/delete" and parse_qs(p.query or "").get("username", [""])[0] == "carlos":
            state["solved"] = True
            return "<html><body>User deleted</body></html>"
        return "<html><body>Not found</body></html>"

    @app.get("/")
    async def home():
        return HTMLResponse(
            academy_html("Basic SSRF against the local server", "Shop", state["solved"])
        )

    @app.post("/product/stock")
    async def stock(request: Request):
        form = await request.form()
        api = str(form.get("stockApi", ""))
        if not api.startswith("http"):
            return HTMLResponse("Missing stockApi", status_code=400)
        return HTMLResponse(internal_fetch(api))

    return app, state


async def test_ssrf_internal_admin_delete_solves_lab():
    port = _free_port()
    app, state = _ssrf_admin_app(port)
    with lab_server(app) as base:
        seed = academy_html("Basic SSRF against the local server", "", False)
        targets = [rt_post(base + "/product/stock", stockApi="http://localhost/product?productId=1")]
        finding = _finding(Category.SSRF, "SSRF in 'stockApi'", base + "/product/stock")
        result, status = await solve_and_report(base, seed, targets, [finding])
        assert state["solved"] is True
        assert status and status["solved"] is True


# ---------------------------------------------------------------------------
# Lab 8: path traversal goal file
# ---------------------------------------------------------------------------


def _traversal_app():
    state = {"solved": False}
    app = FastAPI()

    @app.get("/")
    async def home():
        body = "<img src='/image?filename=1.jpg'>"
        return HTMLResponse(academy_html("File path traversal, simple case", body, state["solved"]))

    @app.get("/image")
    async def image(filename: str = ""):
        if "../" in filename or filename.startswith("/"):
            if filename.replace("../", "").lstrip("/").endswith("etc/passwd"):
                state["solved"] = True
                return HTMLResponse("root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\n")
            return HTMLResponse("No such file", status_code=404)
        return HTMLResponse("binary-image-data")

    return app, state


async def test_traversal_reads_passwd_solves_lab():
    app, state = _traversal_app()
    with lab_server(app) as base:
        seed = academy_html("File path traversal, simple case", "", False)
        targets = [rt_get(base + "/image", filename="1.jpg")]
        finding = _finding(Category.PATH_TRAVERSAL, "Path traversal in 'filename'", base + "/image")
        result, status = await solve_and_report(base, seed, targets, [finding])
        assert state["solved"] is True
        assert status and status["solved"] is True


# ---------------------------------------------------------------------------
# Lab 9: OS command injection (whoami objective)
# ---------------------------------------------------------------------------


def _cmd_app():
    state = {"solved": False}
    app = FastAPI()

    @app.get("/")
    async def home():
        body = ("<form method='post' action='/product/stock'>"
                "<input name='productId' value='1'><input name='storeId' value='1'></form>")
        return HTMLResponse(academy_html("OS command injection, simple case", body, state["solved"]))

    @app.post("/product/stock")
    async def stock(request: Request):
        form = await request.form()
        store_id = str(form.get("storeId", ""))
        if "whoami" in store_id:
            state["solved"] = True
            return HTMLResponse("37 units in stock\nroot\n")
        return HTMLResponse("37 units in stock")

    return app, state


async def test_cmd_injection_whoami_solves_lab():
    app, state = _cmd_app()
    with lab_server(app) as base:
        seed = academy_html("OS command injection, simple case", "", False)
        targets = [rt_post(base + "/product/stock", productId="1", storeId="1")]
        finding = _finding(Category.CMD_INJECTION, "OS command injection in 'storeId'", base + "/product/stock")
        result, status = await solve_and_report(base, seed, targets, [finding])
        assert state["solved"] is True
        assert status and status["solved"] is True


# ---------------------------------------------------------------------------
# Lab 10: JWT alg:none forgery -> admin panel action
# ---------------------------------------------------------------------------


def _b64url(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()


def _jwt_app():
    state = {"solved": False}
    app = FastAPI()
    header = _b64url(json.dumps({"alg": "HS256", "typ": "JWT"}).encode())
    payload = _b64url(json.dumps({"sub": "wiener", "role": "user"}).encode())
    token = f"{header}.{payload}.sig"

    def decode(token_value: str) -> dict:
        try:
            head_b64, payload_b64 = token_value.split(".")[:2]
            head = json.loads(base64.urlsafe_b64decode(head_b64 + "=" * (-len(head_b64) % 4)))
            body = json.loads(base64.urlsafe_b64decode(payload_b64 + "=" * (-len(payload_b64) % 4)))
            return {"header": head, "payload": body}
        except Exception:  # noqa: BLE001
            return {}

    panel = (
        "<html><body><h1>Admin panel</h1><table>"
        "<tr><td>carlos</td><td><a href='/admin/delete?username=carlos'>Delete</a></td></tr>"
        "</table></body></html>"
    )

    @app.get("/")
    async def home():
        resp = HTMLResponse(academy_html("JWT-based session handling", "<a href='/admin'>Admin</a>", state["solved"]))
        resp.set_cookie("session", token)
        return resp

    @app.get("/admin")
    async def admin(request: Request):
        cookie = request.headers.get("cookie", "")
        value = ""
        for part in cookie.split(";"):
            if part.strip().startswith("session="):
                value = part.strip()[len("session="):]
        data = decode(value)
        sub = data.get("payload", {}).get("sub", "")
        if sub == "administrator":
            return HTMLResponse(panel)
        return HTMLResponse("Access denied", status_code=403)

    @app.get("/admin/delete")
    async def delete(username: str = ""):
        if username == "carlos":
            state["solved"] = True
        return HTMLResponse("deleted")

    return app, state


async def test_jwt_alg_none_forge_solves_lab():
    app, state = _jwt_app()
    with lab_server(app) as base:
        seed = academy_html("JWT-based session handling", "", False)
        finding = _finding(Category.CRYPTO, "JWT in 'cookie:session' accepts arbitrary signatures", base + "/")
        result, status = await solve_and_report(base, seed, [], [finding], prime=True)
        assert state["solved"] is True, f"lab not solved; objective={result.objective}"
        assert status and status["solved"] is True


# ---------------------------------------------------------------------------
# Lab 11: broken brute-force / IP lockout (bounded, title-gated)
# ---------------------------------------------------------------------------


def _bruteforce_app():
    state = {"solved": False}
    app = FastAPI()
    attempts_per_ip: dict[str, int] = {}
    # The lab's real password sits somewhere mid-wordlist; the scanner must
    # rotate the spoofable client-IP header to defeat the per-IP lockout.
    correct_password = COMMON_PASSWORDS[37]

    @app.get("/")
    async def home():
        body = ("<form method='post' action='/login'>"
                "<input name='username' value='carlos'><input name='password'></form>")
        return HTMLResponse(academy_html("Broken brute-force / IP lockout", body, state["solved"]))

    @app.get("/login")
    async def login_page():
        return HTMLResponse("<form method='post' action='/login'>"
                            "<input name='username'><input name='password'></form>")

    @app.post("/login")
    async def login(request: Request):
        form = await request.form()
        ip = request.headers.get("x-forwarded-for", "direct")
        attempts_per_ip[ip] = attempts_per_ip.get(ip, 0) + 1
        if attempts_per_ip[ip] > 2 and ip != "direct":
            return HTMLResponse("Too many attempts from your IP", status_code=429)
        if form.get("username") == "carlos" and form.get("password") == correct_password:
            state["solved"] = True
            resp = RedirectResponse("/my-account", status_code=302)
            resp.set_cookie("session", "carlos-session")
            return resp
        return HTMLResponse("Invalid username or password", status_code=401)

    @app.get("/my-account")
    async def my_account(request: Request):
        if "carlos-session" in request.headers.get("cookie", ""):
            return HTMLResponse("<html><body>My Account — carlos — log out</body></html>")
        return RedirectResponse("/login", status_code=302)

    return app, state


async def test_bounded_bruteforce_rotates_ip_and_solves():
    app, state = _bruteforce_app()
    with lab_server(app) as base:
        seed = academy_html("Broken brute-force / IP lockout", "", False)
        targets = [rt_post(base + "/login", username="carlos", password="")]
        result, status = await solve_and_report(base, seed, targets, [])
        assert state["solved"] is True, f"objective={result.objective}"
        assert status and status["solved"] is True
        # The winning strategy must be the bounded stuffing one.
        assert any(a["strategy"] == "bruteforce-bounded" for a in result.objective["attempts"])


# ---------------------------------------------------------------------------
# Throttle resilience: 504 back-pressure + GET retry
# ---------------------------------------------------------------------------


def _throttling_app():
    calls = {"n": 0}
    app = FastAPI()

    @app.get("/flaky")
    async def flaky():
        calls["n"] += 1
        if calls["n"] == 1:
            return HTMLResponse("Gateway Timeout", status_code=504)
        return HTMLResponse("recovered")

    @app.get("/")
    async def home():
        return HTMLResponse("plain")

    return app, calls


async def test_http_client_backs_off_and_retries_get_after_504():
    app, calls = _throttling_app()
    with lab_server(app) as base:
        client = HttpClient(timeout=10)
        r = await client.get(base + "/flaky")
        assert r.status == 200, f"GET should be retried after 504, got {r.status}"
        assert calls["n"] == 2
        assert client.throttle_events == 1
        await client.aclose()


async def test_throttle_status_not_retried_for_post():
    app, calls = _throttling_app()
    with lab_server(app) as base:
        client = HttpClient(timeout=10)

        @app.post("/flaky")
        async def flaky_post():
            calls["n"] += 10
            return HTMLResponse("Gateway Timeout", status_code=503)

        r = await client.post(base + "/flaky")
        assert r.status == 503
        assert calls["n"] == 10  # no retry: POSTs are never replayed
        assert client.throttle_events == 1
        await client.aclose()


# ---------------------------------------------------------------------------
# Ladder ordering: title hints and findings steer the strategy order
# ---------------------------------------------------------------------------


def _minimal_result(*findings):
    from bughound.models import ScanConfig, Target

    target = Target(url="http://lab.test/", scheme="http", host="lab.test", port=80, authorized=True)
    config = ScanConfig(target_url="http://lab.test/", aggressive=True, exploit=True, use_external_tools=False)
    result = ScanResult(target=target, config=config)
    for f in findings:
        result.add(f)
    return result


def test_ladder_orders_by_title_hints():
    from bughound.objectives import build_ladder

    result = _minimal_result()
    ladder = build_ladder("2FA simple bypass", result)
    assert ladder[0].name == "auth-login-2fa-skip"

    ladder = build_ladder("Basic SSRF against the local server", result)
    assert ladder[0].name == "ssrf-admin-action"

    ladder = build_ladder("File path traversal, simple case", result)
    assert ladder[0].name == "traversal-goal-file"

    ladder = build_ladder("JWT-based session handling", result)
    assert ladder[0].name == "jwt-alg-none-forge"

    ladder = build_ladder("SQL injection attack, listing the database contents", result)
    assert ladder[0].name == "sqli-extraction-login"

    ladder = build_ladder("Broken brute-force / IP lockout", result)
    assert ladder[0].name == "bruteforce-bounded"


def test_ladder_orders_by_findings_without_title_hint():
    from bughound.objectives import build_ladder

    result = _minimal_result(
        _finding(Category.SSRF, "SSRF in 'stockApi'", "http://x/product/stock"),
        _finding(Category.PATH_TRAVERSAL, "Path traversal in 'filename'", "http://x/image"),
    )
    ladder = build_ladder("unknown lab", result)
    names = [s.name for s in ladder[:2]]
    assert set(names) == {"ssrf-admin-action", "traversal-goal-file"}


def test_default_ladder_starts_with_cheap_general_strategies():
    from bughound.objectives import build_ladder

    result = _minimal_result()
    ladder = build_ladder("unknown lab", result)
    names = [s.name for s in ladder]
    # every strategy is present exactly once (20 since the time-delay
    # strategy joined the blind-SQLi oracle strategies)
    assert len(names) == len(set(names)) == 20
