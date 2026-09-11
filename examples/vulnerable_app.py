"""A deliberately vulnerable demo app for exercising bughound locally.

Run it, then scan it (authorized, localhost):

    python examples/vulnerable_app.py           # serves on 127.0.0.1:8081
    bughound scan http://127.0.0.1:8081/ \
        --authorize-host 127.0.0.1 --i-am-authorized --aggressive --no-external

DO NOT expose this app to the internet.
"""

from __future__ import annotations

from fastapi import FastAPI, Request, Response
from fastapi.responses import HTMLResponse, RedirectResponse

app = FastAPI()


@app.get("/", response_class=HTMLResponse)
def index() -> HTMLResponse:
    # Missing security headers, exposes a secret and a link with a param, and
    # sets a session cookie without Secure/HttpOnly/SameSite.
    body = """<html><head><title>Demo Shop</title></head><body>
    <h1>Demo</h1>
    <!-- config -->
    <script>const api_key = "AKIAIOSFODNN7EXAMPLE"; var stripe="sk_live_0123456789abcdefghijklmn";</script>
    <a href="/search?q=hello">search</a>
    <a href="/item?id=1">item 1</a>
    <a href="/go?url=/home">home</a>
    <a href="/file?name=readme.txt">readme</a>
    <form method="post" action="/transfer">
      <input name="amount" value="10"/><input name="to" value="bob"/>
      <button>send</button>
    </form>
    <form method="post" action="/login">
      <input name="user"/><input type="password" name="pass"/>
    </form>
    </body></html>"""
    r = HTMLResponse(body)
    r.headers["set-cookie"] = "SESSIONID=abc123; Path=/"
    return r


@app.get("/search", response_class=HTMLResponse)
def search(q: str = "") -> str:
    # Reflected XSS: q echoed unencoded.
    return f"<html><body>Results for: {q}</body></html>"


@app.get("/item", response_class=HTMLResponse)
def item(id: str = "1") -> HTMLResponse:
    # Error-based SQLi simulation: a quote breaks the "query".
    if "'" in id or '"' in id:
        return HTMLResponse(
            "You have an error in your SQL syntax; check the manual that "
            "corresponds to your MySQL server version", status_code=500)
    return HTMLResponse(f"<html><body>Item {id}</body></html>")


@app.get("/file", response_class=HTMLResponse)
def file(name: str = "readme.txt") -> HTMLResponse:
    # Path traversal simulation.
    if "etc/passwd" in name or "../" in name:
        return HTMLResponse("root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:daemon:/usr/sbin")
    return HTMLResponse(f"contents of {name}")


@app.get("/go")
def go(url: str = "/") -> RedirectResponse:
    # Open redirect.
    return RedirectResponse(url)


@app.get("/api/data")
def data(request: Request) -> Response:
    # CORS reflects Origin with credentials.
    origin = request.headers.get("origin", "*")
    r = Response(content='{"ok":true}', media_type="application/json")
    r.headers["access-control-allow-origin"] = origin
    r.headers["access-control-allow-credentials"] = "true"
    return r


@app.get("/login")
def login() -> Response:
    # Session cookie without flags.
    r = Response(content="login")
    r.headers["set-cookie"] = "SESSIONID=abc123; Path=/"
    return r


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(app, host="127.0.0.1", port=8081)
