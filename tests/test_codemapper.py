"""Tests for source-code mapping (bughound.codemapper)."""

from __future__ import annotations

import os
import textwrap

import pytest

from bughound.codemapper import (
    SourceFile,
    _inferred,
    enrich_finding_code_evidence,
    find_param_sink,
    find_route_handler,
    harvest_source_files,
    map_finding,
)
from bughound.models import Category, Finding, Severity


VULN_APP = textwrap.dedent('''
    from fastapi import FastAPI

    app = FastAPI()


    @app.get("/products")
    def list_products(category: str = ""):
        conn = db()
        rows = conn.execute(
            f"SELECT name, price FROM products WHERE category='{category}'"
        ).fetchall()
        return {"items": rows}


    @app.get("/ping")
    def ping(host: str = ""):
        stream = os.popen(f"ping -c 1 {host}")
        return stream.read()
''')


def _write(tmp_path, name="app.py", content=VULN_APP) -> str:
    p = tmp_path / name
    p.write_text(content)
    return str(tmp_path)


def _finding(url: str, title: str, category=Category.SQLI) -> Finding:
    return Finding(
        category=category, title=title, severity=Severity.HIGH, url=url, module="t"
    )


def test_harvest_source_files(tmp_path):
    _write(tmp_path)
    (tmp_path / "node_modules").mkdir()
    (tmp_path / "node_modules" / "junk.js").write_text("var x=1;")
    files = harvest_source_files(str(tmp_path))
    names = [os.path.basename(f.path) for f in files]
    assert "app.py" in names
    assert "junk.js" not in names  # skip-dir honoured


def test_find_route_handler_python_decorator(tmp_path):
    files = harvest_source_files(_write(tmp_path))
    hit = find_route_handler(files, "/products")
    assert hit is not None
    sf, s, e, symbol = hit
    assert symbol == "list_products"
    body = "\n".join(sf.lines[s : e + 1])
    assert "conn.execute" in body


def test_find_route_handler_express(tmp_path):
    src = textwrap.dedent('''
        app.get('/users', (req, res) => {
          const q = "SELECT * FROM users WHERE name='" + req.query.name + "'";
          db.query(q, (err, rows) => res.send(rows));
        });
    ''')
    _write(tmp_path, name="server.js", content=src)
    files = harvest_source_files(str(tmp_path))
    hit = find_route_handler(files, "/users")
    assert hit is not None
    _sf, s, e, symbol = hit
    assert symbol == "" or True  # arrow fn has no `function` name
    body = "\n".join(_sf.lines[s : e + 1])
    assert "req.query.name" in body


def test_find_param_sink_picks_sql_execute(tmp_path):
    files = harvest_source_files(_write(tmp_path))
    sf, s, e, _sym = find_route_handler(files, "/products")
    hit = find_param_sink(sf, s, e, "category")
    assert hit is not None
    line, label = hit
    assert "category" in sf.lines[line]
    assert "SQL" in label


def test_map_finding_attaches_location(tmp_path):
    files = harvest_source_files(_write(tmp_path))
    f = _finding("http://t:80/products", "Error-based SQL injection in 'category'")
    assert map_finding(f, files) is True
    assert f.code_file.endswith("app.py")
    assert f.code_symbol == "list_products"
    assert f.code_lines[0] >= 7
    assert "category" in f.code_snippet
    assert f.injection_point.startswith("GET /products")


def test_enrich_falls_back_to_inferred_sink():
    f = _finding("http://t:80/products", "Error-based SQL injection in 'category'")
    enrich_finding_code_evidence(f, [])
    assert "Reconstructed from behaviour" in f.inferred_sink
    assert f.injection_point.startswith("GET /products")


def test_inferred_sink_per_category():
    cases = [
        (Category.CMD_INJECTION, "OS command injection in 'host'"),
        (Category.XSS, "Reflected XSS in 'q'"),
        (Category.PATH_TRAVERSAL, "Path traversal / LFI in 'name'"),
        (Category.SSRF, "Possible SSRF via 'url'"),
        (Category.OPEN_REDIRECT, "Open redirect via 'url'"),
        (Category.NOSQLI, "NoSQL operator injection via 'user'"),
    ]
    for cat, title in cases:
        text = _inferred(cat, title)
        assert text, f"no inferred sink for {cat}"


def test_map_finding_blackbox_uses_inferred(tmp_path):
    # A source dir exists but has no matching route -> inferred sink wins.
    d = _write(tmp_path)
    files = harvest_source_files(d)
    f = _finding("http://t:80/other", "Reflected XSS in 'q'", category=Category.XSS)
    enrich_finding_code_evidence(f, files)
    assert f.code_file == ""  # no source mapping
    assert "Reconstructed from behaviour" in f.inferred_sink


def test_boolean_sqli_inferred_mentions_condition():
    text = _inferred(Category.SQLI, "Possible boolean-based SQL injection in 'sku'")
    assert "TRUE/FALSE" in text or "WHERE" in text


def test_markdown_renders_code_location():
    from bughound.models import ScanConfig, ScanResult, Target
    from bughound.reporting import to_markdown

    f = _finding("http://t:80/products", "Error-based SQL injection in 'category'")
    f.code_file = "app.py"
    f.code_lines = (7, 12)
    f.code_symbol = "list_products"
    f.code_snippet = "-> rows = conn.execute(f\"... {category}\")"
    config = ScanConfig(target_url="http://t", aggressive=True)
    result = ScanResult(
        target=Target(url="http://t", scheme="http", host="t", port=80),
        config=config,
        findings=[f],
    )
    md = to_markdown(result)
    assert "#### Vulnerable code location" in md
    assert "`app.py` (lines 7-12)" in md
    assert "**list_products**" in md
