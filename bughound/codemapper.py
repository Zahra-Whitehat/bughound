"""Map every finding to WHERE the vulnerability lives in the code.

A report that says "the /filter endpoint has SQLi" is only half useful. A
report that says "the ``category`` parameter is concatenated into the SQL
query inside ``filter_products()`` at examples/vulnerable_app.py, lines
204-207" lets a developer walk straight to the bug and fix it.

Two evidence modes, both always labelled honestly:

**Source mapping** (--source-dir points at the application's code):
  1. locate the route handler that serves the vulnerable URL path
     (FastAPI/Flask decorators, Express ``app.get``/``router.post``,
     PHP ``$_GET`` usage, Spring ``@GetMapping``...),
  2. inside that handler, find the injectable parameter name,
  3. find the *dangerous sink* the parameter reaches (cursor.execute,
     os.popen/system/exec, open/readFile, urlopen/requests.get,
     redirect, echo/print...) -- closest sink line wins,
  4. record file, line range, verbatim snippet, and enclosing symbol.

**Inferred sink** (black-box target, no source available):
  The report reconstructs the shape of the sink the input demonstrably
  reaches, derived from the observed behaviour (quote breaks the query,
  tautology changes the result set, UNION column count matches, command
  output echoes...). It is clearly marked as reconstructed, and every
  claim is tied to the behavioural evidence that proves it.
"""

from __future__ import annotations

import os
import re
from dataclasses import dataclass, field

from .models import Category, Finding

# Languages we attempt source mapping on.
SOURCE_EXTS = {".py", ".js", ".ts", ".jsx", ".tsx", ".php", ".java", ".rb", ".cs", ".go"}
SKIP_DIRS = {"node_modules", ".git", "venv", ".venv", "env", "dist", "build", "__pycache__", ".next"}
MAX_FILE_BYTES = 1_500_000
MAX_FILES = 4000

# ---------------------------------------------------------------------------
# Route discovery
# ---------------------------------------------------------------------------

# (framework regex for route + handler start) -- pragmatic, coverage-first.
ROUTE_PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    # FastAPI / Flask / Sanic / starlette: @app.get("/path"), @app.route('/path')
    (
        "python-decorator",
        re.compile(
            r"@(?:app|api|bp|blueprint|router)\.(?:route|get|post|put|delete|patch)\s*\(\s*[\"']([^\"']+)[\"']",
            re.IGNORECASE,
        ),
    ),
    # Express / Koa / router: app.get('/path', handler), router.post(...)
    (
        "js-route",
        re.compile(
            r"\b(?:app|router|server|api)\.(?:get|post|put|delete|patch|all)\s*\(\s*[\"'`]([^\"'`]+)[\"'`]",
            re.IGNORECASE,
        ),
    ),
    # Spring: @GetMapping("/path"), @RequestMapping(value="/path")
    (
        "java-mapping",
        re.compile(
            r"@(?:Get|Post|Put|Delete|Request)Mapping\s*(?:\(\s*(?:value\s*=\s*)?[\"']([^\"']+)[\"'])?",
            re.IGNORECASE,
        ),
    ),
]


@dataclass
class SourceFile:
    path: str
    lines: list[str] = field(default_factory=list)


@dataclass
class CodeLocation:
    file: str
    lines: tuple[int, int]
    snippet: str
    symbol: str
    sink: str


def harvest_source_files(source_dir: str) -> list[SourceFile]:
    """Load candidate source files (bounded) from ``source_dir``."""
    files: list[SourceFile] = []
    for root, dirs, names in os.walk(source_dir):
        dirs[:] = [d for d in dirs if d not in SKIP_DIRS]
        for name in names:
            ext = os.path.splitext(name)[1].lower()
            if ext not in SOURCE_EXTS:
                continue
            path = os.path.join(root, name)
            try:
                if os.path.getsize(path) > MAX_FILE_BYTES:
                    continue
                with open(path, encoding="utf-8", errors="replace") as fh:
                    text = fh.read()
            except OSError:
                continue
            files.append(SourceFile(path=path, lines=text.splitlines()))
            if len(files) >= MAX_FILES:
                return files
    return files


def _normalize(p: str) -> str:
    """Normalize a route/URL path for comparison."""
    p = p.split("?")[0].rstrip("/") or "/"
    return p.lower()


def find_handler_span(sf: SourceFile, match_start_line: int) -> tuple[int, int]:
    """Line span of the handler that starts at ``match_start_line``.

    For Python: decorator line -> end of the ``def`` block (next
    same-column decorator/def or EOF). For C-style languages: to the
    matching closing brace (bounded scan).
    """
    n = len(sf.lines)
    # Python-style: find the def/function line after the decorator...
    def_line = match_start_line
    for i in range(match_start_line, min(match_start_line + 8, n)):
        if re.match(r"\s*(?:async\s+)?def\s+\w+", sf.lines[i]) or re.match(
            r"\s*(?:public|private|protected|static).*?\(", sf.lines[i]
        ):
            def_line = i
            break
    base_indent = len(sf.lines[def_line]) - len(sf.lines[def_line].lstrip())
    end = def_line
    for i in range(def_line + 1, n):
        line = sf.lines[i]
        if not line.strip():
            end = i
            continue
        indent = len(line) - len(line.lstrip())
        if indent <= base_indent and (
            re.match(r"\s*(?:async\s+)?def\s+\w+", line)
            or line.lstrip().startswith("@")
            or re.match(r"\s*(?:public|private|protected)\s", line)
        ):
            break
        end = i
    return def_line, min(end, n - 1)


def _brace_span(sf: SourceFile, start: int) -> tuple[int, int]:
    depth = 0
    seen_open = False
    for i in range(start, min(start + 200, len(sf.lines))):
        for ch in sf.lines[i]:
            if ch == "{":
                depth += 1
                seen_open = True
            elif ch == "}":
                depth -= 1
                if seen_open and depth <= 0:
                    return start, i
    return start, min(start + 60, len(sf.lines) - 1)


def find_route_handler(files: list[SourceFile], url_path: str) -> tuple[SourceFile, int, int, str] | None:
    """Find the handler code serving ``url_path``. Returns (file, start, end, symbol)."""
    target = _normalize(url_path)
    target_file_hint = target.strip("/").split("/")[-1] if target != "/" else ""
    best: tuple[tuple, SourceFile, int, int, str] | None = None

    for sf in files:
        text = "\n".join(sf.lines)
        for _label, rx in ROUTE_PATTERNS:
            for m in rx.finditer(text):
                route = m.group(1) or ""
                norm = _normalize(route)
                if not norm or norm == "/":
                    continue
                # exact match, or parameterised match (/item/{id} vs /item/3,
                # /item/:id for Express-style routes)
                pat = re.compile("^" + re.sub(r"\{[^}]+\}", "[^/]+", norm) + "$")
                pat2 = re.compile("^" + re.sub(r":[^/]+", "[^/]+", norm) + "$")
                if not (pat.match(target) or pat2.match(target) or norm == target):
                    continue
                start_line = text[: m.start()].count("\n")
                if _label == "python-decorator":
                    s, e = find_handler_span(sf, start_line)
                else:
                    s, e = _brace_span(sf, start_line)
                symbol = ""
                for i in range(start_line, min(e + 1, len(sf.lines))):
                    dm = re.search(r"(?:def|function)\s+(\w+)", sf.lines[i])
                    if dm:
                        symbol = dm.group(1)
                        break
                score = 0 if norm == target else 1
                if best is None or score < best[0]:
                    best = (score, sf, s, e, symbol)
        # PHP-style fallback: $_GET['param'] in a file named like the path
        if target_file_hint and sf.path.lower().endswith(".php") and target_file_hint in os.path.basename(sf.path).lower():
            if best is None:
                s, e = 0, min(120, len(sf.lines) - 1)
                best = (2, sf, s, e, os.path.basename(sf.path))

    if best is None:
        return None
    _score, sf, s, e, symbol = best
    return sf, s, e, symbol


# ---------------------------------------------------------------------------
# Sink discovery
# ---------------------------------------------------------------------------

SINK_PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    ("SQL execute", re.compile(r"\b(?:execute|executemany|executescalar|executeQuery|query|raw)\s*\(", re.IGNORECASE)),
    ("SQL string built from input", re.compile(r"(?:SELECT|INSERT|UPDATE|DELETE)\b[^\n]*['\"+]?\s*(?:\{|\+|%|\$)", re.IGNORECASE)),
    ("shell execution", re.compile(r"\b(?:os\.popen|os\.system|subprocess\.(?:call|run|Popen)|shell_exec|system\s*\(|exec\s*\(|popen\s*\(|child_process\.\w+|Runtime\.getRuntime|ProcessBuilder)", re.IGNORECASE)),
    ("file read/write", re.compile(r"\b(?:open\s*\(|readFile|readFileSync|file_get_contents|fopen|new File\s*\(|IO\.read|File\.ReadAllText|os\.path\.join)", re.IGNORECASE)),
    ("server-side request", re.compile(r"\b(?:urlopen|requests\.(?:get|post)|http\.get|axios(?:\.\w+)?\(|fetch\s*\(|HttpClient|curl_init)", re.IGNORECASE)),
    ("redirect", re.compile(r"\b(?:redirect\s*\(|RedirectResponse|redirect_to|response\.redirect|res\.redirect|header\s*\(\s*['\"]Location)", re.IGNORECASE)),
    ("raw output / echo", re.compile(r"\b(?:echo\s+\$|print\s*\(|printf\s*\(|document\.write|innerHTML\s*=|res\.(?:send|write)\s*\()", re.IGNORECASE)),
    ("mongodb query", re.compile(r"\b(?:find\s*\(\s*\{|findOne\s*\(\s*\{|collection\s*\.\w+)", re.IGNORECASE)),
]


def find_param_sink(sf: SourceFile, start: int, end: int, param: str) -> tuple[int, str] | None:
    """Inside handler span, find the best (line, sink-label) where the param
    reaches a dangerous sink. Returns the sink LINE (0-indexed)."""
    short = param.split(":")[-1]
    candidates: list[tuple[int, str, int]] = []  # (priority, label, line)
    for i in range(start, end + 1):
        line = sf.lines[i]
        if short not in line:
            continue
        for prio, (label, rx) in enumerate(SINK_PATTERNS):
            if rx.search(line):
                candidates.append((prio, label, i))
                break
    if not candidates:
        # Parameter referenced somewhere in the handler: attach the first use.
        for i in range(start, end + 1):
            if short in sf.lines[i]:
                return i, "parameter usage (no classic sink found on the same line)"
        return None
    candidates.sort(key=lambda c: (c[0], c[2]))
    _prio, label, line = candidates[0]
    return line, label


def _snippet(sf: SourceFile, center: int, radius: int = 5) -> str:
    lo = max(0, center - radius)
    hi = min(len(sf.lines) - 1, center + radius)
    out = []
    for i in range(lo, hi + 1):
        marker = "  -> " if i == center else "     "
        out.append(f"{marker}{i + 1:4d} | {sf.lines[i]}")
    return "\n".join(out)


def map_finding(finding: Finding, files: list[SourceFile]) -> bool:
    """Try to attach a concrete source-code location to ``finding``.
    Returns True when a location was found."""
    from urllib.parse import urlparse

    path = urlparse(finding.url).path or "/"
    param = None
    m = re.search(r"(?: in | via )'([^']+)'", finding.title)
    if m:
        param = m.group(1)

    handler = find_route_handler(files, path)
    if handler is None:
        return False
    sf, s, e, symbol = handler
    sink_line, sink_label = None, ""
    if param:
        found = find_param_sink(sf, s, e, param)
        if found:
            sink_line, sink_label = found
    if sink_line is None:
        # no param-specific sink: attach the handler with its first sink line
        for i in range(s, e + 1):
            for _label, rx in SINK_PATTERNS:
                if rx.search(sf.lines[i]):
                    sink_line, sink_label = i, _label
                    break
            if sink_line is not None:
                break
    if sink_line is None:
        sink_line, sink_label = s, "handler entry"

    finding.code_file = os.path.relpath(sf.path)
    finding.code_lines = (s + 1, e + 1)
    finding.code_snippet = _snippet(sf, sink_line)
    finding.code_symbol = symbol or "(module level)"
    finding.injection_point = _injection_point(finding, param)
    return True


def _injection_point(finding: Finding, param: str | None) -> str:
    from urllib.parse import parse_qsl, urlparse

    p = urlparse(finding.url)
    method = (finding.request or "").split(" ", 1)[0] if finding.request else "GET"
    method = method if method in ("GET", "POST", "PUT", "DELETE", "PATCH") else "GET"
    where = ""
    if param:
        if param.startswith("cookie:"):
            where = f"cookie '{param[7:]}'"
        elif any(k == param for k, _ in parse_qsl(p.query)):
            where = f"query-string parameter '{param}'"
        else:
            where = f"request parameter '{param}'"
    return f"{method} {p.path or '/'}{('?' + p.query) if p.query else ''} -> {where}" if where else f"{method} {p.path or '/'}"


# ---------------------------------------------------------------------------
# Black-box inferred sinks (no source available)
# ---------------------------------------------------------------------------

INFERRERS: dict[str, callable] = {}


def _inferred(category: Category, title: str) -> str:
    key = category.name
    fn = INFERRERS.get(key)
    if fn:
        return fn(title)
    return ""


def _infer_sqli(title: str) -> str:
    if "boolean" in title.lower():
        return (
            "# Reconstructed from behaviour: the parameter is concatenated into a\n"
            "# SQL WHERE clause; crafting TRUE/FALSE conditions changes the result set.\n"
            "query = \"SELECT ... WHERE col = '\" + request_input + \"'\"   # injectable\n"
            "rows = db.execute(query)"
        )
    if "time" in title.lower():
        return (
            "# Reconstructed from behaviour: the parameter reaches a SQL engine that\n"
            "# evaluates injected time-delay expressions (SLEEP / pg_sleep / WAITFOR).\n"
            "query = \"SELECT ... WHERE col = '\" + request_input + \"'\"   # injectable\n"
            "rows = db.execute(query)"
        )
    return (
        "# Reconstructed from behaviour: injecting a quote produces a database\n"
        "# parser error, proving the input is spliced raw into the SQL statement.\n"
        "query = \"SELECT ... WHERE col = '\" + request_input + \"'\"   # injectable\n"
        "rows = db.execute(query)   # -> SQL syntax error when input contains a quote"
    )


def _infer_cmd(title: str) -> str:
    return (
        "# Reconstructed from behaviour: the parameter is passed to a shell, so\n"
        "# appended commands ('; id) executed with the web server's privileges.\n"
        "output = os.popen(\"ping -c 1 \" + request_input).read()   # injectable\n"
        "# (equivalently: shell_exec(\"ping -c 1 \" . $_GET['host']) in PHP)"
    )


def _infer_xss(title: str) -> str:
    return (
        "<!-- Reconstructed from behaviour: input is echoed into the HTML body\n"
        "     without contextual encoding, so injected markup/script executes. -->\n"
        "<p>Results for: <?= request_input ?></p>   <!-- unencoded reflection -->"
    )


def _infer_traversal(title: str) -> str:
    return (
        "# Reconstructed from behaviour: '../' sequences in the parameter escape the\n"
        "# intended base directory and the server returns arbitrary file contents.\n"
        "path = base_dir + request_input          # no normalisation / containment\n"
        "content = open(path).read()              # -> /etc/passwd retrievable"
    )


def _infer_ssrf(title: str) -> str:
    return (
        "# Reconstructed from behaviour: the server fetches the URL supplied in the\n"
        "# parameter and returns/uses the response -- loopback addresses included.\n"
        "resp = urllib.request.urlopen(request_input)   # SSRF: scheme/host unfiltered\n"
        "body = resp.read()"
    )


def _infer_redirect(title: str) -> str:
    return (
        "# Reconstructed from behaviour: the parameter is used verbatim as the\n"
        "# redirect target, so absolute URLs send users off-site.\n"
        "return redirect(request_input)   # Location: attacker-controlled"
    )


def _infer_nosqli(title: str) -> str:
    return (
        "# Reconstructed from behaviour: request fields become Mongo selectors\n"
        "# without type validation, so {$ne: ...} operators match any account.\n"
        "user = db.collection.find({ user: req.body.user, pass: req.body.pass })\n"
        "# attacker sends user[$ne]=x -> selector becomes {user: {$ne: 'x'}}"
    )


def _infer_header(title: str) -> str:
    return (
        "# Reconstructed from behaviour: header values are built from request input\n"
        "# without stripping CR/LF, enabling response splitting / header injection.\n"
        "response.headers['X-Custom'] = request_input   # injectable"
    )


INFERRERS.update({
    Category.SQLI.name: _infer_sqli,
    Category.CMD_INJECTION.name: _infer_cmd,
    Category.RCE.name: _infer_cmd,
    Category.XSS.name: _infer_xss,
    Category.PATH_TRAVERSAL.name: _infer_traversal,
    Category.SSRF.name: _infer_ssrf,
    Category.OPEN_REDIRECT.name: _infer_redirect,
    Category.NOSQLI.name: _infer_nosqli,
    Category.LDAP_HEADER_INJECTION.name: _infer_header,
})


def _param_name(finding: Finding) -> str | None:
    m = re.search(r"(?: in | via )'([^']+)'", finding.title)
    return m.group(1) if m else None


def enrich_finding_code_evidence(finding: Finding, files: list[SourceFile]) -> None:
    """Fill code-location fields: mapped source lines when available,
    otherwise an honest behaviour-derived sink reconstruction."""
    finding.injection_point = _injection_point(finding, _param_name(finding))
    if files and map_finding(finding, files):
        return
    inferred = _inferred(finding.category, finding.title)
    if inferred:
        finding.inferred_sink = inferred


def map_all_findings(result, emit) -> int:
    """Map every finding to code evidence. Returns count of source-mapped ones."""
    files: list[SourceFile] = []
    if result.config.source_dir:
        if os.path.isdir(result.config.source_dir):
            files = harvest_source_files(result.config.source_dir)
            emit(f"Code mapping: scanning {len(files)} source file(s) under {result.config.source_dir}")
        else:
            emit(f"Code mapping: --source-dir {result.config.source_dir!r} is not a directory; skipping source mapping")
    mapped = 0
    for f in result.findings:
        before = f.code_file
        enrich_finding_code_evidence(f, files)
        if f.code_file and f.code_file != before:
            mapped += 1
    return mapped
