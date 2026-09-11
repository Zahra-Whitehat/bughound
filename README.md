# bughound

An **authorized** web-vulnerability hunting agent. Given a URL/domain, bughound
crawls the target, runs a set of scanner modules (plus external tools when
installed), attempts to **verify/prove** findings, and writes **Markdown + JSON
reports**. It ships as both a **CLI** and a **web service**.

> ⚠️ **Legal / authorization.** Scanning or exploiting systems you do not own or
> lack written permission to test is illegal in most jurisdictions. bughound
> enforces an authorization gate: it refuses to scan any host that is not in your
> declared scope, and requires an explicit authorization confirmation. Only use
> it against assets you own or are contractually authorized to test (e.g. a
> bug-bounty program whose scope permits automated testing).

## Vulnerability classes covered

| Group | Classes | How |
|---|---|---|
| Injection | SQLi, NoSQLi, OS command injection, LDAP/Header (CRLF) injection, XXE* | active payloads + differential/error/time based |
| Broken access control | IDOR*, privilege escalation*, path traversal / LFI | traversal verified; IDOR/priv-esc surfaced as candidates |
| Server-side | SSRF, RCE (via command injection), deserialization*, race/TOCTOU* | SSRF differential; RCE via command exec |
| Auth & sessions | OAuth/SAML*, session fixation, brute-force*, MFA bypass*, cookie flags | cookie flags verified; auth flows flagged for manual testing |
| Client-side | XSS (reflected), CSRF, CORS, clickjacking | XSS/CORS/clickjacking verified; CSRF form heuristic |
| Logic & config | business logic*, information disclosure, security misconfig, TLS | exposed files/headers/dir-listing/TLS verified |
| Crypto | hardcoded secrets, JWT flaws (alg=none), weak hashing indicators | client-content scanning |

`*` = surfaced as an honestly-labeled **candidate/advisory** finding for manual
verification (these classes generally need authenticated context or human
judgement). Findings are marked `verified` (proven) vs `confidence:
tentative/firm` so reports never overclaim.

## Install

```bash
python3 -m venv .venv && . .venv/bin/activate
pip install -e ".[dev]"
```

Optional external tools (auto-detected, gracefully skipped if missing):
`nuclei`, `nmap`, `sqlmap`.

## CLI

```bash
# List modules
bughound list-modules

# Safe (passive) scan of your own site
bughound scan https://example.com --authorize-host example.com --i-am-authorized

# Aggressive scan (active exploitation) using a scope file
bughound scan https://example.com --scope scope.yml --i-am-authorized --aggressive

# Reports are written to ./reports/<host>-<timestamp>.{md,json}
```

Authorization can be provided by any of: `--scope <file>`, one or more
`--authorize-host <glob>`, or the `BUGHOUND_AUTHORIZED_HOSTS` env var. You must
also pass `--i-am-authorized`.

## Web service

```bash
bughound serve --host 127.0.0.1 --port 8000
# open http://127.0.0.1:8000
```

API:
- `POST /api/scan` `{ "url", "authorized": true, "authorize_hosts": [...], "aggressive": false }`
- `GET /api/scan/{id}` → status, log, result
- `GET /api/scan/{id}/report.md` → Markdown report

## Design

```
crawl (same-origin) → discover URLs + injectable params/forms
      → run modules (passive always; active only with --aggressive)
      → run external tools (nuclei always; nmap/sqlmap in aggressive)
      → dedupe findings → JSON + Markdown report
```

Modules live in `bughound/modules/{passive,active}/` and self-register via a
decorator, so adding a check is a single small file.

## Tests

```bash
pytest
ruff check .
```
