# bughound

An **authorized** web-vulnerability hunting agent. Given a URL/domain, bughound
crawls the target, runs a set of scanner modules (plus external tools when
installed), **exploits what it finds to prove real impact**, **verifies every
finding against false positives with control experiments**, **pinpoints where
in the code each vulnerability lives**, and writes **Markdown + JSON reports**
where every claim is backed by a copy-pasteable proof. It ships as both a
**CLI** and a **web service**.

> ⚠️ **Legal / authorization.** Scanning or exploiting systems you do not own or
> lack written permission to test is illegal in most jurisdictions. bughound
> enforces an authorization gate: it refuses to scan any host that is not in your
> declared scope, and requires an explicit authorization confirmation. Only use
> it against assets you own or are contractually authorized to test (e.g. a
> bug-bounty program whose scope permits automated testing).

## What's new in 0.6.2 (recon hardening)

Recon breadth brought up toward Sn1per-parity, while keeping the authorization
invariant that out-of-scope hosts are reported but never contacted:

- **Active subdomain brute force** joins the existing crt.sh (Certificate
  Transparency) lookup in `subdomain-enum` -- a ~90-entry wordlist resolved
  via DNS-over-HTTPS catches hosts that never had a logged TLS certificate.
- **Subdomain-takeover detection**: every resolved subdomain's CNAME is
  checked against 27 third-party-platform fingerprints (GitHub Pages,
  Heroku, S3, Azure, Netlify, Vercel, ...). Flagged from DNS evidence only --
  bughound never sends an HTTP request to a subdomain outside confirmed
  scope, so takeover candidates are reported as unconfirmed pending manual
  verification or a scope expansion + re-scan.
- **Favicon hash fingerprinting** (`tech-fingerprint`): a pure-Python
  MurmurHash3 implementation reproduces Shodan/Censys's `http.favicon.hash`,
  giving a single high-confidence value to pivot on across the internet for
  the exact product/version in use.
- **New `whois-recon` module**: registrar, creation/expiry dates,
  nameservers and registrant org via RDAP (`rdap.org`), the modern
  HTTPS-based successor to the WHOIS protocol -- no legacy WHOIS client
  needed.
- **New `wayback-urls` module**: harvests every URL archive.org's Wayback
  Machine has ever crawled for the target domain, and separately flags
  archived paths that look like backups/config/credential files
  (`.sql`, `.bak`, `.env`, `.pem`, ...) -- often the highest-yield recon
  source for endpoints the live site no longer links to.

## What's new in 0.6.1

- **Fixed: bare-path `--exploit-endpoint` silently failed.** Passing `--exploit-endpoint /product/stock` (path instead of full URL) produced the hostless URL `http:///product/stock`; every exploit request then failed with a synthetic status-0 response and the direct-exploit chain quietly did nothing (no error shown). Bare paths are now resolved against the scan target (`https://<target>/product/stock`), and the console prints the resolved URL. Regression-tested (5 new tests; suite at 107).

## What's new in 0.6

- **Raw-body direct exploitation (XML/JSON endpoints).** `--exploit-body '<stockCheck><productId>1</productId><storeId>{INJ}</storeId></stockCheck>'` turns any raw-body endpoint into a full injection target: every exploit strategy (UNION shape discovery, dialect probing, table/column enumeration, credential extraction, credential login) substitutes payloads at the `{INJ}` marker.
- **WAF-bypass payload encodings.** `--exploit-encode xml-entities` numeric-character-reference-encodes every payload at the injection point, so filters that scan the raw body for SQL keywords see nothing while the XML parser hands the original payload to the SQL engine.
- **Authorization UX fix.** `--i-am-authorized` alone now auto-scopes the scan to the exact target host (denylist still overrides; explicit `--authorize-host`/`--scope` still win). `--authorize-host` also accepts URLs and `host:port` and normalizes them to the hostname.
- **Dialect-detection fixes.** Version-banner matching no longer truncates real PostgreSQL banners (~126 chars); dialect probes are ordered most-specific-first (PostgreSQL's `||` probe cannot fire on MySQL, MySQL's `CONCAT` cannot be trusted alone on PostgreSQL); the Oracle static fallback now verifies the dialect via `FROM dual` instead of matching any database.
- **Raw-body evidence.** curl PoCs and raw HTTP exchanges for body-template targets render the actual (encoded) body with the correct Content-Type.

## What's new in 0.5

### 1. Exploits that complete the lab objective

- **Direct-exploit mode** — you already know the lab's vulnerable endpoint?
  Point the exploit engine straight at it and it runs the full chain
  (UNION extraction → credential dump → automatic login → account takeover),
  regardless of what the crawler/detector found:

  ```bash
  bughound scan https://lab.web-security-academy.net/ \
      --authorize-host lab.web-security-academy.net --i-am-authorized \
      --aggressive \
      --exploit-endpoint 'https://lab.web-security-academy.net/filter?category=Pets' \
      --exploit-param category
  ```

- **Broader lab dialect support**: Oracle (`FROM dual`, `v$version`,
  `all_tables`/`all_tab_columns`, `LISTAGG`) and MSSQL (`@@version`,
  `FOR XML PATH` enumeration) joined SQLite / MySQL / PostgreSQL for UNION and
  blind extraction.
- **More reliable UNION shape discovery**: candidate column counts are now
  validated by reflecting a unique marker through a string column, so
  suppressed-error endpoints can no longer lock the search onto a wrong count.
- Findings the detector missed as re-targetable are no longer dropped: the
  exploit engine reconstructs a request target from the finding and still
  attempts the chain.
- The console prints a dedicated **Exploit results** block at the end of the
  scan (one ✓ line per successful exploit), so exploitation status is
  impossible to miss.

### 2. False-positive verification (control experiments)

Every finding that the exploit phase could **not** prove is re-tested by
`bughound/verification.py` with a battery of control experiments, and the
report answers "how do we know this is not a false positive?" with the actual
results:

| Check | What it proves |
|---|---|
| `negative-control` | a payload with the active ingredient removed (no quote, no operator, no traversal...) does **not** trigger the signature — so the signature is input-specific, not page noise |
| `repeat-consistency` | the signature reproduces on every repeat request — real injection is deterministic; rotating banners and A/B content are not |
| `baseline-clean` | the unmodified request shows no signature |
| `fresh-canary-*` | reflection findings are re-tested with a unique random canary per check — stale markers can never fake a reflection |
| `directionality` | for boolean SQLi, TRUE must resemble baseline and FALSE must differ — in that direction only |
| `timing-jitter` | for time-based SQLi, baseline network jitter is small enough to trust the delay signal |

Findings that pass everything get a **LOW false-positive risk** verdict; any
failed check **downgrades** the finding (`verified=False`, `confidence=
tentative`) and prints a FAIL row in the report's *False-positive analysis*
table. A succeeded exploit is its own FP disproof and bypasses the battery.

### 3. Reports that show WHERE the vulnerability lives

- **`--source-dir <path>`**: give it the application's source code and every
  finding is mapped to the exact **file + line range + enclosing function +
  sink line** (marked with `->`) — e.g. `os.popen(f"ping -c 1 {host}")` at
  `examples/vulnerable_app.py:280`, inside `ping()`.
  Supports FastAPI/Flask-style decorators, Express/Node routes, Spring
  mappings, and PHP `$_GET` usage; sinks detected include SQL execute,
  shell exec, file read, server-side fetch, redirect and raw echo.
- **No source available?** (black-box lab) Each finding instead carries a
  clearly-labelled **reconstructed sink pattern** — the shape of code the
  input provably reaches, derived from the captured behavioural evidence
  (quote breaks query, tautology changes result set, command output echoes...).
- Every finding also shows its **injection point**
  (e.g. `GET /filter?category=... -> query-string parameter 'category'`).
- Methodology appendix documents the verification and code-attribution steps.

## Exploitation & proof (0.4 features, extended in 0.5)

Detection alone tells you "something looks wrong". bughound's **exploit phase**
(runs automatically in aggressive mode) goes further: every detected finding is
re-targeted with a **safe, non-destructive exploit** that demonstrates the
actual impact — and for SQLi that means **completing the attack objective**,
not just proving an error:

| Finding class | Exploit proof attempted |
|---|---|
| Error-based SQLi | Adaptive UNION extraction (column count + quote-context + string-column discovery): DB version banner, table list, **then real credential rows from any users/credential table** |
| UNION with credentials | **Automatic login** through the application's own login form with the extracted credentials → **ACCOUNT TAKEOVER** proof (failed-login baseline comparison, session markers) |
| Hidden data | Tautology injection (`' OR 1=1--`) that makes filtered-out records reappear — proven by measuring content growth beyond payload reflection |
| Boolean-blind SQLi | Character-by-character binary-search extraction of **a privileged user's password** (length + chars, hash auto-cracking), falling back to the DB version banner |
| Blind + extracted password | **Automatic login** → **ACCOUNT TAKEOVER** proof |
| Cookie SQLi (TrackingId-style) | Cookies are treated as injectable parameters end-to-end: detected, UNION-probed, blind-extracted — with the cookie override isolated to single requests |
| Time-based SQLi | Boolean-oracle upgrade probe, then extraction when possible |
| OS command injection | Runs `id` / `uname -sr` / `hostname` and captures the output — proves RCE **and which user** |
| Path traversal / LFI | Reads `/etc/passwd` (accounts listed) plus a second distinct file to prove the read is arbitrary |
| Reflected XSS | Verifies `<script>`, `onerror=`, `svg onload=` payloads survive unfiltered in an HTML context (content-type aware) |
| SSRF | Makes the target fetch **its own loopback address** and return its content — proves server-side fetching with data exfiltration |
| Open redirect | Walks and documents the full redirect chain (hop-by-hop) |
| NoSQL operator injection | Attempts a real authentication bypass via `[$ne]` and detects authenticated-page markers |
| Everything else | Gets a curl repro + raw HTTP exchange + impact statement + manual steps |

**Every exploited finding lands in the report with:**

- ✅ **EXPLOITED** badge and an executive-summary count,
- the **data extracted from the target** (DB banner, table names, **credential
  rows**, `/etc/passwd` lines, `uid=...` output, loopback fingerprints...),
- the **account-takeover proof** when extracted credentials successfully
  logged into the application (objective completion, not just a read),
- a **ready-to-run `curl` reproduction** (copy-paste, works as-is),
- the **verbatim raw HTTP request/response exchange** (Burp-style),
- numbered **manual reproduction steps** for triagers,
- a written **impact statement** per vulnerability class,
- the **Vulnerable code location** section (source-mapped sink or
  behaviour-derived reconstruction),
- the **False-positive analysis** section (control-experiment table + verdict).

When an exploit *cannot* be completed, the report says so honestly
(`Exploit phase result: ...`) and the finding keeps its detection-stage
evidence and confidence label — bughound never upgrades a finding it could
not prove.

**Safety rules of the exploit phase** (all enforced in code):

- Requires `--aggressive` **and** the normal authorization gate; disable
  independently with `--no-exploit` (CLI) or `"exploit": false` (web API).
- Strictly read-only / informational payloads: SQL extraction of metadata and
  credential rows, `id`/`uname`, system-file reads, marker reflections, and
  logins **using credentials the target itself leaked** (at most 2 attempts —
  a failed-login baseline plus the extracted credential — never brute-force).
  No data is modified, no destructive or denial-of-service payloads exist in
  the codebase.
- SSRF proofs target **loopback / the target itself only** — cloud metadata
  endpoints (169.254.169.254 etc.) are hard-blocked.
- Every exploit request flows through the same denylist-guarded HTTP client
  as the rest of the scan; cookie-override probes are restored immediately
  so the scanner's own session is never polluted.
- Per-finding request budgets keep the phase fast and gentle.

A full example report produced against the bundled vulnerable demo app is in
[`examples/sample-report.md`](examples/sample-report.md).

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
| **Reconnaissance** | subdomains, DNS records, tech stack, WAF, HTTP methods, JS endpoints, admin panels, API docs, backup files, source maps, emails, robots/sitemap | passive discovery (no payloads) |

`*` = surfaced as an honestly-labeled **candidate/advisory** finding for manual
verification (these classes generally need authenticated context or human
judgement). Findings are marked `verified` (proven) vs `confidence:
tentative/firm` so reports never overclaim.

## Reconnaissance (passive attack-surface mapping)

The recon layer is what makes bughound useful as a *recon* tool, not just a
vuln scanner. It runs **always-on in safe (passive) mode** and produces both
INFO-severity findings and a structured `recon` block in the JSON / Markdown
report. The 12 dedicated recon modules are:

| Module | What it discovers |
|---|---|
| `robots-sitemap` | `robots.txt`, `sitemap.xml`, `humans.txt`, `security.txt`, well-known endpoints — surfaces hidden paths |
| `dns-recon` | A / AAAA / MX / TXT / NS / CAA / SOA records via DNS-over-HTTPS (no `dnspython` needed) + SPF / DMARC posture |
| `subdomain-enum` | Subdomains from the Certificate Transparency log (crt.sh) |
| `tech-fingerprint` | Wappalyzer-style detection of web server, language, framework, CMS, CDN, analytics, JS libs |
| `waf-detection` | Cloudflare / AWS WAF / Akamai / Sucuri / Imperva / F5 / Fortinet / etc. |
| `http-methods` | OPTIONS-based method enumeration + risky-method flagging + TRACE-based XST check |
| `js-endpoints` | API endpoints / paths extracted from same-origin JS files (REST, GraphQL, internal) |
| `admin-panels` | 60+ common management paths (/admin, /wp-admin, /phpmyadmin, /actuator, /jenkins, /solr, /kibana, /grafana, ...) |
| `api-discovery` | Swagger / OpenAPI / GraphQL introspection / ReDoc / Spring HAL / RAML / api-docs |
| `backup-files` | `.bak` / `.old` / `.orig` / `~` / `.swp` / `.zip` / `.tar.gz` / `.sql` / `.save` / etc. variants of crawled paths |
| `sourcemap-exposure` | `.js.map` files that ship with minified bundles (leaks un-minified source) |
| `email-harvest` | Email addresses from HTML `mailto:` and free-text + same-origin JS |

Existing passive modules — `cookies`, `cors`, `info-disclosure` (now 80+ paths),
`secrets` (now 60+ patterns), `security-headers` (now 12 checks incl.
Permissions-Policy / COEP / COOP / CORP), `tls` — are also part of the recon
layer. The denylist always applies, so recon requests never touch forbidden
hosts / URLs.

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

# Aggressive scan (active detection + exploit phase) using a scope file
bughound scan https://example.com --scope scope.yml --i-am-authorized --aggressive

# Aggressive but detection-only (skip the exploit phase)
bughound scan https://example.com --authorize-host example.com --i-am-authorized --aggressive --no-exploit

# Map findings to the application's source code (WHERE the bug lives)
bughound scan https://example.com --authorize-host example.com --i-am-authorized \
    --aggressive --source-dir /path/to/app-source

# Direct-exploit mode: push a known-vulnerable endpoint through the full
# exploit chain (UNION -> credentials -> login). Ideal for labs.
bughound scan https://lab.web-security-academy.net/ \
    --authorize-host lab.web-security-academy.net --i-am-authorized \
    --aggressive --no-external \
    --exploit-endpoint 'https://lab.web-security-academy.net/filter?category=Pets' \
    --exploit-param category

# Reports are written to ./reports/<host>-<timestamp>.{md,json}
```

Authorization can be provided by any of: `--scope <file>`, one or more
`--authorize-host <glob>`, or the `BUGHOUND_AUTHORIZED_HOSTS` env var. You must
also pass `--i-am-authorized`.

### Troubleshooting: "0 URLs discovered" / no findings

If a scan finishes almost instantly with `Discovered 0 URLs, 0 injectable
targets` and no findings, the target was unreachable. bughound now does a
single pre-flight GET before crawling and emits the exact failure reason:

```
bughound scanning https://lab.web-security-academy.net/ (aggressive mode, timeout=30.0s)
[08:39:12] Probing target https://lab.web-security-academy.net/ (timeout 30.0s)...
[08:39:42]   initial probe failed: ConnectTimeout:
             retrying once with 2x timeout (target may be waking up)...
[08:40:12] Target unreachable -- aborting scan (see report for details).
```

Common fixes (in order of likelihood for online labs / shared-hosting
targets):

1. **Open the URL in your browser first.** PortSwigger Web Security Academy
   labs, AWS Lambda, and similar on-demand runtimes go to sleep after
   inactivity. The first request wakes them up but can take >15s; once awake
   subsequent requests are fast.
2. **Increase the timeout:** `--timeout 60` (default is now 30s; was 15s).
3. **Override the User-Agent:** `--user-agent 'Mozilla/5.0 ...'`. The
   default is now a recent Chrome UA, but if a site still blocks it pass a
   full browser UA string.
4. **Verify scope:** the host must match an `--authorize-host` glob, a
   `--scope` file entry, or the `BUGHOUND_AUTHORIZED_HOSTS` env var.

You can also pass `--debug` for verbose per-request logging.

### Denylist (forbidden / out-of-scope targets)

Mark hosts or URLs as forbidden and bughound will **never** crawl them or send a
single request to them — not during crawling, not from any scanner module, not
via redirects, and not through external tools. Deny rules are enforced at the
HTTP layer before any connection is opened and **override the allowlist**: a
denied target is refused even if it is otherwise in authorized scope.

```bash
bughound scan https://example.com \
  --authorize-host example.com \
  --deny-host admin.example.com \
  --deny-host '*.internal.example.com' \
  --deny-url https://example.com/logout \
  --deny-url https://example.com/billing \
  --i-am-authorized
```

Deny rules can also be supplied via the scope YAML (`denied_hosts`,
`denied_urls`), the `BUGHOUND_DENIED_HOSTS` env var (comma-separated), or the
web API (`deny_hosts`, `deny_urls`). Matching is case-insensitive; `denied_hosts`
uses glob patterns (use `*.example.com` to cover subdomains) and `denied_urls`
matches by URL prefix (trailing slashes and fragments are ignored).

## Web service

```bash
bughound serve --host 127.0.0.1 --port 8000
# open http://127.0.0.1:8000
```

API:
- `POST /api/scan` `{ "url", "authorized": true, "authorize_hosts": [...], "deny_hosts": [...], "deny_urls": [...], "aggressive": false, "exploit": true }`
- `GET /api/scan/{id}` → status, log, result
- `GET /api/scan/{id}/report.md` → Markdown report

## Design

```
crawl (same-origin) → discover URLs + injectable params/forms
      → run modules (passive always; active only with --aggressive)
        passive modules include the 12-module recon layer:
          robots-sitemap, dns-recon, subdomain-enum, tech-fingerprint,
          waf-detection, http-methods, js-endpoints, admin-panels,
          api-discovery, backup-files, sourcemap-exposure, email-harvest
        (writes structured attack-surface data into result.recon)
      → run external tools (nuclei always; nmap/sqlmap in aggressive)
      → exploit phase (--aggressive only, disable with --no-exploit):
          re-target every finding with a safe impact-proof exploit
          (UNION extraction, `id` capture, file reads, loopback fetches...)
      → verification phase (control experiments on non-exploited findings):
          negative controls, repeat consistency, baseline cleanliness,
          fresh canaries, directionality — flagged findings are downgraded
      → code mapping (--source-dir): findings pinned to file+line+sink,
          or behaviour-derived sink reconstruction for black-box targets
      → dedupe findings → JSON + Markdown report
          (executive summary, per-finding PoC: curl + raw HTTP pair
           + extracted data + repro steps + impact, vulnerable-code-location
           section, false-positive-analysis table, methodology appendix)
```

Modules live in `bughound/modules/{passive,active}/` and self-register via a
decorator, so adding a check is a single small file. The exploit engine lives
in `bughound/exploits/` (one module per proof technique, plus
`evidence.py` which standardizes the curl / raw-HTTP-pair / repro-steps
artefacts). The false-positive verifier lives in `bughound/verification.py`;
the source-code mapper in `bughound/codemapper.py`. Recon helpers (DoH DNS
lookup, crt.sh subdomain query, fingerprint catalog) live in
`bughound/modules/recon_utils.py`.

## Demo: prove it to yourself

```bash
python examples/vulnerable_app.py          # deliberately vulnerable app on 127.0.0.1:8081
bughound scan http://127.0.0.1:8081/ \
    --authorize-host 127.0.0.1 --i-am-authorized --aggressive --no-external \
    --source-dir examples
```

The generated report will show the SQLi finding with the extracted database
banner and table list, the command-injection finding with the captured
`uid=...` output, the traversal finding with `/etc/passwd` contents, the SSRF
finding with the loopback fingerprint, and the NoSQLi finding with the
authentication bypass — each with its curl one-liner, raw HTTP exchange,
exact vulnerable code location (`examples/vulnerable_app.py`, line, function)
and false-positive analysis.
A pre-generated copy is in `examples/sample-report.md`.

## Tests

```bash
pytest
ruff check .
```
