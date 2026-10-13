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

## What's new in 1.6.0 (time-delay blind SQLi -- the "Blind SQL injection with time delays" fix)

Reported live against a fresh Academy instance: "Blind SQL injection with
time delays" was not solved. Diagnosis: this lab family has **no boolean
page differential, no status-flip oracle and no visible error text** -- a
broken quote returns a normal 200 page. The oracle speaks in SECONDS
(`pg_sleep`/`SLEEP`/`WAITFOR`/`DBMS_PIPE`), and the lab's win condition is a
sustained ~10 second delay. The 1.5.0 ladder engaged `sqli-blind-cookie-oracle`
first, which correctly found no boolean/error oracle and gave up, burning
the budget on wrong bug classes afterwards.

Golden path verified on the live instance: `TrackingId=x'||(SELECT
pg_sleep(10))||'` delayed the response 10.85s and the platform banner
flipped to **Solved**. General fixes in 1.6.0:

1. **`exploits/sqli.py`: a third blind-SQLi oracle engine -- the delay
   oracle.** `calibrate_delay_oracle` confirms a delay only when it SCALES
   with the requested duration (2s probe -> ~2s, 4s probe -> ~4s, both above
   floors and strictly increasing), so network jitter and one-off slow
   responses can never fake it. Six dialect templates (PostgreSQL / MySQL /
   SQL Server / Oracle). `fire_objective_delay` fires the lab-winning ~10s
   delay. `exploit_sqli_delay_extraction` drives the "…and information
   processing" variant: conditional `CASE WHEN (pred) THEN pg_sleep(d) ELSE
   pg_sleep(0) END` templates answer yes/no questions in seconds, and the
   same bounded binary search recovers the administrator password, followed
   by the standard login chain.
2. **`objectives.py`: new strategy `sqli-time-delay-objective` (priority 6)** --
   runs BEFORE the boolean/error oracle strategy whenever the lab title
   mentions time delays (finding-free, cookie-first like its sibling).
   Flow: calibrate -> fire the 10s objective delay -> re-read the platform
   banner -> only if still unsolved, run the delay-oracle extraction + login.
   The candidate builder is now shared with `sqli-blind-cookie-oracle`.
3. **`exploits/auth.py`: CSRF parsing accepts UNQUOTED HTML attributes**
   (`name=csrf value=...`) -- loose HTML is common and previously broke
   token refresh whenever no crawl-time token was available.
4. **Mock + tests:** `build_time_delay_lab` (faithful PG emulation: only
   `pg_sleep` primitives evaluate, MySQL/MSSQL/Oracle probes answer
   instantly, real-second sleeps, banner flips on the 10s delay; the
   information-processing variant evaluates CASE-WHEN predicates against a
   seeded users table and flips on admin login). Tests cover ladder
   ordering, scaling-vs-fixed calibration rejection, the full-pipeline e2e
   (solve in 6 solve-phase requests) and the direct extraction chain.

Version 1.6.0; full suite 239 passed.

## What's new in 1.5.0 (visible-error one-shot leaks -- the "visible error-based SQL injection" fix)

Reported live against a fresh Academy instance: "Visible error-based SQL
injection" was not solved, and the solve log showed the 1.4.0 conditional-error
engine passing over the cookie in ~14 seconds without engaging. Manual probing
of the live instance (while it stayed alive) exposed TWO stacked traps, both
now handled generally:

1. **The lab frontend truncates cookie values at ~60 characters**
   (post-decode; measured live: four different payload shapes all cut at
   exactly 60). Every classic payload -- conditional-error templates AND the
   official CAST leak -- is longer than that once the 16-char TrackingId is
   included, so every probe arrived truncated and parsed as a broken
   literal. **Fix: short synthetic base values** (`a'||...`) for cookie
   injection points plus compact `LIMIT 1 OFFSET n` expressions -- the row
   never needs to match the base value, because the backend evaluates the
   injected expression for every row it scans.
2. **The error text itself carries the data.** This family reflects the real
   database error in the response body, so `CAST(expr AS int)` leaks the
   whole value in ONE request (`invalid input syntax for type integer:
   "<value>"`). **New fast path `leak_via_visible_error`** runs before the
   conditional-error binary search: PostgreSQL (`::int`), SQL Server
   (`CAST AS int`) and MySQL (`extractvalue`) templates, per-dialect value
   regexes, then login. The solve phase needs ~3 requests instead of ~140.

The solve-ladder gate was also generalized: the quote-balance signature
(`'` -> 5xx, `''` -> 2xx) alone now admits a candidate into the error-based
strategy, which then tries the visible-error leak first and the
conditional-error engine second. **Verified live end-to-end**: the
`TrackingId` cookie probe -> password `b2so6glvhmboqmlmjyg0` leaked from the
error message in 2 requests -> authenticated as administrator ->
the platform banner flipped to **Solved** (solve phase: 11 requests). A
faithful mock (60-char value cap, reflected PG errors, multi-row/NULL
semantics, CSRF login) is solved autonomously by `run_scan` in the e2e
suite. **234 tests green.**

## What's new in 1.4.0 (error-blind oracles -- the "conditional errors" fix)

Reported live against a fresh Academy instance: "Blind SQL injection with
conditional errors" still was not solved. The scan report told the whole
story in one ladder line: `no blind-SQLi boolean oracle found on cookies or
seed params` after only 5 requests -- because this lab family has **no
boolean oracle at all**. Both `' AND '1'='1` and `' AND '1'='2` render the
identical page; the oracle hides entirely in the **HTTP status code**: a
single quote breaks the query (HTTP 500), doubling it restores validity
(HTTP 200), and `CASE WHEN (<cond>) THEN TO_CHAR(1/0) ELSE '' END` answers
yes/no questions through a conditional division-by-zero error.

**Fix: a second, error-based oracle engine alongside the boolean one.**

1. **`calibrate_error_oracle`** (new, in `exploits/sqli.py`): a 2-request
   signature test (broken quote -> 5xx AND doubled quote -> 2xx) proves the
   input lands inside a SQL string literal and backend errors surface as
   5xx pages; then dialect templates are confirmed 2-requests-each until
   TRUE (`1=1`) and FALSE (`1=2`) differ by status alone. Shipped dialects:
   **Oracle** (`'||(SELECT CASE WHEN ({cond}) THEN TO_CHAR(1/0) ELSE '' END
   FROM dual)||'`), **PostgreSQL** (`(1/0)::text`), **MySQL/MariaDB**
   (`1/0`), **SQL Server** (`CAST(1/0 AS varchar)`).
2. **`ErrorOracle` + `_ask_error`**: a TRUE answer is an HTTP 5xx; the same
   bounded binary search (length, then collation-independent ASCII-numeric
   characters) drives conditional errors instead of page differentials.
   `exploit_sqli_error` mirrors the boolean exploit end to end: candidate
   credential validation probes -> extraction -> **login as the recovered
   user** (account takeover) with a version-banner fallback.
3. **Ladder integration**: `sqli-blind-cookie-oracle` now tries the error
   calibration on every candidate whose boolean calibration comes back
   empty, so the "conditional errors" family is solved finding-free even
   when detection (legitimately) never sees a differential.
4. **Tests**: a faithful mock of the measured live behaviour (SQL-literal
   scanner for syntax errors, CASE-WHEN evaluation against the seeded users
   table, no page differential whatsoever, CSRF login, solved flip) + 3
   tests: quote-balance signature unit test, **full-pipeline e2e
   (`run_scan` drives the mock from "Not solved" to "Solved")**, and a
   direct Oracle-dialect calibration test. **232 tests green.**

## What's new in 1.3.0 (blind-SQLi cookie oracles -- the "conditional responses" fix)

Reported live against a fresh Academy instance: "Blind SQL injection with
conditional responses" still was not solved. Manual probing of the instance
(before it expired) exposed THREE stacked defects that all target the same
lab family, plus one that targets every blind-SQLi target:

1. **The differential is too small for whole-page similarity.** The oracle
   lives in the `TrackingId` cookie; a TRUE answer renders one small
   "Welcome back" block inside a multi-kilobyte shop page. SequenceMatcher
   similarity between the TRUE and FALSE pages stays >= 0.98, so every
   similarity-based signal -- detection AND oracle calibration -- silently
   vanished. **Fix: an exact text-chunk differential** (`_chunk_differential`,
   `pages_differ_by_chunks`): the page is split into visible text chunks; if
   the baseline deterministically reproduces one of the two payload pages and
   the payload pages differ in non-payload chunks, that IS a boolean oracle,
   no matter how small the delta. Payload echoes and rotating content
   (nonces, timestamps) are explicitly rejected.
2. **The oracle polarity could be inverted.** The 1.1.x exploit compared
   answers to the BASELINE page (`sim(r, base) > threshold`), which inverts
   every oracle whose TRUE answer ADDS content the baseline lacks.
   **Fix: a calibrated, polarity-agnostic oracle** (`BooleanOracle` +
   `calibrate_boolean_oracle`): calibration captures the TRUE and FALSE
   reference pages, and every later answer is judged by *closeness to the
   matching reference* -- correct for content-added, content-hidden and
   status-flip oracles alike.
3. **Character extraction followed DB collation.** String-ordering
   comparisons (`SUBSTRING(pw,i,1) < 'x'`) follow the database's collation,
   which interleaves case and reorders the alphabet -- the binary search
   converged to garbage on live instances. Extraction now uses
   **collation-independent ASCII-numeric comparisons**
   (`ASCII(SUBSTRING(...)) > m`) end to end.
4. **No ladder strategy could find an oracle without a finding.**
   **New strategy `sqli-blind-cookie-oracle` (priority 8)**: for
   "Blind SQL injection ..." titles it works finding-free -- every
   session-jar cookie against the seed URL plus cookie-consumer targets, two
   calibration requests per candidate, then the full extraction engine
   (binary search + login) on a synthetic finding where an oracle exists.
   Cookie-based TIME-based probes (pg_sleep/SLEEP/WAITFOR/DBMS_PIPE, both
   stacked and concat forms) joined cookie detection as well.

Verified end to end: a standalone probe solved the live instance (oracle ->
20-char password extraction with per-character equality verification -> CSRF
login -> platform banner flipped to "Solved"), and a faithful mock of the
measured live behaviour (large shop page, tiny welcome block, real SQL
engine behind the cookie, CSRF login, solved flip) is now driven from
"Not solved" to "Solved" by `run_scan` in the e2e suite. **+15 tests (226
total)**.

## What's new in 1.2.0 (hint-driven UNION objectives -- "finding a column containing text")

The 1.1.1 report fixed Oracle UNION extraction; the NEXT user lab exposed the
opposite failure: the objective was never a credential one at all.
"SQL injection UNION attack, finding a column containing text" states its
goal verbatim in the banner hint -- `Make the database retrieve the string:
'kNwvPL'` -- and flips to solved the moment that string comes back through
the vulnerable query. The ladder only knew the credential path (extract
users -> log in as administrator), which can never complete such labs: it
burned UNION extraction plus a boolean-blind fallback and reported
"attempted". 1.2.0 closes that gap generically:

- **The banner hint is now parsed** (`solving.LAB_HINT_RE`): the platform's
  own objective statement (`<p id="hint">...`) travels with the lab title
  into the objective engine.
- **New strategy `sqli-union-hint-objective` (priority 5)**: reads the hint,
  extracts the target string, discovers the UNION shape with the hardened
  1.1.1 engine (marker-validated column count, quote wrapper, per-position
  text compatibility, Oracle FROM dual), then fires the objective string
  through a TEXT column -- exactly what the platform asks for. Success is
  still judged by the solve phase's own banner re-check. Column-count-only
  UNION labs ("determining the number of columns") are recognised from the
  title and completed with a correctly-shaped NULL row.
- **Detection-miss fallback:** if the scan produced no re-targetable SQLi
  finding, the strategy falls back to the crawled GET query-param targets
  (bounded to 3) instead of stranding a lab whose title already vouches for
  the UNION family.
- **+10 tests (217 total)**: a faithful PostgreSQL mock built from live-lab
  measurements -- strings are legal ONLY in the middle UNION position
  (numeric/text/numeric typing), unquoted payloads stay valid literals (the
  1.1.1 trap), the category value is never echoed, and the solved oracle
  flips exactly when the hint string comes back through the query. The full
  pipeline must take it from "Not solved" to "Solved" autonomously.

## What's new in 1.1.1 (Oracle UNION trap -- the "listing the database contents on Oracle" fix)

Reported live against a real Academy instance: the tool detected the
boolean-based SQLi, tried "UNION credential extraction", failed, burned four
minutes on the boolean-blind fallback, solved nothing. Root cause (shape
discovery, not the dialect code): on the Oracle lab the backend query is
``... WHERE category = '<value>'`` -- EVERY value, including the engine's
UNQUOTED payloads, becomes part of the string literal. A plain
``Gifts UNION SELECT NULL,NULL-- -`` is therefore a VALID query that answers
**HTTP 200 with baseline rows only**. The quoted arms all error (Oracle needs
``FROM dual``), so the status-only candidate collector hoarded bogus
unquoted candidates for every column count -- which blocked the
``if not candidates:`` Oracle phase, failed every validation, and returned
``None`` from ``discover_union_shape``.

- **Validate-as-you-collect:** every candidate must now reflect a unique
  string marker through a REAL UNION arm before it is accepted
  (``_validate_shape``). A 200 alone proves nothing on string contexts.
- **The Oracle ``FROM dual`` phase always runs** when no plain candidate
  validates (previously: only when the plain phase collected zero
  candidates).
- Verified live end-to-end on the real instance: 2 columns -> Oracle 11g
  banner -> 75 tables via ``all_tables`` -> ``USERS_<rand>`` ranked first ->
  ``all_tab_columns`` -> credential rows -> automated administrator login ->
  platform ``is-solved`` banner.
- **+3 tests (207 total)**: a faithful Oracle trap mock (unquoted payloads
  are valid literals, no payload echo -- both verified against the live lab)
  pins shape discovery, full extraction, and the automated takeover login.

## What's new in 1.1.0 (dead-lab detection -- the "still not solved" fix)

Users kept reporting "the lab is still not solved" for URLs that could never
be solved by ANY tool: the Academy instances had **expired**. A dead instance
is deceptive -- the PortSwigger gateway keeps answering with `HTTP 504` and
the body `Server Error: Gateway Timeout (0) connecting to <lab-host>`, while
1.0.0's probe treated ANY response (including that error page) as "target is
reachable". Result: a 6+ minute module storm against a corpse, zero findings,
zero explanation. 1.1.0 makes the truth loud and instant:

- **Definitive dead-lab signature** (`http_client.lab_dead_response`): the
  gateway's error BODY is matched (`Gateway Timeout (N) connecting to ...`),
  not the status -- the Academy also throttles live labs with 504s, so the
  status alone is ambiguous. A body-matched death is definitive.
- **Fail-fast instead of back-off:** dead-lab 504s no longer open the adaptive
  throttle cooldown (which was sleeping 2-35s per request). A dead instance
  aborts the scan in ~2 seconds instead of grinding for minutes.
- **Pre-flight verdict:** the probe now fails on any non-2xx/3xx answer and
  prints an unmissable `LAB INSTANCE IS DEAD / EXPIRED / STOPPED` banner with
  exact next steps (Access the lab -> copy the NEW url -> check -> scan).
- **Mid-run death guards:** the death counter is checked between scan phases
  (after recon, after hunting, around exploit/solve). An instance that dies
  WHILE scanning stops the run loudly instead of returning a mystery-empty
  report. The exception unwinds cleanly -- reports are still written.
- **New CLI command `check`:** `python -m bughound check '<URL>'` gives an
  instant ALIVE / DEAD / UNREACHABLE verdict with the lab title and its
  solved status when the Academy banner is present. Exit code 0 only for
  ALIVE. Run it BEFORE every scan -- it costs one request.
- **+11 tests (204 total)**: dead-body matching, throttle-vs-death
  discrimination, fail-fast timing, pre-flight abort, mid-run death, live-lab
  false-positive guard, and both `check` verdicts.

## What's new in 1.0.0 (real-lab hardening: the chain now survives strict apps)

0.9.0's strategy ladder was proven on unit-level mocks with pre-seeded
findings. 1.0.0 replays the ENTIRE pipeline (crawl -> detect -> ladder ->
strategy) against strict, Academy-faithful mock applications -- per-session
CSRF enforcement, required comment fields with email validation, session
rotation on login, a 302-to-/login2 second factor, an internal-only admin
page, a sibling exploit server with a victim bot -- and fixes everything the
strictness exposed:

- **Two brand-new objective strategies (17 total):**
  - `exploit-server-cookie-steal` -- completes the "steal cookies with XSS"
    family end-to-end: posts the exfiltration payload as a stored comment,
    waits for the platform victim bot, reads the exploit server's access
    log, and replays the stolen session against the victim's account. The
    exploit server is discovered three ways (crawled sibling host, seed-page
    "Exploit server" anchor, platform naming convention) -- nothing is
    hardcoded per lab.
  - `cookie-role-flip` -- logs in canonically, flips privilege-bearing
    session cookies (`Admin=false`->`true`, `role=user`->`administrator`,
    numeric bumps), keeps the elevation for the panel's action requests, and
    completes the state-changing objective.
- **Strict-form survival:** every form the solver submits is completed with
  generic required-field values (email/name/website defaults) -- the old
  payload+csrf-only submissions were rejected by real comment forms.
- **2FA-bypass probe fix:** after login the solver now requests
  `/my-account?id=<the user it logged in as>` (plus the classic victim ids)
  -- the missing id-probe was exactly why "2FA simple bypass" labs stayed
  unsolved.
- **SSRF hardening:** the strategy no longer requires a detection finding
  (title hint + crawled stock-check endpoints are enough), probes
  `0.0.0.0`/decimal-IP loopback spellings, and sweeps the documented
  internal ranges (`192.168.0.x:8080`, budget-capped at 150) for the
  "SSRF against another local server" family.
- **Sibling-platform discovery:** the crawler records (but never fetches)
  same-registrable-domain sibling hosts, so the Academy exploit server is
  visible to the solver while the crawl stays same-origin.
- **Expired-lab loudness:** an unreachable Academy target now prints an
  explicit "instances EXPIRE -- spawn a fresh lab" banner instead of a bare
  abort, and every open objective ends the run with a concrete next-steps
  block (fresh instance / --aggressive / throttling / --solve-budget).
- **Brute-force list extended** with the Academy's published candidate
  wordlist for the IP-rotation credential-stuffing family.
- **+6 end-to-end tests** (193 total): each mock lab flips its own solved
  banner only on true objective completion, and the full unsupervised
  pipeline must flip it.

## What's new in 0.9.0 (generalized objective solver -- any lab, not one lab)

0.7.1 completed exactly ONE objective shape: SQLi -> extract administrator
credentials -> log in. Any training lab whose intended objective was anything
else (delete a user through an admin panel, bypass 2FA, store an XSS payload,
SSRF into an internal admin page, read a file, run `whoami`, forge a JWT...)
remained "not solved" forever -- the exact "it worked for that specific lab"
complaint. 0.9.0 replaces that ladder with a **goal-driven, detection-driven
objective engine** (`bughound/objectives.py`):

- **15 generic objective-completion strategies**, none of which references a
  concrete lab URL, path or credential: admin-panel discovery (crawled links
  + robots.txt `Disallow` + common paths) with markup-parsed state-changing
  actions (delete/promote user rows), `X-Original-URL`/`X-Rewrite-URL`
  access-control bypass, trusted-IP header bypass (`X-Custom-IP-Authorization`
  ...), canonical-account login + 2FA-skip (navigate straight to the
  authenticated page), bounded title-gated credential stuffing with
  `X-Forwarded-For` rotation, NoSQL `$ne`/`$regex` operator login bypass,
  stored-XSS via comment form (payload must survive RAW on re-fetch),
  reflected-XSS `alert(1)` triggers, SSRF into `http://localhost/admin` with
  the action replayed through the SAME SSRF channel, path-traversal goal
  files (`/etc/passwd`, `/home/carlos/secret`...), OS command `whoami`
  capture, JWT `alg:none` forgery -> admin panel action, and
  information-disclosure credential mining -> login.
- **The ladder is assembled from two signals**: the lab's own title (the
  platform prints the intended objective -- title keywords promote the
  technique a human would try first) and the scan's FINDINGS (an SSRF
  finding promotes the SSRF strategy, an access-control finding promotes the
  admin-panel strategy...). Both work; either alone works.
- **Success is always the platform's own oracle**: the solve phase re-reads
  the lab status banner after every strategy and stops at the first `Solved`.
  The report's "Objective completion" section now also lists the assembled
  ladder, so you can see exactly what was tried in what order.
- **Throttle resilience (root cause of the "starved" runs)**: the Academy
  rate-limits aggressive automated traffic, and the previous releases had
  ZERO handling for it -- a throttled crawl starved every later phase. The
  HTTP client now treats 429/503/504 as global back-pressure: an adaptive
  cooldown slows every phase (they share one client), idempotent GETs are
  retried once after the cooldown, and POSTs are never replayed. The scan
  log reports throttle events at the end.
- **Solve-phase request budget** (`--solve-budget`, default 220): completing
  an objective can never turn into an unbounded request storm.
- **Proven on 16 new tests / 11 mock Academy labs** (`tests/test_general_solver.py`),
  each flipping its own `is-solved` banner only when the intended objective is
  truly achieved: admin panel (linked + robots.txt-disclosed), X-Original-URL
  bypass, 2FA simple bypass, NoSQL operator injection, stored XSS comment,
  SSRF->internal admin delete, path traversal, OS command injection, JWT
  alg:none forgery -> delete carlos, bounded brute-force with IP rotation,
  throttle back-pressure behaviour, and ladder ordering.

## What's new in 0.8.0 (dialect-adaptive exploitation engine)

0.7.1 completed exactly ONE lab flavor (PostgreSQL, string context, 2
columns). 0.8.0 generalizes the SQLi exploit into a **dialect-adaptive
engine** -- verified on a fresh Academy lab flavour, *"SQL injection attack,
listing the database contents on **Oracle**"*, plus new mock labs for
PostgreSQL and MySQL:

- **`FROM dual` everywhere it belongs** (`bughound/exploits/sqli.py`): Oracle
  requires a FROM clause on every SELECT -- including each UNION arm. The
  old code appended `FROM dual` only inside shape discovery AND built the
  wrapper by slicing a fixed-length tail, which truncated it into SQL
  garbage (`Acc' UNION SEL`). The suffix is now decided in ONE place
  (`UnionContext.union_select()`), driven by `shape.from_dual`, and used by
  every payload site: shape validation, string-column discovery, dialect
  probing, table/column enumeration, row extraction, and the final proof
  payload. Wrapper reconstruction strips the EXACT tail it appended.
- **`_executed()` gate -- error pages can no longer fake success**:
  `Response.ok` only means "no transport error", so HTTP 500 pages passed
  every `r.ok` check. Error pages frequently echo payload fragments (stack
  traces, query echoes, ORA-/pg-identifier messages); a reflected marker
  then poisoned dialect detection and extraction. Every UNION payload site
  now requires 2xx/3xx + no SQL-error signature before trusting a response.
- **Oracle catalog handling**: larger marker caps (Oracle `LISTAGG` over
  `all_tables`/`all_tab_columns` overflows the old 500/1200-char caps;
  VARCHAR2 tops out at 4000), UPPERCASE identifier lookups
  (`all_tab_columns WHERE table_name=UPPER(...)`, results lowercased before
  fuzzy pairing), and credential-table ranking that prefers `user*`/`admin*`
  prefixes so decoys like `PRODUCT_USER_PROFILE` never shadow
  `USERS_<random>`.
- **PostgreSQL schema coverage**: table enumeration now lists every user
  schema (`table_schema NOT IN ('pg_catalog','information_schema')`) instead
  of only `public` -- apps routinely deploy data into named schemas.
- **Multi-dialect mock Academy labs** (`tests/test_dialect_labs.py`): a
  strict per-dialect SQL grammar emulator for Oracle / PostgreSQL / MySQL.
  Each mock REJECTS foreign-dialect payloads exactly like the real DBMS
  (missing `FROM dual` -> `ORA-00923`), evaluates the engine's extraction
  expressions against a randomized catalog (uppercase `USERS_X7Q2MA` on
  Oracle), flips the lab status on admin login, and asserts the objective is
  solved end-to-end on every dialect. 12 new tests; suite total: 171 passing.
- The 0.7.1 failure on Oracle is a named regression test now: a FROM-less
  UNION arm on the Oracle mock raises `ORA-00923`, forcing shape discovery
  through the `FROM dual` retry, and the exact wrapper reconstruction is
  unit-tested (`test_oracle_wrapper_reconstruction_is_exact`).

## What's new in 0.7.1 (objective completion / lab solver)

Detection and proof are not the goal -- **completing the exploit** is. When
the target is a training lab (PortSwigger Web Security Academy & friends),
bughound now drives the exploitation all the way to the platform's own
**"Solved"** banner and records the before/after evidence:

- **Solve phase** (`bughound/solving.py`): after the exploit + chain phases,
  the lab objective (parsed from the `academyLabHeader` markup) is checked
  live; if still open, bughound escalates through its full exploitation
  ladder -- UNION credential extraction -> admin login -> boolean-blind
  extraction -- re-checking the status after each attempt, and records the
  outcome as `result.objective` plus a dedicated report section
  ("Objective completion").
- **UNION shape-discovery fix**: the unquoted payload variant used to be
  tried first; on string contexts it stays *inside* the SQL literal (HTTP
  200 for every column count), so shape discovery locked onto bogus
  candidates and UNION extraction silently bailed out to the weaker
  tautology proof. Quoted variants are now tried first, which makes
  credential extraction + account takeover work on
  string-context endpoints (the overwhelming majority).
- **Marker-pollution fix**: pages that reflect the raw payload (search-term
  echo) made the extraction regexes capture SQL syntax (`'||version()||'`)
  instead of the evaluated UNION result. `_marker_match` now rejects
  pollution fingerprint matches (raw and HTML-escaped quote/concat
  fragments, SQL function names) and prefers the evaluated row.
- **Fuzzy credential-column pairing**: labs randomize schema names
  (`users_fzvkog`, `username_kd9fj2`, `password_hsallo`); exact-name-only
  pairing found nothing. Column discovery now fuzzy-matches user-ish and
  password-ish columns (user columns ranked before email, whose values are
  often NULL).
- Verified end-to-end against a live Academy lab: 2-column PostgreSQL UNION
  shape -> `users_<rnd>` table -> randomized credential columns ->
  administrator password extracted -> login -> lab status `is-solved`.
  12 new tests (including a mock Academy lab with a real status flip);
  suite total: 158 passing.

## What's new in 0.7.0 (sniper-squad edition)

Two battle-tested methodologies were folded into the agent's DNA --
[**Sn1per**](https://github.com/1N3/Sn1per) (phased offensive automation,
workspaces, continuous monitoring) and
[**Bug-Bounty-Agents**](https://github.com/matty69v/Bug-Bounty-Agents)
(phase-organized specialist personas, exploit chaining, hard scope
guardrails) -- and turned from shell-script / prompt folklore into
deterministic Python:

### Sn1per DNA: modes, workspaces, continuous monitoring

- **Scan modes** (`--mode stealth|normal|aggressive|nuke`), Sn1per-style:
  `stealth` = passive-only and throttled to concurrency 2 (WAF-friendly);
  `normal` = passive + active detection without the exploit phase;
  `aggressive` = the full pipeline; `nuke` = aggressive + opt-in
  default-credential checks + external tools forced on. Legacy
  `--aggressive`/`--no-exploit` flags keep working unchanged.
- **Airstrike multi-target scans** (`--targets-file targets.txt`): every
  line is authorized individually against the same scope/denylist and the
  run ends with a combined per-target summary.
- **Workspaces** (`--workspace <name>`): reports land under
  `reports/<workspace>/` with a `<host>-latest.json` snapshot.
- **Continuous monitoring**: `bughound diff old.json new.json` reports new
  findings, resolved findings, newly-exploited proofs and attack-surface
  additions/removals (subdomains, admin paths, API docs, backups...) --
  yesterday's surface vs today's, Sn1per-ASM style.
- **`bughound recon <url>`**: the recon phase as a standalone, strictly
  passive command with a console attack-surface summary.

### Bug-Bounty-Agents DNA: squads, planner, chainer

- **Squad orchestration** (`bughound/agents/squads.py`): every module is
  staffed on a named squad and runs in phases -- **RECON + CONFIG SQUAD**
  (passive, phase 1), then the **INJECTION + ACCESS SQUAD** hunters
  (phase 2), so intelligence steers payload work exactly like the
  recon-advisor -> web-hunter hand-off in the reference workflow.
- **Attack planner** (`agents/planner.py`): after phase 1 the planner
  writes a recon-informed **attack plan** (focus areas, tech-specific
  notes for WordPress/Spring/Next.js/..., WAF advice) into the scan and
  the report's new *Attack plan* section.
- **Exploit chainer** (`agents/exploit_chainer.py`): combines
  individually-proven findings into **attack chains** with full
  provenance (`chain_of` fingerprints):
  - path traversal -> credential-file read -> **account takeover**
    (proven end-to-end, CRITICAL),
  - SSRF -> **internal admin panel** on the target's own loopback (HIGH),
  - reflected XSS + cookie without HttpOnly -> **session hijacking**
    (evidence-composed, HIGH),
  - source-map/backup exposure -> **secret disclosure** (HIGH),
  - open redirect adjacent to OAuth -> **code interception** (candidate).
- **Six new active modules** (persona-flavoured, all differential and
  FP-guarded): `jwt-attacks` (alg=none confusion, guessable HMAC secret,
  kid hints -- only tokens the target itself issued, validated against a
  wrong-secret control first), `graphql-hunter` (endpoint discovery,
  introspection, GET introspection, field suggestions), `xxe-prober`
  (file-disclosure + error-based canary probes with no-DOCTYPE and
  harmless-entity controls), `host-header-poison` (Host /
  X-Forwarded-Host reflection into Location/body/cookie sinks,
  repeat-verified), `prototype-pollution` (server-side merge-echo proof +
  honestly-labelled client-side candidates), and `default-logins`
  (strictly opt-in via `--brute`/nuke mode: 4 pairs, failed-login-baseline
  verified, no lockout risk).
- **Bounty submission drafts**: every verified/exploited critical or high
  finding now carries a triage-ready submission skeleton (the
  report-generator persona), and the methodology appendix documents the
  chaining phase.

The false-positive machinery, denylist/authorization gate and safe-payload
rules from 0.5/0.6 apply to everything above unchanged: chains re-use only
already-proven read-only primitives, JWT attacks touch only tokens the
target issued, and default-credential checks are off unless explicitly
enabled.

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

# Sn1per-style modes: stealth | normal | aggressive | nuke
bughound scan https://example.com --authorize-host example.com --i-am-authorized --mode stealth
bughound scan https://example.com --authorize-host example.com --i-am-authorized --mode nuke

# Aggressive scan (active detection + exploit phase) using a scope file
bughound scan https://example.com --scope scope.yml --i-am-authorized --aggressive

# Aggressive but detection-only (skip the exploit phase)
bughound scan https://example.com --authorize-host example.com --i-am-authorized --aggressive --no-exploit

# Airstrike: multi-target file (each line authorized individually)
bughound scan https://example.com --targets-file targets.txt --authorize-host '*.example.com' --i-am-authorized

# Workspace + continuous monitoring (Sn1per-style diff between runs)
bughound scan https://example.com --authorize-host example.com --i-am-authorized \
    --mode normal --workspace prod-monitor
bughound diff reports/prod-monitor/example.com-latest.json reports/prod-monitor/<newer>.json

# Recon-only pass (passive attack-surface map, no payloads)
bughound recon https://example.com --authorize-host example.com --i-am-authorized

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

# Opt-in default-credential checks (Sn1per -b analogue; 4 pairs, baseline-verified)
bughound scan https://example.com --authorize-host example.com --i-am-authorized --aggressive --brute

# Reports are written to ./reports/<host>-<timestamp>.{md,json}
```

Authorization can be provided by any of: `--scope <file>`, one or more
`--authorize-host <glob>`, or the `BUGHOUND_AUTHORIZED_HOSTS` env var. You must
also pass `--i-am-authorized`.

### Solving a PortSwigger training lab (quick start)

**Step 0 -- make sure the instance is ALIVE (one request, do this first):**

```
python -m bughound check "https://<LAB-ID>.web-security-academy.net/"
```

- `ALIVE -- lab detected: <title> (not solved yet)` -> proceed below.
- `DEAD / EXPIRED LAB` -> click **Access the lab** (or **Restart the lab**)
  on the lab's portswigger.net page, copy the **NEW** URL it opens (every
  fresh instance gets a NEW random subdomain), and re-run `check`. No tool
  can solve a dead instance. Keep the lab browser tab open while scanning --
  instances stop shortly after the browser session ends.

**Step 1 -- scan and solve:**

```
python -m bughound scan "https://<LAB-ID>.web-security-academy.net/" \
    --aggressive --i-am-authorized --timeout 60 --solve-budget 300
```

- The lab is SOLVED when the terminal prints
  `OBJECTIVE COMPLETED -- lab '<title>' is SOLVED` and the report's
  "Objective completion" section shows the platform's own `is-solved`
  banner as evidence.
- If the run ends with the `LAB INSTANCE IS DEAD / EXPIRED / STOPPED`
  banner (or dies mid-scan with it), the instance expired -- spawn a FRESH
  one and re-run against the new URL.
- Without `--aggressive` the exploit/solve phases are disabled
  (detection-only mode) and the lab will NOT be completed.
- If the lab rate-limits the scan ("throttle events" note at the end), wait
  a few minutes, spawn a fresh instance and re-run with lower
  `--concurrency`.

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
authorize + denylist gate -> apply mode (stealth|normal|aggressive|nuke)
  → crawl (same-origin) → discover URLs + injectable params/forms
      → PHASE 1 squads (passive, always):
          RECON SQUAD  : robots-sitemap, dns-recon, subdomain-enum, whois-recon,
                         wayback-urls, tech-fingerprint, waf-detection, http-methods,
                         js-endpoints, admin-panels, api-discovery, backup-files,
                         sourcemap-exposure, email-harvest
          CONFIG SQUAD : security-headers, tls, cookies, cors, info-disclosure, secrets
          (writes structured attack-surface data into result.recon)
      → attack planner (aggressive): recon-informed plan (focus areas, tech notes,
          WAF advice) -> report "Attack plan" section
      → PHASE 2 squads (aggressive only):
          INJECTION SQUAD : sqli, nosqli, command-injection, xss, ssrf,
                            path-traversal, header-injection, open-redirect,
                            xxe-prober, jwt-attacks
          ACCESS SQUAD    : advisory, graphql-hunter, host-header-poison,
                            prototype-pollution, default-logins (--brute only)
      → exploit phase (--aggressive only, disable with --no-exploit):
          re-target every finding with a safe impact-proof exploit
          (UNION extraction, `id` capture, file reads, loopback fetches...)
      → chain phase (exploit-chainer): combines proven findings into attack chains
          (traversal->credentials->takeover, SSRF->internal admin, XSS->session theft...)
      → external tools (nuclei always; nmap/sqlmap in aggressive)
      → verification phase (control experiments on non-exploited findings):
          negative controls, repeat consistency, baseline cleanliness,
          fresh canaries, directionality — flagged findings are downgraded
      → code mapping (--source-dir): findings pinned to file+line+sink,
          or behaviour-derived sink reconstruction for black-box targets
      → dedupe findings → JSON + Markdown report
          (executive summary, attack plan, attack chains, per-finding PoC:
           curl + raw HTTP pair + extracted data + repro steps + impact +
           bounty submission draft, vulnerable-code-location section,
           false-positive-analysis table, methodology appendix)
```

Modules live in `bughound/modules/{passive,active}/` and self-register via a
decorator, so adding a check is a single small file. The exploit engine lives
in `bughound/exploits/` (one module per proof technique, plus
`evidence.py` which standardizes the curl / raw-HTTP-pair / repro-steps
artefacts). The false-positive verifier lives in `bughound/verification.py`;
the source-code mapper in `bughound/codemapper.py`. The 0.7 specialist layer
lives in `bughound.agents` (squads / planner / exploit-chainer) and the
Sn1per-style mode/diff machinery in `bughound.modes` + `bughound.diff`.
Recon helpers (DoH DNS lookup, crt.sh subdomain query, fingerprint catalog)
live in `bughound/modules/recon_utils.py`.

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
