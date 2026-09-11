"""Scan orchestrator: authorization -> crawl -> modules -> external tools."""

from __future__ import annotations

import asyncio
from datetime import datetime, timezone
from urllib.parse import urlparse

from . import integrations
from .authorization import Scope, authorize
from .crawler import crawl
from .http_client import HttpClient
from .models import ScanConfig, ScanResult, Target
from .modules.base import ScanContext, build_modules


def _make_target(url: str, note: str) -> Target:
    parsed = urlparse(url if "://" in url else f"http://{url}")
    scheme = parsed.scheme or "http"
    port = parsed.port or (443 if scheme == "https" else 80)
    return Target(
        url=url,
        scheme=scheme,
        host=parsed.hostname or "",
        port=port,
        authorized=True,
        authorization_note=note,
    )


async def run_scan(
    config: ScanConfig,
    scope: Scope,
    confirmed: bool,
    progress=None,
) -> ScanResult:
    """Run a full scan. Raises AuthorizationError if the target is out of scope."""

    def emit(msg: str) -> None:
        if progress:
            progress(msg)

    note = authorize(config.target_url, scope, confirmed)
    target = _make_target(config.target_url, note)
    result = ScanResult(target=target, config=config)

    client = HttpClient(
        timeout=config.timeout,
        user_agent=config.user_agent,
        extra_headers=config.extra_headers,
        blocked=scope.url_denied,
    )
    try:
        if scope.denied_hosts or scope.denied_urls:
            emit(
                f"Denylist active: {len(scope.denied_hosts)} host pattern(s), "
                f"{len(scope.denied_urls)} URL prefix(es) will never be contacted."
            )
        emit("Crawling target...")
        urls, request_targets, seed_html, seed_headers = await crawl(
            client,
            config.target_url,
            config.max_urls,
            config.max_depth,
            is_denied=scope.url_denied,
        )
        ctx = ScanContext(
            client=client,
            config=config,
            target=target,
            base_url=config.target_url,
            urls=urls,
            request_targets=request_targets,
            seed_html=seed_html,
            seed_headers=seed_headers,
            log=emit,
        )
        result.stats = {"urls_crawled": len(urls), "injectable_targets": len(request_targets)}
        emit(f"Discovered {len(urls)} URLs, {len(request_targets)} injectable targets.")

        modules = build_modules(config)
        sem = asyncio.Semaphore(max(1, config.concurrency))

        async def run_module(mod):
            async with sem:
                emit(f"Running module: {mod.name}")
                try:
                    return mod.name, await mod.run(ctx)
                except Exception as exc:  # noqa: BLE001
                    result.errors.append(f"{mod.name}: {type(exc).__name__}: {exc}")
                    return mod.name, []

        for name, findings in await asyncio.gather(*(run_module(m) for m in modules)):
            result.modules_run.append(name)
            for f in findings:
                result.add(f)

        if config.use_external_tools:
            await _run_external(config, ctx, result, emit, scope)
    finally:
        await client.aclose()

    result.finished_at = datetime.now(timezone.utc)
    result.stats["findings"] = len(result.findings)
    return result


async def _run_external(config, ctx, result, emit, scope) -> None:
    if scope.url_denied(config.target_url):
        result.errors.append("External tools skipped: target is on the denylist.")
        return
    host = integrations.host_from_url(config.target_url)
    missing = integrations.missing_tools_note()
    if missing:
        result.errors.append(f"External tools not installed (skipped): {', '.join(missing)}")

    tasks = [integrations.run_nuclei(config.target_url)]
    if config.aggressive:
        if not scope.host_denied(host):
            tasks.append(integrations.run_nmap(host))
        for rt in ctx.request_targets[:3]:
            if not scope.url_denied(rt.url):
                tasks.append(integrations.run_sqlmap(rt.url, rt.method, rt.params))
    emit("Running external tools (nuclei/nmap/sqlmap where available)...")
    for group in await asyncio.gather(*tasks, return_exceptions=True):
        if isinstance(group, Exception):
            result.errors.append(f"external tool error: {group}")
            continue
        for f in group:
            result.add(f)
            if f.module not in result.modules_run:
                result.modules_run.append(f.module)
