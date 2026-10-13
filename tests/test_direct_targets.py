"""Regression tests: bare-path ``--exploit-endpoint`` values must resolve
against the scan target.

Bug: ``--exploit-endpoint /product/stock`` was parsed as
``http:///product/stock`` (no host), so every exploit-phase request failed
silently (the HTTP client maps invalid URLs to a status-0 response) and the
whole direct-exploit chain did nothing -- with no error shown to the
operator. The direct target must always carry scheme + host.
"""

from __future__ import annotations

import pytest

from bughound.engine import _register_direct_targets
from bughound.http_client import HttpClient
from bughound.models import Category, ScanConfig, ScanResult, Target
from bughound.modules.base import ScanContext

BASE = "https://lab.example.com/"


def _target() -> Target:
    return Target(
        url=BASE, scheme="https", host="lab.example.com", port=443, authorized=True
    )


def _make_ctx(config: ScanConfig) -> ScanContext:
    client = HttpClient(timeout=5.0)
    return ScanContext(client=client, config=config, target=_target(), base_url=BASE)


def _config(**kw) -> ScanConfig:
    defaults = dict(
        target_url=BASE,
        aggressive=True,
        exploit_endpoints=["/product/stock"],
        exploit_body="<stockCheck><productId>1</productId><storeId>{INJ}</storeId></stockCheck>",
        exploit_encode="xml-entities",
    )
    defaults.update(kw)
    return ScanConfig(**defaults)


def test_bare_path_endpoint_resolves_against_target():
    config = _config()
    ctx = _make_ctx(config)
    result = ScanResult(target=_target(), config=config)
    _register_direct_targets(config, ctx, result, lambda *_: None)

    assert len(result.findings) == 1
    assert result.findings[0].category == Category.SQLI
    # THE regression: must be scheme://host/path, never "http:///path".
    assert result.findings[0].url == "https://lab.example.com/product/stock"
    rt = ctx.request_targets[0]
    assert rt.url == "https://lab.example.com/product/stock"
    assert rt.body_template == config.exploit_body
    assert rt.encoding == "xml-entities"
    assert rt.source == "direct"
    assert rt.params["INJ"] == "1"


def test_path_without_leading_slash_resolves_too():
    config = _config(exploit_endpoints=["product/stock"])
    ctx = _make_ctx(config)
    result = ScanResult(target=_target(), config=config)
    _register_direct_targets(config, ctx, result, lambda *_: None)
    assert result.findings[0].url == "https://lab.example.com/product/stock"


def test_full_url_endpoint_still_wins():
    config = _config(exploit_endpoints=["https://other.example.com/stock"])
    ctx = _make_ctx(config)
    result = ScanResult(target=_target(), config=config)
    _register_direct_targets(config, ctx, result, lambda *_: None)
    assert result.findings[0].url == "https://other.example.com/stock"


def test_path_with_query_string_seeds_base_value():
    config = _config(
        exploit_endpoints=["/product/stock?productId=7"], exploit_param="productId"
    )
    ctx = _make_ctx(config)
    result = ScanResult(target=_target(), config=config)
    _register_direct_targets(config, ctx, result, lambda *_: None)
    assert result.findings[0].url == "https://lab.example.com/product/stock"
    assert ctx.request_targets[0].params["INJ"] == "7"


def test_no_hostless_url_ever_registered():
    """Guard: no registered direct target may lack a netloc."""
    for ep in ("/a", "a", "/a/b?c=d"):
        config = _config(exploit_endpoints=[ep])
        ctx = _make_ctx(config)
        result = ScanResult(target=_target(), config=config)
        _register_direct_targets(config, ctx, result, lambda *_: None)
        url = result.findings[0].url
        assert "://" in url and url.split("://", 1)[1].split("/")[0], url
