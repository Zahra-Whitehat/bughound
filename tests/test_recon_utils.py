"""Unit tests for the new recon_utils helpers: favicon hashing, the active
subdomain-brute-force wordlist, and the subdomain-takeover fingerprint
catalog. None of these need network access.
"""

from __future__ import annotations

import base64

from urllib.parse import urlparse

from bughound.modules.recon_utils import (
    COMMON_SUBDOMAIN_WORDLIST,
    SUBDOMAIN_TAKEOVER_FINGERPRINTS,
    _mmh3_32,
    favicon_hash,
)
from bughound.modules.passive.wayback_urls import API_RE, INTERESTING_RE


def test_mmh3_32_matches_known_vectors():
    # Independently verified against a reference MurmurHash3 x86_32 impl.
    assert _mmh3_32(b"", 0) == 0
    assert _mmh3_32(b"a", 0) & 0xFFFFFFFF == 1009084850
    assert _mmh3_32(b"abc", 0) & 0xFFFFFFFF == 3017643002
    assert _mmh3_32(b"hello world", 0) & 0xFFFFFFFF == 1586663183


def test_mmh3_32_returns_signed_value():
    # Shodan/mmh3 report signed 32-bit ints; a hash whose unsigned form has
    # the high bit set must come back negative.
    unsigned = _mmh3_32(b"abc", 0) & 0xFFFFFFFF
    assert unsigned >= 0x80000000  # sanity check on the fixture itself
    signed = _mmh3_32(b"abc", 0)
    assert signed < 0
    assert signed + 0x100000000 == unsigned


def test_favicon_hash_empty_content_returns_none():
    assert favicon_hash(b"") is None


def test_favicon_hash_is_stable_and_matches_shodan_recipe():
    content = b"\x00\x00\x01\x00fake-favicon-bytes-for-testing"
    h1 = favicon_hash(content)
    h2 = favicon_hash(content)
    assert h1 == h2  # deterministic
    # Shodan's recipe: mmh3_32(base64.encodebytes(raw_bytes))
    expected = _mmh3_32(base64.encodebytes(content))
    assert h1 == expected


def test_favicon_hash_differs_for_different_content():
    assert favicon_hash(b"icon-a") != favicon_hash(b"icon-b")


def test_subdomain_wordlist_has_no_duplicates_and_is_nonempty():
    assert len(COMMON_SUBDOMAIN_WORDLIST) > 50
    assert len(COMMON_SUBDOMAIN_WORDLIST) == len(set(COMMON_SUBDOMAIN_WORDLIST))
    assert all(w == w.lower() for w in COMMON_SUBDOMAIN_WORDLIST)


def test_takeover_fingerprints_well_formed():
    assert len(SUBDOMAIN_TAKEOVER_FINGERPRINTS) >= 15
    seen_services = set()
    for service, suffixes, needles in SUBDOMAIN_TAKEOVER_FINGERPRINTS:
        assert service not in seen_services, f"duplicate service entry: {service}"
        seen_services.add(service)
        assert suffixes, f"{service} has no CNAME suffixes"
        assert all(s == s.lower() for s in suffixes)


def test_takeover_fingerprint_matches_expected_cname_suffix():
    # Simulates the matching logic used in SubdomainEnumModule._check_takeovers.
    cname = "myapp.herokudns.com"
    matched = [
        service
        for service, suffixes, _ in SUBDOMAIN_TAKEOVER_FINGERPRINTS
        if any(suffix in cname for suffix in suffixes)
    ]
    assert "Heroku" in matched


def test_takeover_fingerprint_no_false_match_for_unrelated_cname():
    cname = "internal-lb.example-corp-internal.net"
    matched = [
        service
        for service, suffixes, _ in SUBDOMAIN_TAKEOVER_FINGERPRINTS
        if any(suffix in cname for suffix in suffixes)
    ]
    assert matched == []


def test_wayback_interesting_regex_flags_backup_and_config_files():
    for url in (
        "https://example.com/backup.sql",
        "https://example.com/config.env",
        "https://example.com/site_old.bak",
        "https://example.com/secrets.pem",
        "https://example.com/dump.tar.gz",
    ):
        assert INTERESTING_RE.search(urlparse(url).path), url


def test_wayback_interesting_regex_ignores_normal_assets():
    for url in (
        "https://example.com/css/site.css",
        "https://example.com/images/logo.png",
        "https://example.com/about-us",
    ):
        assert not INTERESTING_RE.search(urlparse(url).path), url


def test_wayback_api_regex_flags_api_like_paths():
    for url in (
        "https://example.com/api/v1/users",
        "https://example.com/v2/orders",
        "https://example.com/admin/dashboard",
        "https://example.com/graphql",
    ):
        assert API_RE.search(urlparse(url).path), url


def test_wayback_api_regex_ignores_normal_paths():
    assert not API_RE.search(urlparse("https://example.com/about-us").path)
