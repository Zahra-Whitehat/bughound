import pytest

from bughound.authorization import AuthorizationError, Scope, authorize, host_of, load_scope


def test_host_of():
    assert host_of("https://Example.com:8443/path") == "example.com"
    assert host_of("example.com/x") == "example.com"


def test_scope_glob():
    scope = Scope(allowed_hosts=["*.example.com", "127.0.0.1"])
    assert scope.permits("api.example.com")
    assert scope.permits("127.0.0.1")
    assert not scope.permits("evil.com")


def test_authorize_requires_scope_and_confirmation():
    scope = Scope(allowed_hosts=["example.com"])
    with pytest.raises(AuthorizationError):
        authorize("https://evil.com", scope, confirmed=True)
    with pytest.raises(AuthorizationError):
        authorize("https://example.com", scope, confirmed=False)
    note = authorize("https://example.com", scope, confirmed=True)
    assert "Authorized" in note


def test_load_scope_env(monkeypatch):
    monkeypatch.setenv("BUGHOUND_AUTHORIZED_HOSTS", "a.com, b.com")
    scope = load_scope(explicit_hosts=["c.com"])
    assert scope.permits("a.com") and scope.permits("c.com")


def test_denylist_overrides_allowed_scope():
    scope = Scope(allowed_hosts=["*.example.com"], denied_hosts=["admin.example.com"])
    # Host is in allowed scope but also denied -> denied wins.
    assert scope.permits("admin.example.com")
    assert scope.host_denied("admin.example.com")
    with pytest.raises(AuthorizationError):
        authorize("https://admin.example.com/", scope, confirmed=True)


def test_denylist_host_glob_and_case():
    scope = Scope(allowed_hosts=["*"], denied_hosts=["*.internal.example.com"])
    assert scope.url_denied("https://SECRET.internal.example.com/x")
    assert not scope.url_denied("https://example.com/x")


def test_denylist_url_prefix_normalization():
    scope = Scope(
        allowed_hosts=["example.com"],
        denied_urls=["https://example.com/private"],
    )
    assert scope.url_denied("https://example.com/private")
    assert scope.url_denied("https://example.com/private/")
    assert scope.url_denied("https://EXAMPLE.com/private/sub?x=1#frag")
    assert not scope.url_denied("https://example.com/public")


def test_multiple_deny_entries_and_env(monkeypatch):
    monkeypatch.setenv("BUGHOUND_DENIED_HOSTS", "one.example.com, two.example.com")
    scope = load_scope(
        explicit_hosts=["example.com"],
        denied_hosts=["three.example.com"],
        denied_urls=["https://example.com/x", "https://example.com/y"],
    )
    assert scope.url_denied("https://one.example.com/")
    assert scope.url_denied("https://two.example.com/")
    assert scope.url_denied("https://three.example.com/")
    assert scope.url_denied("https://example.com/x")
    assert scope.url_denied("https://example.com/y")
