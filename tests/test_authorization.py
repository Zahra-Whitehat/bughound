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
