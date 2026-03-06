import pytest

from uiauth import models


def test_get_cred_from_kwargs():
    assert models.get_cred(["username"], {"username": "admin"}) == "admin"


def test_get_cred_from_env(monkeypatch):
    monkeypatch.setenv("USERNAME", "envuser")
    assert models.get_cred(["USERNAME"], {}) == "envuser"


def test_get_cred_kwargs_takes_precedence(monkeypatch):
    monkeypatch.setenv("USERNAME", "envuser")
    assert models.get_cred(["USERNAME"], {"USERNAME": "kwarguser"}) == "kwarguser"


def test_get_cred_not_found():
    assert models.get_cred(["nonexistent_key_xyz"], {}) is None


def test_get_cred_first_match_wins():
    result = models.get_cred(
        ["user", "username"], {"username": "second", "user": "first"}
    )
    assert result == "first"


def test_env_loader_from_kwargs():
    env = models.env_loader(username="user1", password="pass1")
    assert env.username == "user1"
    assert env.password == "pass1"


def test_env_loader_from_env(monkeypatch):
    monkeypatch.setenv("USERNAME", "envuser")
    monkeypatch.setenv("PASSWORD", "envpass")
    env = models.env_loader()
    assert env.username == "envuser"
    assert env.password == "envpass"


def test_env_loader_kwargs_over_env(monkeypatch):
    monkeypatch.setenv("USERNAME", "envuser")
    monkeypatch.setenv("PASSWORD", "envpass")
    env = models.env_loader(username="kwuser", password="kwpass")
    assert env.username == "kwuser"
    assert env.password == "kwpass"


def test_ws_session_defaults():
    session = models.WSSession()
    assert session.client_auth == {}
    assert session.invalid == {}


def test_fallback_defaults():
    fallback = models.Fallback()
    assert fallback.button == "LOGIN"
    assert fallback.path == "/"


def test_fallback_custom_values():
    fallback = models.Fallback(button="ENTER", path="/home")
    assert fallback.button == "ENTER"
    assert fallback.path == "/home"


def test_redirect_exception_all_attributes():
    exc = models.RedirectException(
        destination="/login", source="/protected", detail="expired"
    )
    assert exc.destination == "/login"
    assert exc.source == "/protected"
    assert exc.detail == "expired"


def test_redirect_exception_defaults():
    exc = models.RedirectException(destination="/login")
    assert exc.source == "/"
    assert exc.detail == ""
