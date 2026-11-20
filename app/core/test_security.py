import pytest
from fastapi.testclient import TestClient

from app.core.config import get_settings
from app.main import app

HEADER = "X-RapidAPI-Proxy-Secret"


@pytest.fixture
def secrets(monkeypatch: pytest.MonkeyPatch):
    def _set(value: str):
        monkeypatch.setenv("RAPIDAPI_PROXY_SECRET", value)
        get_settings.cache_clear()

    yield _set
    get_settings.cache_clear()


def _status(secret: str | None) -> int:
    headers = {HEADER: secret} if secret is not None else {}
    with TestClient(app) as client:
        return client.post("/v1/email/verify", json={"email": "a@b.co"}, headers=headers).status_code


def test_any_secret_in_list_is_accepted(secrets):
    secrets("aaa, bbb ,ccc")
    for s in ("aaa", "bbb", "ccc"):
        assert _status(s) != 403


def test_unknown_or_missing_secret_rejected(secrets):
    secrets("aaa,bbb")
    assert _status("zzz") == 403
    assert _status(None) == 403
    assert _status("aaa,bbb") == 403


def test_empty_config_fails_closed(secrets):
    secrets(" , ")
    assert _status("") == 403
