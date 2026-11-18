import json

import pytest

from scanner.url_check import check_url, local_warnings


@pytest.mark.parametrize(
    "url,expect",
    [
        ("http://192.168.1.10/login", "IP"),
        ("https://xn--pple-43d.com", "Punycode"),
        ("https://paypal.com@evil.example", "@"),
        ("http://bank.example.com", "HTTPS"),
    ],
)
def test_local_warnings(url, expect):
    assert any(expect in w for w in local_warnings(url))


def test_clean_https_url_no_warnings():
    assert local_warnings("https://www.google.com/search?q=1") == []


def test_safe_browsing_match(monkeypatch):
    sent = {}

    def fake_post(url, body, timeout):
        sent["url"], sent["body"] = url, json.loads(body)
        return {"matches": [{"threatType": "SOCIAL_ENGINEERING"}]}

    v = check_url("https://bad.example", api_key="KEY", post=fake_post)
    assert not v.safe and v.threats == ["SOCIAL_ENGINEERING"]
    assert "key=KEY" in sent["url"]
    assert sent["body"]["threatInfo"]["threatEntries"] == [{"url": "https://bad.example"}]


def test_safe_browsing_no_match(monkeypatch):
    v = check_url("https://www.google.com", api_key="KEY", post=lambda *a, **k: {})
    assert v.safe and v.checked_online


def test_without_key_uses_only_local_rules():
    v = check_url("http://1.2.3.4/x", api_key=None)
    assert not v.checked_online and not v.safe and v.warnings


def test_adds_scheme_when_missing():
    v = check_url("www.google.com", api_key=None)
    assert v.url == "https://www.google.com" and v.safe
