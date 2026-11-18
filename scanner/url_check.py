"""網址檢查：本機規則 + Google Safe Browsing（有 API 金鑰時）。

注意：Safe Browsing API 僅限非商業用途；商業用途需改用 Google Web Risk。
"""
import ipaddress
import json
import urllib.request
from dataclasses import dataclass, field
from urllib.parse import urlsplit

API_URL = "https://safebrowsing.googleapis.com/v4/threatMatches:find?key={key}"


@dataclass
class UrlVerdict:
    url: str
    safe: bool
    checked_online: bool
    threats: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)


def local_warnings(url: str) -> list[str]:
    parts = urlsplit(url)
    host = parts.hostname or ""
    warnings = []
    if parts.scheme != "https":
        warnings.append("沒有使用 HTTPS 加密連線")
    if "@" in parts.netloc:
        warnings.append("網址含有 @，真正的網站可能在 @ 後面")
    try:
        ipaddress.ip_address(host)
        warnings.append("網址直接使用 IP 位址，不是網域名稱")
    except ValueError:
        pass
    if any(label.startswith("xn--") for label in host.split(".")):
        warnings.append("網域使用 Punycode，可能是偽裝成知名網站的相似字")
    return warnings


def _http_post(url: str, body: str, timeout: int) -> dict:
    req = urllib.request.Request(url, data=body.encode(), headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return json.loads(resp.read() or b"{}")


def check_url(url: str, api_key: str | None, post=_http_post, timeout: int = 10) -> UrlVerdict:
    url = url.strip()
    if "://" not in url:
        url = "https://" + url
    warnings = local_warnings(url)
    if not api_key:
        return UrlVerdict(url, safe=not warnings, checked_online=False, warnings=warnings)

    body = json.dumps({
        "client": {"clientId": "antivirus-mvp", "clientVersion": "0.1"},
        "threatInfo": {
            "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE", "POTENTIALLY_HARMFUL_APPLICATION"],
            "platformTypes": ["ANY_PLATFORM"],
            "threatEntryTypes": ["URL"],
            "threatEntries": [{"url": url}],
        },
    })
    data = post(API_URL.format(key=api_key), body, timeout)
    threats = sorted({m["threatType"] for m in data.get("matches", [])})
    return UrlVerdict(url, safe=not threats, checked_online=True, threats=threats, warnings=warnings)
