"""Capa 1: características léxicas/estructurales de la URL (+ señales de XSS).
Se usa IGUAL en entrenamiento y en el .exe (así no hay desajuste entre ambos)."""
import math
import re
from collections import Counter
from urllib.parse import urlparse, parse_qsl, unquote

import tldextract

_EXTRACT = tldextract.TLDExtract(suffix_list_urls=())   # usa la lista incluida, sin red

SUSP_WORDS = ("login", "signin", "verify", "secure", "account", "update", "bank",
              "confirm", "password", "paypal", "wallet", "suspend")
SHORTENERS = {"bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd", "cutt.ly", "rb.gy"}

_IP_RE = re.compile(r"^(\d{1,3}\.){3}\d{1,3}$")
_TAG_RE = re.compile(r"<\s*/?\s*(script|img|svg|iframe|body|input|details|video|audio|object|embed)\b")
_EVENT_RE = re.compile(r"(?<![a-z])on(error|load|click|mouse\w+|focus|blur|key\w+|pointer\w+|toggle|begin|start)\s*=")
_JS_RE = re.compile(r"(javascript|vbscript|data)\s*:")
_FUNC_RE = re.compile(r"\b(alert|prompt|confirm|eval)\s*\(|document\.cookie|document\.write|fromcharcode")

FEATURE_NAMES = [
    "url_len", "host_len", "path_len", "query_len", "n_dots", "n_hyphens_host", "n_slashes",
    "n_digits", "digit_ratio", "n_special", "has_at", "has_ip", "n_subdomains", "https",
    "odd_port", "path_depth", "entropy", "punycode", "susp_words", "shortener", "n_params",
    "xss_tag", "xss_event", "xss_js_scheme", "xss_func", "n_angle", "n_encoded",
    "double_enc", "n_quotes",
]


def host_of(url: str) -> str:
    try:
        return (urlparse(url if "://" in url else "http://" + url).hostname or "").lower()
    except ValueError:
        return ""


def entropy(s: str) -> float:
    if not s:
        return 0.0
    n = len(s)
    return -sum(c / n * math.log2(c / n) for c in Counter(s).values())


def _decode(s: str) -> str:
    for _ in range(2):                      # decodifica hasta 2 veces (doble codificación)
        d = unquote(s)
        if d == s:
            break
        s = d
    return s


def extract_url_features(url: str) -> dict:
    url = (url or "").strip()
    try:
        p = urlparse(url if "://" in url else "http://" + url)
        host = (p.hostname or "").lower()
        port = p.port
    except ValueError:
        p, host, port = urlparse("http://invalido"), "", None
    ext = _EXTRACT(host)
    low = _decode(url).lower()
    n = max(len(url), 1)
    digits = sum(ch.isdigit() for ch in url)
    return {
        "url_len": len(url), "host_len": len(host), "path_len": len(p.path or ""),
        "query_len": len(p.query or ""), "n_dots": host.count("."),
        "n_hyphens_host": host.count("-"), "n_slashes": url.count("/"),
        "n_digits": digits, "digit_ratio": digits / n,
        "n_special": sum(url.count(c) for c in "@?&=%;"),
        "has_at": int("@" in (p.netloc or "")), "has_ip": int(bool(_IP_RE.match(host))),
        "n_subdomains": len([s for s in ext.subdomain.split(".") if s]),
        "https": int(p.scheme == "https"), "odd_port": int(port not in (None, 80, 443)),
        "path_depth": len([s for s in (p.path or "").split("/") if s]),
        "entropy": entropy(url), "punycode": int("xn--" in host),
        "susp_words": sum(w in low for w in SUSP_WORDS), "shortener": int(host in SHORTENERS),
        "n_params": len(parse_qsl(p.query)),
        "xss_tag": int(bool(_TAG_RE.search(low))), "xss_event": int(bool(_EVENT_RE.search(low))),
        "xss_js_scheme": int(bool(_JS_RE.search(low))), "xss_func": int(bool(_FUNC_RE.search(low))),
        "n_angle": low.count("<") + low.count(">"), "n_encoded": url.count("%"),
        "double_enc": int("%25" in url), "n_quotes": low.count('"') + low.count("'"),
    }


def to_vector(feats: dict) -> list:
    return [feats[k] for k in FEATURE_NAMES]
