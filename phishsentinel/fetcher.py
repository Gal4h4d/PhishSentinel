"""Descarga el HTML estático de la página. NO ejecuta JavaScript."""
import requests

from .config import FETCH_TIMEOUT, MAX_HTML_BYTES

HEADERS = {"User-Agent": "Mozilla/5.0 PhishSentinel/0.1"}


def fetch_html(url: str):
    if not url.lower().startswith(("http://", "https://")):
        url = "http://" + url
    try:
        with requests.get(url, headers=HEADERS, timeout=FETCH_TIMEOUT, stream=True) as r:
            if "html" not in r.headers.get("Content-Type", "").lower():
                return None
            data = b""
            for chunk in r.iter_content(65536):
                data += chunk
                if len(data) > MAX_HTML_BYTES:
                    break
            return data.decode(r.encoding or "utf-8", errors="replace")
    except Exception:          # URLs malformadas, DNS, SSL, timeouts: la capa 2 no debe tumbar la app
        return None
