"""Capa 2: análisis del contenido HTML (reglas; el ML de contenido queda para más adelante)."""
import re
from urllib.parse import urlparse, parse_qsl, unquote

from bs4 import BeautifulSoup

RISKY_JS = ("eval(", "document.write(", "unescape(", "atob(", "fromcharcode", ".innerhtml", "document.cookie")
_PW = re.compile(r"^password$", re.I)


def analyze_content(html: str, page_url: str):
    """Devuelve (score 0-1, características, motivos)."""
    soup = BeautifulSoup(html, "lxml")
    host = (urlparse(page_url if "://" in page_url else "http://" + page_url).hostname or "").lower()
    reasons, f = [], {}

    ext_pw = 0
    for fm in soup.find_all("form"):
        has_pw = fm.find("input", {"type": _PW}) is not None
        act = (fm.get("action") or "").strip()
        a_host = (urlparse(act).hostname or "").lower() if act.startswith(("http://", "https://", "//")) else ""
        if has_pw and a_host and a_host != host:
            ext_pw += 1
    f["pw_form_external"] = ext_pw
    f["has_password"] = int(soup.find("input", {"type": _PW}) is not None)

    hidden = 0
    for fr in soup.find_all("iframe"):
        st = (fr.get("style") or "").replace(" ", "").lower()
        if fr.get("width") in ("0", "1") or fr.get("height") in ("0", "1") \
                or "display:none" in st or "visibility:hidden" in st:
            hidden += 1
    f["hidden_iframes"] = hidden

    scripts = soup.find_all("script")
    inline_js = " ".join((s.string or "") for s in scripts if not s.get("src")).lower()
    f["risky_js"] = sum(inline_js.count(k) for k in RISKY_JS)
    ext_scripts = [s for s in scripts if (s.get("src") or "").startswith(("http", "//"))
                   and (urlparse(s["src"]).hostname or host).lower() != host]
    f["ext_scripts"] = len(ext_scripts)
    f["inline_handlers"] = sum(1 for t in soup.find_all(True) for a in t.attrs if a.lower().startswith("on"))

    reflected = 0
    for _, v in parse_qsl(urlparse(page_url).query):
        v = unquote(v)
        if len(v) >= 4 and re.search(r"[<>\"']", v) and v in html:   # vuelve sin codificar
            reflected += 1
    f["reflected_params"] = reflected

    score = 0.0
    if ext_pw:
        score += 0.6
        reasons.append("Formulario de contraseña que envía los datos a otro dominio")
    if reflected:
        score += 0.6
        reasons.append("Un parámetro de la URL se refleja sin codificar en la página (posible XSS)")
    if hidden:
        score += 0.2
        reasons.append(f"{hidden} iframe(s) oculto(s)")
    if f["risky_js"] >= 3:
        score += 0.2
        reasons.append("Scripts con funciones de riesgo (eval, document.write, atob...)")
    if f["ext_scripts"] >= 4:
        score += 0.1
        reasons.append("Carga muchos scripts desde dominios externos")
    f["content_score"] = min(score, 1.0)
    return f["content_score"], f, reasons
