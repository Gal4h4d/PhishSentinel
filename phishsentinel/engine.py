"""Motor de decisión: combina capa 1 (URL + ML) y capa 2 (contenido)."""
import time
from dataclasses import dataclass, field

import joblib

from . import config, storage
from .features_content import analyze_content
from .features_url import extract_url_features, host_of, to_vector
from .fetcher import fetch_html


@dataclass
class Verdict:
    url: str
    level: str                 # segura | sospechosa | peligrosa
    threat: str                # ninguna | phishing | xss
    score: float
    reasons: list = field(default_factory=list)
    ms_url: float = 0.0
    ms_content: float = 0.0
    used_model: bool = False


def _heuristic(f: dict) -> float:
    """Respaldo cuando todavía no hay modelo entrenado."""
    s = 0.35 * f["has_ip"] + 0.25 * f["has_at"] + 0.15 * f["punycode"] + 0.10 * min(f["susp_words"], 3) / 3
    s += 0.15 * (f["n_subdomains"] >= 3) + 0.10 * (not f["https"]) + 0.10 * f["shortener"]
    s += 0.5 * max(f["xss_tag"], f["xss_event"], f["xss_js_scheme"])
    return min(s, 1.0)


def _reasons_url(f: dict) -> list:
    r = []
    if f["has_ip"]: r.append("Usa una dirección IP en lugar de un dominio")
    if f["has_at"]: r.append("Contiene '@' en la dirección (suele ocultar el destino real)")
    if f["punycode"]: r.append("Dominio con punycode (posible suplantación visual)")
    if f["shortener"]: r.append("Acortador de enlaces: no se ve el destino real")
    if f["n_subdomains"] >= 3: r.append("Demasiados subdominios")
    if f["susp_words"] >= 2: r.append("Palabras típicas de phishing en la URL (login, verify, secure...)")
    if not f["https"]: r.append("No usa HTTPS")
    if f["xss_tag"] or f["xss_event"] or f["xss_js_scheme"] or f["xss_func"]:
        r.append("La URL contiene código que parece JavaScript/HTML inyectado")
    if f["double_enc"]: r.append("Doble codificación de caracteres (técnica de ofuscación)")
    return r


class Engine:
    def __init__(self):
        self.bundle = joblib.load(config.MODEL_PATH) if config.MODEL_PATH.exists() else None

    def _url_proba(self, f: dict):
        """Devuelve (probabilidad de ser maliciosa, amenaza más probable)."""
        xss_sig = any(f[k] for k in ("xss_tag", "xss_event", "xss_js_scheme", "xss_func"))
        if self.bundle is None:
            return _heuristic(f), ("xss" if xss_sig else "phishing")
        classes = self.bundle["classes"]
        proba = self.bundle["model"].predict_proba([to_vector(f)])[0]
        p_mal = 1.0 - proba[classes.index("legitimate")]
        mal = {c: p for c, p in zip(classes, proba) if c != "legitimate"}
        top = max(mal, key=mal.get)
        if top == "malicious":                         # modelo binario: inferimos el tipo
            top = "xss" if xss_sig else "phishing"
        return float(p_mal), top

    def analyze(self, url: str, html: str = None, fetch: bool = True) -> Verdict:
        host = host_of(url)
        t0 = time.perf_counter()
        f = extract_url_features(url)
        xss_sig = any(f[k] for k in ("xss_tag", "xss_event", "xss_js_scheme", "xss_func"))
        if host and storage.is_whitelisted(host) and not xss_sig:
            return Verdict(url, "segura", "ninguna", 0.0, ["Dominio en tu lista de excepciones"])
        p_url, threat = self._url_proba(f)
        reasons = _reasons_url(f)
        if self.bundle:
            reasons.insert(0, f"El modelo estima {p_url:.0%} de probabilidad de que sea maliciosa")
        ms_url = (time.perf_counter() - t0) * 1000

        score, ms_content = p_url, 0.0
        if html is None and fetch and p_url < config.SKIP_FETCH_ABOVE:
            html = fetch_html(url)
        if html:
            t1 = time.perf_counter()
            c_score, cf, c_reasons = analyze_content(html, url)
            # el contenido solo puede SUBIR el puntaje: una página limpia no vuelve segura una URL dudosa
            score = max(p_url, config.W_URL * p_url + config.W_CONTENT * c_score)
            if cf["reflected_params"]:
                score, threat = max(score, 0.85), "xss"
            elif cf["pw_form_external"]:
                score, threat = max(score, 0.80), "phishing"
            reasons += c_reasons
            ms_content = (time.perf_counter() - t1) * 1000

        level = ("peligrosa" if score >= config.T_DANGEROUS
                 else "sospechosa" if score >= config.T_SUSPICIOUS else "segura")
        v = Verdict(url, level, threat if level != "segura" else "ninguna", round(score, 3),
                    reasons, ms_url, ms_content, self.bundle is not None)
        storage.log_detection(v)
        return v
