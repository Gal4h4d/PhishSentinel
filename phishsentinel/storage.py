"""Registro de detecciones y lista de excepciones (SQLite local)."""
import sqlite3
import time
from contextlib import closing

from .config import DB_PATH


def _conn():
    c = sqlite3.connect(DB_PATH)
    c.execute("CREATE TABLE IF NOT EXISTS detections(ts REAL, url TEXT, level TEXT, threat TEXT, score REAL)")
    c.execute("CREATE TABLE IF NOT EXISTS whitelist(domain TEXT PRIMARY KEY)")
    return c


def log_detection(v):
    with closing(_conn()) as c, c:
        c.execute("INSERT INTO detections VALUES (?,?,?,?,?)", (time.time(), v.url, v.level, v.threat, v.score))


def is_whitelisted(domain: str) -> bool:
    with closing(_conn()) as c:
        return c.execute("SELECT 1 FROM whitelist WHERE domain=?", (domain,)).fetchone() is not None


def add_whitelist(domain: str):
    with closing(_conn()) as c, c:
        c.execute("INSERT OR IGNORE INTO whitelist VALUES (?)", (domain,))


def recent(n: int = 50):
    with closing(_conn()) as c:
        return c.execute("SELECT ts,url,level,threat,score FROM detections ORDER BY ts DESC LIMIT ?", (n,)).fetchall()
