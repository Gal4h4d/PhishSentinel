"""Recall de la capa 1 sobre URLs de phishing que NO entraron al entrenamiento.
Uso:  python -m training.phishing_recall_test --n 5000"""
import argparse
import random
from collections import Counter
from pathlib import Path

import pandas as pd

from phishsentinel.engine import Engine

RAW = Path("data/raw")
PROCESSED = Path("data/processed/urls.csv")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--n", type=int, default=5000)
    a = ap.parse_args()

    big = pd.read_csv(RAW / "URL dataset.csv", usecols=["url", "type"])
    phish = set(big.loc[big["type"] == "phishing", "url"])
    used = set(pd.read_csv(PROCESSED, usecols=["url"])["url"])      # lo que pudo entrar al entrenamiento
    unseen = phish - used
    print(f"phishing en URL dataset: {len(phish)} | usadas al preparar: {len(phish & used)} | no vistas: {len(unseen)}")

    small = RAW / "Phishing URLs.csv"
    if small.exists():
        s = set(pd.read_csv(small, usecols=["url"])["url"])
        print(f"Phishing URLs.csv: {len(s)} | ya en URL dataset: {len(s & phish)} | nuevas: {len(s - phish)}")
        unseen |= (s - used)

    pool = sorted(unseen)
    sample = random.Random(5).sample(pool, min(a.n, len(pool)))
    eng, lv = Engine(), Counter()
    for i, u in enumerate(sample, 1):
        try:
            lv[eng.analyze(u, fetch=False).level] += 1
        except Exception:
            lv["error"] += 1
        if i % 1000 == 0:
            print(f"  {i}/{len(sample)}")

    n = sum(lv.values()) - lv["error"]
    print(f"\nAnalizadas: {n} (errores: {lv['error']})")
    for k in ["segura", "sospechosa", "peligrosa"]:
        print(f"{k:>10}: {lv[k]:>5} ({lv[k] / n:.2%})")
    print(f"\nRecall (marcadas como sospechosa o peligrosa): {(n - lv['segura']) / n:.2%}")


if __name__ == "__main__":
    main()