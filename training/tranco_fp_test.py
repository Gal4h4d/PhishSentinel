"""Tasa de falsos positivos sobre dominios populares reales (Tranco).
Todo dominio popular es, en principio, legítimo: cada alerta es un falso positivo.
Uso:  python -m training.tranco_fp_test --n 10000"""
import argparse
from collections import Counter
from pathlib import Path

import pandas as pd

from phishsentinel.engine import Engine

TRANCO = Path("data/raw/tranco.csv")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--n", type=int, default=10_000)
    a = ap.parse_args()

    if not TRANCO.exists():
        raise SystemExit(f"No existe {TRANCO}. Descarga la lista Tranco y guárdala ahí.")

    full = pd.read_csv(TRANCO, header=None, names=["rank", "domain"], nrows=30_000)
    doms = full["domain"].tolist()[20_000:30_000]
    eng = Engine()
    print(f"Modelo: {eng.bundle['name'] if eng.bundle else 'SIN modelo (heurística)'}")
    print(f"Analizando {len(doms)} dominios, solo capa 1 (sin descargar HTML)...")

    levels, threats, flagged = Counter(), Counter(), []
    for i, d in enumerate(doms, 1):
        v = eng.analyze("https://" + d, fetch=False)
        levels[v.level] += 1
        if v.level != "segura":
            threats[v.threat] += 1
            flagged.append((d, v.level, v.threat, v.score))
        if i % 1000 == 0:
            print(f"  {i}/{len(doms)}")

    n = len(doms)
    print("\n=== Resultados ===")
    for lvl in ["segura", "sospechosa", "peligrosa"]:
        print(f"{lvl:>10}: {levels[lvl]:>6}  ({levels[lvl] / n:.2%})")
    fp = (n - levels["segura"]) / n
    print(f"\nTasa de falsos positivos (no segura): {fp:.2%}")
    print(f"Por amenaza: {dict(threats)}")

    if flagged:
        out = Path("models") / "falsos_positivos_tranco.csv"
        pd.DataFrame(flagged, columns=["dominio", "nivel", "amenaza", "score"]).to_csv(out, index=False)
        print(f"Lista de casos marcados guardada en {out}")
        print("Primeros 10:")
        for row in flagged[:10]:
            print("  ", row)


if __name__ == "__main__":
    main()