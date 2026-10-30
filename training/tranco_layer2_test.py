"""Compara falsos positivos de capa 1 sola vs capa 1 + capa 2 en una muestra de Tranco.
Uso:  python -m training.tranco_layer2_test --n 500"""
import argparse
import random
from collections import Counter
from pathlib import Path

import pandas as pd

from phishsentinel.engine import Engine

TRANCO = Path("data/raw/tranco.csv")
random.seed(11)


def level_of(score, cfg):
    if score >= cfg.T_DANGEROUS:
        return "peligrosa"
    if score >= cfg.T_SUSPICIOUS:
        return "sospechosa"
    return "segura"


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--n", type=int, default=500)
    a = ap.parse_args()

    if not TRANCO.exists():
        raise SystemExit(f"No existe {TRANCO}.")

    full = pd.read_csv(TRANCO, header=None, names=["rank", "domain"], nrows=30_000)
    pool = full["domain"].tolist()[20_000:30_000]
    doms = random.sample(pool, a.n)

    eng = Engine()
    from phishsentinel import config as cfg

    only_l1, both = Counter(), Counter()
    flagged = []
    print(f"Analizando {len(doms)} dominios con HTML (puede tardar varios minutos)...")

    for i, d in enumerate(doms, 1):
        url = "https://" + d
        try:
            v1 = eng.analyze(url, fetch=False)
            v2 = eng.analyze(url, fetch=True)
        except Exception as exc:
            print(f"  [omitido] {d}: {exc}")
            continue
        only_l1[v1.level] += 1
        both[v2.level] += 1
        if v2.level != "segura":
            flagged.append((d, v1.level, v2.level, v2.threat, v2.score,
                            " | ".join(v2.reasons[:3])))
        if i % 50 == 0:
            print(f"  {i}/{len(doms)}")

    n = sum(only_l1.values())
    print("\n=== Falsos positivos (no segura) ===")
    print(f"Solo capa 1:      {n - only_l1['segura']:>4}  ({(n - only_l1['segura']) / n:.2%})")
    print(f"Capa 1 + capa 2:  {n - both['segura']:>4}  ({(n - both['segura']) / n:.2%})")

    if flagged:
        out = Path("models") / "falsos_positivos_capa2.csv"
        pd.DataFrame(flagged, columns=["dominio", "nivel_capa1", "nivel_final", "amenaza",
                                       "score", "motivos"]).to_csv(out, index=False)
        print(f"Casos marcados por la capa 1+2 guardados en {out}")
    print("Revisa ese archivo a mano antes de reportar la cifra.")


if __name__ == "__main__":
    main()