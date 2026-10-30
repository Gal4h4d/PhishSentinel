"""Prueba de generalización: entrena con una fuente de payloads XSS y prueba con otra.
Uso:  python -m training.cross_source_test"""
import random
from pathlib import Path
from urllib.parse import quote

import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import classification_report, f1_score

from phishsentinel.features_url import FEATURE_NAMES, extract_url_features, to_vector
from training.prepare_data import PARAMS, WORDS, make_xss_urls

RAW = Path("data/raw")
random.seed(7)
N_PER_CLASS = 15_000


def load_payloads(pattern_csv=None, pattern_txt=None):
    pays = []
    if pattern_csv:
        for p in RAW.glob(pattern_csv):
            d = pd.read_csv(p)
            col = "Sentence" if "Sentence" in d else d.columns[0]
            if "Label" in d:
                d = d[d["Label"] == 1]
            pays += d[col].dropna().astype(str).tolist()
    if pattern_txt:
        for p in RAW.glob(pattern_txt):
            pays += [l.strip() for l in p.read_text(errors="ignore").splitlines()
                     if l.strip() and not l.startswith("#")]
    return list(dict.fromkeys(pays))


def build(payloads, legit_urls, n):
    xss = make_xss_urls(payloads, legit_urls, n)
    leg = [random.choice(legit_urls).split("?")[0] + f"?{random.choice(PARAMS)}={random.choice(WORDS)}"
           for _ in range(n)]
    X = [to_vector(extract_url_features(u)) for u in xss + leg]
    y = ["xss"] * len(xss) + ["legitimate"] * len(leg)
    return np.array(X), np.array(y)


def main():
    legit = pd.read_csv(RAW / "URL dataset.csv", usecols=["url", "type"])
    legit = legit[legit["type"] == "legitimate"]["url"].drop_duplicates().tolist()

    txt_pays = load_payloads(pattern_txt="xss_*.txt")
    csv_pays = load_payloads(pattern_csv="XSS_*.csv")
    print(f"payloads .txt: {len(txt_pays)} | payloads .csv: {len(csv_pays)}")

    # Dirección A: entrenar con .txt, probar con .csv
    # Dirección B: entrenar con .csv, probar con .txt
    for name, train_p, test_p in [("A: txt -> csv", txt_pays, csv_pays),
                                  ("B: csv -> txt", csv_pays, txt_pays)]:
        if not train_p or not test_p:
            print(f"[{name}] sin datos suficientes")
            continue
        Xtr, ytr = build(train_p, legit, N_PER_CLASS)
        Xte, yte = build(test_p, legit, N_PER_CLASS)
        clf = RandomForestClassifier(n_estimators=200, n_jobs=-1, random_state=42).fit(Xtr, ytr)
        pred = clf.predict(Xte)
        print(f"\n=== {name} ===")
        print(classification_report(yte, pred, digits=4))
        print(f"F1 macro: {f1_score(yte, pred, average='macro'):.4f}")


if __name__ == "__main__":
    main()