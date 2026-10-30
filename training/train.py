"""Compara 5 algoritmos y guarda el mejor en models/model_url.joblib.
Uso:  python -m training.train --mode multiclass --max-rows 60000"""
import argparse
import time
from pathlib import Path

import joblib
import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import accuracy_score, confusion_matrix, precision_recall_fscore_support
from sklearn.model_selection import cross_val_score, train_test_split
from sklearn.neighbors import KNeighborsClassifier
from sklearn.pipeline import make_pipeline
from sklearn.preprocessing import StandardScaler
from sklearn.svm import SVC

from phishsentinel.features_url import FEATURE_NAMES, extract_url_features, to_vector

try:
    from xgboost import XGBClassifier
except ImportError:
    XGBClassifier = None


def build_models():
    m = {
        "RandomForest": RandomForestClassifier(n_estimators=200, n_jobs=-1, random_state=42),
        "SVM": make_pipeline(StandardScaler(), SVC(probability=True, random_state=42)),
        "KNN": make_pipeline(StandardScaler(), KNeighborsClassifier(n_neighbors=5)),
        "LogReg": make_pipeline(StandardScaler(), LogisticRegression(max_iter=1000)),
    }
    if XGBClassifier:
        m["XGBoost"] = XGBClassifier(n_estimators=300, max_depth=6, learning_rate=0.1, n_jobs=-1)
    return m


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--data", default="data/processed/urls.csv")
    ap.add_argument("--mode", choices=["binary", "multiclass"], default="multiclass")
    ap.add_argument("--max-rows", type=int, default=60000)    # SVM y KNN son lentos: baja esto para pruebas
    ap.add_argument("--cv", type=int, default=3)
    a = ap.parse_args()

    df = pd.read_csv(a.data).dropna()
    if a.mode == "binary":
        df["label"] = df["label"].replace({"phishing": "malicious", "xss": "malicious"})
    if len(df) > a.max_rows:
        df = df.sample(a.max_rows, random_state=42)

    t0 = time.perf_counter()
    X = np.array([to_vector(extract_url_features(u)) for u in df["url"]])
    ms_feat = (time.perf_counter() - t0) / len(df) * 1000
    classes = sorted(df["label"].unique())
    y = df["label"].map({c: i for i, c in enumerate(classes)}).values
    Xtr, Xte, ytr, yte = train_test_split(X, y, test_size=0.2, stratify=y, random_state=42)
    legit = classes.index("legitimate")

    rows, best = [], (None, -1.0, None)
    for name, clf in build_models().items():
        print(f"== {name}")
        cv = cross_val_score(clf, Xtr, ytr, cv=a.cv, scoring="f1_macro").mean()
        clf.fit(Xtr, ytr)
        t = time.perf_counter()
        pred = clf.predict(Xte)
        ms_pred = (time.perf_counter() - t) / len(Xte) * 1000
        p, r, f1, _ = precision_recall_fscore_support(yte, pred, average="macro", zero_division=0)
        cm = confusion_matrix(yte, pred, labels=range(len(classes)))
        fpr = (cm[legit].sum() - cm[legit, legit]) / max(cm[legit].sum(), 1)   # legítimas marcadas como maliciosas
        rows.append({"modelo": name, "cv_f1": cv, "accuracy": accuracy_score(yte, pred), "precision": p,
                     "recall": r, "f1": f1, "falsos_positivos": fpr, "ms_prediccion": ms_pred})
        if f1 > best[1]:
            best = (name, f1, clf)

    res = pd.DataFrame(rows).sort_values("f1", ascending=False)
    Path("models").mkdir(exist_ok=True)
    res.to_csv("models/resultados.csv", index=False)
    print(res.round(4).to_string(index=False))
    print(f"\nExtracción de características: {ms_feat:.2f} ms/URL · mejor modelo: {best[0]}")
    joblib.dump({"model": best[2], "classes": classes, "features": FEATURE_NAMES, "name": best[0]},
                "models/model_url.joblib")


if __name__ == "__main__":
    main()
