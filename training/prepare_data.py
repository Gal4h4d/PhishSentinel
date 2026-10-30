"""Arma data/processed/urls.csv (url,label) a partir de los datasets en data/raw/.
Uso:  python -m training.prepare_data"""
import random
from pathlib import Path
from urllib.parse import quote

import pandas as pd

RAW, OUT = Path("data/raw"), Path("data/processed")
OUT.mkdir(parents=True, exist_ok=True)
random.seed(42)
CAP_PER_CLASS = 50_000

# (archivo en data/raw, columna URL, columna etiqueta, mapa de etiquetas)
SOURCES = [
    ("URL dataset.csv", "url", "type", {"legitimate": "legitimate", "phishing": "phishing"}),
]
PARAMS = ["q", "search", "s", "query", "id", "name", "redirect", "url", "page", "msg"]
WORDS = ["zapatos", "libros", "mochila", "clima", "noticias", "python", "receta", "hotel"]

TRANCO = RAW / "tranco.csv"
TRANCO_TRAIN_N = 20_000
TRANCO_TEST_START, TRANCO_TEST_END = 20_000, 30_000


def load_tranco_train():
    """Dominios raíz legítimos para entrenamiento (primeros 20,000 de Tranco)."""
    if not TRANCO.exists():
        print("[aviso] no está tranco.csv, se omite")
        return []
    d = pd.read_csv(TRANCO, header=None, names=["rank", "domain"], nrows=TRANCO_TRAIN_N)
    return [f"https://{x}/" for x in d["domain"].tolist()]

def load_sources():
    frames = []
    for fname, c_url, c_lab, mapping in SOURCES:
        p = RAW / fname
        if not p.exists():
            print(f"[aviso] no está {p}, se omite")
            continue
        d = pd.read_csv(p, usecols=[c_url, c_lab]).rename(columns={c_url: "url", c_lab: "label"})
        d["label"] = d["label"].map(mapping)
        frames.append(d.dropna())
    return pd.concat(frames) if frames else pd.DataFrame(columns=["url", "label"])


def load_xss_payloads():
    pays = []
    for p in RAW.glob("xss_*.csv"):        # Kaggle XSS dataset: columnas Sentence, Label (1 = XSS)
        d = pd.read_csv(p)
        col = "Sentence" if "Sentence" in d else d.columns[0]
        if "Label" in d:
            d = d[d["Label"] == 1]
        pays += d[col].dropna().astype(str).tolist()
    for p in RAW.glob("xss_*.txt"):        # PayloadsAllTheThings: un payload por línea
        pays += [l.strip() for l in p.read_text(errors="ignore").splitlines() if l.strip() and not l.startswith("#")]
    return list(dict.fromkeys(pays))


def make_xss_urls(payloads, bases, n):
    """Genera hasta n URLs con payloads XSS en un parámetro.
    Sin parámetro aleatorio: así el modelo no aprende un atajo artificial."""
    out = set()
    attempts, max_attempts = 0, n * 10
    while len(out) < n and payloads and attempts < max_attempts:
        attempts += 1
        pl = random.choice(payloads)
        base = random.choice(bases).split("?")[0]
        val = quote(pl[:300]) if random.random() < 0.5 else pl[:300].replace(" ", "%20")
        out.add(f"{base}?{random.choice(PARAMS)}={val}")
    return list(out)


def main():
    df = load_sources().drop_duplicates("url")
    print("tras cargar:", df.label.value_counts().to_dict())
    legit = df.loc[df.label == "legitimate", "url"].tolist()
    payloads = load_xss_payloads()
    print("payloads xss:", len(payloads))

    extra = []
    extra += [(u, "legitimate") for u in load_tranco_train()]
    if legit and payloads:
        extra += [(u, "xss") for u in make_xss_urls(payloads, legit, CAP_PER_CLASS)]
        # negativos difíciles: URLs legítimas con parámetros normales (reduce falsos positivos)
        extra += [(random.choice(legit).split("?")[0] + f"?{random.choice(PARAMS)}={random.choice(WORDS)}", "legitimate")
                  for _ in range(5000)]
    else:
        print("[aviso] sin payloads XSS o sin URLs legítimas: no se generan ejemplos de XSS")

    df = pd.concat([df, pd.DataFrame(extra, columns=["url", "label"])])
    df = df.drop_duplicates(["url", "label"])
    print("antes de balancear:", df.label.value_counts().to_dict())

    n = min(df.label.value_counts().min(), CAP_PER_CLASS)
    df = df.groupby("label", group_keys=False).sample(n=n, random_state=42)
    df.to_csv(OUT / "urls.csv", index=False)
    print(df.label.value_counts())


if __name__ == "__main__":
    main()