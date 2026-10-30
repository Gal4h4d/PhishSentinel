import os
import sys
from pathlib import Path

FROZEN = getattr(sys, "frozen", False)                       # True dentro del .exe
BASE_DIR = Path(sys._MEIPASS) if FROZEN else Path(__file__).resolve().parent.parent
MODEL_PATH = BASE_DIR / "models" / "model_url.joblib"

DATA_DIR = Path(os.getenv("APPDATA", Path.home())) / "PhishSentinel"
DATA_DIR.mkdir(parents=True, exist_ok=True)
DB_PATH = DATA_DIR / "phishsentinel.db"

T_SUSPICIOUS = 0.50      # >= sospechosa
T_DANGEROUS = 0.80       # >= peligrosa
W_URL, W_CONTENT = 0.6, 0.4
SKIP_FETCH_ABOVE = 0.95  # si la URL ya es clarísimamente maliciosa, no contactamos el sitio
FETCH_TIMEOUT = 5
MAX_HTML_BYTES = 1_500_000
