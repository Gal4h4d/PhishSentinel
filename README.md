# PhishSentinel v0.1

App de escritorio que analiza URLs en dos capas (URL + contenido) y detecta phishing y XSS.

## Pasos
1. `python -m venv .venv` y activar; luego `pip install -r requirements.txt`
2. Descargar los datasets a `data/raw/` (ver nombres en el chat) y ajustar `SOURCES` en `training/prepare_data.py`
3. `python -m training.prepare_data`
4. `python -m training.train --mode multiclass` (usa `--max-rows 20000` para pruebas rápidas)
5. `python main.py`  (sin modelo entrenado usa reglas heurísticas)
6. `build_exe.bat` genera `dist/PhishSentinel.exe`

## Estructura
- `phishsentinel/` motor: `features_url` (capa 1), `features_content` (capa 2), `engine` (decisión), `storage` (SQLite), `fetcher`
- `training/` preparación de datos y comparación de algoritmos
- `main.py` interfaz Tkinter

## Siguiente entregable (extensión)
`Engine.analyze(url, html)` ya acepta el HTML ya descargado: la extensión solo tendrá que enviarlo
(Native Messaging o un servidor local en 127.0.0.1) y el motor no cambia.
