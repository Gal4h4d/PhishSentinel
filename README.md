# PhishSentinel

PhishSentinel es una aplicación de escritorio para Windows que analiza URLs y
ayuda a identificar señales de phishing y Cross-Site Scripting (XSS). Combina
un modelo de aprendizaje automático para la URL con reglas de análisis del
contenido HTML.

El proyecto está pensado como una herramienta de detección y apoyo al análisis,
no como un reemplazo de un navegador seguro, un antivirus o una revisión
manual.

## Funcionalidades

- Análisis manual de una URL desde una interfaz Tkinter.
- Vigilancia opcional del portapapeles para analizar los enlaces que se copian.
- Clasificación en tres niveles: `segura`, `sospechosa` y `peligrosa`.
- Identificación de amenazas como `phishing` y `xss`.
- Análisis en dos capas:
  - **Capa 1:** características léxicas y estructurales de la URL, señales de
    ofuscación, dominios sospechosos y patrones de XSS.
  - **Capa 2:** análisis del HTML estático, formularios de contraseña,
    iframes ocultos, JavaScript potencialmente riesgoso, scripts externos y
    parámetros reflejados.
- Registro local del historial de detecciones mediante SQLite.
- Lista de excepciones por dominio.
- Funcionamiento con reglas heurísticas cuando no hay un modelo entrenado.
- Creación de un ejecutable independiente mediante PyInstaller.

## Requisitos

- Python 3.10 o posterior.
- Tkinter, incluido normalmente en Windows. En distribuciones Linux puede ser
  necesario instalar el paquete del sistema `python3-tk`.
- Conexión a Internet únicamente cuando se analiza el contenido de una URL.

## Instalación y ejecución

En Windows:

```powershell
git clone https://github.com/Gal4h4d/PhishSentinel.git
cd PhishSentinel
python -m venv .venv
.venv\Scripts\activate
python -m pip install --upgrade pip
pip install -r requirements.txt
python main.py
```

La aplicación carga automáticamente `models/model_url.joblib` si el archivo
existe. Si no está disponible, utiliza las reglas heurísticas definidas en
`phishsentinel/engine.py`.

## Uso

1. Introduce una URL que comience por `http://`, `https://` o `www.`.
2. Pulsa **Analizar** o presiona Enter.
3. Revisa el nivel, la amenaza, el puntaje, los tiempos de cada capa y los
   motivos detectados.
4. Activa **Vigilar portapapeles** si quieres analizar automáticamente cada
   enlace que copies.
5. Usa **Agregar dominio a excepciones** solo para dominios de confianza.
6. Consulta **Ver historial** para revisar las detecciones guardadas.

El descargador obtiene únicamente HTML estático: no ejecuta JavaScript. Las
solicitudes tienen un tiempo de espera de cinco segundos y el contenido está
limitado a 1,5 MB. Si la descarga falla, la evaluación de la URL puede
continuar con la primera capa.

## Modelos y datos

El repositorio incluye modelos y resultados generados en `models/`. La
aplicación utiliza automáticamente `model_url.joblib`; los demás archivos
sirven como resultados o artefactos de experimentación.

El entrenamiento requiere conjuntos de datos locales que no se distribuyen en
el repositorio. Colócalos en `data/raw/` con los nombres y columnas esperados:

| Archivo | Columnas principales | Uso |
| --- | --- | --- |
| `URL dataset.csv` | `url`, `type` | URLs legítimas y de phishing |
| `tranco.csv` | rango, dominio | Dominios legítimos adicionales |
| `xss_*.csv` | `Sentence`, `Label` | Payloads XSS |
| `xss_*.txt` | un payload por línea | Payloads XSS adicionales |

`training/prepare_data.py` también puede generar ejemplos XSS a partir de
payloads y ejemplos legítimos con parámetros normales. Revisa las fuentes
configuradas en `SOURCES` antes de preparar los datos.

## Entrenamiento

Después de colocar los datos en `data/raw/`:

```powershell
python -m training.prepare_data
python -m training.train --mode multiclass
```

Para una prueba más rápida:

```powershell
python -m training.train --mode multiclass --max-rows 20000
```

También se puede entrenar un modelo binario que agrupa phishing y XSS como
`malicious`:

```powershell
python -m training.train --mode binary
```

El entrenamiento compara Random Forest, SVM, KNN, regresión logística y
XGBoost cuando está disponible. Guarda el modelo seleccionado en
`models/model_url.joblib` y las métricas en `models/resultados.csv`.

Para comprobar el comportamiento sobre URLs de phishing no utilizadas en el
entrenamiento:

```powershell
python -m training.phishing_recall_test --n 5000
```

## Crear el ejecutable

En Windows, con el entorno virtual activado:

```powershell
build_exe.bat
```

El ejecutable se genera en `dist/PhishSentinel.exe`. El script incluye los
modelos y los recursos necesarios de `tldextract`, scikit-learn y XGBoost.

## Estructura del proyecto

```text
.
├── main.py                       # Interfaz gráfica Tkinter
├── phishsentinel/
│   ├── engine.py                 # Decisión y combinación de las capas
│   ├── features_url.py           # Características de URL y señales XSS
│   ├── features_content.py       # Reglas de análisis HTML
│   ├── fetcher.py                # Descarga de HTML estático
│   ├── storage.py                # Historial y excepciones en SQLite
│   └── config.py                 # Umbrales y rutas de ejecución
├── training/
│   ├── prepare_data.py           # Preparación de los datasets
│   ├── train.py                  # Comparación y entrenamiento de modelos
│   └── *_test.py                 # Pruebas sobre conjuntos separados
├── models/                       # Modelos y resultados incluidos
├── requirements.txt
└── build_exe.bat
```

La base de datos local se guarda en:

```text
%APPDATA%\PhishSentinel\phishsentinel.db
```

## Limitaciones conocidas

- El análisis de contenido solo considera el HTML recibido inicialmente y no
  renderiza páginas ni ejecuta JavaScript.
- Una URL clasificada como segura no garantiza que el sitio sea legítimo.
- La disponibilidad, redirecciones y respuesta del sitio remoto pueden
  afectar al análisis de la segunda capa.
- Los modelos dependen de la calidad y representatividad de los datasets
  utilizados para entrenarlos.

## Licencia

Este repositorio no incluye actualmente un archivo de licencia. Consulta al
autor antes de redistribuir o incorporar el proyecto en otro producto.
