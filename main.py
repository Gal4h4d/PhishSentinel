"""PhishSentinel v0.1 - app de escritorio (Tkinter).
Analiza una URL pegada o vigila el portapapeles. Más adelante, una extensión
podrá llamar al mismo Engine (ver README)."""
import queue
import re
import threading
import time
import tkinter as tk
from tkinter import ttk, messagebox

from phishsentinel import storage
from phishsentinel.engine import Engine
from phishsentinel.features_url import host_of

URL_RE = re.compile(r"^(https?://|www\.)\S+$", re.I)
COLORS = {"segura": "#15803d", "sospechosa": "#b45309", "peligrosa": "#b91c1c"}


class App(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("PhishSentinel")
        self.geometry("760x560")
        self.minsize(640, 480)
        self.engine = Engine()
        self.q = queue.Queue()
        self.last_clip, self.current = "", None
        self.url_var, self.watch_var = tk.StringVar(), tk.BooleanVar(value=False)

        top = ttk.Frame(self, padding=12)
        top.pack(fill="x")
        ttk.Label(top, text="URL a analizar:").pack(anchor="w")
        row = ttk.Frame(top)
        row.pack(fill="x", pady=4)
        entry = ttk.Entry(row, textvariable=self.url_var)
        entry.pack(side="left", fill="x", expand=True)
        entry.bind("<Return>", lambda _e: self.on_analyze())
        ttk.Button(row, text="Analizar", command=self.on_analyze).pack(side="left", padx=(8, 0))
        ttk.Checkbutton(top, text="Vigilar portapapeles (analiza cada enlace que copies)",
                        variable=self.watch_var).pack(anchor="w")
        mode = "modelo ML cargado" if self.engine.bundle else "SIN modelo entrenado: usando reglas heurísticas"
        ttk.Label(top, text=f"Motor: {mode}", foreground="#555").pack(anchor="w")

        self.result = tk.Label(self, text="—", font=("Segoe UI", 22, "bold"), pady=10)
        self.result.pack(fill="x")
        self.detail = ttk.Label(self, text="")
        self.detail.pack()
        self.reasons = tk.Listbox(self, height=8)
        self.reasons.pack(fill="both", expand=True, padx=12, pady=8)

        bot = ttk.Frame(self, padding=(12, 0, 12, 12))
        bot.pack(fill="x")
        ttk.Button(bot, text="Agregar dominio a excepciones", command=self.on_whitelist).pack(side="left")
        ttk.Button(bot, text="Ver historial", command=self.on_history).pack(side="left", padx=8)

        self.after(200, self.poll)
        self.after(1000, self.watch_clipboard)

    # ---- análisis (en hilo aparte para no congelar la ventana) ----
    def start(self, url, source):
        self.result.config(text="Analizando…", fg="#555")
        self.reasons.delete(0, "end")
        threading.Thread(target=self._work, args=(url, source), daemon=True).start()

    def _work(self, url, source):
        try:
            self.q.put((self.engine.analyze(url), source))
        except Exception as exc:                      # no tumbar la app por un error de red/parseo
            self.q.put((exc, source))

    def poll(self):
        try:
            while True:
                res, source = self.q.get_nowait()
                if isinstance(res, Exception):
                    self.result.config(text="Error", fg="#b91c1c")
                    self.detail.config(text=str(res))
                else:
                    self.show(res)
                    if source == "clipboard" and res.level != "segura":
                        messagebox.showwarning("PhishSentinel", f"Enlace {res.level.upper()} ({res.threat})\n\n{res.url}")
        except queue.Empty:
            pass
        self.after(200, self.poll)

    def show(self, v):
        self.current = v
        self.result.config(text=f"{v.level.upper()}", fg=COLORS[v.level])
        self.detail.config(text=f"Amenaza: {v.threat} · puntaje {v.score:.2f} · "
                                f"capa 1: {v.ms_url:.0f} ms · capa 2: {v.ms_content:.0f} ms")
        self.reasons.delete(0, "end")
        for r in v.reasons or ["Sin señales de riesgo"]:
            self.reasons.insert("end", "• " + r)

    # ---- acciones ----
    def on_analyze(self):
        url = self.url_var.get().strip()
        if url:
            self.start(url, "manual")

    def on_whitelist(self):
        if self.current and host_of(self.current.url):
            storage.add_whitelist(host_of(self.current.url))
            messagebox.showinfo("PhishSentinel", f"{host_of(self.current.url)} agregado a excepciones.")

    def on_history(self):
        win = tk.Toplevel(self)
        win.title("Historial")
        lb = tk.Listbox(win, width=110, height=20)
        lb.pack(fill="both", expand=True)
        for ts, url, level, threat, score in storage.recent():
            lb.insert("end", f"{time.strftime('%d/%m %H:%M', time.localtime(ts))}  [{level}/{threat} {score:.2f}]  {url}")

    def watch_clipboard(self):
        if self.watch_var.get():
            try:
                txt = self.clipboard_get().strip()
            except tk.TclError:
                txt = ""
            if txt and txt != self.last_clip and URL_RE.match(txt):
                self.last_clip = txt
                self.url_var.set(txt)
                self.start(txt, "clipboard")
        self.after(1000, self.watch_clipboard)


if __name__ == "__main__":
    App().mainloop()
