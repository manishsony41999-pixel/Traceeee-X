"""
TRACE-X Pro - Antivirus-Safe Python Desktop Launcher & Control Center
Runs directly via Python's officially signed pythonw.exe without triggering antivirus false positives.
"""
import os
import sys
import subprocess
import threading
import time
import webbrowser
import urllib.request
import tkinter as tk
from tkinter import ttk, messagebox, scrolledtext

PROJECT_ROOT = os.path.dirname(os.path.abspath(__file__))
BACKEND_DIR = os.path.join(PROJECT_ROOT, "backend")
FRONTEND_DIR = os.path.join(PROJECT_ROOT, "frontend")
VENV_PYTHON = os.path.join(BACKEND_DIR, "venv", "Scripts", "python.exe")
PYTHON_EXE = VENV_PYTHON if os.path.exists(VENV_PYTHON) else sys.executable


class TraceXLauncherApp:
    def __init__(self, root):
        self.root = root
        self.root.title("TRACE-X PRO - Control Center")
        self.root.geometry("860x650")
        self.root.configure(bg="#f8fafc")

        self.backend_proc = None
        self.frontend_proc = None
        self._running = True
        self.logo_img = None

        self._create_widgets()
        self._start_status_polling()

        self.root.protocol("WM_DELETE_WINDOW", self.on_close)

    def _create_widgets(self):
        # Header frame
        header_frame = tk.Frame(self.root, bg="#ffffff", padx=24, pady=16, highlightthickness=1, highlightbackground="#e2e8f0")
        header_frame.pack(fill="x", padx=20, pady=(16, 8))

        # Logo & Title Container
        title_container = tk.Frame(header_frame, bg="#ffffff")
        title_container.pack(side="left", fill="both")

        # Try loading logo image
        logo_path = os.path.join(PROJECT_ROOT, "logo.png")
        if os.path.exists(logo_path):
            try:
                from PIL import Image, ImageTk
                pil_img = Image.open(logo_path)
                aspect = pil_img.width / pil_img.height
                target_height = 42
                target_width = int(target_height * aspect)
                pil_img = pil_img.resize((target_width, target_height), Image.Resampling.LANCZOS)
                self.logo_img = ImageTk.PhotoImage(pil_img)
                logo_lbl = tk.Label(title_container, image=self.logo_img, bg="#ffffff")
                logo_lbl.pack(side="left", padx=(0, 14))
            except Exception:
                pass

        text_container = tk.Frame(title_container, bg="#ffffff")
        text_container.pack(side="left", fill="both")

        title_lbl = tk.Label(
            text_container,
            text="TRACE-X PRO",
            font=("Segoe UI", 18, "bold"),
            fg="#dc2626",
            bg="#ffffff"
        )
        title_lbl.pack(anchor="w")

        subtitle_lbl = tk.Label(
            text_container,
            text="AI-Powered Email Threat Detection & Real-Time Ingestion Platform",
            font=("Segoe UI", 9),
            fg="#64748b",
            bg="#ffffff"
        )
        subtitle_lbl.pack(anchor="w", pady=(1, 0))

        # Status Bar Panel
        status_panel = tk.Frame(self.root, bg="#ffffff", padx=20, pady=12, highlightthickness=1, highlightbackground="#e2e8f0")
        status_panel.pack(fill="x", padx=20, pady=8)

        self.backend_status_lbl = tk.Label(
            status_panel,
            text="Backend API: Stopped",
            font=("Segoe UI", 9, "bold"),
            fg="#ef4444",
            bg="#ffffff"
        )
        self.backend_status_lbl.pack(side="left", padx=(0, 40))

        self.frontend_status_lbl = tk.Label(
            status_panel,
            text="Frontend UI: Stopped",
            font=("Segoe UI", 9, "bold"),
            fg="#ef4444",
            bg="#ffffff"
        )
        self.frontend_status_lbl.pack(side="left")

        # Action Buttons Frame
        btn_frame = tk.Frame(self.root, bg="#f8fafc")
        btn_frame.pack(fill="x", padx=20, pady=8)

        # Style helpers
        btn_config = {
            "font": ("Segoe UI", 9, "bold"),
            "relief": "flat",
            "cursor": "hand2",
            "padx": 14,
            "pady": 8,
            "fg": "#ffffff"
        }

        self.btn_start = tk.Button(
            btn_frame,
            text="▶ Start TRACE-X",
            bg="#dc2626",
            activebackground="#b91c1c",
            command=self.start_services,
            **btn_config
        )
        self.btn_start.pack(side="left", padx=(0, 8))

        self.btn_stop = tk.Button(
            btn_frame,
            text="⏹ Stop Services",
            bg="#64748b",
            activebackground="#475569",
            command=self.stop_services,
            **btn_config
        )
        self.btn_stop.pack(side="left", padx=(0, 8))

        self.btn_open_ui = tk.Button(
            btn_frame,
            text="🌐 Open Web UI",
            bg="#0f172a",
            activebackground="#1e293b",
            command=lambda: webbrowser.open("http://localhost:5173"),
            **btn_config
        )
        self.btn_open_ui.pack(side="left", padx=(0, 8))

        self.btn_docs = tk.Button(
            btn_frame,
            text="📖 API Swagger",
            bg="#ffffff",
            fg="#334155",
            highlightthickness=1,
            highlightbackground="#cbd5e1",
            activebackground="#f1f5f9",
            command=lambda: webbrowser.open("http://localhost:8000/docs"),
            font=("Segoe UI", 9, "bold"),
            relief="flat",
            cursor="hand2",
            padx=14,
            pady=8
        )
        self.btn_docs.pack(side="left", padx=(0, 8))

        self.btn_tests = tk.Button(
            btn_frame,
            text="🧪 Run Tests",
            bg="#ffffff",
            fg="#334155",
            highlightthickness=1,
            highlightbackground="#cbd5e1",
            activebackground="#f1f5f9",
            command=self.run_tests_threaded,
            font=("Segoe UI", 9, "bold"),
            relief="flat",
            cursor="hand2",
            padx=14,
            pady=8
        )
        self.btn_tests.pack(side="left")

        # Console Log Window
        log_label = tk.Label(
            self.root,
            text="Live Activity & Diagnostics Log:",
            font=("Segoe UI", 9, "bold"),
            fg="#475569",
            bg="#f8fafc"
        )
        log_label.pack(anchor="w", padx=20, pady=(10, 4))

        self.log_box = scrolledtext.ScrolledText(
            self.root,
            bg="#ffffff",
            fg="#0f172a",
            insertbackground="#dc2626",
            font=("Consolas", 9),
            relief="flat",
            highlightthickness=1,
            highlightbackground="#cbd5e1",
            wrap="word"
        )
        self.log_box.pack(fill="both", expand=True, padx=20, pady=(0, 16))

        self.log("TRACE-X Pro Control Center initialized.")
        self.log(f"Project directory: {PROJECT_ROOT}")
        self.log(f"Python interpreter: {PYTHON_EXE}")
        self.log("Click '▶ Start TRACE-X' to launch Backend API and Frontend UI.")

    def log(self, text):
        timestamp = time.strftime("%H:%M:%S")
        self.log_box.insert(tk.END, f"[{timestamp}] {text}\n")
        self.log_box.see(tk.END)

    def start_services(self):
        self.log("Starting TRACE-X services...")

        # 1. Start Backend API
        if not self.backend_proc or self.backend_proc.poll() is not None:
            cmd = [PYTHON_EXE, "-m", "uvicorn", "app.main:app", "--host", "127.0.0.1", "--port", "8000"]
            try:
                self.backend_proc = subprocess.Popen(
                    cmd,
                    cwd=BACKEND_DIR,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.STDOUT,
                    text=True,
                    bufsize=1,
                    creationflags=subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0
                )
                threading.Thread(target=self._stream_proc_output, args=(self.backend_proc, "API"), daemon=True).start()
                self.log(f"FastAPI Backend process launched (PID: {self.backend_proc.pid})")
            except Exception as e:
                self.log(f"ERROR launching backend: {e}")

        # 2. Start Frontend UI
        if not self.frontend_proc or self.frontend_proc.poll() is not None:
            cmd = "npm run dev"
            try:
                self.frontend_proc = subprocess.Popen(
                    cmd,
                    cwd=FRONTEND_DIR,
                    shell=True,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.STDOUT,
                    text=True,
                    bufsize=1,
                    creationflags=subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0
                )
                threading.Thread(target=self._stream_proc_output, args=(self.frontend_proc, "UI"), daemon=True).start()
                self.log(f"Vite Frontend process launched (PID: {self.frontend_proc.pid})")
            except Exception as e:
                self.log(f"ERROR launching frontend: {e}")

        # Open browser in 3.5 seconds
        threading.Thread(target=self._delayed_browser_open, daemon=True).start()

    def _stream_proc_output(self, proc, tag):
        try:
            for line in iter(proc.stdout.readline, ""):
                if not self._running:
                    break
                stripped = line.strip()
                if stripped:
                    self.root.after(0, self.log, f"[{tag}] {stripped}")
        except Exception:
            pass

    def _delayed_browser_open(self):
        time.sleep(3.5)
        webbrowser.open("http://localhost:5173")
        self.root.after(0, self.log, "Browser opened to http://localhost:5173")

    def stop_services(self):
        self.log("Stopping all TRACE-X services...")
        if self.backend_proc and self.backend_proc.poll() is None:
            try:
                self.backend_proc.terminate()
                self.backend_proc.kill()
                self.log("Backend API stopped.")
            except Exception:
                pass
            self.backend_proc = None

        if self.frontend_proc and self.frontend_proc.poll() is None:
            try:
                if os.name == "nt":
                    subprocess.run(["taskkill", "/PID", str(self.frontend_proc.pid), "/T", "/F"], capture_output=True)
                else:
                    self.frontend_proc.kill()
                self.log("Frontend UI stopped.")
            except Exception:
                pass
            self.frontend_proc = None

        self.backend_status_lbl.configure(text="Backend API: Stopped", fg="#f87171")
        self.frontend_status_lbl.configure(text="Frontend UI: Stopped", fg="#f87171")

    def run_tests_threaded(self):
        self.log("Starting pytest test suite in background...")
        threading.Thread(target=self._execute_tests, daemon=True).start()

    def _execute_tests(self):
        try:
            cmd = [PYTHON_EXE, "-m", "pytest", "tests", "-v"]
            p = subprocess.Popen(
                cmd,
                cwd=BACKEND_DIR,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                creationflags=subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0
            )
            for line in iter(p.stdout.readline, ""):
                stripped = line.strip()
                if stripped:
                    self.root.after(0, self.log, f"[TEST] {stripped}")
            p.wait()
            self.root.after(0, self.log, f"Test suite finished with code: {p.returncode}")
        except Exception as e:
            self.root.after(0, self.log, f"Error running tests: {e}")

    def _start_status_polling(self):
        def poll():
            while self._running:
                # Backend check
                backend_online = False
                try:
                    req = urllib.request.Request("http://127.0.0.1:8000/health")
                    with urllib.request.urlopen(req, timeout=1.2) as response:
                        if response.status == 200:
                            backend_online = True
                except Exception:
                    backend_online = False

                # Frontend check
                frontend_online = False
                try:
                    req = urllib.request.Request("http://localhost:5173")
                    with urllib.request.urlopen(req, timeout=1.2) as response:
                        if response.status == 200:
                            frontend_online = True
                except Exception:
                    frontend_online = False

                def update_labels():
                    if backend_online:
                        self.backend_status_lbl.configure(text="Backend API: ONLINE (Port 8000)", fg="#34d399")
                    else:
                        self.backend_status_lbl.configure(text="Backend API: Stopped", fg="#f87171")

                    if frontend_online:
                        self.frontend_status_lbl.configure(text="Frontend UI: ONLINE (Port 5173)", fg="#34d399")
                    else:
                        self.frontend_status_lbl.configure(text="Frontend UI: Stopped", fg="#f87171")

                try:
                    self.root.after(0, update_labels)
                except Exception:
                    break
                time.sleep(2.5)

        threading.Thread(target=poll, daemon=True).start()

    def on_close(self):
        self._running = False
        self.stop_services()
        self.root.destroy()


if __name__ == "__main__":
    root = tk.Tk()
    app = TraceXLauncherApp(root)
    root.mainloop()
