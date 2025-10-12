#!/usr/bin/env python3
"""
miner_gui.py

Lightweight tkinter GUI to control and observe simple_miner.py.
- Start / Stop miner subprocess
- Provide node URL, miner address, token and some flags
- Live log output (stdout/stderr) streaming
- Save logs to disk
"""

import os
import sys
import threading
import subprocess
import queue
import time
import tkinter as tk
from tkinter import ttk, scrolledtext, filedialog, messagebox

# Path to your simple_miner script. Adjust if needed.
SIMPLE_MINER_CMD = [sys.executable, "miners/simple_miner.py"]

class MinerGUI(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("Simple Miner GUI")
        self.geometry("900x600")
        self.miner_proc = None
        self.log_queue = queue.Queue()
        self.reader_thread = None
        self.stop_reader = threading.Event()

        self._build_ui()
        self.after(200, self._flush_log_queue)

    def _build_ui(self):
        frm = ttk.Frame(self)
        frm.pack(fill="x", padx=8, pady=6)

        # Node URL
        ttk.Label(frm, text="Node URL:").grid(row=0, column=0, sticky="w")
        self.node_var = tk.StringVar(value=os.getenv("MINER_NODE_URL", "http://127.0.0.1:5000"))
        ttk.Entry(frm, textvariable=self.node_var, width=40).grid(row=0, column=1, sticky="w", padx=6)

        # Miner address
        ttk.Label(frm, text="Miner Address:").grid(row=0, column=2, sticky="w")
        self.addr_var = tk.StringVar(value=os.getenv("MINER_ADDRESS", "miner-demo-addr"))
        ttk.Entry(frm, textvariable=self.addr_var, width=30).grid(row=0, column=3, sticky="w", padx=6)

        # Token
        ttk.Label(frm, text="Miner Token:").grid(row=1, column=0, sticky="w")
        self.token_var = tk.StringVar(value=os.getenv("MINER_TOKEN", ""))
        ttk.Entry(frm, textvariable=self.token_var, width=40, show="*" if os.getenv("MINER_TOKEN") else "").grid(row=1, column=1, sticky="w", padx=6)

        # Flags
        self.allow_empty_var = tk.BooleanVar(value=os.getenv("MINER_ALLOW_EMPTY", "0") == "1")
        self.use_rig_var = tk.BooleanVar(value=os.getenv("MINER_USE_RIG", "0") == "1")
        ttk.Checkbutton(frm, text="Allow empty blocks", variable=self.allow_empty_var).grid(row=1, column=2, sticky="w")
        ttk.Checkbutton(frm, text="Use rig (GPU)", variable=self.use_rig_var).grid(row=1, column=3, sticky="w")

        # Controls row
        ctrl = ttk.Frame(self)
        ctrl.pack(fill="x", padx=8, pady=(0,6))
        self.start_btn = ttk.Button(ctrl, text="Start Miner", command=self.start_miner)
        self.start_btn.pack(side="left", padx=(0,6))
        self.stop_btn = ttk.Button(ctrl, text="Stop Miner", command=self.stop_miner, state="disabled")
        self.stop_btn.pack(side="left", padx=(0,6))
        self.save_btn = ttk.Button(ctrl, text="Save Logs...", command=self.save_logs)
        self.save_btn.pack(side="left", padx=(8,6))
        self.clear_btn = ttk.Button(ctrl, text="Clear Logs", command=self.clear_logs)
        self.clear_btn.pack(side="left", padx=(6,0))

        # Status label
        self.status_var = tk.StringVar(value="Stopped")
        ttk.Label(ctrl, textvariable=self.status_var).pack(side="right")

        # Log viewer
        self.log_widget = scrolledtext.ScrolledText(self, wrap="none", state="disabled")
        self.log_widget.pack(fill="both", expand=True, padx=8, pady=6)

        # keyboard shortcut: Ctrl+Q exit
        self.bind_all("<Control-q>", lambda e: self.on_close())
        self.protocol("WM_DELETE_WINDOW", self.on_close)

    def _append_log(self, text: str):
        self.log_widget.configure(state="normal")
        self.log_widget.insert("end", text)
        self.log_widget.see("end")
        self.log_widget.configure(state="disabled")

    def _flush_log_queue(self):
        try:
            while True:
                line = self.log_queue.get_nowait()
                self._append_log(line)
        except queue.Empty:
            pass
        self.after(200, self._flush_log_queue)

    def _reader_loop(self, pipe):
        try:
            for raw in iter(pipe.readline, b""):
                if not raw:
                    break
                try:
                    line = raw.decode("utf-8", errors="replace")
                except Exception:
                    line = str(raw)
                timestamped = f"[{time.strftime('%H:%M:%S')}] {line}"
                self.log_queue.put(timestamped)
                if self.stop_reader.is_set():
                    break
        except Exception as e:
            self.log_queue.put(f"[reader-error] {e}\n")

    def start_miner(self):
        if self.miner_proc is not None:
            messagebox.showinfo("Miner GUI", "Miner is already running.")
            return

        cmd = SIMPLE_MINER_CMD[:]
        # add args from UI
        cmd += ["--node", self.node_var.get().rstrip("/")]
        cmd += ["--addr", self.addr_var.get()]
        if self.token_var.get():
            cmd += ["--token", self.token_var.get()]
        if self.allow_empty_var.get():
            cmd += ["--allow-empty"]
        if self.use_rig_var.get():
            cmd += ["--use-rig"]

        # optional other environment handling could be done here
        env = os.environ.copy()

        try:
            # start the subprocess and capture stdout/stderr combined
            self.miner_proc = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                env=env,
                bufsize=1,
            )
        except FileNotFoundError as e:
            messagebox.showerror("Miner GUI", f"Could not start miner: {e}\nMake sure simple_miner.py is in the same directory or adjust SIMPLE_MINER_CMD.")
            self.miner_proc = None
            return
        except Exception as e:
            messagebox.showerror("Miner GUI", f"Failed to start miner: {e}")
            self.miner_proc = None
            return

        # start reader thread that pushes lines into log_queue
        self.stop_reader.clear()
        self.reader_thread = threading.Thread(target=self._reader_loop, args=(self.miner_proc.stdout,), daemon=True)
        self.reader_thread.start()

        self.start_btn.configure(state="disabled")
        self.stop_btn.configure(state="normal")
        self.status_var.set("Running")
        self.log_queue.put(f"[miner-gui] started miner: {' '.join(cmd)}\n")

    def stop_miner(self):
        if self.miner_proc is None:
            return
        self.log_queue.put("[miner-gui] stopping miner...\n")
        try:
            # ask process to terminate gracefully
            self.miner_proc.terminate()
            # wait up to a few seconds
            try:
                self.miner_proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self.log_queue.put("[miner-gui] miner did not exit, killing...\n")
                self.miner_proc.kill()
                self.miner_proc.wait(timeout=2)
        except Exception as e:
            self.log_queue.put(f"[miner-gui] error stopping miner: {e}\n")
        finally:
            self.stop_reader.set()
            # drain stdout to avoid broken pipe; join thread
            try:
                if self.reader_thread and self.reader_thread.is_alive():
                    self.reader_thread.join(timeout=1)
            except Exception:
                pass
            self.miner_proc = None
            self.reader_thread = None
            self.start_btn.configure(state="normal")
            self.stop_btn.configure(state="disabled")
            self.status_var.set("Stopped")
            self.log_queue.put("[miner-gui] miner stopped.\n")

    def save_logs(self):
        fname = filedialog.asksaveasfilename(title="Save logs", defaultextension=".log",
                                             filetypes=[("Log files", "*.log"), ("Text files", "*.txt"), ("All files", "*.*")])
        if not fname:
            return
        try:
            with open(fname, "w", encoding="utf-8") as f:
                f.write(self.log_widget.get("1.0", "end"))
            messagebox.showinfo("Miner GUI", f"Logs saved to: {fname}")
        except Exception as e:
            messagebox.showerror("Miner GUI", f"Could not save logs: {e}")

    def clear_logs(self):
        self.log_widget.configure(state="normal")
        self.log_widget.delete("1.0", "end")
        self.log_widget.configure(state="disabled")

    def on_close(self):
        if self.miner_proc is not None:
            if not messagebox.askyesno("Quit", "Miner is running. Stop miner and quit?"):
                return
            self.stop_miner()
        self.destroy()


if __name__ == "__main__":
    app = MinerGUI()
    app.mainloop()
