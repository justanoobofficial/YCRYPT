from __future__ import annotations

import queue
import threading
import tkinter as tk
from tkinter import filedialog, messagebox, ttk
from pathlib import Path

from .crypto import encrypt_file, decrypt_file, verify_file

BG = "#080b09"
PANEL = "#101612"
LINE = "#27352b"
GREEN = "#a7ff83"
MUTED = "#8a9b8e"
TEXT = "#eaf3eb"


class YcryptApp:
    def __init__(self, root: tk.Tk):
        self.root = root
        self.root.title("YCRYPT // OFFLINE FILE VAULT")
        self.root.geometry("760x700")
        self.root.minsize(620, 620)
        self.root.configure(bg=BG)
        self.events: queue.Queue = queue.Queue()
        self.busy = False
        self.source_vars = {}
        self.output_vars = {}
        self.password_vars = {}
        self.confirm_vars = {}
        self.status_vars = {}
        self.progress_vars = {}
        self._style()
        self._build()
        self.root.after(100, self._poll_events)

    def _style(self):
        style = ttk.Style()
        try:
            style.theme_use("clam")
        except tk.TclError:
            pass
        style.configure("TNotebook", background=BG, borderwidth=0)
        style.configure("TNotebook.Tab", background=PANEL, foreground=MUTED,
                        padding=(18, 10), borderwidth=0, font=("Consolas", 10, "bold"))
        style.map("TNotebook.Tab", background=[("selected", "#1b2b1d")],
                  foreground=[("selected", GREEN)])
        style.configure("Y.Horizontal.TProgressbar", troughcolor="#1a231b",
                        background=GREEN, bordercolor=LINE, lightcolor=GREEN,
                        darkcolor=GREEN)
        style.configure("TCheckbutton", background=PANEL, foreground=TEXT)

    def _label(self, parent, text=None, **kwargs):
        options = {"bg": kwargs.pop("bg", PANEL), "fg": kwargs.pop("fg", TEXT),
                   "font": kwargs.pop("font", ("Consolas", 10))}
        if text is not None:
            options["text"] = text
        options.update(kwargs)
        return tk.Label(parent, **options)

    def _build(self):
        header = tk.Frame(self.root, bg=BG)
        header.pack(fill="x", padx=28, pady=(22, 12))
        self._label(header, "YCRYPT", bg=BG, fg=GREEN,
                    font=("Consolas", 25, "bold")).pack(side="left")
        self._label(header, "OFFLINE FILE VAULT  /  v0.1.0", bg=BG, fg=MUTED,
                    font=("Consolas", 9)).pack(side="left", padx=(14, 0), pady=(10, 0))
        self._label(self.root, "LOCAL BY DESIGN. AUTHENTICATED BY DEFAULT.", bg=BG, fg=GREEN,
                    font=("Consolas", 9, "bold")).pack(anchor="w", padx=30, pady=(0, 12))

        outer = tk.Frame(self.root, bg=PANEL, highlightbackground=LINE, highlightthickness=1)
        outer.pack(fill="both", expand=True, padx=24, pady=(0, 14))
        self.notebook = ttk.Notebook(outer)
        self.notebook.pack(fill="both", expand=True, padx=12, pady=12)
        self._make_tab("ENCRYPT", "encrypt")
        self._make_tab("DECRYPT", "decrypt")
        self._make_tab("VERIFY", "verify")

        footer = tk.Frame(self.root, bg=BG)
        footer.pack(fill="x", padx=28, pady=(0, 16))
        self._label(footer, "NO CLOUD  •  NO ACCOUNT  •  NO TELEMETRY", bg=BG, fg=MUTED,
                    font=("Consolas", 9)).pack(side="left")
        self._label(footer, "KEEP A BACKUP", bg=BG, fg=GREEN,
                    font=("Consolas", 9, "bold")).pack(side="right")

    def _make_tab(self, title, mode):
        tab = tk.Frame(self.notebook, bg=PANEL)
        self.notebook.add(tab, text=title)
        pad = tk.Frame(tab, bg=PANEL)
        pad.pack(fill="both", expand=True, padx=18, pady=18)
        descriptions = {
            "encrypt": ("ENCRYPT A FILE", "Wrap a file in authenticated encryption. The original stays untouched."),
            "decrypt": ("DECRYPT A FILE", "Authenticate and recover a file into a new path."),
            "verify": ("VERIFY INTEGRITY", "Test the passphrase and authenticate every encrypted chunk without saving a recovered file.")
        }
        title_text, desc = descriptions[mode]
        self._label(pad, title_text, fg=GREEN, font=("Consolas", 16, "bold")).pack(anchor="w")
        self._label(pad, desc, fg=MUTED, wraplength=620, justify="left").pack(anchor="w", pady=(7, 20))

        source_var = tk.StringVar()
        self.source_vars[mode] = source_var
        self._label(pad, "SOURCE FILE", fg=TEXT, font=("Consolas", 9, "bold")).pack(anchor="w")
        source_row = tk.Frame(pad, bg=PANEL)
        source_row.pack(fill="x", pady=(5, 16))
        tk.Entry(source_row, textvariable=source_var, bg="#080d09", fg=TEXT,
                 insertbackground=GREEN, relief="flat", highlightbackground=LINE,
                 highlightthickness=1, font=("Consolas", 10)).pack(
                     side="left", fill="x", expand=True, ipady=9, padx=(0, 8))
        tk.Button(source_row, text="BROWSE", command=lambda m=mode: self._browse_source(m),
                  bg="#1a2b1c", fg=GREEN, activebackground="#263d29",
                  activeforeground=GREEN, relief="flat",
                  font=("Consolas", 9, "bold"), padx=13, pady=8).pack(side="right")

        if mode != "verify":
            output_var = tk.StringVar()
            self.output_vars[mode] = output_var
            self._label(pad, "OUTPUT PATH", fg=TEXT, font=("Consolas", 9, "bold")).pack(anchor="w")
            out_row = tk.Frame(pad, bg=PANEL)
            out_row.pack(fill="x", pady=(5, 16))
            tk.Entry(out_row, textvariable=output_var, bg="#080d09", fg=TEXT,
                     insertbackground=GREEN, relief="flat", highlightbackground=LINE,
                     highlightthickness=1, font=("Consolas", 10)).pack(
                         side="left", fill="x", expand=True, ipady=9, padx=(0, 8))
            tk.Button(out_row, text="SAVE AS", command=lambda m=mode: self._browse_output(m),
                      bg="#1a2b1c", fg=GREEN, activebackground="#263d29",
                      activeforeground=GREEN, relief="flat",
                      font=("Consolas", 9, "bold"), padx=13, pady=8).pack(side="right")

        self.password_vars[mode] = tk.StringVar()
        self._label(pad, "PASSPHRASE", fg=TEXT, font=("Consolas", 9, "bold")).pack(anchor="w")
        pw_row = tk.Frame(pad, bg=PANEL)
        pw_row.pack(fill="x", pady=(5, 12))
        tk.Entry(pw_row, textvariable=self.password_vars[mode], show="•",
                 bg="#080d09", fg=TEXT, insertbackground=GREEN, relief="flat",
                 highlightbackground=LINE, highlightthickness=1,
                 font=("Consolas", 11)).pack(fill="x", expand=True, ipady=9)
        self._label(pad, "Use a long, unique passphrase. YCRYPT cannot recover a forgotten one.",
                    fg=MUTED, font=("Consolas", 9), wraplength=620,
                    justify="left").pack(anchor="w", pady=(0, 12))

        if mode == "encrypt":
            self.confirm_vars[mode] = tk.StringVar()
            self._label(pad, "CONFIRM PASSPHRASE", fg=TEXT,
                        font=("Consolas", 9, "bold")).pack(anchor="w")
            tk.Entry(pad, textvariable=self.confirm_vars[mode], show="•", bg="#080d09",
                     fg=TEXT, insertbackground=GREEN, relief="flat",
                     highlightbackground=LINE, highlightthickness=1,
                     font=("Consolas", 11)).pack(fill="x", ipady=9, pady=(5, 16))
        else:
            tk.Frame(pad, bg=PANEL, height=18).pack()

        action_text = {"encrypt": "START ENCRYPTION", "decrypt": "DECRYPT SAFELY",
                       "verify": "RUN INTEGRITY CHECK"}[mode]
        self.progress_vars[mode] = tk.IntVar(value=0)
        ttk.Progressbar(pad, variable=self.progress_vars[mode], maximum=100,
                        style="Y.Horizontal.TProgressbar").pack(fill="x", pady=(2, 10))
        status = tk.StringVar(value="READY // WAITING FOR INPUT")
        self.status_vars[mode] = status
        self._label(pad, textvariable=status, fg=MUTED, font=("Consolas", 9),
                    wraplength=620, justify="left").pack(anchor="w", pady=(0, 14))
        btn = tk.Button(pad, text=action_text, command=lambda m=mode: self._start(m),
                        bg=GREEN, fg="#071008", activebackground="#c5ffae",
                        activeforeground="#071008", relief="flat",
                        font=("Consolas", 10, "bold"), padx=18, pady=12)
        btn.pack(fill="x")
        setattr(self, f"button_{mode}", btn)

    def _browse_source(self, mode):
        filetypes = [("YCRYPT encrypted files", "*.ycrypt"), ("All files", "*.*")]
        if mode == "encrypt":
            filetypes = [("All files", "*.*")]
        path = filedialog.askopenfilename(title="Select source file", filetypes=filetypes)
        if path:
            self.source_vars[mode].set(path)
            if mode == "encrypt":
                self.output_vars[mode].set(path + ".ycrypt")
            elif mode == "decrypt":
                p = Path(path)
                guess = p.with_suffix("") if p.suffix.lower() == ".ycrypt" else p.with_name(p.name + ".decrypted")
                self.output_vars[mode].set(str(guess))

    def _browse_output(self, mode):
        if mode == "encrypt":
            path = filedialog.asksaveasfilename(
                title="Save encrypted file", defaultextension=".ycrypt",
                filetypes=[("YCRYPT encrypted file", "*.ycrypt"), ("All files", "*.*")])
        else:
            path = filedialog.asksaveasfilename(title="Save recovered file",
                                                filetypes=[("All files", "*.*")])
        if path:
            self.output_vars[mode].set(path)

    def _start(self, mode):
        if self.busy:
            return
        source_text = self.source_vars[mode].get().strip()
        password = self.password_vars[mode].get()
        if not source_text or not Path(source_text).is_file():
            messagebox.showerror("YCRYPT // INPUT ERROR", "Choose an existing source file first.")
            return
        if not password:
            messagebox.showerror("YCRYPT // INPUT ERROR", "Enter your passphrase.")
            return
        if mode == "encrypt" and password != self.confirm_vars[mode].get():
            messagebox.showerror("YCRYPT // INPUT ERROR", "The passphrases do not match.")
            return
        destination = None
        if mode != "verify":
            out_text = self.output_vars[mode].get().strip()
            if not out_text:
                messagebox.showerror("YCRYPT // INPUT ERROR", "Choose an output path.")
                return
            destination = Path(out_text)
            if destination.exists():
                messagebox.showerror("YCRYPT // SAFE-STOP",
                                     "That output already exists. Choose a new path; YCRYPT will not overwrite it.")
                return
        self.busy = True
        for m in ("encrypt", "decrypt", "verify"):
            getattr(self, f"button_{m}").configure(state="disabled")
        self.status_vars[mode].set("WORKING // KEEP THIS WINDOW OPEN")
        self.progress_vars[mode].set(0)

        def progress(value):
            self.events.put(("progress", mode, value))

        def worker():
            try:
                if mode == "encrypt":
                    encrypt_file(Path(source_text), destination, password, progress)
                    result = f"ENCRYPTION COMPLETE // {destination.name}"
                elif mode == "decrypt":
                    decrypt_file(Path(source_text), destination, password, progress)
                    result = f"DECRYPTION COMPLETE // {destination.name}"
                else:
                    metadata = verify_file(Path(source_text), password, progress)
                    result = f"AUTHENTICATED // {metadata.get('name', 'file')} // {metadata.get('size', 0):,} bytes"
                self.events.put(("done", mode, True, result))
            except Exception as exc:
                self.events.put(("done", mode, False, str(exc)))

        threading.Thread(target=worker, daemon=True).start()

    def _poll_events(self):
        try:
            while True:
                event = self.events.get_nowait()
                if event[0] == "progress":
                    _, mode, value = event
                    self.progress_vars[mode].set(value)
                elif event[0] == "done":
                    _, mode, success, message = event
                    self.busy = False
                    for m in ("encrypt", "decrypt", "verify"):
                        getattr(self, f"button_{m}").configure(state="normal")
                    self.status_vars[mode].set(message)
                    if success:
                        self.progress_vars[mode].set(100)
                        messagebox.showinfo("YCRYPT // COMPLETE", message)
                        self.password_vars[mode].set("")
                        if mode == "encrypt":
                            self.confirm_vars[mode].set("")
                    else:
                        self.status_vars[mode].set("FAILED // " + message)
                        messagebox.showerror("YCRYPT // OPERATION FAILED", message)
        except queue.Empty:
            pass
        self.root.after(100, self._poll_events)


def main():
    root = tk.Tk()
    YcryptApp(root)
    root.mainloop()
