#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Database Pulse - v1.1 launcher
Adds Linux/Unix Servers and Windows Servers modules alongside Oracle and SQL Server.
- Dynamically lazy-imports modules.
- Provides placeholders when module import fails.
- Persists the last-opened tab.
"""

import importlib, json, os, sys, tkinter as tk
from tkinter import ttk, messagebox
from pathlib import Path

APP_NAME = "Database Pulse"
CFG_DIR = Path(__file__).resolve().parent / "config"
CFG_DIR.mkdir(parents=True, exist_ok=True)
CFG_PATH = CFG_DIR / "launcher.json"

def _load_cfg():
    if CFG_PATH.exists():
        try: return json.loads(CFG_PATH.read_text(encoding="utf-8"))
        except Exception: pass
    return {"last_tab":"Oracle"}

def _save_cfg(cfg):
    CFG_PATH.write_text(json.dumps(cfg, indent=2), encoding="utf-8")

def _lazy_import_oracle():
    return importlib.import_module("dp_oracle_module")

def _lazy_import_sqlserver():
    return importlib.import_module("dp_sqlserver_module")

def _lazy_import_linux():
    return importlib.import_module("dp_linux_module")

def _lazy_import_windows():
    return importlib.import_module("dp_windows_module")

class _ModulePlaceholder(ttk.Frame):
    def __init__(self, master, title: str, err: str):
        super().__init__(master)
        ttk.Label(self, text=f"{title} module failed to load.", font=("Segoe UI", 12, "bold")).pack(pady=(20,6))
        ttk.Label(self, text=err, foreground="#a00", wraplength=720, justify="left").pack(padx=12)

class RouterApp(ttk.Frame):
    def __init__(self, master):
        super().__init__(master)
        self.cfg = _load_cfg()
        self._build_ui()

    def _build_ui(self):
        self.columnconfigure(0, weight=0)
        self.columnconfigure(1, weight=1)
        self.rowconfigure(0, weight=1)

        # Sidebar
        side = ttk.Frame(self); side.grid(row=0,column=0,sticky="nsw", padx=(8,6), pady=8)
        for i in range(8): side.rowconfigure(i, weight=0)
        side.rowconfigure(9, weight=1)

        self.btns = {}
        def add_btn(text, cmd):
            b = ttk.Button(side, text=text, command=cmd, width=24)
            b.pack(anchor="w", pady=4, fill="x")
            self.btns[text]=b

        add_btn("Oracle Databases", self._show_oracle)
        add_btn("SQL Server Databases", self._show_sqlserver)
        ttk.Separator(side, orient="horizontal").pack(fill="x", pady=6)
        add_btn("Linux/Unix Servers", self._show_linux)
        add_btn("Windows Servers", self._show_windows)

        # Content area
        self.content = ttk.Frame(self); self.content.grid(row=0,column=1,sticky="nsew", padx=(0,8), pady=8)
        self.content.rowconfigure(0, weight=1); self.content.columnconfigure(0, weight=1)

        # Launch last tab
        last = self.cfg.get("last_tab","Oracle")
        if last == "SQL": self._show_sqlserver()
        elif last == "Linux": self._show_linux()
        elif last == "Windows": self._show_windows()
        else: self._show_oracle()

    def _swap(self, widget, tabname: str):
        for child in self.content.winfo_children():
            child.destroy()
        widget.grid(row=0,column=0,sticky="nsew")
        self.cfg["last_tab"]=tabname; _save_cfg(self.cfg)

    # --- Oracle ---
    def _show_oracle(self):
        try:
            mod = _lazy_import_oracle()
            frame = mod.create(self.content) if hasattr(mod, "create") else getattr(mod, "OraclePlaceholder", _ModulePlaceholder)(self.content, "Oracle", "Missing create()")
        except Exception as e:
            frame = _ModulePlaceholder(self.content, "Oracle", str(e))
        self._swap(frame, "Oracle")

    # --- SQL Server ---
    def _show_sqlserver(self):
        try:
            mod = _lazy_import_sqlserver()
            frame = mod.create(self.content) if hasattr(mod, "create") else getattr(mod, "SqlServerPlaceholder", _ModulePlaceholder)(self.content, "SQL Server", "Missing create()")
        except Exception as e:
            frame = _ModulePlaceholder(self.content, "SQL Server", str(e))
        self._swap(frame, "SQL")

    # --- Linux/Unix ---
    def _show_linux(self):
        try:
            mod = _lazy_import_linux()
            if hasattr(mod, "create"):
                frame = mod.create(self.content)
            else:
                klass = getattr(mod, "LinuxPlaceholder", getattr(mod, "LinuxMonitorApp", _ModulePlaceholder))
                if klass is _ModulePlaceholder:
                    frame = klass(self.content, "Linux/Unix", "Missing create()")
                else:
                    frame = klass(self.content)
        except Exception as e:
            frame = _ModulePlaceholder(self.content, "Linux/Unix", str(e))
        self._swap(frame, "Linux")

    # --- Windows ---
    def _show_windows(self):
        try:
            mod = _lazy_import_windows()
            if hasattr(mod, "create"):
                frame = mod.create(self.content)
            else:
                klass = getattr(mod, "WindowsPlaceholder", getattr(mod, "WindowsMonitorApp", _ModulePlaceholder))
                if klass is _ModulePlaceholder:
                    frame = klass(self.content, "Windows", "Missing create()")
                else:
                    frame = klass(self.content)
        except Exception as e:
            frame = _ModulePlaceholder(self.content, "Windows", str(e))
        self._swap(frame, "Windows")

def main():
    root = tk.Tk()
    root.title(APP_NAME + " - Launcher")
    root.geometry("1180x720")
    app = RouterApp(root)
    app.pack(fill="both", expand=True)
    root.mainloop()

if __name__ == "__main__":
    main()
