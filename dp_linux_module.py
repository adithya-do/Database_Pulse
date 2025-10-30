#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Linux/Unix Servers module for Database Pulse.
Collects lightweight metrics via SSH (paramiko if available, else 'ssh' CLI).
Columns:
S.No, Server Name, Environment, Status, OS TYPE, OS Version, Memory Allocated (GB), CPU Count,
Memory Usage %, CPU Load Avg %, FS>90% (count), Last Checked, Check Status, Error
"""
from __future__ import annotations

import base64, json, os, re, shlex, subprocess, sys, threading, time
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import tkinter as tk
from tkinter import filedialog, messagebox, ttk
from tkinter import font as tkfont

APP_NAME = "Database Pulse"
APP_VERSION = "Database Pulse v1.2"

GOOD = "✅"; BAD = "❌"; DEFAULT_INTERVAL_SEC = 300

# Optional dep: paramiko for SSH
try:
    import paramiko  # type: ignore
except Exception:
    paramiko = None  # type: ignore

def _base_dir() -> Path:
    if getattr(sys, "frozen", False):
        return Path(sys.executable).resolve().parent
    return Path(__file__).resolve().parent

CONFIG_DIR = (_base_dir() / "config"); CONFIG_DIR.mkdir(parents=True, exist_ok=True)
CONFIG_PATH = CONFIG_DIR / "linux_config.json"

def _win_protect(data: bytes) -> str:
    try:
        import ctypes, ctypes.wintypes as wt
        class DATA_BLOB(ctypes.Structure):
            _fields_ = [("cbData", wt.DWORD), ("pbData", ctypes.POINTER(ctypes.c_char))]
        CryptProtectData = ctypes.windll.crypt32.CryptProtectData
        blob_in = DATA_BLOB(len(data), ctypes.cast(ctypes.create_string_buffer(data), ctypes.POINTER(ctypes.c_char)))
        blob_out = DATA_BLOB()
        if not CryptProtectData(ctypes.byref(blob_in), None, None, None, None, 0, ctypes.byref(blob_out)):
            raise OSError("CryptProtectData failed")
        try:
            encrypted = ctypes.string_at(blob_out.pbData, blob_out.cbData)
        finally:
            ctypes.windll.kernel32.LocalFree(blob_out.pbData)
        import base64 as b64
        return b64.b64encode(encrypted).decode("ascii")
    except Exception:
        import base64 as b64
        return b64.b64encode(data).decode("ascii")

def _win_unprotect(s: str) -> bytes:
    import base64 as b64
    raw = b64.b64decode(s.encode("ascii"))
    try:
        import ctypes, ctypes.wintypes as wt
        class DATA_BLOB(ctypes.Structure):
            _fields_ = [("cbData", wt.DWORD), ("pbData", ctypes.POINTER(ctypes.c_char))]
        CryptUnprotectData = ctypes.windll.crypt32.CryptUnprotectData
        blob_in = DATA_BLOB(len(raw), ctypes.cast(ctypes.create_string_buffer(raw), ctypes.POINTER(ctypes.c_char)))
        blob_out = DATA_BLOB()
        if not CryptUnprotectData(ctypes.byref(blob_in), None, None, None, None, 0, ctypes.byref(blob_out)):
            raise OSError("CryptUnprotectData failed")
        try:
            decrypted = ctypes.string_at(blob_out.pbData, blob_out.cbData)
        finally:
            ctypes.windll.kernel32.LocalFree(blob_out.pbData)
        return decrypted
    except Exception:
        return raw

def _encrypt_password(plain: Optional[str]) -> Optional[str]:
    if not plain: return None
    import base64 as b64
    if sys.platform.startswith("win"): return _win_protect(plain.encode("utf-8"))
    return b64.b64encode(plain.encode("utf-8")).decode("ascii")

def _decrypt_password(enc: Optional[str]) -> Optional[str]:
    if not enc: return None
    import base64 as b64
    try:
        if sys.platform.startswith("win"): return _win_unprotect(enc).decode("utf-8")
        return b64.b64decode(enc.encode("ascii")).decode("utf-8")
    except Exception: return None

@dataclass
class HostTarget:
    name: str
    host: str
    port: int = 22
    environment: str = "NON-PROD"
    username: Optional[str] = None
    auth: str = "password"  # "password" or "key"
    password_enc: Optional[str] = None
    key_path: Optional[str] = None
    key_pass_enc: Optional[str] = None

@dataclass
class HostHealth:
    status: str = "DOWN"
    os_type: str = "-"
    os_version: str = "-"
    mem_gb: Optional[float] = None
    cpu_count: Optional[int] = None
    mem_pct: Optional[float] = None
    cpu_load_pct: Optional[float] = None
    fs_crit_count: Optional[int] = None
    error: str = ""
    elapsed_ms: int = 0
    ts: str = field(default_factory=lambda: datetime.now().strftime("%Y-%m-%d %H:%M:%S"))

def logical_columns() -> List[str]:
    return [
        "S.No","Server Name","Environment","Status",
        "OS TYPE","OS Version","Memory Allocated (GB)","CPU Count",
        "Memory Usage %","CPU Load Avg %","FS>90%",
        "Last Checked","Check Status","Error",
    ]

FILTERABLE_COLUMNS = {"Server Name","Environment","Status","OS TYPE"}

def default_config() -> Dict[str, Any]:
    cols = logical_columns()
    return {
        "interval_sec": DEFAULT_INTERVAL_SEC,
        "hosts": [],
        "ssh_path": "",  # optional: force path to ssh CLI
        "last_health": {},
        "auto_run": False,
        "column_order": cols[:],
        "visible_columns": cols[:],
        "email_columns": cols[:],
        "column_widths": {},
        "active_filter": [],
        "header_filters": {},
    }

def _serialize_host(h: HostTarget) -> Dict[str, Any]:
    return {
        "name": h.name, "host": h.host, "port": h.port, "environment": h.environment,
        "username": h.username, "auth": h.auth, "password_enc": h.password_enc,
        "key_path": h.key_path, "key_pass_enc": h.key_pass_enc,
    }

def _hydrate_host(d: Dict[str, Any]) -> HostTarget:
    return HostTarget(
        name=d.get("name",""), host=d.get("host",""), port=int(d.get("port",22) or 22),
        environment=d.get("environment","NON-PROD"), username=d.get("username"),
        auth=d.get("auth","password"), password_enc=d.get("password_enc"),
        key_path=d.get("key_path"), key_pass_enc=d.get("key_pass_enc"),
    )

def load_config() -> Dict[str, Any]:
    if CONFIG_PATH.exists():
        try:
            with open(CONFIG_PATH,"r",encoding="utf-8") as f: cfg=json.load(f)
            base = default_config()
            for k,v in cfg.items():
                base[k] = v if k != "hosts" else [_serialize_host(_hydrate_host(x)) for x in (v or [])]
            for k, v in {"last_health":{}, "column_order":default_config()["column_order"], "visible_columns":default_config()["visible_columns"], "email_columns":default_config()["email_columns"], "column_widths":{}, "active_filter":[], "header_filters":{}}.items():
                base.setdefault(k, v)
            return base
        except Exception: pass
    return default_config()

def save_config(cfg: Dict[str, Any]):
    out=dict(cfg)
    out["hosts"]=[_serialize_host(_hydrate_host(h) if isinstance(h,dict) else h) for h in cfg.get("hosts",[])]
    with open(CONFIG_PATH,"w",encoding="utf-8") as f: json.dump(out,f,indent=2,default=str)

# ---------------- SSH helpers ----------------
def _ssh_exec_with_paramiko(h: HostTarget, cmd: str, timeout: int = 15) -> Tuple[int, str, str]:
    if not paramiko:
        raise RuntimeError("paramiko not available")
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    kwargs = {"hostname": h.host, "port": h.port, "username": h.username or ""}
    if h.auth == "key":
        pkey = None
        key_pass = _decrypt_password(h.key_pass_enc) if h.key_pass_enc else None
        if h.key_path:
            try:
                pkey = paramiko.RSAKey.from_private_key_file(h.key_path, password=key_pass)
            except Exception:
                try:
                    pkey = paramiko.Ed25519Key.from_private_key_file(h.key_path, password=key_pass)
                except Exception:
                    pkey = None
        if pkey:
            kwargs["pkey"] = pkey
        else:
            kwargs["key_filename"] = h.key_path
            if key_pass:
                kwargs["passphrase"] = key_pass
    else:
        pwd = _decrypt_password(h.password_enc) if h.password_enc else None
        if pwd:
            kwargs["password"] = pwd
    client.connect(timeout=timeout, **kwargs)
    try:
        stdin, stdout, stderr = client.exec_command(cmd, timeout=timeout)
        out = stdout.read().decode("utf-8", errors="ignore")
        err = stderr.read().decode("utf-8", errors="ignore")
        rc = stdout.channel.recv_exit_status()
        return rc, out, err
    finally:
        client.close()

def _ssh_exec_with_cli(cfg: Dict[str, Any], h: HostTarget, cmd: str, timeout: int = 15) -> Tuple[int, str, str]:
    ssh = (cfg.get("ssh_path") or "ssh").strip()
    user_prefix = f"{(h.username or '').strip()}@" if h.username else ""
    port_part = f"-p {h.port}" if h.port else ""
    # Password auth via CLI would require sshpass; we won't attempt that. Expect key-based when CLI path is used.
    full_cmd = f'{ssh} -o BatchMode=yes -o StrictHostKeyChecking=no -o ConnectTimeout={timeout} {port_part} {user_prefix}{h.host} {shlex.quote(cmd)}'
    try:
        p = subprocess.Popen(full_cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        out_b, err_b = p.communicate(timeout=timeout+5)
        return p.returncode, out_b.decode("utf-8","ignore"), err_b.decode("utf-8","ignore")
    except subprocess.TimeoutExpired:
        try: p.kill()
        except Exception: pass
        return 1, "", "ssh timeout"
    except FileNotFoundError:
        return 2, "", "ssh executable not found"
    except Exception as e:
        return 3, "", str(e)

def ssh_exec(cfg: Dict[str, Any], h: HostTarget, cmd: str, timeout: int = 15) -> Tuple[int,str,str]:
    # Prefer paramiko when password auth is desired; else try CLI
    if h.auth == "password":
        if paramiko:
            return _ssh_exec_with_paramiko(h, cmd, timeout=timeout)
        else:
            return 3, "", "paramiko not installed (password auth requires paramiko)"
    else:
        # key-based
        if paramiko:
            try:
                return _ssh_exec_with_paramiko(h, cmd, timeout=timeout)
            except Exception as e:
                # fallback to CLI
                pass
        return _ssh_exec_with_cli(cfg, h, cmd, timeout=timeout)

# ---------------- Metrics ----------------
def _parse_os_info(text: str) -> Tuple[str,str]:
    # Try lines like: NAME=..., VERSION_ID=..., PRETTY_NAME=...
    name = version = ""
    try:
        kv = {}
        for line in text.splitlines():
            line=line.strip()
            if "=" in line:
                k, v = line.split("=",1)
                kv[k.strip()] = v.strip().strip('"')
        name = kv.get("NAME") or kv.get("ID","").capitalize()
        version = kv.get("VERSION") or kv.get("VERSION_ID","")
    except Exception:
        pass
    return name or "-", version or "-"

def collect_metrics(cfg: Dict[str, Any], h: HostTarget) -> HostHealth:
    t0 = time.time()
    sh = r"""
set -o pipefail 2>/dev/null || true
OSR=""
if [ -f /etc/os-release ]; then
  OSR=$(cat /etc/os-release)
fi
NAME=""; VER=""
if [ -n "$OSR" ]; then
  NAME=$(echo "$OSR" | awk -F'=' '/^NAME=/ {gsub(/"/,"",$2); print $2; exit}')
  VER=$(echo "$OSR" | awk -F'=' '/^VERSION=/ {gsub(/"/,"",$2); print $2; exit}')
fi
if [ -z "$NAME" ]; then NAME=$(uname -s 2>/dev/null); fi
if [ -z "$VER" ]; then VER=$(uname -r 2>/dev/null); fi
MEMTOTAL=$(awk '/MemTotal/ {print int($2/1024)}' /proc/meminfo 2>/dev/null) # MB
MEMAVAIL=$(awk '/MemAvailable/ {print int($2/1024)}' /proc/meminfo 2>/dev/null)
if [ -z "$MEMAVAIL" ] || [ "$MEMAVAIL" -eq 0 ]; then
  MEMFREE=$(awk '/MemFree/ {print int($2/1024)}' /proc/meminfo 2>/dev/null)
  MEMBUFF=$(awk '/Buffers/ {print int($2/1024)}' /proc/meminfo 2>/dev/null)
  MEMCACH=$(awk '/^Cached/ {print int($2/1024)}' /proc/meminfo 2>/dev/null)
  MEMAVAIL=$((MEMFREE + MEMBUFF + MEMCACH))
fi
CPUS=$( (nproc 2>/dev/null) || (getconf _NPROCESSORS_ONLN 2>/dev/null) || echo 1 )
LOAD1=$(awk '{print $1}' /proc/loadavg 2>/dev/null)
DFCRIT=$(df -P -k 2>/dev/null | awk 'NR>1 {gsub(/%/,"",$5); if ($5+0>=90) c++} END {print c+0}')
printf '%s|%s|%s|%s|%s|%s\n' "$NAME" "$VER" "$MEMTOTAL" "$MEMAVAIL" "$CPUS" "$LOAD1"
echo "$DFCRIT"
"""
    cmd = f"/bin/sh -lc {shlex.quote(sh)}"
    rc, out, err = ssh_exec(cfg, h, cmd, timeout=20)
    hres = HostHealth()
    hres.elapsed_ms = int((time.time()-t0)*1000)
    if rc != 0:
        hres.status = "DOWN"
        hres.error = err.strip() or out.strip() or f"ssh rc={rc}"
        return hres

    try:
        lines = out.strip().splitlines()
        first = lines[0].strip()
        parts = first.split("|")
        name = parts[0] if len(parts)>0 else "-"
        ver  = parts[1] if len(parts)>1 else "-"
        mem_total_mb = int(parts[2]) if len(parts)>2 and parts[2].isdigit() else 0
        mem_avail_mb = int(parts[3]) if len(parts)>3 and parts[3].isdigit() else 0
        cpus = int(parts[4]) if len(parts)>4 and re.match(r'^\d+$', parts[4]) else 1
        load1 = float(parts[5]) if len(parts)>5 else 0.0
        dfcrit = int(lines[1].strip()) if len(lines)>1 and re.match(r'^\d+$', lines[1].strip()) else 0

        mem_gb = round(mem_total_mb/1024.0,1) if mem_total_mb else None
        mem_used_pct = None
        if mem_total_mb > 0:
            used = mem_total_mb - mem_avail_mb
            mem_used_pct = round(used*100.0 / max(1, mem_total_mb), 1)

        cpu_pct = None
        if cpus and cpus>0:
            cpu_pct = round(min(100.0, (load1 / cpus) * 100.0), 1)

        hres.status = "UP"
        hres.os_type = name or "-"
        hres.os_version = ver or "-"
        hres.mem_gb = mem_gb
        hres.cpu_count = cpus
        hres.mem_pct = mem_used_pct
        hres.cpu_load_pct = cpu_pct
        hres.fs_crit_count = dfcrit
        return hres
    except Exception as e:
        hres.status = "DOWN"
        hres.error = f"parse error: {e}"
        return hres

class LinuxMonitorApp(ttk.Frame):
    LOGICAL_COLUMNS = tuple(logical_columns())
    STATUS_COLUMNS = {"Status","OS TYPE","OS Version","Memory Allocated (GB)","CPU Count","Memory Usage %","CPU Load Avg %","FS>90%","Last Checked","Check Status","Error"}

    def __init__(self, master):
        super().__init__(master)
        self.cfg = load_config()
        self.interval_sec = int(self.cfg.get("interval_sec", DEFAULT_INTERVAL_SEC))
        self.hosts = [_hydrate_host(h) if isinstance(h,dict) else h for h in self.cfg.get("hosts",[])]
        self.last_health = self.cfg.get("last_health", {})
        self._auto_flag = False

        self._active_filter = [tuple(x) for x in self.cfg.get("active_filter", [])]
        self._header_filters = {}
        for c in FILTERABLE_COLUMNS:
            raw = self.cfg.get("header_filters", {}).get(c, [])
            self._header_filters[c] = (set(raw) if raw else None)
        self._detached = set()

        self._build_ui()
        self._refresh_table_from_hosts()
        self._load_last_health_into_rows()
        self._apply_all_filters()

        if self.cfg.get("auto_run"):
            self.auto_var.set(True); self._start_auto()

    def _build_ui(self):
        self.grid_rowconfigure(0,weight=0); self.grid_rowconfigure(1,weight=0); self.grid_rowconfigure(2,weight=1)
        self.grid_columnconfigure(0,weight=1)

        self._font = tkfont.nametofont("TkDefaultFont")
        style = ttk.Style(self)
        try: style.theme_use("clam")
        except Exception: pass
        style.configure("LX.Treeview.Heading", background="#cfe8ff", foreground="#000", font=(self._font.actual("family"), self._font.actual("size"), "bold"))
        style.map("LX.Treeview.Heading", background=[("active","#b7dbff")])
        style.configure("LX.Treeview", rowheight=22)

        t1 = ttk.Frame(self); t1.grid(row=0,column=0,sticky="ew",padx=8,pady=(8,3))
        self.interval_var = tk.IntVar(value=self.interval_sec)
        ttk.Label(t1,text="Interval (sec):").pack(side=tk.LEFT)
        ttk.Spinbox(t1,from_=30,to=3600,textvariable=self.interval_var,width=8).pack(side=tk.LEFT,padx=(4,10))
        self.auto_var = tk.BooleanVar(value=self.cfg.get("auto_run",False))
        ttk.Checkbutton(t1,text="Auto-run",variable=self.auto_var,command=self._toggle_auto).pack(side=tk.LEFT,padx=(0,8))
        ttk.Button(t1,text="Run All",command=self.run_all_once).pack(side=tk.LEFT)
        ttk.Button(t1,text="Run Selected",command=self.run_selected_once).pack(side=tk.LEFT,padx=(6,10))
        ttk.Button(t1,text="Clear All",command=self._clear_all_rows).pack(side=tk.LEFT,padx=(6,4))
        ttk.Button(t1,text="Clear Selected",command=self._clear_selected_row).pack(side=tk.LEFT,padx=(4,10))
        ttk.Button(t1,text="Add Host",command=self._add_dialog).pack(side=tk.LEFT,padx=(10,0))
        ttk.Button(t1,text="Edit Host",command=self._edit_selected).pack(side=tk.LEFT)
        ttk.Button(t1,text="Remove Host",command=self._remove_selected).pack(side=tk.LEFT)
        ttk.Button(t1,text="Import Config",command=self._import_json).pack(side=tk.LEFT,padx=(10,0))
        ttk.Button(t1,text="Export Config",command=self._export_json).pack(side=tk.LEFT)

        ttk.Separator(t1,orient="vertical").pack(side=tk.LEFT,fill=tk.Y,padx=8)
        ttk.Button(t1,text="Customize Columns",command=self._customize_columns).pack(side=tk.LEFT,padx=(0,6))
        ttk.Button(t1,text="Select Columns",command=self._select_columns_dialog).pack(side=tk.LEFT,padx=(0,6))
        ttk.Button(t1,text="Filter…",command=self._open_filter_dialog).pack(side=tk.LEFT,padx=(0,6))
        ttk.Button(t1,text="Clear Filter",command=self._clear_filter).pack(side=tk.LEFT,padx=(0,10))
        ttk.Label(t1,text="ssh path (optional):").pack(side=tk.LEFT,padx=(0,4))
        self.ssh_path_var = tk.StringVar(value=self.cfg.get("ssh_path",""))
        ttk.Entry(t1,textvariable=self.ssh_path_var,width=28).pack(side=tk.LEFT,padx=(0,4))
        ttk.Button(t1,text="Browse",command=self._pick_ssh).pack(side=tk.LEFT)

        tree_frame = ttk.Frame(self); tree_frame.grid(row=2,column=0,sticky="nsew",padx=8,pady=8)
        self.tree = ttk.Treeview(tree_frame,columns=self.LOGICAL_COLUMNS,show="headings",height=20,style="LX.Treeview")
        vsb = ttk.Scrollbar(tree_frame,orient="vertical",command=self.tree.yview)
        xsb = ttk.Scrollbar(tree_frame,orient="horizontal",command=self.tree.xview)
        self.tree.configure(yscrollcommand=vsb.set,xscrollcommand=xsb.set)
        vsb.pack(side=tk.RIGHT,fill=tk.Y); self.tree.pack(side=tk.TOP,fill=tk.BOTH,expand=True); xsb.pack(side=tk.BOTTOM,fill=tk.X)

        for col in self.LOGICAL_COLUMNS:
            self.tree.heading(col,text=col,command=lambda c=col: self._sort_by_column(c,False))
            self.tree.column(col,width=140,stretch=True,anchor="w")

        order=[c for c in self.cfg.get("column_order",list(self.LOGICAL_COLUMNS)) if c in self.LOGICAL_COLUMNS]
        if not order or order[0]!="S.No": order=["S.No"]+[c for c in self.LOGICAL_COLUMNS if c!="S.No"]
        visible=[c for c in self.cfg.get("visible_columns",order) if c in self.LOGICAL_COLUMNS]
        if not visible or visible[0]!="S.No": visible=["S.No"]+[c for c in visible if c!="S.No"]
        display=[c for c in order if c in visible]; self.tree["displaycolumns"]=display

        for col,w in self.cfg.get("column_widths",{}).items():
            try: self.tree.column(col,width=int(w))
            except Exception: pass

        self.menu = tk.Menu(self,tearoff=0)
        self.menu.add_command(label="Copy Cell",command=self._copy_cell)
        self.menu.add_separator()
        self.menu.add_command(label="Copy Server Name",command=lambda: self._copy_by_col("Server Name"))
        self.menu.add_command(label="Copy Error",command=lambda: self._copy_by_col("Error"))
        self.tree.bind("<Button-3>",self._on_button3)
        self.tree.bind("<ButtonRelease-1>",lambda e: self._persist_column_layout())

        bottom=ttk.Frame(self); bottom.grid(row=3,column=0,sticky="ew",padx=8,pady=4)
        self.status_var=tk.StringVar(value="Idle")
        ttk.Label(bottom,textvariable=self.status_var).pack(side=tk.LEFT)

        self._refresh_heading_labels()

    # Column customization (reuse simple dialog from SQL module style)
    def _customize_columns(self): self._select_columns_dialog()

    def _select_columns_dialog(self):
        all_cols = list(self.LOGICAL_COLUMNS)
        current = list(self.tree["displaycolumns"]) or all_cols
        if "S.No" not in current:
            current.insert(0, "S.No")
        hidden = [c for c in all_cols if c not in current]

        dlg = tk.Toplevel(self); dlg.title("Customize Columns"); dlg.geometry("640x360"); dlg.resizable(False, False)
        left = ttk.Frame(dlg); left.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=(10,5), pady=10)
        right = ttk.Frame(dlg); right.pack(side=tk.RIGHT, fill=tk.BOTH, expand=True, padx=(5,10), pady=10)

        ttk.Label(left, text="Visible (use buttons to reorder)").pack(anchor="w")
        lb_vis = tk.Listbox(left, selectmode=tk.EXTENDED, height=12)
        lb_vis.pack(fill=tk.BOTH, expand=True, pady=(4,6))
        for c in current: lb_vis.insert(tk.END, c)

        btns = ttk.Frame(left); btns.pack(fill=tk.X, pady=(0,6))
        def move_up():
            sel = list(lb_vis.curselection())
            for i in sel:
                if i <= 0 or lb_vis.get(i) == "S.No": continue
                t = lb_vis.get(i); lb_vis.delete(i); lb_vis.insert(i-1, t); lb_vis.selection_set(i-1)
        def move_down():
            sel = list(lb_vis.curselection()); sel.reverse()
            for i in sel:
                if i >= lb_vis.size()-1: continue
                t = lb_vis.get(i); lb_vis.delete(i); lb_vis.insert(i+1, t); lb_vis.selection_set(i+1)
        ttk.Button(btns, text="Move Up", command=move_up).pack(side=tk.LEFT)
        ttk.Button(btns, text="Move Down", command=move_down).pack(side=tk.LEFT, padx=(6,0))

        ttk.Label(right, text="Hidden").pack(anchor="w")
        lb_hid = tk.Listbox(right, selectmode=tk.EXTENDED, height=12)
        lb_hid.pack(fill=tk.BOTH, expand=True, pady=(4,6))
        for c in hidden: lb_hid.insert(tk.END, c)

        xfer = ttk.Frame(dlg); xfer.place(relx=0.48, rely=0.25)
        def add_to_visible():
            for i in lb_hid.curselection():
                c = lb_hid.get(i)
                if c not in lb_vis.get(0, tk.END): lb_vis.insert(tk.END, c)
            for i in reversed(lb_hid.curselection()): lb_hid.delete(i)
        def remove_from_visible():
            remove = [lb_vis.get(i) for i in lb_vis.curselection() if lb_vis.get(i) != "S.No"]
            for c in remove: lb_hid.insert(tk.END, c)
            for i in reversed(lb_vis.curselection()):
                if lb_vis.get(i) != "S.No": lb_vis.delete(i)
        ttk.Button(xfer, text="<< Hide", command=remove_from_visible).pack(pady=6)
        ttk.Button(xfer, text="Show >>", command=add_to_visible).pack(pady=6)

        footer = ttk.Frame(dlg); footer.pack(side=tk.BOTTOM, fill=tk.X, padx=10, pady=10)
        def apply_now():
            new_visible = list(lb_vis.get(0, tk.END))
            if not new_visible or new_visible[0] != "S.No":
                new_visible = ["S.No"] + [c for c in new_visible if c != "S.No"]
            self.tree["displaycolumns"] = new_visible
            self._persist_column_layout()
            dlg.destroy()
        ttk.Button(footer, text="Cancel", command=dlg.destroy).pack(side=tk.RIGHT, padx=(6,0))
        ttk.Button(footer, text="Apply", command=apply_now).pack(side=tk.RIGHT)

        dlg.transient(self); dlg.grab_set(); dlg.wait_window()

    def _open_filter_dialog(self):
        dlg = tk.Toplevel(self); dlg.title("Advanced Filter"); dlg.geometry("600x320"); dlg.resizable(False, False)
        container = ttk.Frame(dlg); container.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        ttk.Label(container, text="Rows must satisfy ALL of these conditions:").pack(anchor="w")
        rows_frame = ttk.Frame(container); rows_frame.pack(fill=tk.BOTH, expand=True, pady=(6,6))
        conditions = []

        def add_condition(initial=None):
            row = ttk.Frame(rows_frame); row.pack(fill=tk.X, pady=2)
            col_var=tk.StringVar(value=(initial[0] if initial else "Server Name"))
            op_var =tk.StringVar(value=(initial[1] if initial else "contains"))
            val_var=tk.StringVar(value=(initial[2] if initial else ""))
            ttk.Combobox(row, values=list(self.LOGICAL_COLUMNS), textvariable=col_var, state="readonly", width=24).pack(side=tk.LEFT)
            ttk.Combobox(row, values=["contains","equals",">",">=","<","<=","!="], textvariable=op_var, state="readonly", width=10).pack(side=tk.LEFT, padx=6)
            ttk.Entry(row, textvariable=val_var, width=28).pack(side=tk.LEFT, padx=6)
            def remove_row():
                conditions.remove((col_var, op_var, val_var)); row.destroy()
            ttk.Button(row, text="Remove", command=remove_row).pack(side=tk.LEFT, padx=6)
            conditions.append((col_var, op_var, val_var))

        for c in self._active_filter: add_condition(c)
        if not self._active_filter: add_condition()

        btns = ttk.Frame(container); btns.pack(fill=tk.X)
        ttk.Button(btns, text="Add Condition", command=lambda: add_condition()).pack(side=tk.LEFT)
        def apply_now():
            self._active_filter=[(c.get(), o.get(), v.get()) for (c,o,v) in conditions if v.get().strip()!=""]
            self._apply_all_filters(); dlg.destroy()
        ttk.Button(btns, text="Cancel", command=dlg.destroy).pack(side=tk.RIGHT, padx=(6,0))
        ttk.Button(btns, text="Apply", command=apply_now).pack(side=tk.RIGHT)
        dlg.transient(self); dlg.grab_set(); dlg.wait_window()

    
    def _apply_all_filters(self):
        """
        Apply both header filters and advanced conditions.
        Rows that do not pass are detached (hidden) while preserved in self._detached.
        """
        import re
        def get_val(iid: str, col: str) -> str:
            try:
                idx = self.LOGICAL_COLUMNS.index(col)
                vals = self.tree.item(iid)["values"]
                return "" if idx >= len(vals) else str(vals[idx])
            except Exception:
                return ""

        def parse_num(s: str):
            try:
                # Extract first numeric token (handles "✅ 92.5%" etc.)
                m = re.search(r'[-+]?\d+(?:\.\d+)?', s)
                return float(m.group(0)) if m else None
            except Exception:
                return None

        def header_pass(iid: str) -> bool:
            for col, sel in self._header_filters.items():
                if sel is None:  # no restriction
                    continue
                v = get_val(iid, col)
                if v not in sel:
                    return False
            return True

        def cond_pass(iid: str) -> bool:
            for col, op, val in self._active_filter:
                v = get_val(iid, col)
                if op == "contains":
                    if val.lower() not in v.lower():
                        return False
                elif op == "equals":
                    if v.lower() != val.lower():
                        return False
                elif op in (">", ">=", "<", "<=", "!="):
                    a = parse_num(v)
                    b = parse_num(val) if parse_num(val) is not None else None
                    if a is None or b is None:
                        return False
                    if op == ">"  and not (a >  b): return False
                    if op == ">=" and not (a >= b): return False
                    if op == "<"  and not (a <  b): return False
                    if op == "<=" and not (a <= b): return False
                    if op == "!=" and not (a != b): return False
                else:
                    # Unknown op -> fail safe as False
                    return False
            return True

        # Evaluate rows
        current = set(self.tree.get_children(""))
        all_rows = list(current) + list(self._detached)

        shown = 0
        for iid in all_rows:
            try:
                passes = header_pass(iid) and cond_pass(iid)
                if passes:
                    if iid in self._detached:
                        try:
                            self.tree.move(iid, "", "end")
                        except Exception:
                            pass
                        self._detached.discard(iid)
                    shown += 1
                else:
                    if iid in current:
                        try:
                            self.tree.detach(iid)
                        except Exception:
                            pass
                        self._detached.add(iid)
            except Exception:
                # On any per-row error, keep row visible
                if iid in self._detached:
                    try:
                        self.tree.move(iid, "", "end")
                    except Exception:
                        pass
                    self._detached.discard(iid)
                    shown += 1
        try:
            self._renumber()
        except Exception:
            pass
        try:
            self.status_var.set(f"Filter applied — {shown} row(s) visible")
        except Exception:
            pass
def _clear_filter(self):
        self._active_filter = []
        for k in list(self._header_filters.keys()): self._header_filters[k] = None
        self._refresh_heading_labels()
        self._apply_all_filters()

    def _on_button3(self,event):
        region=self.tree.identify_region(event.x,event.y)
        if region=="heading":
            colid=self.tree.identify_column(event.x)
            try: idx=int(colid.replace("#",""))-1; col=self.LOGICAL_COLUMNS[idx]
            except Exception: return
            if col in FILTERABLE_COLUMNS: self._open_header_filter(col)
        else:
            iid=self.tree.identify_row(event.y); cid=self.tree.identify_column(event.x)
            if iid:
                self.tree.selection_set(iid); self._context_row=iid; self._context_col=cid
                self.menu.tk_popup(event.x_root,event.y_root)

    def _open_header_filter(self,col:str):
        idx=self.LOGICAL_COLUMNS.index(col)
        all_iids=list(self.tree.get_children(""))+list(self._detached)
        distinct,seen=[],set()
        for iid in all_iids:
            try: vals=self.tree.item(iid)["values"]; v="" if idx>=len(vals) else str(vals[idx])
            except Exception: v=""
            if v not in seen: seen.add(v); distinct.append(v)
        distinct.sort(key=lambda s:s.lower())
        current_sel=self._header_filters.get(col)

        dlg=tk.Toplevel(self); dlg.title(f"Filter: {col}"); dlg.geometry("540x360"); dlg.resizable(False,False)
        ttk.Label(dlg,text=f"Filter column: {col}").pack(padx=8,pady=(8,4),anchor="w")
        body=ttk.Frame(dlg); body.pack(fill=tk.BOTH,expand=True,padx=8,pady=6)
        left=ttk.Frame(body); left.pack(side=tk.LEFT,fill=tk.BOTH,expand=True)
        right=ttk.Frame(body); right.pack(side=tk.RIGHT,fill=tk.BOTH,expand=True)

        ttk.Label(left,text="Available").pack(anchor="w")
        lb_all=tk.Listbox(left,selectmode=tk.EXTENDED,height=12); lb_all.pack(fill=tk.BOTH,expand=True,padx=(0,8),pady=(2,0))
        for v in distinct: lb_all.insert(tk.END, v if v else "(blank)")

        btns=ttk.Frame(body); btns.pack(side=tk.LEFT,fill=tk.Y,padx=6)
        def move(src,dst):
            items=[src.get(i) for i in src.curselection()]; existing=set(dst.get(0,tk.END))
            for it in items:
                if it not in existing: dst.insert(tk.END,it)
        ttk.Button(btns,text=">>",command=lambda: move(lb_all,lb_sel)).pack(pady=6)
        def remove_selected():
            sel=list(lb_sel.curselection()); sel.reverse()
            for i in sel: lb_sel.delete(i)
        ttk.Button(btns,text="<<",command=remove_selected).pack(pady=6)

        ttk.Label(right,text="Selected (will be shown)").pack(anchor="w")
        lb_sel=tk.Listbox(right,selectmode=tk.EXTENDED,height=12); lb_sel.pack(fill=tk.BOTH,expand=True,pady=(2,0))
        if current_sel is not None:
            for v in distinct:
                disp=v if v else "(blank)"
                if v in current_sel: lb_sel.insert(tk.END,disp)

        footer=ttk.Frame(dlg); footer.pack(fill=tk.X,padx=8,pady=8)
        def select_all():
            lb_sel.delete(0,tk.END)
            for v in distinct: lb_sel.insert(tk.END, v if v else "(blank)")
        def clear_all(): lb_sel.delete(0,tk.END)
        def apply_now():
            selected=list(lb_sel.get(0,tk.END)); selected=[("" if v=="(blank)" else v) for v in selected]
            if len(selected)==0: self._header_filters[col]=set()
            elif len(selected)==len(distinct): self._header_filters[col]=None
            else: self._header_filters[col]=set(selected)
            self.cfg["header_filters"]={k:(sorted(list(v)) if v else []) for k,v in self._header_filters.items() if k in FILTERABLE_COLUMNS}
            save_config(self.cfg); self._refresh_heading_labels(); self._apply_all_filters(); dlg.destroy()
        ttk.Button(footer,text="Select All",command=select_all).pack(side=tk.LEFT)
        ttk.Button(footer,text="Clear",command=clear_all).pack(side=tk.LEFT,padx=(6,0))
        ttk.Button(footer,text="Cancel",command=dlg.destroy).pack(side=tk.RIGHT,padx=(6,0))
        ttk.Button(footer,text="Apply",command=apply_now).pack(side=tk.RIGHT)
        dlg.transient(self); dlg.grab_set(); dlg.wait_window()

    def _refresh_heading_labels(self):
        for col in self.LOGICAL_COLUMNS:
            if col in FILTERABLE_COLUMNS:
                suffix=" ▼"; sel=self._header_filters.get(col)
                if sel is not None: suffix=" ▼•"
                self.tree.heading(col,text=col+suffix,command=lambda c=col: self._sort_by_column(c,False))
            else:
                self.tree.heading(col,text=col,command=lambda c=col: self._sort_by_column(c,False))

    def _toggle_auto(self):
        if self.auto_var.get(): self._start_auto()
        else: self._stop_auto()
        self.cfg["auto_run"]=self.auto_var.get(); save_config(self.cfg)

    def _start_auto(self):
        if getattr(self,"_auto_flag",False): return
        self._auto_flag=True; self.after(200,self._loop)

    def _stop_auto(self): self._auto_flag=False

    def _loop(self):
        if not self.auto_var.get(): return
        self._checks_async(self.hosts); self.after(self.interval_var.get()*1000,self._loop)

    def _pick_ssh(self):
        p=filedialog.askopenfilename(title="Locate ssh",filetypes=[("ssh","ssh*"),("All","*.*")])
        if p:
            self.ssh_path_var.set(p); self.cfg["ssh_path"]=p; save_config(self.cfg)

    def _persist_column_layout(self):
        widths={col:self.tree.column(col,option="width") for col in self.LOGICAL_COLUMNS}
        self.cfg["column_widths"]=widths
        visible=list(self.tree["displaycolumns"])
        full=self.cfg.get("column_order",list(self.LOGICAL_COLUMNS))
        new_full,seen=[],set()
        for c in visible:
            if c not in seen: new_full.append(c); seen.add(c)
        for c in full:
            if c not in seen and c in self.LOGICAL_COLUMNS: new_full.append(c); seen.add(c)
        self.cfg["column_order"]=new_full; self.cfg["visible_columns"]=visible; save_config(self.cfg)

    def _autosize_columns(self):
        pad=24; visible=list(self.tree["displaycolumns"]); font=tkfont.nametofont("TkDefaultFont")
        for col in visible:
            header_w=font.measure(col); max_w=header_w
            for iid in self.tree.get_children(""):
                vals=self.tree.item(iid)["values"]
                try:
                    idx=self.LOGICAL_COLUMNS.index(col); txt=str(vals[idx]) if idx<len(vals) else ""
                    tw=font.measure(txt); max_w=max(max_w,tw)
                except Exception: pass
            new_w=max(max_w+pad,90); cur=self.tree.column(col,option="width")
            if cur<new_w: self.tree.column(col,width=new_w)

    def _copy_cell(self):
        row=getattr(self,"_context_row",None); colid=getattr(self,"_context_col",None)
        if not row or not colid: return
        col_index=int(colid.replace("#",""))-1; vals=self.tree.item(row)["values"]
        text=str(vals[col_index]) if col_index<len(vals) else ""; self.clipboard_clear(); self.clipboard_append(text)

    def _copy_by_col(self,colname:str):
        sel=self.tree.selection()
        if not sel: return
        iid=sel[0]; vals=self.tree.item(iid)["values"]; idx=self.LOGICAL_COLUMNS.index(colname)
        text=str(vals[idx]) if idx<len(vals) else ""; self.clipboard_clear(); self.clipboard_append(text)

    def _generic_key(self,col:str,s:str):
        def pct_num(x:str)->float:
            try: return float(re.sub(r'[^0-9.\-]','',x))
            except Exception: return -1.0
        if col=="S.No":
            try: return (int(s),)
            except Exception: return (0,)
        if col in ("Status",): return (1 if str(s).strip().startswith(GOOD) else 0, s)
        if col in ("Memory Usage %","CPU Load Avg %"): return (pct_num(s),)
        if col=="FS>90%":
            try: return (int(re.sub(r'[^0-9]','',s)),)
            except Exception: return (-1,)
        if col in ("Last Checked",): 
            try:
                t = re.sub(r'^.*?(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}).*$', r'\1', str(s).strip())
                dt = datetime.strptime(t,"%Y-%m-%d %H:%M:%S")
                return (dt.timestamp(),)
            except Exception: return (float("-inf"),)
        return (str(s).lower(),)

    def _sort_by_column(self,col:str,descending:bool):
        rows=[(self._generic_key(col,self.tree.set(k,col)),k) for k in self.tree.get_children("")]
        rows.sort(reverse=descending,key=lambda x:x[0])
        for idx,(_,k) in enumerate(rows): self.tree.move(k,"",idx)
        self._renumber(); self.tree.heading(col,command=lambda c=col: self._sort_by_column(c,not descending))

    def _renumber(self):
        for i,iid in enumerate(self.tree.get_children(""),start=1):
            vals=list(self.tree.item(iid)["values"])
            if vals: vals[0]=i; self.tree.item(iid,values=vals)

    def _refresh_table_from_hosts(self):
        for i in self.tree.get_children(): self.tree.delete(i)
        for idx,h in enumerate(self.hosts,start=1):
            values=["-"]*len(self.LOGICAL_COLUMNS); values[0]=idx; values[1]=h.name; values[2]=h.environment
            self.tree.insert("",tk.END,iid=h.name,values=tuple(values))
        self._renumber(); 
        try: self._autosize_columns()
        except Exception: pass

    def _load_last_health_into_rows(self):
        for h in self.hosts:
            hdict=self.last_health.get(h.name)
            if not hdict: continue
            self._apply_persisted_row(h.name,hdict)
        try: self._autosize_columns()
        except Exception: pass

    def _mark_cell(self, ok: Optional[bool], text: str) -> str:
        if ok is True: return f"{GOOD} {text}"
        if ok is False: return f"{BAD} {text}"
        return text

    def _apply_persisted_row(self,name:str,h:Dict[str,Any]):
        vals=list(self.tree.item(name)["values"] or ["-"]*len(self.LOGICAL_COLUMNS))
        colidx={c:i for i,c in enumerate(self.LOGICAL_COLUMNS)}
        status_ok=(h.get("status","")=="UP")
        vals[colidx["Status"]]=self._mark_cell(status_ok,h.get("status","-"))
        vals[colidx["OS TYPE"]]=h.get("os_type","-")
        vals[colidx["OS Version"]]=h.get("os_version","-")
        mem_gb=h.get("mem_gb"); vals[colidx["Memory Allocated (GB)"]]=(f"{mem_gb:.1f}" if isinstance(mem_gb,(int,float)) else "-")
        vals[colidx["CPU Count"]]=h.get("cpu_count","-")
        mem_pct=h.get("mem_pct"); vals[colidx["Memory Usage %"]]=self._mark_cell(None if mem_pct is None else (mem_pct<90.0), f"{mem_pct:.1f}%" if mem_pct is not None else "-")
        cpu_pct=h.get("cpu_load_pct"); vals[colidx["CPU Load Avg %"]]=self._mark_cell(None if cpu_pct is None else (cpu_pct<50.0), f"{cpu_pct:.1f}%" if cpu_pct is not None else "-")
        fscrit=int(h.get("fs_crit_count",0) or 0); vals[colidx["FS>90%"]]=self._mark_cell(fscrit==0, str(fscrit))
        vals[colidx["Last Checked"]]=h.get("ts","-"); vals[colidx["Check Status"]]="Complete"; vals[colidx["Error"]]=h.get("error","")
        self.tree.item(name,values=vals)

    def _persist_hosts(self):
        self.cfg["interval_sec"]=self.interval_var.get()
        self.cfg["hosts"]=[_serialize_host(h) for h in self.hosts]
        self.cfg["ssh_path"]=self.ssh_path_var.get().strip()
        self.cfg["auto_run"]=self.auto_var.get()
        self.cfg["active_filter"]=list(self._active_filter)
        self.cfg["header_filters"]={k:(sorted(list(v)) if v else []) for k,v in self._header_filters.items() if k in FILTERABLE_COLUMNS}
        save_config(self.cfg)

    def _import_json(self):
        p=filedialog.askopenfilename(title="Import config (.json)",filetypes=[["JSON","*.json"]])
        if not p: return
        try:
            with open(p,"r",encoding="utf-8") as f: cfg=json.load(f)
            self.cfg.update(cfg)
            self.interval_var.set(int(self.cfg.get("interval_sec",DEFAULT_INTERVAL_SEC)))
            self.ssh_path_var.set(self.cfg.get("ssh_path",""))
            self.auto_var.set(bool(self.cfg.get("auto_run",False)))
            self.hosts=[_hydrate_host(h) for h in self.cfg.get("hosts",[])]
            self.last_health=self.cfg.get("last_health",{})
            self._active_filter=[tuple(x) for x in self.cfg.get("active_filter",[])]
            hf={}
            for k,v in self.cfg.get("header_filters",{}).items():
                if k in FILTERABLE_COLUMNS: hf[k]=set(v) if v else None
            self._header_filters={c:hf.get(c,None) for c in FILTERABLE_COLUMNS}
            self._detached.clear()
            order=[c for c in self.cfg.get("column_order",list(self.LOGICAL_COLUMNS)) if c in self.LOGICAL_COLUMNS]
            if order and order[0]!="S.No": order=["S.No"]+[c for c in order if c!="S.No"]
            visible=[c for c in self.cfg.get("visible_columns",order) if c in self.LOGICAL_COLUMNS]
            if visible and visible[0]!="S.No": visible=["S.No"]+[c for c in visible if c!="S.No"]
            self.tree["displaycolumns"]=visible
            if "column_widths" in self.cfg:
                for col,w in self.cfg["column_widths"].items():
                    try: self.tree.column(col,width=int(w))
                    except Exception: pass
            save_config(self.cfg)
            self._refresh_table_from_hosts(); self._load_last_health_into_rows(); self._refresh_heading_labels(); self._apply_all_filters()
            messagebox.showinfo(APP_NAME,"Imported configuration.")
        except Exception as e:
            messagebox.showerror(APP_NAME,f"Failed to import: {e}")

    def _export_json(self):
        p=filedialog.asksaveasfilename(title="Export config",defaultextension=".json",initialfile="linux_config.json")
        if not p: return
        try:
            export={
                "interval_sec": self.interval_var.get(),
                "hosts": [_serialize_host(h) for h in self.hosts],
                "ssh_path": self.ssh_path_var.get().strip(),
                "last_health": self.last_health,
                "auto_run": self.auto_var.get(),
                "column_order": list(self.cfg.get("column_order", self.LOGICAL_COLUMNS)),
                "visible_columns": list(self.tree["displaycolumns"]),
                "email_columns": list(self.cfg.get("email_columns", self.LOGICAL_COLUMNS)),
                "column_widths": {c: self.tree.column(c,"width") for c in self.LOGICAL_COLUMNS},
                "active_filter": list(self._active_filter),
                "header_filters": {k:(sorted(list(v)) if v else []) for k,v in self._header_filters.items() if k in FILTERABLE_COLUMNS},
            }
            with open(p,"w",encoding="utf-8") as f: json.dump(export,f,indent=2)
            messagebox.showinfo(APP_NAME,"Exported configuration.")
        except Exception as e:
            messagebox.showerror(APP_NAME,f"Failed to export: {e}")

    def run_all_once(self): self._checks_async(self.hosts)

    def run_selected_once(self):
        sel=self.tree.selection()
        if not sel: messagebox.showinfo(APP_NAME,"Select a row (Host) to run."); return
        name=sel[0]; host=next((x for x in self.hosts if x.name==name),None)
        if not host: messagebox.showerror(APP_NAME,"Selected host not found."); return
        self._checks_async([host])

    def _set_check_status(self,name:str,status:str):
        if name in self._detached:
            self.tree.move(name,"","end"); self._detached.discard(name)
        if name in self.tree.get_children("") or name in self._detached:
            vals=list(self.tree.item(name)["values"] or ["-"]*len(self.LOGICAL_COLUMNS))
            idx=self.LOGICAL_COLUMNS.index("Check Status")
            if len(vals)<=idx: vals+=[""]*(idx+1-len(vals))
            vals[idx]=status; self.tree.item(name,values=vals); self._apply_all_filters()

    def _checks_async(self,hosts:List[HostTarget]):
        for t in hosts: self._set_check_status(t.name,"In Progress")
        def job(ht:HostTarget):
            h = collect_metrics(self.cfg, ht)
            self.after(0, lambda n=ht.name, i=ht, rh=h: self._apply_result(n,i,rh))
        for ht in hosts: threading.Thread(target=job,args=(ht,),daemon=True).start()

    def _apply_result(self,name:str,host:HostTarget,h:HostHealth):
        def mark(ok:bool)->str: return GOOD if ok else BAD
        vals=list(self.tree.item(name)["values"] or ["-"]*len(self.LOGICAL_COLUMNS))
        colidx={c:i for i,c in enumerate(self.LOGICAL_COLUMNS)}
        up = (h.status=="UP")
        vals[colidx["Status"]]=f"{mark(up)} {h.status}"
        vals[colidx["OS TYPE"]]=h.os_type or "-"
        vals[colidx["OS Version"]]=h.os_version or "-"
        vals[colidx["Memory Allocated (GB)"]]=(f"{h.mem_gb:.1f}" if h.mem_gb is not None else "-")
        vals[colidx["CPU Count"]]=h.cpu_count if h.cpu_count is not None else "-"
        if h.mem_pct is None:
            vals[colidx["Memory Usage %"]]="-"
        else:
            vals[colidx["Memory Usage %"]]=f"{mark(h.mem_pct<90.0)} {h.mem_pct:.1f}%"
        if h.cpu_load_pct is None:
            vals[colidx["CPU Load Avg %"]]="-"
        else:
            vals[colidx["CPU Load Avg %"]]=f"{mark(h.cpu_load_pct<50.0)} {h.cpu_load_pct:.1f}%"
        fscrit = int(h.fs_crit_count or 0)
        vals[colidx["FS>90%"]]=f"{mark(fscrit==0)} {fscrit}"
        vals[colidx["Last Checked"]]=h.ts; vals[colidx["Check Status"]]="Complete"; vals[colidx["Error"]]=h.error or ""
        self.tree.item(name,values=vals)

        self.last_health[name]={"status":h.status,"os_type":h.os_type,"os_version":h.os_version,"mem_gb":h.mem_gb,"cpu_count":h.cpu_count,"mem_pct":h.mem_pct,"cpu_load_pct":h.cpu_load_pct,"fs_crit_count":h.fs_crit_count,"ts":h.ts,"error":h.error or ""}
        self.cfg["last_health"]=self.last_health; save_config(self.cfg)
        self._renumber(); 
        try: self._autosize_columns()
        except Exception: pass
        self._apply_all_filters()

    def _clear_all_rows(self):
        for iid in list(self._detached):
            try: self.tree.move(iid,"","end")
            except Exception: pass
        self._detached.clear()
        for iid in self.tree.get_children(""):
            vals=list(self.tree.item(iid)["values"]); cleared=list(vals)
            for c in self.STATUS_COLUMNS:
                idx=self.LOGICAL_COLUMNS.index(c); cleared[idx]="-"
            self.tree.item(iid,values=cleared)
        self.status_var.set("Cleared all rows (except S.No, Server Name, Environment)."); self._apply_all_filters()

    def _clear_selected_row(self):
        sel=self.tree.selection()
        if not sel: messagebox.showinfo(APP_NAME,"Select a row to clear."); return
        iid=sel[0]
        if iid in self._detached: self.tree.move(iid,"","end"); self._detached.discard(iid)
        vals=list(self.tree.item(iid)["values"]); cleared=list(vals)
        for c in self.STATUS_COLUMNS: idx=self.LOGICAL_COLUMNS.index(c); cleared[idx]="-"
        self.tree.item(iid,values=cleared); self.status_var.set(f"Cleared row: {iid}"); self._apply_all_filters()

    # CRUD
    def _add_dialog(self): HostEditor(self,on_save=self._add_host)
    def _edit_selected(self):
        sel=self.tree.selection()
        if not sel: messagebox.showinfo(APP_NAME,"Select a row to edit."); return
        name=sel[0]; t=next((x for x in self.hosts if x.name==name),None)
        if not t: messagebox.showerror(APP_NAME,"Host not found."); return
        HostEditor(self,target=t,on_save=self._update_host)
    def _remove_selected(self):
        sel=self.tree.selection()
        if not sel: return
        name=sel[0]; self.hosts=[i for i in self.hosts if i.name!=name]
        self._detached.discard(name); self.tree.delete(name); self._persist_hosts(); self._renumber()
    def _add_host(self,h:HostTarget):
        if any(x.name==h.name for x in self.hosts): messagebox.showerror(APP_NAME,"A host with this name already exists."); return
        self.hosts.append(h); self._persist_hosts()
        values=["-"]*len(self.LOGICAL_COLUMNS); values[0]=len(self.hosts); values[1]=h.name; values[2]=h.environment
        self.tree.insert("",tk.END,iid=h.name,values=tuple(values)); self._renumber(); 
        try: self._autosize_columns()
        except Exception: pass
        self._apply_all_filters()
    def _update_host(self,h:HostTarget):
        found=False
        for idx,cur in enumerate(self.hosts):
            if cur.name==h.name: self.hosts[idx]=h; found=True; break
        if not found: self.hosts.append(h)
        self._persist_hosts()
        if h.name in self.tree.get_children("") or h.name in self._detached:
            if h.name in self._detached: self.tree.move(h.name,"","end"); self._detached.discard(h.name)
            vals=list(self.tree.item(h.name)["values"]); vals[1]=h.name; vals[2]=h.environment; self.tree.item(h.name,values=vals); self._apply_all_filters()
        try: self._autosize_columns()
        except Exception: pass

class HostEditor(tk.Toplevel):
    def __init__(self, app: LinuxMonitorApp, target: Optional[HostTarget] = None, on_save=None):
        super().__init__(app); self.app=app; self.on_save=on_save
        self.title("Add / Edit Linux/Unix Host"); self.resizable(False,False)
        self.name_var=tk.StringVar(value=target.name if target else "")
        self.env_var=tk.StringVar(value=target.environment if target else "NON-PROD")
        self.host_var=tk.StringVar(value=target.host if target else "")
        self.port_var=tk.IntVar(value=target.port if target else 22)
        self.user_var=tk.StringVar(value=target.username if target else "")
        self.auth_var=tk.StringVar(value=target.auth if target else "password")
        self.pass_var=tk.StringVar(value=_decrypt_password(target.password_enc) if target and target.password_enc else "")
        self.key_path=tk.StringVar(value=target.key_path if target else "")
        self.key_pass=tk.StringVar(value=_decrypt_password(target.key_pass_enc) if target and target.key_pass_enc else "")
        body=ttk.Frame(self,padding=10); body.pack(fill=tk.BOTH,expand=True)
        row=0; ttk.Label(body,text="Server Name (display):").grid(row=row,column=0,sticky="e",padx=4,pady=4)
        ttk.Entry(body,textvariable=self.name_var,width=36).grid(row=row,column=1,columnspan=3,sticky="w",padx=4,pady=4)
        row+=1; ttk.Label(body,text="Environment:").grid(row=row,column=0,sticky="e",padx=4,pady=4)
        ttk.Combobox(body,textvariable=self.env_var,values=["NON-PROD","PROD"],width=16,state="readonly").grid(row=row,column=1,sticky="w",padx=4,pady=4)
        row+=1; ttk.Label(body,text="Host / IP:").grid(row=row,column=0,sticky="e",padx=4,pady=4)
        ttk.Entry(body,textvariable=self.host_var,width=36).grid(row=row,column=1,columnspan=3,sticky="w",padx=4,pady=4)
        row+=1; ttk.Label(body,text="SSH Port:").grid(row=row,column=0,sticky="e",padx=4,pady=4)
        ttk.Entry(body,textvariable=self.port_var,width=8).grid(row=row,column=1,sticky="w",padx=4,pady=4)
        row+=1; ttk.Label(body,text="Authentication:").grid(row=row,column=0,sticky="e",padx=4,pady=4)
        ttk.Radiobutton(body,text="Password",variable=self.auth_var,value="password",command=self._refresh).grid(row=row,column=1,sticky="w")
        ttk.Radiobutton(body,text="SSH Key",variable=self.auth_var,value="key",command=self._refresh).grid(row=row,column=2,sticky="w")
        row+=1; self.pass_box=ttk.LabelFrame(body,text="Password Auth"); self.pass_box.grid(row=row,column=0,columnspan=4,sticky="ew",padx=2,pady=6)
        ttk.Label(self.pass_box,text="Username:").grid(row=0,column=0,sticky="e",padx=4,pady=4)
        ttk.Entry(self.pass_box,textvariable=self.user_var,width=20).grid(row=0,column=1,sticky="w",padx=4,pady=4)
        ttk.Label(self.pass_box,text="Password:").grid(row=0,column=2,sticky="e",padx=4,pady=4)
        ttk.Entry(self.pass_box,textvariable=self.pass_var,width=18,show="*").grid(row=0,column=3,sticky="w",padx=4,pady=4)
        row+=1; self.key_box=ttk.LabelFrame(body,text="SSH Key Auth"); self.key_box.grid(row=row,column=0,columnspan=4,sticky="ew",padx=2,pady=6)
        ttk.Label(self.key_box,text="Username:").grid(row=0,column=0,sticky="e",padx=4,pady=4)
        ttk.Entry(self.key_box,textvariable=self.user_var,width=20).grid(row=0,column=1,sticky="w",padx=4,pady=4)
        ttk.Label(self.key_box,text="Private Key Path:").grid(row=1,column=0,sticky="e",padx=4,pady=4)
        ttk.Entry(self.key_box,textvariable=self.key_path,width=28).grid(row=1,column=1,sticky="w",padx=4,pady=4)
        ttk.Button(self.key_box,text="Browse",command=self._pick_key).grid(row=1,column=2,sticky="w",padx=4,pady=4)
        ttk.Label(self.key_box,text="Key Passphrase (optional):").grid(row=2,column=0,sticky="e",padx=4,pady=4)
        ttk.Entry(self.key_box,textvariable=self.key_pass,width=20,show="*").grid(row=2,column=1,sticky="w",padx=4,pady=4)

        btns=ttk.Frame(self,padding=(10,6)); btns.pack(fill=tk.X)
        ttk.Button(btns,text="Test Connection",command=self._test_connection).pack(side=tk.LEFT)
        ttk.Button(btns,text="Cancel",command=self.destroy).pack(side=tk.RIGHT,padx=(6,0))
        ttk.Button(btns,text="Save",command=self._save).pack(side=tk.RIGHT)

        self._refresh(); self.grab_set(); self.transient(app)

    def _refresh(self):
        use_key=(self.auth_var.get()=="key")
        for child in self.key_box.winfo_children(): child.configure(state=("normal" if use_key else "disabled"))
        for child in self.pass_box.winfo_children(): child.configure(state=("disabled" if use_key else "normal"))

    def _pick_key(self):
        p=filedialog.askopenfilename(title="Select private key",filetypes=[("Key","*"),("All","*.*")])
        if p: self.key_path.set(p)

    def _make_target(self)->HostTarget:
        name=self.name_var.get().strip(); env=self.env_var.get().strip() or "NON-PROD"
        host=self.host_var.get().strip(); port=int(self.port_var.get() or 22)
        auth=self.auth_var.get()
        user=self.user_var.get().strip() or None
        if auth=="password":
            pwd=self.pass_var.get()
            return HostTarget(name=name,host=host,port=port,environment=env,username=user,auth="password",password_enc=_encrypt_password(pwd) if pwd else None)
        else:
            kpath=self.key_path.get().strip() or None
            kpass=self.key_pass.get().strip() or None
            return HostTarget(name=name,host=host,port=port,environment=env,username=user,auth="key",key_path=kpath,key_pass_enc=_encrypt_password(kpass) if kpass else None)

    def _test_connection(self):
        try:
            t=self._make_target()
            rc,out,err=ssh_exec(self.app.cfg,t,"/bin/sh -lc 'echo OK'",timeout=10)
            if rc==0 and "OK" in out: messagebox.showinfo(APP_NAME,f"Connection OK: {t.name}")
            else: raise RuntimeError(err or out or "Unknown error")
        except Exception as e:
            messagebox.showerror(APP_NAME,f"Connection failed:\n{e}")

    def _save(self):
        try:
            t=self._make_target()
            if not t.name: messagebox.showerror(APP_NAME,"Server Name is required."); return
            if not t.host: messagebox.showerror(APP_NAME,"Host/IP is required."); return
            if not t.username: messagebox.showerror(APP_NAME,"Username is required."); return
            if self.on_save: self.on_save(t)
            self.destroy()
        except Exception as e: messagebox.showerror(APP_NAME,f"Failed to save: {e}")

# Compatibility alias for main app
class LinuxPlaceholder(LinuxMonitorApp): pass
