#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Windows Servers module for Database Pulse.
Uses local PowerShell to query remote hosts (WinRM/PS-Remoting must be enabled).
Columns:
S.No, Server Name, Environment, Status, OS Version, OS Edition, Security Patch, Memory Allocated (GB),
CPU Count, Memory Usage %, CPU Load Avg %, C, D, E, F, G, H, I, T, S, Last Checked, Check Status, Error
"""
from __future__ import annotations

import base64, json, locale, re, subprocess, sys, threading, time
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional

import tkinter as tk
from tkinter import filedialog, messagebox, ttk
from tkinter import font as tkfont

APP_NAME = "Database Pulse"
APP_VERSION = "Database Pulse v1.2"

GOOD = "✅"; BAD = "❌"; DEFAULT_INTERVAL_SEC = 300

def _base_dir() -> Path:
    if getattr(sys, "frozen", False):
        return Path(sys.executable).resolve().parent
    return Path(__file__).resolve().parent

CONFIG_DIR = (_base_dir() / "config"); CONFIG_DIR.mkdir(parents=True, exist_ok=True)
CONFIG_PATH = CONFIG_DIR / "windows_config.json"

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
        import base64 as b64
        encrypted = ctypes.string_at(blob_out.pbData, blob_out.cbData)
        ctypes.windll.kernel32.LocalFree(blob_out.pbData)
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
        decrypted = ctypes.string_at(blob_out.pbData, blob_out.cbData)
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
class WinHost:
    name: str
    host: str
    environment: str = "NON-PROD"
    auth: str = "current"  # "current" or "cred"
    username: Optional[str] = None  # DOMAIN\User
    password_enc: Optional[str] = None

@dataclass
class WinHealth:
    status: str = "DOWN"
    os_version: str = "-"
    os_edition: str = "-"
    security_patch: str = "-"
    mem_gb: Optional[float] = None
    cpu_count: Optional[int] = None
    mem_pct: Optional[float] = None
    cpu_pct: Optional[float] = None
    disks: Dict[str, Optional[float]] = field(default_factory=dict)  # letter -> used%
    error: str = ""
    elapsed_ms: int = 0
    ts: str = field(default_factory=lambda: datetime.now().strftime("%Y-%m-%d %H:%M:%S"))

LETTERS = ["C","D","E","F","G","H","I","T","S"]

def logical_columns() -> List[str]:
    cols=["S.No","Server Name","Environment","Status","OS Version","OS Edition","Security Patch",
          "Memory Allocated (GB)","CPU Count","Memory Usage %","CPU Load Avg %"]
    cols += LETTERS
    cols += ["Last Checked","Check Status","Error"]
    return cols

FILTERABLE_COLUMNS = {"Server Name","Environment","Status","OS Version","OS Edition"}

def default_config() -> Dict[str, Any]:
    cols = logical_columns()
    return {
        "interval_sec": DEFAULT_INTERVAL_SEC,
        "hosts": [],
        "powershell_path": "powershell.exe",
        "last_health": {},
        "auto_run": False,
        "column_order": cols[:],
        "visible_columns": cols[:],
        "email_columns": cols[:],
        "column_widths": {},
        "active_filter": [],
        "header_filters": {},
    }

def _serialize_host(h: WinHost) -> Dict[str, Any]:
    return {"name":h.name,"host":h.host,"environment":h.environment,"auth":h.auth,"username":h.username,"password_enc":h.password_enc}

def _hydrate_host(d: Dict[str, Any]) -> WinHost:
    return WinHost(name=d.get("name",""), host=d.get("host",""), environment=d.get("environment","NON-PROD"), auth=d.get("auth","current"), username=d.get("username"), password_enc=d.get("password_enc"))

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

# ------------- PowerShell remote query -------------
def _ps_escape(s: str) -> str:
    return s.replace("`","``").replace("'","''")

def run_powershell(host: WinHost, cfg: Dict[str, Any]) -> Dict[str, Any]:
    ps = (cfg.get("powershell_path") or "powershell.exe").strip()
    if not sys.platform.startswith("win"):
        raise RuntimeError("Windows module requires running on Windows (to invoke PowerShell).")
    # Build credential if needed
    cred_script = "$cred=$null;"
    if host.auth == "cred":
        user = host.username or ""
        pwd = _decrypt_password(host.password_enc) or ""
        cred_script = f"$sec=ConvertTo-SecureString '{_ps_escape(pwd)}' -AsPlainText -Force; $cred=New-Object System.Management.Automation.PSCredential('{_ps_escape(user)}',$sec);"

    disk_letters = ",".join([f"'{d}:'" for d in LETTERS])
    inner = rf"""
{cred_script}
$ErrorActionPreference='Stop';
$sb = {{
    $os = Get-CimInstance Win32_OperatingSystem
    $cs = Get-CimInstance Win32_ComputerSystem
    $cpu = Get-CimInstance Win32_Processor | Measure-Object -Property NumberOfLogicalProcessors -Sum
    $memTotalGB = [math]::Round($cs.TotalPhysicalMemory/1GB,1)
    $memPct = if ($os.TotalVisibleMemorySize -gt 0) {{ [math]::Round((($os.TotalVisibleMemorySize - $os.FreePhysicalMemory)*100.0)/$os.TotalVisibleMemorySize,1) }} else {{ $null }}
    $cpuPct = try {{
        ($vals = (Get-Counter '\Processor(_Total)\% Processor Time' -SampleInterval 1 -MaxSamples 3).CounterSamples | Select -ExpandProperty CookedValue)
        [math]::Round(($vals | Measure-Object -Average).Average,1)
    }} catch {{ $null }}
    $hotfix = Get-HotFix | Sort-Object InstalledOn -Descending | Select-Object -First 1
    $kb = if ($hotfix) {{ "$($hotfix.HotFixID) $([datetime]$hotfix.InstalledOn).ToString('yyyy-MM-dd')" }} else {{ '-' }}
    $disks = Get-CimInstance Win32_LogicalDisk -Filter "DriveType=3" | Where-Object {{ $_.DeviceID -in @({disk_letters}) }} | ForEach-Object {{
        $usedPct = if ($_.Size -gt 0) {{ [math]::Round((($_.Size - $_.FreeSpace)*100.0)/$_.Size,1) }} else {{ $null }}
        [pscustomobject]@{{ Letter=$_.DeviceID.TrimEnd(':'); UsedPct=$usedPct }}
    }}
    [pscustomobject]@{{
        Version = $os.Caption
        Edition = $os.OperatingSystemSKU
        KB      = $kb
        MemGB   = $memTotalGB
        CPU     = $cpu.Sum
        MemPct  = $memPct
        CpuPct  = $cpuPct
        Disks   = $disks
    }}
}}
$params=@{{ ComputerName='{_ps_escape(host.host)}' }}
if ($cred -ne $null) {{ $params.Credential = $cred }}
$result = Invoke-Command @params -ScriptBlock $sb
$result | ConvertTo-Json -Compress
"""
    full_cmd = [ps, "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", inner]
    enc = locale.getpreferredencoding(False) or "utf-8"
    try:
        p = subprocess.Popen(full_cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=False)
        out_b, err_b = p.communicate(timeout=60)
        rc = p.returncode
        out = out_b.decode(enc, errors="ignore").strip()
        err = err_b.decode(enc, errors="ignore").strip()
        if rc != 0:
            raise RuntimeError(err or out or f"PowerShell rc={rc}")
        data = json.loads(out)
        if isinstance(data, list) and data:
            data = data[0]
        return data
    except subprocess.TimeoutExpired:
        try: p.kill()
        except Exception: pass
        raise RuntimeError("PowerShell timeout (WinRM/PS-Remoting may be blocked)")

def collect_win_metrics(cfg: Dict[str, Any], host: WinHost) -> WinHealth:
    t0 = time.time()
    h = WinHealth()
    try:
        data = run_powershell(host, cfg)
        h.status = "UP"
        caption = str(data.get("Version","-"))
        # Derive version year heuristically from caption
        # e.g., "Microsoft Windows Server 2022 Datacenter"
        ver_year = "-"
        m = re.search(r"Windows Server\s+(\d{4})", caption)
        if m: ver_year = m.group(1)
        else:
            # fallback from Version number (not provided in our object) -> keep caption
            ver_year = caption
        h.os_version = ver_year
        # Edition
        # OperatingSystemSKU is numeric; we map a few common ones
        sku = str(data.get("Edition","-"))
        sku_map = {
            "8":"Datacenter",
            "7":"Standard",
            "12":"Datacenter Core",
            "13":"Standard Core",
        }
        h.os_edition = sku_map.get(sku, "Unknown/Caption: "+caption.split()[-1] if caption else "-")
        h.security_patch = data.get("KB","-")
        h.mem_gb = float(data.get("MemGB")) if data.get("MemGB") is not None else None
        h.cpu_count = int(data.get("CPU") or 0) or None
        h.mem_pct = float(data.get("MemPct")) if data.get("MemPct") is not None else None
        h.cpu_pct = float(data.get("CpuPct")) if data.get("CpuPct") is not None else None
        # Disks
        dmap = {d["Letter"]: (float(d["UsedPct"]) if d.get("UsedPct") is not None else None) for d in (data.get("Disks") or [])}
        for L in LETTERS:
            if L not in dmap: dmap[L] = None
        h.disks = dmap
    except Exception as e:
        h.status = "DOWN"
        h.error = str(e)
    h.elapsed_ms = int((time.time()-t0)*1000)
    return h

class WindowsMonitorApp(ttk.Frame):
    LOGICAL_COLUMNS = tuple(logical_columns())
    STATUS_COLUMNS = set(LOGICAL_COLUMNS) - {"S.No","Server Name","Environment"}

    def __init__(self, master):
        super().__init__(master)
        self.cfg=load_config()
        self.interval_sec=int(self.cfg.get("interval_sec",DEFAULT_INTERVAL_SEC))
        self.hosts=[_hydrate_host(h) if isinstance(h,dict) else h for h in self.cfg.get("hosts",[])]
        self.last_health=self.cfg.get("last_health",{})
        self._auto_flag=False
        self._active_filter=[tuple(x) for x in self.cfg.get("active_filter",[])]
        self._header_filters={}
        for c in FILTERABLE_COLUMNS:
            raw=self.cfg.get("header_filters",{}).get(c,[])
            self._header_filters[c]=(set(raw) if raw else None)
        self._detached=set()
        self._build_ui()
        self._refresh_table_from_hosts()
        self._load_last_health_into_rows()
        self._apply_all_filters()
        if self.cfg.get("auto_run"):
            self.auto_var.set(True); self._start_auto()

    def _build_ui(self):
        self.grid_rowconfigure(0,weight=0); self.grid_rowconfigure(1,weight=0); self.grid_rowconfigure(2,weight=1)
        self.grid_columnconfigure(0,weight=1)

        self._font=tkfont.nametofont("TkDefaultFont")
        style=ttk.Style(self)
        try: style.theme_use("clam")
        except Exception: pass
        style.configure("WX.Treeview.Heading", background="#cfe8ff", foreground="#000", font=(self._font.actual("family"), self._font.actual("size"), "bold"))
        style.map("WX.Treeview.Heading", background=[("active","#b7dbff")])
        style.configure("WX.Treeview", rowheight=22)

        t1=ttk.Frame(self); t1.grid(row=0,column=0,sticky="ew",padx=8,pady=(8,3))
        self.interval_var=tk.IntVar(value=self.interval_sec)
        ttk.Label(t1,text="Interval (sec):").pack(side=tk.LEFT)
        ttk.Spinbox(t1,from_=30,to=3600,textvariable=self.interval_var,width=8).pack(side=tk.LEFT,padx=(4,10))
        self.auto_var=tk.BooleanVar(value=self.cfg.get("auto_run",False))
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
        ttk.Label(t1,text="PowerShell:").pack(side=tk.LEFT,padx=(0,4))
        self.ps_path_var=tk.StringVar(value=self.cfg.get("powershell_path","powershell.exe"))
        ttk.Entry(t1,textvariable=self.ps_path_var,width=28).pack(side=tk.LEFT,padx=(0,4))
        ttk.Button(t1,text="Browse",command=self._pick_ps).pack(side=tk.LEFT)

        tree_frame=ttk.Frame(self); tree_frame.grid(row=2,column=0,sticky="nsew",padx=8,pady=8)
        self.tree=ttk.Treeview(tree_frame,columns=self.LOGICAL_COLUMNS,show="headings",height=20,style="WX.Treeview")
        vsb=ttk.Scrollbar(tree_frame,orient="vertical",command=self.tree.yview)
        xsb=ttk.Scrollbar(tree_frame,orient="horizontal",command=self.tree.xview)
        self.tree.configure(yscrollcommand=vsb.set,xscrollcommand=xsb.set)
        vsb.pack(side=tk.RIGHT,fill=tk.Y); self.tree.pack(side=tk.TOP,fill=tk.BOTH,expand=True); xsb.pack(side=tk.BOTTOM,fill=tk.X)

        for col in self.LOGICAL_COLUMNS:
            self.tree.heading(col,text=col,command=lambda c=col: self._sort_by_column(c,False))
            self.tree.column(col,width=120,stretch=True,anchor="w")

        order=[c for c in self.cfg.get("column_order",list(self.LOGICAL_COLUMNS)) if c in self.LOGICAL_COLUMNS]
        if not order or order[0]!="S.No": order=["S.No"]+[c for c in self.LOGICAL_COLUMNS if c!="S.No"]
        visible=[c for c in self.cfg.get("visible_columns",order) if c in self.LOGICAL_COLUMNS]
        if not visible or visible[0]!="S.No": visible=["S.No"]+[c for c in visible if c!="S.No"]
        display=[c for c in order if c in visible]; self.tree["displaycolumns"]=display

        for col,w in self.cfg.get("column_widths",{}).items():
            try: self.tree.column(col,width=int(w))
            except Exception: pass

        self.menu=tk.Menu(self,tearoff=0)
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

    def _customize_columns(self): self._select_columns_dialog()

    def _select_columns_dialog(self):
        all_cols = list(self.LOGICAL_COLUMNS)
        current = list(self.tree["displaycolumns"]) or all_cols
        if "S.No" not in current:
            current.insert(0, "S.No")
        hidden = [c for c in all_cols if c not in current]

        dlg = tk.Toplevel(self); dlg.title("Customize Columns"); dlg.geometry("760x400"); dlg.resizable(False, False)
        left = ttk.Frame(dlg); left.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=(10,5), pady=10)
        right = ttk.Frame(dlg); right.pack(side=tk.RIGHT, fill=tk.BOTH, expand=True, padx=(5,10), pady=10)

        ttk.Label(left, text="Visible (use buttons to reorder)").pack(anchor="w")
        lb_vis = tk.Listbox(left, selectmode=tk.EXTENDED, height=14)
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
        lb_hid = tk.Listbox(right, selectmode=tk.EXTENDED, height=14)
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
        dlg = tk.Toplevel(self); dlg.title("Advanced Filter"); dlg.geometry("640x340"); dlg.resizable(False, False)
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

        dlg=tk.Toplevel(self); dlg.title(f"Filter: {col}"); dlg.geometry("560x380"); dlg.resizable(False,False)
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

    def _pick_ps(self):
        p=filedialog.askopenfilename(title="Locate PowerShell",filetypes=[("PowerShell","powershell.exe"),("All","*.*")])
        if p:
            self.ps_path_var.set(p); self.cfg["powershell_path"]=p; save_config(self.cfg)

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
        if col in LETTERS:
            return (pct_num(s),)
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
        vals[colidx["OS Version"]]=h.get("os_version","-")
        vals[colidx["OS Edition"]]=h.get("os_edition","-")
        vals[colidx["Security Patch"]]=h.get("security_patch","-")
        mem_gb=h.get("mem_gb"); vals[colidx["Memory Allocated (GB)"]]=(f"{mem_gb:.1f}" if isinstance(mem_gb,(int,float)) else "-")
        vals[colidx["CPU Count"]]=h.get("cpu_count","-")
        mem_pct=h.get("mem_pct"); vals[colidx["Memory Usage %"]]=self._mark_cell(None if mem_pct is None else (mem_pct<90.0), f"{mem_pct:.1f}%" if mem_pct is not None else "-")
        cpu_pct=h.get("cpu_pct"); vals[colidx["CPU Load Avg %"]]=self._mark_cell(None if cpu_pct is None else (cpu_pct<80.0), f"{cpu_pct:.1f}%" if cpu_pct is not None else "-")
        for L in LETTERS:
            up = h.get("disks",{}).get(L)
            if up is None:
                vals[colidx[L]] = "-"
            else:
                vals[colidx[L]] = self._mark_cell(up < 90.0, f"{up:.1f}%")
        vals[colidx["Last Checked"]]=h.get("ts","-"); vals[colidx["Check Status"]]="Complete"; vals[colidx["Error"]]=h.get("error","")
        self.tree.item(name,values=vals)

    def _persist_hosts(self):
        self.cfg["interval_sec"]=self.interval_var.get()
        self.cfg["hosts"]=[_serialize_host(h) for h in self.hosts]
        self.cfg["powershell_path"]=self.ps_path_var.get().strip()
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
            self.ps_path_var.set(self.cfg.get("powershell_path","powershell.exe"))
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
        p=filedialog.asksaveasfilename(title="Export config",defaultextension=".json",initialfile="windows_config.json")
        if not p: return
        try:
            export={
                "interval_sec": self.interval_var.get(),
                "hosts": [_serialize_host(h) for h in self.hosts],
                "powershell_path": self.ps_path_var.get().strip(),
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

    def _checks_async(self,hosts:List[WinHost]):
        for t in hosts: self._set_check_status(t.name,"In Progress")
        def job(ht:WinHost):
            res=collect_win_metrics(self.cfg, ht)
            self.after(0, lambda n=ht.name, i=ht, rh=res: self._apply_result(n,i,rh))
        for ht in hosts: threading.Thread(target=job,args=(ht,),daemon=True).start()

    def _apply_result(self,name:str,host:WinHost,h:WinHealth):
        def mark(ok:bool)->str: return GOOD if ok else BAD
        vals=list(self.tree.item(name)["values"] or ["-"]*len(self.LOGICAL_COLUMNS))
        colidx={c:i for i,c in enumerate(self.LOGICAL_COLUMNS)}
        up = (h.status=="UP")
        vals[colidx["Status"]]=f"{mark(up)} {h.status}"
        vals[colidx["OS Version"]]=h.os_version or "-"
        vals[colidx["OS Edition"]]=h.os_edition or "-"
        vals[colidx["Security Patch"]]=h.security_patch or "-"
        vals[colidx["Memory Allocated (GB)"]]=(f"{h.mem_gb:.1f}" if h.mem_gb is not None else "-")
        vals[colidx["CPU Count"]]=h.cpu_count if h.cpu_count is not None else "-"
        if h.mem_pct is None:
            vals[colidx["Memory Usage %"]]="-"
        else:
            vals[colidx["Memory Usage %"]]=f"{mark(h.mem_pct<90.0)} {h.mem_pct:.1f}%"
        if h.cpu_pct is None:
            vals[colidx["CPU Load Avg %"]]="-"
        else:
            vals[colidx["CPU Load Avg %"]]=f"{mark(h.cpu_pct<80.0)} {h.cpu_pct:.1f}%"
        for L in LETTERS:
            pct = h.disks.get(L)
            if pct is None:
                vals[colidx[L]]="-"
            else:
                vals[colidx[L]]=f"{mark(pct<90.0)} {pct:.1f}%"
        vals[colidx["Last Checked"]]=h.ts; vals[colidx["Check Status"]]="Complete"; vals[colidx["Error"]]=h.error or ""
        self.tree.item(name,values=vals)

        # persist
        disks_simple = {k:(float(v) if v is not None else None) for k,v in (h.disks or {}).items()}
        self.last_health[name]={"status":h.status,"os_version":h.os_version,"os_edition":h.os_edition,"security_patch":h.security_patch,"mem_gb":h.mem_gb,"cpu_count":h.cpu_count,"mem_pct":h.mem_pct,"cpu_pct":h.cpu_pct,"disks":disks_simple,"ts":h.ts,"error":h.error or ""}
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
    def _add_dialog(self): WinHostEditor(self,on_save=self._add_host)
    def _edit_selected(self):
        sel=self.tree.selection()
        if not sel: messagebox.showinfo(APP_NAME,"Select a row to edit."); return
        name=sel[0]; t=next((x for x in self.hosts if x.name==name),None)
        if not t: messagebox.showerror(APP_NAME,"Host not found."); return
        WinHostEditor(self,target=t,on_save=self._update_host)
    def _remove_selected(self):
        sel=self.tree.selection()
        if not sel: return
        name=sel[0]; self.hosts=[i for i in self.hosts if i.name!=name]
        self._detached.discard(name); self.tree.delete(name); self._persist_hosts(); self._renumber()
    def _add_host(self,h:WinHost):
        if any(x.name==h.name for x in self.hosts): messagebox.showerror(APP_NAME,"A host with this name already exists."); return
        self.hosts.append(h); self._persist_hosts()
        values=["-"]*len(self.LOGICAL_COLUMNS); values[0]=len(self.hosts); values[1]=h.name; values[2]=h.environment
        self.tree.insert("",tk.END,iid=h.name,values=tuple(values)); self._renumber(); 
        try: self._autosize_columns()
        except Exception: pass
        self._apply_all_filters()
    def _update_host(self,h:WinHost):
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

class WinHostEditor(tk.Toplevel):
    def __init__(self, app: WindowsMonitorApp, target: Optional[WinHost] = None, on_save=None):
        super().__init__(app); self.app=app; self.on_save=on_save
        self.title("Add / Edit Windows Host"); self.resizable(False,False)
        self.name_var=tk.StringVar(value=target.name if target else "")
        self.env_var=tk.StringVar(value=target.environment if target else "NON-PROD")
        self.host_var=tk.StringVar(value=target.host if target else "")
        self.auth_var=tk.StringVar(value=target.auth if target else "current")
        self.user_var=tk.StringVar(value=target.username if target else "")
        self.pass_var=tk.StringVar(value=_decrypt_password(target.password_enc) if target and target.password_enc else "")
        body=ttk.Frame(self,padding=10); body.pack(fill=tk.BOTH,expand=True)
        row=0; ttk.Label(body,text="Server Name (display):").grid(row=row,column=0,sticky="e",padx=4,pady=4)
        ttk.Entry(body,textvariable=self.name_var,width=34).grid(row=row,column=1,columnspan=3,sticky="w",padx=4,pady=4)
        row+=1; ttk.Label(body,text="Environment:").grid(row=row,column=0,sticky="e",padx=4,pady=4)
        ttk.Combobox(body,textvariable=self.env_var,values=["NON-PROD","PROD"],width=14,state="readonly").grid(row=row,column=1,sticky="w",padx=4,pady=4)
        row+=1; ttk.Label(body,text="Host / ComputerName:").grid(row=row,column=0,sticky="e",padx=4,pady=4)
        ttk.Entry(body,textvariable=self.host_var,width=34).grid(row=row,column=1,columnspan=3,sticky="w",padx=4,pady=4)
        row+=1; ttk.Label(body,text="Authentication:").grid(row=row,column=0,sticky="e",padx=4,pady=4)
        ttk.Radiobutton(body,text="Current Windows user (Kerberos/NTLM)",variable=self.auth_var,value="current",command=self._refresh).grid(row=row,column=1,sticky="w")
        ttk.Radiobutton(body,text="Specify credential",variable=self.auth_var,value="cred",command=self._refresh).grid(row=row,column=2,sticky="w")
        row+=1; self.cred_box=ttk.LabelFrame(body,text="Credential"); self.cred_box.grid(row=row,column=0,columnspan=4,sticky="ew",padx=2,pady=6)
        ttk.Label(self.cred_box,text="DOMAIN\\User:").grid(row=0,column=0,sticky="e",padx=4,pady=4)
        ttk.Entry(self.cred_box,textvariable=self.user_var,width=24).grid(row=0,column=1,sticky="w",padx=4,pady=4)
        ttk.Label(self.cred_box,text="Password:").grid(row=0,column=2,sticky="e",padx=4,pady=4)
        ttk.Entry(self.cred_box,textvariable=self.pass_var,width=18,show="*").grid(row=0,column=3,sticky="w",padx=4,pady=4)

        btns=ttk.Frame(self,padding=(10,6)); btns.pack(fill=tk.X)
        ttk.Button(btns,text="Test Connection",command=self._test_connection).pack(side=tk.LEFT)
        ttk.Button(btns,text="Cancel",command=self.destroy).pack(side=tk.RIGHT,padx=(6,0))
        ttk.Button(btns,text="Save",command=self._save).pack(side=tk.RIGHT)

        self._refresh(); self.grab_set(); self.transient(app)

    def _refresh(self):
        use_cred=(self.auth_var.get()=="cred")
        for child in self.cred_box.winfo_children(): child.configure(state=("normal" if use_cred else "disabled"))

    def _make_host(self)->WinHost:
        name=self.name_var.get().strip(); env=self.env_var.get().strip() or "NON-PROD"
        host=self.host_var.get().strip(); auth=self.auth_var.get()
        if auth=="cred":
            user=self.user_var.get().strip(); pwd=self.pass_var.get()
            return WinHost(name=name,host=host,environment=env,auth="cred",username=user or None,password_enc=_encrypt_password(pwd) if pwd else None)
        else:
            return WinHost(name=name,host=host,environment=env,auth="current",username=None,password_enc=None)

    def _test_connection(self):
        try:
            h=self._make_host()
            data=run_powershell(h, self.app.cfg)
            if data: messagebox.showinfo(APP_NAME,f"Connection OK: {h.name}")
            else: raise RuntimeError("Empty response")
        except Exception as e:
            messagebox.showerror(APP_NAME,f"Connection failed:\n{e}")

    def _save(self):
        try:
            t=self._make_host()
            if not t.name: messagebox.showerror(APP_NAME,"Server Name is required."); return
            if not t.host: messagebox.showerror(APP_NAME,"Host/ComputerName is required."); return
            if self.on_save: self.on_save(t)
            self.destroy()
        except Exception as e: messagebox.showerror(APP_NAME,f"Failed to save: {e}")

# Alias
class WindowsPlaceholder(WindowsMonitorApp): pass
