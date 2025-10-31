#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# Database Pulse - Linux/Unix Servers module
# Solaris 10/11 (SunOS 5.10+), SUSE, Oracle Linux, RHEL, Ubuntu
# Email toolbar, excel-style filters, common/per-host login, uptime

from __future__ import annotations

import json, os, re, subprocess, sys, threading, time, tkinter as tk
from dataclasses import dataclass
from datetime import datetime
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from pathlib import Path
from tkinter import ttk, messagebox, filedialog as fd
from tkinter import font as tkfont
from typing import Any, Dict, List, Optional, Tuple

# Optional paramiko for SSH
try:
    import paramiko  # type: ignore
except Exception:
    paramiko = None

APP_NAME = "Database Pulse"
DEFAULT_INTERVAL_SEC = 300

def _base_dir() -> Path:
    if getattr(sys, "frozen", False):
        return Path(sys.executable).resolve().parent
    return Path(__file__).resolve().parent

CONFIG_DIR = _base_dir() / "config"
CONFIG_DIR.mkdir(parents=True, exist_ok=True)
CONFIG_PATH = CONFIG_DIR / "linux_config.json"

FILTERABLE_COLUMNS = ("Environment","Status","OS","OS Version")

# --- Simple protect/unprotect (DPAPI on Windows; base64 elsewhere) ---
def _win_protect(data: bytes) -> str:
    try:
        import ctypes, ctypes.wintypes as wt, binascii
        class DATA_BLOB(ctypes.Structure):
            _fields_ = [("cbData", wt.DWORD), ("pbData", ctypes.POINTER(ctypes.c_char))]
        CryptProtectData = ctypes.windll.crypt32.CryptProtectData
        blob_in = DATA_BLOB(len(data), ctypes.cast(ctypes.create_string_buffer(data), ctypes.POINTER(ctypes.c_char)))
        blob_out = DATA_BLOB()
        if not CryptProtectData(ctypes.byref(blob_in), None, None, None, None, 0, ctypes.byref(blob_out)):
            raise RuntimeError("CryptProtectData failed")
        res = ctypes.string_at(blob_out.pbData, blob_out.cbData)
        ctypes.windll.kernel32.LocalFree(blob_out.pbData)
        return binascii.b2a_base64(res).decode().strip()
    except Exception:
        import base64; return base64.b64encode(data).decode()

def _win_unprotect(text: str) -> bytes:
    try:
        import ctypes, ctypes.wintypes as wt, binascii
        raw = binascii.a2b_base64(text.encode())
        class DATA_BLOB(ctypes.Structure):
            _fields_ = [("cbData", wt.DWORD), ("pbData", ctypes.POINTER(ctypes.c_char))]
        CryptUnprotectData = ctypes.windll.crypt32.CryptUnprotectData
        blob_in = DATA_BLOB(len(raw), ctypes.cast(ctypes.create_string_buffer(raw), ctypes.POINTER(ctypes.c_char)))
        blob_out = DATA_BLOB()
        if not CryptUnprotectData(ctypes.byref(blob_in), None, None, None, None, 0, ctypes.byref(blob_out)):
            raise RuntimeError("CryptUnprotectData failed")
        res = ctypes.string_at(blob_out.pbData, blob_out.cbData)
        ctypes.windll.kernel32.LocalFree(blob_out.pbData)
        return res
    except Exception:
        import base64; return base64.b64decode(text.encode())

@dataclass
class Host:
    name: str
    environment: str
    host: str
    user: str = ""
    auth: str = "key"   # key | password
    password_enc: str = ""
    key_path: str = ""

def load_config() -> Dict[str, Any]:
    if CONFIG_PATH.exists():
        try:
            return json.loads(CONFIG_PATH.read_text(encoding="utf-8"))
        except Exception:
            pass
    return {
        "hosts": [],
        "use_common_login": False,
        "common_login": {"user":"", "auth":"key", "password_enc":"", "key_path":""},
        "email": {"server":"", "port":25, "from_addr":"", "to_addrs":"", "subject":"Linux/Unix Health Report"},
        "column_order": [],
        "visible_columns": [],
        "email_columns": [],
        "header_filters": {},
        "interval": DEFAULT_INTERVAL_SEC
    }

def save_config(cfg: Dict[str, Any]):
    CONFIG_PATH.write_text(json.dumps(cfg, indent=2), encoding="utf-8")

def human_uptime(sec: int) -> str:
    sec = max(0,int(sec))
    d, r = divmod(sec, 86400); h, r = divmod(r, 3600); m, _ = divmod(r, 60)
    if d: return f"{d}d {h}h {m}m"
    if h: return f"{h}h {m}m"
    return f"{m}m"

def ping_host(host: str, timeout_ms: int = 2000) -> bool:
    try:
        if sys.platform.startswith("win"):
            cmd = ["ping","-n","1","-w",str(timeout_ms),host]
        else:
            cmd = ["ping","-c","1","-W",str(max(1,timeout_ms//1000)),host]
        return subprocess.run(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL).returncode == 0
    except Exception:
        return False

def _ssh_exec(host: Host, cmd: str, common: Optional[Dict[str,str]] = None, timeout: int = 25) -> Tuple[int,str,str]:
    user = (common["user"] if (common and common.get("user")) else host.user) or host.user
    auth = (common["auth"] if (common and common.get("auth")) else host.auth) or host.auth
    key_path = (common["key_path"] if (common and common.get("key_path")) else host.key_path) or host.key_path
    enc = (common["password_enc"] if (common and common.get("password_enc")) else host.password_enc) or host.password_enc
    password = _win_unprotect(enc).decode(errors="ignore") if enc else ""

    if paramiko is not None:
        try:
            ssh = paramiko.SSHClient(); ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            if auth == "password" and password:
                ssh.connect(hostname=host.host, username=user, password=password, timeout=timeout, allow_agent=False, look_for_keys=False)
            else:
                pkey=None
                if key_path and os.path.exists(key_path):
                    for Key in (paramiko.RSAKey, getattr(paramiko, "Ed25519Key", None)):
                        if not Key: continue
                        try:
                            pkey = Key.from_private_key_file(key_path); break
                        except Exception: pass
                ssh.connect(hostname=host.host, username=user, pkey=pkey, timeout=timeout)
            _, stdout, stderr = ssh.exec_command(cmd, timeout=timeout)
            out = stdout.read().decode("utf-8", errors="ignore"); err = stderr.read().decode("utf-8", errors="ignore")
            rc = stdout.channel.recv_exit_status(); ssh.close()
            return rc, out, err
        except Exception as e:
            return 255, "", str(e)

    base = ["ssh","-o","BatchMode=yes","-o","StrictHostKeyChecking=no","-o",f"ConnectTimeout={timeout}",f"{user}@{host.host}",cmd]
    try:
        p = subprocess.run(base, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=timeout+5)
        return p.returncode, p.stdout, p.stderr
    except Exception as e:
        return 255, "", str(e)

def _remote_script() -> str:
    # Portable sh; supports SunOS and Linux
    return r'''OS=$(uname -s 2>/dev/null || echo Unknown)
if [ "$OS" = "SunOS" ]; then
  OS_NAME="Solaris"
  SUNOS=$(uname -r 2>/dev/null)
  OS_PRETTY="Solaris (SunOS $SUNOS) $(uname -v 2>/dev/null)"
  PHYS=$(kstat -p unix:0:system_pages:physmem 2>/dev/null | awk '{print $2}')
  FREEP=$(kstat -p unix:0:system_pages:freemem 2>/dev/null | awk '{print $2}')
  PSZ=$(/usr/bin/pagesize 2>/dev/null)
  if [ -z "$PHYS" ] || [ -z "$FREEP" ] || [ -z "$PSZ" ]; then
    MEM_GB=0; MEM_PCT=0
  else
    MEM_TOTAL=$((PHYS*PSZ)); MEM_FREE=$((FREEP*PSZ))
    MEM_GB=$(awk -v t="$MEM_TOTAL" 'BEGIN{printf "%.1f", t/1073741824.0}')
    USED=$((MEM_TOTAL-MEM_FREE))
    MEM_PCT=$(awk -v u="$USED" -v t="$MEM_TOTAL" 'BEGIN{if(t>0){printf "%.1f", (u*100.0)/t}else{print "0.0"}}')
  fi
  CPU_COUNT=$(psrinfo 2>/dev/null | wc -l | awk '{print $1}')
  LOAD=$(uptime 2>/dev/null | awk -F"load average: " '{print $2}' | awk -F, '{gsub(/ /,""); print $1}')
  if [ -z "$LOAD" ]; then LOAD=$(kstat -p unix:0:system_misc:avenrun_1min 2>/dev/null | awk '{printf "%.2f", $2/256.0}'); fi
  BOOT=$(kstat -p unix:0:system_misc:boot_time 2>/dev/null | awk '{print $2}'); NOW=$(date +%s 2>/dev/null); UPTIME=0
  if [ -n "$BOOT" ] && [ -n "$NOW" ]; then UPTIME=$((NOW-BOOT)); fi
  FS90=$(df -k 2>/dev/null | awk 'NR>1{gsub(/%/,"",$5); if($5+0>=90)c++} END{print c+0}')
  HN=$(uname -n 2>/dev/null)
else
  OS_NAME="Linux"
  PRETTY=$( (cat /etc/os-release 2>/dev/null || cat /usr/lib/os-release 2>/dev/null) | awk -F= '$1=="PRETTY_NAME"{gsub(/"/,"",$2); print $2}' )
  if [ -z "$PRETTY" ]; then PRETTY=$(uname -s); fi
  OS_PRETTY="$PRETTY"
  MEM_TOTAL_KB=$(awk '/MemTotal:/{print $2}' /proc/meminfo 2>/dev/null)
  MEM_AVAIL_KB=$(awk '/MemAvailable:/{print $2}' /proc/meminfo 2>/dev/null)
  if [ -z "$MEM_TOTAL_KB" ] || [ -z "$MEM_AVAIL_KB" ]; then MEM_GB=0; MEM_PCT=0; else
    MEM_GB=$(awk -v t="$MEM_TOTAL_KB" 'BEGIN{printf "%.1f", (t*1024)/1073741824.0}')
    USED_KB=$((MEM_TOTAL_KB-MEM_AVAIL_KB))
    MEM_PCT=$(awk -v u="$USED_KB" -v t="$MEM_TOTAL_KB" 'BEGIN{if(t>0){printf "%.1f", (u*100.0)/t}else{print "0.0"}}')
  fi
  CPU_COUNT=$( (nproc 2>/dev/null || grep -c ^processor /proc/cpuinfo 2>/dev/null) )
  LOAD=$(awk '{print $1}' /proc/loadavg 2>/dev/null)
  UPTIME=$(awk '{print int($1)}' /proc/uptime 2>/dev/null)
  FS90=$(df -P 2>/dev/null | awk 'NR>1{gsub(/%/,"",$5); if($5+0>=90)c++} END{print c+0}')
  HN=$(hostname 2>/dev/null)
fi
printf '{"os":"%s","os_version":"%s","memory_gb":%.1f,"cpu_count":%d,"mem_used_pct":%.1f,"cpu_load":%.2f,"fs90":%d,"uptime_sec":%d,"host":"%s"}\n' "$OS_NAME" "$OS_PRETTY" "${MEM_GB:-0}" "${CPU_COUNT:-0}" "${MEM_PCT:-0}" "${LOAD:-0}" "${FS90:-0}" "${UPTIME:-0}" "$HN"
'''

class LinuxMonitorApp(tk.Frame):
    LOGICAL_COLUMNS = (
        "S.No","Server Name","Environment","Status","OS","OS Version","Memory (GB)","CPU Count",
        "Memory Usage %","CPU Load Avg","Disks >90%","Uptime","Last Checked","Check Status","Error"
    )

    def __init__(self, master):
        super().__init__(master)
        self.cfg = load_config()
        self._active_filter: List[Tuple[str,str,str]] = []
        self._header_filters: Dict[str, Optional[set]] = {c: None for c in FILTERABLE_COLUMNS}
        if isinstance(self.cfg.get("header_filters"), dict):
            for k,v in self.cfg["header_filters"].items():
                if k in self._header_filters: self._header_filters[k] = set(v) if isinstance(v,list) else None
        self._detached = set()
        self._build_ui()
        self._load_hosts()
        self._toggle_timer_running = False
        self._timer_thread: Optional[threading.Thread] = None

    def _build_ui(self):
        self.grid_rowconfigure(2, weight=1); self.grid_columnconfigure(0, weight=1)
        t1 = ttk.Frame(self); t1.grid(row=0,column=0,sticky="ew",padx=8,pady=4)
        ttk.Button(t1,text="Refresh",command=self._refresh_selected).pack(side=tk.LEFT)
        ttk.Button(t1,text="Refresh All",command=self._refresh_all).pack(side=tk.LEFT,padx=(6,4))
        ttk.Separator(t1,orient="vertical").pack(side=tk.LEFT,fill=tk.Y,padx=8)
        ttk.Button(t1,text="Add Server",command=self._add_dialog).pack(side=tk.LEFT)
        ttk.Button(t1,text="Edit Server",command=self._edit_selected).pack(side=tk.LEFT,padx=(4,0))
        ttk.Button(t1,text="Remove Server",command=self._remove_selected).pack(side=tk.LEFT,padx=(4,0))
        ttk.Button(t1,text="Import Config",command=self._import_json).pack(side=tk.LEFT,padx=(10,0))
        ttk.Button(t1,text="Export Config",command=self._export_json).pack(side=tk.LEFT)
        ttk.Separator(t1,orient="vertical").pack(side=tk.LEFT,fill=tk.Y,padx=8)
        ttk.Button(t1,text="Customize Columns",command=self._customize_columns).pack(side=tk.LEFT)
        ttk.Button(t1,text="Select Columns",command=self._customize_columns).pack(side=tk.LEFT,padx=(4,0))
        ttk.Button(t1,text="Filter…",command=self._open_filter_dialog).pack(side=tk.LEFT,padx=(4,0))
        ttk.Button(t1,text="Clear Filter",command=self._clear_filter).pack(side=tk.LEFT,padx=(4,0))
        ttk.Separator(t1,orient="vertical").pack(side=tk.LEFT,fill=tk.Y,padx=8)
        ttk.Label(t1,text="Interval (sec):").pack(side=tk.LEFT)
        self.interval_var = tk.StringVar(value=str(self.cfg.get("interval", DEFAULT_INTERVAL_SEC)))
        ttk.Entry(t1,textvariable=self.interval_var,width=6).pack(side=tk.LEFT,padx=(2,8))
        self._auto_btn = ttk.Button(t1,text="Start Auto",command=self._toggle_auto); self._auto_btn.pack(side=tk.LEFT)
        ttk.Separator(t1,orient="vertical").pack(side=tk.LEFT,fill=tk.Y,padx=8)
        ttk.Button(t1,text="Auth Settings",command=self._auth_settings).pack(side=tk.LEFT)

        # Email bar
        t2 = ttk.Frame(self); t2.grid(row=1,column=0,sticky="ew",padx=8,pady=(0,6))
        email_cfg = self.cfg.get("email",{})
        ttk.Label(t2,text="SMTP/Exchange:").pack(side=tk.LEFT)
        self.smtp_server_var = tk.StringVar(value=email_cfg.get("server",""))
        self.smtp_port_var = tk.StringVar(value=str(email_cfg.get("port",25)))
        ttk.Entry(t2,textvariable=self.smtp_server_var,width=22).pack(side=tk.LEFT,padx=(4,2))
        ttk.Entry(t2,textvariable=self.smtp_port_var,width=6).pack(side=tk.LEFT,padx=(2,6))
        ttk.Label(t2,text="From:").pack(side=tk.LEFT)
        self.from_var = tk.StringVar(value=email_cfg.get("from_addr",""))
        ttk.Entry(t2,textvariable=self.from_var,width=24).pack(side=tk.LEFT,padx=(4,6))
        ttk.Label(t2,text="To (comma):").pack(side=tk.LEFT)
        self.to_var = tk.StringVar(value=email_cfg.get("to_addrs",""))
        ttk.Entry(t2,textvariable=self.to_var,width=32).pack(side=tk.LEFT,padx=(4,6))
        ttk.Button(t2,text="Save Mail",command=self._save_mail_settings).pack(side=tk.LEFT,padx=(6,0))
        ttk.Button(t2,text="Email Columns",command=self._select_email_columns_dialog).pack(side=tk.LEFT,padx=(6,0))
        ttk.Button(t2,text="Email Report",command=self._email_report).pack(side=tk.LEFT,padx=(6,0))

        tree_frame = ttk.Frame(self); tree_frame.grid(row=2,column=0,sticky="nsew",padx=8,pady=8)
        style = ttk.Style(self); style.configure("LNX.Treeview", font=("Segoe UI", 10))
        self.tree = ttk.Treeview(tree_frame,columns=self.LOGICAL_COLUMNS,show="headings",height=20,style="LNX.Treeview")
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

        self.tree.bind("<Button-3>", self._on_button3)

        bottombar=ttk.Frame(self); bottombar.grid(row=3,column=0,sticky="ew",padx=8,pady=4)
        self.status_var=tk.StringVar(value="Idle"); ttk.Label(bottombar,textvariable=self.status_var).pack(side=tk.LEFT)

        self._refresh_heading_labels()

    def _load_hosts(self):
        self.hosts = [Host(**h) for h in self.cfg.get("hosts",[]) if isinstance(h,dict)]
        self._renumber()

    def _persist_column_layout(self):
        visible=list(self.tree["displaycolumns"])
        if not visible or visible[0]!="S.No": visible=["S.No"]+[c for c in visible if c!="S.No"]
        full=list(self.tree["columns"]); seen=set(); new_full=[]
        for c in visible:
            if c not in seen and c in self.LOGICAL_COLUMNS: new_full.append(c); seen.add(c)
        self.cfg["column_order"]=new_full; self.cfg["visible_columns"]=visible; save_config(self.cfg)

    def _add_dialog(self):
        HostEditor(self, on_save=self._add_or_update_host)

    def _edit_selected(self):
        iid=self.tree.selection()
        if not iid: return
        idx=int(self.tree.item(iid[0])["values"][0])-1
        if idx<0 or idx>=len(self.hosts): return
        HostEditor(self, target=self.hosts[idx], on_save=lambda h:self._add_or_update_host(h, replace_index=idx))

    def _remove_selected(self):
        iids=self.tree.selection()
        if not iids: return
        indices=sorted([int(self.tree.item(i)["values"][0])-1 for i in iids], reverse=True)
        for i in indices:
            if 0<=i<len(self.hosts): self.hosts.pop(i)
        self.cfg["hosts"]=[h.__dict__ for h in self.hosts]; save_config(self.cfg)
        self._renumber()

    def _add_or_update_host(self, host: Host, replace_index: Optional[int]=None):
        if replace_index is None: self.hosts.append(host)
        else: self.hosts[replace_index]=host
        self.cfg["hosts"]=[h.__dict__ for h in self.hosts]; save_config(self.cfg)
        self._renumber()

    def _renumber(self):
        self.tree.delete(*self.tree.get_children(""))
        for idx,h in enumerate(self.hosts, start=1):
            self.tree.insert("",tk.END,values=[idx,h.name,h.environment,"-", "-","-","-","-","-","-","-","-","-","-","-", "" ])
        self._autosize_columns()

    def _customize_columns(self):
        dlg = tk.Toplevel(self); dlg.title("Customize Columns"); dlg.resizable(False,False)
        all_cols=list(self.LOGICAL_COLUMNS); vis=list(self.tree["displaycolumns"])
        checks={}; row=0
        ttk.Label(dlg,text="Show/Hide columns (S.No always visible):",font=("TkDefaultFont",10,"bold")).grid(row=row,column=0,sticky="w",padx=8,pady=(8,4)); row+=1
        for c in all_cols:
            var=tk.BooleanVar(value=(c in vis)); cb=ttk.Checkbutton(dlg,text=c,variable=var)
            if c=="S.No": cb.state(["disabled"]); var.set(True)
            cb.grid(row=row,column=0,sticky="w",padx=8,pady=2); checks[c]=var; row+=1
        def apply():
            new_visible=["S.No"]+[c for c,v in checks.items() if c!="S.No" and v.get()]
            order=[c for c in self.cfg.get("column_order",list(self.LOGICAL_COLUMNS)) if c in self.LOGICAL_COLUMNS]
            display=[c for c in order if c in new_visible]
            if "S.No" not in display: display=["S.No"]+[c for c in display if c!="S.No"]
            self.tree["displaycolumns"]=display; self._persist_column_layout(); dlg.destroy(); self._autosize_columns()
        ttk.Button(dlg,text="Apply",command=apply).grid(row=row,column=0,sticky="e",padx=8,pady=8)

    def _open_filter_dialog(self):
        dlg = tk.Toplevel(self); dlg.title("Filter Rows"); dlg.resizable(False,False)
        cols=list(self.tree["columns"]); pad={"padx":6,"pady":4}
        ttk.Label(dlg,text="Column:").grid(row=0,column=0,sticky="e",**pad)
        col_var=tk.StringVar(value=cols[0] if cols else "")
        ttk.Combobox(dlg,textvariable=col_var,values=cols,state="readonly",width=28).grid(row=0,column=1,sticky="w",**pad)
        ttk.Label(dlg,text="Operator:").grid(row=1,column=0,sticky="e",**pad)
        ops=["contains","equals",">",">=","<","<=","!="]; op_var=tk.StringVar(value="contains")
        ttk.Combobox(dlg,textvariable=op_var,values=ops,state="readonly",width=10).grid(row=1,column=1,sticky="w",**pad)
        ttk.Label(dlg,text="Value:").grid(row=2,column=0,sticky="e",**pad)
        val_var=tk.StringVar(value=""); ttk.Entry(dlg,textvariable=val_var,width=26).grid(row=2,column=1,sticky="w",**pad)
        def add():
            self._active_filter.append((col_var.get(), op_var.get(), val_var.get())); dlg.destroy(); self._apply_all_filters(); self._refresh_heading_labels()
        ttk.Button(dlg,text="Apply",command=add).grid(row=3,column=1,sticky="e",**pad)

    def _open_header_filter(self, col: str):
        idx = self.LOGICAL_COLUMNS.index(col)
        all_iids = list(self.tree.get_children("")) + list(self._detached)
        distinct = []; seen=set()
        for iid in all_iids:
            try:
                vals = self.tree.item(iid)["values"]
                v = "" if idx >= len(vals) else str(vals[idx])
            except Exception:
                v = ""
            if v not in seen: seen.add(v); distinct.append(v)
        distinct.sort(key=lambda s: s.lower())
        current_sel = self._header_filters.get(col)

        dlg = tk.Toplevel(self); dlg.title(f"Filter: {col}"); dlg.geometry("540x360"); dlg.resizable(False, False)
        ttk.Label(dlg, text=f"Filter column: {col}").pack(padx=8, pady=(8,4), anchor="w")
        body = ttk.Frame(dlg); body.pack(fill=tk.BOTH, expand=True, padx=8, pady=6)
        left = ttk.Frame(body); left.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        right = ttk.Frame(body); right.pack(side=tk.RIGHT, fill=tk.BOTH, expand=True)
        ttk.Label(left, text="Available").pack(anchor="w")
        lb_all = tk.Listbox(left, selectmode=tk.EXTENDED, height=12); lb_all.pack(fill=tk.BOTH, expand=True, padx=(0,8), pady=(2,0))
        for v in distinct: lb_all.insert(tk.END, v if v else "(blank)")
        btns = ttk.Frame(body); btns.pack(side=tk.LEFT, fill=tk.Y, padx=6)
        def move(src: tk.Listbox, dst: tk.Listbox):
            items=[src.get(i) for i in src.curselection()]; existing=set(dst.get(0, tk.END))
            for it in items:
                if it not in existing: dst.insert(tk.END, it)
        ttk.Button(btns, text=">>", command=lambda: move(lb_all, lb_sel)).pack(pady=6)
        def remove_selected():
            sel=list(lb_sel.curselection()); sel.reverse()
            for i in sel: lb_sel.delete(i)
        ttk.Button(btns, text="<<", command=remove_selected).pack(pady=6)
        ttk.Label(right, text="Selected (will be shown)").pack(anchor="w")
        lb_sel = tk.Listbox(right, selectmode=tk.EXTENDED, height=12); lb_sel.pack(fill=tk.BOTH, expand=True, pady=(2,0))
        if current_sel is not None:
            for v in distinct:
                if v in current_sel or (v=="" and "" in current_sel): lb_sel.insert(tk.END, v if v else "(blank)")
        footer = ttk.Frame(dlg); footer.pack(fill=tk.X, padx=8, pady=(6,8))
        def select_all():
            lb_sel.delete(0, tk.END)
            for v in distinct: lb_sel.insert(tk.END, v if v else "(blank)")
        def clear_all(): lb_sel.delete(0, tk.END)
        def apply_now():
            selected = [("" if v=="(blank)" else v) for v in list(lb_sel.get(0, tk.END))]
            if len(selected)==0: self._header_filters[col]=set()
            elif len(selected)==len(distinct): self._header_filters[col]=None
            else: self._header_filters[col]=set(selected)
            self.cfg["header_filters"]={k:(sorted(list(v)) if isinstance(v,set) else None) for k,v in self._header_filters.items() if k in FILTERABLE_COLUMNS}
            save_config(self.cfg); self._refresh_heading_labels(); self._apply_all_filters(); dlg.destroy()
        ttk.Button(footer,text="Select All",command=select_all).pack(side=tk.LEFT)
        ttk.Button(footer,text="Clear",command=clear_all).pack(side=tk.LEFT,padx=(6,0))
        ttk.Button(footer,text="Cancel",command=dlg.destroy).pack(side=tk.RIGHT,padx=(6,0))
        ttk.Button(footer,text="Apply",command=apply_now).pack(side=tk.RIGHT)

    def _refresh_heading_labels(self):
        for col in self.LOGICAL_COLUMNS:
            if col in FILTERABLE_COLUMNS:
                suffix=""; sel=self._header_filters.get(col)
                if sel is not None: suffix=" ▼•"
                self.tree.heading(col, text=col + suffix, command=lambda c=col: self._sort_by_column(c, False))
            else:
                self.tree.heading(col, text=col, command=lambda c=col: self._sort_by_column(c, False))

    def _apply_all_filters(self):
        self._detached = set()
        allowed = {c: set(v) for c,v in self._header_filters.items() if v is not None}
        colidx = {c:i for i,c in enumerate(self.LOGICAL_COLUMNS)}
        for iid in self.tree.get_children(""):
            vals = self.tree.item(iid)["values"]
            show=True
            for col, sel in allowed.items():
                v = str(vals[colidx[col]]) if col in colidx else ""
                if len(sel)==0 or v not in sel: show=False; break
            if show and self._active_filter:
                for (c,op,val) in self._active_filter:
                    try:
                        tv=str(vals[colidx[c]])
                        if op=="contains" and (val.lower() not in tv.lower()): show=False; break
                        if op=="equals" and not (tv==val): show=False; break
                        if op in (">",">=","<","<=","!="):
                            fv=float(re.sub(r"[^0-9.\-]","",tv) or "0"); vv=float(val)
                            if op==">" and not (fv>vv): show=False; break
                            if op==">=" and not (fv>=vv): show=False; break
                            if op=="<" and not (fv<vv): show=False; break
                            if op=="<=" and not (fv<=vv): show=False; break
                            if op=="!=" and not (fv!=vv): show=False; break
                    except Exception: pass
            if show: 
                try: self.tree.reattach(iid,"",tk.END)
                except Exception: pass
            else:
                try: self.tree.detach(iid); self._detached.add(iid)
                except Exception: pass

    def _clear_filter(self):
        self._active_filter=[]; self._header_filters={c: None for c in FILTERABLE_COLUMNS}
        self._apply_all_filters(); self._refresh_heading_labels(); self.status_var.set("Filters cleared")

    def _on_button3(self, event):
        region = self.tree.identify_region(event.x, event.y)
        if region == "heading":
            colid = self.tree.identify_column(event.x)
            try:
                idx = int(colid.replace("#","")) - 1; col = self.LOGICAL_COLUMNS[idx]
            except Exception:
                return
            if col in FILTERABLE_COLUMNS: self._open_header_filter(col)
            return
        iid = self.tree.identify_row(event.y)
        if iid: self.tree.selection_set(iid)
        try:
            menu = tk.Menu(self, tearoff=0)
            menu.add_command(label="Refresh Selected", command=self._refresh_selected)
            menu.add_separator()
            menu.add_command(label="Customize Columns", command=self._customize_columns)
            menu.add_command(label="Filter…", command=self._open_filter_dialog)
            menu.add_command(label="Clear Filter", command=self._clear_filter)
            menu.tk_popup(event.x_root, event.y_root)
        finally:
            try: menu.grab_release()
            except Exception: pass

    def _sort_by_column(self, col: str, descending: bool):
        try: idx=self.LOGICAL_COLUMNS.index(col)
        except Exception: return
        data=[]
        for iid in self.tree.get_children(""):
            vals=self.tree.item(iid)["values"]
            key=vals[idx] if idx<len(vals) else ""
            try:
                key_float=float(re.sub(r"[^0-9.\-]","",str(key)) or "0")
                data.append((iid,key_float))
            except Exception:
                data.append((iid,str(key)))
        data.sort(key=lambda x:x[1], reverse=descending)
        for i,(iid,_) in enumerate(data): self.tree.move(iid,"",i)
        self.tree.heading(col, command=lambda c=col: self._sort_by_column(c, not descending))

    def _autosize_columns(self):
        pad=24; visible=list(self.tree["displaycolumns"]); font=tkfont.nametofont("TkDefaultFont")
        for col in visible:
            header_w=font.measure(col); max_w=header_w
            for iid in self.tree.get_children(""):
                vals=self.tree.item(iid)["values"]
                try:
                    idx=self.LOGICAL_COLUMNS.index(col); txt=str(vals[idx]) if idx<len(vals) else ""
                except Exception:
                    txt=""
                w=font.measure(txt); max_w=max(max_w, w)
            self.tree.column(col,width=min(380, max(90, max_w+pad)))

    def _save_mail_settings(self):
        self.cfg.setdefault("email",{})
        self.cfg["email"]["server"]=self.smtp_server_var.get().strip()
        try: self.cfg["email"]["port"]=int(self.smtp_port_var.get() or 25)
        except Exception: self.cfg["email"]["port"]=25
        self.cfg["email"]["from_addr"]=self.from_var.get().strip()
        self.cfg["email"]["to_addrs"]=self.to_var.get().strip()
        save_config(self.cfg); messagebox.showinfo(APP_NAME,"Mail settings saved.")

    def _build_html(self, rows: List[List]) -> str:
        headers=[c for c in self.cfg.get("email_columns", list(self.LOGICAL_COLUMNS)) if c in self.LOGICAL_COLUMNS] or list(self.LOGICAL_COLUMNS)
        def cell_style(text: str, col: str) -> str:
            t=str(text).strip()
            if col=="Memory Usage %":
                try: pct=float(t.replace("%",""))
                except Exception: pct=0.0
                return "background-color:#ffe6e6;color:#7a0000;font-weight:bold;" if pct>=90.0 else ""
            if col=="CPU Load Avg":
                try: v=float(re.sub(r"[^0-9.\-]","",t) or "0")
                except Exception: v=0.0
                return "background-color:#ffe6e6;color:#7a0000;font-weight:bold;" if v>=50.0 else ""
            if col=="Disks >90%" and str(t).strip() not in ("0","-",""):
                try: c=int(str(t))
                except Exception: c=0
                return "background-color:#ffe6e6;color:#7a0000;font-weight:bold;" if c>0 else ""
            if col=="Status":
                if str(t).upper()=="UP": return "background-color:#e6ffe6;color:#064b00;font-weight:bold;"
                if str(t).upper()=="DOWN": return "background-color:#ffe6e6;color:#7a0000;font-weight:bold;"
            return ""
        thead="<tr>" + "".join(f"<th style='padding:6px 10px;border-bottom:2px solid #ccc;text-align:left'>{h}</th>" for h in headers) + "</tr>"
        body=[]
        for r in rows:
            tds=[]
            for col in headers:
                try: idx=self.LOGICAL_COLUMNS.index(col); val=r[idx]
                except Exception: val=""
                style=cell_style(val,col); tds.append(f"<td style='padding:4px 8px;border-bottom:1px solid #eee;{style}'>{val}</td>")
            body.append("<tr>"+"".join(tds)+"</tr>")
        table="<table style='border-collapse:collapse;font-family:Segoe UI, Arial, sans-serif;font-size:12px'>"+thead+"".join(body)+"</table>"
        title=f"<h3>Linux/Unix Health Report - {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</h3>"
        return "<html><body>"+title+table+"</body></html>"

    def _send_html_email(self, server: str, port: int, from_addr: str, to_addrs: List[str], subject: str, html: str):
        import smtplib
        msg=MIMEMultipart("alternative"); msg["Subject"]=subject; msg["From"]=from_addr; msg["To"]=", ".join(to_addrs)
        msg.attach(MIMEText(html,"html","utf-8"))
        with smtplib.SMTP(server,port,timeout=20) as s: s.sendmail(from_addr,to_addrs,msg.as_string())

    def _email_report(self):
        email_cfg=self.cfg.get("email",{})
        server=self.smtp_server_var.get().strip() or email_cfg.get("server","")
        try: port=int(self.smtp_port_var.get() or email_cfg.get("port",25))
        except Exception: port=25
        from_addr=self.from_var.get().strip() or email_cfg.get("from_addr","")
        to_addrs=self.to_var.get().strip() or email_cfg.get("to_addrs","")
        subject=email_cfg.get("subject","Linux/Unix Health Report")
        if not (server and from_addr and to_addrs):
            messagebox.showerror(APP_NAME,"Set SMTP server, From, and To addresses first."); return
        rows=[self.tree.item(i)["values"] for i in self.tree.get_children("")]
        html=self._build_html(rows)
        try:
            self._send_html_email(server,port,from_addr,[x.strip() for x in to_addrs.split(",") if x.strip()],subject,html)
            messagebox.showinfo(APP_NAME,"Email report sent.")
        except Exception as e:
            messagebox.showerror(APP_NAME,f"Failed to send email: {e}")

    def _select_email_columns_dialog(self):
        dlg=tk.Toplevel(self); dlg.title("Email Columns"); dlg.resizable(False,False)
        all_cols=list(self.LOGICAL_COLUMNS); current=list(self.cfg.get("email_columns", all_cols))
        checks={}; row=0
        ttk.Label(dlg,text="Pick columns to include in email:",font=("TkDefaultFont",10,"bold")).grid(row=row,column=0,sticky="w",padx=8,pady=(8,4)); row+=1
        for c in all_cols:
            var=tk.BooleanVar(value=(c in current)); ttk.Checkbutton(dlg,text=c,variable=var).grid(row=row,column=0,sticky="w",padx=8,pady=2); checks[c]=var; row+=1
        def apply_close():
            selected=[c for c,v in checks.items() if v.get() and c in all_cols] or list(all_cols)
            self.cfg["email_columns"]=selected; save_config(self.cfg)
            messagebox.showinfo(APP_NAME,f"Email columns updated ({len(selected)})"); dlg.destroy()
        ttk.Button(dlg,text="Apply",command=apply_close).grid(row=row,column=0,sticky="e",padx=8,pady=8)

    def _auth_settings(self):
        dlg=tk.Toplevel(self); dlg.title("Auth Settings (Common Login)"); dlg.resizable(False,False)
        pad={"padx":8,"pady":4}
        use_var=tk.BooleanVar(value=bool(self.cfg.get("use_common_login",False)))
        ttk.Checkbutton(dlg,text="Use common login for all servers",variable=use_var).grid(row=0,column=0,columnspan=2,sticky="w",**pad)
        cmn=self.cfg.get("common_login",{"user":"","auth":"key","password_enc":"","key_path":""})
        ttk.Label(dlg,text="Username:").grid(row=1,column=0,sticky="e",**pad); user_var=tk.StringVar(value=cmn.get("user","")); ttk.Entry(dlg,textvariable=user_var,width=28).grid(row=1,column=1,sticky="w",**pad)
        ttk.Label(dlg,text="Auth:").grid(row=2,column=0,sticky="e",**pad); auth_var=tk.StringVar(value=cmn.get("auth","key")); ttk.Combobox(dlg,textvariable=auth_var,values=["key","password"],state="readonly",width=12).grid(row=2,column=1,sticky="w",**pad)
        ttk.Label(dlg,text="Password (if password auth):").grid(row=3,column=0,sticky="e",**pad); pw_var=tk.StringVar(value=""); ttk.Entry(dlg,textvariable=pw_var,show="*",width=28).grid(row=3,column=1,sticky="w",**pad)
        ttk.Label(dlg,text="Private key path (if key auth):").grid(row=4,column=0,sticky="e",**pad); key_var=tk.StringVar(value=cmn.get("key_path","")); ttk.Entry(dlg,textvariable=key_var,width=28).grid(row=4,column=1,sticky="w",**pad)
        def save_now():
            self.cfg["use_common_login"]=use_var.get()
            enc=_win_protect(pw_var.get().encode()) if pw_var.get() else cmn.get("password_enc","")
            self.cfg["common_login"]={"user":user_var.get().strip(),"auth":auth_var.get(),"password_enc":enc,"key_path":key_var.get().strip()}
            save_config(self.cfg); dlg.destroy()
        ttk.Button(dlg,text="Save",command=save_now).grid(row=5,column=1,sticky="e",**pad)

    def _toggle_auto(self):
        if self._toggle_timer_running:
            self._toggle_timer_running=False; self._auto_btn.configure(text="Start Auto"); self.status_var.set("Auto refresh stopped"); return
        try: interval=int(self.interval_var.get() or DEFAULT_INTERVAL_SEC)
        except Exception: interval=DEFAULT_INTERVAL_SEC
        self.cfg["interval"]=interval; save_config(self.cfg)
        self._toggle_timer_running=True; self._auto_btn.configure(text="Stop Auto")
        def loop():
            while self._toggle_timer_running:
                self._refresh_all()
                for _ in range(interval):
                    if not self._toggle_timer_running: break
                    time.sleep(1)
        self._timer_thread=threading.Thread(target=loop,daemon=True); self._timer_thread.start()
        self.status_var.set(f"Auto refresh started ({interval}s)")

    def _refresh_selected(self):
        iids=self.tree.selection() or self.tree.get_children("")
        idxs=[int(self.tree.item(i)["values"][0])-1 for i in iids]
        idxs=[i for i in idxs if 0<=i<len(self.hosts)]
        if not idxs: return
        threading.Thread(target=self._collect_many,args=(idxs,),daemon=True).start()

    def _refresh_all(self):
        idxs=list(range(len(self.hosts)))
        threading.Thread(target=self._collect_many,args=(idxs,),daemon=True).start()

    def _collect_many(self, indices: List[int]):
        self.status_var.set("Collecting...")
        cmn=self.cfg["common_login"] if self.cfg.get("use_common_login") else None
        for i in indices:
            try: self._update_host(i, cmn)
            except Exception as e: print("collect error:", e)
        self.status_var.set("Completed at " + datetime.now().strftime("%H:%M:%S"))
        self._autosize_columns(); self._apply_all_filters()

    def _update_host(self, idx: int, cmn: Optional[Dict[str,str]]):
        h=self.hosts[idx]
        up = ping_host(h.host, timeout_ms=2000)
        status="UP" if up else "DOWN"

        os_name=os_ver=mem_gb=cpu_count=mem_pct=cpu_load=fs90=uptime="-"
        err=""; check="Completed"
        if up:
            rc,out,stderr=_ssh_exec(h, _remote_script(), cmn)
            if rc==0 and out.strip():
                try:
                    data=json.loads(out.strip().splitlines()[-1])
                    os_name=data.get("os","-"); os_ver=data.get("os_version","-")
                    mem_gb=f"{float(data.get('memory_gb',0.0)):.1f}"
                    cpu_count=str(int(data.get("cpu_count",0)))
                    mem_pct=f"{float(data.get('mem_used_pct',0.0)):.1f}%"
                    cpu_load=f"{float(data.get('cpu_load',0.0)):.2f}"
                    fs90=str(int(data.get("fs90",0)))
                    uptime=human_uptime(int(data.get("uptime_sec",0)))
                except Exception as e:
                    err=f"parse: {e}"
            else:
                err = stderr.strip() or f"ssh rc={rc}"

        now=datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        values=[idx+1, h.name, h.environment, status, os_name, os_ver, mem_gb, cpu_count, mem_pct, cpu_load, fs90, uptime, now, check, err]
        iid=None
        for rid in self.tree.get_children(""):
            if int(self.tree.item(rid)["values"][0])==idx+1: iid=rid; break
        if iid: self.tree.item(iid, values=values)
        else: self.tree.insert("", tk.END, values=values)

    # --- JSON Import/Export ---
    def _import_json(self):
        path = fd.askopenfilename(title="Import Linux Config", filetypes=[("JSON","*.json")])
        if not path: return
        try:
            data = json.loads(Path(path).read_text(encoding="utf-8"))
            if isinstance(data.get("hosts"), list):
                self.cfg["hosts"]=data["hosts"]
            for k in ("use_common_login","common_login","email"):
                if k in data: self.cfg[k]=data[k]
            save_config(self.cfg); self._load_hosts(); messagebox.showinfo(APP_NAME,"Imported.")
        except Exception as e:
            messagebox.showerror(APP_NAME, f"Import failed: {e}")

    def _export_json(self):
        path = fd.asksaveasfilename(title="Export Linux Config", defaultextension=".json", filetypes=[("JSON","*.json")])
        if not path: return
        try:
            Path(path).write_text(json.dumps(self.cfg, indent=2), encoding="utf-8")
            messagebox.showinfo(APP_NAME,"Exported.")
        except Exception as e:
            messagebox.showerror(APP_NAME, f"Export failed: {e}")

class HostEditor(tk.Toplevel):
    def __init__(self, app: LinuxMonitorApp, target: Optional[Host] = None, on_save=None):
        super().__init__(app); self.app=app; self.target=target; self.on_save=on_save
        self.title("Add / Edit Linux/Unix Server"); self.resizable(False,False)
        pad={"padx":8,"pady":4}

        name=tk.StringVar(value=target.name if target else "")
        env=tk.StringVar(value=target.environment if target else "NON-PROD")
        host=tk.StringVar(value=target.host if target else "")
        user=tk.StringVar(value=target.user if target else "")
        auth=tk.StringVar(value=target.auth if target else "key")
        pw=tk.StringVar(value="")
        key=tk.StringVar(value=target.key_path if target else "")

        ttk.Label(self,text="Server Name:").grid(row=0,column=0,sticky="e",**pad); ttk.Entry(self,textvariable=name,width=28).grid(row=0,column=1,sticky="w",**pad)
        ttk.Label(self,text="Environment:").grid(row=1,column=0,sticky="e",**pad); ttk.Combobox(self,textvariable=env,values=["PROD","NON-PROD"],state="readonly",width=26).grid(row=1,column=1,sticky="w",**pad)
        ttk.Label(self,text="Host / IP:").grid(row=2,column=0,sticky="e",**pad); ttk.Entry(self,textvariable=host,width=28).grid(row=2,column=1,sticky="w",**pad)
        ttk.Label(self,text="Use separate login (overrides common)?").grid(row=3,column=0,columnspan=2,sticky="w",**pad)
        ttk.Label(self,text="Username:").grid(row=4,column=0,sticky="e",**pad); ttk.Entry(self,textvariable=user,width=28).grid(row=4,column=1,sticky="w",**pad)
        ttk.Label(self,text="Auth:").grid(row=5,column=0,sticky="e",**pad); ttk.Combobox(self,textvariable=auth,values=["key","password"],state="readonly",width=12).grid(row=5,column=1,sticky="w",**pad)
        ttk.Label(self,text="Password (if password auth):").grid(row=6,column=0,sticky="e",**pad); ttk.Entry(self,textvariable=pw,show="*",width=28).grid(row=6,column=1,sticky="w",**pad)
        ttk.Label(self,text="Private key path (if key auth):").grid(row=7,column=0,sticky="e",**pad); ttk.Entry(self,textvariable=key,width=28).grid(row=7,column=1,sticky="w",**pad)

        btns=ttk.Frame(self); btns.grid(row=8,column=0,columnspan=2,sticky="ew",**pad)
        def save():
            enc=_win_protect(pw.get().encode()) if pw.get() else (self.target.password_enc if self.target else "")
            h=Host(name=name.get().strip(), environment=env.get().strip(), host=host.get().strip(), user=user.get().strip(), auth=auth.get(), password_enc=enc, key_path=key.get().strip())
            if self.on_save: self.on_save(h); self.destroy()
        ttk.Button(btns,text="Save",command=save).pack(side=tk.RIGHT)
        ttk.Button(btns,text="Cancel",command=self.destroy).pack(side=tk.RIGHT,padx=(0,6))

def create(master): return LinuxMonitorApp(master)

if __name__ == "__main__":
    root = tk.Tk(); root.title("Database Pulse - Linux/Unix Module")
    app = LinuxMonitorApp(root); app.pack(fill="both", expand=True); root.mainloop()
