"""
CertWatch - IP Range Certificate Scanner
בודק תעודות ב-LocalMachine\My (Personal) דרך WinRM
דרישות: pip install pywinrm
"""

import tkinter as tk
from tkinter import ttk, messagebox, filedialog
import threading
import subprocess
import ipaddress
import csv
import json
import os
import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed

try:
    import winrm
    WINRM_AVAILABLE = True
except ImportError:
    WINRM_AVAILABLE = False

# ─── צבעים ───────────────────────────────────────────────
BG_DARK      = "#0d1117"
BG_PANEL     = "#161b22"
BG_CARD      = "#21262d"
ACCENT_BLUE  = "#388bfd"
ACCENT_GREEN = "#3fb950"
ACCENT_YELLOW= "#d29922"
ACCENT_RED   = "#f85149"
ACCENT_ORANGE= "#e3682a"
TEXT_PRIMARY = "#e6edf3"
TEXT_MUTED   = "#8b949e"
BORDER       = "#30363d"

WARN_DAYS_CRITICAL = 30
WARN_DAYS_WARNING  = 60
WARN_DAYS_NOTICE   = 90

PS_SCRIPT = r"""
$certs = Get-ChildItem -Path Cert:\LocalMachine\My -ErrorAction SilentlyContinue
$result = @()
foreach ($cert in $certs) {
    $daysLeft = ($cert.NotAfter - (Get-Date)).Days
    $result += [PSCustomObject]@{
        Subject    = $cert.Subject
        Thumbprint = $cert.Thumbprint
        NotBefore  = $cert.NotBefore.ToString("yyyy-MM-dd")
        NotAfter   = $cert.NotAfter.ToString("yyyy-MM-dd")
        DaysLeft   = $daysLeft
        FriendlyName = $cert.FriendlyName
        Issuer     = $cert.Issuer
    }
}
$result | ConvertTo-Json -Compress
"""


class CertWatchApp:
    def __init__(self, root):
        self.root = root
        self.root.title("CertWatch — סורק תעודות ברשת")
        self.root.geometry("1280x800")
        self.root.minsize(900, 600)
        self.root.configure(bg=BG_DARK)

        self.scan_results = []   # [{ip, hostname, status, certs:[]}]
        self.running = False
        self._executor = None

        self._build_ui()
        self._check_winrm()

    # ─── UI ────────────────────────────────────────────────
    def _build_ui(self):
        # Header
        hdr = tk.Frame(self.root, bg=BG_PANEL, height=58)
        hdr.pack(fill=tk.X)
        hdr.pack_propagate(False)
        tk.Label(hdr, text="🔐  CertWatch", font=("Consolas", 18, "bold"),
                 bg=BG_PANEL, fg=ACCENT_BLUE).pack(side=tk.LEFT, padx=20, pady=12)
        tk.Label(hdr, text="סורק תעודות SSL/TLS בסגמנטי רשת",
                 font=("Segoe UI", 10), bg=BG_PANEL, fg=TEXT_MUTED).pack(side=tk.LEFT, pady=12)

        self.status_lbl = tk.Label(hdr, text="מוכן", font=("Segoe UI", 10),
                                   bg=BG_PANEL, fg=ACCENT_GREEN)
        self.status_lbl.pack(side=tk.RIGHT, padx=20)

        # Main pane
        main = tk.PanedWindow(self.root, orient=tk.HORIZONTAL,
                              bg=BG_DARK, sashwidth=4, sashrelief=tk.FLAT)
        main.pack(fill=tk.BOTH, expand=True, padx=8, pady=8)

        # Left panel — controls
        left = tk.Frame(main, bg=BG_PANEL, width=280)
        left.pack_propagate(False)
        main.add(left, minsize=240)
        self._build_left(left)

        # Right panel — results
        right = tk.Frame(main, bg=BG_DARK)
        main.add(right, minsize=500)
        self._build_right(right)

    def _build_left(self, parent):
        pad = {"padx": 14, "pady": 4}

        # ── סריקת IP ──
        self._section(parent, "🌐  סריקת רשת")

        tk.Label(parent, text="טווח IP  (למשל 192.168.1.1-254)",
                 bg=BG_PANEL, fg=TEXT_MUTED, font=("Segoe UI", 9)).pack(anchor=tk.W, **pad)
        self.ip_range_var = tk.StringVar(value="192.168.1.1-254")
        self._entry(parent, self.ip_range_var)

        tk.Label(parent, text="Timeout ping (שניות)",
                 bg=BG_PANEL, fg=TEXT_MUTED, font=("Segoe UI", 9)).pack(anchor=tk.W, **pad)
        self.ping_timeout_var = tk.IntVar(value=1)
        self._spinbox(parent, self.ping_timeout_var, 1, 10)

        tk.Label(parent, text="Threads מקביליות",
                 bg=BG_PANEL, fg=TEXT_MUTED, font=("Segoe UI", 9)).pack(anchor=tk.W, **pad)
        self.threads_var = tk.IntVar(value=30)
        self._spinbox(parent, self.threads_var, 1, 100)

        # ── WinRM ──
        self._section(parent, "🔑  WinRM / אישורים")

        self.use_current_user_var = tk.BooleanVar(value=True)
        chk = tk.Checkbutton(parent, text="השתמש במשתמש הנוכחי (Domain)",
                             variable=self.use_current_user_var,
                             command=self._toggle_creds,
                             bg=BG_PANEL, fg=TEXT_PRIMARY, selectcolor=BG_CARD,
                             activebackground=BG_PANEL, font=("Segoe UI", 9))
        chk.pack(anchor=tk.W, padx=14, pady=2)

        self.creds_frame = tk.Frame(parent, bg=BG_PANEL)
        self.creds_frame.pack(fill=tk.X)

        tk.Label(self.creds_frame, text="Username (DOMAIN\\user)",
                 bg=BG_PANEL, fg=TEXT_MUTED, font=("Segoe UI", 9)).pack(anchor=tk.W, padx=14, pady=(4,0))
        self.username_var = tk.StringVar()
        self._entry(self.creds_frame, self.username_var)

        tk.Label(self.creds_frame, text="Password",
                 bg=BG_PANEL, fg=TEXT_MUTED, font=("Segoe UI", 9)).pack(anchor=tk.W, padx=14, pady=(4,0))
        self.password_var = tk.StringVar()
        e = tk.Entry(self.creds_frame, textvariable=self.password_var, show="*",
                     bg=BG_CARD, fg=TEXT_PRIMARY, insertbackground=TEXT_PRIMARY,
                     relief=tk.FLAT, font=("Consolas", 10))
        e.pack(fill=tk.X, padx=14, pady=(0,4))
        self._toggle_creds()

        # ── סף התראות ──
        self._section(parent, "⚠️  סף התראות (ימים)")
        for label, var_name, default in [
            ("🔴  קריטי  (ימים)", "crit_var", WARN_DAYS_CRITICAL),
            ("🟡  אזהרה  (ימים)", "warn_var", WARN_DAYS_WARNING),
            ("🔵  תשומת לב", "notice_var", WARN_DAYS_NOTICE),
        ]:
            tk.Label(parent, text=label, bg=BG_PANEL, fg=TEXT_MUTED,
                     font=("Segoe UI", 9)).pack(anchor=tk.W, **pad)
            v = tk.IntVar(value=default)
            setattr(self, var_name, v)
            self._spinbox(parent, v, 1, 365)

        # ── כפתורים ──
        tk.Frame(parent, bg=BORDER, height=1).pack(fill=tk.X, padx=14, pady=10)

        self.scan_btn = tk.Button(parent, text="▶  התחל סריקה",
                                  bg=ACCENT_BLUE, fg="white",
                                  font=("Segoe UI", 11, "bold"),
                                  relief=tk.FLAT, cursor="hand2",
                                  command=self._start_scan)
        self.scan_btn.pack(fill=tk.X, padx=14, pady=4)

        self.stop_btn = tk.Button(parent, text="⏹  עצור",
                                  bg=BG_CARD, fg=TEXT_MUTED,
                                  font=("Segoe UI", 10),
                                  relief=tk.FLAT, cursor="hand2",
                                  state=tk.DISABLED,
                                  command=self._stop_scan)
        self.stop_btn.pack(fill=tk.X, padx=14, pady=2)

        tk.Button(parent, text="💾  ייצוא CSV",
                  bg=BG_CARD, fg=TEXT_PRIMARY,
                  font=("Segoe UI", 10),
                  relief=tk.FLAT, cursor="hand2",
                  command=self._export_csv).pack(fill=tk.X, padx=14, pady=2)

        # progress
        self.progress_var = tk.DoubleVar()
        self.progress = ttk.Progressbar(parent, variable=self.progress_var,
                                        maximum=100, mode="determinate")
        style = ttk.Style()
        style.theme_use("default")
        style.configure("blue.Horizontal.TProgressbar",
                        background=ACCENT_BLUE, troughcolor=BG_CARD, bordercolor=BG_CARD)
        self.progress.configure(style="blue.Horizontal.TProgressbar")
        self.progress.pack(fill=tk.X, padx=14, pady=8)

        self.prog_lbl = tk.Label(parent, text="", bg=BG_PANEL, fg=TEXT_MUTED,
                                 font=("Segoe UI", 8))
        self.prog_lbl.pack()

    def _build_right(self, parent):
        # Tabs
        nb_frame = tk.Frame(parent, bg=BG_DARK)
        nb_frame.pack(fill=tk.BOTH, expand=True)

        style = ttk.Style()
        style.configure("Dark.TNotebook", background=BG_DARK, borderwidth=0)
        style.configure("Dark.TNotebook.Tab", background=BG_CARD, foreground=TEXT_MUTED,
                        padding=[12, 6], font=("Segoe UI", 10))
        style.map("Dark.TNotebook.Tab",
                  background=[("selected", BG_PANEL)],
                  foreground=[("selected", TEXT_PRIMARY)])

        self.nb = ttk.Notebook(nb_frame, style="Dark.TNotebook")
        self.nb.pack(fill=tk.BOTH, expand=True)

        # Tab 1 — תעודות
        certs_tab = tk.Frame(self.nb, bg=BG_DARK)
        self.nb.add(certs_tab, text="🔐  תעודות שמצאתי")
        self._build_certs_table(certs_tab)

        # Tab 2 — סיכום
        summary_tab = tk.Frame(self.nb, bg=BG_DARK)
        self.nb.add(summary_tab, text="📊  סיכום")
        self._build_summary(summary_tab)

        # Tab 3 — לוג סריקה
        log_tab = tk.Frame(self.nb, bg=BG_DARK)
        self.nb.add(log_tab, text="📋  לוג סריקה")
        self._build_log(log_tab)

    def _build_certs_table(self, parent):
        # Filter bar
        bar = tk.Frame(parent, bg=BG_PANEL, height=40)
        bar.pack(fill=tk.X)
        bar.pack_propagate(False)

        tk.Label(bar, text="סנן:", bg=BG_PANEL, fg=TEXT_MUTED,
                 font=("Segoe UI", 9)).pack(side=tk.LEFT, padx=8, pady=8)

        self.filter_var = tk.StringVar(value="הכל")
        for txt, val in [("🔴 קריטי", "critical"), ("🟡 אזהרה", "warning"),
                         ("🔵 תשומת לב", "notice"), ("✅ תקין", "ok"), ("הכל", "all")]:
            rb = tk.Radiobutton(bar, text=txt, variable=self.filter_var, value=val,
                                command=self._apply_filter,
                                bg=BG_PANEL, fg=TEXT_PRIMARY, selectcolor=BG_CARD,
                                activebackground=BG_PANEL, font=("Segoe UI", 9))
            rb.pack(side=tk.LEFT, padx=4)

        self.search_var = tk.StringVar()
        self.search_var.trace("w", lambda *a: self._apply_filter())
        se = tk.Entry(bar, textvariable=self.search_var,
                      bg=BG_CARD, fg=TEXT_PRIMARY, insertbackground=TEXT_PRIMARY,
                      relief=tk.FLAT, font=("Consolas", 9), width=20)
        se.pack(side=tk.RIGHT, padx=8, pady=6)
        tk.Label(bar, text="🔍", bg=BG_PANEL, fg=TEXT_MUTED).pack(side=tk.RIGHT)

        # Treeview
        cols = ("ip", "hostname", "subject", "issuer", "not_after", "days_left", "status")
        col_cfg = {
            "ip":        ("IP כתובת",     110, tk.CENTER),
            "hostname":  ("Hostname",      140, tk.W),
            "subject":   ("Subject",       200, tk.W),
            "issuer":    ("Issuer",        160, tk.W),
            "not_after": ("פג תוקף",       100, tk.CENTER),
            "days_left": ("ימים נותרו",     90, tk.CENTER),
            "status":    ("סטטוס",          90, tk.CENTER),
        }

        frame = tk.Frame(parent, bg=BG_DARK)
        frame.pack(fill=tk.BOTH, expand=True, padx=6, pady=6)

        style = ttk.Style()
        style.configure("Dark.Treeview",
                        background=BG_CARD, foreground=TEXT_PRIMARY,
                        rowheight=26, fieldbackground=BG_CARD, borderwidth=0,
                        font=("Consolas", 9))
        style.configure("Dark.Treeview.Heading",
                        background=BG_PANEL, foreground=TEXT_MUTED,
                        relief=tk.FLAT, font=("Segoe UI", 9, "bold"))
        style.map("Dark.Treeview", background=[("selected", "#2d333b")])

        vsb = ttk.Scrollbar(frame, orient=tk.VERTICAL)
        hsb = ttk.Scrollbar(frame, orient=tk.HORIZONTAL)

        self.tree = ttk.Treeview(frame, columns=cols, show="headings",
                                 style="Dark.Treeview",
                                 yscrollcommand=vsb.set, xscrollcommand=hsb.set)
        vsb.configure(command=self.tree.yview)
        hsb.configure(command=self.tree.xview)

        for c, (heading, width, anchor) in col_cfg.items():
            self.tree.heading(c, text=heading,
                              command=lambda _c=c: self._sort_column(_c))
            self.tree.column(c, width=width, anchor=anchor, minwidth=60)

        # Tag colors
        self.tree.tag_configure("critical", foreground=ACCENT_RED)
        self.tree.tag_configure("warning",  foreground=ACCENT_YELLOW)
        self.tree.tag_configure("notice",   foreground=ACCENT_BLUE)
        self.tree.tag_configure("ok",       foreground=ACCENT_GREEN)
        self.tree.tag_configure("expired",  foreground="#666", background="#1a0a0a")

        vsb.pack(side=tk.RIGHT, fill=tk.Y)
        hsb.pack(side=tk.BOTTOM, fill=tk.X)
        self.tree.pack(fill=tk.BOTH, expand=True)

        self._all_rows = []

    def _build_summary(self, parent):
        self.summary_frame = tk.Frame(parent, bg=BG_DARK)
        self.summary_frame.pack(fill=tk.BOTH, expand=True, padx=16, pady=16)
        tk.Label(self.summary_frame, text="הרץ סריקה כדי לראות סיכום",
                 bg=BG_DARK, fg=TEXT_MUTED, font=("Segoe UI", 12)).pack(pady=40)

    def _build_log(self, parent):
        frame = tk.Frame(parent, bg=BG_DARK)
        frame.pack(fill=tk.BOTH, expand=True, padx=6, pady=6)
        vsb = ttk.Scrollbar(frame, orient=tk.VERTICAL)
        self.log_text = tk.Text(frame, bg=BG_CARD, fg=TEXT_MUTED,
                                font=("Consolas", 9), relief=tk.FLAT,
                                yscrollcommand=vsb.set, state=tk.DISABLED,
                                wrap=tk.NONE)
        vsb.configure(command=self.log_text.yview)
        vsb.pack(side=tk.RIGHT, fill=tk.Y)
        self.log_text.pack(fill=tk.BOTH, expand=True)
        self.log_text.tag_configure("ok",   foreground=ACCENT_GREEN)
        self.log_text.tag_configure("warn", foreground=ACCENT_YELLOW)
        self.log_text.tag_configure("err",  foreground=ACCENT_RED)
        self.log_text.tag_configure("info", foreground=ACCENT_BLUE)

    # ─── Helpers ───────────────────────────────────────────
    def _section(self, parent, title):
        tk.Frame(parent, bg=BORDER, height=1).pack(fill=tk.X, padx=14, pady=(12,4))
        tk.Label(parent, text=title, bg=BG_PANEL, fg=TEXT_MUTED,
                 font=("Segoe UI", 9, "bold")).pack(anchor=tk.W, padx=14)

    def _entry(self, parent, var):
        e = tk.Entry(parent, textvariable=var,
                     bg=BG_CARD, fg=TEXT_PRIMARY, insertbackground=TEXT_PRIMARY,
                     relief=tk.FLAT, font=("Consolas", 10))
        e.pack(fill=tk.X, padx=14, pady=(0, 4))
        return e

    def _spinbox(self, parent, var, from_, to):
        sb = tk.Spinbox(parent, from_=from_, to=to, textvariable=var,
                        bg=BG_CARD, fg=TEXT_PRIMARY, buttonbackground=BG_CARD,
                        relief=tk.FLAT, font=("Consolas", 10), width=6)
        sb.pack(anchor=tk.W, padx=14, pady=(0, 4))
        return sb

    def _toggle_creds(self):
        state = tk.DISABLED if self.use_current_user_var.get() else tk.NORMAL
        for w in self.creds_frame.winfo_children():
            try:
                w.configure(state=state)
            except Exception:
                pass

    def _check_winrm(self):
        if not WINRM_AVAILABLE:
            self._log("⚠  ספריית pywinrm לא מותקנת. התקן עם:  pip install pywinrm", "warn")
            self._log("   בלי זה תסריקת תעודות לא תעבוד (ping עדיין יעבוד)", "warn")
        else:
            self._log("✓  pywinrm זמין", "ok")
        self._log("מוכן לסריקה. הגדר טווח IP ולחץ התחל.", "info")

    def _log(self, msg, tag=""):
        ts = datetime.datetime.now().strftime("%H:%M:%S")
        self.log_text.configure(state=tk.NORMAL)
        self.log_text.insert(tk.END, f"[{ts}] {msg}\n", tag)
        self.log_text.see(tk.END)
        self.log_text.configure(state=tk.DISABLED)

    def _set_status(self, msg, color=TEXT_PRIMARY):
        self.status_lbl.configure(text=msg, fg=color)

    # ─── Parse IP range ────────────────────────────────────
    def _parse_ip_range(self, range_str):
        """
        תומך ב:
          192.168.1.1-254        (range of last octet)
          192.168.1.0/24         (CIDR)
          192.168.1.1,192.168.1.5 (list)
          192.168.1.50           (single)
        """
        ips = []
        range_str = range_str.strip()
        try:
            if "/" in range_str:
                net = ipaddress.ip_network(range_str, strict=False)
                ips = [str(h) for h in net.hosts()]
            elif "-" in range_str:
                parts = range_str.rsplit("-", 1)
                base_ip = parts[0].strip()
                end_octet = int(parts[1].strip())
                prefix = ".".join(base_ip.split(".")[:-1])
                start_octet = int(base_ip.split(".")[-1])
                for i in range(start_octet, end_octet + 1):
                    ips.append(f"{prefix}.{i}")
            elif "," in range_str:
                ips = [s.strip() for s in range_str.split(",")]
            else:
                ips = [range_str]
        except Exception as e:
            raise ValueError(f"טווח IP לא תקין: {e}")
        return ips

    # ─── Scan logic ────────────────────────────────────────
    def _start_scan(self):
        if self.running:
            return
        try:
            ips = self._parse_ip_range(self.ip_range_var.get())
        except ValueError as e:
            messagebox.showerror("שגיאה", str(e))
            return

        # clear
        for row in self.tree.get_children():
            self.tree.delete(row)
        self._all_rows = []
        self.scan_results = []

        self.running = True
        self.scan_btn.configure(state=tk.DISABLED)
        self.stop_btn.configure(state=tk.NORMAL)
        self._set_status("סורק...", ACCENT_YELLOW)
        self.progress_var.set(0)

        threading.Thread(target=self._run_scan, args=(ips,), daemon=True).start()

    def _stop_scan(self):
        self.running = False
        self._set_status("עצר", ACCENT_YELLOW)
        self._log("הסריקה נעצרה על ידי המשתמש", "warn")

    def _run_scan(self, ips):
        total = len(ips)
        done  = 0
        self._log(f"מתחיל סריקה של {total} כתובות IP", "info")

        timeout = self.ping_timeout_var.get()
        threads = self.threads_var.get()

        with ThreadPoolExecutor(max_workers=threads) as ex:
            futures = {ex.submit(self._scan_one, ip, timeout): ip for ip in ips}
            for fut in as_completed(futures):
                if not self.running:
                    ex.shutdown(wait=False, cancel_futures=True)
                    break
                result = fut.result()
                if result:
                    self.scan_results.append(result)
                    self.root.after(0, self._add_result_to_table, result)
                done += 1
                pct = done / total * 100
                self.root.after(0, self._update_progress, pct, done, total)

        self.root.after(0, self._scan_done)

    def _scan_one(self, ip, timeout):
        alive = self._ping(ip, timeout)
        if not alive:
            return None

        hostname = self._resolve_hostname(ip)
        self._log(f"✓  {ip}  ({hostname})  — פעיל, שולף תעודות...", "ok")

        certs = []
        if WINRM_AVAILABLE:
            certs = self._get_certs_winrm(ip)

        return {"ip": ip, "hostname": hostname, "alive": True, "certs": certs}

    def _ping(self, ip, timeout):
        try:
            result = subprocess.run(
                ["ping", "-n", "1", "-w", str(timeout * 1000), ip],
                capture_output=True, timeout=timeout + 2
            )
            return result.returncode == 0
        except Exception:
            return False

    def _resolve_hostname(self, ip):
        try:
            import socket
            return socket.gethostbyaddr(ip)[0].split(".")[0]
        except Exception:
            return ip

    def _get_certs_winrm(self, ip):
        try:
            if self.use_current_user_var.get():
                session = winrm.Session(ip, auth=(None, None),
                                        transport="kerberos",
                                        server_cert_validation="ignore")
            else:
                session = winrm.Session(
                    ip,
                    auth=(self.username_var.get(), self.password_var.get()),
                    transport="ntlm",
                    server_cert_validation="ignore"
                )
            result = session.run_ps(PS_SCRIPT)
            if result.status_code != 0:
                self._log(f"  ⚠  {ip}: WinRM שגיאה — {result.std_err.decode(errors='replace')[:120]}", "warn")
                return []
            raw = result.std_out.decode(errors="replace").strip()
            if not raw or raw == "null":
                return []
            data = json.loads(raw)
            if isinstance(data, dict):
                data = [data]
            return data
        except Exception as e:
            self._log(f"  ✗  {ip}: {str(e)[:100]}", "err")
            return []

    # ─── Table ─────────────────────────────────────────────
    def _cert_status(self, days_left):
        crit   = self.crit_var.get()
        warn   = self.warn_var.get()
        notice = self.notice_var.get()
        if days_left < 0:
            return "פג תוקף", "expired"
        elif days_left <= crit:
            return f"קריטי ({days_left})", "critical"
        elif days_left <= warn:
            return f"אזהרה ({days_left})", "warning"
        elif days_left <= notice:
            return f"שים לב ({days_left})", "notice"
        return f"תקין ({days_left})", "ok"

    def _add_result_to_table(self, result):
        ip = result["ip"]
        hostname = result.get("hostname", ip)
        certs = result.get("certs", [])

        if not certs:
            row = (ip, hostname, "(אין תעודות)", "", "", "", "—")
            iid = self.tree.insert("", tk.END, values=row, tags=("ok",))
            self._all_rows.append({"values": row, "tag": "ok"})
            return

        for cert in certs:
            subject    = cert.get("Subject", "")[:60]
            issuer     = cert.get("Issuer", "")[:50]
            not_after  = cert.get("NotAfter", "")
            days_left  = int(cert.get("DaysLeft", 9999))
            label, tag = self._cert_status(days_left)

            row = (ip, hostname, subject, issuer, not_after, days_left, label)
            self.tree.insert("", tk.END, values=row, tags=(tag,))
            self._all_rows.append({"values": row, "tag": tag})

    def _update_progress(self, pct, done, total):
        self.progress_var.set(pct)
        self.prog_lbl.configure(text=f"{done}/{total}  ({pct:.0f}%)")

    def _scan_done(self):
        self.running = False
        self.scan_btn.configure(state=tk.NORMAL)
        self.stop_btn.configure(state=tk.DISABLED)
        total = len(self.scan_results)
        alive = sum(1 for r in self.scan_results if r.get("alive"))
        crit  = sum(1 for r in self._all_rows if r["tag"] == "critical")
        warn  = sum(1 for r in self._all_rows if r["tag"] == "warning")
        self._log(f"✅  סריקה הסתיימה — {alive} שרתים פעילים, {crit} קריטי, {warn} אזהרה", "ok")
        self._set_status(f"הסתיים | {crit} קריטי | {warn} אזהרה",
                         ACCENT_RED if crit > 0 else ACCENT_GREEN)
        self._update_summary()

    def _update_summary(self):
        for w in self.summary_frame.winfo_children():
            w.destroy()

        tags  = [r["tag"] for r in self._all_rows]
        crit  = tags.count("critical")
        warn  = tags.count("warning")
        notice= tags.count("notice")
        ok    = tags.count("ok")
        exp   = tags.count("expired")
        hosts = len(self.scan_results)

        tk.Label(self.summary_frame, text="סיכום סריקה",
                 bg=BG_DARK, fg=TEXT_PRIMARY, font=("Segoe UI", 14, "bold")).pack(pady=(0,16))

        cards = [
            ("שרתים פעילים", hosts, ACCENT_BLUE),
            ("פג תוקף",      exp,   "#666"),
            ("קריטי",        crit,  ACCENT_RED),
            ("אזהרה",        warn,  ACCENT_YELLOW),
            ("תשומת לב",    notice, ACCENT_BLUE),
            ("תקין",         ok,   ACCENT_GREEN),
        ]

        row_frame = tk.Frame(self.summary_frame, bg=BG_DARK)
        row_frame.pack()
        for i, (label, val, color) in enumerate(cards):
            card = tk.Frame(row_frame, bg=BG_CARD, padx=20, pady=12,
                            relief=tk.FLAT, bd=0)
            card.grid(row=0, column=i, padx=8, pady=4)
            tk.Label(card, text=str(val), bg=BG_CARD, fg=color,
                     font=("Consolas", 28, "bold")).pack()
            tk.Label(card, text=label, bg=BG_CARD, fg=TEXT_MUTED,
                     font=("Segoe UI", 9)).pack()

    # ─── Filter / Sort ─────────────────────────────────────
    def _apply_filter(self):
        flt    = self.filter_var.get()
        search = self.search_var.get().lower()

        for row in self.tree.get_children():
            self.tree.delete(row)

        for r in self._all_rows:
            tag = r["tag"]
            vals = r["values"]
            if flt != "all" and tag != flt:
                continue
            if search and not any(search in str(v).lower() for v in vals):
                continue
            self.tree.insert("", tk.END, values=vals, tags=(tag,))

    def _sort_column(self, col):
        rows = [(self.tree.set(k, col), k) for k in self.tree.get_children("")]
        try:
            rows.sort(key=lambda x: float(x[0]) if x[0].lstrip("-").isdigit() else x[0])
        except Exception:
            rows.sort()
        for i, (_, k) in enumerate(rows):
            self.tree.move(k, "", i)

    # ─── Export ────────────────────────────────────────────
    def _export_csv(self):
        if not self._all_rows:
            messagebox.showinfo("ייצוא", "אין נתונים לייצוא")
            return
        path = filedialog.asksaveasfilename(
            defaultextension=".csv",
            filetypes=[("CSV files", "*.csv")],
            initialfile=f"cert_report_{datetime.date.today()}.csv"
        )
        if not path:
            return
        headers = ["IP", "Hostname", "Subject", "Issuer", "Not After", "Days Left", "Status"]
        with open(path, "w", newline="", encoding="utf-8-sig") as f:
            w = csv.writer(f)
            w.writerow(headers)
            for r in self._all_rows:
                w.writerow(r["values"])
        self._log(f"✅  ייצוא CSV נשמר: {path}", "ok")
        messagebox.showinfo("ייצוא", f"הקובץ נשמר:\n{path}")


if __name__ == "__main__":
    root = tk.Tk()
    app = CertWatchApp(root)
    root.mainloop()
