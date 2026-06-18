"""Scan Oasis — Desktop GUI

Requires: sudo pacman -S tk   (Arch Linux)
Run:      python gui.py
"""

import tkinter as tk
import threading
import math
import time
import sys
import os
import json

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import scanner as _sc
import net_discovery as _nd
import cve_lookup as _cve

# ── Palette (mirrors the web dashboard) ──────────────────────────────────────
BG     = "#08090e"
PANEL  = "#0f1117"
CARD   = "#161822"
HOVER  = "#1c1f2e"
BORDER = "#1e2235"
BORDA  = "#2a3050"
TEXT   = "#e2e8f0"
TSEC   = "#8892a4"
TMUT   = "#4a5568"
ACCENT = "#00d4ff"
ACCENT_HI = "#33ddff"
ERR    = "#ff3860"
OK     = "#27c93f"

# ── Typography (Inter throughout; mono only for technical values) ────────────
FONT     = "Inter"
MONO     = "JetBrains Mono"
F_TITLE  = (FONT, 22, "bold")
F_H1     = (FONT, 15, "bold")
F_H2     = (FONT, 12, "bold")
F_LABEL  = (FONT, 9, "bold")
F_BODY   = (FONT, 11)
F_SMALL  = (FONT, 9)
F_SECTION = (FONT, 8, "bold")

SCAN_STEPS = [
    "Collecting OS information…",
    "Reading CPU & memory…",
    "Scanning block devices…",
    "Enumerating installed packages…",
    "Checking for known CVEs…",
    "Mapping network interfaces…",
    "Finalizing report…",
    "Syncing to cloud…",
]

# Continuous monitoring — seconds between automatic re-scans
SCAN_INTERVAL_SEC = 5 * 60

_LOGO_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "static", "img")
_logo_cache: dict = {}


def _logo(size: int):
    """Load and cache the Scan Oasis logo PNG at the given size (None if unavailable)."""
    if size in _logo_cache:
        return _logo_cache[size]
    try:
        img = tk.PhotoImage(file=os.path.join(_LOGO_DIR, f"logo-{size}.png"))
    except Exception:
        return None
    _logo_cache[size] = img
    return img


# ── Root window ───────────────────────────────────────────────────────────────

class App(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("Scan Oasis")
        self.configure(bg=BG)
        self.resizable(False, False)
        self.protocol("WM_DELETE_WINDOW", self.destroy)
        self._creds: tuple[str, str] | None = None   # (token, uid)
        self._frame: tk.Frame | None = None
        self._center(520, 640)
        self._switch(LoginFrame)

    def destroy(self):
        # Kill any in-flight nmap scans before tearing down the window so nothing
        # is left sweeping the network as an orphan. Covers both close paths
        # (window-manager X and the in-app ✕ button, which both reach here).
        try:
            _nd.cancel_scans()
        except Exception:
            pass
        super().destroy()

    def _center(self, w: int, h: int):
        sw = self.winfo_screenwidth()
        sh = self.winfo_screenheight()
        self.geometry(f"{w}x{h}+{(sw-w)//2}+{(sh-h)//2}")

    def _switch(self, cls, *args, **kwargs):
        if self._frame:
            self._frame.destroy()
        self._frame = cls(self, *args, **kwargs)
        self._frame.pack(fill="both", expand=True)


# ── Login frame ───────────────────────────────────────────────────────────────

class LoginFrame(tk.Frame):
    def __init__(self, master: App):
        super().__init__(master, bg=BG)
        self._build()

    def _build(self):
        _topbar(self)

        # ── Logo / wordmark ────────────────────────────────────────────────────
        top = tk.Frame(self, bg=BG)
        top.pack(pady=(40, 0))
        logo = _logo(48)
        if logo:
            lg = tk.Label(top, image=logo, bg=BG)
            lg.image = logo
            lg.pack()
        else:
            _glyph(top, "shield", 40, ACCENT, BG).pack()
        tk.Label(top, text="Scan Oasis", font=F_TITLE,
                 bg=BG, fg=TEXT).pack(pady=(14, 0))
        tk.Label(top, text="Sign in to continue",
                 font=F_BODY, bg=BG, fg=TSEC).pack(pady=(4, 0))

        # ── Card ──────────────────────────────────────────────────────────────
        card = tk.Frame(self, bg=PANEL,
                        highlightbackground=BORDER, highlightthickness=1)
        card.pack(padx=56, pady=(28, 0), fill="x")
        inn = tk.Frame(card, bg=PANEL)
        inn.pack(padx=34, pady=(24, 34), fill="x")

        # ── Tab switcher ───────────────────────────────────────────────────────
        tab_row = tk.Frame(inn, bg=PANEL)
        tab_row.pack(fill="x", pady=(0, 22))

        self._tab_email_btn = tk.Label(
            tab_row, text="Email / Password", font=(FONT, 10, "bold"),
            bg=ACCENT, fg=BG, padx=14, pady=6, cursor="hand2")
        self._tab_email_btn.pack(side="left")
        self._tab_email_btn.bind("<Button-1>", lambda _: self._switch_tab("email"))

        self._tab_token_btn = tk.Label(
            tab_row, text="Agent Token", font=(FONT, 10),
            bg=HOVER, fg=TSEC, padx=14, pady=6, cursor="hand2")
        self._tab_token_btn.pack(side="left", padx=(2, 0))
        self._tab_token_btn.bind("<Button-1>", lambda _: self._switch_tab("token"))

        # ── Email / password pane ─────────────────────────────────────────────
        self._email_frame = tk.Frame(inn, bg=PANEL)
        self._email_frame.pack(fill="x")

        tk.Label(self._email_frame, text="EMAIL", font=F_LABEL,
                 bg=PANEL, fg=TSEC).pack(anchor="w")
        self._email = Entry(self._email_frame, placeholder="you@example.com")
        self._email.pack(fill="x", pady=(8, 20))

        tk.Label(self._email_frame, text="PASSWORD", font=F_LABEL,
                 bg=PANEL, fg=TSEC).pack(anchor="w")
        self._pw = Entry(self._email_frame, placeholder="••••••••", show="•")
        self._pw.pack(fill="x", pady=(8, 24))

        self._btn = Btn(self._email_frame, "Sign In", self._submit)
        self._btn.pack(fill="x")

        # ── Agent token pane (hidden by default) ──────────────────────────────
        self._token_frame = tk.Frame(inn, bg=PANEL)
        # (shown when token tab is selected)

        tk.Label(self._token_frame, text="TOKEN", font=F_LABEL,
                 bg=PANEL, fg=TSEC).pack(anchor="w")
        self._token_entry = Entry(self._token_frame, placeholder="32-char hex token from dashboard")
        self._token_entry.pack(fill="x", pady=(8, 20))

        tk.Label(self._token_frame, text="SERVER URL", font=F_LABEL,
                 bg=PANEL, fg=TSEC).pack(anchor="w")
        self._server_entry = Entry(self._token_frame, placeholder="http://192.168.1.x:5000")
        self._server_entry.pack(fill="x", pady=(8, 24))

        self._token_btn = Btn(self._token_frame, "Connect with Token", self._token_submit)
        self._token_btn.pack(fill="x")

        # ── Shared status row (spinner + message) ─────────────────────────────
        self._status_row = tk.Frame(inn, bg=PANEL)
        self._status_row.pack(pady=(14, 0))
        self._spin_cv = tk.Canvas(self._status_row, width=16, height=16,
                                   bg=PANEL, highlightthickness=0)
        self._spin_cv.pack(side="left")
        self._err_lbl = tk.Label(self._status_row, text="",
                                  font=("Inter", 9), bg=PANEL,
                                  fg=ERR, wraplength=340)
        self._err_lbl.pack(side="left", padx=(6, 0))

        self._spin_angle = 0.0
        self._spinning   = False
        self._mode       = "email"

        self.master.bind("<Return>", lambda _: self._on_return())

    # ── Tab switching ─────────────────────────────────────────────────────────

    def _switch_tab(self, mode: str):
        self._mode = mode
        self._err_lbl.config(text="")
        if mode == "email":
            self._token_frame.pack_forget()
            self._email_frame.pack(fill="x", before=self._status_row)
            self._tab_email_btn.config(bg=ACCENT, fg=BG, font=(FONT, 10, "bold"))
            self._tab_token_btn.config(bg=HOVER,  fg=TSEC, font=(FONT, 10))
        else:
            self._email_frame.pack_forget()
            self._token_frame.pack(fill="x", before=self._status_row)
            self._tab_token_btn.config(bg=ACCENT, fg=BG, font=(FONT, 10, "bold"))
            self._tab_email_btn.config(bg=HOVER,  fg=TSEC, font=(FONT, 10))

    def _on_return(self):
        if self._mode == "token":
            self._token_submit()
        else:
            self._submit()

    # ── Spinner ───────────────────────────────────────────────────────────────

    def _draw_login_spin(self):
        if not self._spinning or not self._spin_cv.winfo_exists():
            return
        self._spin_cv.delete("all")
        cx = cy = 8
        r  = 5
        n  = 8
        for i in range(n):
            angle = math.radians(self._spin_angle + i * (360 / n))
            x = cx + r * math.cos(angle)
            y = cy + r * math.sin(angle)
            t = i / n
            c = _lerp(BORDER, ACCENT, t)
            s = 1.5 + 1.5 * t
            self._spin_cv.create_oval(
                x-s/2, y-s/2, x+s/2, y+s/2, fill=c, outline="")
        self._spin_angle = (self._spin_angle + 10) % 360
        self.after(40, self._draw_login_spin)

    def _start_spin(self, msg="Authenticating…"):
        self._spinning = True
        self._err_lbl.config(text=msg, fg=TSEC)
        self._draw_login_spin()

    def _stop_spin(self):
        self._spinning = False
        self._spin_cv.delete("all")

    def _err(self, msg: str):
        self._err_lbl.config(text=msg, fg=ERR)

    # ── Email / password login ────────────────────────────────────────────────

    def _submit(self):
        email = self._email.get().strip()
        pw    = self._pw.get()
        if not email or not pw:
            self._err("Please enter your email and password.")
            return
        self._btn.config(state="disabled")
        self._err_lbl.config(text="", fg=ERR)
        self._start_spin()
        threading.Thread(target=self._login_thread, args=(email, pw), daemon=True).start()

    def _login_thread(self, email: str, pw: str):
        token, result = _sc.firebase_login(email, pw)
        self.after(0, lambda: self._on_result(token, result, email))

    def _on_result(self, token, result, email: str):
        self._stop_spin()
        self._btn.config(state="normal")
        if token:
            self.master._creds = (token, result)
            self.master._switch(ScanFrame, email)
        else:
            msgs = {
                "INVALID_LOGIN_CREDENTIALS":   "Incorrect email or password.",
                "EMAIL_NOT_FOUND":             "No account found with that email.",
                "INVALID_PASSWORD":            "Incorrect password.",
                "TOO_MANY_ATTEMPTS_TRY_LATER": "Too many attempts — try later.",
                "USER_DISABLED":               "This account has been disabled.",
            }
            self._err(msgs.get(result, f"Sign-in failed: {result}"))

    # ── Agent token login ─────────────────────────────────────────────────────

    def _token_submit(self):
        token  = self._token_entry.get().strip()
        server = self._server_entry.get().strip().rstrip("/")
        if not token:
            self._err("Please enter a token.")
            return
        if not server:
            self._err("Please enter the server URL.")
            return
        self._token_btn.config(state="disabled")
        self._start_spin("Connecting…")
        threading.Thread(target=self._token_thread, args=(token, server), daemon=True).start()

    def _token_thread(self, token: str, server: str):
        import urllib.request as _ur
        import urllib.error   as _ue
        try:
            url  = f"{server}/api/agent-auth"
            body = json.dumps({"token": token}).encode()
            req  = _ur.Request(url, data=body, headers={"Content-Type": "application/json"})
            with _ur.urlopen(req, timeout=12) as resp:
                data = json.loads(resp.read())
        except _ue.HTTPError as e:
            try:
                data = json.loads(e.read())
            except Exception:
                data = {"ok": False, "error": f"Server returned HTTP {e.code}"}
        except Exception as exc:
            data = {"ok": False, "error": str(exc)}
        self.after(0, lambda: self._on_token_result(data))

    def _on_token_result(self, data: dict):
        self._stop_spin()
        self._token_btn.config(state="normal")
        if data.get("ok"):
            self.master._creds = (data["id_token"], data["uid"])
            self.master._switch(ScanFrame, "agent")
        else:
            self._err(data.get("error", "Authentication failed."))


# ── Scan / loading frame ──────────────────────────────────────────────────────

class ScanFrame(tk.Frame):
    def __init__(self, master: App, email: str):
        super().__init__(master, bg=BG)
        self._email = email
        self._step  = 0
        self._angle = 0.0
        self._done  = False
        self._build()
        self._tick()
        threading.Thread(target=self._run, daemon=True).start()

    def _build(self):
        _topbar(self, subtitle="Scanning…")

        center = tk.Frame(self, bg=BG)
        center.place(relx=0.5, rely=0.5, anchor="center")

        # Signed-in-as pill
        pill = tk.Frame(center, bg=CARD,
                        highlightbackground=BORDA, highlightthickness=1)
        pill.pack(pady=(0, 46))
        tk.Label(pill, text=f"  {self._email}  ",
                 font=F_SMALL, bg=CARD, fg=TSEC, pady=8).pack()

        # Spinner canvas
        self._cv = tk.Canvas(center, width=96, height=96,
                             bg=BG, highlightthickness=0)
        self._cv.pack()

        # Title + step label
        tk.Label(center, text="Running Scan Oasis",
                 font=F_H1, bg=BG, fg=TEXT, pady=20).pack()
        self._step_lbl = tk.Label(center, text=SCAN_STEPS[0],
                                   font=(MONO, 9),
                                   bg=BG, fg=TMUT, wraplength=360)
        self._step_lbl.pack()

    # ── Comet-trail spinner ───────────────────────────────────────────────────

    def _tick(self):
        if not self.winfo_exists():
            return
        self._angle = (self._angle + 6) % 360
        self._draw()
        self._step_lbl.config(text=SCAN_STEPS[min(self._step, len(SCAN_STEPS)-1)])
        if not self._done:
            self.after(35, self._tick)

    def _draw(self):
        self._cv.delete("all")
        cx = cy = 48
        R  = 34
        n  = 14
        for i in range(n):
            angle = math.radians(self._angle + i * (360 / n))
            x = cx + R * math.cos(angle)
            y = cy + R * math.sin(angle)
            t = i / n
            c = _lerp("#1e2235", ACCENT, t)
            s = 2.5 + 4 * t
            self._cv.create_oval(
                x-s/2, y-s/2, x+s/2, y+s/2, fill=c, outline="")

    # ── Scanner thread ────────────────────────────────────────────────────────

    def _run(self):
        token, uid = self.master._creds

        # Step through early stages before the heavy scan
        for i in range(3):
            self._step = i
            time.sleep(0.15)

        self._step = 3          # packages — slow, real work starts here
        report = _sc.scan()

        self._step = 4          # CVE analysis
        cves_list, counts = [], None
        try:
            cves_list = _cve.lookup_cves(report)
            counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "unknown": 0}
            for c in cves_list:
                s = c.get("severity", "unknown")
                counts[s] = counts.get(s, 0) + 1
        except Exception:
            pass  # CVE lookup is best-effort; don't block the sync

        self._step = 6
        time.sleep(0.08)

        self._step = 7          # syncing
        ok, err = _sc.firestore_save(token, uid, report, cves=cves_list, counts=counts)

        self._done = True
        self.after(0, lambda: self.master._switch(
            ResultFrame, report, self._email, ok, err))


# ── Results frame ─────────────────────────────────────────────────────────────

class ResultFrame(tk.Frame):
    def __init__(self, master: App, report: dict, email: str,
                 synced: bool = True, sync_err: str | None = None):
        super().__init__(master, bg=BG)
        self._r       = report
        self._email   = email
        self._synced  = synced
        self._sync_err = sync_err
        self._remaining = SCAN_INTERVAL_SEC
        self._build()
        self._tick_countdown()

    def _build(self):
        bar = _topbar(self, subtitle=self._email)
        # Add a sync chip to the existing bar's inner frame — reflects the real
        # Firestore write result rather than always claiming success.
        inner = bar.winfo_children()[0]   # the inner Frame
        if self._synced:
            tk.Label(inner, text="✓ Synced to cloud",
                     font=("Inter", 9), bg=PANEL, fg=OK).pack(side="right", padx=(0, 8))
        else:
            tk.Label(inner, text="⚠ Sync failed",
                     font=("Inter", 9), bg=PANEL, fg=ERR).pack(side="right", padx=(0, 8))

        # Scrollable body
        wrap = tk.Frame(self, bg=BG)
        wrap.pack(fill="both", expand=True)
        scroll = tk.Scrollbar(wrap, orient="vertical")
        scroll.pack(side="right", fill="y")
        cv = tk.Canvas(wrap, bg=BG, highlightthickness=0,
                       yscrollcommand=scroll.set)
        cv.pack(fill="both", expand=True)
        scroll.config(command=cv.yview)

        content = tk.Frame(cv, bg=BG)
        win = cv.create_window((0, 0), window=content, anchor="nw")
        cv.bind("<Configure>",  lambda e: cv.itemconfig(win, width=e.width))
        content.bind("<Configure>",
                     lambda e: cv.configure(scrollregion=cv.bbox("all")))

        # Mouse-wheel scrolling
        for seq in ("<MouseWheel>", "<Button-4>", "<Button-5>"):
            cv.bind_all(seq, lambda e, c=cv: c.yview_scroll(
                -1 if e.num == 4 or getattr(e, "delta", 0) > 0 else 1, "units"))

        self._fill(content)

    def _fill(self, p):
        r   = self._r
        os_ = r.get("os", {})
        cpu = r.get("cpu", {}).get("summary", {})
        mem = r.get("memory", {}).get("summary", {})
        pkg = r.get("packages", {})
        svc = r.get("services", {})
        dmi = r.get("dmi", {})

        def sec(title: str):
            tk.Label(p, text=title.upper(), font=F_SECTION,
                     bg=BG, fg=TMUT, anchor="w"
                     ).pack(fill="x", padx=28, pady=(26, 8))
            tk.Frame(p, bg=BORDER, height=1).pack(fill="x", padx=28)

        def row(label: str, value: str, mono=False):
            f = tk.Frame(p, bg=BG)
            f.pack(fill="x", padx=28, pady=3)
            tk.Label(f, text=label, font=F_BODY,
                     bg=BG, fg=TSEC, width=16, anchor="w").pack(side="left")
            fnt = (MONO, 10) if mono else F_BODY
            tk.Label(f, text=str(value), font=fnt,
                     bg=BG, fg=TEXT, anchor="w").pack(side="left", fill="x", expand=True)

        sec("SYSTEM")
        row("Hostname", os_.get("hostname", "?"))
        row("OS",       os_.get("pretty_name", "?"))
        row("Kernel",   os_.get("release", "?"),  mono=True)
        row("Arch",     os_.get("machine", "?"),   mono=True)
        if dmi:
            row("Vendor",
                f"{dmi.get('sys_vendor','?')} / {dmi.get('product_name','?')}")
            row("BIOS",
                f"{dmi.get('bios_vendor','?')} {dmi.get('bios_version','?')}")

        sec("CPU")
        row("Model",  cpu.get("model_name", "?"))
        row("Cores",  f"{cpu.get('logical_cpus','?')} logical")
        row("Speed",  f"{float(cpu.get('cpu_mhz', 0) or 0):.0f} MHz", mono=True)
        bugs = cpu.get("bugs", [])
        row("Bugs",   ", ".join(bugs[:5]) + ("…" if len(bugs) > 5 else "") or "none")

        sec("MEMORY")
        total = mem.get("total_bytes",     0) or 0
        avail = mem.get("available_bytes", 0) or 0
        used  = total - avail
        row("Total",   _hb(total), mono=True)
        row("Used",    f"{_hb(used)}  ({used/total*100:.1f}%)" if total else "?", mono=True)
        row("Free",    _hb(avail), mono=True)
        row("Swap",    _hb(mem.get("swap_total_bytes", 0)), mono=True)

        sec("PACKAGES")
        row("Manager",    pkg.get("manager", "?"))
        row("Total",      str(pkg.get("count", "?")), mono=True)
        if "foreign_count" in pkg:
            row("AUR/Foreign", str(pkg.get("foreign_count", 0)), mono=True)

        sec("SERVICES & SECURITY")
        row("Running",    str(len(svc.get("running", []))), mono=True)
        row("SUID Files", str(len(r.get("suid_files", []))), mono=True)
        vulns = r.get("cpu", {}).get("vulnerabilities", {})
        bad   = [k for k, v in vulns.items()
                 if v and not v.lower().startswith(("not affected", "mitigation"))]
        row("CPU Vulns",  f"{len(bad)} unmitigated / {len(vulns)} total")

        # Continuous monitoring — countdown to the next automatic scan
        tk.Frame(p, bg=BG, height=18).pack()
        mon = tk.Frame(p, bg=CARD, highlightbackground=BORDA, highlightthickness=1)
        mon.pack(padx=28, pady=(0, 16), fill="x")
        mrow = tk.Frame(mon, bg=CARD)
        mrow.pack(padx=16, pady=12, fill="x")
        _dot(mrow, OK).pack(side="left", padx=(0, 8))
        tk.Label(mrow, text="Continuous monitoring", font=F_SMALL,
                 bg=CARD, fg=TSEC).pack(side="left")
        self._countdown_lbl = tk.Label(mrow, text="Next scan in 5:00",
                                       font=(MONO, 9), bg=CARD, fg=ACCENT)
        self._countdown_lbl.pack(side="right")

        Btn(p, "Scan Network", self._open_network).pack(
            padx=28, pady=(0, 10), fill="x")
        GhostBtn(p, "Scan System Now",
                 lambda: self.master._switch(ScanFrame, self._email)
                 ).pack(padx=28, pady=(0, 28), fill="x")

    def _open_network(self):
        self.master._switch(NetworkFrame, self._email)

    def _tick_countdown(self):
        if not self.winfo_exists() or not self._countdown_lbl.winfo_exists():
            return
        m, s = divmod(max(self._remaining, 0), 60)
        self._countdown_lbl.config(text=f"Next scan in {m}:{s:02d}")
        if self._remaining <= 0:
            self.master._switch(ScanFrame, self._email)   # auto re-scan
            return
        self._remaining -= 1
        self.after(1000, self._tick_countdown)


# ── Network discovery frame ─────────────────────────────────────────────────────

class NetworkFrame(tk.Frame):
    """Discovers devices on the local network, then lists them and syncs them."""

    def __init__(self, master: App, email: str):
        super().__init__(master, bg=BG)
        self._email   = email
        self._angle   = 0.0
        self._running = True
        self._devices: list = []
        self._summary: dict = {}
        self._error: str | None = None
        self._build_scanning()
        self._spin()
        threading.Thread(target=self._run, daemon=True).start()

    # ── Scanning view ──────────────────────────────────────────────────────────

    def _build_scanning(self):
        _topbar(self, subtitle="Network discovery")
        center = tk.Frame(self, bg=BG)
        center.place(relx=0.5, rely=0.42, anchor="center")

        self._cv = tk.Canvas(center, width=96, height=96,
                             bg=BG, highlightthickness=0)
        self._cv.pack()
        tk.Label(center, text="Scanning local network",
                 font=F_H1, bg=BG, fg=TEXT, pady=20).pack()
        self._step_lbl = tk.Label(
            center, text="Detecting subnet…", font=(MONO, 9),
            bg=BG, fg=ACCENT, wraplength=400)
        self._step_lbl.pack()

        # Live scan log — a small terminal of the most recent nmap activity.
        logwrap = tk.Frame(center, bg=PANEL,
                           highlightbackground=BORDER, highlightthickness=1)
        logwrap.pack(pady=(22, 0), fill="x")
        tk.Label(logwrap, text="LIVE ACTIVITY", font=F_SECTION,
                 bg=PANEL, fg=TMUT, anchor="w").pack(fill="x", padx=12, pady=(8, 2))
        self._log_lbl = tk.Label(
            logwrap, text="", font=(MONO, 8), bg=PANEL, fg=TSEC,
            justify="left", anchor="nw", width=52, height=7)
        self._log_lbl.pack(fill="x", padx=12, pady=(0, 10))
        self._log_lines: list = []

    def _spin(self):
        if not self._running or not self.winfo_exists() or not self._cv.winfo_exists():
            return
        self._angle = (self._angle + 6) % 360
        self._cv.delete("all")
        cx = cy = 48
        R, n = 34, 14
        for i in range(n):
            a = math.radians(self._angle + i * (360 / n))
            x = cx + R * math.cos(a)
            y = cy + R * math.sin(a)
            t = i / n
            c = _lerp("#1e2235", ACCENT, t)
            s = 2.5 + 4 * t
            self._cv.create_oval(x-s/2, y-s/2, x+s/2, y+s/2, fill=c, outline="")
        self.after(35, self._spin)

    def _set_step(self, text: str):
        if self.winfo_exists() and self._step_lbl.winfo_exists():
            self._step_lbl.config(text=text)

    def _append_log(self, text: str):
        """Push a line into the live activity log (keep the last 7)."""
        if not (self.winfo_exists() and self._log_lbl.winfo_exists()):
            return
        self._log_lines.append(text)
        self._log_lines = self._log_lines[-7:]
        self._log_lbl.config(text="\n".join(self._log_lines))

    def _progress(self, msg: str):
        """Called from worker/nmap threads — marshal updates onto the UI thread."""
        if not self.winfo_exists():
            return
        self.after(0, lambda: (self._set_step(msg), self._append_log(msg)))

    # ── Worker thread ──────────────────────────────────────────────────────────

    def _run(self):
        try:
            self._progress("Detecting subnet…")
            subnet = _nd.detect_subnet()
            self._progress(f"Discovering hosts on {subnet or 'local network'}…")
            devices = _nd.discover(subnet, progress=self._progress)
            self._devices = devices

            self._progress(f"Syncing {len(devices)} device(s) to cloud…")
            token, uid = self.master._creds
            self._summary = _nd.save_devices(token, uid, devices)
        except Exception as e:  # never crash the GUI
            self._error = str(e)
        self._running = False
        self.after(0, self._show_results)

    # ── Results view ───────────────────────────────────────────────────────────

    def _show_results(self):
        for w in self.winfo_children():
            w.destroy()

        bar = _topbar(self, subtitle=self._email)
        inner = bar.winfo_children()[0]
        if self._summary and not self._error:
            n = self._summary.get("created", 0) + self._summary.get("updated", 0)
            tk.Label(inner, text="✓ Synced", font=F_SMALL,
                     bg=PANEL, fg=OK).pack(side="right", padx=(0, 8))

        # Header row
        head = tk.Frame(self, bg=BG)
        head.pack(fill="x", padx=28, pady=(20, 4))
        tk.Label(head, text="Network Devices", font=F_H1,
                 bg=BG, fg=TEXT).pack(side="left")
        tk.Label(head, text=f"{len(self._devices)} found", font=F_SMALL,
                 bg=BG, fg=TSEC).pack(side="right")

        if self._summary:
            s = self._summary
            sub = (f"{s.get('created',0)} new · {s.get('updated',0)} updated"
                   + (f" · {s['failed']} failed" if s.get("failed") else ""))
            tk.Label(self, text=sub, font=F_SMALL, bg=BG, fg=TMUT,
                     anchor="w").pack(fill="x", padx=28, pady=(0, 6))
            if s.get("error"):
                tk.Label(self, text=f"Sync error: {s['error']}", font=F_SMALL,
                         bg=BG, fg=ERR, anchor="w", wraplength=440, justify="left"
                         ).pack(fill="x", padx=28, pady=(0, 6))

        tk.Frame(self, bg=BORDER, height=1).pack(fill="x", padx=28, pady=(0, 4))

        # Scrollable device list
        wrap = tk.Frame(self, bg=BG)
        wrap.pack(fill="both", expand=True)
        scroll = tk.Scrollbar(wrap, orient="vertical")
        scroll.pack(side="right", fill="y")
        cv = tk.Canvas(wrap, bg=BG, highlightthickness=0, yscrollcommand=scroll.set)
        cv.pack(fill="both", expand=True)
        scroll.config(command=cv.yview)
        content = tk.Frame(cv, bg=BG)
        win = cv.create_window((0, 0), window=content, anchor="nw")
        cv.bind("<Configure>", lambda e: cv.itemconfig(win, width=e.width))
        content.bind("<Configure>",
                     lambda e: cv.configure(scrollregion=cv.bbox("all")))
        for seq in ("<MouseWheel>", "<Button-4>", "<Button-5>"):
            cv.bind_all(seq, lambda e, c=cv: c.yview_scroll(
                -1 if e.num == 4 or getattr(e, "delta", 0) > 0 else 1, "units"))

        if self._error:
            tk.Label(content, text=f"Discovery failed: {self._error}",
                     font=F_SMALL, bg=BG, fg=ERR, wraplength=420,
                     justify="left").pack(padx=28, pady=20, anchor="w")
        elif not self._devices:
            tk.Label(content,
                     text="No devices discovered. nmap host discovery on a LAN "
                          "may require elevated privileges to report MAC "
                          "addresses and vendors.",
                     font=F_SMALL, bg=BG, fg=TSEC, wraplength=420,
                     justify="left").pack(padx=28, pady=20, anchor="w")
        else:
            for d in self._devices:
                self._device_card(content, d)

        # Footer buttons
        foot = tk.Frame(self, bg=PANEL, highlightbackground=BORDER,
                        highlightthickness=0)
        foot.pack(fill="x", side="bottom")
        tk.Frame(foot, bg=BORDER, height=1).pack(fill="x")
        fin = tk.Frame(foot, bg=PANEL)
        fin.pack(fill="x", padx=28, pady=14)
        Btn(fin, "Rescan Network",
            lambda: self.master._switch(NetworkFrame, self._email)
            ).pack(fill="x", pady=(0, 8))
        GhostBtn(fin, "Back to System Scan",
                 lambda: self.master._switch(ScanFrame, self._email)
                 ).pack(fill="x")

    def _device_card(self, parent, d: dict):
        card = tk.Frame(parent, bg=CARD,
                        highlightbackground=BORDER, highlightthickness=1)
        card.pack(fill="x", padx=28, pady=6)
        inn = tk.Frame(card, bg=CARD)
        inn.pack(fill="x", padx=16, pady=12)

        top = tk.Frame(inn, bg=CARD)
        top.pack(fill="x")
        tk.Label(top, text=d.get("ip", "?"), font=(MONO, 11, "bold"),
                 bg=CARD, fg=ACCENT).pack(side="left")
        dtype = d.get("device_type", "Unknown")
        chip = tk.Frame(top, bg=PANEL, highlightbackground=BORDA,
                        highlightthickness=1)
        chip.pack(side="right")
        tk.Label(chip, text=f" {dtype} ", font=F_SMALL,
                 bg=PANEL, fg=TSEC, pady=2).pack()

        hostname = d.get("hostname") or "—"
        tk.Label(inn, text=hostname, font=F_BODY, bg=CARD, fg=TEXT,
                 anchor="w").pack(fill="x", pady=(8, 2))

        meta = tk.Frame(inn, bg=CARD)
        meta.pack(fill="x")

        def _kv(label, value):
            r = tk.Frame(meta, bg=CARD)
            r.pack(fill="x", pady=1)
            tk.Label(r, text=label, font=F_SMALL, bg=CARD, fg=TMUT,
                     width=9, anchor="w").pack(side="left")
            tk.Label(r, text=value or "—", font=(MONO, 9), bg=CARD,
                     fg=TSEC, anchor="w").pack(side="left", fill="x", expand=True)

        _kv("MAC", d.get("mac"))
        _kv("Vendor", d.get("vendor"))
        _kv("OS", d.get("os_details") or d.get("os_guess"))
        ports = d.get("open_ports") or []
        if ports:
            _kv("Ports", ", ".join(ports[:6]) + ("…" if len(ports) > 6 else ""))


# ── Shared top-bar ────────────────────────────────────────────────────────────

def _topbar(parent: tk.Frame, subtitle: str = "") -> tk.Frame:
    """Renders a slim header with logo, optional subtitle, and a close button."""
    bar = tk.Frame(parent, bg=PANEL, highlightbackground=BORDER, highlightthickness=0)
    bar.pack(fill="x")
    inner = tk.Frame(bar, bg=PANEL)
    inner.pack(fill="x", padx=20, pady=14)

    left = tk.Frame(inner, bg=PANEL)
    left.pack(side="left", fill="x", expand=True)
    logo = _logo(22)
    if logo:
        lg = tk.Label(left, image=logo, bg=PANEL)
        lg.image = logo
        lg.pack(side="left", padx=(0, 10))
    tk.Label(left, text="Scan Oasis", font=F_H2,
             bg=PANEL, fg=TEXT).pack(side="left")
    if subtitle:
        tk.Label(left, text="·", font=F_H2, bg=PANEL, fg=TMUT,
                 padx=8).pack(side="left")
        tk.Label(left, text=subtitle, font=F_SMALL,
                 bg=PANEL, fg=TSEC).pack(side="left")

    close = tk.Button(inner, text="✕", font=(FONT, 12),
                      bg=PANEL, fg=TMUT, activebackground=PANEL,
                      activeforeground=ERR, relief="flat", bd=0,
                      cursor="hand2", padx=4,
                      command=parent.master.destroy)
    close.pack(side="right")

    tk.Frame(parent, bg=BORDER, height=1).pack(fill="x")
    return bar


# ── Widget helpers ─────────────────────────────────────────────────────────────

class Entry(tk.Frame):
    """Styled entry with placeholder support."""

    def __init__(self, parent, placeholder="", show=""):
        super().__init__(parent, bg=CARD,
                         highlightbackground=BORDA, highlightthickness=1)
        self._ph  = placeholder
        self._var = tk.StringVar()
        self._e   = tk.Entry(
            self, textvariable=self._var,
            bg=CARD, fg=TMUT, insertbackground=ACCENT,
            selectbackground=ACCENT, selectforeground=BG,
            relief="flat", font=(FONT, 11), bd=10, show=show or "")
        self._e.pack(fill="x")
        # Accent the hairline border on focus for a refined input feel.
        self._e.bind("<FocusIn>",  self._focus_in, add="+")
        self._e.bind("<FocusOut>", self._focus_out, add="+")
        # Ctrl+A / Cmd+A → select all. Tk's default Ctrl+A is "go to line start",
        # which is why users couldn't select-and-replace what they'd typed.
        for seq in ("<Control-a>", "<Control-A>", "<Command-a>", "<Command-A>"):
            self._e.bind(seq, self._select_all)
        if placeholder and not show:
            self._e.insert(0, placeholder)
            self._e.bind("<FocusIn>",  self._in)
            self._e.bind("<FocusOut>", self._out)
            self._e.bind("<Key>",      self._key)

    def _focus_in(self, _):
        self.config(highlightbackground=ACCENT, highlightcolor=ACCENT)

    def _focus_out(self, _):
        self.config(highlightbackground=BORDA, highlightcolor=BORDA)

    def _in(self, _):
        if self._var.get() == self._ph:
            self._e.delete(0, "end")
            self._e.config(fg=TEXT)

    def _out(self, _):
        if not self._var.get():
            self._e.insert(0, self._ph)
            self._e.config(fg=TMUT)

    def _key(self, _):
        if self._e.cget("fg") == TMUT:
            self._e.config(fg=TEXT)

    def _select_all(self, _):
        # Don't select the greyed-out placeholder text.
        if self._e.cget("fg") == TMUT:
            return "break"
        self._e.select_range(0, "end")
        self._e.icursor("end")
        return "break"

    def get(self) -> str:
        v = self._var.get()
        return "" if v == self._ph else v


class Btn(tk.Button):
    """Primary, accent-filled call-to-action button."""

    def __init__(self, parent, text: str, command):
        super().__init__(
            parent, text=text, command=command,
            bg=ACCENT, fg="#000000",
            activebackground=ACCENT_HI, activeforeground="#000000",
            relief="flat", font=(FONT, 11, "bold"),
            pady=11, cursor="hand2", bd=0,
            highlightthickness=0)


class GhostBtn(tk.Button):
    """Secondary, outlined button — hairline border, hover-lit text."""

    def __init__(self, parent, text: str, command):
        super().__init__(
            parent, text=text, command=command,
            bg=PANEL, fg=TSEC,
            activebackground=HOVER, activeforeground=TEXT,
            relief="flat", font=(FONT, 11, "bold"),
            pady=10, cursor="hand2", bd=0,
            highlightbackground=BORDA, highlightthickness=1)
        self.bind("<Enter>", lambda _: self.config(fg=TEXT, bg=HOVER))
        self.bind("<Leave>", lambda _: self.config(fg=TSEC, bg=PANEL))


def _dot(parent, color: str, size: int = 8) -> tk.Canvas:
    """A small filled status dot drawn on a canvas (no emoji)."""
    pad = 4
    cv = tk.Canvas(parent, width=size + pad, height=size + pad,
                   bg=parent.cget("bg"), highlightthickness=0)
    cv.create_oval(pad / 2, pad / 2, pad / 2 + size, pad / 2 + size,
                   fill=color, outline="")
    return cv


def _glyph(parent, kind: str, size: int, color: str, bg: str) -> tk.Canvas:
    """Minimal monochrome vector glyph (currently: a shield) — no emoji."""
    cv = tk.Canvas(parent, width=size, height=size, bg=bg, highlightthickness=0)
    if kind == "shield":
        w = size
        m = size * 0.12
        pts = [
            w / 2, m,
            w - m, m + size * 0.12,
            w - m, size * 0.55,
            w / 2, w - m,
            m, size * 0.55,
            m, m + size * 0.12,
        ]
        cv.create_polygon(pts, outline=color, fill="", width=2,
                          joinstyle="round")
        cv.create_line(w * 0.34, size * 0.5, w * 0.46, size * 0.62,
                       w * 0.66, size * 0.38, fill=color, width=2,
                       capstyle="round", joinstyle="round")
    return cv


# ── Utilities ─────────────────────────────────────────────────────────────────

def _lerp(c1: str, c2: str, t: float) -> str:
    r1, g1, b1 = int(c1[1:3], 16), int(c1[3:5], 16), int(c1[5:7], 16)
    r2, g2, b2 = int(c2[1:3], 16), int(c2[3:5], 16), int(c2[5:7], 16)
    r = int(r1 + (r2 - r1) * t)
    g = int(g1 + (g2 - g1) * t)
    b = int(b1 + (b2 - b1) * t)
    return f"#{r:02x}{g:02x}{b:02x}"


def _hb(n) -> str:
    if not isinstance(n, (int, float)) or not n:
        return "?"
    for u in ("B", "KiB", "MiB", "GiB", "TiB"):
        if n < 1024:
            return f"{n:.1f} {u}"
        n /= 1024
    return f"{n:.1f} PiB"


if __name__ == "__main__":
    App().mainloop()
