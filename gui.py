"""Oasis Scan — Desktop GUI

Requires: sudo pacman -S tk   (Arch Linux)
Run:      python gui.py
"""

import tkinter as tk
import threading
import math
import time
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import scanner as _sc

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
ERR    = "#ff3860"
OK     = "#27c93f"

SCAN_STEPS = [
    "Collecting OS information…",
    "Reading CPU & memory…",
    "Scanning block devices…",
    "Enumerating installed packages…",
    "Checking running services…",
    "Mapping network interfaces…",
    "Finalizing report…",
    "Syncing to cloud…",
]


# ── Root window ───────────────────────────────────────────────────────────────

class App(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("Oasis Scan")
        self.configure(bg=BG)
        self.resizable(False, False)
        self._creds: tuple[str, str] | None = None   # (token, uid)
        self._frame: tk.Frame | None = None
        self._center(480, 560)
        self._switch(LoginFrame)

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
        # ── Logo ──────────────────────────────────────────────────────────────
        top = tk.Frame(self, bg=BG)
        top.pack(pady=(52, 0))
        tk.Label(top, text="⬡", font=("Inter", 38),
                 bg=BG, fg=ACCENT).pack()
        tk.Label(top, text="Oasis Scan", font=("Inter", 21, "bold"),
                 bg=BG, fg=TEXT).pack(pady=(3, 0))
        tk.Label(top, text="Sign in to your account",
                 font=("Inter", 10), bg=BG, fg=TSEC).pack(pady=(3, 0))

        # ── Card ──────────────────────────────────────────────────────────────
        card = tk.Frame(self, bg=PANEL,
                        highlightbackground=BORDER, highlightthickness=1)
        card.pack(padx=48, pady=30, fill="x")
        inn = tk.Frame(card, bg=PANEL)
        inn.pack(padx=28, pady=28, fill="x")

        # Email
        tk.Label(inn, text="Email", font=("Inter", 9, "bold"),
                 bg=PANEL, fg=TSEC).pack(anchor="w")
        self._email = Entry(inn, placeholder="you@example.com")
        self._email.pack(fill="x", pady=(4, 14))

        # Password
        tk.Label(inn, text="Password", font=("Inter", 9, "bold"),
                 bg=PANEL, fg=TSEC).pack(anchor="w")
        self._pw = Entry(inn, placeholder="••••••••", show="•")
        self._pw.pack(fill="x", pady=(4, 22))

        # Button
        self._btn = Btn(inn, "Sign In", self._submit)
        self._btn.pack(fill="x")

        # Auth status — spinner + label in one row
        self._status_row = tk.Frame(inn, bg=PANEL)
        self._status_row.pack(pady=(12, 0))
        self._spin_cv = tk.Canvas(self._status_row, width=16, height=16,
                                   bg=PANEL, highlightthickness=0)
        self._spin_cv.pack(side="left")
        self._err_lbl = tk.Label(self._status_row, text="",
                                  font=("Inter", 9), bg=PANEL,
                                  fg=ERR, wraplength=320)
        self._err_lbl.pack(side="left", padx=(6, 0))

        self._spin_angle = 0.0
        self._spinning   = False

        self.master.bind("<Return>", lambda _: self._submit())

    # ── Spinner (small, shown while authenticating) ───────────────────────────

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

    def _start_spin(self):
        self._spinning = True
        self._err_lbl.config(text="Authenticating…", fg=TSEC)
        self._draw_login_spin()

    def _stop_spin(self):
        self._spinning = False
        self._spin_cv.delete("all")

    # ── Login logic ───────────────────────────────────────────────────────────

    def _submit(self):
        email = self._email.get().strip()
        pw    = self._pw.get()
        if not email or not pw:
            self._err("Please enter your email and password.")
            return
        self._btn.config(state="disabled")
        self._err_lbl.config(text="", fg=ERR)
        self._start_spin()
        threading.Thread(
            target=self._login_thread, args=(email, pw), daemon=True
        ).start()

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

    def _err(self, msg: str):
        self._err_lbl.config(text=msg, fg=ERR)


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
        center = tk.Frame(self, bg=BG)
        center.place(relx=0.5, rely=0.5, anchor="center")

        # Signed-in-as pill
        pill = tk.Frame(center, bg=CARD,
                        highlightbackground=BORDA, highlightthickness=1)
        pill.pack(pady=(0, 38))
        tk.Label(pill, text=f"  {self._email}  ",
                 font=("Inter", 9), bg=CARD, fg=TSEC, pady=7).pack()

        # Spinner canvas
        self._cv = tk.Canvas(center, width=96, height=96,
                             bg=BG, highlightthickness=0)
        self._cv.pack()

        # Title + step label
        tk.Label(center, text="Running Oasis Scan",
                 font=("Inter", 15, "bold"), bg=BG, fg=TEXT, pady=16).pack()
        self._step_lbl = tk.Label(center, text=SCAN_STEPS[0],
                                   font=("JetBrains Mono", 9),
                                   bg=BG, fg=TMUT, wraplength=340)
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

        self._step = 6
        time.sleep(0.08)

        self._step = 7          # syncing
        _sc.firestore_save(token, uid, report)

        self._done = True
        self.after(0, lambda: self.master._switch(ResultFrame, report, self._email))


# ── Results frame ─────────────────────────────────────────────────────────────

class ResultFrame(tk.Frame):
    def __init__(self, master: App, report: dict, email: str):
        super().__init__(master, bg=BG)
        self._r     = report
        self._email = email
        self._build()

    def _build(self):
        # Top bar
        bar = tk.Frame(self, bg=PANEL)
        bar.pack(fill="x")
        b = tk.Frame(bar, bg=PANEL)
        b.pack(fill="x", padx=20, pady=13)
        tk.Label(b, text="⬡  Oasis Scan",
                 font=("Inter", 13, "bold"), bg=PANEL, fg=TEXT).pack(side="left")
        tk.Label(b, text="✓ Synced to cloud",
                 font=("Inter", 9), bg=PANEL, fg=OK).pack(side="right")
        tk.Label(b, text=self._email,
                 font=("Inter", 9), bg=PANEL, fg=TSEC).pack(side="right", padx=14)
        tk.Frame(self, bg=BORDER, height=1).pack(fill="x")

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
            tk.Label(p, text=title, font=("Inter", 9, "bold"),
                     bg=BG, fg=TMUT, anchor="w"
                     ).pack(fill="x", padx=20, pady=(20, 5))
            tk.Frame(p, bg=BORDER, height=1).pack(fill="x", padx=20)

        def row(label: str, value: str, mono=False):
            f = tk.Frame(p, bg=BG)
            f.pack(fill="x", padx=20, pady=2)
            tk.Label(f, text=label, font=("Inter", 10),
                     bg=BG, fg=TSEC, width=18, anchor="w").pack(side="left")
            fnt = ("JetBrains Mono", 10) if mono else ("Inter", 10)
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

        # Rescan button
        tk.Frame(p, bg=BG, height=12).pack()
        Btn(p, "Run Another Scan",
            lambda: self.master._switch(ScanFrame, self._email)
        ).pack(padx=20, pady=(0, 24), fill="x")


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
            relief="flat", font=("Inter", 11), bd=8, show=show or "")
        self._e.pack(fill="x")
        if placeholder and not show:
            self._e.insert(0, placeholder)
            self._e.bind("<FocusIn>",  self._in)
            self._e.bind("<FocusOut>", self._out)
            self._e.bind("<Key>",      self._key)

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

    def get(self) -> str:
        v = self._var.get()
        return "" if v == self._ph else v


class Btn(tk.Button):
    def __init__(self, parent, text: str, command):
        super().__init__(
            parent, text=text, command=command,
            bg=ACCENT, fg="#000000",
            activebackground="#33ddff", activeforeground="#000000",
            relief="flat", font=("Inter", 11, "bold"),
            pady=10, cursor="hand2", bd=0)


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
