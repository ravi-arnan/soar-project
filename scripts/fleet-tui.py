#!/usr/bin/env python3
"""Fleet Monitor TUI — kembaran terminal dari fleet-monitor.py (GUI web).

Sumber data SAMA: GET /api/fleet + GET /api/events dari fleet-monitor (port 8080).
Jadi GUI dan TUI selalu menampilkan data yang identik — user bebas pilih mana.
Stdlib only (curses + urllib), tanpa dependency tambahan.

Jalankan di laptop admin atau via SSH ke server:

    python3 scripts/fleet-tui.py                          # default 127.0.0.1:8080
    python3 scripts/fleet-tui.py --url http://100.95.198.108:8080
    FLEET_URL=http://100.95.198.108:8080 python3 scripts/fleet-tui.py

Keys:
  1 2 3 4 / Tab   pindah view: overview, agents, threat events, health
  /               cari agent (nama / IP / ID), Enter terapkan, Esc bersihkan
  s               (agents) simulasi heartbeat 004..100 — sama dengan tombol GUI
  e               (events) saring severity berikutnya (semua -> CRITICAL -> ...)
  r               refresh paksa
  q               keluar

ponytail: parity 4 view dengan GUI (overview/agents/threat/health), tapi
read-only kecuali simulasi — keputusan respons tetap lewat Telegram HITL.
"""

import argparse
import curses
import json
import os
import ssl
import sys
import time
import urllib.request

# ---------------------------------------------------------------- konstanta

VIEWS = ["overview", "agents", "events", "health"]
SEV_ORDER = ["", "CRITICAL", "HIGH", "MEDIUM", "UNVERIFIED", "INFO"]
SEV_LABEL = {0: "semua"}

# Pasangan warna (kurang lebih padanan chip warna GUI)
C_HEAD = 1
C_OK = 2
C_BAD = 3
C_WARN = 4
C_RUST = 5
C_MUTED = 6
C_CRIT = 7
C_HIGH = 8
C_MED = 9
C_UNV = 10
C_INFO = 11

SEV_COLOR = {
    "CRITICAL": C_CRIT,
    "HIGH": C_HIGH,
    "MEDIUM": C_MED,
    "UNVERIFIED": C_UNV,
    "INFO": C_INFO,
}


def init_colors():
    curses.start_color()
    curses.use_default_colors()
    curses.init_pair(C_HEAD, curses.COLOR_BLACK, curses.COLOR_CYAN)
    curses.init_pair(C_OK, curses.COLOR_GREEN, -1)
    curses.init_pair(C_BAD, curses.COLOR_RED, -1)
    curses.init_pair(C_WARN, curses.COLOR_YELLOW, -1)
    curses.init_pair(C_RUST, curses.COLOR_BLUE, -1)
    curses.init_pair(C_MUTED, curses.COLOR_WHITE, -1)
    curses.init_pair(C_CRIT, curses.COLOR_RED, -1)
    curses.init_pair(C_HIGH, curses.COLOR_YELLOW, -1)
    curses.init_pair(C_MED, curses.COLOR_YELLOW, -1)
    curses.init_pair(C_UNV, curses.COLOR_MAGENTA, -1)
    curses.init_pair(C_INFO, curses.COLOR_CYAN, -1)


def sev_attr(sev):
    return curses.color_pair(SEV_COLOR.get(sev, C_INFO)) | curses.A_BOLD


def left_trunc(text, width):
    """Potong dari KIRI (simpan bagian akhir) — untuk path file, basename
    yang penting: '/home/budi/Downloads/eicar.com' -> '…/eicar.com'."""
    text = str(text)
    if len(text) <= width:
        return text
    return "…" + text[-(width - 1):] if width > 1 else text[-1:]


def status_attr(status):
    if status == "active":
        return curses.color_pair(C_OK) | curses.A_BOLD
    return curses.color_pair(C_BAD) | curses.A_BOLD


# ---------------------------------------------------------------- fetch data

_CTX = ssl.create_default_context()
_CTX.check_hostname = False
_CTX.verify_mode = ssl.CERT_NONE


def _get_json(url, timeout=6):
    req = urllib.request.Request(url, headers={"User-Agent": "fleet-tui/0.1"})
    with urllib.request.urlopen(req, timeout=timeout, context=_CTX) as r:
        return json.load(r)


def _post_json(url, payload, timeout=6):
    data = json.dumps(payload).encode()
    req = urllib.request.Request(
        url, data=data, headers={"Content-Type": "application/json"}
    )
    with urllib.request.urlopen(req, timeout=timeout, context=_CTX) as r:
        return json.load(r)


def simulate(base):
    """Sama dengan tombol 'Simulasi 100 PC' di GUI (agent 004..100)."""
    for i in range(4, 101):
        try:
            _post_json(
                base + "/api/heartbeat",
                {
                    "id": str(i),
                    "name": f"rust-agent-lab-{i}",
                    "ip": f"192.168.18.{100 + i}",
                    "version": "0.1.0",
                },
            )
        except Exception:
            pass


# ---------------------------------------------------------------- drawing

class Ui:
    def __init__(self, stdscr, base, interval):
        self.scr = stdscr
        self.base = base.rstrip("/")
        self.interval = interval
        self.view = 0
        self.countdown = 0
        self.filter = ""
        self.filtering = False  # sedang mengetik di prompt /
        self.ev_sev = 0
        self.fleet = None
        self.events = []
        self.err = None
        self.last_fetch = None

    # -- data

    def refetch(self):
        try:
            self.fleet = _get_json(self.base + "/api/fleet")
            self.events = _get_json(self.base + "/api/events").get("events", [])
            self.err = None
            self.last_fetch = time.strftime("%H:%M:%S")
        except Exception as e:
            self.err = str(e)

    # -- util

    def w(self, y, x, text, attr=0, maxlen=None):
        """Tulis aman: truncate agar tidak tabrak batas layar."""
        try:
            height, width = self.scr.getmaxyx()
            if y < 0 or y >= height:
                return
            avail = width - x - 1
            if maxlen is not None:
                avail = min(avail, maxlen)
            if avail <= 0:
                return
            self.scr.addnstr(y, x, text, avail, attr)
        except curses.error:
            pass

    def hline(self, y, attr=0):
        _, width = self.scr.getmaxyx()
        self.w(y, 0, " " * width, attr)

    # -- chrome

    def draw_header(self):
        self.hline(0, curses.color_pair(C_HEAD) | curses.A_BOLD)
        title = " WAZUH. Fleet Monitor [TUI] "
        view = VIEWS[self.view]
        right = f"view: {view}  refresh: {self.countdown}s"
        self.w(0, 1, title, curses.color_pair(C_HEAD) | curses.A_BOLD)
        _, width = self.scr.getmaxyx()
        self.w(0, max(1, width - len(right) - 1), right, curses.color_pair(C_HEAD))

    def draw_footer(self):
        _, height = self.scr.getmaxyx()
        if self.filtering:
            hint = f" cari: {self.filter}_  (Enter=terapkan, Esc=batal) "
        else:
            hint = " 1-4/Tab view  / cari agent  e saring severity  s simulasi  r refresh  q keluar "
        self.hline(height - 1, curses.color_pair(C_HEAD))
        self.w(height - 1, 1, hint, curses.color_pair(C_HEAD))

    def draw_banner(self, y):
        """Banner status digambar SEKALI di draw() (bukan per-view) supaya
        error state tetap tampil walau view kosong."""
        if self.err:
            self.w(y, 2, f"fleet-monitor unreachable: {self.err}", curses.color_pair(C_BAD) | curses.A_BOLD)
            self.w(y + 1, 2, f"coba: curl {self.base}/healthz  (GUI: python3 scripts/fleet-monitor.py)", curses.color_pair(C_MUTED))
            return y + 2
        if self.last_fetch:
            self.w(y, 2, f"data terakhir: {self.last_fetch} WITA-server · sumber: {self.base}", curses.color_pair(C_MUTED))
        return y + 1

    # -- views

    def draw_overview(self, y0):
        f = self.fleet
        if not f:
            return y0
        st = f.get("stats", {})
        y = y0 + 1
        sev = st.get("severity", {})

        kpis = [
            ("TOTAL", str(st.get("total", 0)), curses.A_BOLD),
            ("AKTIF", str(st.get("active", 0)), curses.color_pair(C_OK) | curses.A_BOLD),
            ("PUTUS", str(st.get("disconnected", 0)), curses.color_pair(C_BAD) | curses.A_BOLD),
            ("RUST", str(st.get("rust", 0)), curses.color_pair(C_RUST) | curses.A_BOLD),
            ("WAZUH", str(st.get("wazuh", 0)), curses.A_BOLD),
            ("EVENTS", str(st.get("events_total", 0)), curses.A_BOLD),
        ]
        x = 2
        _, width = self.scr.getmaxyx()
        col = max(12, width // (len(kpis) + 1))
        for label, val, attr in kpis:
            self.w(y, x, label, curses.color_pair(C_MUTED))
            self.w(y + 1, x, val, attr)
            x += col
        y += 3

        # severity bars
        self.w(y, 2, "Threat severity", curses.A_BOLD | curses.A_UNDERLINE)
        y += 1
        total_sev = sum(sev.values()) or 1
        for name in ["CRITICAL", "HIGH", "MEDIUM", "UNVERIFIED", "INFO"]:
            n = sev.get(name, 0)
            bar_w = max(1, (width - 34) // 1)
            filled = int(bar_w * n / total_sev)
            bar = "█" * filled + "·" * (bar_w - filled)
            self.w(y, 4, f"{name:<10}", sev_attr(name))
            self.w(y, 15, bar, sev_attr(name))
            self.w(y, 15 + bar_w + 1, str(n), curses.A_BOLD)
            y += 1
        y += 1

        # latest events
        self.w(y, 2, "Latest events (5)", curses.A_BOLD | curses.A_UNDERLINE)
        y += 1
        for ev in self.events[:5]:
            self.w(y, 4, str(ev.get("ts", ""))[11:19], curses.color_pair(C_MUTED))
            self.w(y, 13, str(ev.get("agent", "-"))[:18])
            self.w(y, x, left_trunc(str(ev.get("path", "-")), width - 55))
            self.w(y, width - 20, str(ev.get("severity", "INFO")), sev_attr(ev.get("severity", "INFO")))
            y += 1
        return y

    def draw_agents(self, y0):
        f = self.fleet
        if not f:
            return y0
        y = y0 + 1
        _, width = self.scr.getmaxyx()
        agents = f.get("agents", [])
        if self.filter:
            q = self.filter.lower()
            agents = [
                a
                for a in agents
                if q in a.get("name", "").lower()
                or q in a.get("ip", "").lower()
                or q in a.get("id", "").lower()
            ]

        cols = [
            ("ID", 5),
            ("NAMA", 22),
            ("TIPE", 7),
            ("STATUS", 13),
            ("IP", 17),
            ("VERSI", 9),
            ("KEEP-ALIVE", 21),
            ("RAM", 8),
        ]
        # Terminal sempit: potong kolom keep-alive & RAM
        if width < 110:
            cols = cols[:6]
        x = 2
        for name, cw in cols:
            self.w(y, x, name.ljust(cw), curses.A_BOLD | curses.A_UNDERLINE)
            x += cw
        y += 1

        _, height = self.scr.getmaxyx()
        max_rows = height - y - 2
        for a in agents[:max_rows]:
            x = 2
            t = a.get("type", "wazuh")
            tattr = curses.color_pair(C_RUST) if t == "rust" else curses.color_pair(C_MUTED)
            self.w(y, x, str(a.get("id", "?")).ljust(5), curses.A_BOLD)
            x += 5
            self.w(y, x, str(a.get("name", "?"))[: cols[1][1]].ljust(cols[1][1]))
            x += cols[1][1]
            self.w(y, x, ("rust" if t == "rust" else "wazuh").ljust(7), tattr | curses.A_BOLD)
            x += 7
            self.w(y, x, str(a.get("status", "?")).ljust(13), status_attr(a.get("status")))
            x += 13
            self.w(y, x, str(a.get("ip", "-")).ljust(17))
            x += 17
            if width >= 110:
                self.w(y, x, str(a.get("version", "-")).ljust(9))
                x += 9
                self.w(y, x, str(a.get("lastKeepAlive", "-")).ljust(21), curses.color_pair(C_MUTED))
                x += 21
                self.w(y, x, str(a.get("ram", "-")).ljust(8))
            y += 1
        if len(agents) > max_rows:
            self.w(y + 1, 2, f"... {len(agents) - max_rows} agent lagi (perkecil filter / perbesar terminal)", curses.color_pair(C_MUTED))
        else:
            self.w(y + 1, 2, f"{len(agents)} agent ditampilkan", curses.color_pair(C_MUTED))
        return y

    def draw_events(self, y0):
        y = y0 + 1
        _, width = self.scr.getmaxyx()
        _, height = self.scr.getmaxyx()
        sev = SEV_ORDER[self.ev_sev]
        evs = self.events
        if sev:
            evs = [e for e in evs if e.get("severity") == sev]
        label = sev or "semua severity"
        self.w(y, 2, f"Threat events — saring: {label} ({len(evs)} event)", curses.A_BOLD)
        y += 2

        # Terminal sempit (mis. SSH 80 kolom): tabel menyesuaikan lebar kolom
        if width < 110:
            cols = [
                ("WAKTU", 9), ("AGENT", 16), ("FILE", max(14, width - 66)),
                ("HASH", 12), ("SEVERITY", 10), ("STATUS", 9),
            ]
        else:
            cols = [
                ("WAKTU", 10), ("AGENT", 20), ("FILE", 34),
                ("HASH", 14), ("SEVERITY", 11), ("STATUS", 10),
            ]
        x = 2
        for name, cw in cols:
            self.w(y, x, name.ljust(cw), curses.A_BOLD | curses.A_UNDERLINE)
            x += cw
        y += 1

        for ev in evs[: height - y - 2]:
            x = 2
            self.w(y, x, str(ev.get("ts", ""))[11:19].ljust(cols[0][1]), curses.color_pair(C_MUTED))
            x += cols[0][1]
            self.w(y, x, str(ev.get("agent", "-"))[: cols[1][1]].ljust(cols[1][1]))
            x += cols[1][1]
            self.w(y, x, left_trunc(ev.get("path", "-"), cols[2][1]).ljust(cols[2][1]))
            x += cols[2][1]
            self.w(y, x, str(ev.get("hash", "-"))[: cols[3][1] - 2].ljust(cols[3][1]))
            x += cols[3][1]
            self.w(y, x, str(ev.get("severity", "INFO"))[: cols[4][1]].ljust(cols[4][1]), sev_attr(ev.get("severity", "INFO")))
            x += cols[4][1]
            self.w(y, x, str(ev.get("status", "-"))[: cols[5][1]].ljust(cols[5][1]))
            y += 1
        return y

    def draw_health(self, y0):
        f = self.fleet
        if not f:
            return y0
        y = y0 + 1
        h = f.get("health", {})
        self.w(y, 2, "Komponen inti", curses.A_BOLD | curses.A_UNDERLINE)
        y += 2
        rows = [
            ("n8n (otak orkestrasi)", h.get("n8n")),
            ("Gemini API key", h.get("gemini")),
            ("Wazuh API", h.get("wazuh_api")),
        ]
        for name, ok in rows:
            self.w(y, 4, name.ljust(26))
            if ok:
                self.w(y, 32, "● OK", curses.color_pair(C_OK) | curses.A_BOLD)
            else:
                self.w(y, 32, "● DOWN", curses.color_pair(C_BAD) | curses.A_BOLD)
            y += 1
        y += 1
        self.w(y, 2, "Catatan: GUI web tersedia di port yang sama (browser -> /).", curses.color_pair(C_MUTED))
        return y

    def draw(self):
        self.scr.erase()
        self.draw_header()
        y0 = self.draw_banner(2)
        fn = {
            "overview": self.draw_overview,
            "agents": self.draw_agents,
            "events": self.draw_events,
            "health": self.draw_health,
        }[VIEWS[self.view]]
        try:
            fn(y0)
        except curses.error:
            pass
        self.draw_footer()
        self.scr.noutrefresh()
        curses.doupdate()

    # -- input

    def key(self, ch):
        if self.filtering:
            if ch in (10, 13, curses.KEY_ENTER):
                self.filtering = False
            elif ch in (27,):  # Esc
                self.filter = ""
                self.filtering = False
            elif ch in (curses.KEY_BACKSPACE, 127, 8):
                self.filter = self.filter[:-1]
            elif 32 <= ch < 127:
                self.filter += chr(ch)
            return
        if ch in (ord("q"), ord("Q")):
            raise SystemExit(0)
        if ch == ord("r") or ch == curses.KEY_RESIZE:
            self.refetch()
            return
        if ch in (9,):  # Tab
            self.view = (self.view + 1) % len(VIEWS)
            return
        if ch in (ord("1"), ord("2"), ord("3"), ord("4")):
            self.view = int(chr(ch)) - 1
            return
        if ch == ord("/"):
            self.filtering = True
            return
        if ch == ord("s"):
            if VIEWS[self.view] == "agents":
                self.refetch()
                self.w(2, 2, "mengirim simulasi 004..100 ...", curses.color_pair(C_WARN) | curses.A_BOLD)
                self.scr.refresh()
                simulate(self.base)
                self.refetch()
            return
        if ch == ord("e"):
            if VIEWS[self.view] == "events":
                self.ev_sev = (self.ev_sev + 1) % len(SEV_ORDER)
            return

    def run(self):
        self.refetch()
        self.countdown = self.interval
        self.draw()
        self.scr.timeout(250)
        while True:
            ch = self.scr.getch()
            if ch == -1:
                self.countdown -= 0.25
                if self.countdown <= 0:
                    self.refetch()
                    self.countdown = self.interval
                    self.draw()
                continue
            self.key(ch)
            self.draw()


def main():
    ap = argparse.ArgumentParser(description="Fleet Monitor TUI (kembaran GUI fleet-monitor.py)")
    ap.add_argument("--url", default=os.environ.get("FLEET_URL", "http://127.0.0.1:8080"),
                    help="base URL fleet-monitor (default $FLEET_URL atau http://127.0.0.1:8080)")
    ap.add_argument("--interval", type=float, default=float(os.environ.get("TUI_INTERVAL", "5")),
                    help="detik antar refresh (default 5)")
    args = ap.parse_args()

    try:
        curses.wrapper(lambda scr: _run(scr, args))
    except KeyboardInterrupt:
        pass
    return 0


def _run(scr, args):
    curses.curs_set(0)
    init_colors()
    Ui(scr, args.url, args.interval).run()


if __name__ == "__main__":
    sys.exit(main())
