import os, sys, time, sqlite3, threading, queue, csv, webbrowser, subprocess, re
from datetime import datetime
from typing import Optional, Set

# Silence old macOS Tk warning (optional)
os.environ.setdefault("TK_SILENCE_DEPRECATION", "1")

# -------------------- Flask side (runs in background thread) --------------------
from flask import Flask, request, g
from collections import defaultdict

# Optional GeoIP (local DB first; API fallback if allowed)
try:
    from geoip2.database import Reader as GeoReader
except Exception:
    GeoReader = None

try:
    import requests
except Exception:
    requests = None

# Optional LAN ARP probing
try:
    from scapy.all import ARP, Ether, srp  # type: ignore
    HAVE_SCAPY = True
except Exception:
    HAVE_SCAPY = False

# -------------------- Tkinter UI --------------------
import tkinter as tk
from tkinter import ttk, messagebox, filedialog

APP_PORT = 8000
USE_HTTPS_ADHOC = False   # set True if you want dev HTTPS (self-signed) by default
DB_PATH = "events.db"
GEOLITE_DB = "GeoLite2-City.mmdb"  # put the file next to this script if you have it


def setup_theme(root: tk.Tk) -> None:
    """Force visible ttk theme/colors (helps on macOS dark mode)."""
    style = ttk.Style(root)
    try:
        style.theme_use("clam")
    except Exception:
        pass

    root.configure(bg="#111111")
    style.configure("TFrame", background="#111111")
    style.configure("TLabel", background="#111111", foreground="#eaeaea")
    style.configure("TButton", padding=6)
    style.configure(
        "Treeview",
        background="#1b1b1b",
        fieldbackground="#1b1b1b",
        foreground="#eaeaea",
        rowheight=22,
        borderwidth=0,
    )
    style.configure(
        "Treeview.Heading",
        background="#222222",
        foreground="#eaeaea",
        borderwidth=0,
    )
    style.map(
        "Treeview",
        background=[("selected", "#2d7bbd")],
        foreground=[("selected", "#ffffff")],
    )


def make_app(event_queue: "queue.Queue", deny_set: Set[str]):
    """Create the Flask app. Push (event_dict) into event_queue for UI."""
    app = Flask(__name__)

    # ------------- SQLite -------------
    def get_db():
        if "db" not in g:
            g.db = sqlite3.connect(DB_PATH, check_same_thread=False)
            g.db.execute("""
            CREATE TABLE IF NOT EXISTS events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ts INTEGER,
                ip TEXT,
                path TEXT,
                ua TEXT,
                city TEXT,
                country TEXT,
                lat REAL,
                lon REAL,
                flagged INTEGER DEFAULT 0,
                reason TEXT
            )""")
        return g.db

    @app.teardown_appcontext
    def close_db(_):
        db = g.pop("db", None)
        if db:
            db.close()

    # ------------- GeoIP -------------
    geo_reader = None
    if GeoReader and os.path.exists(GEOLITE_DB):
        try:
            geo_reader = GeoReader(GEOLITE_DB)
        except Exception:
            geo_reader = None

    def ip_to_geo(ip):
        # Prefer local DB for exam/offline
        if geo_reader:
            try:
                resp = geo_reader.city(ip)
                return (
                    (resp.city.name or "")[:64],
                    (resp.country.name or "")[:64],
                    resp.location.latitude,
                    resp.location.longitude,
                )
            except Exception:
                pass
        # Fallback to API (if allowed)
        if requests:
            try:
                r = requests.get(f"http://ip-api.com/json/{ip}", timeout=3)
                j = r.json()
                if j.get("status") == "success":
                    return (j.get("city"), j.get("country"), j.get("lat"), j.get("lon"))
            except Exception:
                pass
        return (None, None, None, None)

    # ------------- Helpers -------------
    hits_by_ip = defaultdict(list)
    SUSPICIOUS_PATHS = ("/.env", "/wp-login.php", "/phpmyadmin", "/etc/passwd", "/vendor/.env")
    RATE_LIMIT_WINDOW = 60
    RATE_LIMIT_MAX = 30

    def get_client_ip():
        xff = request.headers.get("X-Forwarded-For") or request.headers.get("X-Real-IP")
        return (xff.split(",")[0].strip() if xff else request.remote_addr) or "0.0.0.0"

    # Basic blocker
    @app.before_request
    def block_if_denied():
        ip = get_client_ip()
        if ip in deny_set:
            return "Forbidden", 403

    def detect(ip, path, ua):
        reasons = []
        if any(s in (path or "").lower() for s in SUSPICIOUS_PATHS):
            reasons.append("suspicious_path")
        if not ua or "sqlmap" in ua.lower() or "nikto" in ua.lower():
            reasons.append("bad_user_agent")
        now = int(time.time())
        hits = hits_by_ip[ip]
        hits.append(now)
        while hits and now - hits[0] > RATE_LIMIT_WINDOW:
            hits.pop(0)
        if len(hits) > RATE_LIMIT_MAX:
            reasons.append("rate_limit_exceeded")
        return (1 if reasons else 0, ",".join(reasons))

    # ------------- Logging middleware -------------
    @app.before_request
    def log_request():
        db = get_db()
        ip = get_client_ip()
        path = request.full_path or request.path
        ua = request.headers.get("User-Agent", "")
        city, country, lat, lon = ip_to_geo(ip)
        flagged, reason = detect(ip, path, ua)
        ts = int(time.time())
        db.execute(
            "INSERT INTO events (ts, ip, path, ua, city, country, lat, lon, flagged, reason) VALUES (?,?,?,?,?,?,?,?,?,?)",
            (ts, ip, path, ua, city, country, lat, lon, flagged, reason)
        )
        db.commit()

        # push to UI queue
        event_queue.put({
            "ts": ts, "ip": ip, "path": path, "ua": ua,
            "city": city, "country": country, "lat": lat, "lon": lon,
            "flagged": flagged, "reason": reason
        })

    # ------------- Routes -------------
    @app.get("/")
    def index():
        ip = get_client_ip()
        ua = request.headers.get("User-Agent", "")
        city, country, lat, lon = ip_to_geo(ip)
        return (
            f"<h2>OK</h2>"
            f"<p><b>IP:</b> {ip}</p>"
            f"<p><b>Geo:</b> {city or '-'}, {country or '-'}</p>"
            f"<p><b>UA:</b> {ua}</p>"
            f'<p>See <a href="/admin/logs">/admin/logs</a></p>'
        )

    @app.get("/admin/logs")
    def show_logs():
        rows = g.db.execute(
            "SELECT ts, ip, path, flagged, reason, city, country FROM events ORDER BY id DESC LIMIT 200"
        ).fetchall()
        out = []
        for ts, ip, path, flagged, reason, city, country in rows:
            out.append(
                f"{time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(ts))} | {ip:<15} | "
                f"{path:<30} | {'FLAG' if flagged else 'OK  ':<4} | {reason or '-':<18} | "
                f"{city or '-'}, {country or '-'}"
            )
        return " \n".join(out), 200, {"Content-Type": "text/plain; charset=utf-8"}

    @app.get("/favicon.ico")
    def favicon():
        return ("", 204)

    # Safe shutdown hook
    @app.post("/__shutdown")
    def __shutdown():
        func = request.environ.get("werkzeug.server.shutdown")
        if func:
            func()
            return "Shutting down...", 200
        return "Not running with the Werkzeug Server", 400

    return app


class GuardGUI:
    def __init__(self, root: tk.Tk):
        self.root = root
        root.title("Web Attack Detection — Tk GUI")
        root.geometry("1000x600")
        setup_theme(root)

        self.event_queue: "queue.Queue" = queue.Queue()
        self.server_thread: Optional[threading.Thread] = None
        self.server_running = False
        self.deny_ips: Set[str] = set()

        # Top controls
        top = ttk.Frame(root, padding=8)
        top.pack(fill="x")

        self.port_var = tk.StringVar(value=str(APP_PORT))
        self.https_var = tk.BooleanVar(value=USE_HTTPS_ADHOC)

        ttk.Label(top, text="Port:").pack(side="left")
        ttk.Entry(top, textvariable=self.port_var, width=6).pack(side="left", padx=(0, 10))
        ttk.Checkbutton(top, text="HTTPS (adhoc)", variable=self.https_var).pack(side="left", padx=(0, 10))

        self.btn_start = ttk.Button(top, text="Start Server", command=self.start_server)
        self.btn_start.pack(side="left", padx=4)

        self.btn_stop = ttk.Button(top, text="Stop Server", command=self.stop_server, state="disabled")
        self.btn_stop.pack(side="left", padx=4)

        ttk.Button(top, text="Open in Browser", command=self.open_browser).pack(side="left", padx=4)
        ttk.Button(top, text="Export CSV", command=self.export_csv).pack(side="left", padx=4)

        # Table
        cols = ("time", "ip", "path", "flag", "reason", "city", "country")
        self.tree = ttk.Treeview(root, columns=cols, show="headings")
        for c, w in zip(cols, (160, 130, 260, 60, 200, 120, 120)):
            self.tree.heading(c, text=c.upper())
            self.tree.column(c, width=w, stretch=(c in ("path", "reason")))
        self.tree.pack(fill="both", expand=True, padx=8, pady=8)

        # Bottom actions
        bottom = ttk.Frame(root, padding=8)
        bottom.pack(fill="x")
        ttk.Button(bottom, text="Block Selected IP", command=self.block_selected).pack(side="left", padx=4)
        ttk.Button(bottom, text="Unblock Selected IP", command=self.unblock_selected).pack(side="left", padx=4)
        ttk.Button(bottom, text="ARP MAC Lookup (LAN)", command=self.arp_selected).pack(side="left", padx=4)

        self.status = tk.StringVar(value="Server: stopped")
        ttk.Label(root, textvariable=self.status, padding=6).pack(anchor="w")

        # Poll event queue
        self.root.after(250, self.drain_events)

    # ----------------- Server control -----------------
    def _run_flask(self, port: int, use_https: bool):
        app = make_app(self.event_queue, self.deny_ips)
        try:
            if use_https:
                app.run(host="0.0.0.0", port=port, debug=False, ssl_context="adhoc")
            else:
                app.run(host="0.0.0.0", port=port, debug=False)
        except Exception as e:
            self.event_queue.put({"_error": f"Flask crashed: {e}"})
        finally:
            self.server_running = False
            self.event_queue.put({"_info": "Server stopped"})

    def start_server(self):
        if self.server_running:
            return
        try:
            port = int(self.port_var.get())
        except ValueError:
            messagebox.showerror("Invalid Port", "Port must be an integer.")
            return

        self.server_thread = threading.Thread(
            target=self._run_flask, args=(port, self.https_var.get()), daemon=True
        )
        self.server_thread.start()
        self.server_running = True
        self.btn_start.config(state="disabled")
        self.btn_stop.config(state="normal")
        scheme = "https" if self.https_var.get() else "http"
        self.status.set(f"Server: running on {scheme}://127.0.0.1:{port}")

    def stop_server(self):
        if not self.server_running:
            return
        scheme = "https" if self.https_var.get() else "http"
        port = int(self.port_var.get())
        try:
            # Ask Flask to shutdown itself
            import urllib.request
            req = urllib.request.Request(f"{scheme}://127.0.0.1:{port}/__shutdown", method="POST")
            # ignore SSL for adhoc in local
            if scheme == "https":
                import ssl as _ssl
                ctx = _ssl._create_unverified_context()
                urllib.request.urlopen(req, context=ctx, timeout=2)
            else:
                urllib.request.urlopen(req, timeout=2)
        except Exception:
            pass
        self.btn_start.config(state="normal")
        self.btn_stop.config(state="disabled")
        self.status.set("Server: stopping...")

    def open_browser(self):
        scheme = "https" if self.https_var.get() else "http"
        port = int(self.port_var.get())
        webbrowser.open(f"{scheme}://127.0.0.1:{port}/")

    # ----------------- UI actions -----------------
    def drain_events(self):
        try:
            while True:
                ev = self.event_queue.get_nowait()
                if "_error" in ev:
                    messagebox.showerror("Server Error", ev["_error"])
                elif "_info" in ev:
                    self.status.set(f"Server: {ev['_info']}")
                    self.btn_start.config(state="normal")
                    self.btn_stop.config(state="disabled")
                else:
                    ts = datetime.fromtimestamp(ev["ts"]).strftime("%Y-%m-%d %H:%M:%S")
                    row = (
                        ts,
                        ev["ip"],
                        (ev["path"] or "")[:200],
                        "FLAG" if ev["flagged"] else "OK",
                        ev["reason"] or "-",
                        ev["city"] or "-",
                        ev["country"] or "-",
                    )
                    self.tree.insert("", "end", values=row, tags=("flagged" if ev["flagged"] else "ok",))
        except queue.Empty:
            pass

        # tag styles
        self.tree.tag_configure("flagged", background="#ffe6e6")
        self.tree.tag_configure("ok", background="")

        self.root.after(250, self.drain_events)

    def get_selected_ip(self) -> Optional[str]:
        sel = self.tree.selection()
        if not sel:
            messagebox.showinfo("No selection", "Select a row first.")
            return None
        vals = self.tree.item(sel[0], "values")
        return vals[1] if vals and len(vals) > 1 else None

    def block_selected(self):
        ip = self.get_selected_ip()
        if not ip:
            return
        self.deny_ips.add(ip)
        messagebox.showinfo("Blocked", f"IP {ip} added to deny list (403).")

    def unblock_selected(self):
        ip = self.get_selected_ip()
        if not ip:
            return
        self.deny_ips.discard(ip)
        messagebox.showinfo("Unblocked", f"IP {ip} removed from deny list.")

    def export_csv(self):
        path = filedialog.asksaveasfilename(defaultextension=".csv", filetypes=[("CSV", "*.csv")])
        if not path:
            return
        # dump from DB to CSV
        try:
            conn = sqlite3.connect(DB_PATH)
            cur = conn.cursor()
            cur.execute(
                "SELECT ts, ip, path, ua, city, country, lat, lon, flagged, reason FROM events ORDER BY id DESC"
            )
            rows = cur.fetchall()
            conn.close()
            with open(path, "w", newline="", encoding="utf-8") as f:
                writer = csv.writer(f)
                writer.writerow(["time", "ip", "path", "ua", "city", "country", "lat", "lon", "flagged", "reason"])
                for r in rows:
                    r = list(r)
                    r[0] = datetime.fromtimestamp(r[0]).strftime("%Y-%m-%d %H:%M:%S")
                    writer.writerow(r)
            messagebox.showinfo("Exported", f"Saved {len(rows)} rows to {os.path.basename(path)}")
        except Exception as e:
            messagebox.showerror("Export failed", str(e))

    def arp_selected(self):
        ip = self.get_selected_ip()
        if not ip:
            return
        mac = self.arp_lookup(ip) or self.scapy_probe(ip)
        if mac:
            messagebox.showinfo("MAC Found", f"IP {ip}\nMAC {mac}")
        else:
            messagebox.showwarning(
                "Not found",
                "MAC not found. Works only on the same LAN, and may require admin rights."
            )

    # Cross-platform-ish ARP cache lookup
    def arp_lookup(self, ip: str) -> Optional[str]:
        try:
            if sys.platform.startswith("win"):
                out = subprocess.check_output(["arp", "-a"], text=True, stderr=subprocess.STDOUT)
                # 192.168.1.23        9c-xx-xx-xx-xx-2f     dynamic
                m = re.search(rf"\b{re.escape(ip)}\b[^\n\r]*?([0-9a-fA-F:\-]{{17}})", out)
                if m:
                    return m.group(1).replace("-", ":").lower()
            else:
                out = subprocess.check_output(["arp", "-n", ip], text=True, stderr=subprocess.STDOUT)
                m = re.search(r"((?:[0-9a-fA-F]{2}[:\-]){5}[0-9a-fA-F]{2})", out)
                if m:
                    return m.group(1).replace("-", ":").lower()
        except Exception:
            return None
        return None

    def scapy_probe(self, ip: str) -> Optional[str]:
        if not HAVE_SCAPY:
            return None
        try:
            pkt = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=ip)
            ans, _ = srp(pkt, timeout=1, verbose=False)
            for _, rcv in ans:
                return rcv[Ether].src.lower()
        except Exception:
            pass
        return None


def main():
    root = tk.Tk()
    app = GuardGUI(root)

    def on_close():
        try:
            app.stop_server()
        except Exception:
            pass
        root.destroy()

    root.protocol("WM_DELETE_WINDOW", on_close)
    root.mainloop()


if __name__ == "__main__":
    main()
