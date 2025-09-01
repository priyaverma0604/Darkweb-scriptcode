#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
DeepTrace – Dark Web Scanner (Merged & Polished)
- Tor proxy support (SOCKS5 on 127.0.0.1:9150 by default)
- Fetch .onion links from Ahmia
- Dynamic + default keywords (GUI checkboxes + add custom)
- Link list shown in GUI
- Start/Stop threaded scan with safe UI updates (queue)
- Optional "Leak Scan" mode
- Regex word-boundary matching (case-insensitive)
- SQLite history + History tab + CSV export + Reset
- Dark/Light theme toggle

Author: You :)
License: MIT (adjust as you wish)
"""

import os
import re
import csv
import time
import queue
import threading
import sqlite3
import requests
from datetime import datetime
from bs4 import BeautifulSoup

import tkinter as tk
from tkinter import ttk, filedialog, messagebox

# -----------------------------
# CONFIG
# -----------------------------
TOR_PROXIES = {
    "http": "socks5h://127.0.0.1:9150",
    "https": "socks5h://127.0.0.1:9150",
}

DEFAULT_KEYWORDS = [
    "drugs", "meth", "heroin", "cocaine", "weed", "marijuana", "mdma",
    "arms", "weapons", "guns", "firearms",
    "passport", "fake id", "fake passport",
    "btc", "bitcoin", "vendor", "escrow", "payment", "shipping"
]

LEAK_KEYWORDS = [
    "database", "dump", "credentials", "passwords", "emails", "credit card",
    "cc dump", "leaked", "breach", "compromised"
]

DB_FILE = "deeptrace_history.db"
ONIONS_FILE = "onions.txt"
FETCH_LIMIT = 200       # cap fetched onions per run (adjustable)
REQUEST_TIMEOUT = 25    # seconds per request
REQUEST_DELAY = 1.5     # polite delay between requests (seconds)

# -----------------------------
# DB helpers
# -----------------------------
def init_db():
    conn = sqlite3.connect(DB_FILE)
    cur = conn.cursor()
    cur.execute("""
        CREATE TABLE IF NOT EXISTS scans (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT,
            url TEXT,
            mode TEXT,              -- "scan" or "leak-scan"
            keyword TEXT,
            snippet TEXT,
            suspicious INTEGER
        )
    """)
    conn.commit()
    conn.close()

def save_to_db(ts, url, mode, keyword, snippet, suspicious):
    conn = sqlite3.connect(DB_FILE)
    cur = conn.cursor()
    cur.execute(
        "INSERT INTO scans (timestamp, url, mode, keyword, snippet, suspicious) VALUES (?, ?, ?, ?, ?, ?)",
        (ts, url, mode, keyword, snippet, 1 if suspicious else 0)
    )
    conn.commit()
    conn.close()

def load_recent_history(limit=200):
    conn = sqlite3.connect(DB_FILE)
    cur = conn.cursor()
    cur.execute("""
        SELECT timestamp, url, mode, keyword, snippet, suspicious
        FROM scans ORDER BY id DESC LIMIT ?
    """, (limit,))
    rows = cur.fetchall()
    conn.close()
    return rows

def wipe_history():
    conn = sqlite3.connect(DB_FILE)
    cur = conn.cursor()
    cur.execute("DELETE FROM scans")
    conn.commit()
    conn.close()

# -----------------------------
# Networking helpers
# -----------------------------
def create_session():
    s = requests.Session()
    s.headers.update({"User-Agent": "Mozilla/5.0 (DeepTrace)"})
    return s

def fetch_ahmia_links(limit=None, log_fn=None):
    """
    Scrape Ahmia for .onion URLs from /onions and any linked export lists.
    """
    url = "https://ahmia.fi/onions"
    session = create_session()
    links = set()
    try:
        resp = session.get(url, timeout=REQUEST_TIMEOUT)
        resp.raise_for_status()
        soup = BeautifulSoup(resp.text, "html.parser")

        # 1) Anchors with .onion
        for a in soup.find_all("a", href=True):
            href = a["href"]
            if href.endswith(".onion") or ".onion/" in href:
                links.add(href.strip())

        # 2) Any raw text .onion URLs
        text = soup.get_text("\n")
        links.update(re.findall(r"https?://[a-zA-Z0-9\-\.]+\.onion[^\s]*", text))

        # 3) Follow export files (txt/csv/json)
        for a in soup.find_all("a", href=True):
            href = a["href"]
            if any(href.lower().endswith(ext) for ext in (".txt", ".csv", ".json")) or "export" in href.lower():
                if not href.startswith("http"):
                    href = f"https://ahmia.fi{href}"
                try:
                    exp = session.get(href, timeout=REQUEST_TIMEOUT)
                    exp.raise_for_status()
                    links.update(re.findall(r"https?://[a-zA-Z0-9\-\.]+\.onion[^\s]*", exp.text))
                except Exception as e:
                    if log_fn:
                        log_fn(f"[WARN] Export fetch failed: {e}")

        # sanitize + sort
        clean = sorted(set(u.strip().rstrip("/)") for u in links if ".onion" in u))
        if limit:
            clean = clean[:limit]
        with open(ONIONS_FILE, "w", encoding="utf-8") as f:
            for u in clean:
                f.write(u + "\n")
        return clean

    except Exception as e:
        if log_fn:
            log_fn(f"[ERROR] Ahmia fetch failed: {e}")
        return []

# -----------------------------
# GUI App
# -----------------------------
class DeepTraceApp:
    def __init__(self, root):
        self.root = root
        self.root.title("DeepTrace – Dark Web Scanner (Merged)")
        self.root.geometry("1200x760")

        self.dark_mode = True
        self.stop_flag = threading.Event()
        self.msg_queue = queue.Queue()

        self.links = []
        self.keyword_vars = {}
        self.mode_var = tk.StringVar(value="scan")  # "scan" or "leak-scan"
        self.sus_count = 0
        self.benign_count = 0

        init_db()
        self.build_gui()
        self.apply_theme()

        # Queue polling for thread-safe UI updates
        self.root.after(100, self._drain_queue)

    # ------------- UI Build -------------
    def build_gui(self):
        # Top controls
        top = tk.Frame(self.root)
        top.pack(fill=tk.X, padx=10, pady=6)

        # Mode
        mode_frame = tk.LabelFrame(top, text="Mode")
        mode_frame.pack(side=tk.LEFT, padx=5)
        ttk.Radiobutton(mode_frame, text="Keyword Scan", variable=self.mode_var, value="scan", command=self._refresh_keyword_panel).pack(side=tk.LEFT, padx=6)
        ttk.Radiobutton(mode_frame, text="Leak Scan", variable=self.mode_var, value="leak-scan", command=self._refresh_keyword_panel).pack(side=tk.LEFT, padx=6)

        # Theme + Actions
        action_frame = tk.Frame(top)
        action_frame.pack(side=tk.RIGHT)
        ttk.Button(action_frame, text="Toggle Theme", command=self.toggle_theme).pack(side=tk.RIGHT, padx=5)
        ttk.Button(action_frame, text="Export CSV", command=self.export_csv).pack(side=tk.RIGHT, padx=5)
        ttk.Button(action_frame, text="Reset History", command=self.reset_history).pack(side=tk.RIGHT, padx=5)

        # Keywords Frame
        self.kw_group = tk.LabelFrame(self.root, text="Keywords")
        self.kw_group.pack(fill=tk.X, padx=10, pady=6)
        self.kw_scroll = tk.Canvas(self.kw_group, height=70, highlightthickness=0)
        self.kw_scroll.pack(side=tk.TOP, fill=tk.X, expand=True)
        self.kw_inner = tk.Frame(self.kw_scroll)
        self.kw_scroll.create_window((0, 0), window=self.kw_inner, anchor="nw")
        self.kw_inner.bind("<Configure>", lambda e: self.kw_scroll.configure(scrollregion=self.kw_scroll.bbox("all")))

        # Default keyword checkboxes (start with DEFAULT_KEYWORDS; leak mode uses LEAK_KEYWORDS)
        self._populate_keywords(DEFAULT_KEYWORDS)

        # Add custom keyword
        custom_frame = tk.Frame(self.kw_group)
        custom_frame.pack(fill=tk.X, pady=6)
        tk.Label(custom_frame, text="Add Custom Keyword:").pack(side=tk.LEFT)
        self.custom_kw_entry = tk.Entry(custom_frame, width=30)
        self.custom_kw_entry.pack(side=tk.LEFT, padx=6)
        ttk.Button(custom_frame, text="Add", command=self.add_custom_keyword).pack(side=tk.LEFT, padx=4)
        ttk.Button(custom_frame, text="Clear All", command=self.clear_all_keywords).pack(side=tk.LEFT, padx=4)
        ttk.Button(custom_frame, text="Select All", command=self.select_all_keywords).pack(side=tk.LEFT, padx=4)

        # Actions (fetch/scan)
        act = tk.Frame(self.root)
        act.pack(fill=tk.X, padx=10, pady=6)
        ttk.Button(act, text="Fetch .onion Links", command=self.fetch_links).pack(side=tk.LEFT, padx=5)
        ttk.Button(act, text="Start Scan", command=self.start_scan).pack(side=tk.LEFT, padx=5)
        ttk.Button(act, text="Stop Scan", command=self.stop_scan).pack(side=tk.LEFT, padx=5)

        # Counts + status
        status_bar = tk.Frame(self.root)
        status_bar.pack(fill=tk.X, padx=10, pady=2)
        self.status_label = tk.Label(status_bar, text="Ready")
        self.status_label.pack(side=tk.LEFT)
        self.count_label = tk.Label(status_bar, text="Suspicious: 0 | Benign: 0")
        self.count_label.pack(side=tk.RIGHT)

        # Tabs (Links / Console / History)
        self.tabs = ttk.Notebook(self.root)
        self.tabs.pack(fill=tk.BOTH, expand=True, padx=10, pady=8)

        # Links tab
        self.links_tab = tk.Frame(self.tabs)
        self.tabs.add(self.links_tab, text="Fetched Links")
        self.links_text = tk.Text(self.links_tab, wrap="word", height=10)
        self.links_text.pack(fill=tk.BOTH, expand=True)

        # Console tab
        self.console_tab = tk.Frame(self.tabs)
        self.tabs.add(self.console_tab, text="Scan Console")
        self.console = tk.Text(self.console_tab, wrap="word")
        self.console.pack(fill=tk.BOTH, expand=True)

        # History tab
        self.history_tab = tk.Frame(self.tabs)
        self.tabs.add(self.history_tab, text="History")
        self.history_tree = ttk.Treeview(
            self.history_tab,
            columns=("Timestamp", "Mode", "URL", "Keyword", "Snippet", "Suspicious"),
            show="headings",
            height=16
        )
        for col, width in [
            ("Timestamp", 140), ("Mode", 90), ("URL", 240),
            ("Keyword", 120), ("Snippet", 500), ("Suspicious", 90)
        ]:
            self.history_tree.heading(col, text=col)
            self.history_tree.column(col, width=width, stretch=True)
        self.history_tree.pack(fill=tk.BOTH, expand=True)

        self.reload_history()

    # ------------- Theme -------------
    def apply_theme(self):
        bg = "#0F1115" if self.dark_mode else "#FFFFFF"
        fg = "#E6EDF3" if self.dark_mode else "#111111"
        acc = "#39ff14" if self.dark_mode else "#0B5ED7"

        def style_widget(w):
            try:
                if isinstance(w, (tk.Text, tk.Entry, tk.LabelFrame, tk.Frame, tk.Label)):
                    w.configure(bg=bg, fg=fg)
                if isinstance(w, tk.Text):
                    w.configure(insertbackground=fg)
            except Exception:
                pass
            for child in getattr(w, "winfo_children", lambda: [])():
                style_widget(child)

        style_widget(self.root)
        # Accent for console text
        try:
            self.console.configure(fg=acc)
        except Exception:
            pass

    def toggle_theme(self):
        self.dark_mode = not self.dark_mode
        self.apply_theme()

    # ------------- Keywords -------------
    def _populate_keywords(self, keywords):
        # Clear existing
        for child in self.kw_inner.winfo_children():
            child.destroy()
        self.keyword_vars.clear()

        for kw in keywords:
            var = tk.BooleanVar(value=True)
            chk = tk.Checkbutton(self.kw_inner, text=kw, variable=var)
            chk.pack(side=tk.LEFT, padx=4, pady=2)
            self.keyword_vars[kw] = var

    def _refresh_keyword_panel(self):
        mode = self.mode_var.get()
        if mode == "scan":
            self._populate_keywords(DEFAULT_KEYWORDS)
        else:
            self._populate_keywords(LEAK_KEYWORDS)

    def add_custom_keyword(self):
        kw = self.custom_kw_entry.get().strip().lower()
        if not kw:
            messagebox.showwarning("Input Error", "Please enter a keyword.")
            return
        if kw in self.keyword_vars:
            messagebox.showinfo("Exists", f"Keyword '{kw}' already exists.")
            return
        var = tk.BooleanVar(value=True)
        chk = tk.Checkbutton(self.kw_inner, text=kw, variable=var)
        chk.pack(side=tk.LEFT, padx=4, pady=2)
        self.keyword_vars[kw] = var
        self.custom_kw_entry.delete(0, tk.END)

    def clear_all_keywords(self):
        for var in self.keyword_vars.values():
            var.set(False)

    def select_all_keywords(self):
        for var in self.keyword_vars.values():
            var.set(True)

    def selected_keywords(self):
        return [kw for kw, v in self.keyword_vars.items() if v.get()]

    # ------------- Logging (thread-safe) -------------
    def log(self, msg):
        self.msg_queue.put(("log", msg))

    def set_status(self, msg):
        self.msg_queue.put(("status", msg))

    def set_counts(self, sus, benign):
        self.msg_queue.put(("counts", (sus, benign)))

    def append_link_list(self, links):
        self.msg_queue.put(("links", links))

    def add_history_rows(self, rows):  # (ts, url, mode, keyword, snippet, suspicious)
        self.msg_queue.put(("history_rows", rows))

    def clear_links_view(self):
        self.msg_queue.put(("clear_links", None))

    def _drain_queue(self):
        try:
            while True:
                kind, payload = self.msg_queue.get_nowait()
                if kind == "log":
                    self.console.insert(tk.END, payload + "\n")
                    self.console.see(tk.END)
                elif kind == "status":
                    self.status_label.config(text=payload)
                elif kind == "counts":
                    s, b = payload
                    self.count_label.config(text=f"Suspicious: {s} | Benign: {b}")
                elif kind == "links":
                    self.links_text.delete(1.0, tk.END)
                    for u in payload:
                        self.links_text.insert(tk.END, u + "\n")
                elif kind == "clear_links":
                    self.links_text.delete(1.0, tk.END)
                elif kind == "history_rows":
                    # reload fully for simplicity
                    self.reload_history()
                self.msg_queue.task_done()
        except queue.Empty:
            pass
        self.root.after(100, self._drain_queue)

    # ------------- Actions -------------
    def fetch_links(self):
        self.set_status("Fetching links...")
        self.log("[INFO] Fetching .onion links from Ahmia…")
        self.clear_links_view()

        def worker():
            links = fetch_ahmia_links(limit=FETCH_LIMIT, log_fn=self.log)
            if links:
                self.links = links
                self.append_link_list(links)
                self.set_status(f"Fetched {len(links)} links and saved to {ONIONS_FILE}")
                self.log(f"[INFO] {len(links)} links saved to {ONIONS_FILE}")
            else:
                self.links = []
                self.set_status("No links found (or fetch failed).")
                self.log("[WARN] No links found.")

        threading.Thread(target=worker, daemon=True).start()

    def start_scan(self):
        # Load links if not in memory yet
        if not self.links:
            if os.path.exists(ONIONS_FILE):
                with open(ONIONS_FILE, "r", encoding="utf-8") as f:
                    self.links = [ln.strip() for ln in f if ln.strip()]
                self.append_link_list(self.links)
            else:
                messagebox.showwarning("No Links", "No links to scan. Fetch links first.")
                return

        kws = self.selected_keywords()
        mode = self.mode_var.get()
        if mode == "scan" and not kws:
            messagebox.showwarning("No Keywords", "Please select or add at least one keyword.")
            return

        self.sus_count = 0
        self.benign_count = 0
        self.set_counts(self.sus_count, self.benign_count)
        self.set_status("Scanning…")
        self.stop_flag.clear()

        self.log(f"[INFO] Starting {'Leak ' if mode=='leak-scan' else ''}Scan on {len(self.links)} links.")
        threading.Thread(target=self._scan_worker, args=(kws, mode), daemon=True).start()

    def stop_scan(self):
        if messagebox.askyesno("Stop Scan", "Are you sure you want to stop the scan?"):
            self.stop_flag.set()
            self.set_status("Stopping…")

    def _scan_worker(self, keywords, mode):
        session = create_session()

        # Build regex pattern ONCE (word boundaries, case-insensitive)
        pattern = None
        if mode == "scan" and keywords:
            escaped = [re.escape(k) for k in keywords]
            pattern = re.compile(r"\b(" + "|".join(escaped) + r")\b", re.IGNORECASE)

        for idx, url in enumerate(self.links, start=1):
            if self.stop_flag.is_set():
                self.log("[INFO] Scan stopped by user.")
                break

            self.log(f"[SCAN] ({idx}/{len(self.links)}) {url}")
            try:
                resp = session.get(url, proxies=TOR_PROXIES, timeout=REQUEST_TIMEOUT)
                content = resp.text

                hit_kw = None
                if mode == "scan":
                    if pattern:
                        m = pattern.search(content)
                        if m:
                            hit_kw = m.group(1)
                else:  # leak-scan mode
                    for lk in LEAK_KEYWORDS:
                        if re.search(r"\b" + re.escape(lk) + r"\b", content, flags=re.IGNORECASE):
                            hit_kw = lk
                            break

                snippet = re.sub(r"\s+", " ", content[:500])  # compact
                ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

                if hit_kw:
                    self.log(f"[SUSPICIOUS] '{hit_kw}' found in {url}")
                    save_to_db(ts, url, mode, hit_kw, snippet, True)
                    self.sus_count += 1
                else:
                    self.log(f"[OK] No suspicious content in {url}")
                    save_to_db(ts, url, mode, "", snippet, False)
                    self.benign_count += 1

                self.set_counts(self.sus_count, self.benign_count)
                self.add_history_rows([(ts, url, mode, hit_kw or "", snippet, bool(hit_kw))])

            except Exception as e:
                self.log(f"[ERROR] Could not access {url}: {e}")

            time.sleep(REQUEST_DELAY)

        self.set_status("Scan complete.")

    # ------------- History / Export -------------
    def reload_history(self):
        for row in self.history_tree.get_children():
            self.history_tree.delete(row)
        for ts, url, mode, kw, snip, sus in load_recent_history(limit=500):
            self.history_tree.insert("", tk.END, values=(
                ts, mode, url, kw, (snip[:200] + "…") if len(snip) > 200 else snip, "Yes" if sus else "No"
            ))

    def export_csv(self):
        conn = sqlite3.connect(DB_FILE)
        cur = conn.cursor()
        cur.execute("SELECT id, timestamp, url, mode, keyword, snippet, suspicious FROM scans ORDER BY id DESC")
        rows = cur.fetchall()
        conn.close()

        file_path = filedialog.asksaveasfilename(
            defaultextension=".csv",
            filetypes=[("CSV files", "*.csv")],
            initialfile="deeptrace_export.csv"
        )
        if not file_path:
            return

        with open(file_path, "w", encoding="utf-8", newline="") as f:
            w = csv.writer(f)
            w.writerow(["ID", "Timestamp", "URL", "Mode", "Keyword", "Snippet", "Suspicious"])
            for r in rows:
                w.writerow(r)

        messagebox.showinfo("Export Complete", f"Data exported to {file_path}")

    def reset_history(self):
        if messagebox.askyesno("Confirm", "Are you sure you want to delete all scan history?"):
            wipe_history()
            self.reload_history()
            messagebox.showinfo("History Cleared", "All scan history has been deleted.")


# -----------------------------
# Entry point
# -----------------------------
def main():
    root = tk.Tk()
    app = DeepTraceApp(root)
    root.mainloop()

if __name__ == "__main__":
    main()
