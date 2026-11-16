"""
HybridPatcher GUI.

A tkinter window with drag-and-drop input, mode selector ("Detect only" /
"Detect + Fix"), output folder selection, and a live log panel. Runs the
detector / patcher off the Tk thread so the UI stays responsive.

Drag-and-drop uses tkinterdnd2; if it is missing we fall back to
file-picker buttons only (drag still hint-shown but inert).

Run with:
    python -m hybrid_patcher --gui
"""

from __future__ import annotations
import os
import queue
import threading
import traceback
from collections import Counter
from typing import List, Optional

import tkinter as tk
from tkinter import filedialog, ttk, messagebox

try:
    from tkinterdnd2 import TkinterDnD, DND_FILES
    _HAS_DND = True
except Exception:
    _HAS_DND = False
    TkinterDnD = None
    DND_FILES = None

from .rules import RULES, Finding
from .pipeline import fix_apks, fix_tree, process_apk, scan_tree, write_reports
from .stats import (
    load_bulk_stats, BulkStats,
    headline_kpis, status_breakdown, rule_breakdown, top_cwes,
    STATUS_COLORS, SEVERITY_COLORS, FIX_COLORS, RULE_IDS, RULE_COLORS,
    FINDINGS_HIST_ORDER,
    cwe_info,
)

# PIL-rendered charts (anti-aliased, supersampled). The functions below
# return PIL Images that we wrap in ImageTk.PhotoImage and place on a
# Canvas via `create_image`. If Pillow isn't available we fall back to the
# pure-Tk drawing helpers further down (_draw_pie / _draw_hbar / _draw_vbar).
try:
    from . import charts as _charts
    from PIL import ImageTk as _ImageTk
    _HAS_CHARTS = True
except Exception:
    _HAS_CHARTS = False
    _charts = None
    _ImageTk = None


# Color tags applied to the per-APK Treeview rows by status.
_STATUS_COLORS = {
    "patched":          "#1e8a3a",   # green: fixes applied, patched APK built and signed
    "report-only":      "#b88500",   # amber: findings, but none with an automatic APK fix
    "no-findings":      "#888888",   # grey: no rule matched
    "build-failed":     "#b88500",   # amber: fixes applied but the APK could not be rebuilt
    "running":          "#1e6ec4",   # blue: in-progress
    "skip":             "#888888",
    "fail":             "#c8311a",   # red
    "crash":            "#c8311a",   # red
    "queued":           "#444444",
}


def _classify(path: str) -> str:
    if os.path.isfile(path) and path.lower().endswith(".apk"):
        return "apk"
    if os.path.isdir(path):
        return "src"
    return "unknown"


# ---------------------------------------------------------------------------
# Worker logic (no Tk calls -- communicates via a queue)
# ---------------------------------------------------------------------------

def _run_job(inputs: List[str], mode: str, out_dir: str,
             log_q: "queue.Queue[str]"):
    """mode = 'detect' | 'fix'. Pushes log lines into log_q.
       Last item pushed is None to signal completion."""
    def log(msg: str):
        log_q.put(msg)

    try:
        all_findings: List[Finding] = []
        os.makedirs(out_dir, exist_ok=True)

        for path in inputs:
            kind = _classify(path)
            log(f"\n=== {path} ({kind}) ===")
            if kind == "src":
                # Source code pipeline: apply the rules, then (fix mode) fix a copy of the tree
                fs = scan_tree(path)
                all_findings.extend(fs)
                log(f"  detected {len(fs)} finding(s)")
                for f in fs:
                    log(f"    {RULES[f.rule].label}  {os.path.relpath(f.file, path)}:{f.line}  {f.excerpt}")
                if mode == "fix":
                    dst = fix_tree(path, out_dir, fs)
                    log(f"  applied {sum(f.fixed for f in fs)} fix(es) in the copy {dst}")
            elif kind == "apk":
                # APK pipeline: decode, apply the rules, then (fix mode) fix, rebuild and sign
                res = process_apk(path, out_dir, fix=(mode == "fix"), on_log=log)
                all_findings.extend(res.findings)
                if res.status == "fail":
                    log(f"  could not analyse the APK: {res.detail}")
                elif res.output_apk:
                    log(f"  -> {res.output_apk}  ({res.detail})")
                elif mode == "fix" and res.status == "report-only":
                    log("  -> report only (these findings have no automatic fix for APKs)")
                elif mode == "fix" and res.status == "build-failed":
                    log("  -> the fixed APK could not be rebuilt; see the report")
            else:
                log("  skipping (not an APK file or directory)")

        # Always write a report
        report_path, json_path = write_reports(all_findings, out_dir)
        log(f"\nreport: {report_path}")
        log(f"json  : {json_path}")
        log(f"\nTOTAL findings: {len(all_findings)}"
            f"  (fixed: {sum(f.fixed for f in all_findings)})")
    except Exception:
        log("\n!! exception in worker:\n" + traceback.format_exc())
    finally:
        log_q.put(None)


# ---------------------------------------------------------------------------
# Bulk APK fix worker (per-APK pipeline; emits events into a queue)
# ---------------------------------------------------------------------------

def _run_bulk_job(apk_paths: List[str], out_dir: str,
                  resume: bool, keep_work_dir: bool,
                  event_q: "queue.Queue", stop_flag: "threading.Event"):
    """Drive the same pipeline the CLI's `--fix-apks` uses and forward
    events into the GUI queue. Last item pushed is None to signal done."""
    try:
        os.makedirs(out_dir, exist_ok=True)

        def on_event(kind, payload):
            event_q.put((kind, payload))

        def stop_check():
            return stop_flag.is_set()

        rc = fix_apks(apk_paths, out_dir,
                      keep_work_dir=keep_work_dir,
                      resume=resume,
                      on_event=on_event,
                      stop_check=stop_check)
        event_q.put(("rc", rc))
    except Exception:
        event_q.put(("log", "!! exception in bulk worker:\n" + traceback.format_exc()))
    finally:
        event_q.put(None)


# ---------------------------------------------------------------------------
# UI
# ---------------------------------------------------------------------------

class HybridPatcherGUI:

    def __init__(self):
        if _HAS_DND:
            self.root = TkinterDnD.Tk()
        else:
            self.root = tk.Tk()
        self.root.title("HybridPatcher")
        self.root.geometry("900x640")
        self.root.minsize(780, 520)

        self.inputs: List[str] = []
        self.mode_var = tk.StringVar(value="detect")
        self.out_dir_var = tk.StringVar(value=os.path.abspath("./hybrid_patcher_out"))
        self.log_q: "queue.Queue[Optional[str]]" = queue.Queue()
        self.worker: Optional[threading.Thread] = None

        self._build_ui()
        self._tick_log()

    # -------------- UI construction --------------

    def _build_ui(self):
        root = self.root

        # Top: instructions
        top = ttk.Frame(root, padding=(10, 8, 10, 4))
        top.pack(fill=tk.X)
        ttk.Label(top,
            text="Drag APK files or source-code folders into the list below "
                 "(or use the buttons). Pick a mode and Start.",
            font=("Segoe UI", 9)).pack(anchor="w")

        # Middle: input list
        mid = ttk.LabelFrame(root, text="Inputs", padding=(8, 4))
        mid.pack(fill=tk.BOTH, expand=True, padx=10, pady=(4, 4))

        self.listbox = tk.Listbox(mid, height=8, activestyle="dotbox",
                                  selectmode=tk.EXTENDED)
        self.listbox.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        sb = ttk.Scrollbar(mid, orient=tk.VERTICAL, command=self.listbox.yview)
        sb.pack(side=tk.LEFT, fill=tk.Y)
        self.listbox.config(yscrollcommand=sb.set)

        if _HAS_DND:
            self.listbox.drop_target_register(DND_FILES)
            self.listbox.dnd_bind("<<Drop>>", self._on_drop)
        else:
            self.listbox.insert(tk.END, "(install tkinterdnd2 for drag-drop; use buttons below)")

        btns = ttk.Frame(mid)
        btns.pack(side=tk.LEFT, fill=tk.Y, padx=(8, 0))
        ttk.Button(btns, text="Add APK(s)...",   command=self._pick_apks).pack(fill=tk.X, pady=2)
        ttk.Button(btns, text="Add folder...",   command=self._pick_folder).pack(fill=tk.X, pady=2)
        ttk.Button(btns, text="Remove selected", command=self._remove_selected).pack(fill=tk.X, pady=2)
        ttk.Button(btns, text="Clear",           command=self._clear_inputs).pack(fill=tk.X, pady=2)

        # Mode + output
        opts = ttk.LabelFrame(root, text="Mode & output", padding=(8, 4))
        opts.pack(fill=tk.X, padx=10, pady=(4, 4))

        mode_frame = ttk.Frame(opts)
        mode_frame.pack(anchor="w")
        ttk.Radiobutton(mode_frame, text="Detect only (write report.md + report.json)",
                        variable=self.mode_var, value="detect").pack(anchor="w")
        ttk.Radiobutton(mode_frame, text="Detect + Fix (write report + patched APK / patched source)",
                        variable=self.mode_var, value="fix").pack(anchor="w")

        out_row = ttk.Frame(opts)
        out_row.pack(fill=tk.X, pady=(4, 0))
        ttk.Label(out_row, text="Output folder:").pack(side=tk.LEFT)
        ttk.Entry(out_row, textvariable=self.out_dir_var).pack(side=tk.LEFT,
                  fill=tk.X, expand=True, padx=4)
        ttk.Button(out_row, text="Browse...",
                   command=self._pick_output_dir).pack(side=tk.LEFT)

        # Action row
        act = ttk.Frame(root, padding=(10, 4))
        act.pack(fill=tk.X)
        self.start_btn = ttk.Button(act, text="Start", command=self._start)
        self.start_btn.pack(side=tk.LEFT)
        ttk.Button(act, text="Open output folder",
                   command=self._open_output).pack(side=tk.LEFT, padx=8)
        ttk.Button(act, text="Bulk APK fix...",
                   command=self._open_bulk_window).pack(side=tk.LEFT, padx=8)
        ttk.Button(act, text="Statistics...",
                   command=self._open_stats_window).pack(side=tk.LEFT, padx=8)
        self.status_var = tk.StringVar(value="idle")
        ttk.Label(act, textvariable=self.status_var,
                  foreground="#444").pack(side=tk.LEFT, padx=12)

        # Log
        log_frame = ttk.LabelFrame(root, text="Log", padding=(8, 4))
        log_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=(4, 10))
        self.log = tk.Text(log_frame, wrap="none", height=14,
                           font=("Consolas", 9), background="#1e1e1e",
                           foreground="#dcdcdc", insertbackground="#dcdcdc")
        self.log.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        ysb = ttk.Scrollbar(log_frame, orient=tk.VERTICAL,
                            command=self.log.yview)
        ysb.pack(side=tk.LEFT, fill=tk.Y)
        self.log.config(yscrollcommand=ysb.set)

    # -------------- event handlers --------------

    def _on_drop(self, event):
        # tkinterdnd2 returns a string with paths separated by spaces; paths
        # containing spaces are wrapped in {curly braces}.
        raw = event.data
        paths: List[str] = []
        cur = ""
        in_brace = False
        for ch in raw:
            if ch == "{":
                in_brace = True
            elif ch == "}":
                in_brace = False
                paths.append(cur); cur = ""
            elif ch == " " and not in_brace:
                if cur:
                    paths.append(cur); cur = ""
            else:
                cur += ch
        if cur:
            paths.append(cur)
        for p in paths:
            self._add_input(p)

    def _pick_apks(self):
        paths = filedialog.askopenfilenames(
            title="Select APK(s)",
            filetypes=[("APK files", "*.apk"), ("All files", "*.*")])
        for p in paths:
            self._add_input(p)

    def _pick_folder(self):
        p = filedialog.askdirectory(title="Select source folder")
        if p:
            self._add_input(p)

    def _pick_output_dir(self):
        p = filedialog.askdirectory(title="Select output folder")
        if p:
            self.out_dir_var.set(p)

    def _add_input(self, path: str):
        path = os.path.abspath(path)
        kind = _classify(path)
        if kind == "unknown":
            messagebox.showwarning("HybridPatcher",
                f"Skipping (not an APK file or folder):\n{path}")
            return
        if path in self.inputs:
            return
        self.inputs.append(path)
        tag = "[APK]" if kind == "apk" else "[SRC]"
        # If we had the placeholder "(install tkinterdnd2 ...)" message, clear it
        if self.listbox.size() == 1 and not _HAS_DND:
            cur = self.listbox.get(0)
            if cur.startswith("(install"):
                self.listbox.delete(0)
        self.listbox.insert(tk.END, f"{tag}  {path}")

    def _remove_selected(self):
        sel = list(self.listbox.curselection())
        for i in reversed(sel):
            try:
                self.inputs.pop(i)
            except IndexError:
                continue
            self.listbox.delete(i)

    def _clear_inputs(self):
        self.inputs.clear()
        self.listbox.delete(0, tk.END)

    def _open_output(self):
        out = self.out_dir_var.get()
        if not out:
            return
        os.makedirs(out, exist_ok=True)
        try:
            os.startfile(out)   # Windows
        except AttributeError:
            import subprocess
            subprocess.Popen(["xdg-open", out])

    def _open_bulk_window(self):
        BulkApkFixWindow(self.root)

    def _open_stats_window(self):
        # Default to the bulk output dir if one exists.
        default = "./hybrid_patcher_out_bulk"
        StatsWindow(self.root, out_dir=os.path.abspath(default)
                    if os.path.isdir(default) else None)

    def _start(self):
        if not self.inputs:
            messagebox.showwarning("HybridPatcher", "No inputs queued.")
            return
        if self.worker and self.worker.is_alive():
            messagebox.showinfo("HybridPatcher", "A job is already running.")
            return
        out_dir = self.out_dir_var.get().strip()
        if not out_dir:
            messagebox.showwarning("HybridPatcher", "Pick an output folder first.")
            return
        os.makedirs(out_dir, exist_ok=True)
        self.log.delete("1.0", tk.END)
        self.status_var.set("running...")
        self.start_btn.configure(state=tk.DISABLED)
        mode = self.mode_var.get()
        inputs = list(self.inputs)
        self.worker = threading.Thread(target=_run_job,
                                       args=(inputs, mode, out_dir, self.log_q),
                                       daemon=True)
        self.worker.start()

    def _tick_log(self):
        try:
            while True:
                msg = self.log_q.get_nowait()
                if msg is None:
                    self.status_var.set("done")
                    self.start_btn.configure(state=tk.NORMAL)
                    continue
                self.log.insert(tk.END, msg + "\n")
                self.log.see(tk.END)
        except queue.Empty:
            pass
        self.root.after(80, self._tick_log)

    def run(self):
        self.root.mainloop()


# ---------------------------------------------------------------------------
# BulkApkFixWindow -- per-APK Treeview that updates live as the bulk
# pipeline streams `start` / `done` events.
# ---------------------------------------------------------------------------

class BulkApkFixWindow:

    def __init__(self, parent: tk.Misc):
        self.top = tk.Toplevel(parent)
        self.top.title("HybridPatcher  --  Bulk APK fix")
        self.top.geometry("1180x720")
        self.top.minsize(900, 560)

        self.apk_paths: List[str] = []
        self.row_iid_by_name: dict = {}     # base name -> tree iid
        self.out_dir_var = tk.StringVar(
            value=os.path.abspath("./hybrid_patcher_out_bulk"))
        self.resume_var = tk.BooleanVar(value=True)
        self.keep_work_var = tk.BooleanVar(value=False)
        self.event_q: "queue.Queue" = queue.Queue()
        self.worker: Optional[threading.Thread] = None
        self.stop_flag = threading.Event()
        self.t_start: float = 0.0
        self.n_done = 0
        self.n_total = 0

        self._build_ui()
        self._tick()

    # -------- UI --------
    def _build_ui(self):
        root = self.top
        # Top: input picker
        top = ttk.LabelFrame(root, text="Inputs", padding=(8, 4))
        top.pack(fill=tk.X, padx=10, pady=(8, 4))
        row1 = ttk.Frame(top); row1.pack(fill=tk.X)
        ttk.Button(row1, text="Add APK folder...",
                   command=self._add_folder).pack(side=tk.LEFT)
        ttk.Button(row1, text="Add APK file(s)...",
                   command=self._add_files).pack(side=tk.LEFT, padx=(6, 0))
        ttk.Button(row1, text="Clear",
                   command=self._clear).pack(side=tk.LEFT, padx=(6, 0))
        self.count_var = tk.StringVar(value="0 APK(s) queued")
        ttk.Label(row1, textvariable=self.count_var,
                  foreground="#444").pack(side=tk.LEFT, padx=12)

        # Output / options
        opt = ttk.LabelFrame(root, text="Output & options", padding=(8, 4))
        opt.pack(fill=tk.X, padx=10, pady=4)
        out_row = ttk.Frame(opt); out_row.pack(fill=tk.X)
        ttk.Label(out_row, text="Output folder:").pack(side=tk.LEFT)
        ttk.Entry(out_row, textvariable=self.out_dir_var).pack(
            side=tk.LEFT, fill=tk.X, expand=True, padx=4)
        ttk.Button(out_row, text="Browse...",
                   command=self._pick_out_dir).pack(side=tk.LEFT)
        flag_row = ttk.Frame(opt); flag_row.pack(fill=tk.X, pady=(4, 0))
        ttk.Checkbutton(flag_row, text="Resume (skip APKs already in output)",
                        variable=self.resume_var).pack(side=tk.LEFT)
        ttk.Checkbutton(flag_row, text="Keep apktool work dir (debug)",
                        variable=self.keep_work_var).pack(side=tk.LEFT, padx=12)

        # Action row
        act = ttk.Frame(root, padding=(10, 4)); act.pack(fill=tk.X)
        self.start_btn = ttk.Button(act, text="Start", command=self._start)
        self.start_btn.pack(side=tk.LEFT)
        self.stop_btn = ttk.Button(act, text="Stop after current",
                                    command=self._stop, state=tk.DISABLED)
        self.stop_btn.pack(side=tk.LEFT, padx=8)
        ttk.Button(act, text="Open output folder",
                   command=self._open_out).pack(side=tk.LEFT, padx=8)
        ttk.Button(act, text="Statistics...",
                   command=self._open_stats).pack(side=tk.LEFT, padx=8)
        self.status_var = tk.StringVar(value="idle")
        ttk.Label(act, textvariable=self.status_var,
                  foreground="#444").pack(side=tk.LEFT, padx=12)
        self.progress = ttk.Progressbar(act, mode="determinate", length=240)
        self.progress.pack(side=tk.RIGHT)

        # Per-APK Treeview
        mid = ttk.LabelFrame(root, text="Per-APK status", padding=(4, 4))
        mid.pack(fill=tk.BOTH, expand=True, padx=10, pady=4)
        cols = ("idx", "name", "status", "detail", "findings", "elapsed")
        self.tree = ttk.Treeview(mid, columns=cols, show="headings", height=18)
        widths = {"idx": 60, "name": 320, "status": 140, "detail": 360,
                  "findings": 80, "elapsed": 80}
        for c in cols:
            self.tree.heading(c, text=c)
            self.tree.column(c, width=widths[c],
                             anchor="w" if c in ("name", "detail") else "center")
        ysb = ttk.Scrollbar(mid, orient=tk.VERTICAL, command=self.tree.yview)
        self.tree.configure(yscrollcommand=ysb.set)
        self.tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        ysb.pack(side=tk.LEFT, fill=tk.Y)
        self.tree.bind("<Double-1>", self._open_apk_dir)
        for status, color in _STATUS_COLORS.items():
            self.tree.tag_configure(f"st_{status}", foreground=color)

        # Log pane
        log_frame = ttk.LabelFrame(root, text="Log", padding=(4, 4))
        log_frame.pack(fill=tk.BOTH, expand=False, padx=10, pady=(4, 8))
        self.log = tk.Text(log_frame, wrap="none", height=8,
                           font=("Consolas", 9), background="#1e1e1e",
                           foreground="#dcdcdc", insertbackground="#dcdcdc")
        self.log.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        lsb = ttk.Scrollbar(log_frame, orient=tk.VERTICAL,
                             command=self.log.yview)
        lsb.pack(side=tk.LEFT, fill=tk.Y)
        self.log.config(yscrollcommand=lsb.set)

    # -------- input handlers --------
    def _add_folder(self):
        d = filedialog.askdirectory(title="Select folder of APKs")
        if not d:
            return
        added = 0
        for n in sorted(os.listdir(d)):
            if n.lower().endswith(".apk"):
                p = os.path.join(d, n)
                if p not in self.apk_paths:
                    self.apk_paths.append(p); added += 1
        self._refresh_count()
        self._log(f"added {added} APK(s) from {d}\n")

    def _add_files(self):
        files = filedialog.askopenfilenames(
            title="Select APK file(s)",
            filetypes=[("APK files", "*.apk"), ("All files", "*.*")])
        for p in files:
            if p not in self.apk_paths:
                self.apk_paths.append(p)
        self._refresh_count()

    def _clear(self):
        self.apk_paths.clear()
        self._refresh_count()

    def _refresh_count(self):
        self.count_var.set(f"{len(self.apk_paths)} APK(s) queued")

    def _pick_out_dir(self):
        d = filedialog.askdirectory(title="Output folder")
        if d:
            self.out_dir_var.set(d)

    def _open_out(self):
        d = self.out_dir_var.get()
        if not d:
            return
        os.makedirs(d, exist_ok=True)
        try:
            os.startfile(d)
        except AttributeError:
            import subprocess
            subprocess.Popen(["xdg-open", d])

    def _open_apk_dir(self, _ev):
        sel = self.tree.selection()
        if not sel:
            return
        name = self.tree.item(sel[0], "values")[1]
        path = os.path.join(self.out_dir_var.get(), name)
        if os.path.isdir(path):
            try:
                os.startfile(path)
            except AttributeError:
                import subprocess
                subprocess.Popen(["xdg-open", path])

    def _open_stats(self):
        d = self.out_dir_var.get().strip()
        if d and os.path.isdir(d):
            StatsWindow(self.top, out_dir=d)
        else:
            StatsWindow(self.top, out_dir=None)

    # -------- start / stop --------
    def _start(self):
        if self.worker and self.worker.is_alive():
            messagebox.showinfo("HybridPatcher", "A bulk job is already running.")
            return
        if not self.apk_paths:
            messagebox.showwarning("HybridPatcher", "No APKs queued.")
            return
        out_dir = self.out_dir_var.get().strip()
        if not out_dir:
            messagebox.showwarning("HybridPatcher", "Pick an output folder first.")
            return

        self.stop_flag.clear()
        self.tree.delete(*self.tree.get_children())
        self.row_iid_by_name.clear()
        self.log.delete("1.0", tk.END)
        self.n_total = len(self.apk_paths)
        self.n_done = 0
        self.t_start = __import__("time").time()
        self.progress.configure(maximum=self.n_total, value=0)

        # Pre-populate the tree with one row per queued APK in order so the
        # user can scroll through and see exactly what's queued.
        for i, apk in enumerate(self.apk_paths, 1):
            base = os.path.splitext(os.path.basename(apk))[0]
            iid = self.tree.insert("", tk.END,
                                   values=(i, base, "queued", "", "", ""),
                                   tags=("st_queued",))
            self.row_iid_by_name[base] = iid

        self.status_var.set(f"running... 0/{self.n_total}")
        self.start_btn.configure(state=tk.DISABLED)
        self.stop_btn.configure(state=tk.NORMAL)

        self.worker = threading.Thread(
            target=_run_bulk_job,
            args=(list(self.apk_paths), out_dir,
                  bool(self.resume_var.get()),
                  bool(self.keep_work_var.get()),
                  self.event_q, self.stop_flag),
            daemon=True)
        self.worker.start()

    def _stop(self):
        if self.worker and self.worker.is_alive():
            self.stop_flag.set()
            self.status_var.set("stop requested -- finishing current APK")
            self.stop_btn.configure(state=tk.DISABLED)

    # -------- log + tree update tick --------
    def _log(self, line: str):
        self.log.insert(tk.END, line if line.endswith("\n") else line + "\n")
        self.log.see(tk.END)

    def _tick(self):
        try:
            while True:
                ev = self.event_q.get_nowait()
                if ev is None:
                    self.status_var.set(f"done  ({self.n_done}/{self.n_total})")
                    self.start_btn.configure(state=tk.NORMAL)
                    self.stop_btn.configure(state=tk.DISABLED)
                    continue
                kind, payload = ev[0], (ev[1] if len(ev) > 1 else None)
                if kind == "start":
                    name = payload["name"]
                    iid = self.row_iid_by_name.get(name)
                    if iid is not None:
                        self.tree.item(iid, values=(payload["i"], name,
                                                    "running", "...", "", ""),
                                       tags=("st_running",))
                        self.tree.see(iid)
                elif kind == "done":
                    name = payload["name"]
                    iid = self.row_iid_by_name.get(name)
                    fnd = "" if payload["findings"] < 0 else payload["findings"]
                    el = f"{payload['elapsed_s']:.1f}s" if not payload["resumed"] else "resumed"
                    if iid is not None:
                        self.tree.item(iid, values=(payload["i"], name,
                                                    payload["status"],
                                                    payload["detail"],
                                                    fnd, el),
                                       tags=(f"st_{payload['status']}",))
                    self.n_done += 1
                    self.progress.configure(value=self.n_done)
                    elapsed = __import__("time").time() - self.t_start
                    avg = elapsed / max(1, self.n_done)
                    eta = avg * (self.n_total - self.n_done)
                    self.status_var.set(
                        f"running... {self.n_done}/{self.n_total}  "
                        f"avg {avg:.1f}s/apk  ETA {eta/60:.1f} min")
                elif kind == "log":
                    self._log(payload)
                elif kind == "summary":
                    counts = payload.get("counts", {})
                    self._log("=" * 72)
                    self._log("summary:")
                    for s, c in sorted(counts.items()):
                        self._log(f"  {s:18}{c}")
                elif kind == "rc":
                    self._log(f"[exit code {payload}]")
        except queue.Empty:
            pass
        self.top.after(100, self._tick)


# ---------------------------------------------------------------------------
# Chart helpers (pure-Tk Canvas; no matplotlib dependency)
# ---------------------------------------------------------------------------

def _draw_pie(canvas: tk.Canvas, slices: List[tuple],
              cx: int, cy: int, r: int,
              title: Optional[str] = None) -> None:
    """slices = [(label, count, color), ...]. Draws a pie + a legend column
    to the right of the circle. Empty `slices` is a no-op."""
    total = sum(s[1] for s in slices) or 1
    start = 90.0   # 12 o'clock
    for label, count, color in slices:
        if count <= 0:
            continue
        extent = -360.0 * count / total       # negative = clockwise
        canvas.create_arc(cx - r, cy - r, cx + r, cy + r,
                          start=start, extent=extent,
                          fill=color, outline="white", width=1)
        start += extent
    if title:
        canvas.create_text(cx, cy - r - 16, text=title,
                           font=("Segoe UI", 10, "bold"))
    # Legend: right of pie, one row per non-zero slice
    lx = cx + r + 24
    ly = cy - r
    for label, count, color in slices:
        if count <= 0:
            continue
        pct = 100.0 * count / total
        canvas.create_rectangle(lx, ly, lx + 14, ly + 14, fill=color, outline="")
        canvas.create_text(lx + 22, ly + 7, anchor="w",
                           text=f"{label}    {count}  ({pct:.1f}%)",
                           font=("Segoe UI", 9))
        ly += 22


def _draw_hbar(canvas: tk.Canvas, rows: List[tuple],
               x: int, y: int, w: int,
               row_height: int = 20, max_val: Optional[int] = None,
               title: Optional[str] = None,
               label_w: int = 80) -> int:
    """Horizontal bar chart. rows = [(label, value, color), ...].
    Returns the y-coordinate of the next free row."""
    if title:
        canvas.create_text(x, y, anchor="w", text=title,
                           font=("Segoe UI", 10, "bold"))
        y += 22
    if not rows:
        canvas.create_text(x, y, anchor="w", text="(no data)",
                           font=("Segoe UI", 9), fill="#888")
        return y + 20
    if max_val is None:
        max_val = max(v for _, v, _ in rows) or 1
    bar_x0 = x + label_w + 8
    bar_w_max = max(40, w - label_w - 60)
    for label, value, color in rows:
        canvas.create_text(x, y + row_height // 2, anchor="w",
                           text=label, font=("Segoe UI", 9))
        bar_w = int(bar_w_max * value / max_val) if max_val else 0
        canvas.create_rectangle(bar_x0, y + 2,
                                bar_x0 + bar_w, y + row_height - 2,
                                fill=color, outline="")
        canvas.create_text(bar_x0 + bar_w + 6, y + row_height // 2,
                           anchor="w", text=str(value),
                           font=("Segoe UI", 9), fill="#333")
        y += row_height
    return y


def _draw_vbar(canvas: tk.Canvas, rows: List[tuple],
               x: int, y: int, w: int, h: int,
               title: Optional[str] = None) -> None:
    """Vertical bar chart for histograms. rows = [(label, value, color), ...].
    The bottom margin reserves 56px so X-axis labels (drawn 12px below the
    plot floor) are never clipped by the canvas edge."""
    if title:
        canvas.create_text(x + w // 2, y, text=title,
                           font=("Segoe UI", 10, "bold"))
        y += 24
    plot_top = y + 4
    plot_bot = y + h - 56          # was 28 (caused label clipping)
    plot_left = x + 36
    plot_right = x + w - 8
    plot_w = plot_right - plot_left
    plot_h = plot_bot - plot_top
    max_v = max((v for _, v, _ in rows), default=0) or 1

    # Y-axis tick + horizontal grid line at every quartile
    for q in (0.0, 0.25, 0.5, 0.75, 1.0):
        ty = plot_bot - q * plot_h
        canvas.create_line(plot_left, ty, plot_right, ty,
                           fill="#e8e8e8")
        canvas.create_text(plot_left - 6, ty, anchor="e",
                           text=str(int(q * max_v)),
                           font=("Segoe UI", 8), fill="#666")

    if not rows:
        canvas.create_text(x + w // 2, y + h // 2, text="(no data)",
                           font=("Segoe UI", 9), fill="#888")
        return

    n = len(rows)
    cell_w = plot_w / n
    bar_w = max(8, int(cell_w * 0.7))
    for i, (label, value, color) in enumerate(rows):
        cx = plot_left + cell_w * i + cell_w / 2
        bar_h = int(plot_h * value / max_v) if max_v else 0
        canvas.create_rectangle(cx - bar_w // 2, plot_bot - bar_h,
                                cx + bar_w // 2, plot_bot,
                                fill=color, outline="")
        canvas.create_text(cx, plot_bot - bar_h - 8, text=str(value),
                           font=("Segoe UI", 8), fill="#333")
        canvas.create_text(cx, plot_bot + 12, text=label,
                           font=("Segoe UI", 8), fill="#444")


def _save_treeview_csv(tv: ttk.Treeview, default_filename: str) -> None:
    """Ask for a path and write the entire Treeview to a CSV file.
    Header row is the column ids; each row is whatever was set via
    `values=` for that iid."""
    path = filedialog.asksaveasfilename(
        defaultextension=".csv",
        initialfile=default_filename,
        filetypes=[("CSV", "*.csv"), ("TSV", "*.tsv"), ("All", "*.*")])
    if not path:
        return
    import csv
    cols = tv["columns"]
    sep = "\t" if path.lower().endswith(".tsv") else ","
    try:
        with open(path, "w", newline="", encoding="utf-8") as fh:
            writer = csv.writer(fh, delimiter=sep)
            writer.writerow(cols)
            for iid in tv.get_children():
                writer.writerow(tv.item(iid, "values"))
        messagebox.showinfo("HybridPatcher", f"Saved table to:\n{path}")
    except Exception as e:
        messagebox.showerror("HybridPatcher", f"Could not save table:\n{e}")


def _scrollable(parent: tk.Misc) -> tuple:
    """Return (frame_for_widgets, canvas) -- the inner frame is what you
    pack widgets into, the canvas owns the scrollbar."""
    outer = ttk.Frame(parent)
    outer.pack(fill=tk.BOTH, expand=True)
    canvas = tk.Canvas(outer, highlightthickness=0)
    vsb = ttk.Scrollbar(outer, orient="vertical", command=canvas.yview)
    canvas.configure(yscrollcommand=vsb.set)
    canvas.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
    vsb.pack(side=tk.RIGHT, fill=tk.Y)
    inner = ttk.Frame(canvas)
    inner_win = canvas.create_window((0, 0), window=inner, anchor="nw")

    def _on_inner_config(_e):
        canvas.configure(scrollregion=canvas.bbox("all"))
    inner.bind("<Configure>", _on_inner_config)

    def _on_canvas_config(e):
        canvas.itemconfigure(inner_win, width=e.width)
    canvas.bind("<Configure>", _on_canvas_config)

    # Mouse-wheel scrolling -- bind on enter/leave so other widgets keep
    # scrolling locally.
    def _wheel(e):
        canvas.yview_scroll(int(-1 * (e.delta / 120)), "units")
    canvas.bind("<Enter>", lambda _e: canvas.bind_all("<MouseWheel>", _wheel))
    canvas.bind("<Leave>", lambda _e: canvas.unbind_all("<MouseWheel>"))
    return inner, canvas


# ---------------------------------------------------------------------------
# PILChartFrame -- displays one PIL-rendered chart on a Canvas, re-renders
# on resize, falls back to Tk-Canvas drawing if Pillow is missing.
# ---------------------------------------------------------------------------

class PILChartFrame:
    """Renders a single chart in a `tk.Canvas`. The caller passes a
    `render(width, height)` callback that returns a PIL.Image, plus an
    optional `fallback(canvas, width, height)` for the no-Pillow path.

    A small idle-debounce (~80 ms) avoids re-rendering at every pixel of
    a window-drag.

    The wrapper is a Frame containing the canvas and a small toolbar with
    a 'Save image...' button so any chart can be exported to a PNG file
    at the current display size."""

    def __init__(self, parent, height: int,
                 render, fallback=None,
                 background: str = "#fafafa",
                 default_filename: str = "chart.png"):
        self.frame = ttk.Frame(parent)
        self._default_filename = default_filename

        # Toolbar with the Save button on the right side.
        bar = ttk.Frame(self.frame)
        bar.pack(side=tk.TOP, fill=tk.X)
        ttk.Button(bar, text="Save image...",
                   command=self._on_save).pack(side=tk.RIGHT)

        self.canvas = tk.Canvas(self.frame, background=background,
                                height=height, highlightthickness=0)
        self.canvas.pack(side=tk.TOP, fill=tk.BOTH, expand=True)

        self._render = render
        self._fallback = fallback
        self._photo = None        # keep a reference so GC doesn't free it
        self._last_image = None   # last PIL.Image rendered (for export)
        self._pending_after = None
        self._last_size = (0, 0)
        self.canvas.bind("<Configure>", self._on_resize)
        self.canvas.after(50, self._redraw)

    def pack(self, **kw):
        self.frame.pack(**kw)

    # Nominal HD width for exported PNG/JPEG. The chart functions render
    # at SCALE=2 internally, so the actual raster is 4800 px wide before
    # being downsampled to 2400 -- effectively 4x supersampling. The
    # display canvas keeps its smaller size, only the export is HD.
    HD_EXPORT_WIDTH = 2400

    def _on_save(self):
        """Ask for an image path, then re-render the chart at HD nominal
        width (2400 px) with the current display aspect ratio."""
        if not _HAS_CHARTS:
            messagebox.showinfo("HybridPatcher",
                                "Pillow is not installed -- "
                                "cannot save chart as image.")
            return
        path = filedialog.asksaveasfilename(
            defaultextension=".png",
            initialfile=self._default_filename,
            filetypes=[("PNG image", "*.png"),
                       ("JPEG image", "*.jpg"),
                       ("All", "*.*")])
        if not path:
            return
        try:
            disp_w = max(self.canvas.winfo_width() or 900, 1)
            disp_h = max(self.canvas.winfo_height() or 360, 1)
            target_w = self.HD_EXPORT_WIDTH
            target_h = max(int(round(target_w * disp_h / disp_w)), 200)
            img = self._render(target_w, target_h)
            # PNG: keep alpha; JPEG: flatten onto white before saving.
            if path.lower().endswith((".jpg", ".jpeg")):
                from PIL import Image
                bg = Image.new("RGB", img.size, (255, 255, 255))
                bg.paste(img, mask=img.split()[-1] if img.mode == "RGBA"
                                                  else None)
                bg.save(path, quality=95)
            else:
                img.save(path)
            messagebox.showinfo(
                "HybridPatcher",
                f"Saved chart at {target_w}x{target_h} px to:\n{path}")
        except Exception as e:
            messagebox.showerror("HybridPatcher",
                                 f"Could not save chart:\n{e}")

    def _on_resize(self, _ev=None):
        if self._pending_after is not None:
            try:
                self.canvas.after_cancel(self._pending_after)
            except Exception:
                pass
        self._pending_after = self.canvas.after(80, self._redraw)

    def _redraw(self):
        self._pending_after = None
        w = self.canvas.winfo_width()
        h = self.canvas.winfo_height()
        if w < 30 or h < 30:
            self.canvas.after(80, self._redraw)
            return
        if (w, h) == self._last_size and self._photo is not None:
            return
        self._last_size = (w, h)
        self.canvas.delete("all")
        if _HAS_CHARTS:
            try:
                img = self._render(w, h)
                if img is not None:
                    self._photo = _ImageTk.PhotoImage(img)
                    self.canvas.create_image(0, 0, image=self._photo,
                                             anchor="nw")
                    return
            except Exception:
                # Fall through to the Tk-Canvas fallback so the GUI never
                # becomes blank if PIL has a bad-day.
                pass
        if self._fallback is not None:
            try:
                self._fallback(self.canvas, w, h)
            except Exception:
                pass


# ---------------------------------------------------------------------------
# StatsWindow -- tabbed analytics view over a bulk output directory.
# ---------------------------------------------------------------------------

class StatsWindow:

    def __init__(self, parent: tk.Misc, out_dir: Optional[str] = None):
        self.top = tk.Toplevel(parent)
        self.top.title("HybridPatcher  --  Bulk run statistics")
        self.top.geometry("1280x820")
        self.top.minsize(960, 600)

        self.out_dir_var = tk.StringVar(
            value=os.path.abspath(out_dir or "./hybrid_patcher_out_bulk"))
        self.bs: Optional[BulkStats] = None
        self.sort_state: dict = {}     # treeview iid -> (col, reverse)

        self._build_ui()
        if out_dir and os.path.isdir(out_dir):
            self.top.after(50, self._reload)

    # -------- UI scaffolding --------
    def _build_ui(self):
        root = self.top

        # Top: dir picker
        top = ttk.Frame(root, padding=(10, 8, 10, 4))
        top.pack(fill=tk.X)
        ttk.Label(top, text="Bulk output dir:").pack(side=tk.LEFT)
        ttk.Entry(top, textvariable=self.out_dir_var,
                  font=("Segoe UI", 9)).pack(
            side=tk.LEFT, fill=tk.X, expand=True, padx=4)
        ttk.Button(top, text="Browse...",
                   command=self._pick_dir).pack(side=tk.LEFT)
        ttk.Button(top, text="Reload",
                   command=self._reload).pack(side=tk.LEFT, padx=4)
        ttk.Button(top, text="Save .md report...",
                   command=self._save_report).pack(side=tk.LEFT, padx=4)
        self.status_var = tk.StringVar(value="(no data loaded)")
        ttk.Label(root, textvariable=self.status_var,
                  foreground="#444").pack(fill=tk.X, padx=10)

        # Tabs
        nb = ttk.Notebook(root)
        nb.pack(fill=tk.BOTH, expand=True, padx=10, pady=(4, 10))
        self.tab_overview = ttk.Frame(nb)
        self.tab_patterns = ttk.Frame(nb)
        self.tab_cwes     = ttk.Frame(nb)
        self.tab_timing   = ttk.Frame(nb)
        self.tab_hist     = ttk.Frame(nb)
        self.tab_table    = ttk.Frame(nb)
        nb.add(self.tab_overview, text="Overview")
        nb.add(self.tab_patterns, text="Rules")
        nb.add(self.tab_cwes,     text="CWEs")
        nb.add(self.tab_timing,   text="Elapsed time")
        nb.add(self.tab_hist,     text="Findings histogram")
        nb.add(self.tab_table,    text="Per-APK table")

    def _pick_dir(self):
        d = filedialog.askdirectory(title="Pick a bulk output dir")
        if d:
            self.out_dir_var.set(d)
            self._reload()

    # -------- (re)load --------
    def _reload(self):
        d = self.out_dir_var.get().strip()
        if not d:
            return
        if not os.path.isdir(d):
            messagebox.showwarning("HybridPatcher", f"Not a directory:\n{d}")
            return
        self.status_var.set(f"loading {d} ...")
        self.top.update_idletasks()
        try:
            def _prog(i, n, _name):
                self.status_var.set(f"loading {i}/{n} ...")
                self.top.update_idletasks()
            self.bs = load_bulk_stats(d, on_progress=_prog)
        except Exception:
            messagebox.showerror("HybridPatcher",
                                 "Failed to load bulk stats:\n" +
                                 traceback.format_exc())
            return
        bs = self.bs
        self.status_var.set(f"loaded {bs.n_apks} APK(s) from {bs.out_dir}")
        self._render_overview()
        self._render_patterns()
        self._render_cwes()
        self._render_timing()
        self._render_hist()
        self._render_table()

    # -------- tab: Overview --------
    def _render_overview(self):
        for w in self.tab_overview.winfo_children():
            w.destroy()
        bs = self.bs
        if not bs:
            return
        # Left: KPI grid. Right: pipeline outcome donut chart.
        left = ttk.LabelFrame(self.tab_overview, text="Headline KPIs",
                              padding=(8, 6))
        left.pack(side=tk.LEFT, fill=tk.Y, padx=(8, 4), pady=8)
        for r, (k, v) in enumerate(headline_kpis(bs)):
            ttk.Label(left, text=k + ":", font=("Segoe UI", 9),
                      foreground="#444").grid(row=r, column=0,
                                              sticky="w", padx=(0, 12))
            ttk.Label(left, text=v, font=("Segoe UI", 10, "bold")).grid(
                row=r, column=1, sticky="w")

        right = ttk.LabelFrame(self.tab_overview, text="Pipeline outcome",
                               padding=(4, 4))
        right.pack(side=tk.LEFT, fill=tk.BOTH, expand=True,
                   padx=(4, 8), pady=8)

        slices = [(s, c, STATUS_COLORS.get(s, "#888"))
                  for s, c in status_breakdown(bs)]

        def _render_pil(w, h):
            return _charts.draw_pie(
                w, h, slices,
                title=f"{bs.n_apks} APKs by pipeline outcome",
                donut=False)

        def _fallback(canvas, w, h):
            canvas.delete("all")
            r = max(80, min(h, w) // 3)
            cx = max(r + 30, w // 3)
            cy = h // 2
            _draw_pie(canvas, slices, cx, cy, r,
                      title=f"{bs.n_apks} APKs by pipeline outcome")

        chart = PILChartFrame(right, height=280,
                              render=_render_pil, fallback=_fallback,
                              default_filename="pipeline_outcome.png")
        chart.pack(fill=tk.BOTH, expand=True)

    # -------- tab: Rules --------
    def _render_patterns(self):
        for w in self.tab_patterns.winfo_children():
            w.destroy()
        bs = self.bs
        if not bs:
            return
        inner, _ = _scrollable(self.tab_patterns)

        # Findings per rule (all 7 rules), colored by severity
        rows = [(RULES[rid].label, c, RULE_COLORS[rid])
                for rid, c in rule_breakdown(bs)]
        # 28 px per row, 50 px header (title + padding), 14 px bottom pad.
        chart_h = 50 + max(len(rows), 1) * 28 + 14

        def _render_top(w, h):
            return _charts.draw_hbar(
                w, h, rows,
                title=f"Findings per rule across "
                      f"{bs.n_apks} APKs (color = severity)",
                label_w=72)

        def _fallback_top(canvas, w, h):
            canvas.delete("all")
            _draw_hbar(canvas, rows, x=12, y=10, w=w - 24,
                       title=f"Findings per rule across "
                             f"{bs.n_apks} APKs (color = severity)",
                       label_w=70)

        ChartTop = PILChartFrame(inner, height=chart_h,
                                 render=_render_top, fallback=_fallback_top,
                                 default_filename="findings_per_rule.png")
        ChartTop.pack(fill=tk.X, padx=10, pady=(8, 6))

        # Rule legend (one line per rule)
        legend = ttk.Frame(inner)
        legend.pack(fill=tk.X, padx=14, pady=(0, 6))
        for rid in RULE_IDS:
            line = ttk.Frame(legend); line.pack(fill=tk.X)
            sw = tk.Canvas(line, width=14, height=14,
                           highlightthickness=0, bg="#fafafa")
            sw.create_rectangle(0, 0, 14, 14,
                                fill=RULE_COLORS[rid], outline="")
            sw.pack(side=tk.LEFT, padx=(0, 4))
            ttk.Label(line, text=f"{RULES[rid].label}: {RULES[rid].title}"
                                 f"  ({RULES[rid].severity})",
                      font=("Segoe UI", 9)).pack(side=tk.LEFT, padx=(0, 12))

        # Fix status + severity charts side by side
        twin = ttk.Frame(inner); twin.pack(fill=tk.X, padx=10, pady=(8, 4))

        prov_rows = [("Fixed", bs.n_fixed_total, FIX_COLORS["fixed"]),
                     ("Not fixed", bs.n_findings_total - bs.n_fixed_total,
                      FIX_COLORS["not fixed"])]
        sev_rows = [(s.capitalize(), bs.severity_counts.get(s, 0),
                     SEVERITY_COLORS[s])
                    for s in ("high", "medium", "low")]

        def _r_prov(w, h):
            return _charts.draw_hbar(w, h, prov_rows,
                                     title="Findings by fix status",
                                     label_w=100)

        def _f_prov(canvas, w, h):
            canvas.delete("all")
            _draw_hbar(canvas, prov_rows, x=12, y=10, w=w - 24,
                       title="Findings by fix status", label_w=90)

        def _r_sev(w, h):
            return _charts.draw_hbar(w, h, sev_rows,
                                     title="Findings by severity",
                                     label_w=90)

        def _f_sev(canvas, w, h):
            canvas.delete("all")
            _draw_hbar(canvas, sev_rows, x=12, y=10, w=w - 24,
                       title="Findings by severity", label_w=80)

        prov_h = 50 + len(prov_rows) * 28 + 14
        sev_h  = 50 + len(sev_rows)  * 28 + 14
        ChartProv = PILChartFrame(twin, height=prov_h,
                                  render=_r_prov, fallback=_f_prov,
                                  default_filename="findings_by_fix_status.png")
        ChartProv.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=(0, 4))
        ChartSev = PILChartFrame(twin, height=sev_h,
                                 render=_r_sev, fallback=_f_sev,
                                 default_filename="findings_by_severity.png")
        ChartSev.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=(4, 0))

        # Coverage note: where the numbers come from.
        note = (
            f"Findings come from each APK's report.json "
            f"({bs.n_apks - bs.n_without_report}/{bs.n_apks} APKs have one). "
            f"'Fixed' counts the findings whose fix is part of the patched "
            f"APK. Rule 2 and Rule 5 are reported only for APKs; they are "
            f"fixed in source code."
        )
        ttk.Label(inner, text=note, foreground="#666",
                  font=("Segoe UI", 9), wraplength=900,
                  justify=tk.LEFT).pack(anchor="w", padx=14, pady=(8, 12))

    # -------- tab: CWEs --------
    def _render_cwes(self):
        for w in self.tab_cwes.winfo_children():
            w.destroy()
        bs = self.bs
        if not bs:
            return

        # Use the scrollable wrapper so the descriptions table can grow
        # below the bar chart without truncating either one.
        inner, _ = _scrollable(self.tab_cwes)

        rows = top_cwes(bs, 15)
        bar_rows = [(cwe, c, "#7e3acb") for cwe, c in rows]
        bar_h = 50 + max(len(rows), 1) * 28 + 14

        def _r(w, h):
            return _charts.draw_hbar(w, h, bar_rows,
                                     title=f"Top {len(rows)} CWE IDs "
                                           f"by occurrence",
                                     label_w=120)

        def _f(canvas, w, h):
            canvas.delete("all")
            _draw_hbar(canvas, bar_rows, x=20, y=20, w=w - 40,
                       title=f"Top {len(rows)} CWE IDs by occurrence",
                       label_w=110)

        ChartTop = PILChartFrame(inner, height=bar_h,
                                 render=_r, fallback=_f,
                                 default_filename="top_cwes.png")
        ChartTop.pack(fill=tk.X, padx=10, pady=(8, 4))

        # Descriptions panel: one card per CWE with name, MITRE summary,
        # and the HybridPatcher rule that surfaces it.
        intro = ttk.Label(
            inner, padding=(10, 6),
            text=("CWE stands for MITRE Common Weakness Enumeration. It is a "
                  "stable, language-agnostic catalog of bug types. Each finding's "
                  "CWE tag links its detector to a well-known weakness so you "
                  "can prioritise (e.g. CWE Top-25 first) and cross-reference "
                  "with Google Play's pre-launch reports."),
            wraplength=1100, foreground="#444", font=("Segoe UI", 9))
        intro.pack(fill=tk.X, padx=10, pady=(4, 8))

        for cwe_id, count in rows:
            info = cwe_info(cwe_id)
            card = ttk.LabelFrame(
                inner,
                text=f"  {info.cwe}    {info.name}    ({count} occurrence(s))  ",
                padding=(8, 6))
            card.pack(fill=tk.X, padx=10, pady=4)
            ttk.Label(card, text="Summary",
                      font=("Segoe UI", 8, "bold"),
                      foreground="#666").pack(anchor="w")
            ttk.Label(card, text=info.summary or "(no summary available)",
                      wraplength=1080, justify="left",
                      font=("Segoe UI", 9)).pack(anchor="w", pady=(0, 4))
            if info.trigger:
                ttk.Label(card, text="Why HybridPatcher flags it",
                          font=("Segoe UI", 8, "bold"),
                          foreground="#666").pack(anchor="w")
                ttk.Label(card, text=info.trigger,
                          wraplength=1080, justify="left",
                          font=("Segoe UI", 9)).pack(anchor="w")

    # -------- tab: Elapsed time --------
    def _render_timing(self):
        for w in self.tab_timing.winfo_children():
            w.destroy()
        bs = self.bs
        if not bs:
            return

        # Wrap the whole tab in a scrollable container so the chart can have
        # a fixed minimum height that is large enough to fit all status
        # labels along its X axis.
        inner, _ = _scrollable(self.tab_timing)

        # Top: per-status table (ttk.Treeview)
        tbl_frame = ttk.LabelFrame(
            inner, text="Per-status elapsed time", padding=(4, 4))
        tbl_frame.pack(fill=tk.X, padx=10, pady=(8, 4))

        bar = ttk.Frame(tbl_frame); bar.pack(fill=tk.X, pady=(0, 2))
        ttk.Button(bar, text="Save CSV...",
                   command=lambda: _save_treeview_csv(
                       tv, "per_status_elapsed.csv")).pack(side=tk.RIGHT)

        cols = ("status", "n", "min", "median", "p90", "max", "mean", "total")
        tv = ttk.Treeview(tbl_frame, columns=cols, show="headings", height=8)
        for c in cols:
            tv.heading(c, text=c)
            tv.column(c, width=110, anchor="center")
        tv.column("status", width=170, anchor="w")
        tv.pack(fill=tk.X)

        def _fmt(v): return f"{v:.1f}"
        for s, st in sorted(bs.elapsed_by_status.items()):
            tv.insert("", tk.END, values=(s, int(st["n"]),
                                          _fmt(st["min"]),
                                          _fmt(st["median"]),
                                          _fmt(st["p90"]),
                                          _fmt(st["max"]),
                                          _fmt(st["mean"]),
                                          _fmt(st["total"])))

        # Bottom: bar chart of mean elapsed by status, with a fixed minimum
        # height so the X-axis labels always fit (the previous "fill the tab"
        # sizing cropped them when the window was short).
        # Mean elapsed per status
        mean_rows_data = sorted(bs.elapsed_by_status.items(),
                                key=lambda kv: -kv[1]["mean"])

        def _r_mean(w, h):
            rows = [(s, st["mean"], STATUS_COLORS.get(s, "#888"))
                    for s, st in mean_rows_data]
            return _charts.draw_vbar(
                w, h, rows,
                title="Mean elapsed time per status (seconds)",
                y_label="seconds")

        def _f_mean(canvas, w, h):
            canvas.delete("all")
            rows = [(s, st["mean"], STATUS_COLORS.get(s, "#888"))
                    for s, st in mean_rows_data]
            vrows = [(s, int(round(v)), c) for s, v, c in rows]
            _draw_vbar(canvas, vrows, x=10, y=10, w=w - 20, h=h - 20,
                       title="Mean elapsed time per status (seconds)")

        ChartMean = PILChartFrame(inner, height=380,
                                  render=_r_mean, fallback=_f_mean,
                                  default_filename="mean_elapsed_per_status.png")
        ChartMean.pack(fill=tk.X, padx=10, pady=(8, 10))

        # Total wall-clock per status (sort by total desc)
        total_rows_data = sorted(bs.elapsed_by_status.items(),
                                 key=lambda kv: -kv[1]["total"])

        def _r_total(w, h):
            rows = [(s, st["total"], STATUS_COLORS.get(s, "#888"))
                    for s, st in total_rows_data]
            return _charts.draw_vbar(
                w, h, rows,
                title="Total wall-clock per status (seconds)",
                y_label="seconds")

        def _f_total(canvas, w, h):
            canvas.delete("all")
            rows = [(s, st["total"], STATUS_COLORS.get(s, "#888"))
                    for s, st in total_rows_data]
            vrows = [(s, int(round(v)), c) for s, v, c in rows]
            _draw_vbar(canvas, vrows, x=10, y=10, w=w - 20, h=h - 20,
                       title="Total wall-clock per status (seconds)")

        ChartTotal = PILChartFrame(inner, height=380,
                                   render=_r_total, fallback=_f_total,
                                   default_filename="total_elapsed_per_status.png")
        ChartTotal.pack(fill=tk.X, padx=10, pady=(0, 10))

    # -------- tab: Findings histogram --------
    def _render_hist(self):
        for w in self.tab_hist.winfo_children():
            w.destroy()
        bs = self.bs
        if not bs:
            return
        rows = [(b, bs.findings_hist.get(b, 0), "#3a7bcb")
                for b in FINDINGS_HIST_ORDER]

        def _r(w, h):
            return _charts.draw_vbar(
                w, h, rows,
                title="Findings per APK (bucketed)",
                y_label="number of APKs")

        def _f(canvas, w, h):
            canvas.delete("all")
            _draw_vbar(canvas, rows, x=20, y=20, w=w - 40, h=h - 40,
                       title="Findings per APK (bucketed)")

        chart = PILChartFrame(self.tab_hist, height=360,
                              render=_r, fallback=_f,
                              default_filename="findings_histogram.png")
        chart.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

    # -------- tab: Per-APK table --------
    def _render_table(self):
        for w in self.tab_table.winfo_children():
            w.destroy()
        bs = self.bs
        if not bs:
            return
        # Filter row + Save CSV button
        filt_row = ttk.Frame(self.tab_table); filt_row.pack(fill=tk.X,
                                                            padx=10, pady=(8, 4))
        ttk.Label(filt_row, text="Filter:").pack(side=tk.LEFT)
        filt_var = tk.StringVar(value="")
        ent = ttk.Entry(filt_row, textvariable=filt_var)
        ent.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=4)
        ttk.Label(filt_row, text="(matches name, status, detail)",
                  foreground="#666").pack(side=tk.LEFT, padx=(4, 0))
        ttk.Button(filt_row, text="Save CSV...",
                   command=lambda: _save_treeview_csv(
                       tv, "per_apk_table.csv")).pack(side=tk.RIGHT)

        # Treeview
        tbl_frame = ttk.Frame(self.tab_table)
        tbl_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=(0, 10))
        cols = ("name", "status", "detail", "findings", "fixed",
                "elapsed_s") + RULE_IDS
        tv = ttk.Treeview(tbl_frame, columns=cols, show="headings", height=22)
        widths = {"name": 240, "status": 120, "detail": 290,
                  "findings": 70, "fixed": 60, "elapsed_s": 80,
                  **{rid: 45 for rid in RULE_IDS}}
        for c in cols:
            tv.heading(c, text=c, command=lambda c=c: _sort_by(c))
            tv.column(c, width=widths[c],
                      anchor="w" if c in ("name", "detail") else "center")
        ysb = ttk.Scrollbar(tbl_frame, orient="vertical", command=tv.yview)
        tv.configure(yscrollcommand=ysb.set)
        tv.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        ysb.pack(side=tk.LEFT, fill=tk.Y)
        for s, color in STATUS_COLORS.items():
            tv.tag_configure(f"st_{s}", foreground=color)

        all_rows = []
        for r in bs.rows:
            # One column per rule: how many findings of that rule the APK has.
            per_rule = Counter(r.rule_ids)
            all_rows.append((
                r.name, r.status, r.detail,
                len(r.rule_ids), r.fixed, f"{r.elapsed_s:.1f}",
                *(per_rule.get(rid, 0) for rid in RULE_IDS),
                f"st_{r.status}"))

        def _populate(rows):
            for iid in tv.get_children():
                tv.delete(iid)
            for *vals, tag in rows:
                tv.insert("", tk.END, values=vals, tags=(tag,))

        # Sortable columns
        sort_state: dict = {}

        def _sort_by(col):
            idx = cols.index(col)
            cur = sort_state.get(col, False)
            sort_state.clear()
            sort_state[col] = not cur
            def _key(row):
                v = row[idx]
                # numeric columns
                if col in ("findings", "fixed") or col in RULE_IDS:
                    return v
                if col == "elapsed_s":
                    try:
                        return float(v)
                    except Exception:
                        return 0.0
                return str(v).lower()
            sorted_rows = sorted(all_rows, key=_key, reverse=(not cur))
            _populate(_apply_filter(sorted_rows, filt_var.get()))

        def _apply_filter(rows, q):
            q = q.strip().lower()
            if not q:
                return rows
            out = []
            for row in rows:
                if (q in str(row[0]).lower() or
                    q in str(row[1]).lower() or
                    q in str(row[2]).lower()):
                    out.append(row)
            return out

        def _on_filter_change(*_):
            _populate(_apply_filter(all_rows, filt_var.get()))
        filt_var.trace_add("write", _on_filter_change)

        # Double-click opens that APK's per-output folder
        def _open_dir(_ev):
            sel = tv.selection()
            if not sel:
                return
            name = tv.item(sel[0], "values")[0]
            path = os.path.join(bs.out_dir, name)
            if os.path.isdir(path):
                try:
                    os.startfile(path)
                except AttributeError:
                    import subprocess
                    subprocess.Popen(["xdg-open", path])
        tv.bind("<Double-1>", _open_dir)

        _populate(all_rows)

    # -------- save markdown report --------
    def _save_report(self):
        if not self.bs:
            messagebox.showinfo("HybridPatcher", "Load a bulk dir first.")
            return
        f = filedialog.asksaveasfilename(
            defaultextension=".md",
            filetypes=[("Markdown", "*.md"), ("All", "*.*")],
            initialfile="bulk_stats.md")
        if not f:
            return
        try:
            with open(f, "w", encoding="utf-8") as fh:
                fh.write(_render_markdown_report(self.bs))
            messagebox.showinfo("HybridPatcher", f"Wrote {f}")
        except OSError as e:
            messagebox.showerror("HybridPatcher", str(e))


def _render_markdown_report(bs: BulkStats) -> str:
    lines: List[str] = [
        "# Bulk run statistics",
        "",
        f"Source: `{bs.out_dir}`",
        "",
        "## Headline",
        "",
        "| Metric | Value |",
        "|---|---|",
    ]
    for k, v in headline_kpis(bs):
        lines.append(f"| {k} | {v} |")
    lines += ["", "## Pipeline outcome", "",
              "| Status | Count | Share |",
              "|---|---:|---:|"]
    n = bs.n_apks or 1
    for s, c in status_breakdown(bs):
        lines.append(f"| {s} | {c} | {c * 100.0 / n:.1f}% |")
    lines += ["", "## Findings per rule", "",
              "| Rule | Title | Severity | Count |",
              "|---|---|---|---:|"]
    for rid, c in rule_breakdown(bs):
        lines.append(f"| {RULES[rid].label} | {RULES[rid].title} | "
                     f"{RULES[rid].severity} | {c} |")
    lines += ["", "## Findings by severity", "",
              "| Severity | Count |",
              "|---|---:|"]
    for sev in ("high", "medium", "low"):
        lines.append(f"| {sev} | {bs.severity_counts.get(sev, 0)} |")
    lines += ["", "## Findings by fix status", "",
              "| Status | Count |",
              "|---|---:|",
              f"| fixed | {bs.n_fixed_total} |",
              f"| not fixed | {bs.n_findings_total - bs.n_fixed_total} |"]
    lines += ["", "## Top CWEs", "",
              "| CWE | Count |",
              "|---|---:|"]
    for cwe, c in top_cwes(bs, 15):
        lines.append(f"| {cwe} | {c} |")
    lines += ["", "## Per-status elapsed time (seconds)", "",
              "| Status | n | min | median | p90 | max | mean | total |",
              "|---|---:|---:|---:|---:|---:|---:|---:|"]
    for s, st in sorted(bs.elapsed_by_status.items()):
        lines.append(f"| {s} | {int(st['n'])} | {st['min']:.1f} | "
                     f"{st['median']:.1f} | {st['p90']:.1f} | {st['max']:.1f} "
                     f"| {st['mean']:.1f} | {st['total']:.1f} |")
    lines += ["", "## Findings-per-APK histogram", "",
              "| Bucket | APKs |",
              "|---|---:|"]
    for b in FINDINGS_HIST_ORDER:
        lines.append(f"| {b} | {bs.findings_hist.get(b, 0)} |")
    return "\n".join(lines) + "\n"


def open_stats_preloaded(out_dir: str):
    """Open the StatsWindow as a standalone GUI session against `out_dir`."""
    if _HAS_DND:
        root = TkinterDnD.Tk()
    else:
        root = tk.Tk()
    root.withdraw()
    win = StatsWindow(root, out_dir=out_dir)
    win.top.protocol("WM_DELETE_WINDOW",
                     lambda: (win.top.destroy(), root.destroy()))
    root.mainloop()


def open_bulk_preloaded(apk_dir: str, out_dir: Optional[str] = None):
    """Launch the GUI's BulkApkFixWindow pre-populated with every *.apk in
    `apk_dir`. Used by the `--gui-bulk` CLI shortcut so the user doesn't
    have to navigate via the file picker for the 1000-APK run."""
    if _HAS_DND:
        root = TkinterDnD.Tk()
    else:
        root = tk.Tk()
    root.withdraw()                     # hide the (unused) main window
    win = BulkApkFixWindow(root)
    if out_dir:
        win.out_dir_var.set(os.path.abspath(out_dir))
    if os.path.isdir(apk_dir):
        added = 0
        for n in sorted(os.listdir(apk_dir)):
            if n.lower().endswith(".apk"):
                win.apk_paths.append(os.path.join(apk_dir, n))
                added += 1
        win._refresh_count()
        win._log(f"preloaded {added} APK(s) from {os.path.abspath(apk_dir)}\n")
    # When the bulk window is closed, close the hidden root too.
    win.top.protocol("WM_DELETE_WINDOW",
                     lambda: (win.top.destroy(), root.destroy()))
    root.mainloop()


def main():
    HybridPatcherGUI().run()


if __name__ == "__main__":
    main()
