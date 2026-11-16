"""
Statistics for a bulk output folder (written by `--fix-apks` or the Bulk APK fix window).

Inputs:
  <out_dir>/per_apk_status.tsv      one row per APK (name, status, detail, findings, elapsed_s)
  <out_dir>/<apk_name>/report.json  the findings of that APK

Output: a single `BulkStats` object that holds everything the statistics window and the
markdown report need. Nothing is aggregated while the APKs are processed, so any existing
output folder can be inspected later without re-running the pipeline.
"""
from __future__ import annotations
import json
import os
import statistics
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from typing import Dict, List, Tuple

from .rules import RULES

# One entry per outcome of the APK pipeline (kept here so stats.py works without Tk).
STATUS_ORDER = ["patched", "report-only", "no-findings", "build-failed", "skip", "fail", "crash"]
STATUS_COLORS = {
    "patched":      "#1e8a3a",   # green:    fixes applied, patched APK built and signed
    "report-only":  "#c9a14a",   # tan:      findings, but none with an automatic APK fix
    "no-findings":  "#2e6cb6",   # blue:     no rule matched
    "build-failed": "#e07b00",   # orange:   fixes applied, but the APK could not be rebuilt
    "skip":         "#aaaaaa",
    "fail":         "#c8311a",   # red:      the APK could not be analysed
    "crash":        "#7a1a0c",   # dark red: the pipeline crashed
}
SEVERITY_COLORS = {"high": "#c8311a", "medium": "#b88500", "low": "#5a8a3a"}
FIX_COLORS = {"fixed": "#1e8a3a", "not fixed": "#b5b5b5"}

RULE_IDS = tuple(RULES)                                           # R1 .. R7
RULE_COLORS = {r.id: SEVERITY_COLORS[r.severity] for r in RULES.values()}


@dataclass
class ApkRow:
    """One row of `per_apk_status.tsv` joined with that APK's report.json."""
    name: str
    status: str
    detail: str
    findings: int           # the count from the TSV (-1 if resumed)
    elapsed_s: float
    rule_ids: List[str] = field(default_factory=list)
    severities: List[str] = field(default_factory=list)
    cwes: List[str] = field(default_factory=list)
    fixed: int = 0          # findings whose fix is part of the patched APK
    has_report: bool = False


@dataclass
class BulkStats:
    out_dir: str
    rows: List[ApkRow] = field(default_factory=list)

    # Summary aggregates ----------------------------------------------------
    n_apks: int = 0
    n_patched: int = 0
    n_with_findings: int = 0
    n_findings_total: int = 0
    n_fixed_total: int = 0
    n_without_report: int = 0
    elapsed_total_s: float = 0.0

    status_counts: Counter = field(default_factory=Counter)      # status -> APKs
    rule_counts: Counter = field(default_factory=Counter)        # rule id -> findings
    severity_counts: Counter = field(default_factory=Counter)    # severity -> findings
    cwe_counts: Counter = field(default_factory=Counter)         # cwe id -> findings

    # Per-status elapsed-time stats: status -> {min, median, p90, max, mean, n}
    elapsed_by_status: Dict[str, Dict[str, float]] = field(default_factory=dict)
    # Findings-per-APK histogram (bucket key -> count of APKs)
    findings_hist: Counter = field(default_factory=Counter)


# ---------------------------------------------------------------------------
# Loading
# ---------------------------------------------------------------------------

def _read_tsv(path: str) -> List[ApkRow]:
    rows: List[ApkRow] = []
    if not os.path.isfile(path):
        return rows
    with open(path, "r", encoding="utf-8", errors="replace") as fh:
        first = True
        for line in fh:
            line = line.rstrip("\n")
            if not line:
                continue
            if first:
                first = False
                if line.lower().startswith("name"):
                    continue
            parts = line.split("\t")
            while len(parts) < 5:
                parts.append("")
            name, status, detail, findings_s, elapsed_s = parts[:5]
            try:
                findings = int(findings_s) if findings_s else 0
            except ValueError:
                findings = 0
            try:
                elapsed = float(elapsed_s) if elapsed_s else 0.0
            except ValueError:
                elapsed = 0.0
            rows.append(ApkRow(name=name, status=status, detail=detail,
                               findings=findings, elapsed_s=elapsed))
    return rows


def _load_findings(out_dir: str, row: ApkRow) -> None:
    """Fill row.rule_ids / severities / cwes / fixed from <out>/<name>/report.json."""
    path = os.path.join(out_dir, row.name, "report.json")
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as fh:
            findings = json.load(fh)
    except Exception:
        return
    if not isinstance(findings, list):
        return
    row.has_report = True
    for f in findings:
        if not isinstance(f, dict) or not f.get("rule"):
            continue
        row.rule_ids.append(f["rule"])
        if f.get("severity"):
            row.severities.append(f["severity"])
        if f.get("cwe"):
            row.cwes.append(f["cwe"])
        row.fixed += bool(f.get("fixed"))


def load_bulk_stats(out_dir: str, on_progress=None) -> BulkStats:
    """Load `per_apk_status.tsv` + every per-APK `report.json` under `out_dir` into a
    `BulkStats`. `on_progress(i, n, name)` is called per APK so the window can show progress."""
    out_dir = os.path.abspath(out_dir)
    bs = BulkStats(out_dir=out_dir)

    # A resumed run appends nothing for the APKs it skipped, and a re-run appends a second
    # row for the same APK: keep the last row per APK.
    last: Dict[str, ApkRow] = {}
    for row in _read_tsv(os.path.join(out_dir, "per_apk_status.tsv")):
        last[row.name] = row
    bs.rows = list(last.values())

    # If the TSV is missing, fall back to the sub-folders that have a `status` file.
    if not bs.rows:
        for n in sorted(os.listdir(out_dir) if os.path.isdir(out_dir) else []):
            sf = os.path.join(out_dir, n, "status")
            if not os.path.isfile(sf):
                continue
            try:
                with open(sf, "r", encoding="utf-8") as fh:
                    parts = fh.read().strip().split("\t")
            except OSError:
                continue
            bs.rows.append(ApkRow(name=n, status=parts[0] if parts else "?",
                                  detail=parts[1] if len(parts) > 1 else "",
                                  findings=0, elapsed_s=0.0))

    n = len(bs.rows)
    bs.n_apks = n
    elapsed_by_status: Dict[str, List[float]] = defaultdict(list)
    for i, row in enumerate(bs.rows, 1):
        _load_findings(out_dir, row)
        bs.status_counts[row.status] += 1
        bs.elapsed_total_s += row.elapsed_s
        bs.n_patched += row.status == "patched"
        bs.n_without_report += not row.has_report
        n_f = len(row.rule_ids)
        bs.n_with_findings += n_f > 0
        bs.n_findings_total += n_f
        bs.n_fixed_total += row.fixed
        bs.findings_hist[_findings_bucket(n_f)] += 1
        bs.rule_counts.update(row.rule_ids)
        bs.severity_counts.update(row.severities)
        bs.cwe_counts.update(row.cwes)
        if row.elapsed_s > 0:
            elapsed_by_status[row.status].append(row.elapsed_s)
        if on_progress is not None and (i % 25 == 0 or i == n):
            try:
                on_progress(i, n, row.name)
            except Exception:
                pass

    for status, arr in elapsed_by_status.items():
        arr_sorted = sorted(arr)
        bs.elapsed_by_status[status] = {
            "n":      float(len(arr_sorted)),
            "min":    arr_sorted[0],
            "median": statistics.median(arr_sorted),
            "p90":    arr_sorted[max(0, int(len(arr_sorted) * 0.9) - 1)],
            "max":    arr_sorted[-1],
            "mean":   sum(arr_sorted) / len(arr_sorted),
            "total":  sum(arr_sorted),
        }
    return bs


def _findings_bucket(n: int) -> str:
    """Bucket a per-APK finding count into a histogram key."""
    if n == 0: return "0"
    if n <= 2: return "1-2"
    if n <= 5: return "3-5"
    if n <= 10: return "6-10"
    if n <= 20: return "11-20"
    return "21+"


FINDINGS_HIST_ORDER = ("0", "1-2", "3-5", "6-10", "11-20", "21+")


# ---------------------------------------------------------------------------
# Convenience accessors used by the GUI
# ---------------------------------------------------------------------------

def rule_breakdown(bs: BulkStats) -> List[Tuple[str, int]]:
    """Findings per rule, for all 7 rules in rule order (zero counts included)."""
    return [(rid, bs.rule_counts.get(rid, 0)) for rid in RULE_IDS]


def top_cwes(bs: BulkStats, k: int = 15) -> List[Tuple[str, int]]:
    return bs.cwe_counts.most_common(k)


def status_breakdown(bs: BulkStats) -> List[Tuple[str, int]]:
    """Status counts in the canonical STATUS_ORDER (then anything else)."""
    out: List[Tuple[str, int]] = []
    seen = set()
    for s in STATUS_ORDER:
        if bs.status_counts.get(s):
            out.append((s, bs.status_counts[s]))
            seen.add(s)
    for s, c in sorted(bs.status_counts.items()):
        if s not in seen:
            out.append((s, c))
    return out


def headline_kpis(bs: BulkStats) -> List[Tuple[str, str]]:
    """Big-number summary: a list of (label, formatted-value) pairs."""
    n = bs.n_apks or 1   # avoid div-by-zero
    pct = lambda x: f"{x} ({x * 100.0 / n:.1f}%)"
    failed = bs.status_counts.get("fail", 0) + bs.status_counts.get("crash", 0)
    fixed_pct = bs.n_fixed_total * 100.0 / (bs.n_findings_total or 1)
    return [
        ("APKs scanned",         str(bs.n_apks)),
        ("APKs with findings",   pct(bs.n_with_findings)),
        ("APKs without findings", pct(bs.status_counts.get("no-findings", 0))),
        ("Failed to analyse",    pct(failed)),
        ("Patched APKs",         pct(bs.n_patched)),
        ("Report-only",          str(bs.status_counts.get("report-only", 0))),
        ("Rebuild failed",       str(bs.status_counts.get("build-failed", 0))),
        ("Total findings",       str(bs.n_findings_total)),
        ("Fixed findings",       f"{bs.n_fixed_total} ({fixed_pct:.1f}%)"),
        ("Avg findings / APK",   f"{bs.n_findings_total / n:.1f}"),
        ("Total elapsed",        _fmt_hms(bs.elapsed_total_s)),
        ("Mean elapsed / APK",   f"{bs.elapsed_total_s / n:.1f} s"),
    ]


def _fmt_hms(s: float) -> str:
    s = int(s)
    h, rem = divmod(s, 3600)
    m, sec = divmod(rem, 60)
    if h:
        return f"{h}h {m}m {sec}s"
    if m:
        return f"{m}m {sec}s"
    return f"{sec}s"


# ---------------------------------------------------------------------------
# CWE reference table -- each entry is (short name, plain-English summary,
# the HybridPatcher rule that surfaces this CWE).
#
# Source: MITRE CWE database (https://cwe.mitre.org). Summaries are
# paraphrased for readability; consult the canonical CWE page for the
# normative text.
# ---------------------------------------------------------------------------

@dataclass
class CweInfo:
    cwe: str
    name: str
    summary: str
    trigger: str


CWE_INFO: Dict[str, CweInfo] = {
    "CWE-200": CweInfo(
        cwe="CWE-200",
        name="Exposure of Sensitive Information to an Unauthorized Actor",
        summary=(
            "The product makes private information accessible to a party that "
            "should not have it. Causes include accidental exposure, "
            "misconfiguration, or a feature meant for one origin being "
            "reachable by another."
        ),
        trigger=(
            "Rule 4 and Rule 6: setAllowFileAccess(true), "
            "setAllowFileAccessFromFileURLs(true) and "
            "setAllowUniversalAccessFromFileURLs(true) let web content open "
            "file:// URLs and read other files, leaking the contents of the "
            "app's private storage."
        ),
    ),
    "CWE-295": CweInfo(
        cwe="CWE-295",
        name="Improper Certificate Validation",
        summary=(
            "The product accepts a TLS or X.509 certificate that the protocol "
            "should have rejected (expired, hostname mismatch, untrusted CA, "
            "self-signed in production), enabling man-in-the-middle interception."
        ),
        trigger=(
            "Rule 7: WebViewClient.onReceivedSslError calls proceed(), "
            "silently accepting any invalid certificate. The fix is cancel()."
        ),
    ),
    "CWE-319": CweInfo(
        cwe="CWE-319",
        name="Cleartext Transmission of Sensitive Information",
        summary=(
            "Sensitive data is sent over a channel that is not protected from "
            "passive sniffing or active modification (HTTP, plaintext SMTP, etc.)."
        ),
        trigger=(
            "Rule 3: setMixedContentMode(MIXED_CONTENT_ALWAYS_ALLOW). An https:// "
            "page is allowed to load http:// sub-resources, which an attacker on "
            "the network can replace. The fix is MIXED_CONTENT_NEVER_ALLOW."
        ),
    ),
}


def cwe_info(cwe: str) -> CweInfo:
    """Return the CweInfo for `cwe` (case-insensitive). Falls back to a
    placeholder so the GUI never shows blank cells."""
    if not cwe:
        return CweInfo(cwe="(none)", name="(no CWE assigned)", summary="", trigger="")
    canon = cwe.upper().replace(" ", "")
    if canon in CWE_INFO:
        return CWE_INFO[canon]
    return CweInfo(cwe=cwe, name="(no MITRE description in our table)",
                   summary="", trigger="")
