"""HybridPatcher pipelines.

Source code pipeline:  folder -> apply the rules to every .java / .kt file -> report
                       (-> fixed copy of the folder)
APK pipeline:          APK -> apktool decode -> apply the rules to the decoded classes -> report
                       (-> fix the classes -> apktool build -> sign -> patched_<name>.apk)

The APK pipeline needs `java` on PATH and the two jars in tools/.
"""
from __future__ import annotations

import difflib
import json
import os
import re
import shutil
import subprocess
import sys
import threading
import time
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from typing import Callable, Dict, Iterator, List, Optional, Tuple

from .rules import RULES, Finding, apply_fixes, scan_smali, scan_source

TOOLS_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "tools")
APKTOOL_JAR = os.path.join(TOOLS_DIR, "apktool.jar")
SIGNER_JAR = os.path.join(TOOLS_DIR, "uber-apk-signer.jar")

SKIP_DIRS = {".git", "build", "node_modules", ".gradle", ".idea", ".venv"}

# APK pipeline: classes of well-known third-party SDKs are skipped, because a finding there
# belongs to the SDK and not to the app. Hybrid frameworks (Cordova, Capacitor, React Native
# WebView, ...) are scanned: their WebView is the app's WebView.
LIBRARY_PREFIXES = (
    "androidx/", "android/support/", "kotlin/", "kotlinx/", "com/google/", "com/facebook/ads/",
    "com/unity3d/", "com/applovin/", "com/ironsource/", "com/vungle/", "com/chartboost/",
    "com/inmobi/", "com/bytedance/", "com/mbridge/", "com/paypal/", "com/stripe/",
)

Log = Callable[[str], None]


def _read(path: str) -> Tuple[str, str]:
    """(text, encoding) of a file. Line endings are kept exactly as they are."""
    with open(path, "rb") as fh:
        raw = fh.read()
    try:
        return raw.decode("utf-8"), "utf-8"
    except UnicodeDecodeError:
        return raw.decode("latin-1"), "latin-1"


def _write(path: str, text: str, encoding: str) -> None:
    with open(path, "wb") as fh:
        fh.write(text.encode(encoding))


# --------------------------------------------------------------------------- source code pipeline

def scan_tree(root: str) -> List[Finding]:
    """Apply the rules to every .java / .kt file under `root`."""
    sources, min_sdk = [], None
    for folder, dirs, files in os.walk(root):
        dirs[:] = [d for d in dirs if d not in SKIP_DIRS]
        for name in files:
            path = os.path.join(folder, name)
            if name.endswith((".java", ".kt")):
                sources.append(path)
            elif name in ("build.gradle", "build.gradle.kts"):      # lowest minSdk of the project
                for m in re.finditer(r"\bminSdk(?:Version)?\s*[=(]?\s*(\d+)", _read(path)[0]):
                    min_sdk = min(int(m.group(1)), min_sdk or 999)
    findings: List[Finding] = []
    for path in sorted(sources):
        findings += scan_source(_read(path)[0], path.endswith(".kt"), path, min_sdk)
    return findings


def fix_files(findings: List[Finding], root: str = "", copy: str = "") -> int:
    """Apply the proposed fixes file by file and return how many were applied.
    With `root` and `copy`, each file is fixed in the copy `copy` of the tree `root`."""
    by_file: Dict[str, List[Finding]] = defaultdict(list)
    for f in findings:
        if f.edit:
            by_file[f.file].append(f)
    for path, group in by_file.items():
        target = os.path.join(copy, os.path.relpath(path, root)) if copy else path
        text, encoding = _read(target)
        _write(target, apply_fixes(text, group), encoding)
    return sum(f.fixed for f in findings)


def fix_tree(root: str, out_dir: str, findings: List[Finding]) -> str:
    """Copy the tree to <out_dir>/patched_<name> and fix the copy. Returns the copy's path."""
    root, out_dir = os.path.abspath(root), os.path.abspath(out_dir)
    dst = os.path.join(out_dir, "patched_" + (os.path.basename(root) or "src"))
    shutil.rmtree(dst, ignore_errors=True)
    skip = set(SKIP_DIRS)
    if os.path.normcase(out_dir).startswith(os.path.normcase(root) + os.sep):
        skip.add(os.path.relpath(out_dir, root).split(os.sep)[0])   # output folder inside the tree
    shutil.copytree(root, dst, ignore=shutil.ignore_patterns(*skip))
    fix_files(findings, root, dst)
    return dst


def diff_fixes(findings: List[Finding]) -> str:
    """The proposed fixes as a unified diff. Nothing is written."""
    by_file: Dict[str, List[Finding]] = defaultdict(list)
    for f in findings:
        if f.edit:
            by_file[f.file].append(f)
    out = []
    for path, group in sorted(by_file.items()):
        before = _read(path)[0]
        after = apply_fixes(before, group)
        out += difflib.unified_diff(before.splitlines(True), after.splitlines(True),
                                    path, path + " (patched)")
    return "".join(out)


# --------------------------------------------------------------------------- APK pipeline

@dataclass
class ApkResult:
    apk: str
    findings: List[Finding] = field(default_factory=list)
    output_apk: str = ""        # path of patched_<name>.apk when one was built
    status: str = "fail"        # patched | report-only | no-findings | build-failed | fail
    detail: str = ""


def check_environment() -> Tuple[bool, str]:
    """(ok, message): is everything there that the APK pipeline needs?"""
    if shutil.which("java") is None:
        return False, "java not found on PATH (Java 8 or newer is needed for APKs)"
    for jar in (APKTOOL_JAR, SIGNER_JAR):
        if not os.path.isfile(jar):
            return False, f"missing {jar}"
    return True, "ok"


def _run(cmd: List[str], log: Log, timeout: int = 1800) -> int:
    """Run a command, pass its output to `log`, kill it after `timeout` seconds."""
    proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True,
                            encoding="utf-8", errors="replace",
                            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
    timer = threading.Timer(timeout, proc.kill)
    timer.start()
    try:
        with proc.stdout:
            for line in proc.stdout:
                log("      " + line.rstrip())
        return proc.wait()
    finally:
        timer.cancel()


def _smali_files(work_dir: str) -> Iterator[str]:
    """Every .smali file of the app (all dex files), without the third-party SDK classes."""
    for top in sorted(os.listdir(work_dir)):
        base = os.path.join(work_dir, top)
        if not (top == "smali" or top.startswith("smali_")) or not os.path.isdir(base):
            continue
        for folder, dirs, files in os.walk(base):
            if (os.path.relpath(folder, base).replace(os.sep, "/") + "/").startswith(LIBRARY_PREFIXES):
                dirs[:] = []
                continue
            for name in sorted(files):
                if name.endswith(".smali"):
                    yield os.path.join(folder, name)


def _build(work_dir: str, out_dir: str, name: str, log: Log) -> str:
    """apktool build + sign. Returns the path of patched_<name>.apk, or "" when it failed."""
    unsigned = os.path.join(out_dir, f"_unsigned_{name}.apk")
    final = os.path.join(out_dir, f"patched_{name}.apk")
    try:
        log("[3/4] rebuilding the APK")
        if _run(["java", "-jar", APKTOOL_JAR, "b", "-o", unsigned, work_dir], log) != 0:
            return ""
        log("[4/4] signing")
        if _run(["java", "-jar", SIGNER_JAR, "--apks", unsigned, "--out", out_dir,
                 "--allowResign"], log) != 0:
            return ""
        signed = [n for n in os.listdir(out_dir)
                  if n.startswith(f"_unsigned_{name}-") and n.endswith("Signed.apk")]
        if not signed:
            return ""
        os.replace(os.path.join(out_dir, signed[0]), final)
        return final
    finally:
        for n in os.listdir(out_dir):                           # unsigned apk, .idsig leftovers
            if n.startswith(f"_unsigned_{name}"):
                try:
                    os.remove(os.path.join(out_dir, n))
                except OSError:
                    pass


def process_apk(apk: str, out_dir: str, fix: bool = False, keep_work_dir: bool = False,
                on_log: Optional[Log] = None) -> ApkResult:
    """Decode the APK and apply the rules to its classes. With `fix`, the classes are fixed
    and the APK is rebuilt and signed as <out_dir>/patched_<name>.apk."""
    log = on_log or (lambda _line: None)
    apk, out_dir = os.path.abspath(apk), os.path.abspath(out_dir)
    os.makedirs(out_dir, exist_ok=True)
    name = os.path.splitext(os.path.basename(apk))[0]
    work_dir = os.path.join(out_dir, "_work_" + name)
    res = ApkResult(apk)
    ok, res.detail = check_environment()
    if not ok:
        log("      " + res.detail)
        return res
    try:
        log(f"[1/4] decoding {apk}")
        if _run(["java", "-jar", APKTOOL_JAR, "d", "-r", "-f", "-o", work_dir, apk], log) != 0:
            res.detail = "apktool could not decode the APK"
            return res
        log("[2/4] applying the rules to the decoded classes")
        for path in _smali_files(work_dir):
            text, encoding = _read(path)
            found = scan_smali(text, os.path.relpath(path, work_dir).replace(os.sep, "/"))
            res.findings += found
            if fix and any(f.edit for f in found):
                _write(path, apply_fixes(text, found, comment=None), encoding)
        fixed = sum(f.fixed for f in res.findings)
        for f in res.findings:
            log(f"      {RULES[f.rule].label}{' (fixed)' if f.fixed else ''}  {f.file}:{f.line}  {f.excerpt}")
        res.detail = f"{len(res.findings)} finding(s), {fixed} fixed"
        if not res.findings:
            res.status = "no-findings"
        elif not fixed:
            res.status = "report-only"
        else:
            res.output_apk = _build(work_dir, out_dir, name, log)
            res.status = "patched" if res.output_apk else "build-failed"
            if not res.output_apk:
                for f in res.findings:                          # nothing was delivered
                    f.fixed = False
        log(f"      -> {res.status}: {res.detail}")
        return res
    finally:
        if not keep_work_dir:
            shutil.rmtree(work_dir, ignore_errors=True)


def scan_apk(apk: str, on_log: Optional[Log] = None) -> List[Finding]:
    """Detection only: the findings of one APK (decoded in a temporary folder)."""
    import tempfile
    with tempfile.TemporaryDirectory(prefix="hybrid_patcher_") as tmp:
        return process_apk(apk, tmp, on_log=on_log).findings


def fix_apks(apk_paths: List[str], out_dir: str, keep_work_dir: bool = False,
             resume: bool = True, on_event=None, stop_check=None) -> int:
    """Run the APK pipeline (with fixes) on many APKs, one after the other.

    Each APK gets <out_dir>/<name>/ with report.md, report.json, run.log, a `status` file and
    patched_<name>.apk when one was built. <out_dir>/per_apk_status.tsv collects one row per
    APK; with `resume`, APKs that already have a `status` file are skipped.

    on_event(kind, payload) receives ("start", {...}), ("done", {...}), ("log", line) and
    ("summary", {...}); stop_check() returning True stops the run after the current APK.
    """
    out_dir = os.path.abspath(out_dir)
    os.makedirs(out_dir, exist_ok=True)
    status_tsv = os.path.join(out_dir, "per_apk_status.tsv")
    if not os.path.isfile(status_tsv):
        with open(status_tsv, "w", encoding="utf-8") as fh:
            fh.write("name\tstatus\tdetail\tfindings\telapsed_s\n")

    def emit(kind, payload):
        if on_event:
            try:
                on_event(kind, payload)
            except Exception:
                pass                                            # a UI problem must not stop the run

    def say(line):
        print(line, file=sys.stderr)
        emit("log", line)

    ok, msg = check_environment()
    if not ok:
        say("error: " + msg)
        return 2
    n = len(apk_paths)
    rows: List[Tuple[str, str, str]] = []
    say(f"[fix-apks] processing {n} apk(s) -> {out_dir}  resume={resume}")
    for i, apk in enumerate(apk_paths, 1):
        if stop_check and stop_check():
            say(f"[fix-apks] stop requested after {i - 1}/{n} apk(s)")
            break
        apk = os.path.abspath(apk)
        name = os.path.splitext(os.path.basename(apk))[0]
        per_dir = os.path.join(out_dir, name)
        status_file = os.path.join(per_dir, "status")
        done = {"i": i, "n": n, "name": name, "findings": 0, "elapsed_s": 0.0, "resumed": False}
        if not os.path.isfile(apk):
            rows.append((name, "skip", "file not found"))
            emit("done", dict(done, status="skip", detail="file not found"))
            continue
        if resume and os.path.isfile(status_file):
            status, _, detail = _read(status_file)[0].strip().partition("\t")
            rows.append((name, status, detail))
            emit("done", dict(done, status=status, detail=detail, findings=-1, resumed=True))
            continue
        say(f"\n[{i}/{n}] === {apk} ===")
        emit("start", {"i": i, "n": n, "name": name, "apk": apk})
        os.makedirs(per_dir, exist_ok=True)
        started, findings = time.time(), []
        try:
            with open(os.path.join(per_dir, "run.log"), "w", encoding="utf-8") as log_fh:
                res = process_apk(apk, per_dir, fix=True, keep_work_dir=keep_work_dir,
                                  on_log=lambda line: log_fh.write(line + "\n"))
            status, detail, findings = res.status, res.detail, res.findings
            write_reports(findings, per_dir)
        except Exception as e:
            status, detail = "crash", str(e).replace("\n", " ")[:200]
        elapsed = time.time() - started
        rows.append((name, status, detail))
        with open(status_file, "w", encoding="utf-8") as fh:
            fh.write(f"{status}\t{detail}")
        with open(status_tsv, "a", encoding="utf-8") as fh:
            fh.write(f"{name}\t{status}\t{detail}\t{len(findings)}\t{elapsed:.1f}\n")
        say(f"  -> {status}: {detail}  ({elapsed:.1f}s)")
        emit("done", dict(done, status=status, detail=detail, findings=len(findings),
                          elapsed_s=elapsed))

    counts = Counter(status for _, status, _ in rows)
    say("\n" + "=" * 78 + f"\n[fix-apks] summary ({len(rows)} apk(s)):")
    for status, c in sorted(counts.items()):
        say(f"  {status:14}  {c}")
    with open(os.path.join(out_dir, "summary.tsv"), "w", encoding="utf-8") as fh:
        fh.write("name\tstatus\tdetail\n" + "".join(f"{a}\t{b}\t{c}\n" for a, b, c in rows))
    emit("summary", {"counts": dict(counts), "rows": rows})
    return 0 if any(s not in ("fail", "crash", "skip") for _, s, _ in rows) else 1


# --------------------------------------------------------------------------- reports

_SEVERITY = {"high": 0, "medium": 1, "low": 2}


def _by_rule(findings: List[Finding]) -> List[Tuple[str, List[Finding]]]:
    groups: Dict[str, List[Finding]] = defaultdict(list)
    for f in findings:
        groups[f.rule].append(f)
    return sorted(groups.items(), key=lambda kv: (_SEVERITY[RULES[kv[0]].severity], kv[0]))


def format_json(findings: List[Finding]) -> str:
    return json.dumps([f.to_dict() for f in findings], indent=2)


def format_text(findings: List[Finding]) -> str:
    lines = [f"HybridPatcher: {len(findings)} finding(s), {sum(f.fixed for f in findings)} fixed"]
    for rule_id, group in _by_rule(findings):
        r = RULES[rule_id]
        lines += ["", f"{r.label}: {r.title}  [{r.severity}{', ' + r.cwe if r.cwe else ''}]  "
                      f"{len(group)} finding(s)", f"  why: {r.why}", f"  fix: {r.fix}"]
        for f in group:
            state = "fixed" if f.fixed else "fix proposed" if f.fix_after else "no automatic fix"
            lines.append(f"    {f.file}:{f.line}  ({state})  {f.excerpt}")
    return "\n".join(lines) + "\n"


def format_md(findings: List[Finding], limit: int = 50) -> str:
    """The report: every detection with its explanation and its fix as a diff."""
    out = ["# HybridPatcher report", "",
           f"{len(findings)} finding(s), {sum(f.fixed for f in findings)} fixed automatically.", ""]
    if not findings:
        return "\n".join(out)
    out += ["| rule | severity | title | findings | fixed |", "|---|---|---|---:|---:|"]
    for rule_id, group in _by_rule(findings):
        r = RULES[rule_id]
        out.append(f"| {r.label} | {r.severity} | {r.title} | {len(group)} | {sum(f.fixed for f in group)} |")
    for rule_id, group in _by_rule(findings):
        r = RULES[rule_id]
        out += ["", f"## {r.label}: {r.title}", "",
                f"- **Severity:** {r.severity}" + (f" ({r.cwe})" if r.cwe else ""),
                f"- **Why it matters:** {r.why}",
                f"- **Fix:** {r.fix}",
                f"- **Reference:** <{r.reference}>", ""]
        for k, f in enumerate(group[:limit], 1):
            state = "fixed" if f.fixed else "fix proposed" if f.fix_after else \
                "no automatic fix here, change it by hand"
            out += [f"{k}. `{f.file}` line {f.line} ({state})", "", f"   `{f.excerpt}`", ""]
            if f.fix_after:
                out += ["   ```diff"]
                out += ["   - " + ln for ln in f.fix_before.split("\n") if ln.strip()]
                out += ["   + " + ln for ln in f.fix_after.split("\n") if ln.strip()]
                out += ["   ```", ""]
        if len(group) > limit:
            out += [f"... and {len(group) - limit} more (see report.json)", ""]
    return "\n".join(out) + "\n"


def write_reports(findings: List[Finding], out_dir: str) -> Tuple[str, str]:
    """Write report.md and report.json into `out_dir`; returns both paths."""
    os.makedirs(out_dir, exist_ok=True)
    md, js = os.path.join(out_dir, "report.md"), os.path.join(out_dir, "report.json")
    with open(md, "w", encoding="utf-8") as fh:
        fh.write(format_md(findings))
    with open(js, "w", encoding="utf-8") as fh:
        fh.write(format_json(findings))
    return md, js
