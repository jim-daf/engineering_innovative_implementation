"""HybridPatcher command line.

  python -m hybrid_patcher --gui                       open the window
  python -m hybrid_patcher --rules                     list the 7 rules
  python -m hybrid_patcher --src ./repo                report on a source folder
  python -m hybrid_patcher --src ./repo --patch        show the proposed fixes as a diff
  python -m hybrid_patcher --src ./repo --patch-apply  fix the source files in place
  python -m hybrid_patcher --apk app.apk               report on an APK
  python -m hybrid_patcher --fix-apks --apk-dir ./apks --out-dir ./out
                                                       fix many APKs, one folder per APK
"""
from __future__ import annotations

import argparse
import os
import sys

from .pipeline import (diff_fixes, fix_apks, fix_files, format_json, format_md, format_text,
                       scan_apk, scan_tree)
from .rules import RULES


def main(argv=None) -> int:
    p = argparse.ArgumentParser(prog="hybrid_patcher", description=__doc__,
                                formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--src", action="append", default=[], help="source folder (can repeat)")
    p.add_argument("--apk", action="append", default=[], help="APK file (can repeat)")
    p.add_argument("--format", choices=("text", "md", "json"), default="text")
    p.add_argument("--out", default="-", help="report file ('-' = print it)")
    p.add_argument("--rules", action="store_true", help="list the rules and exit")
    p.add_argument("--patch", action="store_true",
                   help="print the proposed source fixes as a diff instead of the report")
    p.add_argument("--patch-apply", action="store_true",
                   help="fix the source files in place (use version control)")
    p.add_argument("--fix-apks", action="store_true",
                   help="decode, fix, rebuild and sign every --apk / --apk-dir input")
    p.add_argument("--apk-dir", help="with --fix-apks: take every *.apk in this folder")
    p.add_argument("--out-dir", help="output folder for --fix-apks (default: ./hybrid_patcher_out)")
    p.add_argument("--no-resume", action="store_true",
                   help="with --fix-apks: redo APKs that already have a result")
    p.add_argument("--keep-work-dir", action="store_true",
                   help="with --fix-apks: keep the decoded APK folder")
    p.add_argument("--gui", action="store_true", help="open the window")
    p.add_argument("--gui-bulk", metavar="APK_DIR", help="open the bulk window with these APKs")
    p.add_argument("--gui-stats", metavar="OUT_DIR", help="open the statistics of a bulk run")
    a = p.parse_args(argv)
    for stream in (sys.stdout, sys.stderr):                     # source excerpts can hold any character
        if hasattr(stream, "reconfigure"):
            stream.reconfigure(errors="replace")

    if a.gui or a.gui_bulk or a.gui_stats:
        from . import gui
        if a.gui_bulk:
            gui.open_bulk_preloaded(a.gui_bulk, a.out_dir)
        elif a.gui_stats:
            gui.open_stats_preloaded(a.gui_stats)
        else:
            gui.main()
        return 0

    if a.rules:
        for r in RULES.values():
            print(f"{r.label}  [{r.severity}{', ' + r.cwe if r.cwe else ''}]  {r.title}\n"
                  f"    why: {r.why}\n    fix: {r.fix}\n    ref: {r.reference}\n")
        return 0

    if a.fix_apks:
        apks = list(a.apk)
        if a.apk_dir:
            if not os.path.isdir(a.apk_dir):
                p.error(f"--apk-dir {a.apk_dir!r} is not a folder")
            apks += [os.path.join(a.apk_dir, n) for n in sorted(os.listdir(a.apk_dir))
                     if n.lower().endswith(".apk")]
        if not apks:
            p.error("--fix-apks needs --apk FILE or --apk-dir DIR")
        return fix_apks(apks, a.out_dir or "hybrid_patcher_out",
                        keep_work_dir=a.keep_work_dir, resume=not a.no_resume)

    if not a.src and not a.apk:
        p.error("give --src DIR or --apk FILE (or --gui, --rules)")
    findings = []
    for src in a.src:
        if os.path.isdir(src):
            findings += scan_tree(src)
        else:
            print(f"warning: --src {src!r} is not a folder, skipped", file=sys.stderr)
    if a.patch_apply:                                           # source files only
        print(f"applied {fix_files(findings)} fix(es)", file=sys.stderr)
        return 0
    if a.patch:
        text = diff_fixes(findings)
    else:
        for apk in a.apk:
            if os.path.isfile(apk):
                findings += scan_apk(apk, on_log=lambda line: print(line, file=sys.stderr))
            else:
                print(f"warning: --apk {apk!r} not found, skipped", file=sys.stderr)
        text = {"text": format_text, "md": format_md, "json": format_json}[a.format](findings)
    if a.out == "-":
        sys.stdout.write(text)
    else:
        with open(a.out, "w", encoding="utf-8") as fh:
            fh.write(text)
        print(f"wrote {len(findings)} finding(s) to {a.out}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
