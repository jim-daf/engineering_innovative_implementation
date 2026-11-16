"""HybridPatcher: detects and fixes 7 WebView issues in hybrid Android apps.

rules.py     the 7 rules (detection and fix, for source code and for decompiled APKs)
pipeline.py  the source code pipeline, the APK pipeline and the reports
gui.py       the window (with stats.py and charts.py for the statistics view)
"""
from .rules import RULES, Finding, apply_fixes, scan_smali, scan_source   # noqa: F401
from .pipeline import (check_environment, fix_apks, fix_files, fix_tree,  # noqa: F401
                       process_apk, scan_apk, scan_tree, write_reports)
