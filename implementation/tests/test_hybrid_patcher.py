"""Tests for HybridPatcher.

Run from the implementation folder:   python -m unittest discover -s tests -v
"""
import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from collections import Counter

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.dirname(HERE))

from hybrid_patcher import pipeline, stats                          # noqa: E402
from hybrid_patcher.rules import RULES, apply_fixes, scan_smali, scan_source   # noqa: E402

FIXTURES = os.path.join(HERE, "fixtures")
SAMPLE = os.path.join(FIXTURES, "sample_app")
EVERY_RULE = {"R1": 1, "R2": 1, "R3": 1, "R4": 1, "R5": 1, "R6": 2, "R7": 1}


def rules_of(findings):
    return dict(Counter(f.rule for f in findings))


def read(path, mode="r"):
    with open(path, mode, encoding=None if "b" in mode else "utf-8") as fh:
        return fh.read()


def write_json(path, data):
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(data, fh)


def fixed(text, kotlin=False, **kw):
    """Scan `text`, apply every fix, return (findings, fixed text)."""
    findings = scan_source(text, kotlin, **kw)
    return findings, apply_fixes(text, findings)


class SourceFixtures(unittest.TestCase):

    def test_every_rule_is_found_in_java_and_kotlin(self):
        by_file = {}
        for f in pipeline.scan_tree(SAMPLE):
            by_file.setdefault(os.path.basename(f.file), []).append(f)
        self.assertEqual(rules_of(by_file["InsecureActivity.java"]), EVERY_RULE)
        self.assertEqual(rules_of(by_file["KotlinActivity.kt"]), EVERY_RULE)
        self.assertNotIn("SafeActivity.java", by_file)
        self.assertTrue(all(f.edit and f.fix_after for fs in by_file.values() for f in fs))

    def test_fixing_a_copy_leaves_nothing_to_report(self):
        with tempfile.TemporaryDirectory() as out:
            findings = pipeline.scan_tree(SAMPLE)
            before = {f.file: read(f.file, "rb") for f in findings}
            copy = pipeline.fix_tree(SAMPLE, out, findings)
            self.assertTrue(all(f.fixed for f in findings))
            self.assertEqual(pipeline.scan_tree(copy), [])
            for path, data in before.items():                       # the originals are untouched
                self.assertEqual(read(path, "rb"), data)
            java = read(os.path.join(copy, "app/src/main/java/com/example/hybrid/InsecureActivity.java"))
            kotlin = read(os.path.join(copy, "app/src/main/java/com/example/hybrid/KotlinActivity.kt"))
            for expected in ("setMixedContentMode(WebSettings.MIXED_CONTENT_NEVER_ALLOW)",
                             "setAllowFileAccess(false)", "setAllowFileAccessFromFileURLs(false)",
                             "setAllowUniversalAccessFromFileURLs(false)", "handler.cancel();",
                             'web.evaluateJavascript("showTotal()", null);',
                             "} catch (Exception linkError) {",
                             "public boolean shouldOverrideUrlLoading(android.webkit.WebView view, String url) {",
                             "// HybridPatcher (Rule 4):"):
                self.assertIn(expected, java)
            for expected in ("mixedContentMode = WebSettings.MIXED_CONTENT_NEVER_ALLOW",
                             "allowFileAccess = false", "allowUniversalAccessFromFileURLs = false",
                             "web.settings.allowFileAccessFromFileURLs = false", "handler?.cancel()",
                             "web.evaluateJavascript(\"show('$name')\", null)",
                             "} catch (linkError: Exception) {",
                             "override fun shouldOverrideUrlLoading(view: android.webkit.WebView?, url: String?): Boolean {"):
                self.assertIn(expected, kotlin)

    @unittest.skipUnless(shutil.which("javac"), "javac not installed")
    def test_fixed_java_still_parses(self):
        with tempfile.TemporaryDirectory() as out:
            copy = pipeline.fix_tree(SAMPLE, out, pipeline.scan_tree(SAMPLE))
            path = os.path.join(copy, "app/src/main/java/com/example/hybrid/InsecureActivity.java")
            cp = subprocess.run(["javac", "-proc:none", "-XDshould-stop.ifNoError=PARSE",
                                 "-XDshould-stop.ifError=PARSE", "-d", out, path],
                                capture_output=True, text=True)
            self.assertNotIn("error:", cp.stdout + cp.stderr)

    def test_minsdk_below_19_blocks_the_rule5_fix(self):
        findings = pipeline.scan_tree(os.path.join(FIXTURES, "old_app"))
        self.assertEqual(rules_of(findings), {"R5": 1})
        self.assertIsNone(findings[0].edit)
        self.assertIn("minSdk", findings[0].excerpt)


class SourceRules(unittest.TestCase):

    def test_comments_and_strings_are_not_code(self):
        text = '''class A {
            // s.setAllowFileAccess(true);
            /* web.loadUrl("javascript:x()");
               s.setMixedContentMode(WebSettings.MIXED_CONTENT_ALWAYS_ALLOW); */
            String hint = "call s.setAllowUniversalAccessFromFileURLs(true); { never";
            boolean allowFileAccess = true;
        }'''
        self.assertEqual(scan_source(text, False), [])

    def test_setting_forms(self):
        findings, out = fixed("s.setMixedContentMode(0);\ns.setMixedContentMode(MIXED_CONTENT_ALWAYS_ALLOW);\n"
                              "s.setAllowFileAccess(\n        true);\n"
                              "s.setMixedContentMode(WebSettings.MIXED_CONTENT_COMPATIBILITY_MODE);\n"
                              "s.setAllowFileAccess(flag);\n")
        self.assertEqual(rules_of(findings), {"R3": 2, "R4": 1})
        self.assertIn("s.setMixedContentMode(1);", out)
        self.assertIn("s.setMixedContentMode(MIXED_CONTENT_NEVER_ALLOW);", out)
        self.assertIn("s.setAllowFileAccess(\n        false);", out)
        findings, out = fixed("settings.mixedContentMode = 0\nif (settings.allowFileAccess == true) {}\n"
                              "val allowFileAccess = true\n", kotlin=True)
        self.assertEqual(rules_of(findings), {"R3": 1})
        self.assertIn("settings.mixedContentMode = 1", out)

    def test_rule1_shapes(self):
        one_line = "class A {\n    void f(WebView w) {\n        w.setWebViewClient(new WebViewClient() {});\n    }\n}\n"
        findings, out = fixed(one_line)
        self.assertEqual(rules_of(findings), {"R1": 1})
        self.assertEqual(scan_source(out, False), [])
        self.assertRegex(out, r"new WebViewClient\(\) \{\n\s+// HybridPatcher \(Rule 1\)")
        self.assertTrue(out.rstrip().endswith("        });\n    }\n}"))
        named = "class C extends android.webkit.WebViewClient implements Runnable {\n  public void run() {}\n}\n"
        findings, out = fixed(named)
        self.assertEqual(rules_of(findings), {"R1": 1})
        self.assertIn("\n  @Override\n  public boolean shouldOverrideUrlLoading(", out)   # 2-space project
        self.assertIn("\n    if (url == null", out)
        kotlin = "class C(val a: Int) : WebViewClient(), Runnable {\n    override fun run() {}\n}\n"
        self.assertEqual(rules_of(scan_source(kotlin, True)), {"R1": 1})
        has_it = "w.webViewClient = object : WebViewClient() {\n    override fun shouldOverrideUrlLoading(v: WebView, u: String) = false\n}\n"
        self.assertEqual(scan_source(has_it, True), [])
        self.assertEqual(scan_source("val c: WebViewClient = WebViewClient()\n", True), [])

    def test_rule2_cases(self):
        method = "class C extends WebViewClient {\n    public boolean shouldOverrideUrlLoading(WebView v, String u) {\n%s\n        return true;\n    }\n}\n"
        findings, out = fixed(method % "        v.getContext().startActivity(\n                new Intent(u));")
        self.assertEqual(rules_of(findings), {"R2": 1})
        self.assertIn("        try {\n            v.getContext().startActivity(\n                    new Intent(u));\n"
                      "        } catch (Exception linkError) {", out)
        self.assertEqual(scan_source(out, False), [])
        inline = scan_source(method % "        if (u != null) startActivity(new Intent(u));", False)
        self.assertEqual(rules_of(inline), {"R2": 1})
        self.assertIsNone(inline[0].edit)                           # reported, left to the developer
        guarded = method % "        try { startActivity(new Intent(u)); } catch (Exception e) { }"
        self.assertEqual(scan_source(guarded, False), [])
        helper = (method % "        startActivity(u);") + \
            "class D { private void startActivity(String u) { try { x(); } catch (Exception e) { } } }\n"
        self.assertEqual(scan_source(helper, False), [])
        kotlin = "class C : WebViewClient() {\n    override fun shouldOverrideUrlLoading(v: WebView, u: String): Boolean {\n" \
                 "        runCatching { v.context.startActivity(Intent(u)) }\n        return true\n    }\n}\n"
        self.assertEqual(scan_source(kotlin, True), [])

    def test_rule5_cases(self):
        findings, out = fixed('w.loadUrl("javascript:" + js);\nw.loadUrl(\n        "javascript:a(" + x + ")");\n')
        self.assertEqual(rules_of(findings), {"R5": 2})
        self.assertIn('w.evaluateJavascript("" + js, null);', out)
        self.assertIn('w.evaluateJavascript(\n        "a(" + x + ")", null);', out)
        two_args = scan_source('engine.loadUrl("javascript:" + js, false);\n', False)
        self.assertIsNone(two_args[0].edit)
        self.assertIn("more than one argument", two_args[0].excerpt)
        self.assertIsNone(scan_source('w.loadUrl("javascript:a()");\n', False, min_sdk=16)[0].edit)
        self.assertIsNotNone(scan_source('w.loadUrl("javascript:a()");\n', False, min_sdk=21)[0].edit)
        self.assertEqual(scan_source('w.loadUrl("https://a.b/javascript:x");\n', False), [])

    def test_rule7_cases(self):
        text = '''class C extends WebViewClient {
            public boolean shouldOverrideUrlLoading(WebView v, String u) { return false; }
            public void onReceivedHttpAuthRequest(WebView v, HttpAuthHandler handler, String h, String r) {
                handler.proceed("user", "pass");
            }
            public void onReceivedSslError(WebView v, SslErrorHandler h, SslError e) {
                super.onReceivedSslError(v, h, e);
                Log.w("T", "we do handler.proceed()");
                if (debug) { h.proceed(); } else { h.cancel(); }
            }
        }'''
        findings, out = fixed(text)
        self.assertEqual(rules_of(findings), {"R7": 1})
        self.assertIn("if (debug) { h.cancel(); } else { h.cancel(); }", out)
        self.assertIn('handler.proceed("user", "pass");', out)
        self.assertIn('"we do handler.proceed()"', out)
        kotlin = "class C : WebViewClient() {\n    override fun shouldOverrideUrlLoading(v: WebView, u: String) = false\n" \
                 "    override fun onReceivedSslError(v: WebView?, handler: SslErrorHandler?, e: SslError?) {\n" \
                 "        handler?.let { it.proceed() }\n    }\n}\n"
        findings, out = fixed(kotlin, kotlin=True)
        self.assertEqual(rules_of(findings), {"R7": 1})
        self.assertIn("handler?.let { it.cancel() }", out)

    def test_windows_line_endings_are_kept(self):
        text = "class A {\r\n    void f() {\r\n        w.loadUrl(\"javascript:a(\" +\r\n                x + \")\");\r\n" \
               "        s.setAllowFileAccess(true);\r\n    }\r\n}\r\n"
        _, out = fixed(text)
        self.assertNotIn("\r\r", out)
        self.assertEqual(out.count("\r\n"), out.count("\n"))
        self.assertIn("s.setAllowFileAccess(false);\r\n", out)


SMALI_MAIN = '''.class public Lcom/example/Main;
.super Landroid/app/Activity;
.source "Main.java"

.method private setup(Landroid/webkit/WebView;)V
    .locals 3

    .line 10
    invoke-virtual {p1}, Landroid/webkit/WebView;->getSettings()Landroid/webkit/WebSettings;

    move-result-object v0

    const/4 v1, 0x1

    const/4 v2, 0x0

    .line 11
    invoke-virtual {v0, v1}, Landroid/webkit/WebSettings;->setJavaScriptEnabled(Z)V

    .line 12
    invoke-virtual {v0, v1}, Landroid/webkit/WebSettings;->setAllowFileAccess(Z)V

    if-eqz p1, :cond_0

    .line 13
    invoke-virtual {v0, v1}, Landroid/webkit/WebSettings;->setAllowUniversalAccessFromFileURLs(Z)V

    :cond_0
    .line 14
    invoke-virtual {v0, v2}, Landroid/webkit/WebSettings;->setMixedContentMode(I)V

    .line 15
    invoke-virtual {v0, v2}, Landroid/webkit/WebSettings;->setAllowFileAccessFromFileURLs(Z)V

    const-string v1, "javascript:init()"

    .line 16
    invoke-virtual {p1, v1}, Landroid/webkit/WebView;->loadUrl(Ljava/lang/String;)V

    return-void
.end method
'''

SMALI_CLIENT = '''.class public Lcom/example/Client;
.super Landroid/webkit/WebViewClient;
.source "Client.kt"

.method public onReceivedSslError(Landroid/webkit/WebView;Landroid/webkit/SslErrorHandler;Landroid/net/http/SslError;)V
    .locals 0

    .line 20
    invoke-virtual {p2}, Landroid/webkit/SslErrorHandler;->proceed()V

    return-void
.end method

.method public onPageFinished(Landroid/webkit/WebView;Ljava/lang/String;)V
    .locals 0

    invoke-virtual {p0}, Lcom/example/Other;->proceed()V

    return-void
.end method
'''

SMALI_LINKS = '''.class public Lcom/example/Links;
.super Landroid/webkit/WebViewClient;

.method public shouldOverrideUrlLoading(Landroid/webkit/WebView;Ljava/lang/String;)Z
    .locals 2

    :try_start_0
    invoke-virtual {p1, v0}, Landroid/content/Context;->startActivity(Landroid/content/Intent;)V
    :try_end_0
    .catch Landroid/content/ActivityNotFoundException; {:try_start_0 .. :try_end_0} :catch_0

    :catch_0
    invoke-virtual {p1, v1}, Landroid/content/Context;->startActivity(Landroid/content/Intent;)V

    const/4 v0, 0x1

    return v0
.end method
'''


class SmaliRules(unittest.TestCase):

    def test_settings_are_fixed_without_touching_other_calls(self):
        findings = scan_smali(SMALI_MAIN, "smali/com/example/Main.smali")
        self.assertEqual(rules_of(findings), {"R3": 1, "R4": 1, "R5": 1, "R6": 1})
        self.assertIn("at Main.java:12", [f for f in findings if f.rule == "R4"][0].excerpt)
        out = apply_fixes(SMALI_MAIN, findings, comment=None)
        # the shared register keeps its value for setJavaScriptEnabled and gets it back afterwards
        self.assertIn("    const/4 v1, 0x1\n\n    const/4 v2, 0x0\n\n    .line 11\n"
                      "    invoke-virtual {v0, v1}, Landroid/webkit/WebSettings;->setJavaScriptEnabled(Z)V", out)
        self.assertIn("    const/4 v1, 0x0\n    invoke-virtual {v0, v1}, Landroid/webkit/WebSettings;"
                      "->setAllowFileAccess(Z)V\n    const/4 v1, 0x1\n", out)
        self.assertIn("    const/4 v2, 0x1\n    invoke-virtual {v0, v2}, Landroid/webkit/WebSettings;"
                      "->setMixedContentMode(I)V\n    const/4 v2, 0x0\n", out)
        self.assertEqual(rules_of(scan_smali(out)), {"R5": 1})         # Rule 5 is report-only for APKs
        self.assertEqual([f.fixed for f in findings if f.rule != "R5"], [True, True, True])

    def test_a_value_that_is_not_certain_is_left_alone(self):
        setter = "    invoke-virtual {v0, v1}, Landroid/webkit/WebSettings;->setAllowFileAccess(Z)V\n"
        method = ".class LA;\n.super Ljava/lang/Object;\n.method f(Z)V\n%s" + setter + "    return-void\n.end method\n"
        branches = "    if-eqz p1, :cond_0\n    const/4 v1, 0x0\n    goto :goto_0\n    :cond_0\n    const/4 v1, 0x1\n    :goto_0\n"
        self.assertEqual(scan_smali(method % branches), [])
        self.assertEqual(scan_smali(method % "    invoke-virtual {v0}, LB;->enabled()Z\n    move-result v1\n"), [])
        self.assertEqual(scan_smali(method % "    const/4 v1, 0x0\n"), [])
        hoisted = "    const/4 v1, 0x1\n    if-eqz p1, :cond_0\n    return-void\n    :cond_0\n"
        self.assertEqual(rules_of(scan_smali(method % hoisted)), {"R4": 1})

    def test_ssl_handler_and_missing_override(self):
        findings = scan_smali(SMALI_CLIENT, "smali/com/example/Client.smali")
        self.assertEqual(rules_of(findings), {"R1": 1, "R7": 1})
        out = apply_fixes(SMALI_CLIENT, findings, comment=None)
        self.assertIn("Landroid/webkit/SslErrorHandler;->cancel()V", out)
        self.assertIn("Lcom/example/Other;->proceed()V", out)          # only inside onReceivedSslError
        self.assertIn(".method public shouldOverrideUrlLoading(Landroid/webkit/WebView;Ljava/lang/String;)Z", out)
        self.assertEqual(out.count(".method "), out.count(".end method"))
        self.assertEqual(scan_smali(out), [])

    def test_startactivity_inside_and_outside_a_try_range(self):
        findings = scan_smali(SMALI_LINKS)
        self.assertEqual(rules_of(findings), {"R2": 1})
        self.assertEqual(findings[0].line, 13)                      # the call after :catch_0
        self.assertIsNone(findings[0].edit)


class ReportsAndStats(unittest.TestCase):

    def test_report_documents_detection_and_fix(self):
        findings = pipeline.scan_tree(SAMPLE)
        md = pipeline.format_md(findings)
        self.assertIn("## Rule 3: Unrestricted Mixed Content", md)
        self.assertIn("```diff", md)
        self.assertIn("-         settings.setAllowFileAccess(true);", md)
        self.assertIn("+         settings.setAllowFileAccess(false);", md)
        rows = json.loads(pipeline.format_json(findings))
        self.assertEqual(len(rows), 16)
        self.assertEqual(set(rows[0]), {"rule", "title", "severity", "cwe", "file", "line", "excerpt",
                                        "confidence", "fix_before", "fix_after", "fixed"})
        self.assertIn("16 finding(s)", pipeline.format_text(findings))

    def test_bulk_statistics(self):
        with tempfile.TemporaryDirectory() as out:
            rows = [("a", "patched", [("R3", True), ("R4", True), ("R5", False)]),
                    ("b", "report-only", [("R2", False)]), ("c", "no-findings", []), ("d", "fail", None)]
            with open(os.path.join(out, "per_apk_status.tsv"), "w", encoding="utf-8") as fh:
                fh.write("name\tstatus\tdetail\tfindings\telapsed_s\n")
                for name, status, found in rows:
                    fh.write(f"{name}\t{status}\tx\t{len(found or [])}\t2.5\n")
                    if found is not None:
                        os.makedirs(os.path.join(out, name))
                        write_json(os.path.join(out, name, "report.json"),
                                   [{"rule": r, "severity": RULES[r].severity, "cwe": RULES[r].cwe, "fixed": fx}
                                    for r, fx in found])
            bs = stats.load_bulk_stats(out)
            self.assertEqual((bs.n_apks, bs.n_patched, bs.n_with_findings, bs.n_findings_total, bs.n_fixed_total),
                             (4, 1, 2, 4, 2))
            self.assertEqual(dict(stats.rule_breakdown(bs))["R3"], 1)
            self.assertEqual(dict(bs.status_counts), {"patched": 1, "report-only": 1, "no-findings": 1, "fail": 1})
            self.assertEqual(dict(stats.headline_kpis(bs))["Fixed findings"], "2 (50.0%)")


def _sample_apk():
    folder = os.path.join(HERE, "apks")
    names = sorted(n for n in os.listdir(folder) if n.endswith(".apk")) if os.path.isdir(folder) else []
    return os.path.join(folder, names[0]) if names else ""


@unittest.skipUnless(_sample_apk() and pipeline.check_environment()[0],
                     "needs java and an APK in tests/apks/")
class ApkPipeline(unittest.TestCase):

    def test_fix_rebuild_sign_and_rescan(self):
        with tempfile.TemporaryDirectory() as out:
            res = pipeline.process_apk(_sample_apk(), out, fix=True)
            self.assertEqual(res.status, "patched", res.detail)
            self.assertTrue(os.path.isfile(res.output_apk))
            self.assertEqual(os.listdir(out), [os.path.basename(res.output_apk)])   # no leftovers
            again = pipeline.scan_apk(res.output_apk)
            self.assertFalse([f for f in again if f.edit], "the patched APK still has fixable findings")
            self.assertEqual(sorted(f.rule for f in again), sorted(f.rule for f in res.findings if not f.fixed))


class Window(unittest.TestCase):

    def test_all_three_windows_open_and_render(self):
        try:
            from hybrid_patcher import gui
            app = gui.HybridPatcherGUI()
        except Exception as e:                                       # no display, no tkinter
            self.skipTest(f"no GUI available: {e}")
        try:
            with tempfile.TemporaryDirectory() as out:
                os.makedirs(os.path.join(out, "a"))
                with open(os.path.join(out, "per_apk_status.tsv"), "w", encoding="utf-8") as fh:
                    fh.write("name\tstatus\tdetail\tfindings\telapsed_s\na\tpatched\t2 finding(s), 1 fixed\t2\t3.5\n")
                write_json(os.path.join(out, "a", "report.json"),
                           [{"rule": "R3", "severity": "high", "cwe": "CWE-319", "fixed": True},
                            {"rule": "R5", "severity": "medium", "cwe": "", "fixed": False}])
                bulk = gui.BulkApkFixWindow(app.root)
                win = gui.StatsWindow(app.root, out_dir=out)
                win._reload()
                app.root.update()
                self.assertEqual(win.bs.n_findings_total, 2)
                self.assertIn("Findings per rule", gui._render_markdown_report(win.bs))
                bulk.top.destroy()
                win.top.destroy()
        finally:
            app.root.destroy()


if __name__ == "__main__":
    unittest.main()
