# HybridPatcher

HybridPatcher finds 7 WebView issues in hybrid Android apps and patches them.
It takes an **APK** or a **source code folder**, applies the 7 rules, proposes a fix for every
finding, writes a report with all detections and fixes, and applies the fixes if you ask for it.
For an APK it then rebuilds and signs a patched APK.



## Requirements

| Needed for | What |
|---|---|
| Everything | Python 3.10 or newer (tested with 3.10.5). The window uses tkinter, which ships with Python |
| APKs | Java 8 or newer on `PATH` (tested with Java 17). `apktool.jar` and `uber-apk-signer.jar` are already in `hybrid_patcher/tools/` |
| Charts in the statistics window | `pip install pillow` |
| Drag and drop into the window (optional) | `pip install tkinterdnd2`. Without it, use the *Add* buttons |

## Run it

Run these from the `implementation` folder.

```
python -m hybrid_patcher --gui                        open the window
python -m hybrid_patcher --rules                      list the 7 rules
python -m hybrid_patcher --src ./repo                 report on a source folder
python -m hybrid_patcher --src ./repo --patch         show the proposed fixes as a diff
python -m hybrid_patcher --src ./repo --patch-apply   fix the source files in place
python -m hybrid_patcher --apk app.apk                report on an APK
python -m hybrid_patcher --fix-apks --apk-dir ./apks --out-dir ./out
                                                      fix many APKs, one folder per APK
```

`--format text|md|json` and `--out FILE` choose the report format and where it goes.

In the window:

1. Add APK files or source folders to the list.
2. Choose **Detect only** (report) or **Detect + Fix** (report plus patched APK / patched copy of the source).
3. Press **Start**. The log shows every step; the report is written to the output folder.

**Bulk APK fix...** runs a whole folder of APKs with one status row per APK.
**Statistics...** shows the result of a bulk run: apps with and without findings, findings per rule,
fix status, CWEs, timing and a table per APK.

## The 7 rules

| Rule | Reported when | Fix in source code | Fix in an APK |
|---|---|---|---|
| 1. Missing `shouldOverrideUrlLoading` | A `WebViewClient` (anonymous or subclass) does not override `shouldOverrideUrlLoading` | Adds an override that hands non-web links (`mailto:`, `tel:`, `geo:`, `market:`, app links) to an external app, inside try/catch | Adds the same method to the class |
| 2. Missing external link guard | `startActivity(...)` inside `shouldOverrideUrlLoading` is not inside a `try` block | Wraps the call in try/catch | Report only |
| 3. Unrestricted Mixed Content | `setMixedContentMode(MIXED_CONTENT_ALWAYS_ALLOW)` (or `0`) | `MIXED_CONTENT_NEVER_ALLOW` | Passes `1` instead of `0` |
| 4. File System Access Enabled | `setAllowFileAccess(true)` | `false` | Passes `0` instead of `1` |
| 5. `loadUrl("javascript:...")` | `loadUrl` is called with a string that starts with `javascript:` | `evaluateJavascript("...", null)` | Report only |
| 6. Cross-Origin File Access Enabled | `setAllowFileAccessFromFileURLs(true)` or `setAllowUniversalAccessFromFileURLs(true)` | `false` | Passes `0` instead of `1` |
| 7. TLS Certificate Errors Ignored | `proceed()` is called inside `onReceivedSslError` | `cancel()` | `cancel()` |

Rules 3, 4 and 6 also match the Kotlin property form (`settings.allowFileAccess = true`).
`python -m hybrid_patcher --rules` prints the reason, the fix and the Android Developers link of each rule.

Rule 2 and Rule 5 are report-only for APKs because their fix changes the structure of a method
(a new try/catch range, a different method call with one more argument). That is safe to do in
source code and not safe to do blindly in bytecode.

### The regexes (source code)

Comments and the content of string literals are blanked out before matching, so a rule never
matches commented-out code or text inside a string. Only Rule 5 looks into strings.

```python
# Rule 1: the start of a WebViewClient body; reported if the body has no shouldOverrideUrlLoading
JAVA    r"\bnew\s+(?:android\.webkit\.)?WebViewClient\s*\(\s*\)\s*\{"
        r"|\bclass\s+\w+[^{;]*?\bextends\s+(?:android\.webkit\.)?WebViewClient\b[^{;]*\{"
KOTLIN  r":\s*(?:android\.webkit\.)?WebViewClient\s*\(\s*\)[^{}();=]*\{"

# Rule 2: inside a shouldOverrideUrlLoading body, a call that is not inside a try block
CALL    r"\bstartActivity(?:ForResult)?\s*\("
TRY     r"\b(?:try|runCatching)\s*\{"

# Rules 3, 4, 6: setX(value) or (Kotlin) x = value; group 1 is the unsafe value
r"(?:\b{setter}\s*\(|(?:\.|^[ \t]*){property}\s*=)\s*(?:[\w.]+\.)?({value})\b"
#   Rule 3: setMixedContentMode / mixedContentMode            value MIXED_CONTENT_ALWAYS_ALLOW|0
#   Rule 4: setAllowFileAccess / allowFileAccess              value true
#   Rule 6: setAllow(?:File|Universal)AccessFromFileURLs      value true

# Rule 5
r'\bloadUrl\s*\(\s*"{1,3}javascript:'

# Rule 7: inside an onReceivedSslError body
r"\bproceed\b(?=\s*\(\s*\))"
```

A fix is not proposed when it would not be correct:

- Rule 5: the project's `minSdk` is below 19 (`evaluateJavascript` does not exist there), or
  `loadUrl` is called with two arguments.
- Rule 2: the `startActivity` call is part of a larger expression instead of a statement of its own.

Such findings are still reported, with the reason.

### The rules on an APK

The APK is decoded with apktool and the rules are applied to the decoded classes (smali), one
method at a time:

- **Rules 3, 4, 6**: a call to the setter whose argument register is known to hold the unsafe
  constant. The fix sets the safe value just for that call and then restores the register, so
  other code that reuses the register is not affected:

  ```diff
  -     invoke-virtual {v0, v3}, Landroid/webkit/WebSettings;->setMixedContentMode(I)V
  +     const/4 v3, 0x1
  +     invoke-virtual {v0, v3}, Landroid/webkit/WebSettings;->setMixedContentMode(I)V
  +     const/4 v3, 0x0
  ```

  If the value is not a known constant (it comes from a parameter, a field or a branch), nothing
  is reported.
- **Rule 7**: `SslErrorHandler;->proceed()V` inside `onReceivedSslError` becomes `->cancel()V`.
- **Rule 1**: a class whose `.super` is `Landroid/webkit/WebViewClient;` and that has no
  `shouldOverrideUrlLoading` method gets one (the Java fix, compiled to bytecode).
- **Rule 2**: `startActivity` inside `shouldOverrideUrlLoading`, outside every try range.
- **Rule 5**: `loadUrl(String)` after a `const-string "javascript:..."` in the same method.

Classes of well-known libraries (androidx, Kotlin, Google, ad SDKs, ...) are skipped; the list is
`LIBRARY_PREFIXES` in `pipeline.py`.

## The two pipelines

**APK:** input APK → decode (apktool) → apply the rules to the decoded classes → propose fixes →
report → apply the fixes → rebuild (apktool) → sign (uber-apk-signer) → `patched_<name>.apk`

**Source code:** input folder → apply the rules to every `.java` / `.kt` file → propose fixes →
report → apply the fixes to a copy (`patched_<folder>`), or in place with `--patch-apply`

Every fixed source line gets a comment above it, for example
`// HybridPatcher (Rule 4): file:// access is disabled now, use WebViewAssetLoader for bundled files`.

### The report

`report.md` and `report.json` are written to the output folder. For each rule the report gives the
severity, the reason, the fix and the Android Developers link; for each finding the file, the line
and the change:

```diff
- settings.setAllowFileAccess(true);
+ settings.setAllowFileAccess(false);
```

### Result of an APK

| Status | Meaning |
|---|---|
| `patched` | Fixes applied, `patched_<name>.apk` built and signed |
| `report-only` | Findings, but none with an APK fix (Rule 2, Rule 5) |
| `no-findings` | No rule matched |
| `build-failed` | Fixes applied but the APK could not be rebuilt; see `run.log` |
| `fail` | The APK could not be decoded |
| `crash` / `skip` | Unexpected error / file not found |

A bulk run writes one folder per APK (`report.md`, `report.json`, `run.log`, `status`, the patched
APK) and `per_apk_status.tsv` for the whole run. Running it again skips the APKs that are done.

The patched APK is signed with a debug key, not with the developer's key. To install it on a
device, the original app has to be uninstalled first. For a release, fix the source code.

## Code

| File | Lines | What |
|---|---:|---|
| `hybrid_patcher/rules.py` | 597 | The 7 rules: detection and fix, for source code and for decoded APKs |
| `hybrid_patcher/pipeline.py` | 408 | Source pipeline, APK pipeline, bulk run, reports |
| `hybrid_patcher/__main__.py` | 109 | Command line |
| `hybrid_patcher/gui.py` | 1639 | The windows  |
| `hybrid_patcher/stats.py`, `charts.py` | 832 | Numbers and charts for the statistics window |
| `tests/test_hybrid_patcher.py` | 424 | 19 tests, with sample apps in `tests/fixtures` and an APK in `tests/apks` |

Run the tests with `python -m unittest discover -s tests`.


## Limits

- Rule 7 replaces every `proceed()` in `onReceivedSslError`, also one that the app only calls
  after asking the user or when a setting allows it.
- Rule 1 looks at classes that extend `WebViewClient` directly. A client that extends another
  class of the app (which extends `WebViewClient`) is not reported.
- Rule 1's added method opens links with `Intent.ACTION_VIEW`. Review it if the app must restrict
  which links may leave the app.
- Rules 3, 4 and 6 on an APK need the value to be a constant in the same method.
- An APK protected by a packer, or one that apktool cannot rebuild, ends as `fail` or `build-failed`.
