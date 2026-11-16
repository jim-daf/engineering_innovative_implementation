"""HybridPatcher rules.

The 7 WebView rules: what each one detects and how it is fixed, for
  * Java / Kotlin source code       -> scan_source()
  * smali code of a decompiled APK  -> scan_smali()
Both return Finding objects. When a rule can fix what it found, the finding carries the
proposed fix as an Edit; apply_fixes() applies those edits to the text.
"""
from __future__ import annotations

import re
from dataclasses import asdict, dataclass
from typing import Dict, Iterator, List, Optional, Tuple


# --------------------------------------------------------------------------- rule catalog

@dataclass(frozen=True)
class Rule:
    id: str          # R1 .. R7
    title: str
    severity: str    # high | medium | low
    cwe: str
    why: str         # what goes wrong
    fix: str         # what the automatic fix does
    note: str        # short comment written above a fixed source line
    reference: str   # Android Developers page

    @property
    def label(self) -> str:
        return "Rule " + self.id[1:]


_DOCS = "https://developer.android.com/reference/android/"

RULES: Dict[str, Rule] = {r.id: r for r in (
    Rule("R1", "Missing shouldOverrideUrlLoading", "medium", "",
         "A WebViewClient without shouldOverrideUrlLoading loads every link inside the WebView. "
         "Links meant for other apps (mailto:, tel:, geo:, market:, app links) end in an error page.",
         "Adds a shouldOverrideUrlLoading override that hands those links to an external app.",
         "",
         _DOCS + "webkit/WebViewClient#shouldOverrideUrlLoading(android.webkit.WebView,%20android.webkit.WebResourceRequest)"),
    Rule("R2", "Missing external link guard", "medium", "",
         "startActivity() inside shouldOverrideUrlLoading throws ActivityNotFoundException when "
         "no installed app can open the link, which crashes the app.",
         "Wraps the startActivity() call in try/catch.",
         "guard added, the app no longer crashes when no app can open the link",
         _DOCS + "content/Context#startActivity(android.content.Intent)"),
    Rule("R3", "Unrestricted Mixed Content", "high", "CWE-319",
         "MIXED_CONTENT_ALWAYS_ALLOW lets a secure https:// page load insecure http:// scripts "
         "and images, which an attacker on the same network can replace.",
         "Sets the mixed content mode to MIXED_CONTENT_NEVER_ALLOW.",
         "mixed content is blocked now, serve every page resource over https",
         _DOCS + "webkit/WebSettings#MIXED_CONTENT_ALWAYS_ALLOW"),
    Rule("R4", "File System Access Enabled", "high", "CWE-200",
         "setAllowFileAccess(true) lets the WebView open file:// URLs, so web content can read "
         "the app's private files.",
         "Sets setAllowFileAccess to false.",
         "file:// access is disabled now, use WebViewAssetLoader for bundled files",
         _DOCS + "webkit/WebSettings#setAllowFileAccess(boolean)"),
    Rule("R5", "URL Handling: script run through loadUrl(\"javascript:...\")", "medium", "",
         "loadUrl(\"javascript:...\") runs the script like a page load, so the app gets no "
         "result back from it.",
         "Replaces the call with evaluateJavascript(script, null), which needs API 19+.",
         "javascript: URL replaced by evaluateJavascript (needs API 19+)",
         _DOCS + "webkit/WebView#evaluateJavascript(java.lang.String,%20android.webkit.ValueCallback%3Cjava.lang.String%3E)"),
    Rule("R6", "Cross-Origin File Access Enabled", "high", "CWE-200",
         "setAllowFileAccessFromFileURLs(true) and setAllowUniversalAccessFromFileURLs(true) "
         "let script in a file:// page read other local files or any website.",
         "Sets both settings to false.",
         "cross-origin access from file:// pages is disabled now",
         _DOCS + "webkit/WebSettings#setAllowFileAccessFromFileURLs(boolean)"),
    Rule("R7", "TLS Certificate Errors Ignored", "high", "CWE-295",
         "Calling proceed() in onReceivedSslError accepts invalid, expired or self-signed "
         "certificates, so anyone on the network can read and change the traffic.",
         "Replaces proceed() with cancel().",
         "invalid certificates are rejected now",
         _DOCS + "webkit/WebViewClient#onReceivedSslError(android.webkit.WebView,%20android.webkit.SslErrorHandler,%20android.net.http.SslError)"),
)}


# --------------------------------------------------------------------------- findings and fixes

@dataclass
class Edit:
    start: int
    end: int
    replacement: str


@dataclass
class Finding:
    rule: str                    # R1 .. R7
    title: str
    severity: str
    cwe: str
    file: str
    line: int
    excerpt: str                 # the offending code
    confidence: str              # regex | structural | absence | smali
    fix_before: str = ""         # the proposed fix: the code before ...
    fix_after: str = ""          # ... and after
    fixed: bool = False          # True once the fix has been applied
    edit: Optional[Edit] = None

    def to_dict(self) -> dict:
        d = asdict(self)
        del d["edit"]
        return d


def _line(text: str, idx: int) -> Tuple[int, int]:
    """(start, end) of the line that contains idx; end excludes the line break."""
    a = text.rfind("\n", 0, idx) + 1
    b = text.find("\n", idx)
    return a, (len(text) if b < 0 else b)


def _make(rule_id: str, path: str, text: str, idx: int, confidence: str,
          edit: Optional[Edit] = None, excerpt: str = "") -> Finding:
    r = RULES[rule_id]
    a, b = _line(text, idx)
    f = Finding(r.id, r.title, r.severity, r.cwe, path, text.count("\n", 0, idx) + 1,
                excerpt or text[a:b].strip()[:200], confidence, edit=edit)
    if edit:
        a, b = _line(text, edit.start)[0], _line(text, edit.end)[1]
        f.fix_before = text[a:b].replace("\r", "").strip("\n")
        f.fix_after = (text[a:edit.start] + edit.replacement
                       + text[edit.end:b]).replace("\r", "").strip("\n")
    return f


def apply_fixes(text: str, findings: List[Finding], comment: Optional[str] = "//") -> str:
    """Apply the proposed fix of every finding to `text` and mark those findings as fixed.
    With `comment`, a `// HybridPatcher (Rule N): ...` note is written above each fixed line."""
    newline = "\r\n" if "\r\n" in text else "\n"
    starts = [0] + [m.end() for m in re.finditer("\n", text)]      # offset of every line
    jobs: List[Tuple[Edit, Optional[Finding]]] = []
    noted = set()
    for f in findings:
        if f.edit is None:
            continue
        jobs.append((f.edit, f))
        note = RULES[f.rule].note
        a = min(starts[min(f.line, len(starts)) - 1], _line(text, f.edit.start)[0])    # line of the finding
        if comment and note and (a, f.rule) not in noted:
            noted.add((a, f.rule))
            indent = re.match(r"[ \t]*", text[a:]).group(0)
            jobs.append((Edit(a, a, f"{indent}{comment} HybridPatcher ({RULES[f.rule].label}): {note}\n"), None))
    limit = len(text)
    for e, f in sorted(jobs, key=lambda j: (j[0].start, j[0].end), reverse=True):
        if e.end > limit:                       # overlaps an edit that was already applied
            continue
        text = text[:e.start] + e.replacement.replace("\r\n", "\n").replace("\n", newline) + text[e.end:]
        limit = e.start
        if f:
            f.fixed = True
    return text


# --------------------------------------------------------------------------- source code rules

_TOKEN = re.compile(r'//[^\n]*|/\*.*?\*/|"""(?:.|\n)*?"""|"(?:\\.|[^"\\\n])*"|\'(?:\\.|[^\'\\\n])*\'', re.S)
_KEYWORDS = re.compile(r"WebViewClient|shouldOverrideUrlLoading|ixedContentMode|llowFileAccess"
                       r"|llowUniversalAccess|javascript:|onReceivedSslError")

# Rule 1: a WebViewClient body (anonymous class or subclass).
_JAVA_CLIENT = re.compile(r"\bnew\s+(?:android\.webkit\.)?WebViewClient\s*\(\s*\)\s*\{"
                          r"|\bclass\s+\w+[^{;]*?\bextends\s+(?:android\.webkit\.)?WebViewClient\b[^{;]*\{")
_KOTLIN_CLIENT = re.compile(r":\s*(?:android\.webkit\.)?WebViewClient\s*\(\s*\)[^{}();=]*\{")
# Rule 2: startActivity outside a try block.
_START_ACTIVITY = re.compile(r"\bstartActivity(?:ForResult)?\s*\(")
_TRY = re.compile(r"\b(?:try|runCatching)\s*\{")
# Rule 5: loadUrl("javascript:...")
_JS_URL = re.compile(r'\bloadUrl\s*\(\s*"{1,3}javascript:')
# Rule 7: proceed() inside onReceivedSslError.
_PROCEED = re.compile(r"\bproceed\b(?=\s*\(\s*\))")


def _setting(setter: str, prop: str, value: str) -> "re.Pattern[str]":
    """An unsafe WebSettings value, written as setX(value) or (Kotlin) x = value.
    Group 1 is the value."""
    return re.compile(rf"(?:\b{setter}\s*\(|(?:\.|^[ \t]*){prop}\s*=)\s*(?:[\w.]+\.)?({value})\b", re.M)


# Rules 3, 4 and 6: (rule, regex, {unsafe value: safe value})
_SETTINGS = (
    ("R3", _setting("setMixedContentMode", "mixedContentMode", "MIXED_CONTENT_ALWAYS_ALLOW|0"),
     {"MIXED_CONTENT_ALWAYS_ALLOW": "MIXED_CONTENT_NEVER_ALLOW", "0": "1"}),
    ("R4", _setting("setAllowFileAccess", "allowFileAccess", "true"), {"true": "false"}),
    ("R6", _setting("setAllow(?:File|Universal)AccessFromFileURLs",
                    "allow(?:File|Universal)AccessFromFileURLs", "true"), {"true": "false"}),
)

_JAVA_OVERRIDE = '''\
// HybridPatcher (Rule 1): links the WebView cannot open itself (mailto:, tel:, geo:,
// market:, app links, ...) are handed to an external app. Add your own host checks here.
@Override
public boolean shouldOverrideUrlLoading(android.webkit.WebView view, String url) {
    if (url == null || url.matches("(?is)(https?|file|about|data|blob|javascript|content):.*")) {
        return false;   // the WebView loads these itself
    }
    try {
        android.content.Intent intent = new android.content.Intent(
                android.content.Intent.ACTION_VIEW, android.net.Uri.parse(url));
        intent.addFlags(android.content.Intent.FLAG_ACTIVITY_NEW_TASK);
        view.getContext().startActivity(intent);
        return true;
    } catch (Exception e) {
        android.util.Log.w("HybridPatcher", "no app can open this link", e);
        return false;
    }
}'''

_KOTLIN_OVERRIDE = '''\
// HybridPatcher (Rule 1): links the WebView cannot open itself (mailto:, tel:, geo:,
// market:, app links, ...) are handed to an external app. Add your own host checks here.
@Suppress("OVERRIDE_DEPRECATION")
override fun shouldOverrideUrlLoading(view: android.webkit.WebView?, url: String?): Boolean {
    if (url == null || url.matches(Regex("(?is)(https?|file|about|data|blob|javascript|content):.*"))) {
        return false   // the WebView loads these itself
    }
    return try {
        val intent = android.content.Intent(android.content.Intent.ACTION_VIEW, android.net.Uri.parse(url))
        intent.addFlags(android.content.Intent.FLAG_ACTIVITY_NEW_TASK)
        view?.context?.startActivity(intent)
        true
    } catch (e: Exception) {
        android.util.Log.w("HybridPatcher", "no app can open this link", e)
        false
    }
}'''


def _mask(src: str, strings: bool = False) -> str:
    """Copy of `src` with comments (and, if `strings`, the content of string literals)
    replaced by spaces. Offsets and line numbers stay the same."""
    def blank(m):
        tok = m.group(0)
        if tok[0] in "\"'":
            if not strings:
                return tok
            q = 3 if tok.startswith('"""') else 1
            return tok[:q] + re.sub(r"[^\n]", " ", tok[q:-q]) + tok[-q:]
        return re.sub(r"[^\n]", " ", tok)
    return _TOKEN.sub(blank, src)


def _close(bare: str, open_idx: int, pair: str = "{}") -> int:
    """Index of the bracket that closes the one at `open_idx`, or -1."""
    depth = 0
    for m in re.compile("[" + re.escape(pair) + "]").finditer(bare, open_idx):
        depth += 1 if m.group(0) == pair[0] else -1
        if depth == 0:
            return m.start()
    return -1


def _bodies(bare: str, name: str) -> Iterator[Tuple[int, int]]:
    """(start, end) of the { body } of every method `name` that is declared in the file."""
    for m in re.finditer(rf"\b{name}\s*\([^()]*\)\s*(?:throws\s[\w.,\s]+?|:\s*[\w.?<>]+\s*)?\{{", bare):
        end = _close(bare, m.end() - 1)
        if end > 0:
            yield m.end(), end


def _top_level_comma(bare: str) -> bool:
    depth = 0
    for c in bare:
        if c in "([{":
            depth += 1
        elif c in ")]}":
            depth -= 1
        elif c == "," and depth == 0:
            return True
    return False


def _override_edit(text: str, open_: int, close: int, kotlin: bool) -> Edit:
    """Rule 1 fix: insert the override just before the brace at `close` that ends the client,
    indented like the members that are already in the block."""
    a = _line(text, close)[0]
    base = re.match(r"[ \t]*", text[a:]).group(0)
    member = re.search(r"\n([ \t]*)\S", text[open_:close])          # first line inside the block
    step = member.group(1)[len(base):] if member and member.group(1).startswith(base) else ""
    step = step or ("\t" if "\t" in base else "    ")
    lines = (_KOTLIN_OVERRIDE if kotlin else _JAVA_OVERRIDE).split("\n")
    body = "".join(f"{base}{step}{ln.replace('    ', step)}\n" for ln in lines)
    if text[a:close].strip():                   # code before the brace on its line: open it up
        return Edit(close, close, "\n" + body + base)
    above = text[_line(text, max(a - 1, 0))[0]:a].strip()           # the line before the brace
    return Edit(a, a, body if not above or above.endswith("{") else "\n" + body)


def _guard_edit(text: str, bare: str, call: int, kotlin: bool) -> Optional[Edit]:
    """Rule 2 fix: wrap the `...startActivity(...)` statement in try/catch. Returns None when
    the call is not a statement on its own line(s); that case is left to the developer."""
    a = _line(text, call)[0]
    indent = re.match(r"[ \t]*", text[a:]).group(0)
    start = a + len(indent)
    close = _close(bare, bare.index("(", call), "()")
    if close < 0 or not re.fullmatch(r"(?:[\w()\[\]?!]+\.)*", bare[start:call]):
        return None                             # something other than a receiver before the call
    tail = re.match(r"[ \t]*;?" if kotlin else r"[ \t]*;", bare[close + 1:])
    if not tail:
        return None
    end = close + 1 + tail.end()
    if bare[end:_line(bare, end)[1]].strip():   # more code after the statement on this line
        return None
    step = "\t" if "\t" in indent else "    "
    caught, semi = ("linkError: Exception", "") if kotlin else ("Exception linkError", ";")
    statement = text[start:end].replace("\n", "\n" + step)
    return Edit(start, end,
                f"try {{\n{indent}{step}{statement}\n"
                f"{indent}}} catch ({caught}) {{\n"
                f"{indent}{step}android.util.Log.w(\"HybridPatcher\", \"no app can open this link\", linkError){semi}\n"
                f"{indent}}}")


def scan_source(text: str, kotlin: bool, path: str = "",
                min_sdk: Optional[int] = None) -> List[Finding]:
    """Apply the 7 rules to one Java or Kotlin file."""
    if not _KEYWORDS.search(text):
        return []
    # `bare` is the code without comments and without the content of string literals, so the
    # rules never match inside either. Only Rule 5 has to look into a string.
    bare = _mask(text, strings=True)
    found: Dict[Tuple[str, int], Finding] = {}

    def add(rule_id, idx, confidence, edit=None, excerpt=""):
        found.setdefault((rule_id, idx), _make(rule_id, path, text, idx, confidence, edit, excerpt))

    # Rule 1: a WebViewClient that does not override shouldOverrideUrlLoading
    for m in (_KOTLIN_CLIENT if kotlin else _JAVA_CLIENT).finditer(bare):
        end = _close(bare, m.end() - 1)
        if end > 0 and "shouldOverrideUrlLoading" not in bare[m.end():end]:
            a, b = _line(text, m.start())
            add("R1", m.start(), "absence", _override_edit(text, m.end() - 1, end, kotlin),
                "WebViewClient without shouldOverrideUrlLoading: " + text[a:b].strip()[:120])

    # Rule 2: startActivity inside shouldOverrideUrlLoading, outside a try block
    own_helper = any(_bodies(bare, "startActivity(?:ForResult)?"))     # the file's own method
    for start, end in _bodies(bare, "shouldOverrideUrlLoading"):
        tries = [(t.end() - 1, _close(bare, t.end() - 1)) for t in _TRY.finditer(bare, start, end)]
        for call in _START_ACTIVITY.finditer(bare, start, end):
            if any(a < call.start() < b for a, b in tries):
                continue
            if own_helper and not bare[:call.start()].rstrip().endswith("."):
                continue                        # a call to that helper, not to Context.startActivity
            add("R2", call.start(), "structural", _guard_edit(text, bare, call.start(), kotlin))

    # Rules 3, 4 and 6: an unsafe WebSettings value
    for rule_id, rx, safe in _SETTINGS:
        for m in rx.finditer(bare):
            if kotlin or "(" in m.group(0):     # the property form is Kotlin only
                add(rule_id, m.start(), "regex", Edit(m.start(1), m.end(1), safe[m.group(1)]))

    # Rule 5: loadUrl("javascript:...") -> evaluateJavascript("...", null)
    for m in _JS_URL.finditer(_mask(text)):
        paren = bare.index("(", m.start())
        end = _close(bare, paren, "()")
        a, b = _line(text, m.start())
        edit, excerpt = None, text[a:b].strip()[:200]
        if min_sdk is not None and min_sdk < 19:
            excerpt += "   [not fixed: the project's minSdk is below 19]"
        elif end < 0 or _top_level_comma(bare[paren + 1:end]):
            excerpt += "   [not fixed: loadUrl is called with more than one argument]"
        else:
            edit = Edit(m.start(), end + 1,
                        "evaluateJavascript" + text[paren:m.end() - 11] + text[m.end():end] + ", null)")
        add("R5", m.start(), "regex", edit, excerpt)

    # Rule 7: proceed() inside onReceivedSslError -> cancel()
    for start, end in _bodies(bare, "onReceivedSslError"):
        for call in _PROCEED.finditer(bare, start, end):
            add("R7", call.start(), "structural", Edit(call.start(), call.end(), "cancel"))

    return sorted(found.values(), key=lambda f: (f.line, f.rule))


# --------------------------------------------------------------------------- smali (APK) rules

# Rules 3, 4 and 6: setter -> (rule, unsafe value, safe value)
_SMALI_SETTERS = {
    ";->setMixedContentMode(I)V": ("R3", 0, 1),
    ";->setAllowFileAccess(Z)V": ("R4", 1, 0),
    ";->setAllowFileAccessFromFileURLs(Z)V": ("R6", 1, 0),
    ";->setAllowUniversalAccessFromFileURLs(Z)V": ("R6", 1, 0),
}
# Instructions whose first register is only read. Every other instruction writes it.
_SMALI_READS = ("invoke", "return", "throw", "if-", "iput", "sput", "aput", "monitor",
                "packed-switch", "sparse-switch", "fill-array-data", "check-cast", "filled-new-array")
_SMALI_KEYWORDS = ("Landroid/webkit/WebViewClient;", "setMixedContentMode", "setAllowFileAccess",
                   "setAllowUniversalAccessFromFileURLs", '"javascript:', "onReceivedSslError",
                   "shouldOverrideUrlLoading")

# Rule 1 fix for APKs: the Java override above, compiled with d8 and disassembled by apktool.
_SMALI_OVERRIDE = '''\
.method public shouldOverrideUrlLoading(Landroid/webkit/WebView;Ljava/lang/String;)Z
    .locals 3

    const/4 v0, 0x0

    if-eqz p2, :cond_1

    const-string v1, "(?is)(https?|file|about|data|blob|javascript|content):.*"

    invoke-virtual {p2, v1}, Ljava/lang/String;->matches(Ljava/lang/String;)Z

    move-result v1

    if-eqz v1, :cond_0

    goto :goto_0

    :cond_0
    :try_start_0
    new-instance v1, Landroid/content/Intent;

    const-string v2, "android.intent.action.VIEW"

    invoke-static {p2}, Landroid/net/Uri;->parse(Ljava/lang/String;)Landroid/net/Uri;

    move-result-object p2

    invoke-direct {v1, v2, p2}, Landroid/content/Intent;-><init>(Ljava/lang/String;Landroid/net/Uri;)V

    const/high16 p2, 0x10000000

    invoke-virtual {v1, p2}, Landroid/content/Intent;->addFlags(I)Landroid/content/Intent;

    invoke-virtual {p1}, Landroid/webkit/WebView;->getContext()Landroid/content/Context;

    move-result-object p1

    invoke-virtual {p1, v1}, Landroid/content/Context;->startActivity(Landroid/content/Intent;)V
    :try_end_0
    .catch Ljava/lang/Exception; {:try_start_0 .. :try_end_0} :catch_0

    const/4 p1, 0x1

    return p1

    :catch_0
    move-exception p1

    const-string p2, "HybridPatcher"

    const-string v1, "no app can open this link"

    invoke-static {p2, v1, p1}, Landroid/util/Log;->w(Ljava/lang/String;Ljava/lang/String;Ljava/lang/Throwable;)I

    :cond_1
    :goto_0
    return v0
.end method'''


class _Method:
    """One smali method: where its labels are, what jumps to them, what writes each register."""

    def __init__(self, header: str, body: List[Tuple[int, str]]):
        self.header, self.body = header, body
        self.name = header.split("(")[0].split()[-1]
        self.labels: Dict[str, int] = {}
        self.jumps: Dict[str, list] = {}                # label -> lines that can jump to it
        self.tries: List[Tuple[str, str]] = []          # (try start label, try end label)
        self.writes: Dict[str, List[Tuple[int, Optional[int], str]]] = {}   # reg -> (line, value, text)
        table = False
        for i, s in body:
            if s.startswith((".packed-switch", ".sparse-switch")):
                table = True
            elif s.startswith(".end "):
                table = False
            elif table:                                 # switch table: a jump from "anywhere"
                self.jumps.setdefault(s[s.find(":"):], []).append(-1)
            elif s.startswith(":"):
                self.labels[s] = i
            elif s.startswith(".catch"):
                m = re.search(r"\{(:\w+) \.\. (:\w+)\} (:\w+)", s)
                if m:                                   # the handler is entered from its try range
                    self.tries.append((m.group(1), m.group(2)))
                    self.jumps.setdefault(m.group(3), []).extend(m.group(1, 2))
            elif not s.startswith("."):
                op, _, rest = s.partition(" ")
                target = s.rsplit(" ", 1)[-1]
                if target.startswith(":"):
                    self.jumps.setdefault(target, []).append(i)
                if not op.startswith(_SMALI_READS):     # every other instruction writes its first register
                    value = None
                    if op in ("const/4", "const/16", "const", "const/high16"):
                        try:
                            value = int(rest.split(",")[1], 16)
                        except (IndexError, ValueError):
                            pass
                    self.writes.setdefault(rest.split(",")[0].strip(), []).append((i, value, s))

    def guarded(self, i: int) -> bool:
        """Is line i inside a try range?"""
        return any(self.labels.get(a, i) < i < self.labels.get(b, i) for a, b in self.tries)

    def constant(self, i: int, reg: str) -> Optional[Tuple[int, Optional[int], str]]:
        """The constant that register `reg` holds when line i runs, as (line, value, text),
        or None when that is not certain."""
        writes = self.writes.get(reg, [])
        before = [w for w in writes if w[0] < i]
        if before and before[-1][1] is not None:
            # The last write is a constant. It is the value at line i unless something
            # jumps to a label between the two from outside that stretch of code.
            w = before[-1][0]
            sources = [j for label, at in self.labels.items() if w < at < i
                       for j in self.jumps.get(label, [])]
            if all(w < (self.labels.get(j, -1) if isinstance(j, str) else j) < i for j in sources):
                return before[-1]
        if reg.startswith("v") and writes and writes[0][1] is not None \
                and len({value for _, value, _ in writes}) == 1:
            return writes[0]                            # the register only ever holds this constant
        return None


def scan_smali(text: str, path: str = "") -> List[Finding]:
    """Apply the 7 rules to one .smali file (one class of a decompiled APK).
    Rules 1, 3, 4, 6 and 7 come with a fix; rules 2 and 5 are reported only."""
    if not any(k in text for k in _SMALI_KEYWORDS):
        return []
    lines = text.split("\n")
    offsets, pos = [], 0
    for ln in lines:
        offsets.append(pos)
        pos += len(ln) + 1
    out: List[Finding] = []
    parent = source = header = ""
    class_line, has_override = 0, False
    body: List[Tuple[int, str]] = []

    def check(m: _Method) -> None:
        src_line, js_url = 0, False

        def add(rule_id, i, what, new_lines=None):
            where = f"{m.name}()" + (f" at {source}:{src_line}" if source and src_line else "")
            raw = lines[i].rstrip("\r")
            edit = Edit(offsets[i], offsets[i] + len(raw), "\n".join(new_lines)) if new_lines else None
            out.append(_make(rule_id, path, text, offsets[i], "smali", edit, f"{what} in {where}"))

        for i, s in m.body:
            if s.startswith(".line "):
                src_line = int(s.split()[1])
            elif s.startswith("const-string"):
                js_url = js_url or s.partition(",")[2].strip().startswith('"javascript:')
            if not s.startswith("invoke-"):
                continue
            regs, _, target = s.partition("}")
            arg = re.split(r"[,.]+", regs.split("{")[-1])[-1].strip()       # the last register
            raw = lines[i].rstrip("\r")
            indent = raw[:len(raw) - len(raw.lstrip())]
            for setter, (rule_id, bad, good) in _SMALI_SETTERS.items():
                known = m.constant(i, arg) if target.endswith(setter) else None
                if known and known[1] == bad:
                    # set the safe value just for this call, then give the register its value back
                    add(rule_id, i, f"{setter[3:].split('(')[0]}() called with {bad:#x}",
                        [f"{indent}{known[2].split()[0]} {arg}, {good:#x}", raw, indent + known[2]])
            if "onReceivedSslError(" in m.header and target.endswith("SslErrorHandler;->proceed()V"):
                add("R7", i, "SslErrorHandler.proceed()", [raw.replace("->proceed()V", "->cancel()V")])
            elif js_url and target.endswith(";->loadUrl(Ljava/lang/String;)V"):
                add("R5", i, 'loadUrl() with a "javascript:" URL')
                js_url = False
            elif " shouldOverrideUrlLoading(" in m.header and not m.guarded(i) \
                    and re.search(r";->startActivity(ForResult)?\(", target):
                add("R2", i, "startActivity() without try/catch")

    for i, raw in enumerate(lines):
        s = raw.strip()
        if not s:
            continue
        if header:                                              # inside a method
            if s == ".end method":
                check(_Method(header, body))
                header = ""
            else:
                body.append((i, s))
        elif s.startswith(".class "):
            class_line = i
        elif s.startswith(".super "):
            parent = s.split()[-1]
        elif s.startswith(".source ") and s.endswith(('.java"', '.kt"')):
            source = s.split('"')[1]
        elif s.startswith(".method "):
            header, body = s, []
            has_override = has_override or " shouldOverrideUrlLoading(" in s

    # Rule 1: a direct WebViewClient subclass without shouldOverrideUrlLoading
    if parent == "Landroid/webkit/WebViewClient;" and not has_override:
        end = len(text)
        out.append(_make("R1", path, text, offsets[class_line], "smali",
                         Edit(end, end, ("" if text.endswith("\n") else "\n") + "\n" + _SMALI_OVERRIDE + "\n"),
                         "WebViewClient without shouldOverrideUrlLoading: " + lines[class_line].strip()))
    return sorted(out, key=lambda f: (f.line, f.rule))
