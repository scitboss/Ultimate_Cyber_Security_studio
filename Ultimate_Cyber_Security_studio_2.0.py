#!/usr/bin/env python3
"""
SCIT-BOSS Ultimate Cyber Security Studio
Version 2.0 Ultimate Edition - 100+ Security Tools
Developed By: SCIT-BOSS
Websites: https://www.scitboss.com | https://www.softkeybazar.com
Technology: Python 3.11+ / Tkinter / Standard Library only
"""

import sys
import os
import re
import json
import csv
import ssl
import socket
import time
import uuid
import html
import gzip
import zlib
import hashlib
import secrets
import shutil
import logging
import platform
import threading
import queue
import traceback
import tempfile
import ipaddress
import webbrowser
import urllib.request
import urllib.parse
import urllib.error
import http.client
from datetime import datetime, timedelta, timezone
from pathlib import Path
from dataclasses import dataclass, field, asdict
from typing import Optional, List, Dict, Any, Tuple, Callable
from collections import Counter
from html.parser import HTMLParser

import tkinter as tk
from tkinter import ttk, filedialog, messagebox
import base64

# ============================================================
# CONSTANTS
# ============================================================

APP_NAME = "SCIT-BOSS Ultimate Cyber Security Studio"
APP_SHORT = "SCIT-BOSS"
APP_VERSION = "2.0 Ultimate Edition"
DEVELOPER = "SCIT-BOSS"
DEV_SITE = "https://www.scitboss.com"
DEV_MARKET = "https://www.softkeybazar.com"

BASE_DIR = Path.home() / "SCITBOSS_Security_Studio"
SETTINGS_FILE = BASE_DIR / "settings.json"
HISTORY_FILE = BASE_DIR / "scan_history.json"
REPORTS_DIR = BASE_DIR / "reports"
EXPORTS_DIR = BASE_DIR / "exports"
BACKUPS_DIR = BASE_DIR / "backups"
LOGS_DIR = BASE_DIR / "logs"

for d in (BASE_DIR, REPORTS_DIR, EXPORTS_DIR, BACKUPS_DIR, LOGS_DIR):
    d.mkdir(parents=True, exist_ok=True)

logging.basicConfig(
    filename=str(LOGS_DIR / "application.log"),
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
)
log = logging.getLogger("SCITBOSS")

# ============================================================
# THEMES
# ============================================================

DARK_THEME = {
    "bg": "#090F1D", "sidebar": "#101B2E", "card": "#17243B",
    "card2": "#1D2C46", "accent": "#00D5FF", "success": "#13D69A",
    "warning": "#FFB020", "critical": "#FF4057", "text": "#F4F7FC",
    "muted": "#91A4BD", "border": "#243452", "input_bg": "#0D1727",
}

SEVERITY_COLORS = {
    "Critical": "#FF4057", "High": "#FF6B35", "Medium": "#FFB020",
    "Low": "#00D5FF", "Informational": "#91A4BD", "Passed": "#13D69A",
}

SEVERITY_WEIGHTS = {
    "Critical": 10, "High": 7, "Medium": 4, "Low": 2, "Informational": 0,
}

# ============================================================
# DATA MODELS
# ============================================================

@dataclass
class Finding:
    fid: str
    tool: str
    url: str
    component: str
    title: str
    category: str
    severity: str
    confidence: str
    detection_method: str
    evidence: str
    description: str
    impact: str
    recommended_fix: str
    example_fix_code: str = ""
    verification: str = ""
    timestamp: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    status: str = "Open"

    def to_dict(self):
        return asdict(self)


@dataclass
class CheckResult:
    name: str
    tool: str
    status: str
    detail: str = ""
    evidence: str = ""
    severity_if_failed: str = "Informational"

    def to_dict(self):
        return asdict(self)


@dataclass
class ModuleResult:
    tool: str
    checks: List[CheckResult] = field(default_factory=list)
    findings: List[Finding] = field(default_factory=list)
    data: Dict[str, Any] = field(default_factory=dict)
    duration: float = 0.0


# ============================================================
# SETTINGS
# ============================================================

DEFAULT_SETTINGS = {
    "theme": "dark", "font_size": 10,
    "report_dir": str(REPORTS_DIR),
    "connection_timeout": 10, "read_timeout": 15,
    "max_response_size": 5 * 1024 * 1024,
    "requests_per_second": 4.0,
    "ssl_verify": True,
    "check_internal_links": True,
    "user_agent": "SCIT-BOSS-Security-Studio/2.0 (Authorized Audit)",
    "expire_warn_days": 30, "expire_high_days": 7,
    "perf_slow_ms": 2000, "perf_large_kb": 500,
    "animations": True,
}


class AppConfig:
    def __init__(self):
        self.data = dict(DEFAULT_SETTINGS)
        self.load()

    def load(self):
        try:
            if SETTINGS_FILE.exists():
                with open(SETTINGS_FILE, "r", encoding="utf-8") as f:
                    self.data.update(json.load(f))
        except Exception as e:
            log.warning("Load settings failed: %s", e)

    def save(self):
        try:
            with open(SETTINGS_FILE, "w", encoding="utf-8") as f:
                json.dump(self.data, f, indent=2)
        except Exception as e:
            log.error("Save settings failed: %s", e)

    def get(self, key, default=None):
        return self.data.get(key, default)

    def set(self, key, value):
        self.data[key] = value


# ============================================================
# SECURITY POLICY
# ============================================================

class SecurityPolicy:
    BLOCKED_NETS = [
        ipaddress.ip_network("0.0.0.0/8"), ipaddress.ip_network("10.0.0.0/8"),
        ipaddress.ip_network("100.64.0.0/10"), ipaddress.ip_network("127.0.0.0/8"),
        ipaddress.ip_network("169.254.0.0/16"), ipaddress.ip_network("172.16.0.0/12"),
        ipaddress.ip_network("192.168.0.0/16"), ipaddress.ip_network("::1/128"),
        ipaddress.ip_network("fc00::/7"), ipaddress.ip_network("fe80::/10"),
    ]

    def __init__(self, local_mode=False):
        self.local_mode = local_mode
        self._last = 0.0
        self._lock = threading.Lock()

    def is_public(self, ip_str):
        try:
            ip = ipaddress.ip_address(ip_str)
            return not any(ip in n for n in self.BLOCKED_NETS)
        except ValueError:
            return False

    def resolve_check(self, hostname):
        if self.local_mode:
            return True, "Local"
        try:
            infos = socket.getaddrinfo(hostname, None)
        except socket.gaierror as e:
            return False, f"DNS failed: {e}"
        for info in infos:
            if not self.is_public(info[4][0]):
                return False, f"Blocked: {info[4][0]}"
        return True, "OK"

    def throttle(self, rps):
        with self._lock:
            interval = 1.0 / max(rps, 0.1)
            elapsed = time.time() - self._last
            if elapsed < interval:
                time.sleep(interval - elapsed)
            self._last = time.time()


class URLValidator:
    @staticmethod
    def normalize(url):
        url = url.strip()
        if not url:
            raise ValueError("URL is empty")
        if "://" not in url:
            url = "https://" + url
        parsed = urllib.parse.urlparse(url)
        if parsed.scheme not in ("http", "https"):
            raise ValueError("Only HTTP/HTTPS")
        if not parsed.hostname:
            raise ValueError("Missing hostname")
        return url


# ============================================================
# HTTP CLIENT
# ============================================================

@dataclass
class HTTPResponse:
    url: str
    final_url: str
    status: int
    reason: str
    headers: List[Tuple[str, str]]
    body: bytes
    elapsed: float
    redirects: List[str] = field(default_factory=list)
    error: Optional[str] = None


class HTTPClient:
    def __init__(self, config, policy):
        self.config = config
        self.policy = policy
        self._cancelled = threading.Event()

    def cancel(self):
        self._cancelled.set()

    def fetch(self, url, method="GET", max_redirects=5):
        url = URLValidator.normalize(url)
        start = time.time()
        redirects = []
        current = url

        for _ in range(max_redirects + 1):
            if self._cancelled.is_set():
                return HTTPResponse(url, current, 0, "Cancelled", [], b"", time.time() - start,
                                    redirects, "Cancelled")
            parsed = urllib.parse.urlparse(current)
            if not self.policy.local_mode:
                ok, msg = self.policy.resolve_check(parsed.hostname or "")
                if not ok:
                    return HTTPResponse(url, current, 0, "Blocked", [], b"",
                                        time.time() - start, redirects, msg)
                self.policy.throttle(float(self.config.get("requests_per_second", 4.0)))

            try:
                ctx = None
                if parsed.scheme == "https":
                    ctx = ssl.create_default_context() if self.config.get("ssl_verify", True) \
                        else ssl._create_unverified_context()

                req = urllib.request.Request(current, method=method, headers={
                    "User-Agent": self.config.get("user_agent"),
                    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
                    "Accept-Encoding": "gzip, deflate",
                    "Accept-Language": "en-US,en;q=0.5",
                    "Connection": "close",
                })

                args = dict(timeout=float(self.config.get("read_timeout", 15)))
                if ctx:
                    args["context"] = ctx

                resp = urllib.request.urlopen(req, **args)
                body = resp.read(int(self.config.get("max_response_size", 5 * 1024 * 1024)))
                headers = list(resp.headers.items())
                enc = (resp.headers.get("Content-Encoding") or "").lower()
                if "gzip" in enc:
                    try: body = gzip.decompress(body)
                    except: pass
                return HTTPResponse(url, current, resp.status, resp.reason, headers,
                                    body, time.time() - start, redirects)

            except urllib.error.HTTPError as e:
                try: body = e.read() if e.fp else b""
                except: body = b""
                headers = list(e.headers.items()) if e.headers else []
                if 300 <= e.code < 400 and e.headers:
                    loc = e.headers.get("Location")
                    if loc:
                        redirects.append(current)
                        current = urllib.parse.urljoin(current, loc)
                        continue
                return HTTPResponse(url, current, e.code, str(e.reason), headers,
                                    body, time.time() - start, redirects)

            except urllib.error.URLError as e:
                return HTTPResponse(url, current, 0, str(e.reason), [], b"",
                                    time.time() - start, redirects, str(e.reason))
            except Exception as e:
                return HTTPResponse(url, current, 0, type(e).__name__, [], b"",
                                    time.time() - start, redirects, str(e))

        return HTTPResponse(url, current, 0, "Too many redirects", [], b"",
                            time.time() - start, redirects, "Redirect limit")


# ============================================================
# HTML PARSER (enhanced)
# ============================================================

class HTMLPageParser(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.title = ""
        self.meta = {}
        self.headings = []
        self.links = []
        self.images = []
        self.scripts = []
        self.stylesheets = []
        self.forms = []
        self.inputs = []
        self.buttons = []
        self.labels = []
        self.iframes = []
        self.videos = []
        self.audios = []
        self.canvases = 0
        self.comments = []
        self._in_title = False
        self._in_comment = False
        self._current_form = None
        self._current_heading = None
        self._heading_text = ""
        self._anchor_text = ""
        self._button_text = ""
        self._in_anchor = False
        self._in_button = False
        self._html_lang = ""
        self._meta_viewport = ""
        self._has_doctype = False
        self._text_content = []

    def handle_starttag(self, tag, attrs):
        tag = tag.lower()
        d = {k.lower(): (v or "") for k, v in attrs}
        if tag == "html":
            self._html_lang = d.get("lang", "")
        elif tag == "title":
            self._in_title = True
        elif tag == "meta":
            name = d.get("name", "").lower()
            prop = d.get("property", "").lower()
            content = d.get("content", "")
            if name: self.meta[name] = content
            if prop: self.meta[prop] = content
            if name == "viewport": self._meta_viewport = content
        elif tag in ("h1", "h2", "h3", "h4", "h5", "h6"):
            self._current_heading = tag
            self._heading_text = ""
        elif tag == "a":
            self.links.append({"href": d.get("href", ""), "text": "",
                               "rel": d.get("rel", ""), "target": d.get("target", "")})
            self._in_anchor = True
            self._anchor_text = ""
        elif tag == "img":
            self.images.append({"src": d.get("src", ""), "alt": d.get("alt", None),
                                "width": d.get("width", ""), "height": d.get("height", "")})
        elif tag == "script":
            if d.get("src"): self.scripts.append(d["src"])
        elif tag == "link":
            rel = d.get("rel", "").lower()
            if "stylesheet" in rel and d.get("href"):
                self.stylesheets.append(d["href"])
        elif tag == "form":
            self._current_form = {
                "action": d.get("action", ""), "method": d.get("method", "get").lower(),
                "inputs": [], "has_csrf": False, "autocomplete": d.get("autocomplete", ""),
            }
            self.forms.append(self._current_form)
        elif tag == "input":
            inp = {
                "type": d.get("type", "text").lower(), "name": d.get("name", ""),
                "id": d.get("id", ""), "autocomplete": d.get("autocomplete", ""),
                "placeholder": d.get("placeholder", ""),
            }
            self.inputs.append(inp)
            if self._current_form is not None:
                self._current_form["inputs"].append(inp)
                name_l = (d.get("name") or "").lower()
                if "csrf" in name_l or "token" in name_l:
                    self._current_form["has_csrf"] = True
        elif tag == "label":
            self.labels.append(d.get("for", ""))
        elif tag == "button":
            self._in_button = True
            self._button_text = ""
            self.buttons.append({"type": d.get("type", ""), "text": ""})
        elif tag == "iframe":
            self.iframes.append({"src": d.get("src", ""), "sandbox": d.get("sandbox", ""),
                                 "title": d.get("title", "")})
        elif tag == "video":
            self.videos.append({"src": d.get("src", ""), "controls": d.get("controls", None)})
        elif tag == "audio":
            self.audios.append({"src": d.get("src", ""), "controls": d.get("controls", None)})
        elif tag == "canvas":
            self.canvases += 1

    def handle_endtag(self, tag):
        tag = tag.lower()
        if tag == "title": self._in_title = False
        elif tag == self._current_heading:
            self.headings.append((self._current_heading, self._heading_text.strip()))
            self._current_heading = None
        elif tag == "a":
            if self.links: self.links[-1]["text"] = self._anchor_text.strip()
            self._in_anchor = False
        elif tag == "form": self._current_form = None
        elif tag == "button":
            if self.buttons: self.buttons[-1]["text"] = self._button_text.strip()
            self._in_button = False

    def handle_data(self, data):
        if self._in_title: self.title += data
        if self._current_heading: self._heading_text += data
        if self._in_anchor: self._anchor_text += data
        if self._in_button: self._button_text += data
        self._text_content.append(data)

    def handle_comment(self, data):
        self.comments.append(data)

    def handle_decl(self, decl):
        if "doctype" in decl.lower(): self._has_doctype = True

    def get_lang(self): return self._html_lang
    def get_viewport(self): return self._meta_viewport
    def has_doctype(self): return self._has_doctype
    def get_text(self): return " ".join(self._text_content)


# ============================================================
# TOOL SCANNER IMPLEMENTATIONS (100+ tools)
# ============================================================

def _mk_finding(fid, tool, url, component, title, category, severity,
                detection, evidence, desc, impact, fix, code="", verification=""):
    return Finding(fid, tool, url, component, title, category, severity,
                   "High Confidence", detection, evidence, desc, impact, fix,
                   code, verification)


def _get_page_data(config, url, policy=None):
    """Fetch page once and parse."""
    policy = policy or SecurityPolicy()
    client = HTTPClient(config, policy)
    resp = client.fetch(url)
    parser = HTMLPageParser()
    if resp.body and not resp.error:
        try:
            parser.feed(resp.body.decode("utf-8", errors="replace"))
        except Exception:
            pass
    return client, resp, parser


# ============================================================
# TRANSPORT SECURITY TOOLS
# ============================================================

def tool_tls_versions(url, config):
    checks, findings = [], []
    parsed = urllib.parse.urlparse(url)
    if parsed.scheme != "https":
        return ModuleResult("TLS Versions", [CheckResult("TLS", "TLS Versions", "Not Applicable", "Not HTTPS")], [], {})
    host = parsed.hostname
    port = parsed.port or 443
    supported = []
    for ver_name, ver_const in [("TLSv1.0", ssl.TLSVersion.TLSv1),
                                 ("TLSv1.1", ssl.TLSVersion.TLSv1_1),
                                 ("TLSv1.2", ssl.TLSVersion.TLSv1_2),
                                 ("TLSv1.3", ssl.TLSVersion.TLSv1_3)]:
        try:
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            ctx.minimum_version = ver_const
            ctx.maximum_version = ver_const
            with socket.create_connection((host, port), timeout=5) as s:
                with ctx.wrap_socket(s, server_hostname=host):
                    supported.append(ver_name)
        except Exception:
            pass
    if supported:
        checks.append(CheckResult("TLS Versions", "TLS Versions", "Info", f"Supported: {', '.join(supported)}"))
    if "TLSv1.0" in supported or "TLSv1.1" in supported:
        checks.append(CheckResult("Outdated TLS", "TLS Versions", "Failed", "TLS 1.0/1.1 enabled", "", "High"))
        findings.append(_mk_finding("TLSV-001", "TLS Versions", url, "TLS", "Outdated TLS Versions Enabled",
                                    "Transport Security", "High", "TLS version probe",
                                    f"Enabled: {', '.join([v for v in supported if v in ('TLSv1.0','TLSv1.1')])}",
                                    "Server accepts deprecated TLS versions.", "Weak crypto.",
                                    "Disable TLS 1.0 and 1.1; require TLS 1.2+.",
                                    "ssl_protocols TLSv1.2 TLSv1.3;", "Re-scan"))
    if "TLSv1.3" in supported:
        checks.append(CheckResult("TLS 1.3", "TLS Versions", "Passed", "Modern TLS 1.3 supported"))
    return ModuleResult("TLS Versions", checks, findings, {"supported": supported})


def tool_hsts_check(url, config):
    checks, findings = [], []
    client, resp, _ = _get_page_data(config, url)
    if resp.error:
        return ModuleResult("HSTS", [CheckResult("Request", "HSTS", "Failed", resp.error)], [], {})
    hdrs = {k.lower(): v for k, v in resp.headers}
    hsts = hdrs.get("strict-transport-security", "")
    if not hsts:
        checks.append(CheckResult("HSTS", "HSTS", "Failed", "Not present", "", "Medium"))
        findings.append(_mk_finding("HSTS-001", "HSTS", url, "Strict-Transport-Security",
                                    "HSTS Not Enabled", "Transport Security", "Medium", "Header inspection",
                                    "No HSTS header", "Missing HSTS header.", "Downgrade attacks possible.",
                                    "Add HSTS header with long max-age.",
                                    'Header always set Strict-Transport-Security "max-age=31536000; includeSubDomains; preload"',
                                    "Re-scan"))
        return ModuleResult("HSTS", checks, findings, {})
    max_age_match = re.search(r"max-age=(\d+)", hsts, re.IGNORECASE)
    max_age = int(max_age_match.group(1)) if max_age_match else 0
    checks.append(CheckResult("HSTS Present", "HSTS", "Passed", hsts[:120]))
    if max_age < 15552000:
        checks.append(CheckResult("HSTS max-age", "HSTS", "Warning", f"{max_age}s (< 180 days)", "", "Low"))
        findings.append(_mk_finding("HSTS-002", "HSTS", url, "HSTS", "HSTS max-age Too Short",
                                    "Transport Security", "Low", "Header inspection",
                                    f"max-age={max_age}", "max-age is short.", "Less protection.",
                                    "Set max-age to at least 31536000 (1 year).", "", "Re-scan"))
    if "includesubdomains" not in hsts.lower():
        checks.append(CheckResult("HSTS includeSubDomains", "HSTS", "Warning", "Not set"))
    if "preload" not in hsts.lower():
        checks.append(CheckResult("HSTS preload", "HSTS", "Info", "Not preloaded"))
    return ModuleResult("HSTS", checks, findings, {"hsts": hsts})


def tool_certificate_chain(url, config):
    checks, findings = [], []
    parsed = urllib.parse.urlparse(url)
    if parsed.scheme != "https":
        return ModuleResult("Cert Chain", [CheckResult("TLS", "Cert Chain", "Not Applicable")], [], {})
    host = parsed.hostname
    port = parsed.port or 443
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((host, port), timeout=10) as s:
            with ctx.wrap_socket(s, server_hostname=host) as ss:
                cert = ss.getpeercert()
                chain = ss.get_verified_chain() if hasattr(ss, "get_verified_chain") else []
                checks.append(CheckResult("Cert Chain Length", "Cert Chain", "Info", f"{len(chain)} cert(s)"))
                subject = dict(x[0] for x in cert.get("subject", ()))
                issuer = dict(x[0] for x in cert.get("issuer", ()))
                checks.append(CheckResult("Issued By", "Cert Chain", "Info", issuer.get("commonName", issuer.get("organizationName", ""))))
                san = cert.get("subjectAltName", ())
                dns_names = [v for t, v in san if t == "DNS"]
                checks.append(CheckResult("SAN DNS Names", "Cert Chain", "Info", ", ".join(dns_names[:5])))
                data = {"subject": subject, "issuer": issuer, "san": dns_names, "chain_len": len(chain)}
    except Exception as e:
        checks.append(CheckResult("Cert Chain", "Cert Chain", "Failed", str(e), "", "High"))
        data = {}
    return ModuleResult("Cert Chain", checks, findings, data)


def tool_ssl_ciphers(url, config):
    checks, findings = [], []
    parsed = urllib.parse.urlparse(url)
    if parsed.scheme != "https":
        return ModuleResult("Ciphers", [CheckResult("TLS", "Ciphers", "Not Applicable")], [], {})
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((parsed.hostname, parsed.port or 443), timeout=10) as s:
            with ctx.wrap_socket(s, server_hostname=parsed.hostname) as ss:
                cipher = ss.cipher()
                version = ss.version()
                checks.append(CheckResult("Negotiated Cipher", "Ciphers", "Info", f"{cipher[0]} ({cipher[1]} bits, {cipher[2]})"))
                checks.append(CheckResult("Protocol Version", "Ciphers", "Info", version))
                if "RC4" in cipher[0] or "DES" in cipher[0] or "MD5" in cipher[0]:
                    checks.append(CheckResult("Weak Cipher", "Ciphers", "Failed", cipher[0], "", "High"))
                    findings.append(_mk_finding("CIPH-001", "Ciphers", url, "TLS Cipher",
                                                "Weak Cipher Suite", "Transport Security", "High",
                                                "SSL handshake", cipher[0], "Weak cipher detected.",
                                                "Vulnerable to attacks.", "Use modern AEAD ciphers.",
                                                "ssl_ciphers HIGH:!aNULL:!MD5;", "Re-scan"))
                if cipher[1] < 128:
                    checks.append(CheckResult("Cipher Strength", "Ciphers", "Warning", f"{cipher[1]} bits"))
                return ModuleResult("Ciphers", checks, findings, {"cipher": cipher, "version": version})
    except Exception as e:
        return ModuleResult("Ciphers", [CheckResult("TLS", "Ciphers", "Failed", str(e))], [], {})


def tool_http2(url, config):
    checks, findings = [], []
    try:
        parsed = urllib.parse.urlparse(url)
        if parsed.scheme != "https":
            return ModuleResult("HTTP/2", [CheckResult("HTTP/2", "HTTP/2", "Not Applicable", "Not HTTPS")], [], {})
        # Check via ALPN
        ctx = ssl.create_default_context()
        ctx.set_alpn_protocols(["h2", "http/1.1"])
        with socket.create_connection((parsed.hostname, parsed.port or 443), timeout=10) as s:
            with ctx.wrap_socket(s, server_hostname=parsed.hostname) as ss:
                proto = ss.selected_alpn_protocol()
                if proto == "h2":
                    checks.append(CheckResult("HTTP/2", "HTTP/2", "Passed", "ALPN negotiated h2"))
                else:
                    checks.append(CheckResult("HTTP/2", "HTTP/2", "Warning", f"Using {proto or 'http/1.1'}"))
                    findings.append(_mk_finding("H2-001", "HTTP/2", url, "Protocol", "HTTP/2 Not Supported",
                                                "Performance", "Low", "ALPN probe", f"Negotiated: {proto}",
                                                "HTTP/2 not available.", "Slower loads.",
                                                "Enable HTTP/2 on server.", "", "Re-scan"))
                return ModuleResult("HTTP/2", checks, findings, {"alpn": proto})
    except Exception as e:
        return ModuleResult("HTTP/2", [CheckResult("HTTP/2", "HTTP/2", "Failed", str(e))], [], {})


def tool_http3(url, config):
    checks, findings = [], []
    # HTTP/3 requires QUIC - not in stdlib, so probe via headers
    client, resp, _ = _get_page_data(config, url)
    if resp.error:
        return ModuleResult("HTTP/3", [CheckResult("Request", "HTTP/3", "Failed", resp.error)], [], {})
    hdrs = {k.lower(): v for k, v in resp.headers}
    alt_svc = hdrs.get("alt-svc", "")
    if "h3" in alt_svc.lower():
        checks.append(CheckResult("HTTP/3 Advertised", "HTTP/3", "Passed", alt_svc))
    else:
        checks.append(CheckResult("HTTP/3", "HTTP/3", "Not Tested", "Not advertised via Alt-Svc"))
    return ModuleResult("HTTP/3", checks, findings, {"alt_svc": alt_svc})


def tool_https_redirect(url, config):
    checks, findings = [], []
    parsed = urllib.parse.urlparse(url)
    if parsed.scheme != "https":
        return ModuleResult("HTTPS Redirect", [CheckResult("Redirect", "HTTPS Redirect", "Not Applicable")], [], {})
    http_url = "http://" + parsed.netloc + parsed.path
    policy = SecurityPolicy()
    client = HTTPClient(config, policy)
    r = client.fetch(http_url, max_redirects=2)
    if r.redirects or (r.final_url or "").startswith("https://"):
        checks.append(CheckResult("HTTP→HTTPS", "HTTPS Redirect", "Passed", "Redirects to HTTPS"))
    elif r.status and 200 <= r.status < 300:
        checks.append(CheckResult("HTTP→HTTPS", "HTTPS Redirect", "Failed", "HTTP served directly", "", "High"))
        findings.append(_mk_finding("REDIR-001", "HTTPS Redirect", url, "HTTP", "No HTTPS Enforcement",
                                    "Transport Security", "High", "HTTP request", "HTTP returned 200",
                                    "HTTP serves content directly.", "Insecure connection.",
                                    "Add 301 redirect HTTP→HTTPS.",
                                    "# Nginx\nreturn 301 https://$host$request_uri;", "Re-scan"))
    return ModuleResult("HTTPS Redirect", checks, findings, {})


def tool_mixed_content(url, config):
    checks, findings = [], []
    if not url.startswith("https://"):
        return ModuleResult("Mixed Content", [CheckResult("Check", "Mixed Content", "Not Applicable")], [], {})
    _, resp, parser = _get_page_data(config, url)
    if resp.error:
        return ModuleResult("Mixed Content", [CheckResult("Request", "Mixed Content", "Failed", resp.error)], [], {})
    http_refs = []
    for link in parser.links:
        if link.get("href", "").startswith("http://"): http_refs.append(link["href"])
    for img in parser.images:
        if img.get("src", "").startswith("http://"): http_refs.append(img["src"])
    for sc in parser.scripts:
        if sc.startswith("http://"): http_refs.append(sc)
    for st in parser.stylesheets:
        if st.startswith("http://"): http_refs.append(st)
    if http_refs:
        checks.append(CheckResult("Mixed Content", "Mixed Content", "Failed", f"{len(http_refs)} HTTP resource(s)", "", "Medium"))
        findings.append(_mk_finding("MC-001", "Mixed Content", url, "HTTPS page", "Mixed Content Detected",
                                    "Transport Security", "Medium", "HTML parsing",
                                    f"{len(http_refs)} HTTP refs", "HTTPS page loads HTTP resources.",
                                    "Browser warnings.", "Use HTTPS for all resources.", "", "Re-scan"))
    else:
        checks.append(CheckResult("Mixed Content", "Mixed Content", "Passed", "No HTTP resources"))
    return ModuleResult("Mixed Content", checks, findings, {"http_refs": http_refs[:10]})


def tool_hsts_preload(url, config):
    checks, findings = [], []
    parsed = urllib.parse.urlparse(url)
    domain = parsed.hostname or ""
    if not domain:
        return ModuleResult("HSTS Preload", [CheckResult("Preload", "HSTS Preload", "Failed", "No hostname")], [], {})
    # Check if base domain is preloaded via Chrome's list (simple heuristic via public endpoint)
    base = domain.split(".")
    if len(base) >= 2:
        base_domain = ".".join(base[-2:])
    else:
        base_domain = domain
    try:
        req = urllib.request.Request(
            f"https://hstspreload.org/api/v2/status?domain={base_domain}",
            headers={"User-Agent": "SCIT-BOSS/2.0"}
        )
        r = urllib.request.urlopen(req, timeout=10)
        data = json.loads(r.read().decode())
        status = data.get("status", "unknown")
        checks.append(CheckResult("Preload Status", "HSTS Preload", "Info", f"{base_domain}: {status}"))
    except Exception as e:
        checks.append(CheckResult("Preload Check", "HSTS Preload", "Not Tested", str(e)[:100]))
    return ModuleResult("HSTS Preload", checks, findings, {})


def tool_certificate_expiry(url, config):
    checks, findings = [], []
    parsed = urllib.parse.urlparse(url)
    if parsed.scheme != "https":
        return ModuleResult("Cert Expiry", [CheckResult("Expiry", "Cert Expiry", "Not Applicable")], [], {})
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((parsed.hostname, parsed.port or 443), timeout=10) as s:
            with ctx.wrap_socket(s, server_hostname=parsed.hostname) as ss:
                cert = ss.getpeercert()
                not_after = cert.get("notAfter")
                if not_after:
                    exp = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z")
                    days = (exp - datetime.utcnow()).days
                    if days < 0:
                        checks.append(CheckResult("Expiry", "Cert Expiry", "Failed", f"Expired {abs(days)}d ago", "", "Critical"))
                        findings.append(_mk_finding("EXP-001", "Cert Expiry", url, "Certificate", "Certificate Expired",
                                                    "Transport Security", "Critical", "notAfter", not_after,
                                                    "Certificate expired.", "Site blocked.", "Renew now.", "", "Re-scan"))
                    elif days < 7:
                        checks.append(CheckResult("Expiry", "Cert Expiry", "Failed", f"Expires in {days}d", "", "High"))
                        findings.append(_mk_finding("EXP-002", "Cert Expiry", url, "Certificate", "Expiring Very Soon",
                                                    "Transport Security", "High", "notAfter", not_after,
                                                    "Expires < 7 days.", "Will break soon.", "Renew now.", "", "Re-scan"))
                    elif days < 30:
                        checks.append(CheckResult("Expiry", "Cert Expiry", "Warning", f"Expires in {days}d"))
                    else:
                        checks.append(CheckResult("Expiry", "Cert Expiry", "Passed", f"Valid {days}d"))
                    return ModuleResult("Cert Expiry", checks, findings, {"days": days, "not_after": not_after})
    except Exception as e:
        return ModuleResult("Cert Expiry", [CheckResult("Expiry", "Cert Expiry", "Failed", str(e))], [], {})


def tool_ocsp_stapling(url, config):
    checks, findings = [], []
    parsed = urllib.parse.urlparse(url)
    if parsed.scheme != "https":
        return ModuleResult("OCSP", [CheckResult("OCSP", "OCSP Stapling", "Not Applicable")], [], {})
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((parsed.hostname, parsed.port or 443), timeout=10) as s:
            with ctx.wrap_socket(s, server_hostname=parsed.hostname) as ss:
                ocsp = ss.ocsp_response()
                if ocsp:
                    checks.append(CheckResult("OCSP Stapling", "OCSP Stapling", "Passed", "Response received"))
                else:
                    checks.append(CheckResult("OCSP Stapling", "OCSP Stapling", "Info", "Not stapled"))
    except Exception as e:
        checks.append(CheckResult("OCSP", "OCSP Stapling", "Not Tested", str(e)[:80]))
    return ModuleResult("OCSP Stapling", checks, findings, {})


def tool_downgrade_attack(url, config):
    checks, findings = [], []
    client, resp, _ = _get_page_data(config, url)
    if resp.error:
        return ModuleResult("Downgrade", [CheckResult("Request", "Downgrade", "Failed", resp.error)], [], {})
    hdrs = {k.lower(): v for k, v in resp.headers}
    proto = hdrs.get("x-forwarded-proto", "")
    if proto and proto != "https":
        findings.append(_mk_finding("DOWN-001", "Downgrade", url, "Proxy", "Protocol Downgrade Detected",
                                    "Transport Security", "High", "X-Forwarded-Proto", proto,
                                    "Proxy indicates HTTP.", "Insecure.", "Fix proxy config.", "", "Re-scan"))
        checks.append(CheckResult("Protocol", "Downgrade", "Failed", proto, "", "High"))
    else:
        checks.append(CheckResult("Protocol", "Downgrade", "Passed", "HTTPS end-to-end"))
    return ModuleResult("Downgrade", checks, findings, {})


# ============================================================
# HEADERS & POLICY TOOLS
# ============================================================

def tool_security_headers_full(url, config):
    checks, findings = [], []
    client, resp, _ = _get_page_data(config, url)
    if resp.error:
        return ModuleResult("Security Headers", [CheckResult("Request", "Security Headers", "Failed", resp.error)], [], {})
    hdrs = {k.lower(): v for k, v in resp.headers}
    headers_to_check = {
        "strict-transport-security": ("Medium", "HSTS"),
        "content-security-policy": ("High", "CSP"),
        "x-frame-options": ("Medium", "X-Frame-Options"),
        "x-content-type-options": ("Low", "X-Content-Type-Options"),
        "referrer-policy": ("Low", "Referrer-Policy"),
        "permissions-policy": ("Low", "Permissions-Policy"),
        "x-xss-protection": ("Informational", "X-XSS-Protection"),
        "cross-origin-opener-policy": ("Medium", "COOP"),
        "cross-origin-embedder-policy": ("Medium", "COEP"),
        "cross-origin-resource-policy": ("Medium", "CORP"),
    }
    for h, (sev, name) in headers_to_check.items():
        if h in hdrs:
            checks.append(CheckResult(name, "Security Headers", "Passed", hdrs[h][:100]))
        else:
            checks.append(CheckResult(name, "Security Headers", "Warning", "Missing", "", sev))
            if sev in ("High", "Medium"):
                findings.append(_mk_finding(f"SEC-{h.upper()[:6]}", "Security Headers", url, h,
                                            f"{name} Missing", "Security Configuration", sev,
                                            "Header inspection", f"Missing: {h}",
                                            f"{name} header not set.", "Reduced security.",
                                            f"Add {h} header.", f"# Add {h} header", "Re-scan"))
    return ModuleResult("Security Headers", checks, findings, {})


def tool_csp_analysis(url, config):
    checks, findings = [], []
    client, resp, _ = _get_page_data(config, url)
    if resp.error:
        return ModuleResult("CSP", [CheckResult("Request", "CSP", "Failed", resp.error)], [], {})
    hdrs = {k.lower(): v for k, v in resp.headers}
    csp = hdrs.get("content-security-policy", "")
    if not csp:
        checks.append(CheckResult("CSP", "CSP", "Failed", "Not present", "", "High"))
        return ModuleResult("CSP", checks, [], {})
    checks.append(CheckResult("CSP Present", "CSP", "Passed", csp[:100]))
    issues = []
    if "unsafe-inline" in csp.lower():
        issues.append("'unsafe-inline'")
    if "unsafe-eval" in csp.lower():
        issues.append("'unsafe-eval'")
    if "*" in csp and "default-src" in csp:
        issues.append("wildcard source")
    if issues:
        findings.append(_mk_finding("CSP-001", "CSP", url, "CSP", "Weak CSP Directives",
                                    "Security Configuration", "Medium", "CSP inspection",
                                    ", ".join(issues), f"CSP contains {', '.join(issues)}",
                                    "Weakens XSS protection.", "Replace with nonces/hashes.", "", "Re-scan"))
        checks.append(CheckResult("CSP Strength", "CSP", "Warning", ", ".join(issues), "", "Medium"))
    else:
        checks.append(CheckResult("CSP Strength", "CSP", "Passed", "No weak directives"))
    return ModuleResult("CSP", checks, findings, {"csp": csp})


def tool_x_frame_options(url, config):
    checks, findings = [], []
    client, resp, _ = _get_page_data(config, url)
    if resp.error:
        return ModuleResult("XFO", [CheckResult("Request", "XFO", "Failed", resp.error)], [], {})
    hdrs = {k.lower(): v for k, v in resp.headers}
    xfo = hdrs.get("x-frame-options", "")
    csp = hdrs.get("content-security-policy", "")
    if xfo:
        checks.append(CheckResult("X-Frame-Options", "XFO", "Passed", xfo))
    elif "frame-ancestors" in csp.lower():
        checks.append(CheckResult("X-Frame-Options", "XFO", "Passed", "CSP frame-ancestors"))
    else:
        checks.append(CheckResult("X-Frame-Options", "XFO", "Failed", "Missing", "", "Medium"))
        findings.append(_mk_finding("XFO-001", "XFO", url, "X-Frame-Options", "Clickjacking Protection Missing",
                                    "Security Configuration", "Medium", "Header inspection",
                                    "No XFO or CSP frame-ancestors", "No clickjacking protection.",
                                    "Clickjacking risk.", "Add X-Frame-Options or CSP frame-ancestors.",
                                    'Header always set X-Frame-Options "SAMEORIGIN"', "Re-scan"))
    return ModuleResult("XFO", checks, findings, {})


def tool_permissions_policy(url, config):
    checks, findings = [], []
    client, resp, _ = _get_page_data(config, url)
    if resp.error:
        return ModuleResult("Permissions", [CheckResult("Request", "Permissions", "Failed", resp.error)], [], {})
    hdrs = {k.lower(): v for k, v in resp.headers}
    pp = hdrs.get("permissions-policy", "")
    if pp:
        checks.append(CheckResult("Permissions-Policy", "Permissions", "Passed", pp[:150]))
    else:
        checks.append(CheckResult("Permissions-Policy", "Permissions", "Warning", "Missing", "", "Low"))
        findings.append(_mk_finding("PP-001", "Permissions", url, "Permissions-Policy",
                                    "Permissions-Policy Missing", "Security Configuration", "Low",
                                    "Header inspection", "No Permissions-Policy",
                                    "No Permissions-Policy set.", "Features may be abused.",
                                    "Add Permissions-Policy header.",
                                    'Permissions-Policy: camera=(), microphone=(), geolocation=()', "Re-scan"))
    return ModuleResult("Permissions", checks, findings, {})


def tool_coop_coep(url, config):
    checks, findings = [], []
    client, resp, _ = _get_page_data(config, url)
    if resp.error:
        return ModuleResult("COOP/COEP", [CheckResult("Request", "COOP/COEP", "Failed", resp.error)], [], {})
    hdrs = {k.lower(): v for k, v in resp.headers}
    for h in ["cross-origin-opener-policy", "cross-origin-embedder-policy", "cross-origin-resource-policy"]:
        if h in hdrs:
            checks.append(CheckResult(h, "COOP/COEP", "Passed", hdrs[h]))
        else:
            checks.append(CheckResult(h, "COOP/COEP", "Warning", "Missing", "", "Low"))
    return ModuleResult("COOP/COEP", checks, findings, {})


def tool_referrer_policy(url, config):
    checks, findings = [], []
    client, resp, _ = _get_page_data(config, url)
    if resp.error:
        return ModuleResult("Referrer", [CheckResult("Request", "Referrer", "Failed", resp.error)], [], {})
    hdrs = {k.lower(): v for k, v in resp.headers}
    rp = hdrs.get("referrer-policy", "")
    if not rp:
        checks.append(CheckResult("Referrer-Policy", "Referrer", "Warning", "Missing", "", "Low"))
        findings.append(_mk_finding("REF-001", "Referrer", url, "Referrer-Policy",
                                    "Referrer-Policy Missing", "Security Configuration", "Low",
                                    "Header inspection", "No Referrer-Policy",
                                    "Missing header.", "Possible referrer leak.",
                                    "Set Referrer-Policy.",
                                    "Referrer-Policy: strict-origin-when-cross-origin", "Re-scan"))
    else:
        checks.append(CheckResult("Referrer-Policy", "Referrer", "Passed", rp))
    return ModuleResult("Referrer", checks, findings, {})


def tool_cache_control(url, config):
    checks, findings = [], []
    client, resp, _ = _get_page_data(config, url)
    if resp.error:
        return ModuleResult("Cache-Control", [CheckResult("Request", "Cache-Control", "Failed", resp.error)], [], {})
    hdrs = {k.lower(): v for k, v in resp.headers}
    cc = hdrs.get("cache-control", "")
    if cc:
        checks.append(CheckResult("Cache-Control", "Cache-Control", "Passed", cc))
    else:
        checks.append(CheckResult("Cache-Control", "Cache-Control", "Warning", "Missing", "", "Low"))
    return ModuleResult("Cache-Control", checks, findings, {})


def tool_pragma(url, config):
    checks, findings = [], []
    client, resp, _ = _get_page_data(config, url)
    if resp.error:
        return ModuleResult("Pragma", [CheckResult("Request", "Pragma", "Failed", resp.error)], [], {})
    hdrs = {k.lower(): v for k, v in resp.headers}
    pragma = hdrs.get("pragma", "")
    checks.append(CheckResult("Pragma", "Pragma", "Info", pragma or "Not set"))
    return ModuleResult("Pragma", checks, findings, {})


def tool_server_header(url, config):
    checks, findings = [], []
    client, resp, _ = _get_page_data(config, url)
    if resp.error:
        return ModuleResult("Server Header", [CheckResult("Request", "Server Header", "Failed", resp.error)], [], {})
    hdrs = {k.lower(): v for k, v in resp.headers}
    server = hdrs.get("server", "")
    powered = hdrs.get("x-powered-by", "")
    if server:
        if re.search(r"\d+\.\d+", server):
            checks.append(CheckResult("Server", "Server Header", "Warning", server, "", "Low"))
            findings.append(_mk_finding("SRV-001", "Server Header", url, "Server",
                                        "Version Disclosure", "Information Exposure", "Low",
                                        "Header inspection", server, "Server version exposed.",
                                        "Helps attackers.", "Suppress version.",
                                        "ServerTokens Prod", "Re-scan"))
        else:
            checks.append(CheckResult("Server", "Server Header", "Passed", server))
    if powered:
        checks.append(CheckResult("X-Powered-By", "Server Header", "Warning", powered, "", "Low"))
        findings.append(_mk_finding("SRV-002", "Server Header", url, "X-Powered-By",
                                    "Technology Disclosure", "Information Exposure", "Low",
                                    "Header inspection", powered, "X-Powered-By exposed.",
                                    "Helps attackers.", "Remove X-Powered-By.",
                                    "Header unset X-Powered-By", "Re-scan"))
    return ModuleResult("Server Header", checks, findings, {})


def tool_x_xss_protection(url, config):
    checks, findings = [], []
    client, resp, _ = _get_page_data(config, url)
    if resp.error:
        return ModuleResult("X-XSS", [CheckResult("Request", "X-XSS", "Failed", resp.error)], [], {})
    hdrs = {k.lower(): v for k, v in resp.headers}
    xss = hdrs.get("x-xss-protection", "")
    if xss:
        checks.append(CheckResult("X-XSS-Protection", "X-XSS", "Info", xss))
        if "0" in xss and "1" not in xss:
            checks.append(CheckResult("Value", "X-XSS", "Warning", "Disabled (recommended for modern)"))
    else:
        checks.append(CheckResult("X-XSS-Protection", "X-XSS", "Info", "Not set (deprecated)"))
    return ModuleResult("X-XSS", checks, findings, {})


def tool_content_type_options(url, config):
    checks, findings = [], []
    client, resp, _ = _get_page_data(config, url)
    if resp.error:
        return ModuleResult("X-CTO", [CheckResult("Request", "X-CTO", "Failed", resp.error)], [], {})
    hdrs = {k.lower(): v for k, v in resp.headers}
    cto = hdrs.get("x-content-type-options", "")
    if cto and "nosniff" in cto.lower():
        checks.append(CheckResult("X-Content-Type-Options", "X-CTO", "Passed", cto))
    else:
        checks.append(CheckResult("X-Content-Type-Options", "X-CTO", "Failed", "Missing or weak", "", "Low"))
        findings.append(_mk_finding("CTO-001", "X-CTO", url, "X-Content-Type-Options",
                                    "X-Content-Type-Options Missing", "Security Configuration", "Low",
                                    "Header inspection", cto or "Missing", "MIME sniffing not disabled.",
                                    "MIME confusion risk.", "Set nosniff.",
                                    'X-Content-Type-Options: nosniff', "Re-scan"))
    return ModuleResult("X-CTO", checks, findings, {})


def tool_header_injection(url, config):
    checks, findings = [], []
    # Check for CRLF in URL parameters
    parsed = urllib.parse.urlparse(url)
    qs = parsed.query
    if "%0d" in qs.lower() or "%0a" in qs.lower() or "\r" in qs or "\n" in qs:
        checks.append(CheckResult("CRLF", "Header Injection", "Warning", "CRLF in URL", "", "Medium"))
    else:
        checks.append(CheckResult("CRLF", "Header Injection", "Passed", "No CRLF in query"))
    return ModuleResult("Header Injection", checks, findings, {})


def tool_cors(url, config):
    checks, findings = [], []
    policy = SecurityPolicy()
    client = HTTPClient(config, policy)
    # Send origin header
    try:
        req = urllib.request.Request(url, headers={
            "User-Agent": config.get("user_agent"),
            "Origin": "https://evil.example.com",
        })
        ctx = ssl.create_default_context() if url.startswith("https") else None
        args = dict(timeout=10)
        if ctx: args["context"] = ctx
        resp = urllib.request.urlopen(req, **args)
        hdrs = {k.lower(): v for k, v in resp.headers.items()}
        acao = hdrs.get("access-control-allow-origin", "")
        acac = hdrs.get("access-control-allow-credentials", "")
        if acao == "*" and acac.lower() == "true":
            checks.append(CheckResult("CORS", "CORS", "Failed", "* with credentials", "", "High"))
            findings.append(_mk_finding("CORS-001", "CORS", url, "Access-Control-Allow-Origin",
                                        "CORS Misconfiguration", "Security Configuration", "High",
                                        "CORS test", f"ACAO=* + ACAC=true", "Wildcard with credentials.",
                                        "Cross-origin data theft.", "Restrict origin.",
                                        "Access-Control-Allow-Origin: https://yourdomain.com", "Re-scan"))
        elif acao == "https://evil.example.com":
            checks.append(CheckResult("CORS", "CORS", "Failed", "Reflects arbitrary origin", "", "High"))
            findings.append(_mk_finding("CORS-002", "CORS", url, "ACAO",
                                        "CORS Reflects Origin", "Security Configuration", "High",
                                        "CORS test", f"ACAO={acao}", "Origin reflected blindly.",
                                        "Data theft.", "Use allowlist.", "", "Re-scan"))
        elif acao:
            checks.append(CheckResult("CORS", "CORS", "Info", acao))
        else:
            checks.append(CheckResult("CORS", "CORS", "Passed", "No permissive CORS"))
    except Exception as e:
        checks.append(CheckResult("CORS", "CORS", "Not Tested", str(e)[:100]))
    return ModuleResult("CORS", checks, findings, {})


# ============================================================
# COOKIE & SESSION TOOLS
# ============================================================

def tool_cookie_flags(url, config):
    checks, findings = [], []
    client, resp, _ = _get_page_data(config, url)
    if resp.error:
        return ModuleResult("Cookie Flags", [CheckResult("Request", "Cookie Flags", "Failed", resp.error)], [], {})
    set_cookies = [v for k, v in resp.headers if k.lower() == "set-cookie"]
    if not set_cookies:
        return ModuleResult("Cookie Flags", [CheckResult("Cookies", "Cookie Flags", "Not Applicable", "No cookies")], [], {})
    for raw in set_cookies:
        parts = [p.strip() for p in raw.split(";")]
        name = parts[0].split("=", 1)[0].strip()
        flags_l = [p.lower() for p in parts[1:]]
        secure = any(f == "secure" for f in flags_l)
        httponly = any(f == "httponly" for f in flags_l)
        samesite = any(f.startswith("samesite=") for f in flags_l)
        missing = []
        if not secure: missing.append("Secure")
        if not httponly: missing.append("HttpOnly")
        if not samesite: missing.append("SameSite")
        if missing:
            checks.append(CheckResult(f"Cookie: {name}", "Cookie Flags", "Warning", f"Missing: {', '.join(missing)}", "", "Medium"))
            findings.append(_mk_finding(f"CK-{hashlib.md5(name.encode()).hexdigest()[:6].upper()}",
                                        "Cookie Flags", url, f"Cookie: {name}",
                                        f"Cookie Missing Flags ({name})", "Session Security", "Medium",
                                        "Set-Cookie inspection", f"Missing: {', '.join(missing)}",
                                        "Cookie lacks security flags.", "Session theft risk.",
                                        "Set Secure, HttpOnly, SameSite.",
                                        "Set-Cookie: name=value; Secure; HttpOnly; SameSite=Lax", "Re-scan"))
        else:
            checks.append(CheckResult(f"Cookie: {name}", "Cookie Flags", "Passed", "All flags present"))
    return ModuleResult("Cookie Flags", checks, findings, {})


def tool_cookie_prefixes(url, config):
    checks, findings = [], []
    client, resp, _ = _get_page_data(config, url)
    if resp.error:
        return ModuleResult("Cookie Prefixes", [CheckResult("Request", "Cookie Prefixes", "Failed", resp.error)], [], {})
    set_cookies = [v for k, v in resp.headers if k.lower() == "set-cookie"]
    for raw in set_cookies:
        name = raw.split("=", 1)[0].strip().lower()
        if name.startswith("__secure-"):
            checks.append(CheckResult("__Secure- prefix", "Cookie Prefixes", "Passed", name))
        elif name.startswith("__host-"):
            checks.append(CheckResult("__Host- prefix", "Cookie Prefixes", "Passed", name))
        elif "session" in name or "auth" in name or "login" in name:
            checks.append(CheckResult(f"Cookie: {name}", "Cookie Prefixes", "Info", "Consider __Host- prefix"))
    if not set_cookies:
        checks.append(CheckResult("Cookie Prefixes", "Cookie Prefixes", "Not Applicable", "No cookies"))
    return ModuleResult("Cookie Prefixes", checks, findings, {})


def tool_cookie_scope(url, config):
    checks, findings = [], []
    client, resp, _ = _get_page_data(config, url)
    if resp.error:
        return ModuleResult("Cookie Scope", [CheckResult("Request", "Cookie Scope", "Failed", resp.error)], [], {})
    set_cookies = [v for k, v in resp.headers if k.lower() == "set-cookie"]
    for raw in set_cookies:
        parts = [p.strip() for p in raw.split(";")]
        name = parts[0].split("=", 1)[0].strip()
        domain_flag = next((p for p in parts if p.lower().startswith("domain=")), "")
        path_flag = next((p for p in parts if p.lower().startswith("path=")), "")
        if domain_flag:
            checks.append(CheckResult(f"Cookie {name} Domain", "Cookie Scope", "Warning", domain_flag, "", "Low"))
        if not path_flag:
            checks.append(CheckResult(f"Cookie {name} Path", "Cookie Scope", "Info", "Path not set (defaults to /)"))
    return ModuleResult("Cookie Scope", checks, findings, {})


def tool_csrf_forms(url, config):
    checks, findings = [], []
    _, resp, parser = _get_page_data(config, url)
    if resp.error:
        return ModuleResult("CSRF", [CheckResult("Request", "CSRF", "Failed", resp.error)], [], {})
    risky_forms = []
    for form in parser.forms:
        if form["method"] == "post" and not form["has_csrf"]:
            risky_forms.append(form.get("action", "(no action)"))
    if risky_forms:
        checks.append(CheckResult("CSRF Tokens", "CSRF", "Failed", f"{len(risky_forms)} form(s) missing CSRF", "", "High"))
        findings.append(_mk_finding("CSRF-001", "CSRF", url, "POST forms", "CSRF Tokens Missing",
                                    "Session Security", "High", "Form parsing",
                                    f"{len(risky_forms)} POST forms without CSRF",
                                    "POST forms lack CSRF tokens.", "CSRF attacks possible.",
                                    "Add CSRF token to all state-changing forms.",
                                    '<input type="hidden" name="csrf_token" value="{{ token }}">', "Re-scan"))
    else:
        checks.append(CheckResult("CSRF Tokens", "CSRF", "Passed", "All POST forms have tokens (or no POST forms)"))
    return ModuleResult("CSRF", checks, findings, {})


def tool_session_entropy(url, config):
    checks, findings = [], []
    client, resp, _ = _get_page_data(config, url)
    if resp.error:
        return ModuleResult("Session Entropy", [CheckResult("Request", "Session Entropy", "Failed", resp.error)], [], {})
    set_cookies = [v for k, v in resp.headers if k.lower() == "set-cookie"]
    for raw in set_cookies:
        val = raw.split("=", 1)[1].split(";")[0].strip() if "=" in raw else ""
        if len(val) > 0 and len(val) < 16:
            checks.append(CheckResult("Session Value Length", "Session Entropy", "Warning", f"{len(val)} chars (< 16)", "", "Medium"))
            findings.append(_mk_finding("ENT-001", "Session Entropy", url, "Session",
                                        "Short Session Token", "Session Security", "Medium",
                                        "Cookie inspection", f"Length: {len(val)}",
                                        "Session token may be too short.", "Brute-force risk.",
                                        "Use cryptographically random 128-bit+ tokens.", "", "Re-scan"))
    if not any("Warning" in c.status for c in checks):
        checks.append(CheckResult("Session Entropy", "Session Entropy", "Passed", "Adequate length"))
    return ModuleResult("Session Entropy", checks, findings, {})


def tool_logout_csrf(url, config):
    checks, findings = [], []
    _, resp, parser = _get_page_data(config, url)
    if resp.error:
        return ModuleResult("Logout CSRF", [CheckResult("Request", "Logout CSRF", "Failed", resp.error)], [], {})
    logout_links = [l for l in parser.links if "logout" in (l.get("href", "") + l.get("text", "")).lower()]
    if logout_links:
        get_logouts = [l for l in logout_links if not l.get("href", "").startswith("POST")]
        if get_logouts:
            checks.append(CheckResult("Logout", "Logout CSRF", "Warning", f"{len(get_logouts)} GET logout link(s)", "", "Low"))
        else:
            checks.append(CheckResult("Logout", "Logout CSRF", "Passed", "No vulnerable logout links"))
    else:
        checks.append(CheckResult("Logout", "Logout CSRF", "Not Applicable", "No logout links found"))
    return ModuleResult("Logout CSRF", checks, findings, {})


# ============================================================
# SEO & METADATA TOOLS
# ============================================================

def tool_title_tag(url, config):
    checks, findings = [], []
    _, resp, parser = _get_page_data(config, url)
    if resp.error:
        return ModuleResult("Title", [CheckResult("Request", "Title", "Failed", resp.error)], [], {})
    t = parser.title.strip()
    if not t:
        checks.append(CheckResult("Title", "Title", "Failed", "Missing", "", "Medium"))
        findings.append(_mk_finding("TTL-001", "Title", url, "<title>", "Missing Title Tag",
                                    "SEO", "Medium", "HTML parsing", "No <title>",
                                    "No title.", "SEO impact.", "Add <title>.",
                                    "<title>Page Title</title>", "Re-scan"))
    elif len(t) > 70:
        checks.append(CheckResult("Title Length", "Title", "Warning", f"{len(t)} chars"))
    elif len(t) < 30:
        checks.append(CheckResult("Title Length", "Title", "Warning", f"{len(t)} chars (short)"))
    else:
        checks.append(CheckResult("Title", "Title", "Passed", t[:80]))
    return ModuleResult("Title", checks, findings, {"title": t})


def tool_meta_description(url, config):
    checks, findings = [], []
    _, resp, parser = _get_page_data(config, url)
    if resp.error:
        return ModuleResult("Meta Description", [CheckResult("Request", "Meta Description", "Failed", resp.error)], [], {})
    d = parser.meta.get("description", "").strip()
    if not d:
        checks.append(CheckResult("Meta Description", "Meta Description", "Failed", "Missing", "", "Low"))
        findings.append(_mk_finding("MD-001", "Meta Description", url, "meta description",
                                    "Missing Meta Description", "SEO", "Low", "HTML parsing",
                                    "No description", "No meta description.", "Poor snippets.",
                                    "Add meta description.", '<meta name="description" content="...">', "Re-scan"))
    elif len(d) > 160:
        checks.append(CheckResult("Description Length", "Meta Description", "Warning", f"{len(d)} chars (long)"))
    elif len(d) < 50:
        checks.append(CheckResult("Description Length", "Meta Description", "Warning", f"{len(d)} chars (short)"))
    else:
        checks.append(CheckResult("Meta Description", "Meta Description", "Passed", d[:100]))
    return ModuleResult("Meta Description", checks, findings, {})


def tool_heading_structure(url, config):
    checks, findings = [], []
    _, resp, parser = _get_page_data(config, url)
    if resp.error:
        return ModuleResult("Headings", [CheckResult("Request", "Headings", "Failed", resp.error)], [], {})
    h_counts = Counter(h[0] for h in parser.headings)
    h1s = h_counts.get("h1", 0)
    if h1s == 0:
        checks.append(CheckResult("H1", "Headings", "Failed", "No H1", "", "Medium"))
        findings.append(_mk_finding("H1-001", "Headings", url, "H1", "Missing H1",
                                    "SEO", "Medium", "HTML parsing", "No H1", "No H1 found.",
                                    "SEO impact.", "Add a single H1.", "<h1>Page Title</h1>", "Re-scan"))
    elif h1s > 1:
        checks.append(CheckResult("H1 Count", "Headings", "Warning", f"{h1s} H1 tags"))
    else:
        checks.append(CheckResult("H1", "Headings", "Passed", "1 H1"))
    for lvl in ["h2", "h3", "h4", "h5", "h6"]:
        c = h_counts.get(lvl, 0)
        checks.append(CheckResult(lvl.upper(), "Headings", "Info", f"{c}"))
    return ModuleResult("Headings", checks, findings, {"counts": dict(h_counts)})


def tool_og_tags(url, config):
    checks, findings = [], []
    _, resp, parser = _get_page_data(config, url)
    if resp.error:
        return ModuleResult("Open Graph", [CheckResult("Request", "Open Graph", "Failed", resp.error)], [], {})
    required = ["og:title", "og:description", "og:image", "og:url", "og:type"]
    missing = [k for k in required if k not in parser.meta]
    if missing:
        checks.append(CheckResult("OG Tags", "Open Graph", "Warning", f"Missing: {', '.join(missing)}", "", "Low"))
        findings.append(_mk_finding("OG-001", "Open Graph", url, "meta[og:*]",
                                    "Open Graph Tags Missing", "SEO", "Low", "HTML parsing",
                                    f"Missing: {', '.join(missing)}", "OG tags incomplete.",
                                    "Poor social sharing.", "Add missing OG tags.",
                                    '<meta property="og:title" content="...">', "Re-scan"))
    else:
        checks.append(CheckResult("OG Tags", "Open Graph", "Passed", "All required OG tags present"))
    return ModuleResult("Open Graph", checks, findings, {})


def tool_twitter_cards(url, config):
    checks, findings = [], []
    _, resp, parser = _get_page_data(config, url)
    if resp.error:
        return ModuleResult("Twitter Cards", [CheckResult("Request", "Twitter Cards", "Failed", resp.error)], [], {})
    required = ["twitter:card", "twitter:title", "twitter:description"]
    missing = [k for k in required if k not in parser.meta]
    if missing:
        checks.append(CheckResult("Twitter Cards", "Twitter Cards", "Warning", f"Missing: {', '.join(missing)}", "", "Low"))
    else:
        checks.append(CheckResult("Twitter Cards", "Twitter Cards", "Passed", "All required tags present"))
    return ModuleResult("Twitter Cards", checks, findings, {})


def tool_canonical(url, config):
    checks, findings = [], []
    _, resp, parser = _get_page_data(config, url)
    if resp.error:
        return ModuleResult("Canonical", [CheckResult("Request", "Canonical", "Failed", resp.error)], [], {})
    found = "canonical" in str(parser.meta).lower() or any(
        l.get("rel", "").lower() == "canonical" for l in parser.links)
    if found:
        checks.append(CheckResult("Canonical", "Canonical", "Passed", "Present"))
    else:
        checks.append(CheckResult("Canonical", "Canonical", "Warning", "Missing", "", "Low"))
        findings.append(_mk_finding("CAN-001", "Canonical", url, "link[rel=canonical]",
                                    "Canonical Link Missing", "SEO", "Low", "HTML parsing",
                                    "No canonical link", "Canonical not defined.",
                                    "Duplicate content risk.", "Add canonical link.",
                                    '<link rel="canonical" href="https://example.com/page">', "Re-scan"))
    return ModuleResult("Canonical", checks, findings, {})


def tool_robots_txt(url, config):
    checks, findings = [], []
    parsed = urllib.parse.urlparse(url)
    robots_url = f"{parsed.scheme}://{parsed.netloc}/robots.txt"
    policy = SecurityPolicy()
    client = HTTPClient(config, policy)
    resp = client.fetch(robots_url)
    if resp.error or resp.status != 200:
        checks.append(CheckResult("robots.txt", "Robots.txt", "Info", f"HTTP {resp.status}"))
    else:
        content = resp.body.decode("utf-8", errors="replace")
        checks.append(CheckResult("robots.txt", "Robots.txt", "Passed", f"{len(content)} bytes"))
        if "disallow: /" in content.lower():
            checks.append(CheckResult("Disallow All", "Robots.txt", "Warning", "Disallow: /", "", "Low"))
            findings.append(_mk_finding("ROB-001", "Robots.txt", url, "robots.txt",
                                        "Robots.txt Disallows All", "SEO", "Low", "Content",
                                        "Disallow: /", "All crawling blocked.", "Site won't be indexed.",
                                        "Review robots.txt", "", "Verify robots.txt"))
        data = {"content": content[:500]}
    return ModuleResult("Robots.txt", checks, findings, data if resp.status == 200 else {})


def tool_sitemap_xml(url, config):
    checks, findings = [], []
    parsed = urllib.parse.urlparse(url)
    sitemap_url = f"{parsed.scheme}://{parsed.netloc}/sitemap.xml"
    policy = SecurityPolicy()
    client = HTTPClient(config, policy)
    resp = client.fetch(sitemap_url)
    if resp.error or resp.status != 200:
        checks.append(CheckResult("sitemap.xml", "Sitemap", "Warning", f"HTTP {resp.status}", "", "Low"))
    else:
        content = resp.body.decode("utf-8", errors="replace")
        url_count = content.count("<loc>")
        checks.append(CheckResult("sitemap.xml", "Sitemap", "Passed", f"{url_count} URLs"))
        data = {"url_count": url_count}
    return ModuleResult("Sitemap", checks, findings, data if resp.status == 200 else {})


def tool_favicon(url, config):
    checks, findings = [], []
    parsed = urllib.parse.urlparse(url)
    favicon_url = f"{parsed.scheme}://{parsed.netloc}/favicon.ico"
    policy = SecurityPolicy()
    client = HTTPClient(config, policy)
    resp = client.fetch(favicon_url)
    if resp.status == 200:
        checks.append(CheckResult("favicon.ico", "Favicon", "Passed", f"{len(resp.body)} bytes"))
    else:
        checks.append(CheckResult("favicon.ico", "Favicon", "Warning", f"HTTP {resp.status}"))
    return ModuleResult("Favicon", checks, findings, {})


def tool_html_lang(url, config):
    checks, findings = [], []
    _, resp, parser = _get_page_data(config, url)
    if resp.error:
        return ModuleResult("HTML Lang", [CheckResult("Request", "HTML Lang", "Failed", resp.error)], [], {})
    lang = parser.get_lang()
    if lang:
        checks.append(CheckResult("HTML lang", "HTML Lang", "Passed", lang))
    else:
        checks.append(CheckResult("HTML lang", "HTML Lang", "Failed", "Missing", "", "Low"))
        findings.append(_mk_finding("LANG-001", "HTML Lang", url, "<html>",
                                    "Missing HTML lang", "SEO", "Low", "HTML parsing",
                                    "No lang attr", "lang not set.", "Accessibility & SEO.",
                                    "Add lang attribute.", '<html lang="en">', "Re-scan"))
    return ModuleResult("HTML Lang", checks, findings, {})


def tool_doctype(url, config):
    checks, findings = [], []
    _, resp, parser = _get_page_data(config, url)
    if resp.error:
        return ModuleResult("DOCTYPE", [CheckResult("Request", "DOCTYPE", "Failed", resp.error)], [], {})
    if parser.has_doctype():
        checks.append(CheckResult("DOCTYPE", "DOCTYPE", "Passed", "HTML5 doctype present"))
    else:
        checks.append(CheckResult("DOCTYPE", "DOCTYPE", "Warning", "Missing doctype", "", "Low"))
    return ModuleResult("DOCTYPE", checks, findings, {})


def tool_viewport(url, config):
    checks, findings = [], []
    _, resp, parser = _get_page_data(config, url)
    if resp.error:
        return ModuleResult("Viewport", [CheckResult("Request", "Viewport", "Failed", resp.error)], [], {})
    vp = parser.get_viewport()
    if vp:
        checks.append(CheckResult("Viewport", "Viewport", "Passed", vp))
    else:
        checks.append(CheckResult("Viewport", "Viewport", "Failed", "Missing viewport meta", "", "Medium"))
        findings.append(_mk_finding("VP-001", "Viewport", url, "meta[viewport]",
                                    "Missing Viewport Meta", "SEO", "Medium", "HTML parsing",
                                    "No viewport", "Mobile rendering broken.",
                                    "Poor mobile UX.", "Add viewport meta.",
                                    '<meta name="viewport" content="width=device-width, initial-scale=1.0">', "Re-scan"))
    return ModuleResult("Viewport", checks, findings, {})


# ============================================================
# PERFORMANCE TOOLS
# ============================================================

def tool_response_time(url, config):
    checks, findings = [], []
    policy = SecurityPolicy()
    client = HTTPClient(config, policy)
    times = []
    for _ in range(3):
        r = client.fetch(url)
        if not r.error:
            times.append(r.elapsed * 1000)
    if times:
        avg = sum(times) / len(times)
        checks.append(CheckResult("Avg Response", "Response Time", "Info", f"{avg:.0f} ms (3 runs)"))
        if avg > config.get("perf_slow_ms", 2000):
            checks.append(CheckResult("Speed", "Response Time", "Warning", f"Slow: {avg:.0f} ms", "", "Low"))
            findings.append(_mk_finding("RT-001", "Response Time", url, "Server",
                                        "Slow Response Time", "Performance", "Low", "Timing",
                                        f"{avg:.0f} ms", "Response too slow.", "Poor UX.",
                                        "Optimize server, enable caching.",
                                        "# Enable caching, use CDN", "Re-scan"))
        else:
            checks.append(CheckResult("Speed", "Response Time", "Passed", f"{avg:.0f} ms"))
        return ModuleResult("Response Time", checks, findings, {"times": times, "avg": avg})
    return ModuleResult("Response Time", [CheckResult("Request", "Response Time", "Failed", "No response")], [], {})


def tool_document_size(url, config):
    checks, findings = [], []
    policy = SecurityPolicy()
    client = HTTPClient(config, policy)
    resp = client.fetch(url)
    if resp.error:
        return ModuleResult("Document Size", [CheckResult("Request", "Document Size", "Failed", resp.error)], [], {})
    size_kb = len(resp.body) / 1024.0
    checks.append(CheckResult("Size", "Document Size", "Info", f"{size_kb:.1f} KB"))
    if size_kb > config.get("perf_large_kb", 500):
        checks.append(CheckResult("Large", "Document Size", "Warning", f"{size_kb:.0f} KB", "", "Low"))
        findings.append(_mk_finding("SIZE-001", "Document Size", url, "HTML",
                                    "Large HTML Document", "Performance", "Low", "Body length",
                                    f"{size_kb:.0f} KB", "HTML too large.", "Slow rendering.",
                                    "Minify HTML, split content.", "", "Re-scan"))
    return ModuleResult("Document Size", checks, findings, {"size_kb": size_kb})


def tool_compression(url, config):
    checks, findings = [], []
    policy = SecurityPolicy()
    client = HTTPClient(config, policy)
    resp = client.fetch(url)
    if resp.error:
        return ModuleResult("Compression", [CheckResult("Request", "Compression", "Failed", resp.error)], [], {})
    hdrs = {k.lower(): v for k, v in resp.headers}
    enc = hdrs.get("content-encoding", "")
    if enc:
        checks.append(CheckResult("Compression", "Compression", "Passed", enc))
    else:
        checks.append(CheckResult("Compression", "Compression", "Warning", "Not enabled", "", "Low"))
        findings.append(_mk_finding("COMP-001", "Compression", url, "Content-Encoding",
                                    "Compression Not Enabled", "Performance", "Low", "Header",
                                    "No Content-Encoding", "No compression.", "Slow loads.",
                                    "Enable gzip/brotli.",
                                    "gzip on; gzip_types text/html;", "Re-scan"))
    return ModuleResult("Compression", checks, findings, {})


def tool_brotli(url, config):
    checks, findings = [], []
    policy = SecurityPolicy()
    client = HTTPClient(config, policy)
    try:
        req = urllib.request.Request(url, headers={
            "User-Agent": config.get("user_agent"),
            "Accept-Encoding": "br, gzip, deflate",
        })
        ctx = ssl.create_default_context() if url.startswith("https") else None
        args = dict(timeout=10)
        if ctx: args["context"] = ctx
        resp = urllib.request.urlopen(req, **args)
        enc = (resp.headers.get("Content-Encoding") or "").lower()
        if "br" in enc:
            checks.append(CheckResult("Brotli", "Brotli", "Passed", "Brotli supported"))
        else:
            checks.append(CheckResult("Brotli", "Brotli", "Info", f"Not used (encoding: {enc or 'none'})"))
    except Exception as e:
        checks.append(CheckResult("Brotli", "Brotli", "Not Tested", str(e)[:80]))
    return ModuleResult("Brotli", checks, findings, {})


def tool_keep_alive(url, config):
    checks, findings = [], []
    policy = SecurityPolicy()
    client = HTTPClient(config, policy)
    resp = client.fetch(url)
    if resp.error:
        return ModuleResult("Keep-Alive", [CheckResult("Request", "Keep-Alive", "Failed", resp.error)], [], {})
    hdrs = {k.lower(): v for k, v in resp.headers}
    conn = hdrs.get("connection", "")
    keep = hdrs.get("keep-alive", "")
    if "keep-alive" in conn.lower() or keep:
        checks.append(CheckResult("Keep-Alive", "Keep-Alive", "Passed", f"Connection: {conn}, {keep}"))
    else:
        checks.append(CheckResult("Keep-Alive", "Keep-Alive", "Info", "Not advertised"))
    return ModuleResult("Keep-Alive", checks, findings, {})


def tool_http_protocol_version(url, config):
    checks, findings = [], []
    parsed = urllib.parse.urlparse(url)
    if parsed.scheme != "https":
        checks.append(CheckResult("Protocol", "HTTP Version", "Info", "HTTP/1.1 (no HTTPS)"))
        return ModuleResult("HTTP Version", checks, findings, {})
    try:
        ctx = ssl.create_default_context()
        ctx.set_alpn_protocols(["h2", "http/1.1"])
        with socket.create_connection((parsed.hostname, parsed.port or 443), timeout=10) as s:
            with ctx.wrap_socket(s, server_hostname=parsed.hostname) as ss:
                proto = ss.selected_alpn_protocol() or "http/1.1"
                checks.append(CheckResult("Protocol", "HTTP Version", "Info", proto))
                return ModuleResult("HTTP Version", checks, findings, {"protocol": proto})
    except Exception as e:
        return ModuleResult("HTTP Version", [CheckResult("Protocol", "HTTP Version", "Failed", str(e)[:100])], [], {})


def tool_cdn_detection(url, config):
    checks, findings = [], []
    policy = SecurityPolicy()
    client = HTTPClient(config, policy)
    resp = client.fetch(url)
    if resp.error:
        return ModuleResult("CDN", [CheckResult("Request", "CDN", "Failed", resp.error)], [], {})
    hdrs = {k.lower(): v for k, v in resp.headers}
    cdn_sigs = {
        "Cloudflare": ["cf-ray", "cf-cache-status"],
        "CloudFront": ["x-amz-cf-id", "x-amz-cf-pop"],
        "Fastly": ["x-fastly", "fastly"],
        "Akamai": ["x-akamai", "akamai"],
        "Vercel": ["x-vercel", "vercel"],
        "Netlify": ["x-nf", "netlify"],
        "Azure CDN": ["x-azure", "azure"],
        "Google Cloud CDN": ["x-cloud-trace-context"],
    }
    detected = []
    for cdn, sigs in cdn_sigs.items():
        for sig in sigs:
            if any(sig in k for k in hdrs):
                detected.append(cdn)
                break
    if detected:
        checks.append(CheckResult("CDN", "CDN", "Passed", f"Detected: {', '.join(set(detected))}"))
    else:
        checks.append(CheckResult("CDN", "CDN", "Info", "No CDN detected"))
    return ModuleResult("CDN", checks, findings, {"cdns": list(set(detected))})


def tool_ttfb(url, config):
    checks, findings = [], []
    parsed = urllib.parse.urlparse(url)
    try:
        if parsed.scheme == "https":
            ctx = ssl.create_default_context()
            with socket.create_connection((parsed.hostname, parsed.port or 443), timeout=10) as s:
                t0 = time.time()
                with ctx.wrap_socket(s, server_hostname=parsed.hostname) as ss:
                    req = b"GET / HTTP/1.1\r\nHost: " + parsed.hostname.encode() + b"\r\nUser-Agent: SCIT-BOSS\r\n\r\n"
                    ss.send(req)
                    first = ss.recv(1)
                    ttfb = (time.time() - t0) * 1000
                    checks.append(CheckResult("TTFB", "TTFB", "Info", f"{ttfb:.0f} ms"))
                    if ttfb > 600:
                        checks.append(CheckResult("TTFB Status", "TTFB", "Warning", "Slow TTFB", "", "Low"))
                    else:
                        checks.append(CheckResult("TTFB Status", "TTFB", "Passed", "Fast"))
                    return ModuleResult("TTFB", checks, findings, {"ttfb_ms": ttfb})
    except Exception as e:
        checks.append(CheckResult("TTFB", "TTFB", "Failed", str(e)[:100]))
    return ModuleResult("TTFB", checks, findings, {})


def tool_static_assets_count(url, config):
    checks, findings = [], []
    _, resp, parser = _get_page_data(config, url)
    if resp.error:
        return ModuleResult("Assets", [CheckResult("Request", "Assets", "Failed", resp.error)], [], {})
    counts = {"scripts": len(parser.scripts), "stylesheets": len(parser.stylesheets),
              "images": len(parser.images), "iframes": len(parser.iframes)}
    total = sum(counts.values())
    checks.append(CheckResult("Total Assets", "Assets", "Info", f"{total} reference(s)"))
    for k, v in counts.items():
        checks.append(CheckResult(k.title(), "Assets", "Info", str(v)))
    if counts["scripts"] > 15:
        checks.append(CheckResult("Script Count", "Assets", "Warning", f"{counts['scripts']} scripts", "", "Low"))
    return ModuleResult("Assets", checks, findings, counts)


def tool_render_blocking(url, config):
    checks, findings = [], []
    _, resp, parser = _get_page_data(config, url)
    if resp.error:
        return ModuleResult("Render Blocking", [CheckResult("Request", "Render Blocking", "Failed", resp.error)], [], {})
    blocking = []
    for sc in parser.scripts:
        if sc and not any(x in sc.lower() for x in ["async", "defer"]):
            blocking.append(sc)
    # scripts list doesn't capture async/defer, so use simple heuristic
    checks.append(CheckResult("Render-blocking scripts", "Render Blocking", "Info", f"{len(parser.scripts)} script(s)"))
    if parser.stylesheets:
        checks.append(CheckResult("Stylesheets", "Render Blocking", "Info", f"{len(parser.stylesheets)} stylesheet(s)"))
    return ModuleResult("Render Blocking", checks, findings, {"blocking": len(blocking)})


# ============================================================
# LINKS & REDIRECTS TOOLS
# ============================================================

def tool_broken_links(url, config):
    checks, findings = [], []
    _, resp, parser = _get_page_data(config, url)
    if resp.error:
        return ModuleResult("Broken Links", [CheckResult("Request", "Broken Links", "Failed", resp.error)], [], {})
    base = urllib.parse.urlparse(url).hostname
    policy = SecurityPolicy()
    client = HTTPClient(config, policy)
    seen, tested, broken = set(), 0, []
    for link in parser.links:
        href = link.get("href", "").strip()
        if not href or href.startswith(("#", "mailto:", "tel:", "javascript:")):
            continue
        full = urllib.parse.urljoin(url, href)
        p = urllib.parse.urlparse(full)
        if p.scheme not in ("http", "https"):
            continue
        key = full.split("#")[0]
        if key in seen: continue
        seen.add(key)
        tested += 1
        if tested > 30: break
        r = client.fetch(key, max_redirects=2)
        if r.status in (404, 410):
            broken.append(key)
            checks.append(CheckResult(key[:60], "Broken Links", "Failed", f"HTTP {r.status}", "", "Medium"))
    if broken:
        findings.append(_mk_finding("BRK-001", "Broken Links", url, "Links",
                                    f"{len(broken)} Broken Link(s)", "Technical Health", "Medium",
                                    "HTTP status", f"{len(broken)} 404/410", "Broken links found.",
                                    "Bad UX + SEO.", "Fix or remove broken links.", "", "Re-run"))
    else:
        checks.append(CheckResult("Links", "Broken Links", "Passed", f"{tested} link(s) checked"))
    return ModuleResult("Broken Links", checks, findings, {"broken": broken, "tested": tested})


def tool_external_links(url, config):
    checks, findings = [], []
    _, resp, parser = _get_page_data(config, url)
    if resp.error:
        return ModuleResult("External Links", [CheckResult("Request", "External Links", "Failed", resp.error)], [], {})
    base = urllib.parse.urlparse(url).hostname
    external = []
    for link in parser.links:
        href = link.get("href", "")
        if href.startswith(("http://", "https://")):
            p = urllib.parse.urlparse(href)
            if p.hostname and p.hostname != base:
                external.append(href)
    checks.append(CheckResult("External Links", "External Links", "Info", f"{len(external)} external"))
    insecure = [e for e in external if e.startswith("http://")]
    if insecure:
        checks.append(CheckResult("Insecure Links", "External Links", "Warning", f"{len(insecure)} HTTP link(s)", "", "Low"))
    return ModuleResult("External Links", checks, findings, {"external": external[:20]})


def tool_redirect_chain(url, config):
    checks, findings = [], []
    policy = SecurityPolicy()
    client = HTTPClient(config, policy)
    resp = client.fetch(url)
    if resp.error:
        return ModuleResult("Redirect Chain", [CheckResult("Request", "Redirect Chain", "Failed", resp.error)], [], {})
    if len(resp.redirects) > 1:
        checks.append(CheckResult("Redirect Chain", "Redirect Chain", "Warning", f"{len(resp.redirects)} hop(s)", "", "Low"))
    else:
        checks.append(CheckResult("Redirect Chain", "Redirect Chain", "Passed", f"{len(resp.redirects)} hop(s)"))
    return ModuleResult("Redirect Chain", checks, findings, {"chain": resp.redirects})


def tool_redirect_loops(url, config):
    checks, findings = [], []
    policy = SecurityPolicy()
    client = HTTPClient(config, policy)
    resp = client.fetch(url, max_redirects=10)
    if resp.error and "limit" in (resp.error or "").lower():
        checks.append(CheckResult("Redirect Loop", "Redirect Loops", "Failed", "Loop detected", "", "High"))
        findings.append(_mk_finding("LOOP-001", "Redirect Loops", url, "Redirect",
                                    "Redirect Loop", "Technical Health", "High", "Multiple requests",
                                    "Loop", "Redirect loop detected.", "Site broken.",
                                    "Fix redirect rules.", "", "Re-scan"))
    else:
        checks.append(CheckResult("Redirect Loops", "Redirect Loops", "Passed", "No loop"))
    return ModuleResult("Redirect Loops", checks, findings, {})


def tool_mailto_links(url, config):
    checks, findings = [], []
    _, resp, parser = _get_page_data(config, url)
    if resp.error:
        return ModuleResult("Mailto", [CheckResult("Request", "Mailto", "Failed", resp.error)], [], {})
    mailtos = [l.get("href", "") for l in parser.links if l.get("href", "").startswith("mailto:")]
    checks.append(CheckResult("Mailto Links", "Mailto", "Info", f"{len(mailtos)} link(s)"))
    return ModuleResult("Mailto", checks, findings, {"mailtos": mailtos[:10]})


def tool_javascript_links(url, config):
    checks, findings = [], []
    _, resp, parser = _get_page_data(config, url)
    if resp.error:
        return ModuleResult("JS Links", [CheckResult("Request", "JS Links", "Failed", resp.error)], [], {})
    js_links = [l.get("href", "") for l in parser.links if l.get("href", "").startswith("javascript:")]
    if js_links:
        checks.append(CheckResult("JavaScript Links", "JS Links", "Warning", f"{len(js_links)} javascript: link(s)", "", "Low"))
    else:
        checks.append(CheckResult("JavaScript Links", "JS Links", "Passed", "None"))
    return ModuleResult("JS Links", checks, findings, {})


def tool_empty_links(url, config):
    checks, findings = [], []
    _, resp, parser = _get_page_data(config, url)
    if resp.error:
        return ModuleResult("Empty Links", [CheckResult("Request", "Empty Links", "Failed", resp.error)], [], {})
    empty = [l for l in parser.links if l.get("href") == "#"]
    if empty:
        checks.append(CheckResult("Empty Links", "Empty Links", "Warning", f"{len(empty)} '#' link(s)", "", "Low"))
    else:
        checks.append(CheckResult("Empty Links", "Empty Links", "Passed", "None"))
    return ModuleResult("Empty Links", checks, findings, {})


# ============================================================
# DNS & DOMAIN TOOLS
# ============================================================

def tool_dns_lookup(url, config):
    checks, findings, data = [], [], {}
    host = urllib.parse.urlparse(url).hostname or ""
    try:
        t0 = time.time()
        infos = socket.getaddrinfo(host, None)
        data["time_ms"] = (time.time() - t0) * 1000
        ips_v4 = sorted({i[4][0] for i in infos if i[0] == socket.AF_INET})
        ips_v6 = sorted({i[4][0] for i in infos if i[0] == socket.AF_INET6})
        data["ipv4"] = ips_v4
        data["ipv6"] = ips_v6
        checks.append(CheckResult("A Records", "DNS Lookup", "Passed" if ips_v4 else "Not Tested",
                                  ", ".join(ips_v4) if ips_v4 else "None"))
        checks.append(CheckResult("AAAA Records", "DNS Lookup", "Passed" if ips_v6 else "Not Tested",
                                  ", ".join(ips_v6) if ips_v6 else "None"))
        checks.append(CheckResult("Timing", "DNS Lookup", "Info", f"{data['time_ms']:.0f} ms"))
    except Exception as e:
        checks.append(CheckResult("DNS", "DNS Lookup", "Failed", str(e), "", "High"))
    return ModuleResult("DNS Lookup", checks, findings, data)


def tool_reverse_dns(url, config):
    checks, findings = [], []
    host = urllib.parse.urlparse(url).hostname or ""
    try:
        ip = socket.gethostbyname(host)
        try:
            reverse = socket.gethostbyaddr(ip)
            checks.append(CheckResult("Reverse DNS", "Reverse DNS", "Passed", f"{ip} → {reverse[0]}"))
        except Exception:
            checks.append(CheckResult("Reverse DNS", "Reverse DNS", "Warning", f"No PTR for {ip}"))
    except Exception as e:
        checks.append(CheckResult("Reverse DNS", "Reverse DNS", "Failed", str(e)))
    return ModuleResult("Reverse DNS", checks, findings, {})


def tool_ip_geolocation(url, config):
    checks, findings = [], []
    host = urllib.parse.urlparse(url).hostname or ""
    try:
        ip = socket.gethostbyname(host)
        # Free API without key
        req = urllib.request.Request(f"http://ip-api.com/json/{ip}",
                                     headers={"User-Agent": config.get("user_agent")})
        with urllib.request.urlopen(req, timeout=10) as r:
            data = json.loads(r.read().decode())
        if data.get("status") == "success":
            loc = f"{data.get('country','?')}, {data.get('city','?')} ({data.get('isp','?')})"
            checks.append(CheckResult("Geo IP", "Geo IP", "Info", loc))
            return ModuleResult("Geo IP", checks, findings, data)
    except Exception as e:
        checks.append(CheckResult("Geo IP", "Geo IP", "Not Tested", str(e)[:100]))
    return ModuleResult("Geo IP", checks, findings, {})


def tool_spf_record(url, config):
    checks, findings = [], []
    host = urllib.parse.urlparse(url).hostname or ""
    parts = host.split(".")
    domain = ".".join(parts[-2:]) if len(parts) >= 2 else host
    try:
        import subprocess
        # Try nslookup fallback
        result = subprocess.run(["nslookup", "-type=TXT", domain],
                                capture_output=True, timeout=10, text=True)
        output = result.stdout.lower()
        if "v=spf1" in output:
            checks.append(CheckResult("SPF", "SPF", "Passed", "SPF record found"))
        else:
            checks.append(CheckResult("SPF", "SPF", "Warning", "No SPF record", "", "Low"))
    except Exception as e:
        checks.append(CheckResult("SPF", "SPF", "Not Tested", str(e)[:100]))
    return ModuleResult("SPF", checks, findings, {})


def tool_dmarc_record(url, config):
    checks, findings = [], []
    host = urllib.parse.urlparse(url).hostname or ""
    parts = host.split(".")
    domain = ".".join(parts[-2:]) if len(parts) >= 2 else host
    try:
        import subprocess
        result = subprocess.run(["nslookup", "-type=TXT", f"_dmarc.{domain}"],
                                capture_output=True, timeout=10, text=True)
        output = result.stdout.lower()
        if "v=dmarc1" in output:
            checks.append(CheckResult("DMARC", "DMARC", "Passed", "DMARC record found"))
        else:
            checks.append(CheckResult("DMARC", "DMARC", "Warning", "No DMARC record", "", "Low"))
    except Exception as e:
        checks.append(CheckResult("DMARC", "DMARC", "Not Tested", str(e)[:100]))
    return ModuleResult("DMARC", checks, findings, {})


def tool_mx_records(url, config):
    checks, findings = [], []
    host = urllib.parse.urlparse(url).hostname or ""
    parts = host.split(".")
    domain = ".".join(parts[-2:]) if len(parts) >= 2 else host
    try:
        import subprocess
        result = subprocess.run(["nslookup", "-type=MX", domain],
                                capture_output=True, timeout=10, text=True)
        output = result.stdout
        if "mail exchanger" in output.lower():
            checks.append(CheckResult("MX Records", "MX Records", "Passed", "MX found"))
        else:
            checks.append(CheckResult("MX Records", "MX Records", "Info", "No MX (may not be needed)"))
    except Exception as e:
        checks.append(CheckResult("MX", "MX Records", "Not Tested", str(e)[:100]))
    return ModuleResult("MX Records", checks, findings, {})


def tool_txt_records(url, config):
    checks, findings = [], []
    host = urllib.parse.urlparse(url).hostname or ""
    parts = host.split(".")
    domain = ".".join(parts[-2:]) if len(parts) >= 2 else host
    try:
        import subprocess
        result = subprocess.run(["nslookup", "-type=TXT", domain],
                                capture_output=True, timeout=10, text=True)
        checks.append(CheckResult("TXT Records", "TXT Records", "Info", "Lookup complete"))
    except Exception as e:
        checks.append(CheckResult("TXT", "TXT Records", "Not Tested", str(e)[:100]))
    return ModuleResult("TXT Records", checks, findings, {})


def tool_ns_records(url, config):
    checks, findings = [], []
    host = urllib.parse.urlparse(url).hostname or ""
    parts = host.split(".")
    domain = ".".join(parts[-2:]) if len(parts) >= 2 else host
    try:
        import subprocess
        result = subprocess.run(["nslookup", "-type=NS", domain],
                                capture_output=True, timeout=10, text=True)
        if "nameserver" in result.stdout.lower():
            checks.append(CheckResult("NS Records", "NS Records", "Passed", "NS found"))
        else:
            checks.append(CheckResult("NS Records", "NS Records", "Warning", "No NS found"))
    except Exception as e:
        checks.append(CheckResult("NS", "NS Records", "Not Tested", str(e)[:100]))
    return ModuleResult("NS Records", checks, findings, {})


def tool_caa_record(url, config):
    checks, findings = [], []
    host = urllib.parse.urlparse(url).hostname or ""
    parts = host.split(".")
    domain = ".".join(parts[-2:]) if len(parts) >= 2 else host
    try:
        import subprocess
        result = subprocess.run(["nslookup", "-type=CAA", domain],
                                capture_output=True, timeout=10, text=True)
        if "issue" in result.stdout.lower() or "caa" in result.stdout.lower():
            checks.append(CheckResult("CAA", "CAA Record", "Passed", "CAA found"))
        else:
            checks.append(CheckResult("CAA", "CAA Record", "Info", "No CAA record"))
    except Exception as e:
        checks.append(CheckResult("CAA", "CAA Record", "Not Tested", str(e)[:100]))
    return ModuleResult("CAA Record", checks, findings, {})


def tool_cname_chain(url, config):
    checks, findings = [], []
    host = urllib.parse.urlparse(url).hostname or ""
    try:
        import subprocess
        result = subprocess.run(["nslookup", "-type=CNAME", host],
                                capture_output=True, timeout=10, text=True)
        if "canonical name" in result.stdout.lower():
            checks.append(CheckResult("CNAME", "CNAME Chain", "Info", "CNAME found"))
        else:
            checks.append(CheckResult("CNAME", "CNAME Chain", "Info", "No CNAME"))
    except Exception as e:
        checks.append(CheckResult("CNAME", "CNAME Chain", "Not Tested", str(e)[:100]))
    return ModuleResult("CNAME Chain", checks, findings, {})


# ============================================================
# TECHNOLOGY DETECTION TOOLS
# ============================================================

def tool_cms_detect(url, config):
    checks, findings, data = [], [], {"detected": []}
    _, resp, parser = _get_page_data(config, url)
    if resp.error:
        return ModuleResult("CMS Detect", [CheckResult("Request", "CMS Detect", "Failed", resp.error)], [], {})
    hdrs = {k.lower(): v for k, v in resp.headers}
    haystack = " ".join([
        hdrs.get("server", ""), hdrs.get("x-powered-by", ""), parser.title,
        " ".join(l.get("href", "") for l in parser.links),
        " ".join(parser.scripts), " ".join(parser.stylesheets),
    ]).lower()
    cms_sigs = {
        "WordPress": r"wp-content|wp-includes|wordpress",
        "Joomla": r"/components/com_|joomla",
        "Drupal": r"drupal\.settings|/sites/default/files/",
        "Magento": r"magento|mage/cookies",
        "Shopify": r"shopify\.com|cdn\.shopify",
        "Wix": r"wix\.com|wixstatic",
        "Squarespace": r"squarespace\.com",
        "Ghost": r"ghost\.org|ghost-url",
        "PrestaShop": r"prestashop",
        "OpenCart": r"opencart",
        "TYPO3": r"typo3",
        "Concrete5": r"concrete5",
        "MODX": r"modx",
        "Blogger": r"blogger\.com",
    }
    for cms, pattern in cms_sigs.items():
        if re.search(pattern, haystack, re.IGNORECASE):
            data["detected"].append(cms)
            checks.append(CheckResult(cms, "CMS Detect", "Info", "Detected"))
    if not data["detected"]:
        checks.append(CheckResult("CMS", "CMS Detect", "Info", "No CMS signatures matched"))
    return ModuleResult("CMS Detect", checks, findings, data)


def tool_framework_detect(url, config):
    checks, findings, data = [], [], {"detected": []}
    _, resp, parser = _get_page_data(config, url)
    if resp.error:
        return ModuleResult("Framework", [CheckResult("Request", "Framework", "Failed", resp.error)], [], {})
    hdrs = {k.lower(): v for k, v in resp.headers}
    haystack = " ".join([
        hdrs.get("x-powered-by", ""), hdrs.get("server", ""),
        " ".join(parser.scripts),
        " ".join(l.get("href", "") for l in parser.links),
    ]).lower()
    sigs = {
        "Laravel": r"laravel",
        "Symfony": r"symfony",
        "Django": r"django|csrfmiddlewaretoken",
        "Flask": r"flask",
        "Rails": r"rails|action_dispatch",
        "Express": r"express",
        "Next.js": r"__next|next\.js|/_next/",
        "Nuxt.js": r"__nuxt|nuxt",
        "Angular": r"ng-version|angular",
        "React": r"_react|react-dom|reactjs",
        "Vue.js": r"vue\.js|vue\.min",
        "Svelte": r"svelte",
        "jQuery": r"jquery",
        "Bootstrap": r"bootstrap",
        "Tailwind": r"tailwind",
    }
    for fw, pattern in sigs.items():
        if re.search(pattern, haystack, re.IGNORECASE):
            data["detected"].append(fw)
            checks.append(CheckResult(fw, "Framework", "Info", "Detected"))
    if not data["detected"]:
        checks.append(CheckResult("Framework", "Framework", "Info", "No signatures matched"))
    return ModuleResult("Framework", checks, findings, data)


def tool_js_libraries(url, config):
    checks, findings, data = [], [], {"libs": []}
    _, resp, parser = _get_page_data(config, url)
    if resp.error:
        return ModuleResult("JS Libraries", [CheckResult("Request", "JS Libraries", "Failed", resp.error)], [], {})
    libs = {}
    for sc in parser.scripts:
        for lib, pattern in [
            ("jQuery", r"jquery"), ("React", r"react"), ("Vue", r"vue"),
            ("Angular", r"angular"), ("Bootstrap", r"bootstrap"),
            ("Lodash", r"lodash"), ("Moment", r"moment"),
            ("D3", r"d3\.js"), ("Chart.js", r"chart\.js"),
            ("Swiper", r"swiper"), ("GSAP", r"gsap"),
        ]:
            if re.search(pattern, sc, re.IGNORECASE):
                libs[lib] = sc
                break
    for lib in libs:
        checks.append(CheckResult(lib, "JS Libraries", "Info", libs[lib][:80]))
    data["libs"] = list(libs.keys())
    if not libs:
        checks.append(CheckResult("Libraries", "JS Libraries", "Info", "None detected"))
    return ModuleResult("JS Libraries", checks, findings, data)


def tool_analytics(url, config):
    checks, findings = [], []
    _, resp, parser = _get_page_data(config, url)
    if resp.error:
        return ModuleResult("Analytics", [CheckResult("Request", "Analytics", "Failed", resp.error)], [], {})
    all_src = " ".join(parser.scripts + [l.get("href", "") for l in parser.links]).lower()
    found = []
    for name, pattern in [
        ("Google Analytics", r"google-analytics|gtag|googletagmanager"),
        ("Facebook Pixel", r"facebook.*pixel|connect\.facebook"),
        ("Hotjar", r"hotjar"),
        ("Mixpanel", r"mixpanel"),
        ("Segment", r"segment\.io"),
        ("Plausible", r"plausible\.io"),
        ("Matomo", r"matomo|piwik"),
    ]:
        if re.search(pattern, all_src, re.IGNORECASE):
            found.append(name)
            checks.append(CheckResult(name, "Analytics", "Info", "Detected"))
    if not found:
        checks.append(CheckResult("Analytics", "Analytics", "Info", "None detected"))
    return ModuleResult("Analytics", checks, findings, {"analytics": found})


def tool_web_server(url, config):
    checks, findings = [], []
    _, resp, _ = _get_page_data(config, url)
    if resp.error:
        return ModuleResult("Web Server", [CheckResult("Request", "Web Server", "Failed", resp.error)], [], {})
    hdrs = {k.lower(): v for k, v in resp.headers}
    server = hdrs.get("server", "")
    if not server:
        checks.append(CheckResult("Server", "Web Server", "Info", "Not disclosed"))
        return ModuleResult("Web Server", checks, findings, {})
    servers = []
    for name in ["nginx", "apache", "iis", "caddy", "litespeed", "openresty", "cloudflare"]:
        if name in server.lower():
            servers.append(name)
    checks.append(CheckResult("Server", "Web Server", "Info", server))
    return ModuleResult("Web Server", checks, findings, {"servers": servers})


def tool_programming_lang(url, config):
    checks, findings = [], []
    _, resp, parser = _get_page_data(config, url)
    if resp.error:
        return ModuleResult("Language", [CheckResult("Request", "Language", "Failed", resp.error)], [], {})
    hdrs = {k.lower(): v for k, v in resp.headers}
    powered = hdrs.get("x-powered-by", "").lower()
    langs = []
    if "php" in powered:
        langs.append("PHP")
    if "asp.net" in powered:
        langs.append("ASP.NET")
    if "express" in powered or "node" in powered:
        langs.append("Node.js")
    if "django" in powered or "python" in powered:
        langs.append("Python")
    if "rails" in powered or "ruby" in powered:
        langs.append("Ruby")
    checks.append(CheckResult("Language", "Language", "Info",
                              ", ".join(langs) if langs else "Unknown"))
    return ModuleResult("Language", checks, findings, {"languages": langs})


def tool_operating_system(url, config):
    checks, findings = [], []
    _, resp, _ = _get_page_data(config, url)
    if resp.error:
        return ModuleResult("OS", [CheckResult("Request", "OS", "Failed", resp.error)], [], {})
    hdrs = {k.lower(): v for k, v in resp.headers}
    server = hdrs.get("server", "").lower()
    os_detected = []
    for os_name, pattern in [("Linux", r"linux|ubuntu|debian|centos"),
                              ("Windows", r"win32|win64|windows|iis"),
                              ("macOS", r"darwin|mac os")]:
        if re.search(pattern, server):
            os_detected.append(os_name)
    checks.append(CheckResult("OS", "OS", "Info",
                              ", ".join(os_detected) if os_detected else "Unknown"))
    return ModuleResult("OS", checks, findings, {"os": os_detected})


def tool_waf_detect(url, config):
    checks, findings = [], []
    _, resp, _ = _get_page_data(config, url)
    if resp.error:
        return ModuleResult("WAF", [CheckResult("Request", "WAF", "Failed", resp.error)], [], {})
    hdrs = {k.lower(): v for k, v in resp.headers}
    waf_sigs = {
        "Cloudflare": ["cf-ray", "server: cloudflare"],
        "AWS WAF": ["x-amzn-requestid", "x-amzn-trace-id"],
        "Sucuri": ["x-sucuri"],
        "Imperva": ["x-iinfo", "incap_ses"],
        "F5 BIG-IP": ["x-wa-info", "bigip"],
        "Akamai": ["x-akamai"],
        "Barracuda": ["barra"],
        "ModSecurity": ["mod_security"],
    }
    detected = []
    hdrs_str = " ".join(f"{k}: {v}" for k, v in hdrs.items()).lower()
    for waf, sigs in waf_sigs.items():
        if any(sig in hdrs_str for sig in sigs):
            detected.append(waf)
    if detected:
        checks.append(CheckResult("WAF", "WAF", "Passed", f"Detected: {', '.join(detected)}"))
    else:
        checks.append(CheckResult("WAF", "WAF", "Info", "No WAF detected"))
    return ModuleResult("WAF", checks, findings, {"wafs": detected})


def tool_cdn_cache(url, config):
    checks, findings = [], []
    _, resp, _ = _get_page_data(config, url)
    if resp.error:
        return ModuleResult("CDN Cache", [CheckResult("Request", "CDN Cache", "Failed", resp.error)], [], {})
    hdrs = {k.lower(): v for k, v in resp.headers}
    cache_status = hdrs.get("cf-cache-status", "") or hdrs.get("x-cache", "") or hdrs.get("x-cache-status", "")
    if cache_status:
        checks.append(CheckResult("Cache Status", "CDN Cache", "Info", cache_status))
    else:
        checks.append(CheckResult("Cache Status", "CDN Cache", "Info", "Not available"))
    return ModuleResult("CDN Cache", checks, findings, {"cache_status": cache_status})


def tool_http_headers_list(url, config):
    checks, findings = [], []
    _, resp, _ = _get_page_data(config, url)
    if resp.error:
        return ModuleResult("HTTP Headers", [CheckResult("Request", "HTTP Headers", "Failed", resp.error)], [], {})
    data = {"headers": []}
    for k, v in resp.headers:
        checks.append(CheckResult(k, "HTTP Headers", "Info", v[:100]))
        data["headers"].append((k, v))
    return ModuleResult("HTTP Headers", checks, findings, data)


# ============================================================
# VULNERABILITY & EXPOSURE TOOLS
# ============================================================

def tool_sensitive_files(url, config):
    checks, findings = [], []
    parsed = urllib.parse.urlparse(url)
    base = f"{parsed.scheme}://{parsed.netloc}"
    sensitive = [
        ".env", ".git/config", ".htaccess", "wp-config.php", "config.php",
        "backup.sql", "database.sql", "phpinfo.php", "test.php",
        "adminer.php", "web.config", ".DS_Store", "composer.json",
        "package.json", "yarn.lock", ".htpasswd",
    ]
    policy = SecurityPolicy()
    client = HTTPClient(config, policy)
    exposed = []
    for f in sensitive:
        try:
            r = client.fetch(f"{base}/{f}", max_redirects=0)
            if r.status == 200 and len(r.body) > 0:
                exposed.append((f, len(r.body)))
                checks.append(CheckResult(f, "Sensitive Files", "Failed", f"Accessible ({len(r.body)} bytes)", "", "High"))
        except Exception:
            pass
    if exposed:
        findings.append(_mk_finding("SENS-001", "Sensitive Files", url, "Exposed files",
                                    f"{len(exposed)} Sensitive File(s) Exposed", "Information Exposure", "High",
                                    "HTTP status check", f"Exposed: {', '.join(f for f,_ in exposed[:5])}",
                                    "Sensitive files are publicly accessible.", "Critical data leak.",
                                    "Remove or restrict access.", "Deny from all", "Re-scan"))
    else:
        checks.append(CheckResult("Sensitive Files", "Sensitive Files", "Passed", "None exposed"))
    return ModuleResult("Sensitive Files", checks, findings, {"exposed": exposed})


def tool_directory_listing(url, config):
    checks, findings = [], []
    parsed = urllib.parse.urlparse(url)
    base = f"{parsed.scheme}://{parsed.netloc}"
    dirs = ["/", "/images/", "/uploads/", "/assets/", "/static/", "/backup/", "/admin/", "/.git/"]
    policy = SecurityPolicy()
    client = HTTPClient(config, policy)
    exposed = []
    for d in dirs:
        try:
            r = client.fetch(f"{base}{d}", max_redirects=0)
            if r.status == 200:
                body_low = r.body[:2000].decode("utf-8", errors="replace").lower()
                if "index of /" in body_low or "parent directory" in body_low:
                    exposed.append(d)
                    checks.append(CheckResult(d, "Directory Listing", "Failed", "Directory listing enabled", "", "High"))
        except Exception:
            pass
    if exposed:
        findings.append(_mk_finding("DIR-001", "Directory Listing", url, "Directories",
                                    "Directory Listing Enabled", "Information Exposure", "High",
                                    "HTML body check", ", ".join(exposed), "Directories browsable.",
                                    "File enumeration.", "Disable autoindex.",
                                    "Options -Indexes", "Re-scan"))
    else:
        checks.append(CheckResult("Directory Listing", "Directory Listing", "Passed", "Not enabled"))
    return ModuleResult("Directory Listing", checks, findings, {"exposed": exposed})


def tool_admin_panels(url, config):
    checks, findings = [], []
    parsed = urllib.parse.urlparse(url)
    base = f"{parsed.scheme}://{parsed.netloc}"
    panels = ["/admin", "/admin/", "/administrator", "/wp-admin", "/cpanel",
              "/phpmyadmin", "/admin.php", "/login", "/dashboard"]
    policy = SecurityPolicy()
    client = HTTPClient(config, policy)
    found = []
    for p in panels:
        try:
            r = client.fetch(f"{base}{p}", max_redirects=0)
            if r.status in (200, 401, 403) and r.status != 404:
                found.append(p)
                checks.append(CheckResult(p, "Admin Panels", "Info", f"HTTP {r.status}"))
        except Exception:
            pass
    if not found:
        checks.append(CheckResult("Admin Panels", "Admin Panels", "Info", "None found"))
    return ModuleResult("Admin Panels", checks, findings, {"panels": found})


def tool_backup_files(url, config):
    checks, findings = [], []
    parsed = urllib.parse.urlparse(url)
    base = f"{parsed.scheme}://{parsed.netloc}"
    backups = [f"{parsed.path or '/'}.bak", f"{parsed.path or '/'}.old",
               "/backup.zip", "/backup.tar.gz", "/backup.sql",
               "/site.zip", "/www.zip", "/db.sql"]
    policy = SecurityPolicy()
    client = HTTPClient(config, policy)
    found = []
    for b in backups:
        try:
            r = client.fetch(f"{base}{b}", max_redirects=0)
            if r.status == 200 and len(r.body) > 100:
                found.append(b)
                checks.append(CheckResult(b, "Backup Files", "Failed", f"Accessible ({len(r.body)} bytes)", "", "Critical"))
        except Exception:
            pass
    if found:
        findings.append(_mk_finding("BAK-001", "Backup Files", url, "Backup files",
                                    "Backup Files Exposed", "Information Exposure", "Critical",
                                    "HTTP check", ", ".join(found), "Backup files accessible.",
                                    "Data breach risk.", "Remove public backups.", "", "Re-scan"))
    else:
        checks.append(CheckResult("Backup Files", "Backup Files", "Passed", "None exposed"))
    return ModuleResult("Backup Files", checks, findings, {"found": found})


def tool_source_map_exposure(url, config):
    checks, findings = [], []
    _, resp, parser = _get_page_data(config, url)
    if resp.error:
        return ModuleResult("Source Maps", [CheckResult("Request", "Source Maps", "Failed", resp.error)], [], {})
    maps = []
    for sc in parser.scripts:
        if sc.endswith(".js"):
            full = urllib.parse.urljoin(url, sc)
            map_url = full + ".map"
            policy = SecurityPolicy()
            client = HTTPClient(config, policy)
            try:
                r = client.fetch(map_url, max_redirects=0)
                if r.status == 200:
                    maps.append(map_url)
            except Exception:
                pass
    if maps:
        checks.append(CheckResult("Source Maps", "Source Maps", "Warning", f"{len(maps)} exposed", "", "Low"))
        findings.append(_mk_finding("MAP-001", "Source Maps", url, "Source maps",
                                    "JavaScript Source Maps Exposed", "Information Exposure", "Low",
                                    "HTTP check", ", ".join(maps[:3]), "Source maps accessible.",
                                    "Reveals source code.", "Remove .map files in production.", "", "Re-scan"))
    else:
        checks.append(CheckResult("Source Maps", "Source Maps", "Passed", "No exposed maps"))
    return ModuleResult("Source Maps", checks, findings, {"maps": maps})


def tool_http_methods(url, config):
    checks, findings = [], []
    policy = SecurityPolicy()
    client = HTTPClient(config, policy)
    methods = ["GET", "POST", "PUT", "DELETE", "OPTIONS", "TRACE", "PATCH", "CONNECT"]
    allowed = []
    for m in methods:
        try:
            r = client.fetch(url, method=m, max_redirects=0)
            if r.status not in (405, 501) and r.error is None:
                allowed.append(m)
                checks.append(CheckResult(m, "HTTP Methods", "Info", f"HTTP {r.status}"))
        except Exception:
            pass
    if "TRACE" in allowed:
        findings.append(_mk_finding("MTH-001", "HTTP Methods", url, "HTTP TRACE",
                                    "TRACE Method Enabled", "Security Configuration", "Medium",
                                    "HTTP method probe", "TRACE allowed", "TRACE enabled.",
                                    "Cross-site tracing risk.", "Disable TRACE method.",
                                    "TraceEnable off", "Re-scan"))
    if "PUT" in allowed or "DELETE" in allowed:
        findings.append(_mk_finding("MTH-002", "HTTP Methods", url, "PUT/DELETE",
                                    "Dangerous HTTP Methods", "Security Configuration", "High",
                                    "HTTP method probe", f"Allowed: {allowed}",
                                    "PUT/DELETE enabled.", "Unauthorized modification.",
                                    "Disable PUT/DELETE.", "", "Re-scan"))
    return ModuleResult("HTTP Methods", checks, findings, {"allowed": allowed})


def tool_open_redirect(url, config):
    checks, findings = [], []
    parsed = urllib.parse.urlparse(url)
    test_url = f"{url}?redirect=https://evil.example.com&next=https://evil.example.com"
    policy = SecurityPolicy()
    client = HTTPClient(config, policy)
    r = client.fetch(test_url, max_redirects=0)
    if r.redirects and any("evil.example.com" in redir for redir in r.redirects):
        checks.append(CheckResult("Open Redirect", "Open Redirect", "Failed", "Redirects to external", "", "High"))
        findings.append(_mk_finding("REDIR-002", "Open Redirect", url, "Redirect parameter",
                                    "Open Redirect Vulnerability", "Security Configuration", "High",
                                    "URL parameter probe", "External redirect confirmed",
                                    "URL parameter allows external redirect.", "Phishing risk.",
                                    "Validate redirect URLs against allowlist.", "", "Re-scan"))
    else:
        checks.append(CheckResult("Open Redirect", "Open Redirect", "Passed", "No open redirect"))
    return ModuleResult("Open Redirect", checks, findings, {})


def tool_crlf_injection(url, config):
    checks, findings = [], []
    test = url + "%0d%0aX-Injected: test"
    policy = SecurityPolicy()
    client = HTTPClient(config, policy)
    try:
        r = client.fetch(test, max_redirects=0)
        if any("x-injected" in (k + v).lower() for k, v in r.headers):
            checks.append(CheckResult("CRLF", "CRLF Injection", "Failed", "Header injection confirmed", "", "High"))
        else:
            checks.append(CheckResult("CRLF", "CRLF Injection", "Passed", "No CRLF injection"))
    except Exception:
        checks.append(CheckResult("CRLF", "CRLF Injection", "Not Tested", "Request failed"))
    return ModuleResult("CRLF Injection", checks, findings, {})


def tool_path_traversal(url, config):
    checks, findings = [], []
    parsed = urllib.parse.urlparse(url)
    base = f"{parsed.scheme}://{parsed.netloc}"
    payloads = ["../etc/passwd", "../../etc/passwd", "/etc/passwd",
                "..%2F..%2Fetc%2Fpasswd"]
    policy = SecurityPolicy()
    client = HTTPClient(config, policy)
    found = []
    for p in payloads:
        try:
            r = client.fetch(f"{base}/{p}", max_redirects=0)
            if r.status == 200 and b"root:" in r.body[:2000]:
                found.append(p)
        except Exception:
            pass
    if found:
        checks.append(CheckResult("Path Traversal", "Path Traversal", "Failed", "LFI detected", "", "Critical"))
        findings.append(_mk_finding("LFI-001", "Path Traversal", url, "Filesystem",
                                    "Path Traversal Vulnerable", "Vulnerability", "Critical",
                                    "Payload probe", ", ".join(found), "Local file inclusion possible.",
                                    "File system access.", "Sanitize file paths.", "", "Immediate fix"))
    else:
        checks.append(CheckResult("Path Traversal", "Path Traversal", "Passed", "No LFI detected"))
    return ModuleResult("Path Traversal", checks, findings, {})


def tool_sql_injection_indicator(url, config):
    checks, findings = [], []
    parsed = urllib.parse.urlparse(url)
    payloads = ["'", "\"", "' OR '1'='1", "1' AND SLEEP(5)--"]
    policy = SecurityPolicy()
    client = HTTPClient(config, policy)
    baseline = client.fetch(url)
    baseline_err = b"sql" in baseline.body.lower() and (b"error" in baseline.body.lower() or b"warning" in baseline.body.lower())
    found = []
    for p in payloads:
        try:
            r = client.fetch(f"{url}?id={urllib.parse.quote(p)}", max_redirects=0)
            low = r.body.lower()
            if b"sql syntax" in low or b"mysql_fetch" in low or b"pg_query" in low or b"sqlite" in low:
                found.append(p)
        except Exception:
            pass
    if found:
        checks.append(CheckResult("SQLi", "SQL Injection", "Failed", "SQL error indicators", "", "High"))
        findings.append(_mk_finding("SQLI-001", "SQL Injection", url, "Query",
                                    "SQL Error Indicators", "Vulnerability", "High",
                                    "Payload probe", f"Payloads triggered SQL errors",
                                    "Possible SQL injection.", "Data compromise.",
                                    "Use parameterized queries.", 
                                    "cursor.execute('SELECT * FROM t WHERE id = %s', (id,))",
                                    "Manual test"))
    else:
        checks.append(CheckResult("SQLi", "SQL Injection", "Passed", "No error indicators"))
    return ModuleResult("SQL Injection", checks, findings, {})


def tool_xss_indicator(url, config):
    checks, findings = [], []
    marker = "scitboss_xss_" + secrets.token_hex(4)
    payload = f"<script>alert('{marker}')</script>"
    policy = SecurityPolicy()
    client = HTTPClient(config, policy)
    r = client.fetch(f"{url}?q={urllib.parse.quote(payload)}", max_redirects=0)
    if r.error:
        return ModuleResult("XSS", [CheckResult("XSS", "XSS", "Not Tested", r.error)], [], {})
    if payload.encode() in r.body or marker.encode() in r.body:
        checks.append(CheckResult("XSS", "XSS", "Warning", "Reflected payload detected", "", "Medium"))
        findings.append(_mk_finding("XSS-001", "XSS", url, "Query parameter",
                                    "Potential Reflected XSS", "Vulnerability", "Medium",
                                    "Payload reflection", "Payload reflected unencoded",
                                    "Reflected XSS possible.", "Script execution risk.",
                                    "HTML-encode all output.", "", "Manual test"))
    else:
        checks.append(CheckResult("XSS", "XSS", "Passed", "No reflection detected"))
    return ModuleResult("XSS", checks, findings, {})


def tool_ssl_stripping(url, config):
    checks, findings = [], []
    parsed = urllib.parse.urlparse(url)
    if parsed.scheme != "https":
        return ModuleResult("SSL Strip", [CheckResult("Stripping", "SSL Strip", "Not Applicable")], [], {})
    hdrs_http = "http://" + parsed.netloc
    policy = SecurityPolicy()
    client = HTTPClient(config, policy)
    r = client.fetch(hdrs_http, max_redirects=0)
    if r.status == 200 and r.body:
        checks.append(CheckResult("SSL Stripping", "SSL Strip", "Failed", "HTTP serves content", "", "High"))
    else:
        checks.append(CheckResult("SSL Stripping", "SSL Strip", "Passed", "HTTP redirects/refuses"))
    return ModuleResult("SSL Strip", checks, findings, {})


def tool_subdomain_takeover(url, config):
    checks, findings = [], []
    parsed = urllib.parse.urlparse(url)
    host = parsed.hostname or ""
    # Check for CNAME pointing to known-hijackable services
    try:
        import subprocess
        result = subprocess.run(["nslookup", "-type=CNAME", host],
                                capture_output=True, timeout=10, text=True)
        output = result.stdout.lower()
        takeover_services = ["herokuapp", "s3.amazonaws", "github.io", "azurewebsites",
                             "cloudfront", "fastly", "pantheon", "wordpress.com"]
        for svc in takeover_services:
            if svc in output:
                checks.append(CheckResult("Subdomain Takeover", "Takeover", "Warning", f"CNAME to {svc}", "", "High"))
                findings.append(_mk_finding("TAKE-001", "Takeover", url, "DNS",
                                            "Potential Subdomain Takeover", "Vulnerability", "High",
                                            "CNAME check", f"CNAME → {svc}", "Dangling CNAME detected.",
                                            "Domain could be hijacked.", "Remove unused CNAME.", "", "Manual verify"))
                break
        else:
            checks.append(CheckResult("Subdomain Takeover", "Takeover", "Passed", "No dangling CNAME"))
    except Exception:
        checks.append(CheckResult("Takeover", "Takeover", "Not Tested", "CNAME lookup failed"))
    return ModuleResult("Subdomain Takeover", checks, findings, {})


def tool_clickjacking_test(url, config):
    checks, findings = [], []
    client, resp, _ = _get_page_data(config, url)
    if resp.error:
        return ModuleResult("Clickjacking", [CheckResult("Request", "Clickjacking", "Failed", resp.error)], [], {})
    hdrs = {k.lower(): v for k, v in resp.headers}
    xfo = hdrs.get("x-frame-options", "")
    csp = hdrs.get("content-security-policy", "")
    if not xfo and "frame-ancestors" not in csp:
        checks.append(CheckResult("Clickjacking", "Clickjacking", "Failed", "No XFO or CSP", "", "Medium"))
        findings.append(_mk_finding("CLICK-001", "Clickjacking", url, "Framing",
                                    "Clickjacking Possible", "Vulnerability", "Medium",
                                    "Header check", "No anti-framing headers",
                                    "Page can be framed.", "Clickjacking attacks.",
                                    "Add X-Frame-Options or CSP frame-ancestors.",
                                    'X-Frame-Options: DENY', "Re-scan"))
    else:
        checks.append(CheckResult("Clickjacking", "Clickjacking", "Passed", "Protection present"))
    return ModuleResult("Clickjacking", checks, findings, {})


def tool_host_header_injection(url, config):
    checks, findings = [], []
    try:
        parsed = urllib.parse.urlparse(url)
        test_host = "evil.example.com"
        req = urllib.request.Request(url, headers={
            "User-Agent": config.get("user_agent"),
            "Host": test_host,
        })
        ctx = ssl.create_default_context() if url.startswith("https") else None
        args = dict(timeout=10)
        if ctx: args["context"] = ctx
        try:
            resp = urllib.request.urlopen(req, **args)
            body = resp.read(2000)
            if test_host.encode() in body:
                checks.append(CheckResult("Host Header", "Host Header", "Failed", "Reflected in body", "", "Medium"))
        except Exception:
            checks.append(CheckResult("Host Header", "Host Header", "Info", "Header rejected"))
    except Exception:
        pass
    return ModuleResult("Host Header", checks, findings, {})


def tool_cookie_bombing(url, config):
    checks, findings = [], []
    # Simple check - just report as info (full test requires complex setup)
    checks.append(CheckResult("Cookie Bombing", "Cookie Bomb", "Not Tested", "Requires manual testing"))
    return ModuleResult("Cookie Bomb", checks, findings, {})


# ============================================================
# HTML & CONTENT TOOLS
# ============================================================

def tool_image_alt_text(url, config):
    checks, findings = [], []
    _, resp, parser = _get_page_data(config, url)
    if resp.error:
        return ModuleResult("Image ALT", [CheckResult("Request", "Image ALT", "Failed", resp.error)], [], {})
    no_alt = [i for i in parser.images if i.get("alt") is None]
    if no_alt:
        checks.append(CheckResult("Image ALT", "Image ALT", "Failed", f"{len(no_alt)} missing alt", "", "Low"))
        findings.append(_mk_finding("A11Y-001", "Image ALT", url, "<img>",
                                    "Images Missing ALT", "Accessibility", "Low",
                                    "HTML parsing", f"{len(no_alt)} images",
                                    "Missing alt text.", "Screen reader issue.",
                                    "Add alt attributes.", '<img src="logo.png" alt="Logo">', "Re-scan"))
    else:
        checks.append(CheckResult("Image ALT", "Image ALT", "Passed", "All images have alt"))
    return ModuleResult("Image ALT", checks, findings, {})


def tool_form_analysis(url, config):
    checks, findings = [], []
    _, resp, parser = _get_page_data(config, url)
    if resp.error:
        return ModuleResult("Forms", [CheckResult("Request", "Forms", "Failed", resp.error)], [], {})
    checks.append(CheckResult("Form Count", "Forms", "Info", f"{len(parser.forms)} form(s)"))
    insecure_forms = [f for f in parser.forms if f["action"].startswith("http://")]
    if insecure_forms:
        checks.append(CheckResult("Insecure Forms", "Forms", "Failed", f"{len(insecure_forms)} HTTP form(s)", "", "High"))
        findings.append(_mk_finding("FORM-001", "Forms", url, "<form>",
                                    "Insecure Form Submission", "Security Configuration", "High",
                                    "Form action check", f"{len(insecure_forms)} HTTP actions",
                                    "Forms submit over HTTP.", "Data interception.",
                                    "Use HTTPS for form actions.", "", "Re-scan"))
    else:
        checks.append(CheckResult("Form Security", "Forms", "Passed", "All forms use HTTPS"))
    return ModuleResult("Forms", checks, findings, {})


def tool_password_fields(url, config):
    checks, findings = [], []
    _, resp, parser = _get_page_data(config, url)
    if resp.error:
        return ModuleResult("Password Fields", [CheckResult("Request", "Password Fields", "Failed", resp.error)], [], {})
    pwd_fields = [i for i in parser.inputs if i.get("type") == "password"]
    if pwd_fields:
        checks.append(CheckResult("Password Fields", "Password Fields", "Info", f"{len(pwd_fields)} password field(s)"))
        no_autocomplete = [p for p in pwd_fields if p.get("autocomplete") != "current-password"
                           and p.get("autocomplete") != "new-password"]
        if no_autocomplete:
            checks.append(CheckResult("Autocomplete", "Password Fields", "Warning", f"{len(no_autocomplete)} without autocomplete", "", "Low"))
    else:
        checks.append(CheckResult("Password Fields", "Password Fields", "Info", "No password fields"))
    return ModuleResult("Password Fields", checks, findings, {})


def tool_email_in_html(url, config):
    checks, findings = [], []
    _, resp, parser = _get_page_data(config, url)
    if resp.error:
        return ModuleResult("Email Exposure", [CheckResult("Request", "Email Exposure", "Failed", resp.error)], [], {})
    text = parser.get_text() + " " + " ".join(l.get("href", "") for l in parser.links)
    emails = set(re.findall(r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}", text))
    if emails:
        checks.append(CheckResult("Emails Found", "Email Exposure", "Warning", f"{len(emails)} email(s) in HTML", "", "Low"))
    else:
        checks.append(CheckResult("Emails", "Email Exposure", "Passed", "No plain emails"))
    return ModuleResult("Email Exposure", checks, findings, {"emails": list(emails)[:10]})


def tool_inline_scripts(url, config):
    checks, findings = [], []
    _, resp, parser = _get_page_data(config, url)
    if resp.error:
        return ModuleResult("Inline Scripts", [CheckResult("Request", "Inline Scripts", "Failed", resp.error)], [], {})
    # Count script tags with content (approximation via regex on body)
    body = resp.body.decode("utf-8", errors="replace")
    inline_count = len(re.findall(r"<script[^>]*>[^<]+</script>", body, re.IGNORECASE))
    checks.append(CheckResult("Inline Scripts", "Inline Scripts", "Info", f"{inline_count} inline script(s)"))
    return ModuleResult("Inline Scripts", checks, findings, {"count": inline_count})


def tool_iframe_security(url, config):
    checks, findings = [], []
    _, resp, parser = _get_page_data(config, url)
    if resp.error:
        return ModuleResult("Iframe", [CheckResult("Request", "Iframe", "Failed", resp.error)], [], {})
    if not parser.iframes:
        checks.append(CheckResult("Iframes", "Iframe", "Info", "None"))
        return ModuleResult("Iframe", checks, findings, {})
    no_sandbox = [i for i in parser.iframes if not i.get("sandbox")]
    if no_sandbox:
        checks.append(CheckResult("Sandbox", "Iframe", "Warning", f"{len(no_sandbox)} without sandbox", "", "Low"))
    else:
        checks.append(CheckResult("Sandbox", "Iframe", "Passed", "All iframes sandboxed"))
    return ModuleResult("Iframe", checks, findings, {})


def tool_media_elements(url, config):
    checks, findings = [], []
    _, resp, parser = _get_page_data(config, url)
    if resp.error:
        return ModuleResult("Media", [CheckResult("Request", "Media", "Failed", resp.error)], [], {})
    checks.append(CheckResult("Videos", "Media", "Info", f"{len(parser.videos)} video(s)"))
    checks.append(CheckResult("Audio", "Media", "Info", f"{len(parser.audios)} audio(s)"))
    checks.append(CheckResult("Canvas", "Media", "Info", f"{parser.canvases} canvas"))
    return ModuleResult("Media", checks, findings, {})


def tool_text_content_scan(url, config):
    checks, findings = [], []
    _, resp, parser = _get_page_data(config, url)
    if resp.error:
        return ModuleResult("Text Scan", [CheckResult("Request", "Text Scan", "Failed", resp.error)], [], {})
    text = parser.get_text()
    word_count = len(text.split())
    checks.append(CheckResult("Word Count", "Text Scan", "Info", f"{word_count} words"))
    if word_count < 300:
        checks.append(CheckResult("Content Length", "Text Scan", "Info", "Short content"))
    return ModuleResult("Text Scan", checks, findings, {"words": word_count})


def tool_comment_scan(url, config):
    checks, findings = [], []
    _, resp, parser = _get_page_data(config, url)
    if resp.error:
        return ModuleResult("Comments", [CheckResult("Request", "Comments", "Failed", resp.error)], [], {})
    sensitive_patterns = [r"password", r"api[_-]?key", r"secret", r"todo", r"fixme", r"debug"]
    flagged = []
    for comment in parser.comments:
        for pat in sensitive_patterns:
            if re.search(pat, comment, re.IGNORECASE):
                flagged.append(comment[:100])
                break
    if flagged:
        checks.append(CheckResult("Comments", "Comments", "Warning", f"{len(flagged)} flagged", "", "Low"))
        findings.append(_mk_finding("CMT-001", "Comments", url, "HTML comments",
                                    "Sensitive HTML Comments", "Information Exposure", "Low",
                                    "Comment scan", f"{len(flagged)} comments with sensitive patterns",
                                    "Comments may leak info.", "Data exposure.",
                                    "Remove sensitive comments in production.", "", "Re-scan"))
    else:
        checks.append(CheckResult("Comments", "Comments", "Passed", "No sensitive patterns"))
    return ModuleResult("Comments", checks, findings, {})


# ============================================================
# ACCESSIBILITY TOOLS
# ============================================================

def tool_aria_labels(url, config):
    checks, findings = [], []
    _, resp, parser = _get_page_data(config, url)
    if resp.error:
        return ModuleResult("ARIA", [CheckResult("Request", "ARIA", "Failed", resp.error)], [], {})
    # Simplified: check for buttons/links without accessible name
    issues = []
    for b in parser.buttons:
        if not b.get("text", "").strip():
            issues.append("Button without text")
    if issues:
        checks.append(CheckResult("Button Labels", "ARIA", "Warning", f"{len(issues)} issue(s)", "", "Low"))
    else:
        checks.append(CheckResult("Button Labels", "ARIA", "Passed", "All buttons labeled"))
    return ModuleResult("ARIA", checks, findings, {})


def tool_lang_attribute(url, config):
    checks, findings = [], []
    _, resp, parser = _get_page_data(config, url)
    if resp.error:
        return ModuleResult("Lang", [CheckResult("Request", "Lang", "Failed", resp.error)], [], {})
    lang = parser.get_lang()
    if lang:
        checks.append(CheckResult("HTML lang", "Lang", "Passed", lang))
    else:
        checks.append(CheckResult("HTML lang", "Lang", "Failed", "Missing", "", "Low"))
    return ModuleResult("Lang", checks, findings, {})


def tool_skip_link(url, config):
    checks, findings = [], []
    _, resp, parser = _get_page_data(config, url)
    if resp.error:
        return ModuleResult("Skip Link", [CheckResult("Request", "Skip Link", "Failed", resp.error)], [], {})
    skip_links = [l for l in parser.links if "skip" in l.get("text", "").lower() or
                  l.get("href", "").startswith("#main")]
    if skip_links:
        checks.append(CheckResult("Skip Link", "Skip Link", "Passed", "Present"))
    else:
        checks.append(CheckResult("Skip Link", "Skip Link", "Info", "No skip link found"))
    return ModuleResult("Skip Link", checks, findings, {})


def tool_keyboard_traps(url, config):
    checks, findings = [], []
    checks.append(CheckResult("Keyboard Traps", "Keyboard", "Not Tested", "Requires browser automation"))
    return ModuleResult("Keyboard", checks, findings, {})


def tool_focus_indicators(url, config):
    checks, findings = [], []
    _, resp, _ = _get_page_data(config, url)
    if resp.error:
        return ModuleResult("Focus", [CheckResult("Request", "Focus", "Failed", resp.error)], [], {})
    body = resp.body.decode("utf-8", errors="replace")
    if "outline: none" in body.lower() or "outline:none" in body.lower():
        checks.append(CheckResult("Focus Indicators", "Focus", "Warning", "outline: none detected", "", "Low"))
    else:
        checks.append(CheckResult("Focus Indicators", "Focus", "Info", "No obvious issues"))
    return ModuleResult("Focus", checks, findings, {})


def tool_color_contrast(url, config):
    checks, findings = [], []
    checks.append(CheckResult("Color Contrast", "Contrast", "Not Tested", "Requires rendering"))
    return ModuleResult("Contrast", checks, findings, {})


def tool_text_scaling(url, config):
    checks, findings = [], []
    _, resp, parser = _get_page_data(config, url)
    if resp.error:
        return ModuleResult("Scaling", [CheckResult("Request", "Scaling", "Failed", resp.error)], [], {})
    vp = parser.get_viewport()
    if vp and ("maximum-scale" in vp.lower() or "user-scalable=no" in vp.lower()):
        checks.append(CheckResult("Text Scaling", "Scaling", "Warning", "Zoom disabled", "", "Low"))
    else:
        checks.append(CheckResult("Text Scaling", "Scaling", "Passed", "Zoom enabled"))
    return ModuleResult("Scaling", checks, findings, {})


# ============================================================
# AUTHENTICATION TOOLS
# ============================================================

def tool_login_form_https(url, config):
    checks, findings = [], []
    parsed = urllib.parse.urlparse(url)
    _, resp, parser = _get_page_data(config, url)
    if resp.error:
        return ModuleResult("Login HTTPS", [CheckResult("Request", "Login HTTPS", "Failed", resp.error)], [], {})
    if parsed.scheme != "https":
        if any(i.get("type") == "password" for i in parser.inputs):
            checks.append(CheckResult("Login HTTPS", "Login HTTPS", "Failed", "Password field on HTTP", "", "Critical"))
            findings.append(_mk_finding("LOGIN-001", "Login HTTPS", url, "Password field",
                                        "Password Field on HTTP", "Session Security", "Critical",
                                        "URL scheme check", "HTTP with password field",
                                        "Password sent insecurely.", "Credentials stolen.",
                                        "Force HTTPS on login pages.", "", "Re-scan"))
    else:
        checks.append(CheckResult("Login HTTPS", "Login HTTPS", "Passed", "HTTPS in use"))
    return ModuleResult("Login HTTPS", checks, findings, {})


def tool_password_autocomplete(url, config):
    checks, findings = [], []
    _, resp, parser = _get_page_data(config, url)
    if resp.error:
        return ModuleResult("Autocomplete", [CheckResult("Request", "Autocomplete", "Failed", resp.error)], [], {})
    pwd_fields = [i for i in parser.inputs if i.get("type") == "password"]
    no_autocomplete = [p for p in pwd_fields if not p.get("autocomplete")]
    if no_autocomplete:
        checks.append(CheckResult("Autocomplete", "Autocomplete", "Info", f"{len(no_autocomplete)} without autocomplete"))
    else:
        checks.append(CheckResult("Autocomplete", "Autocomplete", "Passed", "All set"))
    return ModuleResult("Autocomplete", checks, findings, {})


def tool_autocomplete_cc(url, config):
    checks, findings = [], []
    _, resp, parser = _get_page_data(config, url)
    if resp.error:
        return ModuleResult("CC Autocomplete", [CheckResult("Request", "CC Autocomplete", "Failed", resp.error)], [], {})
    # Check for credit card fields
    cc_fields = [i for i in parser.inputs if "card" in (i.get("name", "") + i.get("id", "")).lower()
                 or i.get("autocomplete", "").startswith("cc-")]
    if cc_fields:
        insecure = [f for f in cc_fields if not f.get("autocomplete", "").startswith("cc-")]
        if insecure:
            checks.append(CheckResult("CC Autocomplete", "CC Autocomplete", "Warning", f"{len(insecure)} field(s) with wrong autocomplete"))
        else:
            checks.append(CheckResult("CC Autocomplete", "CC Autocomplete", "Passed", "Properly configured"))
    else:
        checks.append(CheckResult("CC Autocomplete", "CC Autocomplete", "Not Applicable", "No CC fields"))
    return ModuleResult("CC Autocomplete", checks, findings, {})


def tool_session_cookie_https(url, config):
    checks, findings = [], []
    client, resp, _ = _get_page_data(config, url)
    if resp.error:
        return ModuleResult("Session HTTPS", [CheckResult("Request", "Session HTTPS", "Failed", resp.error)], [], {})
    set_cookies = [v for k, v in resp.headers if k.lower() == "set-cookie"]
    insecure = []
    for raw in set_cookies:
        parts = [p.strip().lower() for p in raw.split(";")]
        if not any(f == "secure" for f in parts):
            insecure.append(raw.split("=", 1)[0])
    if insecure:
        checks.append(CheckResult("Session Cookies", "Session HTTPS", "Failed", f"{len(insecure)} without Secure", "", "High"))
    else:
        checks.append(CheckResult("Session Cookies", "Session HTTPS", "Passed", "All Secure"))
    return ModuleResult("Session HTTPS", checks, findings, {})


def tool_auth_scheme(url, config):
    checks, findings = [], []
    client, resp, _ = _get_page_data(config, url)
    if resp.error:
        return ModuleResult("Auth Scheme", [CheckResult("Request", "Auth Scheme", "Failed", resp.error)], [], {})
    hdrs = {k.lower(): v for k, v in resp.headers}
    www_auth = hdrs.get("www-authenticate", "")
    if www_auth:
        checks.append(CheckResult("Auth Scheme", "Auth Scheme", "Info", www_auth))
    else:
        checks.append(CheckResult("Auth Scheme", "Auth Scheme", "Info", "No WWW-Authenticate header"))
    return ModuleResult("Auth Scheme", checks, findings, {})


def tool_jwt_in_url(url, config):
    checks, findings = [], []
    parsed = urllib.parse.urlparse(url)
    if "token=" in parsed.query.lower() or "jwt=" in parsed.query.lower():
        checks.append(CheckResult("JWT in URL", "JWT URL", "Warning", "Token in URL", "", "Medium"))
        findings.append(_mk_finding("JWT-001", "JWT URL", url, "Query string",
                                    "Token in URL", "Session Security", "Medium",
                                    "URL parsing", "Token in query string",
                                    "Token may leak via referer/history.", "Session theft.",
                                    "Use headers or secure cookies.", "", "Re-scan"))
    else:
        checks.append(CheckResult("JWT in URL", "JWT URL", "Passed", "No token in URL"))
    return ModuleResult("JWT URL", checks, findings, {})


def tool_logout_link(url, config):
    checks, findings = [], []
    _, resp, parser = _get_page_data(config, url)
    if resp.error:
        return ModuleResult("Logout", [CheckResult("Request", "Logout", "Failed", resp.error)], [], {})
    logout = [l for l in parser.links if "logout" in (l.get("href", "") + l.get("text", "")).lower()]
    checks.append(CheckResult("Logout Link", "Logout", "Info", f"{len(logout)} logout link(s)"))
    return ModuleResult("Logout", checks, findings, {})


# ============================================================
# CONTENT ANALYSIS TOOLS
# ============================================================

def tool_phone_numbers(url, config):
    checks, findings = [], []
    _, resp, parser = _get_page_data(config, url)
    if resp.error:
        return ModuleResult("Phones", [CheckResult("Request", "Phones", "Failed", resp.error)], [], {})
    text = parser.get_text()
    phones = set(re.findall(r"\+?\d[\d\s\-\(\)]{7,}\d", text))
    checks.append(CheckResult("Phone Numbers", "Phones", "Info", f"{len(phones)} found"))
    return ModuleResult("Phones", checks, findings, {"phones": list(phones)[:10]})


def tool_social_links(url, config):
    checks, findings = [], []
    _, resp, parser = _get_page_data(config, url)
    if resp.error:
        return ModuleResult("Social Links", [CheckResult("Request", "Social Links", "Failed", resp.error)], [], {})
    social = []
    for l in parser.links:
        href = l.get("href", "")
        for s in ["facebook.com", "twitter.com", "instagram.com", "linkedin.com",
                  "youtube.com", "tiktok.com", "pinterest.com", "github.com"]:
            if s in href:
                social.append(s)
                break
    checks.append(CheckResult("Social Links", "Social Links", "Info", f"{len(set(social))} platforms"))
    return ModuleResult("Social Links", checks, findings, {"socials": list(set(social))})


def tool_word_count(url, config):
    checks, findings = [], []
    _, resp, parser = _get_page_data(config, url)
    if resp.error:
        return ModuleResult("Word Count", [CheckResult("Request", "Word Count", "Failed", resp.error)], [], {})
    text = parser.get_text()
    count = len(text.split())
    checks.append(CheckResult("Word Count", "Word Count", "Info", f"{count} words"))
    return ModuleResult("Word Count", checks, findings, {"words": count})


def tool_reading_time(url, config):
    checks, findings = [], []
    _, resp, parser = _get_page_data(config, url)
    if resp.error:
        return ModuleResult("Reading Time", [CheckResult("Request", "Reading Time", "Failed", resp.error)], [], {})
    count = len(parser.get_text().split())
    minutes = max(1, count // 200)
    checks.append(CheckResult("Reading Time", "Reading Time", "Info", f"~{minutes} min"))
    return ModuleResult("Reading Time", checks, findings, {"minutes": minutes})


def tool_keyword_density(url, config):
    checks, findings = [], []
    _, resp, parser = _get_page_data(config, url)
    if resp.error:
        return ModuleResult("Keywords", [CheckResult("Request", "Keywords", "Failed", resp.error)], [], {})
    text = parser.get_text().lower()
    words = re.findall(r"\b[a-z]{4,}\b", text)
    counter = Counter(words)
    top = counter.most_common(10)
    for w, c in top[:5]:
        checks.append(CheckResult(w, "Keywords", "Info", f"{c} occurrence(s)"))
    return ModuleResult("Keywords", checks, findings, {"top": top})


# ============================================================
# TOOL REGISTRY (100+ TOOLS)
# ============================================================

TOOL_CATEGORIES = [
    ("Transport Security", "🔒", [
        ("tls_versions", "TLS Versions", "Detect supported TLS versions", tool_tls_versions),
        ("hsts_check", "HSTS Check", "Verify Strict-Transport-Security", tool_hsts_check),
        ("cert_chain", "Certificate Chain", "Inspect certificate chain", tool_certificate_chain),
        ("ssl_ciphers", "SSL Ciphers", "Inspect negotiated cipher", tool_ssl_ciphers),
        ("http2", "HTTP/2 Support", "Check ALPN h2", tool_http2),
        ("http3", "HTTP/3 Support", "Check Alt-Svc for h3", tool_http3),
        ("https_redirect", "HTTPS Redirect", "Check HTTP→HTTPS redirect", tool_https_redirect),
        ("mixed_content", "Mixed Content", "Detect HTTP resources on HTTPS", tool_mixed_content),
        ("hsts_preload", "HSTS Preload", "Check HSTS preload status", tool_hsts_preload),
        ("cert_expiry", "Certificate Expiry", "Check days until expiry", tool_certificate_expiry),
        ("ocsp", "OCSP Stapling", "Check OCSP stapling", tool_ocsp_stapling),
        ("downgrade", "Downgrade Attack", "Detect protocol downgrade", tool_downgrade_attack),
        ("ssl_strip", "SSL Stripping", "Check for SSL strip risk", tool_ssl_stripping),
    ]),
    ("Headers & Policy", "📋", [
        ("sec_headers", "Security Headers", "Full security header audit", tool_security_headers_full),
        ("csp", "CSP Analysis", "Content Security Policy audit", tool_csp_analysis),
        ("xfo", "X-Frame-Options", "Clickjacking protection check", tool_x_frame_options),
        ("permissions", "Permissions-Policy", "Feature policy check", tool_permissions_policy),
        ("coop_coep", "COOP/COEP", "Cross-origin isolation headers", tool_coop_coep),
        ("referrer", "Referrer-Policy", "Referrer policy check", tool_referrer_policy),
        ("cache_control", "Cache-Control", "Cache header check", tool_cache_control),
        ("pragma", "Pragma", "Pragma header check", tool_pragma),
        ("server_hdr", "Server Header", "Version disclosure check", tool_server_header),
        ("xxss", "X-XSS-Protection", "Legacy XSS header check", tool_x_xss_protection),
        ("xcto", "X-Content-Type-Options", "MIME sniffing check", tool_content_type_options),
        ("header_inj", "Header Injection", "CRLF injection check", tool_header_injection),
        ("cors", "CORS", "CORS misconfiguration check", tool_cors),
        ("hdr_list", "HTTP Headers List", "Dump all response headers", tool_http_headers_list),
    ]),
    ("Cookies & Sessions", "🍪", [
        ("cookie_flags", "Cookie Flags", "Secure/HttpOnly/SameSite", tool_cookie_flags),
        ("cookie_prefix", "Cookie Prefixes", "__Secure-/__Host- check", tool_cookie_prefixes),
        ("cookie_scope", "Cookie Scope", "Domain/Path check", tool_cookie_scope),
        ("csrf", "CSRF Tokens", "POST form CSRF tokens", tool_csrf_forms),
        ("session_entropy", "Session Entropy", "Session token length", tool_session_entropy),
        ("logout_csrf", "Logout CSRF", "GET logout links", tool_logout_csrf),
        ("session_https", "Session HTTPS", "Session over HTTPS", tool_session_cookie_https),
    ]),
    ("SEO & Metadata", "🎯", [
        ("title_tag", "Title Tag", "Title length and presence", tool_title_tag),
        ("meta_desc", "Meta Description", "Meta description audit", tool_meta_description),
        ("headings", "Heading Structure", "H1-H6 structure", tool_heading_structure),
        ("og_tags", "Open Graph", "og:* tags check", tool_og_tags),
        ("twitter", "Twitter Cards", "twitter:* tags check", tool_twitter_cards),
        ("canonical", "Canonical Link", "Canonical URL check", tool_canonical),
        ("robots", "Robots.txt", "Robots.txt check", tool_robots_txt),
        ("sitemap", "Sitemap.xml", "Sitemap check", tool_sitemap_xml),
        ("favicon", "Favicon", "Favicon presence", tool_favicon),
        ("lang", "HTML Lang", "lang attribute", tool_html_lang),
        ("doctype", "DOCTYPE", "DOCTYPE presence", tool_doctype),
        ("viewport", "Viewport", "Mobile viewport meta", tool_viewport),
    ]),
    ("Performance", "⚡", [
        ("response_time", "Response Time", "Server response time", tool_response_time),
        ("doc_size", "Document Size", "HTML size check", tool_document_size),
        ("compression", "Compression", "gzip/brotli check", tool_compression),
        ("brotli", "Brotli", "Brotli compression check", tool_brotli),
        ("keep_alive", "Keep-Alive", "Connection reuse", tool_keep_alive),
        ("http_version", "HTTP Version", "Protocol version", tool_http_protocol_version),
        ("cdn_detect", "CDN Detection", "Detect CDN provider", tool_cdn_detection),
        ("ttfb", "TTFB", "Time to first byte", tool_ttfb),
        ("assets", "Assets Count", "Count static resources", tool_static_assets_count),
        ("render_block", "Render Blocking", "Render-blocking resources", tool_render_blocking),
    ]),
    ("Links & Redirects", "🔗", [
        ("broken_links", "Broken Links", "Crawl for 404/410", tool_broken_links),
        ("external", "External Links", "Outbound link count", tool_external_links),
        ("redirect_chain", "Redirect Chain", "Chain length", tool_redirect_chain),
        ("redirect_loops", "Redirect Loops", "Loop detection", tool_redirect_loops),
        ("mailto", "Mailto Links", "mailto: link check", tool_mailto_links),
        ("js_links", "JS Links", "javascript: links", tool_javascript_links),
        ("empty_links", "Empty Links", "'#' links", tool_empty_links),
        ("open_redirect", "Open Redirect", "Parameter redirect check", tool_open_redirect),
    ]),
    ("DNS & Domain", "🌐", [
        ("dns_lookup", "DNS Lookup", "A/AAAA records", tool_dns_lookup),
        ("reverse_dns", "Reverse DNS", "PTR lookup", tool_reverse_dns),
        ("geo_ip", "Geo IP", "IP geolocation", tool_ip_geolocation),
        ("spf", "SPF Record", "Email SPF check", tool_spf_record),
        ("dmarc", "DMARC Record", "Email DMARC check", tool_dmarc_record),
        ("mx", "MX Records", "Mail server records", tool_mx_records),
        ("txt", "TXT Records", "DNS TXT lookup", tool_txt_records),
        ("ns", "NS Records", "Nameserver records", tool_ns_records),
        ("caa", "CAA Record", "Certificate authority auth", tool_caa_record),
        ("cname", "CNAME Chain", "CNAME resolution", tool_cname_chain),
    ]),
    ("Technology Detection", "🔬", [
        ("cms", "CMS Detection", "Detect CMS platform", tool_cms_detect),
        ("framework", "Framework Detection", "Detect web framework", tool_framework_detect),
        ("js_libs", "JS Libraries", "Detect JS libraries", tool_js_libraries),
        ("analytics", "Analytics", "Detect analytics tools", tool_analytics),
        ("web_server", "Web Server", "Detect server software", tool_web_server),
        ("language", "Programming Language", "Detect backend language", tool_programming_lang),
        ("os", "Operating System", "Detect server OS", tool_operating_system),
        ("waf", "WAF Detection", "Detect WAF provider", tool_waf_detect),
        ("cdn_cache", "CDN Cache", "Cache status from CDN", tool_cdn_cache),
    ]),
    ("Vulnerability Checks", "🛡️", [
        ("sensitive_files", "Sensitive Files", "Check exposed .env/.git", tool_sensitive_files),
        ("dir_listing", "Directory Listing", "Check autoindex", tool_directory_listing),
        ("admin_panels", "Admin Panels", "Common admin paths", tool_admin_panels),
        ("backup_files", "Backup Files", "Exposed backup files", tool_backup_files),
        ("source_maps", "Source Maps", "Exposed .js.map", tool_source_map_exposure),
        ("http_methods", "HTTP Methods", "Allowed HTTP methods", tool_http_methods),
        ("crlf", "CRLF Injection", "CRLF check", tool_crlf_injection),
        ("path_traversal", "Path Traversal", "LFI probe", tool_path_traversal),
        ("sql_injection", "SQL Injection", "SQL error indicators", tool_sql_injection_indicator),
        ("xss_indicator", "XSS Indicator", "Reflected XSS probe", tool_xss_indicator),
        ("takeover", "Subdomain Takeover", "Dangling CNAME check", tool_subdomain_takeover),
        ("clickjacking", "Clickjacking", "Framing protection", tool_clickjacking_test),
        ("host_injection", "Host Header Injection", "Host header probe", tool_host_header_injection),
        ("cookie_bomb", "Cookie Bombing", "Cookie overflow check", tool_cookie_bombing),
    ]),
    ("HTML & Content", "📄", [
        ("img_alt", "Image ALT", "alt attribute check", tool_image_alt_text),
        ("forms", "Form Analysis", "Insecure forms", tool_form_analysis),
        ("password_fields", "Password Fields", "Password field audit", tool_password_fields),
        ("email_leak", "Email Exposure", "Emails in HTML", tool_email_in_html),
        ("inline_scripts", "Inline Scripts", "Inline script count", tool_inline_scripts),
        ("iframes", "Iframe Security", "sandbox attribute check", tool_iframe_security),
        ("media", "Media Elements", "Video/audio/canvas", tool_media_elements),
        ("text_scan", "Text Content", "Word count & analysis", tool_text_content_scan),
        ("comments", "Comments", "Sensitive HTML comments", tool_comment_scan),
    ]),
    ("Accessibility", "♿", [
        ("aria", "ARIA Labels", "Accessible name check", tool_aria_labels),
        ("lang_a11y", "Language Attr", "lang attribute", tool_lang_attribute),
        ("skip_link", "Skip Link", "Skip to content link", tool_skip_link),
        ("keyboard", "Keyboard Traps", "Keyboard navigation", tool_keyboard_traps),
        ("focus", "Focus Indicators", "Focus outline check", tool_focus_indicators),
        ("contrast", "Color Contrast", "WCAG contrast", tool_color_contrast),
        ("scaling", "Text Scaling", "Zoom enable check", tool_text_scaling),
    ]),
    ("Authentication", "🔐", [
        ("login_https", "Login HTTPS", "Password field security", tool_login_form_https),
        ("autocomplete", "Autocomplete", "Password autocomplete", tool_password_autocomplete),
        ("cc_autocomplete", "CC Autocomplete", "Credit card fields", tool_autocomplete_cc),
        ("auth_scheme", "Auth Scheme", "WWW-Authenticate", tool_auth_scheme),
        ("jwt_url", "JWT in URL", "Token in query string", tool_jwt_in_url),
        ("logout_link", "Logout Link", "Logout presence", tool_logout_link),
    ]),
    ("Content Analysis", "📊", [
        ("phones", "Phone Numbers", "Phone number extraction", tool_phone_numbers),
        ("social", "Social Links", "Social media links", tool_social_links),
        ("word_count", "Word Count", "Total words", tool_word_count),
        ("reading_time", "Reading Time", "Estimated read time", tool_reading_time),
        ("keywords", "Keyword Density", "Top keywords", tool_keyword_density),
    ]),
]

# Flatten for quick lookup
ALL_TOOLS = {}
for cat_name, cat_icon, tools in TOOL_CATEGORIES:
    for tool_id, tool_name, tool_desc, tool_func in tools:
        ALL_TOOLS[tool_id] = (cat_name, cat_icon, tool_name, tool_desc, tool_func)


# ============================================================
# ANIMATION HELPERS
# ============================================================

class Anim:
    @staticmethod
    def pulse(widget, c1, c2, duration=600, cycles=1):
        def hex_to_rgb(h):
            h = h.lstrip("#")
            return tuple(int(h[i:i+2], 16) for i in (0, 2, 4))
        def rgb_to_hex(rgb):
            return "#{:02x}{:02x}{:02x}".format(*[max(0, min(255, int(c))) for c in rgb])
        a, b = hex_to_rgb(c1), hex_to_rgb(c2)
        steps = 20
        delay = max(1, duration // steps)
        def step(i=0):
            try:
                if i >= steps * cycles * 2:
                    widget.configure(bg=c1); return
                phase = (i % steps) / steps
                t = phase if (i // steps) % 2 == 0 else 1 - phase
                widget.configure(bg=rgb_to_hex(tuple(a[j] + (b[j]-a[j]) * t for j in range(3))))
                widget.after(delay, step, i+1)
            except: pass
        step()

    @staticmethod
    def count_up(var, start, end, duration=800, fmt=str):
        steps = 30
        delay = max(1, duration // steps)
        def step(i=0):
            try:
                t = i / steps
                eased = 1 - (1 - t) ** 3
                val = start + (end - start) * eased
                var.set(fmt(val))
                if i < steps:
                    var.after(delay, step, i+1)
            except: pass
        step()

    @staticmethod
    def spinner(label, frames=None, interval=100):
        frames = frames or ["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"]
        state = {"i": 0, "running": True, "orig": label.cget("text")}
        def step():
            if not state["running"]: return
            try:
                label.configure(text=frames[state["i"] % len(frames)] + " " + state["orig"])
                state["i"] += 1
                label.after(interval, step)
            except: pass
        step()
        return lambda: state.update(running=False)


# ============================================================
# SOLUTION KNOWLEDGE BASE
# ============================================================

class SolutionKB:
    def __init__(self):
        self.explanations = {
            "Transport Security": "Transport security protects data in transit via TLS and HTTPS.",
            "Security Configuration": "Security headers provide defense-in-depth mitigation.",
            "Session Security": "Session cookies need Secure, HttpOnly, SameSite flags.",
            "SEO": "SEO findings improve search visibility and social sharing.",
            "Performance": "Performance improvements reduce load times.",
            "Accessibility": "Accessibility improves usability for all users.",
            "Technical Health": "Technical health affects user experience and SEO.",
            "Information Exposure": "Information exposure assists attacker reconnaissance.",
            "Vulnerability": "Potential vulnerabilities require verification and patching.",
        }

    def get(self, finding):
        return {
            "explanation": self.explanations.get(finding.category, finding.description),
            "code": finding.example_fix_code or "# No specific code provided",
        }


# ============================================================
# MODULE PAGE CLASS
# ============================================================

class ToolPage:
    def __init__(self, app, parent, tool_id, cat_icon, tool_name, tool_desc, tool_func):
        self.app = app
        self.parent = parent
        self.tool_id = tool_id
        self.tool_name = tool_name
        self.tool_desc = tool_desc
        self.tool_func = tool_func
        self.url_var = tk.StringVar(value="https://example.com")
        self.running = False
        self.result = None
        self.thread = None
        self._spinner_stop = None
        self.checks_list = []
        self.findings_list = []
        self._build(cat_icon)

    def _build(self, icon):
        app = self.app
        theme = app.theme
        page = self.parent

        header = tk.Frame(page, bg=theme["bg"])
        header.pack(fill="x", padx=30, pady=(16, 8))
        tk.Label(header, text=f"{icon}  {self.tool_name}",
                 bg=theme["bg"], fg=theme["accent"],
                 font=("Segoe UI", 18, "bold")).pack(anchor="w")
        tk.Label(header, text=self.tool_desc, bg=theme["bg"],
                 fg=theme["muted"], font=("Segoe UI", 10)).pack(anchor="w")

        card = tk.Frame(page, bg=theme["card"])
        card.pack(fill="x", padx=30, pady=8)
        inner = tk.Frame(card, bg=theme["card"])
        inner.pack(fill="x", padx=16, pady=10)

        row = tk.Frame(inner, bg=theme["card"])
        row.pack(fill="x")
        tk.Entry(row, textvariable=self.url_var, bg=theme["input_bg"],
                 fg=theme["text"], insertbackground=theme["text"],
                 relief="flat", font=("Segoe UI", 11)).pack(
            side="left", fill="x", expand=True, ipady=8, padx=(0, 10))
        self.run_btn = tk.Button(row, text=f"▶  Run {self.tool_name}",
                                 bg=theme["accent"], fg=theme["bg"],
                                 font=("Segoe UI", 10, "bold"), relief="flat",
                                 padx=20, pady=8, cursor="hand2",
                                 command=self._start)
        self.run_btn.pack(side="left")
        self.cancel_btn = tk.Button(row, text="✕", bg=theme["critical"],
                                    fg="white", relief="flat", padx=10, pady=8,
                                    state="disabled", command=self._cancel)
        self.cancel_btn.pack(side="left", padx=(6, 0))

        prog_frame = tk.Frame(inner, bg=theme["card"])
        prog_frame.pack(fill="x", pady=(8, 0))
        self.progress = ttk.Progressbar(prog_frame, mode="indeterminate")
        self.progress.pack(fill="x")
        self.status_lbl = tk.Label(prog_frame, text="Ready", bg=theme["card"],
                                   fg=theme["muted"], font=("Segoe UI", 9), anchor="w")
        self.status_lbl.pack(anchor="w", pady=(4, 0))

        self.summary_frame = tk.Frame(page, bg=theme["bg"])
        self.summary_frame.pack(fill="x", padx=30, pady=6)

        # Checks
        ch_card = tk.Frame(page, bg=theme["card"])
        ch_card.pack(fill="both", expand=True, padx=30, pady=4)
        tk.Label(ch_card, text="📋  Check Results", bg=theme["card"],
                 fg=theme["accent"], font=("Segoe UI", 11, "bold")).pack(
            anchor="w", padx=12, pady=(6, 2))
        tf = tk.Frame(ch_card, bg=theme["card"])
        tf.pack(fill="both", expand=True, padx=8, pady=(0, 8))
        cols = ("Status", "Check", "Detail")
        self.checks_tree = ttk.Treeview(tf, columns=cols, show="headings", height=6)
        for c in cols:
            self.checks_tree.heading(c, text=c)
            self.checks_tree.column(c, width=120 if c == "Status" else 250 if c == "Check" else 600)
        for st, col in [("Passed", theme["success"]), ("Failed", theme["critical"]),
                        ("Warning", theme["warning"]), ("Info", theme["accent"])]:
            self.checks_tree.tag_configure(st, foreground=col)
        vsb = ttk.Scrollbar(tf, orient="vertical", command=self.checks_tree.yview)
        self.checks_tree.configure(yscrollcommand=vsb.set)
        self.checks_tree.pack(side="left", fill="both", expand=True)
        vsb.pack(side="right", fill="y")

        # Findings
        fi_card = tk.Frame(page, bg=theme["card"])
        fi_card.pack(fill="both", expand=True, padx=30, pady=(0, 16))
        tk.Label(fi_card, text="🔍  Findings", bg=theme["card"],
                 fg=theme["accent"], font=("Segoe UI", 11, "bold")).pack(
            anchor="w", padx=12, pady=(6, 2))
        ftf = tk.Frame(fi_card, bg=theme["card"])
        ftf.pack(fill="both", expand=True, padx=8, pady=(0, 8))
        fcols = ("Severity", "Title", "Category")
        self.findings_tree = ttk.Treeview(ftf, columns=fcols, show="headings", height=5)
        for c in fcols:
            self.findings_tree.heading(c, text=c)
            self.findings_tree.column(c, width=120 if c == "Severity" else 500 if c == "Title" else 200)
        for sev, col in SEVERITY_COLORS.items():
            self.findings_tree.tag_configure(sev, foreground=col)
        vsb2 = ttk.Scrollbar(ftf, orient="vertical", command=self.findings_tree.yview)
        self.findings_tree.configure(yscrollcommand=vsb2.set)
        self.findings_tree.pack(side="left", fill="both", expand=True)
        vsb2.pack(side="right", fill="y")
        self.findings_tree.bind("<Double-1>", self._show_finding)

    def _start(self):
        if self.running:
            return
        raw = self.url_var.get().strip()
        if not raw:
            messagebox.showerror("URL", "Enter a URL", parent=self.parent)
            return
        try:
            url = URLValidator.normalize(raw)
            self.url_var.set(url)
        except Exception as e:
            messagebox.showerror("Invalid URL", str(e), parent=self.parent)
            return
        self.running = True
        self.result = None
        self.run_btn.configure(state="disabled", text="⏳ Scanning…")
        self.cancel_btn.configure(state="normal")
        self.status_lbl.configure(text="Scanning…", fg=self.app.theme["warning"])
        self.progress.start(12)
        self._spinner_stop = Anim.spinner(self.status_lbl)
        self._clear()
        if self.app.config.get("animations"):
            try: Anim.pulse(self.run_btn, self.app.theme["accent"], self.app.theme["warning"])
            except: pass
        self.thread = threading.Thread(target=self._worker, args=(url,), daemon=True)
        self.thread.start()
        self.parent.after(150, self._poll)

    def _worker(self, url):
        try:
            self.result = self.tool_func(url, self.app.config)
        except Exception as e:
            log.exception("Tool scan failed")
            self.result = ModuleResult(self.tool_name, [], [], {"error": str(e)})

    def _poll(self):
        if not self.running:
            return
        if self.thread and self.thread.is_alive():
            self.parent.after(150, self._poll)
            return
        self._finish()

    def _finish(self):
        self.running = False
        self.progress.stop()
        self.run_btn.configure(state="normal", text=f"▶  Run {self.tool_name}")
        self.cancel_btn.configure(state="disabled")
        if self._spinner_stop:
            try: self._spinner_stop()
            except: pass
            self._spinner_stop = None
        res = self.result
        if not res:
            self.status_lbl.configure(text="No result", fg=self.app.theme["critical"])
            return
        if res.data.get("error"):
            self.status_lbl.configure(text=f"Error: {res.data['error']}", fg=self.app.theme["critical"])
            return
        self.checks_list = res.checks
        self.findings_list = res.findings
        self._render_summary(res)
        self._render_checks(res.checks)
        self._render_findings(res.findings)
        if self.app.config.get("animations"):
            try: Anim.pulse(self.run_btn, self.app.theme["success"], self.app.theme["accent"])
            except: pass
        if res.findings:
            self.status_lbl.configure(text=f"✔ Complete — {len(res.findings)} finding(s)",
                                     fg=self.app.theme["warning"])
        else:
            self.status_lbl.configure(text=f"✔ Complete — All passed",
                                     fg=self.app.theme["success"])

    def _cancel(self):
        if self.running:
            self.status_lbl.configure(text="Cancelling…", fg=self.app.theme["warning"])

    def _clear(self):
        for r in self.checks_tree.get_children(): self.checks_tree.delete(r)
        for r in self.findings_tree.get_children(): self.findings_tree.delete(r)
        for w in self.summary_frame.winfo_children(): w.destroy()

    def _render_summary(self, res):
        for w in self.summary_frame.winfo_children(): w.destroy()
        counts = Counter(c.status for c in res.checks)
        stats = [
            ("Checks", len(res.checks), self.app.theme["accent"]),
            ("Passed", counts.get("Passed", 0), self.app.theme["success"]),
            ("Warnings", counts.get("Warning", 0), self.app.theme["warning"]),
            ("Failed", counts.get("Failed", 0), self.app.theme["critical"]),
            ("Findings", len(res.findings),
             self.app.theme["warning"] if res.findings else self.app.theme["success"]),
        ]
        for i, (label, val, color) in enumerate(stats):
            cell = tk.Frame(self.summary_frame, bg=self.app.theme["card"])
            cell.grid(row=0, column=i, padx=4, pady=4, sticky="nsew")
            self.summary_frame.columnconfigure(i, weight=1)
            tk.Label(cell, text=label, bg=self.app.theme["card"],
                     fg=self.app.theme["muted"], font=("Segoe UI", 9)).pack(
                anchor="w", padx=12, pady=(6, 0))
            var = tk.StringVar(value="0")
            tk.Label(cell, textvariable=var, bg=self.app.theme["card"],
                     fg=color, font=("Segoe UI", 16, "bold")).pack(
                anchor="w", padx=12, pady=(0, 6))
            try:
                Anim.count_up(var, 0, val, duration=600, fmt=lambda v: str(int(v)))
            except:
                var.set(str(val))

    def _render_checks(self, checks):
        for c in checks:
            self.checks_tree.insert("", "end",
                                    values=(c.status, c.name, c.detail),
                                    tags=(c.status,))

    def _render_findings(self, findings):
        for f in findings:
            self.findings_tree.insert("", "end",
                                      values=(f.severity, f.title, f.category),
                                      tags=(f.severity,))
        if not findings:
            self.findings_tree.insert("", "end",
                                      values=("Passed", "No issues detected", "—"),
                                      tags=("Passed",))

    def _show_finding(self, event):
        sel = self.findings_tree.selection()
        if not sel: return
        idx = self.findings_tree.index(sel[0])
        if idx >= len(self.findings_list): return
        self.app._show_solution_dialog(self.findings_list[idx])


# ============================================================
# MAIN APPLICATION UI
# ============================================================

class CyberStudioApp:
    def __init__(self, root, config):
        self.root = root
        self.config = config
        self.theme = DARK_THEME.copy()
        self.url_var = tk.StringVar(value="https://example.com")
        self.auth_var = tk.BooleanVar(value=False)
        self.tool_pages = {}
        self.current_page = None
        self.nav_buttons = {}
        self.pages = {}
        self.kb = SolutionKB()

        self.root.title(f"{APP_NAME} v{APP_VERSION}")
        self.root.geometry("1500x920")
        self.root.minsize(1200, 750)
        self.root.configure(bg=self.theme["bg"])
        try: self.root.tk.call("tk", "scaling", 1.2)
        except: pass

        self._setup_styles()
        self._build_ui()
        self._show_page("dashboard")

    def _setup_styles(self):
        s = ttk.Style()
        try: s.theme_use("clam")
        except: pass
        s.configure("Treeview", background=self.theme["card"],
                    foreground=self.theme["text"],
                    fieldbackground=self.theme["card"],
                    rowheight=24, font=("Segoe UI", 9))
        s.configure("Treeview.Heading", background=self.theme["sidebar"],
                    foreground=self.theme["accent"],
                    font=("Segoe UI", 9, "bold"))
        s.map("Treeview", background=[("selected", self.theme["accent"])],
              foreground=[("selected", self.theme["bg"])])

    def _build_ui(self):
        # Top bar
        top = tk.Frame(self.root, bg=self.theme["sidebar"], height=64)
        top.pack(side="top", fill="x")
        top.pack_propagate(False)
        tk.Label(top, text="🛡 SCIT-BOSS",
                 bg=self.theme["sidebar"], fg=self.theme["accent"],
                 font=("Segoe UI", 18, "bold")).pack(side="left", padx=20, pady=10)
        tk.Label(top, text=f"Ultimate Cyber Security Studio · {len(ALL_TOOLS)}+ Tools",
                 bg=self.theme["sidebar"], fg=self.theme["muted"],
                 font=("Segoe UI", 9)).pack(side="left", padx=4, pady=18)
        tk.Label(top, text="● Ready", bg=self.theme["sidebar"],
                 fg=self.theme["success"], font=("Segoe UI", 10, "bold")).pack(
            side="right", padx=20)

        # Main split
        main = tk.Frame(self.root, bg=self.theme["bg"])
        main.pack(fill="both", expand=True)

        # Sidebar with scrollable nav
        sidebar = tk.Frame(main, bg=self.theme["sidebar"], width=260)
        sidebar.pack(side="left", fill="y")
        sidebar.pack_propagate(False)
        canvas = tk.Canvas(sidebar, bg=self.theme["sidebar"], highlightthickness=0)
        scroll = ttk.Scrollbar(sidebar, orient="vertical", command=canvas.yview)
        nav = tk.Frame(canvas, bg=self.theme["sidebar"])
        canvas.create_window((0, 0), window=nav, anchor="nw")
        canvas.configure(yscrollcommand=scroll.set)
        nav.bind("<Configure>", lambda e: canvas.configure(scrollregion=canvas.bbox("all")))
        canvas.pack(side="left", fill="both", expand=True)
        scroll.pack(side="right", fill="y")

        # Content area
        self.content = tk.Frame(main, bg=self.theme["bg"])
        self.content.pack(side="left", fill="both", expand=True)

        # Bottom bar
        bottom = tk.Frame(self.root, bg=self.theme["sidebar"], height=28)
        bottom.pack(side="bottom", fill="x")
        bottom.pack_propagate(False)
        tk.Label(bottom, text="DEVELOP BY SCIT-BOSS · www.scitboss.com · www.softkeybazar.com",
                 bg=self.theme["sidebar"], fg=self.theme["muted"],
                 font=("Segoe UI", 8, "italic")).pack(side="left", padx=20, pady=4)

        # Build nav + pages
        self._build_nav(nav)
        self._build_all_pages()

    def _add_nav_btn(self, parent, key, label, indent=0, color=None):
        btn = tk.Button(parent, text=label, bg=self.theme["sidebar"],
                        fg=color or self.theme["text"], relief="flat", anchor="w",
                        padx=20 + indent * 12, pady=6, font=("Segoe UI", 9),
                        cursor="hand2", activebackground=self.theme["card"],
                        activeforeground=self.theme["accent"],
                        command=lambda k=key: self._show_page(k))
        btn.pack(fill="x")
        self.nav_buttons[key] = btn

    def _build_nav(self, parent):
        # Dashboard
        self._add_nav_btn(parent, "dashboard", "🏠  Dashboard")
        tk.Frame(parent, bg=self.theme["border"], height=1).pack(fill="x", pady=6)

        for cat_name, cat_icon, tools in TOOL_CATEGORIES:
            # Category header
            cat_lbl = tk.Label(parent, text=f"{cat_icon}  {cat_name.upper()}",
                               bg=self.theme["sidebar"], fg=self.theme["accent"],
                               font=("Segoe UI", 8, "bold"), anchor="w", padx=16, pady=4)
            cat_lbl.pack(fill="x")
            for tool_id, tool_name, _, _ in tools:
                self._add_nav_btn(parent, f"tool_{tool_id}", f"   {tool_name}",
                                  indent=1, color=self.theme["muted"])
            tk.Frame(parent, bg=self.theme["border"], height=1).pack(fill="x", pady=2)

        # Extras
        self._add_nav_btn(parent, "settings", "⚙  Settings")
        self._add_nav_btn(parent, "about", "ℹ  About")

    def _build_all_pages(self):
        # Dashboard
        self.pages["dashboard"] = tk.Frame(self.content, bg=self.theme["bg"])
        self._build_dashboard()

        # Tool pages
        for tool_id, (cat_name, cat_icon, tool_name, tool_desc, tool_func) in ALL_TOOLS.items():
            key = f"tool_{tool_id}"
            frame = tk.Frame(self.content, bg=self.theme["bg"])
            self.pages[key] = frame
            self.tool_pages[key] = ToolPage(self, frame, tool_id, cat_icon,
                                            tool_name, tool_desc, tool_func)

        # Settings
        self.pages["settings"] = tk.Frame(self.content, bg=self.theme["bg"])
        self._build_settings(self.pages["settings"])

        # About
        self.pages["about"] = tk.Frame(self.content, bg=self.theme["bg"])
        self._build_about(self.pages["about"])

    def _show_page(self, key):
        if key not in self.pages:
            return
        for k, p in self.pages.items():
            p.pack_forget()
        self.pages[key].pack(fill="both", expand=True)
        for k, b in self.nav_buttons.items():
            if k == key:
                b.configure(bg=self.theme["card"], fg=self.theme["accent"])
            else:
                b.configure(bg=self.theme["sidebar"],
                            fg=self.theme["muted"] if k.startswith("tool_") else self.theme["text"])
        self.current_page = key
        # Sync URL to tool page
        if key.startswith("tool_") and key in self.tool_pages:
            tp = self.tool_pages[key]
            tp.url_var.set(self.url_var.get())

    def _build_dashboard(self):
        page = self.pages["dashboard"]
        header = tk.Frame(page, bg=self.theme["bg"])
        header.pack(fill="x", padx=30, pady=(20, 10))
        tk.Label(header, text="🛡  SCIT-BOSS Ultimate Cyber Security Studio",
                 bg=self.theme["bg"], fg=self.theme["accent"],
                 font=("Segoe UI", 22, "bold")).pack(anchor="w")
        tk.Label(header,
                 text=f"{len(ALL_TOOLS)} fully working security tools · Modular design · Each tool runs independently",
                 bg=self.theme["bg"], fg=self.theme["muted"],
                 font=("Segoe UI", 11)).pack(anchor="w", pady=(4, 0))

        # Hero card
        hero = tk.Frame(page, bg=self.theme["card"])
        hero.pack(fill="x", padx=30, pady=10)
        inner = tk.Frame(hero, bg=self.theme["card"])
        inner.pack(fill="x", padx=20, pady=14)
        tk.Label(inner, text="🌐  Target URL", bg=self.theme["card"],
                 fg=self.theme["text"], font=("Segoe UI", 11, "bold")).pack(anchor="w")
        row = tk.Frame(inner, bg=self.theme["card"])
        row.pack(fill="x", pady=6)
        tk.Entry(row, textvariable=self.url_var, bg=self.theme["input_bg"],
                 fg=self.theme["text"], insertbackground=self.theme["text"],
                 relief="flat", font=("Segoe UI", 12)).pack(
            side="left", fill="x", expand=True, ipady=10, padx=(0, 10))
        tk.Button(row, text="🔍  Browse All Tools",
                  bg=self.theme["accent"], fg=self.theme["bg"],
                  font=("Segoe UI", 10, "bold"), relief="flat",
                  padx=20, pady=10,
                  command=self._show_tools_overview).pack(side="left")

        tk.Checkbutton(inner,
                       text="⚠ I confirm I own or am explicitly authorized to test this website",
                       variable=self.auth_var, bg=self.theme["card"],
                       fg=self.theme["warning"], selectcolor=self.theme["card"],
                       activebackground=self.theme["card"],
                       activeforeground=self.theme["warning"],
                       font=("Segoe UI", 9)).pack(anchor="w", pady=(6, 0))

        # Categories overview
        tk.Label(page, text=f"📦  {len(TOOL_CATEGORIES)} Categories · {len(ALL_TOOLS)} Tools",
                 bg=self.theme["bg"], fg=self.theme["accent"],
                 font=("Segoe UI", 14, "bold")).pack(anchor="w", padx=30, pady=(16, 4))

        cat_grid = tk.Frame(page, bg=self.theme["bg"])
        cat_grid.pack(fill="both", expand=True, padx=30, pady=8)

        for i, (cat_name, cat_icon, tools) in enumerate(TOOL_CATEGORIES):
            r, c = divmod(i, 4)
            card = tk.Frame(cat_grid, bg=self.theme["card2"], cursor="hand2")
            card.grid(row=r, column=c, padx=6, pady=6, sticky="nsew")
            cat_grid.columnconfigure(c, weight=1)
            cat_grid.rowconfigure(r, weight=1)
            tk.Label(card, text=cat_icon, bg=self.theme["card2"],
                     fg=self.theme["accent"], font=("Segoe UI", 28)).pack(pady=(12, 2))
            tk.Label(card, text=cat_name, bg=self.theme["card2"],
                     fg=self.theme["text"], font=("Segoe UI", 11, "bold")).pack()
            tk.Label(card, text=f"{len(tools)} tools", bg=self.theme["card2"],
                     fg=self.theme["muted"], font=("Segoe UI", 9)).pack(pady=(0, 12))

            def mk_hover(w):
                def enter(e):
                    try:
                        w.configure(bg=self.theme["card"])
                        for ch in w.winfo_children():
                            try: ch.configure(bg=self.theme["card"])
                            except: pass
                    except: pass
                def leave(e):
                    try:
                        w.configure(bg=self.theme["card2"])
                        for ch in w.winfo_children():
                            try: ch.configure(bg=self.theme["card2"])
                            except: pass
                    except: pass
                w.bind("<Enter>", enter)
                w.bind("<Leave>", leave)
                for ch in w.winfo_children():
                    ch.bind("<Enter>", enter)
                    ch.bind("<Leave>", leave)
                # First tool of this category
                first_id = tools[0][0]
                w.bind("<Button-1>", lambda e, k=f"tool_{first_id}": self._show_page(k))
                for ch in w.winfo_children():
                    ch.bind("<Button-1>", lambda e, k=f"tool_{first_id}": self._show_page(k))
            mk_hover(card)

    def _show_tools_overview(self):
        # Show first category's first tool as overview
        first_cat = TOOL_CATEGORIES[0]
        first_tool = first_cat[2][0]
        self._show_page(f"tool_{first_tool[0]}")

    def _build_settings(self, page):
        tk.Label(page, text="⚙  Settings", bg=self.theme["bg"],
                 fg=self.theme["accent"], font=("Segoe UI", 20, "bold")).pack(
            anchor="w", padx=30, pady=20)
        form = tk.Frame(page, bg=self.theme["bg"])
        form.pack(fill="x", padx=30, pady=10)

        self.setting_vars = {}

        def add(label, key, wt="entry", values=None):
            f = tk.Frame(form, bg=self.theme["bg"])
            f.pack(fill="x", pady=4)
            tk.Label(f, text=label, bg=self.theme["bg"], fg=self.theme["text"],
                     width=30, anchor="w", font=("Segoe UI", 10)).pack(side="left")
            if wt == "check":
                var = tk.BooleanVar(value=bool(self.config.get(key, False)))
                self.setting_vars[key] = var
                tk.Checkbutton(f, variable=var, bg=self.theme["bg"],
                               activebackground=self.theme["bg"]).pack(side="left", padx=8)
            elif wt == "combo":
                var = tk.StringVar(value=str(self.config.get(key, "")))
                self.setting_vars[key] = var
                ttk.Combobox(f, textvariable=var, values=values,
                             state="readonly", width=30).pack(side="left", padx=8)
            else:
                var = tk.StringVar(value=str(self.config.get(key, "")))
                self.setting_vars[key] = var
                tk.Entry(f, textvariable=var, bg=self.theme["input_bg"],
                         fg=self.theme["text"], width=32, relief="flat").pack(
                    side="left", padx=8)

        add("Font Size", "font_size")
        add("Connection Timeout (s)", "connection_timeout")
        add("Read Timeout (s)", "read_timeout")
        add("Requests/sec", "requests_per_second")
        add("SSL Verification", "ssl_verify", "check")
        add("Enable Animations", "animations", "check")

        tk.Button(form, text="💾  Save Settings",
                  bg=self.theme["accent"], fg=self.theme["bg"],
                  relief="flat", padx=20, pady=8,
                  font=("Segoe UI", 10, "bold"),
                  command=self._save_settings).pack(anchor="w", pady=12)

    def _save_settings(self):
        for k, v in self.setting_vars.items():
            try:
                if isinstance(v, tk.BooleanVar):
                    self.config.set(k, v.get())
                else:
                    cur = self.config.get(k)
                    val = v.get()
                    if isinstance(cur, int): self.config.set(k, int(val))
                    elif isinstance(cur, float): self.config.set(k, float(val))
                    else: self.config.set(k, val)
            except Exception as e:
                log.warning("Set %s: %s", k, e)
        self.config.save()
        messagebox.showinfo("Settings", "Saved successfully.")

    def _build_about(self, page):
        wrap = tk.Frame(page, bg=self.theme["bg"])
        wrap.pack(fill="both", expand=True, padx=40, pady=30)
        tk.Label(wrap, text="🛡", bg=self.theme["bg"], fg=self.theme["accent"],
                 font=("Segoe UI", 60)).pack(anchor="w")
        tk.Label(wrap, text=APP_NAME, bg=self.theme["bg"], fg=self.theme["accent"],
                 font=("Segoe UI", 22, "bold")).pack(anchor="w", pady=4)
        tk.Label(wrap, text=f"Version {APP_VERSION}",
                 bg=self.theme["bg"], fg=self.theme["muted"],
                 font=("Segoe UI", 11)).pack(anchor="w", pady=2)
        tk.Label(wrap, text=f"Developed by: {DEVELOPER}",
                 bg=self.theme["bg"], fg=self.theme["muted"],
                 font=("Segoe UI", 11)).pack(anchor="w", pady=2)
        tk.Label(wrap, text=f"Website: {DEV_SITE}",
                 bg=self.theme["bg"], fg=self.theme["accent"],
                 font=("Segoe UI", 11)).pack(anchor="w", pady=2)
        tk.Label(wrap, text=f"Marketplace: {DEV_MARKET}",
                 bg=self.theme["bg"], fg=self.theme["accent"],
                 font=("Segoe UI", 11)).pack(anchor="w", pady=2)
        tk.Label(wrap, text=f"Total Tools: {len(ALL_TOOLS)} in {len(TOOL_CATEGORIES)} categories",
                 bg=self.theme["bg"], fg=self.theme["warning"],
                 font=("Segoe UI", 12, "bold")).pack(anchor="w", pady=(20, 4))
        tk.Label(wrap,
                 text="Technology: Python 3.11+ / Tkinter / Standard Library only\n"
                      "Each tool operates independently with its own UI, scan engine and results view.\n\n"
                      "⚠ Non-intrusive authorized audits only. Does not attempt exploitation.\n"
                      "A clean report does not guarantee absence of vulnerabilities.",
                 bg=self.theme["bg"], fg=self.theme["muted"],
                 font=("Segoe UI", 10), justify="left").pack(anchor="w", pady=10)

    def _show_solution_dialog(self, finding):
        win = tk.Toplevel(self.root)
        win.title(f"Solution — {finding.title}")
        win.geometry("800x620")
        win.configure(bg=self.theme["bg"])

        header = tk.Frame(win, bg=self.theme["card"])
        header.pack(fill="x")
        sev_color = SEVERITY_COLORS.get(finding.severity, self.theme["muted"])
        tk.Label(header, text=f"💡  {finding.title}",
                 bg=self.theme["card"], fg=self.theme["accent"],
                 font=("Segoe UI", 14, "bold")).pack(anchor="w", padx=16, pady=(12, 4))
        tk.Label(header,
                 text=f"Severity: {finding.severity}  ·  Category: {finding.category}  ·  "
                      f"Confidence: {finding.confidence}",
                 bg=self.theme["card"], fg=sev_color,
                 font=("Segoe UI", 9)).pack(anchor="w", padx=16, pady=(0, 12))

        kb = self.kb.get(finding)
        body = tk.Text(win, bg=self.theme["input_bg"], fg=self.theme["text"],
                       relief="flat", font=("Segoe UI", 10), wrap="word",
                       padx=16, pady=16)
        body.pack(fill="both", expand=True, padx=12, pady=12)
        content = (
            f"PROBLEM\n{finding.title}\n\n"
            f"TECHNICAL EXPLANATION\n{kb['explanation']}\n\n"
            f"DESCRIPTION\n{finding.description}\n\n"
            f"IMPACT\n{finding.impact}\n\n"
            f"EVIDENCE\n{finding.evidence}\n\n"
            f"RECOMMENDED FIX\n{finding.recommended_fix}\n\n"
            f"EXAMPLE CODE\n{kb['code']}\n\n"
            f"VERIFICATION\n{finding.verification or 'Re-scan to verify.'}\n"
        )
        body.insert("1.0", content)
        body.configure(state="disabled")

        btns = tk.Frame(win, bg=self.theme["bg"])
        btns.pack(fill="x", padx=12, pady=8)
        tk.Button(btns, text="📋  Copy Code",
                  bg=self.theme["accent"], fg=self.theme["bg"],
                  relief="flat", padx=14, pady=6,
                  command=lambda: (win.clipboard_clear(),
                                   win.clipboard_append(kb["code"]),
                                   messagebox.showinfo("Copied", "Copied!"))).pack(side="left", padx=4)
        tk.Button(btns, text="✕  Close", bg=self.theme["card2"],
                  fg=self.theme["text"], relief="flat", padx=14, pady=6,
                  command=win.destroy).pack(side="right", padx=4)


# ============================================================
# MAIN
# ============================================================

def main():
    try:
        root = tk.Tk()
    except Exception as e:
        print(f"Tkinter unavailable: {e}")
        return

    config = AppConfig()
    try:
        app = CyberStudioApp(root, config)
    except Exception:
        log.exception("Startup error")
        messagebox.showerror("Startup Error", traceback.format_exc())
        root.destroy()
        return

    def on_close():
        try: config.save()
        except: pass
        root.destroy()

    root.protocol("WM_DELETE_WINDOW", on_close)
    root.mainloop()


if __name__ == "__main__":
    main()
