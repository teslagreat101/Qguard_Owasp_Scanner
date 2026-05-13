"""
Quantara Security v5.0 — Unified Scan Orchestrator

Chains all merged scanner systems into a single pipeline:
  - Phase 1: Scanner_2 OWASP modules (misconfig, injection, frontend_js, etc.)
  - Phase 2: Scanner_1 extended analyzers
  - Phase 3: New module — SSRF scanner
  - Phase 4: code_security_scanner — multi-agent semantic analysis
  - Phase 5: Quantara HTTP scanner — YAML-template-driven live web vulnerability scanner
              (XSS, SQLi, LFI, SSRF, SSTI, Command Injection, IDOR, CORS, JWT,
               security headers, backup files, debug endpoints, tech fingerprinting)
  - Smart routing: URL→Quantara HTTP + live HTTP scan, GitHub→repository scan,
                   local dir→code_security_scanner, code→code analysis
  - Finding deduplication across all phases
  - Unified finding normalization
  - Combined risk scoring
"""

from __future__ import annotations

import os
import re
import sys
import time
import hashlib
import logging
import tempfile
import uuid
import warnings
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Optional

logger = logging.getLogger("scanner_engine.orchestrator")

# ── Ensure parent paths are available for both scanner packages ──
_ROOT = str(Path(__file__).resolve().parent.parent)
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)

_SCANNER2_DIR = os.path.join(_ROOT, "owasp_Scanner")
if _SCANNER2_DIR not in sys.path:
    sys.path.insert(0, _SCANNER2_DIR)

_SCANNER1_DIR = os.path.join(_ROOT, "quantara_protocol")
if _SCANNER1_DIR not in sys.path:
    sys.path.insert(0, _SCANNER1_DIR)

# ── Import Scanner_2 flat modules ──
from misconfig_engine import scan_misconfig_file, scan_misconfig_directory
from injection_scanner import scan_injection_file, scan_injection_directory
from quantara_js_analyzer import scan_frontend_file, scan_frontend_directory
from endpoint_extractor import scan_file_endpoints, scan_directory_endpoints
from auth_scanner import scan_auth_file, scan_auth_directory
from broken_access import scan_access_file, scan_access_directory
from cloud_misconfig import scan_cloud_file, scan_cloud_directory
from api_security import scan_api_file, scan_api_directory
from supply_chain import scan_supply_chain_file, scan_supply_chain_directory
from insecure_design import scan_design_file, scan_design_directory
from integrity_scanner import scan_integrity_file, scan_integrity_directory

# ── Import ALL Scanner_1 (quantum_protocol) analyzers ──
try:
    from quantara_protocol.analyzers.logging_scanner import scan_logging_scanner
    from quantara_protocol.analyzers.exception_scanner import scan_exception_scanner
    from quantara_protocol.analyzers.sensitive_data_exposure import scan_sensitive_data
    from quantara_protocol.core.engine import scan_file as qp_scan_file
    from quantara_protocol.core.engine import scan_local_directory as qp_scan_directory
    from quantara_protocol.core.engine import scan_repository as qp_scan_repository
    from quantara_protocol.models.enums import ScanMode
    _SCANNER1_AVAILABLE = True
    logger.info("Scanner_1 (quantara_protocol) loaded successfully")
except ImportError as _qp_err:
    _SCANNER1_AVAILABLE = False
    logger.warning(f"Scanner_1 quantara_protocol not available: {_qp_err}")

# ── Import code_security_scanner (multi-agent semantic analysis) ──
try:
    from code_security_scanner.scanner import CodeSecurityScanner
    _CODE_SCANNER_AVAILABLE = True
    logger.info("code_security_scanner (multi-agent) loaded successfully")
except ImportError as _cs_err:
    _CODE_SCANNER_AVAILABLE = False
    logger.warning(f"code_security_scanner not available: {_cs_err}")

# ── Import new SSRF scanner ──
from scanner_engine.ssrf_scanner import scan_ssrf_file, scan_ssrf_directory

# ── Import Quantara HTTP scanner ──
try:
    from quantara_scanner import scan_url_with_quantara, QuantaraWebScanner
    _QUANTARA_AVAILABLE = True
    logger.info("Quantara HTTP scanner loaded successfully")
except ImportError as _quantara_err:
    _QUANTARA_AVAILABLE = False
    logger.warning(f"Quantara HTTP scanner not available: {_quantara_err}")

# ── Import Quantara Enterprise Feature Modules (Phase 7) ──
try:
    from quantara_crawler import QuantaraCrawler
    from quantara_auth import QuantaraAuthEngine, AuthConfig
    from quantara_fp_reducer import FPReducer
    from quantara_oast import QuantaraOAST
    from quantara_chains import AttackChainCorrelator
    from quantara_ai import QuantaraAICopilot
    _ENTERPRISE_AVAILABLE = True
    logger.info("Quantara Enterprise modules (crawler/auth/fp_reducer/oast/chains/ai) loaded successfully")
except ImportError as _ent_err:
    _ENTERPRISE_AVAILABLE = False
    logger.warning(f"Quantara Enterprise feature modules not available: {_ent_err}")

# ── Import NEO Intelligence Layer ──
try:
    from scanner_engine.neo_intelligence import (
        NeoScanLoop, get_neo_scan_loop,
        ScanPhase, ScanMode, NeoScanTarget, NeoScanResult,
        get_intelligence_graph, get_spec_abuse_kb,
        get_payload_generator, get_attack_brain, get_learning_memory,
    )
    _NEO_INTELLIGENCE_AVAILABLE = True
    logger.info("NEO Intelligence Layer loaded successfully (5 layers + scan loop)")
except ImportError as _neo_err:
    _NEO_INTELLIGENCE_AVAILABLE = False
    logger.warning(f"NEO Intelligence Layer not available: {_neo_err}")


# ═══════════════════════════════════════════════════════════════════════════════
# Smart Target Type Detection
# ═══════════════════════════════════════════════════════════════════════════════

_GITHUB_PATTERN = re.compile(r"^https?://(www\.)?github\.com/", re.IGNORECASE)
_URL_PATTERN = re.compile(r"^https?://", re.IGNORECASE)


def detect_scan_target_type(target: str) -> str:
    """Auto-detect target type. Returns: 'github', 'url', 'directory', or 'code'."""
    if _GITHUB_PATTERN.match(target):
        return "github"
    if _URL_PATTERN.match(target):
        return "url"
    if os.path.isdir(target):
        return "directory"
    return "code"


# ═══════════════════════════════════════════════════════════════════════════════
# Unified Finding Model
# ═══════════════════════════════════════════════════════════════════════════════

@dataclass
class UnifiedFinding:
    """Normalized finding from any scanner module."""
    id: str
    file: str
    line_number: int
    severity: str
    title: str
    description: str
    matched_content: str = ""
    category: str = ""
    cwe: str = ""
    remediation: str = ""
    confidence: float = 1.0
    module: str = ""
    module_name: str = ""
    owasp: str = ""
    language: str = ""
    tags: list[str] = field(default_factory=list)
    timestamp: str = ""
    injection_type: str = ""
    subcategory: str = ""
    ssrf_type: str = ""
    finding_type: str = ""
    scanner_source: str = ""   # "owasp", "quantara", "code_agent"
    hndl_relevant: bool = False
    quantara_risk: str = ""
    pqc_migration: str = ""
    agent_certainty: float = 0.0
    agent_verdict: str = ""
    patch_suggestion: str = ""
    taint_flow: str = ""
    # PQSI fields
    data_longevity_estimate: str = ""
    hndl_probability_score: float = 0.0
    future_decryption_risk: str = ""
    quantum_exposure_years: float = 0.0
    migration_urgency: str = ""
    pqc_adoption_index: float = 0.0

    def to_dict(self) -> dict:
        d = asdict(self)
        return {k: v for k, v in d.items() if v is not None and v != "" and v != [] and v is not False}


# ═══════════════════════════════════════════════════════════════════════════════
# Module Registry — Complete OWASP Top 10:2025 Coverage + Extensions
# ═══════════════════════════════════════════════════════════════════════════════

UNIFIED_MODULE_REGISTRY = {
    # Phase 1: Core OWASP Modules (from Scanner_2)
    "misconfig": {
        "name": "Security Misconfiguration Engine", "owasp": "A05:2025", "phase": 1,
        "scan_file": scan_misconfig_file, "scan_dir": scan_misconfig_directory,
        "pattern_count": 40, "description": "Debug modes, default creds, missing headers, Docker misconfigs",
    },
    "injection": {
        "name": "Injection Scanner", "owasp": "A03:2025", "phase": 1,
        "scan_file": scan_injection_file, "scan_dir": scan_injection_directory,
        "pattern_count": 90, "description": "SQL, XSS, Command, Template, NoSQL, LDAP, XXE, CRLF injection",
    },
    "frontend_js": {
        "name": "Frontend JS Analyzer", "owasp": "A02:2025", "phase": 1,
        "scan_file": scan_frontend_file, "scan_dir": scan_frontend_directory,
        "pattern_count": 150, "description": "Client-side secrets, eval, source maps, API keys in bundles",
    },
    "endpoint": {
        "name": "Endpoint Extractor & Recon", "owasp": "Recon", "phase": 1,
        "scan_file": scan_file_endpoints, "scan_dir": scan_directory_endpoints,
        "pattern_count": 25, "description": "API endpoint discovery, tech fingerprinting, bug bounty recon",
    },
    "auth": {
        "name": "Authentication Failures Scanner", "owasp": "A07:2025", "phase": 1,
        "scan_file": scan_auth_file, "scan_dir": scan_auth_directory,
        "pattern_count": 35, "description": "Weak passwords, JWT misconfig, session handling, MFA bypass",
    },
    "access_control": {
        "name": "Broken Access Control", "owasp": "A01:2025", "phase": 1,
        "scan_file": scan_access_file, "scan_dir": scan_access_directory,
        "pattern_count": 45, "description": "IDOR, privilege escalation, missing authorization, path traversal",
    },
    "cloud": {
        "name": "Cloud Misconfiguration Scanner", "owasp": "A05:2025-Cloud", "phase": 1,
        "scan_file": scan_cloud_file, "scan_dir": scan_cloud_directory,
        "pattern_count": 50, "description": "AWS, GCP, Azure, Terraform, K8s, Docker security misconfigs",
    },
    "api_security": {
        "name": "API Security Scanner", "owasp": "API-Top-10", "phase": 1,
        "scan_file": scan_api_file, "scan_dir": scan_api_directory,
        "pattern_count": 30, "description": "GraphQL, BOLA, excessive data exposure, rate limiting gaps",
    },
    "supply_chain": {
        "name": "Supply Chain Scanner", "owasp": "A06:2025", "phase": 1,
        "scan_file": scan_supply_chain_file, "scan_dir": scan_supply_chain_directory,
        "pattern_count": 20, "description": "Unpinned deps, typosquatting, vulnerable packages, CI/CD integrity",
    },
    "insecure_design": {
        "name": "Insecure Design Scanner", "owasp": "A04:2025", "phase": 1,
        "scan_file": scan_design_file, "scan_dir": scan_design_directory,
        "pattern_count": 25, "description": "Missing rate limits, CSRF, mass assignment, business logic flaws",
    },
    "integrity": {
        "name": "Integrity Failures Scanner", "owasp": "A08:2025", "phase": 1,
        "scan_file": scan_integrity_file, "scan_dir": scan_integrity_directory,
        "pattern_count": 20, "description": "Unsafe deserialization, missing SRI, CI/CD action pinning",
    },
    # Phase 2: Extended Analyzers (from Scanner_1 quantum_protocol)
    "logging": {
        "name": "Security Logging & Monitoring", "owasp": "A09:2025", "phase": 2,
        "scan_file": None, "scan_dir": None, "pattern_count": 10,
        "description": "Audit logging gaps, PII in logs, log injection, verbose errors",
        "requires_scanner1": True,
    },
    "exception": {
        "name": "Exception Handling Scanner", "owasp": "A10:2025-Ext", "phase": 2,
        "scan_file": None, "scan_dir": None, "pattern_count": 12,
        "description": "Fail-open logic, swallowed errors, resource leaks, broad catches",
        "requires_scanner1": True,
    },
    "sensitive_data": {
        "name": "Sensitive Data Exposure", "owasp": "A02:2025-Data", "phase": 2,
        "scan_file": None, "scan_dir": None, "pattern_count": 7,
        "description": "PII in code, SSN/credit card patterns, cleartext storage",
        "requires_scanner1": True,
    },
    # Phase 3: SSRF Scanner
    "ssrf": {
        "name": "SSRF Scanner", "owasp": "A10:2025", "phase": 3,
        "scan_file": scan_ssrf_file, "scan_dir": scan_ssrf_directory,
        "pattern_count": 15, "description": "Server-Side Request Forgery: metadata, DNS rebinding, PDF gen SSRF",
    },
    # Phase 4: Multi-Agent Code Security Scanner
    "code_agent": {
        "name": "Multi-Agent Code Security Analyzer", "owasp": "A01-A10:2025", "phase": 4,
        "scan_file": None, "scan_dir": None, "pattern_count": 200,
        "description": "Red/Blue/Auditor agents with taint analysis, data flow, patch suggestions",
        "requires_code_scanner": True,
    },
    # Phase 6: Quantara HTTP Scanner (live URL scanning)
    "quantara_http": {
        "name": "Quantara HTTP Vulnerability Scanner", "owasp": "A01-A10:2021", "phase": 6,
        "scan_file": None, "scan_dir": None, "pattern_count": 523,
        "description": (
            "YAML-template-driven live HTTP scanner: SQLi, XSS, LFI, SSRF, SSTI, "
            "Command Injection, IDOR, CORS, JWT, security headers, tech fingerprinting, "
            "backup files, debug endpoints, subdomain takeover, credential disclosure, "
            "open redirect, CRLF injection, CVE-2025-29927 (Next.js middleware bypass), "
            "GraphQL introspection, IIS misconfig, PHP backup files, AWS key exposure — "
            "full OWASP Top 10:2021 coverage + extended Quantara YAML templates"
        ),
        "requires_quantara": True,
        "url_only": True,  # only makes sense for live URL scans
    },
    # Phase 7: Enterprise Quantara Feature Modules
    "quantara_crawler": {
        "name": "Quantara Web Crawler", "owasp": "Recon", "phase": 7,
        "scan_file": None, "scan_dir": None, "pattern_count": 60,
        "description": "BFS recursive crawler: JS endpoint extraction, form discovery, 60+ hidden paths, OpenAPI/GraphQL schema, sitemap/robots.txt parsing",
        "requires_enterprise": True, "url_only": True,
    },
    "quantara_auth": {
        "name": "Quantara Auth Engine", "owasp": "A07:2025", "phase": 7,
        "scan_file": None, "scan_dir": None, "pattern_count": 50,
        "description": "Multi-role auth testing: form login, JWT/Bearer, OAuth2, cookie jar, API key, CSRF extraction, IDOR/privilege escalation detection",
        "requires_enterprise": True, "url_only": True,
    },
    "quantara_fp_reducer": {
        "name": "Quantara FP Reducer", "owasp": "Accuracy", "phase": 7,
        "scan_file": None, "scan_dir": None, "pattern_count": 30,
        "description": "6-step differential FP pipeline: Baseline→Control→Payload→Diff→Reflect→Timing→Confidence (CONFIRMED/LIKELY_TP/FALSE_POSITIVE)",
        "requires_enterprise": True, "url_only": True,
    },
    "quantara_oast": {
        "name": "Quantara OAST Engine", "owasp": "A10:2025", "phase": 7,
        "scan_file": None, "scan_dir": None, "pattern_count": 80,
        "description": "Out-of-band blind vuln detection: interactsh client, blind SSRF/XSS/SQLi/CMDi/XXE payloads, CallbackCorrelator polling",
        "requires_enterprise": True, "url_only": True,
    },
    "quantara_chains": {
        "name": "Quantara Attack Chains", "owasp": "Multi-Stage", "phase": 7,
        "scan_file": None, "scan_dir": None, "pattern_count": 40,
        "description": "Attack chain correlation: 9 chain templates (SSRF→Cloud, LFI→SQLi, XSS→Admin, Secret→Exfil), proximity scoring, MITRE ATT&CK mapping",
        "requires_enterprise": True, "url_only": True,
    },
    "quantara_ai": {
        "name": "Quantara AI Copilot", "owasp": "AI-Enrichment", "phase": 7,
        "scan_file": None, "scan_dir": None, "pattern_count": 100,
        "description": "Multi-LLM enrichment: TP/FP verdict, business impact, code remediation, attack narrative, POC fix — Gemini→Claude→GPT fallback chain",
        "requires_enterprise": True,
    },
    # Phase 9: NEO Intelligence Layer
    "neo_intelligence": {
        "name": "NEO Intelligence Engine", "owasp": "A01-A10:2025", "phase": 9,
        "scan_file": None, "scan_dir": None, "pattern_count": 500,
        "description": (
            "Autonomous 5-layer intelligence: Application Intelligence Graph, "
            "Spec Abuse Knowledge Base (16 patterns, 102 payloads), "
            "Self-Learning Payload Generator (DNA-based mutations, WAF evasion), "
            "Attack Simulation Brain (vulnerability chaining, BFS attack paths), "
            "Continuous Learning Memory (cross-scan intelligence). "
            "MAP→TRACE→REASON→HYPOTHESIZE→EXPLOIT→VERIFY→LEARN"
        ),
        "requires_neo": True,
    },
}


# ═══════════════════════════════════════════════════════════════════════════════
# Finding Normalization
# ═══════════════════════════════════════════════════════════════════════════════

def normalize_finding(finding: Any, module_key: str) -> UnifiedFinding:
    """Normalize any scanner finding into a UnifiedFinding."""
    if isinstance(finding, UnifiedFinding):
        return finding
        
    meta = UNIFIED_MODULE_REGISTRY.get(module_key, {})
    now = datetime.now(timezone.utc).isoformat()

    # Helper for robust attribute/dict access
    def val(attr: str, default: Any = "") -> Any:
        if finding is None: return default
        if isinstance(finding, dict):
            res = finding.get(attr, default)
            return res if res is not None else default
        res = getattr(finding, attr, default)
        return res if res is not None else default

    scanner_source = "owasp"
    if module_key in ("logging", "exception", "sensitive_data"):
        scanner_source = "quantara"
    elif module_key == "code_agent":
        scanner_source = "code_agent"
    elif module_key in (
        "quantara_http", "quantara_crawler", "quantara_auth",
        "quantara_fp_reducer", "quantara_oast", "quantara_chains", "quantara_ai",
        "neo_intelligence"
    ):
        scanner_source = val("scanner_source", "quantara")

    result = UnifiedFinding(
        id=val("id", "") or _gen_id(),
        file=val("file", ""),
        line_number=int(val("line_number", 0)),
        severity=(str(val("severity", "info")) or "info").lower(),
        title=val("title", ""),
        description=val("description", ""),
        matched_content=val("matched_content", "") or val("matched_value", ""),
        category=val("category", "") or meta.get("owasp", ""),
        cwe=val("cwe", "") or val("cwe_id", ""),
        remediation=val("remediation", ""),
        confidence=float(val("confidence", 1.0)),
        module=module_key,
        module_name=meta.get("name", module_key),
        owasp=meta.get("owasp", ""),
        language=val("language", ""),
        tags=list(val("tags", []) or []),
        timestamp=now,
        injection_type=val("injection_type", ""),
        subcategory=val("subcategory", ""),
        ssrf_type=val("ssrf_type", ""),
        finding_type=val("finding_type", ""),
        scanner_source=scanner_source,
    )

    # Endpoint extractor format
    if (hasattr(finding, "url") or (isinstance(finding, dict) and "url" in finding)) and not result.title:
        url_val = val("url")
        result.title = f"Endpoint: {url_val}"
        result.description = val("description", "") or f"{val('endpoint_type', 'unknown')} endpoint discovered"
        result.severity = str(val("risk_level", "info")).lower()
        result.file = val("file", "")
        result.line_number = int(val("line_number", 0))

    # Crypto Scanner format
    if (hasattr(finding, "risk") or (isinstance(finding, dict) and "risk" in finding)) and \
       (hasattr(finding, "family") or (isinstance(finding, dict) and "family" in finding)):
        result.severity = str(val("risk", "info")).lower()
        result.title = f"Crypto: {val('algorithm', 'unknown')} {val('family', 'unknown')}"
        result.finding_type = "cryptographic"
        result.tags.append("crypto")
        # Original Scanner_1 CryptoFinding format fields
        result.matched_content = val("line_content", "") or ""
        result.hndl_relevant = bool(val("hndl_relevant", False))
        migration_data = val("migration", {})
        if isinstance(migration_data, dict):
            result.remediation = migration_data.get("action", "")
            result.pqc_migration = str(migration_data)
            if not result.cwe:
                result.cwe = migration_data.get("cwe", "")
        result.quantara_risk = str(val("risk", ""))
        if scanner_source != "pqsi":
            result.scanner_source = "quantara"
        # PQSI enrichment fields
        if hasattr(finding, "data_longevity_estimate") and finding.data_longevity_estimate:
            result.data_longevity_estimate = str(finding.data_longevity_estimate)
        if hasattr(finding, "hndl_probability_score") and finding.hndl_probability_score:
            result.hndl_probability_score = float(finding.hndl_probability_score)
        if hasattr(finding, "future_decryption_risk") and finding.future_decryption_risk:
            result.future_decryption_risk = str(finding.future_decryption_risk)
        if hasattr(finding, "quantum_exposure_years") and finding.quantum_exposure_years:
            result.quantum_exposure_years = float(finding.quantum_exposure_years)
        if hasattr(finding, "migration_urgency") and finding.migration_urgency:
            result.migration_urgency = str(finding.migration_urgency)
        if hasattr(finding, "pqc_adoption_index") and finding.pqc_adoption_index:
            result.pqc_adoption_index = float(finding.pqc_adoption_index)

    # code_security_scanner ValidatedFinding format
    if hasattr(finding, "verdict") and hasattr(finding, "patch_suggestions"):
        verdict = getattr(finding, "verdict", None)
        if verdict:
            result.agent_certainty = float(getattr(verdict, "certainty", 0.0))
            result.agent_verdict = str(getattr(verdict, "severity", ""))
        suggestions = getattr(finding, "patch_suggestions", [])
        if suggestions:
            first = suggestions[0]
            result.patch_suggestion = getattr(first, "patch_code", "") or str(first)
        taint = getattr(finding, "taint_flow", None)
        if taint:
            result.taint_flow = str(taint)
        sev = getattr(finding, "severity", None)
        if sev:
            result.severity = str(getattr(sev, "value", sev)).lower()
        result.scanner_source = "code_agent"

    return result


def normalize_finding_to_dict(finding: Any, module_key: str) -> dict:
    return normalize_finding(finding, module_key).to_dict()


# ═══════════════════════════════════════════════════════════════════════════════
# Deduplication
# ═══════════════════════════════════════════════════════════════════════════════

def _dedup_key(finding: UnifiedFinding) -> str:
    raw = f"{finding.file}:{finding.line_number}:{finding.title}:{finding.severity}"
    return hashlib.md5(raw.encode()).hexdigest()


def deduplicate_findings(findings: list[UnifiedFinding]) -> list[UnifiedFinding]:
    seen: dict[str, UnifiedFinding] = {}
    for f in findings:
        key = _dedup_key(f)
        if key not in seen or f.confidence > seen[key].confidence:
            seen[key] = f
    return list(seen.values())


# ═══════════════════════════════════════════════════════════════════════════════
# Risk Scoring
# ═══════════════════════════════════════════════════════════════════════════════

@dataclass
class ScanScores:
    overall_score: float = 100.0
    owasp_coverage: dict = field(default_factory=dict)
    severity_counts: dict = field(default_factory=lambda: {
        "critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0
    })
    total_findings: int = 0
    modules_run: int = 0
    risk_level: str = "Unknown"
    confidence: str = "LOW"
    scan_status: str = "INCONCLUSIVE"


def _compute_confidence_risk_score(
    severity_counts: dict,
    modules_run: int,
    total_modules: int,
) -> tuple[float, str, str, str]:
    """
    Confidence-based risk model.

    System NEVER assumes security from absence of findings.
    Low coverage → INCONCLUSIVE status, not a perfect score.

    Returns: (final_score, confidence, scan_status, risk_level)
    Example: 0 findings, 28% coverage → (~42, "LOW", "INCONCLUSIVE", "Unknown")
    """
    coverage = modules_run / max(total_modules, 1)
    severity_penalty = (
        severity_counts.get("critical", 0) * 15 +
        severity_counts.get("high", 0) * 8 +
        severity_counts.get("medium", 0) * 3 +
        severity_counts.get("low", 0) * 1
    )
    # Uncertainty penalty: low coverage means we cannot claim security
    uncertainty_penalty = round((1.0 - coverage) * 80)
    raw = 100 - severity_penalty
    final = max(0, min(100, raw - uncertainty_penalty))

    if coverage < 0.3:
        confidence, scan_status = "LOW", "INCONCLUSIVE"
    elif coverage < 0.7:
        confidence, scan_status = "MEDIUM", "PARTIAL_ASSESSMENT"
    else:
        confidence, scan_status = "HIGH", "ASSESSED"

    if severity_counts.get("critical", 0) > 0:
        risk_level = "Critical"
    elif severity_counts.get("high", 0) > 0:
        risk_level = "High"
    elif severity_counts.get("medium", 0) > 5:
        risk_level = "Medium"
    elif scan_status == "INCONCLUSIVE":
        risk_level = "Unknown"
    else:
        risk_level = "Low"

    return float(final), confidence, scan_status, risk_level


def compute_scan_scores(
    findings: list[UnifiedFinding],
    modules_run: int = 0,
    total_modules: int = 0,
) -> ScanScores:
    scores = ScanScores(modules_run=modules_run)
    scores.total_findings = len(findings)
    _total = total_modules if total_modules > 0 else max(modules_run, 1)
    for f in findings:
        sev = f.severity.lower()
        if sev in scores.severity_counts:
            scores.severity_counts[sev] += 1
        owasp = f.owasp or f.category
        if owasp:
            scores.owasp_coverage[owasp] = scores.owasp_coverage.get(owasp, 0) + 1

    scores.overall_score, scores.confidence, scores.scan_status, scores.risk_level = (
        _compute_confidence_risk_score(scores.severity_counts, modules_run, _total)
    )
    return scores


# ═══════════════════════════════════════════════════════════════════════════════
# Module Execution — Smart Routing
# ═══════════════════════════════════════════════════════════════════════════════

def run_module_scan(module_key: str, target: str, scan_type: str = "directory", target_type: Optional[str] = None) -> list:
    """
    Execute a single scanner module and return raw findings.

    Smart routing:
      - GitHub URL   → quantara_protocol.scan_repository()
      - Live HTTP URL→ fetch content + OWASP module scan
      - directory    → OWASP dir scan + optional code_agent/quantara_pqc
      - code         → inline content analysis
    """
    meta = UNIFIED_MODULE_REGISTRY.get(module_key)
    if not meta:
        raise ValueError(f"Unknown module: {module_key}")

    if meta.get("requires_scanner1") and not _SCANNER1_AVAILABLE:
        logger.warning(f"Skipping {module_key} — Scanner_1 not available")
        return []

    if meta.get("requires_code_scanner") and not _CODE_SCANNER_AVAILABLE:
        logger.warning(f"Skipping {module_key} — code_security_scanner not available")
        return []

    if meta.get("requires_quantara") and not _QUANTARA_AVAILABLE:
        logger.warning(f"Skipping {module_key} — quantara_scanner not available")
        return []

    # Use explicit target_type override first, then scan_type, then auto-detect
    if target_type and target_type in ("url", "github", "directory", "code"):
        effective_scan_type = target_type
    elif scan_type in ("url", "github", "directory", "code"):
        effective_scan_type = scan_type
    else:
        effective_scan_type = detect_scan_target_type(target)

    # GitHub URLs → quantara_protocol repo scan
    if effective_scan_type == "github" or _GITHUB_PATTERN.match(target or ""):
        return _run_github_scan(module_key, target)

    # code_agent — multi-agent semantic analysis
    if module_key == "code_agent":
        if effective_scan_type == "directory":
            return _run_code_agent_dir(target)
        if effective_scan_type == "code":
            return _run_code_agent_inline(target)
        return []

    # quantara_http — live HTTP scanning (URL only)
    if module_key == "quantara_http":
        if effective_scan_type == "url" and _QUANTARA_AVAILABLE:
            return _run_quantara_http_scan(target)
        logger.debug(f"quantara_http skipped: scan_type={effective_scan_type}, available={_QUANTARA_AVAILABLE}")
        return []

    # Enterprise Feature Modules (Phase 7) — URL-only for crawler/auth/fp_reducer/oast/chains; AI supports all
    _ENTERPRISE_URL_MODULES = ("quantara_crawler", "quantara_auth", "quantara_fp_reducer", "quantara_oast", "quantara_chains")
    if module_key in _ENTERPRISE_URL_MODULES or module_key == "quantara_ai":
        if not _ENTERPRISE_AVAILABLE:
            logger.warning(f"Skipping {module_key} — Enterprise modules not available")
            return []
        if effective_scan_type == "url":
            return _run_enterprise_url_module(module_key, target)
        if module_key == "quantara_ai" and effective_scan_type in ("directory", "github", "code"):
            # AI enrichment: post-process static scan findings
            raw = _run_github_scan("quantara_http", target) if effective_scan_type == "github" else []
            return _run_enterprise_ai_analysis(raw)
        logger.debug(f"{module_key} skipped for scan_type={effective_scan_type}")
        return []

    if effective_scan_type == "directory":
        if not os.path.isdir(target):
            return []
        if module_key in ("logging", "exception", "sensitive_data"):
            return _run_scanner1_dir(module_key, target)
        if module_key == "endpoint":
            report = meta["scan_dir"](target)
            return report.endpoints if hasattr(report, "endpoints") else []
        return meta["scan_dir"](target)

    elif effective_scan_type == "code":
        if module_key in ("logging", "exception", "sensitive_data"):
            return _run_scanner1_code(module_key, target)
        if module_key == "endpoint":
            result = meta["scan_file"](target, "paste_input.py")
            return result[0] if isinstance(result, tuple) else result
        return meta["scan_file"](target, "paste_input.py")

    elif effective_scan_type == "url":
        return _scan_url_live(target, module_key)

    return []


# ─────────────────────────────────────────────────────────────────────────────







# ─────────────────────────────────────────────────────────────────────────────

# Track recent GitHub scan failures to prevent duplicate error logging
_github_scan_failures: dict[str, float] = {}
_GITHUB_FAILURE_CACHE_TTL = 60  # seconds


def _run_github_scan(module_key: str, repo_url: str) -> list:
    """Route GitHub URL to repository.scan_repository()."""
    if not _SCANNER1_AVAILABLE:
        logger.warning(f"Cannot scan GitHub repo — scanner primary engine not available")
        return []

    # Check if we recently failed to scan this URL (prevent duplicate error logging)
    now = time.time()
    last_failure = _github_scan_failures.get(repo_url, 0)
    if now - last_failure < _GITHUB_FAILURE_CACHE_TTL:
        # We recently failed for this URL, skip without logging error again
        return []

    try:
        logger.info(f"[{module_key}] Scanning GitHub repo: {repo_url}")
        token = os.getenv("GITHUB_TOKEN")
        summary = qp_scan_repository(repo_url, github_token=token, scan_mode=ScanMode.FULL)
        # Clear any cached failure on success
        _github_scan_failures.pop(repo_url, None)
        return summary.findings if hasattr(summary, "findings") else []
    except Exception as e:
        # Only log the error if we haven't recently logged it
        if now - last_failure >= _GITHUB_FAILURE_CACHE_TTL:
            _github_scan_failures[repo_url] = now
            logger.error(f"GitHub scan failed for {repo_url}: {e}")
        return []





def _run_code_agent_dir(target: str) -> list:
    if not _CODE_SCANNER_AVAILABLE:
        return []
    try:
        scanner = CodeSecurityScanner()
        result = scanner.scan_directory(target)
        return result.findings if hasattr(result, "findings") else []
    except Exception as e:
        logger.error(f"code_security_scanner dir scan failed: {e}")
        return []


def _run_code_agent_inline(content: str) -> list:
    if not _CODE_SCANNER_AVAILABLE:
        return []
    try:
        with tempfile.NamedTemporaryFile(mode="w", suffix=".py", delete=False, encoding="utf-8") as tf:
            tf.write(content)
            tmp_path = tf.name
        try:
            scanner = CodeSecurityScanner()
            return scanner.scan_file(tmp_path)
        finally:
            os.unlink(tmp_path)
    except Exception as e:
        logger.error(f"code_security_scanner inline scan failed: {e}")
        return []


def _run_scanner1_dir(module_key: str, target: str) -> list:
    if not _SCANNER1_AVAILABLE:
        return []
    SKIP_DIRS = {"node_modules", ".git", ".next", "dist", "build", "__pycache__", ".venv", "venv", "vendor"}
    SCAN_EXTENSIONS = {".py", ".js", ".jsx", ".ts", ".tsx", ".java", ".go", ".rb", ".php", ".cs", ".rs", ".yaml", ".yml", ".json", ".xml"}
    scanner_fn = {"logging": scan_logging_scanner, "exception": scan_exception_scanner, "sensitive_data": scan_sensitive_data}.get(module_key)
    if not scanner_fn:
        return []
    all_findings = []
    root_path = Path(target)
    ext_to_lang = {".py": "python", ".js": "javascript", ".jsx": "javascript", ".ts": "typescript", ".tsx": "typescript", ".java": "java", ".go": "go", ".rb": "ruby", ".php": "php", ".cs": "csharp", ".rs": "rust"}
    scanned = 0
    for fpath in root_path.rglob("*"):
        if scanned >= 50_000:
            break
        if fpath.is_dir() or any(skip in fpath.parts for skip in SKIP_DIRS):
            continue
        if fpath.suffix.lower() not in SCAN_EXTENSIONS:
            continue
        try:
            content = fpath.read_text(encoding="utf-8", errors="ignore")
            if len(content) > 5_000_000:
                continue
            relative = str(fpath.relative_to(root_path))
            language = ext_to_lang.get(fpath.suffix.lower(), "unknown")
            all_findings.extend(scanner_fn(content, relative, language, ScanMode.FULL))
            scanned += 1
        except (OSError, PermissionError):
            continue
    return all_findings


def _run_scanner1_code(module_key: str, content: str) -> list:
    if not _SCANNER1_AVAILABLE:
        return []
    scanner_fn = {"logging": scan_logging_scanner, "exception": scan_exception_scanner, "sensitive_data": scan_sensitive_data}.get(module_key)
    if not scanner_fn:
        return []
    return scanner_fn(content, "paste_input.py", "python", ScanMode.FULL)


# ═══════════════════════════════════════════════════════════════════════════════
# Enterprise Feature Module Runners (Phase 7)
# ═══════════════════════════════════════════════════════════════════════════════

def _run_enterprise_url_module(module_key: str, url: str) -> list:
    """Dispatch to a specific Enterprise Quantara module for URL scanning."""
    if not _ENTERPRISE_AVAILABLE:
        return []
    try:
        if module_key == "quantara_crawler":
            return _run_quantara_crawler(url)
        if module_key == "quantara_auth":
            return _run_quantara_auth(url)
        if module_key == "quantara_fp_reducer":
            return _run_quantara_fp_reducer(url)
        if module_key == "quantara_oast":
            return _run_quantara_oast(url)
        if module_key == "quantara_chains":
            raw = _run_quantara_http_scan(url)
            return _run_chain_correlation(raw)
        if module_key == "quantara_ai":
            raw = _run_quantara_http_scan(url)
            return _run_enterprise_ai_analysis(raw)
    except Exception as e:
        logger.error(f"Enterprise module {module_key} failed for {url}: {e}")
    return []


def _run_quantara_crawler(url: str) -> list:
    """BFS crawl + convert discovered endpoints/suspicious paths to UnifiedFindings."""
    try:
        crawler = QuantaraCrawler(url, max_depth=3, max_urls=300, probe_hidden=True)
        graph = crawler.crawl()
        findings = []
        for ep in getattr(graph, "nodes", []):
            ep_url  = getattr(ep, "url", "")
            ep_type = getattr(ep, "endpoint_type", "endpoint")
            suspicious = bool(getattr(ep, "suspicious", False))
            if not ep_url:
                continue
            findings.append(UnifiedFinding(
                id=_gen_id(),
                file=ep_url,
                line_number=0,
                severity="high" if suspicious else "info",
                title=f"{'Suspicious' if suspicious else 'Discovered'} Endpoint: {ep_type}",
                description=f"Crawler discovered {ep_type} at {ep_url}",
                category="Recon",
                owasp="Recon",
                module="quantara_crawler",
                module_name="Quantara Web Crawler",
                scanner_source="quantara",
                tags=["crawler", ep_type],
                timestamp=datetime.now(timezone.utc).isoformat(),
            ))
        logger.info(f"[quantara_crawler] {len(findings)} endpoints discovered on {url}")
        return findings
    except Exception as e:
        logger.error(f"Quantara Crawler failed for {url}: {e}")
        return []


def _run_quantara_auth(url: str) -> list:
    """Test default credentials and common auth weaknesses on a target URL."""
    try:
        import asyncio
        try:
            config = AuthConfig(
                strategy="form",
                login_url=f"{url}/login",
                username="admin",
                password="admin",
            )
        except TypeError:
            config = AuthConfig()
            config.strategy = "form"
            config.login_url = f"{url}/login"

        engine = QuantaraAuthEngine([config])
        # Run async method in sync context safely
        try:
            loop = asyncio.get_event_loop()
            if loop.is_running():
                import concurrent.futures
                with concurrent.futures.ThreadPoolExecutor(max_workers=1) as pool:
                    future = pool.submit(asyncio.run, engine.authenticate_all())
                    results = future.result(timeout=30)
            else:
                results = loop.run_until_complete(engine.authenticate_all())
        except Exception:
            results = {}

        findings = []
        for role, result in (results or {}).items():
            if getattr(result, "success", False):
                findings.append(UnifiedFinding(
                    id=_gen_id(),
                    file=url,
                    line_number=0,
                    severity="high",
                    title=f"Default Credentials Accepted ({role})",
                    description=f"Login succeeded with default credentials for role '{role}' — immediate remediation required",
                    category="Authentication",
                    owasp="A07:2025",
                    cwe="CWE-521",
                    module="quantara_auth",
                    module_name="Quantara Auth Engine",
                    scanner_source="quantara",
                    tags=["auth", "default-credentials", role],
                    timestamp=datetime.now(timezone.utc).isoformat(),
                ))
        logger.info(f"[quantara_auth] {len(findings)} auth vulnerabilities found on {url}")
        return findings
    except Exception as e:
        logger.error(f"Quantara Auth Engine failed for {url}: {e}")
        return []


def _run_quantara_fp_reducer(url: str) -> list:
    """Probe common injection points and return only FP-reduced, confirmed findings."""
    try:
        reducer = FPReducer(timeout=10.0)
        test_cases = [
            (f"{url}?id=1",    "1' OR '1'='1",              "1",    "GET",  "sqli",  "A03:2025", "CWE-89"),
            (f"{url}?q=test",  "<script>alert(1)</script>",  "test", "GET",  "xss",   "A03:2025", "CWE-79"),
            (f"{url}?path=.",  "../../etc/passwd",            ".",    "GET",  "lfi",   "A01:2025", "CWE-22"),
        ]
        findings = []
        for test_url, payload, safe_val, method, inj_type, owasp, cwe in test_cases:
            try:
                result = reducer.verify(test_url, payload, safe_val, method, inj_type)
                if getattr(result, "is_confirmed", False):
                    findings.append(UnifiedFinding(
                        id=_gen_id(),
                        file=test_url,
                        line_number=0,
                        severity="high",
                        title=f"Confirmed {inj_type.upper()} (FP-Reduced)",
                        description=f"FP Reducer confirmed {inj_type} at {test_url} — differential analysis CONFIRMED, not a false positive",
                        category="Injection",
                        owasp=owasp,
                        cwe=cwe,
                        module="quantara_fp_reducer",
                        module_name="Quantara FP Reducer",
                        scanner_source="quantara",
                        tags=["fp-reduced", "confirmed", inj_type],
                        confidence=min(1.0, getattr(result, "confidence_delta", 0.0) + 0.8),
                        timestamp=datetime.now(timezone.utc).isoformat(),
                    ))
            except Exception:
                continue
        logger.info(f"[quantara_fp_reducer] {len(findings)} confirmed findings on {url}")
        return findings
    except Exception as e:
        logger.error(f"Quantara FP Reducer failed for {url}: {e}")
        return []


def _run_quantara_oast(url: str) -> list:
    """Run OAST tests for blind SSRF, XSS, CMDi, XXE via interactsh/local listener."""
    try:
        findings = []
        with QuantaraOAST(mode="auto", poll_timeout=20.0) as oast:
            if not oast.start():
                logger.warning("[quantara_oast] OAST server could not be started — skipping")
                return []
            test_cases = [("ssrf", "url"), ("xss", "callback"), ("cmdi", "cmd"), ("xxe", "entity")]
            for vuln_type, param in test_cases:
                try:
                    oast.create_test(url, vuln_type, param)
                except Exception:
                    continue
            time.sleep(20)  # Wait for out-of-band callbacks
            for res in oast.collect_results():
                findings.append(UnifiedFinding(
                    id=_gen_id(),
                    file=getattr(res, "scan_url", url),
                    line_number=0,
                    severity="critical",
                    title=f"Blind {getattr(res, 'vuln_type', 'UNKNOWN').upper()} Confirmed (OAST)",
                    description=(
                        f"Out-of-band callback received — blind {getattr(res, 'vuln_type', 'vulnerability')} "
                        f"confirmed via {getattr(res, 'protocol', 'HTTP')} at {url}"
                    ),
                    category="OAST",
                    owasp="A10:2025",
                    cwe="CWE-918",
                    confidence=1.0,
                    module="quantara_oast",
                    module_name="Quantara OAST Engine",
                    scanner_source="quantara",
                    tags=["oast", "blind", "confirmed", getattr(res, "vuln_type", "unknown")],
                    timestamp=datetime.now(timezone.utc).isoformat(),
                ))
        logger.info(f"[quantara_oast] {len(findings)} blind vulnerabilities confirmed on {url}")
        return findings
    except Exception as e:
        logger.error(f"Quantara OAST scan failed for {url}: {e}")
        return []


def _run_chain_correlation(raw_findings: list) -> list:
    """Correlate raw findings into multi-step attack chains."""
    if not raw_findings:
        return []
    try:
        correlator = AttackChainCorrelator()
        finding_dicts = [
            f.to_dict() if hasattr(f, "to_dict") else
            (f.__dict__ if hasattr(f, "__dict__") else {})
            for f in raw_findings
        ]
        chains = correlator.correlate(finding_dicts)
        chain_findings = []
        for chain in chains:
            chain_findings.append(UnifiedFinding(
                id=getattr(chain, "chain_id", _gen_id()),
                file="",
                line_number=0,
                severity=getattr(chain, "combined_severity", "high").lower(),
                title=f"Attack Chain: {getattr(chain, 'title', 'Multi-Stage Attack')}",
                description=getattr(chain, "attack_narrative", getattr(chain, "description", "")),
                category="Attack Chain",
                owasp=", ".join(getattr(chain, "owasp_coverage", [])),
                module="quantara_chains",
                module_name="Quantara Attack Chains",
                scanner_source="quantara",
                tags=["attack-chain"] + list(getattr(chain, "mitre_tactics", [])),
                timestamp=datetime.now(timezone.utc).isoformat(),
            ))
        logger.info(f"[quantara_chains] {len(chain_findings)} attack chains correlated from {len(raw_findings)} findings")
        return chain_findings
    except Exception as e:
        logger.error(f"Attack chain correlation failed: {e}")
        return []


def _run_enterprise_ai_analysis(raw_findings: list) -> list:
    """AI-enrich findings via QuantaraAICopilot (Gemini→Claude→GPT fallback)."""
    if not raw_findings:
        return []
    try:
        copilot = QuantaraAICopilot()
        finding_dicts = [
            f.to_dict() if hasattr(f, "to_dict") else
            (f.__dict__ if hasattr(f, "__dict__") else {})
            for f in raw_findings
        ]
        analyses = copilot.batch_analyze(finding_dicts, skip_low_severity=True)
        ai_findings = []
        for analysis in analyses:
            verdict = getattr(analysis, "verdict", None)
            if verdict and getattr(verdict, "verdict", "") == "FALSE_POSITIVE":
                continue  # Skip AI-confirmed FPs
            original = getattr(analysis, "finding", {})
            impact = getattr(analysis, "impact", None)
            remediation = getattr(analysis, "remediation", None)
            ai_findings.append(UnifiedFinding(
                id=_gen_id(),
                file=original.get("file", ""),
                line_number=original.get("line_number", 0),
                severity=original.get("severity", "high"),
                title=f"[AI] {original.get('title', 'AI-Enriched Finding')}",
                description=(
                    getattr(impact, "attack_scenario", "")
                    or original.get("description", "")
                ),
                category=original.get("category", ""),
                owasp=original.get("owasp", ""),
                cwe=original.get("cwe", ""),
                remediation=getattr(remediation, "fix_code", "") or original.get("remediation", ""),
                confidence=getattr(verdict, "confidence", 1.0) if verdict else 1.0,
                module="quantara_ai",
                module_name="Quantara AI Copilot",
                scanner_source="quantara",
                patch_suggestion=getattr(remediation, "fix_code", ""),
                tags=["ai-enriched"],
                timestamp=datetime.now(timezone.utc).isoformat(),
            ))
        logger.info(f"[quantara_ai] AI-enriched {len(ai_findings)} findings (from {len(raw_findings)} raw)")
        return ai_findings
    except Exception as e:
        logger.error(f"Quantara AI enrichment failed: {e}")
        return []


# ═══════════════════════════════════════════════════════════════════════════════
# URL Live Scanner — Real HTTP Security Analysis
# ═══════════════════════════════════════════════════════════════════════════════

def _gen_id() -> str:
    return str(uuid.uuid4())


_SECURITY_HEADERS_REQUIRED = {
    "Content-Security-Policy": {
        "cwe": "CWE-1021", "severity": "high",
        "remediation": "Add Content-Security-Policy header to prevent XSS and data injection attacks.",
        "description": "Missing Content Security Policy (CSP) header allows unrestricted script execution, enabling XSS attacks.",
    },
    "Strict-Transport-Security": {
        "cwe": "CWE-311", "severity": "high",
        "remediation": "Add Strict-Transport-Security: max-age=31536000; includeSubDomains; preload",
        "description": "Missing HSTS header allows protocol downgrade attacks, enabling man-in-the-middle interception.",
    },
    "X-Frame-Options": {
        "cwe": "CWE-1021", "severity": "medium",
        "remediation": "Add X-Frame-Options: DENY or SAMEORIGIN to prevent clickjacking.",
        "description": "Missing X-Frame-Options header allows the page to be embedded in iframes, enabling clickjacking.",
    },
    "X-Content-Type-Options": {
        "cwe": "CWE-116", "severity": "medium",
        "remediation": "Add X-Content-Type-Options: nosniff",
        "description": "Missing X-Content-Type-Options allows MIME-sniffing, enabling content-type confusion attacks.",
    },
    "Referrer-Policy": {
        "cwe": "CWE-200", "severity": "low",
        "remediation": "Add Referrer-Policy: strict-origin-when-cross-origin",
        "description": "Missing Referrer-Policy may leak sensitive URL parameters to third parties.",
    },
    "Permissions-Policy": {
        "cwe": "CWE-732", "severity": "low",
        "remediation": "Add Permissions-Policy header to restrict browser feature access.",
        "description": "Missing Permissions-Policy does not restrict browser features like camera or microphone.",
    },
}

_INFO_DISCLOSURE_HEADERS = {
    "Server": "Server software/version disclosed",
    "X-Powered-By": "Application framework/technology stack disclosed",
    "X-AspNet-Version": "ASP.NET version disclosed",
    "X-AspNetMvc-Version": "ASP.NET MVC version disclosed",
    "X-Generator": "CMS/framework generator disclosed",
    "X-Drupal-Cache": "Drupal CMS usage disclosed",
}

_SQL_ERROR_PATTERNS = [
    (r"SQL syntax.*?MySQL|You have an error in your SQL syntax", "MySQL SQL Error Exposed"),
    (r"ORA-\d{5}:.*?Oracle", "Oracle SQL Error Exposed"),
    (r"Microsoft OLE DB Provider for SQL Server|Unclosed quotation mark", "MSSQL SQL Error Exposed"),
    (r"pg_query\(\): Query failed|ERROR: syntax error at or near", "PostgreSQL SQL Error Exposed"),
    (r"SQLiteException|sqlite3\.OperationalError", "SQLite Error Exposed"),
    (r"Warning: mysql_|Deprecated.*mysql_|mysqlnd", "MySQL PHP Error Exposed"),
]

_SERVER_ERROR_PATTERNS = [
    (r"Fatal error|Parse error|Warning:|Notice:.*on line \d+", "PHP Error Disclosure"),
    (r"System\.Web\.HttpUnhandledException|System\.NullReferenceException", "ASP.NET Exception Disclosure"),
    (r"Traceback \(most recent call last\)|AttributeError:|NameError:", "Python Traceback Disclosure"),
    (r"java\.lang\.[A-Z][a-zA-Z]+Exception|at [a-z]+\.[a-zA-Z]+\(.*\.java:\d+\)", "Java Stack Trace Disclosure"),
    (r"RuntimeError|undefined method|undefined local variable", "Ruby/Rails Error Disclosure"),
]


def _check_security_headers(url: str, headers: dict) -> list:
    findings = []
    lower_headers = {k.lower(): v for k, v in headers.items()}
    for header_name, info in _SECURITY_HEADERS_REQUIRED.items():
        if header_name.lower() not in lower_headers:
            findings.append(UnifiedFinding(
                id=_gen_id(), file=url, line_number=0,
                severity=info["severity"],
                title=f"Missing Security Header: {header_name}",
                description=info["description"],
                category="Security Misconfiguration", cwe=info["cwe"], owasp="A05:2025",
                remediation=info["remediation"], confidence=1.0,
                module="misconfig", module_name="Security Misconfiguration Engine",
                scanner_source="owasp", tags=["header", "misconfiguration", "http"],
            ))
    for header_name, description in _INFO_DISCLOSURE_HEADERS.items():
        value = lower_headers.get(header_name.lower(), "")
        if value:
            findings.append(UnifiedFinding(
                id=_gen_id(), file=url, line_number=0, severity="low",
                title=f"Information Disclosure: {header_name}",
                description=f"{description}. Disclosed value: '{value}'",
                matched_content=f"{header_name}: {value}",
                category="Security Misconfiguration", cwe="CWE-200", owasp="A05:2025",
                remediation=f"Remove or obfuscate the '{header_name}' response header.",
                confidence=1.0, module="misconfig", module_name="Security Misconfiguration Engine",
                scanner_source="owasp", tags=["header", "information-disclosure"],
            ))
    return findings


def _check_http_enforcement(url: str) -> list:
    if url.lower().startswith("http://"):
        return [UnifiedFinding(
            id=_gen_id(), file=url, line_number=0, severity="high",
            title="Insecure HTTP Protocol (No TLS)",
            description="Target uses HTTP instead of HTTPS. All data including credentials transmitted in plaintext.",
            matched_content=url, category="Cryptographic Failures", cwe="CWE-319", owasp="A02:2025",
            remediation="Enforce HTTPS. Configure HSTS to prevent HTTP downgrade attacks.",
            confidence=1.0, module="misconfig", module_name="Security Misconfiguration Engine",
            scanner_source="owasp", tags=["https", "tls", "encryption"],
        )]
    return []


def _check_cookies(url: str, headers: dict) -> list:
    findings = []
    is_https = url.lower().startswith("https://")
    set_cookie_values = []
    for k, v in headers.items():
        if k.lower() == "set-cookie":
            set_cookie_values.append(v)
    for cookie_header in set_cookie_values:
        cookie_lower = cookie_header.lower()
        cookie_name = cookie_header.split("=")[0].strip() if "=" in cookie_header else "unknown"
        if "httponly" not in cookie_lower:
            findings.append(UnifiedFinding(
                id=_gen_id(), file=url, line_number=0, severity="medium",
                title=f"Cookie Missing HttpOnly Flag: {cookie_name}",
                description=f"Cookie '{cookie_name}' is missing HttpOnly, making it accessible via JavaScript and vulnerable to XSS-based theft.",
                matched_content=cookie_header[:150], category="Insecure Cookie Configuration",
                cwe="CWE-1004", owasp="A07:2025",
                remediation=f"Add HttpOnly flag: Set-Cookie: {cookie_name}=value; HttpOnly; Secure; SameSite=Strict",
                confidence=0.95, module="auth", module_name="Authentication Failures Scanner",
                scanner_source="owasp", tags=["cookie", "auth", "httponly"],
            ))
        if is_https and "secure" not in cookie_lower:
            findings.append(UnifiedFinding(
                id=_gen_id(), file=url, line_number=0, severity="medium",
                title=f"Cookie Missing Secure Flag: {cookie_name}",
                description=f"Cookie '{cookie_name}' missing Secure flag — may be sent over insecure HTTP connections.",
                matched_content=cookie_header[:150], category="Insecure Cookie Configuration",
                cwe="CWE-614", owasp="A07:2025",
                remediation=f"Add Secure flag to cookie '{cookie_name}'.",
                confidence=0.95, module="auth", module_name="Authentication Failures Scanner",
                scanner_source="owasp", tags=["cookie", "auth", "secure-flag"],
            ))
        if "samesite" not in cookie_lower:
            findings.append(UnifiedFinding(
                id=_gen_id(), file=url, line_number=0, severity="medium",
                title=f"Cookie Missing SameSite Attribute: {cookie_name}",
                description=f"Cookie '{cookie_name}' missing SameSite attribute, vulnerable to CSRF attacks.",
                matched_content=cookie_header[:150], category="CSRF / Cookie Security",
                cwe="CWE-352", owasp="A01:2025",
                remediation=f"Add SameSite=Strict or Lax to cookie '{cookie_name}'.",
                confidence=0.9, module="auth", module_name="Authentication Failures Scanner",
                scanner_source="owasp", tags=["cookie", "csrf", "samesite"],
            ))
    return findings


def _check_html_content(url: str, html: str) -> list:
    findings = []
    lines = html.split("\n")
    for i, line in enumerate(lines, 1):
        for pattern, title in _SQL_ERROR_PATTERNS:
            if re.search(pattern, line, re.IGNORECASE):
                findings.append(UnifiedFinding(
                    id=_gen_id(), file=url, line_number=i, severity="critical",
                    title=f"SQL Error Disclosure: {title}",
                    description="Application exposes raw SQL error messages, indicating SQL injection vulnerability and revealing database internals.",
                    matched_content=line.strip()[:200], category="SQL Injection",
                    cwe="CWE-89", owasp="A03:2025",
                    remediation="Use parameterized queries. Disable verbose SQL errors in production. Configure proper error handling.",
                    confidence=0.95, module="injection", module_name="Injection Scanner",
                    scanner_source="owasp", tags=["sql", "injection", "error-disclosure"],
                    injection_type="sql",
                ))
                break
        for pattern, title in _SERVER_ERROR_PATTERNS:
            if re.search(pattern, line, re.IGNORECASE):
                findings.append(UnifiedFinding(
                    id=_gen_id(), file=url, line_number=i, severity="medium",
                    title=f"Error Message Disclosure: {title}",
                    description="Application exposes verbose error messages revealing implementation details, file paths, or stack traces.",
                    matched_content=line.strip()[:200], category="Information Disclosure",
                    cwe="CWE-209", owasp="A05:2025",
                    remediation="Disable verbose error reporting in production. Implement custom error pages.",
                    confidence=0.88, module="misconfig", module_name="Security Misconfiguration Engine",
                    scanner_source="owasp", tags=["error-disclosure"],
                ))
                break
    # Forms without CSRF tokens
    form_pattern = re.compile(r"<form\b[^>]*>.*?</form>", re.IGNORECASE | re.DOTALL)
    csrf_pattern = re.compile(r"(csrf|_token|__RequestVerificationToken|authenticity_token)", re.IGNORECASE)
    for form_match in form_pattern.finditer(html):
        form_content = form_match.group(0)
        method_match = re.search(r'method\s*=\s*["\']?(post|put|delete|patch)["\']?', form_content, re.IGNORECASE)
        if method_match and not csrf_pattern.search(form_content):
            line_num = html[:form_match.start()].count("\n") + 1
            findings.append(UnifiedFinding(
                id=_gen_id(), file=url, line_number=line_num, severity="high",
                title="Form Missing CSRF Token",
                description="State-changing form (POST/PUT/DELETE) found without a CSRF token, vulnerable to Cross-Site Request Forgery.",
                matched_content=form_content[:200], category="CSRF",
                cwe="CWE-352", owasp="A04:2025",
                remediation="Add CSRF tokens to all state-changing forms. Use SameSite cookie attribute. Verify Origin/Referer headers.",
                confidence=0.85, module="insecure_design", module_name="Insecure Design Scanner",
                scanner_source="owasp", tags=["csrf", "form"],
            ))
    # Sensitive comments
    comment_pattern = re.compile(r"<!--.*?-->", re.DOTALL)
    sensitive_comment_re = re.compile(r"(password|passwd|secret|api.?key|token|credential|admin|/internal|/debug|/backup)", re.IGNORECASE)
    for comment_match in comment_pattern.finditer(html):
        comment = comment_match.group(0)
        if sensitive_comment_re.search(comment):
            line_num = html[:comment_match.start()].count("\n") + 1
            findings.append(UnifiedFinding(
                id=_gen_id(), file=url, line_number=line_num, severity="medium",
                title="Sensitive Information in HTML Comment",
                description="Potentially sensitive information found in an HTML comment visible in page source.",
                matched_content=comment[:200], category="Information Disclosure",
                cwe="CWE-200", owasp="A02:2025",
                remediation="Remove all sensitive information, credentials, and internal paths from HTML comments.",
                confidence=0.7, module="sensitive_data", module_name="Sensitive Data Exposure",
                scanner_source="owasp", tags=["comment", "information-disclosure"],
            ))
    return findings


def _check_js_content(url: str, html: str) -> list:
    findings = []
    script_pattern = re.compile(r"<script\b[^>]*>(.*?)</script>", re.IGNORECASE | re.DOTALL)
    js_patterns = [
        (r'(?i)(api[_-]?key|apikey)\s*[=:]\s*["\']([a-zA-Z0-9_\-]{20,})["\']', "Hardcoded API Key", "CWE-798", "high"),
        (r'(?i)(secret[_-]?key|secret)\s*[=:]\s*["\']([a-zA-Z0-9_\-]{16,})["\']', "Hardcoded Secret", "CWE-798", "high"),
        (r'(?i)(password|passwd)\s*[=:]\s*["\']([^"\']{4,})["\']', "Hardcoded Password", "CWE-259", "critical"),
        (r'(?i)(access[_-]?token|auth[_-]?token)\s*[=:]\s*["\']([a-zA-Z0-9_\-\.]{20,})["\']', "Hardcoded Token", "CWE-798", "high"),
        (r'(?i)(localStorage|sessionStorage)\.setItem\s*\(\s*["\']([^"\']*(?:token|password|secret|key|auth)[^"\']*)["\']', "Sensitive Data in Browser Storage", "CWE-922", "medium"),
        (r'\beval\s*\(', "Dangerous eval() Usage", "CWE-95", "medium"),
        (r'document\.write\s*\(', "Dangerous document.write()", "CWE-79", "medium"),
        (r'innerHTML\s*=\s*(?!null|""|\'\')', "Unsafe innerHTML Assignment (XSS)", "CWE-79", "medium"),
        (r'(?i)Bearer\s+[a-zA-Z0-9\-_.]{20,}', "JWT/Bearer Token Exposed", "CWE-522", "high"),
    ]
    for script_match in script_pattern.finditer(html):
        script_content = script_match.group(1)
        if not script_content.strip():
            continue
        script_start_line = html[:script_match.start()].count("\n") + 1
        script_lines = script_content.split("\n")
        for line_offset, line in enumerate(script_lines):
            for pattern, title, cwe, severity in js_patterns:
                if re.search(pattern, line, re.IGNORECASE):
                    findings.append(UnifiedFinding(
                        id=_gen_id(), file=url,
                        line_number=script_start_line + line_offset,
                        severity=severity, title=f"JS Security Issue: {title}",
                        description=f"Found potential security issue in inline JavaScript: {title}",
                        matched_content=line.strip()[:200],
                        category="Frontend Security", cwe=cwe, owasp="A02:2025",
                        remediation="Move sensitive values to server-side. Never hardcode credentials in client-side JS.",
                        confidence=0.8, module="frontend_js", module_name="Frontend JS Analyzer",
                        scanner_source="owasp", tags=["javascript", "frontend"],
                    ))
                    break
    return findings


def _check_endpoints_html(url: str, html: str) -> list:
    findings = []
    sensitive_patterns = [
        (r'(?:href|action|src)\s*=\s*["\']([^"\']*(?:admin|manager|console|panel|config|backup|debug|test|phpinfo|phpmyadmin|wp-admin)[^"\']*)["\']', "Sensitive Admin Path", "high"),
        (r'(?:href|action|src)\s*=\s*["\']([^"\']*(?:\.env|\.git|\.svn|config\.php|database\.yml|\.htaccess|web\.config)[^"\']*)["\']', "Config File Reference", "high"),
        (r'"url"\s*:\s*["\']([^"\']+/api/[^"\']+)["\']', "API Endpoint", "info"),
        (r'fetch\s*\(\s*["\']([^"\']+/api[^"\']+)["\']', "JS Fetch API Call", "info"),
    ]
    seen = set()
    for pattern, title, severity in sensitive_patterns:
        for match in re.finditer(pattern, html, re.IGNORECASE):
            path = match.group(1) if match.lastindex >= 1 else ""
            if path and path not in seen:
                seen.add(path)
                findings.append(UnifiedFinding(
                    id=_gen_id(), file=url, line_number=0,
                    severity=severity, title=f"{title}: {path[:80]}",
                    description=f"Found reference to potentially sensitive endpoint: {path}",
                    matched_content=match.group(0)[:200],
                    category="Endpoint Discovery", cwe="CWE-200", owasp="Recon",
                    remediation="Restrict access to sensitive endpoints. Remove debug/admin path references from client code.",
                    confidence=0.75, module="endpoint", module_name="Endpoint Extractor & Recon",
                    scanner_source="owasp", tags=["endpoint", "recon"],
                ))
    return findings


def _check_cors_and_api(url: str, html: str, headers: dict) -> list:
    findings = []
    cors_origin = headers.get("Access-Control-Allow-Origin", "")
    if cors_origin == "*":
        findings.append(UnifiedFinding(
            id=_gen_id(), file=url, line_number=0, severity="medium",
            title="Overly Permissive CORS Policy (wildcard)",
            description="Access-Control-Allow-Origin: * allows any origin to read responses, potentially exposing sensitive API data.",
            matched_content="Access-Control-Allow-Origin: *",
            category="API Security", cwe="CWE-942", owasp="API-Top-10",
            remediation="Restrict CORS to specific trusted origins. Never use * for authenticated endpoints.",
            confidence=0.95, module="api_security", module_name="API Security Scanner",
            scanner_source="owasp", tags=["cors", "api"],
        ))
    for api_path in set(re.findall(r'(?:"/api/v\d+/|/rest/v\d+/|/graphql)', html, re.IGNORECASE)):
        findings.append(UnifiedFinding(
            id=_gen_id(), file=url, line_number=0, severity="info",
            title=f"API Endpoint Detected: {api_path}",
            description=f"Found API endpoint pattern '{api_path}'. Verify proper auth and rate limiting.",
            matched_content=api_path, category="API Discovery", cwe="CWE-200", owasp="API-Top-10",
            remediation="Ensure all API endpoints have authentication, authorization, and rate limiting.",
            confidence=0.8, module="api_security", module_name="API Security Scanner",
            scanner_source="owasp", tags=["api", "endpoint"],
        ))
    return findings


def _check_access_control(url: str, html: str) -> list:
    findings = []
    for pattern in [
        r'(?:href|action)\s*=\s*["\'][^"\']*(?:/user/|/account/|/profile/|/order/)(\d+)',
        r'(?:href|action)\s*=\s*["\'][^"\']*(?:user_?id|account_?id|id)=(\d+)',
    ]:
        for match in re.finditer(pattern, html, re.IGNORECASE):
            findings.append(UnifiedFinding(
                id=_gen_id(), file=url, line_number=0, severity="medium",
                title="Potential IDOR — Sequential Numeric ID in URL",
                description="Numeric ID found in URL. Attackers can enumerate IDs to access other users' resources.",
                matched_content=match.group(0)[:200],
                category="Broken Access Control", cwe="CWE-639", owasp="A01:2025",
                remediation="Use non-sequential UUIDs. Implement server-side authorization checks for every object access.",
                confidence=0.7, module="access_control", module_name="Broken Access Control",
                scanner_source="owasp", tags=["idor", "access-control"],
            ))
            break
    return findings


def _check_sensitive_data(url: str, content: str) -> list:
    findings = []
    lines = content.split("\n")
    patterns = [
        (r'\b\d{4}[\s\-]?\d{4}[\s\-]?\d{4}[\s\-]?\d{4}\b', "Possible Credit Card Number", "critical"),
        (r'\b\d{3}-\d{2}-\d{4}\b', "Possible SSN", "critical"),
        (r'(?i)Bearer\s+[a-zA-Z0-9\-_.]{20,}', "Bearer Token Exposed", "high"),
        (r'(?i)AKIA[0-9A-Z]{16}', "AWS Access Key Exposed", "critical"),
        (r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}', "Email Address in Response", "low"),
    ]
    seen = set()
    for i, line in enumerate(lines, 1):
        for pattern, title, severity in patterns:
            match = re.search(pattern, line)
            if match:
                val = match.group(0)
                if val not in seen:
                    seen.add(val)
                    findings.append(UnifiedFinding(
                        id=_gen_id(), file=url, line_number=i, severity=severity,
                        title=f"Sensitive Data Exposure: {title}",
                        description=f"Possible sensitive data found in HTTP response: {title}",
                        matched_content=line.strip()[:200],
                        category="Sensitive Data Exposure", cwe="CWE-200", owasp="A02:2025",
                        remediation="Ensure sensitive data is not exposed in HTTP responses. Mask or encrypt sensitive values.",
                        confidence=0.7, module="sensitive_data", module_name="Sensitive Data Exposure",
                        scanner_source="owasp", tags=["sensitive-data"],
                    ))
                break
    return findings


def _scan_url_live(url: str, module_key: str) -> list:
    """Perform live URL security analysis using real HTTP requests."""
    try:
        import requests as _req
        warnings.filterwarnings("ignore", message="Unverified HTTPS request")
        response = _req.get(
            url, timeout=25, verify=False, allow_redirects=True,
            headers={
                "User-Agent": "Mozilla/5.0 (compatible; QuantumScanner/5.0; Security-Research)",
                "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            }
        )
        final_url = response.url
        headers = dict(response.headers)
        html = response.text
    except Exception as e:
        logger.error(f"URL live scan failed for {url}: {e}")
        return []

    # Feed the fetched page into NEO intelligence graph
    if _NEO_INTELLIGENCE_AVAILABLE:
        try:
            graph = get_intelligence_graph()
            graph.ingest_endpoint(url_pattern=final_url, method="GET", technology="")
            graph.infer_data_flows_from_code(html, final_url)
        except Exception:
            pass

    if module_key == "misconfig":
        findings = _check_security_headers(final_url, headers)
        findings += _check_http_enforcement(url)
        findings += [f for f in _check_html_content(final_url, html) if "error" in f.title.lower() or "disclosure" in f.title.lower()]
        return findings
    elif module_key == "auth":
        return _check_cookies(final_url, headers)
    elif module_key == "injection":
        findings = [f for f in _check_html_content(final_url, html) if f.module == "injection"]
        # Enrich with NEO spec-abuse pattern detection in the response
        if _NEO_INTELLIGENCE_AVAILABLE:
            try:
                kb = get_spec_abuse_kb()
                # Check if response contains signs of injection vulnerability
                for pattern in kb.get_patterns_for_owasp("A05:2025"):
                    for sig in pattern.detection_signatures:
                        if re.search(sig, html, re.IGNORECASE):
                            findings.append(UnifiedFinding(
                                id=_gen_id(),
                                file=final_url,
                                severity=pattern.severity,
                                title=f"NEO Spec Abuse: {pattern.name}",
                                description=pattern.description[:200],
                                category=pattern.owasp_mapping,
                                confidence=pattern.confidence * 0.7,
                                module="injection",
                                module_name="Injection Scanner + NEO Spec Abuse KB",
                                owasp=pattern.owasp_mapping,
                                tags=["neo-intelligence", "spec-abuse"] + pattern.tags,
                            ))
                            kb.record_success(pattern.id)
                            break
            except Exception:
                pass
        return findings
    elif module_key == "frontend_js":
        return _check_js_content(final_url, html)
    elif module_key == "endpoint":
        return _check_endpoints_html(final_url, html)
    elif module_key == "insecure_design":
        return [f for f in _check_html_content(final_url, html) if f.module == "insecure_design"]
    elif module_key == "access_control":
        return _check_access_control(final_url, html)
    elif module_key == "api_security":
        return _check_cors_and_api(final_url, html, headers)
    elif module_key == "sensitive_data":
        combined = "\n".join(f"Header: {k}: {v}" for k, v in headers.items()) + "\n" + html
        return _check_sensitive_data(final_url, combined)
    elif module_key == "logging":
        # Logging module: check for verbose errors and audit logging gaps
        return [f for f in _check_html_content(final_url, html) if "disclosure" in f.title.lower()]
    elif module_key == "ssrf":
        return scan_ssrf_file(html, "remote_page.html")
    elif module_key == "supply_chain":
        return scan_supply_chain_file(html, "remote_page.html")
    elif module_key == "cloud":
        return scan_cloud_file(url, "remote_page.html")
    elif module_key == "integrity":
        return scan_integrity_file(html, "remote_page.html")
    elif module_key == "exception":
        return scan_exception_scanner(html, "remote_page.html")
    else:
        # Fallback: run file scanner on fetched content
        meta = UNIFIED_MODULE_REGISTRY.get(module_key)
        if meta and meta.get("scan_file"):
            try:
                return meta["scan_file"](html, "remote_page.html") or []
            except Exception as e:
                logger.warning(f"Fallback URL scan failed for module {module_key}: {e}")
        return []


def _run_quantara_http_scan(url: str) -> list:
    """
    Run the Quantara HTTP scanner against a live URL.
    Returns list of QuantaraWebFinding objects (duck-type compatible with normalize_finding).

    When NEO Intelligence is available, populates the intelligence graph
    from the Quantara fingerprint results for downstream attack surface analysis.
    """
    if not _QUANTARA_AVAILABLE:
        return []
    try:
        logger.info(f"[quantara_http] Starting Quantara HTTP scan: {url}")
        findings = scan_url_with_quantara(url, module_key="quantara_http")
        logger.info(f"[quantara_http] Quantara scan complete: {len(findings)} findings on {url}")

        # Feed Quantara findings into the NEO Intelligence Graph
        if _NEO_INTELLIGENCE_AVAILABLE and findings:
            try:
                graph = get_intelligence_graph()
                for f in findings:
                    endpoint = getattr(f, "url", "") or getattr(f, "endpoint", "") or url
                    graph.ingest_endpoint(
                        url_pattern=endpoint,
                        method=getattr(f, "method", "GET"),
                        technology=getattr(f, "technology", ""),
                    )
                # Record successful payloads for learning
                memory = get_learning_memory()
                for f in findings:
                    payload = getattr(f, "matched_content", "") or getattr(f, "payload", "")
                    if payload and getattr(f, "severity", "info") in ("critical", "high", "medium"):
                        category = getattr(f, "category", "").lower()
                        cat_key = "xss" if "xss" in category else \
                                  "sqli" if "sql" in category else \
                                  "ssrf" if "ssrf" in category else \
                                  "ssti" if "template" in category else "generic"
                        memory.remember_successful_payload(
                            payload=payload, category=cat_key,
                            context="url_param", technology=getattr(f, "technology", ""),
                        )
            except Exception as _neo_enrich_err:
                logger.debug(f"NEO enrichment from Quantara results: {_neo_enrich_err}")

        return findings
    except Exception as e:
        logger.error(f"[quantara_http] Quantara scan failed for {url}: {e}")
        return []


# Keep _fetch_url_content for legacy compatibility
def _fetch_url_content(url: str) -> Optional[str]:
    """Fetch URL content (legacy — use _scan_url_live instead)."""
    try:
        import requests
        response = requests.get(url, timeout=15, verify=False, headers={
            "User-Agent": "Helix-Scanner/5.0"
        })
        header_block = "\n".join(
            f"# HTTP-Header: {k}: {v}" for k, v in response.headers.items()
        )
        return f"{header_block}\n{response.text}"
    except Exception as e:
        logger.error(f"Failed to fetch URL {url}: {e}")
        return None


# ═══════════════════════════════════════════════════════════════════════════════
# Scan Profiles
# ═══════════════════════════════════════════════════════════════════════════════

SCAN_PROFILES = {
    "quick": {
        "name": "Quick Scan",
        "description": "Top 5 critical modules for fast assessment",
        "modules": ["quantara_http", "injection", "misconfig", "auth", "access_control", "frontend_js"],
    },
    "standard": {
        "name": "Standard Scan",
        "description": "Core OWASP Top 10 coverage",
        "modules": ["quantara_http", "injection", "misconfig", "auth", "access_control",
                    "frontend_js", "cloud", "api_security", "supply_chain", "insecure_design", "integrity"],
    },
    "full": {
        "name": "Full Scan",
        "description": "Complete OWASP + Quantara HTTP + extended analysis with all modules",
        "modules": list(UNIFIED_MODULE_REGISTRY.keys()),
    },
    "owasp-top-10": {
        "name": "OWASP Top 10:2021",
        "description": "Quantara HTTP + strict OWASP Top 10:2021 coverage",
        "modules": ["quantara_http", "access_control", "frontend_js", "injection", "insecure_design",
                    "misconfig", "supply_chain", "auth", "integrity", "logging", "ssrf"],
    },
    "cloud": {
        "name": "Cloud Security",
        "description": "Cloud-focused scan (AWS, GCP, Azure, IaC)",
        "modules": ["quantara_http", "cloud", "misconfig", "ssrf", "api_security"],
    },
    "api": {
        "name": "API Security",
        "description": "API-focused scan with Quantara HTTP templates",
        "modules": ["quantara_http", "api_security", "injection", "auth", "access_control", "ssrf"],
    },
    "code-deep": {
        "name": "Deep Code Analysis",
        "description": "Multi-agent semantic analysis with taint tracking",
        "modules": ["code_agent", "injection", "auth", "access_control"],
    },
    "quantara": {
        "name": "Quantara HTTP Scan",
        "description": "Pure Quantara-template-driven live HTTP vulnerability scan",
        "modules": ["quantara_http"],
    },
}


def get_modules_for_profile(profile: str) -> list[str]:
    return SCAN_PROFILES.get(profile, SCAN_PROFILES["full"])["modules"]


def get_available_modules() -> list[dict]:
    return [
        {
            "key": k, "name": m["name"], "owasp": m["owasp"], "phase": m["phase"],
            "pattern_count": m["pattern_count"], "description": m["description"],
            "available": (
                (not m.get("requires_scanner1") or _SCANNER1_AVAILABLE) and
                (not m.get("requires_code_scanner") or _CODE_SCANNER_AVAILABLE) and
                (not m.get("requires_quantara") or _QUANTARA_AVAILABLE)
            ),
        }
        for k, m in UNIFIED_MODULE_REGISTRY.items()
    ]


def get_available_profiles() -> list[dict]:
    return [
        {"key": k, "name": p["name"], "description": p["description"], "module_count": len(p["modules"])}
        for k, p in SCAN_PROFILES.items()
    ]


# ═══════════════════════════════════════════════════════════════════════════════
# Enterprise Pipeline Integration — added by enterprise refactor
# Wires in: BaseScanner registry, Scheduler, Analyzer, BehaviorAnalyzer,
# AdaptiveEngine, PayloadContextDetector, PayloadMutator, Payload packs
# ═══════════════════════════════════════════════════════════════════════════════

def _load_enterprise_engines() -> dict:
    """
    Lazy-load all enterprise engines.
    Returns a dict of available engine references.
    Safe to call even if optional deps are missing.
    """
    engines = {}
    _base_dir = os.path.dirname(__file__)

    try:
        from scanner_engine.base_scanner import ScannerRegistry, BaseScanner
        engines["registry"] = ScannerRegistry
        engines["base_scanner"] = BaseScanner
    except ImportError:
        pass

    try:
        from scanner_engine.scheduler import EnterpriseScheduler, get_scheduler
        engines["scheduler"] = get_scheduler
    except ImportError:
        pass

    try:
        from scanner_engine.analyzer import (
            DifferentialAnalyzer, ProbeSession, BlindInjectionAnalyzer,
        )
        engines["analyzer"] = DifferentialAnalyzer
        engines["probe_session"] = ProbeSession
        engines["blind_analyzer"] = BlindInjectionAnalyzer
    except ImportError:
        pass

    try:
        from scanner_engine.behavior_analyzer import BehaviorAnalyzer, create_behavior_analyzer
        engines["behavior_analyzer"] = create_behavior_analyzer
    except ImportError:
        pass

    try:
        from scanner_engine.adaptive_engine import AdaptiveEscalationEngine, AttackChainCorrelator
        engines["adaptive_engine"] = AdaptiveEscalationEngine
        engines["chain_correlator"] = AttackChainCorrelator
    except ImportError:
        pass

    try:
        from scanner_engine.payload_context_detector import (
            PayloadContextDetector, detect_context, detect_all_contexts
        )
        engines["context_detector"] = PayloadContextDetector
        engines["detect_context"] = detect_context
    except ImportError:
        pass

    try:
        from scanner_engine.payload_mutator import (
            PayloadMutator, generate_variants, generate_xss_variants,
            generate_sqli_variants, generate_ssti_variants,
        )
        engines["mutator"] = PayloadMutator
        engines["generate_variants"] = generate_variants
    except ImportError:
        pass

    try:
        from scanner_engine.payloads import get_pack, list_packs
        engines["payload_pack"] = get_pack
        engines["payload_packs"] = list_packs
    except ImportError:
        pass

    return engines


# Singleton — loaded once at module level
_ENTERPRISE_ENGINES: dict = {}

try:
    _ENTERPRISE_ENGINES = _load_enterprise_engines()
    _engines_loaded = list(_ENTERPRISE_ENGINES.keys())
    logger.info(f"Enterprise engines loaded: {_engines_loaded}")
except Exception as _ee:
    logger.warning(f"Enterprise engine load warning: {_ee}")


def get_enterprise_engine(name: str):
    """Retrieve a loaded enterprise engine by name. Returns None if unavailable."""
    return _ENTERPRISE_ENGINES.get(name)


def enterprise_scan_summary(findings: list) -> dict:
    """
    Post-scan enterprise summary with attack chain correlation.
    Appends attack chain data to the standard scan summary.
    """
    correlator_cls = _ENTERPRISE_ENGINES.get("chain_correlator")
    chains = []
    if correlator_cls:
        try:
            finding_dicts = [f if isinstance(f, dict) else (asdict(f) if hasattr(f, '__dataclass_fields__') else vars(f)) for f in findings]
            chains = correlator_cls().correlate(finding_dicts)
        except Exception as e:
            logger.warning(f"Attack chain correlation failed: {e}")

    severity_counts = {}
    for f in findings:
        sev = (f.get("severity") if isinstance(f, dict) else getattr(f, "severity", "info") or "info").lower()
        severity_counts[sev] = severity_counts.get(sev, 0) + 1

    return {
        "total_findings": len(findings),
        "severity_breakdown": severity_counts,
        "attack_chains": chains,
        "attack_chain_count": len(chains),
        "engines_available": list(_ENTERPRISE_ENGINES.keys()),
    }


def get_payload_pack(pack_name: str) -> list:
    """Get a payload pack by name using the enterprise payload library."""
    fn = _ENTERPRISE_ENGINES.get("payload_pack")
    if fn:
        return fn(pack_name)
    return []


def mutate_payload(payload: str, mutation_types: list | None = None) -> list:
    """
    Generate 50-200 mutated variants of a payload using the enterprise mutation engine.
    Falls back to [payload] if the mutator is unavailable.
    """
    fn = _ENTERPRISE_ENGINES.get("generate_variants")
    if fn:
        try:
            return fn(payload, mutation_types=mutation_types)
        except Exception:
            pass
    return [payload]


def detect_injection_context(response_body: str, reflected_value: str | None = None) -> dict:
    """
    Detect the injection context in a response body.
    Returns context information for context-aware payload selection.
    """
    fn = _ENTERPRISE_ENGINES.get("detect_context")
    if fn:
        try:
            result = fn(response_body, reflected_value)
            return result.to_dict() if hasattr(result, "to_dict") else {"context": str(result)}
        except Exception:
            pass
    return {"context": "unknown", "confidence": 0.0}


# ═══════════════════════════════════════════════════════════════════════════════
# NEO Intelligence Integration
# ═══════════════════════════════════════════════════════════════════════════════

async def run_neo_intelligence(
    target: str,
    scan_type: str = "directory",
    findings: list | None = None,
    technology: str = "",
    framework: str = "",
    waf_detected: str = "",
) -> dict:
    """
    Execute the NEO Intelligence scan loop alongside standard modules.

    Args:
        target: URL, directory, or repo URL.
        scan_type: "url", "directory", "github", "code".
        findings: Existing findings from standard modules to enrich.
        technology: Detected technology stack.
        framework: Detected framework.
        waf_detected: Detected WAF type (if any).

    Returns:
        NeoScanResult as dict with attack chains, surfaces, hypotheses, etc.
    """
    if not _NEO_INTELLIGENCE_AVAILABLE:
        logger.warning("NEO Intelligence not available — skipping")
        return {"error": "NEO Intelligence not available"}

    try:
        loop = get_neo_scan_loop()

        # Map scan types to NeoScanTarget
        mode = ScanMode.ACTIVE_SAFE if scan_type in ("url",) else ScanMode.PASSIVE
        neo_target = NeoScanTarget(
            url=target if scan_type in ("url", "github") else "",
            repository_path=target if scan_type in ("directory", "code") else "",
            github_url=target if scan_type == "github" else "",
            scan_mode=mode,
            technology=technology,
            framework=framework,
            waf_detected=waf_detected,
        )

        # Convert UnifiedFinding dicts to simple dicts for NEO
        external_findings = []
        for f in (findings or []):
            if isinstance(f, dict):
                external_findings.append(f)
            elif hasattr(f, "to_dict"):
                external_findings.append(f.to_dict())
            else:
                external_findings.append({
                    "title": getattr(f, "title", ""),
                    "severity": getattr(f, "severity", "info"),
                    "category": getattr(f, "category", ""),
                    "confidence": getattr(f, "confidence", 0.5),
                    "endpoint": getattr(f, "file", ""),
                    "parameter": getattr(f, "matched_content", ""),
                })

        result = await loop.execute(neo_target, external_findings=external_findings)
        return result.to_dict()

    except Exception as e:
        logger.error(f"NEO Intelligence execution error: {e}", exc_info=True)
        return {"error": str(e)}


def get_neo_intelligence_summary() -> dict:
    """Get current NEO intelligence system state and statistics."""
    if not _NEO_INTELLIGENCE_AVAILABLE:
        return {"available": False}

    try:
        loop = get_neo_scan_loop()
        return {
            "available": True,
            "graph_stats": loop.graph.get_stats(),
            "knowledge_base_stats": loop.kb.get_stats(),
            "payload_generator_stats": loop.payload_gen.get_stats(),
            "attack_brain_stats": loop.attack_brain.get_stats(),
            "learning_memory_stats": loop.memory.get_stats(),
        }
    except Exception as e:
        return {"available": True, "error": str(e)}


def get_neo_smart_payloads(
    category: str,
    context: str = "",
    technology: str = "",
    waf_evasion_level: int = 0,
    max_payloads: int = 20,
) -> list[str]:
    """
    Get smart payloads from the NEO Payload Generator + Spec Abuse KB.
    Used by enhanced OWASP modules for intelligent payload selection.

    Maps attack categories to the correct OWASP spec-abuse patterns:
        ssrf         → A01:2025 (Broken Access Control)
        sqli/xss/ssti/cmdi → A05:2025 (Injection)
        jwt/auth     → A07:2025 (Auth Failures)
        deserialize  → A08:2025 (Integrity Failures)
        race_condition→ A10:2025 (Exception Handling)
    """
    if not _NEO_INTELLIGENCE_AVAILABLE:
        return []

    try:
        gen = get_payload_generator()
        kb = get_spec_abuse_kb()
        memory = get_learning_memory()

        payloads: list[str] = []

        # 1. Recall previously successful payloads from memory
        recalled = memory.recall_payloads(category, technology=technology, limit=5)
        payloads.extend(recalled)

        # 2. Spec abuse payloads — map category to correct OWASP code
        _CATEGORY_TO_OWASP = {
            "ssrf": "A01:2025", "idor": "A01:2025", "bac": "A01:2025",
            "sqli": "A05:2025", "xss": "A05:2025", "ssti": "A05:2025",
            "cmdi": "A05:2025", "xxe": "A05:2025", "crlf": "A05:2025",
            "jwt": "A07:2025", "auth": "A07:2025",
            "deserialize": "A08:2025", "integrity": "A08:2025",
            "race_condition": "A10:2025",
        }
        owasp_code = _CATEGORY_TO_OWASP.get(category, "A05:2025")

        if category == "ssrf":
            spec_payloads = kb.get_ssrf_bypass_payloads()
            payloads.extend(spec_payloads[:10])
        else:
            patterns = kb.get_patterns_for_owasp(owasp_code)
            for p in patterns[:5]:
                payloads.extend(p.payload_templates[:5])

        # 3. Framework-specific payloads if technology is known
        if technology:
            fw_payloads = kb.get_framework_specific_payloads(technology)
            payloads.extend(fw_payloads[:5])

        # 4. Mutated payloads from the self-learning generator
        generated = gen.generate_payloads(
            category=category,
            context=context,
            technology=technology,
            waf_evasion_level=waf_evasion_level,
            max_payloads=max(5, max_payloads - len(payloads)),
        )
        payloads.extend([pc.payload for pc in generated])

        # Deduplicate and limit
        seen: set[str] = set()
        unique: list[str] = []
        for p in payloads:
            if p not in seen:
                seen.add(p)
                unique.append(p)
        return unique[:max_payloads]

    except Exception as e:
        logger.debug(f"NEO smart payload error: {e}")
        return []


def neo_record_successful_exploit(
    payload: str,
    category: str,
    context: str = "",
    technology: str = "",
    waf_bypassed: bool = False,
):
    """Record a successful exploit in NEO learning memory."""
    if not _NEO_INTELLIGENCE_AVAILABLE:
        return
    try:
        memory = get_learning_memory()
        memory.remember_successful_payload(
            payload=payload,
            category=category,
            context=context,
            technology=technology,
            waf_bypassed=waf_bypassed,
        )
    except Exception:
        pass


def neo_ingest_endpoints(
    endpoints: list[dict],
    technology: str = "",
    framework: str = "",
) -> dict:
    """
    Feed discovered endpoints into the NEO Intelligence Graph.
    Called after the endpoint extractor module completes.

    Each endpoint dict should have: url, method, auth_required, parameters (optional).
    Returns graph stats after ingestion.
    """
    if not _NEO_INTELLIGENCE_AVAILABLE:
        return {"ingested": 0}

    try:
        graph = get_intelligence_graph()
        ingested = 0
        for ep in endpoints:
            url = ep.get("url", ep.get("endpoint", ep.get("file", "")))
            if not url:
                continue
            method = ep.get("method", "GET")
            auth_req = ep.get("auth_required", False)
            roles = ep.get("roles", [])
            params = ep.get("parameters", None)

            graph.ingest_endpoint(
                url_pattern=url,
                method=method,
                auth_required=auth_req,
                roles=roles,
                parameters=params,
                technology=technology,
            )
            ingested += 1

        return {"ingested": ingested, "graph_stats": graph.get_stats()}
    except Exception as e:
        logger.debug(f"NEO endpoint ingestion error: {e}")
        return {"ingested": 0, "error": str(e)}


def neo_ingest_findings_for_chaining(findings: list[dict]) -> dict:
    """
    Feed normalized findings into the NEO Attack Simulation Brain
    to discover multi-step attack chains.

    Returns discovered chains and hypotheses.
    """
    if not _NEO_INTELLIGENCE_AVAILABLE:
        return {"chains": [], "hypotheses": []}

    try:
        brain = get_attack_brain()
        brain.ingest_findings(findings)
        chains = brain.discover_chains()
        paths = brain.discover_attack_paths()
        hypotheses = brain.generate_hypotheses()

        return {
            "chains": [c.to_dict() for c in chains[:20]],
            "paths": [p.to_dict() for p in paths[:10]],
            "hypotheses": hypotheses,
            "stats": brain.get_stats(),
        }
    except Exception as e:
        logger.debug(f"NEO attack chaining error: {e}")
        return {"chains": [], "hypotheses": [], "error": str(e)}


def neo_compute_attack_surfaces() -> dict:
    """
    Compute attack surfaces from the current Intelligence Graph state.
    Returns OWASP-mapped attack surface analysis.
    """
    if not _NEO_INTELLIGENCE_AVAILABLE:
        return {}

    try:
        graph = get_intelligence_graph()
        surfaces = graph.compute_attack_surfaces()
        return {k: v.to_dict() for k, v in surfaces.items()}
    except Exception as e:
        logger.debug(f"NEO attack surface error: {e}")
        return {"error": str(e)}


def neo_get_learning_memory_stats() -> dict:
    """Get the continuous learning memory statistics."""
    if not _NEO_INTELLIGENCE_AVAILABLE:
        return {"available": False}

    try:
        memory = get_learning_memory()
        return {
            "available": True,
            **memory.get_stats(),
            "trending_vulnerabilities": memory.get_trending_vulnerabilities(days=30),
        }
    except Exception as e:
        return {"available": True, "error": str(e)}
