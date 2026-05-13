"""
Quantara Correlation Engine
==============================
Multi-agent finding correlation and attack chain construction.

Correlates findings from multiple agents into unified intelligence records:
    1. Group related findings by endpoint, CWE, and attack vector
    2. Build multi-step attack chains (recon → vuln → exploit → impact)
    3. Calculate amplified risk from chained vulnerabilities
    4. Identify lateral movement paths
    5. Detect defense gaps via coverage analysis
"""

from __future__ import annotations

import hashlib
import logging
import uuid
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Set, Tuple
from urllib.parse import urlparse

logger = logging.getLogger(__name__)


# ═══════════════════════════════════════════════════════════════════════════════
# Attack Chain — multi-step exploitation path
# ═══════════════════════════════════════════════════════════════════════════════

@dataclass
class AttackChainStep:
    """Single step in an attack chain."""
    step_index:  int
    finding_id:  str
    agent:       str
    title:       str
    severity:    str
    endpoint:    str
    category:    str
    description: str = ""


@dataclass
class AttackChain:
    """Multi-step attack chain correlating findings from multiple agents."""
    chain_id:     str = field(default_factory=lambda: f"chain-{uuid.uuid4().hex[:8]}")
    name:         str = ""
    steps:        List[AttackChainStep] = field(default_factory=list)
    impact:       str = ""           # ultimate impact assessment
    risk_score:   float = 0.0        # amplified risk (higher than individual findings)
    confidence:   float = 0.0
    timestamp:    str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

    def to_dict(self) -> Dict[str, Any]:
        return {
            "chain_id":   self.chain_id,
            "name":       self.name,
            "steps":      [
                {
                    "step": s.step_index,
                    "finding_id": s.finding_id,
                    "agent":      s.agent,
                    "title":      s.title,
                    "severity":   s.severity,
                    "endpoint":   s.endpoint,
                    "category":   s.category,
                }
                for s in self.steps
            ],
            "impact":      self.impact,
            "risk_score":  round(self.risk_score, 2),
            "confidence":  round(self.confidence, 2),
            "step_count":  len(self.steps),
        }

    @property
    def max_severity(self) -> str:
        severity_order = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}
        if not self.steps:
            return "info"
        return max(self.steps, key=lambda s: severity_order.get(s.severity, 0)).severity


# ═══════════════════════════════════════════════════════════════════════════════
# Correlation Group — related findings cluster
# ═══════════════════════════════════════════════════════════════════════════════

@dataclass
class CorrelationGroup:
    """A group of related findings from multiple agents."""
    group_id:    str = field(default_factory=lambda: f"grp-{uuid.uuid4().hex[:8]}")
    finding_ids: List[str] = field(default_factory=list)
    agents:      Set[str] = field(default_factory=set)
    endpoint:    str = ""
    categories:  Set[str] = field(default_factory=set)
    max_severity: str = "info"
    correlation_type: str = ""  # endpoint, cwe, vector, chain


# ═══════════════════════════════════════════════════════════════════════════════
# Correlation Engine
# ═══════════════════════════════════════════════════════════════════════════════

# Attack chain templates: sequences of categories that form valid chains
CHAIN_TEMPLATES = [
    {
        "name": "Recon → Injection → Data Exfiltration",
        "sequence": ["Information Disclosure", "SQL Injection", "Sensitive Data Exposure"],
        "impact": "Full database compromise via SQL injection at a disclosed endpoint",
    },
    {
        "name": "Recon → Auth Bypass → Privilege Escalation",
        "sequence": ["Information Disclosure", "Authentication", "Access Control"],
        "impact": "Complete authentication bypass leading to admin-level access",
    },
    {
        "name": "API Exposure → BOLA → Data Breach",
        "sequence": ["API Security", "Broken Object Level Authorization", "Sensitive Data Exposure"],
        "impact": "Mass data exfiltration via unprotected API endpoints",
    },
    {
        "name": "WAF Bypass → Injection → Remote Code Execution",
        "sequence": ["WAF Bypass", "SQL Injection", "Path Traversal / LFI"],
        "impact": "WAF bypass enables injection leading to server-side code execution",
    },
    {
        "name": "Cloud Misconfig → SSRF → Credential Theft",
        "sequence": ["Cloud Infrastructure", "SSRF", "Sensitive Data Exposure"],
        "impact": "SSRF via cloud misconfiguration exposes IAM credentials",
    },
    {
        "name": "Auth Weakness → Session Hijack → Account Takeover",
        "sequence": ["Authentication", "Session Management", "Brute Force Protection"],
        "impact": "Weak authentication enables session-based account takeover",
    },
    {
        "name": "Info Leak → XSS → Session Theft",
        "sequence": ["Information Disclosure", "Cross-Site Scripting", "Session Management"],
        "impact": "Reflected XSS enables cookie/session token theft",
    },
    {
        "name": "Business Logic → Price Manipulation → Financial Loss",
        "sequence": ["Business Logic", "Error Handling"],
        "impact": "Business logic flaws enable financial manipulation",
    },
]

# Category normalization map
CATEGORY_ALIASES: Dict[str, str] = {
    "SQL Injection":          "SQL Injection",
    "Cross-Site Scripting":   "Cross-Site Scripting",
    "Authentication Bypass":  "Authentication",
    "Brute Force Protection": "Authentication",
    "Session Management":     "Authentication",
    "CORS":                   "Security Headers",
    "HTTP Security":          "Security Headers",
    "Defense in Depth":       "WAF Bypass",
    "Blind Injection":        "SQL Injection",
    "Blind SQL Injection":    "SQL Injection",
    "GraphQL Security":       "API Security",
}


class CorrelationEngine:
    """
    Multi-agent finding correlation engine.

    Performs:
        1. Endpoint-based grouping (findings at the same URL)
        2. CWE-based grouping (same weakness type)
        3. Attack chain construction from chain templates
        4. Risk amplification for chained vulnerabilities
        5. Coverage gap detection
    """

    def __init__(self):
        self._groups: List[CorrelationGroup] = []
        self._chains: List[AttackChain] = []
        self._coverage: Dict[str, bool] = {}

    def correlate(self, findings: List[Dict[str, Any]]) -> Dict[str, Any]:
        """
        Run full correlation pipeline on a set of findings.

        Returns:
            {
                "groups": [...],
                "chains": [...],
                "risk_amplification": float,
                "coverage_gaps": [...],
                "summary": {...},
            }
        """
        self._groups.clear()
        self._chains.clear()

        if not findings:
            return self._empty_result()

        # Step 1: Endpoint-based grouping
        ep_groups = self._group_by_endpoint(findings)

        # Step 2: Category-based grouping
        cat_groups = self._group_by_category(findings)

        # Step 3: CWE-based grouping
        cwe_groups = self._group_by_cwe(findings)

        self._groups = ep_groups + cat_groups + cwe_groups

        # Step 4: Build attack chains from templates
        self._chains = self._build_attack_chains(findings)

        # Step 5: Risk amplification
        amplification = self._compute_amplification(findings)

        # Step 6: Coverage analysis
        gaps = self._analyze_coverage(findings)

        return {
            "groups":             [self._group_to_dict(g) for g in self._groups],
            "chains":             [c.to_dict() for c in self._chains],
            "risk_amplification": round(amplification, 2),
            "coverage_gaps":      gaps,
            "summary": {
                "total_findings":     len(findings),
                "correlation_groups": len(self._groups),
                "attack_chains":      len(self._chains),
                "multi_agent_chains": sum(1 for c in self._chains if len(set(s.agent for s in c.steps)) > 1),
                "max_chain_length":   max((len(c.steps) for c in self._chains), default=0),
                "amplified_risk":     round(amplification, 2),
            },
        }

    # ── Grouping ──────────────────────────────────────────────────────────

    def _group_by_endpoint(self, findings: List[Dict]) -> List[CorrelationGroup]:
        """Group findings targeting the same endpoint."""
        ep_map: Dict[str, List[Dict]] = defaultdict(list)
        for f in findings:
            ep = self._normalize_endpoint(f.get("endpoint", ""))
            if ep:
                ep_map[ep].append(f)

        groups = []
        for ep, flist in ep_map.items():
            if len(flist) < 2:
                continue
            sev_order = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}
            max_sev = max(flist, key=lambda x: sev_order.get(x.get("severity", "info"), 0))
            groups.append(CorrelationGroup(
                finding_ids=[f.get("id", "") for f in flist],
                agents=set(f.get("node_name", "") for f in flist),
                endpoint=ep,
                categories=set(f.get("category", "") for f in flist),
                max_severity=max_sev.get("severity", "info"),
                correlation_type="endpoint",
            ))
        return groups

    def _group_by_category(self, findings: List[Dict]) -> List[CorrelationGroup]:
        """Group findings of the same attack category."""
        cat_map: Dict[str, List[Dict]] = defaultdict(list)
        for f in findings:
            cat = self._normalize_category(f.get("category", ""))
            if cat:
                cat_map[cat].append(f)

        groups = []
        for cat, flist in cat_map.items():
            if len(flist) < 2:
                continue
            agents = set(f.get("node_name", "") for f in flist)
            if len(agents) < 2:
                continue  # only interesting if multiple agents found same type
            groups.append(CorrelationGroup(
                finding_ids=[f.get("id", "") for f in flist],
                agents=agents,
                categories={cat},
                max_severity=self._max_severity(flist),
                correlation_type="category",
            ))
        return groups

    def _group_by_cwe(self, findings: List[Dict]) -> List[CorrelationGroup]:
        """Group findings sharing the same CWE."""
        cwe_map: Dict[str, List[Dict]] = defaultdict(list)
        for f in findings:
            cwe = f.get("cwe", "")
            if cwe:
                cwe_map[cwe].append(f)

        groups = []
        for cwe, flist in cwe_map.items():
            if len(flist) < 2:
                continue
            agents = set(f.get("node_name", "") for f in flist)
            if len(agents) < 2:
                continue
            groups.append(CorrelationGroup(
                finding_ids=[f.get("id", "") for f in flist],
                agents=agents,
                categories=set(f.get("category", "") for f in flist),
                max_severity=self._max_severity(flist),
                correlation_type="cwe",
            ))
        return groups

    # ── Attack Chain Construction ─────────────────────────────────────────

    def _build_attack_chains(self, findings: List[Dict]) -> List[AttackChain]:
        """Build attack chains by matching findings against chain templates."""
        chains: List[AttackChain] = []

        # Index findings by normalized category
        cat_index: Dict[str, List[Dict]] = defaultdict(list)
        for f in findings:
            cat = self._normalize_category(f.get("category", ""))
            if cat:
                cat_index[cat].append(f)

        for template in CHAIN_TEMPLATES:
            sequence = template["sequence"]
            # Check if we have at least one finding for each step in the chain
            step_candidates: List[List[Dict]] = []
            all_present = True
            for step_cat in sequence:
                normalized = self._normalize_category(step_cat)
                candidates = cat_index.get(normalized, [])
                if not candidates:
                    all_present = False
                    break
                step_candidates.append(candidates)

            if not all_present or not step_candidates:
                continue

            # Build chain using the highest-severity finding at each step
            sev_order = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}
            steps: List[AttackChainStep] = []
            for i, candidates in enumerate(step_candidates):
                best = max(candidates, key=lambda x: sev_order.get(x.get("severity", "info"), 0))
                steps.append(AttackChainStep(
                    step_index=i,
                    finding_id=best.get("id", ""),
                    agent=best.get("node_name", best.get("module_name", "")),
                    title=best.get("title", ""),
                    severity=best.get("severity", "info"),
                    endpoint=best.get("endpoint", ""),
                    category=best.get("category", ""),
                ))

            # Compute chain risk: amplified beyond individual findings
            individual_scores = [
                sev_order.get(s.severity, 0) * 25 for s in steps
            ]
            # Chain amplification: risk = sum * (1 + 0.15 * chain_length)
            chain_risk = sum(individual_scores) * (1 + 0.15 * len(steps))
            chain_risk = min(100, chain_risk)

            chain = AttackChain(
                name=template["name"],
                steps=steps,
                impact=template["impact"],
                risk_score=chain_risk,
                confidence=0.7 + 0.05 * len(steps),
            )
            chains.append(chain)

        # Sort chains by risk score
        chains.sort(key=lambda c: c.risk_score, reverse=True)
        return chains[:20]  # top 20 chains

    # ── Risk Amplification ────────────────────────────────────────────────

    def _compute_amplification(self, findings: List[Dict]) -> float:
        """
        Compute risk amplification factor from correlated findings.

        Findings from multiple agents targeting the same endpoint amplify risk.
        A single endpoint with SQLi + missing auth + data exposure is far worse
        than three unrelated low-severity issues.
        """
        if not findings:
            return 1.0

        # Base risk from individual findings
        sev_weights = {"critical": 25, "high": 10, "medium": 3, "low": 1, "info": 0}
        base_risk = sum(
            sev_weights.get(f.get("severity", "info"), 0) for f in findings
        )

        # Amplification from multi-agent correlation
        multi_agent_groups = [g for g in self._groups if len(g.agents) >= 2]
        chain_bonus = len(self._chains) * 5

        amplified = base_risk + len(multi_agent_groups) * 3 + chain_bonus
        return min(100, amplified)

    # ── Coverage Analysis ─────────────────────────────────────────────────

    def _analyze_coverage(self, findings: List[Dict]) -> List[str]:
        """Identify OWASP Top 10 categories not covered by findings."""
        owasp_categories = {
            "A01:2021 - Broken Access Control",
            "A02:2021 - Cryptographic Failures",
            "A03:2021 - Injection",
            "A04:2021 - Insecure Design",
            "A05:2021 - Security Misconfiguration",
            "A06:2021 - Vulnerable Components",
            "A07:2021 - Identification and Authentication Failures",
            "A08:2021 - Software and Data Integrity Failures",
            "A09:2021 - Security Logging and Monitoring Failures",
            "A10:2021 - Server-Side Request Forgery",
        }

        covered = set()
        for f in findings:
            owasp = f.get("owasp", "")
            if owasp:
                covered.add(owasp)

        gaps = sorted(owasp_categories - covered)
        return gaps

    # ── Helpers ────────────────────────────────────────────────────────────

    @staticmethod
    def _normalize_endpoint(ep: str) -> str:
        """Normalize endpoint URL for comparison."""
        if not ep:
            return ""
        parsed = urlparse(ep)
        path = parsed.path.rstrip("/") or "/"
        # Remove query string for grouping
        return f"{parsed.scheme}://{parsed.netloc}{path}"

    @staticmethod
    def _normalize_category(cat: str) -> str:
        """Normalize finding category using alias map."""
        return CATEGORY_ALIASES.get(cat, cat)

    @staticmethod
    def _max_severity(findings: List[Dict]) -> str:
        sev_order = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}
        if not findings:
            return "info"
        best = max(findings, key=lambda f: sev_order.get(f.get("severity", "info"), 0))
        return best.get("severity", "info")

    @staticmethod
    def _group_to_dict(g: CorrelationGroup) -> Dict:
        return {
            "group_id":         g.group_id,
            "finding_ids":      g.finding_ids,
            "agents":           list(g.agents),
            "endpoint":         g.endpoint,
            "categories":       list(g.categories),
            "max_severity":     g.max_severity,
            "correlation_type": g.correlation_type,
            "finding_count":    len(g.finding_ids),
        }

    @staticmethod
    def _empty_result() -> Dict:
        return {
            "groups": [], "chains": [], "risk_amplification": 0,
            "coverage_gaps": [], "summary": {},
        }

    def get_chains(self) -> List[AttackChain]:
        return list(self._chains)

    def get_groups(self) -> List[CorrelationGroup]:
        return list(self._groups)

    def reset(self) -> None:
        self._groups.clear()
        self._chains.clear()
        self._coverage.clear()
