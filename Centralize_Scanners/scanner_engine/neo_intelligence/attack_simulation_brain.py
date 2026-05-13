"""
Layer 4 — Attack Simulation Brain
===================================
Autonomous vulnerability chaining and attack path discovery.

The Attack Simulation Brain chains individual vulnerabilities into
multi-step attack paths, emulating how a human penetration tester
would escalate from an initial foothold to full compromise.

Example attack chain:
    SSRF → internal API access → credential leak → privilege escalation → RCE → cloud takeover

Capabilities:
    - Automatic vulnerability chain discovery
    - Attack path scoring and prioritization
    - Multi-step exploitation planning
    - Impact assessment for chained attacks
    - Graph-based reachability analysis
"""

from __future__ import annotations

import logging
import time
import uuid
from collections import defaultdict
from dataclasses import dataclass, field, asdict
from typing import Any, Dict, List, Optional, Set, Tuple

logger = logging.getLogger("neo.attack_brain")


# ─────────────────────────────────────────────
# Data models
# ─────────────────────────────────────────────

@dataclass
class ChainableVulnerability:
    """A vulnerability that can be part of an attack chain."""
    id: str
    title: str
    category: str                      # OWASP category (A01, A05, etc.)
    vulnerability_type: str            # sqli, ssrf, idor, xss, etc.
    endpoint: str = ""
    parameter: str = ""
    severity: str = "medium"
    confidence: float = 0.0
    verified: bool = False
    # Chain properties
    provides_capabilities: List[str] = field(default_factory=list)  # what this vuln enables
    requires_capabilities: List[str] = field(default_factory=list)  # what's needed to exploit
    escalation_potential: float = 0.0  # 0-1 how likely to escalate
    # Evidence
    payload_used: str = ""
    evidence_summary: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class AttackChain:
    """A sequence of vulnerabilities that chain together for greater impact."""
    id: str = field(default_factory=lambda: str(uuid.uuid4())[:12])
    name: str = ""
    steps: List[ChainableVulnerability] = field(default_factory=list)
    total_impact: str = ""
    chain_confidence: float = 0.0
    chain_severity: str = ""
    attack_narrative: str = ""
    entry_point: str = ""
    final_impact: str = ""
    owasp_categories: List[str] = field(default_factory=list)
    capabilities_gained: List[str] = field(default_factory=list)
    estimated_time_minutes: int = 0
    requires_authentication: bool = False

    @property
    def chain_length(self) -> int:
        return len(self.steps)

    @property
    def chain_risk_score(self) -> float:
        """Compute compound risk score — chains are more dangerous than individual vulns."""
        if not self.steps:
            return 0.0
        base_scores = {"critical": 1.0, "high": 0.8, "medium": 0.5, "low": 0.25, "info": 0.1}
        individual_scores = [base_scores.get(s.severity, 0.3) for s in self.steps]
        # Compound effect: each additional step multiplies the risk
        compound = individual_scores[0]
        for score in individual_scores[1:]:
            compound = min(1.0, compound + score * 0.5)
        return compound * self.chain_confidence

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "name": self.name,
            "steps": [s.to_dict() for s in self.steps],
            "chain_length": self.chain_length,
            "chain_risk_score": round(self.chain_risk_score, 3),
            "chain_confidence": self.chain_confidence,
            "chain_severity": self.chain_severity,
            "attack_narrative": self.attack_narrative,
            "entry_point": self.entry_point,
            "final_impact": self.final_impact,
            "owasp_categories": self.owasp_categories,
            "capabilities_gained": self.capabilities_gained,
            "estimated_time_minutes": self.estimated_time_minutes,
            "requires_authentication": self.requires_authentication,
        }


@dataclass
class AttackPath:
    """A high-level attack path from entry to objective."""
    id: str = field(default_factory=lambda: str(uuid.uuid4())[:8])
    name: str = ""
    objective: str = ""              # e.g., "cloud takeover", "data exfiltration"
    chains: List[AttackChain] = field(default_factory=list)
    total_risk: float = 0.0
    feasibility: float = 0.0        # 0-1 likelihood of successful exploitation
    impact: str = ""
    recommended_priority: int = 0    # 1=highest priority
    reasoning: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "name": self.name,
            "objective": self.objective,
            "chains": [c.to_dict() for c in self.chains],
            "total_risk": round(self.total_risk, 3),
            "feasibility": round(self.feasibility, 3),
            "impact": self.impact,
            "recommended_priority": self.recommended_priority,
            "reasoning": self.reasoning,
        }


# ─────────────────────────────────────────────
# Chain Rules — defines how vulnerabilities connect
# ─────────────────────────────────────────────

# (prerequisite_vuln_type, provides_capability)
CAPABILITY_MAP: Dict[str, List[str]] = {
    "ssrf": ["internal_network_access", "cloud_metadata_access", "service_enumeration"],
    "sqli": ["database_access", "credential_extraction", "data_exfiltration", "rce_via_udf"],
    "xss": ["session_hijack", "credential_theft", "phishing", "dom_manipulation"],
    "ssti": ["code_execution", "file_read", "environment_access"],
    "cmdi": ["code_execution", "file_read", "file_write", "reverse_shell"],
    "rce": ["code_execution", "file_read", "file_write", "reverse_shell", "full_compromise"],
    "idor": ["data_access", "privilege_escalation", "account_takeover"],
    "path_traversal": ["file_read", "source_code_access", "config_access"],
    "auth_bypass": ["authentication_bypass", "privilege_escalation"],
    "jwt_manipulation": ["authentication_bypass", "privilege_escalation", "impersonation"],
    "open_redirect": ["phishing", "ssrf_amplification", "token_theft"],
    "xxe": ["file_read", "internal_network_access", "ssrf_amplification"],
    "deserialize": ["code_execution", "rce_via_deserialize"],
    "credential_leak": ["credential_access", "lateral_movement", "privilege_escalation"],
    "config_exposure": ["credential_access", "architecture_knowledge", "api_key_access"],
    "header_injection": ["cache_poisoning", "session_fixation", "xss_via_header"],
    "race_condition": ["business_logic_bypass", "double_spend", "privilege_escalation"],
    "upload": ["webshell_deployment", "code_execution", "malware_delivery"],
    "cors_misconfig": ["cross_origin_data_access", "credential_theft"],
    "csrf": ["state_modification", "account_takeover"],
}

# (capability, can_escalate_to)
ESCALATION_MAP: Dict[str, List[str]] = {
    "internal_network_access": ["credential_extraction", "service_enumeration", "cloud_metadata_access"],
    "cloud_metadata_access": ["credential_access", "cloud_takeover", "lateral_movement"],
    "credential_access": ["privilege_escalation", "lateral_movement", "data_exfiltration"],
    "credential_extraction": ["privilege_escalation", "lateral_movement", "account_takeover"],
    "code_execution": ["full_compromise", "reverse_shell", "data_exfiltration", "persistence"],
    "file_read": ["credential_access", "source_code_access", "config_access"],
    "file_write": ["webshell_deployment", "persistence", "config_modification"],
    "source_code_access": ["architecture_knowledge", "credential_access", "zero_day_discovery"],
    "config_access": ["credential_access", "architecture_knowledge"],
    "session_hijack": ["account_takeover", "privilege_escalation"],
    "authentication_bypass": ["privilege_escalation", "data_access", "full_compromise"],
    "privilege_escalation": ["full_compromise", "data_exfiltration", "lateral_movement"],
    "database_access": ["data_exfiltration", "credential_extraction"],
    "api_key_access": ["lateral_movement", "cloud_takeover"],
    "webshell_deployment": ["code_execution", "persistence", "full_compromise"],
}

# Impact assessment for final capabilities
IMPACT_SCORES: Dict[str, Tuple[str, float]] = {
    "full_compromise": ("Full system compromise — complete control of the application and infrastructure", 1.0),
    "cloud_takeover": ("Cloud account takeover — access to all cloud resources", 0.95),
    "data_exfiltration": ("Mass data exfiltration — unauthorized extraction of sensitive data", 0.9),
    "account_takeover": ("User account takeover — attacker controls victim accounts", 0.85),
    "reverse_shell": ("Remote code execution with reverse shell — persistent backdoor", 0.9),
    "persistence": ("Attacker persistence — continued access after remediation", 0.85),
    "lateral_movement": ("Lateral movement — attacker can pivot to other systems", 0.8),
    "credential_extraction": ("Credential theft — extracted database credentials or API keys", 0.8),
    "privilege_escalation": ("Privilege escalation — attacker gained elevated permissions", 0.75),
    "data_access": ("Unauthorized data access — read access to protected resources", 0.6),
    "business_logic_bypass": ("Business logic bypass — circumvented application controls", 0.5),
    "phishing": ("Phishing vector — can trick users into revealing credentials", 0.4),
}


# ─────────────────────────────────────────────
# Attack Simulation Brain
# ─────────────────────────────────────────────

class AttackSimulationBrain:
    """
    Autonomous attack chain discovery and simulation.

    Given a set of individual vulnerability findings, the brain:
    1. Classifies each vulnerability by what capabilities it provides
    2. Builds a capability graph
    3. Discovers multi-step attack chains through graph traversal
    4. Scores and prioritizes chains by compound risk
    5. Generates human-readable attack narratives
    """

    def __init__(self):
        self._vulnerabilities: Dict[str, ChainableVulnerability] = {}
        self._discovered_chains: List[AttackChain] = []
        self._discovered_paths: List[AttackPath] = []
        self._capability_graph: Dict[str, Set[str]] = defaultdict(set)
        self._vuln_by_capability: Dict[str, List[str]] = defaultdict(list)

    # ── Ingestion ─────────────────────────────────────────────────

    def ingest_finding(self, finding: Dict[str, Any]) -> ChainableVulnerability:
        """Convert a scan finding into a chainable vulnerability."""
        vuln_type = self._classify_vulnerability_type(finding)
        provides = CAPABILITY_MAP.get(vuln_type, [])

        vuln = ChainableVulnerability(
            id=finding.get("id", str(uuid.uuid4())[:12]),
            title=finding.get("title", "Unknown"),
            category=finding.get("category", ""),
            vulnerability_type=vuln_type,
            endpoint=finding.get("endpoint", finding.get("url", finding.get("file", ""))),
            parameter=finding.get("parameter", finding.get("param", "")),
            severity=finding.get("severity", "medium"),
            confidence=float(finding.get("confidence", 0.5)),
            verified=finding.get("verified", False),
            provides_capabilities=provides,
            payload_used=finding.get("payload", ""),
            evidence_summary=finding.get("description", ""),
        )

        # Estimate escalation potential
        vuln.escalation_potential = self._estimate_escalation(vuln)

        self._vulnerabilities[vuln.id] = vuln

        # Update capability graph
        for cap in provides:
            self._capability_graph[vuln.id].add(cap)
            self._vuln_by_capability[cap].append(vuln.id)

        return vuln

    def ingest_findings(self, findings: List[Dict[str, Any]]) -> List[ChainableVulnerability]:
        """Ingest multiple findings."""
        return [self.ingest_finding(f) for f in findings]

    def _classify_vulnerability_type(self, finding: Dict[str, Any]) -> str:
        """Classify a finding into a vulnerability type for chain analysis."""
        title = (finding.get("title", "") + " " + finding.get("category", "")).lower()
        description = finding.get("description", "").lower()
        combined = title + " " + description

        type_keywords = {
            "ssrf": ["ssrf", "server-side request", "url fetching", "internal url"],
            "sqli": ["sql injection", "sqli", "sql_inject", "database query", "union select"],
            "xss": ["cross-site scripting", "xss", "reflected xss", "stored xss", "dom xss"],
            "ssti": ["template injection", "ssti", "server-side template"],
            "cmdi": ["command injection", "os command", "shell injection", "rce"],
            "rce": ["remote code execution", "rce", "code execution"],
            "idor": ["insecure direct object", "idor", "direct object reference"],
            "path_traversal": ["path traversal", "directory traversal", "file inclusion", "lfi", "rfi"],
            "auth_bypass": ["authentication bypass", "auth bypass", "broken auth"],
            "jwt_manipulation": ["jwt", "json web token", "token manipulation"],
            "open_redirect": ["open redirect", "url redirect", "redirect"],
            "xxe": ["xml external entity", "xxe", "xml injection"],
            "deserialize": ["deserialization", "deserialize", "pickle", "marshal"],
            "credential_leak": ["credential", "password", "secret", "api key", "token exposure"],
            "config_exposure": ["configuration", "config exposure", "misconfiguration", "debug"],
            "header_injection": ["header injection", "crlf", "response splitting"],
            "race_condition": ["race condition", "toctou", "concurrency"],
            "upload": ["file upload", "unrestricted upload", "webshell"],
            "cors_misconfig": ["cors", "cross-origin"],
            "csrf": ["csrf", "cross-site request forgery"],
        }

        for vuln_type, keywords in type_keywords.items():
            for kw in keywords:
                if kw in combined:
                    return vuln_type

        return "unknown"

    def _estimate_escalation(self, vuln: ChainableVulnerability) -> float:
        """Estimate the probability that this vulnerability can be escalated."""
        base = {"critical": 0.9, "high": 0.7, "medium": 0.4, "low": 0.2, "info": 0.05}
        score = base.get(vuln.severity, 0.3)

        # Bonus for verified vulns
        if vuln.verified:
            score = min(1.0, score + 0.15)

        # Bonus for high-capability vulns
        high_value_caps = {"code_execution", "credential_access", "internal_network_access", "database_access"}
        if any(cap in high_value_caps for cap in vuln.provides_capabilities):
            score = min(1.0, score + 0.2)

        return score

    # ── Chain Discovery ───────────────────────────────────────────

    def discover_chains(self, max_depth: int = 5, min_confidence: float = 0.3) -> List[AttackChain]:
        """
        Discover all attack chains by traversing the capability graph.

        Uses BFS from each vulnerability, following capability → escalation edges.
        """
        chains = []

        for vuln_id, vuln in self._vulnerabilities.items():
            if vuln.confidence < min_confidence:
                continue

            # Start BFS from this vulnerability
            discovered = self._bfs_chains(vuln, max_depth)
            chains.extend(discovered)

        # Deduplicate chains by step set
        unique_chains = self._deduplicate_chains(chains)

        # Score and sort
        for chain in unique_chains:
            self._score_chain(chain)
            self._generate_narrative(chain)

        unique_chains.sort(key=lambda c: c.chain_risk_score, reverse=True)

        self._discovered_chains = unique_chains
        return unique_chains

    def _bfs_chains(self, start_vuln: ChainableVulnerability, max_depth: int) -> List[AttackChain]:
        """BFS to discover chains starting from a vulnerability."""
        chains = []

        # Queue: (current_chain_steps, current_capabilities, visited_vuln_ids)
        queue: List[Tuple[List[ChainableVulnerability], Set[str], Set[str]]] = [
            ([start_vuln], set(start_vuln.provides_capabilities), {start_vuln.id})
        ]

        while queue:
            steps, capabilities, visited = queue.pop(0)

            if len(steps) >= max_depth:
                if len(steps) >= 2:
                    chains.append(self._build_chain(steps, capabilities))
                continue

            # Find next possible steps
            expanded = False
            for cap in list(capabilities):
                # What can we escalate to with this capability?
                escalations = ESCALATION_MAP.get(cap, [])
                for next_cap in escalations:
                    # Are there vulns that provide this capability?
                    for vuln_id in self._vuln_by_capability.get(next_cap, []):
                        if vuln_id not in visited:
                            next_vuln = self._vulnerabilities[vuln_id]
                            new_steps = steps + [next_vuln]
                            new_caps = capabilities | set(next_vuln.provides_capabilities)
                            new_visited = visited | {vuln_id}
                            queue.append((new_steps, new_caps, new_visited))
                            expanded = True

            # If we couldn't expand and have 2+ steps, record the chain
            if not expanded and len(steps) >= 2:
                chains.append(self._build_chain(steps, capabilities))

        return chains

    def _build_chain(self, steps: List[ChainableVulnerability], capabilities: Set[str]) -> AttackChain:
        """Build an AttackChain from a list of steps."""
        # Determine final impact
        best_impact = ""
        best_score = 0.0
        for cap in capabilities:
            if cap in IMPACT_SCORES:
                desc, score = IMPACT_SCORES[cap]
                if score > best_score:
                    best_score = score
                    best_impact = desc

        # Determine overall severity
        sevs = [s.severity for s in steps]
        if "critical" in sevs:
            chain_severity = "critical"
        elif "high" in sevs:
            chain_severity = "high"
        elif "medium" in sevs:
            chain_severity = "medium"
        else:
            chain_severity = "low"

        return AttackChain(
            name=f"{steps[0].vulnerability_type} → {'→ '.join(s.vulnerability_type for s in steps[1:])}",
            steps=steps,
            chain_confidence=min(s.confidence for s in steps),
            chain_severity=chain_severity,
            entry_point=steps[0].endpoint,
            final_impact=best_impact or "Unknown impact",
            owasp_categories=list(set(s.category for s in steps)),
            capabilities_gained=list(capabilities),
            requires_authentication=any(s.endpoint and "auth" in s.endpoint.lower() for s in steps),
        )

    def _score_chain(self, chain: AttackChain):
        """Score a chain based on compound risk analysis."""
        # Already computed by chain_risk_score property
        # Set estimated time
        time_per_step = {"ssrf": 2, "sqli": 5, "xss": 3, "ssti": 5, "cmdi": 3, "rce": 1}
        chain.estimated_time_minutes = sum(
            time_per_step.get(s.vulnerability_type, 5) for s in chain.steps
        )

    def _generate_narrative(self, chain: AttackChain):
        """Generate a human-readable attack narrative for the chain."""
        if not chain.steps:
            chain.attack_narrative = "No steps in chain."
            return

        parts = []
        parts.append(f"**Attack Chain: {chain.name}**\n")
        parts.append(f"Entry Point: {chain.steps[0].endpoint or 'Unknown'}\n")

        for i, step in enumerate(chain.steps, 1):
            parts.append(f"  Step {i}: [{step.severity.upper()}] {step.title}")
            if step.endpoint:
                parts.append(f"    Target: {step.endpoint}")
            if step.parameter:
                parts.append(f"    Parameter: {step.parameter}")
            if step.provides_capabilities:
                parts.append(f"    Provides: {', '.join(step.provides_capabilities)}")

        parts.append(f"\nFinal Impact: {chain.final_impact}")
        parts.append(f"Risk Score: {chain.chain_risk_score:.2f}")
        parts.append(f"Confidence: {chain.chain_confidence:.1%}")
        parts.append(f"Estimated Time: {chain.estimated_time_minutes} minutes")

        chain.attack_narrative = "\n".join(parts)

    def _deduplicate_chains(self, chains: List[AttackChain]) -> List[AttackChain]:
        """Remove duplicate chains (same set of vulnerability IDs)."""
        seen = set()
        unique = []
        for chain in chains:
            key = frozenset(s.id for s in chain.steps)
            if key not in seen:
                seen.add(key)
                unique.append(chain)
        return unique

    # ── Attack Path Discovery ─────────────────────────────────────

    def discover_attack_paths(self) -> List[AttackPath]:
        """
        Group related chains into attack paths targeting specific objectives.
        """
        if not self._discovered_chains:
            self.discover_chains()

        objective_chains: Dict[str, List[AttackChain]] = defaultdict(list)

        for chain in self._discovered_chains:
            # Determine objective from final capabilities
            for cap in chain.capabilities_gained:
                if cap in IMPACT_SCORES:
                    objective_chains[cap].append(chain)

        paths = []
        for objective, chains in objective_chains.items():
            impact_desc, impact_score = IMPACT_SCORES[objective]

            chains_sorted = sorted(chains, key=lambda c: c.chain_risk_score, reverse=True)

            path = AttackPath(
                name=f"Path to {objective.replace('_', ' ').title()}",
                objective=objective,
                chains=chains_sorted[:5],  # top 5 chains per objective
                total_risk=max(c.chain_risk_score for c in chains_sorted) if chains_sorted else 0,
                feasibility=sum(c.chain_confidence for c in chains_sorted[:3]) / min(3, len(chains_sorted)),
                impact=impact_desc,
                reasoning=f"Found {len(chains_sorted)} attack chain(s) leading to {objective}. "
                         f"Highest risk chain: {chains_sorted[0].name if chains_sorted else 'none'}.",
            )
            paths.append(path)

        # Set priority
        paths.sort(key=lambda p: p.total_risk, reverse=True)
        for i, path in enumerate(paths):
            path.recommended_priority = i + 1

        self._discovered_paths = paths
        return paths

    # ── Hypothesis Generation ─────────────────────────────────────

    def generate_hypotheses(self) -> List[Dict[str, Any]]:
        """
        Generate security hypotheses based on discovered patterns.
        These represent untested attack theories that warrant investigation.
        """
        hypotheses = []

        # Hypothesis 1: SSRF → Cloud Metadata
        ssrf_vulns = [v for v in self._vulnerabilities.values() if v.vulnerability_type == "ssrf"]
        if ssrf_vulns:
            hypotheses.append({
                "id": "hyp_ssrf_cloud",
                "hypothesis": "SSRF vulnerabilities may provide access to cloud metadata services",
                "test_strategy": "Attempt to fetch http://169.254.169.254/latest/meta-data/ via SSRF endpoints",
                "potential_impact": "Cloud credential theft → full cloud account takeover",
                "priority": "critical",
                "evidence": f"Found {len(ssrf_vulns)} SSRF candidate(s)",
                "vuln_ids": [v.id for v in ssrf_vulns],
            })

        # Hypothesis 2: SQLi → Credential Extraction
        sqli_vulns = [v for v in self._vulnerabilities.values() if v.vulnerability_type == "sqli"]
        if sqli_vulns:
            hypotheses.append({
                "id": "hyp_sqli_creds",
                "hypothesis": "SQL injection may allow credential extraction from user tables",
                "test_strategy": "Use UNION SELECT to enumerate table names, then extract user/password columns",
                "potential_impact": "Credential theft → account takeover → privilege escalation",
                "priority": "high",
                "evidence": f"Found {len(sqli_vulns)} SQL injection candidate(s)",
                "vuln_ids": [v.id for v in sqli_vulns],
            })

        # Hypothesis 3: XSS + CSRF → Account Takeover
        xss_vulns = [v for v in self._vulnerabilities.values() if v.vulnerability_type == "xss"]
        csrf_vulns = [v for v in self._vulnerabilities.values() if v.vulnerability_type == "csrf"]
        if xss_vulns and csrf_vulns:
            hypotheses.append({
                "id": "hyp_xss_csrf_ato",
                "hypothesis": "Combining XSS with missing CSRF protection enables account takeover",
                "test_strategy": "Craft XSS payload that triggers state-changing actions on CSRF-unprotected endpoints",
                "potential_impact": "Full account takeover of any user who visits the crafted page",
                "priority": "critical",
                "evidence": f"Found {len(xss_vulns)} XSS + {len(csrf_vulns)} CSRF vulns",
            })

        # Hypothesis 4: IDOR → Data Exfiltration
        idor_vulns = [v for v in self._vulnerabilities.values() if v.vulnerability_type == "idor"]
        if idor_vulns:
            hypotheses.append({
                "id": "hyp_idor_data",
                "hypothesis": "IDOR vulnerabilities may allow enumeration of all user data",
                "test_strategy": "Iterate through sequential IDs or use predictable identifiers to access other users' data",
                "potential_impact": "Mass data exfiltration of all user records",
                "priority": "high",
                "evidence": f"Found {len(idor_vulns)} IDOR candidate(s)",
            })

        # Hypothesis 5: File Upload → Webshell → RCE
        upload_vulns = [v for v in self._vulnerabilities.values() if v.vulnerability_type == "upload"]
        if upload_vulns:
            hypotheses.append({
                "id": "hyp_upload_rce",
                "hypothesis": "File upload may allow webshell deployment leading to RCE",
                "test_strategy": "Upload a PHP/Python/JSP webshell disguised with double extension or content-type spoofing",
                "potential_impact": "Remote code execution → full server compromise",
                "priority": "critical",
                "evidence": f"Found {len(upload_vulns)} file upload endpoint(s)",
            })

        # Hypothesis 6: Path Traversal → Source Code → More Vulns
        pt_vulns = [v for v in self._vulnerabilities.values() if v.vulnerability_type == "path_traversal"]
        if pt_vulns:
            hypotheses.append({
                "id": "hyp_pt_source",
                "hypothesis": "Path traversal may expose source code, revealing additional vulnerabilities",
                "test_strategy": "Read application source files, configuration, and credential files via path traversal",
                "potential_impact": "Source code disclosure → zero-day discovery → credential theft",
                "priority": "high",
                "evidence": f"Found {len(pt_vulns)} path traversal candidate(s)",
            })

        return hypotheses

    # ── Export ────────────────────────────────────────────────────

    def get_stats(self) -> Dict[str, Any]:
        vuln_types = defaultdict(int)
        for v in self._vulnerabilities.values():
            vuln_types[v.vulnerability_type] += 1

        return {
            "total_vulnerabilities": len(self._vulnerabilities),
            "vulnerability_types": dict(vuln_types),
            "discovered_chains": len(self._discovered_chains),
            "discovered_paths": len(self._discovered_paths),
            "total_capabilities": len(set().union(*self._capability_graph.values())) if self._capability_graph else 0,
            "max_chain_length": max((c.chain_length for c in self._discovered_chains), default=0),
            "highest_risk_score": max((c.chain_risk_score for c in self._discovered_chains), default=0),
        }

    def to_dict(self) -> Dict[str, Any]:
        return {
            "vulnerabilities": {k: v.to_dict() for k, v in self._vulnerabilities.items()},
            "chains": [c.to_dict() for c in self._discovered_chains],
            "paths": [p.to_dict() for p in self._discovered_paths],
            "hypotheses": self.generate_hypotheses(),
            "stats": self.get_stats(),
        }


# ── Singleton ─────────────────────────────────────────────────────

_brain: Optional[AttackSimulationBrain] = None


def get_attack_brain() -> AttackSimulationBrain:
    global _brain
    if _brain is None:
        _brain = AttackSimulationBrain()
    return _brain
