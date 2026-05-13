"""
Quantara Shared Intelligence State
====================================
Centralized, thread-safe scan state that enables coordinated swarm intelligence.
All agents read from and write to this shared state, enabling cross-agent
correlation and context propagation.
"""

from __future__ import annotations

import asyncio
import hashlib
import logging
import time
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Set

logger = logging.getLogger(__name__)


@dataclass
class DiscoveredAsset:
    """An asset discovered during reconnaissance."""
    asset_id:    str
    asset_type:  str          # domain, subdomain, ip, endpoint, service
    value:       str          # the actual URL/domain/IP
    source:      str          # agent that discovered it
    confidence:  float = 0.0
    metadata:    Dict = field(default_factory=dict)
    timestamp:   str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())


@dataclass
class IdentifiedService:
    """A service/technology fingerprinted during scanning."""
    service_id:  str
    endpoint:    str
    technology:  str
    version:     str = ""
    port:        int = 0
    source:      str = ""
    metadata:    Dict = field(default_factory=dict)


@dataclass
class PayloadAttempt:
    """Record of a payload execution attempt."""
    attempt_id:    str
    vector_type:   str        # sqli, xss, cmdi, lfi, ssrf
    payload:       str
    endpoint:      str
    status_code:   int = 0
    response_size: int = 0
    response_time: float = 0.0
    success:       bool = False
    evidence:      str = ""
    agent:         str = ""
    generation:    int = 0     # evolution generation (0 = base)
    fitness:       float = 0.0


@dataclass
class ExploitResult:
    """Result of an exploitation attempt."""
    exploit_id:   str
    finding_id:   str
    chain_step:   int = 0
    verified:     bool = False
    proof:        str = ""
    impact:       str = ""
    agent:        str = ""


class SharedIntelligenceState:
    """
    Centralized shared state for the swarm.
    Thread-safe via asyncio.Lock for concurrent agent access.

    Stores:
        - Discovered assets (domains, subdomains, endpoints)
        - Identified services and technologies
        - Vulnerability findings (cross-referenced)
        - Payload attempts and their results
        - Exploit results and chains
        - Risk scores and metrics
        - Agent telemetry and timing
    """

    def __init__(self, scan_id: str = "", target: str = ""):
        self.scan_id = scan_id
        self.target  = target
        self._lock   = asyncio.Lock()

        # ── Core intelligence stores ──
        self.assets:          Dict[str, DiscoveredAsset]   = {}
        self.services:        Dict[str, IdentifiedService] = {}
        self.vulnerabilities: Dict[str, Dict[str, Any]]    = {}
        self.payload_attempts: List[PayloadAttempt]         = []
        self.exploit_results: List[ExploitResult]           = []

        # ── Derived intelligence ──
        self.attack_chains:    List[Dict[str, Any]]   = []
        self.correlated_groups: List[List[str]]        = []
        self.risk_scores:      Dict[str, float]        = {}

        # ── Agent coordination ──
        self.discovered_endpoints: List[str]     = []
        self.target_base:         str            = ""
        self.tech_disclosed:      List[str]      = []
        self.generated_payloads:  Dict[str, List[str]] = {}
        self.total_payloads:      int            = 0
        self.waf_detected:        Optional[str]  = None
        self.cloud_providers:     List[str]      = []

        # ── Telemetry ──
        self.agent_timings:    Dict[str, float]   = {}
        self.agent_findings:   Dict[str, int]     = defaultdict(int)
        self.phase_history:    List[Dict]          = []
        self.learning_feedback: List[Dict]         = []

        # ── Severity counters ──
        self.severity_counts = {
            "critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0,
        }

    # ── Asset Management ──────────────────────────────────────────────────

    async def add_asset(self, asset: DiscoveredAsset) -> None:
        async with self._lock:
            self.assets[asset.asset_id] = asset

    async def add_endpoint(self, url: str) -> None:
        async with self._lock:
            if url not in self.discovered_endpoints:
                self.discovered_endpoints.append(url)

    async def get_endpoints(self, limit: int = 20) -> List[str]:
        async with self._lock:
            return list(self.discovered_endpoints[:limit])

    # ── Service Management ────────────────────────────────────────────────

    async def add_service(self, svc: IdentifiedService) -> None:
        async with self._lock:
            self.services[svc.service_id] = svc

    async def add_tech(self, tech: str) -> None:
        async with self._lock:
            if tech not in self.tech_disclosed:
                self.tech_disclosed.append(tech)

    # ── Vulnerability Management ──────────────────────────────────────────

    async def add_vulnerability(self, finding: Dict[str, Any]) -> None:
        async with self._lock:
            fid = finding.get("id", "")
            self.vulnerabilities[fid] = finding
            sev = finding.get("severity", "info").lower()
            if sev in self.severity_counts:
                self.severity_counts[sev] += 1
            agent = finding.get("node_name", finding.get("module_name", ""))
            self.agent_findings[agent] += 1

    async def get_vulnerabilities(self, severity: str = "",
                                   limit: int = 200) -> List[Dict]:
        async with self._lock:
            vulns = list(self.vulnerabilities.values())
            if severity:
                vulns = [v for v in vulns if v.get("severity", "").lower() == severity]
            return vulns[:limit]

    # ── Payload Management ────────────────────────────────────────────────

    async def record_payload_attempt(self, attempt: PayloadAttempt) -> None:
        async with self._lock:
            self.payload_attempts.append(attempt)
            if len(self.payload_attempts) > 5000:
                self.payload_attempts = self.payload_attempts[-5000:]

    async def get_successful_payloads(self, vector_type: str = "") -> List[PayloadAttempt]:
        async with self._lock:
            results = [p for p in self.payload_attempts if p.success]
            if vector_type:
                results = [p for p in results if p.vector_type == vector_type]
            return results

    async def set_generated_payloads(self, payloads: Dict[str, List[str]]) -> None:
        async with self._lock:
            self.generated_payloads = payloads
            self.total_payloads = sum(len(v) for v in payloads.values())

    async def get_payloads(self, vector_type: str, limit: int = 30) -> List[str]:
        async with self._lock:
            return self.generated_payloads.get(vector_type, [])[:limit]

    # ── Exploit Results ───────────────────────────────────────────────────

    async def record_exploit(self, result: ExploitResult) -> None:
        async with self._lock:
            self.exploit_results.append(result)

    # ── Attack Chain Management ───────────────────────────────────────────

    async def add_attack_chain(self, chain: Dict[str, Any]) -> None:
        async with self._lock:
            self.attack_chains.append(chain)

    async def get_attack_chains(self) -> List[Dict]:
        async with self._lock:
            return list(self.attack_chains)

    # ── Risk Score ────────────────────────────────────────────────────────

    async def compute_risk_score(self) -> float:
        """Compute composite risk score from all findings."""
        async with self._lock:
            score = min(100,
                self.severity_counts["critical"] * 25 +
                self.severity_counts["high"]     * 10 +
                self.severity_counts["medium"]   *  3 +
                self.severity_counts["low"]      *  1
            )
            self.risk_scores["composite"] = score
            return score

    # ── Context Export (for legacy compatibility) ─────────────────────────

    def to_context(self) -> Dict[str, Any]:
        """Export state as a flat context dict for node execution."""
        return {
            "discovered_endpoints": list(self.discovered_endpoints),
            "target_base":          self.target_base,
            "tech_disclosed":       list(self.tech_disclosed),
            "generated_payloads":   dict(self.generated_payloads),
            "total_payloads":       self.total_payloads,
            "waf_detected":         self.waf_detected,
            "cloud_providers":      list(self.cloud_providers),
            "depth":                "",  # set by orchestrator
            "strategy":             "",
        }

    def import_context(self, ctx: Dict[str, Any]) -> None:
        """Import a legacy context dict back into shared state."""
        if "discovered_endpoints" in ctx:
            self.discovered_endpoints = ctx["discovered_endpoints"]
        if "target_base" in ctx:
            self.target_base = ctx["target_base"]
        if "tech_disclosed" in ctx:
            self.tech_disclosed = ctx["tech_disclosed"]
        if "generated_payloads" in ctx:
            self.generated_payloads = ctx["generated_payloads"]
        if "total_payloads" in ctx:
            self.total_payloads = ctx["total_payloads"]

    # ── Telemetry ─────────────────────────────────────────────────────────

    async def record_agent_timing(self, agent: str, elapsed: float) -> None:
        async with self._lock:
            self.agent_timings[agent] = elapsed

    async def record_learning_feedback(self, feedback: Dict) -> None:
        async with self._lock:
            self.learning_feedback.append(feedback)
            if len(self.learning_feedback) > 500:
                self.learning_feedback = self.learning_feedback[-500:]

    def get_summary(self) -> Dict[str, Any]:
        """Return a summary snapshot of the current intelligence state."""
        return {
            "scan_id":            self.scan_id,
            "target":             self.target,
            "total_assets":       len(self.assets),
            "total_services":     len(self.services),
            "total_endpoints":    len(self.discovered_endpoints),
            "total_vulns":        len(self.vulnerabilities),
            "total_payloads":     self.total_payloads,
            "total_exploits":     len(self.exploit_results),
            "total_chains":       len(self.attack_chains),
            "severity_counts":    dict(self.severity_counts),
            "risk_score":         self.risk_scores.get("composite", 0),
            "agent_timings":      dict(self.agent_timings),
            "waf_detected":       self.waf_detected,
            "cloud_providers":    list(self.cloud_providers),
        }

    def reset(self, scan_id: str = "", target: str = "") -> None:
        """Reset all state for a new scan."""
        self.__init__(scan_id=scan_id, target=target)
