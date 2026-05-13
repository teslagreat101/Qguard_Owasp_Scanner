"""
NEO Scan Loop — Universal Scanning Loop
==========================================
The orchestration layer that ties all 5 intelligence layers together
into a coherent, adaptive scanning process.

Workflow:
    MAP     → Build Application Intelligence Graph
    TRACE   → Map data flows from sources to sinks
    REASON  → Compute attack surfaces using spec abuse knowledge
    HYPOTHESIZE → Generate attack hypotheses using the Attack Brain
    EXPLOIT → Generate and execute context-aware payloads
    VERIFY  → Verify exploits through the Context Replay Engine
    LEARN   → Record outcomes and persist knowledge

Each phase enriches the intelligence available to subsequent phases,
creating a feedback loop that makes each scan more effective than the last.

Integration:
    - Receives scan targets from the existing Orchestrator
    - Outputs NormalizedFinding objects compatible with the existing pipeline
    - Persist learning across scans via ContinuousLearningMemory
"""

from __future__ import annotations

import asyncio
import logging
import time
import uuid
from dataclasses import dataclass, field, asdict
from enum import Enum
from typing import Any, Dict, List, Optional, Tuple

# Import all 5 intelligence layers
from .application_intelligence_graph import (
    ApplicationIntelligenceGraph,
    get_intelligence_graph,
    EndpointNode,
    ParameterNode,
    TrustLevel,
    ParamLocation,
    AttackSurface,
)
from .spec_abuse_knowledge_base import (
    SpecAbuseKnowledgeBase,
    get_spec_abuse_kb,
    AbusePattern,
)
from .self_learning_payload_generator import (
    SelfLearningPayloadGenerator,
    get_payload_generator,
    PayloadCandidate,
    LearningOutcome,
)
from .attack_simulation_brain import (
    AttackSimulationBrain,
    get_attack_brain,
    ChainableVulnerability,
    AttackChain,
    AttackPath,
)
from .continuous_learning_memory import (
    ContinuousLearningMemory,
    get_learning_memory,
    ScanIntelligence,
    PatternSignature,
)

# Try importing the Exploit Verification Engine
try:
    from backend.exploit_verifier import ExploitVerificationEngine, VerificationResult
    _VERIFIER_AVAILABLE = True
except ImportError:
    try:
        # Local development fallback
        import sys
        import os
        sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", "..")))
        from backend.exploit_verifier import ExploitVerificationEngine, VerificationResult  # type: ignore
        _VERIFIER_AVAILABLE = True
    except ImportError:
        _VERIFIER_AVAILABLE = False
        class ExploitVerificationEngine: pass
        class VerificationResult: pass

logger = logging.getLogger("neo.scan_loop")


# ─────────────────────────────────────────────
# Enumerations
# ─────────────────────────────────────────────

class ScanPhase(str, Enum):
    MAP = "map"
    TRACE = "trace"
    REASON = "reason"
    HYPOTHESIZE = "hypothesize"
    EXPLOIT = "exploit"
    VERIFY = "verify"
    LEARN = "learn"


class ScanMode(str, Enum):
    PASSIVE = "passive"           # No active requests
    ACTIVE_SAFE = "active_safe"   # Active but non-destructive
    ACTIVE_FULL = "active_full"   # Full active scanning


# ─────────────────────────────────────────────
# Data models
# ─────────────────────────────────────────────

@dataclass
class NeoScanTarget:
    """Enhanced scan target for the NEO loop."""
    url: str = ""
    repository_path: str = ""
    github_url: str = ""
    scan_mode: ScanMode = ScanMode.ACTIVE_SAFE
    # Target context
    technology: str = ""
    framework: str = ""
    waf_detected: str = ""
    # Scan options
    max_depth: int = 3
    max_endpoints: int = 100
    waf_evasion_level: int = 0
    payload_limit: int = 50
    verify_exploits: bool = True
    # Authentication
    auth_headers: Dict[str, str] = field(default_factory=dict)
    auth_cookies: Dict[str, str] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        d["scan_mode"] = self.scan_mode.value
        return d


@dataclass
class NeoPhaseResult:
    """Result from a single NEO scan phase."""
    phase: ScanPhase
    success: bool = True
    duration_ms: float = 0.0
    items_processed: int = 0
    items_generated: int = 0
    findings: List[Dict[str, Any]] = field(default_factory=list)
    intelligence: Dict[str, Any] = field(default_factory=dict)
    errors: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        d["phase"] = self.phase.value
        return d


@dataclass
class NeoScanResult:
    """Complete result from a NEO scan loop execution."""
    scan_id: str = field(default_factory=lambda: str(uuid.uuid4())[:12])
    target: str = ""
    scan_mode: str = ""
    started_at: float = field(default_factory=time.time)
    completed_at: float = 0.0
    # Phase results
    phase_results: Dict[str, NeoPhaseResult] = field(default_factory=dict)
    # Aggregated findings
    all_findings: List[Dict[str, Any]] = field(default_factory=list)
    verified_findings: List[Dict[str, Any]] = field(default_factory=list)
    unverified_findings: List[Dict[str, Any]] = field(default_factory=list)
    # Attack intelligence
    attack_chains: List[Dict[str, Any]] = field(default_factory=list)
    attack_paths: List[Dict[str, Any]] = field(default_factory=list)
    hypotheses: List[Dict[str, Any]] = field(default_factory=list)
    # Attack surfaces
    attack_surfaces: Dict[str, Dict[str, Any]] = field(default_factory=dict)
    # Intelligence summary
    intelligence_summary: Dict[str, Any] = field(default_factory=dict)
    # Severity breakdown
    severity_counts: Dict[str, int] = field(default_factory=lambda: {
        "critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0,
    })
    # Overall risk
    risk_score: float = 0.0
    risk_level: str = ""

    @property
    def duration_ms(self) -> float:
        if self.completed_at:
            return (self.completed_at - self.started_at) * 1000
        return 0.0

    def to_dict(self) -> Dict[str, Any]:
        return {
            "scan_id": self.scan_id,
            "target": self.target,
            "scan_mode": self.scan_mode,
            "started_at": self.started_at,
            "completed_at": self.completed_at,
            "duration_ms": round(float(self.duration_ms), 2),
            "phase_results": {k: v.to_dict() for k, v in self.phase_results.items()},
            "all_findings": self.all_findings,
            "verified_findings": self.verified_findings,
            "attack_chains": self.attack_chains,
            "attack_paths": self.attack_paths,
            "hypotheses": self.hypotheses,
            "attack_surfaces": self.attack_surfaces,
            "intelligence_summary": self.intelligence_summary,
            "severity_counts": self.severity_counts,
            "risk_score": round(self.risk_score, 3),
            "risk_level": self.risk_level,
            "total_findings": len(self.all_findings),
            "total_verified": len(self.verified_findings),
        }


# ─────────────────────────────────────────────
# NEO Scan Loop Controller
# ─────────────────────────────────────────────

class NeoScanLoop:
    """
    The universal NEO scanning loop.

    Orchestrates the 5 intelligence layers through a structured workflow:
        MAP → TRACE → REASON → HYPOTHESIZE → EXPLOIT → VERIFY → LEARN

    Each phase builds upon the intelligence gathered in previous phases.
    The loop can be run in full (all phases) or partial (specific phases only).
    """

    def __init__(self):
        # Initialize all intelligence layers
        self.graph: ApplicationIntelligenceGraph = get_intelligence_graph()
        self.kb: SpecAbuseKnowledgeBase = get_spec_abuse_kb()
        self.payload_gen: SelfLearningPayloadGenerator = get_payload_generator()
        self.attack_brain: AttackSimulationBrain = get_attack_brain()
        self.memory: ContinuousLearningMemory = get_learning_memory()

        # Exploit Verifier
        self.verifier = ExploitVerificationEngine() if _VERIFIER_AVAILABLE else None

        # Scan state
        self._current_target: Optional[NeoScanTarget] = None
        self._current_result: Optional[NeoScanResult] = None
        self._external_findings: List[Dict[str, Any]] = []

    # ── Main Execution ────────────────────────────────────────────

    async def execute(
        self,
        target: NeoScanTarget,
        external_findings: Optional[List[Dict[str, Any]]] = None,
        phases: Optional[List[ScanPhase]] = None,
    ) -> NeoScanResult:
        """
        Execute the NEO scan loop.

        Args:
            target: The scan target configuration
            external_findings: Findings from existing scanners to incorporate
            phases: Optional subset of phases to run (default: all)

        Returns:
            NeoScanResult with comprehensive intelligence
        """
        self._current_target = target
        self._external_findings = external_findings or []

        result = NeoScanResult(
            target=target.url or target.repository_path or target.github_url,
            scan_mode=target.scan_mode.value,
        )
        self._current_result = result

        all_phases = phases or [
            ScanPhase.MAP,
            ScanPhase.TRACE,
            ScanPhase.REASON,
            ScanPhase.HYPOTHESIZE,
            ScanPhase.EXPLOIT,
            ScanPhase.VERIFY,
            ScanPhase.LEARN,
        ]

        logger.info(f"═══ NEO SCAN LOOP STARTED ═══ Target: {result.target}")
        logger.info(f"Mode: {target.scan_mode.value} | Phases: {[p.value for p in all_phases]}")

        for phase in all_phases:
            try:
                phase_start = time.time()
                logger.info(f"── Phase: {phase.value.upper()} ──")

                phase_result = await self._execute_phase(phase)
                phase_result.duration_ms = (time.time() - phase_start) * 1000
                result.phase_results[phase.value] = phase_result

                if phase_result.findings:
                    result.all_findings.extend(phase_result.findings)

                logger.info(
                    f"  Phase {phase.value} completed in {phase_result.duration_ms:.0f}ms | "
                    f"Processed: {phase_result.items_processed} | Generated: {phase_result.items_generated}"
                )

            except Exception as e:
                logger.error(f"Phase {phase.value} failed: {e}", exc_info=True)
                result.phase_results[phase.value] = NeoPhaseResult(
                    phase=phase, success=False, errors=[str(e)],
                )

        # Finalize
        result.completed_at = time.time()
        self._compute_final_scores(result)

        logger.info(
            f"═══ NEO SCAN LOOP COMPLETED ═══ "
            f"Duration: {result.duration_ms:.0f}ms | "
            f"Findings: {len(result.all_findings)} | "
            f"Verified: {len(result.verified_findings)} | "
            f"Risk: {result.risk_score:.2f} ({result.risk_level})"
        )

        return result

    async def _execute_phase(self, phase: ScanPhase) -> NeoPhaseResult:
        """Execute a single phase of the NEO loop."""
        dispatch = {
            ScanPhase.MAP: self._phase_map,
            ScanPhase.TRACE: self._phase_trace,
            ScanPhase.REASON: self._phase_reason,
            ScanPhase.HYPOTHESIZE: self._phase_hypothesize,
            ScanPhase.EXPLOIT: self._phase_exploit,
            ScanPhase.VERIFY: self._phase_verify,
            ScanPhase.LEARN: self._phase_learn,
        }
        handler = dispatch.get(phase)
        if handler:
            return await handler()
        return NeoPhaseResult(phase=phase, success=False, errors=["Unknown phase"])

    # ── Phase 1: MAP ─────────────────────────────────────────────

    async def _phase_map(self) -> NeoPhaseResult:
        """
        MAP: Build Application Intelligence Graph.
        Populates endpoints, parameters, roles, and services.
        """
        result = NeoPhaseResult(phase=ScanPhase.MAP)
        target = self._current_target

        # Check memory for previous target intelligence
        target_profile = self.memory.get_target_profile(target.url or target.repository_path or "")
        if target_profile:
            logger.info(f"Found previous target profile: {target_profile.scan_count} previous scans")
            for ep in target_profile.known_endpoints:
                self.graph.ingest_endpoint(ep)

        # Ingest external findings as endpoints
        for finding in self._external_findings:
            endpoint = finding.get("endpoint", finding.get("url", finding.get("file", "")))
            if endpoint:
                params = []
                param_name = finding.get("parameter", finding.get("param", ""))
                if param_name:
                    params.append({"name": param_name, "location": "query"})

                self.graph.ingest_endpoint(
                    url_pattern=endpoint,
                    method=finding.get("method", "GET"),
                    auth_required=finding.get("auth_required", False),
                    parameters=params if params else None,
                    technology=target.technology,
                )
                result.items_processed += 1

        result.items_generated = len(self.graph._endpoints)
        result.intelligence = {
            "stats": self.graph.get_stats(),
            "technology": target.technology,
            "framework": target.framework,
        }

        return result

    # ── Phase 2: TRACE ────────────────────────────────────────────

    async def _phase_trace(self) -> NeoPhaseResult:
        """
        TRACE: Map data flows from user inputs to dangerous sinks.
        Identifies taint propagation paths.
        """
        result = NeoPhaseResult(phase=ScanPhase.TRACE)
        target = self._current_target

        # Infer data flows from the intelligence graph
        for key, ep in self.graph._endpoints.items():
            for param in ep.parameters:
                sinks = []
                if param.reaches_db:
                    sinks.append("db_query")
                if param.reaches_http_client:
                    sinks.append("http_request")
                if param.reaches_filesystem:
                    sinks.append("file_write")
                if param.reaches_command:
                    sinks.append("command_exec")
                if param.reaches_template:
                    sinks.append("template_render")
                if param.reaches_redirect:
                    sinks.append("redirect")
                if param.reaches_serializer:
                    sinks.append("deserialization")

                if sinks:
                    self.graph.map_data_flow(
                        endpoint_url=ep.url_pattern,
                        sources=[f"{param.location.value}:{param.name}"],
                        sinks=sinks,
                    )
                    result.items_processed += 1

        # If scanning code, infer flows from source
        if target.repository_path:
            import os
            for root, dirs, files in os.walk(target.repository_path):
                for fname in files:
                    if fname.endswith((".py", ".js", ".ts", ".java", ".rb", ".php")):
                        fpath = os.path.join(root, fname)
                        try:
                            with open(fpath, "r", encoding="utf-8", errors="ignore") as f:
                                content = f.read()
                            if len(content) < 100_000:
                                self.graph.infer_data_flows_from_code(content, fpath)
                                result.items_processed += 1
                        except Exception:
                            pass

        # Detect trust boundaries
        boundaries = self.graph.detect_trust_boundaries()
        result.items_generated = len(self.graph._data_flows)

        result.intelligence = {
            "data_flows": len(self.graph._data_flows),
            "trust_boundaries": len(boundaries),
        }

        return result

    # ── Phase 3: REASON ───────────────────────────────────────────

    async def _phase_reason(self) -> NeoPhaseResult:
        """
        REASON: Compute attack surfaces using spec abuse knowledge
        and graph analysis. Identifies WHERE to attack.
        """
        result = NeoPhaseResult(phase=ScanPhase.REASON)

        # Compute attack surfaces
        surfaces = self.graph.compute_attack_surfaces()

        # Enrich with spec abuse patterns
        for code, surface in surfaces.items():
            patterns = self.kb.get_patterns_for_owasp(code)
            if patterns:
                surface.attack_vectors.extend([p.name for p in patterns[:3]])

        # Get specific attack candidates
        ssrf_candidates = self.graph.get_ssrf_candidates()
        idor_candidates = self.graph.get_idor_candidates()
        injection_candidates = self.graph.get_injection_candidates()
        privesc_paths = self.graph.get_privilege_escalation_paths()

        result.items_processed = len(surfaces)
        result.items_generated = len(ssrf_candidates) + len(idor_candidates) + len(injection_candidates)

        result.intelligence = {
            "attack_surfaces": {k: v.to_dict() for k, v in surfaces.items()},
            "ssrf_candidates": len(ssrf_candidates),
            "idor_candidates": len(idor_candidates),
            "injection_candidates": len(injection_candidates),
            "privilege_escalation_paths": len(privesc_paths),
        }

        # Store surfaces in result
        if self._current_result:
            self._current_result.attack_surfaces = {k: v.to_dict() for k, v in surfaces.items()}

        return result

    # ── Phase 4: HYPOTHESIZE ──────────────────────────────────────

    async def _phase_hypothesize(self) -> NeoPhaseResult:
        """
        HYPOTHESIZE: Generate attack hypotheses and chain
        vulnerabilities into multi-step attack paths.
        """
        result = NeoPhaseResult(phase=ScanPhase.HYPOTHESIZE)

        # Ingest all external findings into the attack brain
        for finding in self._external_findings:
            self.attack_brain.ingest_finding(finding)
            result.items_processed += 1

        # Discover attack chains
        chains = self.attack_brain.discover_chains()
        result.items_generated = len(chains)

        # Discover attack paths
        paths = self.attack_brain.discover_attack_paths()

        # Generate hypotheses
        hypotheses = self.attack_brain.generate_hypotheses()

        result.intelligence = {
            "chains": len(chains),
            "paths": len(paths),
            "hypotheses": len(hypotheses),
        }

        if self._current_result:
            self._current_result.attack_chains = [c.to_dict() for c in chains[:20]]
            self._current_result.attack_paths = [p.to_dict() for p in paths[:10]]
            self._current_result.hypotheses = hypotheses

        return result

    # ── Phase 5: EXPLOIT ──────────────────────────────────────────

    async def _phase_exploit(self) -> NeoPhaseResult:
        """
        EXPLOIT: Generate context-aware payloads for identified attack surfaces.
        Creates payloads using the Self-Learning Payload Generator.
        """
        result = NeoPhaseResult(phase=ScanPhase.EXPLOIT)
        target = self._current_target
        findings = []

        # Generate payloads for each attack category
        categories_to_scan = self._determine_scan_categories()

        for category, candidates in categories_to_scan.items():
            # Recall previously successful payloads from memory
            recalled_payloads = self.memory.recall_payloads(
                category=category,
                technology=target.technology,
                limit=10,
            )

            # Generate new payloads
            payloads = self.payload_gen.generate_payloads(
                category=category,
                context=candidates.get("context", ""),
                technology=target.technology,
                waf_evasion_level=target.waf_evasion_level,
                max_payloads=target.payload_limit,
                seed_payloads=recalled_payloads if recalled_payloads else None,
            )

            for pc in payloads:
                finding = {
                    "id": pc.id,
                    "title": f"Potential {category.upper()} — Payload Generated",
                    "category": category,
                    "severity": self._category_default_severity(category),
                    "confidence": pc.estimated_confidence,
                    "payload": pc.payload,
                    "context": pc.context,
                    "mutation_chain": pc.mutation_chain,
                    "waf_evasion_level": pc.waf_evasion_level,
                    "endpoint": candidates.get("endpoint", ""),
                    "parameter": candidates.get("parameter", ""),
                    "verified": False,
                    "phase": "exploit",
                }
                findings.append(finding)

            result.items_processed += len(payloads)

        result.items_generated = len(findings)
        result.findings = findings

        return result

    def _determine_scan_categories(self) -> Dict[str, Dict[str, Any]]:
        """Determine which attack categories to scan based on intelligence."""
        categories = {}

        # From injection candidates
        for endpoint, param, sink_type in self.graph.get_injection_candidates():
            sink_to_cat = {
                "db_query": "sqli",
                "command_exec": "cmdi",
                "template_render": "ssti",
            }
            cat = sink_to_cat.get(sink_type, "sqli")
            if cat not in categories:
                categories[cat] = {"endpoint": endpoint, "parameter": param, "context": "sql_query" if cat == "sqli" else "command"}

        # From SSRF candidates
        ssrf_candidates = self.graph.get_ssrf_candidates()
        if ssrf_candidates:
            ep, param = ssrf_candidates[0]
            categories["ssrf"] = {"endpoint": ep.url_pattern, "parameter": param.name, "context": "url_param"}

        # From IDOR candidates
        idor_candidates = self.graph.get_idor_candidates()
        if idor_candidates:
            ep, param = idor_candidates[0]
            categories["idor"] = {"endpoint": ep.url_pattern, "parameter": param.name, "context": "url_param"}

        # Always test XSS and path traversal
        if not categories:
            categories["xss"] = {"endpoint": "", "parameter": "", "context": "html_body"}
            categories["sqli"] = {"endpoint": "", "parameter": "", "context": "sql_query"}
            categories["ssrf"] = {"endpoint": "", "parameter": "", "context": "url_param"}
            categories["path_traversal"] = {"endpoint": "", "parameter": "", "context": "url_param"}

        return categories

    def _category_default_severity(self, category: str) -> str:
        severity_map = {
            "sqli": "high", "xss": "medium", "ssti": "critical",
            "cmdi": "critical", "ssrf": "high", "idor": "medium",
            "path_traversal": "medium", "xxe": "high", "csrf": "medium",
            "rce": "critical", "deserialize": "critical",
        }
        return severity_map.get(category, "medium")

    # ── Phase 6: VERIFY ───────────────────────────────────────────

    async def _phase_verify(self) -> NeoPhaseResult:
        """
        VERIFY: Verify exploit findings using the Exploit Verification Engine.
        Sends real HTTP requests to confirm vulnerabilities through non-destructive
        behavioral probes (timing, reflection, differential analysis).
        """
        result = NeoPhaseResult(phase=ScanPhase.VERIFY)
        target = self._current_target
        if not target or not self._current_result:
            return result

        # Verify generated findings from EXPLOIT phase
        exploit_phase = self._current_result.phase_results.get("exploit")
        if _VERIFIER_AVAILABLE and self.verifier and exploit_phase and target.url:
            logger.info(f"Verifying {len(exploit_phase.findings)} generated findings...")

            # Batch verify exploits (non-blocking where possible)
            verification_tasks = []
            for f_raw in exploit_phase.findings:
                if not isinstance(f_raw, dict):
                    logger.warning(f"Skipping non-dict finding in exploit phase: {f_raw}")
                    continue
                f: Dict[str, Any] = f_raw
                if f.get("endpoint") or target.url:
                    # Update finding with target URL if missing
                    if not f.get("endpoint"):
                        f["endpoint"] = target.url

                    # Ensure _current_result is not None before accessing scan_id
                    if self._current_result:
                        verification_tasks.append(self.verifier.verify(
                            finding=f,
                            target_url=target.url,
                            scan_id=self._current_result.scan_id
                        ))

            if verification_tasks:
                verification_results = await asyncio.gather(*verification_tasks, return_exceptions=True)

                for i, v_res in enumerate(verification_results):
                    if isinstance(v_res, Exception):
                        logger.error(f"Verification failed with error: {v_res}")
                        continue

                    # Ensure the original finding is still a dict before modification
                    if i < len(exploit_phase.findings) and isinstance(exploit_phase.findings[i], dict):
                        if v_res and v_res.verification_status == "confirmed":
                            finding = exploit_phase.findings[i]
                            finding["verified"] = True
                            finding["confidence"] = v_res.confidence_score
                            finding["verification_details"] = v_res.to_dict()
                            finding["proof"] = v_res.evidence_hash

                            # Add to verified findings
                            if self._current_result:
                                self._current_result.verified_findings.append(finding)
                            result.items_processed += 1
                            logger.info(f"  [CONFIRMED] {finding['title']} at {finding.get('parameter','')}")

        # Mark high-confidence external findings as verified if not already processed
        for finding in self._external_findings:
            if finding.get("verified"):
                continue
            confidence = float(finding.get("confidence", 0))
            if confidence >= 0.85:
                finding["verified"] = True
                result.items_processed += 1
                if self._current_result:
                    self._current_result.verified_findings.append(finding)

        # Record payload outcomes for learning across ALL findings
        if exploit_phase:
            for f_raw in exploit_phase.findings:
                if not isinstance(f_raw, dict):
                    continue
                f: Dict[str, Any] = f_raw
                outcome = LearningOutcome(
                    payload_id=f.get("id", ""),
                    payload=f.get("payload", ""),
                    category=f.get("category", ""),
                    succeeded=f.get("verified", False),
                    context=f.get("context", ""),
                    mutation_chain=f.get("mutation_chain", []),
                )
                self.payload_gen.record_outcome(outcome)
                result.items_processed += 1

        result.items_generated = len(self._current_result.verified_findings) if self._current_result else 0
        return result

    # ── Phase 7: LEARN ────────────────────────────────────────────

    async def _phase_learn(self) -> NeoPhaseResult:
        """
        LEARN: Record all intelligence and persist learning memory.
        Updates patterns, payload memory, technology profiles, and target history.
        """
        result = NeoPhaseResult(phase=ScanPhase.LEARN)
        target = self._current_target
        if not target or not self._current_result:
            return result

        # Record scan intelligence
        scan_intel = ScanIntelligence(
            scan_id=self._current_result.scan_id,
            target=target.url or target.repository_path or "",
            scan_type="neo_loop",
            total_findings=len(self._current_result.all_findings) if self._current_result else 0,
            verified_findings=len(self._current_result.verified_findings) if self._current_result else 0,
            detected_technologies=[target.technology] if target.technology else [],
            detected_frameworks=[target.framework] if target.framework else [],
            detected_waf=target.waf_detected or None,
            endpoints_discovered=len(self.graph._endpoints),
            parameters_discovered=len(self.graph._parameters),
            data_flows_mapped=len(self.graph._data_flows),
        )

        # Count severities
        for finding in self._current_result.all_findings if self._current_result else []:
            sev = finding.get("severity", "info")
            scan_intel.severity_counts[sev] = scan_intel.severity_counts.get(sev, 0) + 1
            vtype = finding.get("category", "unknown")
            scan_intel.vulnerability_types[vtype] = scan_intel.vulnerability_types.get(vtype, 0) + 1

        # Record successful payloads
        for finding in self._current_result.verified_findings:
            payload = finding.get("payload", "")
            if payload:
                self.memory.remember_successful_payload(
                    payload=payload,
                    category=finding.get("category", ""),
                    context=finding.get("context", ""),
                    technology=target.technology,
                )
                scan_intel.successful_payloads.append({
                    "payload": payload,
                    "category": finding.get("category", ""),
                })

        self.memory.record_scan(scan_intel)

        # Update technology profile
        if target.technology:
            vuln_types = list(scan_intel.vulnerability_types.keys())
            self.memory.update_technology_profile(
                technology=target.technology,
                framework=target.framework,
                vulnerabilities=vuln_types,
                waf_type=target.waf_detected,
            )

        # Prune low-quality patterns periodically
        self.memory.prune_low_quality_patterns()

        # Save to disk
        self.memory.save()

        result.items_processed = len(self._current_result.all_findings) if self._current_result else 0
        result.intelligence = self.memory.get_stats()

        return result

    # ── Scoring ───────────────────────────────────────────────────

    def _compute_final_scores(self, result: NeoScanResult):
        """Compute final risk scores and severity breakdown."""
        # Count severities
        for finding in result.all_findings:
            sev = finding.get("severity", "info")
            result.severity_counts[sev] = result.severity_counts.get(sev, 0) + 1

        # Compute risk score (0-10)
        risk = (
            result.severity_counts.get("critical", 0) * 10
            + result.severity_counts.get("high", 0) * 5
            + result.severity_counts.get("medium", 0) * 2
            + result.severity_counts.get("low", 0) * 0.5
        )
        # Factor in verified findings
        if result.verified_findings:
            risk *= 1.5

        # Factor in attack chains
        if result.attack_chains:
            max_chain_risk = max(
                (c.get("chain_risk_score", 0) for c in result.attack_chains), default=0,
            )
            risk = max(risk, max_chain_risk * 10)

        result.risk_score = min(10.0, risk / max(1, len(result.all_findings)) * 2)

        # Risk level
        if result.risk_score >= 8:
            result.risk_level = "CRITICAL"
        elif result.risk_score >= 6:
            result.risk_level = "HIGH"
        elif result.risk_score >= 4:
            result.risk_level = "MEDIUM"
        elif result.risk_score >= 2:
            result.risk_level = "LOW"
        else:
            result.risk_level = "INFO"

        # Intelligence summary
        result.intelligence_summary = {
            "graph_stats": self.graph.get_stats(),
            "kb_stats": self.kb.get_stats(),
            "payload_gen_stats": self.payload_gen.get_stats(),
            "attack_brain_stats": self.attack_brain.get_stats(),
            "learning_memory_stats": self.memory.get_stats(),
        }


# ── Singleton ─────────────────────────────────────────────────────

_loop: Optional[NeoScanLoop] = None


def get_neo_scan_loop() -> NeoScanLoop:
    global _loop
    if _loop is None:
        _loop = NeoScanLoop()
    return _loop
