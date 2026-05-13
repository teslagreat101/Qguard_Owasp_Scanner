"""
NEO Intelligence Layer — Autonomous Security Analysis System
=============================================================
The five permanent intelligence layers that transform the OWASP scanner
from a signature-based tool into an autonomous security engineer.

Layers:
    1. ApplicationIntelligenceGraph  — endpoint/role/trust-boundary mapping
    2. SpecAbuseKnowledgeBase        — RFC/parser/protocol confusion patterns
    3. SelfLearningPayloadGenerator  — adaptive, mutation-driven payload engine
    4. AttackSimulationBrain         — vulnerability chaining & attack paths
    5. ContinuousLearningMemory      — persistent cross-scan intelligence

NEO Loop:  Map → Trace → Reason → Hypothesize → Exploit → Verify → Learn
"""

from .application_intelligence_graph import (
    ApplicationIntelligenceGraph,
    get_intelligence_graph,
    EndpointNode,
    RoleNode,
    TrustBoundary,
    AttackSurface,
)

from .spec_abuse_knowledge_base import (
    SpecAbuseKnowledgeBase,
    get_spec_abuse_kb,
    AbusePattern,
    ProtocolConfusion,
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
    AttackChain,
    AttackPath,
    ChainableVulnerability,
)

from .continuous_learning_memory import (
    ContinuousLearningMemory,
    get_learning_memory,
    ScanIntelligence,
    PatternSignature,
)

from .neo_scan_loop import (
    NeoScanLoop,
    get_neo_scan_loop,
    ScanPhase,
    ScanMode,
    NeoScanTarget,
    NeoScanResult,
    NeoPhaseResult,
)

__all__ = [
    # Layer 1
    "ApplicationIntelligenceGraph", "get_intelligence_graph",
    "EndpointNode", "RoleNode", "TrustBoundary", "AttackSurface",
    # Layer 2
    "SpecAbuseKnowledgeBase", "get_spec_abuse_kb",
    "AbusePattern", "ProtocolConfusion",
    # Layer 3
    "SelfLearningPayloadGenerator", "get_payload_generator",
    "PayloadCandidate", "LearningOutcome",
    # Layer 4
    "AttackSimulationBrain", "get_attack_brain",
    "AttackChain", "AttackPath", "ChainableVulnerability",
    # Layer 5
    "ContinuousLearningMemory", "get_learning_memory",
    "ScanIntelligence", "PatternSignature",
    # NEO Loop
    "NeoScanLoop", "get_neo_scan_loop",
    "ScanPhase", "ScanMode", "NeoScanTarget",
    "NeoScanResult", "NeoPhaseResult",
]
