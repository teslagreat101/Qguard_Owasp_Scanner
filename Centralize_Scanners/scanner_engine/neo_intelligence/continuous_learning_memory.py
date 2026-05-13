"""
Layer 5 — Continuous Learning Memory
======================================
Persistent cross-scan intelligence that retains and evolves knowledge
across scanning sessions.

Capabilities:
    - Cross-scan pattern sharing (payload DNA, attack patterns)
    - Technology fingerprint caching
    - Vulnerability pattern signatures for future detection
    - WAF/filter evasion knowledge accumulation
    - Application behavior profiling
    - Historical scan intelligence for trend analysis

Data persists in a local JSON file, enabling the scanner to get
smarter with each run without requiring a database.
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
import time
import uuid
from collections import defaultdict
from dataclasses import dataclass, field, asdict
from pathlib import Path
from typing import Any, Dict, List, Optional, Set

logger = logging.getLogger("neo.learning_memory")

# Default persistence path
_DEFAULT_MEMORY_PATH = os.path.join(
    os.path.dirname(os.path.abspath(__file__)),
    "..", "..", ".neo_learning_memory.json",
)


# ─────────────────────────────────────────────
# Data models
# ─────────────────────────────────────────────

@dataclass
class PatternSignature:
    """A learned pattern signature for vulnerability detection."""
    id: str = field(default_factory=lambda: str(uuid.uuid4())[:12])
    name: str = ""
    pattern_type: str = ""                # regex_match, data_flow, behavioral, semantic
    signature: str = ""                   # regex or description
    category: str = ""                    # OWASP category
    vulnerability_type: str = ""          # sqli, xss, ssrf, etc.
    severity: str = "medium"
    confidence: float = 0.7
    detection_count: int = 0
    false_positive_count: int = 0
    last_detected: Optional[float] = None
    source_scan_id: str = ""
    technology_context: str = ""
    tags: List[str] = field(default_factory=list)

    @property
    def precision(self) -> float:
        total = self.detection_count + self.false_positive_count
        if total == 0:
            return 0.5
        return self.detection_count / total

    def to_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        d["precision"] = self.precision
        return d


@dataclass
class ScanIntelligence:
    """Intelligence gathered from a single scan session."""
    scan_id: str = field(default_factory=lambda: str(uuid.uuid4())[:12])
    target: str = ""
    scan_type: str = ""                   # code_scan, url_scan, github_scan
    timestamp: float = field(default_factory=time.time)
    duration_ms: float = 0.0
    # Results summary
    total_findings: int = 0
    verified_findings: int = 0
    severity_counts: Dict[str, int] = field(default_factory=lambda: {
        "critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0,
    })
    vulnerability_types: Dict[str, int] = field(default_factory=dict)
    # Technology intelligence
    detected_technologies: List[str] = field(default_factory=list)
    detected_frameworks: List[str] = field(default_factory=list)
    detected_waf: Optional[str] = None
    # Payload intelligence
    successful_payloads: List[Dict[str, str]] = field(default_factory=list)  # {payload, category, context}
    blocked_payloads: List[Dict[str, str]] = field(default_factory=list)
    # Attack chains discovered
    attack_chains: List[Dict[str, Any]] = field(default_factory=list)
    # Learned patterns
    new_patterns: List[str] = field(default_factory=list)  # pattern IDs
    # Attack surface
    endpoints_discovered: int = 0
    parameters_discovered: int = 0
    data_flows_mapped: int = 0

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class TechnologyProfile:
    """Accumulated knowledge about a technology's security posture."""
    technology: str = ""
    framework: str = ""
    common_vulnerabilities: List[str] = field(default_factory=list)
    effective_payloads: Dict[str, List[str]] = field(default_factory=dict)  # category → payloads
    waf_present: bool = False
    waf_type: str = ""
    evasion_techniques: List[str] = field(default_factory=list)
    scan_count: int = 0
    vuln_count: int = 0
    last_scanned: Optional[float] = None

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class TargetProfile:
    """Remembered profile of a previously scanned target."""
    target: str = ""
    first_scanned: float = field(default_factory=time.time)
    last_scanned: float = field(default_factory=time.time)
    scan_count: int = 0
    technology_profile: Optional[TechnologyProfile] = None
    known_endpoints: List[str] = field(default_factory=list)
    known_vulnerabilities: List[str] = field(default_factory=list)
    risk_trend: List[Dict[str, Any]] = field(default_factory=list)  # [{timestamp, score}]
    notes: str = ""

    def to_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        return d


# ─────────────────────────────────────────────
# Continuous Learning Memory
# ─────────────────────────────────────────────

class ContinuousLearningMemory:
    """
    Persistent learning memory for the NEO intelligence system.

    Retains knowledge across scanning sessions:
    - Learned vulnerability patterns
    - Effective payload/mutation combinations by context
    - Technology profiles
    - Target reconnaissance data
    - WAF evasion knowledge
    - Attack chain templates

    The memory self-organizes: high-precision patterns are promoted,
    low-precision patterns are demoted or removed.
    """

    def __init__(self, memory_path: str = _DEFAULT_MEMORY_PATH):
        self._memory_path = memory_path
        self._patterns: Dict[str, PatternSignature] = {}
        self._scan_history: List[ScanIntelligence] = []
        self._tech_profiles: Dict[str, TechnologyProfile] = {}
        self._target_profiles: Dict[str, TargetProfile] = {}
        self._payload_memory: Dict[str, List[Dict[str, Any]]] = defaultdict(list)  # category → payloads
        self._waf_evasion_db: Dict[str, List[str]] = defaultdict(list)  # waf_type → evasion_mutations
        self._global_stats: Dict[str, Any] = {}
        self._created_at = time.time()
        self._last_saved = 0.0

        # Load existing memory
        self._load()

    # ── Pattern Management ────────────────────────────────────────

    def learn_pattern(self, pattern: PatternSignature):
        """Add or update a learned vulnerability pattern."""
        if pattern.id in self._patterns:
            existing = self._patterns[pattern.id]
            existing.detection_count += pattern.detection_count
            existing.confidence = max(existing.confidence, pattern.confidence)
            existing.last_detected = time.time()
        else:
            self._patterns[pattern.id] = pattern
            logger.info(f"Learned new pattern: {pattern.name} ({pattern.pattern_type})")

    def record_detection(self, pattern_id: str, is_true_positive: bool = True):
        """Record a detection event for a pattern."""
        if pattern_id in self._patterns:
            if is_true_positive:
                self._patterns[pattern_id].detection_count += 1
            else:
                self._patterns[pattern_id].false_positive_count += 1
            self._patterns[pattern_id].last_detected = time.time()

    def get_patterns_for_context(
        self,
        vulnerability_type: str = "",
        technology: str = "",
        min_precision: float = 0.5,
    ) -> List[PatternSignature]:
        """Get learned patterns relevant to a scanning context."""
        results = []
        for pattern in self._patterns.values():
            if vulnerability_type and pattern.vulnerability_type != vulnerability_type:
                continue
            if technology and pattern.technology_context and technology.lower() not in pattern.technology_context.lower():
                continue
            if pattern.precision < min_precision:
                continue
            results.append(pattern)

        results.sort(key=lambda p: p.precision * p.confidence, reverse=True)
        return results

    def prune_low_quality_patterns(self, min_precision: float = 0.3, min_detections: int = 3):
        """Remove patterns that have proven unreliable."""
        to_remove = []
        for pid, pattern in self._patterns.items():
            total = pattern.detection_count + pattern.false_positive_count
            if total >= min_detections and pattern.precision < min_precision:
                to_remove.append(pid)
                logger.info(f"Pruning low-quality pattern: {pattern.name} (precision: {pattern.precision:.1%})")

        for pid in to_remove:
            del self._patterns[pid]

    # ── Payload Memory ────────────────────────────────────────────

    def remember_successful_payload(
        self,
        payload: str,
        category: str,
        context: str = "",
        technology: str = "",
        waf_bypassed: bool = False,
    ):
        """Remember a payload that successfully exploited a vulnerability."""
        entry = {
            "payload": payload,
            "context": context,
            "technology": technology,
            "waf_bypassed": waf_bypassed,
            "timestamp": time.time(),
            "success_count": 1,
        }

        # Check if payload already known
        for existing in self._payload_memory[category]:
            if existing["payload"] == payload:
                existing["success_count"] = existing.get("success_count", 0) + 1
                return

        self._payload_memory[category].append(entry)

        # Limit memory per category
        if len(self._payload_memory[category]) > 200:
            # Keep top 200 by success count
            self._payload_memory[category].sort(
                key=lambda e: e.get("success_count", 0), reverse=True,
            )
            self._payload_memory[category] = self._payload_memory[category][:200]

    def recall_payloads(
        self,
        category: str,
        context: str = "",
        technology: str = "",
        limit: int = 20,
    ) -> List[str]:
        """Recall successful payloads for a given context."""
        entries = self._payload_memory.get(category, [])

        # Filter by context/technology if specified
        if context or technology:
            filtered = []
            for entry in entries:
                context_match = not context or entry.get("context") == context
                tech_match = not technology or technology.lower() in entry.get("technology", "").lower()
                if context_match or tech_match:
                    filtered.append(entry)
            entries = filtered or entries  # fallback to all if no matches

        # Sort by success count
        entries.sort(key=lambda e: e.get("success_count", 0), reverse=True)

        return [e["payload"] for e in entries[:limit]]

    # ── WAF Evasion Knowledge ─────────────────────────────────────

    def learn_waf_evasion(self, waf_type: str, successful_mutation: str):
        """Record a mutation that successfully evaded a WAF."""
        if successful_mutation not in self._waf_evasion_db[waf_type]:
            self._waf_evasion_db[waf_type].append(successful_mutation)
            logger.info(f"Learned WAF evasion: {waf_type} → {successful_mutation}")

    def recall_waf_evasions(self, waf_type: str) -> List[str]:
        """Recall known evasion techniques for a WAF type."""
        exact = self._waf_evasion_db.get(waf_type, [])
        if exact:
            return exact

        # Fuzzy match
        for known_waf, techniques in self._waf_evasion_db.items():
            if waf_type.lower() in known_waf.lower() or known_waf.lower() in waf_type.lower():
                return techniques

        return []

    # ── Technology Profiles ───────────────────────────────────────

    def update_technology_profile(
        self,
        technology: str,
        framework: str = "",
        vulnerabilities: Optional[List[str]] = None,
        effective_payloads: Optional[Dict[str, List[str]]] = None,
        waf_type: str = "",
    ):
        """Update or create a technology profile."""
        key = f"{technology}:{framework}".lower()

        if key not in self._tech_profiles:
            self._tech_profiles[key] = TechnologyProfile(
                technology=technology,
                framework=framework,
            )

        profile = self._tech_profiles[key]
        profile.scan_count += 1
        profile.last_scanned = time.time()

        if vulnerabilities:
            profile.common_vulnerabilities = list(set(profile.common_vulnerabilities + vulnerabilities))
            profile.vuln_count += len(vulnerabilities)

        if effective_payloads:
            for cat, payloads in effective_payloads.items():
                existing = profile.effective_payloads.get(cat, [])
                profile.effective_payloads[cat] = list(set(existing + payloads))[:50]

        if waf_type:
            profile.waf_present = True
            profile.waf_type = waf_type

    def get_technology_profile(self, technology: str, framework: str = "") -> Optional[TechnologyProfile]:
        key = f"{technology}:{framework}".lower()
        return self._tech_profiles.get(key)

    # ── Target Profiles ───────────────────────────────────────────

    def update_target_profile(
        self,
        target: str,
        endpoints: Optional[List[str]] = None,
        vulnerabilities: Optional[List[str]] = None,
        risk_score: Optional[float] = None,
    ):
        """Update or create a target profile."""
        if target not in self._target_profiles:
            self._target_profiles[target] = TargetProfile(target=target)

        profile = self._target_profiles[target]
        profile.scan_count += 1
        profile.last_scanned = time.time()

        if endpoints:
            profile.known_endpoints = list(set(profile.known_endpoints + endpoints))
        if vulnerabilities:
            profile.known_vulnerabilities = list(set(profile.known_vulnerabilities + vulnerabilities))
        if risk_score is not None:
            profile.risk_trend.append({
                "timestamp": time.time(),
                "score": risk_score,
            })

    def get_target_profile(self, target: str) -> Optional[TargetProfile]:
        return self._target_profiles.get(target)

    # ── Scan History ──────────────────────────────────────────────

    def record_scan(self, intelligence: ScanIntelligence):
        """Record intelligence from a completed scan."""
        self._scan_history.append(intelligence)

        # Limit history
        if len(self._scan_history) > 1000:
            self._scan_history = self._scan_history[-1000:]

        # Auto-update target profile
        self.update_target_profile(
            target=intelligence.target,
            risk_score=sum(
                intelligence.severity_counts.get(s, 0) * w
                for s, w in [("critical", 10), ("high", 5), ("medium", 2), ("low", 1)]
            ),
        )

        # Auto-update tech profile
        for tech in intelligence.detected_technologies:
            self.update_technology_profile(
                technology=tech,
                framework=intelligence.detected_frameworks[0] if intelligence.detected_frameworks else "",
                vulnerabilities=list(intelligence.vulnerability_types.keys()),
            )

    # ── Cross-Scan Intelligence ───────────────────────────────────

    def get_similar_scans(self, target: str, technology: str = "", limit: int = 5) -> List[ScanIntelligence]:
        """Find similar past scans for context."""
        similar = []
        for scan in reversed(self._scan_history):
            if target in scan.target or technology in str(scan.detected_technologies):
                similar.append(scan)
            if len(similar) >= limit:
                break
        return similar

    def get_trending_vulnerabilities(self, days: int = 30) -> Dict[str, int]:
        """Get vulnerability types trending in recent scans."""
        cutoff = time.time() - (days * 86400)
        counts: Dict[str, int] = defaultdict(int)
        for scan in self._scan_history:
            if scan.timestamp >= cutoff:
                for vtype, count in scan.vulnerability_types.items():
                    counts[vtype] += count
        return dict(sorted(counts.items(), key=lambda x: x[1], reverse=True))

    # ── Persistence ───────────────────────────────────────────────

    def save(self):
        """Save memory state to disk."""
        try:
            state = {
                "version": "1.0",
                "created_at": self._created_at,
                "saved_at": time.time(),
                "patterns": {k: v.to_dict() for k, v in self._patterns.items()},
                "scan_history": [s.to_dict() for s in self._scan_history[-100:]],  # last 100 scans
                "tech_profiles": {k: v.to_dict() for k, v in self._tech_profiles.items()},
                "target_profiles": {k: v.to_dict() for k, v in self._target_profiles.items()},
                "payload_memory": dict(self._payload_memory),
                "waf_evasion_db": dict(self._waf_evasion_db),
            }

            memory_path = Path(self._memory_path)
            memory_path.parent.mkdir(parents=True, exist_ok=True)

            with open(memory_path, "w", encoding="utf-8") as f:
                json.dump(state, f, indent=2, default=str)

            self._last_saved = time.time()
            logger.info(f"Learning memory saved: {len(self._patterns)} patterns, "
                       f"{len(self._scan_history)} scans, {sum(len(v) for v in self._payload_memory.values())} payloads")

        except Exception as e:
            logger.warning(f"Failed to save learning memory: {e}")

    def _load(self):
        """Load memory state from disk."""
        try:
            memory_path = Path(self._memory_path)
            if not memory_path.exists():
                logger.info("No existing learning memory found — starting fresh.")
                return

            with open(memory_path, "r", encoding="utf-8") as f:
                state = json.load(f)

            # Restore patterns
            for pid, p_dict in state.get("patterns", {}).items():
                p_dict.pop("precision", None)
                self._patterns[pid] = PatternSignature(**{
                    k: v for k, v in p_dict.items()
                    if k in PatternSignature.__dataclass_fields__
                })

            # Restore payload memory
            for cat, payloads in state.get("payload_memory", {}).items():
                self._payload_memory[cat] = payloads

            # Restore WAF evasion DB
            for waf, techniques in state.get("waf_evasion_db", {}).items():
                self._waf_evasion_db[waf] = techniques

            # Restore tech profiles
            for key, tp_dict in state.get("tech_profiles", {}).items():
                self._tech_profiles[key] = TechnologyProfile(**{
                    k: v for k, v in tp_dict.items()
                    if k in TechnologyProfile.__dataclass_fields__
                })

            self._created_at = state.get("created_at", time.time())

            logger.info(f"Learning memory loaded: {len(self._patterns)} patterns, "
                       f"{sum(len(v) for v in self._payload_memory.values())} payloads")

        except Exception as e:
            logger.warning(f"Failed to load learning memory: {e}")

    # ── Statistics ────────────────────────────────────────────────

    def get_stats(self) -> Dict[str, Any]:
        return {
            "total_patterns": len(self._patterns),
            "total_scans": len(self._scan_history),
            "total_tech_profiles": len(self._tech_profiles),
            "total_target_profiles": len(self._target_profiles),
            "total_remembered_payloads": sum(len(v) for v in self._payload_memory.values()),
            "waf_types_known": len(self._waf_evasion_db),
            "high_precision_patterns": sum(1 for p in self._patterns.values() if p.precision >= 0.8),
            "created_at": self._created_at,
            "last_saved": self._last_saved,
        }

    def to_dict(self) -> Dict[str, Any]:
        return {
            "stats": self.get_stats(),
            "patterns": {k: v.to_dict() for k, v in self._patterns.items()},
            "tech_profiles": {k: v.to_dict() for k, v in self._tech_profiles.items()},
            "target_profiles": {k: v.to_dict() for k, v in self._target_profiles.items()},
            "trending_vulns": self.get_trending_vulnerabilities(),
        }


# ── Singleton ─────────────────────────────────────────────────────

_memory: Optional[ContinuousLearningMemory] = None


def get_learning_memory(memory_path: str = _DEFAULT_MEMORY_PATH) -> ContinuousLearningMemory:
    global _memory
    if _memory is None:
        _memory = ContinuousLearningMemory(memory_path)
    return _memory
