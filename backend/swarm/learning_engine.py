"""
Quantara Learning Engine
===========================
Feedback loop and heuristic optimization system.

Collects scan results and outcomes to:
    1. Update detection heuristics (adjust confidence thresholds)
    2. Optimize payload selection (promote effective payloads)
    3. Improve agent scheduling (prioritize high-yield agents)
    4. Track historical scan patterns for anomaly detection
    5. Generate strategy recommendations for future scans
"""

from __future__ import annotations

import logging
import time
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Set, Tuple

logger = logging.getLogger(__name__)


# ═══════════════════════════════════════════════════════════════════════════════
# Learning Records
# ═══════════════════════════════════════════════════════════════════════════════

@dataclass
class ScanOutcome:
    """Record of a completed scan for learning."""
    scan_id:          str
    target:           str
    total_findings:   int
    severity_counts:  Dict[str, int]
    agent_findings:   Dict[str, int]    # agent_name → finding_count
    agent_timings:    Dict[str, float]  # agent_name → elapsed_sec
    payload_success:  Dict[str, int]    # vector_type → success_count
    depth:            str = ""
    strategy:         str = ""
    risk_score:       float = 0.0
    chain_count:      int = 0
    elapsed_total:    float = 0.0
    timestamp:        str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())


@dataclass
class HeuristicUpdate:
    """A learned heuristic adjustment."""
    heuristic_id:  str
    agent:         str
    parameter:     str
    old_value:     float
    new_value:     float
    reason:        str
    confidence:    float = 0.0
    timestamp:     str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())


@dataclass
class StrategyRecommendation:
    """A strategy recommendation based on learning."""
    target_pattern:  str            # regex or domain pattern
    recommended_depth: str
    recommended_strategy: str
    priority_agents: List[str]
    skip_agents:     List[str]
    reason:          str
    confidence:      float = 0.0


# ═══════════════════════════════════════════════════════════════════════════════
# Learning Engine
# ═══════════════════════════════════════════════════════════════════════════════

class LearningEngine:
    """
    Feedback loop and heuristic optimization system.

    Maintains:
        - Historical scan outcomes
        - Agent performance profiles (yield rate, timing)
        - Payload effectiveness scores
        - Detection confidence calibration
        - Strategy recommendations
    """

    MAX_HISTORY = 100

    def __init__(self):
        self._scan_history:       List[ScanOutcome] = []
        self._heuristic_updates:  List[HeuristicUpdate] = []
        self._recommendations:    List[StrategyRecommendation] = []

        # ── Agent performance tracking ──
        self._agent_yield:        Dict[str, List[float]] = defaultdict(list)  # yield rates
        self._agent_avg_time:     Dict[str, List[float]] = defaultdict(list)  # timing history

        # ── Payload effectiveness ──
        self._payload_scores:     Dict[str, Dict[str, float]] = defaultdict(lambda: defaultdict(float))
        # vector_type → {payload_hash → cumulative_score}

        # ── Confidence calibration ──
        self._confidence_adjustments: Dict[str, float] = {}  # category → adjustment factor

        # ── Behavioral patterns ──
        self._target_patterns:    Dict[str, Dict[str, Any]] = {}
        # domain_pattern → {avg_findings, common_vulns, recommended_agents}

    # ── Record Scan Outcome ───────────────────────────────────────────────

    def record_outcome(self, outcome: ScanOutcome) -> List[HeuristicUpdate]:
        """
        Record a completed scan outcome and derive heuristic updates.
        Returns list of heuristic updates produced.
        """
        self._scan_history.append(outcome)
        if len(self._scan_history) > self.MAX_HISTORY:
            self._scan_history = self._scan_history[-self.MAX_HISTORY:]

        updates: List[HeuristicUpdate] = []

        # Update agent yield rates
        updates.extend(self._update_agent_profiles(outcome))

        # Update payload effectiveness
        updates.extend(self._update_payload_scores(outcome))

        # Update confidence calibration
        updates.extend(self._calibrate_confidence(outcome))

        # Update target patterns
        self._update_target_pattern(outcome)

        self._heuristic_updates.extend(updates)
        return updates

    # ── Agent Performance ─────────────────────────────────────────────────

    def _update_agent_profiles(self, outcome: ScanOutcome) -> List[HeuristicUpdate]:
        """Update agent yield rates and timing profiles."""
        updates = []

        for agent, count in outcome.agent_findings.items():
            # Yield rate = findings per scan
            self._agent_yield[agent].append(float(count))
            if len(self._agent_yield[agent]) > 50:
                self._agent_yield[agent] = self._agent_yield[agent][-50:]

        for agent, elapsed in outcome.agent_timings.items():
            self._agent_avg_time[agent].append(elapsed)
            if len(self._agent_avg_time[agent]) > 50:
                self._agent_avg_time[agent] = self._agent_avg_time[agent][-50:]

            # Detect agents that are consistently slow with low yield
            avg_yield = self._get_avg_yield(agent)
            avg_time = self._get_avg_time(agent)
            if avg_yield < 0.5 and avg_time > 15.0 and len(self._agent_yield[agent]) >= 5:
                updates.append(HeuristicUpdate(
                    heuristic_id=f"agent-deprioritize-{agent}",
                    agent=agent,
                    parameter="priority",
                    old_value=1.0,
                    new_value=0.5,
                    reason=(
                        f"{agent} averages {avg_yield:.1f} findings in {avg_time:.1f}s. "
                        f"Consider deprioritizing for standard scans."
                    ),
                    confidence=0.7,
                ))

            # Detect high-yield agents to promote
            if avg_yield > 3.0 and len(self._agent_yield[agent]) >= 3:
                updates.append(HeuristicUpdate(
                    heuristic_id=f"agent-promote-{agent}",
                    agent=agent,
                    parameter="priority",
                    old_value=1.0,
                    new_value=1.5,
                    reason=(
                        f"{agent} averages {avg_yield:.1f} findings — high-yield agent."
                    ),
                    confidence=0.8,
                ))

        return updates

    def _get_avg_yield(self, agent: str) -> float:
        yields = self._agent_yield.get(agent, [])
        return sum(yields) / len(yields) if yields else 0.0

    def _get_avg_time(self, agent: str) -> float:
        times = self._agent_avg_time.get(agent, [])
        return sum(times) / len(times) if times else 0.0

    # ── Payload Effectiveness ─────────────────────────────────────────────

    def _update_payload_scores(self, outcome: ScanOutcome) -> List[HeuristicUpdate]:
        """Track which payload types are most effective."""
        updates = []
        for vector_type, success_count in outcome.payload_success.items():
            score = float(success_count)
            self._payload_scores[vector_type]["cumulative"] += score
            self._payload_scores[vector_type]["attempts"] += 1

            effectiveness = (
                self._payload_scores[vector_type]["cumulative"]
                / max(1, self._payload_scores[vector_type]["attempts"])
            )

            if effectiveness > 2.0:
                updates.append(HeuristicUpdate(
                    heuristic_id=f"payload-boost-{vector_type}",
                    agent="PayloadEvolution",
                    parameter=f"{vector_type}_population_size",
                    old_value=40.0,
                    new_value=60.0,
                    reason=f"{vector_type} payloads have high effectiveness ({effectiveness:.1f}). Expand population.",
                    confidence=0.75,
                ))

        return updates

    # ── Confidence Calibration ────────────────────────────────────────────

    def _calibrate_confidence(self, outcome: ScanOutcome) -> List[HeuristicUpdate]:
        """Adjust confidence thresholds based on false positive patterns."""
        updates = []

        # If a scan found many medium findings but no high/critical,
        # the confidence thresholds may be too generous
        sev = outcome.severity_counts
        if sev.get("medium", 0) > 10 and sev.get("critical", 0) == 0 and sev.get("high", 0) == 0:
            updates.append(HeuristicUpdate(
                heuristic_id="confidence-tighten-medium",
                agent="global",
                parameter="medium_confidence_threshold",
                old_value=0.75,
                new_value=0.82,
                reason=(
                    f"Scan produced {sev.get('medium', 0)} medium findings with no high/critical. "
                    f"Tightening confidence threshold to reduce potential false positives."
                ),
                confidence=0.6,
            ))

        return updates

    # ── Target Pattern Learning ───────────────────────────────────────────

    def _update_target_pattern(self, outcome: ScanOutcome) -> None:
        """Learn patterns about target domains."""
        from urllib.parse import urlparse
        parsed = urlparse(outcome.target)
        domain = parsed.hostname or outcome.target

        # Extract TLD pattern (e.g., "*.example.com")
        parts = domain.split(".")
        pattern = f"*.{'.'.join(parts[-2:])}" if len(parts) >= 2 else domain

        if pattern not in self._target_patterns:
            self._target_patterns[pattern] = {
                "scan_count": 0,
                "avg_findings": 0,
                "common_agents": defaultdict(int),
                "common_categories": defaultdict(int),
            }

        tp = self._target_patterns[pattern]
        tp["scan_count"] += 1
        n = tp["scan_count"]
        tp["avg_findings"] = (tp["avg_findings"] * (n - 1) + outcome.total_findings) / n

        for agent, count in outcome.agent_findings.items():
            if count > 0:
                tp["common_agents"][agent] += 1

        # Build recommendation if we have enough data
        if tp["scan_count"] >= 3:
            # Identify top-yielding agents for this target pattern
            top_agents = sorted(
                tp["common_agents"].items(), key=lambda x: x[1], reverse=True
            )[:6]
            priority = [a for a, _ in top_agents]

            self._recommendations = [
                r for r in self._recommendations
                if r.target_pattern != pattern
            ]
            self._recommendations.append(StrategyRecommendation(
                target_pattern=pattern,
                recommended_depth="deep" if tp["avg_findings"] > 5 else "standard",
                recommended_strategy="autonomous",
                priority_agents=priority,
                skip_agents=[],
                reason=f"Based on {tp['scan_count']} historical scans, avg {tp['avg_findings']:.0f} findings",
                confidence=min(0.9, 0.5 + tp["scan_count"] * 0.1),
            ))

    # ── Query Interface ───────────────────────────────────────────────────

    def get_agent_performance(self) -> Dict[str, Dict[str, float]]:
        """Get performance summary for all agents."""
        result = {}
        all_agents = set(list(self._agent_yield.keys()) + list(self._agent_avg_time.keys()))
        for agent in all_agents:
            result[agent] = {
                "avg_yield": round(self._get_avg_yield(agent), 2),
                "avg_time":  round(self._get_avg_time(agent), 2),
                "samples":   len(self._agent_yield.get(agent, [])),
            }
        return result

    def get_recommendations(self, target: str = "") -> List[Dict]:
        """Get strategy recommendations, optionally filtered by target."""
        results = self._recommendations
        if target:
            from urllib.parse import urlparse
            parsed = urlparse(target)
            domain = parsed.hostname or target
            results = [r for r in results if domain.endswith(r.target_pattern.lstrip("*."))]

        return [
            {
                "target_pattern":       r.target_pattern,
                "recommended_depth":    r.recommended_depth,
                "recommended_strategy": r.recommended_strategy,
                "priority_agents":      r.priority_agents,
                "reason":               r.reason,
                "confidence":           round(r.confidence, 2),
            }
            for r in results
        ]

    def get_heuristic_updates(self, limit: int = 50) -> List[Dict]:
        return [
            {
                "heuristic_id": h.heuristic_id,
                "agent":        h.agent,
                "parameter":    h.parameter,
                "old_value":    h.old_value,
                "new_value":    h.new_value,
                "reason":       h.reason,
                "confidence":   h.confidence,
                "timestamp":    h.timestamp,
            }
            for h in self._heuristic_updates[-limit:]
        ]

    def get_payload_effectiveness(self) -> Dict[str, float]:
        """Get payload effectiveness by vector type."""
        result = {}
        for vtype, scores in self._payload_scores.items():
            attempts = max(1, scores.get("attempts", 1))
            result[vtype] = round(scores.get("cumulative", 0) / attempts, 2)
        return result

    def get_scan_history_summary(self) -> Dict[str, Any]:
        """Get summary of historical scan outcomes."""
        if not self._scan_history:
            return {"total_scans": 0}
        return {
            "total_scans":     len(self._scan_history),
            "avg_findings":    round(
                sum(s.total_findings for s in self._scan_history) / len(self._scan_history), 1
            ),
            "avg_risk_score":  round(
                sum(s.risk_score for s in self._scan_history) / len(self._scan_history), 1
            ),
            "total_chains":    sum(s.chain_count for s in self._scan_history),
            "agent_performance": self.get_agent_performance(),
        }

    def reset(self) -> None:
        self._scan_history.clear()
        self._heuristic_updates.clear()
        self._recommendations.clear()
        self._agent_yield.clear()
        self._agent_avg_time.clear()
        self._payload_scores.clear()
        self._confidence_adjustments.clear()
        self._target_patterns.clear()
