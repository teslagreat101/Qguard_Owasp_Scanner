"""
Learning Agent — Scan Result Collection & Heuristic Improvement
=================================================================
Collects results from all agents, analyzes patterns, and feeds
improvements back into the swarm intelligence system.
"""

from __future__ import annotations

import asyncio
import logging
import uuid
from collections import defaultdict
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)


class LearningAgent:
    """
    Learning agent that analyzes completed scan results and produces
    actionable intelligence for improving future scans.
    """

    def __init__(self, emitter=None, message_bus=None, shared_state=None,
                 learning_engine=None):
        self.name = "Learning-AI"
        self.role = "Heuristic Optimization Engine"
        self.emitter = emitter
        self.bus = message_bus
        self.state = shared_state
        self.learning_engine = learning_engine
        self.is_active = False

    async def execute(self, target: str, scan_id: str,
                       context: Dict = None) -> List[Dict]:
        self.is_active = True
        context = context or {}
        findings: List[Dict] = []

        try:
            if self.emitter:
                await self.emitter.emit("node_started", {
                    "node": self.name, "role": self.role, "target": target,
                }, scan_id)

            all_findings = context.get("all_findings", [])

            # Phase 1: Analyze agent performance
            agent_analysis = await self._analyze_agent_performance(
                all_findings, context, scan_id
            )

            # Phase 2: Detect finding patterns
            pattern_analysis = await self._detect_patterns(
                all_findings, scan_id
            )

            # Phase 3: Generate optimization recommendations
            recommendations = await self._generate_recommendations(
                agent_analysis, pattern_analysis, context, scan_id
            )

            # Phase 4: Feed into learning engine
            if self.learning_engine:
                from backend.swarm.learning_engine import ScanOutcome
                outcome = ScanOutcome(
                    scan_id=scan_id,
                    target=target,
                    total_findings=len(all_findings),
                    severity_counts=self._count_severities(all_findings),
                    agent_findings=self._count_by_agent(all_findings),
                    agent_timings=context.get("agent_timings", {}),
                    payload_success=self._count_payload_success(all_findings),
                    depth=context.get("depth", ""),
                    strategy=context.get("strategy", ""),
                    risk_score=context.get("risk_score", 0),
                    chain_count=len(context.get("attack_chains", [])),
                )
                updates = self.learning_engine.record_outcome(outcome)

                for update in updates:
                    if self.emitter:
                        await self.emitter.emit("heuristic_updated", {
                            "node": self.name,
                            "heuristic": update.heuristic_id,
                            "parameter": update.parameter,
                            "reason": update.reason,
                            "message": f"Learning-AI: {update.reason}",
                        }, scan_id)

            if self.emitter:
                await self.emitter.emit("node_completed", {
                    "node": self.name,
                    "findings_count": len(findings),
                    "recommendations": len(recommendations),
                    "message": (
                        f"Learning-AI: analyzed {len(all_findings)} findings, "
                        f"generated {len(recommendations)} optimization recommendations"
                    ),
                }, scan_id)

        except Exception as exc:
            logger.error(f"[{self.name}] Error: {exc}", exc_info=True)
        finally:
            self.is_active = False

        return findings

    async def _analyze_agent_performance(
        self, all_findings: List, context: Dict, scan_id: str
    ) -> Dict[str, Any]:
        """Analyze which agents produced the most valuable findings."""
        agent_stats: Dict[str, Dict] = defaultdict(lambda: {
            "count": 0, "critical": 0, "high": 0, "medium": 0, "low": 0,
        })

        for f in all_findings:
            agent = f.node_name if hasattr(f, "node_name") else f.get("node_name", "")
            sev = (f.severity if hasattr(f, "severity") else f.get("severity", "info")).lower()
            agent_stats[agent]["count"] += 1
            if sev in agent_stats[agent]:
                agent_stats[agent][sev] += 1

        # Log analysis
        if self.emitter:
            top_agents = sorted(
                agent_stats.items(),
                key=lambda x: x[1]["critical"] * 10 + x[1]["high"] * 5 + x[1]["count"],
                reverse=True
            )[:5]
            for agent, stats in top_agents:
                await self.emitter.emit("learning.events", {
                    "node": self.name,
                    "agent": agent,
                    "stats": stats,
                    "message": (
                        f"Agent performance: {agent} — "
                        f"{stats['count']} findings "
                        f"(C:{stats['critical']} H:{stats['high']} M:{stats['medium']})"
                    ),
                }, scan_id)
                await asyncio.sleep(0.02)

        return dict(agent_stats)

    async def _detect_patterns(self, all_findings: List,
                                 scan_id: str) -> Dict[str, Any]:
        """Detect patterns in findings (repeated categories, endpoints)."""
        category_counts: Dict[str, int] = defaultdict(int)
        endpoint_counts: Dict[str, int] = defaultdict(int)
        cwe_counts: Dict[str, int] = defaultdict(int)

        for f in all_findings:
            cat = f.category if hasattr(f, "category") else f.get("category", "")
            ep = f.endpoint if hasattr(f, "endpoint") else f.get("endpoint", "")
            cwe = f.cwe if hasattr(f, "cwe") else f.get("cwe", "")
            if cat:
                category_counts[cat] += 1
            if ep:
                # Normalize endpoint
                ep_base = ep.split("?")[0]
                endpoint_counts[ep_base] += 1
            if cwe:
                cwe_counts[cwe] += 1

        # Find hotspots (endpoints with 3+ findings)
        hotspots = {ep: count for ep, count in endpoint_counts.items() if count >= 3}

        if hotspots and self.emitter:
            await self.emitter.emit("learning.events", {
                "node": self.name,
                "message": (
                    f"Vulnerability hotspots detected: {len(hotspots)} endpoints "
                    f"with 3+ findings each"
                ),
                "hotspots": list(hotspots.keys())[:5],
            }, scan_id)

        return {
            "category_counts": dict(category_counts),
            "hotspots": hotspots,
            "top_cwes": dict(sorted(cwe_counts.items(), key=lambda x: x[1], reverse=True)[:10]),
        }

    async def _generate_recommendations(
        self, agent_analysis: Dict, pattern_analysis: Dict,
        context: Dict, scan_id: str
    ) -> List[Dict]:
        """Generate optimization recommendations."""
        recommendations = []

        # Rec 1: If no critical findings, suggest deeper scan
        sev_counts = self._count_severities(context.get("all_findings", []))
        if sev_counts["critical"] == 0 and context.get("depth") != "deep":
            recommendations.append({
                "type": "depth_increase",
                "recommendation": "Consider running a deep scan for more thorough coverage",
                "reason": "No critical findings detected in standard scan",
                "confidence": 0.6,
            })

        # Rec 2: If hotspots found, suggest focused re-scan
        hotspots = pattern_analysis.get("hotspots", {})
        if hotspots:
            recommendations.append({
                "type": "focused_rescan",
                "recommendation": f"Focus re-scan on {len(hotspots)} vulnerability hotspots",
                "reason": f"Multiple findings concentrated at: {list(hotspots.keys())[:3]}",
                "confidence": 0.8,
            })

        # Rec 3: Agent efficiency
        for agent, stats in agent_analysis.items():
            if stats["count"] == 0:
                recommendations.append({
                    "type": "agent_review",
                    "recommendation": f"Review {agent} effectiveness — produced 0 findings",
                    "reason": "Zero-yield agent may indicate target incompatibility or scan configuration issue",
                    "confidence": 0.5,
                })

        return recommendations

    @staticmethod
    def _count_severities(findings: List) -> Dict[str, int]:
        counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
        for f in findings:
            sev = (f.severity if hasattr(f, "severity") else f.get("severity", "info")).lower()
            if sev in counts:
                counts[sev] += 1
        return counts

    @staticmethod
    def _count_by_agent(findings: List) -> Dict[str, int]:
        counts: Dict[str, int] = defaultdict(int)
        for f in findings:
            agent = f.node_name if hasattr(f, "node_name") else f.get("node_name", "")
            counts[agent] += 1
        return dict(counts)

    @staticmethod
    def _count_payload_success(findings: List) -> Dict[str, int]:
        counts: Dict[str, int] = defaultdict(int)
        for f in findings:
            cat = (f.category if hasattr(f, "category") else f.get("category", "")).lower()
            if "sql" in cat:
                counts["sqli"] += 1
            elif "xss" in cat or "cross-site" in cat:
                counts["xss"] += 1
            elif "command" in cat or "rce" in cat:
                counts["cmdi"] += 1
            elif "traversal" in cat or "lfi" in cat:
                counts["lfi"] += 1
            elif "ssrf" in cat:
                counts["ssrf"] += 1
        return dict(counts)
