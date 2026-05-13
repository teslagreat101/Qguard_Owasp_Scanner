"""
Quantara Base Swarm Agent
============================
Enhanced BaseAgent class with MessageBus pub/sub, SharedState integration,
and telemetry emission. All specialized agents inherit from this class.
"""

from __future__ import annotations

import asyncio
import logging
import time
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Callable, Dict, List, Optional

logger = logging.getLogger(__name__)


class BaseSwarmAgent:
    """
    Enhanced base class for all swarm intelligence agents.

    Provides:
        - Message bus topic subscription and publishing
        - Shared intelligence state read/write
        - Telemetry event emission
        - Lifecycle management (start, execute, stop)
        - Task queue processing
    """

    def __init__(
        self,
        name: str,
        role: str,
        message_bus: Any = None,       # MessageBus instance
        shared_state: Any = None,      # SharedIntelligenceState instance
        emitter: Any = None,           # SwarmTelemetryEmitter (legacy bridge)
    ):
        self.name = name
        self.role = role
        self.bus = message_bus
        self.state = shared_state
        self.emitter = emitter

        self.is_active = False
        self.start_time = 0.0
        self.findings: List[Dict] = []
        self._sub_ids: List[str] = []
        self._task_queue: asyncio.Queue = asyncio.Queue(maxsize=100)

    # ── Lifecycle ─────────────────────────────────────────────────────────

    async def initialize(self) -> None:
        """Initialize agent: subscribe to relevant topics."""
        if self.bus:
            self._register_subscriptions()
        logger.debug(f"[{self.name}] Initialized")

    def _register_subscriptions(self) -> None:
        """Override in subclass to subscribe to relevant message bus topics."""
        pass

    async def shutdown(self) -> None:
        """Clean shutdown: unsubscribe from all topics."""
        if self.bus:
            self.bus.unsubscribe_all(self.name)
        self._sub_ids.clear()
        self.is_active = False

    # ── Execution ─────────────────────────────────────────────────────────

    async def execute(
        self,
        target: str,
        scan_id: str,
        context: Optional[Dict[str, Any]] = None,
    ) -> List[Dict]:
        """
        Execute the agent's analysis task.
        Handles lifecycle events and error recovery.
        """
        self.is_active = True
        self.start_time = time.time()
        self.findings = []
        context = context or {}

        # Emit start event
        await self._emit_event("AGENT_STARTED", scan_id, {
            "agent": self.name,
            "role": self.role,
            "target": target,
        })

        try:
            results = await self._run(target, scan_id, context)

            # Store findings in shared state
            if self.state:
                for finding in results:
                    if isinstance(finding, dict):
                        await self.state.add_vulnerability(finding)
                        self.findings.append(finding)

            elapsed = round(time.time() - self.start_time, 2)

            # Record timing
            if self.state:
                await self.state.record_agent_timing(self.name, elapsed)

            await self._emit_event("AGENT_COMPLETED", scan_id, {
                "agent": self.name,
                "role": self.role,
                "findings_count": len(results),
                "elapsed_seconds": elapsed,
            })

            return results

        except Exception as exc:
            logger.error(f"[{self.name}] Error: {exc}", exc_info=True)
            await self._emit_event("AGENT_ERROR", scan_id, {
                "agent": self.name,
                "error": str(exc)[:200],
            })
            return []
        finally:
            self.is_active = False

    async def _run(
        self, target: str, scan_id: str, context: Dict
    ) -> List[Dict]:
        """
        Core analysis logic — override in subclass.
        Returns list of finding dicts.
        """
        raise NotImplementedError(f"{self.name} must implement _run()")

    # ── Message Bus Helpers ───────────────────────────────────────────────

    def _subscribe(self, topic: str, handler: Callable) -> str:
        """Subscribe to a message bus topic."""
        if not self.bus:
            return ""
        sub_id = self.bus.subscribe(
            topic=topic, handler=handler,
            source=self.name,
        )
        self._sub_ids.append(sub_id)
        return sub_id

    async def _publish(self, event_type: str, scan_id: str,
                        data: Dict = None, priority: int = 0) -> None:
        """Publish an event to the message bus."""
        if not self.bus:
            return
        event = self.bus.create_event(
            event_type=event_type,
            scan_id=scan_id,
            source=self.name,
            data=data or {},
            priority=priority,
        )
        await self.bus.publish(event)

    # ── Telemetry Emission ────────────────────────────────────────────────

    async def _emit_event(self, event_type: str, scan_id: str,
                           data: Dict = None) -> None:
        """Emit a telemetry event via both bus and legacy emitter."""
        # Message bus
        if self.bus:
            await self._publish(event_type, scan_id, data)

        # Legacy emitter bridge (for SSE streaming compatibility)
        if self.emitter:
            await self.emitter.emit(
                event_type.lower(), data or {}, scan_id
            )

    async def _emit_finding(self, scan_id: str, finding: Dict) -> None:
        """Emit a finding event and store in shared state."""
        if self.emitter:
            self.emitter.add_finding(finding)
            await self.emitter.emit("vulnerability_detected", finding, scan_id)

        if self.bus:
            await self._publish("VULNERABILITY_DETECTED", scan_id, finding, priority=5)

        if self.state:
            await self.state.add_vulnerability(finding)

    # ── Finding Factory ───────────────────────────────────────────────────

    def _make_finding_dict(self, **kwargs) -> Dict[str, Any]:
        """Create a standardized finding dict."""
        finding_id = str(uuid.uuid4())
        return {
            "id":              finding_id,
            "node_name":       self.name,
            "module_name":     self.name,
            "module":          self.name,
            "title":           kwargs.get("title", ""),
            "description":     kwargs.get("description", ""),
            "severity":        kwargs.get("severity", "info"),
            "endpoint":        kwargs.get("endpoint", ""),
            "file":            kwargs.get("endpoint", ""),
            "confidence":      kwargs.get("confidence", 0.0),
            "cwe":             kwargs.get("cwe", ""),
            "owasp":           kwargs.get("owasp", ""),
            "category":        kwargs.get("category", ""),
            "evidence":        kwargs.get("evidence", {}),
            "remediation":     kwargs.get("remediation", ""),
            "exploit_payload": kwargs.get("exploit_payload", ""),
            "matched_content": kwargs.get("matched_content", ""),
            "timestamp":       datetime.now(timezone.utc).isoformat(),
            "tags":            [self.name, kwargs.get("category", "")],
            "line_number":     0,
        }

    # ── Graph Helpers ─────────────────────────────────────────────────────

    def _add_graph_node(self, node_id: str, label: str,
                         node_type: str, risk: str,
                         status: str = "active") -> None:
        """Add a node to the attack graph via the emitter."""
        if self.emitter:
            self.emitter.add_graph_node({
                "id": node_id,
                "label": label,
                "type": node_type,
                "risk": risk,
                "status": status,
            })

    def _add_graph_edge(self, source: str, target: str,
                         edge_type: str = "exploit",
                         active: bool = True) -> None:
        """Add an edge to the attack graph via the emitter."""
        if self.emitter:
            self.emitter.add_graph_edge({
                "source": source,
                "target": target,
                "type": edge_type,
                "active": active,
            })

    def _add_vuln_graph_node(self, vuln_id: str, label: str,
                              severity: str, endpoint: str) -> None:
        """Convenience: add a vulnerability node + edge from endpoint."""
        self._add_graph_node(vuln_id, label, "vulnerability", severity, "compromised")
        ep_id = "ep-" + endpoint.split("?")[0].replace("/", "-").strip("-")[:40]
        self._add_graph_edge(ep_id, vuln_id, "exploit", True)
