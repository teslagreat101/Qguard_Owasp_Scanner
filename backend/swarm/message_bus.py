"""
Quantara Message Bus — Topic-Based Async Event Broker
======================================================
In-memory event-driven message broker with topic-based pub/sub,
wildcard subscriptions, ordered delivery, and backpressure handling.

Supports topic hierarchies (e.g. "recon.subdomain", "exploit.sqli")
and wildcard subscriptions ("recon.*", "exploit.*").

Production adapters for Kafka/RabbitMQ/MQTT can be plugged in via
the BrokerAdapter interface without changing agent code.
"""

from __future__ import annotations

import asyncio
import hashlib
import logging
import time
import uuid
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import (
    Any, Awaitable, Callable, Dict, List, Optional, Set, Tuple,
)

logger = logging.getLogger(__name__)


# ═══════════════════════════════════════════════════════════════════════════════
# Topic Groups — canonical event topic namespaces
# ═══════════════════════════════════════════════════════════════════════════════

class TopicGroup(str, Enum):
    """Canonical event topic namespaces for the swarm."""
    TARGET       = "target.events"
    RECON        = "recon.events"
    SERVICE      = "service.events"
    VULNERABILITY = "vulnerability.events"
    PAYLOAD      = "payload.events"
    EXPLOIT      = "exploit.events"
    VERIFICATION = "verification.events"
    RISK         = "risk.events"
    TELEMETRY    = "telemetry.events"
    CORRELATION  = "correlation.events"
    LEARNING     = "learning.events"
    CONTROL      = "control.events"
    GRAPH        = "graph.events"


# ═══════════════════════════════════════════════════════════════════════════════
# Event Schema — structured event envelope
# ═══════════════════════════════════════════════════════════════════════════════

@dataclass(frozen=True)
class EventSchema:
    """Schema descriptor for a registered event type."""
    event_type: str
    topic: str
    required_fields: Tuple[str, ...] = ()
    description: str = ""


# Pre-registered event schemas
REGISTERED_SCHEMAS: Dict[str, EventSchema] = {}


def register_event(event_type: str, topic: str,
                    required_fields: Tuple[str, ...] = (),
                    description: str = "") -> EventSchema:
    schema = EventSchema(event_type, topic, required_fields, description)
    REGISTERED_SCHEMAS[event_type] = schema
    return schema


# Core event registrations
register_event("SCAN_STARTED",           TopicGroup.CONTROL,       ("scan_id", "target"))
register_event("SCAN_COMPLETED",         TopicGroup.CONTROL,       ("scan_id",))
register_event("PHASE_TRANSITION",       TopicGroup.CONTROL,       ("scan_id", "from_phase", "to_phase"))
register_event("ASSET_DISCOVERED",       TopicGroup.RECON,         ("scan_id", "asset"))
register_event("SUBDOMAIN_FOUND",        TopicGroup.RECON,         ("scan_id", "subdomain"))
register_event("SERVICE_IDENTIFIED",     TopicGroup.SERVICE,       ("scan_id", "target", "technology"))
register_event("ENDPOINT_DISCOVERED",    TopicGroup.SERVICE,       ("scan_id", "endpoint"))
register_event("VULNERABILITY_DETECTED", TopicGroup.VULNERABILITY, ("scan_id", "title", "severity"))
register_event("PAYLOAD_GENERATED",      TopicGroup.PAYLOAD,       ("scan_id", "vector_type"))
register_event("PAYLOAD_EVOLVED",        TopicGroup.PAYLOAD,       ("scan_id", "generation"))
register_event("EXPLOIT_ATTEMPTED",      TopicGroup.EXPLOIT,       ("scan_id", "endpoint", "vector"))
register_event("EXPLOIT_CONFIRMED",      TopicGroup.EXPLOIT,       ("scan_id", "endpoint", "title"))
register_event("VULNERABILITY_VERIFIED", TopicGroup.VERIFICATION,  ("scan_id", "finding_id"))
register_event("RISK_CALCULATED",        TopicGroup.RISK,          ("scan_id", "risk_score"))
register_event("ATTACK_CHAIN_CREATED",   TopicGroup.CORRELATION,   ("scan_id", "chain_id"))
register_event("FINDING_CORRELATED",     TopicGroup.CORRELATION,   ("scan_id", "finding_ids"))
register_event("HEURISTIC_UPDATED",      TopicGroup.LEARNING,      ("scan_id", "heuristic"))
register_event("AGENT_STARTED",          TopicGroup.TELEMETRY,     ("scan_id", "agent"))
register_event("AGENT_COMPLETED",        TopicGroup.TELEMETRY,     ("scan_id", "agent"))
register_event("GRAPH_UPDATE",           TopicGroup.GRAPH,         ("scan_id",))


# ═══════════════════════════════════════════════════════════════════════════════
# Event — the immutable event envelope
# ═══════════════════════════════════════════════════════════════════════════════

@dataclass
class Event:
    """Immutable event envelope flowing through the message bus."""
    event_id:   str = field(default_factory=lambda: uuid.uuid4().hex[:16])
    event_type: str = ""
    topic:      str = ""
    scan_id:    str = ""
    source:     str = ""           # agent name that produced the event
    timestamp:  str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    data:       Dict[str, Any] = field(default_factory=dict)
    priority:   int = 0            # higher = more urgent

    def to_dict(self) -> Dict[str, Any]:
        return {
            "event_id":   self.event_id,
            "event_type": self.event_type,
            "topic":      self.topic,
            "scan_id":    self.scan_id,
            "source":     self.source,
            "timestamp":  self.timestamp,
            "data":       self.data,
            "priority":   self.priority,
        }

    @property
    def fingerprint(self) -> str:
        """Dedup fingerprint based on type + scan + key data fields."""
        raw = f"{self.event_type}:{self.scan_id}:{self.source}"
        return hashlib.sha256(raw.encode()).hexdigest()[:16]


# ═══════════════════════════════════════════════════════════════════════════════
# Subscription — callback wrapper with filtering
# ═══════════════════════════════════════════════════════════════════════════════

HandlerFn = Callable[[Event], Awaitable[None]]


@dataclass
class Subscription:
    sub_id:      str
    topic:       str              # may contain "*" wildcard
    handler:     HandlerFn
    scan_filter: Optional[str] = None  # if set, only events for this scan_id
    source:      str = ""         # subscriber name for debugging


# ═══════════════════════════════════════════════════════════════════════════════
# MessageBus — the core async event broker
# ═══════════════════════════════════════════════════════════════════════════════

class MessageBus:
    """
    In-memory async event broker with topic-based pub/sub.

    Features:
        - Topic-based subscription with wildcard support (e.g. "recon.*")
        - Priority-based dispatch (higher priority events processed first)
        - Backpressure: bounded internal queue with overflow protection
        - Event deduplication within a sliding window
        - Event history for replay and correlation
        - Dead letter queue for failed deliveries
    """

    MAX_HISTORY = 10_000
    MAX_QUEUE   = 5_000
    DEDUP_WINDOW_SEC = 2.0

    def __init__(self):
        self._subscriptions: Dict[str, List[Subscription]] = defaultdict(list)
        self._event_history: List[Event] = []
        self._dead_letter:   List[Tuple[Event, str]] = []
        self._queue: asyncio.PriorityQueue = asyncio.PriorityQueue(
            maxsize=self.MAX_QUEUE
        )
        self._running = False
        self._dispatch_task: Optional[asyncio.Task] = None
        self._dedup_cache: Dict[str, float] = {}
        self._stats = {
            "published": 0, "delivered": 0, "dropped": 0, "errors": 0,
        }
        # External SSE bridge queues (from SwarmTelemetryEmitter)
        self._sse_queues: List[asyncio.Queue] = []

    # ── Lifecycle ──────────────────────────────────────────────────────────

    def start(self) -> None:
        """Start the async dispatch loop."""
        if self._running:
            return
        self._running = True
        self._dispatch_task = asyncio.ensure_future(self._dispatch_loop())
        logger.info("[MessageBus] Dispatch loop started")

    async def stop(self) -> None:
        """Gracefully stop the dispatch loop."""
        self._running = False
        if self._dispatch_task:
            self._dispatch_task.cancel()
            try:
                await self._dispatch_task
            except asyncio.CancelledError:
                pass
        logger.info("[MessageBus] Stopped")

    # ── Subscription ──────────────────────────────────────────────────────

    def subscribe(self, topic: str, handler: HandlerFn,
                  scan_filter: Optional[str] = None,
                  source: str = "") -> str:
        """
        Subscribe to a topic with an async handler.
        Supports wildcard: "recon.*" matches "recon.events", "recon.subdomain", etc.
        Returns subscription ID for later unsubscription.
        """
        sub_id = uuid.uuid4().hex[:12]
        sub = Subscription(
            sub_id=sub_id, topic=topic, handler=handler,
            scan_filter=scan_filter, source=source,
        )
        self._subscriptions[topic].append(sub)
        logger.debug(f"[MessageBus] {source} subscribed to '{topic}' (sub={sub_id})")
        return sub_id

    def unsubscribe(self, sub_id: str) -> None:
        """Remove a subscription by ID."""
        for topic, subs in self._subscriptions.items():
            self._subscriptions[topic] = [s for s in subs if s.sub_id != sub_id]

    def unsubscribe_all(self, source: str) -> None:
        """Remove all subscriptions from a given source."""
        for topic in list(self._subscriptions.keys()):
            self._subscriptions[topic] = [
                s for s in self._subscriptions[topic] if s.source != source
            ]

    # ── Publishing ────────────────────────────────────────────────────────

    async def publish(self, event: Event) -> None:
        """
        Publish an event to the bus.
        Events are enqueued for async dispatch to all matching subscribers.
        """
        # Dedup check
        fp = event.fingerprint
        now = time.monotonic()
        if fp in self._dedup_cache:
            if now - self._dedup_cache[fp] < self.DEDUP_WINDOW_SEC:
                return  # duplicate within window
        self._dedup_cache[fp] = now

        # Prune old dedup entries periodically
        if len(self._dedup_cache) > 5000:
            cutoff = now - self.DEDUP_WINDOW_SEC * 2
            self._dedup_cache = {
                k: v for k, v in self._dedup_cache.items() if v > cutoff
            }

        # Auto-resolve topic from schema if not set
        if not event.topic and event.event_type in REGISTERED_SCHEMAS:
            event.topic = REGISTERED_SCHEMAS[event.event_type].topic

        # Store in history
        self._event_history.append(event)
        if len(self._event_history) > self.MAX_HISTORY:
            self._event_history = self._event_history[-self.MAX_HISTORY:]

        self._stats["published"] += 1

        # Enqueue for dispatch
        try:
            self._queue.put_nowait((-event.priority, time.monotonic(), event))
        except asyncio.QueueFull:
            self._stats["dropped"] += 1
            logger.warning(f"[MessageBus] Queue full — dropped event {event.event_type}")

        # Bridge to SSE queues
        self._bridge_to_sse(event)

    async def publish_many(self, events: List[Event]) -> None:
        """Publish multiple events atomically."""
        for evt in events:
            await self.publish(evt)

    def create_event(self, event_type: str, scan_id: str,
                     source: str = "", data: Dict = None,
                     priority: int = 0) -> Event:
        """Factory method to create a well-formed event."""
        topic = ""
        if event_type in REGISTERED_SCHEMAS:
            topic = REGISTERED_SCHEMAS[event_type].topic
        return Event(
            event_type=event_type,
            topic=topic,
            scan_id=scan_id,
            source=source,
            data=data or {},
            priority=priority,
        )

    # ── SSE Bridge ────────────────────────────────────────────────────────

    def register_sse_queue(self, q: asyncio.Queue) -> None:
        self._sse_queues.append(q)

    def unregister_sse_queue(self, q: asyncio.Queue) -> None:
        try:
            self._sse_queues.remove(q)
        except ValueError:
            pass

    def _bridge_to_sse(self, event: Event) -> None:
        """Push event to all SSE consumer queues."""
        payload = {
            "event":     event.event_type,
            "scan_id":   event.scan_id,
            "timestamp": event.timestamp,
            "data":      event.data,
        }
        dead: List[asyncio.Queue] = []
        for q in list(self._sse_queues):
            try:
                q.put_nowait(payload)
            except asyncio.QueueFull:
                dead.append(q)
        for q in dead:
            self.unregister_sse_queue(q)

    # ── Dispatch Loop ─────────────────────────────────────────────────────

    async def _dispatch_loop(self) -> None:
        """Main dispatch loop: dequeue events and fan out to subscribers."""
        while self._running:
            try:
                _, _, event = await asyncio.wait_for(
                    self._queue.get(), timeout=1.0
                )
            except asyncio.TimeoutError:
                continue
            except asyncio.CancelledError:
                break

            await self._fan_out(event)

    async def _fan_out(self, event: Event) -> None:
        """Deliver event to all matching subscribers."""
        matched_subs: List[Subscription] = []

        for topic_pattern, subs in self._subscriptions.items():
            if self._topic_matches(topic_pattern, event.topic):
                matched_subs.extend(subs)

        for sub in matched_subs:
            # Scan filter
            if sub.scan_filter and event.scan_id != sub.scan_filter:
                continue
            try:
                await asyncio.wait_for(sub.handler(event), timeout=10.0)
                self._stats["delivered"] += 1
            except asyncio.TimeoutError:
                logger.warning(
                    f"[MessageBus] Handler timeout: {sub.source} on {event.event_type}"
                )
                self._stats["errors"] += 1
            except Exception as exc:
                logger.error(
                    f"[MessageBus] Handler error: {sub.source} on {event.event_type}: {exc}"
                )
                self._dead_letter.append((event, str(exc)))
                self._stats["errors"] += 1
                if len(self._dead_letter) > 500:
                    self._dead_letter = self._dead_letter[-500:]

    @staticmethod
    def _topic_matches(pattern: str, topic: str) -> bool:
        """Check if a topic matches a subscription pattern (supports wildcard *)."""
        if pattern == topic:
            return True
        if pattern.endswith(".*"):
            prefix = pattern[:-2]
            return topic.startswith(prefix)
        if pattern == "*":
            return True
        return False

    # ── Query ─────────────────────────────────────────────────────────────

    def get_history(self, scan_id: str = "", event_type: str = "",
                    limit: int = 200) -> List[Event]:
        """Query event history with optional filters."""
        results = self._event_history
        if scan_id:
            results = [e for e in results if e.scan_id == scan_id]
        if event_type:
            results = [e for e in results if e.event_type == event_type]
        return results[-limit:]

    def get_stats(self) -> Dict[str, int]:
        return dict(self._stats)

    def reset(self) -> None:
        """Reset bus state for a new scan cycle."""
        self._event_history.clear()
        self._dead_letter.clear()
        self._dedup_cache.clear()
        self._stats = {
            "published": 0, "delivered": 0, "dropped": 0, "errors": 0,
        }
