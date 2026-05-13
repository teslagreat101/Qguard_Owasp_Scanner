"""
Quantara Autonomous AI Swarm Intelligence Framework v5.2
=========================================================
Enterprise-grade, event-driven multi-agent cybersecurity orchestration.

Components:
    MessageBus           — Topic-based async pub/sub event broker
    SharedIntelligenceState — Centralized scan state for inter-agent coordination
    ScanStateMachine     — Lifecycle state machine with guarded transitions
    PayloadEvolutionEngine — Genetic algorithm for adaptive payload mutation
    CorrelationEngine    — Multi-agent finding correlation & attack chain builder
    LearningEngine       — Feedback loop & heuristic optimization
    BaseSwarmAgent       — Enhanced agent base class with bus/state integration
"""

from backend.swarm.message_bus import MessageBus, Event, EventSchema, TopicGroup
from backend.swarm.shared_state import SharedIntelligenceState
from backend.swarm.state_machine import ScanStateMachine, ScanPhase
from backend.swarm.payload_evolution import PayloadEvolutionEngine
from backend.swarm.correlation_engine import CorrelationEngine
from backend.swarm.learning_engine import LearningEngine
from backend.swarm.base_agent import BaseSwarmAgent

__all__ = [
    "MessageBus", "Event", "EventSchema", "TopicGroup",
    "SharedIntelligenceState",
    "ScanStateMachine", "ScanPhase",
    "PayloadEvolutionEngine",
    "CorrelationEngine",
    "LearningEngine",
    "BaseSwarmAgent",
]
