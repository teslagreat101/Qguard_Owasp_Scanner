"""
Quantara Supporting Intelligence Agents
==========================================
Additional specialized agents that extend the core 12-node swarm.
"""

from backend.swarm.agents.zeroday_agent import ZeroDayAgent
from backend.swarm.agents.threat_intel_agent import ThreatIntelAgent
from backend.swarm.agents.learning_agent import LearningAgent
from backend.swarm.agents.anomaly_agent import EnhancedAnomalyAgent

__all__ = [
    "ZeroDayAgent",
    "ThreatIntelAgent",
    "LearningAgent",
    "EnhancedAnomalyAgent",
]
