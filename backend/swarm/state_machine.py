"""
Quantara Scan State Machine
=============================
Finite state machine governing the lifecycle of a security scan.
Enforces ordered phase transitions with guards and hooks.
"""

from __future__ import annotations

import logging
import time
from enum import Enum, auto
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Callable, Dict, List, Optional, Tuple

logger = logging.getLogger(__name__)


class ScanPhase(str, Enum):
    """Ordered scan lifecycle phases."""
    INITIALIZING     = "initializing"
    RECONNAISSANCE   = "reconnaissance"
    ATTACK_SURFACE   = "attack_surface_mapping"
    FINGERPRINTING   = "service_fingerprinting"
    VULNERABILITY    = "vulnerability_analysis"
    PAYLOAD_GEN      = "payload_generation"
    EXPLOITATION     = "exploitation"
    VERIFICATION     = "verification"
    CORRELATION      = "correlation"
    RISK_SCORING     = "risk_scoring"
    REPORTING        = "reporting"
    COMPLETED        = "completed"
    ERROR            = "error"


# Valid transitions: from_phase -> set of allowed to_phases
TRANSITIONS: Dict[ScanPhase, set] = {
    ScanPhase.INITIALIZING:   {ScanPhase.RECONNAISSANCE, ScanPhase.ERROR},
    ScanPhase.RECONNAISSANCE: {ScanPhase.ATTACK_SURFACE, ScanPhase.FINGERPRINTING, ScanPhase.PAYLOAD_GEN, ScanPhase.ERROR},
    ScanPhase.ATTACK_SURFACE: {ScanPhase.FINGERPRINTING, ScanPhase.PAYLOAD_GEN, ScanPhase.ERROR},
    ScanPhase.FINGERPRINTING: {ScanPhase.VULNERABILITY, ScanPhase.PAYLOAD_GEN, ScanPhase.ERROR},
    ScanPhase.VULNERABILITY:  {ScanPhase.PAYLOAD_GEN, ScanPhase.EXPLOITATION, ScanPhase.ERROR},
    ScanPhase.PAYLOAD_GEN:    {ScanPhase.EXPLOITATION, ScanPhase.VULNERABILITY, ScanPhase.ERROR},
    ScanPhase.EXPLOITATION:   {ScanPhase.VERIFICATION, ScanPhase.CORRELATION, ScanPhase.ERROR},
    ScanPhase.VERIFICATION:   {ScanPhase.CORRELATION, ScanPhase.RISK_SCORING, ScanPhase.ERROR},
    ScanPhase.CORRELATION:    {ScanPhase.RISK_SCORING, ScanPhase.ERROR},
    ScanPhase.RISK_SCORING:   {ScanPhase.REPORTING, ScanPhase.ERROR},
    ScanPhase.REPORTING:      {ScanPhase.COMPLETED, ScanPhase.ERROR},
    ScanPhase.COMPLETED:      set(),
    ScanPhase.ERROR:          {ScanPhase.INITIALIZING},  # allow restart
}


@dataclass
class PhaseRecord:
    """Record of a phase transition."""
    from_phase:  str
    to_phase:    str
    timestamp:   str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    elapsed_sec: float = 0.0
    metadata:    Dict = field(default_factory=dict)


TransitionGuard = Callable[[ScanPhase, ScanPhase, Dict], bool]
TransitionHook  = Callable[[ScanPhase, ScanPhase, Dict], None]


class ScanStateMachine:
    """
    Finite state machine for scan lifecycle management.

    Features:
        - Ordered phase transitions with validation
        - Guards: callable predicates that must return True for transition
        - Hooks: callbacks executed on successful transition
        - Phase timing: tracks duration of each phase
        - History: full transition log for audit
        - Parallel phase support: multiple agents can work within a phase
    """

    def __init__(self, scan_id: str = ""):
        self.scan_id      = scan_id
        self.current_phase = ScanPhase.INITIALIZING
        self.history:      List[PhaseRecord] = []
        self._guards:      List[TransitionGuard] = []
        self._hooks:       List[TransitionHook]  = []
        self._phase_start: float = time.monotonic()
        self._phase_timings: Dict[str, float] = {}
        self._metadata:    Dict[str, Any] = {}

    @property
    def is_terminal(self) -> bool:
        return self.current_phase in (ScanPhase.COMPLETED, ScanPhase.ERROR)

    @property
    def phase_elapsed(self) -> float:
        return round(time.monotonic() - self._phase_start, 2)

    def add_guard(self, guard: TransitionGuard) -> None:
        """Add a transition guard. All guards must pass for transition."""
        self._guards.append(guard)

    def add_hook(self, hook: TransitionHook) -> None:
        """Add a post-transition hook."""
        self._hooks.append(hook)

    def can_transition(self, to_phase: ScanPhase) -> bool:
        """Check if transition is valid without executing it."""
        if to_phase not in TRANSITIONS.get(self.current_phase, set()):
            return False
        for guard in self._guards:
            try:
                if not guard(self.current_phase, to_phase, self._metadata):
                    return False
            except Exception:
                return False
        return True

    def transition(self, to_phase: ScanPhase,
                   metadata: Dict = None) -> bool:
        """
        Attempt a phase transition.
        Returns True if successful, False if transition is invalid or guarded.
        """
        if to_phase not in TRANSITIONS.get(self.current_phase, set()):
            logger.warning(
                f"[StateMachine] Invalid transition: {self.current_phase.value} → {to_phase.value}"
            )
            return False

        combined_meta = {**self._metadata, **(metadata or {})}

        # Check guards
        for guard in self._guards:
            try:
                if not guard(self.current_phase, to_phase, combined_meta):
                    logger.warning(
                        f"[StateMachine] Guard blocked: {self.current_phase.value} → {to_phase.value}"
                    )
                    return False
            except Exception as exc:
                logger.error(f"[StateMachine] Guard error: {exc}")
                return False

        # Record timing
        elapsed = round(time.monotonic() - self._phase_start, 2)
        self._phase_timings[self.current_phase.value] = elapsed

        # Record transition
        record = PhaseRecord(
            from_phase=self.current_phase.value,
            to_phase=to_phase.value,
            elapsed_sec=elapsed,
            metadata=combined_meta,
        )
        self.history.append(record)

        from_phase = self.current_phase
        self.current_phase = to_phase
        self._phase_start  = time.monotonic()

        logger.info(
            f"[StateMachine] {from_phase.value} → {to_phase.value} "
            f"(phase took {elapsed:.1f}s)"
        )

        # Execute hooks
        for hook in self._hooks:
            try:
                hook(from_phase, to_phase, combined_meta)
            except Exception as exc:
                logger.error(f"[StateMachine] Hook error: {exc}")

        return True

    def force_error(self, reason: str = "") -> None:
        """Force transition to ERROR state from any phase."""
        elapsed = round(time.monotonic() - self._phase_start, 2)
        self._phase_timings[self.current_phase.value] = elapsed
        record = PhaseRecord(
            from_phase=self.current_phase.value,
            to_phase=ScanPhase.ERROR.value,
            elapsed_sec=elapsed,
            metadata={"error_reason": reason},
        )
        self.history.append(record)
        self.current_phase = ScanPhase.ERROR
        self._phase_start  = time.monotonic()

    def get_timings(self) -> Dict[str, float]:
        """Get timing for each completed phase."""
        return dict(self._phase_timings)

    def get_progress_pct(self) -> int:
        """Estimate overall progress as a percentage."""
        phase_order = [p for p in ScanPhase if p not in (ScanPhase.ERROR,)]
        try:
            idx = phase_order.index(self.current_phase)
        except ValueError:
            return 0
        total = len(phase_order) - 1  # exclude COMPLETED from denominator
        return min(100, int((idx / max(total, 1)) * 100))

    def reset(self, scan_id: str = "") -> None:
        self.scan_id       = scan_id
        self.current_phase = ScanPhase.INITIALIZING
        self.history.clear()
        self._phase_start  = time.monotonic()
        self._phase_timings.clear()
        self._metadata.clear()
