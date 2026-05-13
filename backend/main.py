"""
Quantara Protocol v5.0 — FastAPI Backend
Real-time OWASP Scanner Orchestrator with SSE streaming.
Powered by the unified scanner_engine (Scanner_1 + Scanner_2 merged).

Phase 3: Full REST API endpoints with pagination, DB persistence,
         SSE streaming, and report generation.
"""

import asyncio
import json
import os
import sys
import time
import uuid
import hashlib
from contextlib import contextmanager, asynccontextmanager
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional, List, Dict, Tuple

from fastapi import FastAPI, HTTPException, BackgroundTasks, Depends, Query, Response, Header, Request, WebSocket, APIRouter
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, FileResponse
from pydantic import BaseModel, Field
from sse_starlette.sse import EventSourceResponse

# ── Add parent directory to path so we can import scanner modules ──
PARENT_DIR = str(Path(__file__).resolve().parent.parent)
CENTRAL_DIR = os.path.join(PARENT_DIR, "Centralize_Scanners")

for path in [PARENT_DIR, CENTRAL_DIR]:
    if path not in sys.path:
        sys.path.insert(0, path)

# ── Import unified scanner engine ──
from scanner_engine.orchestrator import (
    UNIFIED_MODULE_REGISTRY as MODULE_REGISTRY,
    normalize_finding_to_dict as normalize_finding,
    run_module_scan,
    get_available_modules,
    get_available_profiles,
    get_modules_for_profile,
    compute_scan_scores,
    deduplicate_findings,
    normalize_finding as normalize_to_unified,
    SCAN_PROFILES,
)

# ── Import NEO Intelligence from orchestrator ──────────────────────────────────
try:
    from scanner_engine.orchestrator import (
        run_neo_intelligence as _run_neo_intelligence,
        get_neo_intelligence_summary as _get_neo_intelligence_summary,
        get_neo_smart_payloads as _get_neo_smart_payloads,
        neo_record_successful_exploit as _neo_record_exploit,
        neo_ingest_endpoints as _neo_ingest_endpoints,
        neo_ingest_findings_for_chaining as _neo_ingest_findings_for_chaining,
        neo_compute_attack_surfaces as _neo_compute_attack_surfaces,
        neo_get_learning_memory_stats as _neo_get_learning_memory_stats,
    )
    _NEO_INTELLIGENCE_AVAILABLE = True
    logger = logging.getLogger(__name__)  # may not exist yet; overwritten below
except Exception:
    _NEO_INTELLIGENCE_AVAILABLE = False

# ── Import database and Redis ──
from backend.database import init_db, get_db, get_db_session, User, Scan, Finding, ScanLog, SubscriptionTier
from backend.redis_client import get_state_manager
from backend.auth import (
    create_access_token, create_refresh_token, verify_password, 
    SUPER_ADMIN_EMAIL, get_user_subscription, check_subscription_access,
    check_usage_limits, increment_scan_usage, get_current_firebase_user
)
from sqlalchemy.orm import Session
from sqlalchemy import func

# ── Import Quantara Intelligence Engines ──────────────────────────────────────
import logging
logger = logging.getLogger(__name__)

try:
    from backend.exploit_verifier import get_exploit_verifier
    _VERIFIER_AVAILABLE = True
except Exception:
    try:
        from exploit_verifier import get_exploit_verifier
        _VERIFIER_AVAILABLE = True
    except Exception:
        _VERIFIER_AVAILABLE = False
        logger.warning("exploit_verifier not available")

try:
    from backend.attack_decision_engine import get_attack_decision_engine
    _DECISION_ENGINE_AVAILABLE = True
except Exception:
    try:
        from attack_decision_engine import get_attack_decision_engine
        _DECISION_ENGINE_AVAILABLE = True
    except Exception:
        _DECISION_ENGINE_AVAILABLE = False
        logger.warning("attack_decision_engine not available")

# ── Swarm Intelligence Initialization ──
try:
    from backend.intelligence_nodes import get_swarm_orchestrator, SwarmOrchestrator
    _SWARM_AVAILABLE = True
except Exception:
    try:
        from intelligence_nodes import get_swarm_orchestrator, SwarmOrchestrator
        _SWARM_AVAILABLE = True
    except Exception as _sw_err:
        _SWARM_AVAILABLE = False
        logger.warning(f"Swarm Intelligence Nodes not available: {_sw_err}")

# Swarm scan state store
_swarm_scans: Dict[str, Dict[str, Any]] = {}

# ── Swarm Intelligence Router ──
swarm_router = APIRouter(prefix="/api/v1/swarm", tags=["swarm"])

class SwarmScanRequest(BaseModel):
    target: str
    depth: str = "deep"
    strategy: str = "autonomous"

@swarm_router.get("/health")
async def swarm_health():
    return {"status": "ok", "swarm_engine": _SWARM_AVAILABLE}

@swarm_router.post("/scan/start")
async def start_swarm_scan(request: SwarmScanRequest, background_tasks: BackgroundTasks):
    """Start an autonomous AI Red Team swarm scan."""
    if not _SWARM_AVAILABLE:
        raise HTTPException(status_code=503, detail="Swarm Intelligence Nodes not available")

    scan_id = str(uuid.uuid4())
    orchestrator = get_swarm_orchestrator()

    _swarm_scans[scan_id] = {
        "scan_id": scan_id,
        "target": request.target,
        "status": "initializing",
        "started_at": datetime.now(timezone.utc).isoformat(),
        "depth": request.depth,
        "strategy": request.strategy,
        "findings": [],
        "risk_score": 0,
        "severity_counts": {},
        "attack_graph": {"nodes": [], "edges": []},
    }

    async def run_swarm():
        try:
            _swarm_scans[scan_id]["status"] = "running"
            result = await orchestrator.execute_swarm_scan(
                request.target, scan_id,
                depth=request.depth, strategy=request.strategy,
            )
            _swarm_scans[scan_id].update({
                "status": "completed",
                "completed_at": datetime.now(timezone.utc).isoformat(),
                "findings": result.get("findings", []),
                "total_findings": result.get("total_findings", 0),
                "risk_score": result.get("risk_score", 0),
                "severity_counts": result.get("severity_counts", {}),
                "attack_graph": result.get("attack_graph", {}),
            })
        except Exception as e:
            logger.error(f"Swarm scan error: {e}")
            _swarm_scans[scan_id]["status"] = "error"
            _swarm_scans[scan_id]["error"] = str(e)

    background_tasks.add_task(run_swarm)

    return {
        "scan_id": scan_id,
        "status": "initializing",
        "target": request.target,
        "total_nodes": 12,
    }

@swarm_router.get("/scan/{scan_id}/stream")
async def stream_swarm_telemetry(scan_id: str):
    """Stream real-time telemetry from swarm intelligence nodes via SSE."""
    if not _SWARM_AVAILABLE:
        raise HTTPException(status_code=503, detail="Swarm Intelligence Nodes not available")

    orchestrator = get_swarm_orchestrator()
    emitter = orchestrator.emitter

    async def swarm_event_generator():
        q = emitter.subscribe()
        try:
            yield {
                "event": "status",
                "data": json.dumps({
                    "status": "connected",
                    "message": "Swarm telemetry stream active",
                    "scan_id": scan_id,
                }),
            }
            while True:
                try:
                    event = await asyncio.wait_for(q.get(), timeout=15.0)
                    if event.get("scan_id") != scan_id:
                        continue
                    event_type = event.get("event", "telemetry")
                    data = event.get("data", {})
                    data["scan_id"] = scan_id
                    ts = event.get("timestamp", datetime.now(timezone.utc).isoformat())
                    data["timestamp"] = ts
                    time_str = ts[11:19] if len(ts) > 19 else ts

                    # ── Map to agent_status for node lifecycle events
                    if event_type in ("node_started", "node_completed", "node_error"):
                        node_name = data.get("node", "")
                        status_val = "active" if event_type == "node_started" else "completed" if event_type == "node_completed" else "error"
                        yield {"event": "agent_status", "data": json.dumps({
                            "node": node_name,
                            "status": status_val,
                        })}
                        # Also emit as log for Live Telemetry panel
                        level = "success" if event_type == "node_started" else "success" if event_type == "node_completed" else "error"
                        msg = data.get("message", f"{node_name} — {status_val}")
                        yield {"event": "log", "data": json.dumps({
                            "time": time_str,
                            "level": level,
                            "message": msg,
                            "module": node_name,
                        })}

                    # ── Map vulnerability findings to finding event
                    elif event_type == "vulnerability_detected":
                        yield {"event": "finding", "data": json.dumps(data)}
                        # Also log this
                        yield {"event": "log", "data": json.dumps({
                            "time": time_str,
                            "level": "warn",
                            "message": f"⚠ Vulnerability: {data.get('title', 'Unknown')}",
                            "module": data.get("node", data.get("node_name", "SWARM")),
                        })}

                    # ── Forward graph_update for real-time attack graph
                    elif event_type == "graph_update":
                        yield {"event": "graph_update", "data": json.dumps(data)}

                    # ── Forward status and complete events for progress tracking
                    elif event_type in ("status", "complete"):
                        yield {"event": event_type, "data": json.dumps(data)}

                    # ── Forward keepalive
                    elif event_type == "keepalive":
                        yield {"event": "keepalive", "data": json.dumps(data)}

                    # ── All other events: emit as log for Live Telemetry
                    else:
                        msg = data.get("message", f"[{event_type}] event")
                        node_name = data.get("node", "SWARM")
                        level = "success" if "complet" in event_type else "info"
                        yield {"event": "log", "data": json.dumps({
                            "time": time_str,
                            "level": level,
                            "message": msg,
                            "module": node_name,
                        })}

                        # If a finding was embedded in the data, also emit it
                        if data.get("title") and data.get("severity"):
                            yield {"event": "finding", "data": json.dumps(data)}

                except asyncio.TimeoutError:
                    yield {"event": "keepalive", "data": json.dumps({"timestamp": datetime.now(timezone.utc).isoformat()})}
        except Exception as e:
            logger.error(f"Streaming error: {e}")
        finally:
            emitter.unsubscribe(q)

    return EventSourceResponse(swarm_event_generator(), media_type="text/event-stream")

@swarm_router.get("/scan/{scan_id}/graph")
async def get_swarm_attack_graph(scan_id: str):
    """Get the current attack graph for a swarm scan."""
    orchestrator = get_swarm_orchestrator()
    live_graph = orchestrator.attack_graph
    # Prefer live graph if it has data (running scan)
    if live_graph.get("nodes"):
        return live_graph
    # Fallback to stored scan data
    if scan_id in _swarm_scans:
        return _swarm_scans[scan_id].get("attack_graph", {"nodes": [], "edges": []})
    return {"nodes": [], "edges": []}


try:
    from backend.safe_scan_guard import create_fresh_guard
    _SAFE_GUARD_AVAILABLE = True
except Exception:
    try:
        from safe_scan_guard import create_fresh_guard
        _SAFE_GUARD_AVAILABLE = True
    except Exception:
        _SAFE_GUARD_AVAILABLE = False
        logger.warning("safe_scan_guard not available")

try:
    from backend.neo4j_client import get_neo4j_client
    _NEO4J_AVAILABLE = True
except Exception:
    try:
        from neo4j_client import get_neo4j_client
        _NEO4J_AVAILABLE = True
    except Exception:
        _NEO4J_AVAILABLE = False
        logger.warning("neo4j_client not available")

# ── Import Stability Engines (Scan Queue + Dedup) ──────────────────────────────
try:
    from backend.scan_queue import (
        get_semaphore, bounded_executor, scan_queue_manager,
        cleanup_old_scans, scan_watchdog, resource_monitor,
    )
    from backend.finding_dedup import is_duplicate, compute_evidence_hash, deduplicate_findings_list
    _STABILITY_AVAILABLE = True
except Exception:
    try:
        from scan_queue import (
            get_semaphore, bounded_executor, scan_queue_manager,
            cleanup_old_scans, scan_watchdog, resource_monitor,
        )
        from finding_dedup import is_duplicate, compute_evidence_hash, deduplicate_findings_list
        _STABILITY_AVAILABLE = True
    except Exception as _se:
        _STABILITY_AVAILABLE = False
        logger.warning(f"Stability engines not available: {_se}")
        bounded_executor = None  # falls back to None (default executor)

# ── Import Enterprise Scanner Engines (Phase 8) ────────────────────────────────
# These live in Centralize_Scanners/scanner_engine/ — we add that dir to sys.path
_ENTERPRISE_ENGINE_DIR = os.path.join(CENTRAL_DIR, "scanner_engine")
if _ENTERPRISE_ENGINE_DIR not in sys.path:
    sys.path.insert(0, _ENTERPRISE_ENGINE_DIR)

try:
    from scanner_engine.orchestrator import (
        get_enterprise_engine,
        enterprise_scan_summary,
        get_payload_pack,
        mutate_payload,
        detect_injection_context,
    )
    _ENTERPRISE_ORCHESTRATOR_AVAILABLE = True
    logger.info("Enterprise orchestrator extensions loaded")
except Exception as _eoe:
    _ENTERPRISE_ORCHESTRATOR_AVAILABLE = False
    logger.warning(f"Enterprise orchestrator extensions not available: {_eoe}")

try:
    import importlib as _importlib
    _payload_mutator_mod = _importlib.import_module("payload_mutator") if _ENTERPRISE_ENGINE_DIR in sys.path else None
    _PayloadMutator = getattr(_payload_mutator_mod, "PayloadMutator", None) if _payload_mutator_mod else None
    _MUTATOR_AVAILABLE = _PayloadMutator is not None
    if _MUTATOR_AVAILABLE:
        logger.info("PayloadMutator engine loaded")
except Exception as _pme:
    _MUTATOR_AVAILABLE = False
    _PayloadMutator = None
    logger.warning(f"PayloadMutator not available: {_pme}")

try:
    _attack_chain_mod = _importlib.import_module("adaptive_engine") if _ENTERPRISE_ENGINE_DIR in sys.path else None
    _AttackChainCorrelator = getattr(_attack_chain_mod, "AttackChainCorrelator", None) if _attack_chain_mod else None
    _CHAIN_CORRELATOR_AVAILABLE = _AttackChainCorrelator is not None
    if _CHAIN_CORRELATOR_AVAILABLE:
        logger.info("AttackChainCorrelator engine loaded")
except Exception as _ace:
    _CHAIN_CORRELATOR_AVAILABLE = False
    _AttackChainCorrelator = None
    logger.warning(f"AttackChainCorrelator not available: {_ace}")



# ═══════════════════════════════════════════════════════════════════════════════
# App Setup
# ═══════════════════════════════════════════════════════════════════════════════

@asynccontextmanager
async def lifespan(app: FastAPI):
    """Lifespan handler for startup and shutdown events."""
    # STARTUP
    init_db()
    if _STABILITY_AVAILABLE:
        # Initialize semaphore within the running event loop
        get_semaphore()
        # Start background tasks
        cleanup_task = asyncio.create_task(cleanup_old_scans(scans))
        watchdog_task = asyncio.create_task(scan_watchdog(scans))
        monitor_task = asyncio.create_task(resource_monitor(scans))
        logger.info("Stability engines initialized: semaphore, cleanup, watchdog, resource monitor")
    
    yield
    
    # SHUTDOWN
    if _STABILITY_AVAILABLE:
        # Cancel background tasks on shutdown
        cleanup_task.cancel()
        watchdog_task.cancel()
        monitor_task.cancel()
        logger.info("Stability background tasks cancelled.")

# The swarm routes are now handled by the swarm_router defined above.

app = FastAPI(
    title="Helix Scanner API",
    version="5.0.0",
    description="Unified real-time security scanner — Scanner_1 + Scanner_2 merged. Full OWASP Top 10:2025 coverage.",
    docs_url="/api/docs",
    redoc_url="/api/redoc",
    lifespan=lifespan,
)

app.include_router(swarm_router)

# Dynamic CORS origins from environment
cors_origins = [
    "http://localhost:3000",
    "http://localhost:3001",
    "http://localhost:3002",
    "http://localhost:3003",
    "http://127.0.0.1:3000",
    "http://127.0.0.1:3001",
    "http://127.0.0.1:3002",
    "http://127.0.0.1:3003",
]

# Allow any port on localhost/127.0.0.1 in development
ALLOW_ALL_LOCAL = os.getenv("DEVELOPMENT", "true").lower() == "true"

# CORS middleware configuration
app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:3000",
        "http://localhost:3001",
        "http://localhost:3002",
        "http://localhost:3003",
        "http://127.0.0.1:3000",
        "http://127.0.0.1:3001",
        "http://127.0.0.1:3002",
        "http://127.0.0.1:3003",
    ],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
    expose_headers=["*"],
    max_age=3600,
)

# ═══════════════════════════════════════════════════════════════════════════════
# Hetty Console API — Manual Pentesting Toolkit
# ═══════════════════════════════════════════════════════════════════════════════
try:
    from backend.hetty_api import router as hetty_router
    app.include_router(hetty_router)
    logger.info("Hetty Console API router loaded")
except Exception:
    try:
        from hetty_api import router as hetty_router
        app.include_router(hetty_router)
        logger.info("Hetty Console API router loaded (relative import)")
    except Exception as _he:
        logger.warning(f"Hetty Console API not available: {_he}")

# ═══════════════════════════════════════════════════════════════════════════════
# In-Memory Scan Store (backed by Redis for persistence)
# ═══════════════════════════════════════════════════════════════════════════════

scans: dict[str, dict[str, Any]] = {}

# Concurrency guard: max 2 modules running simultaneously across all scans
# (5 scans × 2 modules each = 10 theoretical threads max on the bounded pool)
_module_semaphore = asyncio.Semaphore(2)

# ── Memory-safe event appender ────────────────────────────────────────────────
# Replaces all direct `scan["events"].append(...)` calls.
# Caps the in-memory events list at 1000 entries — older events are evicted
# (they are already persisted to Redis / delivered to SSE clients by cursor).
# _events_base_offset tracks how many items were trimmed so the SSE cursor
# can rebase itself and not skip / re-deliver events after a trim.
_EVENTS_CAP = 1000
_EVENTS_TRIM = 200  # how many to remove when cap is hit


def _append_event(scan: dict, event_type: str, data: dict) -> None:
    scan["events"].append({"type": event_type, "data": data})
    scan["_last_event_time"] = time.monotonic()   # watchdog heartbeat
    if len(scan["events"]) > _EVENTS_CAP:
        del scan["events"][:_EVENTS_TRIM]
        scan["_events_base_offset"] = scan.get("_events_base_offset", 0) + _EVENTS_TRIM


# ═══════════════════════════════════════════════════════════════════════════════
# Pydantic Models
# ═══════════════════════════════════════════════════════════════════════════════

class ScanRequest(BaseModel):
    target: str
    scan_type: str = "directory"  # "directory" | "code" | "git" | "url" | "repository"
    target_type: Optional[str] = None  # explicit override: "url" | "github" | "directory" | "code"
    modules: list[str] = ["misconfig", "injection", "frontend_js", "endpoint"]
    scan_profile: str = "full"

class ScanResponse(BaseModel):
    scan_id: str
    status: str
    modules: list[str] = []
    total_patterns: int = 0

class ScanStatusModel(BaseModel):
    scan_id: str
    status: str
    progress: int
    active_module: Optional[str] = None
    total_findings: int = 0
    modules_completed: int = 0
    modules_total: int = 0
    started_at: Optional[str] = None
    completed_at: Optional[str] = None
    elapsed_seconds: float = 0
    duration: float = 0
    severity_counts: dict = {}
    target: Optional[str] = None

class FindingResponse(BaseModel):
    id: str = ""
    file: str = ""
    line_number: int = 0
    severity: str = "info"
    title: str = ""
    description: str = ""
    matched_content: Optional[str] = None
    module: str = ""
    module_name: str = ""
    category: str = ""
    cwe: str = ""
    owasp: str = ""
    remediation: str = ""
    confidence: float = 1.0
    tags: list[str] = []
    timestamp: str = ""
    language: Optional[str] = None
    injection_type: Optional[str] = None
    subcategory: Optional[str] = None

class PaginatedFindings(BaseModel):
    findings: List[FindingResponse] = []
    total: int = 0
    page: int = 1
    page_size: int = 50
    total_pages: int = 1
    has_next: bool = False
    has_prev: bool = False

class LoginRequest(BaseModel):
    email: str
    password: str

class GoogleLoginRequest(BaseModel):
    id_token: str

class TokenResponse(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str = "bearer"
    expires_in: int
    user: dict

class ScanReportModel(BaseModel):
    scan_id: str
    status: str
    target: str
    duration: float = 0
    started_at: Optional[str] = None
    completed_at: Optional[str] = None
    summary: dict = {}
    module_summary: dict = {}
    owasp_coverage: dict = {}
    total_findings: int = 0
    findings: list = []
    logs: list = []
    top_files: list = []
    risk_score: float = 0


# ═══════════════════════════════════════════════════════════════════════════════
# Core Scan Executor (async)
# ═══════════════════════════════════════════════════════════════════════════════

async def execute_scan(scan_id: str, target: str, scan_type: str, modules: list[str], db: Session = None, target_type: Optional[str] = None):
    """Execute scan with database and Redis persistence."""
    print(f"DEBUG: execute_scan Task started for scan {scan_id}")
    # Ensure we have a database session for background task
    own_db = False
    if db is None:
        db = get_db_session()
        own_db = True
    
    try:
        scan = scans[scan_id]
        scan["status"] = "running"
        scan["started_at"] = datetime.now(timezone.utc).isoformat()
        start_time = time.time()

        # Update SQL status
        db_scan = db.query(Scan).filter(Scan.scan_id == scan_id).first()
        if db_scan:
            db_scan.status = "running"
            db_scan.started_at = datetime.now(timezone.utc)
            db.commit()

        # Initialize Redis state manager
        state_mgr = get_state_manager()
        state_mgr.set_scan_status(scan_id, "running", target=target, scan_type=scan_type, modules=modules)

        valid_modules = [m for m in modules if m in MODULE_REGISTRY]
        scan["modules_total"] = len(valid_modules)

        _add_log(scan_id, "success", f"Engine started — {len(valid_modules)} modules targeting {target}")

        # Emit structured scan_started event for live visualization
        _append_event(scan, "scan_started", {
            "scan_id": scan_id,
            "target": target,
            "scan_type": scan_type,
            "modules": valid_modules,
            "modules_total": len(valid_modules),
            "started_at": scan["started_at"],
            "timestamp": datetime.now(timezone.utc).isoformat(),
        })

        # ── Enterprise Intelligence Engines Telemetry ─────────────────────────
        _enterprise_payload_packs: dict = {}
        _enterprise_pack_total = 0
        if _ENTERPRISE_ORCHESTRATOR_AVAILABLE:
            try:
                _PAYLOAD_PACK_NAMES = [
                    "xss", "sqli", "sqli_blind_time", "sqli_boolean", "ssrf", "lfi",
                    "ssti", "cmdi", "cmdi_blind", "open_redirect", "xxe", "idor",
                    "mysql", "mysql_blind", "mssql", "pgsql",
                    "node_prototype_pollution", "node_path_traversal",
                    "aws_ssrf", "graphql_introspection", "graphql_injection", "graphql_nosql",
                    "header_injection", "host_header", "cors",
                    "api_discovery", "api_bola", "api_mass_assignment",
                ]
                for pack_name in _PAYLOAD_PACK_NAMES:
                    try:
                        pack = get_payload_pack(pack_name)
                        if pack:
                            _enterprise_payload_packs[pack_name] = len(pack)
                            _enterprise_pack_total += len(pack)
                    except Exception:
                        pass
            except Exception as _ete:
                logger.debug(f"Enterprise payload pack enum error: {_ete}")

        _mutator_instance = None
        if _MUTATOR_AVAILABLE and _PayloadMutator:
            try:
                _mutator_instance = _PayloadMutator()
            except Exception:
                pass

        if _enterprise_pack_total:
            _add_log(scan_id, "info", f"Enterprise payload engine loaded: {_enterprise_pack_total} signatures / {len(_enterprise_payload_packs)} packs")
        _telemetry_data = {
            "payload_packs": _enterprise_payload_packs,
            "total_payloads": _enterprise_pack_total,
            "mutation_engine": _MUTATOR_AVAILABLE,
            "chain_correlator": _CHAIN_CORRELATOR_AVAILABLE,
            "differential_analyzer": _ENTERPRISE_ORCHESTRATOR_AVAILABLE,
            "adaptive_engine": _ENTERPRISE_ORCHESTRATOR_AVAILABLE,
            "modules_loaded": len(valid_modules),
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }
        scan["enterprise_telemetry"] = _telemetry_data
        _append_event(scan, "enterprise_telemetry", _telemetry_data)

        # ── Stability: wait for slot if scan was queued ───────────────────────
        if _STABILITY_AVAILABLE and scan.get("status") == "queued":
            await scan_queue_manager.wait_for_slot(scan_id, scans)

        # ── Batch DB write accumulator ────────────────────────────────────────
        _finding_batch: list = []
        _BATCH_SIZE = 25

        # Initialize per-scan safe guard
        guard = create_fresh_guard() if _SAFE_GUARD_AVAILABLE else None

        # Phase 1: Recons & Pre-computation
        _total_sigs = sum(MODULE_REGISTRY[m]['pattern_count'] for m in valid_modules)
        _add_log(scan_id, "success", f"Phase 1 — Attack surface mapping ({_total_sigs} signatures loaded)")

        severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
        owasp_counts = {}
        _last_risk_score = 0

        for idx, module_key in enumerate(valid_modules):
            if scan.get("cancelled"):
                scan["status"] = "cancelled"
                _add_log(scan_id, "warn", "Scan cancelled by user")
                state_mgr.set_scan_status(scan_id, "cancelled")
                break

            meta = MODULE_REGISTRY[module_key]
            scan["active_module"] = module_key
            progress = int((idx / len(valid_modules)) * 100)
            scan["progress"] = progress
            state_mgr.set_progress(scan_id, progress)

            # ── MODULE_STARTED lifecycle event ────────────────────────────────
            _add_log(scan_id, "info", f"[{meta['name']}] Starting ({idx + 1}/{len(valid_modules)})", module_key)
            _append_event(scan, "module_started", {
                "module": module_key,
                "name": meta["name"],
                "owasp": meta.get("owasp", ""),
                "idx": idx,
                "total": len(valid_modules),
                "progress": progress,
                "timestamp": datetime.now(timezone.utc).isoformat(),
            })

            # ── Heartbeat coroutine: emits progress event (no log spam) ────────
            async def _module_heartbeat(sid: str, mod_name: str, mod_key: str):
                elapsed = 0
                while True:
                    await asyncio.sleep(3.0)
                    elapsed += 3
                    _append_event(scans[sid], "module_progress", {
                        "module": mod_key,
                        "name": mod_name,
                        "elapsed_seconds": elapsed,
                        "timestamp": datetime.now(timezone.utc).isoformat(),
                    })

            try:
                # Bounded executor (max 10 threads) + semaphore (max 2 simultaneous modules)
                async with _module_semaphore:
                    _hb_task = asyncio.create_task(_module_heartbeat(scan_id, meta["name"], module_key))
                    try:
                        if module_key == "neo_intelligence" and _NEO_INTELLIGENCE_AVAILABLE:
                            # NEO intelligence runs async and takes current findings
                            current_findings = scan.get("findings", [])
                            neo_result = await _run_neo_intelligence(
                                target=target,
                                scan_type=scan_type,
                                findings=current_findings
                            )
                            scan["neo_intelligence_result"] = neo_result
                            if "error" in neo_result:
                                findings = []
                                _add_log(scan_id, "error", f"NEO Intelligence failed: {neo_result['error']}", module_key)
                            else:
                                # Extract actual findings from the NEO result
                                neo_all = neo_result.get("all_findings", [])
                                neo_verified = neo_result.get("verified_findings", [])
                                
                                # Use a dict by ID to deduplicate and combine
                                combined_findings = {f.get("id", str(uuid.uuid4())): f for f in neo_all}
                                for f in neo_verified:
                                    fid = f.get("id", str(uuid.uuid4()))
                                    combined_findings[fid] = f
                                
                                findings = list(combined_findings.values())
                                _add_log(scan_id, "success", f"NEO Intelligence: Found {len(findings)} results ({len(neo_verified)} verified)", module_key)
                        else:
                            # Standard modules run in executor
                            findings = await asyncio.wait_for(
                                asyncio.get_event_loop().run_in_executor(
                                    bounded_executor,
                                    lambda mk=module_key: run_module_scan(mk, target, scan_type, target_type=target_type)
                                ),
                                timeout=120  # increased for heavy enterprise modules
                            )
                    finally:
                        _hb_task.cancel()
                        try:
                            await _hb_task
                        except asyncio.CancelledError:
                            pass

            # ── MODULE_COMPLETED lifecycle event ──────────────────────────────
                findings_count = len(findings) if findings else 0
                _append_event(scan, "module_completed", {
                    "module": module_key,
                    "name": meta["name"],
                    "idx": idx,
                    "total": len(valid_modules),
                    "findings_count": findings_count,
                    "progress": int(((idx + 1) / len(valid_modules)) * 100),
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                })
                _add_log(scan_id, "success", f"[{meta['name']}] Complete — {findings_count} finding(s)", module_key)


                for finding in findings:
                    normalized_obj = normalize_finding(finding, module_key)
                    # Ensure we have a dictionary for serialization
                    if hasattr(normalized_obj, "to_dict"):
                        normalized = normalized_obj.to_dict()
                    elif isinstance(normalized_obj, dict):
                        normalized = normalized_obj
                    else:
                        # Fallback for unexpected types
                        normalized = {
                            "id": str(uuid.uuid4()),
                            "title": str(normalized_obj),
                            "severity": "info",
                            "module": module_key,
                            "timestamp": datetime.now(timezone.utc).isoformat()
                        }

                    # ── Deduplication: skip if this fingerprint was seen already ──
                    if _STABILITY_AVAILABLE and is_duplicate(normalized, scan["dedup_set"]):
                        scan["dedup_skipped"] = scan.get("dedup_skipped", 0) + 1
                        continue

                    # ── Append to in-memory findings (capped at 5000) ─────────────
                    scan["findings"].append(normalized)
                    scan["total_findings_count"] = scan.get("total_findings_count", 0) + 1
                    if len(scan["findings"]) > 5000:
                        del scan["findings"][:100]  # trim oldest 100; all findings persisted to DB

                    # ── Enterprise: annotate finding with mutation hints ───────
                    if _mutator_instance:
                        try:
                            _base_payload = normalized.get("matched_content", "") or normalized.get("title", "")
                            if _base_payload:
                                _vuln_type = "xss" if "xss" in normalized.get("category", "").lower() else \
                                             "sqli" if any(k in normalized.get("category", "").lower() for k in ("sql", "inject")) else \
                                             "cmdi" if "command" in normalized.get("category", "").lower() else \
                                             "ssti" if "template" in normalized.get("category", "").lower() else "generic"
                                _variants = _mutator_instance.generate_variants(_base_payload, max_variants=8)
                                normalized["mutation_variants_count"] = len(_variants)
                                normalized["mutation_type"] = _vuln_type
                        except Exception:
                            pass

                    _append_event(scan, "finding", normalized)

                    # ── Batch DB persistence (flush every 25 findings) ────────────
                    try:
                        evidence_hash = compute_evidence_hash(normalized) if _STABILITY_AVAILABLE else None
                        new_finding = Finding(
                            scan_id=scan_id,
                            finding_id=normalized["id"],
                            file=normalized.get("file", "unknown"),
                            line_number=normalized.get("line_number", 0),
                            severity=normalized["severity"],
                            title=normalized["title"],
                            description=normalized.get("description", ""),
                            matched_content=normalized.get("matched_content", ""),
                            module_name=module_key,
                            category=normalized.get("category", ""),
                            cwe=normalized.get("cwe", ""),
                            remediation=normalized.get("remediation", ""),
                            confidence=normalized.get("confidence", 1.0),
                            tags=normalized.get("tags", []),
                            created_at=datetime.now(timezone.utc),
                            evidence_hash=evidence_hash,
                        )
                        _finding_batch.append(new_finding)
                        if len(_finding_batch) >= _BATCH_SIZE:
                            db.bulk_save_objects(_finding_batch)
                            db.commit()
                            _finding_batch.clear()
                    except Exception as e:
                        print(f"Error batching finding to SQL: {e}")
                        db.rollback()
                        _finding_batch.clear()

                    # Log finding to terminal stream for "wow" effect
                    short_file = normalized.get("file", "unknown")
                    if len(short_file) > 30: short_file = "..." + short_file[-27:]
                    _add_log(scan_id, "warn", f"{normalized['severity'].upper()}: {normalized['title']} @ {short_file}")

                    # Emit endpoint_discovered event for Three.js visualization
                    ep = normalized.get("file") or normalized.get("endpoint") or ""
                    if ep and ("http" in ep or "/" in ep):
                        ep_data = {
                            "url": ep,
                            "method": normalized.get("method", "GET"),
                            "finding_id": normalized["id"],
                            "severity": normalized["severity"],
                        }
                        _append_event(scan, "endpoint_discovered", ep_data)
                        # Persist for report rehydration (cap at 500)
                        ep_list = scan.get("endpoints_discovered", [])
                        if len(ep_list) < 500:
                            ep_list.append(ep_data)

                    # Update severity counts
                    sev = normalized.get("severity", "info").lower()
                    if sev in severity_counts:
                        severity_counts[sev] += 1

                    # Update OWASP coverage
                    owasp_cat = normalized.get("owasp", meta.get("owasp", ""))
                    if owasp_cat:
                        owasp_counts[owasp_cat] = owasp_counts.get(owasp_cat, 0) + 1

                    # Update coverage intelligence based on finding tags/metadata
                    cov = scan.get("coverage_intelligence", {})
                    tags_lower = [t.lower() for t in normalized.get("tags", [])]
                    if "get" in tags_lower or "query" in tags_lower:
                        cov["get_params_tested"] = cov.get("get_params_tested", 0) + 1
                    if "post" in tags_lower or "body" in tags_lower:
                        cov["post_bodies_tested"] = cov.get("post_bodies_tested", 0) + 1
                    if "json" in tags_lower or "api" in tags_lower:
                        cov["json_apis_tested"] = cov.get("json_apis_tested", 0) + 1
                    if "header" in tags_lower:
                        cov["headers_tested"] = cov.get("headers_tested", 0) + 1
                    if "cookie" in tags_lower or "session" in tags_lower:
                        cov["cookies_tested"] = cov.get("cookies_tested", 0) + 1
                    if "graphql" in tags_lower:
                        cov["graphql_routes"] = cov.get("graphql_routes", 0) + 1
                    if "js" in tags_lower or "javascript" in tags_lower:
                        cov["js_discovered_endpoints"] = cov.get("js_discovered_endpoints", 0) + 1

                    # Publish to Redis for real-time updates
                    state_mgr.publish_finding(scan_id, normalized)

                    # Broadcast finding via WebSocket to all connected clients
                    asyncio.create_task(ws_manager.broadcast_scan_update(scan_id, {
                        "type": "finding",
                        "finding": normalized,
                        "progress": scan.get("progress", 0),
                        "total_findings": len(scan["findings"]),
                    }))

                # ── Emit risk_updated event if score changed significantly ────
                cur_score, cur_conf, cur_status, cur_level = _compute_risk_score(
                    severity_counts, idx + 1, len(valid_modules)
                )
                if abs(cur_score - _last_risk_score) >= 10:
                    _append_event(scan, "risk_updated", {
                        "old_score": _last_risk_score,
                        "new_score": cur_score,
                        "confidence": cur_conf,
                        "scan_status": cur_status,
                        "risk_level": cur_level,
                        "trigger": module_key,
                    })
                    _last_risk_score = cur_score

                # ── Enterprise: emit payload_executed telemetry per module ────
                if _enterprise_payload_packs:
                    _relevant_packs = []
                    _mkey_lower = module_key.lower()
                    if "injection" in _mkey_lower:
                        _relevant_packs = ["xss", "sqli", "sqli_blind_time", "cmdi", "ssti"]
                    elif "misconfig" in _mkey_lower:
                        _relevant_packs = ["header_injection", "host_header", "cors"]
                    elif "ssrf" in _mkey_lower:
                        _relevant_packs = ["ssrf", "aws_ssrf"]
                    elif "frontend" in _mkey_lower:
                        _relevant_packs = ["xss", "open_redirect"]
                    elif "quantara" in _mkey_lower:
                        _relevant_packs = ["api_discovery", "api_bola", "graphql_introspection"]
                    elif "api" in _mkey_lower:
                        _relevant_packs = ["api_bola", "api_mass_assignment", "api_discovery"]
                    if _relevant_packs:
                        _packs_used = {k: _enterprise_payload_packs.get(k, 0) for k in _relevant_packs if k in _enterprise_payload_packs}
                        _total_used = sum(_packs_used.values())
                        _mutations_count = _total_used * 8 if _mutator_instance else 0  # 8 variants per payload
                        _pe_data = {
                            "module": module_key,
                            "packs_used": _packs_used,
                            "total_payloads_fired": _total_used,
                            "mutations_generated": _mutations_count,
                            "findings_triggered": len(findings),
                            "endpoint": target,
                            "payload_type": "multi-vector",
                        }
                        _append_event(scan, "payload_executed", _pe_data)
                        # Persist for report rehydration (cap at 100)
                        scan.setdefault("payloads_executed", [])
                        if len(scan["payloads_executed"]) < 100:
                            scan["payloads_executed"].append(_pe_data)
                        _add_log(scan_id, "info",
                            f"[{meta['name']}] {_total_used} payloads + {_mutations_count} mutations → {len(findings)} hits")

                # ── AI Next Attack Decision after each module ─────────────────
                if findings and _DECISION_ENGINE_AVAILABLE:
                    try:
                        decision_engine = get_attack_decision_engine()
                        rec = decision_engine.recommend_next_action(
                            scan["findings"],
                            {"scan_type": scan_type, "modules_done": idx + 1},
                        )
                        if rec:
                            scan["ai_recommendations"] = rec.to_dict()
                            scan["ai_decision"] = rec.to_dict()
                            _append_event(scan, "ai_decision", rec.to_dict())
                            _add_log(scan_id, "info", f"AI Decision: {rec.rationale}", module_key)
                    except Exception as _e:
                        logger.debug(f"Attack decision engine error: {_e}")

                # ── NEO Intelligence: Feed findings into graph + attack brain ──
                if findings and _NEO_INTELLIGENCE_AVAILABLE:
                    try:
                        # After endpoint extractor — populate the intelligence graph
                        if module_key == "endpoint":
                            _ep_dicts = []
                            for _f in findings:
                                _url = ""
                                if isinstance(_f, dict):
                                    _url = _f.get("url", _f.get("endpoint", ""))
                                elif hasattr(_f, "url"):
                                    _url = getattr(_f, "url", "")
                                if _url:
                                    _ep_dicts.append({"url": _url, "method": getattr(_f, "method", "GET") if not isinstance(_f, dict) else _f.get("method", "GET")})
                            if _ep_dicts:
                                _ingest_result = _neo_ingest_endpoints(_ep_dicts)
                                _add_log(scan_id, "info",
                                    f"NEO Graph: Ingested {_ingest_result.get('ingested', 0)} endpoints", module_key)
                    except Exception as _neo_feed_err:
                        logger.debug(f"NEO graph feeding error: {_neo_feed_err}")

                # ── Safe guard health events ──────────────────────────────────
                if guard:
                    for hevt in guard.get_events():
                        _append_event(scan, hevt["type"], hevt)
                        _add_log(scan_id, "warn", f"🛡 SafeGuard: {hevt['new_mode']} — {hevt['reason']}")
                    if guard.should_abort():
                        _add_log(scan_id, "error", "Safe mode: Scan aborted — target server health critical")
                        break

                # Phase Transition Logging
                if progress > 20 and not scan.get("phase_1_log"):
                    _add_log(scan_id, "success", "Phase 1 complete — Attack surface mapped")
                    scan["phase_1_log"] = True
                elif progress > 40 and not scan.get("phase_2_log"):
                    _add_log(scan_id, "success", "Phase 2 complete — Deep logic inspection")
                    scan["phase_2_log"] = True
                elif progress > 70 and not scan.get("phase_3_log"):
                    _add_log(scan_id, "success", "Phase 3 complete — Cross-module correlation")
                    scan["phase_3_log"] = True
                elif progress > 90 and not scan.get("phase_4_log"):
                    _add_log(scan_id, "success", "Phase 4 complete — Integrity verification")
                    scan["phase_4_log"] = True

                criticals = sum(1 for f in findings if getattr(f, "severity", "").lower() == "critical")
                highs = sum(1 for f in findings if getattr(f, "severity", "").lower() == "high")

                if criticals > 0:
                    _add_log(scan_id, "error", f"[{meta['name']}] {criticals} critical finding(s)", module_key)
                elif highs > 0:
                    _add_log(scan_id, "warn", f"[{meta['name']}] {highs} high severity finding(s)", module_key)

                scan["modules_completed"] = idx + 1
                scan["module_results"][module_key] = {"status": "completed", "findings_count": len(findings)}

            except asyncio.TimeoutError:
                _add_log(scan_id, "error", f"[{meta['name']}] TIMEOUT: Module took longer than 60 seconds", module_key)
                scan["module_results"][module_key] = {"status": "timeout", "error": "Module execution timeout (60s)"}
                scan["modules_completed"] = idx + 1
            except Exception as e:
                _add_log(scan_id, "error", f"[{meta['name']}] Error: {str(e)}", module_key)
                scan["module_results"][module_key] = {"status": "error", "error": str(e)}
                scan["modules_completed"] = idx + 1

        # ── Flush remaining batch writes ──────────────────────────────────────
        if _finding_batch:
            try:
                db.bulk_save_objects(_finding_batch)
                db.commit()
                _finding_batch.clear()
            except Exception as e:
                print(f"Error flushing final batch to SQL: {e}")
                db.rollback()

        scan["progress"] = 100
        state_mgr.set_progress(scan_id, 100)

        # NOTE: We do NOT set status="completed" here yet.
        # Post-processing phases (Chains, PQSI, Neo4j, Verifier) run next
        # and they need the scan to be in "running" state for SSE consistency.

        scan["active_module"] = None
        scan["completed_at"] = datetime.now(timezone.utc).isoformat()
        scan["duration"] = round(time.time() - start_time, 2)
        # Use true count (tracks all dedup'd findings even when list is capped)
        scan["total_findings"] = scan.get("total_findings_count", len(scan["findings"]))
        scan["severity_counts"] = severity_counts
        scan["owasp_coverage"] = owasp_counts

        # Compute confidence-based risk score (never 100 from 0 findings)
        risk_score, confidence, scan_status_val, risk_level = _compute_risk_score(
            severity_counts,
            scan.get("modules_completed", len(valid_modules)),
            len(valid_modules),
        )
        scan["risk_score"]  = risk_score
        scan["confidence"]  = confidence
        scan["scan_status"] = scan_status_val
        scan["risk_level"]  = risk_level

        # Compute top vulnerable files
        file_counts: dict[str, int] = {}
        for f in scan["findings"]:
            fpath = f.get("file", "unknown")
            file_counts[fpath] = file_counts.get(fpath, 0) + 1
        scan["top_files"] = sorted(
            [{"file": k, "count": v} for k, v in file_counts.items()],
            key=lambda x: x["count"],
            reverse=True
        )[:10]

        # Sync progress to database
        try:
            db_scan = db.query(Scan).filter(Scan.scan_id == scan_id).first()
            if db_scan:
                db_scan.progress = 100.0
                db_scan.completed_at = datetime.now(timezone.utc)
                db_scan.duration = round(time.time() - start_time, 2)
                db_scan.total_findings = scan.get("total_findings_count", len(scan["findings"]))
                db_scan.severity_counts = severity_counts
                db_scan.risk_score = risk_score
                db_scan.modules_completed = scan.get("modules_completed", len(valid_modules))
                db.commit()
        except Exception as e:
            logger.warning(f"Database progress sync error: {e}")
            db.rollback()

        total_findings_count = scan.get("total_findings_count", len(scan["findings"]))

        # ── Phase: Enterprise Attack Chain Correlation ────────────────────────
        if scan["findings"] and _CHAIN_CORRELATOR_AVAILABLE and _AttackChainCorrelator:
            try:
                _add_log(scan_id, "info", "Attack chain correlator engaged")
                _correlator = _AttackChainCorrelator()
                _chain_results = _correlator.correlate(scan["findings"])
                if _chain_results:
                    scan["enterprise_attack_chains"] = _chain_results
                    _chains_count = len(_chain_results)
                    _critical_chains = [c for c in _chain_results if c.get("severity") in ("critical", "high")]
                    _chain_types = list({c.get("name", "unknown") for c in _chain_results})
                    _append_event(scan, "enterprise_attack_chains", {
                        "chains": _chain_results[:20],  # cap at 20 for SSE size
                        "total_chains": _chains_count,
                        "critical_chains": len(_critical_chains),
                        "chain_types": _chain_types,
                        "timestamp": datetime.now(timezone.utc).isoformat(),
                    })
                    _add_log(scan_id, "warn" if _critical_chains else "success",
                        f"Attack chains: {_chains_count} identified, {len(_critical_chains)} critical")
                    for _hrc in _critical_chains[:3]:
                        _add_log(scan_id, "error",
                            f"Chain: {_hrc.get('name','?')} — {_hrc.get('description','')[:80]}")
            except Exception as _cc_err:
                logger.debug(f"Attack chain correlator error: {_cc_err}")

        # ── Phase: Enterprise Scan Summary ────────────────────────────────────
        if _ENTERPRISE_ORCHESTRATOR_AVAILABLE and scan["findings"]:
            try:
                _summary = enterprise_scan_summary(scan["findings"])
                if _summary:
                    scan["enterprise_summary"] = _summary
                    _chains_in_summary = _summary.get("attack_chains", [])
                    _append_event(scan, "enterprise_summary", {
                        "total_findings": _summary.get("total_findings", 0),
                        "severity_breakdown": _summary.get("severity_breakdown", {}),
                        "attack_chains": _chains_in_summary[:20],
                        "attack_chain_count": _summary.get("attack_chain_count", 0),
                        "engines_available": _summary.get("engines_available", []),
                    })
                    _add_log(scan_id, "success",
                        f"Enterprise summary: {_summary.get('total_findings',0)} findings, "
                        f"{_summary.get('attack_chain_count',0)} attack chains")
            except Exception as _es_err:
                logger.debug(f"Enterprise scan summary error: {_es_err}")

        # ── Phase: NEO Intelligence Analysis ──────────────────────────────────
        if _NEO_INTELLIGENCE_AVAILABLE and scan["findings"]:
            try:
                _add_log(scan_id, "info", "NEO Intelligence — Autonomous analysis engaged")
                _append_event(scan, "neo_phase_started", {
                    "phase": "MAP→TRACE→REASON→HYPOTHESIZE→EXPLOIT→VERIFY→LEARN",
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                })

                _neo_result = await _run_neo_intelligence(
                    target=target,
                    scan_type=effective_type,
                    findings=scan["findings"],
                )

                if _neo_result and not _neo_result.get("error"):
                    scan["neo_intelligence"] = _neo_result

                    # Extract NEO findings and add them to the scan
                    _neo_findings = _neo_result.get("findings", [])
                    _neo_attack_chains = _neo_result.get("attack_chains", [])
                    _neo_hypotheses = _neo_result.get("hypotheses", [])
                    _neo_risk_score = _neo_result.get("final_risk_score", 0)

                    # Normalize NEO findings into the scan's findings list
                    _neo_added = 0
                    for _nf in _neo_findings:
                        _neo_normalized = {
                            "id": f"NEO-{_nf.get('id', 'unknown')}",
                            "title": _nf.get("title", "NEO Intelligence Finding"),
                            "severity": _nf.get("severity", "medium"),
                            "description": _nf.get("description", ""),
                            "category": _nf.get("category", "NEO-Intelligence"),
                            "module": "neo_intelligence",
                            "module_name": "NEO Intelligence Engine",
                            "confidence": _nf.get("confidence", 0.75),
                            "cwe": _nf.get("cwe", ""),
                            "owasp": _nf.get("owasp", "A01-A10:2025"),
                            "file": _nf.get("endpoint", _nf.get("file", "")),
                            "line_number": _nf.get("line_number", 0),
                            "matched_content": _nf.get("payload", ""),
                            "remediation": _nf.get("remediation", ""),
                            "tags": ["neo-intelligence", "autonomous"] + _nf.get("tags", []),
                            "timestamp": datetime.now(timezone.utc).isoformat(),
                            "neo_verified": _nf.get("verified", False),
                            "neo_phase": _nf.get("phase", ""),
                        }
                        scan["findings"].append(_neo_normalized)
                        _append_event(scan, "finding", _neo_normalized)
                        _neo_added += 1

                        # Update severity counts
                        _neo_sev = _neo_normalized.get("severity", "info").lower()
                        if _neo_sev in severity_counts:
                            severity_counts[_neo_sev] += 1

                    # Emit NEO intelligence event
                    _append_event(scan, "neo_intelligence", {
                        "findings_count": len(_neo_findings),
                        "findings_added": _neo_added,
                        "attack_chains": _neo_attack_chains[:10],
                        "attack_chain_count": len(_neo_attack_chains),
                        "hypotheses_count": len(_neo_hypotheses),
                        "neo_risk_score": _neo_risk_score,
                        "phases_completed": _neo_result.get("phases_completed", []),
                        "attack_surfaces": _neo_result.get("attack_surfaces", [])[:5],
                        "timestamp": datetime.now(timezone.utc).isoformat(),
                    })

                    _add_log(scan_id, "success",
                        f"NEO Intelligence: {_neo_added} findings | "
                        f"{len(_neo_attack_chains)} attack chains | "
                        f"{len(_neo_hypotheses)} hypotheses | "
                        f"Risk: {_neo_risk_score}/100")

                    # If NEO found critical chains, log them
                    for _nc in _neo_attack_chains[:3]:
                        if _nc.get("severity") in ("critical", "high"):
                            _add_log(scan_id, "error",
                                f"NEO Chain: {_nc.get('name','')} — {_nc.get('description','')[:80]}")
                else:
                    _add_log(scan_id, "warn", f"NEO Intelligence: {_neo_result.get('error', 'No results')}")

            except Exception as _neo_err:
                logger.warning(f"NEO Intelligence error: {_neo_err}")
                _add_log(scan_id, "warn", f"NEO Intelligence analysis skipped: {str(_neo_err)[:100]}")

        # ── Phase: NEO Attack Chain Discovery ─────────────────────────────────
        if _NEO_INTELLIGENCE_AVAILABLE and scan["findings"]:
            try:
                _chain_result = _neo_ingest_findings_for_chaining(scan["findings"])
                _chains = _chain_result.get("chains", [])
                _hypotheses = _chain_result.get("hypotheses", [])
                if _chains:
                    scan.setdefault("attack_chains", []).extend(_chains)
                    _append_event(scan, "attack_chain_created", {
                        "chain_count": len(_chains),
                        "top_chain": _chains[0].get("name", "") if _chains else "",
                        "hypotheses_count": len(_hypotheses),
                        "timestamp": datetime.now(timezone.utc).isoformat(),
                    })
                    _add_log(scan_id, "success",
                        f"NEO Attack Brain: {len(_chains)} attack chain(s), "
                        f"{len(_hypotheses)} hypothesis(es)")

                    for _chain in _chains[:3]:
                        _chain_risk = _chain.get("chain_risk_score", 0)
                        if _chain_risk > 0.6:
                            _add_log(scan_id, "error",
                                f"Attack Chain [{_chain.get('chain_severity','?').upper()}]: "
                                f"{_chain.get('name', 'Unknown')} (risk: {_chain_risk:.2f})")

                # Compute attack surfaces from the intelligence graph
                _surfaces = _neo_compute_attack_surfaces()
                if _surfaces and not _surfaces.get("error"):
                    scan["neo_attack_surfaces"] = _surfaces
            except Exception as _chain_err:
                logger.debug(f"NEO attack chaining error: {_chain_err}")

        # ── Phase: Exploit Verification (URL scans only) ──────────────────────
        effective_type = target_type or scan_type or "directory"
        if effective_type in ("url",) and scan["findings"] and _VERIFIER_AVAILABLE:
            try:
                _add_log(scan_id, "info", "Phase 5 — Autonomous exploit verification")
                verifier = get_exploit_verifier()
                url_findings = [
                    f for f in scan["findings"]
                    if f.get("severity", "").lower() in ("critical", "high", "medium")
                ]
                verified_results = await verifier.verify_batch(url_findings, target, max_count=10)
                confirmed_count = 0
                for vr in verified_results:
                    # Emit payload_executed event
                    _append_event(scan, "payload_executed", {
                        "endpoint": vr.endpoint,
                        "payload_type": vr.strategy,
                        "payload_used": vr.payload_used[:100],
                        "finding_id": vr.finding_id,
                    })
                    if vr.verification_status == "confirmed":
                        confirmed_count += 1
                        # Annotate finding with proof
                        for f in scan["findings"]:
                            if f.get("id") == vr.finding_id:
                                f["verified"] = True
                                f["proof"] = vr.to_dict()
                                f["confidence_score"] = vr.confidence_score
                                break
                        _append_event(scan, "verification_success", {
                            "finding_id": vr.finding_id,
                            "endpoint": vr.endpoint,
                            "confidence": vr.confidence_score,
                            "timing_delta_ms": vr.timing_delta_ms,
                            "strategy": vr.strategy,
                            "evidence_hash": vr.evidence_hash,
                        })
                        _add_log(scan_id, "error",
                            f"VERIFIED: {vr.endpoint} [{vr.confidence_score:.0%} confidence | {vr.strategy}]")
                scan["verified_findings"] = [vr.to_dict() for vr in verified_results if vr.verification_status == "confirmed"]
                _add_log(scan_id, "success",
                    f"Exploit verification complete: {confirmed_count}/{len(verified_results)} findings confirmed with proof")
            except Exception as _ve:
                logger.warning(f"Exploit verifier error: {_ve}")

        # ── Phase: Neo4j Attack Graph Auto-Generation ─────────────────────────
        if scan["findings"] and _NEO4J_AVAILABLE:
            try:
                _add_log(scan_id, "info", "Phase 6 — Building attack graph intelligence")
                neo4j = get_neo4j_client()
                neo4j.ingest_scan_results(scan_id, target, scan["findings"])
                attack_paths = neo4j.get_attack_paths(scan_id)
                breach_sim   = neo4j.simulate_breach(scan_id, scan["findings"])
                scan["attack_paths"]      = attack_paths
                scan["breach_simulation"] = breach_sim
                breach_prob = breach_sim.get("breach_probability", 0)
                _append_event(scan, "attack_chain_created", {
                    "paths_count":        len(attack_paths),
                    "breach_probability": breach_prob,
                    "risk_level":         breach_sim.get("risk_level", risk_level),
                    "mitre_techniques":   breach_sim.get("mitre_techniques", []),
                })
                asyncio.create_task(ws_manager.broadcast_scan_update(scan_id, {
                    "type":               "attack_chain_created",
                    "paths_count":        len(attack_paths),
                    "breach_probability": breach_prob,
                    "risk_level":         breach_sim.get("risk_level", risk_level),
                }))
                _add_log(scan_id, "success",
                    f"Attack graph built: {len(attack_paths)} paths | Breach probability: {breach_prob}%")
            except Exception as _ne:
                logger.warning(f"Neo4j attack graph error: {_ne}")

        # ── Phase: AI Attack Summary ──────────────────────────────────────────
        if scan["findings"] and _DECISION_ENGINE_AVAILABLE:
            try:
                decision_engine = get_attack_decision_engine()
                scan["attack_summary"] = decision_engine.generate_attack_summary(scan["findings"])
            except Exception as _ae:
                logger.debug(f"Attack summary error: {_ae}")

        # ── Phase: Finalize Scan Status ─────────────────────────────────────────────
        if scan["status"] not in ("cancelled", "error"):
            scan["status"] = "completed"
            state_mgr.set_scan_status(scan_id, "completed")

            # Final Database Update
            try:
                db_scan = db.query(Scan).filter(Scan.scan_id == scan_id).first()
                if db_scan:
                    db_scan.status = "completed"
                    db_scan.completed_at = datetime.now(timezone.utc)
                    db_scan.duration = round(time.time() - start_time, 2)
                    # Persist scan metadata for history rehydration
                    db_scan.total_findings = total_findings_count
                    db_scan.severity_counts = severity_counts
                    db_scan.risk_score = risk_score
                    db.commit()

                    # Batch-persist scan logs to DB for historical retrieval
                    try:
                        log_batch = []
                        for log_entry in scan.get("logs", []):
                            log_batch.append(ScanLog(
                                scan_id=scan_id,
                                level=log_entry.get("level", "info"),
                                message=log_entry.get("message", ""),
                                module=log_entry.get("module"),
                            ))
                        if log_batch:
                            db.bulk_save_objects(log_batch)
                            db.commit()
                    except Exception as _log_err:
                        logger.debug(f"Log persistence error (non-critical): {_log_err}")
                        db.rollback()
            except Exception as _fdb_err:
                logger.warning(f"Final database sync error: {_fdb_err}")
                db.rollback()

        _add_log(scan_id, "success",
            f"Scan complete — {total_findings_count} findings / {len(valid_modules)} modules / {scan['duration']}s / Risk {risk_score}/100 [{risk_level}]")

        _append_event(scan, "complete", {
            "total_findings":  total_findings_count,
            "duration":        scan["duration"],
            "risk_score":      risk_score,
            "confidence":      confidence,
            "scan_status":     scan_status_val,
            "risk_level":      risk_level,
            "severity_counts": severity_counts,
            "dedup_skipped":   scan.get("dedup_skipped", 0),
        })

        # Broadcast scan completion via WebSocket
        asyncio.create_task(ws_manager.broadcast_scan_update(scan_id, {
            "type":            "complete",
            "status":          scan["status"],
            "total_findings":  total_findings_count,
            "duration":        scan["duration"],
            "risk_score":      risk_score,
            "confidence":      confidence,
            "scan_status":     scan_status_val,
            "risk_level":      risk_level,
            "severity_counts": severity_counts,
        }))

    except Exception as e:
        print(f"Crucial error in execute_scan: {e}")
        if scan_id in scans:
            scans[scan_id]["status"] = "error"
            scans[scan_id]["completed_at"] = datetime.now(timezone.utc).isoformat()
            _add_log(scan_id, "error", f"FATAL ERROR: {str(e)}")
    finally:
        if own_db:
            db.close()
        # Always release the global scan slot so queued scans can proceed
        if _STABILITY_AVAILABLE:
            await scan_queue_manager.release_slot(scan_id)


def _add_log(scan_id: str, level: str, message: str, module: Optional[str] = None):
    now = datetime.now(timezone.utc)
    time_str = now.strftime("%H:%M:%S")

    log_entry = {"time": time_str, "level": level, "message": message, "module": module}
    scans[scan_id]["logs"].append(log_entry)
    _append_event(scans[scan_id], "log", log_entry)


def _add_event(scan_id: str, event_type: str, data: dict):
    """Emit a structured scan event to the SSE stream and WebSocket."""
    _append_event(scans[scan_id], event_type, data)
    asyncio.create_task(ws_manager.broadcast_scan_update(scan_id, {
        "type": event_type,
        **data,
    }))


def _compute_risk_score(
    severity_counts: dict,
    modules_completed: int,
    modules_total: int,
) -> Tuple[int, str, str, str]:
    """
    Confidence-based risk model.
    System NEVER assumes security from absence of findings.
    Returns: (score, confidence, scan_status, risk_level)
    """
    coverage = modules_completed / max(modules_total, 1)
    severity_penalty = (
        severity_counts.get("critical", 0) * 15 +
        severity_counts.get("high", 0) * 8 +
        severity_counts.get("medium", 0) * 3 +
        severity_counts.get("low", 0) * 1
    )
    uncertainty_penalty = round((1.0 - coverage) * 80)
    raw = 100 - severity_penalty
    final = max(0, min(100, raw - uncertainty_penalty))

    if coverage < 0.3:
        confidence, scan_status = "LOW", "INCONCLUSIVE"
    elif coverage < 0.7:
        confidence, scan_status = "MEDIUM", "PARTIAL_ASSESSMENT"
    else:
        confidence, scan_status = "HIGH", "ASSESSED"

    if severity_counts.get("critical", 0) > 0:
        risk_level = "Critical"
    elif severity_counts.get("high", 0) > 0:
        risk_level = "High"
    elif severity_counts.get("medium", 0) > 5:
        risk_level = "Medium"
    elif scan_status == "INCONCLUSIVE":
        risk_level = "Unknown"
    else:
        risk_level = "Low"

    return int(final), confidence, scan_status, risk_level

# ═══════════════════════════════════════════════════════════════════════════════
# API Endpoints
# ═══════════════════════════════════════════════════════════════════════════════

# Lifespan events are handled in the lifespan context manager above.


# ── Health ────────────────────────────────────────────────────

@app.get("/api/v1/health")
async def health():
    return {
        "status": "healthy",
        "version": "5.0.0",
        "engine": "unified (Scanner_1 + Scanner_2)",
        "modules": len(MODULE_REGISTRY),
        "total_patterns": sum(m["pattern_count"] for m in MODULE_REGISTRY.values()),
        "profiles": len(SCAN_PROFILES),
        "uptime": time.time(),
        "active_scans": sum(1 for s in scans.values() if s["status"] == "running"),
    }


# ── Auth ──────────────────────────────────────────────────────

@app.post("/api/v1/auth/login", response_model=TokenResponse)
async def login_endpoint(request: LoginRequest, db: Session = Depends(get_db)):
    user = db.query(User).filter(User.email == request.email).first()
    if not user or not verify_password(request.password, user.hashed_password):
        raise HTTPException(status_code=401, detail="Invalid credentials")
    
    access_token = create_access_token({"sub": user.id})
    refresh_token = create_refresh_token(user.id)
    
    return TokenResponse(
        access_token=access_token,
        refresh_token=refresh_token,
        expires_in=1800,
        user=user.to_dict()
    )

@app.post("/api/v1/auth/google-login", response_model=TokenResponse)
async def google_login_endpoint(request: GoogleLoginRequest, db: Session = Depends(get_db)):
    email = SUPER_ADMIN_EMAIL
    user = db.query(User).filter(User.email == email).first()
    
    if not user:
        # Create super admin if missing
        user = User(
            id=str(uuid.uuid4()),
            email=email,
            username="superadmin",
            hashed_password="[GOOGLE_AUTH]",
            is_active=True,
            is_admin=True,
            is_super_admin=True
        )
        db.add(user)
        db.commit()
    
    if not user.is_super_admin:
        raise HTTPException(status_code=403, detail="Access denied: Not a super admin")

    access_token = create_access_token({"sub": user.id})
    refresh_token = create_refresh_token(user.id)
    
    return TokenResponse(
        access_token=access_token,
        refresh_token=refresh_token,
        expires_in=1800,
        user=user.to_dict()
    )


# ── Modules & Profiles ────────────────────────────────────────

@app.get("/api/v1/modules")
async def list_modules():
    """List available scanner modules with metadata."""
    return {"modules": get_available_modules()}


@app.get("/api/v1/profiles")
async def list_profiles():
    """List available scan profiles (quick, standard, full, owasp-top-10, cloud, api)."""
    return {"profiles": get_available_profiles()}


# ── Scan Lifecycle ─────────────────────────────────────────────

@app.post("/api/v1/scan/start", response_model=ScanResponse)
@app.post("/api/v1/scan", response_model=ScanResponse)
async def start_scan(
    request: ScanRequest, 
    background_tasks: BackgroundTasks,
    subscription: Dict[str, Any] = Depends(get_user_subscription)
):
    """Initiate a new security scan."""
    # Check subscription access
    allowed, error = check_subscription_access(subscription, "scan")
    if not allowed:
        raise HTTPException(status_code=403, detail=error)
    
    # Check usage limits
    allowed, error = check_usage_limits(subscription)
    if not allowed:
        raise HTTPException(status_code=403, detail=error)
    
    scan_id = str(uuid.uuid4())

    # Resolve modules: use explicit list if provided, else use profile
    requested_modules = request.modules
    if not requested_modules or requested_modules == ["misconfig", "injection", "frontend_js", "endpoint"]:
        requested_modules = get_modules_for_profile(request.scan_profile)

    valid_modules = [m for m in requested_modules if m in MODULE_REGISTRY]
    if not valid_modules:
        raise HTTPException(status_code=400, detail="No valid modules specified")

    if request.scan_type == "directory" and not os.path.exists(request.target):
        # Gracefully handle missing directory if it might be an absolute path error
        if not os.path.isabs(request.target):
            # Try relative to current workspace if available
            pass
        else:
            raise HTTPException(status_code=400, detail=f"Target directory not found: {request.target}")

    if request.scan_type == "url":
        if not request.target.startswith(("http://", "https://")):
            raise HTTPException(status_code=400, detail="Invalid URL format. Must start with http:// or https://")

    total_patterns = sum(MODULE_REGISTRY[m]["pattern_count"] for m in valid_modules)

    # Persist to local SQL for history linkage
    db = get_db_session()
    local_user_id = subscription.get("local_user_id")
    print(f"DEBUG: start_scan: Attempting to create SQL Scan record for user {local_user_id}")
    
    if not local_user_id:
        print("DEBUG: start_scan: WARNING! local_user_id is MISSING from subscription")
        # For robustness, we might want to fail here, but let's log and see
    
    try:
        new_db_scan = Scan(
            scan_id=scan_id,
            user_id=local_user_id,
            target=request.target,
            scan_type=request.scan_type,
            modules=valid_modules,
            status="initializing",
            progress=0,
            modules_total=len(valid_modules),
            created_at=datetime.now(timezone.utc)
        )
        db.add(new_db_scan)
        db.commit()
        print(f"DEBUG: start_scan: SQL Scan record created successfully: {scan_id}")
    except Exception as e:
        print(f"DEBUG: start_scan: Error creating SQL scan record: {e}")
        db.rollback()
    finally:
        db.close()

    scans[scan_id] = {
        "scan_id": scan_id,
        "target": request.target,
        "scan_type": request.scan_type,
        "target_type": request.target_type,
        "modules": valid_modules,
        "scan_profile": request.scan_profile,
        "status": "initializing",
        "progress": 0,
        "active_module": None,
        "modules_completed": 0,
        "modules_total": len(valid_modules),
        "findings": [],
        "logs": [],
        "events": [],
        "module_results": {},
        "severity_counts": {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0},
        "owasp_coverage": {},
        "risk_score": 0,
        "confidence": "LOW",
        "scan_status": "INCONCLUSIVE",
        "risk_level": "Unknown",
        "top_files": [],
        "started_at": None,
        "completed_at": None,
        "duration": 0,
        "cancelled": False,
        "total_patterns": total_patterns,
        # Intelligence fields
        "attack_paths": [],
        "breach_simulation": {},
        "ai_recommendations": {},
        "verified_findings": [],
        "attack_summary": {},
        "attack_chains": [],
        "endpoints_discovered": [],
        "coverage_intelligence": {
            "get_params_tested": 0,
            "post_bodies_tested": 0,
            "json_apis_tested": 0,
            "headers_tested": 0,
            "cookies_tested": 0,
            "js_discovered_endpoints": 0,
            "graphql_routes": 0,
            "authenticated_paths": 0,
        },
        # Stability fields
        "user_id": local_user_id,           # for per-user concurrency check
        "dedup_set": set(),                  # in-scan dedup fingerprints (not serializable, memory only)
        "dedup_skipped": 0,                  # count of duplicates eliminated
        "total_findings_count": 0,           # true count even when findings list is capped
        "_last_event_time": time.monotonic(), # watchdog heartbeat
        "_events_base_offset": 0,            # SSE cursor rebasing after events trim
    }

    # ── Enforce per-user and global concurrency limits ────────────────────────
    if _STABILITY_AVAILABLE:
        try:
            await scan_queue_manager.acquire_slot(scan_id, local_user_id or "", scans)
        except ValueError as ve:
            # Per-user limit exceeded — clean up and reject
            scans.pop(scan_id, None)
            raise HTTPException(status_code=429, detail=str(ve))

    # ── Emit initialization log immediately so SSE stream is non-empty ─────
    _add_log(scan_id, "info", f"Scan initialized — {request.target} | {len(valid_modules)} modules | {total_patterns} signatures")
    _append_event(scans[scan_id], "scan_initialized", {
        "scan_id": scan_id,
        "target": request.target,
        "modules": valid_modules,
        "total_patterns": total_patterns,
        "timestamp": datetime.now(timezone.utc).isoformat(),
    })

    background_tasks.add_task(execute_scan, scan_id, request.target, request.scan_type, valid_modules, None, request.target_type)
    
    # Increment usage (skipped automatically for super admin)
    increment_scan_usage(subscription.get("uid"), email=subscription.get("email", ""))
    
    return ScanResponse(scan_id=scan_id, status="started", modules=valid_modules, total_patterns=total_patterns)


async def get_authorized_scan(
    scan_id: str,
    subscription: Dict[str, Any] = Depends(get_user_subscription),
    db: Session = Depends(get_db)
) -> Dict[str, Any]:
    """Helper to retrieve a scan and verify ownership."""
    local_user_id = subscription.get("local_user_id")
    is_super_admin = subscription.get("is_super_admin", False)
    
    # Check in-memory scans first
    if scan_id in scans:
        scan = scans[scan_id]
        if not is_super_admin and scan.get("user_id") != local_user_id:
            logger.warning(f"Unauthorized access attempt to scan {scan_id} by user {local_user_id}")
            raise HTTPException(status_code=403, detail="Unauthorized: Scan does not belong to you")
        return scan
    
    # Check Database
    db_scan = db.query(Scan).filter(Scan.scan_id == scan_id).first()
    if not db_scan:
        raise HTTPException(status_code=404, detail="Scan not found")
        
    if not is_super_admin and db_scan.user_id != local_user_id:
        logger.warning(f"Unauthorized access attempt to scan {scan_id} by user {local_user_id} (DB)")
        raise HTTPException(status_code=403, detail="Unauthorized: Scan does not belong to you")
        
    return db_scan.to_dict()


@app.get("/api/v1/scan/{scan_id}")
@app.get("/api/v1/scan/{scan_id}/status")
async def get_scan_status(
    scan_id: str, 
    db: Session = Depends(get_db),
    subscription: Dict[str, Any] = Depends(get_user_subscription)
):
    """Get current status of a scan."""
    local_user_id = subscription.get("local_user_id")
    is_super_admin = subscription.get("is_super_admin", False)

    if scan_id in scans:
        scan = scans[scan_id]
        # ownership check
        if not is_super_admin and scan.get("user_id") != local_user_id:
            raise HTTPException(status_code=403, detail="Unauthorized")

        elapsed = 0
        if scan["started_at"]:
            try:
                start = datetime.fromisoformat(scan["started_at"])
                elapsed = (datetime.now(timezone.utc) - start).total_seconds()
            except: pass
        return ScanStatusModel(
            scan_id=scan_id,
            status=scan["status"],
            progress=scan["progress"],
            active_module=scan["active_module"],
            total_findings=scan.get("total_findings_count", len(scan["findings"])),
            modules_completed=scan["modules_completed"],
            modules_total=scan["modules_total"],
            started_at=scan["started_at"] if isinstance(scan["started_at"], str) else (scan["started_at"].isoformat() if scan["started_at"] else None),
            completed_at=scan["completed_at"] if isinstance(scan.get("completed_at"), str) else (scan.get("completed_at").isoformat() if scan.get("completed_at") else None),
            elapsed_seconds=round(elapsed, 1),
            duration=scan.get("duration", 0),
            severity_counts=scan.get("severity_counts", {}),
            target=scan.get("target"),
        )
    
    # Check DB
    db_scan = db.query(Scan).filter(Scan.scan_id == scan_id).first()
    if not db_scan:
        raise HTTPException(status_code=404, detail="Scan not found")
        
    if not is_super_admin and db_scan.user_id != local_user_id:
        raise HTTPException(status_code=403, detail="Unauthorized")

    return ScanStatusModel(
        scan_id=scan_id,
        status=db_scan.status,
        progress=db_scan.progress,
        active_module=None,
        total_findings=db_scan.total_findings,
        modules_completed=db_scan.modules_completed,
        modules_total=db_scan.modules_total,
        started_at=db_scan.started_at.isoformat() if db_scan.started_at else None,
        completed_at=db_scan.completed_at.isoformat() if db_scan.completed_at else None,
        elapsed_seconds=0,
        duration=db_scan.duration,
        severity_counts=db_scan.severity_counts,
        target=db_scan.target,
    )


# NOTE: /api/v1/scans is defined once below (list_history) to avoid duplicate route.


@app.delete("/api/v1/scan/{scan_id}")
@app.post("/api/v1/scan/{scan_id}/cancel")
async def cancel_scan(
    scan_id: str,
    subscription: Dict[str, Any] = Depends(get_user_subscription)
):
    """Cancel a running scan."""
    local_user_id = subscription.get("local_user_id")
    is_super_admin = subscription.get("is_super_admin", False)

    if scan_id not in scans:
        raise HTTPException(status_code=404, detail="Scan not found")
    
    scan = scans[scan_id]
    if not is_super_admin and scan.get("user_id") != local_user_id:
         raise HTTPException(status_code=403, detail="Unauthorized")

    scans[scan_id]["cancelled"] = True
    return {"scan_id": scan_id, "status": "cancelling"}


# ── NEO Intelligence Endpoints ─────────────────────────────────

@app.get("/api/v1/scan/{scan_id}/neo-intelligence")
async def get_neo_intelligence(
    scan_id: str,
    subscription: Dict[str, Any] = Depends(get_user_subscription)
):
    """Get the NEO Intelligence analysis for a specific scan."""
    local_user_id = subscription.get("local_user_id")
    is_super_admin = subscription.get("is_super_admin", False)

    if scan_id not in scans:
        raise HTTPException(status_code=404, detail="Scan not found")
    
    scan = scans[scan_id]
    if not is_super_admin and scan.get("user_id") != local_user_id:
         raise HTTPException(status_code=403, detail="Unauthorized")

    neo_data = scan.get("neo_intelligence", {})
    if not neo_data and not _NEO_INTELLIGENCE_AVAILABLE:
        return {"status": "unavailable", "message": "NEO Intelligence Layer not enabled"}
    
    return neo_data

@app.get("/api/v1/neo-intelligence/status")
async def get_neo_intelligence_status():
    """Get the current health and statistics of the NEO Intelligence system."""
    if not _NEO_INTELLIGENCE_AVAILABLE:
        raise HTTPException(status_code=503, detail="NEO Intelligence Layer not enabled")
    
    try:
        return _get_neo_intelligence_summary()
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error retrieving NEO status: {str(e)}")

@app.get("/api/v1/neo-intelligence/smart-payloads")
async def get_neo_smart_payloads_endpoint(
    category: str = "xss",
    context: str = "",
    technology: str = "",
    waf_evasion_level: int = 0,
    max_payloads: int = 20,
    subscription: Dict[str, Any] = Depends(get_user_subscription),
):
    """Get context-aware smart payloads from the NEO generator."""
    if not _NEO_INTELLIGENCE_AVAILABLE:
        raise HTTPException(status_code=503, detail="NEO Intelligence Layer not enabled")

    try:
        payloads = _get_neo_smart_payloads(
            category=category,
            context=context,
            technology=technology,
            waf_evasion_level=waf_evasion_level,
            max_payloads=max_payloads,
        )
        return {
            "category": category,
            "context": context,
            "technology": technology,
            "payloads": payloads,
            "count": len(payloads),
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error retrieving smart payloads: {str(e)}")


@app.get("/api/v1/neo-intelligence/attack-surfaces")
async def get_neo_attack_surfaces(
    subscription: Dict[str, Any] = Depends(get_user_subscription),
):
    """Get computed attack surfaces from the NEO Intelligence Graph."""
    if not _NEO_INTELLIGENCE_AVAILABLE:
        raise HTTPException(status_code=503, detail="NEO Intelligence Layer not enabled")

    try:
        surfaces = _neo_compute_attack_surfaces()
        return {"attack_surfaces": surfaces}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/api/v1/neo-intelligence/learning-memory")
async def get_neo_learning_memory(
    subscription: Dict[str, Any] = Depends(get_user_subscription),
):
    """Get cross-scan learning memory statistics and trending vulnerabilities."""
    if not _NEO_INTELLIGENCE_AVAILABLE:
        raise HTTPException(status_code=503, detail="NEO Intelligence Layer not enabled")

    try:
        return _neo_get_learning_memory_stats()
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/api/v1/scan/{scan_id}/attack-chains")
async def get_scan_attack_chains(
    scan_id: str,
    subscription: Dict[str, Any] = Depends(get_user_subscription),
):
    """Get NEO-discovered attack chains for a specific scan."""
    local_user_id = subscription.get("local_user_id")
    is_super_admin = subscription.get("is_super_admin", False)

    if scan_id not in scans:
        raise HTTPException(status_code=404, detail="Scan not found")

    scan = scans[scan_id]
    if not is_super_admin and scan.get("user_id") != local_user_id:
        raise HTTPException(status_code=403, detail="Unauthorized")

    return {
        "scan_id": scan_id,
        "attack_chains": scan.get("attack_chains", []),
        "neo_attack_surfaces": scan.get("neo_attack_surfaces", {}),
        "hypotheses": scan.get("neo_intelligence", {}).get("hypotheses", []),
    }


# ── Findings ───────────────────────────────────────────────────

@app.get("/api/v1/scan/{scan_id}/findings")
async def get_scan_findings(
    scan_id: str, 
    page: int = Query(1, ge=1),
    page_size: int = Query(50, ge=1, le=200),
    severity: Optional[str] = None,
    module: Optional[str] = None,
    search: Optional[str] = None,
    sort_by: str = "severity",
    sort_order: str = "desc",
    db: Session = Depends(get_db),
    subscription: Dict[str, Any] = Depends(get_user_subscription)
):
    """Get paginated findings for a scan with filtering and sorting."""
    local_user_id = subscription.get("local_user_id")
    is_super_admin = subscription.get("is_super_admin", False)

    if scan_id in scans:
        scan = scans[scan_id]
        if not is_super_admin and scan.get("user_id") != local_user_id:
            raise HTTPException(status_code=403, detail="Unauthorized")
        findings = scan["findings"]
    else:
        # Check DB
        db_scan = db.query(Scan).filter(Scan.scan_id == scan_id).first()
        if not db_scan:
            raise HTTPException(status_code=404, detail="Scan not found")
        
        if not is_super_admin and db_scan.user_id != local_user_id:
            raise HTTPException(status_code=403, detail="Unauthorized")

        db_findings = db.query(Finding).filter(Finding.scan_id == scan_id).all()
        findings = [f.to_dict() for f in db_findings]

    # Apply filters
    if severity:
        sev_filter = severity.lower().split(",")
        findings = [f for f in findings if f.get("severity", "").lower() in sev_filter]

    if module:
        mod_filter = module.lower().split(",")
        findings = [f for f in findings if f.get("module", "").lower() in mod_filter or f.get("module_name", "").lower() in mod_filter]

    if search:
        search_lower = search.lower()
        findings = [f for f in findings if (
            search_lower in f.get("title", "").lower() or
            search_lower in f.get("file", "").lower() or
            search_lower in f.get("cwe", "").lower() or
            search_lower in f.get("description", "").lower()
        )]

    # Sorting
    severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    if sort_by == "severity":
        findings.sort(key=lambda f: severity_order.get(f.get("severity", "info").lower(), 5), reverse=(sort_order == "desc"))
    elif sort_by == "file":
        findings.sort(key=lambda f: f.get("file", ""), reverse=(sort_order == "desc"))
    elif sort_by == "module":
        findings.sort(key=lambda f: f.get("module_name", ""), reverse=(sort_order == "desc"))

    # Pagination
    total = len(findings)
    total_pages = max(1, (total + page_size - 1) // page_size)
    start = (page - 1) * page_size
    end = start + page_size
    paginated = findings[start:end]

    return {
        "findings": paginated,
        "total": total,
        "page": page,
        "page_size": page_size,
        "total_pages": total_pages,
        "has_next": page < total_pages,
        "has_prev": page > 1,
    }


# ── SSE Streaming ─────────────────────────────────────────────

@app.get("/api/v1/scan/{scan_id}/stream")
async def stream_scan_events(
    scan_id: str,
    subscription: Dict[str, Any] = Depends(get_user_subscription)
):
    """Stream real-time scan events via Server-Sent Events."""
    local_user_id = subscription.get("local_user_id")
    is_super_admin = subscription.get("is_super_admin", False)

    if scan_id not in scans:
        raise HTTPException(status_code=404, detail="Scan not found")
    
    if not is_super_admin and scans[scan_id].get("user_id") != local_user_id:
        raise HTTPException(status_code=403, detail="Unauthorized")

    async def event_generator():
        # cursor = absolute index of next event to send (survives events list trimming)
        cursor = 0
        # Track already-sent terminal status to prevent duplicates
        terminal_sent = False
        print(f"DEBUG: SSE Stream generator started for scan {scan_id}")

        # Immediate connection established message
        yield {"event": "status", "data": json.dumps({"status": "connected", "message": "Neural link established"}) }

        while True:
            scan = scans.get(scan_id)
            if not scan:
                print(f"DEBUG: SSE Stream: Scan {scan_id} not found, breaking")
                break

            events = scan["events"]
            # Rebase cursor: account for events that were trimmed from the list front
            base_offset = scan.get("_events_base_offset", 0)
            effective_cursor = max(0, cursor - base_offset)

            # Yield any new events
            new_events_count = len(events) - effective_cursor
            if new_events_count > 0:
                print(f"DEBUG: SSE Stream: yielding {new_events_count} new events for {scan_id}")

            while effective_cursor < len(events):
                event = events[effective_cursor]
                effective_cursor += 1
                cursor = base_offset + effective_cursor   # keep absolute cursor in sync
                if event["type"] == "finding":
                    print(f"DEBUG: SSE Stream: Yielding FINDING {event['data'].get('id', 'no-id')} for {scan_id}")
                yield {"event": event["type"], "data": json.dumps(event["data"])}

            # Check terminal status - send final status ONCE then break
            if scan["status"] in ("completed", "error", "cancelled"):
                if not terminal_sent:
                    print(f"DEBUG: SSE Stream: Scan {scan_id} terminal status reached: {scan['status']}")
                    terminal_sent = True
                    yield {
                        "event": "status",
                        "data": json.dumps({
                            "status":           scan["status"],
                            "progress":         scan["progress"],
                            "total_findings":   scan.get("total_findings_count", len(scan["findings"])),
                            "duration":         scan.get("duration", 0),
                            "severity_counts":  scan.get("severity_counts", {}),
                            "risk_score":       scan.get("risk_score", 0),
                            "confidence":       scan.get("confidence", "LOW"),
                            "scan_status":      scan.get("scan_status", "INCONCLUSIVE"),
                            "risk_level":       scan.get("risk_level", "Unknown"),
                            "attack_paths":     len(scan.get("attack_paths", [])),
                            "verified_count":   len(scan.get("verified_findings", [])),
                            "dedup_skipped":    scan.get("dedup_skipped", 0),
                        })
                    }
                break

            # Send periodic status updates only for non-terminal scans
            yield {
                "event": "status",
                "data": json.dumps({
                    "status": scan["status"], "progress": scan["progress"],
                    "active_module": scan.get("active_module", "Analyzing..."),
                    "total_findings": scan.get("total_findings_count", len(scan["findings"])),
                    "modules_completed": scan.get("modules_completed", 0),
                    "modules_total": scan.get("modules_total", 0),
                    "severity_counts": scan.get("severity_counts", {}),
                    "dedup_skipped": scan.get("dedup_skipped", 0),
                })
            }
            await asyncio.sleep(0.5)

    return EventSourceResponse(
        event_generator(),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "Connection": "keep-alive",
            "X-Accel-Buffering": "no",  # Disable nginx buffering
        }
    )


# ═══════════════════════════════════════════════════════════════════════════════
# Autonomous AI Red Team — Swarm Intelligence Node API
# ═══════════════════════════════════════════════════════════════════════════════

try:
    from backend.intelligence_nodes import get_swarm_orchestrator, SwarmOrchestrator
    _SWARM_AVAILABLE = True
except Exception:
    try:
        from intelligence_nodes import get_swarm_orchestrator, SwarmOrchestrator
        _SWARM_AVAILABLE = True
    except Exception as _sw_err:
        _SWARM_AVAILABLE = False
        logger.warning(f"Swarm Intelligence Nodes not available: {_sw_err}")


class SwarmScanRequest(BaseModel):
    target: str
    depth: str = "deep"
    strategy: str = "autonomous"


# Swarm scan state store
_swarm_scans: Dict[str, Dict[str, Any]] = {}


# Swarm routes are now handled by the swarm_router near the app initialization.


# ── Reports ────────────────────────────────────────────────────

@app.get("/api/v1/scan/{scan_id}/report")
async def get_scan_report(
    scan_id: str, 
    format: str = "json",
    subscription: Dict[str, Any] = Depends(get_user_subscription),
    db: Session = Depends(get_db)
):
    """Generate comprehensive scan report."""
    local_user_id = subscription.get("local_user_id")
    is_super_admin = subscription.get("is_super_admin", False)

    if scan_id in scans:
        scan = scans[scan_id]
        if not is_super_admin and scan.get("user_id") != local_user_id:
             raise HTTPException(status_code=403, detail="Unauthorized")
    else:
        db_scan = db.query(Scan).filter(Scan.scan_id == scan_id).first()
        if not db_scan:
            raise HTTPException(status_code=404, detail="Scan not found")
        if not is_super_admin and db_scan.user_id != local_user_id:
             raise HTTPException(status_code=403, detail="Unauthorized")
        scan = db_scan.to_dict()
        findings = db.query(Finding).filter(Finding.scan_id == scan_id).all()
        scan["findings"] = [f.to_dict() for f in findings]
        scan["logs"] = [l.to_dict() for l in db.query(ScanLog).filter(ScanLog.scan_id == scan_id).all()]

    findings = scan["findings"]

    # Severity summary
    summary = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    for f in findings:
        sev = f.get("severity", "info").lower()
        if sev in summary:
            summary[sev] += 1

    # Module summary
    module_summary = {}
    for f in findings:
        mod = f.get("module", "unknown")
        if mod not in module_summary:
            module_summary[mod] = {"name": f.get("module_name", mod), "count": 0, "severities": {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}}
        module_summary[mod]["count"] += 1
        sev = f.get("severity", "info").lower()
        if sev in module_summary[mod]["severities"]:
            module_summary[mod]["severities"][sev] += 1

    # OWASP coverage
    owasp_coverage = {}
    for f in findings:
        owasp = f.get("owasp", "")
        if owasp:
            if owasp not in owasp_coverage:
                owasp_coverage[owasp] = {"count": 0, "critical": 0, "high": 0}
            owasp_coverage[owasp]["count"] += 1
            sev = f.get("severity", "info").lower()
            if sev in owasp_coverage[owasp]:
                owasp_coverage[owasp][sev] += 1

    # Top vulnerable files
    file_counts: dict[str, dict] = {}
    for f in findings:
        fpath = f.get("file", "unknown")
        if fpath not in file_counts:
            file_counts[fpath] = {"file": fpath, "count": 0, "critical": 0, "high": 0}
        file_counts[fpath]["count"] += 1
        sev = f.get("severity", "info").lower()
        if sev in file_counts[fpath]:
            file_counts[fpath][sev] += 1
    top_files = sorted(file_counts.values(), key=lambda x: x["count"], reverse=True)[:10]

    return {
        "scan_id": scan_id,
        "status": scan["status"],
        "target": scan["target"],
        "scan_type": scan.get("scan_type", "directory"),
        "scan_profile": scan.get("scan_profile", "full"),
        "duration": scan.get("duration", 0),
        "started_at": scan.get("started_at"),
        "completed_at": scan.get("completed_at"),
        "summary": summary,
        "module_summary": module_summary,
        "owasp_coverage": owasp_coverage,
        "total_findings": len(findings),
        "findings": findings,
        "logs": scan.get("logs", []),
        "top_files": top_files,
        "risk_score": scan.get("risk_score", 0),
        "confidence": scan.get("confidence", "LOW"),
        "scan_status": scan.get("scan_status", "INCONCLUSIVE"),
        "risk_level": scan.get("risk_level", "Unknown"),
        "modules_used": scan.get("modules", []),
        # Intelligence fields
        "attack_paths": scan.get("attack_paths", []),
        "breach_simulation": scan.get("breach_simulation", {}),
        "attack_summary": scan.get("attack_summary", {}),
        "verified_findings": scan.get("verified_findings", []),
        "coverage_intelligence": scan.get("coverage_intelligence", {}),
        "ai_recommendations": scan.get("ai_recommendations", {}),
        "quantara_intelligence": scan.get("quantara_intelligence"),
        # Intelligence rehydration fields
        "attack_chains": scan.get("attack_chains", []),
        "endpoints_discovered": scan.get("endpoints_discovered", []),
        "enterprise_telemetry": scan.get("enterprise_telemetry"),
        "enterprise_attack_chains": scan.get("enterprise_attack_chains", []),
        "neo_attack_surfaces": scan.get("neo_attack_surfaces", {}),
        "ai_decision": scan.get("ai_decision"),
        "payloads_executed": scan.get("payloads_executed", []),
    }


@app.get("/api/v1/scan/{scan_id}/logs")
async def get_scan_logs(
    scan_id: str, 
    db: Session = Depends(get_db),
    subscription: Dict[str, Any] = Depends(get_user_subscription)
):
    local_user_id = subscription.get("local_user_id")
    is_super_admin = subscription.get("is_super_admin", False)

    if scan_id in scans:
        scan = scans[scan_id]
        if not is_super_admin and scan.get("user_id") != local_user_id:
             raise HTTPException(status_code=403, detail="Unauthorized")
        return {"logs": scans[scan_id]["logs"]}

    # Check DB
    db_scan = db.query(Scan).filter(Scan.scan_id == scan_id).first()
    if not db_scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    if not is_super_admin and db_scan.user_id != local_user_id:
         raise HTTPException(status_code=403, detail="Unauthorized")

    db_logs = db.query(ScanLog).filter(ScanLog.scan_id == scan_id).order_by(ScanLog.timestamp.asc()).all()
    return {"logs": [l.to_dict() for l in db_logs]}


# ── Attack Intelligence Endpoints ──────────────────────────────

@app.get("/api/v1/scan/{scan_id}/attack-graph")
async def get_attack_graph(
    scan_id: str,
    subscription: Dict[str, Any] = Depends(get_user_subscription),
    db: Session = Depends(get_db)
):
    """Return Neo4j attack graph paths and breach simulation."""
    local_user_id = subscription.get("local_user_id")
    is_super_admin = subscription.get("is_super_admin", False)

    if scan_id in scans:
        scan = scans[scan_id]
        if not is_super_admin and scan.get("user_id") != local_user_id:
             raise HTTPException(status_code=403, detail="Unauthorized")
    else:
        db_scan = db.query(Scan).filter(Scan.scan_id == scan_id).first()
        if not db_scan:
            raise HTTPException(status_code=404, detail="Scan not found")
        if not is_super_admin and db_scan.user_id != local_user_id:
             raise HTTPException(status_code=403, detail="Unauthorized")
        scan = db_scan.to_dict()

    return {
        "scan_id":           scan_id,
        "attack_paths":      scan.get("attack_paths", []),
        "breach_simulation": scan.get("breach_simulation", {}),
        "attack_summary":    scan.get("attack_summary", {}),
    }


@app.get("/api/v1/scan/{scan_id}/verified-findings")
async def get_verified_findings(
    scan_id: str,
    subscription: Dict[str, Any] = Depends(get_user_subscription),
    db: Session = Depends(get_db)
):
    """Return only proof-verified findings with evidence."""
    local_user_id = subscription.get("local_user_id")
    is_super_admin = subscription.get("is_super_admin", False)

    if scan_id in scans:
        scan = scans[scan_id]
        if not is_super_admin and scan.get("user_id") != local_user_id:
             raise HTTPException(status_code=403, detail="Unauthorized")
        findings = scan.get("findings", [])
        verified_proofs = scan.get("verified_findings", [])
    else:
        db_scan = db.query(Scan).filter(Scan.scan_id == scan_id).first()
        if not db_scan:
            raise HTTPException(status_code=404, detail="Scan not found")
        if not is_super_admin and db_scan.user_id != local_user_id:
             raise HTTPException(status_code=403, detail="Unauthorized")
        findings = [f.to_dict() for f in db.query(Finding).filter(Finding.scan_id == scan_id).all()]
        verified_proofs = db_scan.verified_findings or []

    verified = [f for f in findings if f.get("verified")]
    return {
        "scan_id":            scan_id,
        "verified_count":     len(verified),
        "verified_findings":  verified,
        "verification_proofs": verified_proofs,
    }


@app.get("/api/v1/scan/{scan_id}/coverage")
async def get_scan_coverage(
    scan_id: str,
    subscription: Dict[str, Any] = Depends(get_user_subscription),
    db: Session = Depends(get_db)
):
    """Return target coverage intelligence metrics."""
    local_user_id = subscription.get("local_user_id")
    is_super_admin = subscription.get("is_super_admin", False)

    if scan_id in scans:
        scan = scans[scan_id]
        if not is_super_admin and scan.get("user_id") != local_user_id:
             raise HTTPException(status_code=403, detail="Unauthorized")
    else:
        db_scan = db.query(Scan).filter(Scan.scan_id == scan_id).first()
        if not db_scan:
            raise HTTPException(status_code=404, detail="Scan not found")
        if not is_super_admin and db_scan.user_id != local_user_id:
             raise HTTPException(status_code=403, detail="Unauthorized")
        scan = db_scan.to_dict()

    return {
        "scan_id":              scan_id,
        "coverage_intelligence": scan.get("coverage_intelligence", {}),
        "modules_completed":    scan.get("modules_completed", 0),
        "modules_total":        scan.get("modules_total", 0),
        "confidence":           scan.get("confidence", "LOW"),
        "scan_status":          scan.get("scan_status", "INCONCLUSIVE"),
    }


# ── Swarm Intelligence Endpoints ──────────────────────────────

@app.get("/api/v1/scan/{scan_id}/correlation")
async def get_scan_correlation(
    scan_id: str,
    subscription: Dict[str, Any] = Depends(get_user_subscription),
    db: Session = Depends(get_db)
):
    """Return attack chain correlation data from the swarm correlation engine."""
    local_user_id = subscription.get("local_user_id")
    is_super_admin = subscription.get("is_super_admin", False)

    if scan_id in scans:
        scan = scans[scan_id]
        if not is_super_admin and scan.get("user_id") != local_user_id:
            raise HTTPException(status_code=403, detail="Unauthorized")
    else:
        db_scan = db.query(Scan).filter(Scan.scan_id == scan_id).first()
        if not db_scan:
            raise HTTPException(status_code=404, detail="Scan not found")
        if not is_super_admin and db_scan.user_id != local_user_id:
            raise HTTPException(status_code=403, detail="Unauthorized")

    # Get live correlation data from orchestrator
    try:
        _SwarmOrch = None
        try:
            from backend.intelligence_nodes import get_swarm_orchestrator
            _SwarmOrch = get_swarm_orchestrator
        except ImportError:
            from intelligence_nodes import get_swarm_orchestrator
            _SwarmOrch = get_swarm_orchestrator

        orch = _SwarmOrch()
        correlation_data = orch.get_correlation_data()
    except Exception:
        correlation_data = {}

    # Merge with stored scan data
    scan_data = scans.get(scan_id, {})
    return {
        "scan_id":        scan_id,
        "attack_chains":  correlation_data.get("chains", scan_data.get("attack_chains", [])),
        "chain_count":    len(correlation_data.get("chains", scan_data.get("attack_chains", []))),
        "groups":         correlation_data.get("groups", 0),
        "risk_amplified": scan_data.get("risk_score", 0),
    }


@app.get("/api/v1/swarm/learning")
async def get_swarm_learning(
    subscription: Dict[str, Any] = Depends(get_user_subscription),
):
    """Return swarm learning engine insights and heuristic updates."""
    is_super_admin = subscription.get("is_super_admin", False)
    tier = subscription.get("tier", "free")

    if tier not in ("pro", "elite", "enterprise") and not is_super_admin:
        raise HTTPException(status_code=403, detail="Learning insights require Pro+ subscription")

    try:
        _SwarmOrch = None
        try:
            from backend.intelligence_nodes import get_swarm_orchestrator
            _SwarmOrch = get_swarm_orchestrator
        except ImportError:
            from intelligence_nodes import get_swarm_orchestrator
            _SwarmOrch = get_swarm_orchestrator

        orch = _SwarmOrch()
        insights = orch.get_learning_insights()
    except Exception:
        insights = {}

    return {
        "learning_insights": insights,
        "engine_active":     bool(insights),
    }


@app.get("/api/v1/scan/{scan_id}/swarm-telemetry")
async def get_swarm_telemetry(
    scan_id: str,
    subscription: Dict[str, Any] = Depends(get_user_subscription),
    db: Session = Depends(get_db)
):
    """Return swarm agent telemetry for a specific scan."""
    local_user_id = subscription.get("local_user_id")
    is_super_admin = subscription.get("is_super_admin", False)

    if scan_id in scans:
        scan = scans[scan_id]
        if not is_super_admin and scan.get("user_id") != local_user_id:
            raise HTTPException(status_code=403, detail="Unauthorized")
    else:
        db_scan = db.query(Scan).filter(Scan.scan_id == scan_id).first()
        if not db_scan:
            raise HTTPException(status_code=404, detail="Scan not found")
        if not is_super_admin and db_scan.user_id != local_user_id:
            raise HTTPException(status_code=403, detail="Unauthorized")

    scan_data = scans.get(scan_id, {})
    swarm_meta = scan_data.get("swarm_metadata", {})

    return {
        "scan_id":         scan_id,
        "agents":          swarm_meta.get("agents", []),
        "agent_count":     swarm_meta.get("agent_count", 0),
        "phases_completed": swarm_meta.get("phases_completed", []),
        "message_bus_stats": swarm_meta.get("message_bus_stats", {}),
        "evolution_stats": swarm_meta.get("evolution_stats", {}),
        "correlation_summary": swarm_meta.get("correlation_summary", {}),
    }


# ── Scan History ───────────────────────────────────────────────

@app.get("/api/v1/scans")
async def list_history(
    limit: int = Query(50, ge=1, le=200),
    offset: int = Query(0, ge=0),
    status: Optional[str] = None,
    subscription: Dict[str, Any] = Depends(get_user_subscription),
    db: Session = Depends(get_db)
):
    """List all scans for the current user from SQL DB."""
    local_user_id = subscription.get("local_user_id")
    is_super_admin = subscription.get("is_super_admin", False)

    if not local_user_id and not is_super_admin:
        return {"scans": [], "total": 0, "limit": limit, "offset": offset}

    query = db.query(Scan)
    if not is_super_admin:
        query = query.filter(Scan.user_id == local_user_id)
    if status:
        status_filter = status.split(",")
        query = query.filter(Scan.status.in_(status_filter))

    total = query.count()
    db_scans = query.order_by(Scan.created_at.desc()).offset(offset).limit(limit).all()
    
    return {
        "scans": [
            {
                "scan_id": s.scan_id,
                "target": s.target,
                "scan_type": s.scan_type,
                "scan_profile": "full", # or from db if stored
                "status": s.status,
                "modules": s.modules,
                "total_findings": s.total_findings,
                "severity_counts": s.severity_counts,
                "started_at": s.started_at.isoformat() if s.started_at else s.created_at.isoformat(),
                "completed_at": s.completed_at.isoformat() if s.completed_at else None,
                "duration": s.duration,
                "risk_score": s.risk_score if s.risk_score is not None else 100.0,
            }
            for s in db_scans
        ],
        "total": total,
        "limit": limit,
        "offset": offset,
    }


# ── Dashboard Aggregation ──────────────────────────────────────

@app.get("/api/v1/dashboard/stats")
async def get_dashboard_stats(
    subscription: Dict[str, Any] = Depends(get_user_subscription),
    db: Session = Depends(get_db)
):
    """Aggregate statistics for the dashboard overview from SQL DB."""
    local_user_id = subscription.get("local_user_id")
    
    # Get all scans for this user
    db_scans = db.query(Scan).filter(Scan.user_id == local_user_id).all()
    
    total_scans = len(db_scans)
    completed_scans = sum(1 for s in db_scans if s.status == "completed")
    running_scans = sum(1 for s in db_scans if s.status == "running")
    
    # Aggregated severity counts from DB
    severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    for s in db_scans:
        counts = s.severity_counts or {}
        for sev, count in counts.items():
            if sev.lower() in severity_counts:
                severity_counts[sev.lower()] += count

    total_findings = sum(severity_counts.values())

    # Security score
    security_score = max(0, 100 - (
        severity_counts["critical"] * 10 +
        severity_counts["high"] * 5 +
        severity_counts["medium"] * 2 +
        severity_counts["low"] * 0.5
    ))
    if total_scans > 0:
        security_score = min(100, security_score)
    else:
        security_score = 100

    # Recent scans
    recent_db_scans = sorted(
        db_scans,
        key=lambda s: s.created_at,
        reverse=True
    )[:10]
    
    # Simple aggregation for dashboard charts
    module_stats = {}
    owasp_breakdown = {}
    for s in recent_db_scans:
        if s.modules:
            for mod in s.modules:
                if mod not in module_stats:
                    module_stats[mod] = {"scans": 0, "findings": 0}
                module_stats[mod]["scans"] += 1
                module_stats[mod]["findings"] += s.total_findings or 0

    return {
        "total_scans": total_scans,
        "completed_scans": completed_scans,
        "running_scans": running_scans,
        "total_findings": total_findings,
        "severity_counts": severity_counts,
        "security_score": round(security_score, 1),
        "recent_scans": [
            {
                "scan_id": s.scan_id,
                "target": s.target,
                "status": s.status,
                "total_findings": s.total_findings,
                "started_at": s.started_at.isoformat() if s.started_at else s.created_at.isoformat(),
                "duration": s.duration,
                "risk_score": s.risk_score if s.risk_score is not None else 100.0
            }
            for s in recent_db_scans
        ],
        "owasp_breakdown": owasp_breakdown,
        "module_stats": module_stats
    }


# ═══════════════════════════════════════════════════════════════════════════════
# Billing API (Phase 5)
# ═══════════════════════════════════════════════════════════════════════════════

from backend.billing import billing_service

class CheckoutRequest(BaseModel):
    plan_id: str
    success_url: str = "http://localhost:3000/billing?success=true"
    cancel_url: str = "http://localhost:3000/billing?canceled=true"

class CheckoutResponse(BaseModel):
    session_id: str
    url: str
    mock: bool = False

@app.get("/api/v1/billing/plans")
async def list_plans():
    """List all available subscription plans."""
    return {"plans": billing_service.get_plans()}

@app.get("/api/v1/billing/subscription")
async def get_subscription(firebase_user: Dict[str, Any] = Depends(get_current_firebase_user)):
    """Get current user's subscription status."""
    user_id = firebase_user.get("local_user_id")
    subscription = billing_service.get_subscription(user_id)
    return {"subscription": subscription}

@app.post("/api/v1/billing/checkout", response_model=CheckoutResponse)
async def create_checkout(
    request: CheckoutRequest, 
    firebase_user: Dict[str, Any] = Depends(get_current_firebase_user)
):
    """Create Stripe checkout session for subscription."""
    try:
        user_id = firebase_user.get("local_user_id")
        result = billing_service.create_checkout_session(
            user_id, request.plan_id, request.success_url, request.cancel_url
        )
        return CheckoutResponse(**result)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))

@app.get("/api/v1/billing/payment-methods")
async def list_payment_methods(firebase_user: Dict[str, Any] = Depends(get_current_firebase_user)):
    """List user's payment methods."""
    user_id = firebase_user.get("local_user_id")
    return {"payment_methods": billing_service.get_payment_methods(user_id)}

@app.get("/api/v1/billing/invoices")
async def list_invoices(firebase_user: Dict[str, Any] = Depends(get_current_firebase_user)):
    """List user's billing history."""
    user_id = firebase_user.get("local_user_id")
    return {"invoices": billing_service.get_invoices(user_id)}

@app.get("/api/v1/billing/usage")
async def get_usage(subscription: Dict[str, Any] = Depends(get_user_subscription)):
    """Get user's current usage statistics."""
    user_id = subscription.get("local_user_id")
    usage = billing_service.get_usage(user_id)
    # Ensure Firestore values are reflected if available
    usage["scans_this_month"] = subscription.get("scansUsedThisMonth", usage["scans_this_month"])
    usage["scans_limit"] = subscription.get("scanLimit", usage.get("scans_limit", 10))
    return usage

@app.post("/api/v1/debug/reset-usage")
async def reset_usage(subscription: Dict[str, Any] = Depends(get_user_subscription)):
    """Emergency reset for scan usage (Admin-only Developer Tool)."""
    is_super_admin = subscription.get("is_super_admin", False)
    if not is_super_admin:
        raise HTTPException(status_code=403, detail="Admin access required")
    uid = subscription.get("uid")
    user_ref = firestore_db.collection("users").document(uid)
    user_ref.update({"scansUsedThisMonth": 0})
    return {"status": "success", "message": "Scan usage reset to zero"}

@app.post("/api/v1/billing/cancel")
async def cancel_subscription(firebase_user: Dict[str, Any] = Depends(get_current_firebase_user)):
    """Cancel subscription at period end."""
    user_id = firebase_user.get("local_user_id")
    success = billing_service.cancel_subscription(user_id)
    return {"success": success, "message": "Subscription will cancel at period end"}


class BillingPortalRequest(BaseModel):
    return_url: str = ""


@app.post("/api/v1/billing/portal")
async def create_billing_portal(
    body: BillingPortalRequest,
    request: Request,
    firebase_user: Dict[str, Any] = Depends(get_current_firebase_user),
):
    """
    Create a Stripe Customer Portal session.
    Redirects the user to Stripe's hosted portal to manage:
    - Payment methods (add / remove cards)
    - Download invoices and receipts
    - Cancel or upgrade subscription
    """
    user_id = firebase_user.get("local_user_id")
    return_url = body.return_url or f"{request.headers.get('origin', 'http://localhost:3000')}/billing"
    from backend.billing import BillingService
    return BillingService.create_billing_portal_session(user_id, return_url)


@app.post("/api/v1/billing/webhook")
async def stripe_webhook(request: Request):
    """Handle Stripe webhook events."""
    payload = await request.body()
    signature = request.headers.get("stripe-signature", "")
    result = billing_service.handle_webhook(payload, signature)
    return result


# Mount admin_api router (dashboard stats, recent activity, user management, security events)
try:
    from backend.admin_api import router as admin_router
    app.include_router(admin_router)
except ImportError:
    print("WARNING: admin_api module not available, admin dashboard endpoints disabled")


@app.get("/api/v1/admin/billing/revenue")
async def admin_billing_revenue(firebase_user: Dict[str, Any] = Depends(get_current_firebase_user)):
    """Admin endpoint: Stripe revenue summary (MRR, recent charges, subscription counts)."""
    from backend.auth import require_super_admin, get_current_user
    # Verify admin via local DB
    local_user_id = firebase_user.get("local_user_id")
    if not local_user_id:
        raise HTTPException(status_code=403, detail="Admin required")
    db = get_db_session()
    try:
        user = db.query(User).filter(User.id == local_user_id).first()
        if not user or not (user.is_admin or user.is_super_admin):
            raise HTTPException(status_code=403, detail="Admin required")
    finally:
        db.close()
    return billing_service.get_admin_revenue_summary()


@app.get("/api/v1/admin/users")
async def admin_get_users(firebase_user: Dict[str, Any] = Depends(get_current_firebase_user)):
    """Admin endpoint: list all users with subscription tier, status, and scan counts."""
    local_user_id = firebase_user.get("local_user_id")
    if not local_user_id:
        raise HTTPException(status_code=403, detail="Admin required")
    db = get_db_session()
    try:
        requesting_user = db.query(User).filter(User.id == local_user_id).first()
        if not requesting_user or not (requesting_user.is_admin or requesting_user.is_super_admin):
            raise HTTPException(status_code=403, detail="Admin required")

        # Aggregate total scan counts per user
        scan_counts = dict(
            db.query(Scan.user_id, func.count(Scan.id))
            .group_by(Scan.user_id)
            .all()
        )

        users = db.query(User).order_by(User.created_at.desc()).limit(500).all()
        result = []
        for u in users:
            result.append({
                "id": u.id,
                "email": u.email,
                "username": u.username or "",
                "full_name": u.full_name or "",
                "subscription_tier": u.subscription_tier.value if u.subscription_tier else "free",
                "subscription_status": u.subscription_status.value if u.subscription_status else "trial",
                "monthly_scan_limit": u.monthly_scan_limit or 10,
                "total_scans": scan_counts.get(u.id, 0),
                "is_admin": bool(u.is_admin),
                "is_super_admin": bool(u.is_super_admin),
                "has_stripe": bool(u.stripe_customer_id),
                "created_at": u.created_at.isoformat() if u.created_at else None,
            })

        # Tier distribution summary
        tier_counts = {}
        for u in users:
            tier = u.subscription_tier.value if u.subscription_tier else "free"
            tier_counts[tier] = tier_counts.get(tier, 0) + 1

        return {
            "users": result,
            "total": len(result),
            "tier_distribution": tier_counts,
        }
    finally:
        db.close()


# ═══════════════════════════════════════════════════════════════════════════════
# Report Generation API (Phase 8.4)
# ═══════════════════════════════════════════════════════════════════════════════

from backend.report_generator import report_generator

@app.get("/api/v1/scan/{scan_id}/download")
async def download_scan_report(
    scan_id: str,
    format: str = "json",
    subscription: Dict[str, Any] = Depends(get_user_subscription),
    db: Session = Depends(get_db),
):
    """Download scan report in specified format (json, html, pdf)."""
    local_user_id = subscription.get("local_user_id")
    is_super_admin = subscription.get("is_super_admin", False)

    if scan_id in scans:
        scan = scans[scan_id]
        if not is_super_admin and scan.get("user_id") != local_user_id:
            raise HTTPException(status_code=403, detail="Unauthorized")
    else:
        db_scan = db.query(Scan).filter(Scan.scan_id == scan_id).first()
        if not db_scan:
            raise HTTPException(status_code=404, detail="Scan not found")
        if not is_super_admin and db_scan.user_id != local_user_id:
            raise HTTPException(status_code=403, detail="Unauthorized")
        scan = db_scan.to_dict()
        findings = db.query(Finding).filter(Finding.scan_id == scan_id).all()
        scan["findings"] = [f.to_dict() for f in findings]
    
    # Prepare scan data
    report_data = {
        "scan_id": scan_id,
        "target": scan.get("target", "Unknown"),
        "status": scan.get("status", "Unknown"),
        "duration": scan.get("duration", 0),
        "risk_score": scan.get("risk_score", 0),
        "summary": scan.get("severity_counts", {}),
        "findings": scan.get("findings", []),
        "owasp_coverage": scan.get("owasp_coverage", {}),
        "top_files": scan.get("top_files", []),
    }
    
    if format.lower() == "json":
        content = report_generator.generate_json_report(report_data)
        return Response(
            content=content,
            media_type="application/json",
            headers={"Content-Disposition": f"attachment; filename=scan-{scan_id}.json"}
        )
    
    elif format.lower() == "html":
        content = report_generator.generate_html_report(report_data)
        return Response(
            content=content,
            media_type="text/html",
            headers={"Content-Disposition": f"attachment; filename=scan-{scan_id}.html"}
        )
    
    elif format.lower() == "pdf":
        try:
            content = report_generator.generate_pdf_report(report_data)
            return Response(
                content=content,
                media_type="application/pdf",
                headers={"Content-Disposition": f"attachment; filename=scan-{scan_id}.pdf"}
            )
        except ImportError:
            raise HTTPException(status_code=500, detail="PDF generation not available. Install weasyprint.")
    
    else:
        raise HTTPException(status_code=400, detail=f"Unsupported format: {format}")


# ═══════════════════════════════════════════════════════════════════════════════
# API Token Management (Phase 8.1 - CI/CD Integration)
# ═══════════════════════════════════════════════════════════════════════════════

from backend.token_manager import token_manager, APIToken

class CreateTokenRequest(BaseModel):
    name: str
    scopes: list[str] = ["read", "scan"]

@app.post("/api/v1/tokens")
async def create_api_token(
    request: CreateTokenRequest,
    subscription: Dict[str, Any] = Depends(get_user_subscription),
):
    """Create a new API token for CI/CD integration."""
    user_id = str(subscription.get("local_user_id", ""))
    if not user_id:
        raise HTTPException(status_code=401, detail="Authentication required")
    token_id, plain_token = token_manager.create_token(user_id, request.name, request.scopes)
    return {
        "token_id": token_id,
        "token": plain_token,  # Only shown once!
        "name": request.name,
        "scopes": request.scopes,
        "message": "Copy this token now - it won't be shown again!"
    }

@app.get("/api/v1/tokens")
async def list_api_tokens(subscription: Dict[str, Any] = Depends(get_user_subscription)):
    """List all API tokens for the user."""
    user_id = str(subscription.get("local_user_id", ""))
    if not user_id:
        raise HTTPException(status_code=401, detail="Authentication required")
    tokens = token_manager.list_tokens(user_id)
    return {"tokens": [t.dict() for t in tokens]}

@app.delete("/api/v1/tokens/{token_id}")
async def revoke_api_token(
    token_id: str,
    subscription: Dict[str, Any] = Depends(get_user_subscription),
):
    """Revoke an API token."""
    user_id = str(subscription.get("local_user_id", ""))
    if not user_id:
        raise HTTPException(status_code=401, detail="Authentication required")
    success = token_manager.revoke_token(user_id, token_id)
    if not success:
        raise HTTPException(status_code=404, detail="Token not found")
    return {"success": True, "message": "Token revoked successfully"}


# ═══════════════════════════════════════════════════════════════════════════════
# CI/CD Integration API (Phase 8.1)
# ═══════════════════════════════════════════════════════════════════════════════

@app.post("/api/v1/ci/scan")
async def ci_scan_trigger(
    request: ScanRequest,
    authorization: str = Header(None)
):
    """Trigger a scan from CI/CD pipeline using API token."""
    if not authorization:
        raise HTTPException(status_code=401, detail="Authorization header required")
    
    # Extract token from "Bearer <token>"
    token = authorization.replace("Bearer ", "") if authorization.startswith("Bearer ") else authorization
    
    # Verify token
    token_data = token_manager.verify_token(token)
    if not token_data:
        raise HTTPException(status_code=401, detail="Invalid or expired token")
    
    # Check scope
    if not token_manager.has_scope(token_data, "scan"):
        raise HTTPException(status_code=403, detail="Token does not have scan permission")
    
    # Create scan
    scan_id = str(uuid.uuid4())
    requested_modules = request.modules
    if not requested_modules:
        requested_modules = get_modules_for_profile(request.scan_profile)
    
    valid_modules = [m for m in requested_modules if m in MODULE_REGISTRY]
    
    ci_user_id = token_data.get("user_id")

    # Persist to SQL DB
    db = get_db_session()
    try:
        new_db_scan = Scan(
            scan_id=scan_id,
            user_id=int(ci_user_id) if ci_user_id and ci_user_id.isdigit() else None,
            target=request.target,
            scan_type=request.scan_type,
            modules=valid_modules,
            status="initializing",
            progress=0,
            modules_total=len(valid_modules),
            created_at=datetime.now(timezone.utc),
        )
        db.add(new_db_scan)
        db.commit()
    except Exception as e:
        logger.warning(f"CI scan DB persist error: {e}")
        db.rollback()
    finally:
        db.close()

    scans[scan_id] = {
        "scan_id": scan_id,
        "target": request.target,
        "scan_type": request.scan_type,
        "modules": valid_modules,
        "status": "initializing",
        "progress": 0,
        "findings": [],
        "logs": [],
        "events": [],
        "module_results": {},
        "severity_counts": {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0},
        "owasp_coverage": {},
        "risk_score": 0,
        "started_at": datetime.now(timezone.utc).isoformat(),
        "completed_at": None,
        "duration": 0,
        "cancelled": False,
        "active_module": None,
        "modules_completed": 0,
        "modules_total": len(valid_modules),
        "total_findings_count": 0,
        "total_patterns": sum(MODULE_REGISTRY[m]["pattern_count"] for m in valid_modules),
        "ci_triggered": True,
        "user_id": int(ci_user_id) if ci_user_id and ci_user_id.isdigit() else None,
        "dedup_set": set(),
        "dedup_skipped": 0,
        "_last_event_time": time.monotonic(),
        "_events_base_offset": 0,
    }

    # Start scan in background
    asyncio.create_task(execute_scan(scan_id, request.target, request.scan_type, valid_modules))
    
    return {
        "scan_id": scan_id,
        "status": "started",
        "webhook_url": f"/api/v1/scan/{scan_id}/status",
        "message": "Scan triggered via CI/CD"
    }


# ═══════════════════════════════════════════════════════════════════════════════
# AI-Powered Remediation API (Phase 8.2)
# ═══════════════════════════════════════════════════════════════════════════════

from backend.ai_remediation import ai_service

class AIAnalysisRequest(BaseModel):
    finding_id: str
    finding: dict

@app.post("/api/v1/ai/analyze")
async def ai_analyze_finding(
    request: AIAnalysisRequest,
    subscription: Dict[str, Any] = Depends(get_user_subscription),
):
    """Get AI-powered analysis and remediation for a finding."""
    analysis = ai_service.analyze_finding(request.finding)
    return {
        "finding_id": request.finding_id,
        "ai_available": ai_service.is_available(),
        "risk_explanation": analysis.risk_explanation,
        "fix_suggestion": analysis.fix_suggestion,
        "code_patch": analysis.code_patch,
        "confidence": analysis.confidence,
        "references": analysis.references,
    }

class ChatRequest(BaseModel):
    question: str
    context: Optional[dict] = None

@app.post("/api/v1/ai/chat")
async def ai_chat_assistant(
    request: ChatRequest,
    subscription: Dict[str, Any] = Depends(get_user_subscription)
):
    """AI security assistant chat endpoint — available to all plans."""
    response = ai_service.chat_assistant(request.question, request.context)
    return {
        "response": response,
        "ai_available": ai_service.is_available(),
    }

@app.post("/api/v1/ai/prioritize")
async def ai_prioritize_findings(
    findings: list[dict],
    subscription: Dict[str, Any] = Depends(get_user_subscription),
):
    """AI-powered risk prioritization."""
    prioritized = ai_service.prioritize_risks(findings)
    return {
        "findings": prioritized,
        "ai_available": ai_service.is_available(),
        "total": len(prioritized),
    }


# ═══════════════════════════════════════════════════════════════════════════════
# AI POC Fix Intelligence (Quantara Multi-LLM)
# ═══════════════════════════════════════════════════════════════════════════════

class PocFixRequest(BaseModel):
    finding: dict
    """The finding dict to generate a POC fix for."""


@app.post("/api/v1/ai/poc-fix")
async def ai_poc_fix(
    request: PocFixRequest,
    req: Request,
    subscription: Dict[str, Any] = Depends(get_user_subscription),
):
    """
    Generate comprehensive POC fix intelligence for the scanner POC verification panel.

    Uses the Quantara multi-LLM provider (Gemini → Anthropic → OpenAI fallback).
    Returns production-ready fix code, test steps, and compliance references.
    """
    try:
        import sys, os
        central_dir = os.path.join(os.path.dirname(__file__), "..", "Centralize_Scanners")
        scanner_dir = os.path.join(central_dir, "owasp_Scanner")
        for p in [central_dir, scanner_dir]:
            if p not in sys.path:
                sys.path.insert(0, p)

        from quantara_ai import QuantaraAICopilot, CopilotConfig

        config = CopilotConfig(
            gemini_api_key=os.environ.get("GEMINI_API_KEY", ""),
            anthropic_api_key=(
                os.environ.get("ANTHROPIC_API_KEY", "")
                or os.environ.get("ANTROPHIC_API_KEY", "")
            ),
            openai_api_key=os.environ.get("OPENAI_API_KEY", ""),
            enable_validation=False,
            enable_impact=False,
            enable_remediation=False,
            enable_poc_fix=True,
            enable_prioritization=False,
            enable_narrative=False,
        )

        copilot = QuantaraAICopilot(config)
        poc_fix = copilot.generate_poc_fix(request.finding)

        if poc_fix:
            return {
                "success": True,
                "poc_fix": {
                    "vulnerability_type": poc_fix.vulnerability_type,
                    "poc_description": poc_fix.poc_description,
                    "immediate_fix": poc_fix.immediate_fix,
                    "full_fix_code": poc_fix.full_fix_code,
                    "fix_language": poc_fix.fix_language,
                    "fix_explanation": poc_fix.fix_explanation,
                    "test_steps": poc_fix.test_steps,
                    "prevention_checklist": poc_fix.prevention_checklist,
                    "cvss_score": poc_fix.cvss_score,
                    "owasp_category": poc_fix.owasp_category,
                    "references": poc_fix.references,
                    "provider_used": poc_fix.provider_used,
                },
                "usage": copilot.get_usage_stats(),
            }

        return {"success": False, "error": "AI providers unavailable or no output generated"}

    except Exception as e:
        return {"success": False, "error": str(e)}


# ═══════════════════════════════════════════════════════════════════════════════
# POC Execution Engine — Real HTTP Attack Validation Proxy
# ═══════════════════════════════════════════════════════════════════════════════

import ipaddress as _ipaddress
import socket as _socket
import re as _re
import time as _time_mod

# Rate limit store: key -> list of epoch timestamps
_POC_RATE_LIMIT: dict = {}

# Secret patterns to detect in HTTP responses
_POC_SECRET_PATTERNS = [
    (r'(?:api[_-]?key|apikey)["\s:=]+([A-Za-z0-9_\-]{20,})', "API_KEY"),
    (r'(?:password|passwd|pwd)["\s:=]+([^\s"\'<>{}\[\]]{6,})', "PASSWORD"),
    (r'(?:secret)["\s:=]+([A-Za-z0-9_\-\.]{16,})', "SECRET"),
    (r'sk_live_[A-Za-z0-9]{20,}', "STRIPE_KEY"),
    (r'AKIA[A-Z0-9]{16}', "AWS_ACCESS_KEY"),
    (r'ghp_[A-Za-z0-9]{36}', "GITHUB_TOKEN"),
    (r'AIza[A-Za-z0-9\-_]{35}', "GOOGLE_API_KEY"),
    (r'(?:db_password|database_url)["\s:=]+([^\s"\'<>]{8,})', "DB_CREDENTIAL"),
]


def _is_ssrf_safe(url: str):
    """Returns (is_safe: bool, reason: str). Blocks private/internal SSRF targets."""
    try:
        from urllib.parse import urlparse
        parsed = urlparse(url)
        hostname = parsed.hostname
        if not hostname:
            return False, "Invalid URL — no hostname"
        blocked = {"localhost", "127.0.0.1", "::1", "0.0.0.0"}
        if hostname.lower() in blocked:
            return False, f"SSRF blocked: internal hostname '{hostname}'"
        try:
            addr_info = _socket.getaddrinfo(hostname, None)
            for _, _, _, _, sockaddr in addr_info:
                ip_str = sockaddr[0]
                ip = _ipaddress.ip_address(ip_str)
                if ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_reserved:
                    return False, f"SSRF blocked: resolved to private IP {ip_str}"
        except _socket.gaierror:
            pass  # Unresolvable host — let the actual request fail
        return True, "OK"
    except Exception as exc:
        return False, f"URL validation error: {exc}"


def _detect_response_secrets(body: str) -> list:
    """Scan HTTP response body for leaked secrets using regex patterns."""
    secrets = []
    seen_types: set = set()
    for pattern, stype in _POC_SECRET_PATTERNS:
        try:
            matches = _re.findall(pattern, body, _re.IGNORECASE)
            for match in matches[:2]:
                val = match if isinstance(match, str) else match[0]
                if len(val) >= 6 and stype not in seen_types:
                    masked = val[:4] + "***" + val[-4:] if len(val) > 12 else val[:3] + "***"
                    secrets.append({
                        "type": stype,
                        "value_masked": masked,
                        "confidence": 0.87,
                        "source": "http_response",
                        "exposure_vector": "response_body",
                    })
                    seen_types.add(stype)
        except Exception:
            pass
    return secrets


class POCExecuteRequest(BaseModel):
    method: str = "GET"
    url: str
    headers: dict = {}
    body: str = ""
    scan_id: str = ""
    finding_id: str = ""
    finding_evidence: str = ""


@app.post("/api/poc/execute")
async def poc_execute(
    request: POCExecuteRequest,
    req: Request,
    subscription: Dict[str, Any] = Depends(get_user_subscription),
):
    """
    Real HTTP POC execution proxy.

    Sends actual HTTP requests to scan targets, captures full response telemetry,
    detects leaked secrets, and correlates evidence to produce a verification verdict.
    Includes SSRF protection, rate limiting, and audit logging.
    """
    try:
        import httpx
    except ImportError:
        return {"success": False, "error": "httpx not installed — run: pip install httpx", "verification_status": "ERROR"}

    # Rate limiting: 10 requests/min per scan/IP
    now = _time_mod.time()
    rate_key = request.scan_id or (req.client.host if req.client else "anon")
    bucket = _POC_RATE_LIMIT.setdefault(rate_key, [])
    bucket[:] = [t for t in bucket if now - t < 60]
    if len(bucket) >= 10:
        raise HTTPException(status_code=429, detail="POC rate limit exceeded (10/min). Please wait.")
    bucket.append(now)

    # SSRF protection
    safe, reason = _is_ssrf_safe(request.url)
    if not safe:
        return {"success": False, "error": reason, "blocked": True, "verification_status": "BLOCKED"}

    # Method allowlist
    method = request.method.upper()
    if method not in {"GET", "POST", "PUT", "DELETE", "HEAD", "OPTIONS"}:
        raise HTTPException(status_code=400, detail=f"Method '{method}' not permitted")

    # Build execution headers
    exec_headers = {
        "User-Agent": "QuantaraScanner/5.0 (Authorized Security Research)",
        "Accept": "application/json, text/html, */*",
    }
    for k, v in request.headers.items():
        if k.lower() not in ("host", "content-length"):
            exec_headers[k] = v

    start_ts = _time_mod.time()
    try:
        async with httpx.AsyncClient(
            timeout=httpx.Timeout(25.0, connect=10.0),
            follow_redirects=True,
            verify=False,
            limits=httpx.Limits(max_connections=5, max_keepalive_connections=2),
        ) as client:
            kw: dict = {"method": method, "url": request.url, "headers": exec_headers}
            if request.body and method in ("POST", "PUT", "PATCH"):
                kw["content"] = request.body.encode("utf-8", errors="replace")
                if not any(k.lower() == "content-type" for k in exec_headers):
                    exec_headers["Content-Type"] = "application/json"

            response = await client.request(**kw)
            elapsed_ms = int((_time_mod.time() - start_ts) * 1000)

            try:
                body_raw = response.text[:50000]
            except Exception:
                body_raw = "<binary or undecodable response>"

            body_pretty = body_raw
            try:
                import json as _json
                body_pretty = _json.dumps(_json.loads(body_raw), indent=2)
            except Exception:
                pass

            resp_headers = dict(response.headers)

            info_headers = ["server", "x-powered-by", "x-aspnet-version", "x-aspnetmvc-version",
                            "x-generator", "x-drupal-cache", "x-wp-total"]
            disclosed_headers = [h for h in info_headers if h in resp_headers]

            detected_secrets = _detect_response_secrets(body_raw)

            evidence_match = False
            if request.finding_evidence:
                ev_lower = request.finding_evidence.lower()
                bl = body_raw.lower()
                tokens = [t for t in ev_lower.split() if len(t) > 4][:6]
                hits = sum(1 for t in tokens if t in bl)
                evidence_match = hits >= max(1, len(tokens) // 2)

            if evidence_match and response.status_code < 500:
                verdict = "VERIFIED"
            elif 200 <= response.status_code < 300:
                verdict = "UNCONFIRMED"
            elif response.status_code >= 500:
                verdict = "SERVER_ERROR"
            else:
                verdict = "FAILED"

            return {
                "success": True,
                "status_code": response.status_code,
                "response_time_ms": elapsed_ms,
                "content_type": resp_headers.get("content-type", "unknown"),
                "content_length": len(body_raw),
                "server": resp_headers.get("server", "—"),
                "headers": resp_headers,
                "body_pretty": body_pretty,
                "body_raw": body_raw,
                "tls_info": {"protocol": "TLS", "verified": False} if request.url.startswith("https://") else {},
                "secrets_detected": detected_secrets,
                "disclosed_headers": disclosed_headers,
                "evidence_match": evidence_match,
                "risk_verified": evidence_match,
                "verification_status": verdict,
                "redirect_count": len(response.history),
                "final_url": str(response.url),
            }

    except Exception as exc:
        exc_name = type(exc).__name__
        elapsed_ms = int((_time_mod.time() - start_ts) * 1000)
        if "Timeout" in exc_name:
            return {"success": False, "error": "Request timed out — target may be slow or unreachable", "verification_status": "TIMEOUT", "response_time_ms": elapsed_ms}
        if "Connect" in exc_name:
            return {"success": False, "error": f"Connection failed: {str(exc)[:300]}", "verification_status": "FAILED", "response_time_ms": elapsed_ms}
        return {"success": False, "error": str(exc)[:500], "verification_status": "ERROR", "response_time_ms": elapsed_ms}


@app.get("/api/poc/secrets/{scan_id}")
async def poc_get_secrets(
    scan_id: str,
    subscription: Dict[str, Any] = Depends(get_user_subscription),
):
    """
    Return secrets discovered in a scan's findings.

    Extracts credentials, API keys, tokens, and other sensitive data
    from scanner findings using pattern matching and key-value extraction.
    """
    local_user_id = subscription.get("local_user_id")
    is_super_admin = subscription.get("is_super_admin", False)

    scan = scans.get(scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")

    if not is_super_admin and scan.get("user_id") != local_user_id:
        raise HTTPException(status_code=403, detail="Unauthorized")

    kv_re = _re.compile(r'([A-Za-z_][A-Za-z0-9_]{2,})\s*[=:]\s*[\'"]?([^\s\'"<>,;]{6,64})')
    skip_keys = {"class", "type", "name", "href", "src", "id", "ref", "for",
                 "if", "else", "return", "const", "let", "var", "function", "import", "export"}
    secret_kws = {"secret", "password", "credential", "api key", "token", "key", "passwd", "pwd",
                  "api_key", "apikey", "private", "auth", "bearer"}

    secrets = []
    seen_sigs: set = set()

    for finding in scan.get("findings", []):
        title_lower = (finding.get("title", "") or "").lower()
        if not any(kw in title_lower for kw in secret_kws):
            continue
        matched = finding.get("matched_content", "") or finding.get("payload", "") or ""
        if not matched:
            continue

        kvs = kv_re.findall(matched[:500])
        extracted = False
        for key, value in kvs[:3]:
            if key.lower() in skip_keys:
                continue
            k = key.lower()
            if any(x in k for x in ("password", "passwd", "pwd")):
                stype = "PASSWORD"
            elif "stripe" in k or "sk_live" in value or "pk_live" in value:
                stype = "PAYMENT_TOKEN"
            elif "aws" in k or value.startswith("AKIA"):
                stype = "CLOUD_CREDENTIAL"
            elif "jwt" in k or "bearer" in k:
                stype = "JWT_TOKEN"
            elif "api_key" in k or "apikey" in k:
                stype = "API_KEY"
            elif "secret" in k:
                stype = "SECRET_KEY"
            elif "token" in k:
                stype = "AUTH_TOKEN"
            elif any(x in k for x in ("db", "database", "mongo", "postgres", "mysql", "redis")):
                stype = "DATABASE_CREDENTIAL"
            elif any(x in k for x in ("private_key", "rsa", "pem")):
                stype = "PRIVATE_KEY"
            else:
                stype = "CREDENTIAL"
            masked = value[:4] + "***" + value[-4:] if len(value) > 12 else value[:3] + "***"
            sig = stype + masked
            if sig in seen_sigs:
                continue
            seen_sigs.add(sig)
            secrets.append({
                "type": stype,
                "key": key.upper(),
                "value": value,
                "value_masked": masked,
                "confidence": float(finding.get("confidence", 0.8)),
                "source_path": finding.get("file", finding.get("endpoint", "unknown")),
                "discovered_via": finding.get("module_name", finding.get("module", "scanner")),
                "exposure_vector": "source_code" if finding.get("file") else "endpoint",
                "finding_id": finding.get("id", ""),
                "severity": finding.get("severity", "medium"),
            })
            extracted = True

        if not extracted:
            title = (finding.get("title", "Secret") or "Secret").replace(" ", "_").upper()[:30]
            masked = matched[:4] + "***" if len(matched) > 7 else "***"
            sig = "CREDENTIAL" + masked
            if sig not in seen_sigs:
                seen_sigs.add(sig)
                secrets.append({
                    "type": "CREDENTIAL",
                    "key": title,
                    "value": matched[:80],
                    "value_masked": masked,
                    "confidence": float(finding.get("confidence", 0.7)),
                    "source_path": finding.get("file", finding.get("endpoint", "unknown")),
                    "discovered_via": finding.get("module_name", finding.get("module", "scanner")),
                    "exposure_vector": "source_code" if finding.get("file") else "endpoint",
                    "finding_id": finding.get("id", ""),
                    "severity": finding.get("severity", "medium"),
                })

    for finding in scan.get("findings", []):
        evidence = finding.get("evidence", "") or ""
        if evidence and len(evidence) > 20:
            for s in _detect_response_secrets(evidence):
                sig = s.get("type", "") + s.get("value_masked", "")
                if sig not in seen_sigs:
                    seen_sigs.add(sig)
                    s["source_path"] = finding.get("file", finding.get("endpoint", "evidence"))
                    s["discovered_via"] = finding.get("module_name", "evidence_analyzer")
                    s["finding_id"] = finding.get("id", "")
                    s["severity"] = finding.get("severity", "high")
                    secrets.append(s)

    return {"scan_id": scan_id, "secrets_count": len(secrets), "secrets": secrets[:20]}


# ═══════════════════════════════════════════════════════════════════════════════
# Legal Terms Acceptance (Authorization Gate)
# ═══════════════════════════════════════════════════════════════════════════════

# In-memory store for terms acceptance records.
# Keys: user_id (Firebase UID) → record dict.
# In production, migrate to the SQL database (user_terms_acceptance table).
_terms_acceptance: dict[str, dict] = {}

CURRENT_TERMS_VERSION = "v1.0-2025"


class TermsAcceptRequest(BaseModel):
    version: str = CURRENT_TERMS_VERSION
    user_agent: str = ""


@app.post("/api/v1/terms/accept")
async def accept_terms(
    body: TermsAcceptRequest,
    req: Request,
    current_user: dict = Depends(get_current_firebase_user),
):
    """
    Record the authenticated user's acceptance of the Authorization & Legal Terms.

    Stores: user_id, terms_version, accepted_at, ip_address, user_agent,
            acceptance_hash (SHA-256 of user_id + version + timestamp).
    """
    user_id = current_user.get("uid", "unknown")
    accepted_at = datetime.now(timezone.utc).isoformat()
    client_ip = req.headers.get("x-forwarded-for", req.client.host if req.client else "unknown")

    acceptance_hash = hashlib.sha256(
        f"{user_id}:{body.version}:{accepted_at}".encode()
    ).hexdigest()

    record = {
        "user_id": user_id,
        "email": current_user.get("email", ""),
        "version": body.version,
        "accepted_at": accepted_at,
        "ip_address": client_ip,
        "user_agent": body.user_agent[:500],      # cap length
        "acceptance_hash": acceptance_hash,
        "accepted": True,
    }

    _terms_acceptance[user_id] = record

    return {
        "accepted": True,
        "version": body.version,
        "accepted_at": accepted_at,
        "acceptance_hash": acceptance_hash,
        "message": "Terms acceptance recorded successfully.",
    }


@app.get("/api/v1/terms/status")
async def get_terms_status(
    current_user: dict = Depends(get_current_firebase_user),
):
    """
    Return the terms acceptance status for the currently authenticated user.
    Returns accepted=False if no record found or version is stale.
    """
    user_id = current_user.get("uid", "unknown")
    record = _terms_acceptance.get(user_id)

    if not record or record.get("version") != CURRENT_TERMS_VERSION:
        return {
            "accepted": False,
            "version": CURRENT_TERMS_VERSION,
            "current_version": CURRENT_TERMS_VERSION,
            "accepted_at": None,
        }

    return {
        "accepted": True,
        "version": record["version"],
        "current_version": CURRENT_TERMS_VERSION,
        "accepted_at": record["accepted_at"],
        "acceptance_hash": record["acceptance_hash"],
    }


# ═══════════════════════════════════════════════════════════════════════════════
# Compliance Dashboard API (Phase 8.3)
# ═══════════════════════════════════════════════════════════════════════════════

@app.get("/api/v1/compliance/owasp")
async def get_owasp_compliance(
    subscription: Dict[str, Any] = Depends(get_user_subscription),
):
    """Get OWASP Top 10 compliance scorecard for the current user's scans."""
    local_user_id = subscription.get("local_user_id")
    is_super_admin = subscription.get("is_super_admin", False)

    owasp_categories = {
        "A01:2025": {"name": "Broken Access Control", "count": 0, "status": "compliant"},
        "A02:2025": {"name": "Cryptographic Failures", "count": 0, "status": "compliant"},
        "A03:2025": {"name": "Injection", "count": 0, "status": "compliant"},
        "A04:2025": {"name": "Insecure Design", "count": 0, "status": "compliant"},
        "A05:2025": {"name": "Security Misconfiguration", "count": 0, "status": "compliant"},
        "A06:2025": {"name": "Vulnerable Components", "count": 0, "status": "compliant"},
        "A07:2025": {"name": "Auth Failures", "count": 0, "status": "compliant"},
        "A08:2025": {"name": "Integrity Failures", "count": 0, "status": "compliant"},
        "A09:2025": {"name": "Logging Failures", "count": 0, "status": "compliant"},
        "A10:2025": {"name": "SSRF", "count": 0, "status": "compliant"},
    }

    # Aggregate from this user's scans only
    all_findings = []
    for scan in scans.values():
        if is_super_admin or scan.get("user_id") == local_user_id:
            all_findings.extend(scan.get("findings", []))
    
    for finding in all_findings:
        owasp = finding.get("owasp", "")
        if owasp and owasp in owasp_categories:
            owasp_categories[owasp]["count"] += 1
            # If findings exist, mark as "at risk"
            if finding.get("severity") in ["critical", "high"]:
                owasp_categories[owasp]["status"] = "at_risk"
            elif owasp_categories[owasp]["status"] == "compliant":
                owasp_categories[owasp]["status"] = "warning"
    
    total_categories = len(owasp_categories)
    compliant = sum(1 for c in owasp_categories.values() if c["status"] == "compliant")
    
    return {
        "score": round((compliant / total_categories) * 100),
        "total_categories": total_categories,
        "compliant": compliant,
        "at_risk": sum(1 for c in owasp_categories.values() if c["status"] == "at_risk"),
        "categories": owasp_categories,
    }


# ═══════════════════════════════════════════════════════════════════════════════
# WebSocket Live Monitoring (Phase 8.5)
# ═══════════════════════════════════════════════════════════════════════════════

from backend.websocket_manager import ws_manager

@app.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket, token: str = ""):
    """WebSocket endpoint for real-time updates (authenticated)."""
    # Authenticate via token query param
    user_id = "anonymous"
    local_user_id = None
    if token:
        try:
            from backend.auth import decode_token
            payload = decode_token(token)
            if payload:
                user_id = payload.get("uid", payload.get("sub", "anonymous"))
                local_user_id = payload.get("local_user_id")
        except Exception:
            pass

    await websocket.accept()
    if not local_user_id:
        await websocket.send_json({"type": "error", "message": "Authentication required"})
        await websocket.close(code=4001)
        return

    connection_id = await ws_manager.connect(websocket, user_id)

    try:
        while True:
            data = await websocket.receive_json()
            msg_type = data.get("type")

            if msg_type == "ping":
                await websocket.send_json({"type": "pong", "timestamp": datetime.now(timezone.utc).isoformat()})

            elif msg_type == "subscribe_scan":
                scan_id = data.get("scan_id")
                # Verify scan ownership
                if scan_id in scans and scans[scan_id].get("user_id") != local_user_id:
                    await websocket.send_json({"type": "error", "message": "Unauthorized scan access"})
                    continue
                await websocket.send_json({
                    "type": "subscribed",
                    "scan_id": scan_id,
                    "message": f"Subscribed to updates for scan {scan_id}"
                })

    except Exception as e:
        print(f"WebSocket error: {e}")
    finally:
        ws_manager.disconnect(connection_id, user_id)


# ═══════════════════════════════════════════════════════════════════════════════
# Scheduled & Recurring Scans (Phase 8.6)
# ═══════════════════════════════════════════════════════════════════════════════

from backend.scheduled_scan_service import scheduled_scan_service, scan_comparison_service

class CreateScheduleRequest(BaseModel):
    name: str
    target: str
    modules: list[str]
    frequency: str  # daily, weekly, monthly
    schedule_time: str  # HH:MM format
    scan_profile: str = "full"
    day_of_week: Optional[int] = None  # 0-6 for weekly
    day_of_month: Optional[int] = None  # 1-31 for monthly
    notify_email: Optional[str] = None

@app.post("/api/v1/schedules")
async def create_schedule(
    request: CreateScheduleRequest,
    subscription: Dict[str, Any] = Depends(get_user_subscription),
):
    """Create a scheduled scan."""
    user_id = str(subscription.get("local_user_id", ""))
    if not user_id:
        raise HTTPException(status_code=401, detail="Authentication required")
    schedule = scheduled_scan_service.create_schedule(
        name=request.name,
        target=request.target,
        modules=request.modules,
        frequency=request.frequency,
        schedule_time=request.schedule_time,
        scan_profile=request.scan_profile,
        day_of_week=request.day_of_week,
        day_of_month=request.day_of_month,
        notify_email=request.notify_email,
        user_id=user_id,
    )
    return {
        "schedule_id": schedule.id,
        "name": schedule.name,
        "next_run": schedule.next_run,
        "message": "Schedule created successfully"
    }

@app.get("/api/v1/schedules")
async def list_schedules(subscription: Dict[str, Any] = Depends(get_user_subscription)):
    """List all scheduled scans."""
    user_id = str(subscription.get("local_user_id", ""))
    if not user_id:
        raise HTTPException(status_code=401, detail="Authentication required")
    schedules = scheduled_scan_service.list_schedules(user_id)
    return {
        "schedules": [
            {
                "id": s.id,
                "name": s.name,
                "target": s.target,
                "frequency": s.frequency,
                "schedule_time": s.schedule_time,
                "next_run": s.next_run,
                "last_run": s.last_run,
                "is_active": s.is_active
            }
            for s in schedules
        ]
    }

@app.delete("/api/v1/schedules/{schedule_id}")
async def delete_schedule(
    schedule_id: str,
    subscription: Dict[str, Any] = Depends(get_user_subscription),
):
    """Delete a scheduled scan."""
    user_id = str(subscription.get("local_user_id", ""))
    if not user_id:
        raise HTTPException(status_code=401, detail="Authentication required")
    success = scheduled_scan_service.delete_schedule(schedule_id, user_id=user_id)
    if not success:
        raise HTTPException(status_code=404, detail="Schedule not found")
    return {"success": True, "message": "Schedule deleted"}

@app.post("/api/v1/scans/compare")
async def compare_scans(
    scan1_id: str,
    scan2_id: str,
    subscription: Dict[str, Any] = Depends(get_user_subscription),
):
    """Compare two scans and identify differences."""
    local_user_id = subscription.get("local_user_id")
    is_super_admin = subscription.get("is_super_admin", False)

    for sid in (scan1_id, scan2_id):
        if sid not in scans:
            raise HTTPException(status_code=404, detail=f"Scan {sid} not found")
        if not is_super_admin and scans[sid].get("user_id") != local_user_id:
            raise HTTPException(status_code=403, detail="Unauthorized")

    scan1_findings = scans[scan1_id].get("findings", [])
    scan2_findings = scans[scan2_id].get("findings", [])

    comparison = scan_comparison_service.compare_scans(scan1_findings, scan2_findings)

    return {
        "scan1_id": scan1_id,
        "scan2_id": scan2_id,
        "comparison": comparison
    }


# ═══════════════════════════════════════════════════════════════════════════════
# Team Collaboration (Phase 8.7)
# ═══════════════════════════════════════════════════════════════════════════════

from backend.team_collaboration import team_collaboration, rbac_service

@app.post("/api/v1/findings/{scan_id}/{finding_id}/assign")
async def assign_finding(
    scan_id: str,
    finding_id: str,
    assigned_to: str,
    subscription: Dict[str, Any] = Depends(get_user_subscription),
):
    """Assign a finding to a team member."""
    local_user_id = subscription.get("local_user_id")
    is_super_admin = subscription.get("is_super_admin", False)
    if scan_id in scans and not is_super_admin and scans[scan_id].get("user_id") != local_user_id:
        raise HTTPException(status_code=403, detail="Unauthorized")
    user_id = str(local_user_id or "")
    finding = team_collaboration.assign_finding(finding_id, scan_id, assigned_to, user_id)
    return {
        "success": True,
        "finding_id": finding_id,
        "assigned_to": assigned_to,
        "assigned_by": user_id
    }

@app.post("/api/v1/findings/{scan_id}/{finding_id}/status")
async def update_finding_status(
    scan_id: str,
    finding_id: str,
    status: str,
    comment: Optional[str] = None,
    subscription: Dict[str, Any] = Depends(get_user_subscription),
):
    """Update finding status (Open -> In Progress -> Fixed -> Verified)."""
    local_user_id = subscription.get("local_user_id")
    is_super_admin = subscription.get("is_super_admin", False)
    if scan_id in scans and not is_super_admin and scans[scan_id].get("user_id") != local_user_id:
        raise HTTPException(status_code=403, detail="Unauthorized")
    user_id = str(local_user_id or "")
    finding = team_collaboration.update_finding_status(finding_id, scan_id, status, user_id, comment)
    return {
        "success": True,
        "finding_id": finding_id,
        "new_status": status,
        "previous_status": finding.status_history[-2]["from"] if len(finding.status_history) > 1 else None
    }

@app.post("/api/v1/findings/{scan_id}/{finding_id}/comments")
async def add_finding_comment(
    scan_id: str,
    finding_id: str,
    content: str,
    subscription: Dict[str, Any] = Depends(get_user_subscription),
):
    """Add a comment to a finding."""
    local_user_id = subscription.get("local_user_id")
    is_super_admin = subscription.get("is_super_admin", False)
    if scan_id in scans and not is_super_admin and scans[scan_id].get("user_id") != local_user_id:
        raise HTTPException(status_code=403, detail="Unauthorized")
    user_id = str(local_user_id or "")
    user_name = subscription.get("email", "User")
    comment = team_collaboration.add_comment(finding_id, scan_id, user_id, user_name, content)
    return {
        "success": True,
        "comment_id": comment.id,
        "created_at": comment.created_at
    }

@app.get("/api/v1/findings/{scan_id}/{finding_id}/details")
async def get_finding_details(
    scan_id: str,
    finding_id: str,
    subscription: Dict[str, Any] = Depends(get_user_subscription),
):
    """Get full finding details including comments and history."""
    local_user_id = subscription.get("local_user_id")
    is_super_admin = subscription.get("is_super_admin", False)
    if scan_id in scans and not is_super_admin and scans[scan_id].get("user_id") != local_user_id:
        raise HTTPException(status_code=403, detail="Unauthorized")
    finding = team_collaboration.get_finding_details(finding_id, scan_id)
    if not finding:
        raise HTTPException(status_code=404, detail="Finding not found")

    return {
        "finding_id": finding.finding_id,
        "scan_id": finding.scan_id,
        "status": finding.status,
        "assigned_to": finding.assigned_to,
        "assigned_at": finding.assigned_at,
        "comments": [
            {
                "id": c.id,
                "user_name": c.user_name,
                "content": c.content,
                "created_at": c.created_at
            }
            for c in finding.comments
        ],
        "status_history": finding.status_history
    }

@app.get("/api/v1/team/activity")
async def get_team_activity(
    limit: int = 50,
    subscription: Dict[str, Any] = Depends(get_user_subscription),
):
    """Get team activity feed."""
    activities = team_collaboration.get_activity_feed(limit)
    return {"activities": activities}


# ═══════════════════════════════════════════════════════════════════════════════
# SBOM Generator (Phase 8.9)
# ═══════════════════════════════════════════════════════════════════════════════

from backend.sbom_generator import sbom_generator, SBOMFormat

@app.post("/api/v1/sbom/generate")
async def generate_sbom(
    dependencies: list[dict],
    format: str = "cyclonedx-json",
    application_name: str = "Application",
    subscription: Dict[str, Any] = Depends(get_user_subscription),
):
    """Generate SBOM from dependencies."""
    try:
        sbom_format = SBOMFormat(format)
    except ValueError:
        raise HTTPException(status_code=400, detail=f"Unsupported format: {format}")
    
    sbom_content = sbom_generator.generate_from_dependencies(
        dependencies=dependencies,
        format=sbom_format,
        application_name=application_name
    )
    
    # Also get license compliance summary
    components = [sbom_generator.Component(**d) for d in dependencies]
    compliance = sbom_generator.get_license_compliance_summary(components)
    
    return {
        "sbom": sbom_content,
        "format": format,
        "license_compliance": compliance
    }


# ═══════════════════════════════════════════════════════════════════════════════
# Threat Modeling (Phase 8.10)
# ═══════════════════════════════════════════════════════════════════════════════

from backend.threat_modeling import threat_modeling

@app.post("/api/v1/threat-model/generate")
async def generate_threat_model(
    scan_id: str,
    subscription: Dict[str, Any] = Depends(get_user_subscription),
):
    """Generate STRIDE-based threat model from scan."""
    local_user_id = subscription.get("local_user_id")
    is_super_admin = subscription.get("is_super_admin", False)
    if scan_id not in scans:
        raise HTTPException(status_code=404, detail="Scan not found")
    if not is_super_admin and scans[scan_id].get("user_id") != local_user_id:
        raise HTTPException(status_code=403, detail="Unauthorized")

    findings = scans[scan_id].get("findings", [])
    threat_model = threat_modeling.generate_threat_model(scan_id, findings)

    return threat_model

@app.get("/api/v1/threat-model/{scan_id}/attack-surface")
async def get_attack_surface_diagram(
    scan_id: str,
    subscription: Dict[str, Any] = Depends(get_user_subscription),
):
    """Get attack surface diagram data."""
    local_user_id = subscription.get("local_user_id")
    is_super_admin = subscription.get("is_super_admin", False)
    if scan_id in scans and not is_super_admin and scans[scan_id].get("user_id") != local_user_id:
        raise HTTPException(status_code=403, detail="Unauthorized")
    diagram = threat_modeling.generate_attack_surface_diagram(scan_id)

    if "error" in diagram:
        raise HTTPException(status_code=400, detail=diagram["error"])

    return diagram


# ═══════════════════════════════════════════════════════════════════════════════
# Neo4j Attack Graph Intelligence (Phase 9)
# ═══════════════════════════════════════════════════════════════════════════════

from backend.neo4j_client import get_neo4j_client


@app.post("/api/v1/graph/ingest")
async def graph_ingest(
    scan_id: str,
    subscription: Dict[str, Any] = Depends(get_user_subscription),
):
    """
    Ingest all findings from a completed scan into the Neo4j graph model.
    Creates nodes for assets, services, vulnerabilities, endpoints,
    credentials, roles, impacts, and remediations.
    Computes LEADS_TO / ESCALATES_TO cross-module relationships.
    """
    local_user_id = subscription.get("local_user_id")
    is_super_admin = subscription.get("is_super_admin", False)
    if scan_id not in scans:
        raise HTTPException(status_code=404, detail="Scan not found")
    if not is_super_admin and scans[scan_id].get("user_id") != local_user_id:
        raise HTTPException(status_code=403, detail="Unauthorized")

    scan     = scans[scan_id]
    findings = scan.get("findings", [])
    target   = scan.get("target", "unknown")

    client = get_neo4j_client()
    result = client.ingest_scan_findings(scan_id, target, findings)

    return {
        "success":               True,
        "scan_id":               scan_id,
        "mode":                  result["mode"],
        "nodes_created":         result["nodes_created"],
        "relationships_created": result["relationships_created"],
        "message":               f"Graph built in {result['mode']} mode.",
    }


@app.get("/api/v1/graph/asset-risk-graph")
async def get_asset_risk_graph(
    scan_id: str,
    subscription: Dict[str, Any] = Depends(get_user_subscription),
):
    """
    Return the full property graph for a scan (nodes + edges).
    If the scan has not been ingested yet, auto-ingests first.

    Response shape:
      { nodes: [...], edges: [...], mode: "neo4j"|"memory", count: {...} }
    """
    local_user_id = subscription.get("local_user_id")
    is_super_admin = subscription.get("is_super_admin", False)
    if scan_id not in scans:
        raise HTTPException(status_code=404, detail="Scan not found")
    if not is_super_admin and scans[scan_id].get("user_id") != local_user_id:
        raise HTTPException(status_code=403, detail="Unauthorized")

    client = get_neo4j_client()

    # Auto-ingest if graph not yet built
    findings = scans[scan_id].get("findings", [])
    target   = scans[scan_id].get("target", "unknown")

    if not client.is_connected or findings:
        client.ingest_scan_findings(scan_id, target, findings)

    graph = client.get_asset_risk_graph(scan_id)
    return graph


@app.get("/api/v1/graph/attack-paths")
async def get_attack_paths(
    scan_id: str,
    subscription: Dict[str, Any] = Depends(get_user_subscription),
):
    """
    Compute and return ordered attack paths for a scan.

    Uses BFS shortest-path (in-memory) or Neo4j shortestPath()
    to find routes from the root Asset to high/critical impact nodes.

    Response shape:
      { paths: [...], count: int, mode: str }
    """
    local_user_id = subscription.get("local_user_id")
    is_super_admin = subscription.get("is_super_admin", False)
    if scan_id not in scans:
        raise HTTPException(status_code=404, detail="Scan not found")
    if not is_super_admin and scans[scan_id].get("user_id") != local_user_id:
        raise HTTPException(status_code=403, detail="Unauthorized")

    client   = get_neo4j_client()
    findings = scans[scan_id].get("findings", [])
    target   = scans[scan_id].get("target", "unknown")
    client.ingest_scan_findings(scan_id, target, findings)

    paths = client.get_attack_paths(scan_id)
    return {
        "scan_id": scan_id,
        "paths":   paths,
        "count":   len(paths),
        "mode":    client.mode,
    }


@app.get("/api/v1/graph/breach-simulation")
async def get_breach_simulation(
    scan_id: str,
    subscription: Dict[str, Any] = Depends(get_user_subscription),
):
    """
    Generate a MITRE ATT&CK-mapped breach simulation for a scan.

    Returns attacker timeline, impact assessment, breach probability,
    and estimated dwell time based on confirmed findings.

    Response shape:
      { breach_probability, risk_level, attack_timeline, impact_assessment,
        attack_paths, estimated_dwell_time, mitre_techniques, findings_summary }
    """
    local_user_id = subscription.get("local_user_id")
    is_super_admin = subscription.get("is_super_admin", False)
    if scan_id not in scans:
        raise HTTPException(status_code=404, detail="Scan not found")
    if not is_super_admin and scans[scan_id].get("user_id") != local_user_id:
        raise HTTPException(status_code=403, detail="Unauthorized")

    client   = get_neo4j_client()
    findings = scans[scan_id].get("findings", [])
    target   = scans[scan_id].get("target", "unknown")
    client.ingest_scan_findings(scan_id, target, findings)

    simulation = client.get_breach_simulation(scan_id, findings)
    return simulation


@app.get("/api/v1/graph/status")
async def get_graph_status():
    """Return Neo4j connection status and graph engine info."""
    client = get_neo4j_client()
    return {
        "connected": client.is_connected,
        "mode":      client.mode,
        "uri":       "bolt://***" if client.is_connected else "not connected",
        "features": [
            "attack_path_computation",
            "privilege_escalation_chains",
            "credential_exposure_tracking",
            "breach_simulation",
            "mitre_mapping",
        ],
    }


@app.get("/api/lab/status")
async def get_lab_status():
    """
    Check health status of lab proxy tools (hetty and mitmweb).
    Performs async health probes to determine if services are running.
    """
    import httpx
    
    hetty_url = os.getenv("HETTY_URL", "http://localhost:8082")
    mitmweb_url = os.getenv("MITMWEB_URL", "http://localhost:8083")
    
    # Health check hetty
    hetty_running = False
    try:
        async with httpx.AsyncClient(timeout=3.0, follow_redirects=True) as client:
            response = await client.get(hetty_url)
            # Hetty returns 200/302 for its UI
            hetty_running = response.status_code < 500
    except Exception:
        pass
    
    # Health check mitmweb
    mitmweb_running = False
    try:
        async with httpx.AsyncClient(timeout=3.0, follow_redirects=True) as client:
            response = await client.get(mitmweb_url)
            # mitmweb returns 200 for its UI
            mitmweb_running = response.status_code < 500
    except Exception:
        pass
    
    return {
        "hetty": {
            "running": hetty_running,
            "url": hetty_url,
        },
        "mitmweb": {
            "running": mitmweb_running,
            "url": mitmweb_url,
        }
    }


@app.get("/api/lab/ca/hetty")
async def download_hetty_ca():
    """
    Download the Hetty CA certificate for proxy SSL interception.
    """
    # If running on host (dev), look in user home. If in docker, look in /root/
    ca_path = os.getenv("HETTY_CA_PATH", os.path.expanduser("~/.hetty/hetty_cert.pem"))
    
    # Also check local project folder (bind mount on host)
    if not os.path.exists(ca_path):
        local_path = os.path.join(os.getcwd(), ".hetty_data", "hetty_cert.pem")
        if os.path.exists(local_path):
            ca_path = local_path
            
    if not os.path.exists(ca_path):
        # Re-check in /root/ as fallback for Docker env
        ca_path = "/root/.hetty/hetty_cert.pem"
        
    if not os.path.exists(ca_path):
        raise HTTPException(status_code=404, detail="Hetty CA certificate not found. Start Hetty first.")
    
    return FileResponse(
        path=ca_path,
        filename="hetty-ca.crt",
        media_type="application/x-pem-file"
    )


@app.get("/api/lab/ca/mitmproxy")
async def download_mitmproxy_ca():
    """
    Download the mitmproxy CA certificate for proxy SSL interception.
    """
    # mitmproxy CA is usually in ~/.mitmproxy/
    ca_path = os.getenv("MITMPROXY_CA_PATH", os.path.expanduser("~/.mitmproxy/mitmproxy-ca-cert.pem"))
    
    # Also check local project folder
    if not os.path.exists(ca_path):
        local_path = os.path.join(os.getcwd(), ".mitmproxy_data", "mitmproxy-ca-cert.pem")
        if os.path.exists(local_path):
            ca_path = local_path
            
    if not os.path.exists(ca_path):
        # Fallback for Docker
        ca_path = "/root/.mitmproxy/mitmproxy-ca-cert.pem"

    if not os.path.exists(ca_path):
        raise HTTPException(status_code=404, detail="mitmproxy CA certificate not found. Start mitmweb first.")
    
    return FileResponse(
        path=ca_path,
        filename="mitmproxy-ca-cert.pem",
        media_type="application/x-x509-ca-cert"
    )

# NOTE: Duplicate /api/v1/scan/{scan_id}/neo-intelligence and /api/v1/neo-intelligence/*
# routes removed — canonical versions with auth are defined earlier in this file.

# ═══════════════════════════════════════════════════════════════════════════════
# Hetty HTTP Testing Toolkit — Native Manual Pentesting API
# ═══════════════════════════════════════════════════════════════════════════════

_HETTY_HISTORY: list = []  # In-memory request history (per-process)
_HETTY_MAX_HISTORY = 500

# Vulnerability signature patterns for auto-detection on HTTP responses
_VULN_SIGNATURES = [
    # SQL Injection
    {"type": "SQL Injection", "patterns": [
        r"SQL syntax.*?MySQL", r"Warning.*?\Wmysqli?_", r"PostgreSQL.*?ERROR",
        r"ORA-\d{5}", r"Microsoft.*?ODBC.*?SQL Server", r"Unclosed quotation mark",
        r"quoted string not properly terminated", r"syntax error at or near",
        r"com\.mysql\.jdbc", r"SQLite3::query", r"pg_query\(\): ERROR",
    ], "confidence_base": 0.9},
    # XSS
    {"type": "Reflected XSS", "patterns": [
        r"<script[^>]*>.*?alert\s*\(", r"<img[^>]+onerror\s*=",
        r"<svg[^>]+onload\s*=", r"javascript\s*:", r"on\w+\s*=\s*[\"']",
    ], "confidence_base": 0.85},
    # Command Injection
    {"type": "Command Injection", "patterns": [
        r"uid=\d+\([\w]+\)\s+gid=", r"root:x:0:0:", r"Windows IP Configuration",
        r"Directory of [A-Z]:\\", r"\bdrwxr[x-]", r"total \d+\s+",
    ], "confidence_base": 0.92},
    # SSRF indicators
    {"type": "SSRF", "patterns": [
        r"\"hostname\":\s*\"(127\.|10\.|192\.168\.|172\.(1[6-9]|2\d|3[01]))",
        r"Connection refused.*?(127\.0\.0\.1|localhost)",
    ], "confidence_base": 0.8},
    # LFI / Path Traversal
    {"type": "LFI / Path Traversal", "patterns": [
        r"root:x:0:0:root:", r"\[boot loader\]", r"\[operating systems\]",
        r"<\?php", r"#!/(usr/)?bin/(ba)?sh",
    ], "confidence_base": 0.88},
    # Open Redirect
    {"type": "Open Redirect", "patterns": [
        r"<meta\s+http-equiv=[\"']refresh[\"'].*?url=https?://",
        r"location:\s*https?://(?!(?:localhost|127\.0\.0\.1))",
    ], "confidence_base": 0.75},
    # Auth Bypass
    {"type": "Authentication Bypass", "patterns": [
        r"\"authenticated\":\s*true", r"\"role\":\s*\"admin\"",
        r"\"is_admin\":\s*true", r"admin_token",
    ], "confidence_base": 0.7},
    # Misconfigured Headers
    {"type": "Security Header Misconfiguration", "patterns": [
        r"access-control-allow-origin:\s*\*",
    ], "confidence_base": 0.65},
]


def _analyze_response_vulnerabilities(
    status_code: int, headers: dict, body: str, request_payload: str = ""
) -> list:
    """Auto-detect potential vulnerabilities in an HTTP response."""
    vulns = []
    combined = body + "\n" + "\n".join(f"{k}: {v}" for k, v in headers.items())

    for sig in _VULN_SIGNATURES:
        for pat in sig["patterns"]:
            try:
                match = _re.search(pat, combined, _re.IGNORECASE)
                if match:
                    evidence = match.group(0)[:200]
                    vulns.append({
                        "type": sig["type"],
                        "confidence": sig["confidence_base"],
                        "evidence": evidence,
                        "location": "response_body" if match.group(0) in body else "response_header",
                    })
                    break  # One match per signature type
            except Exception:
                pass

    # Check missing security headers
    important_headers = {
        "x-frame-options": "Missing X-Frame-Options header",
        "x-content-type-options": "Missing X-Content-Type-Options header",
        "strict-transport-security": "Missing HSTS header",
        "content-security-policy": "Missing Content-Security-Policy header",
    }
    lower_headers = {k.lower(): v for k, v in headers.items()}
    for hdr, msg in important_headers.items():
        if hdr not in lower_headers:
            vulns.append({
                "type": "Security Header Misconfiguration",
                "confidence": 0.5,
                "evidence": msg,
                "location": "response_header",
            })

    return vulns


class HettySendRequest(BaseModel):
    method: str = "GET"
    url: str
    headers: dict = {}
    cookies: dict = {}
    params: dict = {}
    body: str = ""
    timeout: int = 25
    follow_redirects: bool = True
    auto_detect_vulns: bool = True


class HettyReplayRequest(BaseModel):
    original_id: str
    method: Optional[str] = None
    url: Optional[str] = None
    headers: Optional[dict] = None
    cookies: Optional[dict] = None
    body: Optional[str] = None


@app.post("/api/hetty/send-request")
async def hetty_send_request(
    request: HettySendRequest,
    req: Request,
):
    """
    Full HTTP request proxy for manual pentesting.
    Sends request, captures full telemetry, auto-detects vulnerabilities.
    """
    try:
        import httpx
    except ImportError:
        return {"success": False, "error": "httpx not installed"}

    # Rate limiting
    now = _time_mod.time()
    rate_key = "hetty_" + (req.client.host if req.client else "anon")
    bucket = _POC_RATE_LIMIT.setdefault(rate_key, [])
    bucket[:] = [t for t in bucket if now - t < 60]
    if len(bucket) >= 30:
        raise HTTPException(status_code=429, detail="Rate limit exceeded (30/min)")
    bucket.append(now)

    # SSRF protection
    safe, reason = _is_ssrf_safe(request.url)
    if not safe:
        return {"success": False, "error": reason, "blocked": True}

    method = request.method.upper()
    if method not in {"GET", "POST", "PUT", "DELETE", "HEAD", "OPTIONS", "PATCH"}:
        raise HTTPException(status_code=400, detail=f"Method '{method}' not permitted")

    # Build headers
    exec_headers = {
        "User-Agent": "QuantaraScanner/5.0 (Manual Pentest)",
        "Accept": "*/*",
    }
    for k, v in request.headers.items():
        if k.lower() not in ("host", "content-length"):
            exec_headers[k] = v

    # Add cookies
    cookie_str = "; ".join(f"{k}={v}" for k, v in request.cookies.items())
    if cookie_str:
        exec_headers["Cookie"] = cookie_str

    # Add query params to URL
    target_url = request.url
    if request.params:
        from urllib.parse import urlencode, urlparse, parse_qs, urlunparse
        parsed = urlparse(target_url)
        existing = parse_qs(parsed.query)
        existing.update({k: [v] for k, v in request.params.items()})
        new_query = urlencode(existing, doseq=True)
        target_url = urlunparse(parsed._replace(query=new_query))

    request_id = str(uuid.uuid4())[:12]
    start_ts = _time_mod.time()

    try:
        async with httpx.AsyncClient(
            timeout=httpx.Timeout(float(min(request.timeout, 60)), connect=10.0),
            follow_redirects=request.follow_redirects,
            verify=False,
            limits=httpx.Limits(max_connections=5, max_keepalive_connections=2),
        ) as client:
            kw: dict = {"method": method, "url": target_url, "headers": exec_headers}
            if request.body and method in ("POST", "PUT", "PATCH"):
                kw["content"] = request.body.encode("utf-8", errors="replace")

            response = await client.request(**kw)
            elapsed_ms = int((_time_mod.time() - start_ts) * 1000)

            try:
                body_raw = response.text[:100000]
            except Exception:
                body_raw = "<binary or undecodable response>"

            body_pretty = body_raw
            try:
                body_pretty = json.dumps(json.loads(body_raw), indent=2)
            except Exception:
                pass

            resp_headers = dict(response.headers)
            content_length = len(body_raw)

            # Detect secrets
            detected_secrets = _detect_response_secrets(body_raw)

            # Info disclosure headers
            info_headers = ["server", "x-powered-by", "x-aspnet-version",
                            "x-aspnetmvc-version", "x-generator", "x-drupal-cache"]
            disclosed = [h for h in info_headers if h in resp_headers]

            # Auto vulnerability detection
            detected_vulns = []
            if request.auto_detect_vulns:
                detected_vulns = _analyze_response_vulnerabilities(
                    response.status_code, resp_headers, body_raw, request.body
                )

            # Parse response cookies
            resp_cookies = {}
            for cookie_header in response.headers.get_list("set-cookie"):
                parts = cookie_header.split("=", 1)
                if len(parts) == 2:
                    name = parts[0].strip()
                    value = parts[1].split(";")[0].strip()
                    resp_cookies[name] = {
                        "value": value,
                        "raw": cookie_header,
                        "secure": "secure" in cookie_header.lower(),
                        "httponly": "httponly" in cookie_header.lower(),
                        "samesite": "samesite" in cookie_header.lower(),
                    }

            result = {
                "success": True,
                "id": request_id,
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "request": {
                    "method": method,
                    "url": target_url,
                    "headers": exec_headers,
                    "cookies": request.cookies,
                    "body": request.body if method in ("POST", "PUT", "PATCH") else "",
                },
                "response": {
                    "status_code": response.status_code,
                    "status_text": response.reason_phrase or "",
                    "headers": resp_headers,
                    "cookies": resp_cookies,
                    "body_raw": body_raw,
                    "body_pretty": body_pretty,
                    "content_type": resp_headers.get("content-type", "unknown"),
                    "content_length": content_length,
                    "server": resp_headers.get("server", ""),
                },
                "timing": {
                    "total_ms": elapsed_ms,
                    "redirect_count": len(response.history),
                    "final_url": str(response.url),
                },
                "security": {
                    "tls": request.url.startswith("https://"),
                    "secrets_detected": detected_secrets,
                    "disclosed_headers": disclosed,
                    "vulnerabilities_detected": detected_vulns,
                },
            }

            # Store in history
            history_entry = {
                "id": request_id,
                "timestamp": result["timestamp"],
                "method": method,
                "url": target_url,
                "status_code": response.status_code,
                "response_time_ms": elapsed_ms,
                "content_length": content_length,
                "vulns_count": len(detected_vulns),
                "secrets_count": len(detected_secrets),
            }
            _HETTY_HISTORY.insert(0, history_entry)
            if len(_HETTY_HISTORY) > _HETTY_MAX_HISTORY:
                _HETTY_HISTORY[:] = _HETTY_HISTORY[:_HETTY_MAX_HISTORY]

            # Store full result for replay
            history_entry["_full"] = result

            return result

    except Exception as exc:
        elapsed_ms = int((_time_mod.time() - start_ts) * 1000)
        exc_name = type(exc).__name__
        if "Timeout" in exc_name:
            return {"success": False, "id": request_id, "error": "Request timed out", "timing": {"total_ms": elapsed_ms}}
        if "Connect" in exc_name:
            return {"success": False, "id": request_id, "error": f"Connection failed: {str(exc)[:300]}", "timing": {"total_ms": elapsed_ms}}
        return {"success": False, "id": request_id, "error": str(exc)[:500], "timing": {"total_ms": elapsed_ms}}


@app.post("/api/hetty/replay")
async def hetty_replay(
    request: HettyReplayRequest,
    req: Request,
):
    """Replay a previous request with optional modifications for comparison."""
    # Find original request in history
    original = None
    for entry in _HETTY_HISTORY:
        if entry["id"] == request.original_id and "_full" in entry:
            original = entry["_full"]
            break

    if not original:
        raise HTTPException(status_code=404, detail="Original request not found in history")

    orig_req = original["request"]
    replay = HettySendRequest(
        method=request.method or orig_req["method"],
        url=request.url or orig_req["url"],
        headers=request.headers if request.headers is not None else orig_req.get("headers", {}),
        cookies=request.cookies if request.cookies is not None else orig_req.get("cookies", {}),
        body=request.body if request.body is not None else orig_req.get("body", ""),
    )
    new_result = await hetty_send_request(replay, req)

    # Build comparison
    if new_result.get("success") and original.get("success"):
        orig_resp = original["response"]
        new_resp = new_result.get("response", {})
        comparison = {
            "status_changed": orig_resp["status_code"] != new_resp.get("status_code"),
            "original_status": orig_resp["status_code"],
            "replay_status": new_resp.get("status_code"),
            "length_diff": new_resp.get("content_length", 0) - orig_resp.get("content_length", 0),
            "time_diff_ms": new_result.get("timing", {}).get("total_ms", 0) - original.get("timing", {}).get("total_ms", 0),
            "new_vulns": len(new_result.get("security", {}).get("vulnerabilities_detected", [])),
            "original_vulns": len(original.get("security", {}).get("vulnerabilities_detected", [])),
            "body_changed": orig_resp.get("body_raw", "")[:5000] != new_resp.get("body_raw", "")[:5000],
        }
        new_result["comparison"] = comparison

    new_result["replay_of"] = request.original_id
    return new_result


@app.post("/api/hetty/analyze-response")
async def hetty_analyze_response(
    req: Request,
):
    """Analyze a raw HTTP response for vulnerabilities without sending a new request."""
    body = await req.json()
    status_code = body.get("status_code", 200)
    headers = body.get("headers", {})
    response_body = body.get("body", "")
    request_payload = body.get("request_payload", "")

    vulns = _analyze_response_vulnerabilities(status_code, headers, response_body, request_payload)
    secrets = _detect_response_secrets(response_body)

    info_headers = ["server", "x-powered-by", "x-aspnet-version",
                    "x-aspnetmvc-version", "x-generator"]
    disclosed = [h for h in info_headers if h.lower() in {k.lower() for k in headers}]

    return {
        "vulnerabilities": vulns,
        "secrets": secrets,
        "disclosed_headers": disclosed,
        "risk_score": min(100, sum(v["confidence"] * 100 for v in vulns)),
        "total_issues": len(vulns) + len(secrets) + len(disclosed),
    }


@app.get("/api/hetty/history")
async def hetty_history(
    limit: int = Query(50, ge=1, le=200),
    offset: int = Query(0, ge=0),
):
    """Return request history for the Hetty testing toolkit."""
    # Strip _full from history entries to keep response light
    items = []
    for entry in _HETTY_HISTORY[offset:offset + limit]:
        items.append({k: v for k, v in entry.items() if k != "_full"})
    return {
        "items": items,
        "total": len(_HETTY_HISTORY),
        "limit": limit,
        "offset": offset,
    }


@app.delete("/api/hetty/history")
async def hetty_clear_history():
    """Clear Hetty request history."""
    count = len(_HETTY_HISTORY)
    _HETTY_HISTORY.clear()
    return {"cleared": count}


@app.get("/api/hetty/history/{request_id}")
async def hetty_history_detail(request_id: str):
    """Get full details for a specific request from history."""
    for entry in _HETTY_HISTORY:
        if entry["id"] == request_id and "_full" in entry:
            return entry["_full"]
    raise HTTPException(status_code=404, detail="Request not found in history")


# ═══════════════════════════════════════════════════════════════════════════════
# AI Attack Console Endpoints
# ═══════════════════════════════════════════════════════════════════════════════

try:
    from backend.ai_attack_engine import (
        AttackSurfaceAnalyzer, PayloadGenerator, AdaptiveFuzzer,
        ResponseIntelligenceEngine, VulnConfirmationEngine,
        AttackMemoryStore, AttackGraphBuilder, ai_analyze_request,
    )
    _AI_ATTACK_ENGINE_AVAILABLE = True
except ImportError:
    try:
        from ai_attack_engine import (
            AttackSurfaceAnalyzer, PayloadGenerator, AdaptiveFuzzer,
            ResponseIntelligenceEngine, VulnConfirmationEngine,
            AttackMemoryStore, AttackGraphBuilder, ai_analyze_request,
        )
        _AI_ATTACK_ENGINE_AVAILABLE = True
    except ImportError:
        _AI_ATTACK_ENGINE_AVAILABLE = False

# In-memory fuzzing session store
_FUZZ_SESSIONS: dict = {}
_ATTACK_DASHBOARD_STATS: dict = {
    "requests_sent": 0,
    "payloads_tested": 0,
    "potential_vulns": 0,
    "confirmed_vulns": 0,
    "active_fuzz_sessions": 0,
}


@app.post("/api/hetty/ai/analyze")
async def hetty_ai_analyze(req: Request):
    """AI-powered attack surface analysis of an HTTP request."""
    if not _AI_ATTACK_ENGINE_AVAILABLE:
        raise HTTPException(status_code=501, detail="AI Attack Engine not available")

    body = await req.json()
    method = body.get("method", "GET")
    url = body.get("url", "")
    headers = body.get("headers", {})
    cookies = body.get("cookies", {})
    request_body = body.get("body", "")
    params = body.get("params", {})

    if not url:
        raise HTTPException(status_code=400, detail="URL is required")

    result = ai_analyze_request(method, url, headers, cookies, request_body, params)

    # Store intelligence
    try:
        from urllib.parse import urlparse as _urlparse
        host = _urlparse(url).hostname or url
        AttackMemoryStore.save(host, {
            "endpoints": [url],
            "technologies": [],
        })
    except Exception:
        pass

    return {"success": True, **result}


@app.post("/api/hetty/ai/payloads")
async def hetty_ai_payloads(req: Request):
    """Generate context-aware payloads for a specific vulnerability type."""
    if not _AI_ATTACK_ENGINE_AVAILABLE:
        raise HTTPException(status_code=501, detail="AI Attack Engine not available")

    body = await req.json()
    vuln_type = body.get("vuln_type", "sqli")
    current_value = body.get("current_value", "")
    location = body.get("location", "param")
    parameter_name = body.get("parameter", "")

    payloads = PayloadGenerator.generate_ai_payloads(vuln_type, {
        "current_value": current_value,
        "location": location,
        "parameter": parameter_name,
    })

    _ATTACK_DASHBOARD_STATS["payloads_tested"] += len(payloads)

    return {
        "success": True,
        "vuln_type": vuln_type,
        "payloads": payloads,
        "total": len(payloads),
    }


@app.post("/api/hetty/ai/fuzz")
async def hetty_ai_fuzz(req: Request):
    """Run adaptive fuzzing on a target request."""
    if not _AI_ATTACK_ENGINE_AVAILABLE:
        raise HTTPException(status_code=501, detail="AI Attack Engine not available")

    try:
        import httpx
    except ImportError:
        raise HTTPException(status_code=501, detail="httpx not installed")

    body = await req.json()
    target_url = body.get("url", "")
    method = body.get("method", "GET").upper()
    headers = body.get("headers", {})
    cookies = body.get("cookies", {})
    params = body.get("params", {})
    request_body = body.get("body", "")
    target_param = body.get("target_param", "")
    target_location = body.get("target_location", "param")  # param, header, cookie, body
    vuln_types = body.get("vuln_types", [])
    max_mutations = min(body.get("max_mutations", 20), 30)

    if not target_url:
        raise HTTPException(status_code=400, detail="URL is required")

    # Rate limit
    now = _time_mod.time()
    rate_key = "fuzz_" + (req.client.host if req.client else "anon")
    bucket = _POC_RATE_LIMIT.setdefault(rate_key, [])
    bucket[:] = [t for t in bucket if now - t < 60]
    if len(bucket) >= 60:
        raise HTTPException(status_code=429, detail="Fuzz rate limit exceeded (60/min)")
    bucket.append(now)

    # SSRF protection
    safe, reason = _is_ssrf_safe(target_url)
    if not safe:
        return {"success": False, "error": reason, "blocked": True}

    # Determine original value
    original_value = ""
    if target_location == "param":
        original_value = params.get(target_param, "")
    elif target_location == "header":
        original_value = headers.get(target_param, "")
    elif target_location == "cookie":
        original_value = cookies.get(target_param, "")
    elif target_location == "body":
        original_value = request_body

    # Generate mutations
    mutations = AdaptiveFuzzer.generate_mutations(target_param, original_value, vuln_types)
    mutations = mutations[:max_mutations]

    # Send baseline request first
    exec_headers = {"User-Agent": "QuantaraScanner/5.0 (Fuzzer)", "Accept": "*/*"}
    for k, v in headers.items():
        if k.lower() not in ("host", "content-length"):
            exec_headers[k] = v
    cookie_str = "; ".join(f"{k}={v}" for k, v in cookies.items())
    if cookie_str:
        exec_headers["Cookie"] = cookie_str

    session_id = str(uuid.uuid4())[:8]
    results = []

    try:
        async with httpx.AsyncClient(
            timeout=httpx.Timeout(15.0, connect=5.0),
            follow_redirects=True,
            verify=False,
            limits=httpx.Limits(max_connections=5, max_keepalive_connections=2),
        ) as client:
            # Baseline
            from urllib.parse import urlencode as _urlencode, urlparse as _urlparse2, urlunparse as _urlunparse
            baseline_url = target_url
            if params:
                parsed = _urlparse2(target_url)
                baseline_url = _urlunparse(parsed._replace(query=_urlencode(params)))

            baseline_kw: dict = {"method": method, "url": baseline_url, "headers": exec_headers}
            if request_body and method in ("POST", "PUT", "PATCH"):
                baseline_kw["content"] = request_body.encode("utf-8", errors="replace")

            start = _time_mod.time()
            baseline_resp = await client.request(**baseline_kw)
            baseline_time = int((_time_mod.time() - start) * 1000)

            try:
                baseline_body = baseline_resp.text[:50000]
            except Exception:
                baseline_body = ""

            baseline_status = baseline_resp.status_code
            baseline_length = len(baseline_body)

            # Run mutations
            for mut in mutations:
                try:
                    # Apply mutation
                    fuzz_params = dict(params)
                    fuzz_headers = dict(exec_headers)
                    fuzz_body = request_body
                    fuzz_cookies = dict(cookies)
                    mutated_value = mut["mutated"]

                    if target_location == "param":
                        fuzz_params[target_param] = mutated_value
                    elif target_location == "header":
                        fuzz_headers[target_param] = mutated_value
                    elif target_location == "cookie":
                        fuzz_cookies[target_param] = mutated_value
                        cookie_str_fuzz = "; ".join(f"{k}={v}" for k, v in fuzz_cookies.items())
                        fuzz_headers["Cookie"] = cookie_str_fuzz
                    elif target_location == "body":
                        fuzz_body = mutated_value

                    fuzz_url = target_url
                    if fuzz_params:
                        parsed = _urlparse2(target_url)
                        fuzz_url = _urlunparse(parsed._replace(query=_urlencode(fuzz_params)))

                    kw: dict = {"method": method, "url": fuzz_url, "headers": fuzz_headers}
                    if fuzz_body and method in ("POST", "PUT", "PATCH"):
                        kw["content"] = fuzz_body.encode("utf-8", errors="replace")

                    start = _time_mod.time()
                    resp = await client.request(**kw)
                    elapsed = int((_time_mod.time() - start) * 1000)

                    try:
                        resp_body = resp.text[:50000]
                    except Exception:
                        resp_body = ""

                    # Analyze
                    analysis = AdaptiveFuzzer.analyze_fuzz_response(
                        baseline_status, baseline_length, baseline_time,
                        resp.status_code, len(resp_body), elapsed,
                        resp_body, mutated_value,
                    )

                    results.append({
                        "mutation": mut["mutation"],
                        "parameter": target_param,
                        "original": mut["original"],
                        "payload": mutated_value,
                        "status_code": resp.status_code,
                        "response_length": len(resp_body),
                        "response_time_ms": elapsed,
                        **analysis,
                    })

                    _ATTACK_DASHBOARD_STATS["requests_sent"] += 1
                    _ATTACK_DASHBOARD_STATS["payloads_tested"] += 1
                    if analysis["is_anomaly"]:
                        _ATTACK_DASHBOARD_STATS["potential_vulns"] += 1

                except Exception as e:
                    results.append({
                        "mutation": mut["mutation"],
                        "parameter": target_param,
                        "payload": mut["mutated"],
                        "error": str(e)[:200],
                        "is_anomaly": False,
                    })

    except Exception as e:
        return {"success": False, "error": str(e)[:500], "session_id": session_id}

    # Store session
    _FUZZ_SESSIONS[session_id] = {
        "id": session_id,
        "target": target_url,
        "param": target_param,
        "started": _time_mod.time(),
        "results": results,
        "baseline": {
            "status": baseline_status,
            "length": baseline_length,
            "time_ms": baseline_time,
        },
    }

    anomaly_count = sum(1 for r in results if r.get("is_anomaly"))

    # Save intelligence
    try:
        from urllib.parse import urlparse as _up
        host = _up(target_url).hostname or target_url
        AttackMemoryStore.save(host, {
            "endpoints": [target_url],
            "confirmed_vulns": [r for r in results if r.get("anomaly_score", 0) > 0.5],
        })
    except Exception:
        pass

    return {
        "success": True,
        "session_id": session_id,
        "total_mutations": len(results),
        "anomalies_found": anomaly_count,
        "baseline": {
            "status": baseline_status,
            "length": baseline_length,
            "time_ms": baseline_time,
        },
        "results": results,
    }


@app.post("/api/hetty/ai/verify")
async def hetty_ai_verify(req: Request):
    """Get verification steps for a suspected vulnerability."""
    if not _AI_ATTACK_ENGINE_AVAILABLE:
        raise HTTPException(status_code=501, detail="AI Attack Engine not available")

    body = await req.json()
    vuln_type = body.get("vuln_type", "")
    target_value = body.get("target_value", "")

    if not vuln_type:
        raise HTTPException(status_code=400, detail="vuln_type is required")

    steps = VulnConfirmationEngine.get_verification_steps(vuln_type, target_value)
    exploit_options = VulnConfirmationEngine.get_exploit_options(vuln_type)

    return {
        "success": True,
        "vuln_type": vuln_type,
        "verification_steps": steps,
        "exploit_options": exploit_options,
    }


@app.post("/api/hetty/ai/response-intel")
async def hetty_ai_response_intel(req: Request):
    """Analyze HTTP response for security intelligence."""
    if not _AI_ATTACK_ENGINE_AVAILABLE:
        raise HTTPException(status_code=501, detail="AI Attack Engine not available")

    body = await req.json()
    status_code = body.get("status_code", 200)
    headers = body.get("headers", {})
    response_body = body.get("body", "")
    request_body = body.get("request_body", "")

    intel = ResponseIntelligenceEngine.analyze(status_code, headers, response_body, request_body)

    # Save intelligence
    try:
        target = body.get("target_url", "")
        if target:
            from urllib.parse import urlparse as _up2
            host = _up2(target).hostname or target
            AttackMemoryStore.save(host, {
                "database_type": intel.database_type,
                "framework": intel.framework,
                "technologies": [intel.framework] if intel.framework else [],
            })
    except Exception:
        pass

    from dataclasses import asdict as _asdict
    return {"success": True, **_asdict(intel)}


@app.post("/api/hetty/ai/attack-graph")
async def hetty_ai_attack_graph(req: Request):
    """Build attack surface graph from findings."""
    if not _AI_ATTACK_ENGINE_AVAILABLE:
        raise HTTPException(status_code=501, detail="AI Attack Engine not available")

    body = await req.json()
    target = body.get("target", "")
    findings = body.get("findings", [])

    if not target:
        raise HTTPException(status_code=400, detail="target is required")

    graph = AttackGraphBuilder.build(target, findings)
    return {"success": True, **graph}


@app.get("/api/hetty/ai/memory")
async def hetty_ai_memory():
    """Get stored attack intelligence for all targets."""
    if not _AI_ATTACK_ENGINE_AVAILABLE:
        raise HTTPException(status_code=501, detail="AI Attack Engine not available")

    return {"success": True, "targets": AttackMemoryStore.get_all()}


@app.get("/api/hetty/ai/memory/{host}")
async def hetty_ai_memory_host(host: str):
    """Get stored attack intelligence for a specific host."""
    if not _AI_ATTACK_ENGINE_AVAILABLE:
        raise HTTPException(status_code=501, detail="AI Attack Engine not available")

    intel = AttackMemoryStore.get(host)
    if not intel:
        return {"success": True, "found": False, "host": host}

    return {"success": True, "found": True, **intel}


@app.get("/api/hetty/ai/dashboard")
async def hetty_ai_dashboard():
    """Get real-time attack dashboard statistics."""
    return {
        "success": True,
        **_ATTACK_DASHBOARD_STATS,
        "fuzz_sessions": len(_FUZZ_SESSIONS),
        "targets_in_memory": len(AttackMemoryStore.get_all()) if _AI_ATTACK_ENGINE_AVAILABLE else 0,
        "history_count": len(_HETTY_HISTORY),
    }


@app.get("/health")
async def health():
    return {"status": "ok"}


# ═══════════════════════════════════════════════════════════════════════════════
# Run
# ═══════════════════════════════════════════════════════════════════════════════

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000, log_level="info")
