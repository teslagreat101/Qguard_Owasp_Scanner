"""
Quantara Security v4.0 — API Security Scanner (OWASP API Security Top 10)

Detects:
  - Excessive data exposure (full model serialization, no field filtering)
  - Broken Object Level Authorization (BOLA — accessing resources by ID without auth)
  - Unrestricted resource consumption (no pagination, no size limits, no timeout)
  - API documentation exposure (Swagger/GraphQL introspection in production)
  - Mass assignment via API
  - Security misconfiguration on API endpoints
"""

from __future__ import annotations
import re
from dataclasses import dataclass, field
from pathlib import Path
import time as _api_time
from typing import Optional, Callable

try:
    from Centralize_Scanners.scanner_engine.neo_intelligence import get_payload_generator, get_spec_abuse_kb
except ImportError:
    get_payload_generator = lambda: None
    get_spec_abuse_kb = lambda: None

@dataclass
class APIFinding:
    id: str
    file: str
    line_number: int
    severity: str
    title: str
    description: str
    matched_content: str
    category: str
    subcategory: str  # data-exposure | bola | resource-consumption | docs-exposure | mass-assignment | api-misconfig
    cwe: str
    remediation: str
    confidence: float
    tags: list[str] = field(default_factory=list)

@dataclass
class APIPattern:
    id: str
    pattern: str
    severity: str
    title: str
    description: str
    cwe: str
    remediation: str
    confidence: float
    subcategory: str
    tags: tuple[str, ...] = ()

def _build_rules() -> list[APIPattern]:
    rules: list[APIPattern] = []
    def _add(id_, pat, sev, title, desc, cwe, rem, conf, sub, tags=()):
        rules.append(APIPattern(id_, pat, sev, title, desc, cwe, rem, conf, sub, tags))

    # ── Excessive Data Exposure ───────────────────────────────────
    _add("API-001", r"""(?:serializer_class|Serializer)\s*(?:=|:)\s*\w+Serializer\b(?!.*?fields\s*=)""",
         "High", "DRF Serializer Without Field Restriction",
         "Django REST serializer used without explicit 'fields'. All model fields may be exposed.",
         "CWE-200", "Define fields = ['field1', 'field2'] in serializer Meta class. Use exclude for sensitive fields.",
         0.70, "data-exposure", ("drf", "serializer"))

    _add("API-002", r"""fields\s*=\s*["']__all__["']""",
         "High", "Serializer Exposing All Fields (__all__)",
         "Serializer configured with fields='__all__'. Exposes every model field including sensitive ones.",
         "CWE-200", "Explicitly list only the fields that should be exposed. Exclude passwords, internal IDs.",
         0.85, "data-exposure", ("serializer", "all-fields"))

    _add("API-003", r"""\.(?:to_dict|to_json|model_to_dict|as_dict)\(\s*\)""",
         "High", "Full Object Serialization Without Filtering",
         "Object converted to dict/JSON without field filtering. May include sensitive internal data.",
         "CWE-200", "Implement a DTO/presenter pattern that explicitly selects safe fields.",
         0.65, "data-exposure", ("serialization", "unfiltered"))

    _add("API-004", r"""res(?:ponse)?\.(?:json|send)\s*\(\s*(?:user|account|profile|customer|order)\b""",
         "Medium", "Full Object in API Response",
         "Full object sent in API response. May include password hashes, internal IDs, PII.",
         "CWE-200", "Create a response DTO that excludes sensitive fields before sending.",
         0.55, "data-exposure", ("response", "full-object"))

    # ── Broken Object Level Authorization ─────────────────────────
    _add("API-010", r"""@(?:api_view|route|app\.(?:get|post|put|delete|patch))\s*\([^)]*["'].*?(?:/:id|/\{id\}|/<\w+>|/<int:\w+>)""",
         "High", "API Endpoint with ID Parameter — Potential BOLA",
         "API endpoint uses path parameter for object ID. Verify authorization check on every request.",
         "CWE-639", "Add authorization middleware that verifies the authenticated user owns the requested resource.",
         0.55, "bola", ("api", "authorization"))

    _add("API-011", r"""(?:findById|findOne|get_object_or_404)\s*\(\s*\w*(?:id|pk|slug)\s*\)""",
         "Medium", "Object Lookup by ID Without Authorization Context",
         "Object fetched by ID without visible authorization check nearby.",
         "CWE-639", "Use get_object_or_404(Model, id=id, owner=request.user) pattern.",
         0.50, "bola", ("idor", "lookup"))

    # ── Unrestricted Resource Consumption ─────────────────────────
    _add("API-020", r"""\.(?:find|all|list|filter|query)\s*\(\s*\)(?!.*?(?:limit|page|paginate|offset|take|skip|per_page))""",
         "High", "API Query Without Pagination/Limit",
         "Database query without pagination or limit. Can cause DoS via unbounded result sets.",
         "CWE-770", "Add pagination with max page size. Use .limit() and .offset(). Set default page size.",
         0.60, "resource-consumption", ("pagination", "dos"))

    _add("API-021", r"""(?:maxFileSize|max_content_length|bodyParser\.json)\s*\(\s*\{?\s*(?:limit\s*[:=]\s*["']?\d{3,}(?:mb|gb)|$)""",
         "High", "Excessive Request Size Limit",
         "Request body size limit set very high or missing. Large payloads can cause memory exhaustion.",
         "CWE-770", "Set reasonable body size limits: 1MB for JSON, 10MB for file uploads.",
         0.65, "resource-consumption", ("body-size", "dos"))

    _add("API-022", r"""(?:graphql|GraphQL)(?:.*?(?:maxDepth|depthLimit|queryComplexity|costAnalysis))?""",
         "Medium", "GraphQL Endpoint — Check for Query Depth Limiting",
         "GraphQL endpoint detected. Deeply nested queries can cause exponential DB load.",
         "CWE-770", "Implement query depth limiting (max 10), complexity analysis, and timeout.",
         0.50, "resource-consumption", ("graphql", "depth"))

    _add("API-023", r"""(?:timeout|Timeout|TIMEOUT)\s*(?:=|:)\s*(?:0|None|null|false|Float::INFINITY)""",
         "High", "No Request Timeout Configured",
         "HTTP request timeout set to zero/infinity. Hanging connections can exhaust server resources.",
         "CWE-400", "Set reasonable timeouts: 30s for user-facing, 60s for background tasks.",
         0.75, "resource-consumption", ("timeout", "dos"))

    # ── API Documentation Exposure ────────────────────────────────
    _add("API-030", r"""(?:swagger|openapi|api-?docs|api-?doc).*?(?:path|route|endpoint|url)\s*(?:=|:)\s*["'].*?(?:swagger|openapi|api-?docs)""",
         "Medium", "API Documentation Endpoint Exposed",
         "Swagger/OpenAPI docs accessible — may reveal internal API structure, schemas, and endpoints.",
         "CWE-200", "Restrict API docs to authenticated users in production. Disable in production deploy.",
         0.65, "docs-exposure", ("swagger", "openapi"))

    _add("API-031", r"""introspection\s*(?:=|:)\s*(?:true|True|enabled)""",
         "High", "GraphQL Introspection Enabled",
         "GraphQL introspection exposes entire API schema including all types, fields, and queries.",
         "CWE-200", "Disable introspection in production: introspection=False / introspection: false.",
         0.85, "docs-exposure", ("graphql", "introspection"))

    # ── Mass Assignment ───────────────────────────────────────────
    _add("API-040", r"""(?:Model|model)\.(?:create|update)\s*\(\s*(?:req\.body|request\.data|request\.json|params\.permit!)""",
         "Critical", "Mass Assignment — Direct Request Body to Model",
         "All request fields passed directly to model create/update. Attacker can set admin=true, price=0.",
         "CWE-915", "Use allowlists: Model.create(req.body.only(['name', 'email'])). Define permitted params.",
         0.80, "mass-assignment", ("mass-assignment",))

    _add("API-041", r"""(?:\.permit|strong_parameters).*?(?:permit!|permit\s*\()""",
         "High", "Rails Mass Assignment — Review Permitted Params",
         "Rails strong parameters detected. Review that only safe fields are permitted.",
         "CWE-915", "Ensure params.permit only lists fields users should modify. Never use permit!",
         0.60, "mass-assignment", ("rails", "strong-params"))

    # ── API Security Misconfiguration ─────────────────────────────
    _add("API-050", r"""(?:@csrf_exempt|csrf_exempt|DisableCsrf|disable_csrf)""",
         "High", "CSRF Protection Disabled on API Endpoint",
         "CSRF protection explicitly disabled. State-changing operations are vulnerable to CSRF attacks.",
         "CWE-352", "Use token-based auth (JWT) for APIs or ensure CSRF tokens are required.",
         0.75, "api-misconfig", ("csrf", "disabled"))

    _add("API-051", r"""(?:X-Rate-Limit|rateLimit|rate_limit|throttle).*?(?:=|:)\s*(?:0|false|None|disabled)""",
         "High", "Rate Limiting Disabled",
         "Rate limiting explicitly disabled on API endpoint. Vulnerable to brute force and DoS.",
         "CWE-770", "Enable rate limiting: 100 requests/minute for normal APIs, 5/minute for auth endpoints.",
         0.80, "api-misconfig", ("rate-limit", "disabled"))

    return rules

ALL_API_RULES = _build_rules()
COMPILED_API_RULES = [(re.compile(r.pattern, re.IGNORECASE | re.MULTILINE | re.DOTALL), r) for r in ALL_API_RULES]
SKIP_DIRS = {"node_modules", ".git", ".next", "dist", "build", "__pycache__", ".venv", "venv", "vendor", ".cache"}
SCAN_EXTENSIONS = {".py", ".js", ".jsx", ".ts", ".tsx", ".java", ".go", ".rb", ".php", ".cs", ".yaml", ".yml", ".json", ".graphql", ".gql"}

def scan_api_file(content: str, filepath: str, base_path: str = "") -> list[APIFinding]:
    findings: list[APIFinding] = []
    relative = filepath.replace(base_path, "").lstrip("/\\") if base_path else filepath
    seen: set[str] = set()
    for compiled_re, rule in COMPILED_API_RULES:
        for match in compiled_re.finditer(content):
            line_num = content.count("\n", 0, match.start()) + 1
            key = f"{rule.id}:{line_num}"
            if key in seen: continue
            seen.add(key)
            findings.append(APIFinding(
                id=f"API-{relative}:{line_num}:{rule.id}", file=relative, line_number=line_num,
                severity=rule.severity, title=rule.title, description=rule.description,
                matched_content=str(match.group(0)).strip()[0:200], category="API Security",
                subcategory=rule.subcategory, cwe=rule.cwe, remediation=rule.remediation,
                confidence=float(rule.confidence), tags=list(rule.tags),
            ))
    return findings

def normalize_api_finding(finding: APIFinding, scan_id: str = "manual") -> APIFinding:
    """Enrich API finding with NEO Intelligence."""
    kb = get_spec_abuse_kb()
    if kb and hasattr(finding, 'subcategory'):
        # Map subcategory to language/tech for KB lookup
        # API scanner patterns are multi-lang, we try to infer from file extension
        ext = Path(finding.file).suffix.lower()
        lang_map = {
            ".py": "python", ".js": "javascript", ".ts": "typescript",
            ".java": "java", ".go": "go", ".rb": "ruby", ".php": "php"
        }
        lang = lang_map.get(ext, "generic")
        
        vectors = kb.get_abuse_vectors(lang)
        if vectors:
            relevant = [v for v in vectors if finding.subcategory in str(v.get("description", "")).lower()]
            relevant_list = list(relevant) if relevant else list(vectors)
            relevant_vectors = relevant_list[0:2] # type: ignore
            
            vector_str = "\n".join([f"• {str(v.get('description', ''))}" for v in relevant_vectors])
            
            spec_abuse_intel = f"\n\n[NEO SPEC ABUSE INTELLIGENCE]\nKnown vectors for {finding.subcategory}:\n{vector_str}"
            finding.description = f"{finding.description}{spec_abuse_intel}"
            
    return finding

def scan_api_directory(root: str, scan_id: str = "manual", max_files: int = 50_000, 
                       on_finding: Optional[Callable] = None) -> list[APIFinding]:
    """Walk a directory tree and scan for API vulnerabilities."""
    all_findings: list[APIFinding] = []
    root_path = Path(root)
    scanned: int = 0
    start = _api_time.time()

    for fpath in root_path.rglob("*"):
        _sc = int(scanned)
        if _sc >= int(max_files):
            break
        if fpath.is_dir():
            continue
        if any(s in fpath.parts for s in SKIP_DIRS):
            continue
        if fpath.suffix.lower() not in SCAN_EXTENSIONS:
            continue
        
        try:
            content = fpath.read_text(encoding="utf-8", errors="ignore")
            if len(content) > 5_000_000:
                continue
            
            findings = scan_api_file(content, str(fpath), str(root_path))
            for f in findings:
                normalized = normalize_api_finding(f, scan_id)
                all_findings.append(normalized)
                if on_finding:
                    try:
                        on_finding(normalized)
                    except Exception:
                        pass
            
            scanned = int(scanned) + 1 # type: ignore
        except (OSError, PermissionError):
            continue
            
    return all_findings

def get_api_scan_summary(findings: list[APIFinding], root: str, files_scanned: int, 
                         start_time: float, scan_id: str = "manual") -> dict:
    """Generate a summary of the API scan results."""
    elapsed_ms = (_api_time.time() - start_time) * 1000
    return {
        "scan_id": scan_id,
        "root": root,
        "files_scanned": files_scanned,
        "findings_count": len(findings),
        "duration_ms": float(f"{elapsed_ms:.2f}"),
        "severity_breakdown": {
            sev: sum(1 for f in findings if f.severity.lower() == sev)
            for sev in ["critical", "high", "medium", "low", "info"]
        },
        "timestamp": _api_time.time()
    }
