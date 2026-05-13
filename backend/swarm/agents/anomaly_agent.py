"""
Enhanced Anomaly Detection Agent — Advanced Response Analysis
================================================================
Enhanced anomaly detection with:
    - Statistical baseline profiling per endpoint
    - Response fingerprinting (hash-based change detection)
    - HTTP method confusion testing
    - Content-type mismatch detection
    - Cache poisoning analysis
    - Race condition detection via parallel requests
"""

from __future__ import annotations

import asyncio
import hashlib
import logging
import time
import uuid
from collections import defaultdict
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urljoin

logger = logging.getLogger(__name__)


class EnhancedAnomalyAgent:
    """
    Advanced anomaly detection using statistical analysis,
    response fingerprinting, and behavioral probing.
    """

    def __init__(self, emitter=None, message_bus=None, shared_state=None):
        self.name = "Anomaly-Pro"
        self.role = "Advanced Behavioral Analysis Engine"
        self.emitter = emitter
        self.bus = message_bus
        self.state = shared_state
        self.is_active = False

    async def execute(self, target: str, scan_id: str,
                       context: Dict = None) -> List[Dict]:
        self.is_active = True
        context = context or {}
        findings: List[Dict] = []

        try:
            from backend.intelligence_nodes import HTTPProbe, ResponseAnalyzer
            probe = HTTPProbe(connect_timeout=5.0, read_timeout=10.0, max_rps=4.0)

            base = context.get("target_base", target)
            endpoints = context.get("discovered_endpoints", [target])[:5]

            if self.emitter:
                await self.emitter.emit("node_started", {
                    "node": self.name, "role": self.role, "target": target,
                }, scan_id)

            # Phase 1: Statistical baseline profiling
            baselines = await self._build_baselines(probe, endpoints, scan_id)

            # Phase 2: Content-type mismatch detection
            findings.extend(await self._content_type_analysis(
                probe, base, endpoints, scan_id
            ))

            # Phase 3: HTTP method confusion
            findings.extend(await self._method_confusion(
                probe, endpoints, scan_id
            ))

            # Phase 4: Cache poisoning analysis
            findings.extend(await self._cache_poisoning(
                probe, base, endpoints, scan_id
            ))

            # Phase 5: Race condition detection
            findings.extend(await self._race_condition_probe(
                probe, endpoints, scan_id
            ))

            # Phase 6: Response stability analysis
            findings.extend(await self._stability_analysis(
                probe, baselines, endpoints, scan_id
            ))

            if self.emitter:
                await self.emitter.emit("node_completed", {
                    "node": self.name,
                    "findings_count": len(findings),
                    "message": f"Anomaly-Pro: {len(findings)} behavioral anomalies detected",
                }, scan_id)

        except Exception as exc:
            logger.error(f"[{self.name}] Error: {exc}", exc_info=True)
        finally:
            self.is_active = False

        return findings

    async def _build_baselines(self, probe, endpoints: List[str],
                                 scan_id: str) -> Dict[str, Dict]:
        """Build statistical baselines for each endpoint."""
        baselines: Dict[str, Dict] = {}

        for ep in endpoints[:4]:
            samples = []
            for _ in range(3):
                result = await probe.get(ep)
                if result.ok:
                    samples.append({
                        "status": result.status_code,
                        "size": len(result.body),
                        "time": result.response_time,
                        "hash": hashlib.md5(result.body[:2000].encode()).hexdigest()[:12],
                    })
                await asyncio.sleep(0.03)

            if samples:
                avg_size = sum(s["size"] for s in samples) / len(samples)
                avg_time = sum(s["time"] for s in samples) / len(samples)
                baselines[ep] = {
                    "avg_size": avg_size,
                    "avg_time": avg_time,
                    "status": samples[0]["status"],
                    "hash": samples[0]["hash"],
                    "stable": len(set(s["hash"] for s in samples)) == 1,
                }

                if self.emitter:
                    await self.emitter.emit("anomaly_detected", {
                        "node": self.name,
                        "check": "Baseline",
                        "message": (
                            f"Baseline: {ep.split('?')[0][-40:]} — "
                            f"size={avg_size:.0f}B time={avg_time:.2f}s "
                            f"stable={'yes' if baselines[ep]['stable'] else 'no'}"
                        ),
                    }, scan_id)

        return baselines

    async def _content_type_analysis(self, probe, base: str,
                                       endpoints: List[str],
                                       scan_id: str) -> List[Dict]:
        """Detect content-type mismatches and MIME sniffing vulnerabilities."""
        findings = []

        for ep in endpoints[:3]:
            result = await probe.get(ep)
            if not result.ok:
                continue

            content_type = result.headers.get("Content-Type", "").lower()
            x_content_type = result.headers.get("X-Content-Type-Options", "").lower()

            # Check for JSON response without proper content type
            if result.body.strip().startswith("{") and "json" not in content_type:
                finding = self._make_finding(
                    title="Content-Type Mismatch: JSON Response Without application/json",
                    description=(
                        f"Endpoint {ep.split('?')[0]} returns JSON data but Content-Type is "
                        f"'{content_type}'. This can lead to MIME confusion attacks and "
                        f"Content-Type sniffing vulnerabilities."
                    ),
                    severity="low",
                    endpoint=ep,
                    confidence=0.85,
                    cwe="CWE-436",
                    owasp="A05:2021 - Security Misconfiguration",
                    category="Content Security",
                    remediation="Set Content-Type: application/json for JSON responses.",
                )
                findings.append(finding)
                if self.emitter:
                    self.emitter.add_finding(finding)
                    await self.emitter.emit("vulnerability_detected", finding, scan_id)

            # Check for missing X-Content-Type-Options
            if not x_content_type:
                await self.emitter.emit("anomaly_detected", {
                    "node": self.name,
                    "message": f"Missing X-Content-Type-Options at {ep.split('?')[0][-30:]}",
                }, scan_id) if self.emitter else None

        return findings

    async def _method_confusion(self, probe, endpoints: List[str],
                                  scan_id: str) -> List[Dict]:
        """Test for HTTP method confusion and verb tampering."""
        findings = []

        unusual_methods = ["PATCH", "OPTIONS", "HEAD", "TRACE"]

        for ep in endpoints[:2]:
            get_result = await probe.get(ep)
            if not get_result.ok:
                continue

            for method in unusual_methods:
                await asyncio.sleep(0.03)
                result = await probe._request(method, ep)

                if method == "TRACE" and result.ok and result.status_code == 200:
                    if "TRACE" in result.body.upper():
                        finding = self._make_finding(
                            title="HTTP TRACE Method Enabled — Cross-Site Tracing Risk",
                            description=(
                                f"TRACE method is enabled at {ep.split('?')[0]} and echoes "
                                f"the request back. This enables Cross-Site Tracing (XST) "
                                f"attacks that can steal HTTP-only cookies via JavaScript."
                            ),
                            severity="medium",
                            endpoint=ep,
                            confidence=0.95,
                            cwe="CWE-693",
                            owasp="A05:2021 - Security Misconfiguration",
                            category="HTTP Security",
                            remediation="Disable TRACE method in web server configuration.",
                        )
                        findings.append(finding)
                        if self.emitter:
                            self.emitter.add_finding(finding)
                            await self.emitter.emit("vulnerability_detected", finding, scan_id)

                # Method confusion: POST returns different auth level than GET
                if method == "PATCH" and result.ok:
                    if result.status_code == 200 and get_result.status_code in (401, 403):
                        finding = self._make_finding(
                            title="HTTP Method Confusion — Auth Bypass via Verb Tampering",
                            description=(
                                f"GET to {ep.split('?')[0]} returns {get_result.status_code} "
                                f"but {method} returns 200. Method-based auth enforcement is "
                                f"inconsistent, allowing potential access control bypass."
                            ),
                            severity="high",
                            endpoint=ep,
                            confidence=0.80,
                            cwe="CWE-287",
                            owasp="A01:2021 - Broken Access Control",
                            category="Access Control",
                            remediation="Enforce authentication consistently across all HTTP methods.",
                        )
                        findings.append(finding)
                        if self.emitter:
                            self.emitter.add_finding(finding)
                            await self.emitter.emit("vulnerability_detected", finding, scan_id)

        return findings

    async def _cache_poisoning(self, probe, base: str,
                                 endpoints: List[str],
                                 scan_id: str) -> List[Dict]:
        """Test for web cache poisoning via header injection."""
        findings = []

        poison_headers = {
            "X-Forwarded-Host": "evil.attacker.com",
            "X-Original-URL": "/admin",
            "X-Rewrite-URL": "/admin",
            "X-Forwarded-Scheme": "nothttps",
        }

        for ep in endpoints[:2]:
            for header, value in poison_headers.items():
                await asyncio.sleep(0.03)
                result = await probe.get(ep, extra_headers={header: value})

                if result.ok and value in result.body:
                    if self.emitter:
                        await self.emitter.emit("anomaly_detected", {
                            "node": self.name,
                            "check": "Cache Poisoning",
                            "message": f"Header '{header}: {value}' reflected in response body",
                        }, scan_id)

                    finding = self._make_finding(
                        title=f"Web Cache Poisoning via {header}",
                        description=(
                            f"Header '{header}: {value}' is reflected in the response body "
                            f"at {ep.split('?')[0]}. If this endpoint is cached, attackers can "
                            f"poison the cache to serve malicious content to other users."
                        ),
                        severity="high",
                        endpoint=ep,
                        confidence=0.82,
                        cwe="CWE-444",
                        owasp="A05:2021 - Security Misconfiguration",
                        category="Cache Poisoning",
                        evidence={"header": header, "value": value},
                        remediation=(
                            "Do not reflect unvalidated request headers in responses. "
                            "Configure cache to key on security-relevant headers."
                        ),
                    )
                    findings.append(finding)
                    if self.emitter:
                        self.emitter.add_finding(finding)
                        await self.emitter.emit("vulnerability_detected", finding, scan_id)
                    break

        return findings

    async def _race_condition_probe(self, probe, endpoints: List[str],
                                      scan_id: str) -> List[Dict]:
        """Detect potential race conditions via parallel request analysis."""
        findings = []

        for ep in endpoints[:2]:
            # Send 5 identical requests in parallel
            tasks = [probe.get(ep) for _ in range(5)]
            results = await asyncio.gather(*tasks, return_exceptions=True)

            valid = [r for r in results if isinstance(r, type(results[0])) and hasattr(r, 'ok') and r.ok]

            if len(valid) >= 3:
                statuses = set(r.status_code for r in valid)
                sizes = [len(r.body) for r in valid]
                size_variance = max(sizes) - min(sizes) if sizes else 0

                if self.emitter:
                    await self.emitter.emit("anomaly_detected", {
                        "node": self.name,
                        "check": "Race Condition",
                        "message": (
                            f"Parallel request analysis: {len(statuses)} distinct statuses, "
                            f"size variance: {size_variance}B"
                        ),
                    }, scan_id)

                # Different statuses for identical requests = race condition indicator
                if len(statuses) > 1:
                    finding = self._make_finding(
                        title="Potential Race Condition — Inconsistent Parallel Responses",
                        description=(
                            f"5 identical parallel requests to {ep.split('?')[0]} returned "
                            f"{len(statuses)} different status codes: {sorted(statuses)}. "
                            f"This inconsistency indicates a potential race condition in "
                            f"server-side state management."
                        ),
                        severity="medium",
                        endpoint=ep,
                        confidence=0.68,
                        cwe="CWE-362",
                        owasp="A04:2021 - Insecure Design",
                        category="Race Condition",
                        evidence={"statuses": list(statuses), "size_variance": size_variance},
                        remediation=(
                            "Implement proper synchronization (mutexes, transactions) for "
                            "state-modifying operations. Use idempotency keys for critical endpoints."
                        ),
                    )
                    findings.append(finding)
                    if self.emitter:
                        self.emitter.add_finding(finding)
                        await self.emitter.emit("vulnerability_detected", finding, scan_id)

        return findings

    async def _stability_analysis(self, probe, baselines: Dict,
                                    endpoints: List[str],
                                    scan_id: str) -> List[Dict]:
        """Analyze response stability over time."""
        findings = []

        for ep, baseline in baselines.items():
            if not baseline.get("stable", True):
                finding = self._make_finding(
                    title="Unstable Response Content — Non-Deterministic Behavior",
                    description=(
                        f"Multiple identical requests to {ep.split('?')[0]} produced "
                        f"different response bodies. Non-deterministic behavior may indicate "
                        f"race conditions, caching issues, or dynamic content injection points."
                    ),
                    severity="low",
                    endpoint=ep,
                    confidence=0.65,
                    cwe="CWE-330",
                    owasp="A04:2021 - Insecure Design",
                    category="Behavioral Anomaly",
                    remediation="Investigate non-deterministic response generation. Ensure consistent state handling.",
                )
                findings.append(finding)
                if self.emitter:
                    self.emitter.add_finding(finding)
                    await self.emitter.emit("vulnerability_detected", finding, scan_id)

        return findings

    def _make_finding(self, **kwargs) -> Dict:
        return {
            "id": str(uuid.uuid4()),
            "node_name": self.name,
            "module_name": self.name,
            "module": self.name,
            "title": kwargs.get("title", ""),
            "description": kwargs.get("description", ""),
            "severity": kwargs.get("severity", "info"),
            "endpoint": kwargs.get("endpoint", ""),
            "file": kwargs.get("endpoint", ""),
            "confidence": kwargs.get("confidence", 0.0),
            "cwe": kwargs.get("cwe", ""),
            "owasp": kwargs.get("owasp", ""),
            "category": kwargs.get("category", ""),
            "evidence": kwargs.get("evidence", {}),
            "remediation": kwargs.get("remediation", ""),
            "exploit_payload": kwargs.get("exploit_payload", ""),
            "matched_content": kwargs.get("matched_content", ""),
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "tags": [self.name, kwargs.get("category", "")],
            "line_number": 0,
        }
