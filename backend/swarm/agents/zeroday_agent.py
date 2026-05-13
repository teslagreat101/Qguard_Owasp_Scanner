"""
ZeroDay Agent — Anomaly-Based Unknown Vulnerability Discovery
================================================================
Discovers potential zero-day vulnerabilities through:
    - Behavioral anomaly detection via response differential analysis
    - Exploit primitive generation (boundary, overflow, format string)
    - Mutation testing against unexpected input handling
    - Unknown attack surface discovery via fuzzing novel parameter spaces
"""

from __future__ import annotations

import asyncio
import logging
import random
import time
import uuid
from typing import Any, Dict, List, Optional
from urllib.parse import urljoin, urlparse

logger = logging.getLogger(__name__)


class ZeroDayAgent:
    """
    Anomaly-based vulnerability discovery agent.
    Uses differential response analysis and mutation fuzzing
    to discover non-catalogued vulnerabilities.
    """

    # Exploit primitives for boundary/overflow testing
    PRIMITIVES = [
        # Integer overflow
        "2147483647", "-2147483648", "4294967295", "9999999999999999",
        "0", "-0", "00", "-1",
        # Format string
        "%s%s%s%s%s%s%s", "%n%n%n%n", "%x%x%x%x", "%p%p%p%p",
        # Buffer overflow markers
        "A" * 256, "A" * 1024, "A" * 4096,
        # Type confusion
        "null", "undefined", "NaN", "Infinity", "-Infinity",
        "true", "false", "[]", "{}", "[object Object]",
        # Unicode edge cases
        "\u0000", "\uffff", "\ud800", "\u202e",
        "\x00\x00\x00\x00",
        # Template injection probes
        "{{7*7}}", "${7*7}", "#{7*7}", "<%= 7*7 %>",
        "{#7*7#}", "{{constructor.constructor('return 7*7')()}}",
        # Prototype pollution
        "__proto__[test]=polluted",
        "constructor[prototype][test]=polluted",
        # Parser differential
        "<!--", "-->", "]]>", "<?xml?>",
    ]

    # Hidden parameter names to discover
    HIDDEN_PARAMS = [
        "debug", "test", "admin", "internal", "verbose", "trace",
        "dev", "staging", "beta", "flag", "feature", "config",
        "secret", "hidden", "override", "bypass", "raw", "unsafe",
        "mode", "level", "role", "auth", "token", "key",
    ]

    def __init__(self, emitter=None, message_bus=None, shared_state=None):
        self.name = "ZeroDay"
        self.role = "Unknown Vulnerability Discovery Engine"
        self.emitter = emitter
        self.bus = message_bus
        self.state = shared_state
        self.probe = None  # Set by orchestrator
        self.is_active = False

    async def execute(self, target: str, scan_id: str,
                       context: Dict = None) -> List[Dict]:
        self.is_active = True
        context = context or {}
        findings: List[Dict] = []

        try:
            # Import probe from intelligence_nodes
            from backend.intelligence_nodes import HTTPProbe, ResponseAnalyzer
            self.probe = HTTPProbe(connect_timeout=5.0, read_timeout=10.0, max_rps=4.0)

            base = context.get("target_base", target)
            endpoints = context.get("discovered_endpoints", [target])[:5]

            if self.emitter:
                await self.emitter.emit("node_started", {
                    "node": self.name, "role": self.role, "target": target,
                }, scan_id)

            # Phase 1: Behavioral differential analysis
            findings.extend(await self._differential_analysis(
                base, endpoints, scan_id
            ))

            # Phase 2: Exploit primitive testing
            findings.extend(await self._primitive_testing(
                base, endpoints, scan_id
            ))

            # Phase 3: Hidden parameter discovery
            findings.extend(await self._parameter_discovery(
                base, endpoints, scan_id
            ))

            # Phase 4: Template injection probing
            findings.extend(await self._template_injection_probe(
                base, endpoints, scan_id
            ))

            if self.emitter:
                await self.emitter.emit("node_completed", {
                    "node": self.name,
                    "findings_count": len(findings),
                }, scan_id)

        except Exception as exc:
            logger.error(f"[{self.name}] Error: {exc}", exc_info=True)
        finally:
            self.is_active = False

        return findings

    async def _differential_analysis(self, base: str, endpoints: List[str],
                                       scan_id: str) -> List[Dict]:
        """Compare responses between normal and anomalous inputs to detect vulnerabilities."""
        findings = []

        for ep in endpoints[:3]:
            baseline = await self.probe.get(ep)
            if not baseline.ok:
                continue

            baseline_size = len(baseline.body)
            baseline_time = baseline.response_time

            # Test with each primitive
            for prim in random.sample(self.PRIMITIVES, min(12, len(self.PRIMITIVES))):
                await asyncio.sleep(0.03)
                probe_url = ep + ("&" if "?" in ep else "?") + f"input={prim}&data={prim}"
                result = await self.probe.get(probe_url)

                if not result.ok:
                    continue

                # Differential analysis
                anomalies = []

                # Server error on normally-safe input
                if result.is_server_error and not baseline.is_server_error:
                    anomalies.append(f"Server error {result.status_code} triggered")

                # Massive response size change (>200%)
                if baseline_size > 0:
                    delta = abs(len(result.body) - baseline_size) / baseline_size
                    if delta > 2.0:
                        anomalies.append(f"Response size anomaly: {delta:.0%} change")

                # Timing anomaly (>5x baseline)
                if baseline_time > 0 and result.response_time > baseline_time * 5:
                    anomalies.append(
                        f"Timing anomaly: {result.response_time:.1f}s vs {baseline_time:.1f}s baseline"
                    )

                # Template injection indicator: check for computed result "49"
                if "49" in result.body and "7*7" in prim:
                    anomalies.append("Template expression evaluated (49 found in response)")

                if anomalies:
                    if self.emitter:
                        await self.emitter.emit("anomaly_detected", {
                            "node": self.name,
                            "anomalies": anomalies,
                            "primitive": prim[:60],
                            "message": f"ZeroDay anomaly: {anomalies[0]} with primitive '{prim[:30]}'",
                        }, scan_id)

                    sev = "high" if "Template" in anomalies[0] or "Server error" in anomalies[0] else "medium"

                    finding = self._make_finding(
                        title=f"Anomalous Behavior: {anomalies[0]}",
                        description=(
                            f"Exploit primitive '{prim[:60]}' triggered anomalous server behavior "
                            f"at {ep.split('?')[0]}: {'; '.join(anomalies)}. "
                            f"This may indicate an unexploited vulnerability class."
                        ),
                        severity=sev,
                        endpoint=ep,
                        confidence=0.72,
                        cwe="CWE-754",
                        owasp="A04:2021 - Insecure Design",
                        category="Zero-Day Discovery",
                        exploit_payload=prim[:100],
                        evidence={"anomalies": anomalies, "primitive": prim[:60]},
                        remediation=(
                            "Investigate the anomalous behavior. Implement strict input validation "
                            "and error handling for all input parameters. Consider implementing "
                            "runtime application self-protection (RASP)."
                        ),
                    )
                    findings.append(finding)

                    if self.emitter:
                        self.emitter.add_finding(finding)
                        await self.emitter.emit("vulnerability_detected", finding, scan_id)
                        self._add_vuln_graph_node(
                            f"vuln-zday-{len(findings)}",
                            f"ZeroDay: {anomalies[0][:30]}",
                            sev, ep
                        )

        return findings

    async def _primitive_testing(self, base: str, endpoints: List[str],
                                   scan_id: str) -> List[Dict]:
        """Test exploit primitives for crash/error indicators."""
        findings = []

        # Test format string vulnerability
        for ep in endpoints[:2]:
            await asyncio.sleep(0.03)
            fmt_url = ep + ("&" if "?" in ep else "?") + "name=%s%s%s%s%s%n"
            result = await self.probe.get(fmt_url)

            if result.ok and result.is_server_error:
                finding = self._make_finding(
                    title="Potential Format String Vulnerability",
                    description=(
                        f"Format string specifiers (%s, %n) caused server error "
                        f"at {ep.split('?')[0]}. This is a strong indicator of "
                        f"a format string vulnerability that could lead to "
                        f"information disclosure or code execution."
                    ),
                    severity="critical",
                    endpoint=ep,
                    confidence=0.80,
                    cwe="CWE-134",
                    owasp="A03:2021 - Injection",
                    category="Zero-Day Discovery",
                    exploit_payload="%s%s%s%s%s%n",
                    remediation="Never pass user input directly to format string functions.",
                )
                findings.append(finding)
                if self.emitter:
                    self.emitter.add_finding(finding)
                    await self.emitter.emit("vulnerability_detected", finding, scan_id)

        return findings

    async def _parameter_discovery(self, base: str, endpoints: List[str],
                                     scan_id: str) -> List[Dict]:
        """Discover hidden/debug parameters that change application behavior."""
        findings = []

        for ep in endpoints[:2]:
            baseline = await self.probe.get(ep)
            if not baseline.ok:
                continue

            for param in random.sample(self.HIDDEN_PARAMS, min(10, len(self.HIDDEN_PARAMS))):
                await asyncio.sleep(0.02)
                test_url = ep + ("&" if "?" in ep else "?") + f"{param}=true"
                result = await self.probe.get(test_url)

                if not result.ok:
                    continue

                # Check if hidden param changes behavior
                if result.status_code != baseline.status_code:
                    if self.emitter:
                        await self.emitter.emit("endpoint_discovered", {
                            "node": self.name,
                            "message": f"Hidden parameter '{param}' changes response status at {ep.split('?')[0]}",
                        }, scan_id)

                    finding = self._make_finding(
                        title=f"Hidden Parameter Discovered: {param}",
                        description=(
                            f"Parameter '{param}=true' changes HTTP status from "
                            f"{baseline.status_code} to {result.status_code} at {ep.split('?')[0]}. "
                            f"Hidden debug/admin parameters may bypass security controls."
                        ),
                        severity="medium",
                        endpoint=ep,
                        confidence=0.70,
                        cwe="CWE-912",
                        owasp="A04:2021 - Insecure Design",
                        category="Zero-Day Discovery",
                        evidence={"param": param, "status_change": f"{baseline.status_code} → {result.status_code}"},
                        remediation="Remove debug/test parameters from production. Implement strict parameter whitelisting.",
                    )
                    findings.append(finding)
                    if self.emitter:
                        self.emitter.add_finding(finding)
                        await self.emitter.emit("vulnerability_detected", finding, scan_id)

                # Check for verbose error output
                body_len_delta = abs(len(result.body) - len(baseline.body))
                if body_len_delta > 500 and param in ("debug", "verbose", "trace"):
                    finding = self._make_finding(
                        title=f"Debug Parameter Enables Verbose Output: {param}",
                        description=(
                            f"Parameter '{param}=true' increases response body by {body_len_delta} bytes, "
                            f"indicating debug/verbose mode is accessible. This may expose "
                            f"internal application state, stack traces, or configuration."
                        ),
                        severity="high",
                        endpoint=ep,
                        confidence=0.78,
                        cwe="CWE-215",
                        owasp="A05:2021 - Security Misconfiguration",
                        category="Zero-Day Discovery",
                        remediation="Disable all debug modes in production. Use environment-based configuration.",
                    )
                    findings.append(finding)
                    if self.emitter:
                        self.emitter.add_finding(finding)
                        await self.emitter.emit("vulnerability_detected", finding, scan_id)
                    break

        return findings

    async def _template_injection_probe(self, base: str, endpoints: List[str],
                                          scan_id: str) -> List[Dict]:
        """Test for server-side template injection (SSTI)."""
        findings = []
        ssti_probes = [
            ("{{7*7}}", "49"),
            ("${7*7}", "49"),
            ("#{7*7}", "49"),
            ("<%= 7*7 %>", "49"),
        ]

        for ep in endpoints[:2]:
            for payload, expected in ssti_probes:
                await asyncio.sleep(0.03)
                test_url = ep + ("&" if "?" in ep else "?") + f"q={payload}&name={payload}"
                result = await self.probe.get(test_url)

                if result.ok and expected in result.body:
                    finding = self._make_finding(
                        title=f"Server-Side Template Injection (SSTI) Confirmed",
                        description=(
                            f"Template expression '{payload}' was evaluated server-side, "
                            f"producing '{expected}' in the response at {ep.split('?')[0]}. "
                            f"SSTI can lead to remote code execution on the server."
                        ),
                        severity="critical",
                        endpoint=ep,
                        confidence=0.95,
                        cwe="CWE-1336",
                        owasp="A03:2021 - Injection",
                        category="Zero-Day Discovery",
                        exploit_payload=payload,
                        matched_content=expected,
                        remediation=(
                            "Never pass user input into template rendering engines. "
                            "Use sandboxed template environments. "
                            "Implement strict input validation."
                        ),
                    )
                    findings.append(finding)
                    if self.emitter:
                        self.emitter.add_finding(finding)
                        await self.emitter.emit("vulnerability_detected", finding, scan_id)
                        self._add_vuln_graph_node(
                            "vuln-ssti", "SSTI — Remote Code Execution",
                            "critical", ep
                        )
                    break  # one confirmed SSTI per endpoint is enough

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
            "timestamp": __import__("datetime").datetime.now(
                __import__("datetime").timezone.utc
            ).isoformat(),
            "tags": [self.name, kwargs.get("category", "")],
            "line_number": 0,
        }

    def _add_vuln_graph_node(self, vuln_id, label, severity, endpoint):
        if self.emitter:
            self.emitter.add_graph_node({
                "id": vuln_id, "label": label,
                "type": "vulnerability", "risk": severity, "status": "compromised",
            })
            ep_id = "ep-" + endpoint.split("?")[0].replace("/", "-").strip("-")[:40]
            self.emitter.add_graph_edge({
                "source": ep_id, "target": vuln_id,
                "type": "exploit", "active": True,
            })
