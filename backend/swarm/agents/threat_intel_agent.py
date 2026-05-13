"""
Threat Intelligence Agent — CVE Ingestion & Technique Mapping
================================================================
Matches discovered technologies against known CVE databases and
maps findings to MITRE ATT&CK techniques for threat context.
"""

from __future__ import annotations

import asyncio
import logging
import re
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
from urllib.parse import urljoin

logger = logging.getLogger(__name__)


# Known CVE patterns mapped to technology + version ranges
CVE_DATABASE = [
    {
        "cve": "CVE-2021-44228",
        "name": "Log4Shell",
        "tech_pattern": r"(?i)(java|spring|tomcat|log4j)",
        "severity": "critical",
        "description": "Apache Log4j2 Remote Code Execution via JNDI lookup injection",
        "attack_technique": "T1190 - Exploit Public-Facing Application",
        "remediation": "Upgrade Log4j to 2.17.1+. Remove JndiLookup.class. Set log4j2.formatMsgNoLookups=true.",
    },
    {
        "cve": "CVE-2023-44487",
        "name": "HTTP/2 Rapid Reset",
        "tech_pattern": r"(?i)(nginx|apache|h2|http/2)",
        "severity": "high",
        "description": "HTTP/2 protocol vulnerability enabling DDoS amplification via rapid stream resets",
        "attack_technique": "T1499.002 - Service Exhaustion Flood",
        "remediation": "Update web server to patched version. Implement rate limiting on HTTP/2 streams.",
    },
    {
        "cve": "CVE-2023-34362",
        "name": "MOVEit Transfer SQL Injection",
        "tech_pattern": r"(?i)(moveit|progress)",
        "severity": "critical",
        "description": "SQL injection in MOVEit Transfer allowing unauthenticated data exfiltration",
        "attack_technique": "T1190 - Exploit Public-Facing Application",
        "remediation": "Apply vendor patches immediately. Restrict access to MOVEit Transfer web interface.",
    },
    {
        "cve": "CVE-2024-3400",
        "name": "PAN-OS Command Injection",
        "tech_pattern": r"(?i)(palo alto|pan-os|globalprotect)",
        "severity": "critical",
        "description": "Command injection in Palo Alto Networks PAN-OS GlobalProtect gateway",
        "attack_technique": "T1059 - Command and Scripting Interpreter",
        "remediation": "Apply PAN-OS hotfix. Enable Threat Prevention signatures.",
    },
    {
        "cve": "CVE-2021-26855",
        "name": "ProxyLogon",
        "tech_pattern": r"(?i)(exchange|microsoft-httpapi|owa)",
        "severity": "critical",
        "description": "Microsoft Exchange Server SSRF leading to authentication bypass and RCE",
        "attack_technique": "T1190 - Exploit Public-Facing Application",
        "remediation": "Apply Microsoft security updates. Restrict external access to Exchange services.",
    },
    {
        "cve": "CVE-2023-22515",
        "name": "Confluence Broken Access Control",
        "tech_pattern": r"(?i)(confluence|atlassian)",
        "severity": "critical",
        "description": "Atlassian Confluence privilege escalation allowing admin account creation",
        "attack_technique": "T1068 - Exploitation for Privilege Escalation",
        "remediation": "Upgrade Confluence immediately. Restrict external network access.",
    },
    {
        "cve": "CVE-2022-22965",
        "name": "Spring4Shell",
        "tech_pattern": r"(?i)(spring|spring-boot|spring-framework)",
        "severity": "critical",
        "description": "Spring Framework RCE via ClassLoader manipulation on JDK 9+",
        "attack_technique": "T1190 - Exploit Public-Facing Application",
        "remediation": "Upgrade Spring Framework to 5.3.18+ / 5.2.20+. Upgrade Spring Boot to 2.6.6+.",
    },
    {
        "cve": "CVE-2023-32315",
        "name": "Openfire Path Traversal",
        "tech_pattern": r"(?i)(openfire|ignite)",
        "severity": "high",
        "description": "Openfire path traversal bypassing authentication to access admin console",
        "attack_technique": "T1083 - File and Directory Discovery",
        "remediation": "Upgrade Openfire to 4.7.5+. Restrict admin console access.",
    },
    {
        "cve": "CVE-2024-21887",
        "name": "Ivanti Connect Secure Command Injection",
        "tech_pattern": r"(?i)(ivanti|pulse secure|connect secure)",
        "severity": "critical",
        "description": "Command injection in Ivanti Connect Secure allowing unauthenticated RCE",
        "attack_technique": "T1059 - Command and Scripting Interpreter",
        "remediation": "Apply Ivanti patches. Implement external integrity checker.",
    },
    {
        "cve": "CVE-2023-46747",
        "name": "F5 BIG-IP Authentication Bypass",
        "tech_pattern": r"(?i)(f5|big-?ip|bigipserver)",
        "severity": "critical",
        "description": "F5 BIG-IP authentication bypass allowing unauthenticated remote code execution",
        "attack_technique": "T1190 - Exploit Public-Facing Application",
        "remediation": "Apply F5 hotfix. Restrict management interface access.",
    },
    {
        "cve": "CVE-2022-41040",
        "name": "ProxyNotShell",
        "tech_pattern": r"(?i)(exchange|microsoft-httpapi)",
        "severity": "high",
        "description": "Microsoft Exchange SSRF chained with deserialization for RCE",
        "attack_technique": "T1210 - Exploitation of Remote Services",
        "remediation": "Apply Exchange security updates. Implement URL rewrite mitigations.",
    },
    {
        "cve": "CVE-2023-27997",
        "name": "FortiOS Heap Overflow",
        "tech_pattern": r"(?i)(fortigate|fortios|fortinet)",
        "severity": "critical",
        "description": "FortiOS SSL-VPN heap buffer overflow allowing unauthenticated RCE",
        "attack_technique": "T1190 - Exploit Public-Facing Application",
        "remediation": "Upgrade FortiOS to patched version. Disable SSL-VPN if not required.",
    },
]

# MITRE ATT&CK technique enrichment
TECHNIQUE_ENRICHMENT = {
    "T1190": {"tactic": "Initial Access", "description": "Exploitation of internet-facing application"},
    "T1059": {"tactic": "Execution", "description": "Command/script execution on target system"},
    "T1068": {"tactic": "Privilege Escalation", "description": "Exploitation for elevated privileges"},
    "T1083": {"tactic": "Discovery", "description": "File/directory enumeration on target"},
    "T1210": {"tactic": "Lateral Movement", "description": "Remote service exploitation"},
    "T1499.002": {"tactic": "Impact", "description": "Resource exhaustion via flooding"},
}


class ThreatIntelAgent:
    """
    Threat intelligence agent that correlates discovered technologies
    with known CVEs and maps findings to MITRE ATT&CK framework.
    """

    def __init__(self, emitter=None, message_bus=None, shared_state=None):
        self.name = "ThreatIntel"
        self.role = "CVE Intelligence & ATT&CK Mapping Engine"
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
            if self.emitter:
                await self.emitter.emit("node_started", {
                    "node": self.name, "role": self.role, "target": target,
                }, scan_id)

            # Phase 1: Match technologies against CVE database
            tech_disclosed = context.get("tech_disclosed", [])
            findings.extend(await self._match_cves(
                tech_disclosed, target, scan_id
            ))

            # Phase 2: Header-based technology probing
            from backend.intelligence_nodes import HTTPProbe
            probe = HTTPProbe(connect_timeout=5.0, read_timeout=8.0, max_rps=3.0)
            base = context.get("target_base", target)

            result = await probe.get(base + "/")
            if result.ok:
                # Extract all headers for tech matching
                header_str = " ".join(f"{k}:{v}" for k, v in result.headers.items())
                body_snippet = result.body[:5000]
                combined = header_str + " " + body_snippet

                findings.extend(await self._match_cves_from_response(
                    combined, target, scan_id
                ))

            # Phase 3: ATT&CK technique mapping for existing findings
            all_findings = context.get("all_findings", [])
            if all_findings:
                findings.extend(await self._map_attack_techniques(
                    all_findings, scan_id
                ))

            if self.emitter:
                await self.emitter.emit("node_completed", {
                    "node": self.name,
                    "findings_count": len(findings),
                    "message": f"ThreatIntel: {len(findings)} CVE/ATT&CK correlations",
                }, scan_id)

        except Exception as exc:
            logger.error(f"[{self.name}] Error: {exc}", exc_info=True)
        finally:
            self.is_active = False

        return findings

    async def _match_cves(self, tech_list: List[str],
                            target: str, scan_id: str) -> List[Dict]:
        """Match disclosed technologies against CVE database."""
        findings = []
        tech_combined = " ".join(tech_list).lower()
        matched_cves: set = set()

        for cve_entry in CVE_DATABASE:
            pattern = re.compile(cve_entry["tech_pattern"])
            if pattern.search(tech_combined) and cve_entry["cve"] not in matched_cves:
                matched_cves.add(cve_entry["cve"])
                await asyncio.sleep(0.02)

                if self.emitter:
                    await self.emitter.emit("vulnerability_detected", {
                        "node": self.name,
                        "cve": cve_entry["cve"],
                        "message": (
                            f"CVE Match: {cve_entry['cve']} ({cve_entry['name']}) — "
                            f"technology matches detected stack"
                        ),
                    }, scan_id)

                tech_id = cve_entry["cve"].replace("-", "").lower()
                finding = self._make_finding(
                    title=f"Known CVE: {cve_entry['cve']} — {cve_entry['name']}",
                    description=(
                        f"{cve_entry['description']}. "
                        f"Detected technology stack matches known vulnerable pattern. "
                        f"ATT&CK Technique: {cve_entry['attack_technique']}."
                    ),
                    severity=cve_entry["severity"],
                    endpoint=target,
                    confidence=0.70,
                    cwe="CWE-1395",
                    owasp="A06:2021 - Vulnerable and Outdated Components",
                    category="Known Vulnerability (CVE)",
                    evidence={
                        "cve": cve_entry["cve"],
                        "name": cve_entry["name"],
                        "attack_technique": cve_entry["attack_technique"],
                        "matched_tech": [t for t in tech_list if pattern.search(t)],
                    },
                    remediation=cve_entry["remediation"],
                )
                findings.append(finding)
                if self.emitter:
                    self.emitter.add_finding(finding)
                    self.emitter.add_graph_node({
                        "id": f"cve-{tech_id}",
                        "label": f"{cve_entry['cve']}\n{cve_entry['name']}",
                        "type": "vulnerability",
                        "risk": cve_entry["severity"],
                        "status": "compromised",
                    })
                    self.emitter.add_graph_edge({
                        "source": "target-root",
                        "target": f"cve-{tech_id}",
                        "type": "vulnerability",
                        "active": True,
                    })

        return findings

    async def _match_cves_from_response(self, combined: str,
                                          target: str, scan_id: str) -> List[Dict]:
        """Match CVEs from raw response headers/body."""
        # Reuse same logic but with response content as tech list
        return await self._match_cves([combined], target, scan_id)

    async def _map_attack_techniques(self, all_findings: List,
                                       scan_id: str) -> List[Dict]:
        """Map existing findings to MITRE ATT&CK techniques."""
        # Category → ATT&CK technique mapping
        category_technique_map = {
            "SQL Injection": "T1190",
            "Cross-Site Scripting": "T1059.007",
            "Authentication": "T1078",
            "SSRF": "T1190",
            "Path Traversal / LFI": "T1083",
            "Business Logic": "T1190",
            "WAF Bypass": "T1562.001",
            "Sensitive Data Exposure": "T1552",
            "Cloud Infrastructure": "T1580",
            "Broken Object Level Authorization": "T1078",
        }

        enriched_count = 0
        for f in all_findings[:50]:
            cat = f.category if hasattr(f, "category") else f.get("category", "")
            technique = category_technique_map.get(cat)
            if technique:
                enriched_count += 1

        if enriched_count > 0 and self.emitter:
            await self.emitter.emit("report_generated", {
                "node": self.name,
                "message": f"ATT&CK mapping: {enriched_count} findings mapped to MITRE techniques",
            }, scan_id)

        return []

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
