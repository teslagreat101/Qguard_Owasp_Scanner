"use client";

import React from "react";
import {
  Shield,
  AlertTriangle,
  XCircle,
  UserCheck,
  Database,
  Eye,
  CheckSquare,
} from "lucide-react";

const SECTION_ICON_CLASS = "w-4 h-4 text-primary shrink-0 mt-0.5";
const SECTION_TITLE_CLASS = "text-[11px] font-black text-primary uppercase tracking-[0.15em] mb-3 flex items-center gap-2";
const SECTION_BODY_CLASS = "text-[11px] text-[#8BA89E] leading-relaxed space-y-2";
const DIVIDER_CLASS = "border-t border-primary/10 my-5";
const LIST_ITEM_CLASS = "flex items-start gap-2 text-[11px] text-[#8BA89E] leading-relaxed";
const BULLET_CLASS = "text-primary shrink-0 mt-0.5 font-black";

export function TermsContent() {
  return (
    <div className="space-y-0 text-left">

      {/* ── Section 1: Authorization & Scope ─────────────────── */}
      <div>
        <div className={SECTION_TITLE_CLASS}>
          <Shield className={SECTION_ICON_CLASS} />
          1. Authorization &amp; Scope
        </div>
        <div className={SECTION_BODY_CLASS}>
          <p>
            By accessing and using the <span className="text-white font-bold">Quantara Security Platform</span>, you
            explicitly confirm and warrant that:
          </p>
          <ul className="space-y-1.5 pl-1">
            {[
              "You are a duly authorized security professional, penetration tester, or authorized representative of the target organization.",
              "You possess written, documented authorization from all system and data owners for every target you intend to scan, test, or probe.",
              "All scanning activities will be conducted exclusively within the defined scope of your authorization — no scope expansion without updated written consent.",
              "You understand that unauthorized scanning of computer systems constitutes a criminal offence under the Computer Fraud and Abuse Act (CFAA), Computer Misuse Act 1990 (UK), EU Directive 2013/40/EU, and equivalent legislation in your jurisdiction.",
              "You acknowledge that evidence of unauthorized use will be reported to relevant law enforcement agencies.",
            ].map((item, i) => (
              <li key={i} className={LIST_ITEM_CLASS}>
                <span className={BULLET_CLASS}>▸</span>
                <span>{item}</span>
              </li>
            ))}
          </ul>
          <p className="mt-2 text-[10px] text-primary/60 border border-primary/10 rounded-lg px-3 py-2 bg-primary/5">
            ⚠ This platform is designed exclusively for authorized security testing. Any use outside your
            authorized scope will result in immediate account suspension and legal referral.
          </p>
        </div>
      </div>

      <div className={DIVIDER_CLASS} />

      {/* ── Section 2: Acceptable Use Policy ─────────────────── */}
      <div>
        <div className={SECTION_TITLE_CLASS}>
          <UserCheck className={SECTION_ICON_CLASS} />
          2. Acceptable Use Policy
        </div>
        <div className={SECTION_BODY_CLASS}>
          <p>Authorized use of this platform is limited to the following legitimate security activities:</p>
          <ul className="space-y-1.5 pl-1">
            {[
              "Penetration testing and vulnerability assessments on systems you own or have explicit written permission to test.",
              "Security audits conducted as part of a formal engagement with a defined Statement of Work (SOW) or Rules of Engagement (ROE).",
              "Bug bounty participation within the explicitly defined program scope and rules.",
              "Internal red team / blue team exercises on organizational infrastructure you are authorized to test.",
              "Security research in controlled, isolated lab environments using non-production systems.",
              "Compliance testing (PCI-DSS, HIPAA, SOC 2, ISO 27001) within your organization's own infrastructure.",
            ].map((item, i) => (
              <li key={i} className={LIST_ITEM_CLASS}>
                <span className={BULLET_CLASS}>▸</span>
                <span>{item}</span>
              </li>
            ))}
          </ul>
        </div>
      </div>

      <div className={DIVIDER_CLASS} />

      {/* ── Section 3: Prohibited Actions ─────────────────────── */}
      <div>
        <div className={SECTION_TITLE_CLASS}>
          <XCircle className="w-4 h-4 text-red-400 shrink-0 mt-0.5" />
          3. Prohibited Actions
        </div>
        <div className={SECTION_BODY_CLASS}>
          <p>
            The following actions are <span className="text-red-400 font-bold">strictly prohibited</span> and
            constitute grounds for immediate termination and legal action:
          </p>
          <ul className="space-y-1.5 pl-1">
            {[
              "Scanning, probing, or testing any system, network, or application without explicit written authorization from the owner.",
              "Using this platform to conduct Denial-of-Service (DoS) or Distributed Denial-of-Service (DDoS) attacks.",
              "Exploiting vulnerabilities to gain unauthorized access, exfiltrate data, or cause damage to target systems.",
              "Targeting critical infrastructure (power grids, healthcare systems, financial institutions) without highest-level government authorization.",
              "Conducting supply chain attacks or targeting third-party dependencies without explicit scope inclusion.",
              "Using discovered vulnerabilities for extortion, blackmail, unauthorized data monetization, or competitive espionage.",
              "Bypassing platform security controls, rate limiting, or audit logging mechanisms.",
              "Sharing platform access credentials or scan results with unauthorized third parties.",
              "Using this platform to test systems in jurisdictions where security testing is illegal without a government license.",
            ].map((item, i) => (
              <li key={i} className={LIST_ITEM_CLASS}>
                <span className="text-red-400 shrink-0 mt-0.5 font-black">✗</span>
                <span>{item}</span>
              </li>
            ))}
          </ul>
        </div>
      </div>

      <div className={DIVIDER_CLASS} />

      {/* ── Section 4: Responsibility & Liability ─────────────── */}
      <div>
        <div className={SECTION_TITLE_CLASS}>
          <AlertTriangle className="w-4 h-4 text-yellow-400 shrink-0 mt-0.5" />
          4. Responsibility &amp; Liability
        </div>
        <div className={SECTION_BODY_CLASS}>
          <p>You accept full legal and financial responsibility for:</p>
          <ul className="space-y-1.5 pl-1">
            {[
              "All scanning activities, exploit attempts, and security tests initiated through this platform using your account credentials.",
              "Any damage, data loss, service disruption, or security incidents resulting from your testing activities — even if unintentional.",
              "Ensuring your testing activities comply with all applicable local, national, and international laws and regulations.",
              "Maintaining secure custody of your authorization documents and making them available upon request.",
              "Promptly disclosing discovered vulnerabilities to the system owner through responsible disclosure channels.",
              "Any civil or criminal liability arising from misuse of this platform or testing outside your authorized scope.",
            ].map((item, i) => (
              <li key={i} className={LIST_ITEM_CLASS}>
                <span className={BULLET_CLASS}>▸</span>
                <span>{item}</span>
              </li>
            ))}
          </ul>
          <p className="mt-2 text-[10px] text-yellow-400/70 border border-yellow-400/15 rounded-lg px-3 py-2 bg-yellow-400/5">
            The platform operators disclaim all liability for damages resulting from unauthorized or negligent use.
            The platform is provided "as-is" for authorized security professionals only.
          </p>
        </div>
      </div>

      <div className={DIVIDER_CLASS} />

      {/* ── Section 5: Data Handling & Privacy ───────────────── */}
      <div>
        <div className={SECTION_TITLE_CLASS}>
          <Database className={SECTION_ICON_CLASS} />
          5. Data Handling &amp; Privacy
        </div>
        <div className={SECTION_BODY_CLASS}>
          <p>By using this platform, you acknowledge the following data handling practices:</p>
          <ul className="space-y-1.5 pl-1">
            {[
              "Scan results, findings, and vulnerability data are stored securely and encrypted at rest using AES-256.",
              "Scan data may be retained for up to 90 days for audit, support, and compliance purposes.",
              "No scan data is shared with third parties except as required by law enforcement requests.",
              "You are responsible for ensuring any sensitive data discovered during scans is handled in accordance with applicable data protection laws (GDPR, CCPA, HIPAA, etc.).",
              "Platform usage data (IP addresses, scan timestamps, API calls) is collected for security monitoring and compliance.",
              "Discovered credentials, PII, or sensitive data must be reported to system owners and handled per your organization's incident response policy.",
            ].map((item, i) => (
              <li key={i} className={LIST_ITEM_CLASS}>
                <span className={BULLET_CLASS}>▸</span>
                <span>{item}</span>
              </li>
            ))}
          </ul>
        </div>
      </div>

      <div className={DIVIDER_CLASS} />

      {/* ── Section 6: Audit Logging & Monitoring ────────────── */}
      <div>
        <div className={SECTION_TITLE_CLASS}>
          <Eye className={SECTION_ICON_CLASS} />
          6. Audit Logging &amp; Monitoring
        </div>
        <div className={SECTION_BODY_CLASS}>
          <p>
            You consent to comprehensive audit logging of all platform activity:
          </p>
          <ul className="space-y-1.5 pl-1">
            {[
              "All scan initiations, targets, modules used, and findings are logged with timestamps and your user identity.",
              "IP address, geolocation, device fingerprint, and session metadata are recorded for every session.",
              "This terms acceptance event is logged with timestamp, IP address, user agent, and agreement version hash.",
              "Audit logs are immutable and may be used as evidence in legal proceedings.",
              "Platform administrators may review usage logs for abuse detection, compliance, and security monitoring.",
              "You have the right to request a copy of your audit log data under applicable data protection regulations.",
            ].map((item, i) => (
              <li key={i} className={LIST_ITEM_CLASS}>
                <span className={BULLET_CLASS}>▸</span>
                <span>{item}</span>
              </li>
            ))}
          </ul>
        </div>
      </div>

      <div className={DIVIDER_CLASS} />

      {/* ── Section 7: Compliance Confirmation ───────────────── */}
      <div>
        <div className={SECTION_TITLE_CLASS}>
          <CheckSquare className={SECTION_ICON_CLASS} />
          7. Compliance &amp; Regulatory Confirmation
        </div>
        <div className={SECTION_BODY_CLASS}>
          <p>By proceeding, you confirm compliance with the following regulatory frameworks:</p>
          <div className="grid grid-cols-2 gap-2 mt-2">
            {[
              { framework: "OWASP", desc: "Testing within OWASP Top 10:2025 guidelines" },
              { framework: "NIST SP 800-115", desc: "Technical Guide to Information Security Testing" },
              { framework: "PTES", desc: "Penetration Testing Execution Standard" },
              { framework: "GDPR/CCPA", desc: "Data privacy compliance during testing" },
              { framework: "PCI-DSS", desc: "If testing cardholder data environments" },
              { framework: "HIPAA", desc: "If testing healthcare systems or data" },
            ].map((item, i) => (
              <div key={i} className="flex items-start gap-2 bg-primary/5 border border-primary/10 rounded-lg p-2">
                <span className="text-[10px] font-black text-primary shrink-0">{item.framework}</span>
                <span className="text-[10px] text-[#8BA89E]">{item.desc}</span>
              </div>
            ))}
          </div>
          <p className="mt-3 text-[10px] text-white/60 leading-relaxed">
            This agreement is governed by the laws of the jurisdiction in which the platform operators are incorporated.
            By accepting, you submit to the exclusive jurisdiction of the competent courts for any disputes arising
            from your use of this platform.
          </p>
        </div>
      </div>

    </div>
  );
}
