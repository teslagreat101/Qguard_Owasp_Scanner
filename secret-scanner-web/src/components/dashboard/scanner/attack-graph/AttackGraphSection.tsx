"use client";

/**
 * Quantara Attack Path Intelligence Graph v5.0
 * Enterprise Canvas Animation Engine
 *
 * Animation systems:
 *  1. Directional attack-flow pulse particles along edges
 *  2. Progressive attack replay (play / pause / scrubber)
 *  3. Node security-state animations (SECURE→CRITICAL)
 *  4. Lateral movement ripple expansion
 *  5. Privilege-escalation energy beam
 *  6. Path-focus mode (dim unrelated nodes)
 *  7. Breach-impact shockwave event
 *  8. Autonomous graph-life system (heartbeat, idle pulses)
 *  9. AI-driven risk-scored attack paths
 * 10. GPU-style Canvas 2D + requestAnimationFrame loop
 * 11. Full interaction controls (play / pause / scrubber / filter / focus)
 * 12. Enterprise-scale visual fidelity
 */

import React, {
  useState, useEffect, useRef, useCallback, useMemo,
} from "react";
import {
  motion, AnimatePresence,
  useMotionValue, useSpring, useTransform,
} from "framer-motion";
import {
  Network, AlertTriangle, GitBranch, ArrowRight, ChevronDown, ChevronUp,
  Shield, Globe, Key, Zap, Server, Users, Target, Activity,
  Play, Pause, SkipBack, Radio, Cpu, Eye, EyeOff,
} from "lucide-react";
import { cn } from "@/lib/utils";

// ══════════════════════════════════════════════════════════════════════════════
// Types
// ══════════════════════════════════════════════════════════════════════════════

type NodeType =
  | "Asset" | "Endpoint" | "Vulnerability" | "Credential"
  | "Service" | "UserRole" | "Impact" | "Remediation";

type EdgeType =
  | "HAS_VULNERABILITY" | "EXPOSES" | "GRANTS_ACCESS"
  | "CONNECTED_TO" | "LEADS_TO" | "ESCALATES_TO";

type Severity = "critical" | "high" | "medium" | "low" | "info";

/** Node security state for animation system */
type NodeState =
  | "SECURE"       // soft breathing glow
  | "VULNERABLE"   // slow warning pulse
  | "EXPLOITED"    // sharp red flicker
  | "COMPROMISED"  // continuous energy emission
  | "CRITICAL";    // expanding shockwave ripple

interface GraphNode {
  id: string;
  type: NodeType;
  label: string;
  severity: Severity;
  metadata?: Record<string, string>;
}

interface GraphEdge {
  source: string;
  target: string;
  type: EdgeType;
}

interface AttackPath {
  nodes: Array<{ id: string; label: string; type: string; severity: string }>;
  hops: number;
  risk_level: string;
  path_type?: string;
}

interface BreachStep {
  step: number;
  phase: string;
  action: string;
  impact: string;
  severity: string;
  technique: string;
  time_estimate: string;
}

interface SimNode extends GraphNode {
  x: number; y: number;
  vx: number; vy: number;
  fixed?: boolean;
}

/** Edge particle travelling along an attack path */
interface Particle {
  edgeIndex: number;
  progress: number;   // 0–1 along the edge
  speed: number;
  color: string;
  alpha: number;
  size: number;
}

/** Expanding ripple emitted on compromise / breach */
interface Ripple {
  x: number; y: number;
  radius: number;
  maxRadius: number;
  color: string;
  alpha: number;
  createdAt: number;
  duration: number;
}

/** Vertical privilege-escalation energy beam */
interface EscBeam {
  x: number; y: number;
  height: number;
  alpha: number;
  createdAt: number;
  duration: number;
}

// ══════════════════════════════════════════════════════════════════════════════
// Visual constants — neon-green theme for UI chrome
// ══════════════════════════════════════════════════════════════════════════════

const NEON   = "#00FF88";
const NEON20 = "rgba(0,255,136,0.20)";
const NEON08 = "rgba(0,255,136,0.08)";
const NEON04 = "rgba(0,255,136,0.04)";
const BG     = "#060A08";

const NODE_PALETTE: Record<string, { fill: string; border: string; glow: string }> = {
  Asset:       { fill: "#00A3FF", border: "#0066CC", glow: "rgba(0,163,255,0.6)"   },
  Service:     { fill: "#14B8A6", border: "#0F766E", glow: "rgba(20,184,166,0.6)"  },
  Endpoint:    { fill: "#8B5CF6", border: "#6D28D9", glow: "rgba(139,92,246,0.6)"  },
  UserRole:    { fill: "#EC4899", border: "#BE185D", glow: "rgba(236,72,153,0.6)"  },
  Impact:      { fill: "#EF4444", border: "#B91C1C", glow: "rgba(239,68,68,0.7)"   },
  Remediation: { fill: "#00FF88", border: "#00CC66", glow: "rgba(0,255,136,0.6)"   },
  Credential:  { fill: "#F97316", border: "#C2410C", glow: "rgba(249,115,22,0.6)"  },
};

const VULN_PALETTE: Record<string, { fill: string; border: string; glow: string }> = {
  critical: { fill: "#FF1744", border: "#B71C1C", glow: "rgba(255,23,68,0.7)"   },
  high:     { fill: "#FF6D00", border: "#E65100", glow: "rgba(255,109,0,0.6)"   },
  medium:   { fill: "#FFD600", border: "#F9A825", glow: "rgba(255,214,0,0.6)"   },
  low:      { fill: "#69F0AE", border: "#00C853", glow: "rgba(105,240,174,0.5)" },
  info:     { fill: "#78909C", border: "#455A64", glow: "rgba(120,144,156,0.3)" },
};

const EDGE_PALETTE: Record<EdgeType, string> = {
  HAS_VULNERABILITY: "#FF1744",
  EXPOSES:           "#FF6D00",
  GRANTS_ACCESS:     "#8B5CF6",
  CONNECTED_TO:      "#00A3FF",
  LEADS_TO:          "#FFD600",
  ESCALATES_TO:      "#FF1744",
};

/** Particle color by risk level — yellow probe → orange exploit → red compromise */
const PARTICLE_COLOR: Record<string, string> = {
  HAS_VULNERABILITY: "#FF1744",
  EXPOSES:           "#FF6D00",
  GRANTS_ACCESS:     "#FFD600",
  CONNECTED_TO:      "#00FF88",
  LEADS_TO:          "#FF4444",
  ESCALATES_TO:      "#FF0000",
};

const NODE_RADIUS: Record<NodeType, number> = {
  Asset: 30, Impact: 26, Service: 22, Vulnerability: 20,
  Credential: 18, Endpoint: 16, UserRole: 18, Remediation: 16,
};

// ══════════════════════════════════════════════════════════════════════════════
// Demo graph data
// ══════════════════════════════════════════════════════════════════════════════

const DEMO_NODES: GraphNode[] = [
  { id: "asset-0",       type: "Asset",         label: "Target System",       severity: "info"     },
  { id: "svc-api",       type: "Service",        label: "REST API Gateway",    severity: "info"     },
  { id: "svc-auth",      type: "Service",        label: "Auth Service",        severity: "info"     },
  { id: "svc-db",        type: "Service",        label: "Database Cluster",    severity: "info"     },
  { id: "vuln-sqli",     type: "Vulnerability",  label: "SQL Injection",       severity: "critical" },
  { id: "vuln-secret",   type: "Vulnerability",  label: "Hardcoded Secret",    severity: "high"     },
  { id: "vuln-ssrf",     type: "Vulnerability",  label: "SSRF Vector",         severity: "high"     },
  { id: "vuln-xss",      type: "Vulnerability",  label: "Stored XSS",          severity: "medium"   },
  { id: "vuln-auth",     type: "Vulnerability",  label: "Auth Bypass",         severity: "high"     },
  { id: "ep-users",      type: "Endpoint",       label: "/api/users?id=",      severity: "info"     },
  { id: "ep-admin",      type: "Endpoint",       label: "/api/admin/cmd",      severity: "info"     },
  { id: "ep-internal",   type: "Endpoint",       label: "/internal/services",  severity: "info"     },
  { id: "cred-db",       type: "Credential",     label: "DB_PASSWORD exposed", severity: "critical" },
  { id: "cred-api",      type: "Credential",     label: "API_SECRET_KEY",      severity: "high"     },
  { id: "role-admin",    type: "UserRole",       label: "Admin Role",          severity: "high"     },
  { id: "impact-breach", type: "Impact",         label: "Data Breach",         severity: "critical" },
  { id: "rem-patch",     type: "Remediation",    label: "Patch Required",      severity: "info"     },
];

const DEMO_EDGES: GraphEdge[] = [
  { source: "asset-0",       target: "svc-api",       type: "CONNECTED_TO"      },
  { source: "asset-0",       target: "svc-auth",      type: "CONNECTED_TO"      },
  { source: "asset-0",       target: "svc-db",        type: "CONNECTED_TO"      },
  { source: "svc-api",       target: "vuln-sqli",     type: "HAS_VULNERABILITY" },
  { source: "svc-api",       target: "vuln-xss",      type: "HAS_VULNERABILITY" },
  { source: "svc-api",       target: "vuln-ssrf",     type: "HAS_VULNERABILITY" },
  { source: "svc-auth",      target: "vuln-secret",   type: "HAS_VULNERABILITY" },
  { source: "svc-auth",      target: "vuln-auth",     type: "HAS_VULNERABILITY" },
  { source: "vuln-sqli",     target: "ep-users",      type: "EXPOSES"           },
  { source: "vuln-ssrf",     target: "ep-internal",   type: "EXPOSES"           },
  { source: "vuln-auth",     target: "ep-admin",      type: "EXPOSES"           },
  { source: "vuln-secret",   target: "cred-db",       type: "GRANTS_ACCESS"     },
  { source: "vuln-auth",     target: "cred-api",      type: "GRANTS_ACCESS"     },
  { source: "cred-db",       target: "svc-db",        type: "GRANTS_ACCESS"     },
  { source: "vuln-auth",     target: "role-admin",    type: "GRANTS_ACCESS"     },
  { source: "vuln-ssrf",     target: "vuln-sqli",     type: "ESCALATES_TO"      },
  { source: "vuln-sqli",     target: "impact-breach", type: "LEADS_TO"          },
  { source: "cred-db",       target: "impact-breach", type: "LEADS_TO"          },
  { source: "role-admin",    target: "impact-breach", type: "LEADS_TO"          },
  { source: "impact-breach", target: "rem-patch",     type: "CONNECTED_TO"      },
];

const DEMO_PATHS: AttackPath[] = [
  {
    nodes: [
      { id: "asset-0",       label: "Target System",    type: "Asset",         severity: "info"     },
      { id: "svc-api",       label: "REST API Gateway", type: "Service",       severity: "info"     },
      { id: "vuln-ssrf",     label: "SSRF Vector",      type: "Vulnerability", severity: "high"     },
      { id: "vuln-sqli",     label: "SQL Injection",    type: "Vulnerability", severity: "critical" },
      { id: "impact-breach", label: "Data Breach",      type: "Impact",        severity: "critical" },
    ],
    hops: 4, risk_level: "critical", path_type: "Lateral Movement",
  },
  {
    nodes: [
      { id: "asset-0",       label: "Target System",    type: "Asset",         severity: "info"     },
      { id: "svc-auth",      label: "Auth Service",     type: "Service",       severity: "info"     },
      { id: "vuln-secret",   label: "Hardcoded Secret", type: "Vulnerability", severity: "high"     },
      { id: "cred-db",       label: "DB_PASSWORD",      type: "Credential",    severity: "critical" },
      { id: "impact-breach", label: "Data Breach",      type: "Impact",        severity: "critical" },
    ],
    hops: 4, risk_level: "critical", path_type: "Credential Theft",
  },
  {
    nodes: [
      { id: "asset-0",       label: "Target System",    type: "Asset",         severity: "info"     },
      { id: "svc-auth",      label: "Auth Service",     type: "Service",       severity: "info"     },
      { id: "vuln-auth",     label: "Auth Bypass",      type: "Vulnerability", severity: "high"     },
      { id: "role-admin",    label: "Admin Role",       type: "UserRole",      severity: "high"     },
      { id: "impact-breach", label: "Data Breach",      type: "Impact",        severity: "critical" },
    ],
    hops: 4, risk_level: "critical", path_type: "Privilege Escalation",
  },
];

const DEMO_BREACH: BreachStep[] = [
  { step: 1, phase: "Reconnaissance",   action: "Enumerate API endpoints and map internal network via SSRF",             impact: "Internal topology exposed",           severity: "high",     technique: "T1590 — Gather Victim Network Info",            time_estimate: "< 5 min"   },
  { step: 2, phase: "Initial Access",   action: "Exploit SQL injection on /api/users?id= for database access",          impact: "Unauthorized database read/write",     severity: "critical", technique: "T1190 — Exploit Public-Facing Application",     time_estimate: "5-10 min"  },
  { step: 3, phase: "Credential Access",action: "Extract DB_PASSWORD hardcoded in source repository",                   impact: "Full database credential compromise",  severity: "critical", technique: "T1552 — Unsecured Credentials",                 time_estimate: "1-3 min"   },
  { step: 4, phase: "Priv. Escalation", action: "Exploit auth bypass misconfiguration to obtain admin session token",   impact: "Admin panel access, config control",   severity: "high",     technique: "T1068 — Exploitation for Privilege Escalation", time_estimate: "10-20 min" },
  { step: 5, phase: "Exfiltration",     action: "Archive PII, session tokens, and secrets; exfiltrate via C2 channel", impact: "Full data breach · GDPR violation",    severity: "critical", technique: "T1041 — Exfiltration Over C2 Channel",          time_estimate: "30-90 min" },
];

// ══════════════════════════════════════════════════════════════════════════════
// Graph builder from live findings
// ══════════════════════════════════════════════════════════════════════════════

function buildGraphFromFindings(findings: any[]): {
  nodes: GraphNode[]; edges: GraphEdge[];
  paths: AttackPath[]; breach: BreachStep[];
} {
  if (!findings || findings.length === 0)
    return { nodes: DEMO_NODES, edges: DEMO_EDGES, paths: DEMO_PATHS, breach: DEMO_BREACH };

  const nodes: GraphNode[] = [], edges: GraphEdge[] = [], seen = new Set<string>();
  const addNode = (n: GraphNode) => { if (!seen.has(n.id)) { seen.add(n.id); nodes.push(n); } };
  const sevRank: Record<string, number> = { critical: 4, high: 3, medium: 2, low: 1, info: 0 };

  const assetId = "asset-root";
  addNode({ id: assetId, type: "Asset", label: "Target", severity: "info" });

  const modMap: Record<string, string> = {};
  for (const f of findings) {
    const mod = (f.module || f.module_name || "scanner") as string;
    const svcId = `svc-${mod}`;
    if (!modMap[mod]) {
      modMap[mod] = svcId;
      addNode({ id: svcId, type: "Service", label: f.module_name || mod, severity: "info" });
      edges.push({ source: assetId, target: svcId, type: "CONNECTED_TO" });
    }
  }

  const critHigh: Array<{ vulnId: string; f: any }> = [];
  for (const f of findings.slice(0, 24)) {
    const vulnId = `vuln-${f.id}`;
    const sev = (f.severity || "info") as Severity;
    const mod = (f.module || f.module_name || "scanner") as string;
    addNode({ id: vulnId, type: "Vulnerability", label: (f.title || "Unknown").slice(0, 32), severity: sev });
    edges.push({ source: modMap[mod] || assetId, target: vulnId, type: "HAS_VULNERABILITY" });
    if (f.file || f.endpoint) {
      const epId = `ep-${f.id}`;
      addNode({ id: epId, type: "Endpoint", label: (f.file || f.endpoint).slice(0, 32), severity: "info" });
      edges.push({ source: vulnId, target: epId, type: "EXPOSES" });
    }
    if (f.matched_content) {
      const credId = `cred-${f.id}`;
      addNode({ id: credId, type: "Credential", label: `[${mod}] secret`, severity: sev });
      edges.push({ source: vulnId, target: credId, type: "GRANTS_ACCESS" });
    }
    if ((sevRank[sev] || 0) >= 3) critHigh.push({ vulnId, f });
  }

  if (critHigh.length > 0) {
    const impactId = "impact-breach";
    addNode({ id: impactId, type: "Impact", label: "Data Breach Risk", severity: "critical" });
    for (const item of critHigh.slice(0, 4))
      edges.push({ source: item.vulnId, target: impactId, type: "LEADS_TO" });
    const remId = "rem-action";
    addNode({ id: remId, type: "Remediation", label: "Remediation Plan", severity: "info" });
    edges.push({ source: impactId, target: remId, type: "CONNECTED_TO" });
  }

  const paths: AttackPath[] = critHigh.slice(0, 3).map(item => {
    const chain: AttackPath["nodes"] = [
      { id: assetId, label: "Target", type: "Asset", severity: "info" },
      { id: modMap[item.f.module || "scanner"] || assetId, label: item.f.module_name || "Service", type: "Service", severity: "info" },
      { id: item.vulnId, label: (item.f.title || "Vulnerability").slice(0, 32), type: "Vulnerability", severity: item.f.severity },
    ];
    if (item.f.matched_content)
      chain.push({ id: `cred-${item.f.id}`, label: "Credential exposed", type: "Credential", severity: item.f.severity });
    chain.push({ id: "impact-breach", label: "Data Breach Risk", type: "Impact", severity: "critical" });
    return {
      nodes: chain, hops: chain.length - 1, risk_level: item.f.severity,
      path_type: item.f.matched_content ? "Credential Theft" : item.f.severity === "critical" ? "Direct Exploitation" : "Privilege Escalation",
    };
  });

  const sorted = [...findings].sort((a, b) => (sevRank[b.severity] || 0) - (sevRank[a.severity] || 0));
  const hasCred = findings.some(f => f.matched_content);
  const hasInj  = findings.some(f => (f.module || "").includes("injection"));
  const breach: BreachStep[] = [];
  let s = 1;
  if (sorted.length > 0) breach.push({ step: s++, phase: "Initial Access",    action: `Exploit "${(sorted[0].title || "vuln").slice(0, 40)}"`,        impact: "System foothold",                  severity: sorted[0].severity, technique: "T1190 — Exploit Public-Facing App",          time_estimate: "< 5 min"   });
  if (hasInj)            breach.push({ step: s++, phase: "Execution",          action: "Inject payload via vulnerable endpoint",                        impact: "Remote code / query execution",    severity: "critical",         technique: "T1059 — Command and Scripting Interpreter",  time_estimate: "5-15 min"  });
  if (hasCred)           breach.push({ step: s++, phase: "Credential Access",  action: "Extract exposed credentials / API keys from source",            impact: "Authentication bypass",            severity: "critical",         technique: "T1552 — Unsecured Credentials",             time_estimate: "1-5 min"   });
                         breach.push({ step: s++, phase: "Priv. Escalation",   action: `Leverage ${findings.filter(f => f.severity === "high").length} high-severity misconfigurations`, impact: "Admin access acquired", severity: "high", technique: "T1068 — Exploitation for Privilege Escalation", time_estimate: "10-30 min" });
                         breach.push({ step: s,   phase: "Exfiltration",       action: "Archive PII and secrets; exfiltrate via encrypted C2 channel",  impact: "Full data breach / ransomware",    severity: "critical",         technique: "T1041 — Exfiltration Over C2 Channel",      time_estimate: "30-90 min" });

  return { nodes, edges, paths, breach };
}

// ══════════════════════════════════════════════════════════════════════════════
// Assign node security states from graph data
// ══════════════════════════════════════════════════════════════════════════════

function assignNodeStates(nodes: GraphNode[]): Map<string, NodeState> {
  const map = new Map<string, NodeState>();
  for (const n of nodes) {
    if (n.type === "Impact")                           map.set(n.id, "COMPROMISED");
    else if (n.type === "Credential")                  map.set(n.id, "EXPLOITED");
    else if (n.type === "Vulnerability" && n.severity === "critical") map.set(n.id, "CRITICAL");
    else if (n.type === "Vulnerability" && n.severity === "high")     map.set(n.id, "VULNERABLE");
    else if (n.type === "Vulnerability")               map.set(n.id, "VULNERABLE");
    else                                               map.set(n.id, "SECURE");
  }
  return map;
}

// ══════════════════════════════════════════════════════════════════════════════
// Physics simulation
// ══════════════════════════════════════════════════════════════════════════════

function initSimNodes(nodes: GraphNode[], W: number, H: number): SimNode[] {
  const cx = W / 2, cy = H / 2;
  return nodes.map(n => ({
    ...n,
    x: n.type === "Asset" ? cx : cx + (Math.random() - 0.5) * 280,
    y: n.type === "Asset" ? cy : cy + (Math.random() - 0.5) * 240,
    vx: 0, vy: 0,
    fixed: n.type === "Asset",
  }));
}

function tickSimulation(sn: SimNode[], edges: GraphEdge[], W: number, H: number) {
  const REPULSION = 6500, SPRING = 0.022, REST = 145, GRAVITY = 0.012, DAMP = 0.88;
  const cx = W / 2, cy = H / 2;
  for (let i = 0; i < sn.length; i++) {
    for (let j = i + 1; j < sn.length; j++) {
      const dx = sn[j].x - sn[i].x, dy = sn[j].y - sn[i].y;
      const d = Math.sqrt(dx * dx + dy * dy) || 0.1;
      const f = REPULSION / (d * d), fx = (f * dx) / d, fy = (f * dy) / d;
      if (!sn[i].fixed) { sn[i].vx -= fx; sn[i].vy -= fy; }
      if (!sn[j].fixed) { sn[j].vx += fx; sn[j].vy += fy; }
    }
  }
  for (const e of edges) {
    const s = sn.find(n => n.id === e.source), t = sn.find(n => n.id === e.target);
    if (!s || !t) continue;
    const dx = t.x - s.x, dy = t.y - s.y;
    const d = Math.sqrt(dx * dx + dy * dy) || 0.1;
    const f = (d - REST) * SPRING, fx = (f * dx) / d, fy = (f * dy) / d;
    if (!s.fixed) { s.vx += fx; s.vy += fy; }
    if (!t.fixed) { t.vx -= fx; t.vy -= fy; }
  }
  for (const n of sn) {
    if (n.fixed) { n.x = cx; n.y = cy; continue; }
    n.vx += (cx - n.x) * GRAVITY; n.vy += (cy - n.y) * GRAVITY;
    n.vx *= DAMP; n.vy *= DAMP;
    n.x += n.vx; n.y += n.vy;
    n.x = Math.max(48, Math.min(W - 48, n.x));
    n.y = Math.max(48, Math.min(H - 48, n.y));
  }
}

// ══════════════════════════════════════════════════════════════════════════════
// Helpers
// ══════════════════════════════════════════════════════════════════════════════

function nodeColor(node: GraphNode) {
  if (node.type === "Vulnerability")
    return VULN_PALETTE[node.severity] ?? VULN_PALETTE.info;
  return NODE_PALETTE[node.type] ?? NODE_PALETTE.Service;
}

function severityColor(sev: string): string {
  switch (sev) {
    case "critical": return "#FF1744";
    case "high":     return "#FF6D00";
    case "medium":   return "#FFD600";
    case "low":      return "#69F0AE";
    default:         return "#78909C";
  }
}

function hexToRgb(hex: string): [number, number, number] {
  const r = parseInt(hex.slice(1, 3), 16);
  const g = parseInt(hex.slice(3, 5), 16);
  const b = parseInt(hex.slice(5, 7), 16);
  return [r, g, b];
}

// ══════════════════════════════════════════════════════════════════════════════
// Canvas draw functions
// ══════════════════════════════════════════════════════════════════════════════

function drawBackground(ctx: CanvasRenderingContext2D, w: number, h: number, t: number) {
  // Deep background
  ctx.fillStyle = BG;
  ctx.fillRect(0, 0, w, h);

  // Animated neon-green grid
  const GRID = 36;
  ctx.save();
  ctx.strokeStyle = NEON;
  ctx.lineWidth = 0.4;
  ctx.globalAlpha = 0.03 + 0.01 * Math.sin(t / 3000);
  for (let x = 0; x <= w; x += GRID) {
    ctx.beginPath(); ctx.moveTo(x, 0); ctx.lineTo(x, h); ctx.stroke();
  }
  for (let y = 0; y <= h; y += GRID) {
    ctx.beginPath(); ctx.moveTo(0, y); ctx.lineTo(w, y); ctx.stroke();
  }
  ctx.restore();

  // Scanning pulse — horizontal sweep bar
  const scanY = ((t / 4000) % 1) * h;
  const scanGrad = ctx.createLinearGradient(0, scanY - 40, 0, scanY + 40);
  scanGrad.addColorStop(0,   "rgba(0,255,136,0)");
  scanGrad.addColorStop(0.5, "rgba(0,255,136,0.025)");
  scanGrad.addColorStop(1,   "rgba(0,255,136,0)");
  ctx.fillStyle = scanGrad;
  ctx.fillRect(0, scanY - 40, w, 80);
}

function drawEdges(
  ctx: CanvasRenderingContext2D,
  edges: GraphEdge[],
  simNodes: SimNode[],
  highlightIds: Set<string>,
  focusMode: boolean,
  _t: number,
) {
  for (const edge of edges) {
    const s = simNodes.find(n => n.id === edge.source);
    const tgt = simNodes.find(n => n.id === edge.target);
    if (!s || !tgt) continue;

    const inPath = highlightIds.has(edge.source) && highlightIds.has(edge.target);
    const color = EDGE_PALETTE[edge.type] ?? "#888";
    const [r, g, b] = hexToRgb(color);

    let alpha = inPath ? 0.90 : focusMode ? 0.05 : 0.18;
    const width = inPath ? 2.0 : 0.8;

    ctx.save();
    ctx.strokeStyle = `rgba(${r},${g},${b},${alpha})`;
    ctx.lineWidth = width;

    // Dashed for certain types
    if (edge.type === "ESCALATES_TO" || edge.type === "HAS_VULNERABILITY") {
      ctx.setLineDash([5, 4]);
    } else {
      ctx.setLineDash([]);
    }

    ctx.beginPath();
    ctx.moveTo(s.x, s.y);
    ctx.lineTo(tgt.x, tgt.y);
    ctx.stroke();

    // Arrowhead
    if (inPath || !focusMode) {
      const dx = tgt.x - s.x, dy = tgt.y - s.y;
      const len = Math.sqrt(dx * dx + dy * dy) || 1;
      const ux = dx / len, uy = dy / len;
      const tgtR = NODE_RADIUS[tgt.type as NodeType] ?? 18;
      const ax = tgt.x - ux * (tgtR + 5);
      const ay = tgt.y - uy * (tgtR + 5);
      const head = 8;
      const px = -uy * head * 0.4, py = ux * head * 0.4;
      ctx.setLineDash([]);
      ctx.fillStyle = `rgba(${r},${g},${b},${alpha})`;
      ctx.beginPath();
      ctx.moveTo(ax, ay);
      ctx.lineTo(ax - ux * head + px, ay - uy * head + py);
      ctx.lineTo(ax - ux * head - px, ay - uy * head - py);
      ctx.closePath();
      ctx.fill();
    }

    ctx.restore();
  }
}

function drawParticles(
  ctx: CanvasRenderingContext2D,
  particles: Particle[],
  simNodes: SimNode[],
  edges: GraphEdge[],
) {
  for (const p of particles) {
    const edge = edges[p.edgeIndex];
    if (!edge) continue;
    const s = simNodes.find(n => n.id === edge.source);
    const t = simNodes.find(n => n.id === edge.target);
    if (!s || !t) continue;

    // Interpolated position
    const x = s.x + (t.x - s.x) * p.progress;
    const y = s.y + (t.y - s.y) * p.progress;

    // Motion-blur trail (3 ghost circles behind the particle)
    const [r, g, b] = hexToRgb(p.color);
    for (let i = 3; i >= 0; i--) {
      const trailP = Math.max(0, p.progress - i * 0.04);
      const tx = s.x + (t.x - s.x) * trailP;
      const ty = s.y + (t.y - s.y) * trailP;
      const trailAlpha = (p.alpha * (4 - i)) / (4 * 4);
      ctx.beginPath();
      ctx.arc(tx, ty, p.size * (1 - i * 0.2), 0, Math.PI * 2);
      ctx.fillStyle = `rgba(${r},${g},${b},${trailAlpha})`;
      ctx.fill();
    }

    // Main particle with glow
    ctx.save();
    ctx.shadowColor = p.color;
    ctx.shadowBlur = 12;
    ctx.beginPath();
    ctx.arc(x, y, p.size, 0, Math.PI * 2);
    ctx.fillStyle = `rgba(${r},${g},${b},${p.alpha})`;
    ctx.fill();
    ctx.restore();
  }
}

function drawNode(
  ctx: CanvasRenderingContext2D,
  node: SimNode,
  isSelected: boolean,
  isHighlighted: boolean,
  isFaded: boolean,
  state: NodeState,
  t: number,
) {
  const r = NODE_RADIUS[node.type] ?? 18;
  const color = nodeColor(node);
  const [fr, fg, fb] = hexToRgb(color.fill);

  const alpha = isFaded ? 0.15 : 1.0;
  ctx.save();
  ctx.globalAlpha = alpha;
  ctx.translate(node.x, node.y);

  // State-driven glow sizing
  let glowRadius = 4;
  let glowAlpha  = 0.4;

  switch (state) {
    case "SECURE": {
      // Gentle breathing glow
      glowRadius = 6 + 3 * Math.sin(t / 1800 + node.x);
      glowAlpha  = 0.25 + 0.10 * Math.sin(t / 1800 + node.x);
      break;
    }
    case "VULNERABLE": {
      // Slow orange pulse
      glowRadius = 8 + 6 * Math.abs(Math.sin(t / 900));
      glowAlpha  = 0.35 + 0.20 * Math.abs(Math.sin(t / 900));
      break;
    }
    case "EXPLOITED": {
      // Sharp red flicker
      const flicker = Math.random() > 0.85 ? 1.0 : 0.6;
      glowRadius = 10 * flicker;
      glowAlpha  = 0.55 * flicker;
      break;
    }
    case "COMPROMISED": {
      // Continuous energy emission — rotating halo
      glowRadius = 12 + 4 * Math.sin(t / 400);
      glowAlpha  = 0.50 + 0.20 * Math.sin(t / 400);
      break;
    }
    case "CRITICAL": {
      // Shockwave ring outside node
      const wave = (t / 1200) % 1;
      glowRadius = r + wave * 28;
      glowAlpha  = (1 - wave) * 0.5;
      // Outer shockwave ring
      ctx.beginPath();
      ctx.arc(0, 0, glowRadius, 0, Math.PI * 2);
      ctx.strokeStyle = color.fill;
      ctx.globalAlpha = glowAlpha * alpha;
      ctx.lineWidth = 2;
      ctx.stroke();
      ctx.globalAlpha = alpha;
      glowRadius = 14;
      glowAlpha  = 0.6;
      break;
    }
  }

  // Glow halo
  const glowGrad = ctx.createRadialGradient(0, 0, r * 0.5, 0, 0, r + glowRadius);
  glowGrad.addColorStop(0,   `rgba(${fr},${fg},${fb},${glowAlpha})`);
  glowGrad.addColorStop(1,   `rgba(${fr},${fg},${fb},0)`);
  ctx.fillStyle = glowGrad;
  ctx.beginPath();
  ctx.arc(0, 0, r + glowRadius, 0, Math.PI * 2);
  ctx.fill();

  // Node shape
  ctx.strokeStyle = (isSelected || isHighlighted) ? "#ffffff" : color.border;
  ctx.lineWidth   = (isSelected || isHighlighted) ? 2.5 : 1.5;
  ctx.fillStyle   = color.fill;

  switch (node.type) {
    case "Vulnerability": {
      const d = r * 1.35;
      ctx.beginPath();
      ctx.moveTo(0, -d); ctx.lineTo(d, 0); ctx.lineTo(0, d); ctx.lineTo(-d, 0);
      ctx.closePath(); ctx.fill(); ctx.stroke();
      break;
    }
    case "Endpoint": {
      ctx.beginPath();
      for (let i = 0; i < 6; i++) {
        const a = (Math.PI / 3) * i - Math.PI / 6;
        i === 0 ? ctx.moveTo(r * Math.cos(a), r * Math.sin(a))
                : ctx.lineTo(r * Math.cos(a), r * Math.sin(a));
      }
      ctx.closePath(); ctx.fill(); ctx.stroke();
      break;
    }
    case "Asset": {
      // Concentric rings
      ctx.beginPath(); ctx.arc(0, 0, r + 9, 0, Math.PI * 2);
      ctx.strokeStyle = color.fill; ctx.globalAlpha = 0.15 * alpha; ctx.lineWidth = 1.2; ctx.stroke();
      ctx.globalAlpha = alpha;
      ctx.beginPath(); ctx.arc(0, 0, r + 5, 0, Math.PI * 2);
      ctx.strokeStyle = color.fill; ctx.globalAlpha = 0.25 * alpha; ctx.lineWidth = 0.8; ctx.stroke();
      ctx.globalAlpha = alpha;
      ctx.beginPath(); ctx.arc(0, 0, r, 0, Math.PI * 2);
      ctx.fillStyle = color.fill; ctx.fill();
      ctx.strokeStyle = (isSelected || isHighlighted) ? "#fff" : color.border;
      ctx.lineWidth = (isSelected || isHighlighted) ? 2.5 : 1.5;
      ctx.stroke();
      break;
    }
    case "Impact": {
      const h = r * 1.4;
      ctx.beginPath();
      ctx.moveTo(0, -h); ctx.lineTo(h * 0.866, h * 0.5); ctx.lineTo(-h * 0.866, h * 0.5);
      ctx.closePath(); ctx.fill(); ctx.stroke();
      break;
    }
    case "Credential": {
      const s2 = r * 0.85;
      ctx.beginPath();
      ctx.roundRect(-s2, -s2, s2 * 2, s2 * 2, 4);
      ctx.fill(); ctx.stroke();
      break;
    }
    case "UserRole": {
      ctx.beginPath();
      for (let i = 0; i < 5; i++) {
        const a = (Math.PI * 2 / 5) * i - Math.PI / 2;
        i === 0 ? ctx.moveTo(r * Math.cos(a), r * Math.sin(a))
                : ctx.lineTo(r * Math.cos(a), r * Math.sin(a));
      }
      ctx.closePath(); ctx.fill(); ctx.stroke();
      break;
    }
    default: {
      ctx.beginPath(); ctx.arc(0, 0, r, 0, Math.PI * 2);
      ctx.fill(); ctx.stroke();
    }
  }

  // Node label
  const label = node.label.length > 14 ? node.label.slice(0, 13) + "…" : node.label;
  ctx.font = `${(isSelected || isHighlighted) ? "bold " : ""}9px 'Outfit', monospace`;
  ctx.textAlign = "center";
  ctx.fillStyle = (isSelected || isHighlighted) ? "#ffffff" : "#8899aa";
  ctx.fillText(label, 0, r + 13);

  ctx.restore();
}

function drawRipples(
  ctx: CanvasRenderingContext2D,
  ripples: Ripple[],
  nowMs: number,
) {
  for (const rip of ripples) {
    const age    = (nowMs - rip.createdAt) / rip.duration;
    if (age < 0 || age > 1) continue;  // guard: skip future-scheduled or expired ripples
    const radius = rip.maxRadius * age;
    const alpha  = rip.alpha * (1 - age);
    const [r, g, b] = hexToRgb(rip.color);
    ctx.save();
    ctx.beginPath();
    ctx.arc(rip.x, rip.y, radius, 0, Math.PI * 2);
    ctx.strokeStyle = `rgba(${r},${g},${b},${alpha})`;
    ctx.lineWidth = 2.5 * (1 - age * 0.7);
    ctx.stroke();
    // Inner glow fill
    ctx.beginPath();
    ctx.arc(rip.x, rip.y, radius * 0.6, 0, Math.PI * 2);
    ctx.fillStyle = `rgba(${r},${g},${b},${alpha * 0.08})`;
    ctx.fill();
    ctx.restore();
  }
}

function drawEscalationBeams(
  ctx: CanvasRenderingContext2D,
  beams: EscBeam[],
  nowMs: number,
) {
  for (const beam of beams) {
    const age = (nowMs - beam.createdAt) / beam.duration;
    if (age > 1) continue;
    const alpha  = beam.alpha * (1 - age);
    const height = beam.height * age;
    ctx.save();
    const grad = ctx.createLinearGradient(beam.x, beam.y, beam.x, beam.y - height);
    grad.addColorStop(0, `rgba(255,50,0,${alpha})`);
    grad.addColorStop(0.5, `rgba(255,150,0,${alpha * 0.6})`);
    grad.addColorStop(1, `rgba(255,200,0,0)`);
    ctx.strokeStyle = grad;
    ctx.lineWidth   = 3 * (1 - age * 0.6);
    ctx.shadowColor = "#FF6D00";
    ctx.shadowBlur  = 20;
    ctx.beginPath();
    ctx.moveTo(beam.x, beam.y);
    ctx.lineTo(beam.x, beam.y - height);
    ctx.stroke();
    // Side wisps
    ctx.lineWidth = 1;
    ctx.shadowBlur = 8;
    for (const offset of [-10, 10]) {
      ctx.beginPath();
      ctx.moveTo(beam.x + offset * (1 - age), beam.y);
      ctx.lineTo(beam.x + offset * 0.3, beam.y - height * 0.7);
      ctx.stroke();
    }
    ctx.restore();
  }
}

function drawReplayDot(
  ctx: CanvasRenderingContext2D,
  nodeX: number, nodeY: number, t: number,
) {
  const pulse = 0.7 + 0.3 * Math.sin(t / 120);
  ctx.save();
  ctx.shadowColor = "#FF1744";
  ctx.shadowBlur  = 20;
  ctx.beginPath();
  ctx.arc(nodeX, nodeY, 8 * pulse, 0, Math.PI * 2);
  ctx.fillStyle = "#FF1744";
  ctx.fill();
  // Outer ring
  ctx.beginPath();
  ctx.arc(nodeX, nodeY, 14 * pulse, 0, Math.PI * 2);
  ctx.strokeStyle = "rgba(255,23,68,0.35)";
  ctx.lineWidth = 2;
  ctx.stroke();
  ctx.restore();
}

// ══════════════════════════════════════════════════════════════════════════════
// Main Section Component
// ══════════════════════════════════════════════════════════════════════════════

interface AttackGraphSectionProps {
  findings: any[];
  scanId?: string;
  /** Enterprise attack chains from AttackChainCorrelator */
  attackChains?: any[];
}

type ActiveView = "graph" | "paths" | "breach";

export function AttackGraphSection({ findings, scanId: _scanId, attackChains = [] }: AttackGraphSectionProps) {
  const [isCollapsed,  setIsCollapsed]  = useState(false);
  const [activeView,   setActiveView]   = useState<ActiveView>("graph");
  const [,             setSimNodes]     = useState<SimNode[]>([]);
  const [selectedNode, setSelectedNode] = useState<SimNode | null>(null);
  const [highlightIds, setHighlightIds] = useState<Set<string>>(new Set());
  const [activePath,   setActivePath]   = useState(-1);
  const [focusMode,    setFocusMode]    = useState(false);
  const [isPlaying,    setIsPlaying]    = useState(false);
  const [replayStep,   setReplayStep]   = useState(-1);
  const [canvasSize,   setCanvasSize]   = useState({ w: 700, h: 520 });
  const [cardHovered,  setCardHovered]  = useState(false);

  // Card glassmorphism hover glow — mouse-tracked radial gradient
  const cardMouseX  = useMotionValue(0);
  const cardMouseY  = useMotionValue(0);
  const cardSpringX = useSpring(cardMouseX, { damping: 25, stiffness: 350 });
  const cardSpringY = useSpring(cardMouseY, { damping: 25, stiffness: 350 });
  const cardGlowBg  = useTransform(
    [cardSpringX, cardSpringY] as const,
    ([x, y]: readonly number[]) =>
      `radial-gradient(circle 420px at ${x}px ${y}px, rgba(0,255,136,0.12), transparent 80%)`,
  );

  const canvasRef    = useRef<HTMLCanvasElement>(null);
  const containerRef = useRef<HTMLDivElement>(null);
  const rafRef       = useRef<number>(0);
  const startMsRef   = useRef<number>(0);
  const simNodesRef  = useRef<SimNode[]>([]);
  const particlesRef = useRef<Particle[]>([]);
  const ripplesRef   = useRef<Ripple[]>([]);
  const beamsRef     = useRef<EscBeam[]>([]);
  const highlightRef = useRef<Set<string>>(new Set());
  const focusModeRef = useRef(false);
  const selectedRef  = useRef<string | null>(null);
  const replayRef    = useRef<{ path: AttackPath | null; step: number }>({ path: null, step: -1 });
  const edgesRef     = useRef<GraphEdge[]>([]);
  const nodeStatesRef = useRef<Map<string, NodeState>>(new Map());
  const playTimerRef = useRef<ReturnType<typeof setInterval> | null>(null);
  const dragNodeRef  = useRef<{ id: string; offsetX: number; offsetY: number } | null>(null);

  const { nodes, edges, paths, breach } = useMemo(
    () => buildGraphFromFindings(findings),
    [findings]
  );
  const isDemo = !findings || findings.length === 0;

  // Keep refs in sync
  useEffect(() => { edgesRef.current = edges; }, [edges]);
  useEffect(() => { highlightRef.current = highlightIds; }, [highlightIds]);
  useEffect(() => { focusModeRef.current = focusMode; }, [focusMode]);
  useEffect(() => { selectedRef.current = selectedNode?.id ?? null; }, [selectedNode]);

  // ── Measure canvas ──────────────────────────────────────────────────────────
  useEffect(() => {
    const measure = () => {
      if (containerRef.current) {
        const { width } = containerRef.current.getBoundingClientRect();
        setCanvasSize({ w: Math.max(380, width), h: 520 });
      }
    };
    measure();
    const ro = new ResizeObserver(measure);
    if (containerRef.current) ro.observe(containerRef.current);
    return () => ro.disconnect();
  }, []);

  // ── Build simulation + particles on graph change ────────────────────────────
  useEffect(() => {
    const sn = initSimNodes(nodes, canvasSize.w, canvasSize.h);
    for (let i = 0; i < 300; i++) tickSimulation(sn, edges, canvasSize.w, canvasSize.h);
    simNodesRef.current = sn;
    setSimNodes([...sn]);
    setSelectedNode(null); setHighlightIds(new Set()); setActivePath(-1);
    setReplayStep(-1); setIsPlaying(false); setFocusMode(false);
    replayRef.current = { path: null, step: -1 };

    // Node states
    nodeStatesRef.current = assignNodeStates(nodes);

    // Initialise particles — 2-4 per edge based on severity
    const parts: Particle[] = [];
    edges.forEach((edge, idx) => {
      const color = PARTICLE_COLOR[edge.type] ?? "#00FF88";
      const count = edge.type === "LEADS_TO" || edge.type === "ESCALATES_TO" ? 4
                  : edge.type === "HAS_VULNERABILITY" ? 3 : 2;
      for (let k = 0; k < count; k++) {
        parts.push({
          edgeIndex: idx,
          progress:  Math.random(),
          speed:     0.0012 + Math.random() * 0.0015,
          color,
          alpha: 0.55 + Math.random() * 0.35,
          size:  2.5 + Math.random() * 1.5,
        });
      }
    });
    particlesRef.current = parts;
    ripplesRef.current   = [];
    beamsRef.current     = [];

    // Autonomous idle ripples on CRITICAL / COMPROMISED nodes
    const now = performance.now();
    for (const node of sn) {
      const state = nodeStatesRef.current.get(node.id) ?? "SECURE";
      if (state === "CRITICAL" || state === "COMPROMISED") {
        ripplesRef.current.push({
          x: node.x, y: node.y,
          radius: 0, maxRadius: 60,
          color: nodeColor(node).fill,
          alpha: 0.45,
          createdAt: now + Math.random() * 2000,
          duration: 1800,
        });
      }
    }
  }, [nodes, edges, canvasSize]);

  // ── RAF render loop ─────────────────────────────────────────────────────────
  useEffect(() => {
    const canvas = canvasRef.current;
    if (!canvas) return;
    const ctx = canvas.getContext("2d");
    if (!ctx) return;
    startMsRef.current = performance.now();

    let lastRippleSpawn = 0;

    const draw = (nowMs: number) => {
      const t = nowMs - startMsRef.current;
      const { w, h } = canvasSize;

      canvas.width  = w * window.devicePixelRatio;
      canvas.height = h * window.devicePixelRatio;
      canvas.style.width  = `${w}px`;
      canvas.style.height = `${h}px`;
      ctx.scale(window.devicePixelRatio, window.devicePixelRatio);

      const sn     = simNodesRef.current;
      const edges  = edgesRef.current;
      const hi     = highlightRef.current;
      const focus  = focusModeRef.current;
      const selId  = selectedRef.current;
      const replay = replayRef.current;
      const states = nodeStatesRef.current;

      // 1. Background + grid + scan pulse
      drawBackground(ctx, w, h, t);

      // 2. Autonomous idle ripples — respawn periodically
      if (nowMs - lastRippleSpawn > 2500) {
        lastRippleSpawn = nowMs;
        const critNodes = sn.filter(n => {
          const s = states.get(n.id);
          return s === "CRITICAL" || s === "COMPROMISED";
        });
        if (critNodes.length > 0) {
          const n = critNodes[Math.floor(Math.random() * critNodes.length)];
          ripplesRef.current.push({
            x: n.x, y: n.y, radius: 0, maxRadius: 55,
            color: nodeColor(n).fill, alpha: 0.40,
            createdAt: nowMs, duration: 1600,
          });
        }
        // Prune dead ripples
        ripplesRef.current = ripplesRef.current.filter(
          r => nowMs - r.createdAt < r.duration
        );
      }

      // 3. Ripple effects
      drawRipples(ctx, ripplesRef.current, nowMs);

      // 4. Privilege-escalation beams
      beamsRef.current = beamsRef.current.filter(b => nowMs - b.createdAt < b.duration);
      drawEscalationBeams(ctx, beamsRef.current, nowMs);

      // 5. Edges
      drawEdges(ctx, edges, sn, hi, focus, t);

      // 6. Update + draw particles
      for (const p of particlesRef.current) {
        // Speed up particles on highlighted edges
        const edgeInPath = hi.has(edges[p.edgeIndex]?.source) &&
                           hi.has(edges[p.edgeIndex]?.target);
        p.progress += p.speed * (edgeInPath ? 2.5 : 1.0) * (focus && !edgeInPath ? 0.0 : 1.0);
        if (p.progress >= 1) p.progress -= 1;
      }
      drawParticles(ctx, particlesRef.current, sn, edges);

      // 7. Nodes
      for (const node of sn) {
        const isSel  = node.id === selId;
        const isHi   = hi.has(node.id);
        const isFade = focus && !isHi && !isSel;
        const state  = states.get(node.id) ?? "SECURE";
        drawNode(ctx, node, isSel, isHi, isFade, state, t);
      }

      // 8. Replay traversal indicator
      if (replay.path && replay.step >= 0) {
        const pathNode = replay.path.nodes[replay.step];
        if (pathNode) {
          const snode = sn.find(n => n.id === pathNode.id);
          if (snode) drawReplayDot(ctx, snode.x, snode.y, t);
        }
      }

      rafRef.current = requestAnimationFrame(draw);
    };

    rafRef.current = requestAnimationFrame(draw);
    return () => cancelAnimationFrame(rafRef.current);
  }, [canvasSize]);

  // ── Attack path selection ───────────────────────────────────────────────────
  const selectPath = useCallback((idx: number) => {
    const p = paths[idx];
    if (!p) return;
    setActivePath(idx);
    const ids = new Set(p.nodes.map(n => n.id));
    setHighlightIds(ids);
    setFocusMode(true);
    setReplayStep(-1);
    replayRef.current = { path: p, step: -1 };
    // Emit ripples on all path nodes
    const sn = simNodesRef.current;
    const now = performance.now();
    for (const pn of p.nodes) {
      const node = sn.find(n => n.id === pn.id);
      if (node) {
        ripplesRef.current.push({
          x: node.x, y: node.y, radius: 0, maxRadius: 70,
          color: severityColor(pn.severity), alpha: 0.55,
          createdAt: now, duration: 1400,
        });
      }
    }
    // Escalation beam for privilege-escalation paths
    if (p.path_type?.includes("Privilege")) {
      const lastNode = sn.find(n => n.id === p.nodes[p.nodes.length - 2]?.id);
      if (lastNode) {
        beamsRef.current.push({
          x: lastNode.x, y: lastNode.y, height: 140,
          alpha: 0.85, createdAt: now, duration: 2200,
        });
      }
    }
  }, [paths]);

  // ── Play / Pause replay ─────────────────────────────────────────────────────
  const startReplay = useCallback(() => {
    if (activePath < 0) { selectPath(0); }
    const p = paths[activePath < 0 ? 0 : activePath];
    if (!p) return;
    replayRef.current = { path: p, step: 0 };
    setReplayStep(0);
    setIsPlaying(true);
    if (playTimerRef.current) clearInterval(playTimerRef.current);
    let step = 0;
    playTimerRef.current = setInterval(() => {
      step++;
      if (step >= p.nodes.length) {
        clearInterval(playTimerRef.current!);
        setIsPlaying(false);
        // Breach impact flash on final node
        const sn = simNodesRef.current;
        const last = sn.find(n => n.id === p.nodes[p.nodes.length - 1]?.id);
        if (last) {
          const now = performance.now();
          // Big shockwave
          for (let k = 0; k < 3; k++) {
            ripplesRef.current.push({
              x: last.x, y: last.y, radius: 0, maxRadius: 90 + k * 30,
              color: "#FF1744", alpha: 0.70 - k * 0.18,
              createdAt: now + k * 200, duration: 1800,
            });
          }
          // Flash all neighbor nodes
          const allEdges = edgesRef.current;
          const neighbors = allEdges
            .filter(e => e.source === last.id || e.target === last.id)
            .flatMap(e => [e.source, e.target])
            .filter((id, i, arr) => arr.indexOf(id) === i && id !== last.id);
          for (const nid of neighbors) {
            const nn = sn.find(n => n.id === nid);
            if (nn) {
              ripplesRef.current.push({
                x: nn.x, y: nn.y, radius: 0, maxRadius: 40,
                color: "#FF4444", alpha: 0.45,
                createdAt: now + 300, duration: 900,
              });
            }
          }
        }
        return;
      }
      replayRef.current = { path: p, step };
      setReplayStep(step);
      // Emit ripple at each step
      const sn = simNodesRef.current;
      const cur = sn.find(n => n.id === p.nodes[step]?.id);
      if (cur) {
        const sev = p.nodes[step]?.severity;
        ripplesRef.current.push({
          x: cur.x, y: cur.y, radius: 0, maxRadius: 50,
          color: severityColor(sev), alpha: 0.5,
          createdAt: performance.now(), duration: 1000,
        });
      }
    }, 750);
  }, [activePath, paths, selectPath]);

  const pauseReplay = useCallback(() => {
    setIsPlaying(false);
    if (playTimerRef.current) clearInterval(playTimerRef.current);
  }, []);

  const resetReplay = useCallback(() => {
    pauseReplay();
    setReplayStep(-1);
    setHighlightIds(new Set());
    setFocusMode(false);
    setActivePath(-1);
    replayRef.current = { path: null, step: -1 };
  }, [pauseReplay]);

  useEffect(() => () => {
    cancelAnimationFrame(rafRef.current);
    if (playTimerRef.current) clearInterval(playTimerRef.current);
  }, []);

  // ── Canvas mouse events (click + drag) ─────────────────────────────────────
  const hitNode = useCallback((ex: number, ey: number): SimNode | null => {
    const canvas = canvasRef.current;
    if (!canvas) return null;
    const rect = canvas.getBoundingClientRect();
    const mx   = ex - rect.left, my = ey - rect.top;
    let closest: SimNode | null = null, bestD = 9999;
    for (const node of simNodesRef.current) {
      const r   = (NODE_RADIUS[node.type] ?? 18) + 8;
      const dx  = mx - node.x, dy = my - node.y;
      const d   = Math.sqrt(dx * dx + dy * dy);
      if (d < r && d < bestD) { bestD = d; closest = node; }
    }
    return closest;
  }, []);

  const handleCanvasMouseDown = useCallback((e: React.MouseEvent) => {
    const node = hitNode(e.clientX, e.clientY);
    if (node) {
      const canvas = canvasRef.current!;
      const rect   = canvas.getBoundingClientRect();
      dragNodeRef.current = {
        id: node.id,
        offsetX: e.clientX - rect.left - node.x,
        offsetY: e.clientY - rect.top  - node.y,
      };
      e.preventDefault();
    }
  }, [hitNode]);

  const handleCanvasClick = useCallback((e: React.MouseEvent) => {
    if (dragNodeRef.current) return;
    const node = hitNode(e.clientX, e.clientY);
    setSelectedNode(node);
    selectedRef.current = node?.id ?? null;
  }, [hitNode]);

  useEffect(() => {
    const onMove = (e: MouseEvent) => {
      const drag = dragNodeRef.current;
      if (!drag) return;
      const canvas = canvasRef.current;
      if (!canvas) return;
      const rect = canvas.getBoundingClientRect();
      const mx   = e.clientX - rect.left - drag.offsetX;
      const my   = e.clientY - rect.top  - drag.offsetY;
      simNodesRef.current = simNodesRef.current.map(n =>
        n.id === drag.id ? { ...n, x: mx, y: my, vx: 0, vy: 0 } : n
      );
    };
    const onUp = () => { dragNodeRef.current = null; };
    window.addEventListener("mousemove", onMove);
    window.addEventListener("mouseup",   onUp);
    return () => {
      window.removeEventListener("mousemove", onMove);
      window.removeEventListener("mouseup",   onUp);
    };
  }, []);

  // ── Legend data ─────────────────────────────────────────────────────────────
  const NODE_ICON: Record<NodeType, React.ElementType> = {
    Asset: Target, Service: Server, Endpoint: Globe,
    Vulnerability: AlertTriangle, Credential: Key,
    UserRole: Users, Impact: Zap, Remediation: Shield,
  };

  const LEGEND_ITEMS = [
    { type: "Asset"         as NodeType, color: NODE_PALETTE.Asset.fill        },
    { type: "Service"       as NodeType, color: NODE_PALETTE.Service.fill      },
    { type: "Vulnerability" as NodeType, color: VULN_PALETTE.critical.fill     },
    { type: "Endpoint"      as NodeType, color: NODE_PALETTE.Endpoint.fill     },
    { type: "Credential"    as NodeType, color: NODE_PALETTE.Credential.fill   },
    { type: "UserRole"      as NodeType, color: NODE_PALETTE.UserRole.fill     },
    { type: "Impact"        as NodeType, color: NODE_PALETTE.Impact.fill       },
    { type: "Remediation"   as NodeType, color: NODE_PALETTE.Remediation.fill  },
  ];

  const breachPct = isDemo
    ? 85
    : Math.min(95,
        findings.filter(f => f.severity === "critical").length * 25 +
        findings.filter(f => f.severity === "high").length * 10
      );

  // ══════════════════════════════════════════════════════════════════════════
  // Render
  // ══════════════════════════════════════════════════════════════════════════

  return (
    <div className="w-full mt-8 relative">
      <motion.div
        className={cn(
          "group relative rounded-2xl overflow-hidden border transition-all duration-500",
          cardHovered
            ? "border-[rgba(0,255,136,0.35)] shadow-[0_20px_50px_rgba(0,0,0,0.7),0_0_30px_rgba(0,255,136,0.08)]"
            : "border-[rgba(0,255,136,0.12)] shadow-[0_8px_32px_rgba(0,0,0,0.6)]",
        )}
        style={{
          background: cardHovered ? "rgba(12,18,15,0.85)" : "rgba(6,10,8,0.96)",
          backdropFilter: "blur(24px)",
          WebkitBackdropFilter: "blur(24px)",
        }}
        onMouseMove={(e) => {
          const { left, top } = e.currentTarget.getBoundingClientRect();
          cardMouseX.set(e.clientX - left);
          cardMouseY.set(e.clientY - top);
        }}
        onMouseEnter={() => setCardHovered(true)}
        onMouseLeave={() => setCardHovered(false)}
      >
        {/* Mouse-tracked radial glow */}
        <motion.div
          className="absolute inset-0 z-0 pointer-events-none opacity-0 group-hover:opacity-100 transition-opacity duration-700"
          style={{ background: cardGlowBg }}
        />

        {/* All card content sits above the glow layers */}
        <div className="relative z-[1]">

        {/* Header */}
        <div
          className="flex items-center justify-between p-5 border-b"
          style={{
            borderColor: "rgba(0,255,136,0.08)",
            background: `linear-gradient(90deg, ${NEON08} 0%, transparent 60%)`,
          }}
        >
          <div className="flex items-center gap-4">
            <div className="relative">
              <div
                className="w-10 h-10 rounded-xl flex items-center justify-center"
                style={{
                  background: "rgba(0,255,136,0.08)",
                  border: `1px solid rgba(0,255,136,0.20)`,
                }}
              >
                <Network className="w-5 h-5" style={{ color: NEON }} />
              </div>
              {!isDemo && (
                <div className="absolute -bottom-0.5 -right-0.5 w-3 h-3 rounded-full flex items-center justify-center" style={{ background: BG, border: `1px solid rgba(0,255,136,0.30)` }}>
                  <div className="w-1.5 h-1.5 rounded-full animate-pulse" style={{ background: NEON }} />
                </div>
              )}
            </div>

            <div>
              <h2 className="text-base font-bold text-foreground uppercase tracking-tight flex items-center gap-2 flex-wrap">
                Attack Path
                <span style={{ color: NEON }}>Intelligence</span>
                {isDemo && (
                  <span className="flex items-center gap-1 bg-[#FFD600]/10 text-[#FFD600] px-2 py-0.5 rounded border border-[#FFD600]/20 text-[9px] font-bold tracking-wider">
                    DEMO
                  </span>
                )}
              </h2>
              <p className="text-[10px] text-muted-foreground font-medium uppercase tracking-wider">
                {paths.length > 0
                  ? `${paths.length} attack path(s) · ${nodes.length} nodes · ${breachPct}% breach probability`
                  : "Attack simulation · privilege escalation · breach impact analysis"
                }
              </p>
            </div>
          </div>

          {/* Stats + collapse */}
          <div className="flex items-center gap-3">
            <div className="hidden lg:flex items-center gap-4 px-4 py-1.5 rounded-lg bg-background/40 border border-white/5">
              {[
                { label: "Nodes",    value: nodes.length.toString(), color: "#fff"     },
                { label: "Edges",    value: edges.length.toString(), color: "#94a3b8"  },
                { label: "Paths",    value: paths.length.toString(), color: NEON       },
                { label: "Breach",   value: `${breachPct}%`,         color: breachPct > 50 ? "#FF6D00" : "#94a3b8" },
              ].map((stat, i) => (
                <React.Fragment key={stat.label}>
                  {i > 0 && <div className="w-px h-6 bg-white/5" />}
                  <div className="text-center">
                    <p className="text-[8px] text-muted-foreground font-bold uppercase tracking-widest">{stat.label}</p>
                    <p className="text-sm font-bold" style={{ color: stat.color }}>{stat.value}</p>
                  </div>
                </React.Fragment>
              ))}
            </div>
            <button
              type="button"
              onClick={() => setIsCollapsed(v => !v)}
              className="p-2 rounded-lg bg-white/5 border border-white/5 text-muted-foreground hover:text-foreground hover:border-[rgba(0,255,136,0.30)] transition-colors"
            >
              {isCollapsed ? <ChevronDown className="w-4 h-4" /> : <ChevronUp className="w-4 h-4" />}
            </button>
          </div>
        </div>

        {/* ══════════════════════════════════════════════════════════════
            Body
        ══════════════════════════════════════════════════════════════ */}
        <AnimatePresence>
          {!isCollapsed && (
            <motion.div
              initial={{ height: 0, opacity: 0 }}
              animate={{ height: "auto", opacity: 1 }}
              exit={{ height: 0, opacity: 0 }}
              transition={{ duration: 0.3, ease: "easeInOut" }}
              className="overflow-hidden"
            >
              {/* Tabs */}
              <div className="flex gap-1.5 p-4 border-b bg-background/20" style={{ borderColor: "rgba(0,255,136,0.05)" }}>
                {(["graph", "paths", "breach"] as const).map(v => (
                  <button
                    type="button"
                    key={v}
                    onClick={() => setActiveView(v)}
                    className={cn(
                      "px-5 py-2 rounded-lg text-[10px] font-black uppercase tracking-[0.15em] transition-all duration-300 border",
                      activeView === v
                        ? "border-[rgba(0,255,136,0.25)] text-primary"
                        : "bg-white/[0.03] border-transparent text-muted-foreground hover:text-muted-foreground hover:bg-white/[0.06]"
                    )}
                    style={activeView === v ? { background: NEON08 } : {}}
                  >
                    {v === "graph"  && "⬡  Attack Graph"}
                    {v === "paths"  && "⇢  Attack Paths"}
                    {v === "breach" && "⚠  Breach Simulation"}
                  </button>
                ))}
              </div>

              {/* ══════════════════════════════════════════════════════════
                  VIEW: GRAPH
              ══════════════════════════════════════════════════════════ */}
              {activeView === "graph" && (
                <div className="flex flex-col lg:flex-row" style={{ minHeight: 520 }}>
                  {/* Canvas */}
                  <div
                    ref={containerRef}
                    className="flex-1 relative overflow-hidden"
                    style={{ minHeight: 520, background: BG }}
                  >
                    {/* Corner decorations — neon green */}
                    {["top-0 left-0 border-t border-l","top-0 right-0 border-t border-r","bottom-0 left-0 border-b border-l","bottom-0 right-0 border-b border-r"].map(cls => (
                      <div key={cls} className={`absolute w-8 h-8 ${cls} pointer-events-none`} style={{ borderColor: "rgba(0,255,136,0.20)" }} />
                    ))}

                    {/* GPU canvas */}
                    <canvas
                      ref={canvasRef}
                      style={{
                        width: canvasSize.w, height: canvasSize.h,
                        cursor: "crosshair", display: "block",
                      }}
                      onMouseDown={handleCanvasMouseDown}
                      onClick={handleCanvasClick}
                    />

                    {/* Replay controls overlay */}
                    <div className="absolute bottom-4 left-1/2 -translate-x-1/2 flex items-center gap-2 z-20">
                      <div
                        className="flex items-center gap-2 px-4 py-2 rounded-xl border backdrop-blur-xl"
                        style={{ background: "rgba(6,10,8,0.88)", borderColor: NEON20 }}
                      >
                        <button
                          type="button"
                          onClick={resetReplay}
                          className="p-1.5 rounded-lg text-muted-foreground hover:text-foreground transition-colors duration-200"
                          title="Reset"
                        >
                          <SkipBack className="w-3.5 h-3.5" />
                        </button>
                        <button
                          type="button"
                          onClick={isPlaying ? pauseReplay : startReplay}
                          className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg font-black text-[10px] uppercase tracking-wider transition-all duration-200"
                          style={{
                            background: isPlaying ? "rgba(239,68,68,0.15)" : NEON08,
                            color: isPlaying ? "#EF4444" : NEON,
                            border: `1px solid ${isPlaying ? "rgba(239,68,68,0.25)" : "rgba(0,255,136,0.25)"}`,
                          }}
                        >
                          {isPlaying
                            ? <><Pause className="w-3 h-3" />Pause</>
                            : <><Play  className="w-3 h-3" />Replay Attack</>
                          }
                        </button>
                        <button
                          type="button"
                          onClick={() => setFocusMode(v => !v)}
                          className="flex items-center gap-1 px-2.5 py-1.5 rounded-lg text-[10px] font-bold transition-all duration-200"
                          style={{
                            background: focusMode ? NEON08 : "transparent",
                            color: focusMode ? NEON : "#6b7280",
                            border: `1px solid ${focusMode ? "rgba(0,255,136,0.25)" : "transparent"}`,
                          }}
                          title="Focus mode"
                        >
                          {focusMode ? <Eye className="w-3 h-3" /> : <EyeOff className="w-3 h-3" />}
                          Focus
                        </button>
                        {replayStep >= 0 && paths[activePath < 0 ? 0 : activePath] && (
                          <span className="text-[9px] font-mono text-muted-foreground">
                            Step {replayStep + 1} / {paths[activePath < 0 ? 0 : activePath].nodes.length}
                          </span>
                        )}
                      </div>
                    </div>

                    {/* Status badges — top right */}
                    <div className="absolute top-4 right-4 flex flex-col gap-2 z-10">
                      <div className="flex items-center gap-1.5 px-2.5 py-1 rounded-lg text-[9px] font-black uppercase tracking-wider"
                        style={{ background: "rgba(6,10,8,0.80)", border: `1px solid ${NEON20}`, color: NEON }}>
                        <Radio className="w-3 h-3" />
                        LIVE ENGINE
                      </div>
                      <div className="flex items-center gap-1.5 px-2.5 py-1 rounded-lg text-[9px] font-black uppercase tracking-wider"
                        style={{ background: "rgba(6,10,8,0.80)", border: "1px solid rgba(255,109,0,0.22)", color: "#FF6D00" }}>
                        <Cpu className="w-3 h-3" />
                        RAF CANVAS
                      </div>
                    </div>

                    {/* Selected node tooltip */}
                    <AnimatePresence>
                      {selectedNode && (
                        <motion.div
                          key="tooltip"
                          initial={{ opacity: 0, y: 8, scale: 0.95 }}
                          animate={{ opacity: 1, y: 0,  scale: 1    }}
                          exit  ={{ opacity: 0, y: 8, scale: 0.95 }}
                          transition={{ duration: 0.18 }}
                          className="absolute bottom-16 left-4 w-72 rounded-xl p-4 z-30"
                          style={{
                            border: `1px solid rgba(0,255,136,0.15)`,
                            background: "rgba(6,10,8,0.95)",
                            backdropFilter: "blur(20px)",
                            boxShadow: "0 12px 40px rgba(0,0,0,0.85)",
                          }}
                        >
                          <div className="flex items-center justify-between mb-3">
                            <div className="flex items-center gap-2">
                              <div className="w-2.5 h-2.5 rounded-full" style={{ background: nodeColor(selectedNode).fill }} />
                              <span className="text-[9px] font-black uppercase tracking-widest text-muted-foreground">
                                {selectedNode.type}
                              </span>
                            </div>
                            <span
                              className="text-[9px] font-black uppercase px-2 py-0.5 rounded-full"
                              style={{
                                background: `${severityColor(selectedNode.severity)}18`,
                                color:       severityColor(selectedNode.severity),
                                border:      `1px solid ${severityColor(selectedNode.severity)}30`,
                              }}
                            >
                              {selectedNode.severity}
                            </span>
                          </div>
                          <p className="text-sm font-bold text-foreground mb-1">{selectedNode.label}</p>
                          <p className="text-[9px] text-muted-foreground font-mono mb-2">ID: {selectedNode.id}</p>
                          <div className="flex items-center gap-2">
                            <span className="text-[8px] font-black uppercase tracking-widest text-muted-foreground">State</span>
                            <span
                              className="text-[9px] font-black px-2 py-0.5 rounded-full"
                              style={{
                                background: NEON08, color: NEON,
                                border: `1px solid rgba(0,255,136,0.20)`,
                              }}
                            >
                              {nodeStatesRef.current.get(selectedNode.id) ?? "SECURE"}
                            </span>
                          </div>
                        </motion.div>
                      )}
                    </AnimatePresence>
                  </div>

                  {/* Right panel */}
                  <div
                    className="w-full lg:w-60 border-t lg:border-t-0 lg:border-l flex flex-col shrink-0"
                    style={{ borderColor: "rgba(0,255,136,0.08)", background: "#070B09" }}
                  >
                    {/* Node legend */}
                    <div className="p-4 border-b" style={{ borderColor: "rgba(255,255,255,0.04)" }}>
                      <p className="text-[9px] font-black text-muted-foreground uppercase tracking-widest mb-3">Node Types</p>
                      <div className="space-y-2">
                        {LEGEND_ITEMS.map(item => {
                          const Icon = NODE_ICON[item.type];
                          return (
                            <div key={item.type} className="flex items-center gap-2.5">
                              <Icon className="w-3 h-3 shrink-0" style={{ color: item.color }} />
                              <span className="text-[10px] text-muted-foreground font-medium">{item.type}</span>
                            </div>
                          );
                        })}
                      </div>
                    </div>

                    {/* Node state legend */}
                    <div className="p-4 border-b" style={{ borderColor: "rgba(255,255,255,0.04)" }}>
                      <p className="text-[9px] font-black text-muted-foreground uppercase tracking-widest mb-3">Security States</p>
                      <div className="space-y-1.5">
                        {([
                          ["SECURE",      "#00FF88", "breathing glow"],
                          ["VULNERABLE",  "#FFD600", "warning pulse"],
                          ["EXPLOITED",   "#FF6D00", "red flicker"],
                          ["COMPROMISED", "#FF1744", "energy emission"],
                          ["CRITICAL",    "#FF0000", "shockwave ripple"],
                        ] as const).map(([s, c, desc]) => (
                          <div key={s} className="flex items-center justify-between">
                            <div className="flex items-center gap-1.5">
                              <div className="w-2 h-2 rounded-full shrink-0" style={{ background: c, boxShadow: `0 0 4px ${c}` }} />
                              <span className="text-[9px] font-mono text-muted-foreground">{s}</span>
                            </div>
                            <span className="text-[8px] text-muted-foreground italic">{desc}</span>
                          </div>
                        ))}
                      </div>
                    </div>

                    {/* Edge types */}
                    <div className="p-4 border-b" style={{ borderColor: "rgba(255,255,255,0.04)" }}>
                      <p className="text-[9px] font-black text-muted-foreground uppercase tracking-widest mb-3">Edge Relationships</p>
                      <div className="space-y-1.5">
                        {(Object.entries(EDGE_PALETTE) as [EdgeType, string][]).map(([t, c]) => (
                          <div key={t} className="flex items-center gap-2">
                            <div className="w-6 h-0.5 shrink-0 rounded-full" style={{ background: c }} />
                            <span className="text-[9px] text-muted-foreground font-mono leading-tight">{t.replace(/_/g, " ")}</span>
                          </div>
                        ))}
                      </div>
                    </div>

                    {/* Highlight paths */}
                    <div className="p-4 flex-1 overflow-y-auto">
                      <p className="text-[9px] font-black text-muted-foreground uppercase tracking-widest mb-3">Select Attack Path</p>
                      <div className="space-y-2">
                        {paths.map((p, i) => (
                          <button
                            type="button"
                            key={i}
                            onClick={() => selectPath(i)}
                            className={cn(
                              "w-full text-left px-3 py-2.5 rounded-lg border text-[10px] font-bold transition-all duration-300",
                              activePath === i
                                ? "text-primary"
                                : "bg-white/[0.02] border-white/5 text-muted-foreground hover:text-muted-foreground hover:bg-white/[0.05]"
                            )}
                            style={activePath === i
                              ? { background: NEON08, borderColor: "rgba(0,255,136,0.25)" }
                              : {}}
                          >
                            <div className="flex items-center justify-between">
                              <span className="truncate mr-1">{p.path_type || `Path ${i + 1}`}</span>
                              <span className="font-mono text-[9px] shrink-0" style={{ color: severityColor(p.risk_level) }}>
                                {p.hops}h
                              </span>
                            </div>
                          </button>
                        ))}
                      </div>
                    </div>
                  </div>
                </div>
              )}

              {/* ══════════════════════════════════════════════════════════
                  VIEW: ATTACK PATHS
              ══════════════════════════════════════════════════════════ */}
              {activeView === "paths" && (
                <div className="p-6 space-y-4">
                  <div className="flex items-center gap-3 mb-2">
                    <Activity className="w-4 h-4" style={{ color: NEON }} />
                    <p className="text-[11px] text-muted-foreground font-bold uppercase tracking-widest">
                      {paths.length} computed attack chains — BFS shortest-path graph traversal
                      {attackChains.length > 0 && ` + ${attackChains.length} enterprise-correlated chains`}
                    </p>
                  </div>

                  {/* Enterprise Attack Chains from AttackChainCorrelator */}
                  {attackChains.length > 0 && (
                    <div className="mb-4 space-y-2">
                      <p className="text-[9px] font-black uppercase tracking-widest text-primary/60 mb-2">
                        ⛓ Enterprise Correlated Chains
                      </p>
                      {attackChains.map((chain: any, ci: number) => (
                        <div
                          key={chain.chain_id || ci}
                          className="rounded-xl border px-4 py-3 space-y-1"
                          style={{ borderColor: "rgba(255,68,68,0.25)", background: "rgba(255,68,68,0.04)" }}
                        >
                          <div className="flex items-center justify-between">
                            <span className="text-[11px] font-black text-foreground">{chain.name || chain.chain_id}</span>
                            <span className="text-[9px] font-black px-2 py-0.5 rounded-full uppercase"
                              style={{ background: "rgba(255,68,68,0.15)", color: "#FF4444", border: "1px solid rgba(255,68,68,0.3)" }}>
                              {chain.severity || "critical"}
                            </span>
                          </div>
                          <p className="text-[10px] text-muted-foreground">{chain.description}</p>
                          <p className="text-[9px] font-mono text-muted-foreground">OWASP: {chain.owasp} · {chain.finding_ids?.length || 0} findings</p>
                        </div>
                      ))}
                    </div>
                  )}

                  {paths.map((p, i) => (
                    <motion.div
                      key={i}
                      initial={{ opacity: 0, x: -16 }}
                      animate={{ opacity: 1, x: 0 }}
                      transition={{ delay: i * 0.08, duration: 0.3 }}
                      className="rounded-xl border overflow-hidden cursor-pointer"
                      style={{
                        borderColor: `${severityColor(p.risk_level)}22`,
                        background:  `${severityColor(p.risk_level)}05`,
                      }}
                      onClick={() => { setActiveView("graph"); selectPath(i); }}
                    >
                      <div className="flex items-center justify-between px-5 py-3 border-b border-white/5">
                        <div className="flex items-center gap-3">
                          <div className="w-6 h-6 rounded-full bg-background/50 border border-white/10 flex items-center justify-center text-[9px] font-black text-muted-foreground">
                            {i + 1}
                          </div>
                          <div>
                            <span className="text-sm font-black text-foreground">{p.path_type || `Attack Chain ${i + 1}`}</span>
                            <span className="text-[9px] text-muted-foreground ml-3 font-mono">{p.hops} hops</span>
                          </div>
                        </div>
                        <span
                          className="text-[10px] font-black px-3 py-1 rounded-full uppercase"
                          style={{
                            background: `${severityColor(p.risk_level)}14`,
                            color:       severityColor(p.risk_level),
                            border:      `1px solid ${severityColor(p.risk_level)}28`,
                          }}
                        >
                          {p.risk_level} risk
                        </span>
                      </div>

                      <div className="px-5 py-4">
                        <div className="flex items-center gap-1 flex-wrap">
                          {p.nodes.map((n, ni) => {
                            const c = n.type === "Vulnerability" ? severityColor(n.severity)
                                    : n.type === "Asset"         ? "#00A3FF"
                                    : n.type === "Impact"        ? "#EF4444"
                                    : n.type === "Credential"    ? "#F97316"
                                    : n.type === "Service"       ? "#14B8A6"
                                    : n.type === "UserRole"      ? "#EC4899"
                                    : "#78909C";
                            return (
                              <React.Fragment key={ni}>
                                <div className="px-2.5 py-1.5 rounded-lg border text-center"
                                  style={{ background: `${c}0E`, borderColor: `${c}28`, color: c }}>
                                  <div className="text-[8px] opacity-55 mb-0.5">{n.type}</div>
                                  <div className="text-[10px] font-bold max-w-[110px] truncate">{n.label}</div>
                                </div>
                                {ni < p.nodes.length - 1 && (
                                  <ArrowRight className="w-3.5 h-3.5 text-muted-foreground shrink-0" />
                                )}
                              </React.Fragment>
                            );
                          })}
                        </div>
                        <p className="text-[9px] text-muted-foreground mt-3 font-mono">
                          → Click to visualize on graph
                        </p>
                      </div>
                    </motion.div>
                  ))}
                </div>
              )}

              {/* ══════════════════════════════════════════════════════════
                  VIEW: BREACH SIMULATION
              ══════════════════════════════════════════════════════════ */}
              {activeView === "breach" && (
                <div className="p-6">
                  {/* Banner */}
                  <motion.div
                    initial={{ opacity: 0, y: -8 }}
                    animate={{ opacity: 1, y: 0 }}
                    className="mb-6 p-4 rounded-xl flex items-start gap-4"
                    style={{ background: NEON08, border: `1px solid rgba(0,255,136,0.15)` }}
                  >
                    <div
                      className="w-10 h-10 rounded-xl flex items-center justify-center shrink-0"
                      style={{ background: NEON08, border: `1px solid rgba(0,255,136,0.20)` }}
                    >
                      <AlertTriangle className="w-5 h-5" style={{ color: NEON }} />
                    </div>
                    <div>
                      <p className="text-sm font-black uppercase tracking-widest" style={{ color: NEON }}>
                        Simulated Breach Timeline
                      </p>
                      <p className="text-[11px] text-muted-foreground mt-1 leading-relaxed">
                        Based on {isDemo ? "demo" : `${findings.length} confirmed`} findings.
                        MITRE ATT&CK techniques mapped. Models real-world attacker progression from
                        initial access to data exfiltration.
                      </p>
                    </div>
                  </motion.div>

                  {/* Timeline */}
                  <div className="relative">
                    <div
                      className="absolute left-8 top-0 bottom-0 w-px pointer-events-none"
                      style={{ background: `linear-gradient(to bottom, rgba(0,255,136,0.40), rgba(255,109,0,0.20), transparent)` }}
                    />
                    <div className="space-y-0">
                      {breach.map((step, i) => (
                        <motion.div
                          key={step.step}
                          initial={{ opacity: 0, x: 24 }}
                          animate={{ opacity: 1, x: 0 }}
                          transition={{ delay: i * 0.07, duration: 0.3 }}
                          className="relative flex gap-5 pb-5"
                        >
                          {/* Step circle */}
                          <div
                            className="relative z-10 w-16 h-16 shrink-0 rounded-full flex items-center justify-center border"
                            style={{
                              background:  `${severityColor(step.severity)}0E`,
                              borderColor: `${severityColor(step.severity)}28`,
                            }}
                          >
                            <div className="text-center">
                              <div className="text-[8px] text-muted-foreground font-bold uppercase">Step</div>
                              <div className="text-base font-black" style={{ color: severityColor(step.severity) }}>
                                {step.step}
                              </div>
                            </div>
                          </div>

                          {/* Content card */}
                          <div className="flex-1 border rounded-xl p-4 transition-all duration-300"
                            style={{ background: "#090D0B", borderColor: "rgba(255,255,255,0.05)" }}>
                            <div className="flex items-start justify-between gap-3 mb-3">
                              <div>
                                <div
                                  className="text-[9px] font-black uppercase tracking-widest mb-1"
                                  style={{ color: severityColor(step.severity) }}
                                >
                                  Phase {step.step}: {step.phase}
                                </div>
                                <p className="text-sm font-bold text-foreground">{step.action}</p>
                              </div>
                              <div className="flex flex-col items-end gap-1 shrink-0">
                                <span
                                  className="text-[9px] font-black px-2 py-0.5 rounded-full uppercase"
                                  style={{
                                    background: `${severityColor(step.severity)}14`,
                                    color:       severityColor(step.severity),
                                    border:      `1px solid ${severityColor(step.severity)}28`,
                                  }}
                                >
                                  {step.severity}
                                </span>
                                <span className="text-[9px] text-muted-foreground font-mono">{step.time_estimate}</span>
                              </div>
                            </div>
                            <div className="grid grid-cols-1 md:grid-cols-2 gap-2">
                              <div className="px-3 py-2 rounded-lg bg-background/40 border border-white/5">
                                <p className="text-[8px] text-muted-foreground font-black uppercase tracking-widest mb-1">Impact</p>
                                <p className="text-[11px] text-muted-foreground font-medium">{step.impact}</p>
                              </div>
                              <div className="px-3 py-2 rounded-lg bg-background/40 border border-white/5">
                                <p className="text-[8px] text-muted-foreground font-black uppercase tracking-widest mb-1">MITRE Technique</p>
                                <p className="text-[10px] text-muted-foreground font-mono">{step.technique}</p>
                              </div>
                            </div>
                          </div>
                        </motion.div>
                      ))}
                    </div>
                  </div>

                  {/* Summary metrics */}
                  <div className="mt-2 p-5 rounded-xl bg-background/40 border border-white/5">
                    <div className="grid grid-cols-2 md:grid-cols-4 gap-4 text-center">
                      {[
                        { label: "Attack Steps",       value: breach.length.toString(),          color: "#fff"    },
                        { label: "Est. Dwell Time",    value: `~${breach.length * 15}m`,         color: "#FF6D00" },
                        { label: "MITRE Techniques",   value: breach.length.toString(),          color: NEON      },
                        { label: "Breach Probability", value: `${breachPct}%`,                   color: "#FF1744" },
                      ].map(m => (
                        <div key={m.label}>
                          <p className="text-[9px] text-muted-foreground font-black uppercase tracking-widest mb-1">{m.label}</p>
                          <p className="text-xl font-black" style={{ color: m.color }}>{m.value}</p>
                        </div>
                      ))}
                    </div>
                  </div>
                </div>
              )}
            </motion.div>
          )}
        </AnimatePresence>

        </div>{/* /relative z-[1] content wrapper */}
      </motion.div>
    </div>
  );
}
