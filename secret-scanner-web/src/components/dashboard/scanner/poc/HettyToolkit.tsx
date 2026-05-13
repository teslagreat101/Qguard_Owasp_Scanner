"use client";

import React, { useState, useCallback, useRef, useEffect, useMemo } from "react";
import {
  Send, Trash2, Clock, Shield, AlertTriangle,
  Copy, Check, ChevronDown, ChevronRight, Play,
  Globe, Zap, Eye, Code, FileText, Cookie, History,
  GitCompare, Search, X, RefreshCw,
  Terminal, ShieldAlert, ShieldCheck, Bug, ArrowRight,
  Brain, Crosshair, Network, Activity,
  Lock, FolderOpen, Bookmark,
  Timer, Gauge, Fingerprint,
} from "lucide-react";
import { cn } from "@/lib/utils";
import { toast } from "sonner";
import { AIAttackAssistant } from "@/components/dashboard/hetty/AIAttackAssistant";
import { AIPayloadGenerator } from "@/components/dashboard/hetty/AIPayloadGenerator";
import { AdaptiveFuzzer } from "@/components/dashboard/hetty/AdaptiveFuzzer";
import { VulnConfirmation } from "@/components/dashboard/hetty/VulnConfirmation";
import { ResponseIntelligence } from "@/components/dashboard/hetty/ResponseIntelligence";
import { AttackGraph } from "@/components/dashboard/hetty/AttackGraph";
import { AttackDashboard } from "@/components/dashboard/hetty/AttackDashboard";

const API_BASE = process.env.NEXT_PUBLIC_API_URL || "http://localhost:8000";

// ─── Types ───────────────────────────────────────────────────────────────────

type HttpMethod = "GET" | "POST" | "PUT" | "DELETE" | "PATCH" | "HEAD" | "OPTIONS";
type RequestTab = "headers" | "params" | "auth" | "cookies" | "body" | "raw" | "fuzzer";
type ResponseTab = "body" | "headers" | "cookies" | "raw" | "preview" | "timing" | "jwt";
type ToolkitPanel = "request" | "history" | "compare" | "ai-assistant" | "payloads" | "fuzzer" | "verify" | "intel" | "attack-graph" | "dashboard";
type AuthType = "none" | "bearer" | "basic" | "apikey" | "jwt";
type SidebarPanel = "collections" | "saved" | "graph";

interface KeyValue {
  key: string;
  value: string;
  enabled: boolean;
}

interface DetectedVuln {
  type: string;
  confidence: number;
  evidence: string;
  location: string;
}

interface DetectedSecret {
  type: string;
  value_masked: string;
  confidence: number;
}

interface HettyResponse {
  success: boolean;
  id: string;
  timestamp?: string;
  error?: string;
  blocked?: boolean;
  request?: {
    method: string;
    url: string;
    headers: Record<string, string>;
    cookies: Record<string, string>;
    body: string;
  };
  response?: {
    status_code: number;
    status_text: string;
    headers: Record<string, string>;
    cookies: Record<string, string>;
    body: string;
    body_size: number;
    content_type: string;
  };
  timing?: {
    total_ms: number;
    dns_ms: number;
    connect_ms: number;
    tls_ms: number;
    ttfb_ms: number;
  };
  security?: {
    vulnerabilities: DetectedVuln[];
    secrets: DetectedSecret[];
    tls_info: Record<string, any>;
    security_headers: Record<string, any>;
  };
}

interface CompareResult {
  original: { status: number; body_size: number; timing_ms: number };
  replayed: { status: number; body_size: number; timing_ms: number };
  diff: {
    status_changed: boolean;
    size_delta: number;
    timing_delta_ms: number;
    body_similarity: number;
  };
}

interface HistoryEntry {
  id: string;
  method: string;
  url: string;
  status_code: number;
  timing_ms: number;
  timestamp: string;
  vuln_count: number;
}

interface CollectionEndpoint {
  id: string;
  name: string;
  method: HttpMethod;
  url: string;
  headers?: Record<string, string>;
  body?: string;
  authType?: AuthType;
  authValue?: string;
}

interface ApiCollection {
  id: string;
  name: string;
  endpoints: CollectionEndpoint[];
  expanded: boolean;
}

interface JwtDecoded {
  header: Record<string, any>;
  payload: Record<string, any>;
  signature: string;
  raw: string;
  expired: boolean;
  expiresAt: string | null;
}

interface HettyToolkitProps {
  findingData?: any;
  finding?: any;
  scanId?: string;
}

// ─── Helpers ─────────────────────────────────────────────────────────────────

function extractQueryParams(rawUrl: string): KeyValue[] {
  try {
    const qIdx = rawUrl.indexOf("?");
    if (qIdx === -1) return [];
    const search = rawUrl.slice(qIdx + 1);
    const pairs = new URLSearchParams(search);
    const items: KeyValue[] = [];
    pairs.forEach((v, k) => items.push({ key: k, value: v, enabled: true }));
    return items;
  } catch {
    return [];
  }
}

function applyParamsToUrl(rawUrl: string, params: KeyValue[]): string {
  try {
    const base = rawUrl.split("?")[0];
    const enabled = params.filter(p => p.enabled && p.key.trim());
    if (enabled.length === 0) return base;
    const qs = enabled.map(p => `${encodeURIComponent(p.key)}=${encodeURIComponent(p.value)}`).join("&");
    return `${base}?${qs}`;
  } catch {
    return rawUrl;
  }
}

function parseRawRequest(raw: string): { method: HttpMethod; url: string; headers: KeyValue[]; cookies: KeyValue[]; body: string } | null {
  const lines = raw.split("\n");
  if (lines.length === 0) return null;
  const firstLine = lines[0].trim();
  const match = firstLine.match(/^(GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS)\s+(\S+)/i);
  if (!match) return null;

  const method = match[1].toUpperCase() as HttpMethod;
  const url = match[2];
  const headers: KeyValue[] = [];
  const cookies: KeyValue[] = [];
  let bodyStartIdx = -1;

  for (let i = 1; i < lines.length; i++) {
    const line = lines[i];
    if (line.trim() === "") {
      bodyStartIdx = i + 1;
      break;
    }
    const colonIdx = line.indexOf(":");
    if (colonIdx === -1) continue;
    const hKey = line.slice(0, colonIdx).trim();
    const hVal = line.slice(colonIdx + 1).trim();

    if (hKey.toLowerCase() === "cookie") {
      hVal.split(";").forEach(c => {
        const eqIdx = c.indexOf("=");
        if (eqIdx > 0) {
          cookies.push({ key: c.slice(0, eqIdx).trim(), value: c.slice(eqIdx + 1).trim(), enabled: true });
        }
      });
    } else {
      headers.push({ key: hKey, value: hVal, enabled: true });
    }
  }

  const body = bodyStartIdx > 0 ? lines.slice(bodyStartIdx).join("\n") : "";
  return { method, url, headers, cookies, body };
}

function buildRawRequest(method: string, url: string, headers: KeyValue[], cookies: KeyValue[], body: string): string {
  let raw = `${method} ${url || "/"} HTTP/1.1\n`;
  headers.filter(h => h.enabled && h.key.trim()).forEach(h => {
    raw += `${h.key}: ${h.value}\n`;
  });
  const enabledCookies = cookies.filter(c => c.enabled && c.key.trim());
  if (enabledCookies.length > 0) {
    raw += `Cookie: ${enabledCookies.map(c => `${c.key}=${c.value}`).join("; ")}\n`;
  }
  if (body) {
    raw += `\n${body}`;
  }
  return raw;
}

function decodeJwt(token: string): JwtDecoded | null {
  try {
    const parts = token.replace("Bearer ", "").trim().split(".");
    if (parts.length !== 3) return null;
    const header = JSON.parse(atob(parts[0].replace(/-/g, "+").replace(/_/g, "/")));
    const payload = JSON.parse(atob(parts[1].replace(/-/g, "+").replace(/_/g, "/")));
    const exp = payload.exp ? new Date(payload.exp * 1000) : null;
    return {
      header,
      payload,
      signature: parts[2],
      raw: token,
      expired: exp ? exp.getTime() < Date.now() : false,
      expiresAt: exp ? exp.toISOString() : null,
    };
  } catch {
    return null;
  }
}

function extractJwtFromResponse(headers: Record<string, string>, body: string): string | null {
  // Check authorization header
  for (const [k, v] of Object.entries(headers)) {
    if (k.toLowerCase() === "authorization" && v.includes("Bearer ")) {
      return v.replace("Bearer ", "").trim();
    }
  }
  // Check set-cookie for JWT-like tokens
  for (const [k, v] of Object.entries(headers)) {
    if (k.toLowerCase() === "set-cookie") {
      const tokenMatch = v.match(/eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+/);
      if (tokenMatch) return tokenMatch[0];
    }
  }
  // Check body for JWT pattern
  const bodyMatch = body.match(/eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+/);
  if (bodyMatch) return bodyMatch[0];
  return null;
}

const METHOD_COLORS: Record<HttpMethod, string> = {
  GET: "text-green-400",
  POST: "text-blue-400",
  PUT: "text-yellow-400",
  DELETE: "text-red-400",
  PATCH: "text-purple-400",
  HEAD: "text-muted-foreground",
  OPTIONS: "text-cyan-400",
};

const METHOD_BG: Record<HttpMethod, string> = {
  GET: "bg-green-400/10 border-green-400/20",
  POST: "bg-blue-400/10 border-blue-400/20",
  PUT: "bg-yellow-400/10 border-yellow-400/20",
  DELETE: "bg-red-400/10 border-red-400/20",
  PATCH: "bg-purple-400/10 border-purple-400/20",
  HEAD: "bg-muted/10 border-border/20",
  OPTIONS: "bg-cyan-400/10 border-cyan-400/20",
};

const defaultKv = (): KeyValue => ({ key: "", value: "", enabled: true });

const DEFAULT_COLLECTIONS: ApiCollection[] = [
  {
    id: "auth", name: "Auth APIs", expanded: true,
    endpoints: [
      { id: "auth-login", name: "Login", method: "POST", url: "/login", body: '{"username": "", "password": ""}' },
      { id: "auth-register", name: "Register", method: "POST", url: "/register", body: '{"username": "", "email": "", "password": ""}' },
      { id: "auth-logout", name: "Logout", method: "POST", url: "/logout" },
      { id: "auth-refresh", name: "Refresh Token", method: "POST", url: "/auth/refresh" },
    ],
  },
  {
    id: "user", name: "User APIs", expanded: false,
    endpoints: [
      { id: "user-profile", name: "Get Profile", method: "GET", url: "/api/user/profile" },
      { id: "user-update", name: "Update Profile", method: "PUT", url: "/api/user/profile", body: '{"name": "", "email": ""}' },
      { id: "user-list", name: "List Users", method: "GET", url: "/api/users" },
      { id: "user-delete", name: "Delete User", method: "DELETE", url: "/api/user/{id}" },
    ],
  },
  {
    id: "admin", name: "Admin APIs", expanded: false,
    endpoints: [
      { id: "admin-users", name: "Admin Users", method: "GET", url: "/api/v1/admin/users" },
      { id: "admin-debug", name: "Debug Info", method: "GET", url: "/api/debug" },
      { id: "admin-config", name: "Config", method: "GET", url: "/api/v1/admin/config" },
    ],
  },
  {
    id: "payment", name: "Payment APIs", expanded: false,
    endpoints: [
      { id: "pay-create", name: "Create Payment", method: "POST", url: "/api/payment/create", body: '{"amount": 0, "currency": "USD"}' },
      { id: "pay-history", name: "Payment History", method: "GET", url: "/api/payment/history" },
      { id: "pay-refund", name: "Refund", method: "POST", url: "/api/payment/refund", body: '{"transaction_id": ""}' },
    ],
  },
];

// ─── Sub-components ──────────────────────────────────────────────────────────

function StatusBadge({ code }: { code: number }) {
  const color = code >= 500 ? "text-red-400 bg-red-500/10 border-red-500/20"
    : code >= 400 ? "text-orange-400 bg-orange-500/10 border-orange-500/20"
      : code >= 300 ? "text-yellow-400 bg-yellow-500/10 border-yellow-500/20"
        : "text-green-400 bg-green-500/10 border-green-500/20";
  return (
    <span className={cn("px-2.5 py-0.5 rounded-md border text-xs font-black", color)}>
      {code}
    </span>
  );
}

function MethodBadge({ method }: { method: string }) {
  return (
    <span className={cn("text-[10px] font-black uppercase", METHOD_COLORS[method as HttpMethod] || "text-muted-foreground")}>
      {method}
    </span>
  );
}

function MethodBadgeSmall({ method }: { method: string }) {
  return (
    <span className={cn(
      "text-[7px] font-black uppercase tracking-widest px-1.5 py-0.5 rounded border shrink-0",
      METHOD_COLORS[method as HttpMethod] || "text-muted-foreground",
      METHOD_BG[method as HttpMethod] || "bg-muted/10 border-border/20",
    )}>
      {method}
    </span>
  );
}

function VulnAlert({ vuln }: { vuln: DetectedVuln }) {
  const Icon = vuln.confidence > 0.7 ? ShieldAlert : AlertTriangle;
  return (
    <div className="flex items-start gap-3 p-3 bg-red-500/5 border border-red-500/15 rounded-xl">
      <Icon className="w-4 h-4 text-red-400 shrink-0 mt-0.5" />
      <div className="min-w-0 flex-1">
        <div className="flex items-center gap-2 mb-1">
          <span className="text-[10px] font-black text-red-400 uppercase tracking-widest">{vuln.type}</span>
          <span className="text-[9px] font-bold text-red-400/60">{Math.round(vuln.confidence * 100)}%</span>
        </div>
        <p className="text-[10px] text-muted-foreground leading-relaxed break-all">{vuln.evidence.slice(0, 200)}</p>
      </div>
    </div>
  );
}

function KeyValueEditor({ items, onChange, placeholder }: { items: KeyValue[]; onChange: (items: KeyValue[]) => void; placeholder?: string }) {
  const updateItem = (idx: number, field: keyof KeyValue, val: string | boolean) => {
    const next = [...items];
    (next[idx] as any)[field] = val;
    onChange(next);
  };
  const removeItem = (idx: number) => {
    const next = items.filter((_, i) => i !== idx);
    onChange(next.length === 0 ? [defaultKv()] : next);
  };
  const addItem = () => onChange([...items, defaultKv()]);

  return (
    <div className="space-y-1.5">
      {items.map((item, idx) => (
        <div key={idx} className="flex items-center gap-1.5">
          <button
            type="button"
            onClick={() => updateItem(idx, "enabled", !item.enabled)}
            className={cn("w-5 h-5 rounded border flex items-center justify-center shrink-0 transition-colors",
              item.enabled ? "bg-primary/10 border-primary/30" : "bg-muted/20 border-border"
            )}
          >
            {item.enabled && <Check className="w-3 h-3 text-primary" />}
          </button>
          <input
            className="flex-1 bg-muted/40 border border-border rounded-lg px-2.5 py-1.5 text-[11px] font-mono text-foreground placeholder:text-muted-foreground/50 focus:border-primary/30 focus:outline-none transition-colors"
            placeholder={placeholder || "Key"}
            value={item.key}
            onChange={e => updateItem(idx, "key", e.target.value)}
          />
          <input
            className="flex-1 bg-muted/40 border border-border rounded-lg px-2.5 py-1.5 text-[11px] font-mono text-foreground placeholder:text-muted-foreground/50 focus:border-primary/30 focus:outline-none transition-colors"
            placeholder="Value"
            value={item.value}
            onChange={e => updateItem(idx, "value", e.target.value)}
          />
          <button type="button" onClick={() => removeItem(idx)} title="Remove item" aria-label="Remove item" className="p-1 text-muted-foreground hover:text-red-400 transition-colors">
            <X className="w-3.5 h-3.5" />
          </button>
        </div>
      ))}
      <button
        type="button"
        onClick={addItem}
        className="text-[9px] font-bold text-muted-foreground hover:text-primary uppercase tracking-widest transition-colors"
      >
        + Add Item
      </button>
    </div>
  );
}

// ─── JWT Decoder Panel ───────────────────────────────────────────────────────

function JwtDecoderPanel({ token }: { token: string | null }) {
  const [manualToken, setManualToken] = useState("");
  const activeToken = token || manualToken;
  const decoded = useMemo(() => activeToken ? decodeJwt(activeToken) : null, [activeToken]);

  return (
    <div className="space-y-3">
      <div className="flex items-center gap-2 mb-2">
        <Fingerprint className="w-3.5 h-3.5 text-primary" />
        <span className="text-[9px] font-black text-primary uppercase tracking-widest">JWT Intelligence</span>
        {decoded?.expired && (
          <span className="text-[7px] font-black uppercase tracking-widest px-1.5 py-0.5 rounded border text-red-500 bg-red-500/10 border-red-500/20">
            Expired
          </span>
        )}
        {decoded && !decoded.expired && (
          <span className="text-[7px] font-black uppercase tracking-widest px-1.5 py-0.5 rounded border text-green-500 bg-green-500/10 border-green-500/20">
            Valid
          </span>
        )}
      </div>

      {!token && (
        <div>
          <textarea
            className="w-full h-16 bg-muted/40 border border-border rounded-lg p-2 text-[10px] font-mono text-foreground placeholder:text-muted-foreground/50 resize-none focus:border-primary/30 focus:outline-none transition-colors"
            placeholder="Paste JWT token here (eyJ...)"
            value={manualToken}
            onChange={e => setManualToken(e.target.value)}
          />
        </div>
      )}

      {token && (
        <div className="px-2 py-1.5 rounded bg-primary/5 border border-primary/10">
          <span className="text-[8px] font-black text-primary/60 uppercase tracking-widest">Auto-detected from response</span>
        </div>
      )}

      {decoded ? (
        <div className="space-y-2">
          {/* Header */}
          <div className="rounded-lg bg-card border border-border overflow-hidden">
            <div className="px-3 py-1.5 border-b border-border bg-blue-500/5">
              <span className="text-[8px] font-black text-blue-500 uppercase tracking-widest">Header</span>
            </div>
            <pre className="p-3 text-[10px] font-mono text-foreground whitespace-pre-wrap break-all">
              {JSON.stringify(decoded.header, null, 2)}
            </pre>
          </div>

          {/* Payload */}
          <div className="rounded-lg bg-card border border-border overflow-hidden">
            <div className="px-3 py-1.5 border-b border-border bg-purple-500/5">
              <span className="text-[8px] font-black text-purple-400 uppercase tracking-widest">Payload</span>
            </div>
            <pre className="p-3 text-[10px] font-mono text-foreground whitespace-pre-wrap break-all">
              {JSON.stringify(decoded.payload, null, 2)}
            </pre>
            {decoded.expiresAt && (
              <div className="px-3 py-1.5 border-t border-white/5 flex items-center gap-2">
                <Clock className="w-2.5 h-2.5 text-muted-foreground" />
                <span className="text-[8px] font-mono text-muted-foreground">
                  Expires: {decoded.expiresAt}
                </span>
              </div>
            )}
          </div>

          {/* Signature */}
          <div className="rounded-lg bg-card border border-border overflow-hidden">
            <div className="px-3 py-1.5 border-b border-border bg-orange-500/5">
              <span className="text-[8px] font-black text-orange-400 uppercase tracking-widest">Signature</span>
            </div>
            <div className="p-3">
              <code className="text-[9px] font-mono text-muted-foreground break-all">{decoded.signature}</code>
            </div>
          </div>
        </div>
      ) : activeToken ? (
        <div className="flex items-center justify-center py-6">
          <span className="text-[9px] text-red-400/60 uppercase tracking-widest">Invalid JWT token</span>
        </div>
      ) : (
        <div className="flex items-center justify-center py-6">
          <span className="text-[9px] text-foreground/20 uppercase tracking-widest">No JWT detected</span>
        </div>
      )}
    </div>
  );
}

// ─── Auth Editor Panel ───────────────────────────────────────────────────────

function AuthEditor({ authType, setAuthType, authValue, setAuthValue, authKey, setAuthKey, authUser, setAuthUser, authPass, setAuthPass }: {
  authType: AuthType;
  setAuthType: (t: AuthType) => void;
  authValue: string;
  setAuthValue: (v: string) => void;
  authKey: string;
  setAuthKey: (k: string) => void;
  authUser: string;
  setAuthUser: (u: string) => void;
  authPass: string;
  setAuthPass: (p: string) => void;
}) {
  return (
    <div className="space-y-3">
      {/* Auth type selector */}
      <div className="flex gap-1.5 flex-wrap">
        {(["none", "bearer", "basic", "apikey", "jwt"] as AuthType[]).map(t => (
          <button
            key={t}
            type="button"
            onClick={() => setAuthType(t)}
            className={cn(
              "px-2.5 py-1 rounded-lg text-[8px] font-black uppercase tracking-widest border transition-colors",
              authType === t
                ? "bg-primary/10 border-primary/30 text-primary"
                : "bg-muted/20 border-border text-muted-foreground hover:text-foreground"
            )}
          >
            {t === "none" ? "No Auth" : t === "bearer" ? "Bearer Token" : t === "basic" ? "Basic Auth" : t === "apikey" ? "API Key" : "JWT"}
          </button>
        ))}
      </div>

      {authType === "none" && (
        <div className="flex items-center justify-center py-6">
          <span className="text-[9px] text-foreground/20 uppercase tracking-widest">No authentication configured</span>
        </div>
      )}

      {authType === "bearer" && (
        <div className="space-y-2">
          <label className="text-[8px] font-black text-muted-foreground uppercase tracking-widest">Bearer Token</label>
          <div className="flex items-center gap-2">
            <Lock className="w-3.5 h-3.5 text-primary/40 shrink-0" />
            <input
              className="flex-1 bg-muted/40 border border-border rounded-lg px-3 py-2 text-[11px] font-mono text-foreground placeholder:text-muted-foreground/50 focus:border-primary/30 focus:outline-none transition-colors"
              placeholder="eyJhbGciOiJIUzI1NiIs..."
              value={authValue}
              onChange={e => setAuthValue(e.target.value)}
            />
          </div>
          <p className="text-[8px] text-muted-foreground">Header: Authorization: Bearer {authValue ? authValue.slice(0, 20) + "..." : "<token>"}</p>
        </div>
      )}

      {authType === "basic" && (
        <div className="space-y-2">
          <label className="text-[8px] font-black text-muted-foreground uppercase tracking-widest">Basic Authentication</label>
          <div className="grid grid-cols-2 gap-2">
            <div>
              <span className="text-[7px] text-muted-foreground uppercase tracking-widest">Username</span>
              <input
                className="w-full bg-muted/40 border border-border rounded-lg px-3 py-2 text-[11px] font-mono text-foreground placeholder:text-muted-foreground/50 focus:border-primary/30 focus:outline-none transition-colors mt-1"
                placeholder="admin"
                value={authUser}
                onChange={e => setAuthUser(e.target.value)}
              />
            </div>
            <div>
              <span className="text-[7px] text-muted-foreground uppercase tracking-widest">Password</span>
              <input
                type="password"
                className="w-full bg-muted/40 border border-border rounded-lg px-3 py-2 text-[11px] font-mono text-foreground placeholder:text-muted-foreground/50 focus:border-primary/30 focus:outline-none transition-colors mt-1"
                placeholder="••••••••"
                value={authPass}
                onChange={e => setAuthPass(e.target.value)}
              />
            </div>
          </div>
          <p className="text-[8px] text-muted-foreground">Header: Authorization: Basic {authUser ? btoa(`${authUser}:${authPass}`).slice(0, 20) + "..." : "<base64>"}</p>
        </div>
      )}

      {authType === "apikey" && (
        <div className="space-y-2">
          <label className="text-[8px] font-black text-muted-foreground uppercase tracking-widest">API Key</label>
          <div className="grid grid-cols-2 gap-2">
            <div>
              <span className="text-[7px] text-muted-foreground uppercase tracking-widest">Header Name</span>
              <input
                className="w-full bg-muted/40 border border-border rounded-lg px-3 py-2 text-[11px] font-mono text-foreground placeholder:text-muted-foreground/50 focus:border-primary/30 focus:outline-none transition-colors mt-1"
                placeholder="X-API-Key"
                value={authKey}
                onChange={e => setAuthKey(e.target.value)}
              />
            </div>
            <div>
              <span className="text-[7px] text-muted-foreground uppercase tracking-widest">Key Value</span>
              <input
                className="w-full bg-muted/40 border border-border rounded-lg px-3 py-2 text-[11px] font-mono text-foreground placeholder:text-muted-foreground/50 focus:border-primary/30 focus:outline-none transition-colors mt-1"
                placeholder="2f8ad8123..."
                value={authValue}
                onChange={e => setAuthValue(e.target.value)}
              />
            </div>
          </div>
          <p className="text-[8px] text-muted-foreground">Header: {authKey || "X-API-Key"}: {authValue ? authValue.slice(0, 20) + "..." : "<key>"}</p>
        </div>
      )}

      {authType === "jwt" && (
        <div className="space-y-2">
          <label className="text-[8px] font-black text-muted-foreground uppercase tracking-widest">JWT Token</label>
          <textarea
            className="w-full h-20 bg-muted/40 border border-border rounded-lg p-3 text-[10px] font-mono text-foreground placeholder:text-muted-foreground/50 resize-none focus:border-primary/30 focus:outline-none transition-colors"
            placeholder="eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."
            value={authValue}
            onChange={e => setAuthValue(e.target.value)}
          />
          {authValue && decodeJwt(authValue) && (
            <div className="px-2 py-1.5 rounded bg-primary/5 border border-primary/10 space-y-1">
              <span className="text-[7px] font-black text-primary/60 uppercase tracking-widest">Decoded Payload</span>
              <pre className="text-[8px] font-mono text-muted-foreground whitespace-pre-wrap">
                {JSON.stringify(decodeJwt(authValue)?.payload, null, 2)}
              </pre>
            </div>
          )}
          <p className="text-[8px] text-muted-foreground">Header: Authorization: Bearer {authValue ? authValue.slice(0, 20) + "..." : "<jwt>"}</p>
        </div>
      )}
    </div>
  );
}

// ─── Inline Fuzzer Tab ───────────────────────────────────────────────────────

function InlineFuzzerTab({ url, method, params, headers, body, onSelectPayload }: {
  url: string;
  method: HttpMethod;
  params: KeyValue[];
  headers: KeyValue[];
  body: string;
  onSelectPayload: (payload: string, param: string, location: string) => void;
}) {
  const [selectedTarget, setSelectedTarget] = useState<string>("");
  const [fuzzType, setFuzzType] = useState("sqli");
  const [wordlist, setWordlist] = useState("");
  const [running, setRunning] = useState(false);
  const [results, setResults] = useState<Array<{ payload: string; status: number; length: number; time: number; anomaly: boolean }>>([]);

  const targets = useMemo(() => {
    const t: Array<{ name: string; value: string; location: string }> = [];
    params.filter(p => p.enabled && p.key.trim()).forEach(p =>
      t.push({ name: p.key, value: p.value, location: "param" })
    );
    headers.filter(h => h.enabled && h.key.trim()).forEach(h =>
      t.push({ name: h.key, value: h.value, location: "header" })
    );
    if (body) t.push({ name: "body", value: body.slice(0, 50), location: "body" });
    return t;
  }, [params, headers, body]);

  const runFuzz = useCallback(async () => {
    if (!url.trim() || !selectedTarget) return;
    setRunning(true);
    setResults([]);

    try {
      const target = targets.find(t => t.name === selectedTarget);
      const res = await fetch(`${API_BASE}/api/hetty/ai/fuzz`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          url,
          method,
          parameter: selectedTarget,
          location: target?.location || "param",
          original_value: target?.value || "",
          vuln_types: [fuzzType],
          max_payloads: 20,
          custom_wordlist: wordlist ? wordlist.split("\n").filter(Boolean) : undefined,
        }),
      });
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      const data = await res.json();
      setResults(data.results || []);
      if (data.results?.some((r: any) => r.anomaly)) {
        toast.warning("Anomalies detected in fuzz results!");
      } else {
        toast.success(`Fuzz complete — ${data.results?.length || 0} results`);
      }
    } catch (err: any) {
      toast.error(err.message || "Fuzz failed");
    } finally {
      setRunning(false);
    }
  }, [url, method, selectedTarget, fuzzType, wordlist, targets]);

  return (
    <div className="space-y-3">
      {/* Target selection */}
      <div className="flex items-center gap-2 flex-wrap">
        <span className="text-[8px] font-black text-muted-foreground uppercase tracking-widest shrink-0">Target:</span>
        {targets.map(t => (
          <button
            key={t.name}
            type="button"
            onClick={() => setSelectedTarget(t.name)}
            className={cn(
              "px-2 py-0.5 rounded text-[8px] font-bold border transition-colors",
              selectedTarget === t.name
                ? "bg-primary/10 border-primary/30 text-primary"
                : "bg-muted/20 border-border text-muted-foreground hover:text-foreground"
            )}
          >
            {t.name} <span className="text-muted-foreground/60">({t.location})</span>
          </button>
        ))}
        {targets.length === 0 && (
          <span className="text-[8px] text-muted-foreground">No parameters found — add params/headers first</span>
        )}
      </div>

      {/* Vuln type + wordlist */}
      <div className="grid grid-cols-2 gap-2">
        <div>
          <span className="text-[7px] text-muted-foreground uppercase tracking-widest">Attack Type</span>
          <select
            value={fuzzType}
            onChange={e => setFuzzType(e.target.value)}
            title="Attack type"
            aria-label="Attack type"
            className="w-full mt-1 bg-muted/40 border border-border rounded-lg px-2 py-1.5 text-[10px] font-bold text-foreground focus:outline-none focus:border-primary/30 transition-colors"
          >
            <option value="sqli">SQL Injection</option>
            <option value="xss">Cross-Site Scripting</option>
            <option value="lfi">Local File Inclusion</option>
            <option value="ssrf">Server-Side Request Forgery</option>
            <option value="ssti">Template Injection</option>
            <option value="cmdi">Command Injection</option>
            <option value="idor">IDOR</option>
            <option value="auth_bypass">Auth Bypass</option>
          </select>
        </div>
        <div>
          <span className="text-[7px] text-muted-foreground uppercase tracking-widest">Custom Wordlist (optional)</span>
          <textarea
            className="w-full mt-1 h-[60px] bg-muted/40 border border-border rounded-lg p-2 text-[9px] font-mono text-foreground placeholder:text-muted-foreground/50 resize-none focus:border-primary/30 focus:outline-none transition-colors"
            placeholder="One payload per line..."
            value={wordlist}
            onChange={e => setWordlist(e.target.value)}
          />
        </div>
      </div>

      {/* Run button */}
      <button
        type="button"
        onClick={runFuzz}
        disabled={running || !selectedTarget || !url.trim()}
        className={cn(
          "w-full flex items-center justify-center gap-2 px-4 py-2 rounded-lg text-[9px] font-black uppercase tracking-widest transition-colors",
          running ? "bg-orange-500/20 text-orange-400 cursor-wait" : "bg-orange-500/10 border border-orange-500/30 text-orange-400 hover:bg-orange-500/20",
          (!selectedTarget || !url.trim()) && "opacity-40 cursor-not-allowed"
        )}
      >
        {running ? <RefreshCw className="w-3 h-3 animate-spin" /> : <Zap className="w-3 h-3" />}
        {running ? "Fuzzing..." : "Start Fuzzing"}
      </button>

      {/* Results */}
      {results.length > 0 && (
        <div className="rounded-lg border border-white/10 overflow-hidden">
          <div className="px-3 py-1.5 bg-white/[0.02] border-b border-white/5 flex items-center justify-between">
            <span className="text-[8px] font-black text-muted-foreground uppercase tracking-widest">Results ({results.length})</span>
            <span className="text-[8px] font-black text-red-400">
              {results.filter(r => r.anomaly).length} anomalies
            </span>
          </div>
          <div className="max-h-[200px] overflow-y-auto divide-y divide-border/10">
            {results.map((r, i) => (
              <div
                key={i}
                className={cn(
                  "px-3 py-1.5 flex items-center gap-2 text-[9px]",
                  r.anomaly ? "bg-red-500/10" : "hover:bg-primary/5"
                )}
              >
                <div className={cn("w-1.5 h-1.5 rounded-full shrink-0", r.anomaly ? "bg-red-500" : "bg-muted-foreground")} />
                <code className="flex-1 font-mono text-muted-foreground truncate">{r.payload}</code>
                <span className={cn("font-black shrink-0", r.status >= 500 ? "text-red-500" : r.status >= 400 ? "text-orange-500" : "text-green-500")}>
                  {r.status}
                </span>
                <span className="text-muted-foreground/60 shrink-0 w-14 text-right">{r.length}B</span>
                <span className="text-muted-foreground/60 shrink-0 w-14 text-right">{r.time}ms</span>
                <button
                  type="button"
                  onClick={() => onSelectPayload(r.payload, selectedTarget, targets.find(t => t.name === selectedTarget)?.location || "param")}
                  className="p-0.5 text-muted-foreground hover:text-primary transition-colors shrink-0"
                  title="Use this payload"
                >
                  <ArrowRight className="w-2.5 h-2.5" />
                </button>
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  );
}

// ─── Main Component ──────────────────────────────────────────────────────────

export function HettyToolkit({ findingData, finding, scanId }: HettyToolkitProps) {
  // Request state
  const [method, setMethod] = useState<HttpMethod>("GET");
  const [url, setUrl] = useState("");
  const [headerItems, setHeaderItems] = useState<KeyValue[]>([defaultKv()]);
  const [paramItems, setParamItems] = useState<KeyValue[]>([defaultKv()]);
  const [cookieItems, setCookieItems] = useState<KeyValue[]>([defaultKv()]);
  const [bodyContent, setBodyContent] = useState("");
  const [rawRequest, setRawRequest] = useState("");
  const [rawEdited, setRawEdited] = useState(false);
  const [requestTimeout, setRequestTimeout] = useState(25);

  // Auth state
  const [authType, setAuthType] = useState<AuthType>("none");
  const [authValue, setAuthValue] = useState("");
  const [authKey, setAuthKey] = useState("X-API-Key");
  const [authUser, setAuthUser] = useState("");
  const [authPass, setAuthPass] = useState("");

  // Response state
  const [response, setResponse] = useState<HettyResponse | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  // UI state
  const [requestTab, setRequestTab] = useState<RequestTab>("headers");
  const [responseTab, setResponseTab] = useState<ResponseTab>("body");
  const [activePanel, setActivePanel] = useState<ToolkitPanel>("request");
  const [methodDropdown, setMethodDropdown] = useState(false);
  const [sidebarOpen, setSidebarOpen] = useState(true);
  const [sidebarPanel, setSidebarPanel] = useState<SidebarPanel>("collections");

  // Collections state
  const [collections, setCollections] = useState<ApiCollection[]>(DEFAULT_COLLECTIONS);
  const [discoveredEndpoints, setDiscoveredEndpoints] = useState<CollectionEndpoint[]>([]);
  const [savedRequests, setSavedRequests] = useState<CollectionEndpoint[]>([]);
  const [endpointDropdownOpen, setEndpointDropdownOpen] = useState(false);

  // History + Compare state
  const [history, setHistory] = useState<HistoryEntry[]>([]);
  const [compareResult, setCompareResult] = useState<CompareResult | null>(null);
  const [replayLoading, setReplayLoading] = useState(false);

  // AI Console state
  const [fuzzTargetParam, setFuzzTargetParam] = useState("");
  const [fuzzTargetLocation, setFuzzTargetLocation] = useState("param");
  const [collectedFindings, setCollectedFindings] = useState<any[]>([]);

  // Refs
  const paramSyncRef = useRef(false);
  const urlInputRef = useRef<HTMLInputElement>(null);

  // JWT detection from response
  const detectedJwt = useMemo(() => {
    if (!response?.response) return null;
    return extractJwtFromResponse(response.response.headers || {}, response.response.body || "");
  }, [response]);

  // Build auth headers for request
  const getAuthHeaders = useCallback((): Record<string, string> => {
    switch (authType) {
      case "bearer": return authValue ? { Authorization: `Bearer ${authValue}` } : {};
      case "basic": return (authUser || authPass) ? { Authorization: `Basic ${btoa(`${authUser}:${authPass}`)}` } : {};
      case "apikey": return (authKey && authValue) ? { [authKey]: authValue } : {};
      case "jwt": return authValue ? { Authorization: `Bearer ${authValue}` } : {};
      default: return {};
    }
  }, [authType, authValue, authKey, authUser, authPass]);

  // Build flat list of all endpoints for selector
  const allEndpoints = useMemo(() => {
    const eps: CollectionEndpoint[] = [];
    collections.forEach(c => c.endpoints.forEach(e => eps.push(e)));
    discoveredEndpoints.forEach(e => eps.push(e));
    return eps;
  }, [collections, discoveredEndpoints]);

  // ─── Pre-load finding data ──────────────────────────────────────────────
  useEffect(() => {
    const data = findingData || finding;
    if (data) {
      const targetUrl = data.url || data.target || data.endpoint || "";
      if (targetUrl) {
        setUrl(targetUrl);
        setParamItems(extractQueryParams(targetUrl));
      }
      setMethod((data.method || "GET").toUpperCase() as HttpMethod);
    }
  }, [findingData, finding]);

  // ─── URL → Params sync ──────────────────────────────────────────────────
  useEffect(() => {
    if (paramSyncRef.current) {
      paramSyncRef.current = false;
      return;
    }
    const extracted = extractQueryParams(url);
    if (extracted.length > 0) {
      setParamItems(extracted);
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [url]);

  // ─── Params → URL sync ─────────────────────────────────────────────────
  const handleParamsChange = useCallback((items: KeyValue[]) => {
    setParamItems(items);
    paramSyncRef.current = true;
    setUrl(prev => applyParamsToUrl(prev, items));
  }, []);

  // ─── Build raw request for raw tab ──────────────────────────────────────
  useEffect(() => {
    if (requestTab === "raw" && !rawEdited) {
      setRawRequest(buildRawRequest(method, url, headerItems, cookieItems, bodyContent));
    }
  }, [requestTab, method, url, headerItems, cookieItems, bodyContent, rawEdited]);

  // ─── Apply raw edits back to structured fields ─────────────────────────
  const applyRawEdits = useCallback(() => {
    const parsed = parseRawRequest(rawRequest);
    if (!parsed) {
      toast.error("Could not parse raw request. Check format.");
      return;
    }
    setMethod(parsed.method);
    setUrl(parsed.url);
    setHeaderItems(parsed.headers.length > 0 ? parsed.headers : [defaultKv()]);
    setCookieItems(parsed.cookies.length > 0 ? parsed.cookies : [defaultKv()]);
    setBodyContent(parsed.body);
    setParamItems(extractQueryParams(parsed.url));
    setRawEdited(false);
    toast.success("Raw edits applied to request fields");
  }, [rawRequest]);

  // ─── Fetch history ─────────────────────────────────────────────────────
  const fetchHistory = useCallback(async () => {
    try {
      const res = await fetch(`${API_BASE}/api/hetty/history`);
      if (res.ok) {
        const data = await res.json();
        setHistory(data.history || []);
      }
    } catch { /* ignore */ }
  }, []);

  useEffect(() => { fetchHistory(); }, [fetchHistory]);

  // ─── Load endpoint from collection ──────────────────────────────────────
  const loadEndpoint = useCallback((ep: CollectionEndpoint) => {
    // If URL is relative, try to build absolute from current URL's base
    let targetUrl = ep.url;
    if (targetUrl.startsWith("/") && url) {
      try {
        const base = new URL(url);
        targetUrl = `${base.protocol}//${base.host}${targetUrl}`;
      } catch { /* keep relative */ }
    }
    setMethod(ep.method);
    setUrl(targetUrl);
    setParamItems(extractQueryParams(targetUrl));
    if (ep.body) setBodyContent(ep.body);
    if (ep.headers) {
      const hdrs = Object.entries(ep.headers).map(([k, v]) => ({ key: k, value: v, enabled: true }));
      setHeaderItems(hdrs.length > 0 ? hdrs : [defaultKv()]);
    }
    if (ep.authType && ep.authType !== "none") {
      setAuthType(ep.authType);
      if (ep.authValue) setAuthValue(ep.authValue);
    }
    setEndpointDropdownOpen(false);
    setActivePanel("request");
    toast.success(`Loaded: ${ep.name}`);
  }, [url]);

  // ─── Save current request ──────────────────────────────────────────────
  const saveCurrentRequest = useCallback(() => {
    if (!url.trim()) { toast.error("Enter a URL first"); return; }
    const name = url.split("/").pop() || url;
    const ep: CollectionEndpoint = {
      id: `saved-${Date.now()}`,
      name: `${method} ${name}`,
      method,
      url,
      body: bodyContent || undefined,
      authType,
      authValue,
    };
    setSavedRequests(prev => [...prev, ep]);
    toast.success("Request saved");
  }, [url, method, bodyContent, authType, authValue]);

  // ─── Send request ──────────────────────────────────────────────────────
  const handleSend = useCallback(async () => {
    if (!url.trim()) {
      toast.error("Enter a URL to send");
      return;
    }

    // If raw tab was edited, apply edits first
    if (rawEdited) {
      const parsed = parseRawRequest(rawRequest);
      if (parsed) {
        setMethod(parsed.method);
        setUrl(parsed.url);
        setHeaderItems(parsed.headers.length > 0 ? parsed.headers : [defaultKv()]);
        setCookieItems(parsed.cookies.length > 0 ? parsed.cookies : [defaultKv()]);
        setBodyContent(parsed.body);
        setRawEdited(false);
      }
    }

    setLoading(true);
    setError(null);
    setResponse(null);

    try {
      const hdrs: Record<string, string> = {};
      headerItems.filter(h => h.enabled && h.key.trim()).forEach(h => { hdrs[h.key] = h.value; });

      // Merge auth headers
      const authHdrs = getAuthHeaders();
      Object.assign(hdrs, authHdrs);

      const cks: Record<string, string> = {};
      cookieItems.filter(c => c.enabled && c.key.trim()).forEach(c => { cks[c.key] = c.value; });

      const params: Record<string, string> = {};
      paramItems.filter(p => p.enabled && p.key.trim()).forEach(p => { params[p.key] = p.value; });

      const payload = {
        method,
        url: url.trim(),
        headers: hdrs,
        cookies: cks,
        params,
        body: bodyContent || undefined,
        timeout: requestTimeout,
      };

      const res = await fetch(`${API_BASE}/api/hetty/send-request`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(payload),
      });

      const data: HettyResponse = await res.json();

      if (!res.ok || !data.success) {
        setError(data.error || `Request failed with status ${res.status}`);
        if (data.blocked) {
          toast.error("Request blocked by SSRF protection");
        } else {
          toast.error(data.error || "Request failed");
        }
      } else {
        setResponse(data);
        setResponseTab("body");

        const vulnCount = data.security?.vulnerabilities?.length || 0;
        const secretCount = data.security?.secrets?.length || 0;

        if (vulnCount > 0 || secretCount > 0) {
          toast.warning(`Detected ${vulnCount} vulnerabilities, ${secretCount} secrets`);
        } else {
          toast.success(`${data.response?.status_code} — ${data.timing?.total_ms}ms`);
        }

        // Auto-detect and add to discovered endpoints
        try {
          const parsed = new URL(url.trim());
          const path = parsed.pathname;
          if (!discoveredEndpoints.some(e => e.url === path && e.method === method)) {
            setDiscoveredEndpoints(prev => [...prev, {
              id: `disc-${Date.now()}`,
              name: path.split("/").filter(Boolean).pop() || path,
              method,
              url: path,
            }]);
          }
        } catch { /* ignore parse errors */ }
      }

      fetchHistory();
    } catch (err: any) {
      const msg = err.message || "Network error — is the backend running?";
      setError(msg);
      toast.error(msg);
    } finally {
      setLoading(false);
    }
  }, [url, method, headerItems, cookieItems, paramItems, bodyContent, requestTimeout, rawEdited, rawRequest, fetchHistory, getAuthHeaders, discoveredEndpoints]);

  // ─── Replay request ────────────────────────────────────────────────────
  const handleReplay = useCallback(async () => {
    if (!response?.id) {
      toast.error("Send a request first before replaying");
      return;
    }
    setReplayLoading(true);
    setCompareResult(null);

    try {
      const res = await fetch(`${API_BASE}/api/hetty/replay`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ original_id: response.id }),
      });
      const data = await res.json();
      if (data.success) {
        setCompareResult(data.comparison);
        setActivePanel("compare");
        toast.success("Replay complete — see comparison");
      } else {
        toast.error(data.error || "Replay failed");
      }
      fetchHistory();
    } catch (err: any) {
      toast.error(err.message || "Replay failed");
    } finally {
      setReplayLoading(false);
    }
  }, [response?.id, fetchHistory]);

  // ─── Load from history ─────────────────────────────────────────────────
  const loadFromHistory = useCallback(async (entryId: string) => {
    try {
      const res = await fetch(`${API_BASE}/api/hetty/history/${entryId}`);
      if (!res.ok) { toast.error("Failed to load history entry"); return; }
      const data = await res.json();
      if (data.request) {
        setMethod((data.request.method || "GET").toUpperCase() as HttpMethod);
        setUrl(data.request.url || "");
        const hdrs = Object.entries(data.request.headers || {}).map(([k, v]) => ({ key: k, value: v as string, enabled: true }));
        setHeaderItems(hdrs.length > 0 ? hdrs : [defaultKv()]);
        const cks = Object.entries(data.request.cookies || {}).map(([k, v]) => ({ key: k, value: typeof v === "object" && v !== null ? String((v as Record<string, unknown>).value ?? JSON.stringify(v)) : String(v), enabled: true }));
        setCookieItems(cks.length > 0 ? cks : [defaultKv()]);
        setBodyContent(data.request.body || "");
        setParamItems(extractQueryParams(data.request.url || ""));
      }
      if (data.response) {
        setResponse(data as HettyResponse);
        setResponseTab("body");
      }
      setActivePanel("request");
      setRawEdited(false);
      toast.success("Loaded from history");
    } catch {
      toast.error("Failed to load history entry");
    }
  }, []);

  // ─── Reset ──────────────────────────────────────────────────────────────
  const handleReset = useCallback(() => {
    setMethod("GET");
    setUrl("");
    setHeaderItems([defaultKv()]);
    setParamItems([defaultKv()]);
    setCookieItems([defaultKv()]);
    setBodyContent("");
    setRawRequest("");
    setRawEdited(false);
    setResponse(null);
    setError(null);
    setCompareResult(null);
    setResponseTab("body");
    setRequestTab("headers");
    setAuthType("none");
    setAuthValue("");
    toast.success("Request cleared");
  }, []);

  // ─── Copy response ─────────────────────────────────────────────────────
  const copyResponse = useCallback(() => {
    const text = response?.response?.body || "";
    if (!text) { toast.error("No response body to copy"); return; }
    navigator.clipboard.writeText(text);
    toast.success("Response copied");
  }, [response]);

  // ─── Keyboard shortcut ─────────────────────────────────────────────────
  useEffect(() => {
    const handler = (e: KeyboardEvent) => {
      if ((e.ctrlKey || e.metaKey) && e.key === "Enter") {
        e.preventDefault();
        handleSend();
      }
    };
    window.addEventListener("keydown", handler);
    return () => window.removeEventListener("keydown", handler);
  }, [handleSend]);

  // ─── AI Console Callbacks ────────────────────────────────────────────────

  const handleSelectPayload = useCallback((payload: string, param: string, location: string) => {
    if (location === "param") {
      const newParams = paramItems.map(p =>
        p.key === param ? { ...p, value: payload } : p
      );
      if (!newParams.some(p => p.key === param)) {
        newParams.push({ key: param, value: payload, enabled: true });
      }
      setParamItems(newParams);
      paramSyncRef.current = true;
      setUrl(prev => applyParamsToUrl(prev, newParams));
    } else if (location === "header") {
      const newHeaders = headerItems.map(h =>
        h.key === param ? { ...h, value: payload } : h
      );
      if (!newHeaders.some(h => h.key === param)) {
        newHeaders.push({ key: param, value: payload, enabled: true });
      }
      setHeaderItems(newHeaders);
    } else if (location === "cookie") {
      const newCookies = cookieItems.map(c =>
        c.key === param ? { ...c, value: payload } : c
      );
      if (!newCookies.some(c => c.key === param)) {
        newCookies.push({ key: param, value: payload, enabled: true });
      }
      setCookieItems(newCookies);
    } else if (location === "body") {
      setBodyContent(payload);
    }
    toast.success(`Payload applied to ${param}`);
    setActivePanel("request");
  }, [paramItems, headerItems, cookieItems]);

  // Collect findings from response security data for attack graph
  useEffect(() => {
    if (response?.security?.vulnerabilities?.length) {
      const newFindings = response.security.vulnerabilities.map((v: any) => ({
        endpoint: url,
        type: v.type,
        severity: v.confidence > 0.7 ? "high" : v.confidence > 0.4 ? "medium" : "low",
        confidence: v.confidence,
        parameter: v.location || "",
      }));
      setCollectedFindings(prev => {
        const merged = [...prev, ...newFindings];
        const seen = new Set<string>();
        return merged.filter(f => {
          const key = `${f.endpoint}:${f.type}:${f.parameter}`;
          if (seen.has(key)) return false;
          seen.add(key);
          return true;
        }).slice(-50);
      });
    }
  }, [response, url]);

  // ─── Tab definitions ───────────────────────────────────────────────────
  const reqTabs: { id: RequestTab; label: string; icon: React.ElementType }[] = [
    { id: "headers", label: "Headers", icon: FileText },
    { id: "params", label: "Params", icon: Search },
    { id: "auth", label: "Auth", icon: Lock },
    { id: "cookies", label: "Cookies", icon: Cookie },
    { id: "body", label: "Body", icon: Code },
    { id: "raw", label: "Raw", icon: Terminal },
    { id: "fuzzer", label: "Fuzzer", icon: Zap },
  ];

  const resTabs: { id: ResponseTab; label: string; icon: React.ElementType }[] = [
    { id: "body", label: "Body", icon: Code },
    { id: "headers", label: "Headers", icon: FileText },
    { id: "cookies", label: "Cookies", icon: Cookie },
    { id: "raw", label: "Raw", icon: Terminal },
    { id: "preview", label: "Preview", icon: Eye },
    { id: "timing", label: "Timing", icon: Timer },
    { id: "jwt", label: "JWT", icon: Fingerprint },
  ];

  const panels: { id: ToolkitPanel; label: string; icon: React.ElementType; group?: string }[] = [
    { id: "request", label: "Request", icon: Send, group: "core" },
    { id: "history", label: "History", icon: History, group: "core" },
    { id: "compare", label: "Compare", icon: GitCompare, group: "core" },
    { id: "ai-assistant", label: "AI Assistant", icon: Brain, group: "ai" },
    { id: "payloads", label: "Payloads", icon: Crosshair, group: "ai" },
    { id: "fuzzer", label: "Fuzzer", icon: Zap, group: "ai" },
    { id: "verify", label: "Verify", icon: ShieldCheck, group: "ai" },
    { id: "intel", label: "Intel", icon: Eye, group: "ai" },
    { id: "attack-graph", label: "Attack Graph", icon: Network, group: "ai" },
    { id: "dashboard", label: "Dashboard", icon: Activity, group: "ai" },
  ];

  // ─── Render ─────────────────────────────────────────────────────────────

  return (
    <div className="flex gap-4">
      {/* ═══ LEFT SIDEBAR — API Collections ═══ */}
      {sidebarOpen && (
        <div className="w-64 shrink-0 bg-card border border-border rounded-2xl overflow-hidden flex flex-col max-h-[calc(100vh-200px)]">
          {/* Sidebar header */}
          <div className="flex items-center justify-between px-3 py-2 border-b border-border">
            <div className="flex gap-1">
              {(["collections", "saved", "graph"] as SidebarPanel[]).map(p => (
                <button
                  key={p}
                  type="button"
                  onClick={() => setSidebarPanel(p)}
                  className={cn(
                    "px-2 py-1 rounded text-[7px] font-black uppercase tracking-widest transition-colors",
                    sidebarPanel === p
                      ? "bg-primary/10 text-primary"
                      : "text-muted-foreground hover:text-foreground"
                  )}
                >
                  {p === "collections" ? "APIs" : p === "saved" ? "Saved" : "Graph"}
                </button>
              ))}
            </div>
            <button
              type="button"
              onClick={() => setSidebarOpen(false)}
              title="Close sidebar"
              aria-label="Close sidebar"
              className="p-1 text-muted-foreground hover:text-foreground transition-colors"
            >
              <X className="w-3 h-3" />
            </button>
          </div>

          {/* Collections panel */}
          {sidebarPanel === "collections" && (
            <div className="flex-1 overflow-y-auto no-scrollbar">
              {collections.map(col => (
                <div key={col.id}>
                  <button
                    type="button"
                    onClick={() => setCollections(prev => prev.map(c => c.id === col.id ? { ...c, expanded: !c.expanded } : c))}
                    className="w-full flex items-center gap-2 px-3 py-2 hover:bg-primary/5 transition-colors"
                  >
                    {col.expanded ? <ChevronDown className="w-2.5 h-2.5 text-primary/50" /> : <ChevronRight className="w-2.5 h-2.5 text-primary/50" />}
                    <FolderOpen className="w-3 h-3 text-primary/40" />
                    <span className="text-[9px] font-black text-foreground uppercase tracking-widest">{col.name}</span>
                    <span className="ml-auto text-[7px] text-muted-foreground">{col.endpoints.length}</span>
                  </button>
                  {col.expanded && (
                    <div className="pb-1">
                      {col.endpoints.map(ep => (
                        <button
                          key={ep.id}
                          type="button"
                          onClick={() => loadEndpoint(ep)}
                          className="w-full flex items-center gap-2 px-3 py-1.5 pl-8 hover:bg-primary/10 transition-colors group"
                        >
                          <MethodBadgeSmall method={ep.method} />
                          <span className="text-[9px] font-mono text-muted-foreground truncate group-hover:text-foreground transition-colors">
                            {ep.name}
                          </span>
                        </button>
                      ))}
                    </div>
                  )}
                </div>
              ))}

              {/* Discovered Endpoints */}
              {discoveredEndpoints.length > 0 && (
                <div>
                  <div className="px-3 py-2 flex items-center gap-2">
                    <Globe className="w-3 h-3 text-blue-500/40" />
                    <span className="text-[9px] font-black text-blue-500/60 uppercase tracking-widest">Discovered</span>
                    <span className="ml-auto text-[7px] text-blue-500/40">{discoveredEndpoints.length}</span>
                  </div>
                  {discoveredEndpoints.map(ep => (
                    <button
                      key={ep.id}
                      type="button"
                      onClick={() => loadEndpoint(ep)}
                      className="w-full flex items-center gap-2 px-3 py-1.5 pl-6 hover:bg-primary/10 transition-colors group"
                    >
                      <MethodBadgeSmall method={ep.method} />
                      <span className="text-[9px] font-mono text-muted-foreground truncate group-hover:text-foreground transition-colors">
                        {ep.url}
                      </span>
                    </button>
                  ))}
                </div>
              )}
            </div>
          )}

          {/* Saved requests panel */}
          {sidebarPanel === "saved" && (
            <div className="flex-1 overflow-y-auto no-scrollbar">
              {savedRequests.length === 0 ? (
                <div className="flex flex-col items-center justify-center py-8 gap-2">
                  <Bookmark className="w-5 h-5 text-muted-foreground/20" />
                  <span className="text-[8px] text-muted-foreground uppercase tracking-widest">No saved requests</span>
                  <span className="text-[7px] text-muted-foreground/60">Click save icon to bookmark a request</span>
                </div>
              ) : (
                savedRequests.map(ep => (
                  <button
                    key={ep.id}
                    type="button"
                    onClick={() => loadEndpoint(ep)}
                    className="w-full flex items-center gap-2 px-3 py-2 hover:bg-primary/10 transition-colors group"
                  >
                    <MethodBadgeSmall method={ep.method} />
                    <span className="text-[9px] font-mono text-muted-foreground truncate group-hover:text-foreground transition-colors">
                      {ep.name}
                    </span>
                  </button>
                ))
              )}
            </div>
          )}

          {/* Attack graph mini panel */}
          {sidebarPanel === "graph" && (
            <div className="flex-1 overflow-y-auto no-scrollbar p-3">
              {collectedFindings.length === 0 ? (
                <div className="flex flex-col items-center justify-center py-8 gap-2">
                  <Network className="w-5 h-5 text-muted-foreground/20" />
                  <span className="text-[8px] text-muted-foreground uppercase tracking-widest">No findings yet</span>
                </div>
              ) : (
                <div className="space-y-1">
                  {collectedFindings.map((f, i) => (
                    <div key={i} className="flex items-center gap-2 px-2 py-1 rounded bg-primary/5">
                      <div className={cn("w-1.5 h-1.5 rounded-full shrink-0",
                        f.severity === "high" ? "bg-red-500" : f.severity === "medium" ? "bg-yellow-500" : "bg-muted-foreground"
                      )} />
                      <span className="text-[8px] font-mono text-muted-foreground truncate">{f.type}</span>
                    </div>
                  ))}
                </div>
              )}
            </div>
          )}
        </div>
      )}

      {/* ═══ MAIN CONTENT ═══ */}
      <div className="flex-1 space-y-4 min-w-0">
        {/* Top Bar — Endpoint Selector + Method + URL + Send */}
        <div className="bg-card border border-border rounded-2xl p-3 space-y-2">
          {/* Endpoint Selector Row */}
          <div className="flex items-center gap-2">
            {!sidebarOpen && (
              <button
                type="button"
                onClick={() => setSidebarOpen(true)}
                className="p-2 rounded-lg border border-border text-muted-foreground hover:text-primary hover:border-primary/30 transition-colors"
                title="Show API Collections"
              >
                <FolderOpen className="w-3.5 h-3.5" />
              </button>
            )}

            {/* Endpoint Dropdown */}
            <div className="relative flex-1 max-w-xs">
              <button
                type="button"
                onClick={() => setEndpointDropdownOpen(!endpointDropdownOpen)}
                className="w-full flex items-center justify-between gap-2 px-3 py-1.5 rounded-lg bg-muted/40 border border-border text-[9px] font-bold text-muted-foreground hover:border-primary/30 transition-colors"
              >
                <span className="truncate">
                  {url ? (url.length > 40 ? "..." + url.slice(-37) : url) : "Select Endpoint"}
                </span>
                <ChevronDown className="w-3 h-3 shrink-0" />
              </button>
              {endpointDropdownOpen && (
                <div className="absolute top-full left-0 mt-1 w-full z-50 bg-card border border-border rounded-xl shadow-2xl overflow-hidden max-h-[300px] overflow-y-auto">
                  {allEndpoints.map(ep => (
                    <button
                      key={ep.id}
                      type="button"
                      onClick={() => loadEndpoint(ep)}
                      className="w-full flex items-center gap-2 px-3 py-2 hover:bg-primary/5 transition-colors"
                    >
                      <MethodBadgeSmall method={ep.method} />
                      <span className="text-[9px] font-mono text-muted-foreground truncate">{ep.url}</span>
                      <span className="ml-auto text-[7px] text-muted-foreground/60 truncate">{ep.name}</span>
                    </button>
                  ))}
                  {allEndpoints.length === 0 && (
                    <div className="px-3 py-4 text-center">
                      <span className="text-[8px] text-muted-foreground">No endpoints — start sending requests</span>
                    </div>
                  )}
                </div>
              )}
            </div>

            {/* Save button */}
            <button
              type="button"
              onClick={saveCurrentRequest}
              title="Save request"
              className="p-2 rounded-lg border border-border text-muted-foreground hover:text-primary hover:border-primary/30 transition-colors"
            >
              <Bookmark className="w-3.5 h-3.5" />
            </button>
          </div>

          {/* Method + URL + Actions row */}
          <div className="flex items-center gap-2">
            {/* Method Selector */}
            <div className="relative">
              <button
                type="button"
                onClick={() => setMethodDropdown(!methodDropdown)}
                className={cn(
                  "flex items-center gap-1.5 px-3 py-2 rounded-lg border bg-muted border-border text-xs font-black uppercase tracking-widest transition-colors hover:border-primary/30",
                  METHOD_COLORS[method]
                )}
              >
                {method}
                <ChevronDown className="w-3 h-3" />
              </button>
              {methodDropdown && (
                <div className="absolute top-full left-0 mt-1 z-50 bg-card border border-border rounded-xl shadow-2xl overflow-hidden min-w-[120px]">
                  {(["GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS"] as HttpMethod[]).map(m => (
                    <button
                      key={m}
                      type="button"
                      onClick={() => { setMethod(m); setMethodDropdown(false); }}
                      className={cn(
                        "w-full px-4 py-2 text-left text-[10px] font-black uppercase tracking-widest transition-colors hover:bg-primary/5",
                        METHOD_COLORS[m],
                        m === method && "bg-primary/5 text-primary"
                      )}
                    >
                      {m}
                    </button>
                  ))}
                </div>
              )}
            </div>

            {/* URL Input */}
            <input
              ref={urlInputRef}
              className="flex-1 bg-muted border border-border rounded-lg px-3 py-2 text-sm font-mono text-foreground placeholder:text-muted-foreground/50 focus:border-primary/30 focus:outline-none transition-colors"
              placeholder="https://target.example.com/api/endpoint"
              value={url}
              onChange={e => setUrl(e.target.value)}
              onKeyDown={e => { if (e.key === "Enter") handleSend(); }}
            />

            {/* Timeout */}
            <select
              value={requestTimeout}
              onChange={e => setRequestTimeout(Number(e.target.value))}
              title="Request timeout"
              aria-label="Request timeout"
              className="bg-muted border border-border rounded-lg px-2 py-2 text-[10px] font-bold text-muted-foreground uppercase tracking-widest focus:outline-none focus:border-primary/30 transition-colors"
            >
              <option value={5}>5s</option>
              <option value={10}>10s</option>
              <option value={15}>15s</option>
              <option value={25}>25s</option>
              <option value={45}>45s</option>
              <option value={60}>60s</option>
            </select>

            {/* Send */}
            <button
              type="button"
              onClick={handleSend}
              disabled={loading || !url.trim()}
              className={cn(
                "flex items-center gap-2 px-5 py-2 rounded-lg text-[10px] font-black uppercase tracking-widest",
                loading
                  ? "bg-primary/20 text-primary/60 cursor-wait"
                  : "bg-primary text-primary-foreground hover:bg-primary/90 active:scale-[0.97]",
                !url.trim() && "opacity-40 cursor-not-allowed"
              )}
            >
              {loading ? <RefreshCw className="w-3.5 h-3.5 animate-spin" /> : <Send className="w-3.5 h-3.5" />}
              {loading ? "Sending" : "Send"}
            </button>

            {/* Replay */}
            <button
              type="button"
              onClick={handleReplay}
              disabled={!response?.id || replayLoading}
              className={cn(
                "flex items-center gap-1.5 px-3 py-2 rounded-lg border text-[10px] font-black uppercase tracking-widest transition-colors",
                response?.id
                  ? "border-blue-500/30 text-blue-500 hover:bg-blue-500/10"
                  : "border-border text-muted-foreground cursor-not-allowed"
              )}
            >
              {replayLoading ? <RefreshCw className="w-3 h-3 animate-spin" /> : <Play className="w-3 h-3" />}
              Replay
            </button>

            {/* Reset */}
            <button
              type="button"
              onClick={handleReset}
              title="Reset request"
              aria-label="Reset request"
              className="p-2 rounded-lg border border-border text-muted-foreground hover:text-red-500 hover:border-red-500/30 transition-colors"
            >
              <Trash2 className="w-3.5 h-3.5" />
            </button>
          </div>

          <p className="text-[8px] text-muted-foreground/60 font-mono ml-1">
            Ctrl+Enter to send{authType !== "none" && <span className="text-primary/40 ml-2">Auth: {authType}</span>}
          </p>
        </div>

        {/* Panel Tabs */}
        <div className="flex gap-1.5 flex-wrap items-center">
          {panels.map((p, i) => (
            <React.Fragment key={p.id}>
              {i > 0 && panels[i - 1].group !== p.group && (
                <div className="w-px h-5 bg-border/20 mx-1" />
              )}
              <button
                type="button"
                onClick={() => setActivePanel(p.id)}
                className={cn(
                  "flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-[9px] font-black uppercase tracking-widest border transition-colors",
                  activePanel === p.id
                    ? p.group === "ai"
                      ? "bg-blue-500/10 border-blue-500/30 text-blue-500"
                      : "bg-primary/10 border-primary/30 text-primary"
                    : "bg-muted border-border text-muted-foreground hover:text-foreground"
                )}
              >
                <p.icon className="w-3 h-3" />
                {p.label}
                {p.id === "history" && history.length > 0 && (
                  <span className="ml-1 text-[8px] text-muted-foreground/60">{history.length}</span>
                )}
                {p.id === "attack-graph" && collectedFindings.length > 0 && (
                  <span className="ml-1 text-[8px] text-red-500">{collectedFindings.length}</span>
                )}
              </button>
            </React.Fragment>
          ))}
        </div>

        {/* ═══ Panel Content ═══ */}
        {activePanel === "request" && (
          <div className="grid grid-cols-1 xl:grid-cols-2 gap-4">
            {/* REQUEST PANEL */}
            <div className="bg-card border border-border rounded-2xl overflow-hidden">
              {/* Request header */}
              <div className="flex items-center justify-between border-b border-border px-4 py-2">
                <div className="flex items-center gap-3">
                  <span className="text-[9px] font-black text-muted-foreground uppercase tracking-widest">Request</span>
                  <span className={cn("text-[9px] font-black uppercase tracking-widest", METHOD_COLORS[method])}>{method}</span>
                  {authType !== "none" && (
                    <span className="flex items-center gap-1 px-1.5 py-0.5 rounded bg-primary/5 border border-primary/20">
                      <Lock className="w-2 h-2 text-primary/50" />
                      <span className="text-[7px] font-black text-primary/50 uppercase tracking-widest">{authType}</span>
                    </span>
                  )}
                </div>
              </div>

              {/* Request Tabs */}
              <div className="flex border-b border-border overflow-x-auto no-scrollbar">
                {reqTabs.map(t => (
                  <button
                    key={t.id}
                    type="button"
                    onClick={() => setRequestTab(t.id)}
                    className={cn(
                      "flex items-center gap-1.5 px-3 py-2.5 text-[9px] font-black uppercase tracking-widest border-b-2 transition-colors shrink-0",
                      requestTab === t.id
                        ? t.id === "fuzzer"
                          ? "border-orange-500 text-orange-500 bg-orange-500/10"
                          : t.id === "auth"
                            ? "border-primary text-primary bg-primary/5"
                            : "border-primary text-primary bg-primary/5"
                        : "border-transparent text-muted-foreground hover:text-foreground"
                    )}
                  >
                    <t.icon className="w-3 h-3" />
                    {t.label}
                  </button>
                ))}
              </div>

              {/* Request Tab Content */}
              <div className="p-4 min-h-[250px]">
                {requestTab === "headers" && (
                  <KeyValueEditor items={headerItems} onChange={setHeaderItems} placeholder="Header name" />
                )}
                {requestTab === "params" && (
                  <KeyValueEditor items={paramItems} onChange={handleParamsChange} placeholder="Param name" />
                )}
                {requestTab === "auth" && (
                  <AuthEditor
                    authType={authType} setAuthType={setAuthType}
                    authValue={authValue} setAuthValue={setAuthValue}
                    authKey={authKey} setAuthKey={setAuthKey}
                    authUser={authUser} setAuthUser={setAuthUser}
                    authPass={authPass} setAuthPass={setAuthPass}
                  />
                )}
                {requestTab === "cookies" && (
                  <KeyValueEditor items={cookieItems} onChange={setCookieItems} placeholder="Cookie name" />
                )}
                {requestTab === "body" && (
                  <textarea
                    className="w-full h-[250px] bg-muted border border-border rounded-xl p-3 text-[11px] font-mono text-foreground placeholder:text-muted-foreground/50 resize-none focus:border-primary/30 focus:outline-none transition-colors"
                    placeholder='{"key": "value"}'
                    value={bodyContent}
                    onChange={e => setBodyContent(e.target.value)}
                  />
                )}
                {requestTab === "raw" && (
                  <div className="space-y-2">
                    {rawEdited && (
                      <div className="flex items-center justify-between">
                        <span className="text-[9px] text-yellow-500 font-bold uppercase tracking-widest">Raw modified — apply to update fields</span>
                        <button
                          type="button"
                          onClick={applyRawEdits}
                          className="px-3 py-1 rounded-lg bg-yellow-500/10 border border-yellow-500/20 text-[9px] font-black text-yellow-400 uppercase tracking-widest hover:bg-yellow-500/20 transition-colors"
                        >
                          Apply Edits
                        </button>
                      </div>
                    )}
                    <textarea
                      className="w-full h-[250px] bg-muted border border-border rounded-xl p-3 text-[11px] font-mono text-foreground resize-none focus:border-primary/30 focus:outline-none transition-colors"
                      placeholder="GET /path HTTP/1.1&#10;Host: example.com&#10;&#10;body"
                      title="Raw HTTP request"
                      value={rawRequest}
                      onChange={e => { setRawRequest(e.target.value); setRawEdited(true); }}
                    />
                  </div>
                )}
                {requestTab === "fuzzer" && (
                  <InlineFuzzerTab
                    url={url}
                    method={method}
                    params={paramItems}
                    headers={headerItems}
                    body={bodyContent}
                    onSelectPayload={handleSelectPayload}
                  />
                )}
              </div>
            </div>

            {/* RESPONSE PANEL */}
            <div className="bg-card border border-border rounded-2xl overflow-hidden">
              {/* Response header */}
              <div className="flex items-center justify-between border-b border-border px-4 py-2">
                <div className="flex items-center gap-3">
                  <span className="text-[9px] font-black text-muted-foreground uppercase tracking-widest">Response</span>
                  {response?.response && (
                    <>
                      <StatusBadge code={response.response.status_code} />
                      <span className="text-[9px] text-muted-foreground font-mono">{response.response.status_text}</span>
                    </>
                  )}
                </div>
                <div className="flex items-center gap-3">
                  {response?.timing && (
                    <div className="flex items-center gap-1.5">
                      <Clock className="w-3 h-3 text-muted-foreground" />
                      <span className="text-[9px] font-bold text-muted-foreground/60">{response.timing.total_ms}ms</span>
                    </div>
                  )}
                  {response?.response && (
                    <div className="flex items-center gap-1.5">
                      <Globe className="w-3 h-3 text-muted-foreground" />
                      <span className="text-[9px] font-bold text-muted-foreground/60">
                        {response.response.body_size > 1024 ? `${(response.response.body_size / 1024).toFixed(1)}KB` : `${response.response.body_size}B`}
                      </span>
                    </div>
                  )}
                  {response?.response && (
                    <button type="button" onClick={copyResponse} title="Copy response" aria-label="Copy response" className="p-1 text-muted-foreground hover:text-primary transition-colors">
                      <Copy className="w-3 h-3" />
                    </button>
                  )}
                </div>
              </div>

              {/* Response Tabs */}
              <div className="flex border-b border-border overflow-x-auto no-scrollbar">
                {resTabs.map(t => (
                  <button
                    key={t.id}
                    type="button"
                    onClick={() => setResponseTab(t.id)}
                    className={cn(
                      "flex items-center gap-1.5 px-3 py-2 text-[9px] font-black uppercase tracking-widest border-b-2 transition-colors shrink-0",
                      responseTab === t.id
                        ? t.id === "jwt"
                          ? "border-purple-400 text-purple-400 bg-purple-400/10"
                          : "border-primary text-primary bg-primary/5"
                        : "border-transparent text-muted-foreground hover:text-foreground"
                    )}
                  >
                    <t.icon className="w-3 h-3" />
                    {t.label}
                    {t.id === "jwt" && detectedJwt && (
                      <div className="w-1.5 h-1.5 rounded-full bg-purple-500 ml-0.5" />
                    )}
                  </button>
                ))}
              </div>

              {/* Response Content */}
              <div className="p-4 min-h-[250px]">
                {loading && (
                  <div className="flex flex-col items-center justify-center h-[250px] gap-3">
                    <RefreshCw className="w-6 h-6 text-primary animate-spin" />
                    <p className="text-[10px] text-muted-foreground font-bold uppercase tracking-widest">Sending request...</p>
                  </div>
                )}

                {!loading && error && (
                  <div className="flex flex-col items-center justify-center h-[250px] gap-3">
                    <AlertTriangle className="w-6 h-6 text-red-400" />
                    <p className="text-xs text-red-400 font-bold text-center max-w-sm">{error}</p>
                  </div>
                )}

                {!loading && !error && !response && (
                  <div className="flex flex-col items-center justify-center h-[250px] gap-3">
                    <Send className="w-6 h-6 text-muted-foreground/20" />
                    <p className="text-[10px] text-muted-foreground font-bold uppercase tracking-widest">Send a request to see the response</p>
                  </div>
                )}

                {!loading && !error && response?.response && (
                  <>
                    {responseTab === "body" && (
                      <pre className="text-[11px] font-mono text-foreground whitespace-pre-wrap break-all max-h-[400px] overflow-y-auto no-scrollbar select-all leading-relaxed">
                        {response.response.body || "(empty body)"}
                      </pre>
                    )}

                    {responseTab === "headers" && (
                      <div className="space-y-1">
                        {Object.entries(response.response.headers || {}).map(([k, v]) => (
                          <div key={k} className="flex gap-2 py-1 border-b border-border/50 last:border-0">
                            <span className="text-[10px] font-black text-primary uppercase shrink-0 w-40 truncate">{k}</span>
                            <span className="text-[10px] font-mono text-muted-foreground break-all">{v}</span>
                          </div>
                        ))}
                        {Object.keys(response.response.headers || {}).length === 0 && (
                          <p className="text-[10px] text-muted-foreground">No response headers</p>
                        )}
                      </div>
                    )}

                    {responseTab === "cookies" && (
                      <div className="space-y-1">
                        {Object.entries(response.response.cookies || {}).map(([k, v]) => {
                          const display = typeof v === "object" && v !== null ? (v as Record<string, unknown>).value ?? JSON.stringify(v) : String(v);
                          return (
                            <div key={k} className="flex gap-2 py-1 border-b border-border/50 last:border-0">
                              <span className="text-[10px] font-black text-yellow-500 shrink-0 w-40 truncate">{k}</span>
                              <span className="text-[10px] font-mono text-muted-foreground break-all">{String(display)}</span>
                            </div>
                          );
                        })}
                        {Object.keys(response.response.cookies || {}).length === 0 && (
                          <p className="text-[10px] text-muted-foreground">No cookies in response</p>
                        )}
                      </div>
                    )}

                    {responseTab === "raw" && (
                      <pre className="text-[11px] font-mono text-foreground whitespace-pre-wrap break-all max-h-[400px] overflow-y-auto no-scrollbar select-all leading-relaxed">
                        {`HTTP/1.1 ${response.response.status_code} ${response.response.status_text}\n`}
                        {Object.entries(response.response.headers || {}).map(([k, v]) => `${k}: ${v}`).join("\n")}
                        {"\n\n"}
                        {response.response.body || ""}
                      </pre>
                    )}

                    {responseTab === "preview" && (
                      <div className="h-[400px] rounded-lg overflow-hidden bg-white">
                        {response.response.content_type?.includes("html") ? (
                          <iframe
                            title="Response Preview"
                            srcDoc={response.response.body}
                            className="w-full h-full border-0"
                            sandbox="allow-same-origin"
                          />
                        ) : response.response.content_type?.includes("image") ? (
                          <div className="flex items-center justify-center h-full bg-card">
                            <p className="text-[10px] text-muted-foreground">Image preview not supported for proxied responses</p>
                          </div>
                        ) : (
                          <pre className="text-[11px] font-mono text-muted-foreground p-4 whitespace-pre-wrap break-all overflow-y-auto h-full">
                            {response.response.body || "(empty)"}
                          </pre>
                        )}
                      </div>
                    )}

                    {responseTab === "timing" && response.timing && (
                      <div className="space-y-4">
                        {/* Visual timing bar */}
                        <div className="space-y-2">
                          {[
                            { label: "DNS", value: response.timing.dns_ms, color: "bg-primary", icon: Globe },
                            { label: "Connect", value: response.timing.connect_ms, color: "bg-blue-500", icon: Globe },
                            { label: "TLS", value: response.timing.tls_ms, color: "bg-purple-500", icon: Shield },
                            { label: "TTFB", value: response.timing.ttfb_ms, color: "bg-yellow-500", icon: Clock },
                            { label: "Total", value: response.timing.total_ms, color: "bg-foreground/30", icon: Gauge },
                          ].map(t => {
                            const pct = response.timing!.total_ms > 0 ? Math.min((t.value / response.timing!.total_ms) * 100, 100) : 0;
                            return (
                              <div key={t.label} className="flex items-center gap-3">
                                <t.icon className="w-3 h-3 text-muted-foreground shrink-0" />
                                <span className="text-[8px] font-black text-muted-foreground uppercase tracking-widest w-16 shrink-0">{t.label}</span>
                                <div className="flex-1 h-2 bg-muted/40 rounded-full overflow-hidden">
                                  <div className={cn("h-full rounded-full transition-all", t.color)} style={{ width: `${pct}%` }} />
                                </div>
                                <span className="text-[10px] font-black text-foreground w-14 text-right shrink-0">{t.value}ms</span>
                              </div>
                            );
                          })}
                        </div>

                        {/* Waterfall summary */}
                        <div className="rounded-lg bg-muted border border-border p-3 space-y-1.5">
                          <span className="text-[8px] font-black text-muted-foreground uppercase tracking-widest">Waterfall</span>
                          <div className="flex items-center gap-1 h-6">
                            {response.timing.dns_ms > 0 && (
                              <div className="h-full bg-primary/30 rounded" style={{ flex: response.timing.dns_ms }} title={`DNS: ${response.timing.dns_ms}ms`} />
                            )}
                            {response.timing.connect_ms > 0 && (
                              <div className="h-full bg-blue-500/30 rounded" style={{ flex: response.timing.connect_ms }} title={`Connect: ${response.timing.connect_ms}ms`} />
                            )}
                            {response.timing.tls_ms > 0 && (
                              <div className="h-full bg-purple-500/30 rounded" style={{ flex: response.timing.tls_ms }} title={`TLS: ${response.timing.tls_ms}ms`} />
                            )}
                            {response.timing.ttfb_ms > 0 && (
                              <div className="h-full bg-yellow-500/30 rounded" style={{ flex: response.timing.ttfb_ms }} title={`TTFB: ${response.timing.ttfb_ms}ms`} />
                            )}
                          </div>
                          <div className="flex items-center gap-3 mt-1">
                            <span className="flex items-center gap-1 text-[7px] text-muted-foreground"><div className="w-2 h-2 rounded bg-primary/30" /> DNS</span>
                            <span className="flex items-center gap-1 text-[7px] text-muted-foreground"><div className="w-2 h-2 rounded bg-blue-500/30" /> Connect</span>
                            <span className="flex items-center gap-1 text-[7px] text-muted-foreground"><div className="w-2 h-2 rounded bg-purple-500/30" /> TLS</span>
                            <span className="flex items-center gap-1 text-[7px] text-muted-foreground"><div className="w-2 h-2 rounded bg-yellow-500/30" /> TTFB</span>
                          </div>
                        </div>
                      </div>
                    )}

                    {responseTab === "timing" && !response.timing && (
                      <div className="flex items-center justify-center h-[250px]">
                        <span className="text-[9px] text-muted-foreground/20 uppercase tracking-widest">No timing data</span>
                      </div>
                    )}

                    {responseTab === "jwt" && (
                      <JwtDecoderPanel token={detectedJwt} />
                    )}
                  </>
                )}
              </div>

              {/* Security Findings */}
              {response?.security && (response.security.vulnerabilities?.length > 0 || response.security.secrets?.length > 0) && (
                <div className="border-t border-white/5 px-4 py-3 space-y-3">
                  <div className="flex items-center gap-2">
                    <Bug className="w-3.5 h-3.5 text-red-400" />
                    <span className="text-[9px] font-black text-red-400 uppercase tracking-widest">
                      Security Findings ({(response.security.vulnerabilities?.length || 0) + (response.security.secrets?.length || 0)})
                    </span>
                  </div>

                  {response.security.vulnerabilities?.map((v, i) => (
                    <VulnAlert key={i} vuln={v} />
                  ))}

                  {response.security.secrets?.map((s, i) => (
                    <div key={i} className="flex items-center gap-3 p-3 bg-yellow-500/10 border border-yellow-500/30 rounded-xl">
                      <ShieldAlert className="w-4 h-4 text-yellow-500 shrink-0" />
                      <div>
                        <span className="text-[10px] font-black text-yellow-500 uppercase tracking-widest">{s.type}</span>
                        <p className="text-[10px] font-mono text-muted-foreground">{s.value_masked}</p>
                      </div>
                    </div>
                  ))}
                </div>
              )}

              {/* Security Headers */}
              {response?.security?.security_headers && Object.keys(response.security.security_headers).length > 0 && (
                <div className="border-t border-border px-4 py-3">
                  <div className="flex items-center gap-2 mb-2">
                    <ShieldCheck className="w-3.5 h-3.5 text-primary/60" />
                    <span className="text-[9px] font-black text-muted-foreground uppercase tracking-widest">Security Headers</span>
                  </div>
                  <div className="flex flex-wrap gap-1.5">
                    {Object.entries(response.security.security_headers).map(([header, present]) => (
                      <span
                        key={header}
                        className={cn(
                          "px-2 py-0.5 rounded text-[8px] font-bold uppercase tracking-widest border",
                          present
                            ? "bg-primary/10 border-primary/30 text-primary"
                            : "bg-red-500/10 border-red-500/30 text-red-500"
                        )}
                      >
                        {present ? "+" : "-"} {header}
                      </span>
                    ))}
                  </div>
                </div>
              )}
            </div>
          </div>
        )}

        {/* HISTORY PANEL */}
        {activePanel === "history" && (
          <div className="bg-card border border-border rounded-2xl overflow-hidden">
            <div className="flex items-center justify-between px-4 py-3 border-b border-border">
              <div className="flex items-center gap-2">
                <History className="w-4 h-4 text-primary/60" />
                <span className="text-[10px] font-black text-muted-foreground uppercase tracking-widest">Request History</span>
              </div>
              <button type="button" onClick={fetchHistory} title="Refresh history" aria-label="Refresh history" className="p-1.5 text-muted-foreground hover:text-primary transition-colors">
                <RefreshCw className="w-3 h-3" />
              </button>
            </div>

            {history.length === 0 ? (
              <div className="p-10 flex flex-col items-center gap-3">
                <Clock className="w-8 h-8 text-muted-foreground/20" />
                <p className="text-[10px] text-muted-foreground font-bold uppercase tracking-widest">No requests yet</p>
              </div>
            ) : (
              <div className="divide-y divide-border/50 max-h-[400px] overflow-y-auto no-scrollbar">
                {history.map(entry => (
                  <button
                    key={entry.id}
                    type="button"
                    onClick={() => loadFromHistory(entry.id)}
                    className="w-full flex items-center gap-3 px-4 py-3 hover:bg-primary/5 transition-colors text-left group"
                  >
                    <MethodBadge method={entry.method} />
                    <span className="flex-1 text-[10px] font-mono text-muted-foreground truncate">{entry.url}</span>
                    <StatusBadge code={entry.status_code} />
                    <span className="text-[9px] text-muted-foreground font-mono shrink-0">{entry.timing_ms}ms</span>
                    {entry.vuln_count > 0 && (
                      <span className="text-[8px] font-black text-red-500 bg-red-500/10 px-1.5 py-0.5 rounded border border-red-500/20">
                        {entry.vuln_count}
                      </span>
                    )}
                    <ArrowRight className="w-3 h-3 text-muted-foreground/60 opacity-0 group-hover:opacity-100 transition-opacity" />
                  </button>
                ))}
              </div>
            )}
          </div>
        )}

        {/* COMPARE PANEL */}
        {activePanel === "compare" && (
          <div className="bg-card border border-border rounded-2xl overflow-hidden">
            <div className="flex items-center gap-2 px-4 py-3 border-b border-border">
              <GitCompare className="w-4 h-4 text-blue-500/60" />
              <span className="text-[10px] font-black text-muted-foreground uppercase tracking-widest">Replay Comparison</span>
            </div>

            {!compareResult ? (
              <div className="p-10 flex flex-col items-center gap-3">
                <GitCompare className="w-8 h-8 text-muted-foreground/20" />
                <p className="text-[10px] text-muted-foreground font-bold uppercase tracking-widest">
                  Send a request, then click Replay to compare
                </p>
              </div>
            ) : (
              <div className="p-4 space-y-4">
                <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                  {/* Summary Cards */}
                  <div className="grid grid-cols-2 gap-4">
                    <div className="bg-muted border border-border rounded-xl p-4 space-y-2">
                      <p className="text-[9px] font-black text-muted-foreground uppercase tracking-widest">Original</p>
                      <div className="space-y-1">
                        <div className="flex justify-between">
                          <span className="text-[9px] text-muted-foreground/60">Status</span>
                          <StatusBadge code={compareResult.original.status} />
                        </div>
                        <div className="flex justify-between">
                          <span className="text-[9px] text-muted-foreground/60">Size</span>
                          <span className="text-[10px] font-mono text-muted-foreground">{compareResult.original.body_size}B</span>
                        </div>
                        <div className="flex justify-between">
                          <span className="text-[9px] text-muted-foreground/60">Time</span>
                          <span className="text-[10px] font-mono text-muted-foreground">{compareResult.original.timing_ms}ms</span>
                        </div>
                      </div>
                    </div>

                    <div className="bg-muted border border-border rounded-xl p-4 space-y-2">
                      <p className="text-[9px] font-black text-blue-500 uppercase tracking-widest">Replayed</p>
                      <div className="space-y-1">
                        <div className="flex justify-between">
                          <span className="text-[9px] text-muted-foreground/60">Status</span>
                          <StatusBadge code={compareResult.replayed.status} />
                        </div>
                        <div className="flex justify-between">
                          <span className="text-[9px] text-muted-foreground/60">Size</span>
                          <span className="text-[10px] font-mono text-muted-foreground">{compareResult.replayed.body_size}B</span>
                        </div>
                        <div className="flex justify-between">
                          <span className="text-[9px] text-muted-foreground/60">Time</span>
                          <span className="text-[10px] font-mono text-muted-foreground">{compareResult.replayed.timing_ms}ms</span>
                        </div>
                      </div>
                    </div>
                  </div>

                  {/* Diff Analysis */}
                  <div className="bg-muted border border-border rounded-xl p-4 space-y-2">
                    <p className="text-[9px] font-black text-muted-foreground uppercase tracking-widest">Diff Analysis</p>
                    <div className="grid grid-cols-2 gap-3">
                      <div className="flex items-center gap-2">
                        <div className={cn("w-2 h-2 rounded-full", compareResult.diff.status_changed ? "bg-red-500" : "bg-primary")} />
                        <span className="text-[10px] text-muted-foreground">
                          Status {compareResult.diff.status_changed ? "changed" : "same"}
                        </span>
                      </div>
                      <div className="flex items-center gap-2">
                        <span className="text-[10px] text-muted-foreground">
                          Size delta: <span className={cn("font-black", compareResult.diff.size_delta !== 0 ? "text-yellow-500" : "text-muted-foreground/40")}>{compareResult.diff.size_delta > 0 ? "+" : ""}{compareResult.diff.size_delta}B</span>
                        </span>
                      </div>
                      <div className="flex items-center gap-2">
                        <span className="text-[10px] text-muted-foreground">
                          Timing delta: <span className="font-black text-foreground">{compareResult.diff.timing_delta_ms > 0 ? "+" : ""}{compareResult.diff.timing_delta_ms}ms</span>
                        </span>
                      </div>
                      <div className="flex items-center gap-2">
                        <span className="text-[10px] text-muted-foreground">
                          Body similarity: <span className={cn("font-black", compareResult.diff.body_similarity >= 0.95 ? "text-primary" : compareResult.diff.body_similarity >= 0.7 ? "text-yellow-500" : "text-red-500")}>{Math.round(compareResult.diff.body_similarity * 100)}%</span>
                        </span>
                      </div>
                    </div>
                  </div>
                </div>
              </div>
            )}
          </div>
        )}

        {/* AI PANELS — delegated to separate components */}
        {activePanel === "ai-assistant" && (
          <AIAttackAssistant
            method={method}
            url={url}
            headers={Object.fromEntries(headerItems.filter(h => h.enabled && h.key.trim()).map(h => [h.key, h.value]))}
            cookies={Object.fromEntries(cookieItems.filter(c => c.enabled && c.key.trim()).map(c => [c.key, c.value]))}
            params={Object.fromEntries(paramItems.filter(p => p.enabled && p.key.trim()).map(p => [p.key, p.value]))}
            body={bodyContent}
            onSelectPayload={handleSelectPayload}
          />
        )}
        {activePanel === "payloads" && (
          <AIPayloadGenerator
            onSelectPayload={(payload: string) => handleSelectPayload(payload, "", "body")}
          />
        )}
        {activePanel === "fuzzer" && (
          <AdaptiveFuzzer
            url={url}
            method={method}
            headers={Object.fromEntries(headerItems.filter(h => h.enabled && h.key.trim()).map(h => [h.key, h.value]))}
            cookies={Object.fromEntries(cookieItems.filter(c => c.enabled && c.key.trim()).map(c => [c.key, c.value]))}
            params={Object.fromEntries(paramItems.filter(p => p.enabled && p.key.trim()).map(p => [p.key, p.value]))}
            body={bodyContent}
            initialParam={fuzzTargetParam}
            initialLocation={fuzzTargetLocation}
            onSelectPayload={(payload: string, param: string) => handleSelectPayload(payload, param, fuzzTargetLocation)}
          />
        )}
        {activePanel === "verify" && (
          <VulnConfirmation
            vulnType=""
            targetValue=""
            endpoint={url}
            parameter=""
            onRunPayload={(payload: string) => handleSelectPayload(payload, "", "body")}
          />
        )}
        {activePanel === "intel" && response?.response && (
          <ResponseIntelligence
            statusCode={response.response.status_code}
            headers={response.response.headers || {}}
            body={response.response.body || ""}
            requestBody={bodyContent}
            targetUrl={url}
          />
        )}
        {activePanel === "intel" && !response?.response && (activePanel === "intel") && (
          <div className="bg-card border border-border rounded-2xl p-10 flex flex-col items-center gap-3">
            <Eye className="w-8 h-8 text-muted-foreground/20" />
            <p className="text-[10px] text-muted-foreground font-bold uppercase tracking-widest">Send a request first to analyze response</p>
          </div>
        )}
        {activePanel === "attack-graph" && (
          <AttackGraph target={url} findings={collectedFindings} />
        )}
        {activePanel === "dashboard" && (
          <AttackDashboard />
        )}
      </div>
    </div>
  );
}
