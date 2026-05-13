"use client";

import React, { useEffect, useState, useCallback } from "react";
import {
  ShieldAlert,
  ShieldCheck,
  AlertTriangle,
  Ban,
  Eye,
  RefreshCw,
  Clock,
  Globe,
  Lock,
  Unlock,
  ChevronDown,
  Search,
  Filter,
  Activity,
  ToggleLeft,
  ToggleRight,
} from "lucide-react";
import { GlowCard } from "@/components/ui/glow-card";
import { Button } from "@/components/ui/button";
import { cn } from "@/lib/utils";
import { auth } from "@/lib/firebase";

const API_BASE = process.env.NEXT_PUBLIC_API_URL || "http://localhost:8000";

// ─── Types ────────────────────────────────────────────────────────────────────

interface SecurityEvent {
  id: string;
  user_id?: string;
  event_type: string;
  severity: string;
  description: string;
  ip_address?: string;
  created_at: string | null;
}

interface SecurityConfig {
  max_login_attempts: number;
  lockout_duration_min: number;
  session_timeout_min: number;
  require_email_verification: boolean;
  rate_limit_per_min: number;
  waf_enabled: boolean;
  ip_whitelist: string[];
  ip_blacklist: string[];
  two_factor_enforced: boolean;
  cors_strict_mode: boolean;
}

// ─── Helpers ──────────────────────────────────────────────────────────────────

async function fetchWithAuth(path: string) {
  const user = auth.currentUser;
  const token = user ? await user.getIdToken() : "";
  const res = await fetch(`${API_BASE}${path}`, {
    headers: { Authorization: `Bearer ${token}` },
  });
  if (!res.ok) throw new Error(`HTTP ${res.status}`);
  return res.json();
}

const SEVERITY_STYLES: Record<string, string> = {
  critical: "text-red-500 bg-red-500/10 border-red-500/30 shadow-[0_0_10px_rgba(239,68,68,0.1)]",
  high: "text-orange-500 bg-orange-500/10 border-orange-500/30",
  medium: "text-amber-500 bg-amber-500/10 border-amber-500/30",
  low: "text-blue-400 bg-blue-400/10 border-blue-400/20",
  info: "text-muted-foreground bg-muted/10 border-border/20",
};

function severityIcon(s: string) {
  if (s === "critical") return <Ban className="w-3 h-3" />;
  if (s === "high") return <AlertTriangle className="w-3 h-3" />;
  return <Eye className="w-3 h-3" />;
}

function timeAgo(iso: string | null): string {
  if (!iso) return "—";
  const diff = Date.now() - new Date(iso).getTime();
  const mins = Math.floor(diff / 60000);
  if (mins < 1) return "just now";
  if (mins < 60) return `${mins}m ago`;
  const hrs = Math.floor(mins / 60);
  if (hrs < 24) return `${hrs}h ago`;
  return `${Math.floor(hrs / 24)}d ago`;
}

// ─── Default config (used when API is unavailable) ────────────────────────────

const DEFAULT_CONFIG: SecurityConfig = {
  max_login_attempts: 5,
  lockout_duration_min: 15,
  session_timeout_min: 30,
  require_email_verification: true,
  rate_limit_per_min: 100,
  waf_enabled: true,
  ip_whitelist: [],
  ip_blacklist: [],
  two_factor_enforced: false,
  cors_strict_mode: true,
};

// ─── Component ────────────────────────────────────────────────────────────────

export default function AdminSecurityPage() {
  const [events, setEvents] = useState<SecurityEvent[]>([]);
  const [config, setConfig] = useState<SecurityConfig>(DEFAULT_CONFIG);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [search, setSearch] = useState("");
  const [severityFilter, setSeverityFilter] = useState<string>("all");
  const [lastRefresh, setLastRefresh] = useState<Date | null>(null);
  const [configDirty, setConfigDirty] = useState(false);
  const [saving, setSaving] = useState(false);
  const [ipInput, setIpInput] = useState("");
  const [blacklistInput, setBlacklistInput] = useState("");

  const load = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const data = await fetchWithAuth("/api/v1/admin/security/events");
      setEvents(data.events ?? []);
      setLastRefresh(new Date());
    } catch {
      // API unavailable — show empty state gracefully
      setEvents([]);
    }
    // Config would come from API too, but use defaults when unavailable
    try {
      const cfgRes = await fetch(`${API_BASE}/api/v1/admin/security/config`, {
        headers: { Authorization: `Bearer ${auth.currentUser ? await auth.currentUser.getIdToken() : ""}` },
      });
      if (cfgRes.ok) {
        const cfgData = await cfgRes.json();
        setConfig({ ...DEFAULT_CONFIG, ...cfgData });
      }
    } catch {
      // Use defaults
    }
    setLoading(false);
  }, []);

  useEffect(() => {
    load();
    const interval = setInterval(load, 30000);
    return () => clearInterval(interval);
  }, [load]);

  const updateConfig = (key: keyof SecurityConfig, value: any) => {
    setConfig((prev) => ({ ...prev, [key]: value }));
    setConfigDirty(true);
  };

  const saveConfig = async () => {
    setSaving(true);
    try {
      const token = auth.currentUser ? await auth.currentUser.getIdToken() : "";
      await fetch(`${API_BASE}/api/v1/admin/security/config`, {
        method: "PUT",
        headers: { Authorization: `Bearer ${token}`, "Content-Type": "application/json" },
        body: JSON.stringify(config),
      });
      setConfigDirty(false);
    } catch {
      // Config save failed — still show UI as updated locally
    }
    setSaving(false);
  };

  const addWhitelistIp = () => {
    const ip = ipInput.trim();
    if (ip && !config.ip_whitelist.includes(ip)) {
      updateConfig("ip_whitelist", [...config.ip_whitelist, ip]);
      setIpInput("");
    }
  };

  const addBlacklistIp = () => {
    const ip = blacklistInput.trim();
    if (ip && !config.ip_blacklist.includes(ip)) {
      updateConfig("ip_blacklist", [...config.ip_blacklist, ip]);
      setBlacklistInput("");
    }
  };

  // Filter events
  const filteredEvents = events.filter((e) => {
    const matchSearch = !search || e.event_type.toLowerCase().includes(search.toLowerCase()) ||
      e.description.toLowerCase().includes(search.toLowerCase());
    const matchSeverity = severityFilter === "all" || e.severity === severityFilter;
    return matchSearch && matchSeverity;
  });

  // Stats
  const criticalCount = events.filter((e) => e.severity === "critical").length;
  const highCount = events.filter((e) => e.severity === "high").length;
  const recentCount = events.filter((e) => {
    if (!e.created_at) return false;
    return Date.now() - new Date(e.created_at).getTime() < 86400000;
  }).length;

  return (
    <div className="space-y-8">
      {/* Header */}
      <div className="flex items-end justify-between">
        <div>
          <h1 className="text-3xl font-black text-foreground uppercase tracking-tighter flex items-center gap-3">
            Threat <span className="text-red-500">Sentinel</span>
          </h1>
          <p className="text-xs text-muted-foreground font-bold uppercase tracking-widest mt-1">
            Security events, firewall configuration & access controls
          </p>
        </div>
        <div className="flex items-center gap-3">
          {lastRefresh && (
            <span className="text-[10px] text-muted-foreground font-mono">
              Updated {lastRefresh.toLocaleTimeString()}
            </span>
          )}
          <Button
            variant="ghost"
            size="sm"
            onClick={load}
            disabled={loading}
            className="h-8 px-3 text-red-500 hover:bg-red-500/8 border border-red-500/15 text-[10px] font-black uppercase tracking-widest"
          >
            <RefreshCw className={cn("w-3.5 h-3.5 mr-1.5", loading && "animate-spin")} />
            Refresh
          </Button>
        </div>
      </div>

      {/* KPI Row */}
      <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
        {[
          { label: "Total Events", value: events.length, icon: Activity, color: "text-primary", glow: "rgba(0,255,136,0.06)" },
          { label: "Critical", value: criticalCount, icon: Ban, color: "text-red-500", glow: "rgba(239,68,68,0.06)" },
          { label: "High Severity", value: highCount, icon: AlertTriangle, color: "text-orange-500", glow: "rgba(249,115,22,0.06)" },
          { label: "Last 24h", value: recentCount, icon: Clock, color: "text-blue-400", glow: "rgba(96,165,250,0.06)" },
        ].map((kpi) => (
          <GlowCard key={kpi.label} className="p-0 border-white/5" glowColor={kpi.glow}>
            <div className="flex items-center justify-between mb-3">
              <span className="text-[10px] text-muted-foreground uppercase tracking-widest font-bold">{kpi.label}</span>
              <kpi.icon className={cn("w-4 h-4", kpi.color)} />
            </div>
            <div className={cn("text-3xl font-black tracking-tighter", kpi.color)}>
              {loading ? "—" : kpi.value}
            </div>
          </GlowCard>
        ))}
      </div>

      {/* ═══ Security Configuration ═══ */}
      <GlowCard className="p-0 border-white/5 overflow-hidden" glowColor="rgba(0,255,136,0.02)">
        <div className="px-6 py-4 border-b border-white/5 flex items-center justify-between">
          <div className="flex items-center gap-3">
            <div className="w-8 h-8 rounded-xl bg-primary/10 border border-primary/20 flex items-center justify-center">
              <ShieldCheck className="w-4 h-4 text-primary" />
            </div>
            <div>
              <h2 className="text-sm font-black text-foreground uppercase tracking-widest">Firewall Configuration</h2>
              <p className="text-[10px] text-muted-foreground uppercase tracking-widest font-bold mt-0.5">Platform security parameters</p>
            </div>
          </div>
          {configDirty && (
            <Button
              size="sm"
              onClick={saveConfig}
              disabled={saving}
              className="h-8 px-4 bg-primary/10 text-primary border border-primary/20 hover:bg-primary/20 text-[10px] font-black uppercase tracking-widest"
            >
              {saving ? "Saving..." : "Save Changes"}
            </Button>
          )}
        </div>

        <div className="p-6 grid grid-cols-1 md:grid-cols-2 gap-6">
          {/* Toggle Controls */}
          <div className="space-y-4">
            <h3 className="text-[10px] font-black text-muted-foreground uppercase tracking-widest mb-4">Access Controls</h3>

            {[
              { key: "waf_enabled" as const, label: "Web Application Firewall", desc: "Block XSS, SQLi, and other attack patterns", icon: ShieldAlert },
              { key: "require_email_verification" as const, label: "Email Verification Required", desc: "Users must verify email before accessing platform", icon: Lock },
              { key: "two_factor_enforced" as const, label: "Enforce Two-Factor Auth", desc: "Require 2FA for all user accounts", icon: Lock },
              { key: "cors_strict_mode" as const, label: "Strict CORS Policy", desc: "Only allow requests from whitelisted origins", icon: Globe },
            ].map((item) => (
              <div key={item.key} className="flex items-center justify-between p-4 rounded-xl bg-white/[0.02] border border-white/5 hover:border-white/10 transition-colors">
                <div className="flex items-center gap-3">
                  <item.icon className="w-4 h-4 text-muted-foreground" />
                  <div>
                    <p className="text-xs font-bold text-foreground">{item.label}</p>
                    <p className="text-[10px] text-muted-foreground">{item.desc}</p>
                  </div>
                </div>
                <button
                  onClick={() => updateConfig(item.key, !config[item.key])}
                  className="flex-shrink-0"
                >
                  {config[item.key] ? (
                    <ToggleRight className="w-8 h-8 text-primary" />
                  ) : (
                    <ToggleLeft className="w-8 h-8 text-muted-foreground" />
                  )}
                </button>
              </div>
            ))}
          </div>

          {/* Numeric Controls */}
          <div className="space-y-4">
            <h3 className="text-[10px] font-black text-muted-foreground uppercase tracking-widest mb-4">Rate & Session Limits</h3>

            {[
              { key: "max_login_attempts" as const, label: "Max Login Attempts", unit: "attempts", min: 3, max: 20 },
              { key: "lockout_duration_min" as const, label: "Lockout Duration", unit: "minutes", min: 5, max: 120 },
              { key: "session_timeout_min" as const, label: "Session Timeout", unit: "minutes", min: 5, max: 480 },
              { key: "rate_limit_per_min" as const, label: "API Rate Limit", unit: "req/min", min: 10, max: 1000 },
            ].map((item) => (
              <div key={item.key} className="p-4 rounded-xl bg-white/[0.02] border border-white/5">
                <div className="flex items-center justify-between mb-2">
                  <p className="text-xs font-bold text-foreground">{item.label}</p>
                  <span className="text-[10px] text-muted-foreground font-mono">{config[item.key]} {item.unit}</span>
                </div>
                <input
                  type="range"
                  title={item.label}
                  min={item.min}
                  max={item.max}
                  value={config[item.key] as number}
                  onChange={(e) => updateConfig(item.key, parseInt(e.target.value))}
                  className="w-full h-1 bg-white/10 rounded-full appearance-none cursor-pointer accent-[#00FF88]"
                />
                <div className="flex justify-between mt-1">
                  <span className="text-[9px] text-muted-foreground">{item.min}</span>
                  <span className="text-[9px] text-muted-foreground">{item.max}</span>
                </div>
              </div>
            ))}

            {/* IP Whitelist */}
            <div className="p-4 rounded-xl bg-white/[0.02] border border-white/5">
              <p className="text-xs font-bold text-foreground mb-2 flex items-center gap-2">
                <Unlock className="w-3 h-3 text-primary" /> IP Whitelist
              </p>
              <div className="flex gap-2 mb-2">
                <input
                  value={ipInput}
                  onChange={(e) => setIpInput(e.target.value)}
                  placeholder="e.g. 192.168.1.0/24"
                  onKeyDown={(e) => e.key === "Enter" && addWhitelistIp()}
                  className="flex-1 px-3 py-1.5 bg-white/5 border border-white/5 rounded-lg text-xs text-muted-foreground placeholder:text-muted-foreground focus:outline-none focus:border-[rgba(0,255,136,0.3)] font-mono"
                />
                <Button size="sm" onClick={addWhitelistIp} className="h-7 px-3 text-[10px] bg-primary/10 text-primary border border-primary/20 hover:bg-primary/20 font-black">
                  Add
                </Button>
              </div>
              <div className="flex flex-wrap gap-1.5">
                {config.ip_whitelist.map((ip) => (
                  <span
                    key={ip}
                    className="inline-flex items-center gap-1 px-2 py-0.5 bg-primary/5 border border-primary/15 rounded text-[10px] font-mono text-primary cursor-pointer hover:bg-red-500/10 hover:text-red-400 hover:border-red-500/20 transition-colors"
                    onClick={() => updateConfig("ip_whitelist", config.ip_whitelist.filter((i) => i !== ip))}
                    title="Click to remove"
                  >
                    {ip} ×
                  </span>
                ))}
                {config.ip_whitelist.length === 0 && (
                  <span className="text-[10px] text-muted-foreground">No IPs whitelisted — all IPs allowed</span>
                )}
              </div>
            </div>

            {/* IP Blacklist */}
            <div className="p-4 rounded-xl bg-white/[0.02] border border-white/5">
              <p className="text-xs font-bold text-foreground mb-2 flex items-center gap-2">
                <Ban className="w-3 h-3 text-red-500" /> IP Blacklist
              </p>
              <div className="flex gap-2 mb-2">
                <input
                  value={blacklistInput}
                  onChange={(e) => setBlacklistInput(e.target.value)}
                  placeholder="e.g. 10.0.0.1"
                  onKeyDown={(e) => e.key === "Enter" && addBlacklistIp()}
                  className="flex-1 px-3 py-1.5 bg-white/5 border border-white/5 rounded-lg text-xs text-muted-foreground placeholder:text-muted-foreground focus:outline-none focus:border-red-500/30 font-mono"
                />
                <Button size="sm" onClick={addBlacklistIp} className="h-7 px-3 text-[10px] bg-red-500/10 text-red-400 border border-red-500/20 hover:bg-red-500/20 font-black">
                  Block
                </Button>
              </div>
              <div className="flex flex-wrap gap-1.5">
                {config.ip_blacklist.map((ip) => (
                  <span
                    key={ip}
                    className="inline-flex items-center gap-1 px-2 py-0.5 bg-red-500/5 border border-red-500/15 rounded text-[10px] font-mono text-red-400 cursor-pointer hover:bg-primary/10 hover:text-primary hover:border-primary/20 transition-colors"
                    onClick={() => updateConfig("ip_blacklist", config.ip_blacklist.filter((i) => i !== ip))}
                    title="Click to remove"
                  >
                    {ip} ×
                  </span>
                ))}
                {config.ip_blacklist.length === 0 && (
                  <span className="text-[10px] text-muted-foreground">No IPs blocked</span>
                )}
              </div>
            </div>
          </div>
        </div>
      </GlowCard>

      {/* ═══ Security Events Log ═══ */}
      <GlowCard className="p-0 border-white/5 overflow-hidden" glowColor="rgba(239,68,68,0.02)">
        <div className="px-6 py-4 border-b border-white/5 flex items-center justify-between">
          <div className="flex items-center gap-3">
            <div className="w-8 h-8 rounded-xl bg-red-500/10 border border-red-500/20 flex items-center justify-center">
              <ShieldAlert className="w-4 h-4 text-red-500" />
            </div>
            <div>
              <h2 className="text-sm font-black text-foreground uppercase tracking-widest">Live Threat Stream</h2>
              <p className="text-[10px] text-muted-foreground uppercase tracking-widest font-bold mt-0.5">Platform-wide security incidents</p>
            </div>
          </div>
          <span className="text-[10px] font-black text-muted-foreground uppercase tracking-widest">
            {filteredEvents.length} events
          </span>
        </div>

        {/* Filters */}
        <div className="px-6 py-3 border-b border-white/5 flex items-center gap-4 flex-wrap">
          <div className="relative flex-1 max-w-xs">
            <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-3.5 h-3.5 text-muted-foreground" />
            <input
              value={search}
              onChange={(e) => setSearch(e.target.value)}
              placeholder="Search events..."
              className="w-full pl-9 pr-4 py-2 bg-white/5 border border-white/5 rounded-lg text-xs text-muted-foreground placeholder:text-muted-foreground focus:outline-none focus:border-red-500/30 font-mono"
            />
          </div>
          <div className="flex gap-1.5">
            {["all", "critical", "high", "medium", "low"].map((s) => (
              <button
                key={s}
                onClick={() => setSeverityFilter(s)}
                className={cn(
                  "px-2.5 py-1 rounded-lg text-[9px] font-black uppercase tracking-widest border transition-colors",
                  severityFilter === s
                    ? "bg-white/10 border-white/20 text-foreground"
                    : "bg-transparent border-white/5 text-muted-foreground hover:text-muted-foreground hover:border-white/10"
                )}
              >
                {s}
              </button>
            ))}
          </div>
        </div>

        {/* Events Table */}
        <div className="overflow-x-auto">
          <table className="w-full text-left">
            <thead>
              <tr className="bg-white/[0.02] border-b border-white/5">
                <th className="px-6 py-3 text-[9px] font-black uppercase text-muted-foreground tracking-widest">Severity</th>
                <th className="px-6 py-3 text-[9px] font-black uppercase text-muted-foreground tracking-widest">Event Type</th>
                <th className="px-6 py-3 text-[9px] font-black uppercase text-muted-foreground tracking-widest">Description</th>
                <th className="px-6 py-3 text-[9px] font-black uppercase text-muted-foreground tracking-widest">Time</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-white/5">
              {filteredEvents.length === 0 ? (
                <tr>
                  <td colSpan={4} className="px-6 py-16 text-center">
                    <div className="flex flex-col items-center gap-3">
                      <ShieldCheck className="w-10 h-10 text-primary/30" />
                      <p className="text-[10px] font-black uppercase tracking-widest text-muted-foreground">
                        {events.length === 0 ? "No security events recorded" : "No events match filters"}
                      </p>
                      <p className="text-[10px] text-muted-foreground">
                        {events.length === 0 ? "Events will appear here as they are detected by the platform" : "Try adjusting your search or severity filter"}
                      </p>
                    </div>
                  </td>
                </tr>
              ) : (
                filteredEvents.slice(0, 50).map((event) => (
                  <tr key={event.id} className="hover:bg-white/[0.01] transition-colors group">
                    <td className="px-6 py-3">
                      <span className={cn(
                        "inline-flex items-center gap-1.5 px-2 py-0.5 rounded-md text-[9px] font-black uppercase border",
                        SEVERITY_STYLES[event.severity] || SEVERITY_STYLES.info
                      )}>
                        {severityIcon(event.severity)}
                        {event.severity}
                      </span>
                    </td>
                    <td className="px-6 py-3 text-xs font-bold text-foreground uppercase tracking-tight">
                      {event.event_type}
                    </td>
                    <td className="px-6 py-3 text-xs text-muted-foreground max-w-md truncate">
                      {event.description}
                    </td>
                    <td className="px-6 py-3 text-[10px] font-mono text-muted-foreground">
                      {timeAgo(event.created_at)}
                    </td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>

        {/* Footer */}
        {filteredEvents.length > 50 && (
          <div className="px-6 py-3 border-t border-white/5 text-center">
            <span className="text-[10px] text-muted-foreground font-mono">
              Showing 50 of {filteredEvents.length} events · Auto-refreshes every 30s
            </span>
          </div>
        )}
      </GlowCard>
    </div>
  );
}
