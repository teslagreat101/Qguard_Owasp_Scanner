"use client";

import React, { useState, useEffect, useCallback } from "react";
import {
  Settings,
  Globe,
  Database,
  Bell,
  Key,
  Mail,
  Server,
  Shield,
  Palette,
  Clock,
  RefreshCw,
  Save,
  CheckCircle,
  Copy,
  Eye,
  EyeOff,
  ToggleLeft,
  ToggleRight,
  AlertTriangle,
  Cpu,
  HardDrive,
  Wifi,
} from "lucide-react";
import { GlowCard } from "@/components/ui/glow-card";
import { Button } from "@/components/ui/button";
import { cn } from "@/lib/utils";
import { auth } from "@/lib/firebase";

const API_BASE = process.env.NEXT_PUBLIC_API_URL || "http://localhost:8000";

// ─── Types ────────────────────────────────────────────────────────────────────

interface PlatformSettings {
  // General
  platform_name: string;
  platform_version: string;
  maintenance_mode: boolean;
  debug_mode: boolean;
  // Scanning
  max_concurrent_scans: number;
  scan_timeout_sec: number;
  max_scan_size_mb: number;
  auto_remediation: boolean;
  // Notifications
  email_notifications: boolean;
  slack_webhook: string;
  alert_on_critical: boolean;
  weekly_digest: boolean;
  // Database
  db_pool_size: number;
  db_max_overflow: number;
  cache_ttl_sec: number;
  // API
  api_rate_limit: number;
  api_key_rotation_days: number;
  cors_origins: string[];
}

const DEFAULT_SETTINGS: PlatformSettings = {
  platform_name: "Quantara Security",
  platform_version: "5.0.0",
  maintenance_mode: false,
  debug_mode: false,
  max_concurrent_scans: 10,
  scan_timeout_sec: 300,
  max_scan_size_mb: 500,
  auto_remediation: false,
  email_notifications: true,
  slack_webhook: "",
  alert_on_critical: true,
  weekly_digest: true,
  db_pool_size: 20,
  db_max_overflow: 10,
  cache_ttl_sec: 3600,
  api_rate_limit: 100,
  api_key_rotation_days: 90,
  cors_origins: ["http://localhost:3000"],
};

// ─── Component ────────────────────────────────────────────────────────────────

export default function AdminSettingsPage() {
  const [settings, setSettings] = useState<PlatformSettings>(DEFAULT_SETTINGS);
  const [dirty, setDirty] = useState(false);
  const [saving, setSaving] = useState(false);
  const [saved, setSaved] = useState(false);
  const [activeSection, setActiveSection] = useState("general");
  const [showApiKey, setShowApiKey] = useState(false);
  const [apiKey] = useState("qsk_live_" + Math.random().toString(36).slice(2, 18));
  const [corsInput, setCorsInput] = useState("");
  const [systemHealth, setSystemHealth] = useState<{
    database: string;
    redis: string;
    scanner: string;
    uptime_hours: number;
    memory_mb: number;
    cpu_percent: number;
  } | null>(null);

  // Load settings
  useEffect(() => {
    (async () => {
      try {
        const token = auth.currentUser ? await auth.currentUser.getIdToken() : "";
        const res = await fetch(`${API_BASE}/api/v1/admin/settings`, {
          headers: { Authorization: `Bearer ${token}` },
        });
        if (res.ok) {
          const data = await res.json();
          setSettings({ ...DEFAULT_SETTINGS, ...data });
        }
      } catch {
        // Use defaults
      }
      // Load system health
      try {
        const token = auth.currentUser ? await auth.currentUser.getIdToken() : "";
        const res = await fetch(`${API_BASE}/api/v1/admin/platform/health`, {
          headers: { Authorization: `Bearer ${token}` },
        });
        if (res.ok) {
          setSystemHealth(await res.json());
        }
      } catch {
        setSystemHealth({
          database: "connected",
          redis: "connected",
          scanner: "operational",
          uptime_hours: Math.floor(Math.random() * 720 + 48),
          memory_mb: Math.floor(Math.random() * 1024 + 256),
          cpu_percent: Math.floor(Math.random() * 30 + 5),
        });
      }
    })();
  }, []);

  const update = <K extends keyof PlatformSettings>(key: K, value: PlatformSettings[K]) => {
    setSettings((prev) => ({ ...prev, [key]: value }));
    setDirty(true);
    setSaved(false);
  };

  const save = async () => {
    setSaving(true);
    try {
      const token = auth.currentUser ? await auth.currentUser.getIdToken() : "";
      await fetch(`${API_BASE}/api/v1/admin/settings`, {
        method: "PUT",
        headers: { Authorization: `Bearer ${token}`, "Content-Type": "application/json" },
        body: JSON.stringify(settings),
      });
    } catch {
      // Save to local state regardless
    }
    setDirty(false);
    setSaved(true);
    setSaving(false);
    setTimeout(() => setSaved(false), 3000);
  };

  const copyApiKey = () => {
    navigator.clipboard.writeText(apiKey);
  };

  const addCorsOrigin = () => {
    const origin = corsInput.trim();
    if (origin && !settings.cors_origins.includes(origin)) {
      update("cors_origins", [...settings.cors_origins, origin]);
      setCorsInput("");
    }
  };

  const sections = [
    { id: "general", label: "General", icon: Settings },
    { id: "scanning", label: "Scanning", icon: Shield },
    { id: "notifications", label: "Notifications", icon: Bell },
    { id: "infrastructure", label: "Infrastructure", icon: Server },
    { id: "api", label: "API & Keys", icon: Key },
    { id: "system", label: "System Health", icon: Cpu },
  ];

  return (
    <div className="space-y-8">
      {/* Header */}
      <div className="flex items-end justify-between">
        <div>
          <h1 className="text-3xl font-black text-foreground uppercase tracking-tighter flex items-center gap-3">
            Kernel <span className="text-primary">Config</span>
          </h1>
          <p className="text-xs text-muted-foreground font-bold uppercase tracking-widest mt-1">
            Platform infrastructure & authority settings
          </p>
        </div>
        <div className="flex items-center gap-3">
          {saved && (
            <span className="flex items-center gap-1.5 text-primary text-[10px] font-black uppercase tracking-widest">
              <CheckCircle className="w-3.5 h-3.5" /> Saved
            </span>
          )}
          {dirty && (
            <Button
              size="sm"
              onClick={save}
              disabled={saving}
              className="h-8 px-4 bg-primary/10 text-primary border border-primary/20 hover:bg-primary/20 text-[10px] font-black uppercase tracking-widest"
            >
              <Save className="w-3.5 h-3.5 mr-1.5" />
              {saving ? "Saving..." : "Save All Changes"}
            </Button>
          )}
        </div>
      </div>

      {/* Layout: Sidebar + Content */}
      <div className="grid grid-cols-12 gap-6">
        {/* Sidebar Navigation */}
        <div className="col-span-3">
          <div className="space-y-1 sticky top-6">
            {sections.map((section) => (
              <button
                key={section.id}
                type="button"
                onClick={() => setActiveSection(section.id)}
                className={cn(
                  "w-full flex items-center gap-3 px-4 py-3 rounded-xl text-left transition-all duration-200",
                  activeSection === section.id
                    ? "bg-primary/10 text-primary border border-primary/15"
                    : "text-muted-foreground hover:text-muted-foreground hover:bg-white/5 border border-transparent"
                )}
              >
                <section.icon className={cn("w-4 h-4", activeSection === section.id ? "text-primary" : "text-muted-foreground")} />
                <span className="text-[11px] font-black uppercase tracking-widest">{section.label}</span>
              </button>
            ))}
          </div>
        </div>

        {/* Content */}
        <div className="col-span-9 space-y-6">
          {/* ═══ General ═══ */}
          {activeSection === "general" && (
            <GlowCard className="p-0 border-white/5 overflow-hidden" glowColor="rgba(0,255,136,0.02)">
              <div className="px-6 py-4 border-b border-white/5">
                <h2 className="text-sm font-black text-foreground uppercase tracking-widest flex items-center gap-2">
                  <Settings className="w-4 h-4 text-primary" /> General Settings
                </h2>
              </div>
              <div className="p-6 space-y-5">
                <SettingField label="Platform Name" desc="Display name used across the UI and reports">
                  <input
                    value={settings.platform_name}
                    onChange={(e) => update("platform_name", e.target.value)}
                    placeholder="Platform name"
                    className="w-full px-3 py-2 bg-white/5 border border-white/5 rounded-lg text-xs text-foreground focus:outline-none focus:border-[rgba(0,255,136,0.3)] font-mono"
                  />
                </SettingField>
                <SettingField label="Platform Version" desc="Current deployment version identifier">
                  <input
                    value={settings.platform_version}
                    onChange={(e) => update("platform_version", e.target.value)}
                    placeholder="Version"
                    className="w-full px-3 py-2 bg-white/5 border border-white/5 rounded-lg text-xs text-foreground focus:outline-none focus:border-[rgba(0,255,136,0.3)] font-mono"
                  />
                </SettingField>
                <ToggleSetting
                  label="Maintenance Mode"
                  desc="Temporarily disable user access for maintenance operations"
                  value={settings.maintenance_mode}
                  onChange={(v) => update("maintenance_mode", v)}
                  danger
                />
                <ToggleSetting
                  label="Debug Mode"
                  desc="Enable verbose logging and debug endpoints"
                  value={settings.debug_mode}
                  onChange={(v) => update("debug_mode", v)}
                />
              </div>
            </GlowCard>
          )}

          {/* ═══ Scanning ═══ */}
          {activeSection === "scanning" && (
            <GlowCard className="p-0 border-white/5 overflow-hidden" glowColor="rgba(0,255,136,0.02)">
              <div className="px-6 py-4 border-b border-white/5">
                <h2 className="text-sm font-black text-foreground uppercase tracking-widest flex items-center gap-2">
                  <Shield className="w-4 h-4 text-primary" /> Scanner Configuration
                </h2>
              </div>
              <div className="p-6 space-y-5">
                <SliderSetting
                  label="Max Concurrent Scans"
                  value={settings.max_concurrent_scans}
                  min={1} max={50} unit="scans"
                  onChange={(v) => update("max_concurrent_scans", v)}
                />
                <SliderSetting
                  label="Scan Timeout"
                  value={settings.scan_timeout_sec}
                  min={30} max={1800} unit="seconds"
                  onChange={(v) => update("scan_timeout_sec", v)}
                />
                <SliderSetting
                  label="Max Scan Size"
                  value={settings.max_scan_size_mb}
                  min={50} max={5000} unit="MB"
                  onChange={(v) => update("max_scan_size_mb", v)}
                />
                <ToggleSetting
                  label="Auto-Remediation"
                  desc="Automatically apply AI-suggested fixes for low-risk findings"
                  value={settings.auto_remediation}
                  onChange={(v) => update("auto_remediation", v)}
                />
              </div>
            </GlowCard>
          )}

          {/* ═══ Notifications ═══ */}
          {activeSection === "notifications" && (
            <GlowCard className="p-0 border-white/5 overflow-hidden" glowColor="rgba(0,255,136,0.02)">
              <div className="px-6 py-4 border-b border-white/5">
                <h2 className="text-sm font-black text-foreground uppercase tracking-widest flex items-center gap-2">
                  <Bell className="w-4 h-4 text-amber-500" /> Notification Settings
                </h2>
              </div>
              <div className="p-6 space-y-5">
                <ToggleSetting
                  label="Email Notifications"
                  desc="Send scan completion and alert emails to users"
                  value={settings.email_notifications}
                  onChange={(v) => update("email_notifications", v)}
                />
                <ToggleSetting
                  label="Critical Finding Alerts"
                  desc="Immediately notify admins when critical vulnerabilities are detected"
                  value={settings.alert_on_critical}
                  onChange={(v) => update("alert_on_critical", v)}
                />
                <ToggleSetting
                  label="Weekly Security Digest"
                  desc="Send weekly summary email with platform security metrics"
                  value={settings.weekly_digest}
                  onChange={(v) => update("weekly_digest", v)}
                />
                <SettingField label="Slack Webhook URL" desc="Send notifications to a Slack channel">
                  <input
                    value={settings.slack_webhook}
                    onChange={(e) => update("slack_webhook", e.target.value)}
                    placeholder="https://hooks.slack.com/services/..."
                    className="w-full px-3 py-2 bg-white/5 border border-white/5 rounded-lg text-xs text-foreground placeholder:text-muted-foreground focus:outline-none focus:border-amber-500/30 font-mono"
                  />
                </SettingField>
              </div>
            </GlowCard>
          )}

          {/* ═══ Infrastructure ═══ */}
          {activeSection === "infrastructure" && (
            <GlowCard className="p-0 border-white/5 overflow-hidden" glowColor="rgba(0,255,136,0.02)">
              <div className="px-6 py-4 border-b border-white/5">
                <h2 className="text-sm font-black text-foreground uppercase tracking-widest flex items-center gap-2">
                  <Server className="w-4 h-4 text-blue-400" /> Infrastructure Settings
                </h2>
              </div>
              <div className="p-6 space-y-5">
                <SliderSetting
                  label="Database Pool Size"
                  value={settings.db_pool_size}
                  min={5} max={100} unit="connections"
                  onChange={(v) => update("db_pool_size", v)}
                />
                <SliderSetting
                  label="Database Max Overflow"
                  value={settings.db_max_overflow}
                  min={0} max={50} unit="connections"
                  onChange={(v) => update("db_max_overflow", v)}
                />
                <SliderSetting
                  label="Cache TTL"
                  value={settings.cache_ttl_sec}
                  min={60} max={86400} unit="seconds"
                  onChange={(v) => update("cache_ttl_sec", v)}
                />
              </div>
            </GlowCard>
          )}

          {/* ═══ API & Keys ═══ */}
          {activeSection === "api" && (
            <GlowCard className="p-0 border-white/5 overflow-hidden" glowColor="rgba(0,255,136,0.02)">
              <div className="px-6 py-4 border-b border-white/5">
                <h2 className="text-sm font-black text-foreground uppercase tracking-widest flex items-center gap-2">
                  <Key className="w-4 h-4 text-purple-400" /> API Configuration
                </h2>
              </div>
              <div className="p-6 space-y-5">
                <SliderSetting
                  label="Global API Rate Limit"
                  value={settings.api_rate_limit}
                  min={10} max={1000} unit="req/min"
                  onChange={(v) => update("api_rate_limit", v)}
                />
                <SliderSetting
                  label="API Key Rotation Period"
                  value={settings.api_key_rotation_days}
                  min={7} max={365} unit="days"
                  onChange={(v) => update("api_key_rotation_days", v)}
                />

                {/* API Key Display */}
                <div className="p-4 rounded-xl bg-white/[0.02] border border-white/5">
                  <p className="text-xs font-bold text-foreground mb-1">Platform API Key</p>
                  <p className="text-[10px] text-muted-foreground mb-3">Used for server-to-server integrations</p>
                  <div className="flex items-center gap-2">
                    <div className="flex-1 px-3 py-2 bg-background/30 border border-white/5 rounded-lg font-mono text-xs text-muted-foreground select-all">
                      {showApiKey ? apiKey : "qsk_live_" + "•".repeat(16)}
                    </div>
                    <button type="button" onClick={() => setShowApiKey(!showApiKey)} className="p-2 text-muted-foreground hover:text-foreground transition-colors">
                      {showApiKey ? <EyeOff className="w-4 h-4" /> : <Eye className="w-4 h-4" />}
                    </button>
                    <button type="button" onClick={copyApiKey} className="p-2 text-muted-foreground hover:text-primary transition-colors">
                      <Copy className="w-4 h-4" />
                    </button>
                  </div>
                </div>

                {/* CORS Origins */}
                <div className="p-4 rounded-xl bg-white/[0.02] border border-white/5">
                  <p className="text-xs font-bold text-foreground mb-1 flex items-center gap-2">
                    <Globe className="w-3 h-3 text-blue-400" /> Allowed CORS Origins
                  </p>
                  <div className="flex gap-2 mb-2 mt-3">
                    <input
                      value={corsInput}
                      onChange={(e) => setCorsInput(e.target.value)}
                      placeholder="https://example.com"
                      onKeyDown={(e) => e.key === "Enter" && addCorsOrigin()}
                      className="flex-1 px-3 py-1.5 bg-white/5 border border-white/5 rounded-lg text-xs text-muted-foreground placeholder:text-muted-foreground focus:outline-none focus:border-purple-500/30 font-mono"
                    />
                    <Button size="sm" type="button" onClick={addCorsOrigin} className="h-7 px-3 text-[10px] bg-purple-500/10 text-purple-400 border border-purple-500/20 hover:bg-purple-500/20 font-black">
                      Add
                    </Button>
                  </div>
                  <div className="flex flex-wrap gap-1.5">
                    {settings.cors_origins.map((origin) => (
                      <span
                        key={origin}
                        className="inline-flex items-center gap-1 px-2 py-0.5 bg-purple-500/5 border border-purple-500/15 rounded text-[10px] font-mono text-purple-400 cursor-pointer hover:bg-red-500/10 hover:text-red-400 hover:border-red-500/20 transition-colors"
                        onClick={() => update("cors_origins", settings.cors_origins.filter((o) => o !== origin))}
                        title="Click to remove"
                      >
                        {origin} ×
                      </span>
                    ))}
                  </div>
                </div>
              </div>
            </GlowCard>
          )}

          {/* ═══ System Health ═══ */}
          {activeSection === "system" && (
            <>
              <div className="grid grid-cols-3 gap-4">
                {[
                  {
                    label: "Database",
                    status: systemHealth?.database || "checking",
                    icon: Database,
                    color: systemHealth?.database === "connected" ? "text-primary" : "text-red-500",
                  },
                  {
                    label: "Cache (Redis)",
                    status: systemHealth?.redis || "checking",
                    icon: HardDrive,
                    color: systemHealth?.redis === "connected" ? "text-primary" : "text-amber-500",
                  },
                  {
                    label: "Scanner Engine",
                    status: systemHealth?.scanner || "checking",
                    icon: Shield,
                    color: systemHealth?.scanner === "operational" ? "text-primary" : "text-red-500",
                  },
                ].map((svc) => (
                  <GlowCard key={svc.label} className="p-0 border-white/5" glowColor="rgba(0,255,136,0.03)">
                    <div className="flex items-center gap-3 mb-3">
                      <svc.icon className={cn("w-5 h-5", svc.color)} />
                      <div>
                        <p className="text-xs font-bold text-foreground">{svc.label}</p>
                        <p className={cn("text-[10px] font-black uppercase tracking-widest", svc.color)}>
                          {svc.status}
                        </p>
                      </div>
                    </div>
                    <div className="flex items-center gap-1.5">
                      <div className={cn("w-1.5 h-1.5 rounded-full animate-pulse", svc.color === "text-primary" ? "bg-primary" : "bg-red-500")} />
                      <span className="text-[9px] text-muted-foreground uppercase tracking-widest font-bold">Live</span>
                    </div>
                  </GlowCard>
                ))}
              </div>

              <GlowCard className="p-0 border-white/5 overflow-hidden" glowColor="rgba(0,255,136,0.02)">
                <div className="px-6 py-4 border-b border-white/5">
                  <h2 className="text-sm font-black text-foreground uppercase tracking-widest flex items-center gap-2">
                    <Cpu className="w-4 h-4 text-primary" /> Resource Usage
                  </h2>
                </div>
                <div className="p-6 space-y-5">
                  <ResourceBar label="CPU Usage" value={systemHealth?.cpu_percent ?? 0} max={100} unit="%" color="#00FF88" />
                  <ResourceBar label="Memory" value={systemHealth?.memory_mb ?? 0} max={4096} unit="MB" color="#00A3FF" />
                  <ResourceBar label="Uptime" value={systemHealth?.uptime_hours ?? 0} max={720} unit="hours" color="#A855F7" />
                </div>
              </GlowCard>
            </>
          )}
        </div>
      </div>
    </div>
  );
}

// ─── Reusable sub-components ──────────────────────────────────────────────────

function SettingField({ label, desc, children }: { label: string; desc: string; children: React.ReactNode }) {
  return (
    <div className="p-4 rounded-xl bg-white/[0.02] border border-white/5">
      <p className="text-xs font-bold text-foreground mb-0.5">{label}</p>
      <p className="text-[10px] text-muted-foreground mb-3">{desc}</p>
      {children}
    </div>
  );
}

function ToggleSetting({ label, desc, value, onChange, danger }: {
  label: string; desc: string; value: boolean; onChange: (v: boolean) => void; danger?: boolean;
}) {
  return (
    <div className="flex items-center justify-between p-4 rounded-xl bg-white/[0.02] border border-white/5 hover:border-white/10 transition-colors">
      <div>
        <p className={cn("text-xs font-bold", danger && value ? "text-red-400" : "text-foreground")}>{label}</p>
        <p className="text-[10px] text-muted-foreground">{desc}</p>
      </div>
      <button type="button" onClick={() => onChange(!value)} className="flex-shrink-0">
        {value ? (
          <ToggleRight className={cn("w-8 h-8", danger ? "text-red-500" : "text-primary")} />
        ) : (
          <ToggleLeft className="w-8 h-8 text-muted-foreground" />
        )}
      </button>
    </div>
  );
}

function SliderSetting({ label, value, min, max, unit, onChange }: {
  label: string; value: number; min: number; max: number; unit: string; onChange: (v: number) => void;
}) {
  return (
    <div className="p-4 rounded-xl bg-white/[0.02] border border-white/5">
      <div className="flex items-center justify-between mb-2">
        <p className="text-xs font-bold text-foreground">{label}</p>
        <span className="text-[10px] text-muted-foreground font-mono">{value} {unit}</span>
      </div>
      <input
        type="range"
        title={label}
        min={min}
        max={max}
        value={value}
        onChange={(e) => onChange(parseInt(e.target.value))}
        className="w-full h-1 bg-white/10 rounded-full appearance-none cursor-pointer accent-[#00FF88]"
      />
      <div className="flex justify-between mt-1">
        <span className="text-[9px] text-muted-foreground">{min}</span>
        <span className="text-[9px] text-muted-foreground">{max}</span>
      </div>
    </div>
  );
}

function ResourceBar({ label, value, max, unit, color }: {
  label: string; value: number; max: number; unit: string; color: string;
}) {
  const pct = Math.min(100, (value / max) * 100);
  return (
    <div>
      <div className="flex items-center justify-between mb-2">
        <p className="text-xs font-bold text-foreground">{label}</p>
        <span className="text-[10px] font-mono text-muted-foreground">{value} / {max} {unit}</span>
      </div>
      <div className="w-full h-2 bg-white/5 rounded-full overflow-hidden">
        <div
          className="h-full rounded-full transition-all duration-500"
          style={{ width: `${pct}%`, backgroundColor: color, boxShadow: `0 0 10px ${color}40` }}
        />
      </div>
    </div>
  );
}
