"use client";

import React, { useState, useEffect, useRef, useCallback } from "react";
import {
  Activity,
  BarChart3,
  Brain,
  Clock,
  Database,
  Globe,
  Shield,
  Target,
  Zap,
} from "lucide-react";
import { cn } from "@/lib/utils";
import { toast } from "sonner";

const API_BASE = process.env.NEXT_PUBLIC_API_URL || "http://localhost:8000";

/* ------------------------------------------------------------------ */
/*  Types                                                              */
/* ------------------------------------------------------------------ */

interface DashboardStats {
  requests_sent: number;
  payloads_tested: number;
  potential_vulnerabilities: number;
  confirmed_vulnerabilities: number;
  fuzz_sessions_active: number;
  targets_in_memory: number;
  history_count: number;
}

interface TargetMemory {
  hostname: string;
  last_seen: string;
  db_type: string;
  framework: string;
  technologies: string[];
  endpoints_discovered: number;
  confirmed_vulns: number;
}

interface MemoryResponse {
  targets: TargetMemory[];
}

/* ------------------------------------------------------------------ */
/*  Stat card                                                          */
/* ------------------------------------------------------------------ */

function StatCard({
  icon: Icon,
  label,
  value,
  badgeColor,
}: {
  icon: React.ElementType;
  label: string;
  value: number;
  badgeColor?: "yellow" | "red";
}) {
  const badgeClasses = badgeColor === "red"
    ? "bg-red-500/15 text-red-400 border-red-500/30"
    : badgeColor === "yellow"
      ? "bg-yellow-500/15 text-yellow-400 border-yellow-500/30"
      : "";

  return (
    <div
      className={cn(
        "relative overflow-hidden rounded-md border border-white/[0.06]",
        "bg-background/80 backdrop-blur-sm p-3",
        "transition-transform duration-200 ease-out hover:scale-[1.02]"
      )}
    >
      <div className="flex items-center justify-between gap-2">
        <div className="flex items-center gap-2 min-w-0">
          <div className="flex-shrink-0 rounded bg-primary/10 p-1.5">
            <Icon className="h-3 w-3 text-primary" strokeWidth={2.5} />
          </div>
          <span className="text-[8px] font-black uppercase tracking-widest text-foreground/50 truncate">
            {label}
          </span>
        </div>

        {badgeColor ? (
          <span
            className={cn(
              "flex-shrink-0 rounded border px-1.5 py-0.5 text-[11px] font-bold tabular-nums",
              badgeClasses
            )}
          >
            {value.toLocaleString()}
          </span>
        ) : (
          <span className="flex-shrink-0 text-[11px] font-bold tabular-nums text-foreground/90">
            {value.toLocaleString()}
          </span>
        )}
      </div>
    </div>
  );
}

/* ------------------------------------------------------------------ */
/*  Main component                                                     */
/* ------------------------------------------------------------------ */

export function AttackDashboard() {
  const [stats, setStats] = useState<DashboardStats | null>(null);
  const [memory, setMemory] = useState<TargetMemory[]>([]);
  const [loading, setLoading] = useState(true);
  const intervalRef = useRef<ReturnType<typeof setInterval> | null>(null);

  /* ---------- fetch helpers ---------- */

  const fetchDashboard = useCallback(async () => {
    try {
      const res = await fetch(`${API_BASE}/api/hetty/ai/dashboard`);
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      const data: DashboardStats = await res.json();
      setStats(data);
    } catch {
      /* silent — poll will retry */
    }
  }, []);

  const fetchMemory = useCallback(async () => {
    try {
      const res = await fetch(`${API_BASE}/api/hetty/ai/memory`);
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      const data = await res.json();
      const targets = Array.isArray(data?.targets) ? data.targets : Array.isArray(data) ? data : [];
      setMemory(targets);
    } catch {
      /* silent — memory may not exist yet */
      setMemory([]);
    }
  }, []);

  /* ---------- lifecycle ---------- */

  useEffect(() => {
    const init = async () => {
      setLoading(true);
      await Promise.all([fetchDashboard(), fetchMemory()]);
      setLoading(false);
    };
    init();

    intervalRef.current = setInterval(fetchDashboard, 5000);

    return () => {
      if (intervalRef.current) clearInterval(intervalRef.current);
    };
  }, [fetchDashboard, fetchMemory]);

  /* ---------- render ---------- */

  if (loading && !stats) {
    return (
      <div className="flex items-center justify-center py-12">
        <Activity className="h-4 w-4 animate-pulse text-primary/60" />
        <span className="ml-2 text-[9px] font-black uppercase tracking-widest text-foreground/40">
          Loading dashboard...
        </span>
      </div>
    );
  }

  return (
    <div className="space-y-4">
      {/* ---- Section: Live Metrics ---- */}
      <div>
        <h3 className="mb-2 flex items-center gap-1.5 text-[9px] font-black uppercase tracking-widest text-primary/70">
          <Zap className="h-3 w-3" strokeWidth={2.5} />
          Live Metrics
        </h3>

        <div className="grid grid-cols-2 gap-2 sm:grid-cols-4">
          <StatCard
            icon={Globe}
            label="Requests Sent"
            value={stats?.requests_sent ?? 0}
          />
          <StatCard
            icon={Target}
            label="Payloads Tested"
            value={stats?.payloads_tested ?? 0}
          />
          <StatCard
            icon={Shield}
            label="Potential Vulns"
            value={stats?.potential_vulnerabilities ?? 0}
            badgeColor="yellow"
          />
          <StatCard
            icon={Zap}
            label="Confirmed Vulns"
            value={stats?.confirmed_vulnerabilities ?? 0}
            badgeColor="red"
          />
        </div>
      </div>

      {/* ---- Section: Additional Stats ---- */}
      <div>
        <h3 className="mb-2 flex items-center gap-1.5 text-[9px] font-black uppercase tracking-widest text-[#00A3FF]/70">
          <BarChart3 className="h-3 w-3" strokeWidth={2.5} />
          Additional Stats
        </h3>

        <div className="grid grid-cols-3 gap-2">
          <div className="rounded-md border border-white/[0.06] bg-background/80 p-2.5">
            <span className="block text-[8px] font-black uppercase tracking-widest text-foreground/40">
              Fuzz Sessions Active
            </span>
            <span className="mt-1 block text-[11px] font-bold tabular-nums text-primary">
              {stats?.fuzz_sessions_active ?? 0}
            </span>
          </div>

          <div className="rounded-md border border-white/[0.06] bg-background/80 p-2.5">
            <span className="block text-[8px] font-black uppercase tracking-widest text-foreground/40">
              Targets in Memory
            </span>
            <span className="mt-1 block text-[11px] font-bold tabular-nums text-[#00A3FF]">
              {stats?.targets_in_memory ?? 0}
            </span>
          </div>

          <div className="rounded-md border border-white/[0.06] bg-background/80 p-2.5">
            <span className="block text-[8px] font-black uppercase tracking-widest text-foreground/40">
              History Count
            </span>
            <span className="mt-1 block text-[11px] font-bold tabular-nums text-foreground/70">
              {stats?.history_count ?? 0}
            </span>
          </div>
        </div>
      </div>

      {/* ---- Section: AI Learning Memory ---- */}
      <div>
        <h3 className="mb-2 flex items-center gap-1.5 text-[9px] font-black uppercase tracking-widest text-primary/70">
          <Brain className="h-3 w-3" strokeWidth={2.5} />
          AI Learning Memory
        </h3>

        {!Array.isArray(memory) || memory.length === 0 ? (
          <div className="rounded-md border border-white/[0.06] bg-background/80 p-4 text-center">
            <span className="text-[9px] font-black uppercase tracking-widest text-foreground/30">
              No targets in memory yet
            </span>
          </div>
        ) : (
          <div className="space-y-2">
            {(Array.isArray(memory) ? memory : []).map((target) => (
              <div
                key={target.hostname}
                className={cn(
                  "rounded-md border border-white/[0.06] bg-background/80 p-3",
                  "transition-colors duration-150 hover:border-primary/20"
                )}
              >
                {/* Header row */}
                <div className="flex items-center justify-between gap-2 mb-2">
                  <div className="flex items-center gap-1.5 min-w-0">
                    <Globe className="h-3 w-3 flex-shrink-0 text-[#00A3FF]" strokeWidth={2.5} />
                    <span className="text-[10px] font-bold text-foreground/90 truncate">
                      {target.hostname}
                    </span>
                  </div>
                  <div className="flex items-center gap-1 flex-shrink-0">
                    <Clock className="h-2.5 w-2.5 text-foreground/30" strokeWidth={2} />
                    <span className="text-[8px] text-foreground/30 tabular-nums">
                      {target.last_seen}
                    </span>
                  </div>
                </div>

                {/* Detail grid */}
                <div className="grid grid-cols-2 gap-x-4 gap-y-1 mb-2">
                  <div className="flex items-center gap-1">
                    <Database className="h-2.5 w-2.5 text-foreground/25" strokeWidth={2} />
                    <span className="text-[8px] font-black uppercase tracking-widest text-foreground/40">
                      DB
                    </span>
                    <span className="text-[9px] text-foreground/70">
                      {target.db_type || "Unknown"}
                    </span>
                  </div>
                  <div className="flex items-center gap-1">
                    <Activity className="h-2.5 w-2.5 text-foreground/25" strokeWidth={2} />
                    <span className="text-[8px] font-black uppercase tracking-widest text-foreground/40">
                      Framework
                    </span>
                    <span className="text-[9px] text-foreground/70">
                      {target.framework || "Unknown"}
                    </span>
                  </div>
                </div>

                {/* Technologies */}
                {target.technologies.length > 0 && (
                  <div className="flex flex-wrap gap-1 mb-2">
                    {target.technologies.map((tech) => (
                      <span
                        key={tech}
                        className="rounded border border-[#00A3FF]/20 bg-[#00A3FF]/10 px-1.5 py-0.5 text-[8px] font-bold text-[#00A3FF]/80"
                      >
                        {tech}
                      </span>
                    ))}
                  </div>
                )}

                {/* Footer stats */}
                <div className="flex items-center gap-3 border-t border-white/[0.04] pt-2">
                  <div className="flex items-center gap-1">
                    <Target className="h-2.5 w-2.5 text-primary/60" strokeWidth={2} />
                    <span className="text-[8px] font-black uppercase tracking-widest text-foreground/40">
                      Endpoints
                    </span>
                    <span className="text-[9px] font-bold text-primary tabular-nums">
                      {target.endpoints_discovered}
                    </span>
                  </div>
                  <div className="flex items-center gap-1">
                    <Shield className="h-2.5 w-2.5 text-red-400/60" strokeWidth={2} />
                    <span className="text-[8px] font-black uppercase tracking-widest text-foreground/40">
                      Confirmed
                    </span>
                    <span
                      className={cn(
                        "text-[9px] font-bold tabular-nums",
                        target.confirmed_vulns > 0 ? "text-red-400" : "text-foreground/50"
                      )}
                    >
                      {target.confirmed_vulns}
                    </span>
                  </div>
                </div>
              </div>
            ))}
          </div>
        )}
      </div>
    </div>
  );
}
