"use client";

import React, { useEffect, useState, useCallback } from "react";
import {
  Users,
  ShieldAlert,
  Search,
  CreditCard,
  TrendingUp,
  AlertCircle,
  ExternalLink,
  RefreshCw
} from "lucide-react";
import { GlowCard } from "@/components/ui/glow-card";
import { cn } from "@/lib/utils";
import Link from "next/link";
import { auth } from "@/lib/firebase";

const API_BASE_URL = process.env.NEXT_PUBLIC_API_URL || "http://localhost:8000";

async function fetchWithAuth(path: string) {
  const user = auth.currentUser;
  const token = user ? await user.getIdToken() : "";
  const res = await fetch(`${API_BASE_URL}${path}`, {
    headers: { Authorization: `Bearer ${token}` },
  });
  if (!res.ok) throw new Error(`HTTP ${res.status}`);
  return res.json();
}

interface DashboardStats {
  total_users: number;
  active_users: number;
  users_this_month: number;
  total_scans: number;
  scans_today: number;
  revenue_this_month: number;
  security_events_24h: number;
}

interface ActivityItem {
  id: string;
  user_id?: string;
  event_type?: string;
  severity?: string;
  description?: string;
  amount_usd?: number;
  scan_id?: string;
  target?: string;
  status?: string;
  created_at: string;
}

interface ActivityData {
  recent_security_events: ActivityItem[];
  recent_scans: ActivityItem[];
}

export default function AdminDashboardPage() {
  const [stats, setStats] = useState<DashboardStats | null>(null);
  const [activity, setActivity] = useState<ActivityData | null>(null);
  const [loading, setLoading] = useState(true);
  const [apiError, setApiError] = useState(false);

  const fetchDashboardData = useCallback(async () => {
    try {
      const [statsData, activityData] = await Promise.all([
        fetchWithAuth("/api/v1/admin/dashboard/stats"),
        fetchWithAuth("/api/v1/admin/dashboard/recent-activity"),
      ]);
      setStats(statsData);
      setActivity(activityData);
      setApiError(false);
    } catch {
      setApiError(true);
      // Show zeros instead of keeping the loading spinner forever
      if (!stats) {
        setStats({ total_users: 0, active_users: 0, users_this_month: 0, total_scans: 0, scans_today: 0, revenue_this_month: 0, security_events_24h: 0 });
        setActivity({ recent_security_events: [], recent_scans: [] });
      }
    } finally {
      setLoading(false);
    }
  }, [stats]);

  useEffect(() => {
    fetchDashboardData();
    // Auto-refresh every 15 seconds for real-time telemetry
    const interval = setInterval(fetchDashboardData, 15000);
    return () => clearInterval(interval);
  }, [fetchDashboardData]);

  if (loading) {
    return (
      <div className="flex flex-col items-center justify-center py-20">
        <div className="w-10 h-10 border-2 border-primary/20 border-t-[#00FF88] rounded-full animate-spin mb-4" />
        <p className="text-[10px] font-black uppercase tracking-widest text-muted-foreground">Querying Admin Data...</p>
      </div>
    );
  }

  return (
    <div className="space-y-10">
      {/* Header */}
      <div className="flex items-end justify-between">
        <div>
          <h1 className="text-3xl font-black text-foreground uppercase tracking-tighter flex items-center gap-3">
            System <span className="text-primary">Overview</span>
          </h1>
          <p className="text-xs text-muted-foreground font-bold uppercase tracking-widest mt-1">Global platform telemetry and security status</p>
        </div>
        <button
          onClick={() => fetchDashboardData()}
          className="flex items-center gap-2 px-5 py-2.5 rounded-xl bg-[rgba(0,255,136,0.1)] border border-[rgba(0,255,136,0.2)] text-primary hover:bg-[rgba(0,255,136,0.2)] transition-all text-[11px] font-black uppercase tracking-widest"
        >
          <RefreshCw className="w-3.5 h-3.5" />
          Force Sync
        </button>
      </div>

      {/* API Error Banner */}
      {apiError && (
        <div className="bg-amber-500/5 border border-amber-500/20 rounded-2xl p-4 flex items-center gap-4">
          <AlertCircle className="w-5 h-5 text-amber-500 shrink-0" />
          <div>
            <p className="text-xs font-black text-amber-400 uppercase tracking-widest">Backend API Unavailable</p>
            <p className="text-[10px] text-amber-300/60 mt-0.5">Ensure the Quantara backend is running on port 8000. Data shown may be stale or empty.</p>
          </div>
        </div>
      )}

      {/* Stats Grid */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6">
        <StatCard
          icon={Users}
          title="Global Identity"
          value={stats?.total_users || 0}
          subtitle={`${stats?.active_users || 0} Pulse-Active`}
          color="#00FF88"
        />
        <StatCard
          icon={TrendingUp}
          title="Growth Velocity"
          value={stats?.users_this_month || 0}
          subtitle="Users Joined (MTD)"
          color="#00A3FF"
        />
        <StatCard
          icon={Search}
          title="Scan Cycles"
          value={stats?.total_scans || 0}
          subtitle={`${stats?.scans_today || 0} in last 24h`}
          color="#A855F7"
        />
        <StatCard
          icon={CreditCard}
          title="Yield Forecast"
          value={`$${stats?.revenue_this_month?.toLocaleString() || "0"}`}
          subtitle="Monthly Recurring"
          color="#FACC15"
        />
      </div>

      {/* Security Alert Banner */}
      {stats && stats.security_events_24h > 0 && (
        <GlowCard
          glowColor="rgba(239, 68, 68, 0.15)"
          borderColor="rgba(239, 68, 68, 0.2)"
          className="bg-red-500/5 animate-pulse"
        >
          <div className="flex items-center justify-between p-1">
            <div className="flex items-center gap-5">
              <div className="w-12 h-12 rounded-xl bg-red-500/20 border border-red-500/30 flex items-center justify-center">
                <ShieldAlert className="w-6 h-6 text-red-500" />
              </div>
              <div>
                <h3 className="text-lg font-black text-red-500 uppercase tracking-tighter">Critical Security Telemetry</h3>
                <p className="text-sm text-red-400/60 font-medium">Detected {stats.security_events_24h} unresolved security events requiring level 1 authority.</p>
              </div>
            </div>
            <Link
              href="/admin/security"
              className="px-6 py-3 bg-red-500 text-foreground font-black text-[10px] uppercase tracking-widest rounded-xl shadow-[0_0_20px_rgba(239,68,68,0.3)] hover:scale-105 transition-all"
            >
              Analyze Threat Map
            </Link>
          </div>
        </GlowCard>
      )}

      {/* Bottom Grids */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-8">
        {/* Recent Security Events */}
        <GlowCard className="lg:col-span-12 p-8" glowColor="rgba(255,255,255,0.02)">
          <div className="flex items-center justify-between mb-8">
            <div className="flex items-center gap-3">
              <div className="w-10 h-10 rounded-xl bg-amber-500/10 border border-amber-500/20 flex items-center justify-center">
                <AlertCircle className="w-5 h-5 text-amber-500" />
              </div>
              <div>
                <h2 className="text-xl font-bold text-foreground uppercase tracking-tighter">Live Threat Stream</h2>
                <p className="text-[10px] text-muted-foreground uppercase font-black tracking-widest mt-1">Platform-wide security incidents</p>
              </div>
            </div>
          </div>

          <div className="overflow-hidden border border-white/5 rounded-2xl">
            <table className="w-full text-left">
              <thead>
                <tr className="bg-white/[0.02] border-b border-white/5">
                  <th className="px-6 py-4 text-[10px] font-black uppercase text-muted-foreground tracking-widest">Severity</th>
                  <th className="px-6 py-4 text-[10px] font-black uppercase text-muted-foreground tracking-widest">Incident Root</th>
                  <th className="px-6 py-4 text-[10px] font-black uppercase text-muted-foreground tracking-widest">Description</th>
                  <th className="px-6 py-4 text-[10px] font-black uppercase text-muted-foreground tracking-widest">Timestamp</th>
                  <th className="px-6 py-4"></th>
                </tr>
              </thead>
              <tbody className="divide-y divide-white/5">
                {activity?.recent_security_events?.slice(0, 6).map((event) => (
                  <tr key={event.id} className="hover:bg-white/[0.01] transition-colors group">
                    <td className="px-6 py-4">
                      <div className={cn(
                        "inline-flex items-center px-2.5 py-1 rounded-md text-[9px] font-black uppercase border",
                        event.severity === "critical" ? "text-red-500 bg-red-500/10 border-red-500/30 shadow-[0_0_10px_rgba(239,68,68,0.1)]" :
                          event.severity === "high" ? "text-orange-500 bg-orange-500/10 border-orange-500/30" :
                            "text-[#00A3FF] bg-[#00A3FF]/10 border-[#00A3FF]/30"
                      )}>
                        {event.severity}
                      </div>
                    </td>
                    <td className="px-6 py-4 text-sm font-bold text-foreground uppercase tracking-tighter">
                      {event.event_type}
                    </td>
                    <td className="px-6 py-4 text-xs text-muted-foreground max-w-xs truncate font-medium uppercase tracking-tight">
                      {event.description}
                    </td>
                    <td className="px-6 py-4 text-[10px] font-mono text-muted-foreground">
                      {new Date(event.created_at).toLocaleString()}
                    </td>
                    <td className="px-6 py-4 text-right">
                      <button className="p-2 opacity-0 group-hover:opacity-100 text-muted-foreground hover:text-primary transition-all">
                        <ExternalLink className="w-4 h-4" />
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
            {!activity?.recent_security_events?.length && (
              <div className="py-20 text-center space-y-3 opacity-20">
                <Search className="w-10 h-10 mx-auto" />
                <p className="text-[10px] font-black uppercase tracking-[0.3em]">Buffer Empty: No Recent Incidents</p>
              </div>
            )}
          </div>
        </GlowCard>
      </div>
    </div>
  );
}

function StatCard({ icon: Icon, title, value, subtitle, color }: any) {
  return (
    <GlowCard className="p-7" glowColor={`${color}15`}>
      <div className="flex items-start justify-between mb-4">
        <div
          className="w-12 h-12 rounded-2xl flex items-center justify-center border transition-all duration-500"
          style={{
            backgroundColor: `${color}10`,
            borderColor: `${color}25`,
            boxShadow: `0 0 20px ${color}05`
          }}
        >
          <Icon className="w-6 h-6" style={{ color: color }} />
        </div>
        <div className="px-2 py-0.5 rounded-lg bg-white/5 border border-white/5 flex items-center gap-1.5 shadow-inner">
          <div className="w-1 h-1 rounded-full animate-pulse" style={{ backgroundColor: color }} />
          <span className="text-[8px] font-black text-muted-foreground uppercase tracking-widest">Active</span>
        </div>
      </div>
      <div>
        <p className="text-xs font-black text-muted-foreground uppercase tracking-[0.2em]">{title}</p>
        <div className="flex items-baseline gap-2 mt-2">
          <h4 className="text-3xl font-black text-foreground font-outfit tracking-tighter">{value}</h4>
        </div>
        <p className="text-[10px] font-bold text-muted-foreground uppercase mt-1 tracking-tight">{subtitle}</p>
      </div>
    </GlowCard>
  );
}
