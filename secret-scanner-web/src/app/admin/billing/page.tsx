"use client";

import React, { useEffect, useState, useCallback } from "react";
import {
  CreditCard,
  TrendingUp,
  DollarSign,
  Zap,
  RefreshCw,
  AlertTriangle,
  CheckCircle,
  Clock,
  FileText,
  Users,
} from "lucide-react";
import { GlowCard } from "@/components/ui/glow-card";
import { Button } from "@/components/ui/button";
import { auth } from "@/lib/firebase";

const API_BASE = process.env.NEXT_PUBLIC_API_URL || "http://localhost:8000";

interface RevenueSummary {
  mrr_cents: number;
  mrr_formatted: string;
  revenue_30d_cents: number;
  revenue_30d_formatted: string;
  active_subscriptions: number;
  error?: string;
}

interface Invoice {
  id: string;
  number: string;
  amount_paid: number;
  amount_due: number;
  currency: string;
  status: string;
  period_start: string | null;
  period_end: string | null;
  hosted_invoice_url: string;
  invoice_pdf: string;
}

async function fetchWithAuth(path: string) {
  const user = auth.currentUser;
  const token = user ? await user.getIdToken() : "";
  const res = await fetch(`${API_BASE}${path}`, {
    headers: { Authorization: `Bearer ${token}` },
  });
  if (!res.ok) throw new Error(`HTTP ${res.status}`);
  return res.json();
}

function StatCard({
  label,
  value,
  sub,
  icon: Icon,
  color = "amber",
}: {
  label: string;
  value: string;
  sub?: string;
  icon: React.ElementType;
  color?: string;
}) {
  const colorMap: Record<string, string> = {
    amber: "text-amber-500 bg-amber-500/10 border-amber-500/20",
    green: "text-primary bg-primary/10 border-primary/20",
    blue: "text-blue-400 bg-blue-400/10 border-blue-400/20",
    red: "text-red-400 bg-red-400/10 border-red-400/20",
  };
  const cls = colorMap[color] || colorMap.amber;

  return (
    <GlowCard className="p-6" glowColor="rgba(245,158,11,0.04)">
      <div className="flex items-start justify-between">
        <div>
          <p className="text-[10px] font-black text-muted-foreground uppercase tracking-widest mb-2">
            {label}
          </p>
          <p className="text-3xl font-black text-foreground tracking-tighter">{value}</p>
          {sub && (
            <p className="text-xs text-muted-foreground mt-1 uppercase tracking-wide font-medium">{sub}</p>
          )}
        </div>
        <div className={`p-3 rounded-xl border ${cls}`}>
          <Icon className={`w-5 h-5 ${cls.split(" ")[0]}`} />
        </div>
      </div>
    </GlowCard>
  );
}

function statusColor(s: string) {
  if (s === "paid") return "text-primary bg-primary/10";
  if (s === "open") return "text-amber-400 bg-amber-400/10";
  if (s === "void" || s === "uncollectible") return "text-red-400 bg-red-400/10";
  return "text-muted-foreground bg-muted/10";
}

export default function AdminBillingPage() {
  const [revenue, setRevenue] = useState<RevenueSummary | null>(null);
  const [invoices, setInvoices] = useState<Invoice[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [lastRefreshed, setLastRefreshed] = useState<Date | null>(null);

  const load = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const [rev, inv] = await Promise.all([
        fetchWithAuth("/api/v1/admin/billing/revenue"),
        fetchWithAuth("/api/v1/billing/invoices"),
      ]);
      setRevenue(rev);
      setInvoices(inv.invoices || []);
      setLastRefreshed(new Date());
    } catch (e: any) {
      setError(e.message || "Failed to load billing data");
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    load();
  }, [load]);

  return (
    <div className="space-y-10">
      {/* Header */}
      <div className="flex items-end justify-between">
        <div>
          <h1 className="text-3xl font-black text-foreground uppercase tracking-tighter flex items-center gap-3">
            Revenue <span className="text-amber-500">Engine</span>
          </h1>
          <p className="text-xs text-muted-foreground font-bold uppercase tracking-widest mt-1">
            Platform subscription yields and financial projections
          </p>
        </div>
        <div className="flex items-center gap-3">
          {lastRefreshed && (
            <p className="text-[10px] text-muted-foreground uppercase tracking-widest font-medium">
              Updated {lastRefreshed.toLocaleTimeString()}
            </p>
          )}
          <Button
            variant="outline"
            size="sm"
            onClick={load}
            disabled={loading}
            className="border-amber-500/20 text-amber-500 hover:bg-amber-500/10 uppercase text-[10px] font-black tracking-widest px-4"
          >
            <RefreshCw className={`w-3 h-3 mr-2 ${loading ? "animate-spin" : ""}`} />
            Refresh
          </Button>
        </div>
      </div>

      {/* Error Banner */}
      {error && (
        <div className="bg-red-500/5 border border-red-500/20 rounded-2xl p-4 flex items-center gap-4">
          <AlertTriangle className="w-5 h-5 text-red-500 shrink-0" />
          <p className="text-sm text-red-400">{error}</p>
        </div>
      )}

      {/* KPI Stats Row */}
      {loading && !revenue ? (
        <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
          {[...Array(4)].map((_, i) => (
            <div key={i} className="h-32 rounded-2xl bg-white/[0.02] border border-white/5 animate-pulse" />
          ))}
        </div>
      ) : (
        <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
          <StatCard
            label="Monthly Recurring Revenue"
            value={revenue?.mrr_formatted || "$0.00"}
            sub="Active subscriptions"
            icon={DollarSign}
            color="amber"
          />
          <StatCard
            label="Revenue (Last 30 Days)"
            value={revenue?.revenue_30d_formatted || "$0.00"}
            sub="All paid charges"
            icon={TrendingUp}
            color="green"
          />
          <StatCard
            label="Active Subscriptions"
            value={String(revenue?.active_subscriptions ?? 0)}
            sub="Across all plans"
            icon={Users}
            color="blue"
          />
          <StatCard
            label="Recent Invoices"
            value={String(invoices.length)}
            sub="Last 24 invoices"
            icon={FileText}
            color="amber"
          />
        </div>
      )}

      {/* Invoices Table */}
      <GlowCard className="p-0 border-white/5 overflow-hidden" glowColor="rgba(245,158,11,0.02)">
        <div className="px-6 py-4 border-b border-white/5 flex items-center justify-between">
          <h2 className="text-sm font-black text-foreground uppercase tracking-widest flex items-center gap-2">
            <CreditCard className="w-4 h-4 text-amber-500" />
            Invoice History
          </h2>
          <span className="text-[10px] font-black text-muted-foreground uppercase tracking-widest">
            {invoices.length} records
          </span>
        </div>

        {loading && invoices.length === 0 ? (
          <div className="p-8 flex items-center justify-center">
            <div className="flex items-center gap-3 text-muted-foreground">
              <RefreshCw className="w-4 h-4 animate-spin" />
              <span className="text-xs uppercase tracking-widest font-bold">Loading invoices…</span>
            </div>
          </div>
        ) : invoices.length === 0 ? (
          <div className="p-12 flex flex-col items-center text-center">
            <FileText className="w-10 h-10 text-muted-foreground mb-4" />
            <p className="text-sm text-muted-foreground uppercase tracking-widest font-bold">No invoices found</p>
            <p className="text-xs text-muted-foreground mt-1">Invoices will appear here after the first payment</p>
          </div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-xs">
              <thead>
                <tr className="border-b border-white/5">
                  {["Invoice #", "Period", "Amount", "Status", "Actions"].map((h) => (
                    <th
                      key={h}
                      className="px-6 py-3 text-left font-black text-muted-foreground uppercase tracking-widest"
                    >
                      {h}
                    </th>
                  ))}
                </tr>
              </thead>
              <tbody className="divide-y divide-white/[0.03]">
                {invoices.map((inv) => (
                  <tr key={inv.id} className="hover:bg-white/[0.02] transition-colors">
                    <td className="px-6 py-4 font-mono text-muted-foreground font-medium">
                      {inv.number || inv.id.slice(0, 12)}
                    </td>
                    <td className="px-6 py-4 text-muted-foreground">
                      {inv.period_start
                        ? new Date(inv.period_start).toLocaleDateString()
                        : "—"}{" "}
                      –{" "}
                      {inv.period_end
                        ? new Date(inv.period_end).toLocaleDateString()
                        : "—"}
                    </td>
                    <td className="px-6 py-4 font-black text-foreground">
                      ${((inv.amount_paid || inv.amount_due) / 100).toFixed(2)}{" "}
                      <span className="text-muted-foreground font-medium uppercase">
                        {inv.currency}
                      </span>
                    </td>
                    <td className="px-6 py-4">
                      <span
                        className={`inline-flex items-center gap-1 px-2 py-0.5 rounded-full text-[10px] font-black uppercase tracking-widest ${statusColor(inv.status)}`}
                      >
                        {inv.status === "paid" ? (
                          <CheckCircle className="w-3 h-3" />
                        ) : inv.status === "open" ? (
                          <Clock className="w-3 h-3" />
                        ) : (
                          <AlertTriangle className="w-3 h-3" />
                        )}
                        {inv.status}
                      </span>
                    </td>
                    <td className="px-6 py-4 flex items-center gap-2">
                      {inv.hosted_invoice_url && (
                        <a
                          href={inv.hosted_invoice_url}
                          target="_blank"
                          rel="noopener noreferrer"
                          className="text-[10px] font-black text-amber-500 hover:text-amber-400 uppercase tracking-widest border border-amber-500/20 rounded px-2 py-1 hover:bg-amber-500/10 transition-colors"
                        >
                          View
                        </a>
                      )}
                      {inv.invoice_pdf && (
                        <a
                          href={inv.invoice_pdf}
                          target="_blank"
                          rel="noopener noreferrer"
                          className="text-[10px] font-black text-muted-foreground hover:text-foreground uppercase tracking-widest border border-white/10 rounded px-2 py-1 hover:bg-white/5 transition-colors"
                        >
                          PDF
                        </a>
                      )}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </GlowCard>

      {/* Stripe API error notice */}
      {revenue?.error && (
        <div className="bg-amber-500/5 border border-amber-500/20 rounded-2xl p-4 flex items-start gap-4">
          <AlertTriangle className="w-5 h-5 text-amber-500 shrink-0 mt-0.5" />
          <div>
            <p className="text-xs font-black text-amber-400 uppercase tracking-widest mb-1">
              Stripe API Warning
            </p>
            <p className="text-xs text-amber-300/60">{revenue.error}</p>
            <p className="text-[10px] text-muted-foreground mt-1">
              Verify STRIPE_SECRET_KEY is set correctly in your environment.
            </p>
          </div>
        </div>
      )}
    </div>
  );
}
