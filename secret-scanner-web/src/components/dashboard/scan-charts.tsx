"use client";

import { GlowCard } from "@/components/ui/glow-card";
import {
    PieChart, Pie, Cell, ResponsiveContainer, BarChart, Bar,
    XAxis, YAxis, Tooltip, LineChart, Line, CartesianGrid
} from "recharts";

const SEVERITY_COLORS: Record<string, string> = {
    critical: "#EF4444", high: "#F97316", medium: "#EAB308", low: "#059669", info: "#64748B",
};

interface ScanChartsProps {
    severityCounts: Record<string, number>;
    owaspBreakdown: Record<string, number>;
    recentScans: { scan_id: string; target: string; total_findings: number; started_at: string; risk_score: number }[];
}

export function ScanCharts({ severityCounts, owaspBreakdown, recentScans }: ScanChartsProps) {
    const severityData = Object.entries(severityCounts)
        .filter(([k]) => k !== "info")
        .map(([name, value]) => ({ name: name.charAt(0).toUpperCase() + name.slice(1), value, color: SEVERITY_COLORS[name] || "#6B7F77" }));

    const owaspData = Object.entries(owaspBreakdown)
        .map(([cat, count]) => ({ category: cat.length > 12 ? cat.slice(0, 12) + "…" : cat, count, fill: "#00FF88" }))
        .sort((a, b) => b.count - a.count)
        .slice(0, 8);

    const trendData = recentScans.slice(0, 10).reverse().map((s) => ({
        date: s.started_at ? new Date(s.started_at).toLocaleDateString("en-US", { month: "short", day: "numeric" }) : "?",
        findings: s.total_findings,
        score: s.risk_score,
    }));

    const tooltipStyle = {
        background: "var(--bg-card)",
        border: "1px solid var(--border-green)",
        borderRadius: "12px",
        color: "var(--text-primary)",
        fontSize: "0.75rem",
        boxShadow: "0 10px 15px -3px rgba(0, 0, 0, 0.1)"
    };

    return (
        <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
            {/* Severity Pie */}
            <GlowCard className="p-0 border-border bg-card" glowColor="rgba(0, 255, 136, 0.05)">
                <div className="p-6">
                    <h4 className="text-foreground text-[10px] uppercase tracking-[0.2em] font-bold mb-6">Severity Distribution</h4>
                    <ResponsiveContainer width="100%" height={200}>
                        <PieChart>
                            <Pie data={severityData} cx="50%" cy="50%" innerRadius={50} outerRadius={75} paddingAngle={4} dataKey="value">
                                {severityData.map((e, i) => <Cell key={i} fill={e.color} />)}
                            </Pie>
                            <Tooltip contentStyle={tooltipStyle} />
                        </PieChart>
                    </ResponsiveContainer>
                    <div className="flex flex-wrap justify-center gap-3 mt-4">
                        {severityData.map((d) => (
                            <div key={d.name} className="flex items-center gap-1.5">
                                <div className="w-2 h-2 rounded-full" style={{ backgroundColor: d.color }} />
                                <span className="text-[10px] font-mono text-muted-foreground uppercase tracking-tighter">{d.name}: {d.value}</span>
                            </div>
                        ))}
                    </div>
                </div>
            </GlowCard>

            {/* OWASP Bar */}
            <GlowCard className="p-0 border-border bg-card" glowColor="rgba(0, 163, 255, 0.05)">
                <div className="p-6">
                    <h4 className="text-foreground text-[10px] uppercase tracking-[0.2em] font-bold mb-6">OWASP Coverage Matrix</h4>
                    <ResponsiveContainer width="100%" height={220}>
                        <BarChart data={owaspData} layout="vertical" margin={{ left: 0, right: 10 }}>
                            <XAxis type="number" tick={{ fill: "var(--text-muted)", fontSize: 10 }} hide />
                            <YAxis dataKey="category" type="category" width={100} tick={{ fill: "var(--text-muted)", fontSize: 9 }} />
                            <Tooltip contentStyle={tooltipStyle} />
                            <Bar dataKey="count" fill="var(--neon-green)" radius={[0, 4, 4, 0]} barSize={12} />
                        </BarChart>
                    </ResponsiveContainer>
                </div>
            </GlowCard>

            {/* Trend Line */}
            <GlowCard className="p-0 border-border bg-card" glowColor="rgba(0, 255, 136, 0.05)">
                <div className="p-6">
                    <h4 className="text-foreground text-[10px] uppercase tracking-[0.2em] font-bold mb-6">Attack Surface History</h4>
                    <ResponsiveContainer width="100%" height={220}>
                        <LineChart data={trendData}>
                            <CartesianGrid strokeDasharray="3 3" stroke="var(--border-green)" vertical={false} />
                            <XAxis dataKey="date" tick={{ fill: "var(--text-muted)", fontSize: 9 }} />
                            <YAxis tick={{ fill: "var(--text-muted)", fontSize: 9 }} />
                            <Tooltip contentStyle={tooltipStyle} />
                            <Line type="monotone" dataKey="findings" stroke="var(--neon-green)" strokeWidth={3} dot={{ fill: "var(--neon-green)", r: 4, strokeWidth: 0 }} activeDot={{ r: 6, strokeWidth: 0 }} />
                        </LineChart>
                    </ResponsiveContainer>
                </div>
            </GlowCard>
        </div>
    );
}
