"use client";

import { motion } from "framer-motion";
import {
    Shield, AlertTriangle, Bug, Target, Activity, Eye,
    Brain, FileText, RefreshCw, Radio, Link2, BarChart3
} from "lucide-react";

interface GlobalSecuritySummaryProps {
    criticalCount: number;
    highCount: number;
    mediumCount: number;
    lowCount: number;
    verifiedExploits: number;
    attackPaths: number;
    riskScore: number;
    exposedAssets: number;
    threatLevel?: string;
    activeExploits?: number;
    exfiltrationRisk?: number;
    lateralMovement?: number;
    monitoredEndpoints?: number;
    onViewAttackChain: () => void;
    onAIRiskAnalysis: () => void;
    onExecutiveSummary: () => void;
    onExportDFIR: () => void;
    onRecalculateRisk: () => void;
    onContinuousMonitoring: () => void;
}

const severityColors: Record<string, { bg: string; text: string; glow: string }> = {
    critical: { bg: "rgba(239,68,68,0.12)", text: "#ef4444", glow: "0 0 20px rgba(239,68,68,0.3)" },
    high: { bg: "rgba(249,115,22,0.12)", text: "#f97316", glow: "0 0 20px rgba(249,115,22,0.3)" },
    medium: { bg: "rgba(234,179,8,0.12)", text: "#eab308", glow: "0 0 20px rgba(234,179,8,0.3)" },
    low: { bg: "rgba(0,255,136,0.12)", text: "#00FF88", glow: "0 0 20px rgba(0,255,136,0.3)" },
};

export function GlobalSecuritySummary({
    criticalCount, highCount, mediumCount, lowCount,
    verifiedExploits, attackPaths, riskScore, exposedAssets,
    threatLevel, activeExploits, exfiltrationRisk, lateralMovement, monitoredEndpoints,
    onViewAttackChain, onAIRiskAnalysis, onExecutiveSummary,
    onExportDFIR, onRecalculateRisk, onContinuousMonitoring,
}: GlobalSecuritySummaryProps) {
    const totalVulns = criticalCount + highCount + mediumCount + lowCount;
    const riskColor = riskScore >= 75 ? "#ef4444" : riskScore >= 50 ? "#f97316" : riskScore >= 25 ? "#eab308" : "#00FF88";

    const metrics = [
        { label: "Critical", value: criticalCount, ...severityColors.critical, icon: AlertTriangle },
        { label: "High", value: highCount, ...severityColors.high, icon: Bug },
        { label: "Medium", value: mediumCount, ...severityColors.medium, icon: Shield },
        { label: "Low", value: lowCount, ...severityColors.low, icon: Activity },
    ];

    const globalMetrics = [
        { label: "Verified Exploits", value: verifiedExploits || activeExploits || 0, icon: Target, color: "#ef4444" },
        { label: "Attack Paths", value: attackPaths || lateralMovement || 0, icon: Link2, color: "#f97316" },
        { label: "Exposed Assets", value: exposedAssets || monitoredEndpoints || 0, icon: Eye, color: "#eab308" },
        { label: "Exfiltration Risk", value: `${exfiltrationRisk || 0}%`, icon: Radio, color: "#00A3FF" },
    ];

    const actions = [
        { label: "View Attack Chain", icon: Link2, onClick: onViewAttackChain, variant: "primary" as const },
        { label: "AI Risk Analysis", icon: Brain, onClick: onAIRiskAnalysis, variant: "primary" as const },
        { label: "Executive Summary", icon: FileText, onClick: onExecutiveSummary, variant: "secondary" as const },
        { label: "Export DFIR Report", icon: FileText, onClick: onExportDFIR, variant: "secondary" as const },
        { label: "Recalculate Risk", icon: RefreshCw, onClick: onRecalculateRisk, variant: "secondary" as const },
        { label: "Continuous Monitoring", icon: Radio, onClick: onContinuousMonitoring, variant: "accent" as const },
    ];

    return (
        <motion.div
            initial={{ opacity: 0, y: 20 }}
            animate={{ opacity: 1, y: 0 }}
            className="rounded-2xl overflow-hidden"
            style={{
                background: "var(--bg-card)",
                border: "1px solid var(--border-green)",
                boxShadow: "var(--shadow-card)",
            }}
        >
            {/* Header */}
            <div className="px-6 py-4 flex items-center justify-between"
                style={{ borderBottom: "1px solid var(--border-green)", background: "rgba(0,255,136,0.03)" }}>
                <div className="flex items-center gap-3">
                    <div className="w-10 h-10 rounded-xl flex items-center justify-center"
                        style={{ background: "rgba(0,255,136,0.1)", border: "1px solid rgba(0,255,136,0.2)" }}>
                        <Shield className="w-5 h-5 text-primary" />
                    </div>
                    <div>
                        <h2 className="text-lg font-black text-foreground uppercase tracking-tight">Global Security Summary</h2>
                        <p className="text-[10px] text-muted-foreground uppercase tracking-[0.2em] font-bold">Verified Security Posture</p>
                    </div>
                </div>
                <div className="flex items-center gap-2">
                    {threatLevel && (
                        <span className="px-2 py-0.5 rounded text-[9px] font-black uppercase tracking-tighter mr-2"
                            style={{
                                background: threatLevel === 'critical' ? 'rgba(239,68,68,0.2)' : 'rgba(249,115,22,0.2)',
                                color: threatLevel === 'critical' ? '#ef4444' : '#f97316',
                                border: `1px solid ${threatLevel === 'critical' ? '#ef4444' : '#f97316'}30`
                            }}>
                            {threatLevel} THREAT
                        </span>
                    )}
                    <div className="w-2 h-2 rounded-full bg-primary animate-pulse" />
                    <span className="text-[10px] font-bold text-primary uppercase tracking-widest">Live</span>
                </div>
            </div>

            <div className="p-6 space-y-6">
                {/* Risk Score + Total Vulns */}
                <div className="grid grid-cols-1 md:grid-cols-6 gap-4">
                    {/* Overall Risk Score */}
                    <div className="md:col-span-2 rounded-xl p-5 relative overflow-hidden"
                        style={{ background: "var(--bg-elevated)", border: `1px solid ${riskColor}30` }}>
                        <div className="absolute top-0 right-0 w-32 h-32 rounded-full opacity-10"
                            style={{ background: `radial-gradient(circle, ${riskColor}, transparent)`, transform: "translate(30%, -30%)" }} />
                        <p className="text-[10px] text-muted-foreground uppercase tracking-[0.2em] font-bold mb-2">Overall Risk Score</p>
                        <div className="flex items-end gap-2">
                            <span className="text-5xl font-black" style={{ color: riskColor }}>{riskScore}</span>
                            <span className="text-lg text-muted-foreground mb-1">%</span>
                        </div>
                        <div className="mt-3 h-2 rounded-full overflow-hidden" style={{ background: "var(--bg-elevated)" }}>
                            <motion.div
                                className="h-full rounded-full"
                                initial={{ width: 0 }}
                                animate={{ width: `${riskScore}%` }}
                                transition={{ duration: 1.5, ease: "easeOut" }}
                                style={{ background: `linear-gradient(90deg, ${riskColor}88, ${riskColor})` }}
                            />
                        </div>
                        <p className="text-xs mt-2 font-semibold" style={{ color: riskColor }}>
                            {riskScore >= 75 ? "CRITICAL RISK" : riskScore >= 50 ? "HIGH RISK" : riskScore >= 25 ? "MODERATE RISK" : "LOW RISK"}
                        </p>
                    </div>

                    {/* Severity Breakdown */}
                    {metrics.map((m, i) => (
                        <motion.div
                            key={m.label}
                            initial={{ opacity: 0, y: 10 }}
                            animate={{ opacity: 1, y: 0 }}
                            transition={{ delay: i * 0.1 }}
                            className="rounded-xl p-4 hover-lift cursor-default"
                            style={{ background: m.bg, border: `1px solid ${m.text}20`, boxShadow: m.glow }}
                        >
                            <div className="flex items-center justify-between mb-2">
                                <m.icon className="w-4 h-4" style={{ color: m.text }} />
                                <span className="text-[10px] font-bold uppercase tracking-wider" style={{ color: m.text }}>{m.label}</span>
                            </div>
                            <p className="text-3xl font-black" style={{ color: m.text }}>{m.value}</p>
                            <div className="mt-1 h-1 rounded-full overflow-hidden" style={{ background: `${m.text}15` }}>
                                <div className="h-full rounded-full" style={{ width: totalVulns ? `${(m.value / totalVulns) * 100}%` : "0%", background: m.text }} />
                            </div>
                        </motion.div>
                    ))}
                </div>

                {/* Secondary Metrics */}
                <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
                    {globalMetrics.map((m, i) => (
                        <motion.div
                            key={m.label}
                            initial={{ opacity: 0, x: -10 }}
                            animate={{ opacity: 1, x: 0 }}
                            transition={{ delay: 0.3 + i * 0.1 }}
                            className="rounded-xl p-4 flex items-center gap-4"
                            style={{ background: "var(--bg-elevated)", border: `1px solid ${m.color}20` }}
                        >
                            <div className="w-12 h-12 rounded-xl flex items-center justify-center"
                                style={{ background: `${m.color}15`, border: `1px solid ${m.color}25` }}>
                                <m.icon className="w-5 h-5" style={{ color: m.color }} />
                            </div>
                            <div>
                                <p className="text-2xl font-black text-foreground">{m.value}</p>
                                <p className="text-[10px] text-muted-foreground uppercase tracking-wider font-bold">{m.label}</p>
                            </div>
                        </motion.div>
                    ))}
                </div>

                {/* Action Buttons */}
                <div className="flex flex-wrap gap-2">
                    {actions.map((a, i) => (
                        <motion.button
                            key={a.label}
                            initial={{ opacity: 0, scale: 0.95 }}
                            animate={{ opacity: 1, scale: 1 }}
                            transition={{ delay: 0.5 + i * 0.05 }}
                            onClick={a.onClick}
                            className="flex items-center gap-2 px-4 py-2.5 rounded-xl text-xs font-bold uppercase tracking-wider transition-all duration-300"
                            style={{
                                background: a.variant === "primary" ? "rgba(0,255,136,0.1)" :
                                    a.variant === "accent" ? "rgba(0,163,255,0.1)" : "var(--bg-elevated)",
                                border: `1px solid ${a.variant === "primary" ? "rgba(0,255,136,0.25)" :
                                    a.variant === "accent" ? "rgba(0,163,255,0.25)" : "var(--border-green)"}`,
                                color: a.variant === "primary" ? "var(--neon-green)" :
                                    a.variant === "accent" ? "#00A3FF" : "var(--text-secondary)",
                            }}
                            whileHover={{ scale: 1.02, y: -1 }}
                            whileTap={{ scale: 0.98 }}
                        >
                            <a.icon className="w-3.5 h-3.5" />
                            {a.label}
                        </motion.button>
                    ))}
                </div>
            </div>
        </motion.div>
    );
}
