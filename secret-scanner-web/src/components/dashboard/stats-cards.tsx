"use client";

import { motion } from "framer-motion";
import { GlowCard } from "@/components/ui/glow-card";
import { cn } from "@/lib/utils";
import { FileSearch, AlertTriangle, Shield, TrendingUp, Zap } from "lucide-react";
import Link from "next/link";

interface StatsCardsProps {
    totalScans: number;
    completedScans: number;
    totalFindings: number;
    criticalFindings: number;
    securityScore: number;
    runningScans: number;
    plan?: string;
    scansUsed?: number;
    scansLimit?: number;
}

export function StatsCards({ totalScans, completedScans, totalFindings, criticalFindings, securityScore, runningScans, plan, scansUsed, scansLimit }: StatsCardsProps) {
    const used = scansUsed ?? 0;
    const limit = scansLimit ?? 0;
    const isUnlimited = !limit || limit >= 1000000;
    const usageRatio = isUnlimited ? 0 : used / limit;
    const isAtLimit = !isUnlimited && used >= limit;
    const isNearLimit = !isUnlimited && !isAtLimit && usageRatio >= 0.8;

    const quotaSubtext = isUnlimited
        ? "Unlimited Scans"
        : isAtLimit
            ? "Limit Reached — Upgrade Now"
            : `${used} / ${limit} Scans Used`;

    const quotaColor = isAtLimit
        ? "text-red-400"
        : isNearLimit
            ? "text-amber-400"
            : "text-primary";

    const quotaGlow = isAtLimit
        ? "rgba(239, 68, 68, 0.12)"
        : isNearLimit
            ? "rgba(251, 191, 36, 0.1)"
            : "rgba(var(--primary), 0.08)";

    const stats = [
        {
            title: "Total Scans",
            value: totalScans,
            subtext: `${completedScans} completed${runningScans > 0 ? ` · ${runningScans} active` : ""}`,
            icon: FileSearch,
            color: "text-primary",
            glow: "rgba(var(--primary), 0.1)",
        },
        {
            title: "Total Findings",
            value: totalFindings,
            subtext: "Across all scans",
            icon: AlertTriangle,
            color: "text-orange-400",
            glow: "rgba(249, 115, 22, 0.1)",
        },
        {
            title: "Critical Issues",
            value: criticalFindings,
            subtext: criticalFindings > 0 ? "Require immediate action" : "No critical issues",
            icon: Shield,
            color: criticalFindings > 0 ? "text-red-500" : "text-primary",
            glow: criticalFindings > 0 ? "rgba(239, 68, 68, 0.1)" : "rgba(var(--primary), 0.1)",
        },
        {
            title: "Security Score",
            value: `${securityScore}/100`,
            subtext: securityScore > 80 ? "Good" : securityScore > 50 ? "Needs Attention" : "Critical",
            icon: TrendingUp,
            color: securityScore > 80 ? "text-primary" : securityScore > 50 ? "text-yellow-500" : "text-red-500",
            glow: securityScore > 80 ? "rgba(var(--primary), 0.1)" : "rgba(234, 179, 8, 0.1)",
        },
    ];

    return (
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-5 gap-4">
            {stats.map((stat, i) => (
                <motion.div key={stat.title} initial={{ opacity: 0, y: 20 }} animate={{ opacity: 1, y: 0 }} transition={{ delay: i * 0.08 }}>
                    <GlowCard className="p-0 border-border bg-card" glowColor={stat.glow}>
                        <div className="flex flex-row items-center justify-between space-y-0 pb-2">
                            <h3 className="text-[10px] uppercase tracking-[0.2em] font-medium text-muted-foreground">{stat.title}</h3>
                            <div className={cn("p-2 rounded-lg bg-secondary border border-border")}>
                                <stat.icon className={cn("h-4 w-4", stat.color)} />
                            </div>
                        </div>
                        <div className="mt-3">
                            <div className={cn("text-3xl font-black tracking-tighter", stat.color)}>{stat.value}</div>
                            <p className="text-[10px] uppercase tracking-widest text-muted-foreground mt-1 font-bold">{stat.subtext}</p>
                        </div>
                    </GlowCard>
                </motion.div>
            ))}

            {/* Plan & Quota card — 5th column with dynamic limit warnings */}
            <motion.div initial={{ opacity: 0, y: 20 }} animate={{ opacity: 1, y: 0 }} transition={{ delay: 4 * 0.08 }}>
                <GlowCard
                    className={cn(
                        "p-0 border-border bg-card",
                        isAtLimit && "border-red-500/30",
                        isNearLimit && "border-amber-500/20"
                    )}
                    glowColor={quotaGlow}
                >
                    <div className="flex flex-row items-center justify-between space-y-0 pb-2">
                        <h3 className="text-[10px] uppercase tracking-[0.2em] font-medium text-muted-foreground">Plan & Quota</h3>
                        <div className={cn(
                            "p-2 rounded-lg bg-secondary border",
                            isAtLimit ? "border-red-500/30" : isNearLimit ? "border-amber-500/20" : "border-border"
                        )}>
                            {isAtLimit ? (
                                <AlertTriangle className="h-4 w-4 text-red-400" />
                            ) : (
                                <Zap className={cn("h-4 w-4", quotaColor)} />
                            )}
                        </div>
                    </div>
                    <div className="mt-3">
                        <div className={cn("text-3xl font-black tracking-tighter", quotaColor)}>
                            {(plan || "Free").toUpperCase()}
                        </div>
                        <p className={cn(
                            "text-[10px] uppercase tracking-widest mt-1 font-bold",
                            isAtLimit ? "text-red-400" : isNearLimit ? "text-amber-400" : "text-muted-foreground"
                        )}>
                            {quotaSubtext}
                        </p>

                        {/* Usage progress bar for capped plans */}
                        {!isUnlimited && (
                            <div className="mt-2 w-full bg-white/5 rounded-full h-1 overflow-hidden">
                                <div
                                    className={cn(
                                        "h-full rounded-full transition-all duration-500",
                                        isAtLimit
                                            ? "bg-red-500 shadow-[0_0_6px_rgba(239,68,68,0.6)]"
                                            : isNearLimit
                                                ? "bg-amber-400 shadow-[0_0_6px_rgba(251,191,36,0.4)]"
                                                : "bg-primary shadow-[0_0_6px_rgba(var(--primary),0.4)]"
                                    )}
                                    style={{ width: `${Math.min(100, usageRatio * 100)}%` }}
                                />
                            </div>
                        )}

                        {/* Upgrade CTA when at/near limit */}
                        {(isAtLimit || isNearLimit) && (
                            <Link href="/billing" className="block mt-2">
                                <span className={cn(
                                    "text-[9px] font-black uppercase tracking-widest px-2 py-0.5 rounded-full border inline-block",
                                    isAtLimit
                                        ? "text-red-400 border-red-500/30 bg-red-500/5 hover:bg-red-500/10"
                                        : "text-amber-400 border-amber-500/30 bg-amber-500/5 hover:bg-amber-500/10"
                                )}>
                                    {isAtLimit ? "Upgrade Required →" : "Upgrade Soon →"}
                                </span>
                            </Link>
                        )}
                    </div>
                </GlowCard>
            </motion.div>
        </div>
    );
}
