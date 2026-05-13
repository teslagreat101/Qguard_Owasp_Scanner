"use client";

import React, { useState, useMemo } from "react";
import {
    BarChart3,
    Target,
    Layers,
    GitMerge,
    TrendingUp,
    ChevronDown,
    ChevronUp,
    AlertTriangle
} from "lucide-react";
import { InsightCard } from "./InsightCard";
import { cn } from "@/lib/utils";

interface AIInsightSidebarProps {
    findings: any[];
    onInsightInteract: (topic: string) => void;
}

export function AIInsightSidebar({ findings, onInsightInteract }: AIInsightSidebarProps) {
    const [openSections, setOpenSections] = useState({
        risk: true,
        vulnerabilities: true,
        remediation: true
    });

    const toggleSection = (section: keyof typeof openSections) => {
        setOpenSections(prev => ({ ...prev, [section]: !prev[section] }));
    };

    const stats = useMemo(() => {
        const critical = findings.filter(f => f.severity === "critical").length;
        const high = findings.filter(f => f.severity === "high").length;
        const medium = findings.filter(f => f.severity === "medium").length;
        const low = findings.filter(f => f.severity === "low").length;

        // Threat score: weighted severity sum capped at 100
        const raw = critical * 25 + high * 12 + medium * 5 + low * 2;
        const threatScore = Math.min(100, raw);

        // Risk trend label
        let trendLabel = "Clean";
        let trendDetail = "No significant threats detected";
        if (critical > 0) { trendLabel = "Critical"; trendDetail = `${critical} critical issue${critical > 1 ? "s" : ""} require immediate action`; }
        else if (high > 3) { trendLabel = "Degraded"; trendDetail = `${high} high-severity findings detected`; }
        else if (high > 0) { trendLabel = "Elevated"; trendDetail = `${high} high-severity finding${high > 1 ? "s" : ""} detected`; }
        else if (medium > 0) { trendLabel = "Moderate"; trendDetail = `${medium} medium-severity finding${medium > 1 ? "s" : ""}`; }

        // Cluster by OWASP category
        const categoryMap: Record<string, number> = {};
        findings.forEach(f => {
            const cat = f.owasp || f.category || f.module_name || "Uncategorized";
            categoryMap[cat] = (categoryMap[cat] || 0) + 1;
        });
        const clusters = Object.keys(categoryMap).length;
        const topCategory = Object.entries(categoryMap).sort((a, b) => b[1] - a[1])[0];

        // Fix priorities: top critical/high findings by title
        const priorityFindings = [...findings]
            .filter(f => ["critical", "high", "medium"].includes(f.severity))
            .sort((a, b) => {
                const order: Record<string, number> = { critical: 3, high: 2, medium: 1 };
                return (order[b.severity] || 0) - (order[a.severity] || 0);
            })
            .slice(0, 3);

        const fixItems = priorityFindings.map(f => ({
            label: f.title?.slice(0, 32) || "Unknown Finding",
            severity: f.severity as string,
            prompt: `How do I fix: ${f.title}?`,
        }));

        // Correlation certainty
        const correlation = clusters > 2 ? "High" : clusters > 0 ? "Moderate" : "N/A";

        return { threatScore, trendLabel, trendDetail, clusters, topCategory, fixItems, correlation, critical, high };
    }, [findings]);

    const empty = findings.length === 0;

    return (
        <div className="h-full overflow-y-auto pr-2 custom-scrollbar space-y-6">
            {/* Risk Summary Section */}
            <div className="space-y-3">
                <button
                    type="button"
                    onClick={() => toggleSection('risk')}
                    className="flex items-center justify-between w-full px-1"
                >
                    <div className="flex items-center gap-2">
                        <BarChart3 className="w-3.5 h-3.5 text-primary" />
                        <span className="text-[11px] font-black text-foreground uppercase tracking-widest">Risk Summary</span>
                    </div>
                    {openSections.risk ? <ChevronUp className="w-3 h-3 text-muted-foreground" /> : <ChevronDown className="w-3 h-3 text-muted-foreground" />}
                </button>

                {openSections.risk && (
                    <div className="grid gap-3 animate-in fade-in slide-in-from-top-1 duration-300">
                        <InsightCard
                            icon={Target}
                            title="Threat Level"
                            value={empty ? "—" : `${stats.threatScore}/100`}
                            label={empty ? "No Data" : stats.threatScore >= 75 ? "Severe" : stats.threatScore >= 40 ? "Elevated" : "Low"}
                            severity={stats.threatScore >= 75 ? "high" : "low"}
                            trend={empty ? "Run a scan to populate" : `${findings.length} finding${findings.length !== 1 ? "s" : ""} detected`}
                            onClick={() => onInsightInteract(`Explain the current threat level of ${stats.threatScore}/100 and which findings are contributing most.`)}
                        />
                        <InsightCard
                            icon={TrendingUp}
                            title="Risk Trend"
                            value={empty ? "—" : stats.trendLabel}
                            label="Status"
                            trend={empty ? "Awaiting scan data" : stats.trendDetail}
                            onClick={() => onInsightInteract(`What assets are contributing to the ${stats.trendLabel} risk trend and what should be prioritized?`)}
                        />
                    </div>
                )}
            </div>

            {/* Intelligence Section */}
            <div className="space-y-3">
                <button
                    type="button"
                    onClick={() => toggleSection('vulnerabilities')}
                    className="flex items-center justify-between w-full px-1"
                >
                    <div className="flex items-center gap-2">
                        <Layers className="w-3.5 h-3.5 text-blue-500" />
                        <span className="text-[11px] font-black text-foreground uppercase tracking-widest">Intelligence</span>
                    </div>
                    {openSections.vulnerabilities ? <ChevronUp className="w-3 h-3 text-muted-foreground" /> : <ChevronDown className="w-3 h-3 text-muted-foreground" />}
                </button>

                {openSections.vulnerabilities && (
                    <div className="grid gap-3 animate-in fade-in slide-in-from-top-1 duration-300">
                        <InsightCard
                            icon={Layers}
                            title="Clusters"
                            value={empty ? "—" : String(stats.clusters)}
                            label={empty ? "No Data" : stats.topCategory ? `Top: ${stats.topCategory[0].slice(0, 12)}` : "Linked Issues"}
                            onClick={() => onInsightInteract("Explain the vulnerability clusters found in this scan and how they relate to each other.")}
                        />
                        <InsightCard
                            icon={GitMerge}
                            title="Correlation"
                            value={empty ? "—" : stats.correlation}
                            label="Certainty"
                            onClick={() => onInsightInteract("Analyze the correlation between detected vulnerabilities, secrets, and the scan target's history.")}
                        />
                    </div>
                )}
            </div>

            {/* Fix Radar Section */}
            <div className="space-y-3">
                <div className="flex items-center gap-2 px-1">
                    <GitMerge className="w-3.5 h-3.5 text-amber-500" />
                    <span className="text-[11px] font-black text-foreground uppercase tracking-widest">Fix Radar</span>
                </div>

                <div className="space-y-2">
                    {empty ? (
                        <div className="px-3 py-3 rounded-lg bg-secondary border border-border text-center">
                            <p className="text-[10px] text-muted-foreground uppercase tracking-wider">No active findings</p>
                        </div>
                    ) : stats.fixItems.length > 0 ? (
                        stats.fixItems.map((fix, i) => (
                            <div
                                key={`${fix.label}-${i}`}
                                className="px-3 py-2 rounded-lg bg-secondary border border-border flex items-center justify-between group hover:border-primary/20 transition-colors cursor-pointer"
                                onClick={() => onInsightInteract(fix.prompt)}
                            >
                                <span className="text-[10px] text-muted-foreground font-medium truncate max-w-[140px]">{fix.label}</span>
                                <span className={cn(
                                    "w-1.5 h-1.5 rounded-full shadow-[0_0_8px] shrink-0",
                                    fix.severity === "critical" ? "bg-red-500 shadow-red-500/50"
                                        : fix.severity === "high" ? "bg-orange-500 shadow-orange-500/50"
                                            : "bg-amber-500 shadow-amber-500/50"
                                )} />
                            </div>
                        ))
                    ) : (
                        <div className="px-3 py-2 rounded-lg bg-secondary border border-border">
                            <p className="text-[10px] text-muted-foreground uppercase tracking-wider text-center">All clear</p>
                        </div>
                    )}
                </div>
            </div>
        </div>
    );
}
