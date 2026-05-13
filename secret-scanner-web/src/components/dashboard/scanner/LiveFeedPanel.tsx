"use client";

import React, { useState, useEffect, useRef, useMemo } from "react";
import { GlowCard } from "./GlowCard";
import { Search, ShieldAlert, Clock, ChevronRight, AlertTriangle, Shield } from "lucide-react";
import { cn } from "@/lib/utils";
import { motion, AnimatePresence } from "framer-motion";

interface Finding {
    id: string;
    severity: "critical" | "high" | "medium" | "low" | "info" | string;
    title: string;
    target: string;
    timestamp: string;
    module?: string;
    cwe?: string;
    owasp?: string;
    matched_content?: string;
    description?: string;
    line_number?: number | null;
    confidence?: number | null;
    verified?: boolean;
}

interface LiveFeedPanelProps {
    findings: Finding[];
    isScanning: boolean;
}

const severityTw: Record<string, { icon: string; badge: string; dot: string; border: string }> = {
    critical: {
        icon: "bg-red-500/10 text-red-500",
        badge: "text-red-500 bg-red-500/10 border-red-500/20",
        dot: "bg-red-500",
        border: "border-l-red-500",
    },
    high: {
        icon: "bg-orange-500/10 text-orange-500",
        badge: "text-orange-500 bg-orange-500/10 border-orange-500/20",
        dot: "bg-orange-500",
        border: "border-l-orange-500",
    },
    medium: {
        icon: "bg-yellow-500/10 text-yellow-500",
        badge: "text-yellow-500 bg-yellow-500/10 border-yellow-500/20",
        dot: "bg-yellow-500",
        border: "border-l-yellow-500",
    },
    low: {
        icon: "bg-blue-500/10 text-blue-500",
        badge: "text-blue-500 bg-blue-500/10 border-blue-500/20",
        dot: "bg-blue-500",
        border: "border-l-blue-500",
    },
    info: {
        icon: "bg-muted/10 text-muted-foreground",
        badge: "text-muted-foreground bg-muted/10 border-border/20",
        dot: "bg-muted",
        border: "border-l-gray-500",
    },
};

function getSeverityTw(sev: string) {
    return severityTw[sev?.toLowerCase()] ?? severityTw.low;
}

function DetailRow({ label, value }: { label: string; value: string }) {
    return (
        <div className="space-y-0.5">
            <p className="text-[8px] text-muted-foreground font-bold uppercase tracking-widest">{label}</p>
            <p className="text-[10px] font-mono text-muted-foreground/80 truncate">{value}</p>
        </div>
    );
}

export function LiveFeedPanel({ findings, isScanning }: LiveFeedPanelProps) {
    const [filter, setFilter] = useState<string>("all");
    const [expandedId, setExpandedId] = useState<string | null>(null);
    const scrollRef = useRef<HTMLDivElement>(null);

    const filteredFindings = findings.filter(f => filter === "all" || f.severity === filter);

    const MAX_DISPLAY = 200;
    const hasMore = filteredFindings.length > MAX_DISPLAY;
    const displayFindings = useMemo(
        () => filteredFindings.slice(0, MAX_DISPLAY).reverse(),
        // eslint-disable-next-line react-hooks/exhaustive-deps
        [filteredFindings.length, filter]
    );

    useEffect(() => {
        if (scrollRef.current && isScanning) {
            scrollRef.current.scrollTop = 0;
        }
    }, [findings, isScanning]);

    const stats = useMemo(() => ({
        all: findings.length,
        critical: findings.filter(f => f.severity === "critical").length,
        high: findings.filter(f => f.severity === "high").length,
        medium: findings.filter(f => f.severity === "medium").length,
        low: findings.filter(f => f.severity === "low").length,
    }), [findings]);

    // Unique OWASP categories found
    const owaspCategories = useMemo(() => {
        const cats = new Set<string>();
        findings.forEach(f => { if (f.owasp) cats.add(f.owasp); });
        return cats.size;
    }, [findings]);

    // Unique modules that produced findings
    const activeModules = useMemo(() => {
        const mods = new Set<string>();
        findings.forEach(f => { if (f.module) mods.add(f.module); });
        return mods.size;
    }, [findings]);

    return (
        <GlowCard className="h-full flex flex-col" glowColor="rgba(var(--primary), 0.08)">
            {/* Header */}
            <div className="mb-4 flex items-start justify-between">
                <div className="space-y-1">
                    <div className="flex items-center gap-2">
                        <ShieldAlert className="w-4 h-4 text-primary" />
                        <h2 className="text-sm font-bold text-foreground uppercase tracking-tight">Live Findings</h2>
                    </div>
                    <p className="text-[10px] text-muted-foreground font-medium uppercase tracking-wider">Real-time vulnerability detection</p>
                </div>
                {isScanning && (
                    <div className="flex items-center gap-1.5 px-2 py-1 rounded-full bg-primary/10 border border-primary/20">
                        <motion.div
                            className="w-1.5 h-1.5 rounded-full bg-primary"
                            animate={{ scale: [1, 1.4, 1] }}
                            transition={{ duration: 1, repeat: Infinity }}
                        />
                        <span className="text-[9px] font-bold text-primary uppercase">Live</span>
                    </div>
                )}
            </div>

            {/* Summary Metrics Row */}
            {findings.length > 0 && (
                <div className="grid grid-cols-4 gap-2 mb-4">
                    <div className="bg-secondary/50 rounded-lg p-2 border border-border text-center">
                        <p className="text-[16px] font-bold text-foreground">{findings.length}</p>
                        <p className="text-[8px] text-muted-foreground uppercase tracking-wider">Total</p>
                    </div>
                    <div className="bg-secondary/50 rounded-lg p-2 border border-red-500/20 text-center">
                        <p className="text-[16px] font-bold text-red-500">{stats.critical + stats.high}</p>
                        <p className="text-[8px] text-muted-foreground uppercase tracking-wider">High+</p>
                    </div>
                    <div className="bg-secondary/50 rounded-lg p-2 border border-border text-center">
                        <p className="text-[16px] font-bold text-foreground">{owaspCategories}</p>
                        <p className="text-[8px] text-muted-foreground uppercase tracking-wider">OWASP</p>
                    </div>
                    <div className="bg-secondary/50 rounded-lg p-2 border border-border text-center">
                        <p className="text-[16px] font-bold text-foreground">{activeModules}</p>
                        <p className="text-[8px] text-muted-foreground uppercase tracking-wider">Modules</p>
                    </div>
                </div>
            )}

            {/* Filters */}
            <div className="flex flex-wrap gap-1.5 mb-4">
                {(["all", "critical", "high", "medium", "low"] as const).map((sev) => (
                    <button
                        type="button"
                        key={sev}
                        onClick={() => setFilter(sev)}
                        className={cn(
                            "flex items-center gap-1.5 px-2.5 py-1 rounded-md text-[9px] font-bold uppercase transition-colors border",
                            filter === sev
                                ? "bg-background border-border text-foreground"
                                : "bg-transparent border-transparent text-muted-foreground hover:text-foreground hover:bg-secondary/50"
                        )}
                    >
                        <span className={cn("w-1.5 h-1.5 rounded-full", sev === "all" ? "bg-muted-foreground" : getSeverityTw(sev).dot)} />
                        {sev}
                        <span className="opacity-50 font-mono">({stats[sev]})</span>
                    </button>
                ))}
            </div>

            {/* Feed Container */}
            <div
                ref={scrollRef}
                className="flex-1 overflow-y-auto space-y-1.5 pr-1 scrollbar-thin scrollbar-thumb-muted-foreground/20"
            >
                <AnimatePresence initial={false}>
                    {hasMore && (
                        <div className="text-[9px] text-center text-muted-foreground py-1.5 border-b border-border font-mono">
                            — Showing {MAX_DISPLAY} of {filteredFindings.length} findings
                            {filter !== "all" && ` (${filter})`} —
                        </div>
                    )}
                    {displayFindings.length > 0 ? (
                        displayFindings.map((finding) => {
                            const tw = getSeverityTw(finding.severity);
                            const isExpanded = expandedId === finding.id;
                            const hasDetails = !!(finding.cwe || finding.owasp || finding.module || finding.description || finding.matched_content || finding.line_number);

                            return (
                                <motion.div
                                    key={finding.id}
                                    initial={{ opacity: 0, x: 12, scale: 0.97 }}
                                    animate={{ opacity: 1, x: 0, scale: 1 }}
                                    transition={{ duration: 0.15 }}
                                    className={cn(
                                        "rounded-lg border-l-2 border bg-secondary/30 transition-colors duration-200 overflow-hidden",
                                        tw.border,
                                        isExpanded
                                            ? "border-r-border/80 border-t-border/80 border-b-border/80 bg-background"
                                            : "border-r-border/30 border-t-border/30 border-b-border/30 hover:bg-secondary/50"
                                    )}
                                >
                                    <button
                                        type="button"
                                        onClick={() => setExpandedId(prev => prev === finding.id ? null : finding.id)}
                                        className="w-full text-left px-3 py-2.5"
                                        aria-expanded={isExpanded}
                                    >
                                        <div className="flex items-start gap-2.5">
                                            <div className={cn("p-1 rounded shrink-0", tw.icon)}>
                                                <ShieldAlert className="w-3.5 h-3.5" />
                                            </div>
                                            <div className="flex-1 space-y-0.5 min-w-0">
                                                <div className="flex items-center justify-between gap-2">
                                                    <h4 className="text-[11px] font-bold text-foreground leading-tight truncate">
                                                        {finding.title}
                                                    </h4>
                                                    <div className="flex items-center gap-1.5 shrink-0">
                                                        {finding.verified && (
                                                            <span className="text-[8px] font-bold text-primary bg-primary/10 px-1.5 py-0.5 rounded border border-primary/20">
                                                                VERIFIED
                                                            </span>
                                                        )}
                                                        <span className={cn("text-[8px] font-black uppercase px-1.5 py-0.5 rounded border", tw.badge)}>
                                                            {finding.severity}
                                                        </span>
                                                    </div>
                                                </div>
                                                <div className="flex items-center gap-3 text-[9px] text-muted-foreground">
                                                    <span className="truncate max-w-[180px]">{finding.target || "—"}</span>
                                                    {finding.module && (
                                                        <span className="text-muted-foreground/70">{finding.module}</span>
                                                    )}
                                                    {finding.confidence != null && (
                                                        <span className="text-muted-foreground/70">{(finding.confidence * 100).toFixed(0)}%</span>
                                                    )}
                                                </div>
                                            </div>
                                            <motion.div
                                                animate={{ rotate: isExpanded ? 90 : 0 }}
                                                transition={{ duration: 0.15 }}
                                                className="shrink-0 mt-1"
                                            >
                                                <ChevronRight className={cn("w-3.5 h-3.5", isExpanded ? "text-primary" : "text-muted-foreground/30")} />
                                            </motion.div>
                                        </div>
                                    </button>

                                    {/* Expandable Detail Panel */}
                                    <AnimatePresence>
                                        {isExpanded && (
                                            <motion.div
                                                key="detail"
                                                initial={{ height: 0, opacity: 0 }}
                                                animate={{ height: "auto", opacity: 1 }}
                                                exit={{ height: 0, opacity: 0 }}
                                                transition={{ duration: 0.2 }}
                                                className="overflow-hidden"
                                            >
                                                <div className="px-3 pb-3 pt-1 border-t border-border/50 space-y-2.5">
                                                    {/* Metadata Grid */}
                                                    {(finding.cwe || finding.owasp || finding.module || finding.line_number) && (
                                                        <div className="grid grid-cols-2 gap-x-4 gap-y-1.5">
                                                            {finding.cwe && <DetailRow label="CWE" value={finding.cwe} />}
                                                            {finding.owasp && <DetailRow label="OWASP" value={finding.owasp} />}
                                                            {finding.module && <DetailRow label="Module" value={finding.module} />}
                                                            {finding.line_number != null && <DetailRow label="Line" value={String(finding.line_number)} />}
                                                        </div>
                                                    )}

                                                    {finding.description && (
                                                        <div className="space-y-0.5">
                                                            <p className="text-[8px] text-muted-foreground font-bold uppercase tracking-widest">Description</p>
                                                            <p className="text-[10px] text-muted-foreground/80 leading-relaxed">
                                                                {finding.description.slice(0, 200)}{finding.description.length > 200 ? "…" : ""}
                                                            </p>
                                                        </div>
                                                    )}

                                                    {finding.matched_content && (
                                                        <div className="space-y-0.5">
                                                            <p className="text-[8px] text-muted-foreground font-bold uppercase tracking-widest">Evidence</p>
                                                            <code className="block text-[10px] font-mono text-red-500 bg-muted/50 border border-red-500/10 rounded-md p-2 break-all leading-relaxed max-h-16 overflow-y-auto">
                                                                {finding.matched_content.slice(0, 200)}{finding.matched_content.length > 200 ? "…" : ""}
                                                            </code>
                                                        </div>
                                                    )}

                                                    {!hasDetails && (
                                                        <p className="text-[9px] text-muted-foreground uppercase tracking-widest text-center py-1">
                                                            No additional detail available
                                                        </p>
                                                    )}
                                                </div>
                                            </motion.div>
                                        )}
                                    </AnimatePresence>
                                </motion.div>
                            );
                        })
                    ) : (
                        <div className="h-full flex flex-col items-center justify-center space-y-3 opacity-30 py-8">
                            <div className="p-4 rounded-full bg-gradient-to-b from-muted/10 to-transparent">
                                <Shield className="w-8 h-8 text-muted-foreground" />
                            </div>
                            <div className="text-center">
                                <h3 className="text-xs font-bold text-foreground uppercase tracking-widest">No Findings</h3>
                                <p className="text-[9px] text-muted-foreground uppercase mt-0.5">
                                    {isScanning ? "Scanning in progress..." : "Start a scan to detect vulnerabilities"}
                                </p>
                            </div>
                        </div>
                    )}
                </AnimatePresence>
            </div>

            {/* Footer */}
            <div className="mt-3 pt-3 border-t border-border flex items-center justify-between">
                <span className="text-[9px] uppercase font-bold text-muted-foreground tracking-wider">
                    {hasMore
                        ? `${MAX_DISPLAY} of ${filteredFindings.length} displayed`
                        : `${filteredFindings.length} finding${filteredFindings.length !== 1 ? "s" : ""}`}
                    {filter !== "all" && ` · ${filter}`}
                </span>
                <button type="button" className="text-[9px] uppercase font-bold text-primary/60 hover:text-primary tracking-widest transition-colors">
                    Export
                </button>
            </div>
        </GlowCard>
    );
}
