"use client";

import React, { useState, useMemo, useEffect } from "react";
import { GlowCard } from "./GlowCard";
import { cn } from "@/lib/utils";
import { Download, Filter, ChevronUp, ChevronDown, ExternalLink, ShieldAlert, X, Search } from "lucide-react";
import { motion, AnimatePresence } from "framer-motion";

interface Finding {
    id: string;
    severity: "critical" | "high" | "medium" | "low" | "info";
    title: string;
    target: string;
    module: string;
    confidence: number;
    timestamp: string;
}

interface FindingsTableProps {
    findings: Finding[];
    onExport?: () => void;
    /** True total finding count (may be higher than findings.length when state is capped) */
    totalFindingsCount?: React.RefObject<number>;
}

const PAGE_SIZE = 50;

export function FindingsTable({ findings, onExport, totalFindingsCount }: FindingsTableProps) {
    const [sortField, setSortField] = useState<keyof Finding>("severity");
    const [sortOrder, setSortOrder] = useState<"asc" | "desc">("desc");
    const [showFilter, setShowFilter] = useState(false);
    const [filterSeverity, setFilterSeverity] = useState<string[]>([]);
    const [filterText, setFilterText] = useState("");
    const [filterModule, setFilterModule] = useState("");
    const [currentPage, setCurrentPage] = useState(1);

    const severityOrder: Record<string, number> = { critical: 4, high: 3, medium: 2, low: 1, info: 0 };

    const severityStyles = {
        critical: "text-red-500 bg-red-500/10 border-red-500/30",
        high: "text-orange-500 bg-orange-500/10 border-orange-500/30",
        medium: "text-amber-500 bg-amber-500/10 border-amber-500/30",
        low: "text-blue-500 bg-blue-500/10 border-blue-500/30",
        info: "text-muted-foreground bg-muted/10 border-border/30",
    };

    const severityDots: Record<string, string> = {
        critical: "bg-red-500",
        high: "bg-orange-500",
        medium: "bg-amber-500",
        low: "bg-blue-500",
        info: "bg-muted",
    };

    // Quick severity counts for filter bar
    const severityCounts = useMemo(() => ({
        all: findings.length,
        critical: findings.filter(f => f.severity === "critical").length,
        high: findings.filter(f => f.severity === "high").length,
        medium: findings.filter(f => f.severity === "medium").length,
        low: findings.filter(f => f.severity === "low").length,
        info: findings.filter(f => f.severity === "info").length,
    }), [findings]);

    const allModules = useMemo(() =>
        Array.from(new Set(findings.map(f => f.module))).filter(Boolean),
        [findings]
    );

    const filteredFindings = useMemo(() => {
        return findings.filter(f => {
            if (filterSeverity.length > 0 && !filterSeverity.includes(f.severity)) return false;
            if (filterModule && f.module !== filterModule) return false;
            if (filterText) {
                const q = filterText.toLowerCase();
                if (!f.title.toLowerCase().includes(q) && !f.target.toLowerCase().includes(q)) return false;
            }
            return true;
        });
    }, [findings, filterSeverity, filterModule, filterText]);

    const sortedFindings = useMemo(() => {
        return [...filteredFindings].sort((a, b) => {
            let aVal: any = a[sortField];
            let bVal: any = b[sortField];
            if (sortField === "severity") {
                aVal = severityOrder[a.severity] ?? 0;
                bVal = severityOrder[b.severity] ?? 0;
            }
            if (aVal < bVal) return sortOrder === "asc" ? -1 : 1;
            if (aVal > bVal) return sortOrder === "asc" ? 1 : -1;
            return 0;
        });
    }, [filteredFindings, sortField, sortOrder]);

    // Pagination — render only PAGE_SIZE rows at a time
    const totalPages = Math.max(1, Math.ceil(sortedFindings.length / PAGE_SIZE));
    const paginatedFindings = useMemo(() =>
        sortedFindings.slice((currentPage - 1) * PAGE_SIZE, currentPage * PAGE_SIZE),
        [sortedFindings, currentPage]
    );

    // Reset to page 1 whenever filters or sort change
    useEffect(() => {
        setCurrentPage(1);
    }, [filterSeverity, filterModule, filterText, sortField, sortOrder]);

    const activeFiltersCount = filterSeverity.length + (filterModule ? 1 : 0) + (filterText ? 1 : 0);

    const toggleSeverityFilter = (sev: string) => {
        setFilterSeverity(prev =>
            prev.includes(sev) ? prev.filter(s => s !== sev) : [...prev, sev]
        );
    };

    return (
        <GlowCard className="w-full" glowColor="rgba(255, 255, 255, 0.02)">
            <div className="flex items-center justify-between mb-6">
                <div>
                    <h2 className="text-xl font-bold text-foreground uppercase tracking-tighter flex items-center gap-3">
                        <ShieldAlert className="w-6 h-6 text-primary" />
                        Security Intelligence Ledger
                    </h2>
                    <p className="text-xs text-muted-foreground mt-1 uppercase tracking-wider">Historical and real-time detection telemetry</p>
                </div>

                <div className="flex items-center gap-3">
                    <button
                        type="button"
                        onClick={() => setShowFilter(f => !f)}
                        className={cn(
                            "flex items-center gap-2 px-4 py-2 rounded-lg border text-[11px] font-bold uppercase tracking-widest transition-colors",
                            showFilter
                                ? "bg-primary/10 border-primary/30 text-primary"
                                : "bg-card border-border text-muted-foreground hover:text-foreground hover:border-primary/20"
                        )}
                    >
                        <Filter className="w-3.5 h-3.5" />
                        Advanced Filter
                        {activeFiltersCount > 0 && (
                            <span className="ml-1 w-4 h-4 rounded-full bg-primary text-primary-foreground text-[9px] font-black flex items-center justify-center">{activeFiltersCount}</span>
                        )}
                    </button>
                    <button
                        type="button"
                        onClick={onExport}
                        className="flex items-center gap-2 px-4 py-2 rounded-lg bg-primary/10 border border-primary/20 text-primary hover:bg-primary/20 transition-colors text-[11px] font-bold uppercase tracking-widest"
                    >
                        <Download className="w-3.5 h-3.5" />
                        Export Data
                    </button>
                </div>
            </div>

            {/* Quick Severity Filter Bar — always visible */}
            <div className="flex flex-wrap gap-2 mb-4">
                {(["all", "critical", "high", "medium", "low", "info"] as const).map(sev => {
                    const count = severityCounts[sev];
                    const isActive = sev === "all"
                        ? filterSeverity.length === 0
                        : filterSeverity.length === 1 && filterSeverity[0] === sev;
                    return (
                        <button
                            key={sev}
                            type="button"
                            onClick={() => {
                                if (sev === "all") setFilterSeverity([]);
                                else setFilterSeverity([sev]);
                            }}
                            className={cn(
                                "flex items-center gap-2 px-3 py-1.5 rounded-lg text-[10px] font-bold uppercase border transition-colors",
                                isActive
                                    ? sev === "all"
                                        ? "bg-primary/10 border-primary/30 text-primary"
                                        : `${severityStyles[sev as keyof typeof severityStyles]} border-opacity-50`
                                    : "bg-transparent border-border text-muted-foreground hover:text-foreground hover:border-primary/20"
                            )}
                        >
                            {sev !== "all" && (
                                <span className={cn("w-1.5 h-1.5 rounded-full shrink-0", severityDots[sev])} />
                            )}
                            {sev}
                            <span className="opacity-50 font-mono">({count})</span>
                        </button>
                    );
                })}
            </div>

            {/* Advanced Filter Panel */}
            <AnimatePresence>
                {showFilter && (
                    <motion.div
                        initial={{ opacity: 0, height: 0 }}
                        animate={{ opacity: 1, height: "auto" }}
                        exit={{ opacity: 0, height: 0 }}
                        className="overflow-hidden mb-6"
                    >
                        <div className="bg-background/40 border border-border rounded-xl p-4 space-y-4">
                            <div className="flex items-center justify-between">
                                <span className="text-[10px] font-black text-foreground uppercase tracking-widest">Filter Controls</span>
                                {activeFiltersCount > 0 && (
                                    <button
                                        type="button"
                                        onClick={() => { setFilterSeverity([]); setFilterModule(""); setFilterText(""); }}
                                        className="flex items-center gap-1 text-[9px] text-destructive hover:text-destructive/80 uppercase tracking-widest"
                                    >
                                        <X className="w-3 h-3" /> Clear All
                                    </button>
                                )}
                            </div>

                            {/* Severity chips */}
                            <div className="space-y-1.5">
                                <p className="text-[9px] text-muted-foreground font-bold uppercase tracking-widest">Severity</p>
                                <div className="flex gap-2 flex-wrap">
                                    {["critical", "high", "medium", "low", "info"].map(sev => (
                                        <button
                                            type="button"
                                            key={sev}
                                            onClick={() => toggleSeverityFilter(sev)}
                                            className={cn(
                                                "px-3 py-1 rounded-md text-[10px] font-bold uppercase border transition-colors",
                                                filterSeverity.includes(sev)
                                                    ? severityStyles[sev as keyof typeof severityStyles]
                                                    : "border-border text-muted-foreground hover:border-primary/20 hover:text-foreground"
                                            )}
                                        >
                                            {sev}
                                        </button>
                                    ))}
                                </div>
                            </div>

                            {/* Module filter */}
                            {allModules.length > 0 && (
                                <div className="space-y-1.5">
                                    <p className="text-[9px] text-muted-foreground font-bold uppercase tracking-widest">Module</p>
                                    <div className="flex gap-2 flex-wrap">
                                        <button
                                            type="button"
                                            onClick={() => setFilterModule("")}
                                            className={cn(
                                                "px-3 py-1 rounded-md text-[10px] font-bold uppercase border transition-colors",
                                                !filterModule ? "border-primary/30 text-primary bg-primary/5" : "border-border text-muted-foreground hover:border-primary/20 hover:text-foreground"
                                            )}
                                        >All</button>
                                        {allModules.map(mod => (
                                            <button
                                                type="button"
                                                key={mod}
                                                onClick={() => setFilterModule(mod)}
                                                className={cn(
                                                    "px-3 py-1 rounded-md text-[10px] font-bold uppercase border transition-colors",
                                                    filterModule === mod ? "border-blue-500/30 text-blue-500 bg-blue-500/5" : "border-border text-muted-foreground hover:border-primary/20 hover:text-foreground"
                                                )}
                                            >{mod}</button>
                                        ))}
                                    </div>
                                </div>
                            )}

                            {/* Text search */}
                            <div className="space-y-1.5">
                                <p className="text-[9px] text-muted-foreground font-bold uppercase tracking-widest">Search</p>
                                <div className="flex items-center gap-2 bg-secondary border border-border rounded-lg px-3 py-2">
                                    <Search className="w-3.5 h-3.5 text-muted-foreground shrink-0" />
                                    <input
                                        type="text"
                                        value={filterText}
                                        onChange={e => setFilterText(e.target.value)}
                                        placeholder="Search title or target..."
                                        className="flex-1 bg-transparent text-[11px] text-foreground placeholder-muted-foreground outline-none font-mono"
                                    />
                                    {filterText && (
                                        <button type="button" onClick={() => setFilterText("")}>
                                            <X className="w-3 h-3 text-muted-foreground hover:text-foreground" />
                                        </button>
                                    )}
                                </div>
                            </div>
                        </div>
                    </motion.div>
                )}
            </AnimatePresence>

            <div className="overflow-x-auto">
                <table className="w-full border-collapse">
                    <thead>
                        <tr className="border-b border-border">
                            {[
                                { label: "Severity", field: "severity" },
                                { label: "ID Hash", field: "id" },
                                { label: "Target Asset", field: "target" },
                                { label: "Detection Vector", field: "module" },
                                { label: "Confidence", field: "confidence" },
                                { label: "Detected At", field: "timestamp" },
                            ].map((head) => (
                                <th
                                    key={head.field}
                                    className="px-4 py-4 text-left font-mono text-[10px] uppercase tracking-[0.2em] text-muted-foreground cursor-pointer hover:text-foreground transition-colors"
                                    onClick={() => {
                                        if (sortField === head.field) setSortOrder(sortOrder === "asc" ? "desc" : "asc");
                                        else setSortField(head.field as any);
                                    }}
                                >
                                    <div className="flex items-center gap-1">
                                        {head.label}
                                        {sortField === head.field && (
                                            sortOrder === "asc" ? <ChevronUp className="w-3 h-3" /> : <ChevronDown className="w-3 h-3" />
                                        )}
                                    </div>
                                </th>
                            ))}
                            <th className="px-4 py-4" aria-label="Actions"></th>
                        </tr>
                    </thead>
                    <tbody className="divide-y divide-border/50">
                        <AnimatePresence>
                            {paginatedFindings.length > 0 ? (
                                paginatedFindings.map((finding) => (
                                    <motion.tr
                                        key={finding.id}
                                        initial={{ opacity: 0 }}
                                        animate={{ opacity: 1 }}
                                        className="group hover:bg-muted/50 transition-colors"
                                    >
                                        <td className="px-4 py-4">
                                            <div className={cn(
                                                "inline-flex items-center px-2 py-0.5 rounded text-[9px] font-bold uppercase border",
                                                severityStyles[finding.severity] ?? "text-muted-foreground bg-secondary border-border"
                                            )}>
                                                {finding.severity}
                                            </div>
                                        </td>
                                        <td className="px-4 py-4 text-[11px] font-mono text-muted-foreground group-hover:text-foreground">
                                            {finding.id.substring(0, 8)}...
                                        </td>
                                        <td className="px-4 py-4 text-[11px] text-muted-foreground truncate max-w-[200px]">
                                            {finding.target}
                                        </td>
                                        <td className="px-4 py-4">
                                            <span className="text-[10px] text-muted-foreground font-bold uppercase tracking-tight">
                                                {finding.module}
                                            </span>
                                        </td>
                                        <td className="px-4 py-4">
                                            <div className="flex items-center gap-2">
                                                <div className="w-16 h-1 bg-secondary rounded-full overflow-hidden">
                                                    <div
                                                        className="h-full bg-blue-500"
                                                        style={{ width: `${finding.confidence * 100}%` }}
                                                    />
                                                </div>
                                                <span className="text-[10px] font-mono text-muted-foreground">{(finding.confidence * 100).toFixed(0)}%</span>
                                            </div>
                                        </td>
                                        <td className="px-4 py-4 text-[10px] text-muted-foreground font-mono">
                                            {finding.timestamp}
                                        </td>
                                        <td className="px-4 py-4 text-right">
                                            <button type="button" title="View finding details" className="p-2 opacity-0 group-hover:opacity-100 text-muted-foreground hover:text-primary transition-colors">
                                                <ExternalLink className="w-4 h-4" />
                                            </button>
                                        </td>
                                    </motion.tr>
                                ))
                            ) : (
                                <tr>
                                    <td colSpan={7} className="px-4 py-20 text-center">
                                        <div className="flex flex-col items-center gap-3 opacity-20">
                                            <ShieldAlert className="w-12 h-12" />
                                            <p className="text-xs uppercase tracking-[0.3em] font-bold">
                                                {activeFiltersCount > 0 ? "No findings match filters" : "No Records Found"}
                                            </p>
                                        </div>
                                    </td>
                                </tr>
                            )}
                        </AnimatePresence>
                    </tbody>
                </table>
            </div>

            {/* Footer with real pagination */}
            <div className="mt-6 pt-4 border-t border-border flex items-center justify-between flex-wrap gap-3">
                <p className="text-[10px] text-muted-foreground uppercase font-mono">
                    Showing {paginatedFindings.length} of {sortedFindings.length} filtered
                    {" · "}
                    <span className="text-muted-foreground/60">
                        Total: {totalFindingsCount?.current ?? findings.length}
                    </span>
                    {activeFiltersCount > 0 && <span className="ml-2 text-primary">(filtered)</span>}
                </p>
                <div className="flex items-center gap-2">
                    <button
                        type="button"
                        disabled={currentPage <= 1}
                        onClick={() => setCurrentPage(p => Math.max(1, p - 1))}
                        className="px-3 py-1 rounded bg-secondary text-[10px] text-muted-foreground hover:text-foreground disabled:opacity-30 disabled:cursor-not-allowed transition-colors"
                    >PREV</button>
                    <span className="text-[10px] font-mono text-muted-foreground px-2 select-none">
                        {currentPage} / {totalPages}
                    </span>
                    <button
                        type="button"
                        disabled={currentPage >= totalPages}
                        onClick={() => setCurrentPage(p => Math.min(totalPages, p + 1))}
                        className="px-3 py-1 rounded bg-primary/10 text-[10px] text-primary hover:bg-primary/20 disabled:opacity-30 disabled:cursor-not-allowed transition-colors"
                    >NEXT</button>
                </div>
            </div>
        </GlowCard>
    );
}
