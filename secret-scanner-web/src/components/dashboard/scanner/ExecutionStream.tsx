"use client";

import React, { useRef, useEffect, useState, useMemo } from "react";
import { GlowCard } from "./GlowCard";
import { Terminal, Trash2, Activity } from "lucide-react";
import { cn } from "@/lib/utils";
import { motion, AnimatePresence } from "framer-motion";

interface LogEntry {
    message: string;
    level?: "info" | "warn" | "error" | "success" | "debug";
    timestamp: string;
    module?: string;
}

interface ExecutionStreamProps {
    logs: LogEntry[];
    isScanning: boolean;
    onClear?: () => void;
    scanStatus?: {
        progress: number;
        active_module?: string | null;
        modules_completed?: number;
        modules_total?: number;
        elapsed_seconds?: number;
    } | null;
    /** Total findings discovered so far */
    findingsCount?: number;
    /** Payloads fired so far */
    payloadsFired?: number;
}

function ScanningCursor() {
    return (
        <motion.span
            className="inline-block w-1.5 h-3 bg-primary align-middle ml-0.5 rounded-[1px]"
            animate={{ opacity: [1, 0, 1] }}
            transition={{ duration: 0.8, repeat: Infinity, ease: "linear" }}
        />
    );
}

// Severity filter config
const STREAM_FILTERS = [
    { id: "all", label: "ALL", dotClass: "bg-muted-foreground" },
    { id: "critical", label: "CRITICAL", dotClass: "bg-red-600 shadow-[0_0_8px_rgba(220,38,38,0.5)]" },
    { id: "high", label: "HIGH", dotClass: "bg-orange-600 shadow-[0_0_8px_rgba(234,88,12,0.5)]" },
    { id: "medium", label: "MEDIUM", dotClass: "bg-amber-500 shadow-[0_0_8px_rgba(245,158,11,0.5)]" },
    { id: "low", label: "LOW", dotClass: "bg-blue-500 shadow-[0_0_8px_rgba(59,130,246,0.5)]" },
    { id: "info", label: "INFO", dotClass: "bg-muted-foreground shadow-[0_0_8px_rgba(156,163,175,0.5)]" },
] as const;

type StreamFilter = typeof STREAM_FILTERS[number]["id"];

function matchesFilter(log: LogEntry, filter: StreamFilter): boolean {
    if (filter === "all") return true;
    const msg = log.message.toLowerCase();
    const level = (log.level || "info").toLowerCase();

    // Check if the level property itself matches the filter ID or if the message contains the label
    switch (filter) {
        case "critical":
            return level === "critical" || level === "error" || msg.includes("critical");
        case "high":
            return level === "high" || msg.includes("high");
        case "medium":
            return level === "medium" || msg.includes("medium");
        case "low":
            return level === "low" || msg.includes("low");
        case "info":
            // Info matches if level is info/success/debug OR if message contains info
            return level === "info" || level === "success" || level === "debug" || msg.includes("info");
        default:
            return true;
    }
}

const LEVEL_CONFIG: Record<string, { color: string; indicator: string; bg: string }> = {
    error: { color: "text-red-500", indicator: "bg-red-500", bg: "bg-red-500/5" },
    warn: { color: "text-amber-500", indicator: "bg-amber-500", bg: "bg-amber-500/5" },
    success: { color: "text-primary", indicator: "bg-primary", bg: "bg-primary/5" },
    debug: { color: "text-muted-foreground", indicator: "bg-muted-foreground/80", bg: "" },
    info: { color: "text-muted-foreground", indicator: "bg-muted-foreground/80", bg: "" },
};

function getLevelConfig(level?: string) {
    return LEVEL_CONFIG[level || "info"] || LEVEL_CONFIG.info;
}

function formatElapsed(seconds: number): string {
    const mins = Math.floor(seconds / 60);
    const secs = Math.floor(seconds % 60);
    return mins > 0 ? `${mins}m ${secs}s` : `${secs}s`;
}

export function ExecutionStream({ logs, isScanning, onClear, scanStatus, findingsCount = 0, payloadsFired = 0 }: ExecutionStreamProps) {
    const scrollRef = useRef<HTMLDivElement>(null);
    const [activeFilter, setActiveFilter] = useState<StreamFilter>("all");
    const [autoScroll, setAutoScroll] = useState(true);
    // Local elapsed counter for heartbeat when backend hasn't sent elapsed_seconds yet
    const [localElapsed, setLocalElapsed] = useState(0);

    const filteredLogs = useMemo(() => {
        if (activeFilter === "all") return logs;
        return logs.filter(log => matchesFilter(log, activeFilter));
    }, [logs, activeFilter]);

    // Cap rendered log items at 500
    const MAX_STREAM_ITEMS = 500;
    const displayLogs = filteredLogs.length > MAX_STREAM_ITEMS
        ? filteredLogs.slice(filteredLogs.length - MAX_STREAM_ITEMS)
        : filteredLogs;
    const streamTrimmed = filteredLogs.length > MAX_STREAM_ITEMS;

    // Count per filter
    const counts = useMemo(() => ({
        critical: logs.filter(l => matchesFilter(l, "critical")).length,
        high: logs.filter(l => matchesFilter(l, "high")).length,
        medium: logs.filter(l => matchesFilter(l, "medium")).length,
        low: logs.filter(l => matchesFilter(l, "low")).length,
        info: logs.filter(l => matchesFilter(l, "info")).length,
    }), [logs]);

    useEffect(() => {
        if (scrollRef.current && autoScroll) {
            scrollRef.current.scrollTop = scrollRef.current.scrollHeight;
        }
    }, [filteredLogs, autoScroll]);

    // Detect manual scroll
    const handleScroll = () => {
        if (!scrollRef.current) return;
        const { scrollTop, scrollHeight, clientHeight } = scrollRef.current;
        const isAtBottom = scrollHeight - scrollTop - clientHeight < 60;
        setAutoScroll(isAtBottom);
    };

    // Local elapsed timer — provides immediate feedback while scan is running
    useEffect(() => {
        if (!isScanning) { setLocalElapsed(0); return; }
        setLocalElapsed(0);
        const t = setInterval(() => setLocalElapsed(prev => prev + 1), 1000);
        return () => clearInterval(t);
    }, [isScanning]);

    const progress = scanStatus?.progress ?? 0;
    const modulesCompleted = scanStatus?.modules_completed ?? 0;
    const modulesTotal = scanStatus?.modules_total ?? 0;
    const elapsed = scanStatus?.elapsed_seconds ?? localElapsed;
    const activeModule = scanStatus?.active_module;

    return (
        <GlowCard className="h-full flex flex-col" glowColor="rgba(0, 255, 136, 0.05)">
            {/* Terminal Title Bar */}
            <div className="flex items-center justify-between mb-3 pb-2 border-b border-border">
                <div className="flex items-center gap-2">
                    <Terminal className="w-4 h-4 text-muted-foreground" />
                    <h3 className="text-[10px] font-bold text-muted-foreground uppercase tracking-[0.2em]">Execution Stream</h3>
                    {isScanning && (
                        <div className="flex items-center gap-1.5 ml-2">
                            <motion.div
                                className="w-1.5 h-1.5 rounded-full bg-primary"
                                style={{ boxShadow: "0 0 6px rgba(var(--primary), 0.5)" }}
                                animate={{ scale: [1, 1.3, 1], opacity: [1, 0.6, 1] }}
                                transition={{ duration: 1, repeat: Infinity }}
                            />
                            <span className="text-[9px] font-bold text-primary uppercase tracking-widest">Live</span>
                        </div>
                    )}
                </div>
                <div className="flex items-center gap-1">
                    {isScanning && (
                        <span className="text-[9px] font-mono text-muted-foreground mr-2">{formatElapsed(elapsed)}</span>
                    )}
                    <button type="button" onClick={onClear} className="p-1 hover:bg-muted/50 rounded transition-colors" title="Clear">
                        <Trash2 className="w-3.5 h-3.5 text-muted-foreground hover:text-foreground" />
                    </button>
                </div>
            </div>

            {/* Live Scan Status Panel — shows IMMEDIATELY when scanning starts */}
            {isScanning && (
                <div className="mb-3 rounded-lg border border-primary/20 bg-primary/5 p-3 space-y-2.5">
                    {/* Active Module + Progress */}
                    <div className="flex items-center justify-between">
                        <div className="flex items-center gap-2 min-w-0">
                            <motion.div
                                className="w-2 h-2 rounded-full bg-primary shrink-0"
                                animate={{ scale: [1, 1.4, 1], opacity: [1, 0.5, 1] }}
                                transition={{ duration: 1.2, repeat: Infinity }}
                            />
                            <span className="text-[10px] font-bold text-primary uppercase tracking-wider truncate">
                                {activeModule
                                    ? activeModule
                                    : progress === 0
                                        ? "Initializing scan engine..."
                                        : "Processing..."
                                }
                            </span>
                        </div>
                        <span className="text-[11px] font-mono font-bold text-primary shrink-0 ml-2">{progress}%</span>
                    </div>

                    {/* Progress Bar */}
                    <div className="w-full h-1.5 rounded-full bg-border overflow-hidden">
                        <motion.div
                            className="h-full rounded-full"
                            style={{
                                background: "linear-gradient(90deg, rgba(var(--primary), 0.4) 0%, rgba(var(--primary), 1) 100%)",
                                boxShadow: "0 0 8px rgba(var(--primary), 0.4)",
                            }}
                            animate={{ width: `${Math.max(progress, 2)}%` }}
                            transition={{ duration: 0.5, ease: "easeOut" }}
                        />
                    </div>

                    {/* Telemetry Row */}
                    <div className="flex items-center gap-4 text-[9px] font-mono text-muted-foreground">
                        {modulesTotal > 0 && (
                            <div className="flex items-center gap-1">
                                <Activity className="w-3 h-3 text-muted-foreground" />
                                <span>Module {modulesCompleted + (activeModule ? 1 : 0)}/{modulesTotal}</span>
                            </div>
                        )}
                        {findingsCount > 0 && (
                            <span className="text-amber-500/80">{findingsCount} finding{findingsCount !== 1 ? "s" : ""}</span>
                        )}
                        {payloadsFired > 0 && (
                            <span>{payloadsFired} payloads</span>
                        )}
                        <span className="ml-auto">{formatElapsed(elapsed)}</span>
                    </div>
                </div>
            )}

            {/* Filter Bar */}
            <div className="flex flex-wrap gap-1.5 mb-3">
                {STREAM_FILTERS.map((f) => {
                    const count = f.id === "all" ? logs.length : counts[f.id as keyof typeof counts];
                    const isActive = activeFilter === f.id;
                    return (
                        <button
                            key={f.id}
                            type="button"
                            onClick={() => setActiveFilter(f.id)}
                            className={cn(
                                "flex items-center gap-1.5 px-2.5 py-1 rounded-md text-[9px] font-bold uppercase tracking-wider border transition-colors",
                                isActive
                                    ? "bg-primary/10 border-primary/30 text-primary"
                                    : "bg-transparent border-border/50 text-muted-foreground hover:text-foreground hover:border-border"
                            )}
                        >
                            <span className={cn("w-1.5 h-1.5 rounded-full shrink-0", f.dotClass)} />
                            {f.label}
                            <span className="opacity-50 font-mono">({count})</span>
                        </button>
                    );
                })}
            </div>

            {/* Log Container */}
            <div
                ref={scrollRef}
                onScroll={handleScroll}
                className="flex-1 bg-card/40 rounded-lg p-3 font-mono text-[11px] overflow-y-auto space-y-0.5 scrollbar-thin scrollbar-thumb-muted-foreground/30 scroll-smooth border border-border shadow-inner"
            >
                <AnimatePresence initial={false}>
                    {displayLogs.length > 0 ? (
                        <>
                            {streamTrimmed && (
                                <div className="text-center text-[9px] text-muted-foreground/50 py-1 font-mono border-b border-border/50 mb-2">
                                    — Showing last {MAX_STREAM_ITEMS} of {filteredLogs.length} entries —
                                </div>
                            )}
                            {displayLogs.map((log, idx) => {
                                const isNewest = idx === displayLogs.length - 1;
                                const stableKey = `${idx}-${log.timestamp}-${log.message.slice(0, 40)}`;
                                const config = getLevelConfig(log.level);

                                const inner = (
                                    <div className={cn(
                                        "flex items-start gap-2 py-0.5 px-1.5 rounded group",
                                        config.bg,
                                        "hover:bg-muted/30"
                                    )}>
                                        {/* Level indicator dot */}
                                        <div className="flex items-center gap-1.5 shrink-0 pt-[3px]">
                                            <div className={cn("w-1.5 h-1.5 rounded-full", config.indicator)} />
                                        </div>
                                        {/* Timestamp */}
                                        <span className="text-muted-foreground/40 shrink-0 select-none text-[10px]">{log.timestamp}</span>
                                        {/* Level badge */}
                                        <span className={cn("shrink-0 uppercase font-bold text-[9px] w-[42px]", config.color)}>
                                            {log.level || "info"}
                                        </span>
                                        {/* Message */}
                                        <span className="text-muted-foreground break-all leading-relaxed group-hover:text-foreground transition-colors">
                                            {log.message}
                                        </span>
                                    </div>
                                );

                                return isNewest ? (
                                    <motion.div
                                        key={stableKey}
                                        initial={{ opacity: 0, y: -2 }}
                                        animate={{ opacity: 1, y: 0 }}
                                        transition={{ duration: 0.12 }}
                                    >
                                        {inner}
                                    </motion.div>
                                ) : (
                                    <div key={stableKey}>{inner}</div>
                                );
                            })}
                            {isScanning && (
                                <div className="flex items-center gap-2 py-0.5 px-1.5 pt-1">
                                    <div className="w-1.5 h-1.5 rounded-full bg-primary shrink-0" />
                                    <span className="text-muted-foreground/40 shrink-0 select-none text-[10px]">{logs[logs.length - 1]?.timestamp ?? "…"}</span>
                                    <span className="shrink-0 uppercase font-bold text-[9px] w-[42px] text-primary">proc</span>
                                    <ScanningCursor />
                                </div>
                            )}
                        </>
                    ) : (
                        <div className="h-full flex flex-col items-center justify-center gap-2 text-muted-foreground">
                            <Terminal className="w-6 h-6 opacity-30" />
                            <span className="italic text-[10px] uppercase tracking-widest text-muted-foreground/80">
                                {isScanning
                                    ? "Connecting to scan engine..."
                                    : logs.length > 0
                                        ? `No ${activeFilter} entries`
                                        : "Awaiting scan execution..."
                                }
                            </span>
                        </div>
                    )}
                </AnimatePresence>
            </div>

            {/* Terminal Footer */}
            <div className="mt-2 flex items-center justify-between text-[9px] font-mono text-muted-foreground">
                <div className="flex gap-4">
                    <span>{displayLogs.length}/{logs.length} entries</span>
                    {!autoScroll && isScanning && (
                        <button
                            type="button"
                            onClick={() => {
                                setAutoScroll(true);
                                if (scrollRef.current) scrollRef.current.scrollTop = scrollRef.current.scrollHeight;
                            }}
                            className="text-primary hover:underline"
                        >
                            Resume auto-scroll
                        </button>
                    )}
                </div>
                <div className="flex items-center gap-1.5">
                    <div className={cn(
                        "w-2 h-2 rounded-full border",
                        isScanning ? "border-primary bg-primary/20" : "border-border/30"
                    )} />
                    <span>localhost:8000</span>
                </div>
            </div>
        </GlowCard>
    );
}
