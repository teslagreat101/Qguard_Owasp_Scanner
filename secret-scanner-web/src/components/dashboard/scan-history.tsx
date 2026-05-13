"use client";

import { CheckCircle, AlertTriangle, Clock, RefreshCw, Download, Trash2 } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { GlowCard } from "@/components/ui/glow-card";
import { cn } from "@/lib/utils";

interface ScanHistoryEntry {
    scan_id: string;
    target: string;
    status: string;
    modules?: string[];
    total_findings: number;
    severity_counts?: Record<string, number>;
    started_at?: string | null;
    completed_at?: string | null;
    duration?: number;
    risk_score?: number;
    scan_type?: string;
    scan_profile?: string;
}

interface ScanHistoryProps {
    scans: ScanHistoryEntry[];
    onRefresh: () => void;
    onViewScan?: (scanId: string) => void;
    onDownloadReport?: (scanId: string) => void;
    onDeleteScan?: (scanId: string) => void;
}

const statusIcon = (status: string) => {
    switch (status) {
        case "completed": return <CheckCircle className="h-3.5 w-3.5 text-primary" />;
        case "error": case "failed": return <AlertTriangle className="h-3.5 w-3.5 text-destructive" />;
        case "running": return <Clock className="h-3.5 w-3.5 text-primary animate-pulse" />;
        default: return <Clock className="h-3.5 w-3.5 text-muted-foreground" />;
    }
};

export function ScanHistory({ scans, onRefresh, onViewScan, onDownloadReport, onDeleteScan }: ScanHistoryProps) {
    return (
        <GlowCard className="p-0 border-border bg-card" glowColor="rgba(var(--primary), 0.15)">
            <div className="p-8">
                <div className="flex items-center justify-between mb-8">
                    <div>
                        <h3 className="text-xl font-black text-foreground uppercase tracking-tighter">Security Intelligence Ledger</h3>
                        <p className="text-[10px] text-muted-foreground uppercase tracking-widest font-bold mt-0.5">Historical scan telemetry and protocol logs</p>
                    </div>
                    <Button variant="outline" onClick={onRefresh} className="h-10 border-border bg-secondary text-muted-foreground hover:text-primary hover:border-primary/30 uppercase text-[10px] font-black tracking-widest px-6 transition-all">
                        <RefreshCw className="h-3.5 w-3.5 mr-2" /> Refresh Stream
                    </Button>
                </div>

                <div className="rounded-xl border border-border overflow-hidden bg-secondary/50">
                    <Table>
                        <TableHeader className="bg-secondary">
                            <TableRow className="border-border hover:bg-transparent">
                                <TableHead className="text-[10px] uppercase tracking-widest font-black text-muted-foreground h-12">Intelligence Target</TableHead>
                                <TableHead className="text-[10px] uppercase tracking-widest font-black text-muted-foreground h-12 w-32">Status</TableHead>
                                <TableHead className="text-[10px] uppercase tracking-widest font-black text-muted-foreground h-12">Timestamp</TableHead>
                                <TableHead className="text-[10px] uppercase tracking-widest font-black text-muted-foreground h-12 w-28">Findings</TableHead>
                                <TableHead className="text-[10px] uppercase tracking-widest font-black text-muted-foreground h-12 w-24">Risk Score</TableHead>
                                <TableHead className="text-[10px] uppercase tracking-widest font-black text-muted-foreground h-12 w-24 text-right pr-8">Actions</TableHead>
                            </TableRow>
                        </TableHeader>
                        <TableBody>
                            {scans.length === 0 ? (
                                <TableRow><TableCell colSpan={6} className="text-center text-muted-foreground py-20 uppercase text-[10px] font-bold tracking-[0.2em]">No intelligence logged in protocol history</TableCell></TableRow>
                            ) : (
                                scans.map((scan) => (
                                    <TableRow key={scan.scan_id} className="border-border hover:bg-secondary transition-colors cursor-pointer group" onClick={() => onViewScan?.(scan.scan_id)}>
                                        <TableCell className="py-5 font-mono text-sm text-foreground group-hover:text-primary transition-colors max-w-[300px] truncate">{scan.target}</TableCell>
                                        <TableCell>
                                            <div className="flex items-center gap-2">
                                                {statusIcon(scan.status)}
                                                <span className="uppercase text-[9px] font-black tracking-widest text-muted-foreground">{scan.status}</span>
                                            </div>
                                        </TableCell>
                                        <TableCell className="text-muted-foreground font-mono text-[11px] uppercase">{scan.started_at ? new Date(scan.started_at).toLocaleString() : "—"}</TableCell>
                                        <TableCell>
                                            <div className={cn(
                                                "w-fit px-3 py-1 rounded-full text-[10px] font-black border",
                                                scan.total_findings > 0 ? "bg-red-500/10 text-red-500 border-red-500/20" : "bg-primary/10 text-primary border-primary/20"
                                            )}>
                                                {scan.total_findings} ISSUES
                                            </div>
                                        </TableCell>
                                        <TableCell>
                                            <div className="font-mono text-sm font-black tracking-tighter" style={{ color: (scan.risk_score || 0) > 75 ? "#ef4444" : (scan.risk_score || 0) > 40 ? "#f59e0b" : "hsl(var(--primary))" }}>
                                                {scan.risk_score?.toFixed(1) ?? "0.0"}
                                            </div>
                                        </TableCell>
                                        <TableCell className="text-right pr-4">
                                            <div className="flex justify-end gap-1" onClick={(e) => e.stopPropagation()}>
                                                {onDownloadReport && scan.status === "completed" && (
                                                    <Button variant="ghost" size="icon" className="h-9 w-9 text-muted-foreground hover:text-primary hover:bg-primary/10 rounded-lg transition-all" onClick={() => onDownloadReport(scan.scan_id)}>
                                                        <Download className="h-4 w-4" />
                                                    </Button>
                                                )}
                                                <Button
                                                    variant="ghost"
                                                    size="icon"
                                                    className="h-9 w-9 text-muted-foreground/40 hover:text-destructive transition-all"
                                                    onClick={() => onDeleteScan?.(scan.scan_id)}
                                                >
                                                    <Trash2 className="h-4 w-4" />
                                                </Button>
                                            </div>
                                        </TableCell>
                                    </TableRow>
                                ))
                            )}
                        </TableBody>
                    </Table>
                </div>
            </div>
        </GlowCard>
    );
}
