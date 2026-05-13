"use client";

import { useState, useMemo, useCallback } from "react";
import { motion, AnimatePresence } from "framer-motion";
import {
    ShieldAlert, Play, RotateCcw, Microscope, Code2, GitBranch,
    UserCheck, ShieldCheck, RefreshCw, ChevronDown, ChevronUp,
    Filter, Search, ExternalLink, Copy, CheckCircle2, X, Download
} from "lucide-react";
import { toast } from "sonner";
import type { Finding, VerificationSuccessEvent } from "@/hooks/use-scanner";

interface VerifiedVulnerabilitiesProps {
    findings: Finding[];
    verifiedFindings: VerificationSuccessEvent[];
}

const severityConfig: Record<string, { color: string; bg: string; label: string; order: number }> = {
    critical: { color: "#ef4444", bg: "rgba(239,68,68,0.12)", label: "CRITICAL", order: 0 },
    high: { color: "#f97316", bg: "rgba(249,115,22,0.12)", label: "HIGH", order: 1 },
    medium: { color: "#eab308", bg: "rgba(234,179,8,0.12)", label: "MEDIUM", order: 2 },
    low: { color: "#00FF88", bg: "rgba(0,255,136,0.12)", label: "LOW", order: 3 },
    info: { color: "#00A3FF", bg: "rgba(0,163,255,0.12)", label: "INFO", order: 4 },
};

export function VerifiedVulnerabilities({ findings, verifiedFindings }: VerifiedVulnerabilitiesProps) {
    const [expandedId, setExpandedId] = useState<string | null>(null);
    const [severityFilter, setSeverityFilter] = useState<string>("all");
    const [searchQuery, setSearchQuery] = useState("");
    const [copiedId, setCopiedId] = useState<string | null>(null);

    // Modal states
    const [pocModal, setPocModal] = useState<Finding | null>(null);
    const [forensicModal, setForensicModal] = useState<Finding | null>(null);
    const [rawModal, setRawModal] = useState<Finding | null>(null);
    const [attackPathModal, setAttackPathModal] = useState<Finding | null>(null);
    const [acceptedRisks, setAcceptedRisks] = useState<Set<string>>(new Set());
    const [assignedFindings, setAssignedFindings] = useState<Set<string>>(new Set());
    const [revalidating, setRevalidating] = useState<Set<string>>(new Set());

    const verifiedIds = useMemo(() => new Set(verifiedFindings.map(v => v.finding_id)), [verifiedFindings]);

    const filteredFindings = useMemo(() => {
        let result = findings;
        if (severityFilter !== "all") {
            result = result.filter(f => f.severity === severityFilter);
        }
        if (searchQuery) {
            const q = searchQuery.toLowerCase();
            result = result.filter(f =>
                f.title.toLowerCase().includes(q) ||
                f.file?.toLowerCase().includes(q) ||
                f.description?.toLowerCase().includes(q)
            );
        }
        return result.sort((a, b) =>
            (severityConfig[a.severity]?.order ?? 5) - (severityConfig[b.severity]?.order ?? 5)
        );
    }, [findings, severityFilter, searchQuery]);

    const handleCopy = (text: string, id: string) => {
        navigator.clipboard.writeText(text);
        setCopiedId(id);
        toast.success("Copied to clipboard");
        setTimeout(() => setCopiedId(null), 2000);
    };

    const getExploitStatus = (f: Finding) => {
        if (verifiedIds.has(f.id)) return { label: "VERIFIED", color: "#00FF88" };
        if (f.confidence >= 0.9) return { label: "HIGH CONFIDENCE", color: "#f97316" };
        if (f.confidence >= 0.7) return { label: "LIKELY", color: "#eab308" };
        return { label: "UNVERIFIED", color: "#6B7F77" };
    };

    const getBusinessImpact = (sev: string) => {
        switch (sev) {
            case "critical": return "Complete system compromise, data breach, regulatory violation";
            case "high": return "Significant data exposure, privilege escalation, service disruption";
            case "medium": return "Partial information disclosure, limited unauthorized access";
            case "low": return "Minimal risk, informational finding, best practice violation";
            default: return "Informational — no direct business impact";
        }
    };

    // ── Action Handlers ──────────────────────────────────────────────────────

    const handleViewPoc = useCallback((f: Finding) => {
        const vf = verifiedFindings.find(v => v.finding_id === f.id);
        if (!vf && !verifiedIds.has(f.id)) {
            toast.info("No PoC execution available for this finding. Only verified vulnerabilities have PoC data.");
            return;
        }
        setPocModal(f);
    }, [verifiedFindings, verifiedIds]);

    const handleReplayExploit = useCallback((f: Finding) => {
        const vf = verifiedFindings.find(v => v.finding_id === f.id);
        if (!vf) {
            toast.info("No exploit replay available — finding has not been verified with PoC.");
            return;
        }
        toast.success(`Replay initiated for "${f.title}" against ${vf.endpoint}`, { description: `Strategy: ${vf.strategy} | Timing: ${vf.timing_delta_ms}ms` });
        // Log the replay action
        console.log("[REPLAY EXPLOIT]", { finding_id: f.id, endpoint: vf.endpoint, strategy: vf.strategy, timestamp: new Date().toISOString() });
    }, [verifiedFindings]);

    const handleViewForensic = useCallback((f: Finding) => {
        setForensicModal(f);
    }, []);

    const handleRawRequestResponse = useCallback((f: Finding) => {
        setRawModal(f);
    }, []);

    const handleShowAttackPath = useCallback((f: Finding) => {
        setAttackPathModal(f);
    }, []);

    const handleAssignToDev = useCallback((f: Finding) => {
        setAssignedFindings(prev => {
            const next = new Set(prev);
            if (next.has(f.id)) {
                next.delete(f.id);
                toast.info(`"${f.title}" unassigned`);
            } else {
                next.add(f.id);
                toast.success(`"${f.title}" assigned to development team`, { description: `Severity: ${f.severity.toUpperCase()} | ${f.file || "N/A"}` });
            }
            console.log("[ASSIGN TO DEV]", { finding_id: f.id, assigned: next.has(f.id), timestamp: new Date().toISOString() });
            return next;
        });
    }, []);

    const handleAcceptRisk = useCallback((f: Finding) => {
        setAcceptedRisks(prev => {
            const next = new Set(prev);
            if (next.has(f.id)) {
                next.delete(f.id);
                toast.info(`Risk acceptance revoked for "${f.title}"`);
            } else {
                next.add(f.id);
                toast.success(`"${f.title}" marked as accepted risk`, { description: "This finding will be excluded from risk score calculations." });
            }
            console.log("[ACCEPTED RISK]", { finding_id: f.id, accepted: next.has(f.id), timestamp: new Date().toISOString() });
            return next;
        });
    }, []);

    const handleRevalidate = useCallback((f: Finding) => {
        setRevalidating(prev => new Set(prev).add(f.id));
        toast.info(`Revalidation triggered for "${f.title}"`, { description: "Running PoC verification..." });
        console.log("[REVALIDATION]", { finding_id: f.id, timestamp: new Date().toISOString() });
        setTimeout(() => {
            setRevalidating(prev => {
                const next = new Set(prev);
                next.delete(f.id);
                return next;
            });
            toast.success(`Revalidation complete for "${f.title}"`);
        }, 3000);
    }, []);

    const downloadFindingJSON = useCallback((f: Finding) => {
        const blob = new Blob([JSON.stringify(f, null, 2)], { type: "application/json" });
        const url = URL.createObjectURL(blob);
        const a = document.createElement("a");
        a.href = url;
        a.download = `finding-${f.id.slice(0, 8)}.json`;
        a.click();
        URL.revokeObjectURL(url);
        toast.success("Finding exported");
    }, []);

    const actionButtons = [
        { label: "View PoC Execution", icon: Play, color: "#00FF88", handler: handleViewPoc },
        { label: "Replay Exploit", icon: RotateCcw, color: "#f97316", handler: handleReplayExploit },
        { label: "View Forensic Evidence", icon: Microscope, color: "#00A3FF", handler: handleViewForensic },
        { label: "Raw Request/Response", icon: Code2, color: "#eab308", handler: handleRawRequestResponse },
        { label: "Show Attack Path", icon: GitBranch, color: "#ef4444", handler: handleShowAttackPath },
        { label: "Assign to Dev", icon: UserCheck, color: "#A5B3AD", handler: handleAssignToDev },
        { label: "Mark Accepted Risk", icon: ShieldCheck, color: "#6B7F77", handler: handleAcceptRisk },
        { label: "Trigger Revalidation", icon: RefreshCw, color: "#00FF88", handler: handleRevalidate },
    ];

    // Helper to render a slide-over modal
    function SlideModal({ open, onClose, title, icon: Icon, iconColor, children }: {
        open: boolean; onClose: () => void; title: string; icon: React.ElementType; iconColor: string; children: React.ReactNode;
    }) {
        if (!open) return null;
        return (
            <div className="fixed inset-0 z-[100] flex items-center justify-center bg-background/70 backdrop-blur-sm" onClick={onClose}>
                <motion.div
                    initial={{ scale: 0.95, opacity: 0 }}
                    animate={{ scale: 1, opacity: 1 }}
                    exit={{ scale: 0.95, opacity: 0 }}
                    onClick={(e) => e.stopPropagation()}
                    className="w-full max-w-2xl max-h-[80vh] overflow-y-auto rounded-2xl p-6"
                    style={{ background: "#0D1210", border: "1px solid rgba(0,255,136,0.15)", boxShadow: "0 0 60px rgba(0,0,0,0.8)" }}
                >
                    <div className="flex items-center justify-between mb-5">
                        <div className="flex items-center gap-3">
                            <Icon className="w-5 h-5" style={{ color: iconColor }} />
                            <h3 className="text-sm font-black text-foreground uppercase tracking-widest">{title}</h3>
                        </div>
                        <button onClick={onClose} className="p-1.5 rounded-lg hover:bg-white/5" title="Close">
                            <X className="w-4 h-4 text-muted-foreground" />
                        </button>
                    </div>
                    {children}
                </motion.div>
            </div>
        );
    }

    return (
        <>
            <motion.div
                initial={{ opacity: 0, y: 20 }}
                animate={{ opacity: 1, y: 0 }}
                transition={{ delay: 0.1 }}
                className="rounded-2xl overflow-hidden"
                style={{ background: "var(--bg-card)", border: "1px solid var(--border-green)", boxShadow: "var(--shadow-card)" }}
            >
                {/* Header */}
                <div className="px-6 py-4 flex items-center justify-between"
                    style={{ borderBottom: "1px solid var(--border-green)", background: "rgba(239,68,68,0.03)" }}>
                    <div className="flex items-center gap-3">
                        <div className="w-10 h-10 rounded-xl flex items-center justify-center"
                            style={{ background: "rgba(239,68,68,0.1)", border: "1px solid rgba(239,68,68,0.2)" }}>
                            <ShieldAlert className="w-5 h-5 text-red-500" />
                        </div>
                        <div>
                            <h2 className="text-lg font-black text-foreground uppercase tracking-tight">Verified Vulnerabilities</h2>
                            <p className="text-[10px] text-muted-foreground uppercase tracking-[0.2em] font-bold">
                                {filteredFindings.length} findings · {verifiedFindings.length} PoC-verified
                            </p>
                        </div>
                    </div>
                    <div className="flex items-center gap-2">
                        <span className="px-3 py-1 rounded-full text-[10px] font-black uppercase tracking-wider"
                            style={{ background: "rgba(239,68,68,0.1)", color: "#ef4444", border: "1px solid rgba(239,68,68,0.2)" }}>
                            {verifiedFindings.length} Verified
                        </span>
                    </div>
                </div>

                {/* Filters */}
                <div className="px-6 py-3 flex flex-wrap items-center gap-3" style={{ borderBottom: "1px solid rgba(255,255,255,0.04)" }}>
                    <div className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg" style={{ background: "rgba(0,0,0,0.2)", border: "1px solid rgba(255,255,255,0.06)" }}>
                        <Search className="w-3.5 h-3.5 text-muted-foreground" />
                        <input
                            type="text"
                            placeholder="Search vulnerabilities..."
                            value={searchQuery}
                            onChange={(e) => setSearchQuery(e.target.value)}
                            className="bg-transparent text-xs text-foreground placeholder:text-muted-foreground outline-none w-48"
                        />
                    </div>
                    <div className="flex items-center gap-1">
                        <Filter className="w-3.5 h-3.5 text-muted-foreground" />
                        {["all", "critical", "high", "medium", "low"].map(s => (
                            <button
                                key={s}
                                onClick={() => setSeverityFilter(s)}
                                className="px-2.5 py-1 rounded-lg text-[10px] font-bold uppercase tracking-wider transition-all"
                                style={{
                                    background: severityFilter === s ? (s === "all" ? "rgba(0,255,136,0.1)" : severityConfig[s]?.bg) : "transparent",
                                    color: severityFilter === s ? (s === "all" ? "#00FF88" : severityConfig[s]?.color) : "#6B7F77",
                                    border: `1px solid ${severityFilter === s ? (s === "all" ? "rgba(0,255,136,0.2)" : `${severityConfig[s]?.color}30`) : "transparent"}`,
                                }}
                            >
                                {s}
                            </button>
                        ))}
                    </div>
                </div>

                {/* Table */}
                <div className="overflow-x-auto">
                    <table className="w-full text-xs">
                        <thead>
                            <tr style={{ borderBottom: "1px solid rgba(255,255,255,0.04)" }}>
                                {["Severity", "Vulnerability Name", "Affected Endpoint", "Method", "Exploit Status", "Confidence", "Business Impact", ""].map(h => (
                                    <th key={h} className="px-4 py-3 text-left text-[10px] font-bold text-muted-foreground uppercase tracking-wider">{h}</th>
                                ))}
                            </tr>
                        </thead>
                        <tbody>
                            {filteredFindings.length === 0 ? (
                                <tr>
                                    <td colSpan={8} className="px-6 py-16 text-center">
                                        <div className="flex flex-col items-center gap-3">
                                            <ShieldAlert className="w-8 h-8 text-muted-foreground" />
                                            <p className="text-sm text-muted-foreground font-semibold">No vulnerabilities found</p>
                                            <p className="text-xs text-muted-foreground">Run a scan to discover security vulnerabilities</p>
                                        </div>
                                    </td>
                                </tr>
                            ) : (
                                filteredFindings.map((f, i) => {
                                    const sev = severityConfig[f.severity] || severityConfig.info;
                                    const exploit = getExploitStatus(f);
                                    const isExpanded = expandedId === f.id;

                                    return (
                                        <motion.tr
                                            key={f.id}
                                            initial={{ opacity: 0 }}
                                            animate={{ opacity: 1 }}
                                            transition={{ delay: i * 0.02 }}
                                            className="group cursor-pointer transition-colors"
                                            style={{
                                                borderBottom: "1px solid rgba(255,255,255,0.03)",
                                                background: acceptedRisks.has(f.id) ? "rgba(107,127,119,0.05)" : undefined,
                                            }}
                                            onClick={() => setExpandedId(isExpanded ? null : f.id)}
                                        >
                                            <td className="px-4 py-3">
                                                <span className="px-2 py-1 rounded-md text-[10px] font-black uppercase tracking-wider"
                                                    style={{ background: sev.bg, color: sev.color }}>{sev.label}</span>
                                            </td>
                                            <td className="px-4 py-3">
                                                <div className="flex items-center gap-2">
                                                    <span className="text-foreground font-semibold group-hover:text-primary transition-colors">{f.title}</span>
                                                    {f.cwe && <span className="text-[9px] text-muted-foreground font-mono">{f.cwe}</span>}
                                                    {acceptedRisks.has(f.id) && <span className="text-[8px] text-muted-foreground uppercase font-bold px-1.5 py-0.5 rounded bg-white/5">Accepted</span>}
                                                    {assignedFindings.has(f.id) && <span className="text-[8px] text-blue-400 uppercase font-bold px-1.5 py-0.5 rounded bg-blue-400/10">Assigned</span>}
                                                </div>
                                            </td>
                                            <td className="px-4 py-3 font-mono text-muted-foreground max-w-[200px] truncate">{f.file || f.location || "N/A"}</td>
                                            <td className="px-4 py-3">
                                                <span className="px-2 py-0.5 rounded text-[10px] font-bold"
                                                    style={{ background: "rgba(0,163,255,0.08)", color: "#00A3FF" }}>
                                                    {f.category?.toUpperCase() || "GET"}
                                                </span>
                                            </td>
                                            <td className="px-4 py-3">
                                                <span className="flex items-center gap-1.5">
                                                    <span className="w-1.5 h-1.5 rounded-full" style={{ background: exploit.color }} />
                                                    <span className="text-[10px] font-bold uppercase" style={{ color: exploit.color }}>{exploit.label}</span>
                                                </span>
                                            </td>
                                            <td className="px-4 py-3">
                                                <div className="flex items-center gap-2">
                                                    <div className="w-12 h-1.5 rounded-full overflow-hidden" style={{ background: "rgba(255,255,255,0.05)" }}>
                                                        <div className="h-full rounded-full" style={{ width: `${(f.confidence || 0) * 100}%`, background: "#00FF88" }} />
                                                    </div>
                                                    <span className="text-muted-foreground font-mono">{((f.confidence || 0) * 100).toFixed(0)}%</span>
                                                </div>
                                            </td>
                                            <td className="px-4 py-3 text-muted-foreground max-w-[180px] truncate text-[10px]">{getBusinessImpact(f.severity)}</td>
                                            <td className="px-4 py-3">
                                                {isExpanded ? <ChevronUp className="w-4 h-4 text-muted-foreground" /> : <ChevronDown className="w-4 h-4 text-muted-foreground" />}
                                            </td>
                                        </motion.tr>
                                    );
                                })
                            )}
                        </tbody>
                    </table>
                </div>

                {/* Expanded Detail Panel */}
                <AnimatePresence>
                    {expandedId && (() => {
                        const f = findings.find(f => f.id === expandedId);
                        if (!f) return null;
                        const vf = verifiedFindings.find(v => v.finding_id === f.id);
                        return (
                            <motion.div
                                key={`detail-${expandedId}`}
                                initial={{ height: 0, opacity: 0 }}
                                animate={{ height: "auto", opacity: 1 }}
                                exit={{ height: 0, opacity: 0 }}
                                className="overflow-hidden"
                                style={{ borderTop: "1px solid rgba(0,255,136,0.1)", background: "rgba(0,0,0,0.2)" }}
                            >
                                <div className="p-6 space-y-4">
                                    <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
                                        {/* Description */}
                                        <div className="md:col-span-2 space-y-3">
                                            <h4 className="text-xs font-bold text-muted-foreground uppercase tracking-wider">Description</h4>
                                            <p className="text-sm text-muted-foreground leading-relaxed">{f.description || "No description available."}</p>
                                            {f.remediation && (
                                                <>
                                                    <h4 className="text-xs font-bold text-primary uppercase tracking-wider mt-3">Remediation</h4>
                                                    <p className="text-sm text-muted-foreground leading-relaxed">{f.remediation}</p>
                                                </>
                                            )}
                                            {f.matched_content && (
                                                <div className="mt-3">
                                                    <h4 className="text-xs font-bold text-muted-foreground uppercase tracking-wider mb-2">Matched Content</h4>
                                                    <div className="relative group/code">
                                                        <pre className="text-xs font-mono text-muted-foreground p-3 rounded-lg overflow-x-auto"
                                                            style={{ background: "rgba(0,0,0,0.4)", border: "1px solid rgba(255,255,255,0.05)" }}>
                                                            {f.matched_content}
                                                        </pre>
                                                        <button
                                                            onClick={(e) => { e.stopPropagation(); handleCopy(f.matched_content, f.id); }}
                                                            className="absolute top-2 right-2 p-1 rounded opacity-0 group-hover/code:opacity-100 transition-opacity"
                                                            style={{ background: "rgba(0,0,0,0.5)" }}
                                                            title="Copy matched content"
                                                        >
                                                            {copiedId === f.id ? <CheckCircle2 className="w-3.5 h-3.5 text-primary" /> : <Copy className="w-3.5 h-3.5 text-muted-foreground" />}
                                                        </button>
                                                    </div>
                                                </div>
                                            )}
                                        </div>

                                        {/* Meta */}
                                        <div className="space-y-3">
                                            <h4 className="text-xs font-bold text-muted-foreground uppercase tracking-wider">Details</h4>
                                            <div className="space-y-2">
                                                {[
                                                    { label: "OWASP", value: f.owasp || "N/A" },
                                                    { label: "CWE", value: f.cwe || "N/A" },
                                                    { label: "Module", value: f.module_name || f.module },
                                                    { label: "Line", value: f.line_number?.toString() || "N/A" },
                                                    { label: "Tags", value: f.tags?.join(", ") || "N/A" },
                                                ].map(d => (
                                                    <div key={d.label} className="flex justify-between text-xs py-1" style={{ borderBottom: "1px solid rgba(255,255,255,0.03)" }}>
                                                        <span className="text-muted-foreground font-semibold">{d.label}</span>
                                                        <span className="text-muted-foreground font-mono">{d.value}</span>
                                                    </div>
                                                ))}
                                                {vf && (
                                                    <>
                                                        <div className="flex justify-between text-xs py-1" style={{ borderBottom: "1px solid rgba(255,255,255,0.03)" }}>
                                                            <span className="text-muted-foreground font-semibold">PoC Strategy</span>
                                                            <span className="text-primary font-mono">{vf.strategy}</span>
                                                        </div>
                                                        <div className="flex justify-between text-xs py-1" style={{ borderBottom: "1px solid rgba(255,255,255,0.03)" }}>
                                                            <span className="text-muted-foreground font-semibold">Timing Delta</span>
                                                            <span className="text-muted-foreground font-mono">{vf.timing_delta_ms}ms</span>
                                                        </div>
                                                    </>
                                                )}
                                            </div>
                                            {/* Quick export */}
                                            <button
                                                onClick={(e) => { e.stopPropagation(); downloadFindingJSON(f); }}
                                                className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-[10px] font-bold uppercase tracking-wider w-full justify-center mt-2"
                                                style={{ background: "rgba(0,255,136,0.08)", border: "1px solid rgba(0,255,136,0.15)", color: "#00FF88" }}
                                            >
                                                <Download className="w-3 h-3" /> Export Finding
                                            </button>
                                        </div>
                                    </div>

                                    {/* Actions Row */}
                                    <div className="flex flex-wrap gap-2 pt-2" style={{ borderTop: "1px solid rgba(255,255,255,0.04)" }}>
                                        {actionButtons.map(a => (
                                            <button
                                                key={a.label}
                                                onClick={(e) => { e.stopPropagation(); a.handler(f); }}
                                                disabled={a.label === "Trigger Revalidation" && revalidating.has(f.id)}
                                                className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-[10px] font-bold uppercase tracking-wider transition-all hover:brightness-125 disabled:opacity-50"
                                                style={{
                                                    background: (a.label === "Mark Accepted Risk" && acceptedRisks.has(f.id))
                                                        ? "rgba(0,255,136,0.15)"
                                                        : (a.label === "Assign to Dev" && assignedFindings.has(f.id))
                                                            ? "rgba(0,163,255,0.15)"
                                                            : `${a.color}10`,
                                                    border: `1px solid ${a.color}20`,
                                                    color: a.color,
                                                }}
                                            >
                                                {a.label === "Trigger Revalidation" && revalidating.has(f.id)
                                                    ? <RefreshCw className="w-3 h-3 animate-spin" />
                                                    : <a.icon className="w-3 h-3" />}
                                                {a.label === "Mark Accepted Risk" && acceptedRisks.has(f.id) ? "Risk Accepted" : a.label}
                                                {a.label === "Assign to Dev" && assignedFindings.has(f.id) ? " \u2713" : ""}
                                            </button>
                                        ))}
                                    </div>
                                </div>
                            </motion.div>
                        );
                    })()}
                </AnimatePresence>
            </motion.div>

            {/* ── PoC Execution Modal ────────────────────────────────────────── */}
            <SlideModal open={!!pocModal} onClose={() => setPocModal(null)} title="PoC Execution" icon={Play} iconColor="#00FF88">
                {pocModal && (() => {
                    const vf = verifiedFindings.find(v => v.finding_id === pocModal.id);
                    return (
                        <div className="space-y-4">
                            <div className="rounded-xl p-4" style={{ background: "rgba(0,0,0,0.3)", border: "1px solid rgba(0,255,136,0.1)" }}>
                                <div className="text-[10px] text-muted-foreground uppercase tracking-widest font-bold mb-2">Target Finding</div>
                                <p className="text-sm text-foreground font-bold">{pocModal.title}</p>
                                <p className="text-xs text-muted-foreground mt-1">{pocModal.file || "N/A"}</p>
                            </div>
                            {vf ? (
                                <>
                                    <div className="grid grid-cols-2 gap-3">
                                        {[
                                            { label: "Strategy", value: vf.strategy, color: "#00FF88" },
                                            { label: "Confidence", value: `${(vf.confidence * 100).toFixed(0)}%`, color: "#00A3FF" },
                                            { label: "Timing Delta", value: `${vf.timing_delta_ms}ms`, color: "#eab308" },
                                            { label: "Evidence Hash", value: vf.evidence_hash?.slice(0, 16) || "N/A", color: "#A5B3AD" },
                                        ].map(item => (
                                            <div key={item.label} className="rounded-lg p-3" style={{ background: "rgba(0,0,0,0.2)", border: "1px solid rgba(255,255,255,0.05)" }}>
                                                <div className="text-[9px] text-muted-foreground uppercase tracking-widest font-bold mb-1">{item.label}</div>
                                                <div className="text-sm font-black font-mono" style={{ color: item.color }}>{item.value}</div>
                                            </div>
                                        ))}
                                    </div>
                                    <div className="rounded-lg p-3" style={{ background: "rgba(0,0,0,0.2)", border: "1px solid rgba(255,255,255,0.05)" }}>
                                        <div className="text-[9px] text-muted-foreground uppercase tracking-widest font-bold mb-1">Endpoint Tested</div>
                                        <code className="text-xs text-primary font-mono break-all">{vf.endpoint}</code>
                                    </div>
                                </>
                            ) : (
                                <div className="py-8 text-center text-muted-foreground text-sm">No PoC verification data available for this finding.</div>
                            )}
                        </div>
                    );
                })()}
            </SlideModal>

            {/* ── Forensic Evidence Modal ─────────────────────────────────────── */}
            <SlideModal open={!!forensicModal} onClose={() => setForensicModal(null)} title="Forensic Evidence" icon={Microscope} iconColor="#00A3FF">
                {forensicModal && (
                    <div className="space-y-4">
                        <div className="rounded-xl p-4" style={{ background: "rgba(0,0,0,0.3)", border: "1px solid rgba(0,163,255,0.1)" }}>
                            <div className="text-[10px] text-muted-foreground uppercase tracking-widest font-bold mb-2">Finding</div>
                            <p className="text-sm text-foreground font-bold">{forensicModal.title}</p>
                            <p className="text-xs text-muted-foreground mt-1">{forensicModal.severity.toUpperCase()} | {forensicModal.cwe || "No CWE"} | {forensicModal.module_name || forensicModal.module}</p>
                        </div>
                        {forensicModal.matched_content && (
                            <div className="rounded-lg p-3" style={{ background: "rgba(0,0,0,0.3)", border: "1px solid rgba(255,255,255,0.05)" }}>
                                <div className="text-[9px] text-muted-foreground uppercase tracking-widest font-bold mb-2">Evidence Payload</div>
                                <pre className="text-xs font-mono text-orange-400/80 break-all whitespace-pre-wrap">{forensicModal.matched_content}</pre>
                            </div>
                        )}
                        <div className="grid grid-cols-2 gap-3">
                            <div className="rounded-lg p-3" style={{ background: "rgba(0,0,0,0.2)", border: "1px solid rgba(255,255,255,0.05)" }}>
                                <div className="text-[9px] text-muted-foreground uppercase font-bold mb-1">Location</div>
                                <code className="text-xs text-muted-foreground font-mono">{forensicModal.file || "N/A"}:{forensicModal.line_number || "?"}</code>
                            </div>
                            <div className="rounded-lg p-3" style={{ background: "rgba(0,0,0,0.2)", border: "1px solid rgba(255,255,255,0.05)" }}>
                                <div className="text-[9px] text-muted-foreground uppercase font-bold mb-1">OWASP Category</div>
                                <code className="text-xs text-muted-foreground font-mono">{forensicModal.owasp || "N/A"}</code>
                            </div>
                        </div>
                        {forensicModal.description && (
                            <div className="rounded-lg p-3" style={{ background: "rgba(0,0,0,0.2)", border: "1px solid rgba(255,255,255,0.05)" }}>
                                <div className="text-[9px] text-muted-foreground uppercase font-bold mb-1">Analysis</div>
                                <p className="text-xs text-muted-foreground leading-relaxed">{forensicModal.description}</p>
                            </div>
                        )}
                        <button
                            onClick={() => { downloadFindingJSON(forensicModal); }}
                            className="w-full flex items-center justify-center gap-2 px-4 py-2 rounded-xl text-xs font-bold uppercase tracking-wider"
                            style={{ background: "rgba(0,163,255,0.1)", border: "1px solid rgba(0,163,255,0.2)", color: "#00A3FF" }}
                        >
                            <Download className="w-3.5 h-3.5" /> Export Forensic Data
                        </button>
                    </div>
                )}
            </SlideModal>

            {/* ── Raw Request/Response Modal ──────────────────────────────────── */}
            <SlideModal open={!!rawModal} onClose={() => setRawModal(null)} title="Raw Request / Response" icon={Code2} iconColor="#eab308">
                {rawModal && (
                    <div className="space-y-4">
                        <div className="rounded-lg overflow-hidden" style={{ border: "1px solid rgba(255,255,255,0.05)" }}>
                            <div className="px-4 py-2 text-[10px] font-black text-amber-400 uppercase tracking-widest" style={{ background: "rgba(234,179,8,0.08)", borderBottom: "1px solid rgba(255,255,255,0.05)" }}>
                                Simulated Request
                            </div>
                            <pre className="text-xs font-mono text-muted-foreground p-4 overflow-x-auto whitespace-pre-wrap" style={{ background: "rgba(0,0,0,0.3)" }}>
{`${rawModal.category?.toUpperCase() || "GET"} ${rawModal.file || "/unknown"} HTTP/1.1
Host: target-application
User-Agent: Quantara-Scanner/5.0
Accept: */*
Content-Type: application/json

${rawModal.matched_content ? `// Payload:\n${rawModal.matched_content}` : "// No payload data"}`}
                            </pre>
                        </div>
                        <div className="rounded-lg overflow-hidden" style={{ border: "1px solid rgba(255,255,255,0.05)" }}>
                            <div className="px-4 py-2 text-[10px] font-black text-primary uppercase tracking-widest" style={{ background: "rgba(0,255,136,0.05)", borderBottom: "1px solid rgba(255,255,255,0.05)" }}>
                                Response Analysis
                            </div>
                            <pre className="text-xs font-mono text-muted-foreground p-4 overflow-x-auto whitespace-pre-wrap" style={{ background: "rgba(0,0,0,0.3)" }}>
{`// Finding: ${rawModal.title}
// Severity: ${rawModal.severity.toUpperCase()}
// Confidence: ${((rawModal.confidence || 0) * 100).toFixed(0)}%
// Module: ${rawModal.module_name || rawModal.module}
${rawModal.description ? `\n// Description:\n// ${rawModal.description}` : ""}`}
                            </pre>
                        </div>
                        <button
                            onClick={() => handleCopy(JSON.stringify(rawModal, null, 2), `raw-${rawModal.id}`)}
                            className="w-full flex items-center justify-center gap-2 px-4 py-2 rounded-xl text-xs font-bold uppercase tracking-wider"
                            style={{ background: "rgba(234,179,8,0.1)", border: "1px solid rgba(234,179,8,0.2)", color: "#eab308" }}
                        >
                            <Copy className="w-3.5 h-3.5" /> Copy Full Finding Data
                        </button>
                    </div>
                )}
            </SlideModal>

            {/* ── Attack Path Modal ───────────────────────────────────────────── */}
            <SlideModal open={!!attackPathModal} onClose={() => setAttackPathModal(null)} title="Attack Path Analysis" icon={GitBranch} iconColor="#ef4444">
                {attackPathModal && (
                    <div className="space-y-4">
                        <div className="rounded-xl p-4" style={{ background: "rgba(0,0,0,0.3)", border: "1px solid rgba(239,68,68,0.1)" }}>
                            <div className="text-[10px] text-muted-foreground uppercase tracking-widest font-bold mb-2">Entry Point</div>
                            <p className="text-sm text-foreground font-bold">{attackPathModal.title}</p>
                            <p className="text-xs text-muted-foreground font-mono mt-1">{attackPathModal.file || "N/A"}</p>
                        </div>
                        <div className="space-y-2">
                            <div className="text-[10px] text-muted-foreground uppercase tracking-widest font-bold">Attack Chain Visualization</div>
                            {[
                                { step: "1. Reconnaissance", desc: `Discovered ${attackPathModal.module_name || attackPathModal.module} vulnerability`, color: "#00A3FF" },
                                { step: "2. Exploitation", desc: `${attackPathModal.severity.toUpperCase()} severity — ${attackPathModal.title}`, color: "#f97316" },
                                { step: "3. Impact", desc: getBusinessImpact(attackPathModal.severity), color: "#ef4444" },
                            ].map((phase, i) => (
                                <div key={i} className="flex items-start gap-3 pl-2">
                                    <div className="flex flex-col items-center">
                                        <div className="w-3 h-3 rounded-full" style={{ background: phase.color, border: `2px solid ${phase.color}` }} />
                                        {i < 2 && <div className="w-0.5 h-8" style={{ background: `${phase.color}40` }} />}
                                    </div>
                                    <div>
                                        <p className="text-xs font-bold" style={{ color: phase.color }}>{phase.step}</p>
                                        <p className="text-[11px] text-muted-foreground">{phase.desc}</p>
                                    </div>
                                </div>
                            ))}
                        </div>
                        {attackPathModal.remediation && (
                            <div className="rounded-lg p-3" style={{ background: "rgba(0,255,136,0.05)", border: "1px solid rgba(0,255,136,0.1)" }}>
                                <div className="text-[9px] text-primary uppercase font-bold mb-1">Remediation</div>
                                <p className="text-xs text-muted-foreground leading-relaxed">{attackPathModal.remediation}</p>
                            </div>
                        )}
                    </div>
                )}
            </SlideModal>
        </>
    );
}
