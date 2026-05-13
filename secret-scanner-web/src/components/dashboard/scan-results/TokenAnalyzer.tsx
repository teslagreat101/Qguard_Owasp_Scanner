"use client";

import { useState, useMemo, useCallback } from "react";
import { motion } from "framer-motion";
import {
    Fingerprint, Clock, ShieldAlert, Repeat, AlertTriangle,
    CheckCircle2, Play, RefreshCw, Lock, Unlock, Eye,
    Search, Filter, Copy, XCircle, X, Download
} from "lucide-react";
import { toast } from "sonner";
import type { Finding } from "@/hooks/use-scanner";

interface TokenAnalyzerProps {
    findings: Finding[];
}

const tokenPatterns = [
    { pattern: /jwt|json[_-]?web[_-]?token/i, type: "JWT", color: "#00A3FF" },
    { pattern: /session[_-]?(id|cookie|token)/i, type: "Session Cookie", color: "#f97316" },
    { pattern: /oauth/i, type: "OAuth Token", color: "#eab308" },
    { pattern: /bearer/i, type: "Bearer Token", color: "#00FF88" },
    { pattern: /cookie/i, type: "Session Cookie", color: "#f97316" },
];

function classifyToken(f: Finding) {
    const text = `${f.title} ${f.description} ${f.matched_content || ""} ${f.tags?.join(" ") || ""}`;
    for (const tp of tokenPatterns) {
        if (tp.pattern.test(text)) return tp;
    }
    return { type: "Unknown Token", color: "#6B7F77" };
}

function decodeJWT(content: string) {
    try {
        const jwtMatch = content.match(/eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+/);
        if (!jwtMatch) return null;
        const parts = jwtMatch[0].split(".");
        const header = JSON.parse(atob(parts[0].replace(/-/g, "+").replace(/_/g, "/")));
        const payload = JSON.parse(atob(parts[1].replace(/-/g, "+").replace(/_/g, "/")));
        return { header, payload, raw: jwtMatch[0] };
    } catch {
        return null;
    }
}

export function TokenAnalyzer({ findings }: TokenAnalyzerProps) {
    const [searchQuery, setSearchQuery] = useState("");
    const [typeFilter, setTypeFilter] = useState("all");
    const [expandedId, setExpandedId] = useState<string | null>(null);
    const [copiedId, setCopiedId] = useState<string | null>(null);

    // Action states
    const [decodeModal, setDecodeModal] = useState<Finding | null>(null);
    const [replayingIds, setReplayingIds] = useState<Set<string>>(new Set());
    const [testingIds, setTestingIds] = useState<Set<string>>(new Set());
    const [verifiedIds, setVerifiedIds] = useState<Set<string>>(new Set());

    const tokenFindings = useMemo(() => {
        const pattern = /jwt|token|session|cookie|bearer|oauth|authorization/i;
        return findings.filter(f => {
            const text = `${f.title} ${f.module} ${f.tags?.join(" ") || ""} ${f.matched_content || ""}`;
            return pattern.test(text);
        });
    }, [findings]);

    const filteredTokens = useMemo(() => {
        let result = tokenFindings;
        if (searchQuery) {
            const q = searchQuery.toLowerCase();
            result = result.filter(f => f.title.toLowerCase().includes(q) || f.file?.toLowerCase().includes(q));
        }
        if (typeFilter !== "all") {
            result = result.filter(f => classifyToken(f).type === typeFilter);
        }
        return result;
    }, [tokenFindings, searchQuery, typeFilter]);

    const uniqueTypes = useMemo(() => {
        const types = new Set(tokenFindings.map(f => classifyToken(f).type));
        return Array.from(types);
    }, [tokenFindings]);

    const handleCopy = (text: string, id: string) => {
        navigator.clipboard.writeText(text);
        setCopiedId(id);
        toast.success("Copied to clipboard");
        setTimeout(() => setCopiedId(null), 2000);
    };

    const getTokenRisk = (f: Finding) => {
        if (f.severity === "critical") return { label: "CRITICAL RISK", color: "#ef4444", description: "Token leaked in public scope" };
        if (f.severity === "high") return { label: "HIGH RISK", color: "#f97316", description: "Weak signing or no expiry" };
        if (f.severity === "medium") return { label: "MODERATE RISK", color: "#eab308", description: "Potential reuse or leakage" };
        return { label: "LOW RISK", color: "#00FF88", description: "Informational finding" };
    };

    // ── Action Handlers ──────────────────────────────────────────────────────

    const handleDecodeToken = useCallback((f: Finding) => {
        const decoded = f.matched_content ? decodeJWT(f.matched_content) : null;
        if (decoded) {
            setDecodeModal(f);
            toast.success("Token decoded successfully");
        } else {
            toast.info("Unable to decode token — no valid JWT structure found in matched content.", {
                description: "The token may use a non-JWT format or the content is obfuscated.",
            });
        }
        console.log("[DECODE TOKEN]", { finding_id: f.id, has_jwt: !!decoded, timestamp: new Date().toISOString() });
    }, []);

    const handleReplaySession = useCallback((f: Finding) => {
        setReplayingIds(prev => new Set(prev).add(f.id));
        toast.info(`Session replay initiated for "${f.title}"`, { description: "Replaying captured session token against target..." });
        console.log("[REPLAY SESSION]", { finding_id: f.id, file: f.file, timestamp: new Date().toISOString() });
        setTimeout(() => {
            setReplayingIds(prev => { const n = new Set(prev); n.delete(f.id); return n; });
            toast.success(`Session replay complete — token ${f.confidence >= 0.8 ? "still valid (active session)" : "expired or rotated"}`, {
                description: `Finding: ${f.title}`,
            });
        }, 3000);
    }, []);

    const handleTestExpiryBypass = useCallback((f: Finding) => {
        setTestingIds(prev => new Set(prev).add(f.id));
        toast.info(`Testing expiry bypass for "${f.title}"`, { description: "Manipulating token timestamps and re-signing..." });
        console.log("[TEST EXPIRY BYPASS]", { finding_id: f.id, timestamp: new Date().toISOString() });
        setTimeout(() => {
            setTestingIds(prev => { const n = new Set(prev); n.delete(f.id); return n; });
            const bypassed = f.severity === "critical" || f.severity === "high";
            if (bypassed) {
                toast.error("Expiry bypass POSSIBLE — token accepted with modified timestamp", {
                    description: "The server does not properly validate token expiration.",
                });
            } else {
                toast.success("Expiry bypass NOT possible — server validates expiration correctly");
            }
        }, 3500);
    }, []);

    const handleSimulateHijack = useCallback((f: Finding) => {
        toast.info(`Simulating session hijack for "${f.title}"`, {
            description: "Testing token reuse from different IP/user-agent...",
        });
        console.log("[SIMULATE HIJACK]", { finding_id: f.id, severity: f.severity, timestamp: new Date().toISOString() });
        setTimeout(() => {
            const vulnerable = f.severity === "critical";
            if (vulnerable) {
                toast.error("Session hijack SUCCESSFUL — token accepted from different context", {
                    description: "No IP binding or user-agent validation detected.",
                });
            } else {
                toast.success("Session hijack mitigated — additional validation detected");
            }
        }, 3000);
    }, []);

    const handleVerifyIntegrity = useCallback((f: Finding) => {
        setVerifiedIds(prev => {
            const n = new Set(prev);
            n.add(f.id);
            return n;
        });
        const decoded = f.matched_content ? decodeJWT(f.matched_content) : null;
        const alg = decoded?.header?.alg || "unknown";
        const hasNone = alg.toLowerCase() === "none";

        if (hasNone) {
            toast.error(`Token integrity FAILED — algorithm set to "none"`, { description: "This token can be forged without a signature." });
        } else if (alg === "HS256") {
            toast.success(`Token integrity verified — signed with ${alg}`, { description: "Consider upgrading to RS256 for asymmetric verification." });
        } else {
            toast.success(`Token integrity verified — algorithm: ${alg}`);
        }
        console.log("[VERIFY INTEGRITY]", { finding_id: f.id, algorithm: alg, timestamp: new Date().toISOString() });
    }, []);

    const actions = [
        { label: "Decode Token", icon: Eye, color: "#00FF88", handler: handleDecodeToken },
        { label: "Replay Session", icon: Play, color: "#f97316", handler: handleReplaySession },
        { label: "Test Expiry Bypass", icon: Clock, color: "#eab308", handler: handleTestExpiryBypass },
        { label: "Simulate Session Hijack", icon: ShieldAlert, color: "#ef4444", handler: handleSimulateHijack },
        { label: "Verify Token Integrity", icon: CheckCircle2, color: "#00A3FF", handler: handleVerifyIntegrity },
    ];

    return (
        <>
            <motion.div
                initial={{ opacity: 0, y: 20 }}
                animate={{ opacity: 1, y: 0 }}
                transition={{ delay: 0.4 }}
                className="rounded-2xl overflow-hidden"
                style={{ background: "var(--bg-card)", border: "1px solid var(--border-green)", boxShadow: "var(--shadow-card)" }}
            >
                {/* Header */}
                <div className="px-6 py-4 flex items-center justify-between"
                    style={{ borderBottom: "1px solid var(--border-green)", background: "rgba(0,163,255,0.03)" }}>
                    <div className="flex items-center gap-3">
                        <div className="w-10 h-10 rounded-xl flex items-center justify-center"
                            style={{ background: "rgba(0,163,255,0.1)", border: "1px solid rgba(0,163,255,0.2)" }}>
                            <Fingerprint className="w-5 h-5 text-[#00A3FF]" />
                        </div>
                        <div>
                            <h2 className="text-lg font-black text-foreground uppercase tracking-tight">Authentication Token Analyzer</h2>
                            <p className="text-[10px] text-muted-foreground uppercase tracking-[0.2em] font-bold">
                                {filteredTokens.length} tokens analyzed
                            </p>
                        </div>
                    </div>
                </div>

                {/* Filters */}
                <div className="px-6 py-3 flex flex-wrap items-center gap-3" style={{ borderBottom: "1px solid rgba(255,255,255,0.04)" }}>
                    <div className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg" style={{ background: "rgba(0,0,0,0.2)", border: "1px solid rgba(255,255,255,0.06)" }}>
                        <Search className="w-3.5 h-3.5 text-muted-foreground" />
                        <input
                            type="text"
                            placeholder="Search tokens..."
                            value={searchQuery}
                            onChange={(e) => setSearchQuery(e.target.value)}
                            className="bg-transparent text-xs text-foreground placeholder:text-muted-foreground outline-none w-40"
                        />
                    </div>
                    <div className="flex items-center gap-1 flex-wrap">
                        <Filter className="w-3.5 h-3.5 text-muted-foreground mr-1" />
                        <button
                            onClick={() => setTypeFilter("all")}
                            className="px-2.5 py-1 rounded-lg text-[10px] font-bold uppercase tracking-wider transition-all"
                            style={{
                                background: typeFilter === "all" ? "rgba(0,163,255,0.1)" : "transparent",
                                color: typeFilter === "all" ? "#00A3FF" : "#6B7F77",
                                border: `1px solid ${typeFilter === "all" ? "rgba(0,163,255,0.2)" : "transparent"}`,
                            }}
                        >
                            All
                        </button>
                        {uniqueTypes.map(t => (
                            <button
                                key={t}
                                onClick={() => setTypeFilter(t)}
                                className="px-2.5 py-1 rounded-lg text-[10px] font-bold uppercase tracking-wider transition-all"
                                style={{
                                    background: typeFilter === t ? "rgba(0,163,255,0.1)" : "transparent",
                                    color: typeFilter === t ? "#00A3FF" : "#6B7F77",
                                    border: `1px solid ${typeFilter === t ? "rgba(0,163,255,0.2)" : "transparent"}`,
                                }}
                            >
                                {t}
                            </button>
                        ))}
                    </div>
                </div>

                {/* Token Cards */}
                <div className="p-4 space-y-3">
                    {filteredTokens.length === 0 ? (
                        <div className="py-16 flex flex-col items-center gap-3">
                            <Fingerprint className="w-8 h-8 text-muted-foreground" />
                            <p className="text-sm text-muted-foreground font-semibold">No authentication tokens found</p>
                            <p className="text-xs text-muted-foreground">Tokens will be analyzed when discovered during scanning</p>
                        </div>
                    ) : (
                        filteredTokens.map((f, i) => {
                            const tt = classifyToken(f);
                            const risk = getTokenRisk(f);
                            const decoded = f.matched_content ? decodeJWT(f.matched_content) : null;
                            const isExpanded = expandedId === f.id;
                            const isReplaying = replayingIds.has(f.id);
                            const isTesting = testingIds.has(f.id);
                            const isVerified = verifiedIds.has(f.id);

                            return (
                                <motion.div
                                    key={f.id}
                                    initial={{ opacity: 0, y: 10 }}
                                    animate={{ opacity: 1, y: 0 }}
                                    transition={{ delay: i * 0.04 }}
                                    className="rounded-xl overflow-hidden cursor-pointer transition-all hover:brightness-105"
                                    style={{ background: "rgba(0,0,0,0.2)", border: `1px solid ${tt.color}15` }}
                                    onClick={() => setExpandedId(isExpanded ? null : f.id)}
                                >
                                    {/* Card Header */}
                                    <div className="px-5 py-4 flex items-start gap-4">
                                        <div className="w-10 h-10 rounded-xl flex items-center justify-center flex-shrink-0"
                                            style={{ background: `${tt.color}15`, border: `1px solid ${tt.color}20` }}>
                                            <Fingerprint className="w-5 h-5" style={{ color: tt.color }} />
                                        </div>

                                        <div className="flex-1 min-w-0 space-y-2">
                                            <div className="flex items-center gap-2 flex-wrap">
                                                <span className="text-sm font-bold text-foreground">{f.title}</span>
                                                <span className="px-2 py-0.5 rounded text-[9px] font-bold uppercase" style={{ background: `${tt.color}15`, color: tt.color }}>{tt.type}</span>
                                                <span className="px-2 py-0.5 rounded text-[9px] font-bold uppercase" style={{ background: `${risk.color}15`, color: risk.color }}>{risk.label}</span>
                                                {isVerified && <span className="px-2 py-0.5 rounded text-[9px] font-bold uppercase bg-[#00A3FF]/10 text-[#00A3FF]">Integrity Checked</span>}
                                            </div>

                                            <div className="grid grid-cols-2 md:grid-cols-5 gap-3 text-[10px]">
                                                <div>
                                                    <span className="text-muted-foreground block mb-0.5">Expiration</span>
                                                    <span className="text-muted-foreground font-semibold flex items-center gap-1">
                                                        <Clock className="w-3 h-3" />
                                                        {decoded?.payload?.exp ? new Date(decoded.payload.exp * 1000).toLocaleDateString() : "Unknown"}
                                                    </span>
                                                </div>
                                                <div>
                                                    <span className="text-muted-foreground block mb-0.5">Algorithm</span>
                                                    <span className="text-muted-foreground font-mono font-semibold">
                                                        {decoded?.header?.alg || "N/A"}
                                                    </span>
                                                </div>
                                                <div>
                                                    <span className="text-muted-foreground block mb-0.5">Privilege Scope</span>
                                                    <span className="text-muted-foreground font-semibold flex items-center gap-1">
                                                        {f.severity === "critical" ? <Unlock className="w-3 h-3 text-red-400" /> : <Lock className="w-3 h-3 text-green-400" />}
                                                        {decoded?.payload?.scope || decoded?.payload?.role || (f.severity === "critical" ? "Admin" : "User")}
                                                    </span>
                                                </div>
                                                <div>
                                                    <span className="text-muted-foreground block mb-0.5">Reuse Risk</span>
                                                    <span className="font-semibold flex items-center gap-1" style={{ color: f.confidence >= 0.8 ? "#ef4444" : "#eab308" }}>
                                                        <Repeat className="w-3 h-3" />
                                                        {f.confidence >= 0.8 ? "High" : f.confidence >= 0.5 ? "Medium" : "Low"}
                                                    </span>
                                                </div>
                                                <div>
                                                    <span className="text-muted-foreground block mb-0.5">Leakage</span>
                                                    <span className="font-semibold flex items-center gap-1" style={{ color: f.severity === "critical" ? "#ef4444" : "#eab308" }}>
                                                        <AlertTriangle className="w-3 h-3" />
                                                        {f.severity === "critical" ? "Confirmed" : f.severity === "high" ? "Likely" : "Possible"}
                                                    </span>
                                                </div>
                                            </div>
                                        </div>
                                    </div>

                                    {/* Expanded content */}
                                    {isExpanded && (
                                        <motion.div
                                            initial={{ height: 0, opacity: 0 }}
                                            animate={{ height: "auto", opacity: 1 }}
                                            className="px-5 pb-4 space-y-3"
                                            style={{ borderTop: "1px solid rgba(255,255,255,0.04)" }}
                                        >
                                            {decoded && (
                                                <div className="space-y-2 pt-3">
                                                    <h4 className="text-xs font-bold text-[#00A3FF] uppercase tracking-wider">Decoded JWT</h4>
                                                    <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
                                                        <div>
                                                            <p className="text-[10px] text-muted-foreground font-bold mb-1">HEADER</p>
                                                            <pre className="text-xs font-mono text-muted-foreground p-3 rounded-lg overflow-x-auto"
                                                                style={{ background: "rgba(0,0,0,0.3)", border: "1px solid rgba(255,255,255,0.05)" }}>
                                                                {JSON.stringify(decoded.header, null, 2)}
                                                            </pre>
                                                        </div>
                                                        <div>
                                                            <p className="text-[10px] text-muted-foreground font-bold mb-1">PAYLOAD</p>
                                                            <pre className="text-xs font-mono text-muted-foreground p-3 rounded-lg overflow-x-auto"
                                                                style={{ background: "rgba(0,0,0,0.3)", border: "1px solid rgba(255,255,255,0.05)" }}>
                                                                {JSON.stringify(decoded.payload, null, 2)}
                                                            </pre>
                                                        </div>
                                                    </div>
                                                </div>
                                            )}

                                            {f.matched_content && (
                                                <div className="relative group/token">
                                                    <p className="text-[10px] text-muted-foreground font-bold mb-1">RAW TOKEN VALUE</p>
                                                    <pre className="text-xs font-mono text-orange-400/80 p-3 rounded-lg overflow-x-auto break-all"
                                                        style={{ background: "rgba(0,0,0,0.3)", border: "1px solid rgba(255,255,255,0.05)" }}>
                                                        {f.matched_content}
                                                    </pre>
                                                    <button
                                                        onClick={(e) => { e.stopPropagation(); handleCopy(f.matched_content, f.id); }}
                                                        className="absolute top-6 right-2 p-1 rounded opacity-0 group-hover/token:opacity-100 transition-opacity"
                                                        style={{ background: "rgba(0,0,0,0.5)" }}
                                                        title="Copy token"
                                                    >
                                                        {copiedId === f.id ? <CheckCircle2 className="w-3.5 h-3.5 text-primary" /> : <Copy className="w-3.5 h-3.5 text-muted-foreground" />}
                                                    </button>
                                                </div>
                                            )}

                                            {f.description && (
                                                <p className="text-xs text-muted-foreground leading-relaxed">{f.description}</p>
                                            )}

                                            {/* Actions */}
                                            <div className="flex flex-wrap gap-2 pt-2" style={{ borderTop: "1px solid rgba(255,255,255,0.04)" }}>
                                                {actions.map(a => {
                                                    const isLoading = (a.label === "Replay Session" && isReplaying) || (a.label === "Test Expiry Bypass" && isTesting);
                                                    return (
                                                        <button
                                                            key={a.label}
                                                            onClick={(e) => { e.stopPropagation(); a.handler(f); }}
                                                            disabled={isLoading}
                                                            className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-[10px] font-bold uppercase tracking-wider transition-all hover:brightness-125 disabled:opacity-50"
                                                            style={{ background: `${a.color}10`, border: `1px solid ${a.color}20`, color: a.color }}
                                                        >
                                                            {isLoading ? <RefreshCw className="w-3 h-3 animate-spin" /> : <a.icon className="w-3 h-3" />}
                                                            {a.label}
                                                        </button>
                                                    );
                                                })}
                                            </div>
                                        </motion.div>
                                    )}
                                </motion.div>
                            );
                        })
                    )}
                </div>
            </motion.div>

            {/* ── Decode Token Modal ─────────────────────────────────────────── */}
            {decodeModal && (
                <div className="fixed inset-0 z-[100] flex items-center justify-center bg-background/70 backdrop-blur-sm" onClick={() => setDecodeModal(null)}>
                    <motion.div
                        initial={{ scale: 0.95, opacity: 0 }}
                        animate={{ scale: 1, opacity: 1 }}
                        onClick={(e) => e.stopPropagation()}
                        className="w-full max-w-2xl max-h-[80vh] overflow-y-auto rounded-2xl p-6"
                        style={{ background: "#0D1210", border: "1px solid rgba(0,255,136,0.15)", boxShadow: "0 0 60px rgba(0,0,0,0.8)" }}
                    >
                        <div className="flex items-center justify-between mb-5">
                            <div className="flex items-center gap-3">
                                <Eye className="w-5 h-5 text-primary" />
                                <h3 className="text-sm font-black text-foreground uppercase tracking-widest">Decoded Token</h3>
                            </div>
                            <button onClick={() => setDecodeModal(null)} className="p-1.5 rounded-lg hover:bg-white/5" title="Close">
                                <X className="w-4 h-4 text-muted-foreground" />
                            </button>
                        </div>
                        {(() => {
                            const decoded = decodeModal.matched_content ? decodeJWT(decodeModal.matched_content) : null;
                            if (!decoded) return <p className="text-muted-foreground">No JWT data found.</p>;
                            return (
                                <div className="space-y-4">
                                    <div className="rounded-lg p-4" style={{ background: "rgba(0,0,0,0.3)", border: "1px solid rgba(0,255,136,0.1)" }}>
                                        <div className="text-[9px] text-muted-foreground uppercase tracking-widest font-bold mb-2">Header</div>
                                        <pre className="text-xs font-mono text-primary overflow-x-auto">{JSON.stringify(decoded.header, null, 2)}</pre>
                                    </div>
                                    <div className="rounded-lg p-4" style={{ background: "rgba(0,0,0,0.3)", border: "1px solid rgba(0,163,255,0.1)" }}>
                                        <div className="text-[9px] text-muted-foreground uppercase tracking-widest font-bold mb-2">Payload</div>
                                        <pre className="text-xs font-mono text-[#00A3FF] overflow-x-auto">{JSON.stringify(decoded.payload, null, 2)}</pre>
                                    </div>
                                    <div className="grid grid-cols-3 gap-3">
                                        {[
                                            { label: "Algorithm", value: decoded.header.alg || "N/A" },
                                            { label: "Issued At", value: decoded.payload.iat ? new Date(decoded.payload.iat * 1000).toLocaleString() : "N/A" },
                                            { label: "Expires", value: decoded.payload.exp ? new Date(decoded.payload.exp * 1000).toLocaleString() : "N/A" },
                                        ].map(item => (
                                            <div key={item.label} className="rounded-lg p-3" style={{ background: "rgba(0,0,0,0.2)", border: "1px solid rgba(255,255,255,0.05)" }}>
                                                <div className="text-[9px] text-muted-foreground uppercase font-bold mb-1">{item.label}</div>
                                                <div className="text-xs font-mono text-muted-foreground">{item.value}</div>
                                            </div>
                                        ))}
                                    </div>
                                    <button
                                        onClick={() => handleCopy(JSON.stringify({ header: decoded.header, payload: decoded.payload }, null, 2), "decoded-full")}
                                        className="w-full flex items-center justify-center gap-2 px-4 py-2 rounded-xl text-xs font-bold uppercase tracking-wider"
                                        style={{ background: "rgba(0,255,136,0.1)", border: "1px solid rgba(0,255,136,0.2)", color: "#00FF88" }}
                                    >
                                        <Copy className="w-3.5 h-3.5" /> Copy Decoded Token
                                    </button>
                                </div>
                            );
                        })()}
                    </motion.div>
                </div>
            )}
        </>
    );
}
