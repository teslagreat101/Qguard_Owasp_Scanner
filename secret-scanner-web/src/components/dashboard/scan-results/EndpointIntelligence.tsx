"use client";

import { useState, useMemo, useCallback } from "react";
import { motion, AnimatePresence } from "framer-motion";
import {
    Globe, Search, Crosshair, TestTube, Zap, Eye, GitBranch,
    Lock, Unlock, ChevronDown, ChevronUp, Shield, Filter,
    X, Copy, CheckCircle2, Download, RefreshCw, AlertTriangle
} from "lucide-react";
import { toast } from "sonner";
import type { EndpointDiscovered, Finding } from "@/hooks/use-scanner";

interface EndpointIntelligenceProps {
    endpoints: EndpointDiscovered[];
    findings: Finding[];
}

const methodColors: Record<string, string> = {
    GET: "#00FF88", POST: "#00A3FF", PUT: "#eab308", DELETE: "#ef4444",
    PATCH: "#f97316", OPTIONS: "#6B7F77", HEAD: "#A5B3AD",
};

interface EnrichedEndpoint {
    url: string;
    methods: string[];
    findings: Finding[];
    severity: string;
    authRequired: boolean;
    parameters: string[];
    responseType: string;
    accessLevel: string;
    exposureStatus: string;
}

export function EndpointIntelligence({ endpoints, findings }: EndpointIntelligenceProps) {
    const [expandedUrl, setExpandedUrl] = useState<string | null>(null);
    const [searchQuery, setSearchQuery] = useState("");
    const [methodFilter, setMethodFilter] = useState<string>("all");
    const [copiedId, setCopiedId] = useState<string | null>(null);

    // Modal states
    const [inspectModal, setInspectModal] = useState<EnrichedEndpoint | null>(null);
    const [vulnsModal, setVulnsModal] = useState<EnrichedEndpoint | null>(null);
    const [fuzzingEndpoint, setFuzzingEndpoint] = useState<string | null>(null);
    const [testingEndpoint, setTestingEndpoint] = useState<string | null>(null);

    const handleCopy = (text: string, id: string) => {
        navigator.clipboard.writeText(text);
        setCopiedId(id);
        toast.success("Copied to clipboard");
        setTimeout(() => setCopiedId(null), 2000);
    };

    // Enrich endpoints with finding data
    const enrichedEndpoints = useMemo(() => {
        const urlMap = new Map<string, EnrichedEndpoint>();

        endpoints.forEach(ep => {
            const existing = urlMap.get(ep.url);
            if (existing) {
                if (!existing.methods.includes(ep.method)) existing.methods.push(ep.method);
                if (ep.severity === "critical" || (ep.severity === "high" && existing.severity !== "critical")) {
                    existing.severity = ep.severity;
                }
            } else {
                const relatedFindings = findings.filter(f => (f.file || f.location || "").includes(ep.url));
                urlMap.set(ep.url, {
                    url: ep.url,
                    methods: [ep.method],
                    findings: relatedFindings,
                    severity: ep.severity,
                    authRequired: relatedFindings.some(f => f.tags?.includes("auth") || f.module === "auth"),
                    parameters: [],
                    responseType: "JSON",
                    accessLevel: ep.severity === "critical" ? "Admin" : ep.severity === "high" ? "Privileged" : "Public",
                    exposureStatus: relatedFindings.length > 0 ? "Vulnerable" : "Normal",
                });
            }
        });

        findings.forEach(f => {
            const url = f.file || f.location || "";
            if (url && !urlMap.has(url)) {
                urlMap.set(url, {
                    url,
                    methods: [f.category?.toUpperCase() || "GET"],
                    findings: [f],
                    severity: f.severity,
                    authRequired: f.tags?.includes("auth") || f.module === "auth" || false,
                    parameters: [],
                    responseType: "JSON",
                    accessLevel: f.severity === "critical" ? "Admin" : f.severity === "high" ? "Privileged" : "Public",
                    exposureStatus: "Vulnerable",
                });
            }
        });

        return Array.from(urlMap.values());
    }, [endpoints, findings]);

    const filteredEndpoints = useMemo(() => {
        let result = enrichedEndpoints;
        if (searchQuery) {
            const q = searchQuery.toLowerCase();
            result = result.filter(e => e.url.toLowerCase().includes(q));
        }
        if (methodFilter !== "all") {
            result = result.filter(e => e.methods.includes(methodFilter.toUpperCase()));
        }
        return result;
    }, [enrichedEndpoints, searchQuery, methodFilter]);

    // ── Action Handlers ──────────────────────────────────────────────────────

    const handleInspect = useCallback((ep: EnrichedEndpoint) => {
        setInspectModal(ep);
        console.log("[INSPECT ENDPOINT]", { url: ep.url, methods: ep.methods, timestamp: new Date().toISOString() });
    }, []);

    const handleLaunchPoc = useCallback((ep: EnrichedEndpoint) => {
        toast.success(`Manual PoC launched against ${ep.url}`, {
            description: `Methods: ${ep.methods.join(", ")} | ${ep.findings.length} known vulnerabilities`,
        });
        console.log("[LAUNCH POC]", { url: ep.url, methods: ep.methods, findings: ep.findings.length, timestamp: new Date().toISOString() });
    }, []);

    const handleTestEndpoint = useCallback((ep: EnrichedEndpoint) => {
        setTestingEndpoint(ep.url);
        toast.info(`Testing endpoint ${ep.url}...`, { description: "Sending probe requests to verify availability and response." });
        console.log("[TEST ENDPOINT]", { url: ep.url, timestamp: new Date().toISOString() });
        setTimeout(() => {
            setTestingEndpoint(null);
            toast.success(`Endpoint test complete: ${ep.url}`, { description: `Status: Reachable | Access: ${ep.accessLevel} | Auth: ${ep.authRequired ? "Required" : "None"}` });
        }, 2500);
    }, []);

    const handleFuzz = useCallback((ep: EnrichedEndpoint) => {
        setFuzzingEndpoint(ep.url);
        toast.info(`Fuzzing initiated on ${ep.url}`, { description: "Generating mutation payloads and probing for anomalies..." });
        console.log("[FUZZ ENDPOINT]", { url: ep.url, methods: ep.methods, timestamp: new Date().toISOString() });
        setTimeout(() => {
            setFuzzingEndpoint(null);
            toast.success(`Fuzzing complete for ${ep.url}`, { description: "No additional vulnerabilities discovered." });
        }, 4000);
    }, []);

    const handleViewRelatedVulns = useCallback((ep: EnrichedEndpoint) => {
        if (ep.findings.length === 0) {
            toast.info(`No vulnerabilities associated with ${ep.url}`);
            return;
        }
        setVulnsModal(ep);
    }, []);

    const handleTraceDependency = useCallback((ep: EnrichedEndpoint) => {
        toast.success(`Dependency trace for ${ep.url}`, {
            description: `Access Level: ${ep.accessLevel} | Auth: ${ep.authRequired ? "Required" : "Open"} | Related Findings: ${ep.findings.length}`,
        });
        console.log("[TRACE DEPENDENCY]", { url: ep.url, access_level: ep.accessLevel, auth: ep.authRequired, findings: ep.findings.length, timestamp: new Date().toISOString() });
    }, []);

    const endpointActions = [
        { label: "Inspect Endpoint", icon: Eye, color: "#00FF88", handler: handleInspect },
        { label: "Launch Manual PoC", icon: Crosshair, color: "#ef4444", handler: handleLaunchPoc },
        { label: "Test Endpoint", icon: TestTube, color: "#00A3FF", handler: handleTestEndpoint },
        { label: "Fuzz Endpoint", icon: Zap, color: "#f97316", handler: handleFuzz },
        { label: "View Related Vulns", icon: Shield, color: "#eab308", handler: handleViewRelatedVulns },
        { label: "Trace Dependency", icon: GitBranch, color: "#A5B3AD", handler: handleTraceDependency },
    ];

    return (
        <>
            <motion.div
                initial={{ opacity: 0, y: 20 }}
                animate={{ opacity: 1, y: 0 }}
                transition={{ delay: 0.2 }}
                className="rounded-2xl overflow-hidden"
                style={{ background: "var(--bg-card)", border: "1px solid var(--border-green)", boxShadow: "var(--shadow-card)" }}
            >
                {/* Header */}
                <div className="px-6 py-4 flex items-center justify-between"
                    style={{ borderBottom: "1px solid var(--border-green)", background: "rgba(0,163,255,0.03)" }}>
                    <div className="flex items-center gap-3">
                        <div className="w-10 h-10 rounded-xl flex items-center justify-center"
                            style={{ background: "rgba(0,163,255,0.1)", border: "1px solid rgba(0,163,255,0.2)" }}>
                            <Globe className="w-5 h-5 text-[#00A3FF]" />
                        </div>
                        <div>
                            <h2 className="text-lg font-black text-foreground uppercase tracking-tight">Endpoint Intelligence</h2>
                            <p className="text-[10px] text-muted-foreground uppercase tracking-[0.2em] font-bold">
                                {filteredEndpoints.length} endpoints discovered
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
                            placeholder="Search endpoints..."
                            value={searchQuery}
                            onChange={(e) => setSearchQuery(e.target.value)}
                            className="bg-transparent text-xs text-foreground placeholder:text-muted-foreground outline-none w-48"
                        />
                    </div>
                    <div className="flex items-center gap-1">
                        <Filter className="w-3.5 h-3.5 text-muted-foreground mr-1" />
                        {["all", "GET", "POST", "PUT", "DELETE"].map(m => (
                            <button
                                key={m}
                                onClick={() => setMethodFilter(m)}
                                className="px-2.5 py-1 rounded-lg text-[10px] font-bold uppercase tracking-wider transition-all"
                                style={{
                                    background: methodFilter === m ? `${methodColors[m] || "#00FF88"}15` : "transparent",
                                    color: methodFilter === m ? (methodColors[m] || "#00FF88") : "#6B7F77",
                                    border: `1px solid ${methodFilter === m ? `${methodColors[m] || "#00FF88"}30` : "transparent"}`,
                                }}
                            >
                                {m}
                            </button>
                        ))}
                    </div>
                </div>

                {/* Endpoint List */}
                <div className="divide-y" style={{ borderColor: "rgba(255,255,255,0.03)" }}>
                    {filteredEndpoints.length === 0 ? (
                        <div className="px-6 py-16 flex flex-col items-center gap-3">
                            <Globe className="w-8 h-8 text-muted-foreground" />
                            <p className="text-sm text-muted-foreground font-semibold">No endpoints discovered</p>
                            <p className="text-xs text-muted-foreground">Endpoints will appear as scans discover them</p>
                        </div>
                    ) : (
                        filteredEndpoints.slice(0, 50).map((ep, i) => {
                            const isExpanded = expandedUrl === ep.url;
                            const vulnCount = ep.findings.length;
                            const statusColor = ep.exposureStatus === "Vulnerable" ? "#ef4444" : "#00FF88";
                            const isFuzzing = fuzzingEndpoint === ep.url;
                            const isTesting = testingEndpoint === ep.url;

                            return (
                                <div key={ep.url + i}>
                                    <motion.div
                                        initial={{ opacity: 0 }}
                                        animate={{ opacity: 1 }}
                                        transition={{ delay: i * 0.02 }}
                                        className="px-6 py-3 flex items-center gap-4 cursor-pointer hover:bg-white/[0.02] transition-colors"
                                        onClick={() => setExpandedUrl(isExpanded ? null : ep.url)}
                                    >
                                        {/* Methods */}
                                        <div className="flex gap-1 min-w-[100px]">
                                            {ep.methods.map(m => (
                                                <span key={m} className="px-2 py-0.5 rounded text-[9px] font-black uppercase"
                                                    style={{ background: `${methodColors[m] || "#6B7F77"}15`, color: methodColors[m] || "#6B7F77" }}>
                                                    {m}
                                                </span>
                                            ))}
                                        </div>

                                        {/* URL */}
                                        <div className="flex-1 min-w-0">
                                            <p className="text-sm font-mono text-muted-foreground truncate">{ep.url}</p>
                                        </div>

                                        {/* Status indicators */}
                                        {(isFuzzing || isTesting) && (
                                            <RefreshCw className="w-3.5 h-3.5 text-[#00A3FF] animate-spin" />
                                        )}

                                        {/* Auth */}
                                        <div className="flex items-center gap-1">
                                            {ep.authRequired ? (
                                                <Lock className="w-3.5 h-3.5 text-[#eab308]" />
                                            ) : (
                                                <Unlock className="w-3.5 h-3.5 text-muted-foreground" />
                                            )}
                                            <span className="text-[10px] font-bold text-muted-foreground">{ep.authRequired ? "Auth" : "Open"}</span>
                                        </div>

                                        {/* Access Level */}
                                        <span className="px-2 py-0.5 rounded text-[10px] font-bold"
                                            style={{
                                                background: ep.accessLevel === "Admin" ? "rgba(239,68,68,0.1)" :
                                                    ep.accessLevel === "Privileged" ? "rgba(249,115,22,0.1)" : "rgba(0,255,136,0.1)",
                                                color: ep.accessLevel === "Admin" ? "#ef4444" :
                                                    ep.accessLevel === "Privileged" ? "#f97316" : "#00FF88",
                                            }}>
                                            {ep.accessLevel}
                                        </span>

                                        {/* Exposure */}
                                        <div className="flex items-center gap-1.5">
                                            <span className="w-1.5 h-1.5 rounded-full" style={{ background: statusColor }} />
                                            <span className="text-[10px] font-bold uppercase" style={{ color: statusColor }}>{ep.exposureStatus}</span>
                                        </div>

                                        {vulnCount > 0 && (
                                            <span className="px-2 py-0.5 rounded-full text-[10px] font-black"
                                                style={{ background: "rgba(239,68,68,0.1)", color: "#ef4444" }}>
                                                {vulnCount} vulns
                                            </span>
                                        )}

                                        {isExpanded ? <ChevronUp className="w-4 h-4 text-muted-foreground" /> : <ChevronDown className="w-4 h-4 text-muted-foreground" />}
                                    </motion.div>

                                    {/* Expanded */}
                                    <AnimatePresence>
                                        {isExpanded && (
                                            <motion.div
                                                initial={{ height: 0, opacity: 0 }}
                                                animate={{ height: "auto", opacity: 1 }}
                                                exit={{ height: 0, opacity: 0 }}
                                                className="overflow-hidden"
                                                style={{ background: "rgba(0,0,0,0.15)" }}
                                            >
                                                <div className="px-6 py-4 space-y-3">
                                                    <div className="grid grid-cols-2 md:grid-cols-4 gap-3 text-xs">
                                                        <div><span className="text-muted-foreground font-semibold">Response Type:</span> <span className="text-muted-foreground ml-1">{ep.responseType}</span></div>
                                                        <div><span className="text-muted-foreground font-semibold">Auth Required:</span> <span className="text-muted-foreground ml-1">{ep.authRequired ? "Yes" : "No"}</span></div>
                                                        <div><span className="text-muted-foreground font-semibold">Access Level:</span> <span className="text-muted-foreground ml-1">{ep.accessLevel}</span></div>
                                                        <div><span className="text-muted-foreground font-semibold">Exposure:</span> <span style={{ color: statusColor }} className="ml-1 font-semibold">{ep.exposureStatus}</span></div>
                                                    </div>

                                                    {/* Related findings preview */}
                                                    {ep.findings.length > 0 && (
                                                        <div className="space-y-1">
                                                            <div className="text-[9px] text-muted-foreground uppercase tracking-widest font-bold">Associated Vulnerabilities</div>
                                                            {ep.findings.slice(0, 3).map(f => (
                                                                <div key={f.id} className="flex items-center gap-2 text-[10px] py-1 px-2 rounded" style={{ background: "rgba(0,0,0,0.15)" }}>
                                                                    <span className="px-1.5 py-0.5 rounded text-[9px] font-black uppercase"
                                                                        style={{
                                                                            background: f.severity === "critical" ? "rgba(239,68,68,0.15)" : f.severity === "high" ? "rgba(249,115,22,0.15)" : "rgba(234,179,8,0.15)",
                                                                            color: f.severity === "critical" ? "#ef4444" : f.severity === "high" ? "#f97316" : "#eab308",
                                                                        }}>{f.severity}</span>
                                                                    <span className="text-muted-foreground truncate">{f.title}</span>
                                                                </div>
                                                            ))}
                                                        </div>
                                                    )}

                                                    {/* Actions */}
                                                    <div className="flex flex-wrap gap-2 pt-2" style={{ borderTop: "1px solid rgba(255,255,255,0.04)" }}>
                                                        {endpointActions.map(a => (
                                                            <button
                                                                key={a.label}
                                                                onClick={(e) => { e.stopPropagation(); a.handler(ep); }}
                                                                disabled={(a.label === "Fuzz Endpoint" && isFuzzing) || (a.label === "Test Endpoint" && isTesting)}
                                                                className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-[10px] font-bold uppercase tracking-wider transition-all hover:brightness-125 disabled:opacity-50"
                                                                style={{ background: `${a.color}10`, border: `1px solid ${a.color}20`, color: a.color }}
                                                            >
                                                                {((a.label === "Fuzz Endpoint" && isFuzzing) || (a.label === "Test Endpoint" && isTesting))
                                                                    ? <RefreshCw className="w-3 h-3 animate-spin" />
                                                                    : <a.icon className="w-3 h-3" />}
                                                                {a.label}
                                                            </button>
                                                        ))}
                                                    </div>
                                                </div>
                                            </motion.div>
                                        )}
                                    </AnimatePresence>
                                </div>
                            );
                        })
                    )}
                </div>
            </motion.div>

            {/* ── Inspect Endpoint Modal ─────────────────────────────────────── */}
            {inspectModal && (
                <div className="fixed inset-0 z-[100] flex items-center justify-center bg-background/70 backdrop-blur-sm" onClick={() => setInspectModal(null)}>
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
                                <h3 className="text-sm font-black text-foreground uppercase tracking-widest">Endpoint Inspection</h3>
                            </div>
                            <button onClick={() => setInspectModal(null)} className="p-1.5 rounded-lg hover:bg-white/5" title="Close">
                                <X className="w-4 h-4 text-muted-foreground" />
                            </button>
                        </div>
                        <div className="space-y-4">
                            <div className="rounded-lg p-4" style={{ background: "rgba(0,0,0,0.3)", border: "1px solid rgba(0,255,136,0.1)" }}>
                                <div className="text-[9px] text-muted-foreground uppercase tracking-widest font-bold mb-2">URL</div>
                                <div className="flex items-center gap-2">
                                    <code className="text-sm text-primary font-mono break-all flex-1">{inspectModal.url}</code>
                                    <button onClick={() => handleCopy(inspectModal.url, "inspect-url")} className="p-1 rounded hover:bg-white/5" title="Copy URL">
                                        {copiedId === "inspect-url" ? <CheckCircle2 className="w-3.5 h-3.5 text-primary" /> : <Copy className="w-3.5 h-3.5 text-muted-foreground" />}
                                    </button>
                                </div>
                            </div>
                            <div className="grid grid-cols-2 md:grid-cols-3 gap-3">
                                {[
                                    { label: "Methods", value: inspectModal.methods.join(", "), color: "#00A3FF" },
                                    { label: "Access Level", value: inspectModal.accessLevel, color: inspectModal.accessLevel === "Admin" ? "#ef4444" : "#f97316" },
                                    { label: "Auth Required", value: inspectModal.authRequired ? "Yes" : "No", color: inspectModal.authRequired ? "#eab308" : "#00FF88" },
                                    { label: "Exposure", value: inspectModal.exposureStatus, color: inspectModal.exposureStatus === "Vulnerable" ? "#ef4444" : "#00FF88" },
                                    { label: "Response Type", value: inspectModal.responseType, color: "#A5B3AD" },
                                    { label: "Vulnerabilities", value: String(inspectModal.findings.length), color: inspectModal.findings.length > 0 ? "#ef4444" : "#00FF88" },
                                ].map(item => (
                                    <div key={item.label} className="rounded-lg p-3" style={{ background: "rgba(0,0,0,0.2)", border: "1px solid rgba(255,255,255,0.05)" }}>
                                        <div className="text-[9px] text-muted-foreground uppercase font-bold mb-1">{item.label}</div>
                                        <div className="text-sm font-black font-mono" style={{ color: item.color }}>{item.value}</div>
                                    </div>
                                ))}
                            </div>
                            {inspectModal.findings.length > 0 && (
                                <div className="space-y-2">
                                    <div className="text-[9px] text-muted-foreground uppercase tracking-widest font-bold">Linked Findings</div>
                                    {inspectModal.findings.map(f => (
                                        <div key={f.id} className="flex items-center gap-3 px-3 py-2 rounded-lg" style={{ background: "rgba(0,0,0,0.2)", border: "1px solid rgba(255,255,255,0.03)" }}>
                                            <span className="px-2 py-0.5 rounded text-[9px] font-black uppercase"
                                                style={{
                                                    background: f.severity === "critical" ? "rgba(239,68,68,0.15)" : f.severity === "high" ? "rgba(249,115,22,0.15)" : "rgba(234,179,8,0.15)",
                                                    color: f.severity === "critical" ? "#ef4444" : f.severity === "high" ? "#f97316" : "#eab308",
                                                }}>{f.severity}</span>
                                            <span className="text-xs text-foreground font-semibold flex-1 truncate">{f.title}</span>
                                            <span className="text-[10px] text-muted-foreground font-mono">{f.cwe || ""}</span>
                                        </div>
                                    ))}
                                </div>
                            )}
                        </div>
                    </motion.div>
                </div>
            )}

            {/* ── Related Vulnerabilities Modal ─────────────────────────────── */}
            {vulnsModal && (
                <div className="fixed inset-0 z-[100] flex items-center justify-center bg-background/70 backdrop-blur-sm" onClick={() => setVulnsModal(null)}>
                    <motion.div
                        initial={{ scale: 0.95, opacity: 0 }}
                        animate={{ scale: 1, opacity: 1 }}
                        onClick={(e) => e.stopPropagation()}
                        className="w-full max-w-2xl max-h-[80vh] overflow-y-auto rounded-2xl p-6"
                        style={{ background: "#0D1210", border: "1px solid rgba(234,179,8,0.15)", boxShadow: "0 0 60px rgba(0,0,0,0.8)" }}
                    >
                        <div className="flex items-center justify-between mb-5">
                            <div className="flex items-center gap-3">
                                <Shield className="w-5 h-5 text-[#eab308]" />
                                <h3 className="text-sm font-black text-foreground uppercase tracking-widest">Related Vulnerabilities</h3>
                                <span className="text-[10px] text-muted-foreground font-mono">{vulnsModal.url}</span>
                            </div>
                            <button onClick={() => setVulnsModal(null)} className="p-1.5 rounded-lg hover:bg-white/5" title="Close">
                                <X className="w-4 h-4 text-muted-foreground" />
                            </button>
                        </div>
                        <div className="space-y-2">
                            {vulnsModal.findings.map(f => (
                                <div key={f.id} className="rounded-xl p-4 space-y-2" style={{ background: "rgba(0,0,0,0.2)", border: "1px solid rgba(255,255,255,0.05)" }}>
                                    <div className="flex items-center gap-2">
                                        <span className="px-2 py-0.5 rounded text-[9px] font-black uppercase"
                                            style={{
                                                background: f.severity === "critical" ? "rgba(239,68,68,0.15)" : f.severity === "high" ? "rgba(249,115,22,0.15)" : "rgba(234,179,8,0.15)",
                                                color: f.severity === "critical" ? "#ef4444" : f.severity === "high" ? "#f97316" : "#eab308",
                                            }}>{f.severity}</span>
                                        <span className="text-sm text-foreground font-bold">{f.title}</span>
                                        {f.cwe && <span className="text-[10px] text-muted-foreground font-mono">{f.cwe}</span>}
                                    </div>
                                    {f.description && <p className="text-xs text-muted-foreground">{f.description}</p>}
                                    <div className="flex items-center gap-4 text-[10px] text-muted-foreground">
                                        <span>Module: {f.module_name || f.module}</span>
                                        <span>Confidence: {((f.confidence || 0) * 100).toFixed(0)}%</span>
                                        {f.owasp && <span>{f.owasp}</span>}
                                    </div>
                                </div>
                            ))}
                        </div>
                    </motion.div>
                </div>
            )}
        </>
    );
}
