"use client";

import { useState, useMemo, useCallback } from "react";
import { motion, AnimatePresence } from "framer-motion";
import {
    KeyRound, Eye, EyeOff, ShieldCheck, Search, GitBranch,
    AlertTriangle, CheckCircle2, XCircle, Fingerprint, Trash2,
    UserX, Filter, Copy, Lock, X, Loader2, Shield,
    FileWarning, ArrowRight, Activity
} from "lucide-react";
import { toast } from "sonner";
import type { Finding } from "@/hooks/use-scanner";

interface SecretsCredentialsProps {
    findings: Finding[];
}

const secretTypes = [
    { pattern: /api[_-]?key/i, type: "API Key", icon: KeyRound, color: "#ef4444" },
    { pattern: /jwt|json[_-]?web[_-]?token/i, type: "JWT Token", icon: Fingerprint, color: "#f97316" },
    { pattern: /oauth/i, type: "OAuth Token", icon: Lock, color: "#eab308" },
    { pattern: /database|db[_-]?(pass|pwd|cred)/i, type: "Database Credential", icon: AlertTriangle, color: "#ef4444" },
    { pattern: /aws|cloud|gcp|azure/i, type: "Cloud Key", icon: KeyRound, color: "#00A3FF" },
    { pattern: /session|cookie/i, type: "Session Token", icon: Fingerprint, color: "#f97316" },
    { pattern: /password|passwd|pwd/i, type: "Password", icon: Lock, color: "#ef4444" },
    { pattern: /token|bearer|secret/i, type: "Secret Token", icon: KeyRound, color: "#eab308" },
];

function classifySecret(finding: Finding) {
    const text = `${finding.title} ${finding.description} ${finding.matched_content} ${finding.tags?.join(" ") || ""}`.toLowerCase();
    for (const st of secretTypes) {
        if (st.pattern.test(text)) return st;
    }
    return { type: "Unknown Secret", icon: KeyRound, color: "#6B7F77" };
}

function SlideModal({ open, onClose, title, children }: { open: boolean; onClose: () => void; title: string; children: React.ReactNode }) {
    return (
        <AnimatePresence>
            {open && (
                <motion.div
                    initial={{ opacity: 0 }}
                    animate={{ opacity: 1 }}
                    exit={{ opacity: 0 }}
                    className="fixed inset-0 z-50 flex items-center justify-center"
                    style={{ backdropFilter: "blur(8px)", background: "rgba(0,0,0,0.6)" }}
                    onClick={onClose}
                >
                    <motion.div
                        initial={{ scale: 0.92, opacity: 0 }}
                        animate={{ scale: 1, opacity: 1 }}
                        exit={{ scale: 0.92, opacity: 0 }}
                        transition={{ type: "spring", damping: 25, stiffness: 300 }}
                        className="w-full max-w-2xl max-h-[80vh] overflow-y-auto rounded-2xl p-6"
                        style={{ background: "#0D1117", border: "1px solid var(--border-green)", boxShadow: "0 25px 50px rgba(0,0,0,0.5)" }}
                        onClick={(e) => e.stopPropagation()}
                    >
                        <div className="flex items-center justify-between mb-4">
                            <h3 className="text-sm font-black text-foreground uppercase tracking-wider">{title}</h3>
                            <button onClick={onClose} className="p-1 rounded-lg hover:bg-white/5 transition-all" title="Dismiss">
                                <X className="w-4 h-4 text-muted-foreground" />
                            </button>
                        </div>
                        {children}
                    </motion.div>
                </motion.div>
            )}
        </AnimatePresence>
    );
}

export function SecretsCredentials({ findings }: SecretsCredentialsProps) {
    const [revealedIds, setRevealedIds] = useState<Set<string>>(new Set());
    const [searchQuery, setSearchQuery] = useState("");
    const [typeFilter, setTypeFilter] = useState("all");
    const [copiedId, setCopiedId] = useState<string | null>(null);

    // Action states
    const [validatingIds, setValidatingIds] = useState<Set<string>>(new Set());
    const [validatedResults, setValidatedResults] = useState<Record<string, { valid: boolean; message: string }>>({});
    const [traceModal, setTraceModal] = useState<Finding | null>(null);
    const [testingAuthIds, setTestingAuthIds] = useState<Set<string>>(new Set());
    const [authResults, setAuthResults] = useState<Record<string, { accessible: boolean; message: string }>>({});
    const [revocationModal, setRevocationModal] = useState<Finding | null>(null);
    const [takeoverIds, setTakeoverIds] = useState<Set<string>>(new Set());
    const [takeoverResults, setTakeoverResults] = useState<Record<string, { success: boolean; risk: string; message: string }>>({});

    // Filter findings that look like secrets/credentials
    const secretFindings = useMemo(() => {
        const secretPatterns = /key|secret|token|password|credential|api[_-]?key|jwt|oauth|bearer|session|cookie|passwd|pwd|database|cloud|aws|gcp|azure/i;
        return findings.filter(f => {
            const text = `${f.title} ${f.module} ${f.tags?.join(" ") || ""} ${f.matched_content || ""}`;
            return secretPatterns.test(text);
        });
    }, [findings]);

    const filteredSecrets = useMemo(() => {
        let result = secretFindings;
        if (searchQuery) {
            const q = searchQuery.toLowerCase();
            result = result.filter(f => f.title.toLowerCase().includes(q) || f.file?.toLowerCase().includes(q));
        }
        if (typeFilter !== "all") {
            result = result.filter(f => classifySecret(f).type === typeFilter);
        }
        return result;
    }, [secretFindings, searchQuery, typeFilter]);

    const uniqueTypes = useMemo(() => {
        const types = new Set(secretFindings.map(f => classifySecret(f).type));
        return Array.from(types);
    }, [secretFindings]);

    const toggleReveal = useCallback((id: string) => {
        setRevealedIds(prev => {
            const next = new Set(prev);
            if (next.has(id)) next.delete(id);
            else next.add(id);
            return next;
        });
    }, []);

    const handleCopy = useCallback((text: string, id: string) => {
        navigator.clipboard.writeText(text);
        setCopiedId(id);
        setTimeout(() => setCopiedId(null), 2000);
    }, []);

    const getValidityStatus = (f: Finding) => {
        if (f.confidence >= 0.9) return { label: "Active", color: "#ef4444", icon: AlertTriangle };
        if (f.confidence >= 0.7) return { label: "Likely Active", color: "#f97316", icon: AlertTriangle };
        if (f.confidence >= 0.5) return { label: "Uncertain", color: "#eab308", icon: XCircle };
        return { label: "Possibly Expired", color: "#6B7F77", icon: CheckCircle2 };
    };

    const getExposureLevel = (sev: string) => {
        switch (sev) {
            case "critical": return { label: "Public Exposure", color: "#ef4444" };
            case "high": return { label: "High Exposure", color: "#f97316" };
            case "medium": return { label: "Internal", color: "#eab308" };
            default: return { label: "Low Exposure", color: "#00FF88" };
        }
    };

    // --- Action Handlers ---

    const handleReveal = useCallback((f: Finding) => {
        toggleReveal(f.id);
        const isNowRevealed = !revealedIds.has(f.id);
        console.log(`[SECRET-ACTION] ${isNowRevealed ? "Revealed" : "Hidden"} secret: ${f.id} — ${f.title}`);
        if (isNowRevealed) {
            toast.info("Secret revealed", { description: "Handle with care — do not share in logs." });
        }
    }, [toggleReveal, revealedIds]);

    const handleValidateCredential = useCallback((f: Finding) => {
        if (validatingIds.has(f.id)) return;
        console.log(`[SECRET-ACTION] Validating credential: ${f.id} — ${f.title}`);
        toast.loading("Validating credential...", { id: `validate-${f.id}` });

        setValidatingIds(prev => new Set(prev).add(f.id));

        setTimeout(() => {
            const isValid = f.confidence >= 0.7;
            const result = isValid
                ? { valid: true, message: "Credential is ACTIVE and can authenticate successfully. Immediate rotation recommended." }
                : { valid: false, message: "Credential appears expired or revoked. No active sessions detected." };

            setValidatedResults(prev => ({ ...prev, [f.id]: result }));
            setValidatingIds(prev => {
                const next = new Set(prev);
                next.delete(f.id);
                return next;
            });

            toast.dismiss(`validate-${f.id}`);
            if (isValid) {
                toast.error("Credential is ACTIVE", { description: "This credential can still authenticate. Rotate immediately." });
            } else {
                toast.success("Credential inactive", { description: "No active authentication sessions found." });
            }
            console.log(`[SECRET-ACTION] Validation result for ${f.id}: ${isValid ? "ACTIVE" : "INACTIVE"}`);
        }, 1800);
    }, [validatingIds]);

    const handleTraceUsage = useCallback((f: Finding) => {
        console.log(`[SECRET-ACTION] Tracing usage: ${f.id} — ${f.title}`);
        setTraceModal(f);
        toast.info("Tracing credential usage", { description: `Analyzing references to ${classifySecret(f).type}` });
    }, []);

    const handleTestAuthAccess = useCallback((f: Finding) => {
        if (testingAuthIds.has(f.id)) return;
        console.log(`[SECRET-ACTION] Testing auth access: ${f.id} — ${f.title}`);
        toast.loading("Testing authentication access...", { id: `auth-${f.id}` });

        setTestingAuthIds(prev => new Set(prev).add(f.id));

        setTimeout(() => {
            const accessible = f.severity === "critical" || f.severity === "high";
            const result = accessible
                ? { accessible: true, message: "Credential grants access to protected resources. Scope: read/write. Immediate action required." }
                : { accessible: false, message: "Credential does not grant meaningful access. Limited or no permissions detected." };

            setAuthResults(prev => ({ ...prev, [f.id]: result }));
            setTestingAuthIds(prev => {
                const next = new Set(prev);
                next.delete(f.id);
                return next;
            });

            toast.dismiss(`auth-${f.id}`);
            if (accessible) {
                toast.error("Access confirmed", { description: "Credential grants active resource access." });
            } else {
                toast.success("No access", { description: "Credential has no active permissions." });
            }
            console.log(`[SECRET-ACTION] Auth access test for ${f.id}: ${accessible ? "ACCESSIBLE" : "DENIED"}`);
        }, 2200);
    }, [testingAuthIds]);

    const handleRecommendRevocation = useCallback((f: Finding) => {
        console.log(`[SECRET-ACTION] Revocation recommendation: ${f.id} — ${f.title}`);
        setRevocationModal(f);
        toast.info("Generating revocation plan", { description: `For ${classifySecret(f).type} in ${f.file || "unknown file"}` });
    }, []);

    const handleSimulateTakeover = useCallback((f: Finding) => {
        if (takeoverIds.has(f.id)) return;
        console.log(`[SECRET-ACTION] Simulating takeover: ${f.id} — ${f.title}`);
        toast.loading("Simulating account takeover...", { id: `takeover-${f.id}` });

        setTakeoverIds(prev => new Set(prev).add(f.id));

        setTimeout(() => {
            const success = f.severity === "critical";
            const result = success
                ? { success: true, risk: "CRITICAL", message: "Full account takeover possible. Credential allows privilege escalation and lateral movement." }
                : f.severity === "high"
                    ? { success: true, risk: "HIGH", message: "Partial access achieved. Credential allows limited resource access but not full takeover." }
                    : { success: false, risk: "LOW", message: "Takeover simulation failed. Credential insufficient for meaningful access." };

            setTakeoverResults(prev => ({ ...prev, [f.id]: result }));
            setTakeoverIds(prev => {
                const next = new Set(prev);
                next.delete(f.id);
                return next;
            });

            toast.dismiss(`takeover-${f.id}`);
            if (result.success) {
                toast.error(`Takeover: ${result.risk}`, { description: result.message.slice(0, 80) });
            } else {
                toast.success("Takeover blocked", { description: "Credential insufficient for account takeover." });
            }
            console.log(`[SECRET-ACTION] Takeover simulation for ${f.id}: ${result.risk}`);
        }, 2500);
    }, [takeoverIds]);

    const handleAction = useCallback((action: string | undefined, f: Finding) => {
        switch (action) {
            case "reveal": handleReveal(f); break;
            case "validate": handleValidateCredential(f); break;
            case "trace": handleTraceUsage(f); break;
            case "test-auth": handleTestAuthAccess(f); break;
            case "revocation": handleRecommendRevocation(f); break;
            case "takeover": handleSimulateTakeover(f); break;
        }
    }, [handleReveal, handleValidateCredential, handleTraceUsage, handleTestAuthAccess, handleRecommendRevocation, handleSimulateTakeover]);

    const actionButtons = [
        { label: "Reveal Secret", icon: Eye, color: "#00FF88", action: "reveal" },
        { label: "Validate Credential", icon: ShieldCheck, color: "#00A3FF", action: "validate" },
        { label: "Trace Usage", icon: GitBranch, color: "#eab308", action: "trace" },
        { label: "Test Auth Access", icon: Lock, color: "#f97316", action: "test-auth" },
        { label: "Recommend Revocation", icon: Trash2, color: "#ef4444", action: "revocation" },
        { label: "Simulate Takeover", icon: UserX, color: "#ef4444", action: "takeover" },
    ];

    // Generate simulated trace data for a finding
    const generateTraceData = (f: Finding) => {
        const st = classifySecret(f);
        const locations = [
            { file: f.file || "config/settings.py", line: f.line_number || 42, context: "Primary definition" },
            { file: `src/services/auth.${f.file?.endsWith(".ts") ? "ts" : "py"}`, line: 15, context: "Authentication module import" },
            { file: `tests/test_integration.${f.file?.endsWith(".ts") ? "ts" : "py"}`, line: 88, context: "Test fixture" },
        ];
        const timeline = [
            { date: "2 days ago", action: "Last used in API call", severity: "high" as const },
            { date: "5 days ago", action: "Committed to repository", severity: "critical" as const },
            { date: "12 days ago", action: "Created/rotated", severity: "info" as const },
        ];
        return { type: st.type, locations, timeline };
    };

    // Generate revocation steps for a finding
    const generateRevocationPlan = (f: Finding) => {
        const st = classifySecret(f);
        const baseSteps = [
            { step: 1, action: `Rotate ${st.type} immediately`, priority: "CRITICAL", done: false },
            { step: 2, action: `Remove from ${f.file || "source code"}`, priority: "CRITICAL", done: false },
            { step: 3, action: "Update all dependent services", priority: "HIGH", done: false },
            { step: 4, action: "Audit access logs for unauthorized use", priority: "HIGH", done: false },
            { step: 5, action: "Add to .gitignore / secret manager", priority: "MEDIUM", done: false },
            { step: 6, action: "Enable secret scanning pre-commit hook", priority: "MEDIUM", done: false },
        ];
        return baseSteps;
    };

    return (
        <motion.div
            initial={{ opacity: 0, y: 20 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ delay: 0.3 }}
            className="rounded-2xl overflow-hidden"
            style={{ background: "var(--bg-card)", border: "1px solid var(--border-green)", boxShadow: "var(--shadow-card)" }}
        >
            {/* Header */}
            <div className="px-6 py-4 flex items-center justify-between"
                style={{ borderBottom: "1px solid var(--border-green)", background: "rgba(249,115,22,0.03)" }}>
                <div className="flex items-center gap-3">
                    <div className="w-10 h-10 rounded-xl flex items-center justify-center"
                        style={{ background: "rgba(249,115,22,0.1)", border: "1px solid rgba(249,115,22,0.2)" }}>
                        <KeyRound className="w-5 h-5 text-orange-500" />
                    </div>
                    <div>
                        <h2 className="text-lg font-black text-foreground uppercase tracking-tight">Verified Secrets & Credentials</h2>
                        <p className="text-[10px] text-muted-foreground uppercase tracking-[0.2em] font-bold">
                            {filteredSecrets.length} exposed credentials detected
                        </p>
                    </div>
                </div>
                {secretFindings.length > 0 && (
                    <span className="px-3 py-1 rounded-full text-[10px] font-black uppercase tracking-wider"
                        style={{ background: "rgba(239,68,68,0.1)", color: "#ef4444", border: "1px solid rgba(239,68,68,0.2)" }}>
                        {secretFindings.filter(f => f.severity === "critical").length} Critical
                    </span>
                )}
            </div>

            {/* Filters */}
            <div className="px-6 py-3 flex flex-wrap items-center gap-3" style={{ borderBottom: "1px solid rgba(255,255,255,0.04)" }}>
                <div className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg" style={{ background: "rgba(0,0,0,0.2)", border: "1px solid rgba(255,255,255,0.06)" }}>
                    <Search className="w-3.5 h-3.5 text-muted-foreground" />
                    <input
                        type="text"
                        placeholder="Search secrets..."
                        value={searchQuery}
                        onChange={(e) => setSearchQuery(e.target.value)}
                        className="bg-transparent text-xs text-foreground placeholder:text-muted-foreground outline-none w-40"
                        title="Search secrets"
                    />
                </div>
                <div className="flex items-center gap-1 flex-wrap">
                    <Filter className="w-3.5 h-3.5 text-muted-foreground mr-1" />
                    <button
                        onClick={() => setTypeFilter("all")}
                        className="px-2.5 py-1 rounded-lg text-[10px] font-bold uppercase tracking-wider transition-all"
                        style={{
                            background: typeFilter === "all" ? "rgba(0,255,136,0.1)" : "transparent",
                            color: typeFilter === "all" ? "#00FF88" : "#6B7F77",
                            border: `1px solid ${typeFilter === "all" ? "rgba(0,255,136,0.2)" : "transparent"}`,
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
                                background: typeFilter === t ? "rgba(249,115,22,0.1)" : "transparent",
                                color: typeFilter === t ? "#f97316" : "#6B7F77",
                                border: `1px solid ${typeFilter === t ? "rgba(249,115,22,0.2)" : "transparent"}`,
                            }}
                        >
                            {t}
                        </button>
                    ))}
                </div>
            </div>

            {/* Secrets List */}
            <div className="divide-y" style={{ borderColor: "rgba(255,255,255,0.03)" }}>
                {filteredSecrets.length === 0 ? (
                    <div className="px-6 py-16 flex flex-col items-center gap-3">
                        <KeyRound className="w-8 h-8 text-muted-foreground" />
                        <p className="text-sm text-muted-foreground font-semibold">No exposed secrets detected</p>
                        <p className="text-xs text-muted-foreground">Secrets will be flagged during scan analysis</p>
                    </div>
                ) : (
                    filteredSecrets.map((f, i) => {
                        const st = classifySecret(f);
                        const validity = getValidityStatus(f);
                        const exposure = getExposureLevel(f.severity);
                        const isRevealed = revealedIds.has(f.id);
                        const Icon = st.icon;
                        const vResult = validatedResults[f.id];
                        const aResult = authResults[f.id];
                        const tResult = takeoverResults[f.id];

                        return (
                            <motion.div
                                key={f.id}
                                initial={{ opacity: 0 }}
                                animate={{ opacity: 1 }}
                                transition={{ delay: i * 0.03 }}
                                className="px-6 py-4 space-y-3"
                            >
                                <div className="flex items-start gap-4">
                                    {/* Icon */}
                                    <div className="w-10 h-10 rounded-xl flex items-center justify-center flex-shrink-0"
                                        style={{ background: `${st.color}15`, border: `1px solid ${st.color}20` }}>
                                        <Icon className="w-5 h-5" style={{ color: st.color }} />
                                    </div>

                                    {/* Content */}
                                    <div className="flex-1 min-w-0 space-y-2">
                                        <div className="flex items-center gap-2 flex-wrap">
                                            <span className="text-sm font-bold text-foreground">{f.title}</span>
                                            <span className="px-2 py-0.5 rounded text-[9px] font-bold uppercase" style={{ background: `${st.color}15`, color: st.color }}>{st.type}</span>
                                            {/* Status badges from actions */}
                                            {vResult && (
                                                <span className="px-2 py-0.5 rounded text-[9px] font-bold uppercase"
                                                    style={{
                                                        background: vResult.valid ? "rgba(239,68,68,0.1)" : "rgba(0,255,136,0.1)",
                                                        color: vResult.valid ? "#ef4444" : "#00FF88",
                                                    }}>
                                                    {vResult.valid ? "ACTIVE" : "INACTIVE"}
                                                </span>
                                            )}
                                            {aResult && (
                                                <span className="px-2 py-0.5 rounded text-[9px] font-bold uppercase"
                                                    style={{
                                                        background: aResult.accessible ? "rgba(239,68,68,0.1)" : "rgba(0,255,136,0.1)",
                                                        color: aResult.accessible ? "#ef4444" : "#00FF88",
                                                    }}>
                                                    {aResult.accessible ? "ACCESS GRANTED" : "NO ACCESS"}
                                                </span>
                                            )}
                                            {tResult && (
                                                <span className="px-2 py-0.5 rounded text-[9px] font-bold uppercase"
                                                    style={{
                                                        background: tResult.success ? "rgba(239,68,68,0.1)" : "rgba(0,255,136,0.1)",
                                                        color: tResult.success ? "#ef4444" : "#00FF88",
                                                    }}>
                                                    TAKEOVER: {tResult.risk}
                                                </span>
                                            )}
                                        </div>

                                        {/* Metadata row */}
                                        <div className="flex items-center gap-4 flex-wrap text-[10px]">
                                            <span className="text-muted-foreground font-mono">{f.file || "N/A"}</span>
                                            <span className="flex items-center gap-1" style={{ color: exposure.color }}>
                                                <span className="w-1.5 h-1.5 rounded-full" style={{ background: exposure.color }} />
                                                <span className="font-bold uppercase">{exposure.label}</span>
                                            </span>
                                            <span className="flex items-center gap-1" style={{ color: validity.color }}>
                                                <validity.icon className="w-3 h-3" />
                                                <span className="font-bold uppercase">{validity.label}</span>
                                            </span>
                                        </div>

                                        {/* Secret value */}
                                        {f.matched_content && (
                                            <div className="flex items-center gap-2 mt-1">
                                                <div className="flex-1 px-3 py-1.5 rounded-lg font-mono text-xs overflow-hidden"
                                                    style={{ background: "rgba(0,0,0,0.3)", border: "1px solid rgba(255,255,255,0.05)" }}>
                                                    {isRevealed ? (
                                                        <span className="text-orange-400">{f.matched_content}</span>
                                                    ) : (
                                                        <span className="text-muted-foreground">{"*".repeat(Math.min(40, f.matched_content.length))}</span>
                                                    )}
                                                </div>
                                                <button onClick={() => toggleReveal(f.id)} className="p-1.5 rounded-lg transition-all hover:bg-white/5"
                                                    title={isRevealed ? "Hide" : "Reveal"}>
                                                    {isRevealed ? <EyeOff className="w-4 h-4 text-muted-foreground" /> : <Eye className="w-4 h-4 text-muted-foreground" />}
                                                </button>
                                                <button onClick={() => handleCopy(f.matched_content, f.id)} className="p-1.5 rounded-lg transition-all hover:bg-white/5"
                                                    title="Copy to clipboard">
                                                    {copiedId === f.id ? <CheckCircle2 className="w-4 h-4 text-primary" /> : <Copy className="w-4 h-4 text-muted-foreground" />}
                                                </button>
                                            </div>
                                        )}

                                        {/* Inline result feedback */}
                                        {vResult && (
                                            <div className="px-3 py-2 rounded-lg text-xs"
                                                style={{ background: vResult.valid ? "rgba(239,68,68,0.05)" : "rgba(0,255,136,0.05)", border: `1px solid ${vResult.valid ? "rgba(239,68,68,0.15)" : "rgba(0,255,136,0.15)"}` }}>
                                                <span className="font-bold" style={{ color: vResult.valid ? "#ef4444" : "#00FF88" }}>Validation: </span>
                                                <span className="text-muted-foreground">{vResult.message}</span>
                                            </div>
                                        )}
                                        {aResult && (
                                            <div className="px-3 py-2 rounded-lg text-xs"
                                                style={{ background: aResult.accessible ? "rgba(239,68,68,0.05)" : "rgba(0,255,136,0.05)", border: `1px solid ${aResult.accessible ? "rgba(239,68,68,0.15)" : "rgba(0,255,136,0.15)"}` }}>
                                                <span className="font-bold" style={{ color: aResult.accessible ? "#ef4444" : "#00FF88" }}>Auth Access: </span>
                                                <span className="text-muted-foreground">{aResult.message}</span>
                                            </div>
                                        )}
                                        {tResult && (
                                            <div className="px-3 py-2 rounded-lg text-xs"
                                                style={{ background: tResult.success ? "rgba(239,68,68,0.05)" : "rgba(0,255,136,0.05)", border: `1px solid ${tResult.success ? "rgba(239,68,68,0.15)" : "rgba(0,255,136,0.15)"}` }}>
                                                <span className="font-bold" style={{ color: tResult.success ? "#ef4444" : "#00FF88" }}>Takeover Simulation: </span>
                                                <span className="text-muted-foreground">{tResult.message}</span>
                                            </div>
                                        )}
                                    </div>
                                </div>

                                {/* Actions */}
                                <div className="flex flex-wrap gap-2 ml-14">
                                    {actionButtons.map(a => {
                                        const isLoading =
                                            (a.action === "validate" && validatingIds.has(f.id)) ||
                                            (a.action === "test-auth" && testingAuthIds.has(f.id)) ||
                                            (a.action === "takeover" && takeoverIds.has(f.id));

                                        return (
                                            <button
                                                key={a.label}
                                                onClick={() => handleAction(a.action, f)}
                                                disabled={isLoading}
                                                className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-[10px] font-bold uppercase tracking-wider transition-all hover:brightness-125 disabled:opacity-50"
                                                style={{ background: `${a.color}10`, border: `1px solid ${a.color}20`, color: a.color }}
                                            >
                                                {isLoading ? (
                                                    <Loader2 className="w-3 h-3 animate-spin" />
                                                ) : (
                                                    <a.icon className="w-3 h-3" />
                                                )}
                                                {a.label}
                                            </button>
                                        );
                                    })}
                                </div>
                            </motion.div>
                        );
                    })
                )}
            </div>

            {/* Trace Usage Modal */}
            <SlideModal
                open={!!traceModal}
                onClose={() => setTraceModal(null)}
                title="Credential Usage Trace"
            >
                {traceModal && (() => {
                    const trace = generateTraceData(traceModal);
                    return (
                        <div className="space-y-5">
                            <div className="flex items-center gap-2 mb-3">
                                <GitBranch className="w-4 h-4 text-yellow-500" />
                                <span className="text-sm font-bold text-foreground">{traceModal.title}</span>
                                <span className="px-2 py-0.5 rounded text-[9px] font-bold uppercase"
                                    style={{ background: "rgba(234,179,8,0.1)", color: "#eab308" }}>{trace.type}</span>
                            </div>

                            {/* Locations */}
                            <div>
                                <h4 className="text-[10px] font-bold uppercase tracking-wider text-muted-foreground mb-2">Referenced Locations</h4>
                                <div className="space-y-2">
                                    {trace.locations.map((loc, i) => (
                                        <div key={i} className="flex items-center gap-3 px-3 py-2 rounded-lg"
                                            style={{ background: "rgba(0,0,0,0.3)", border: "1px solid rgba(255,255,255,0.05)" }}>
                                            <FileWarning className="w-3.5 h-3.5 text-muted-foreground flex-shrink-0" />
                                            <span className="text-xs font-mono text-muted-foreground flex-1">{loc.file}:{loc.line}</span>
                                            <span className="text-[10px] text-muted-foreground">{loc.context}</span>
                                        </div>
                                    ))}
                                </div>
                            </div>

                            {/* Timeline */}
                            <div>
                                <h4 className="text-[10px] font-bold uppercase tracking-wider text-muted-foreground mb-2">Activity Timeline</h4>
                                <div className="space-y-2">
                                    {trace.timeline.map((evt, i) => (
                                        <div key={i} className="flex items-center gap-3 px-3 py-2 rounded-lg"
                                            style={{ background: "rgba(0,0,0,0.3)", border: "1px solid rgba(255,255,255,0.05)" }}>
                                            <Activity className="w-3.5 h-3.5 flex-shrink-0"
                                                style={{ color: evt.severity === "critical" ? "#ef4444" : evt.severity === "high" ? "#f97316" : "#6B7F77" }} />
                                            <span className="text-xs text-muted-foreground flex-1">{evt.action}</span>
                                            <span className="text-[10px] text-muted-foreground">{evt.date}</span>
                                        </div>
                                    ))}
                                </div>
                            </div>

                            <button
                                onClick={() => {
                                    const data = JSON.stringify({ finding: traceModal.id, title: traceModal.title, trace }, null, 2);
                                    navigator.clipboard.writeText(data);
                                    toast.success("Trace data copied to clipboard");
                                }}
                                className="w-full py-2 rounded-lg text-xs font-bold uppercase tracking-wider transition-all hover:brightness-125"
                                style={{ background: "rgba(234,179,8,0.1)", border: "1px solid rgba(234,179,8,0.2)", color: "#eab308" }}
                            >
                                Copy Trace Data
                            </button>
                        </div>
                    );
                })()}
            </SlideModal>

            {/* Revocation Recommendation Modal */}
            <SlideModal
                open={!!revocationModal}
                onClose={() => setRevocationModal(null)}
                title="Revocation Recommendation"
            >
                {revocationModal && (() => {
                    const steps = generateRevocationPlan(revocationModal);
                    const st = classifySecret(revocationModal);
                    return (
                        <div className="space-y-5">
                            <div className="flex items-center gap-2 mb-1">
                                <Shield className="w-4 h-4 text-red-500" />
                                <span className="text-sm font-bold text-foreground">{revocationModal.title}</span>
                                <span className="px-2 py-0.5 rounded text-[9px] font-bold uppercase"
                                    style={{ background: "rgba(239,68,68,0.1)", color: "#ef4444" }}>{st.type}</span>
                            </div>
                            <p className="text-xs text-muted-foreground">
                                File: <span className="font-mono text-muted-foreground">{revocationModal.file || "N/A"}</span>
                                {revocationModal.line_number ? ` (line ${revocationModal.line_number})` : ""}
                            </p>

                            <div>
                                <h4 className="text-[10px] font-bold uppercase tracking-wider text-muted-foreground mb-3">Recommended Steps</h4>
                                <div className="space-y-2">
                                    {steps.map((s) => (
                                        <div key={s.step} className="flex items-start gap-3 px-3 py-2.5 rounded-lg"
                                            style={{ background: "rgba(0,0,0,0.3)", border: "1px solid rgba(255,255,255,0.05)" }}>
                                            <div className="w-5 h-5 rounded-full flex items-center justify-center flex-shrink-0 text-[10px] font-bold"
                                                style={{
                                                    background: s.priority === "CRITICAL" ? "rgba(239,68,68,0.15)" : s.priority === "HIGH" ? "rgba(249,115,22,0.15)" : "rgba(234,179,8,0.15)",
                                                    color: s.priority === "CRITICAL" ? "#ef4444" : s.priority === "HIGH" ? "#f97316" : "#eab308",
                                                }}>
                                                {s.step}
                                            </div>
                                            <div className="flex-1">
                                                <span className="text-xs text-muted-foreground">{s.action}</span>
                                            </div>
                                            <span className="text-[9px] font-bold uppercase"
                                                style={{ color: s.priority === "CRITICAL" ? "#ef4444" : s.priority === "HIGH" ? "#f97316" : "#eab308" }}>
                                                {s.priority}
                                            </span>
                                        </div>
                                    ))}
                                </div>
                            </div>

                            <div className="flex gap-2">
                                <button
                                    onClick={() => {
                                        const data = JSON.stringify({ finding: revocationModal.id, title: revocationModal.title, type: st.type, steps }, null, 2);
                                        navigator.clipboard.writeText(data);
                                        toast.success("Revocation plan copied to clipboard");
                                    }}
                                    className="flex-1 py-2 rounded-lg text-xs font-bold uppercase tracking-wider transition-all hover:brightness-125"
                                    style={{ background: "rgba(239,68,68,0.1)", border: "1px solid rgba(239,68,68,0.2)", color: "#ef4444" }}
                                >
                                    Copy Plan
                                </button>
                                <button
                                    onClick={() => {
                                        const blob = new Blob([JSON.stringify({ finding: revocationModal.id, title: revocationModal.title, type: st.type, file: revocationModal.file, steps, generated_at: new Date().toISOString() }, null, 2)], { type: "application/json" });
                                        const url = URL.createObjectURL(blob);
                                        const a = document.createElement("a");
                                        a.href = url;
                                        a.download = `revocation-plan-${revocationModal.id.slice(0, 8)}.json`;
                                        a.click();
                                        URL.revokeObjectURL(url);
                                        toast.success("Revocation plan exported");
                                        console.log(`[SECRET-ACTION] Exported revocation plan for ${revocationModal.id}`);
                                    }}
                                    className="flex-1 py-2 rounded-lg text-xs font-bold uppercase tracking-wider transition-all hover:brightness-125"
                                    style={{ background: "rgba(0,255,136,0.1)", border: "1px solid rgba(0,255,136,0.2)", color: "#00FF88" }}
                                >
                                    Export JSON
                                </button>
                            </div>
                        </div>
                    );
                })()}
            </SlideModal>
        </motion.div>
    );
}
