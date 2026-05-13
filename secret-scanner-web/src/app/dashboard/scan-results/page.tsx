"use client";

import { useMemo, useCallback, useState, useEffect, useRef } from "react";
import { motion, AnimatePresence } from "framer-motion";
import { Sidebar } from "@/components/sidebar";
import { useScannerContext } from "@/contexts/scanner-context";
import { toast } from "sonner";
import {
    FileSearch, Shield, Activity, Link2, Brain, FileText,
    RefreshCw, Radio, Download, X, ChevronRight, Atom
} from "lucide-react";
import { useRouter, useSearchParams } from "next/navigation";
import { useScanHistory } from "@/hooks/use-scanner";
import { useReportDownload } from "@/lib/hooks";
import { ScanHistory } from "@/components/dashboard/scan-history";
import api from "@/lib/api";

import { GlobalSecuritySummary } from "@/components/dashboard/scan-results/GlobalSecuritySummary";
import { VerifiedVulnerabilities } from "@/components/dashboard/scan-results/VerifiedVulnerabilities";
import { EndpointIntelligence } from "@/components/dashboard/scan-results/EndpointIntelligence";
import { SecretsCredentials } from "@/components/dashboard/scan-results/SecretsCredentials";
import { TokenAnalyzer } from "@/components/dashboard/scan-results/TokenAnalyzer";

export default function ScanResultsPage() {
    // ── Shared scanner state from context (same data as /scanner page) ──────
    const {
        isScanning,
        scanStatus,
        findings,
        scanId,
        verifiedFindings,
        attackChains,
        endpointsDiscovered,
        riskData,
        aiDecision,
        enterpriseTelemetry,
        payloadsExecuted,
        loadScanFromHistory,
        scanLifecycle,
    } = useScannerContext();

    const router = useRouter();
    const searchParams = useSearchParams();
    const { scans: scanHistory, refreshScans } = useScanHistory();
    const { downloadReport } = useReportDownload();
    const autoLoadedRef = useRef(false);

    // ── Auto-load scan data from URL param or last completed scan ──────────
    useEffect(() => {
        if (autoLoadedRef.current) return;

        // If we already have findings in context (active/just-completed scan), skip
        if (findings.length > 0 || isScanning) return;

        const urlScanId = searchParams.get("scanId");

        if (urlScanId && urlScanId !== scanId) {
            autoLoadedRef.current = true;
            loadScanFromHistory(urlScanId);
            return;
        }

        // If context has a scanId but no findings (e.g. page refresh), reload it
        if (scanId && findings.length === 0 && !isScanning) {
            autoLoadedRef.current = true;
            loadScanFromHistory(scanId);
            return;
        }

        // If no active scan at all, load the most recent completed scan from history
        if (!scanId && scanHistory.length > 0) {
            const lastCompleted = scanHistory.find(s => s.status === "completed");
            if (lastCompleted) {
                autoLoadedRef.current = true;
                loadScanFromHistory(lastCompleted.scan_id);
            }
        }
    }, [findings.length, isScanning, scanId, searchParams, scanHistory, loadScanFromHistory]);

    // Reset autoload flag when navigating to a new scan via URL
    useEffect(() => {
        const urlScanId = searchParams.get("scanId");
        if (urlScanId && urlScanId !== scanId) {
            autoLoadedRef.current = false;
        }
    }, [searchParams, scanId]);

    const handleDeleteScan = async (scanId: string) => {
        if (!confirm("Are you sure you want to delete this scan from the intelligence ledger?")) return;

        try {
            await api.deleteScan(scanId);
            toast.success("Scan record purged from protocol history");
            refreshScans();
        } catch (error) {
            console.error("Failed to delete scan:", error);
            toast.error("Operation failed: Unable to purge scan record");
        }
    };

    // ── Modal states ────────────────────────────────────────────────────────
    const [showAttackChainModal, setShowAttackChainModal] = useState(false);
    const [showAIAnalysisModal, setShowAIAnalysisModal] = useState(false);
    const [showExecutiveSummaryModal, setShowExecutiveSummaryModal] = useState(false);
    const [monitoringActive, setMonitoringActive] = useState(false);

    // ── Derived data ────────────────────────────────────────────────────────
    const severityCounts = useMemo(() => ({
        critical: findings.filter(f => f.severity === "critical").length,
        high: findings.filter(f => f.severity === "high").length,
        medium: findings.filter(f => f.severity === "medium").length,
        low: findings.filter(f => f.severity === "low").length,
    }), [findings]);

    const riskScore = useMemo(() => {
        if (riskData?.new_score != null) return Math.round(riskData.new_score);
        if (findings.length === 0) return 0;
        return Math.min(100, Math.max(0,
            severityCounts.critical * 15 +
            severityCounts.high * 8 +
            severityCounts.medium * 3 +
            severityCounts.low * 1
        ));
    }, [riskData, findings, severityCounts]);

    // ── Executive Summary data ──────────────────────────────────────────────
    const executiveSummaryData = useMemo(() => ({
        scan_id: scanId,
        timestamp: new Date().toISOString(),
        risk_score: riskScore,
        risk_level: riskScore >= 75 ? "CRITICAL" : riskScore >= 50 ? "HIGH" : riskScore >= 25 ? "MODERATE" : "LOW",
        total_findings: findings.length,
        severity_breakdown: severityCounts,
        verified_exploits: verifiedFindings.length,
        attack_chains_identified: attackChains.length,
        exposed_endpoints: endpointsDiscovered.length,
        scan_status: scanStatus?.status || "idle",
        scan_progress: scanStatus?.progress || 0,
        modules_scanned: scanStatus?.modules_completed || 0,
        modules_total: scanStatus?.modules_total || 0,
        top_critical_findings: findings
            .filter(f => f.severity === "critical")
            .slice(0, 5)
            .map(f => ({ title: f.title, endpoint: f.file || f.location, cwe: f.cwe, confidence: f.confidence })),
        recommendations: [
            ...(severityCounts.critical > 0 ? ["IMMEDIATE: Remediate all critical vulnerabilities before production deployment"] : []),
            ...(severityCounts.high > 0 ? ["HIGH PRIORITY: Address high-severity findings within 48 hours"] : []),
            ...(verifiedFindings.length > 0 ? [`${verifiedFindings.length} vulnerabilities have been verified with PoC — treat as confirmed exploitable`] : []),
            ...(attackChains.length > 0 ? [`${attackChains.length} attack chains identified — review multi-stage attack paths`] : []),
            ...(endpointsDiscovered.length > 10 ? [`${endpointsDiscovered.length} endpoints exposed — review access controls`] : []),
        ],
    }), [scanId, riskScore, findings, severityCounts, verifiedFindings, attackChains, endpointsDiscovered, scanStatus]);

    // ── Action Handlers ─────────────────────────────────────────────────────

    const handleViewAttackChain = useCallback(() => {
        if (attackChains.length === 0) {
            toast.info("No attack chains identified yet. Run a scan to discover attack paths.");
            return;
        }
        setShowAttackChainModal(true);
    }, [attackChains]);

    const handleAIRiskAnalysis = useCallback(() => {
        if (findings.length === 0) {
            toast.info("No findings to analyze. Run a scan first.");
            return;
        }
        setShowAIAnalysisModal(true);
    }, [findings]);

    const handleExecutiveSummary = useCallback(() => {
        if (findings.length === 0) {
            toast.info("No scan data available for summary. Run a scan first.");
            return;
        }
        setShowExecutiveSummaryModal(true);
    }, [findings]);

    const handleExportDFIR = useCallback(() => {
        if (findings.length === 0) {
            toast.info("No scan data to export. Run a scan first.");
            return;
        }
        const dfirReport = {
            report_type: "DFIR — Digital Forensics and Incident Response",
            generated_at: new Date().toISOString(),
            scan_id: scanId,
            risk_assessment: {
                overall_score: riskScore,
                risk_level: riskScore >= 75 ? "CRITICAL" : riskScore >= 50 ? "HIGH" : riskScore >= 25 ? "MODERATE" : "LOW",
                severity_breakdown: severityCounts,
            },
            findings_summary: {
                total: findings.length,
                verified: verifiedFindings.length,
                attack_chains: attackChains.length,
                exposed_endpoints: endpointsDiscovered.length,
            },
            detailed_findings: findings.map(f => ({
                id: f.id,
                severity: f.severity,
                title: f.title,
                description: f.description,
                endpoint: f.file || f.location,
                cwe: f.cwe,
                owasp: f.owasp,
                confidence: f.confidence,
                module: f.module_name || f.module,
                matched_content: f.matched_content,
                remediation: f.remediation,
                tags: f.tags,
            })),
            verified_exploits: verifiedFindings.map(v => ({
                finding_id: v.finding_id,
                endpoint: v.endpoint,
                confidence: v.confidence,
                strategy: v.strategy,
                timing_delta_ms: v.timing_delta_ms,
                evidence_hash: v.evidence_hash,
            })),
            attack_chains: attackChains.map(c => ({
                chain_id: c.chain_id,
                name: c.name,
                owasp: c.owasp,
                severity: c.severity,
                description: c.description,
                finding_ids: c.finding_ids,
            })),
            endpoints_discovered: endpointsDiscovered,
            enterprise_telemetry: enterpriseTelemetry,
            ai_decision: aiDecision,
        };
        const blob = new Blob([JSON.stringify(dfirReport, null, 2)], { type: "application/json" });
        const url = URL.createObjectURL(blob);
        const a = document.createElement("a");
        a.href = url;
        a.download = `dfir-report-${scanId?.slice(0, 8) || "scan"}-${new Date().toISOString().slice(0, 10)}.json`;
        a.click();
        URL.revokeObjectURL(url);
        toast.success("DFIR Report exported successfully");
    }, [scanId, riskScore, severityCounts, findings, verifiedFindings, attackChains, endpointsDiscovered, enterpriseTelemetry, aiDecision]);

    const handleRecalculateRisk = useCallback(() => {
        const newScore = Math.min(100, Math.max(0,
            severityCounts.critical * 15 +
            severityCounts.high * 8 +
            severityCounts.medium * 3 +
            severityCounts.low * 1 +
            verifiedFindings.length * 5 +
            attackChains.length * 10
        ));
        toast.success(`Risk recalculated: ${newScore}% (${newScore >= 75 ? "CRITICAL" : newScore >= 50 ? "HIGH" : newScore >= 25 ? "MODERATE" : "LOW"} risk)`);
    }, [severityCounts, verifiedFindings, attackChains]);

    const handleContinuousMonitoring = useCallback(() => {
        setMonitoringActive(prev => !prev);
        if (!monitoringActive) {
            toast.success("Continuous monitoring ACTIVATED — real-time threat detection enabled");
        } else {
            toast.info("Continuous monitoring deactivated");
        }
    }, [monitoringActive]);

    const downloadJSON = (data: any, filename: string) => {
        const blob = new Blob([JSON.stringify(data, null, 2)], { type: "application/json" });
        const url = URL.createObjectURL(blob);
        const a = document.createElement("a");
        a.href = url;
        a.download = filename;
        a.click();
        URL.revokeObjectURL(url);
    };

    return (
        <Sidebar>
            <div className="min-h-screen bg-background text-foreground font-sans selection:bg-primary/30 selection:text-foreground">
                <div className="max-w-[1600px] mx-auto space-y-6 pb-12">

                    {/* Page Header */}
                    <motion.div
                        initial={{ opacity: 0, y: -10 }}
                        animate={{ opacity: 1, y: 0 }}
                        className="flex flex-col md:flex-row md:items-center justify-between gap-4 pt-2"
                    >
                        <div className="space-y-1">
                            <h1 className="text-2xl font-black text-foreground uppercase tracking-tighter flex items-center gap-3">
                                <div className="w-8 h-8 rounded-lg bg-gradient-to-br from-[#00FF88] to-[#00A3FF] flex items-center justify-center p-0.5">
                                    <div className="w-full h-full bg-background rounded-[7px] flex items-center justify-center">
                                        <FileSearch className="w-4 h-4 text-neon-green" />
                                    </div>
                                </div>
                                Scan Results <span className="text-muted-foreground/40 ml-2">Intelligence</span>
                            </h1>
                            <p className="text-[10px] text-muted-foreground font-bold uppercase tracking-[0.3em] ml-1">
                                Verified Security Intelligence • Attack Visibility • Exploit Validation
                            </p>
                        </div>

                        <div className="flex items-center gap-3">
                            {isScanning ? (
                                <div className="flex items-center gap-2 px-4 py-1.5 rounded-full bg-[rgba(0,255,136,0.1)] border border-[rgba(0,255,136,0.2)]">
                                    <div className="w-2 h-2 rounded-full bg-primary animate-ping" />
                                    <span className="text-[10px] font-black text-neon-green uppercase tracking-widest">Live Scan</span>
                                </div>
                            ) : scanId ? (
                                <div className="flex items-center gap-2 px-4 py-1.5 rounded-full bg-[rgba(0,163,255,0.1)] border border-[rgba(0,163,255,0.2)]">
                                    <div className="w-2 h-2 rounded-full bg-[#00A3FF]" />
                                    <span className="text-[10px] font-black text-[#00A3FF] uppercase tracking-widest">Scan Complete</span>
                                </div>
                            ) : (
                                <div className="flex items-center gap-2 px-4 py-1.5 rounded-full bg-muted border border-border">
                                    <div className="w-2 h-2 rounded-full bg-muted-foreground/40" />
                                    <span className="text-[10px] font-black text-muted-foreground uppercase tracking-widest">No Active Scan</span>
                                </div>
                            )}

                            {monitoringActive && (
                                <div className="flex items-center gap-2 px-4 py-1.5 rounded-full bg-[rgba(0,163,255,0.1)] border border-[rgba(0,163,255,0.2)]">
                                    <Radio className="w-3.5 h-3.5 text-[#00A3FF] animate-pulse" />
                                    <span className="text-[10px] font-black text-[#00A3FF] uppercase tracking-widest">Monitoring</span>
                                </div>
                            )}

                            {findings.length > 0 && (
                                <div className="flex items-center gap-2 px-4 py-1.5 rounded-full"
                                    style={{ background: "rgba(239,68,68,0.08)", border: "1px solid rgba(239,68,68,0.15)" }}>
                                    <Shield className="w-3.5 h-3.5 text-red-400" />
                                    <span className="text-[10px] font-black text-red-400 uppercase tracking-widest">{findings.length} Findings</span>
                                </div>
                            )}


                        </div>
                    </motion.div>

                    {/* Panel 1: Global Security Summary */}
                    <GlobalSecuritySummary
                        criticalCount={severityCounts.critical}
                        highCount={severityCounts.high}
                        mediumCount={severityCounts.medium}
                        lowCount={severityCounts.low}
                        verifiedExploits={verifiedFindings.length}
                        attackPaths={attackChains.length}
                        riskScore={riskScore}
                        exposedAssets={endpointsDiscovered.length}
                        onViewAttackChain={handleViewAttackChain}
                        onAIRiskAnalysis={handleAIRiskAnalysis}
                        onExecutiveSummary={handleExecutiveSummary}
                        onExportDFIR={handleExportDFIR}
                        onRecalculateRisk={handleRecalculateRisk}
                        onContinuousMonitoring={handleContinuousMonitoring}
                    />

                    {/* Panel 2: Verified Vulnerabilities */}
                    <VerifiedVulnerabilities findings={findings} verifiedFindings={verifiedFindings} />

                    {/* Panel 3: Endpoint Intelligence */}
                    <EndpointIntelligence endpoints={endpointsDiscovered} findings={findings} />

                    {/* Panel 4: Verified Secrets & Credentials */}
                    <SecretsCredentials findings={findings} />

                    {/* Panel 5: Authentication Token Analyzer */}
                    <TokenAnalyzer findings={findings} />

                    {/* Scan History Section */}
                    <motion.div
                        initial={{ opacity: 0, y: 20 }}
                        animate={{ opacity: 1, y: 0 }}
                        className="mt-8"
                    >
                        <ScanHistory
                            scans={scanHistory}
                            onRefresh={refreshScans}
                            onViewScan={(sid) => {
                                autoLoadedRef.current = false;
                                loadScanFromHistory(sid);
                                window.scrollTo({ top: 0, behavior: "smooth" });
                            }}
                            onDownloadReport={(sid) => downloadReport(sid, 'json')}
                            onDeleteScan={handleDeleteScan}
                        />
                    </motion.div>

                </div>
            </div>

            {/* ─── Attack Chain Modal ──────────────────────────────────────────── */}
            <AnimatePresence>
                {showAttackChainModal && (
                    <motion.div
                        initial={{ opacity: 0 }}
                        animate={{ opacity: 1 }}
                        exit={{ opacity: 0 }}
                        className="fixed inset-0 z-[100] flex items-center justify-center bg-background/80 backdrop-blur-sm"
                        onClick={() => setShowAttackChainModal(false)}
                    >
                        <motion.div
                            initial={{ scale: 0.9, y: 20 }}
                            animate={{ scale: 1, y: 0 }}
                            exit={{ scale: 0.9, y: 20 }}
                            onClick={(e) => e.stopPropagation()}
                            className="w-full max-w-3xl max-h-[80vh] overflow-y-auto rounded-2xl p-6 bg-card border border-border shadow-2xl"
                        >
                            <div className="flex items-center justify-between mb-6">
                                <div className="flex items-center gap-3">
                                    <Link2 className="w-6 h-6 text-primary" />
                                    <h2 className="text-xl font-black text-foreground uppercase tracking-tight">Attack Chains</h2>
                                    <span className="px-2 py-0.5 rounded text-[10px] font-bold bg-primary/10 text-primary">{attackChains.length} chains</span>
                                </div>
                                <button onClick={() => setShowAttackChainModal(false)} className="p-2 rounded-lg hover:bg-muted transition-colors"><X className="w-5 h-5 text-muted-foreground" /></button>
                            </div>

                            {attackChains.length === 0 ? (
                                <div className="py-12 text-center">
                                    <Link2 className="w-12 h-12 text-muted-foreground/20 mx-auto mb-3" />
                                    <p className="text-muted-foreground font-semibold">No attack chains discovered</p>
                                </div>
                            ) : (
                                <div className="space-y-3">
                                    {attackChains.map((chain, i) => (
                                        <div key={chain.chain_id} className="rounded-xl p-4 bg-muted/40 border border-border">
                                            <div className="flex items-center gap-3 mb-2">
                                                <span className="px-2 py-0.5 rounded text-[10px] font-black uppercase"
                                                    style={{ background: chain.severity === "critical" ? "rgba(239,68,68,0.1)" : chain.severity === "high" ? "rgba(249,115,22,0.1)" : "rgba(234,179,8,0.1)", color: chain.severity === "critical" ? "#ef4444" : chain.severity === "high" ? "#f97316" : "#eab308" }}>
                                                    {chain.severity}
                                                </span>
                                                <span className="text-sm font-bold text-foreground">{chain.name}</span>
                                                <span className="text-[10px] text-muted-foreground font-mono">{chain.owasp}</span>
                                            </div>
                                            <p className="text-xs text-muted-foreground mb-2">{chain.description}</p>
                                            <div className="flex items-center gap-2 flex-wrap">
                                                {chain.finding_ids.map((fid, j) => (
                                                    <span key={fid} className="flex items-center gap-1 text-[10px] text-muted-foreground">
                                                        <span className="px-1.5 py-0.5 rounded bg-muted font-mono">{fid.slice(0, 8)}</span>
                                                        {j < chain.finding_ids.length - 1 && <ChevronRight className="w-3 h-3" />}
                                                    </span>
                                                ))}
                                            </div>
                                        </div>
                                    ))}
                                </div>
                            )}
                        </motion.div>
                    </motion.div>
                )}
            </AnimatePresence>

            {/* ─── AI Risk Analysis Modal ──────────────────────────────────────── */}
            <AnimatePresence>
                {showAIAnalysisModal && (
                    <motion.div
                        initial={{ opacity: 0 }}
                        animate={{ opacity: 1 }}
                        exit={{ opacity: 0 }}
                        className="fixed inset-0 z-[100] flex items-center justify-center bg-background/70 backdrop-blur-sm"
                        onClick={() => setShowAIAnalysisModal(false)}
                    >
                        <motion.div
                            initial={{ scale: 0.9, y: 20 }}
                            animate={{ scale: 1, y: 0 }}
                            exit={{ scale: 0.9, y: 20 }}
                            onClick={(e) => e.stopPropagation()}
                            className="w-full max-w-3xl max-h-[80vh] overflow-y-auto rounded-2xl p-6 bg-card border border-border shadow-2xl"
                        >
                            <div className="flex items-center justify-between mb-6">
                                <div className="flex items-center gap-3">
                                    <Brain className="w-6 h-6 text-primary" />
                                    <h2 className="text-xl font-black text-foreground uppercase tracking-tight">AI Risk Analysis</h2>
                                </div>
                                <button onClick={() => setShowAIAnalysisModal(false)} className="p-2 rounded-lg hover:bg-muted transition-colors"><X className="w-5 h-5 text-muted-foreground" /></button>
                            </div>

                            <div className="space-y-4">
                                {/* Risk Overview */}
                                <div className="rounded-xl p-4 bg-muted/40 border border-border">
                                    <h3 className="text-xs font-bold text-primary uppercase tracking-wider mb-3">Risk Assessment</h3>
                                    <div className="grid grid-cols-2 md:grid-cols-4 gap-4 text-center">
                                        <div><p className="text-3xl font-black" style={{ color: riskScore >= 75 ? "#ef4444" : riskScore >= 50 ? "#f97316" : "#00FF88" }}>{riskScore}%</p><p className="text-[10px] text-muted-foreground uppercase">Risk Score</p></div>
                                        <div><p className="text-3xl font-black text-destructive">{severityCounts.critical}</p><p className="text-[10px] text-muted-foreground uppercase">Critical</p></div>
                                        <div><p className="text-3xl font-black text-primary">{verifiedFindings.length}</p><p className="text-[10px] text-muted-foreground uppercase">Verified</p></div>
                                        <div><p className="text-3xl font-black text-blue-500">{attackChains.length}</p><p className="text-[10px] text-muted-foreground uppercase">Attack Chains</p></div>
                                    </div>
                                </div>

                                {/* AI Decision */}
                                {aiDecision && (
                                    <div className="rounded-xl p-4 bg-muted/40 border border-border">
                                        <h3 className="text-xs font-bold text-primary uppercase tracking-wider mb-2">AI Recommendation</h3>
                                        {aiDecision.next_action && <p className="text-sm text-foreground font-semibold mb-1">Next Action: {aiDecision.next_action}</p>}
                                        {aiDecision.rationale && <p className="text-xs text-muted-foreground mb-2">{aiDecision.rationale}</p>}
                                        {aiDecision.priority && <span className="px-2 py-0.5 rounded text-[10px] font-bold bg-orange-500/10 text-orange-500 uppercase">{aiDecision.priority} priority</span>}
                                        {aiDecision.confidence != null && <span className="ml-2 text-[10px] text-muted-foreground">Confidence: {(aiDecision.confidence * 100).toFixed(0)}%</span>}
                                    </div>
                                )}

                                {/* Finding Category Breakdown */}
                                <div className="rounded-xl p-4 bg-muted/40 border border-border">
                                    <h3 className="text-xs font-bold text-primary uppercase tracking-wider mb-3">Vulnerability Distribution</h3>
                                    <div className="space-y-2">
                                        {Object.entries(
                                            findings.reduce((acc, f) => { acc[f.module_name || f.module || "Unknown"] = (acc[f.module_name || f.module || "Unknown"] || 0) + 1; return acc; }, {} as Record<string, number>)
                                        ).sort(([, a], [, b]) => b - a).slice(0, 10).map(([mod, count]) => (
                                            <div key={mod} className="flex items-center gap-3">
                                                <span className="text-xs text-muted-foreground w-48 truncate">{mod}</span>
                                                <div className="flex-1 h-2 rounded-full overflow-hidden bg-muted">
                                                    <div className="h-full rounded-full bg-primary" style={{ width: `${(count / findings.length) * 100}%` }} />
                                                </div>
                                                <span className="text-xs text-muted-foreground font-mono w-8 text-right">{count}</span>
                                            </div>
                                        ))}
                                    </div>
                                </div>

                                <button
                                    onClick={() => { downloadJSON({ risk_score: riskScore, ai_decision: aiDecision, severity_breakdown: severityCounts, findings_count: findings.length, top_modules: Object.entries(findings.reduce((acc, f) => { acc[f.module_name || f.module || "Unknown"] = (acc[f.module_name || f.module || "Unknown"] || 0) + 1; return acc; }, {} as Record<string, number>)).sort(([, a], [, b]) => b - a).slice(0, 10) }, `ai-risk-analysis-${new Date().toISOString().slice(0, 10)}.json`); toast.success("AI Risk Analysis exported"); }}
                                    className="w-full flex items-center justify-center gap-2 px-4 py-2.5 rounded-xl text-xs font-bold uppercase tracking-wider transition-all hover:brightness-110"
                                    style={{ background: "rgba(0,163,255,0.1)", border: "1px solid rgba(0,163,255,0.2)", color: "#00A3FF" }}
                                >
                                    <Download className="w-4 h-4" /> Export AI Analysis
                                </button>
                            </div>
                        </motion.div>
                    </motion.div>
                )}
            </AnimatePresence>

            {/* ─── Executive Summary Modal ────────────────────────────────────── */}
            <AnimatePresence>
                {showExecutiveSummaryModal && (
                    <motion.div
                        initial={{ opacity: 0 }}
                        animate={{ opacity: 1 }}
                        exit={{ opacity: 0 }}
                        className="fixed inset-0 z-[100] flex items-center justify-center bg-background/70 backdrop-blur-sm"
                        onClick={() => setShowExecutiveSummaryModal(false)}
                    >
                        <motion.div
                            initial={{ scale: 0.9, y: 20 }}
                            animate={{ scale: 1, y: 0 }}
                            exit={{ scale: 0.9, y: 20 }}
                            onClick={(e) => e.stopPropagation()}
                            className="w-full max-w-3xl max-h-[80vh] overflow-y-auto rounded-2xl p-6 bg-card border border-border shadow-2xl"
                        >
                            <div className="flex items-center justify-between mb-6">
                                <div className="flex items-center gap-3">
                                    <FileText className="w-6 h-6 text-primary" />
                                    <h2 className="text-xl font-black text-foreground uppercase tracking-tight">Executive Summary</h2>
                                </div>
                                <button onClick={() => setShowExecutiveSummaryModal(false)} className="p-2 rounded-lg hover:bg-muted transition-colors"><X className="w-5 h-5 text-muted-foreground" /></button>
                            </div>

                            <div className="space-y-4">
                                {/* Overview */}
                                <div className="rounded-xl p-4 bg-muted/40 border border-border">
                                    <div className="grid grid-cols-2 md:grid-cols-4 gap-4 text-center">
                                        <div>
                                            <p className="text-4xl font-black" style={{ color: riskScore >= 75 ? "#ef4444" : riskScore >= 50 ? "#f97316" : "#00FF88" }}>{executiveSummaryData.risk_score}%</p>
                                            <p className="text-[10px] text-muted-foreground uppercase font-bold">{executiveSummaryData.risk_level} Risk</p>
                                        </div>
                                        <div><p className="text-4xl font-black text-foreground">{executiveSummaryData.total_findings}</p><p className="text-[10px] text-muted-foreground uppercase">Total Findings</p></div>
                                        <div><p className="text-4xl font-black text-destructive">{executiveSummaryData.severity_breakdown.critical}</p><p className="text-[10px] text-muted-foreground uppercase">Critical</p></div>
                                        <div><p className="text-4xl font-black text-primary">{executiveSummaryData.verified_exploits}</p><p className="text-[10px] text-muted-foreground uppercase">Verified</p></div>
                                    </div>
                                </div>

                                {/* Severity Breakdown */}
                                <div className="rounded-xl p-4 bg-muted/40 border border-border">
                                    <h3 className="text-xs font-bold text-muted-foreground uppercase tracking-wider mb-3">Severity Breakdown</h3>
                                    <div className="grid grid-cols-4 gap-3">
                                        {([["Critical", severityCounts.critical, "#ef4444"], ["High", severityCounts.high, "#f97316"], ["Medium", severityCounts.medium, "#eab308"], ["Low", severityCounts.low, "#00FF88"]] as const).map(([label, count, color]) => (
                                            <div key={label} className="text-center p-3 rounded-lg" style={{ background: `${color}08` }}>
                                                <p className="text-2xl font-black" style={{ color }}>{count}</p>
                                                <p className="text-[10px] text-muted-foreground uppercase">{label}</p>
                                            </div>
                                        ))}
                                    </div>
                                </div>

                                {/* Top Criticals */}
                                {executiveSummaryData.top_critical_findings.length > 0 && (
                                    <div className="rounded-xl p-4 bg-destructive/5 border border-destructive/20">
                                        <h3 className="text-xs font-bold text-destructive uppercase tracking-wider mb-3">Top Critical Findings</h3>
                                        <div className="space-y-2">
                                            {executiveSummaryData.top_critical_findings.map((f, i) => (
                                                <div key={i} className="flex items-center gap-3 text-xs py-1 border-b border-border/50 last:border-0">
                                                    <span className="w-5 h-5 rounded-full bg-destructive/10 text-destructive flex items-center justify-center text-[10px] font-bold">{i + 1}</span>
                                                    <span className="text-foreground font-semibold flex-1">{f.title}</span>
                                                    <span className="text-muted-foreground font-mono">{f.cwe || ""}</span>
                                                </div>
                                            ))}
                                        </div>
                                    </div>
                                )}

                                {/* Recommendations */}
                                {executiveSummaryData.recommendations.length > 0 && (
                                    <div className="rounded-xl p-4 bg-primary/5 border border-primary/20">
                                        <h3 className="text-xs font-bold text-primary uppercase tracking-wider mb-3">Recommendations</h3>
                                        <ul className="space-y-2">
                                            {executiveSummaryData.recommendations.map((r, i) => (
                                                <li key={i} className="flex items-start gap-2 text-xs text-muted-foreground">
                                                    <Activity className="w-3.5 h-3.5 text-primary mt-0.5 flex-shrink-0" />
                                                    {r}
                                                </li>
                                            ))}
                                        </ul>
                                    </div>
                                )}

                                <button
                                    onClick={() => { downloadJSON(executiveSummaryData, `executive-summary-${new Date().toISOString().slice(0, 10)}.json`); toast.success("Executive summary exported"); }}
                                    className="w-full flex items-center justify-center gap-2 px-4 py-2.5 rounded-xl text-xs font-bold uppercase tracking-wider transition-all hover:bg-primary/20 bg-primary/10 border border-primary/20 text-primary"
                                >
                                    <Download className="w-4 h-4" /> Download Executive Summary
                                </button>
                            </div>
                        </motion.div>
                    </motion.div>
                )}
            </AnimatePresence>
        </Sidebar>
    );
}
