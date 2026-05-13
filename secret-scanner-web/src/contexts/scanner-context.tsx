"use client";

import React, { createContext, useContext, useState, useCallback, useRef, useEffect } from "react";
import { toast } from "sonner";
import { useAuth } from "@/contexts/auth-context";
import type {
    Finding, ScanStatus, ScanLog, ScanResult,
    EnterpriseTelemetry, PayloadExecutedEvent, VerificationSuccessEvent,
    AttackChain, AiDecision, RiskUpdate, EndpointDiscovered,
} from "@/hooks/use-scanner";

const API_BASE_URL = process.env.NEXT_PUBLIC_API_URL || "http://localhost:8000";

// ── Scan lifecycle state machine ─────────────────────────────────────────────
export type ScanLifecycle =
    | "IDLE"
    | "INITIALIZING"
    | "SCANNING"
    | "STREAMING_RESULTS"
    | "COMPLETED"
    | "FAILED";

// ── Context value type ────────────────────────────────────────────────────────
export interface ScannerContextValue {
    isScanning: boolean;
    scanLifecycle: ScanLifecycle;
    scanStatus: ScanStatus | null;
    findings: Finding[];
    logs: ScanLog[];
    scanResult: ScanResult | null;
    scanId: string | null;
    startScan: (target: string, modules: string[], scanType?: "url" | "directory" | "upload" | "code", scanProfile?: string) => Promise<string | undefined>;
    cancelScan: () => Promise<void>;
    clearScan: () => void;
    loadScanFromHistory: (scanId: string) => Promise<void>;
    totalFindingsCount: React.MutableRefObject<number>;
    totalLogsCount: React.MutableRefObject<number>;
    enterpriseTelemetry: EnterpriseTelemetry | null;
    payloadsExecuted: PayloadExecutedEvent[];
    verifiedFindings: VerificationSuccessEvent[];
    attackChains: AttackChain[];
    aiDecision: AiDecision | null;
    riskData: RiskUpdate | null;
    endpointsDiscovered: EndpointDiscovered[];
    enterpriseSummary: any | null;
}

const ScannerContext = createContext<ScannerContextValue | null>(null);

export function useScannerContext(): ScannerContextValue {
    const ctx = useContext(ScannerContext);
    if (!ctx) {
        throw new Error("useScannerContext must be used within a ScannerProvider");
    }
    return ctx;
}

// ── Provider ──────────────────────────────────────────────────────────────────
export function ScannerProvider({ children }: { children: React.ReactNode }) {
    const [isScanning, setIsScanning] = useState(false);
    const [scanLifecycle, setScanLifecycle] = useState<ScanLifecycle>("IDLE");
    const [scanStatus, setScanStatus] = useState<ScanStatus | null>(null);
    const [findings, setFindings] = useState<Finding[]>([]);
    const [logs, setLogs] = useState<ScanLog[]>([]);
    const [scanResult, setScanResult] = useState<ScanResult | null>(null);
    const [scanId, setScanId] = useState<string | null>(null);
    const { user } = useAuth();
    const eventSourceRef = useRef<EventSource | null>(null);

    // Enterprise intelligence state
    const [enterpriseTelemetry, setEnterpriseTelemetry] = useState<EnterpriseTelemetry | null>(null);
    const [payloadsExecuted, setPayloadsExecuted] = useState<PayloadExecutedEvent[]>([]);
    const [verifiedFindings, setVerifiedFindings] = useState<VerificationSuccessEvent[]>([]);
    const [attackChains, setAttackChains] = useState<AttackChain[]>([]);
    const [aiDecision, setAiDecision] = useState<AiDecision | null>(null);
    const [riskData, setRiskData] = useState<RiskUpdate | null>(null);
    const [endpointsDiscovered, setEndpointsDiscovered] = useState<EndpointDiscovered[]>([]);
    const [enterpriseSummary, setEnterpriseSummary] = useState<any | null>(null);

    // Stability refs
    const totalFindingsCountRef = useRef<number>(0);
    const totalLogsCountRef = useRef<number>(0);
    const findingsBatchRef = useRef<Finding[]>([]);
    const logsBatchRef = useRef<ScanLog[]>([]);
    const batchTimerRef = useRef<ReturnType<typeof setTimeout> | null>(null);
    const logsTimerRef = useRef<ReturnType<typeof setTimeout> | null>(null);

    const clearScan = useCallback(() => {
        setIsScanning(false);
        setScanLifecycle("IDLE");
        setScanStatus(null);
        setFindings([]);
        setLogs([]);
        setScanResult(null);
        setScanId(null);
        setEnterpriseTelemetry(null);
        setPayloadsExecuted([]);
        setVerifiedFindings([]);
        setAttackChains([]);
        setAiDecision(null);
        setRiskData(null);
        setEndpointsDiscovered([]);
        setEnterpriseSummary(null);
        if (eventSourceRef.current) {
            eventSourceRef.current.close();
            eventSourceRef.current = null;
        }
        totalFindingsCountRef.current = 0;
        totalLogsCountRef.current = 0;
        findingsBatchRef.current = [];
        logsBatchRef.current = [];
        if (batchTimerRef.current !== null) { clearTimeout(batchTimerRef.current); batchTimerRef.current = null; }
        if (logsTimerRef.current !== null) { clearTimeout(logsTimerRef.current); logsTimerRef.current = null; }
    }, []);

    const getTargetType = (scanType: string, target: string): "url" | "github" | "directory" | "code" => {
        if (scanType === "url") return "url";
        if ((scanType === "code" || scanType === "repository") && /^https?:\/\/(www\.)?github\.com\//i.test(target)) return "github";
        if (scanType === "directory" || scanType === "upload") return "directory";
        return "code";
    };

    const hydrateFromReport = useCallback((data: any) => {
        setScanResult(data);
        const reportFindings: Finding[] = data.findings || [];
        const reportLogs: ScanLog[] = data.logs || [];
        totalFindingsCountRef.current = reportFindings.length;
        totalLogsCountRef.current = reportLogs.length;
        setFindings(reportFindings.slice(0, 500));
        setLogs(reportLogs.slice(-1000));

        // Hydrate intelligence fields from report
        if (data.verified_findings?.length) {
            setVerifiedFindings(data.verified_findings.map((vf: any) => ({
                finding_id: vf.finding_id || vf.id || "",
                endpoint: vf.endpoint || vf.file || "",
                confidence: vf.confidence ?? 0,
                timing_delta_ms: vf.timing_delta_ms ?? 0,
                strategy: vf.strategy || vf.verification_method || "",
                evidence_hash: vf.evidence_hash || "",
            })));
        }
        if (data.attack_chains?.length) {
            setAttackChains(data.attack_chains.slice(0, 50));
        }
        if (data.endpoints_discovered?.length) {
            setEndpointsDiscovered(data.endpoints_discovered.slice(0, 500));
        }
        if (data.enterprise_telemetry) {
            setEnterpriseTelemetry(data.enterprise_telemetry);
        }
        if (data.payloads_executed?.length) {
            setPayloadsExecuted(data.payloads_executed.slice(0, 100));
        }
        if (data.ai_decision || data.ai_recommendations) {
            setAiDecision(data.ai_decision || data.ai_recommendations || null);
        }
        if (data.risk_score != null) {
            setRiskData({
                old_score: 0,
                new_score: data.risk_score,
                confidence: data.confidence || "LOW",
                scan_status: data.scan_status || "INCONCLUSIVE",
                risk_level: data.risk_level || "Unknown",
                trigger: "report_load",
            });
        }
        // Reconstruct endpoints from findings if backend didn't persist them
        if (!data.endpoints_discovered?.length && reportFindings.length > 0) {
            const eps: EndpointDiscovered[] = [];
            for (const f of reportFindings) {
                const ep = f.file || (f as any).location || "";
                if (ep && (ep.includes("http") || ep.includes("/"))) {
                    eps.push({ url: ep, method: (f as any).method || "GET", finding_id: f.id, severity: f.severity });
                }
                if (eps.length >= 500) break;
            }
            if (eps.length > 0) setEndpointsDiscovered(eps);
        }
    }, []);

    const fetchScanReport = useCallback(async (sid: string) => {
        try {
            const token = await user?.getIdToken();
            const response = await fetch(`${API_BASE_URL}/api/v1/scan/${sid}/report`, {
                headers: { ...(token ? { "Authorization": `Bearer ${token}` } : {}) }
            });
            if (!response.ok) throw new Error("Failed to fetch report");
            const data = await response.json();
            hydrateFromReport(data);
        } catch (error) {
            console.error("Failed to fetch scan report:", error);
        }
    }, [user, hydrateFromReport]);

    const loadScanFromHistory = useCallback(async (historyScanId: string) => {
        try {
            // Clear current state before loading historical scan
            if (eventSourceRef.current) {
                eventSourceRef.current.close();
                eventSourceRef.current = null;
            }
            setIsScanning(false);

            const token = await user?.getIdToken();
            const response = await fetch(`${API_BASE_URL}/api/v1/scan/${historyScanId}/report`, {
                headers: { ...(token ? { "Authorization": `Bearer ${token}` } : {}) }
            });
            if (!response.ok) throw new Error("Failed to load scan report");
            const data = await response.json();

            // Set scan identity
            setScanId(historyScanId);
            setScanLifecycle(data.status === "completed" ? "COMPLETED" : data.status === "error" ? "FAILED" : "IDLE");
            setScanStatus({
                scan_id: historyScanId,
                status: data.status || "completed",
                progress: 100,
                active_module: null,
                total_findings: data.total_findings || 0,
                modules_completed: data.modules_used?.length || 0,
                modules_total: data.modules_used?.length || 0,
                started_at: data.started_at || null,
                elapsed_seconds: data.duration || 0,
            });

            // Hydrate all fields from report
            hydrateFromReport(data);
        } catch (error) {
            console.error("Failed to load historical scan:", error);
            toast.error("Failed to load scan from history");
        }
    }, [user, hydrateFromReport]);

    const startEventStream = useCallback(async (sid: string) => {
        if (eventSourceRef.current) {
            eventSourceRef.current.close();
        }
        const abortController = new AbortController();
        eventSourceRef.current = { close: () => { abortController.abort(); } } as any;

        try {
            const token = await user?.getIdToken();
            const streamUrl = `${API_BASE_URL}/api/v1/scan/${sid}/stream`;
            const response = await fetch(streamUrl, {
                signal: abortController.signal,
                headers: {
                    "Accept": "text/event-stream",
                    ...(token ? { "Authorization": `Bearer ${token}` } : {})
                },
            });

            if (!response.ok) {
                throw new Error(`SSE Connection failed: ${response.status} ${response.statusText}`);
            }

            const reader = response.body?.getReader();
            if (!reader) throw new Error("Disconnected from stream: No body");

            const decoder = new TextDecoder();
            let buffer = "";

            while (true) {
                const { done, value } = await reader.read();
                if (done) break;

                const chunk = decoder.decode(value, { stream: true });
                buffer += chunk;

                const parts = buffer.split(/\r?\n\r?\n/);
                buffer = parts.pop() || "";

                for (const part of parts) {
                    if (!part.trim()) continue;

                    const lines = part.split(/\r?\n/);
                    let eventType = "message";
                    let dataLines: string[] = [];

                    for (const line of lines) {
                        if (line.startsWith("event: ")) eventType = line.slice(7).trim();
                        else if (line.startsWith("data: ")) dataLines.push(line.slice(6).trim());
                        else if (line.trim() === "data:") dataLines.push("");
                    }

                    const dataStr = dataLines.join("\n");
                    if (dataStr) {
                        try {
                            const data = JSON.parse(dataStr);

                            if (eventType === "finding") {
                                setScanLifecycle((prev) => prev === "SCANNING" || prev === "INITIALIZING" ? "STREAMING_RESULTS" : prev);
                                totalFindingsCountRef.current += 1;
                                findingsBatchRef.current.unshift(data);
                                if (batchTimerRef.current !== null) clearTimeout(batchTimerRef.current);
                                batchTimerRef.current = setTimeout(() => {
                                    setFindings((prev) => {
                                        const combined = [...findingsBatchRef.current, ...prev];
                                        findingsBatchRef.current = [];
                                        return combined.length > 500 ? combined.slice(0, 500) : combined;
                                    });
                                }, 200);
                            } else if (eventType === "log") {
                                setScanLifecycle((prev) => prev === "SCANNING" || prev === "INITIALIZING" ? "STREAMING_RESULTS" : prev);
                                totalLogsCountRef.current += 1;
                                logsBatchRef.current.push(data);
                                if (logsTimerRef.current !== null) clearTimeout(logsTimerRef.current);
                                logsTimerRef.current = setTimeout(() => {
                                    setLogs((prev) => {
                                        const combined = [...prev, ...logsBatchRef.current];
                                        logsBatchRef.current = [];
                                        return combined.length > 1000 ? combined.slice(combined.length - 1000) : combined;
                                    });
                                    logsTimerRef.current = null;
                                }, 50);
                            } else if (eventType === "status") {
                                setScanStatus(data);
                                if (["completed", "error", "cancelled"].includes(data.status)) {
                                    setIsScanning(false);
                                    setScanLifecycle(data.status === "completed" ? "COMPLETED" : "FAILED");
                                    fetchScanReport(sid);
                                }
                            } else if (eventType === "complete") {
                                setIsScanning(false);
                                setScanLifecycle("COMPLETED");
                                toast.success(`Scan completed! ${data.total_findings} findings discovered.`);
                                fetchScanReport(sid);
                                return;
                            } else if (eventType === "module_started") {
                                setScanLifecycle((prev) => prev === "INITIALIZING" ? "SCANNING" : prev);
                                setScanStatus((prev) => prev ? { ...prev, active_module: data.module, progress: data.progress ?? prev.progress } : prev);
                            } else if (eventType === "module_completed") {
                                setScanStatus((prev) => prev ? { ...prev, modules_completed: (data.idx ?? 0) + 1, progress: data.progress ?? prev.progress } : prev);
                            } else if (eventType === "scan_initialized") {
                                setScanLifecycle("SCANNING");
                                setScanStatus((prev) => prev
                                    ? { ...prev, status: "running" as const }
                                    : { scan_id: data.scan_id, status: "running", progress: 0, active_module: null, total_findings: 0, modules_completed: 0, modules_total: data.modules?.length ?? 0, started_at: null, elapsed_seconds: 0 }
                                );
                            } else if (eventType === "enterprise_telemetry") {
                                setEnterpriseTelemetry(data as EnterpriseTelemetry);
                            } else if (eventType === "payload_executed") {
                                setPayloadsExecuted((prev) => { const next = [data as PayloadExecutedEvent, ...prev]; return next.length > 100 ? next.slice(0, 100) : next; });
                            } else if (eventType === "verification_success") {
                                setVerifiedFindings((prev) => { const next = [...prev, data as VerificationSuccessEvent]; return next.length > 200 ? next.slice(next.length - 200) : next; });
                            } else if (eventType === "attack_chain_created" || eventType === "enterprise_attack_chains") {
                                if (data.chains) {
                                    setAttackChains((prev) => { const merged = [...prev, ...(data.chains as AttackChain[])]; return merged.length > 50 ? merged.slice(0, 50) : merged; });
                                }
                            } else if (eventType === "enterprise_summary") {
                                setEnterpriseSummary(data);
                                if (data.attack_chains?.length > 0) {
                                    setAttackChains((prev) => {
                                        const existingIds = new Set(prev.map((c: AttackChain) => c.chain_id));
                                        const newChains = (data.attack_chains as AttackChain[]).filter(c => !existingIds.has(c.chain_id));
                                        return [...prev, ...newChains];
                                    });
                                }
                            } else if (eventType === "ai_decision") {
                                setAiDecision(data as AiDecision);
                            } else if (eventType === "risk_updated") {
                                setRiskData(data as RiskUpdate);
                            } else if (eventType === "endpoint_discovered") {
                                setEndpointsDiscovered((prev) => { const next = [...prev, data as EndpointDiscovered]; return next.length > 500 ? next.slice(next.length - 500) : next; });
                            }
                        } catch (e) {
                            console.error("[ScannerProvider] Failed to parse SSE data:", dataStr, e);
                        }
                    }
                }
            }
        } catch (error: any) {
            if (error.name === 'AbortError') return;
            console.error("[ScannerProvider] SSE Error:", error);
            setIsScanning(false);
            setScanLifecycle("FAILED");
            if (!abortController.signal.aborted) {
                toast.error(`Scan stream error: ${error.message}`);
            }
        }
    }, [user, fetchScanReport]);

    const startScan = useCallback(async (
        target: string,
        modules: string[],
        scanType: "url" | "directory" | "upload" | "code" = "directory",
        scanProfile: string = "full"
    ) => {
        if (!target?.trim()) { toast.error("Please enter a target path or code to scan"); throw new Error("Target is required"); }
        if (!modules?.length) { toast.error("Please select at least one scan module"); throw new Error("No modules selected"); }

        try {
            clearScan();
            setIsScanning(true);
            setScanLifecycle("INITIALIZING");

            // Health check
            try {
                const hc = await fetch(`${API_BASE_URL}/api/v1/health`, { method: "GET", headers: { "Content-Type": "application/json" }, signal: AbortSignal.timeout(5000) });
                if (!hc.ok) throw new Error("Backend health check failed");
            } catch {
                setIsScanning(false);
                toast.error("Cannot connect to backend server. Please ensure the backend is running.");
                throw new Error("Backend unavailable");
            }

            const token = await user?.getIdToken();
            const profileMap: Record<string, string> = { "quick-audit": "quick", "standard-scan": "standard", "full-assessment": "full", "compliance-check": "compliance" };
            const resolvedProfile = profileMap[scanProfile] ?? scanProfile;

            const response = await fetch(`${API_BASE_URL}/api/v1/scan/start`, {
                method: "POST",
                headers: { "Content-Type": "application/json", ...(token ? { "Authorization": `Bearer ${token}` } : {}) },
                body: JSON.stringify({ target: target.trim(), modules, scan_type: scanType, target_type: getTargetType(scanType, target.trim()), scan_profile: resolvedProfile }),
            });

            if (!response.ok) {
                const errorText = await response.text();
                let errorMessage = "Failed to start scan";
                try { const ej = JSON.parse(errorText); errorMessage = ej.detail || ej.message || errorMessage; } catch { errorMessage = errorText || errorMessage; }
                throw new Error(errorMessage);
            }

            const data = await response.json();
            const newScanId = data.scan_id;
            setScanId(newScanId);
            toast.success(`Scan started! ID: ${newScanId.slice(0, 8)}...`);
            startEventStream(newScanId);
            return newScanId;
        } catch (error) {
            setIsScanning(false);
            setScanLifecycle("FAILED");
            const message = error instanceof Error ? error.message : "Failed to start scan";
            if (!message.includes("Backend unavailable") && !message.includes("Target is required") && !message.includes("No modules selected")) {
                toast.error(message);
            }
            throw error;
        }
    }, [clearScan, user, startEventStream]);

    const cancelScan = useCallback(async () => {
        if (!scanId) return;
        try {
            const token = await user?.getIdToken();
            const response = await fetch(`${API_BASE_URL}/api/v1/scan/${scanId}/cancel`, {
                method: "POST",
                headers: { ...(token ? { "Authorization": `Bearer ${token}` } : {}) }
            });
            if (!response.ok) throw new Error("Failed to cancel scan");
            toast.info("Scan cancelled");
            if (eventSourceRef.current) { eventSourceRef.current.close(); eventSourceRef.current = null; }
            setIsScanning(false);
            setScanLifecycle("FAILED");
        } catch { toast.error("Failed to cancel scan"); }
    }, [scanId, user]);

    // Cleanup on unmount
    useEffect(() => {
        return () => { if (eventSourceRef.current) eventSourceRef.current.close(); };
    }, []);

    const value: ScannerContextValue = {
        isScanning, scanLifecycle, scanStatus, findings, logs, scanResult, scanId,
        startScan, cancelScan, clearScan, loadScanFromHistory,
        totalFindingsCount: totalFindingsCountRef,
        totalLogsCount: totalLogsCountRef,
        enterpriseTelemetry, payloadsExecuted, verifiedFindings, attackChains, aiDecision,
        riskData, endpointsDiscovered, enterpriseSummary,
    };

    return <ScannerContext.Provider value={value}>{children}</ScannerContext.Provider>;
}
