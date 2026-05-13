/**
 * Security Protocol v5.0 — React Hooks for Scanner
 * Custom hooks: useScan, useScanHistory, useScanStream, useModules,
 * useProfiles, useDashboardStats, useFindingsFilter
 *
 * Phase 3: Complete hook library for all scanning operations
 */

'use client';

import { useState, useEffect, useCallback, useRef, useMemo } from 'react';
import api, {
    type ScanRequest, type ScanResponse, type ScanStatus,
    type Finding, type LogEntry, type ScanReport,
    type ScanModule, type ScanProfile, type ScanHistoryItem,
    type HealthResponse, type DashboardStats, type PaginatedFindings,
    type FindingsFilter,
} from './api';
import { useAuth } from '@/contexts/auth-context';
import { saveScanResult } from './db-service';

// ═══════════════════════════════════════════════════════════════
// useHealth — Check backend health
// ═══════════════════════════════════════════════════════════════

export function useHealth() {
    const [health, setHealth] = useState<HealthResponse | null>(null);
    const [loading, setLoading] = useState(true);
    const [error, setError] = useState<string | null>(null);

    const checkHealth = useCallback(async () => {
        try {
            const data = await api.getHealth();
            setHealth(data);
            setError(null);
        } catch (e: any) {
            setError(e.message);
            setHealth(null);
        } finally {
            setLoading(false);
        }
    }, []);

    useEffect(() => {
        checkHealth();
        const interval = setInterval(checkHealth, 30000);
        return () => clearInterval(interval);
    }, [checkHealth]);

    return { health, loading, error, isHealthy: health?.status === 'healthy', checkHealth };
}

// ═══════════════════════════════════════════════════════════════
// useModules — List scanner modules
// ═══════════════════════════════════════════════════════════════

export function useModules() {
    const [modules, setModules] = useState<ScanModule[]>([]);
    const [loading, setLoading] = useState(true);

    useEffect(() => {
        api.getModules()
            .then(setModules)
            .catch(() => { })
            .finally(() => setLoading(false));
    }, []);

    return { modules, loading };
}

// ═══════════════════════════════════════════════════════════════
// useProfiles — List scan profiles
// ═══════════════════════════════════════════════════════════════

export function useProfiles() {
    const [profiles, setProfiles] = useState<ScanProfile[]>([]);
    const [loading, setLoading] = useState(true);

    useEffect(() => {
        api.getProfiles()
            .then(setProfiles)
            .catch(() => { })
            .finally(() => setLoading(false));
    }, []);

    return { profiles, loading };
}

// ═══════════════════════════════════════════════════════════════
// useDashboardStats — Aggregate dashboard statistics
// ═══════════════════════════════════════════════════════════════

export function useDashboardStats() {
    const [stats, setStats] = useState<DashboardStats | null>(null);
    const [loading, setLoading] = useState(true);
    const [error, setError] = useState<string | null>(null);

    const refresh = useCallback(async () => {
        try {
            const data = await api.getDashboardStats();
            setStats(data);
            setError(null);
        } catch (e: any) {
            setError(e.message);
        } finally {
            setLoading(false);
        }
    }, []);

    useEffect(() => {
        refresh();
    }, [refresh]);

    return { stats, loading, error, refresh };
}

// ═══════════════════════════════════════════════════════════════
// useScan — Full scan lifecycle management
// ═══════════════════════════════════════════════════════════════

export interface UseScanReturn {
    scanId: string | null;
    status: ScanStatus | null;
    findings: Finding[];
    logs: LogEntry[];
    report: ScanReport | null;
    isScanning: boolean;
    isComplete: boolean;
    error: string | null;
    startScan: (request: ScanRequest) => Promise<void>;
    cancelScan: () => Promise<void>;
    reset: () => void;
    severityCounts: Record<string, number>;
    progress: number;
    riskScore: number;
}

export function useScan(): UseScanReturn {
    const { user } = useAuth();
    const [scanId, setScanId] = useState<string | null>(null);
    const [status, setStatus] = useState<ScanStatus | null>(null);
    const [findings, setFindings] = useState<Finding[]>([]);
    const [logs, setLogs] = useState<LogEntry[]>([]);
    const [report, setReport] = useState<ScanReport | null>(null);
    const [isScanning, setIsScanning] = useState(false);
    const [isComplete, setIsComplete] = useState(false);
    const [error, setError] = useState<string | null>(null);
    const cleanupRef = useRef<(() => void) | null>(null);

    const severityCounts = useMemo(() =>
        findings.reduce((acc, f) => {
            const sev = (f.severity || 'info').toLowerCase();
            acc[sev] = (acc[sev] || 0) + 1;
            return acc;
        }, {} as Record<string, number>),
        [findings]
    );

    const riskScore = useMemo(() => {
        return Math.max(0, 100 - (
            (severityCounts.critical || 0) * 15 +
            (severityCounts.high || 0) * 8 +
            (severityCounts.medium || 0) * 3 +
            (severityCounts.low || 0) * 1
        ));
    }, [severityCounts]);

    const startScan = useCallback(async (request: ScanRequest) => {
        try {
            setError(null);
            setFindings([]);
            setLogs([]);
            setReport(null);
            setIsComplete(false);
            setIsScanning(true);

            const response = await api.startScan(request);
            setScanId(response.scan_id);

            // Start SSE stream
            const cleanup = api.streamScanEvents(response.scan_id, {
                onLog: (log) => setLogs(prev => [...prev, log]),
                onFinding: (finding) => setFindings(prev => [...prev, finding]),
                onStatus: (statusUpdate) => {
                    setStatus(prev => prev ? { ...prev, ...statusUpdate } : statusUpdate);
                },
                onComplete: async (data) => {
                    setIsScanning(false);
                    setIsComplete(true);
                    try {
                        const fullReport = await api.getScanReport(response.scan_id);
                        setReport(fullReport);
                        if (fullReport.findings) {
                            setFindings(fullReport.findings);
                        }

                        // Save to Firestore if user is logged in
                        if (user) {
                            await saveScanResult({
                                uid: user.uid,
                                target: request.target,
                                scan_type: request.scan_type || 'directory',
                                status: 'completed',
                                results: {
                                    findings: fullReport.findings || [],
                                    logs: logs, // Note: this uses current state logs
                                    stats: fullReport.summary || {},
                                    duration: fullReport.duration || 0,
                                    risk_score: 100 - ((fullReport.findings?.filter((f: any) => f.severity === 'critical').length || 0) * 15) // simple calc
                                }
                            });
                        }
                    } catch (e) {
                        console.error('Failed to process/save scan report:', e);
                    }
                },
                onError: (err) => {
                    setError(err.message);
                    setIsScanning(false);
                },
            });
            cleanupRef.current = cleanup;

            // Also poll status for reliability
            const pollInterval = setInterval(async () => {
                try {
                    const s = await api.getScanStatus(response.scan_id);
                    setStatus(s);
                    if (s.status === 'completed' || s.status === 'error' || s.status === 'cancelled') {
                        clearInterval(pollInterval);
                        setIsScanning(false);
                        setIsComplete(s.status === 'completed');
                        if (s.status === 'error') setError('Scan failed');
                    }
                } catch { }
            }, 2000);

            cleanupRef.current = () => {
                cleanup();
                clearInterval(pollInterval);
            };
        } catch (err: any) {
            setError(err.message);
            setIsScanning(false);
        }
    }, []);

    const cancelScan = useCallback(async () => {
        if (scanId) {
            try {
                await api.cancelScan(scanId);
                setIsScanning(false);
                cleanupRef.current?.();
            } catch (err: any) {
                setError(err.message);
            }
        }
    }, [scanId]);

    const reset = useCallback(() => {
        cleanupRef.current?.();
        setScanId(null);
        setStatus(null);
        setFindings([]);
        setLogs([]);
        setReport(null);
        setIsScanning(false);
        setIsComplete(false);
        setError(null);
    }, []);

    useEffect(() => {
        return () => cleanupRef.current?.();
    }, []);

    return {
        scanId,
        status,
        findings,
        logs,
        report,
        isScanning,
        isComplete,
        error,
        startScan,
        cancelScan,
        reset,
        severityCounts,
        progress: status?.progress || 0,
        riskScore,
    };
}

// ═══════════════════════════════════════════════════════════════
// useScanHistory — Fetch and refresh scan history
// ═══════════════════════════════════════════════════════════════

export function useScanHistory() {
    const [scans, setScans] = useState<ScanHistoryItem[]>([]);
    const [loading, setLoading] = useState(true);
    const [error, setError] = useState<string | null>(null);
    const [total, setTotal] = useState(0);

    const refresh = useCallback(async (limit: number = 50, offset: number = 0, status?: string) => {
        setLoading(true);
        try {
            const result = await api.getScanHistory(limit, offset, status);
            setScans(result.scans);
            setTotal(result.total);
            setError(null);
        } catch (err: any) {
            setError(err.message);
        } finally {
            setLoading(false);
        }
    }, []);

    useEffect(() => {
        refresh();
    }, [refresh]);

    return { scans, loading, error, total, refresh };
}

// ═══════════════════════════════════════════════════════════════
// useScanStream — Standalone SSE stream for a scan ID
// ═══════════════════════════════════════════════════════════════

export function useScanStream(scanId: string | null) {
    const [logs, setLogs] = useState<LogEntry[]>([]);
    const [findings, setFindings] = useState<Finding[]>([]);
    const [isStreaming, setIsStreaming] = useState(false);
    const [status, setStatus] = useState<any>(null);

    useEffect(() => {
        if (!scanId) return;

        setIsStreaming(true);
        const cleanup = api.streamScanEvents(scanId, {
            onLog: (log) => setLogs(prev => [...prev, log]),
            onFinding: (finding) => setFindings(prev => [...prev, finding]),
            onStatus: (s) => setStatus(s),
            onComplete: () => setIsStreaming(false),
            onError: () => setIsStreaming(false),
        });

        return () => {
            cleanup();
            setIsStreaming(false);
        };
    }, [scanId]);

    return { logs, findings, isStreaming, status };
}

// ═══════════════════════════════════════════════════════════════
// usePaginatedFindings — Paginated findings with filters
// ═══════════════════════════════════════════════════════════════

export function usePaginatedFindings(scanId: string | null) {
    const [findings, setFindings] = useState<Finding[]>([]);
    const [loading, setLoading] = useState(false);
    const [pagination, setPagination] = useState({
        total: 0, page: 1, page_size: 50, total_pages: 1, has_next: false, has_prev: false
    });
    const [filters, setFilters] = useState<FindingsFilter>({
        page: 1, page_size: 50,
        sort_by: 'severity', sort_order: 'desc'
    });

    const fetchFindings = useCallback(async (newFilters?: Partial<FindingsFilter>) => {
        if (!scanId) return;

        const mergedFilters = { ...filters, ...newFilters };
        setFilters(mergedFilters);
        setLoading(true);

        try {
            const result = await api.getScanFindings(scanId, mergedFilters);
            setFindings(result.findings);
            setPagination({
                total: result.total,
                page: result.page,
                page_size: result.page_size,
                total_pages: result.total_pages,
                has_next: result.has_next,
                has_prev: result.has_prev,
            });
        } catch (e) {
            console.error('Failed to fetch findings:', e);
        } finally {
            setLoading(false);
        }
    }, [scanId, filters]);

    useEffect(() => {
        if (scanId) {
            fetchFindings();
        }
    }, [scanId]);

    const nextPage = () => fetchFindings({ page: (filters.page || 1) + 1 });
    const prevPage = () => fetchFindings({ page: Math.max(1, (filters.page || 1) - 1) });
    const setSeverityFilter = (severity: string) => fetchFindings({ severity, page: 1 });
    const setModuleFilter = (module: string) => fetchFindings({ module, page: 1 });
    const setSearch = (search: string) => fetchFindings({ search, page: 1 });

    return {
        findings, loading, pagination, filters,
        fetchFindings, nextPage, prevPage,
        setSeverityFilter, setModuleFilter, setSearch,
    };
}

// ═══════════════════════════════════════════════════════════════
// useReportDownload — Download scan reports
// ═══════════════════════════════════════════════════════════════

export function useReportDownload() {
    const [isDownloading, setIsDownloading] = useState(false);

    const downloadReport = useCallback(async (scanId: string, format: 'json' | 'html' = 'json') => {
        setIsDownloading(true);
        try {
            const blob = await api.downloadReport(scanId, format);
            const url = URL.createObjectURL(blob);
            const a = document.createElement('a');
            a.href = url;
            a.download = `scan-report-${scanId.slice(0, 8)}.${format}`;
            document.body.appendChild(a);
            a.click();
            document.body.removeChild(a);
            URL.revokeObjectURL(url);
        } catch (e) {
            console.error('Failed to download report:', e);
        } finally {
            setIsDownloading(false);
        }
    }, []);

    return { downloadReport, isDownloading };
}

// ═══════════════════════════════════════════════════════════════
// useBilling — Subscription and billing management
// ═══════════════════════════════════════════════════════════════

export function useBilling() {
    const { user } = useAuth();
    const [plans, setPlans] = useState<import('./api').SubscriptionPlan[]>([]);
    const [subscription, setSubscription] = useState<import('./api').UserSubscription | null>(null);
    const [profile, setProfile] = useState<any>(null);
    const [paymentMethods, setPaymentMethods] = useState<import('./api').PaymentMethod[]>([]);
    const [invoices, setInvoices] = useState<import('./api').Invoice[]>([]);
    const [usage, setUsage] = useState<import('./api').UsageStats | null>(null);
    const [loading, setLoading] = useState(true);
    const [checkoutLoading, setCheckoutLoading] = useState(false);

    const refresh = useCallback(async () => {
        setLoading(true);
        try {
            // Helper to handle safe fetch
            const safeFetch = async (promise: Promise<any>, fallback: any) => {
                try {
                    return await promise;
                } catch (e) {
                    console.warn('Individual billing fetch failed:', e);
                    return fallback;
                }
            };

            const [plansData, subData, pmData, invData, usageData, profileData] = await Promise.all([
                safeFetch(api.getBillingPlans(), []),
                safeFetch(api.getSubscription(), null),
                safeFetch(api.getPaymentMethods(), []),
                safeFetch(api.getInvoices(), []),
                safeFetch(api.getUsage(), null),
                user ? safeFetch(import('./db-service').then(m => m.getUserProfile(user.uid)), null) : Promise.resolve(null),
            ]);

            setPlans(plansData);
            setSubscription(subData);
            setPaymentMethods(pmData);
            setInvoices(invData);
            setUsage(usageData);
            setProfile(profileData);
        } catch (e) {
            console.error('Critical billing refresh failure:', e);
        } finally {
            setLoading(false);
        }
    }, []);

    const upgrade = useCallback(async (planId: string) => {
        setCheckoutLoading(true);
        try {
            const result = await api.createCheckout(planId);
            if (result.mock) {
                // Mock mode - just refresh to show updated state
                await refresh();
                return { success: true, mock: true };
            }
            // Redirect to Stripe Checkout
            window.location.href = result.url;
            return { success: true, mock: false };
        } catch (e) {
            console.error('Checkout failed:', e);
            return { success: false, error: e };
        } finally {
            setCheckoutLoading(false);
        }
    }, [refresh]);

    const cancel = useCallback(async () => {
        try {
            await api.cancelSubscription();
            await refresh();
            return true;
        } catch (e) {
            console.error('Cancel failed:', e);
            return false;
        }
    }, [refresh]);

    useEffect(() => {
        refresh();
    }, [refresh]);

    useEffect(() => {
        if (!user) return;

        // Use a cancelled flag to handle the async import race condition:
        // if signout happens before the import resolves, don't set up the listener at all.
        let cancelled = false;
        let unsubscribe: (() => void) | undefined;

        import('./db-service').then(m => {
            if (cancelled) return;
            unsubscribe = m.subscribeToUserProfile(user.uid, (data) => {
                setProfile(data);
            });
        });

        return () => {
            cancelled = true;
            unsubscribe?.();
        };
    }, [user]);

    return {
        plans,
        subscription,
        paymentMethods,
        invoices,
        usage,
        profile,
        loading,
        checkoutLoading,
        upgrade,
        cancel,
        refresh,
    };
}
// ═══════════════════════════════════════════════════════════════
// useCloudHistory — Fetch history from Firestore
// ═══════════════════════════════════════════════════════════════

export function useCloudHistory(limitCount: number = 20) {
    const { user } = useAuth();
    const [scans, setScans] = useState<any[]>([]);
    const [loading, setLoading] = useState(true);

    const refresh = useCallback(async () => {
        if (!user) return;
        setLoading(true);
        try {
            const { getScanHistory } = await import('./db-service');
            const data = await getScanHistory(user.uid, limitCount);
            setScans(data);
        } catch (e) {
            console.error('Failed to fetch cloud history:', e);
        } finally {
            setLoading(false);
        }
    }, [user, limitCount]);

    useEffect(() => {
        refresh();
    }, [refresh]);

    return { scans, loading, refresh };
}

// ═══════════════════════════════════════════════════════════════
// useTasks — Manage workflow tasks
// ═══════════════════════════════════════════════════════════════

export function useTasks() {
    const { user } = useAuth();
    const [tasks, setTasks] = useState<any[]>([]);
    const [loading, setLoading] = useState(true);

    const refresh = useCallback(async () => {
        if (!user) return;
        setLoading(true);
        try {
            const { getTasks } = await import('./db-service');
            const data = await getTasks(user.uid);
            setTasks(data);
        } catch (e) {
            console.error('Failed to fetch tasks:', e);
        } finally {
            setLoading(false);
        }
    }, [user]);

    const toggleTask = async (taskId: string, currentStatus: boolean) => {
        if (!user) return;
        try {
            const { updateTaskStatus } = await import('./db-service');
            await updateTaskStatus(user.uid, taskId, !currentStatus);
            await refresh();
        } catch (e) {
            console.error('Failed to update task:', e);
        }
    };

    useEffect(() => {
        refresh();
    }, [refresh]);

    return { tasks, loading, refresh, toggleTask };
}

// ═══════════════════════════════════════════════════════════════
// useSchedules — Manage recurring scans
// ═══════════════════════════════════════════════════════════════

export function useSchedules() {
    const { user } = useAuth();
    const [schedules, setSchedules] = useState<any[]>([]);
    const [loading, setLoading] = useState(true);

    const refresh = useCallback(async () => {
        if (!user) return;
        setLoading(true);
        try {
            const { getSchedules } = await import('./db-service');
            const data = await getSchedules(user.uid);
            setSchedules(data);
        } catch (e) {
            console.error('Failed to fetch schedules:', e);
        } finally {
            setLoading(false);
        }
    }, [user]);

    useEffect(() => {
        refresh();
    }, [refresh]);

    return { schedules, loading, refresh };
}

// ═══════════════════════════════════════════════════════════════
// useAICopilot — AI Security Assistant Chat
// ═══════════════════════════════════════════════════════════════

export interface Message {
    id: string;
    role: "user" | "assistant";
    content: string;
    timestamp: string;
}

export function useAICopilot() {
    const [messages, setMessages] = useState<Message[]>([]);
    const [isThinking, setIsThinking] = useState(false);
    const [isAvailable, setIsAvailable] = useState<boolean | null>(null);

    const sendMessage = useCallback(async (text: string, context?: any) => {
        const userMsg: Message = {
            id: Date.now().toString(),
            role: "user",
            content: text,
            timestamp: new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })
        };

        setMessages(prev => [...prev, userMsg]);
        setIsThinking(true);

        try {
            const result = await api.aiChat(text, context);
            setIsAvailable(result.ai_available);

            const aiMsg: Message = {
                id: (Date.now() + 1).toString(),
                role: "assistant",
                content: result.response,
                timestamp: new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })
            };
            setMessages(prev => [...prev, aiMsg]);
        } catch (e: any) {
            console.error('AI Copilot error:', e);
            const errorStr = String(e?.message || e);
            let friendlyMsg = "Unable to connect to the AI service. Please check that your backend is running and the GOOGLE_API_KEY is configured.";
            if (errorStr.includes("403")) {
                friendlyMsg = "AI access is restricted. Please check your subscription or contact support.";
            } else if (errorStr.includes("429")) {
                friendlyMsg = "Too many requests — please wait a moment and try again.";
            } else if (errorStr.includes("500") || errorStr.includes("502")) {
                friendlyMsg = "The AI service encountered an internal error. Check that GOOGLE_API_KEY is set in your .env file.";
            }
            const errMsg: Message = {
                id: (Date.now() + 1).toString(),
                role: "assistant",
                content: friendlyMsg,
                timestamp: new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })
            };
            setMessages(prev => [...prev, errMsg]);
        } finally {
            setIsThinking(false);
        }
    }, []);

    const analyzeFinding = useCallback(async (findingId: string, finding: any) => {
        setIsThinking(true);
        try {
            const result = await api.aiAnalyzeFinding(findingId, finding);
            const content = `### AI Analysis for finding: ${finding.title}\n\n**Risk Explanation:** ${result.risk_explanation}\n\n**Fix Suggestion:** ${result.fix_suggestion}\n\n${result.code_patch ? '```patch\n' + result.code_patch + '\n```' : ''}`;

            const aiMsg: Message = {
                id: Date.now().toString(),
                role: "assistant",
                content: content,
                timestamp: new Date().toLocaleTimeString()
            };
            setMessages(prev => [...prev, aiMsg]);
            return result;
        } catch (e) {
            console.error('AI Analysis error:', e);
        } finally {
            setIsThinking(false);
        }
    }, []);

    return {
        messages,
        isThinking,
        isAvailable,
        sendMessage,
        analyzeFinding,
        clearChat: () => setMessages([])
    };
}

