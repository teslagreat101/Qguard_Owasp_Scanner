/**
 * Security Protocol v5.0 — Frontend API Client
 * Typed API client for scanner backend with SSE streaming, auth, retry logic,
 * paginated findings, dashboard stats, and report generation.
 *
 * Phase 3: Complete API coverage for all backend endpoints
 */

const API_BASE = process.env.NEXT_PUBLIC_API_URL || 'http://localhost:8000';

// ═══════════════════════════════════════════════════════════════
// Types
// ═══════════════════════════════════════════════════════════════

export interface ScanModule {
    key: string;
    name: string;
    owasp: string;
    phase: number;
    pattern_count: number;
    description: string;
    available: boolean;
}

export interface ScanProfile {
    key: string;
    name: string;
    description: string;
    module_count: number;
}

export interface ScanRequest {
    target: string;
    scan_type: 'directory' | 'code' | 'git' | 'url' | 'repository';
    target_type?: 'url' | 'github' | 'directory' | 'code';
    modules?: string[];
    scan_profile?: string;
}

export interface ScanResponse {
    scan_id: string;
    status: string;
    modules?: string[];
    total_patterns?: number;
}

export interface ScanStatus {
    scan_id: string;
    status: 'initializing' | 'running' | 'completed' | 'error' | 'cancelled';
    progress: number;
    active_module: string | null;
    total_findings: number;
    modules_completed: number;
    modules_total: number;
    started_at: string | null;
    completed_at: string | null;
    elapsed_seconds: number;
    duration: number;
    severity_counts: Record<string, number>;
    target: string | null;
}

export interface Finding {
    id: string;
    file: string;
    line_number: number;
    severity: 'Critical' | 'High' | 'Medium' | 'Low' | 'Info' | string;
    title: string;
    description: string;
    matched_content?: string;
    category: string;
    cwe: string;
    remediation: string;
    confidence: number;
    module: string;
    module_name: string;
    owasp: string;
    language?: string;
    tags: string[];
    timestamp: string;
    injection_type?: string;
    subcategory?: string;
    ssrf_type?: string;
    endpoint?: string;
}

export interface PaginatedFindings {
    findings: Finding[];
    total: number;
    page: number;
    page_size: number;
    total_pages: number;
    has_next: boolean;
    has_prev: boolean;
}

export interface FindingsFilter {
    severity?: string;
    module?: string;
    search?: string;
    sort_by?: 'severity' | 'file' | 'module';
    sort_order?: 'asc' | 'desc';
    page?: number;
    page_size?: number;
}

export interface ScanReport {
    scan_id: string;
    status: string;
    target: string;
    scan_type: string;
    scan_profile: string;
    duration: number;
    started_at: string;
    completed_at: string;
    summary: Record<string, number>;
    module_summary: Record<string, { name: string; count: number; severities: Record<string, number> }>;
    owasp_coverage: Record<string, { count: number; critical: number; high: number }>;
    total_findings: number;
    findings: Finding[];
    logs: LogEntry[];
    top_files: { file: string; count: number; critical?: number; high?: number }[];
    risk_score: number;
    modules_used: string[];
}

export interface AIAnalysisResponse {
    finding_id: string;
    ai_available: boolean;
    risk_explanation: string;
    fix_suggestion: string;
    code_patch: string;
    confidence: number;
    references: string[];
}

export interface AIChatResponse {
    response: string;
    ai_available: boolean;
}

export interface SwarmScanRequest {
    target: string;
    depth?: 'surface' | 'standard' | 'deep';
    strategy?: 'passive' | 'active' | 'autonomous';
}

export interface SwarmScanResponse {
    scan_id: string;
    status: string;
    target: string;
    total_nodes: number;
}

export interface SwarmAttackGraph {
    nodes: Array<{
        id: string;
        label: string;
        type: string;
        severity?: string;
        timestamp?: string;
        metadata?: any;
    }>;
    edges: Array<{
        source: string;
        target: string;
        label: string;
        type?: string;
    }>;
}

export interface LogEntry {
    time: string;
    level: 'info' | 'success' | 'warn' | 'error' | 'debug';
    message: string;
    module: string | null;
}

export interface HealthResponse {
    status: string;
    version: string;
    engine: string;
    modules: number;
    total_patterns: number;
    profiles: number;
    active_scans: number;
}

export interface ScanHistoryItem {
    scan_id: string;
    target: string;
    scan_type: string;
    scan_profile: string;
    status: string;
    modules: string[];
    total_findings: number;
    severity_counts: Record<string, number>;
    started_at: string;
    completed_at: string | null;
    duration: number;
    risk_score: number;
}

export interface DashboardStats {
    total_scans: number;
    completed_scans: number;
    running_scans: number;
    total_findings: number;
    severity_counts: Record<string, number>;
    security_score: number;
    owasp_breakdown: Record<string, number>;
    module_stats: Record<string, { scans: number; findings: number }>;
    recent_scans: {
        scan_id: string;
        target: string;
        status: string;
        total_findings: number;
        started_at: string;
        duration: number;
        risk_score: number;
    }[];
}

// ═══════════════════════════════════════════════════════════════
// API Client
// ═══════════════════════════════════════════════════════════════

class ApiClient {
    private baseUrl: string;
    private authToken: string | null = null;

    constructor(baseUrl: string = API_BASE) {
        this.baseUrl = baseUrl;
    }

    setAuthToken(token: string | null) {
        this.authToken = token;
    }

    private async request<T>(path: string, options: RequestInit = {}): Promise<T> {
        const headers: Record<string, string> = {
            'Content-Type': 'application/json',
            ...(options.headers as Record<string, string> || {}),
        };

        if (this.authToken) {
            headers['Authorization'] = `Bearer ${this.authToken}`;
        }

        const url = `${this.baseUrl}${path}`;
        let lastError: Error | null = null;

        // Retry logic (3 attempts with exponential backoff)
        for (let attempt = 0; attempt < 3; attempt++) {
            try {
                const controller = new AbortController();
                const timeout = setTimeout(() => controller.abort(new Error("Timeout")), 30000); // 30s timeout

                const response = await fetch(url, {
                    ...options,
                    headers,
                    signal: controller.signal,
                });
                clearTimeout(timeout);

                if (!response.ok) {
                    const errorBody = await response.text();
                    throw new Error(`API error ${response.status}: ${errorBody}`);
                }
                return await response.json() as T;
            } catch (error) {
                lastError = error as Error;
                if (attempt < 2 && !(error instanceof DOMException)) {
                    await new Promise(r => setTimeout(r, 1000 * Math.pow(2, attempt)));
                }
            }
        }
        throw lastError;
    }

    // ── Health ──
    async getHealth(): Promise<HealthResponse> {
        return this.request<HealthResponse>('/api/v1/health');
    }

    // ── Modules & Profiles ──
    async getModules(): Promise<ScanModule[]> {
        const res = await this.request<{ modules: ScanModule[] }>('/api/v1/modules');
        return res.modules;
    }

    async getProfiles(): Promise<ScanProfile[]> {
        const res = await this.request<{ profiles: ScanProfile[] }>('/api/v1/profiles');
        return res.profiles;
    }

    // ── Scanning ──
    async startScan(request: ScanRequest): Promise<ScanResponse> {
        return this.request<ScanResponse>('/api/v1/scan/start', {
            method: 'POST',
            body: JSON.stringify(request),
        });
    }

    async getScanStatus(scanId: string): Promise<ScanStatus> {
        return this.request<ScanStatus>(`/api/v1/scan/${scanId}/status`);
    }

    async cancelScan(scanId: string): Promise<{ scan_id: string; status: string }> {
        return this.request(`/api/v1/scan/${scanId}/cancel`, { method: 'POST' });
    }

    async deleteScan(scanId: string): Promise<{ scan_id: string; status: string }> {
        return this.request(`/api/v1/scan/${scanId}`, { method: 'DELETE' });
    }

    // ── Findings (Paginated) ──
    async getScanFindings(scanId: string, filters: FindingsFilter = {}): Promise<PaginatedFindings> {
        const params = new URLSearchParams();
        if (filters.page) params.set('page', String(filters.page));
        if (filters.page_size) params.set('page_size', String(filters.page_size));
        if (filters.severity) params.set('severity', filters.severity);
        if (filters.module) params.set('module', filters.module);
        if (filters.search) params.set('search', filters.search);
        if (filters.sort_by) params.set('sort_by', filters.sort_by);
        if (filters.sort_order) params.set('sort_order', filters.sort_order);

        const query = params.toString();
        return this.request<PaginatedFindings>(`/api/v1/scan/${scanId}/findings${query ? `?${query}` : ''}`);
    }

    // ── Reports ──
    async getScanReport(scanId: string): Promise<ScanReport> {
        return this.request<ScanReport>(`/api/v1/scan/${scanId}/report`);
    }

    async getScanLogs(scanId: string): Promise<{ logs: LogEntry[] }> {
        return this.request(`/api/v1/scan/${scanId}/logs`);
    }

    // ── Scan History ──
    async getScanHistory(limit: number = 50, offset: number = 0, status?: string): Promise<{
        scans: ScanHistoryItem[];
        total: number;
    }> {
        const params = new URLSearchParams({ limit: String(limit), offset: String(offset) });
        if (status) params.set('status', status);
        return this.request(`/api/v1/scans?${params.toString()}`);
    }

    // ── Dashboard Stats ──
    async getDashboardStats(): Promise<DashboardStats> {
        return this.request<DashboardStats>('/api/v1/dashboard/stats');
    }

    // ── SSE Stream ──
    streamScanEvents(
        scanId: string,
        callbacks: {
            onLog?: (log: LogEntry) => void;
            onFinding?: (finding: Finding) => void;
            onStatus?: (status: any) => void;
            onComplete?: (data: any) => void;
            onError?: (error: Error) => void;
        }
    ): () => void {
        const token = this.authToken;
        const tokenParam = token ? `?token=${encodeURIComponent(token)}` : "";
        const url = `${this.baseUrl}/api/v1/scan/${scanId}/stream${tokenParam}`;
        
        console.log(`📡 Opening telemetry stream: ${url.split('?')[0]}`);
        
        const eventSource = new EventSource(url);

        eventSource.onopen = () => {
            console.log("✅ Telemetry stream connected");
        };

        eventSource.addEventListener('log', (e) => {
            try {
                const data = JSON.parse(e.data);
                callbacks.onLog?.(data);
            } catch { }
        });

        eventSource.addEventListener('finding', (e) => {
            try {
                const data = JSON.parse(e.data);
                callbacks.onFinding?.(data);
            } catch { }
        });

        eventSource.addEventListener('status', (e) => {
            try {
                const data = JSON.parse(e.data);
                callbacks.onStatus?.(data);
            } catch { }
        });

        eventSource.addEventListener('complete', (e) => {
            try {
                const data = JSON.parse(e.data);
                callbacks.onComplete?.(data);
                eventSource.close();
            } catch { }
        });

        eventSource.onerror = () => {
            callbacks.onError?.(new Error('SSE connection error'));
            eventSource.close();
        };

        return () => eventSource.close();
    }

    // ── Swarm Scan (New) ──
    async startSwarmScan(request: SwarmScanRequest): Promise<SwarmScanResponse> {
        return this.request<SwarmScanResponse>('/api/v1/swarm/scan/start', {
            method: 'POST',
            body: JSON.stringify(request),
        });
    }

    streamSwarmTelemetry(
        scanId: string,
        callbacks: {
            onLog?: (log: LogEntry) => void;
            onFinding?: (finding: Finding) => void;
            onStatus?: (status: any) => void;
            onComplete?: (data: any) => void;
            onError?: (error: Error) => void;
            onAgentStatus?: (agentStatus: { node: string; status: 'active' | 'completed' | 'error' }) => void;
            onKeepalive?: (data: any) => void;
            onGraphUpdate?: (graph: { nodes: any[]; edges: any[] }) => void;
        }
    ): () => void {
        const token = this.authToken;
        const tokenParam = token ? `?token=${encodeURIComponent(token)}` : "";
        const url = `${this.baseUrl}/api/v1/swarm/scan/${scanId}/stream${tokenParam}`;

        console.log(`Opening swarm telemetry stream: ${url.split('?')[0]}`);

        const eventSource = new EventSource(url);

        eventSource.onopen = () => {
            console.log("Swarm telemetry stream connected");
        };

        eventSource.addEventListener('log', (e) => {
            try {
                const data = JSON.parse(e.data);
                callbacks.onLog?.(data);
            } catch { }
        });

        eventSource.addEventListener('finding', (e) => {
            try {
                const data = JSON.parse(e.data);
                callbacks.onFinding?.(data);
            } catch { }
        });

        eventSource.addEventListener('agent_status', (e) => {
            try {
                const data = JSON.parse(e.data);
                callbacks.onAgentStatus?.(data);
            } catch { }
        });

        eventSource.addEventListener('status', (e) => {
            try {
                const data = JSON.parse(e.data);
                callbacks.onStatus?.(data);
            } catch { }
        });

        eventSource.addEventListener('complete', (e) => {
            try {
                const data = JSON.parse(e.data);
                callbacks.onComplete?.(data);
                eventSource.close();
            } catch { }
        });

        eventSource.addEventListener('keepalive', (e) => {
            try {
                const data = JSON.parse(e.data);
                callbacks.onKeepalive?.(data);
            } catch { }
        });

        eventSource.addEventListener('graph_update', (e) => {
            try {
                const data = JSON.parse(e.data);
                callbacks.onGraphUpdate?.(data);
            } catch { }
        });

        eventSource.onerror = () => {
            callbacks.onError?.(new Error('Swarm SSE connection error'));
            eventSource.close();
        };

        return () => eventSource.close();
    }

    async getSwarmAttackGraph(scanId: string): Promise<SwarmAttackGraph> {
        return this.request<SwarmAttackGraph>(`/api/v1/swarm/scan/${scanId}/graph`);
    }

    async getSwarmFindings(scanId: string): Promise<{ findings: Finding[]; total: number }> {
        return this.request(`/api/v1/swarm/scan/${scanId}/findings`);
    }

    // ── Report Download ──
    async downloadReport(scanId: string, format: 'json' | 'html' = 'json'): Promise<Blob> {
        const report = await this.getScanReport(scanId);

        if (format === 'json') {
            return new Blob([JSON.stringify(report, null, 2)], { type: 'application/json' });
        }

        // Generate HTML report
        const html = generateHtmlReport(report);
        return new Blob([html], { type: 'text/html' });
    }

    // ═══════════════════════════════════════════════════════════════
    // Billing API (Phase 5)
    // ═══════════════════════════════════════════════════════════════

    async getBillingPlans(): Promise<SubscriptionPlan[]> {
        const res = await this.request<{ plans: SubscriptionPlan[] }>('/api/v1/billing/plans');
        return res.plans;
    }

    async getSubscription(): Promise<UserSubscription | null> {
        const res = await this.request<{ subscription: UserSubscription | null }>('/api/v1/billing/subscription');
        return res.subscription;
    }

    async createCheckout(planId: string, successUrl?: string, cancelUrl?: string): Promise<{ session_id: string; url: string; mock?: boolean }> {
        return this.request('/api/v1/billing/checkout', {
            method: 'POST',
            body: JSON.stringify({
                plan_id: planId,
                success_url: successUrl || `${window.location.origin}/billing?success=true`,
                cancel_url: cancelUrl || `${window.location.origin}/billing?canceled=true`,
            }),
        });
    }

    async getPaymentMethods(): Promise<PaymentMethod[]> {
        const res = await this.request<{ payment_methods: PaymentMethod[] }>('/api/v1/billing/payment-methods');
        return res.payment_methods;
    }

    async getInvoices(): Promise<Invoice[]> {
        const res = await this.request<{ invoices: Invoice[] }>('/api/v1/billing/invoices');
        return res.invoices;
    }

    async getUsage(): Promise<UsageStats> {
        return this.request<UsageStats>('/api/v1/billing/usage');
    }

    async cancelSubscription(): Promise<{ success: boolean; message: string }> {
        return this.request('/api/v1/billing/cancel', { method: 'POST' });
    }

    async createBillingPortal(returnUrl?: string): Promise<{ url: string }> {
        return this.request('/api/v1/billing/portal', {
            method: 'POST',
            body: JSON.stringify({
                return_url: returnUrl || (typeof window !== 'undefined' ? `${window.location.origin}/billing` : '/billing'),
            }),
        });
    }

    /** Generic GET — used by AcceptanceGuard and other utilities */
    async get<T = any>(path: string): Promise<T> {
        return this.request<T>(path);
    }

    /** Generic POST — used by AcceptanceGuard and other utilities */
    async post<T = any>(path: string, body?: any): Promise<T> {
        return this.request<T>(path, {
            method: 'POST',
            body: body ? JSON.stringify(body) : undefined,
        });
    }

    // ── AI Security (Phase 8.2) ──
    async aiAnalyzeFinding(findingId: string, finding: any): Promise<AIAnalysisResponse> {
        return this.request<AIAnalysisResponse>('/api/v1/ai/analyze', {
            method: 'POST',
            body: JSON.stringify({ finding_id: findingId, finding }),
        });
    }

    async aiChat(question: string, context?: any): Promise<AIChatResponse> {
        return this.request<AIChatResponse>('/api/v1/ai/chat', {
            method: 'POST',
            body: JSON.stringify({ question, context }),
        });
    }

    async aiPrioritize(findings: any[]): Promise<{ findings: any[]; ai_available: boolean; total: number }> {
        return this.request('/api/v1/ai/prioritize', {
            method: 'POST',
            body: JSON.stringify(findings),
        });
    }
}

// ═══════════════════════════════════════════════════════════════
// Billing Types
// ═══════════════════════════════════════════════════════════════

export interface SubscriptionPlan {
    id: string;
    name: string;
    description: string;
    price_cents: number;
    price_formatted: string;
    interval: string;
    features: string[];
    popular: boolean;
}

export interface UserSubscription {
    id: string;
    status: string;
    plan_name: string;
    current_period_start: string;
    current_period_end: string;
    cancel_at_period_end: boolean;
    scans_used: number;
    scans_limit: number;
}

export interface PaymentMethod {
    id: string;
    brand: string;
    last4: string;
    exp_month: number;
    exp_year: number;
    is_default: boolean;
}

export interface Invoice {
    id: string;
    number: string;
    date: string;
    amount_formatted: string;
    amount_paid: number;
    currency: string;
    status: string;
    plan_name: string;
    pdf_url: string | null;
    /** Stripe-hosted invoice page (view in browser) */
    hosted_invoice_url: string;
    /** Direct PDF download URL */
    invoice_pdf: string;
    period_start: string | null;
    period_end: string | null;
}

export interface UsageStats {
    scans_this_month: number;
    scans_limit: number;
    storage_used_mb: number;
    storage_limit_mb: number;
    api_calls_this_month: number;
    api_calls_limit: number;
}

// ═══════════════════════════════════════════════════════════════
// HTML Report Generator
// ═══════════════════════════════════════════════════════════════

function generateHtmlReport(report: ScanReport): string {
    const severityColors: Record<string, string> = {
        critical: '#ef4444',
        high: '#f97316',
        medium: '#eab308',
        low: '#22c55e',
        info: '#6b7280',
    };

    return `<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Security Scan Report — ${report.target}</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body { font-family: 'Inter', -apple-system, sans-serif; background: #0B0F0C; color: #A5B3AD; line-height: 1.6; }
        .container { max-width: 1200px; margin: 0 auto; padding: 40px 20px; }
        h1 { color: #00FF88; font-size: 2rem; margin-bottom: 8px; }
        h2 { color: #fff; font-size: 1.5rem; margin: 32px 0 16px; border-bottom: 1px solid rgba(0,255,136,0.15); padding-bottom: 8px; }
        .summary { display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 16px; margin: 24px 0; }
        .stat { background: #111716; border: 1px solid rgba(0,255,136,0.1); border-radius: 12px; padding: 20px; }
        .stat-value { font-size: 2rem; font-weight: 700; color: #00FF88; }
        .stat-label { font-size: 0.875rem; color: #6B7F77; }
        table { width: 100%; border-collapse: collapse; margin: 16px 0; }
        th { background: rgba(0,255,136,0.06); color: #6B7F77; text-align: left; padding: 12px; font-size: 0.75rem; text-transform: uppercase; }
        td { padding: 12px; border-bottom: 1px solid rgba(0,255,136,0.06); font-size: 0.875rem; }
        .sev { display: inline-block; padding: 2px 10px; border-radius: 6px; font-size: 0.75rem; font-weight: 600; }
        .footer { text-align: center; margin-top: 40px; color: #3D4F48; font-size: 0.75rem; }
    </style>
</head>
<body>
    <div class="container">
        <h1>🔒 Quantara Security Report</h1>
        <p>Target: <strong style="color:#fff">${report.target}</strong> | Duration: ${report.duration}s | Risk Score: ${report.risk_score}/100</p>

        <div class="summary">
            ${Object.entries(report.summary).map(([sev, count]) => `
                <div class="stat">
                    <div class="stat-value" style="color:${severityColors[sev] || '#6b7280'}">${count}</div>
                    <div class="stat-label">${sev.charAt(0).toUpperCase() + sev.slice(1)} Findings</div>
                </div>
            `).join('')}
            <div class="stat">
                <div class="stat-value">${report.total_findings}</div>
                <div class="stat-label">Total Findings</div>
            </div>
        </div>

        <h2>Findings (${report.total_findings})</h2>
        <table>
            <thead><tr><th>Severity</th><th>Title</th><th>File</th><th>CWE</th><th>Module</th></tr></thead>
            <tbody>
                ${report.findings.map(f => `
                    <tr>
                        <td><span class="sev" style="background:${severityColors[(f.severity || '').toLowerCase()] || '#6b7280'}22;color:${severityColors[(f.severity || '').toLowerCase()] || '#6b7280'}">${f.severity}</span></td>
                        <td style="color:#fff">${f.title}</td>
                        <td style="color:#00FF88;font-family:monospace;font-size:0.75rem">${f.file}:${f.line_number}</td>
                        <td>${f.cwe || '-'}</td>
                        <td>${f.module_name || f.module}</td>
                    </tr>
                `).join('')}
            </tbody>
        </table>

        <div class="footer">
            Generated by Quantara Security v5.0 Platform — ${new Date().toISOString()}
        </div>
    </div>
</body>
</html>`;
}

// Singleton instance
export const api = new ApiClient();
export default api;
