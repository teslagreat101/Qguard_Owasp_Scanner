"use client";

import { useState, useCallback, useRef, useEffect } from "react";
import { toast } from "sonner";
import { useAuth } from "@/contexts/auth-context";

const API_BASE_URL = process.env.NEXT_PUBLIC_API_URL || "http://localhost:8000";

export interface Finding {
  id: string;
  file: string;
  line_number: number;
  severity: "critical" | "high" | "medium" | "low" | "info";
  title: string;
  description: string;
  matched_content: string;
  cwe: string;
  remediation: string;
  confidence: number;
  tags: string[];
  category: string;
  module: string;
  module_name: string;
  owasp: string;
  timestamp: string;
  scanner_source?: string;
  location?: string;
}

export interface ScanStatus {
  scan_id: string;
  status: "initializing" | "running" | "completed" | "error" | "cancelled";
  progress: number;
  active_module: string | null;
  total_findings: number;
  modules_completed: number;
  modules_total: number;
  started_at: string | null;
  elapsed_seconds: number;
}

export interface ScanLog {
  time: string;
  level: "info" | "success" | "warn" | "error" | "debug";
  message: string;
  module?: string;
}

export interface ScanResult {
  scan_id: string;
  target: string;
  status: string;
  progress: number;
  findings: Finding[];
  logs: ScanLog[];
  duration?: number;
  summary: {
    critical: number;
    high: number;
    medium: number;
    low: number;
    info: number;
  };
}

// ── Enterprise telemetry types ──────────────────────────────────────────────
export interface EnterpriseTelemetry {
  payload_packs: Record<string, number>;
  total_payloads: number;
  mutation_engine: boolean;
  chain_correlator: boolean;
  differential_analyzer: boolean;
  adaptive_engine: boolean;
  modules_loaded: number;
  timestamp: string;
}

export interface PayloadExecutedEvent {
  module: string;
  packs_used: Record<string, number>;
  total_payloads_fired: number;
  mutations_generated: number;
  findings_triggered: number;
  endpoint: string;
  payload_type: string;
}

export interface VerificationSuccessEvent {
  finding_id: string;
  endpoint: string;
  confidence: number;
  timing_delta_ms: number;
  strategy: string;
  evidence_hash: string;
}

export interface AttackChain {
  chain_id: string;
  name: string;
  owasp: string;
  finding_ids: string[];
  severity: string;
  description: string;
}

export interface AiDecision {
  next_action?: string;
  rationale?: string;
  priority?: string;
  suggested_payloads?: string[];
  confidence?: number;
  [key: string]: any;
}

export interface RiskUpdate {
  old_score: number;
  new_score: number;
  confidence: string;
  scan_status: string;
  risk_level: string;
  trigger: string;
}

export interface EndpointDiscovered {
  url: string;
  method: string;
  finding_id: string;
  severity: string;
}



export const AVAILABLE_MODULES = [
  { key: "misconfig", name: "Security Misconfiguration", owasp: "A02:2025", patterns: 40, description: "Detects debug modes, default credentials, and missing security headers." },
  { key: "injection", name: "Injection Vulnerabilities", owasp: "A05:2025", patterns: 90, description: "Scans for SQLi, XSS, Command Injection, and NoSQL injection points." },
  { key: "frontend_js", name: "Frontend JS Analyzer", owasp: "A04:2025", patterns: 150, description: "Analyzes client-side bundles for secrets, API keys, and insecure eval()." },
  { key: "endpoint", name: "Endpoint Extractor", owasp: "Recon", patterns: 25, description: "Discovers hidden API endpoints and maps the application attack surface." },
  { key: "auth", name: "Auth Failures", owasp: "A07:2025", patterns: 35, description: "Check for weak password policies, JWT misconfigs, and session issues." },
  { key: "access_control", name: "Broken Access Control", owasp: "A01:2025", patterns: 45, description: "Identifies IDOR, path traversal, and missing authorization checks." },
  { key: "cloud", name: "Cloud Misconfiguration", owasp: "A02:2025-Cloud", patterns: 50, description: "Scans Terraform, K8s, and Docker configs for cloud-native risks." },
  { key: "api_security", name: "API Security", owasp: "API-Top-10", patterns: 30, description: "Focuses on BOLA, rate limiting gaps, and excessive data exposure." },
  { key: "supply_chain", name: "Supply Chain", owasp: "A03:2025", patterns: 20, description: "Detects unpinned dependencies and known-vulnerable packages." },
  { key: "insecure_design", name: "Insecure Design", owasp: "A06:2025", patterns: 25, description: "Identifies logic flaws, missing CSRF tokens, and mass assignment." },
  { key: "integrity", name: "Integrity Failures", owasp: "A08:2025", patterns: 20, description: "Scans for unsafe deserialization and missing software integrity checks." },
  { key: "ssrf", name: "SSRF Scanner", owasp: "A10:2025", patterns: 15, description: "Detects Server-Side Request Forgery: metadata endpoints, DNS rebinding, and PDF generator SSRF." },
  { key: "logging", name: "Security Logging & Monitoring", owasp: "A09:2025", patterns: 10, description: "Audit logging gaps, PII in logs, log injection, and verbose error disclosure." },
  { key: "exception", name: "Exception Handling Scanner", owasp: "A10:2025-Ext", patterns: 12, description: "Fail-open logic, swallowed errors, resource leaks, and broad catch-all patterns." },
  { key: "sensitive_data", name: "Sensitive Data Exposure", owasp: "A02:2025-Data", patterns: 7, description: "PII in code, SSN/credit card patterns, and cleartext storage detection." },
  { key: "code_agent", name: "Multi-Agent Code Analyzer", owasp: "A03:2025", patterns: 200, description: "Deep semantic code analysis using multi-agent pipeline (Discovery → Verification → Assessment)." },
  // Phase 6 — Quantara enterprise live HTTP scanner
  { key: "quantara_http", name: "Quantara HTTP Scanner", owasp: "A01-A10:2021", patterns: 523, description: "YAML-template-driven live HTTP scanner: SQLi, XSS, LFI, SSRF, SSTI, IDOR, CORS, JWT, security headers, tech fingerprinting — full OWASP Top 10:2021 coverage + extended Quantara YAML templates." },
  // Phase 7 — Enterprise Quantara Feature Modules
  { key: "quantara_crawler", name: "Quantara Web Crawler", owasp: "Recon", patterns: 60, description: "BFS recursive crawler with JS endpoint extraction, form discovery, and 60+ hidden paths." },
  { key: "quantara_auth", name: "Quantara Auth Engine", owasp: "A07:2025", patterns: 50, description: "Multi-role auth testing: JWT/Bearer, OAuth2, CSRF extraction, IDOR/privilege escalation detection." },
  { key: "quantara_fp_reducer", name: "Quantara FP Reducer", owasp: "Accuracy", patterns: 30, description: "6-step differential FP pipeline to reduce false positives (CONFIRMED/LIKELY_TP/FALSE_POSITIVE)." },
  { key: "quantara_oast", name: "Quantara OAST Engine", owasp: "A10:2025", patterns: 80, description: "Out-of-band blind vuln detection: blind SSRF, XSS, SQLi, CMDi, XXE via interactsh." },
  { key: "quantara_chains", name: "Quantara Attack Chains", owasp: "Multi-Stage", patterns: 40, description: "Attack chain correlation: SSRF→Cloud, LFI→SQLi, XSS→Admin with MITRE ATT&CK mapping." },
  { key: "quantara_ai", name: "Quantara AI Copilot", owasp: "AI-Enrichment", patterns: 100, description: "Multi-LLM enrichment: TP/FP verdict, business impact, code remediation, POC fix." },
  { key: "neo_intelligence", name: "NEO Intelligence Engine", owasp: "A01-A10:2025", patterns: 500, description: "Autonomous 5-layer intelligence: Application Graph, Spec Abuse, DNA-based mutations, and Attack Simulation." },
];

export function useScanner() {
  const [isScanning, setIsScanning] = useState(false);
  const [scanStatus, setScanStatus] = useState<ScanStatus | null>(null);
  const [findings, setFindings] = useState<Finding[]>([]);
  const [logs, setLogs] = useState<ScanLog[]>([]);
  const [scanResult, setScanResult] = useState<ScanResult | null>(null);
  const [scanId, setScanId] = useState<string | null>(null);
  const { user } = useAuth();
  const eventSourceRef = useRef<EventSource | null>(null);

  // ── Enterprise intelligence state ─────────────────────────────────────────
  const [enterpriseTelemetry, setEnterpriseTelemetry] = useState<EnterpriseTelemetry | null>(null);
  const [payloadsExecuted, setPayloadsExecuted] = useState<PayloadExecutedEvent[]>([]);
  const [verifiedFindings, setVerifiedFindings] = useState<VerificationSuccessEvent[]>([]);
  const [attackChains, setAttackChains] = useState<AttackChain[]>([]);
  const [aiDecision, setAiDecision] = useState<AiDecision | null>(null);
  const [riskData, setRiskData] = useState<RiskUpdate | null>(null);
  const [endpointsDiscovered, setEndpointsDiscovered] = useState<EndpointDiscovered[]>([]);
  const [enterpriseSummary, setEnterpriseSummary] = useState<any | null>(null);

  // ── Stability refs: track true counts + batch incoming events ─────────────
  // Using refs (not state) so they don't trigger re-renders on every finding.
  const totalFindingsCountRef = useRef<number>(0);
  const totalLogsCountRef = useRef<number>(0);
  const findingsBatchRef = useRef<Finding[]>([]);
  const logsBatchRef = useRef<ScanLog[]>([]);
  // Separate timers: findings use 200ms debounce, logs use 50ms so they appear immediately
  const batchTimerRef = useRef<ReturnType<typeof setTimeout> | null>(null);
  const logsTimerRef = useRef<ReturnType<typeof setTimeout> | null>(null);

  const clearScan = useCallback(() => {
    setIsScanning(false);
    setScanStatus(null);
    setFindings([]);
    setLogs([]);
    setScanResult(null);
    setScanId(null);
    // Reset enterprise state
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
    // Reset stability refs
    totalFindingsCountRef.current = 0;
    totalLogsCountRef.current = 0;
    findingsBatchRef.current = [];
    logsBatchRef.current = [];
    if (batchTimerRef.current !== null) {
      clearTimeout(batchTimerRef.current);
      batchTimerRef.current = null;
    }
    if (logsTimerRef.current !== null) {
      clearTimeout(logsTimerRef.current);
      logsTimerRef.current = null;
    }
  }, []);

  const getTargetType = (scanType: string, target: string): "url" | "github" | "code" => {
    if (scanType === "url") return "url";
    if (
      (scanType === "code" || scanType === "repository") &&
      /^https?:\/\/(www\.)?github\.com\//i.test(target)
    ) return "github";
    return "code";
  };

  const startScan = useCallback(async (
    target: string,
    modules: string[],
    scanType: "url" | "code" = "code",
    scanProfile: string = "full"
  ) => {
    // Validate target input
    if (!target || !target.trim()) {
      toast.error("Please enter a target path or code to scan");
      throw new Error("Target is required");
    }

    // Validate modules
    if (!modules || modules.length === 0) {
      toast.error("Please select at least one scan module");
      throw new Error("No modules selected");
    }

    try {
      clearScan();
      setIsScanning(true);

      // First check if backend is reachable
      try {
        const healthCheck = await fetch(`${API_BASE_URL}/api/v1/health`, {
          method: "GET",
          headers: { "Content-Type": "application/json" },
          signal: AbortSignal.timeout(5000),
        });
        if (!healthCheck.ok) {
          throw new Error("Backend health check failed");
        }
        const healthData = await healthCheck.json();
        console.log("Backend connected:", healthData);
      } catch (healthError) {
        setIsScanning(false);
        toast.error("Cannot connect to backend server. Please ensure the backend is running.");
        throw new Error("Backend unavailable");
      }

      const token = await user?.getIdToken();

      // Map frontend strategy IDs to backend scan_profile values
      const profileMap: Record<string, string> = {
        "quick-audit": "quick",
        "standard-scan": "standard",
        "full-assessment": "full",
        "compliance-check": "compliance",
      };
      const resolvedProfile = profileMap[scanProfile] ?? scanProfile;

      const response = await fetch(`${API_BASE_URL}/api/v1/scan/start`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          ...(token ? { "Authorization": `Bearer ${token}` } : {})
        },
        body: JSON.stringify({
          target: target.trim(),
          modules,
          scan_type: scanType,
          target_type: getTargetType(scanType, target.trim()),
          scan_profile: resolvedProfile,
        }),
      });

      if (!response.ok) {
        const errorText = await response.text();
        let errorMessage = "Failed to start scan";
        try {
          const errorJson = JSON.parse(errorText);
          errorMessage = errorJson.detail || errorJson.message || errorMessage;
        } catch {
          errorMessage = errorText || errorMessage;
        }
        throw new Error(errorMessage);
      }

      const data = await response.json();
      const newScanId = data.scan_id;
      setScanId(newScanId);

      toast.success(`Scan started! ID: ${newScanId.slice(0, 8)}...`);

      // Start streaming events
      startEventStream(newScanId);

      return newScanId;
    } catch (error) {
      setIsScanning(false);
      const message = error instanceof Error ? error.message : "Failed to start scan";
      if (!message.includes("Backend unavailable") && !message.includes("Target is required") && !message.includes("No modules selected")) {
        toast.error(message);
      }
      throw error;
    }
  }, [clearScan, user]);

  const startEventStream = useCallback(async (sid: string) => {
    if (eventSourceRef.current) {
      console.log("[useScanner] Closing existing event source for", sid);
      eventSourceRef.current.close();
    }

    const abortController = new AbortController();

    // Create a mock EventSource-like object for the ref
    eventSourceRef.current = {
      close: () => {
        console.log("[useScanner] Explicit close called for stream", sid);
        abortController.abort();
      }
    } as any;

    console.log("[useScanner] Initiating SSE stream for scan ID:", sid);

    try {
      const token = await user?.getIdToken();
      const streamUrl = `${API_BASE_URL}/api/v1/scan/${sid}/stream`;
      console.log("[useScanner] Fetching stream from:", streamUrl);

      const response = await fetch(streamUrl, {
        signal: abortController.signal,
        headers: {
          "Accept": "text/event-stream",
          ...(token ? { "Authorization": `Bearer ${token}` } : {})
        },
      });

      if (!response.ok) {
        const errText = await response.text().catch(() => "No error body");
        console.error("[useScanner] Stream response not OK:", response.status, errText);
        throw new Error(`SSE Connection failed: ${response.status} ${response.statusText}`);
      }

      console.log("[useScanner] SSE Stream connected successfully via fetch");

      const reader = response.body?.getReader();
      if (!reader) {
        console.error("[useScanner] No reader available on response body");
        throw new Error("Disconnected from stream: No body");
      }

      const decoder = new TextDecoder();
      let buffer = "";

      while (true) {
        const { done, value } = await reader.read();
        if (done) {
          console.log("[useScanner] Stream read complete (done=true)");
          break;
        }

        const chunk = decoder.decode(value, { stream: true });
        buffer += chunk;

        // Handle all variations of line endings (\n\n, \r\n\r\n)
        const parts = buffer.split(/\r?\n\r?\n/);
        buffer = parts.pop() || "";

        for (const part of parts) {
          if (!part.trim()) continue;

          // Support multi-line data fields and event type from SSE format
          const lines = part.split(/\r?\n/);
          let eventType = "message";
          let dataLines: string[] = [];

          for (const line of lines) {
            if (line.startsWith("event: ")) {
              eventType = line.slice(7).trim();
            } else if (line.startsWith("data: ")) {
              dataLines.push(line.slice(6).trim());
            } else if (line.trim() === "data:") {
              dataLines.push("");
            }
          }

          const dataStr = dataLines.join("\n");
          if (dataStr) {
            try {
              const data = JSON.parse(dataStr);

              if (eventType === "finding") {
                // Track true count (ref never causes re-render)
                totalFindingsCountRef.current += 1;
                // Accumulate in batch buffer
                findingsBatchRef.current.unshift(data);
                // Debounce state update to max 1 re-render per 200ms
                if (batchTimerRef.current !== null) clearTimeout(batchTimerRef.current);
                batchTimerRef.current = setTimeout(() => {
                  setFindings((prev) => {
                    const combined = [...findingsBatchRef.current, ...prev];
                    findingsBatchRef.current = [];
                    // Cap at 500: drop oldest (tail) to prevent memory explosion
                    return combined.length > 500 ? combined.slice(0, 500) : combined;
                  });
                }, 200);
              } else if (eventType === "log") {
                totalLogsCountRef.current += 1;
                logsBatchRef.current.push(data);
                // Logs use their own short-delay timer (50ms) so they appear near-immediately
                // and are NOT blocked by rapid findings batching on batchTimerRef.
                if (logsTimerRef.current !== null) clearTimeout(logsTimerRef.current);
                logsTimerRef.current = setTimeout(() => {
                  setLogs((prev) => {
                    const combined = [...prev, ...logsBatchRef.current];
                    logsBatchRef.current = [];
                    // Cap at 1000: drop oldest (head) when over limit
                    return combined.length > 1000 ? combined.slice(combined.length - 1000) : combined;
                  });
                  logsTimerRef.current = null;
                }, 50);
              } else if (eventType === "status") {
                setScanStatus(data);
                if (["completed", "error", "cancelled"].includes(data.status)) {
                  console.log(`[useScanner] Scan reached terminal state: ${data.status}`);
                  setIsScanning(false);
                  fetchScanReport(sid);
                }
              } else if (eventType === "complete") {
                console.log("[useScanner] Received explicit complete event");
                setIsScanning(false);
                toast.success(`Scan completed! ${data.total_findings} findings discovered.`);
                fetchScanReport(sid);
                return;

                // ── Lifecycle events: update active_module immediately ────────
              } else if (eventType === "module_started") {
                // Patch scanStatus immediately so PhaseTracker sees the active module
                setScanStatus((prev) => prev
                  ? { ...prev, active_module: data.module, progress: data.progress ?? prev.progress }
                  : prev
                );

              } else if (eventType === "module_completed") {
                // Advance progress and modules_completed
                setScanStatus((prev) => prev
                  ? {
                    ...prev,
                    modules_completed: (data.idx ?? 0) + 1,
                    progress: data.progress ?? prev.progress,
                  }
                  : prev
                );

              } else if (eventType === "module_progress") {
                // Silent heartbeat — no log, just keeps connection alive
                // Can be used by PhaseTracker to show elapsed time per module

              } else if (eventType === "scan_initialized") {
                // Scan is ready — even before execute_scan background task runs
                setScanStatus((prev) => prev
                  ? { ...prev, status: "running" as const }
                  : {
                    scan_id: data.scan_id,
                    status: "running",
                    progress: 0,
                    active_module: null,
                    total_findings: 0,
                    modules_completed: 0,
                    modules_total: data.modules?.length ?? 0,
                    started_at: null,
                    elapsed_seconds: 0,
                  }
                );

              } else if (eventType === "scan_started") {
                // Backend officially started execution
                setScanStatus((prev) => prev
                  ? {
                    ...prev,
                    status: "running",
                    modules_total: data.modules_total ?? prev.modules_total,
                    started_at: data.started_at ?? prev.started_at,
                  }
                  : {
                    scan_id: sid,
                    status: "running",
                    progress: 0,
                    active_module: null,
                    total_findings: 0,
                    modules_completed: 0,
                    modules_total: data.modules_total ?? 0,
                    started_at: data.started_at,
                    elapsed_seconds: 0,
                  }
                );

                // ── Enterprise Intelligence Events ──────────────────────────
              } else if (eventType === "enterprise_telemetry") {
                setEnterpriseTelemetry(data as EnterpriseTelemetry);

              } else if (eventType === "payload_executed") {
                setPayloadsExecuted((prev) => {
                  const next = [data as PayloadExecutedEvent, ...prev];
                  return next.length > 100 ? next.slice(0, 100) : next;
                });

              } else if (eventType === "verification_success") {
                setVerifiedFindings((prev) => {
                  const next = [...prev, data as VerificationSuccessEvent];
                  return next.length > 200 ? next.slice(next.length - 200) : next;
                });

              } else if (eventType === "attack_chain_created" || eventType === "enterprise_attack_chains") {
                // attack_chain_created = Neo4j paths, enterprise_attack_chains = correlator results
                if (data.chains) {
                  setAttackChains((prev) => {
                    const merged = [...prev, ...(data.chains as AttackChain[])];
                    return merged.length > 50 ? merged.slice(0, 50) : merged;
                  });
                }

              } else if (eventType === "enterprise_summary") {
                setEnterpriseSummary(data);
                // Merge any attack chains from summary
                if (data.attack_chains && data.attack_chains.length > 0) {
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
                setEndpointsDiscovered((prev) => {
                  const next = [...prev, data as EndpointDiscovered];
                  return next.length > 500 ? next.slice(next.length - 500) : next;
                });

              }
            } catch (e) {
              console.error("[useScanner] Failed to parse SSE data string:", dataStr, "Error:", e);
            }
          }
        }
      }
    } catch (error: any) {
      if (error.name === 'AbortError') {
        process.env.NODE_ENV === 'development' && console.log("[useScanner] SSE Stream aborted locally for", sid);
        return;
      }
      console.error("[useScanner] Critical SSE Error:", error);
      setIsScanning(false);
      if (!abortController.signal.aborted) {
        toast.error(`Scan stream error: ${error.message}`);
      }
    }
  }, [user]);

  const fetchScanReport = useCallback(async (sid: string) => {
    try {
      const token = await user?.getIdToken();
      const response = await fetch(`${API_BASE_URL}/api/v1/scan/${sid}/report`, {
        headers: {
          ...(token ? { "Authorization": `Bearer ${token}` } : {})
        }
      });
      if (!response.ok) throw new Error("Failed to fetch report");

      const data = await response.json();
      setScanResult(data);
      // Cap loaded report data to prevent state explosion on large scans
      const reportFindings: Finding[] = data.findings || [];
      const reportLogs: ScanLog[] = data.logs || [];
      totalFindingsCountRef.current = reportFindings.length;
      totalLogsCountRef.current = reportLogs.length;
      setFindings(reportFindings.slice(0, 500));
      setLogs(reportLogs.slice(-1000));
    } catch (error) {
      console.error("Failed to fetch scan report:", error);
    }
  }, [user]);

  const cancelScan = useCallback(async () => {
    if (!scanId) return;

    try {
      const token = await user?.getIdToken();
      const response = await fetch(`${API_BASE_URL}/api/v1/scan/${scanId}/cancel`, {
        method: "POST",
        headers: {
          ...(token ? { "Authorization": `Bearer ${token}` } : {})
        }
      });

      if (!response.ok) throw new Error("Failed to cancel scan");

      toast.info("Scan cancelled");

      if (eventSourceRef.current) {
        eventSourceRef.current.close();
        eventSourceRef.current = null;
      }

      setIsScanning(false);
    } catch (error) {
      toast.error("Failed to cancel scan");
    }
  }, [scanId, user]);

  // Cleanup on unmount
  useEffect(() => {
    return () => {
      if (eventSourceRef.current) {
        eventSourceRef.current.close();
      }
    };
  }, []);

  return {
    isScanning,
    scanStatus,
    findings,
    logs,
    scanResult,
    scanId,
    startScan,
    cancelScan,
    clearScan,
    // True counts: updated on every event but don't cause re-renders (refs)
    // Read via totalFindingsCount.current in UI where needed
    totalFindingsCount: totalFindingsCountRef,
    totalLogsCount: totalLogsCountRef,
    // ── Enterprise Intelligence State ──────────────────────────────────────
    enterpriseTelemetry,
    payloadsExecuted,
    verifiedFindings,
    attackChains,
    aiDecision,
    riskData,
    endpointsDiscovered,
    enterpriseSummary,
  };
}

export function useScanHistory() {
  const { user } = useAuth();
  const [scans, setScans] = useState<Array<{
    scan_id: string;
    target: string;
    status: string;
    modules: string[];
    total_findings: number;
    started_at: string | null;
    duration: number;
  }>>([]);
  const [isLoading, setIsLoading] = useState(false);
  const [isBackendAvailable, setIsBackendAvailable] = useState(true);

  const fetchScans = useCallback(async () => {
    setIsLoading(true);

    try {
      const signal = AbortSignal.timeout(15000);

      const token = await user?.getIdToken();
      const response = await fetch(`${API_BASE_URL}/api/v1/scans`, {
        signal,
        headers: {
          'Accept': 'application/json',
          'Content-Type': 'application/json',
          ...(token ? { "Authorization": `Bearer ${token}` } : {})
        },
        mode: 'cors',
      });

      if (!response.ok) {
        // Silently mark as unavailable — no error surfaced to the user
        setIsBackendAvailable(false);
        return;
      }

      const data = await response.json();
      setScans(data.scans || []);
      setIsBackendAvailable(true);
    } catch (err) {
      // Network errors and timeouts: keep existing scans, don't surface errors
      const isTimeout = err instanceof Error &&
        (err.name === 'TimeoutError' || err.name === 'AbortError' || err.message.includes('timed out'));

      if (!isTimeout) {
        // Only log unexpected errors in dev — never shown to user
        if (process.env.NODE_ENV === 'development') {
          console.debug('[useScanHistory] Backend unreachable:', err instanceof Error ? err.message : err);
        }
      }

      setIsBackendAvailable(false);
      // Preserve current scans rather than wiping them on a transient failure
    } finally {
      setIsLoading(false);
    }
  }, [user]);

  useEffect(() => {
    fetchScans();
    const interval = setInterval(fetchScans, 30000);
    return () => clearInterval(interval);
  }, [fetchScans]);

  return { scans, isLoading, isBackendAvailable, refreshScans: fetchScans };
}

export function useModules() {
  const { user } = useAuth();
  const [modules, setModules] = useState(AVAILABLE_MODULES);
  const [isLoading, setIsLoading] = useState(false);
  const [isBackendAvailable, setIsBackendAvailable] = useState(true);

  const fetchModules = useCallback(async () => {
    setIsLoading(true);
    try {
      const signal = AbortSignal.timeout(10000);

      const token = await user?.getIdToken();
      const response = await fetch(`${API_BASE_URL}/api/v1/modules`, {
        signal,
        headers: {
          'Accept': 'application/json',
          ...(token ? { "Authorization": `Bearer ${token}` } : {})
        },
        mode: 'cors'
      });

      if (!response.ok) throw new Error(`Failed to fetch modules: ${response.status}`);

      const data = await response.json();
      if (data.modules && data.modules.length > 0) {
        setModules(data.modules);
        setIsBackendAvailable(true);
      }
    } catch (error) {
      console.error("Failed to fetch modules:", error);
      setIsBackendAvailable(false);
      // Fall back to default modules
    } finally {
      setIsLoading(false);
    }
  }, [user]);

  useEffect(() => {
    fetchModules();
  }, [fetchModules]);

  return { modules, isLoading, isBackendAvailable };
}

export function useHealthCheck() {
  const [health, setHealth] = useState<{
    status: string;
    version: string;
    modules: number;
    total_patterns: number;
  } | null>(null);
  const [isHealthy, setIsHealthy] = useState(false);

  const checkHealth = useCallback(async () => {
    try {
      const signal = AbortSignal.timeout(5000);

      const response = await fetch(`${API_BASE_URL}/api/v1/health`, {
        signal,
        headers: { 'Accept': 'application/json' },
        mode: 'cors'
      });

      if (!response.ok) throw new Error("Health check failed");

      const data = await response.json();
      setHealth(data);
      setIsHealthy(data.status === "healthy");
    } catch (error) {
      setIsHealthy(false);
      setHealth(null);
    }
  }, []);

  useEffect(() => {
    checkHealth();
    const interval = setInterval(checkHealth, 30000);
    return () => clearInterval(interval);
  }, [checkHealth]);

  return { health, isHealthy, checkHealth };
}
