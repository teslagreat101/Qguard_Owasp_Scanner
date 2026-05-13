"use client";

import { useState, useCallback } from "react";
import {
  Terminal, Play, RotateCcw, CheckCircle, Layers, Save,
  Settings, ShieldCheck, AlertTriangle, Clock, Wifi,
  Lock, Globe, ChevronDown, Copy, Check, AlertCircle,
} from "lucide-react";
import { cn } from "@/lib/utils";
import { toast } from "sonner";

const API_BASE = process.env.NEXT_PUBLIC_API_URL || "http://localhost:8000";

interface POCConsoleProps {
  vulnerability: any;
  scanId?: string;
  onResult?: (result: POCResult) => void;
}

type ViewMode = "pretty" | "raw";
type ExecState = "idle" | "executing" | "streaming" | "verified" | "unconfirmed" | "failed" | "timeout" | "blocked";

interface POCResult {
  success: boolean;
  status_code?: number;
  response_time_ms?: number;
  content_type?: string;
  server?: string;
  tls_info?: Record<string, any>;
  headers?: Record<string, string>;
  body_pretty?: string;
  body_raw?: string;
  secrets_detected?: any[];
  disclosed_headers?: string[];
  evidence_match?: boolean;
  risk_verified?: boolean;
  verification_status?: string;
  redirect_count?: number;
  final_url?: string;
  error?: string;
  blocked?: boolean;
}

function StatusBadge({ code }: { code: number }) {
  const color =
    code < 300 ? "text-primary bg-primary/10 border-primary/30" :
      code < 400 ? "text-yellow-400 bg-yellow-400/10 border-yellow-400/30" :
        code < 500 ? "text-orange-400 bg-orange-400/10 border-orange-400/30" :
          "text-red-500 bg-red-500/10 border-red-500/30";
  return (
    <span className={cn("text-[9px] font-black px-2 py-0.5 rounded border uppercase", color)}>
      HTTP {code}
    </span>
  );
}

function VerificationBadge({ status }: { status: string }) {
  if (status === "VERIFIED") {
    return (
      <span className="flex items-center gap-1.5 text-[9px] font-black text-primary bg-primary/10 border border-primary/30 px-2 py-0.5 rounded uppercase tracking-widest">
        <ShieldCheck className="w-3 h-3" /> Verified
      </span>
    );
  }
  if (status === "UNCONFIRMED") {
    return (
      <span className="flex items-center gap-1.5 text-[9px] font-black text-yellow-400 bg-yellow-400/10 border border-yellow-400/30 px-2 py-0.5 rounded uppercase tracking-widest">
        <AlertTriangle className="w-3 h-3" /> Unconfirmed
      </span>
    );
  }
  if (status === "BLOCKED") {
    return (
      <span className="flex items-center gap-1.5 text-[9px] font-black text-red-400 bg-red-400/10 border border-red-400/30 px-2 py-0.5 rounded uppercase tracking-widest">
        <Lock className="w-3 h-3" /> Blocked (SSRF)
      </span>
    );
  }
  if (status === "TIMEOUT") {
    return (
      <span className="flex items-center gap-1.5 text-[9px] font-black text-muted-foreground bg-muted/50 border border-border px-2 py-0.5 rounded uppercase tracking-widest">
        <Clock className="w-3 h-3" /> Timeout
      </span>
    );
  }
  return (
    <span className="flex items-center gap-1.5 text-[9px] font-black text-red-400 bg-red-400/10 border border-red-400/30 px-2 py-0.5 rounded uppercase tracking-widest">
      <AlertCircle className="w-3 h-3" /> Failed
    </span>
  );
}

export function POCConsole({ vulnerability, scanId, onResult }: POCConsoleProps) {
  const [method, setMethod] = useState(vulnerability.method || "GET");
  const [path, setPath] = useState(
    vulnerability.path || vulnerability.file || vulnerability.endpoint || "/api/v1/endpoint"
  );
  const [headers, setHeaders] = useState(
    "Content-Type: application/json\nUser-Agent: SecurityScanner/5.0"
  );
  const [payload, setPayload] = useState(
    vulnerability.matched_content
      ? JSON.stringify({ probe: vulnerability.matched_content.slice(0, 200) }, null, 2)
      : JSON.stringify({ username: "' OR 1=1 --", password: "password123" }, null, 2)
  );

  const [result, setResult] = useState<POCResult | null>(null);
  const [execState, setExecState] = useState<ExecState>("idle");
  const [viewMode, setViewMode] = useState<ViewMode>("pretty");
  const [showHeaders, setShowHeaders] = useState(false);
  const [copiedBody, setCopiedBody] = useState(false);

  // Parse headers textarea into dict
  const parseHeaders = useCallback((): Record<string, string> => {
    const out: Record<string, string> = {};
    headers.split("\n").forEach((line) => {
      const sep = line.indexOf(":");
      if (sep > 0) {
        out[line.slice(0, sep).trim()] = line.slice(sep + 1).trim();
      }
    });
    return out;
  }, [headers]);

  const handleExecute = useCallback(async () => {
    if (execState === "executing") return;
    setExecState("executing");
    setResult(null);

    // Build target URL — if path is relative, use evidence endpoint or skip prefix
    let targetUrl = path.trim();
    if (!targetUrl.startsWith("http://") && !targetUrl.startsWith("https://")) {
      // Try to extract base URL from the vulnerability target
      const baseTarget = vulnerability.target || vulnerability.endpoint || "";
      if (baseTarget.startsWith("http")) {
        const origin = new URL(baseTarget).origin;
        targetUrl = origin + (targetUrl.startsWith("/") ? targetUrl : "/" + targetUrl);
      } else {
        // Cannot make relative URL absolute — run through backend proxy as-is
        targetUrl = "https://" + targetUrl;
      }
    }

    try {
      const res = await fetch(`${API_BASE}/api/poc/execute`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          method,
          url: targetUrl,
          headers: parseHeaders(),
          body: method !== "GET" && method !== "DELETE" ? payload : "",
          scan_id: scanId || "",
          finding_id: vulnerability.id || "",
          finding_evidence: vulnerability.matched_content || vulnerability.evidence || "",
        }),
        signal: AbortSignal.timeout(30000),
      });

      const data: POCResult = await res.json();
      setResult(data);
      onResult?.(data);

      const vs = data.verification_status || "FAILED";
      if (vs === "VERIFIED") {
        setExecState("verified");
        toast.success("Vulnerability VERIFIED — evidence matched live response", { icon: "🛡" });
      } else if (vs === "BLOCKED") {
        setExecState("blocked");
        toast.error("SSRF attempt blocked — target resolved to internal IP");
      } else if (vs === "TIMEOUT") {
        setExecState("timeout");
        toast.warning("Request timed out — target may be unreachable");
      } else if (vs === "UNCONFIRMED") {
        setExecState("unconfirmed");
        toast.info("Request succeeded — evidence correlation inconclusive");
      } else {
        setExecState("failed");
        toast.error(data.error ? `Execution failed: ${data.error}` : "POC execution failed");
      }
    } catch (err: any) {
      const isTimeout = err?.name === "AbortError" || err?.name === "TimeoutError" || String(err).includes("timed out") || String(err).includes("timeout");
      if (isTimeout) {
        setResult({ success: false, error: "Request timed out — the target may be slow or unreachable. Try increasing timeout or checking the URL.", verification_status: "TIMEOUT" });
        setExecState("timeout");
        toast.warning("POC request timed out — target may be unreachable");
      } else {
        const msg = String(err?.message || err);
        setResult({ success: false, error: msg, verification_status: "ERROR" });
        setExecState("failed");
        toast.error(`POC execution error: ${msg}`);
      }
    }
  }, [execState, method, path, headers, payload, parseHeaders, vulnerability, scanId]);

  const handleReset = useCallback(() => {
    setPath(vulnerability.path || vulnerability.file || vulnerability.endpoint || "/api/v1/endpoint");
    setResult(null);
    setExecState("idle");
  }, [vulnerability]);

  const copyBody = useCallback(() => {
    const text = viewMode === "pretty" ? (result?.body_pretty || "") : (result?.body_raw || "");
    navigator.clipboard.writeText(text).then(() => {
      setCopiedBody(true);
      setTimeout(() => setCopiedBody(false), 2000);
    });
  }, [result, viewMode]);

  const bodyText = viewMode === "pretty" ? (result?.body_pretty || result?.body_raw || "") : (result?.body_raw || "");

  const stateLabel: Record<ExecState, string> = {
    idle: "Ready for payload injection",
    executing: "Executing live HTTP request...",
    streaming: "Streaming response...",
    verified: "Vulnerability confirmed via live evidence",
    unconfirmed: "Response received — evidence inconclusive",
    failed: "Execution failed or target unreachable",
    timeout: "Request timed out",
    blocked: "SSRF target blocked by security policy",
  };

  const stateColor: Record<ExecState, string> = {
    idle: "text-primary",
    executing: "text-blue-500",
    streaming: "text-blue-500",
    verified: "text-primary",
    unconfirmed: "text-yellow-400",
    failed: "text-destructive",
    timeout: "text-muted-foreground",
    blocked: "text-destructive",
  };

  return (
    <div className="bg-background border border-border rounded-2xl flex flex-col h-[700px] shadow-2xl overflow-hidden">
      {/* ── Console Header ── */}
      <div className="flex items-center justify-between p-4 bg-muted/30 border-b border-border">
        <div className="flex items-center gap-3">
          <div className="p-2 rounded-lg bg-primary/10 border border-primary/20">
            <Terminal className="w-4 h-4 text-primary" />
          </div>
          <div>
            <h4 className="text-[11px] font-black text-foreground uppercase tracking-widest leading-tight">
              POC Execution Console
            </h4>
            <p className={cn("text-[9px] font-bold uppercase tracking-[0.2em] mt-0.5 transition-colors", stateColor[execState],
              execState === "executing" && "animate-pulse"
            )}>
              {stateLabel[execState]}
            </p>
          </div>
        </div>

        <div className="flex items-center gap-2">
          {/* Live indicator */}
          {execState === "executing" && (
            <div className="flex items-center gap-1.5 px-2 py-1 rounded-lg bg-blue-500/10 border border-blue-500/20">
              <div className="w-1.5 h-1.5 rounded-full bg-blue-500 animate-ping" />
              <span className="text-[9px] font-black text-blue-500 uppercase tracking-widest">Live</span>
            </div>
          )}
          <button type="button" className="p-2 text-muted-foreground hover:text-foreground transition-colors" title="Save">
            <Save className="w-4 h-4" />
          </button>
          <button type="button" onClick={handleReset} className="p-2 text-muted-foreground hover:text-foreground transition-colors" title="Reset">
            <RotateCcw className="w-4 h-4" />
          </button>
          <button type="button" className="p-2 text-muted-foreground hover:text-foreground transition-colors" title="Settings">
            <Settings className="w-4 h-4" />
          </button>
        </div>
      </div>

      {/* ── Editor Area ── */}
      <div className="flex-1 overflow-hidden grid grid-rows-2">
        {/* Top: Request Editor */}
        <div className="border-b border-border p-4 flex flex-col gap-4 overflow-hidden">
          {/* Method + URL bar */}
          <div className="flex items-center gap-2 bg-secondary/50 border border-border rounded-xl p-1.5 focus-within:border-primary/40 transition-all">
            <select
              value={method}
              onChange={(e) => setMethod(e.target.value)}
              className="bg-background text-[10px] font-black text-primary rounded-lg px-3 py-1.5 border border-border outline-none"
            >
              <option>GET</option>
              <option>POST</option>
              <option>PUT</option>
              <option>DELETE</option>
            </select>
            <input
              type="text"
              value={path}
              onChange={(e) => setPath(e.target.value)}
              className="bg-transparent flex-1 text-xs font-mono text-foreground px-2 outline-none"
              placeholder="https://target.example.com/api/route"
            />
            {path.startsWith("https://") && (
              <Lock className="w-3.5 h-3.5 text-primary/50 mr-1 shrink-0" />
            )}
            {path.startsWith("http://") && (
              <Globe className="w-3.5 h-3.5 text-yellow-400/50 mr-1 shrink-0" />
            )}
          </div>

          {/* Headers + Body */}
          <div className="flex-1 grid grid-cols-2 gap-4 overflow-hidden">
            <div className="flex flex-col gap-2">
              <p className="text-[9px] text-muted-foreground font-bold uppercase tracking-widest pl-1">Headers</p>
              <textarea
                value={headers}
                onChange={(e) => setHeaders(e.target.value)}
                className="flex-1 bg-secondary/30 border border-border rounded-xl p-3 text-[11px] font-mono text-muted-foreground outline-none focus:border-primary/20 transition-all resize-none"
              />
            </div>
            <div className="flex flex-col gap-2">
              <p className="text-[9px] text-muted-foreground font-bold uppercase tracking-widest pl-1">Request Body (JSON)</p>
              <textarea
                value={payload}
                onChange={(e) => setPayload(e.target.value)}
                className="flex-1 bg-secondary/30 border border-border rounded-xl p-3 text-[11px] font-mono text-muted-foreground outline-none focus:border-primary/20 transition-all resize-none shadow-inner"
              />
            </div>
          </div>
        </div>

        {/* Bottom: Response Viewer */}
        <div className="p-4 flex flex-col gap-3 bg-card overflow-hidden">
          {/* Response metadata bar */}
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-2 flex-wrap">
              <p className="text-[9px] text-muted-foreground font-bold uppercase tracking-widest">HTTP Response</p>

              {result?.status_code && <StatusBadge code={result.status_code} />}

              {result?.response_time_ms !== undefined && (
                <span className="flex items-center gap-1 text-[9px] font-black text-muted-foreground bg-secondary px-2 py-0.5 rounded border border-border uppercase">
                  <Clock className="w-2.5 h-2.5" />
                  {result.response_time_ms}ms
                </span>
              )}

              {result?.server && result.server !== "—" && (
                <span className="text-[9px] font-black text-muted-foreground bg-secondary px-2 py-0.5 rounded border border-border uppercase">
                  {result.server}
                </span>
              )}

              {result?.verification_status && (
                <VerificationBadge status={result.verification_status} />
              )}

              {(result?.secrets_detected?.length ?? 0) > 0 && (
                <span className="text-[9px] font-black text-red-400 bg-red-400/10 border border-red-400/20 px-2 py-0.5 rounded uppercase">
                  {result!.secrets_detected!.length} secret{result!.secrets_detected!.length !== 1 ? "s" : ""} detected
                </span>
              )}
            </div>

            <div className="flex items-center gap-2">
              {/* Info disclosure badge */}
              {(result?.disclosed_headers?.length ?? 0) > 0 && (
                <button
                  type="button"
                  onClick={() => setShowHeaders((v) => !v)}
                  className="flex items-center gap-1 text-[9px] font-black text-orange-400 bg-orange-400/10 border border-orange-400/20 px-2 py-0.5 rounded uppercase hover:bg-orange-400/20 transition-colors"
                >
                  <ChevronDown className={cn("w-2.5 h-2.5 transition-transform", showHeaders && "rotate-180")} />
                  Headers ({result!.disclosed_headers!.length})
                </button>
              )}

              {/* Copy body */}
              {result && (
                <button
                  type="button"
                  onClick={copyBody}
                  className="p-1.5 text-muted-foreground hover:text-foreground transition-colors"
                  title="Copy response body"
                >
                  {copiedBody ? <Check className="w-3.5 h-3.5 text-primary" /> : <Copy className="w-3.5 h-3.5" />}
                </button>
              )}

              {/* Pretty / Raw toggle */}
              <div className="flex bg-secondary border border-border rounded-lg p-0.5">
                <button
                  type="button"
                  onClick={() => setViewMode("pretty")}
                  className={cn(
                    "px-3 py-1 rounded-md text-[9px] font-black uppercase tracking-widest transition-colors",
                    viewMode === "pretty" ? "text-primary bg-primary/10" : "text-muted-foreground"
                  )}
                >
                  Pretty
                </button>
                <button
                  type="button"
                  onClick={() => setViewMode("raw")}
                  className={cn(
                    "px-3 py-1 rounded-md text-[9px] font-black uppercase tracking-widest transition-colors",
                    viewMode === "raw" ? "text-primary bg-primary/10" : "text-muted-foreground"
                  )}
                >
                  Raw
                </button>
              </div>
            </div>
          </div>

          {/* Disclosed headers detail */}
          {showHeaders && result?.disclosed_headers && result.disclosed_headers.length > 0 && result.headers && (
            <div className="bg-orange-400/5 border border-orange-400/20 rounded-xl p-3 space-y-1">
              <p className="text-[9px] font-black text-orange-400 uppercase tracking-widest mb-2">
                Information Disclosure Headers
              </p>
              {result.disclosed_headers.map((h) => (
                <div key={h} className="flex items-center gap-2 font-mono text-[10px]">
                  <span className="text-orange-400/70">{h}:</span>
                  <span className="text-muted-foreground">{result.headers![h]}</span>
                </div>
              ))}
            </div>
          )}

          {/* Response body */}
          <div className="flex-1 bg-secondary/30 border border-border rounded-xl p-4 overflow-y-auto no-scrollbar relative font-mono text-[11px] leading-relaxed">
            {execState === "executing" ? (
              <div className="absolute inset-0 flex items-center justify-center bg-background/50 backdrop-blur-sm z-10">
                <div className="flex flex-col items-center gap-4">
                  <div className="relative">
                    <div className="w-10 h-10 border-2 border-primary/20 border-t-primary rounded-full animate-spin" />
                    <Wifi className="w-4 h-4 text-primary/60 absolute inset-0 m-auto" />
                  </div>
                  <div className="text-center space-y-1">
                    <p className="text-[10px] font-black text-primary uppercase tracking-[0.3em] animate-pulse">
                      Executing Live HTTP Request...
                    </p>
                    <p className="text-[9px] text-muted-foreground font-bold uppercase tracking-widest">
                      {method} → {path.slice(0, 50)}{path.length > 50 ? "…" : ""}
                    </p>
                  </div>
                </div>
              </div>
            ) : result ? (
              result.success ? (
                <pre className="text-muted-foreground select-all whitespace-pre-wrap break-words">
                  {bodyText || "(empty response body)"}
                </pre>
              ) : (
                <div className="flex flex-col gap-3 text-center py-4">
                  <AlertCircle className="w-8 h-8 text-destructive mx-auto" />
                  <p className="text-[10px] font-black text-destructive uppercase tracking-widest">
                    {result.verification_status || "ERROR"}
                  </p>
                  <p className="text-[10px] text-muted-foreground font-mono leading-relaxed max-w-xs mx-auto">
                    {result.error}
                  </p>
                </div>
              )
            ) : (
              <div className="h-full flex flex-col items-center justify-center text-muted-foreground p-8 text-center opacity-40">
                <Layers className="w-12 h-12 mb-4" />
                <p className="text-[10px] font-bold uppercase tracking-widest leading-relaxed">
                  No response data available.<br />
                  Click Execute to send a real HTTP request to the target.
                </p>
              </div>
            )}
          </div>
        </div>
      </div>

      {/* ── Footer Controls ── */}
      <div className="p-4 bg-muted/80 border-t border-border grid grid-cols-3 gap-4">
        <button
          onClick={handleExecute}
          disabled={execState === "executing"}
          className="col-span-2 group/execute relative overflow-hidden flex items-center justify-center gap-3 bg-gradient-to-r from-primary to-blue-500 py-3 rounded-xl font-black text-[11px] text-primary-foreground uppercase tracking-widest transition-all hover:scale-[1.02] active:scale-[0.98] shadow-lg disabled:opacity-50"
        >
          <Play className="w-4 h-4 fill-current" />
          <span>{execState === "executing" ? "Executing…" : "Execute POC"}</span>
          <div className="absolute -inset-1 bg-white/20 -translate-x-full group-hover/execute:translate-x-full transition-transform duration-1000 skew-x-12" />
        </button>

        <button
          type="button"
          disabled={!result}
          onClick={() => {
            if (result?.verification_status === "VERIFIED") {
              toast.success("Validated: vulnerability confirmed with live evidence");
            } else if (result) {
              toast.info("Run POC first to generate live evidence for validation");
            }
          }}
          className={cn(
            "flex items-center justify-center gap-2 border py-3 rounded-xl font-black text-[11px] uppercase tracking-widest transition-all",
            result?.verification_status === "VERIFIED"
              ? "bg-primary/10 border-primary/30 text-primary hover:bg-primary/20"
              : "bg-secondary border-border text-foreground hover:bg-secondary/80 hover:border-primary/30"
          )}
        >
          <CheckCircle className="w-4 h-4" />
          Validate
        </button>
      </div>
    </div>
  );
}
