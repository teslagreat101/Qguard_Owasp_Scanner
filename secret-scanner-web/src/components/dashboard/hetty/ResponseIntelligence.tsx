"use client";

import React, { useState, useEffect, useRef, useCallback } from "react";
import {
  Shield, AlertTriangle, Database, Server, Globe, Eye,
  Lock, Unlock, Fingerprint, Loader2, RefreshCw,
  ChevronDown, ChevronRight, Copy, Check, FileWarning,
} from "lucide-react";
import { cn } from "@/lib/utils";
import { toast } from "sonner";

const API_BASE = process.env.NEXT_PUBLIC_API_URL || "http://localhost:8000";

/* ------------------------------------------------------------------ */
/*  Types                                                              */
/* ------------------------------------------------------------------ */

interface PatternMatch {
  type: string;
  detail: string;
  severity: "critical" | "high" | "medium" | "low";
  evidence?: string;
}

interface ResponseIntelResult {
  patterns: PatternMatch[];
  database_type: string | null;
  framework: string | null;
  internal_ips: string[];
  tokens_exposed: string[];
  stack_trace_detected: boolean;
  reflected_parameters: string[];
  missing_security_headers: string[];
}

interface ResponseIntelligenceProps {
  statusCode: number;
  headers: Record<string, string>;
  body: string;
  requestBody: string;
  targetUrl: string;
}

/* ------------------------------------------------------------------ */
/*  Severity helpers                                                    */
/* ------------------------------------------------------------------ */

const SEVERITY_STYLES: Record<string, string> = {
  critical: "text-red-400 bg-red-400/10 border-red-400/20",
  high: "text-orange-400 bg-orange-400/10 border-orange-400/20",
  medium: "text-yellow-400 bg-yellow-400/10 border-yellow-400/20",
  low: "text-muted-foreground bg-muted/10 border-border/20",
};

const SEVERITY_DOT: Record<string, string> = {
  critical: "bg-red-400",
  high: "bg-orange-400",
  medium: "bg-yellow-400",
  low: "bg-muted",
};

function maskToken(token: string): string {
  if (token.length <= 8) return "****";
  return token.slice(0, 4) + "****" + token.slice(-4);
}

/* ------------------------------------------------------------------ */
/*  Component                                                          */
/* ------------------------------------------------------------------ */

export function ResponseIntelligence({
  statusCode,
  headers,
  body,
  requestBody,
  targetUrl,
}: ResponseIntelligenceProps) {
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState<ResponseIntelResult | null>(null);
  const [expandedPatterns, setExpandedPatterns] = useState(true);
  const [expandedHeaders, setExpandedHeaders] = useState(false);
  const [copied, setCopied] = useState<string | null>(null);
  const lastFetchRef = useRef<string>("");

  const fingerprint = `${statusCode}::${targetUrl}::${body.slice(0, 256)}`;

  const fetchIntel = useCallback(async () => {
    if (!targetUrl.trim()) return;
    if (lastFetchRef.current === fingerprint && result) return;

    lastFetchRef.current = fingerprint;
    setLoading(true);

    try {
      const res = await fetch(`${API_BASE}/api/hetty/ai/response-intel`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          status_code: statusCode,
          headers,
          body,
          request_body: requestBody,
          target_url: targetUrl,
        }),
      });

      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      const data: ResponseIntelResult = await res.json();
      setResult(data);
    } catch (err) {
      toast.error("Response intel failed");
      console.error(err);
    } finally {
      setLoading(false);
    }
  }, [statusCode, headers, body, requestBody, targetUrl, fingerprint, result]);

  useEffect(() => {
    fetchIntel();
  }, [fetchIntel]);

  const copyText = useCallback((text: string, key: string) => {
    navigator.clipboard.writeText(text);
    setCopied(key);
    setTimeout(() => setCopied(null), 1500);
  }, []);

  /* ---------------------------------------------------------------- */
  /*  Render                                                           */
  /* ---------------------------------------------------------------- */

  return (
    <div className="w-full rounded border border-primary/10 bg-background overflow-hidden">
      {/* Header */}
      <div className="flex items-center justify-between px-3 py-2 border-b border-primary/10 bg-primary/[0.03]">
        <div className="flex items-center gap-2">
          <Fingerprint className="h-3.5 w-3.5 text-primary" />
          <span className="text-[10px] font-black uppercase tracking-widest text-primary">
            Response Intelligence
          </span>
        </div>
        <button
          onClick={() => { lastFetchRef.current = ""; fetchIntel(); }}
          disabled={loading}
          className={cn(
            "p-1 rounded transition-opacity duration-150",
            "hover:bg-primary/10 text-primary/60 hover:text-primary",
            loading && "opacity-40 cursor-not-allowed"
          )}
        >
          {loading ? (
            <Loader2 className="h-3 w-3 animate-spin" />
          ) : (
            <RefreshCw className="h-3 w-3" />
          )}
        </button>
      </div>

      {/* Loading state */}
      {loading && !result && (
        <div className="flex items-center justify-center gap-2 py-8">
          <Loader2 className="h-4 w-4 animate-spin text-primary/60" />
          <span className="text-[9px] font-black uppercase tracking-widest text-primary/40">
            Analyzing response
          </span>
        </div>
      )}

      {/* No result */}
      {!loading && !result && (
        <div className="flex items-center justify-center py-8">
          <span className="text-[9px] uppercase tracking-widest text-foreground/20">
            No intelligence data
          </span>
        </div>
      )}

      {/* Results */}
      {result && (
        <div className="divide-y divide-[#00FF88]/5">
          {/* Detection summary row */}
          <div className="px-3 py-2 flex flex-wrap gap-2">
            {result.database_type && (
              <div className="flex items-center gap-1 px-2 py-0.5 rounded border border-[#00A3FF]/20 bg-[#00A3FF]/5">
                <Database className="h-2.5 w-2.5 text-[#00A3FF]" />
                <span className="text-[8px] font-black uppercase tracking-widest text-[#00A3FF]">
                  {result.database_type}
                </span>
              </div>
            )}
            {result.framework && (
              <div className="flex items-center gap-1 px-2 py-0.5 rounded border border-purple-400/20 bg-purple-400/5">
                <Server className="h-2.5 w-2.5 text-purple-400" />
                <span className="text-[8px] font-black uppercase tracking-widest text-purple-400">
                  {result.framework}
                </span>
              </div>
            )}
            {result.stack_trace_detected && (
              <div className="flex items-center gap-1 px-2 py-0.5 rounded border border-red-400/20 bg-red-400/5">
                <FileWarning className="h-2.5 w-2.5 text-red-400" />
                <span className="text-[8px] font-black uppercase tracking-widest text-red-400">
                  Stack Trace
                </span>
              </div>
            )}
          </div>

          {/* Patterns section */}
          {result.patterns.length > 0 && (
            <div>
              <button
                onClick={() => setExpandedPatterns(!expandedPatterns)}
                className="w-full flex items-center gap-1.5 px-3 py-1.5 hover:bg-white/[0.02] transition-opacity duration-150"
              >
                {expandedPatterns ? (
                  <ChevronDown className="h-2.5 w-2.5 text-primary/50" />
                ) : (
                  <ChevronRight className="h-2.5 w-2.5 text-primary/50" />
                )}
                <AlertTriangle className="h-2.5 w-2.5 text-primary" />
                <span className="text-[9px] font-black uppercase tracking-widest text-foreground/70">
                  Patterns
                </span>
                <span className="ml-auto text-[8px] font-black text-primary/60">
                  {result.patterns.length}
                </span>
              </button>
              {expandedPatterns && (
                <div className="px-3 pb-2 space-y-1">
                  {result.patterns.map((p, i) => (
                    <div
                      key={i}
                      className="flex items-start gap-2 px-2 py-1.5 rounded bg-white/[0.02] border border-white/[0.04]"
                    >
                      <div className={cn("w-1.5 h-1.5 rounded-full mt-1 shrink-0", SEVERITY_DOT[p.severity])} />
                      <div className="flex-1 min-w-0">
                        <div className="flex items-center gap-1.5">
                          <span className="text-[9px] font-bold text-foreground/80 truncate">
                            {p.type}
                          </span>
                          <span
                            className={cn(
                              "text-[7px] font-black uppercase tracking-widest px-1.5 py-0.5 rounded border",
                              SEVERITY_STYLES[p.severity]
                            )}
                          >
                            {p.severity}
                          </span>
                        </div>
                        <p className="text-[8px] text-foreground/40 mt-0.5 leading-relaxed">
                          {p.detail}
                        </p>
                        {p.evidence && (
                          <div className="mt-1 flex items-center gap-1">
                            <code className="text-[7px] text-primary/60 bg-primary/5 px-1 py-0.5 rounded font-mono truncate max-w-[200px]">
                              {p.evidence}
                            </code>
                            <button
                              onClick={() => copyText(p.evidence!, `ev-${i}`)}
                              className="p-0.5 hover:bg-white/5 rounded transition-opacity duration-150"
                            >
                              {copied === `ev-${i}` ? (
                                <Check className="h-2 w-2 text-primary" />
                              ) : (
                                <Copy className="h-2 w-2 text-foreground/20" />
                              )}
                            </button>
                          </div>
                        )}
                      </div>
                    </div>
                  ))}
                </div>
              )}
            </div>
          )}

          {/* Internal IPs */}
          {result.internal_ips.length > 0 && (
            <div className="px-3 py-2">
              <div className="flex items-center gap-1.5 mb-1.5">
                <Globe className="h-2.5 w-2.5 text-orange-400" />
                <span className="text-[9px] font-black uppercase tracking-widest text-foreground/70">
                  Internal IPs
                </span>
              </div>
              <div className="flex flex-wrap gap-1">
                {result.internal_ips.map((ip, i) => (
                  <div
                    key={i}
                    className="flex items-center gap-1 px-1.5 py-0.5 rounded bg-orange-400/5 border border-orange-400/15"
                  >
                    <code className="text-[8px] font-mono text-orange-400">{ip}</code>
                    <button
                      onClick={() => copyText(ip, `ip-${i}`)}
                      className="p-0.5 hover:bg-white/5 rounded transition-opacity duration-150"
                    >
                      {copied === `ip-${i}` ? (
                        <Check className="h-2 w-2 text-primary" />
                      ) : (
                        <Copy className="h-2 w-2 text-foreground/20" />
                      )}
                    </button>
                  </div>
                ))}
              </div>
            </div>
          )}

          {/* Tokens exposed (masked) */}
          {result.tokens_exposed.length > 0 && (
            <div className="px-3 py-2">
              <div className="flex items-center gap-1.5 mb-1.5">
                <Unlock className="h-2.5 w-2.5 text-red-400" />
                <span className="text-[9px] font-black uppercase tracking-widest text-foreground/70">
                  Tokens Exposed
                </span>
                <span className="text-[7px] font-black text-red-400/60 uppercase tracking-widest">
                  masked
                </span>
              </div>
              <div className="space-y-1">
                {result.tokens_exposed.map((token, i) => (
                  <div
                    key={i}
                    className="flex items-center gap-1.5 px-2 py-1 rounded bg-red-400/5 border border-red-400/10"
                  >
                    <Lock className="h-2.5 w-2.5 text-red-400/50 shrink-0" />
                    <code className="text-[8px] font-mono text-red-400/70 truncate">
                      {maskToken(token)}
                    </code>
                  </div>
                ))}
              </div>
            </div>
          )}

          {/* Reflected parameters */}
          {result.reflected_parameters.length > 0 && (
            <div className="px-3 py-2">
              <div className="flex items-center gap-1.5 mb-1.5">
                <Eye className="h-2.5 w-2.5 text-yellow-400" />
                <span className="text-[9px] font-black uppercase tracking-widest text-foreground/70">
                  Reflected Parameters
                </span>
              </div>
              <div className="flex flex-wrap gap-1">
                {result.reflected_parameters.map((param, i) => (
                  <span
                    key={i}
                    className="text-[8px] font-mono text-yellow-400 bg-yellow-400/5 border border-yellow-400/15 px-1.5 py-0.5 rounded"
                  >
                    {param}
                  </span>
                ))}
              </div>
            </div>
          )}

          {/* Missing security headers */}
          {result.missing_security_headers.length > 0 && (
            <div>
              <button
                onClick={() => setExpandedHeaders(!expandedHeaders)}
                className="w-full flex items-center gap-1.5 px-3 py-1.5 hover:bg-white/[0.02] transition-opacity duration-150"
              >
                {expandedHeaders ? (
                  <ChevronDown className="h-2.5 w-2.5 text-primary/50" />
                ) : (
                  <ChevronRight className="h-2.5 w-2.5 text-primary/50" />
                )}
                <Shield className="h-2.5 w-2.5 text-[#00A3FF]" />
                <span className="text-[9px] font-black uppercase tracking-widest text-foreground/70">
                  Missing Security Headers
                </span>
                <span className="ml-auto text-[8px] font-black text-red-400/60">
                  {result.missing_security_headers.length}
                </span>
              </button>
              {expandedHeaders && (
                <div className="px-3 pb-2 space-y-0.5">
                  {result.missing_security_headers.map((hdr, i) => (
                    <div
                      key={i}
                      className="flex items-center gap-1.5 px-2 py-1 rounded bg-white/[0.02]"
                    >
                      <div className="w-1 h-1 rounded-full bg-red-400/60" />
                      <code className="text-[8px] font-mono text-foreground/50">{hdr}</code>
                    </div>
                  ))}
                </div>
              )}
            </div>
          )}
        </div>
      )}
    </div>
  );
}
