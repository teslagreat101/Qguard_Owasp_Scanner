"use client";

import React, { useState, useCallback } from "react";
import {
  Zap, Play, Loader2, AlertTriangle, CheckCircle, XCircle,
  BarChart3, Clock, ArrowUpDown, ChevronRight, Copy, Check,
} from "lucide-react";
import { cn } from "@/lib/utils";
import { toast } from "sonner";

const API_BASE = process.env.NEXT_PUBLIC_API_URL || "http://localhost:8000";

interface FuzzAnomaly {
  type: string;
  detail: string;
  severity: string;
}

interface FuzzResultItem {
  mutation: string;
  parameter: string;
  original?: string;
  payload: string;
  status_code?: number;
  response_length?: number;
  response_time_ms?: number;
  is_anomaly: boolean;
  anomaly_score?: number;
  anomalies?: FuzzAnomaly[];
  recommendation?: string;
  error?: string;
}

interface FuzzSession {
  session_id: string;
  total_mutations: number;
  anomalies_found: number;
  baseline: {
    status: number;
    length: number;
    time_ms: number;
  };
  results: FuzzResultItem[];
}

interface AdaptiveFuzzerProps {
  method: string;
  url: string;
  headers: Record<string, string>;
  cookies: Record<string, string>;
  params: Record<string, string>;
  body: string;
  initialParam?: string;
  initialLocation?: string;
  initialVulnTypes?: string[];
  onSelectPayload?: (payload: string, param: string) => void;
}

const SEVERITY_COLORS: Record<string, string> = {
  critical: "text-red-400 bg-red-500/10 border-red-500/20",
  high: "text-orange-400 bg-orange-500/10 border-orange-500/20",
  medium: "text-yellow-400 bg-yellow-500/10 border-yellow-500/20",
  low: "text-muted-foreground bg-muted/10 border-border/20",
};

export function AdaptiveFuzzer({
  method, url, headers, cookies, params, body,
  initialParam, initialLocation, initialVulnTypes,
  onSelectPayload,
}: AdaptiveFuzzerProps) {
  const [targetParam, setTargetParam] = useState(initialParam || "");
  const [targetLocation, setTargetLocation] = useState(initialLocation || "param");
  const [maxMutations, setMaxMutations] = useState(20);
  const [loading, setLoading] = useState(false);
  const [session, setSession] = useState<FuzzSession | null>(null);
  const [sortBy, setSortBy] = useState<"default" | "anomaly" | "time" | "status">("default");
  const [expandedResult, setExpandedResult] = useState<number | null>(null);
  const [copied, setCopied] = useState<string | null>(null);

  // Available parameters from the request
  const availableParams = {
    param: Object.keys(params),
    header: Object.keys(headers),
    cookie: Object.keys(cookies),
    body: body ? ["request_body"] : [],
  };

  const allParams = Object.entries(availableParams).flatMap(([loc, names]) =>
    names.map(n => ({ name: n, location: loc }))
  );

  const startFuzz = useCallback(async () => {
    if (!url.trim()) {
      toast.error("Enter a URL first");
      return;
    }
    if (!targetParam.trim()) {
      toast.error("Select a parameter to fuzz");
      return;
    }

    setLoading(true);
    setSession(null);

    try {
      const res = await fetch(`${API_BASE}/api/hetty/ai/fuzz`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          url, method, headers, cookies, params, body,
          target_param: targetParam,
          target_location: targetLocation,
          vuln_types: initialVulnTypes || [],
          max_mutations: maxMutations,
        }),
        signal: AbortSignal.timeout(120000),
      });

      const data = await res.json();
      if (data.success) {
        setSession(data);
        const anom = data.anomalies_found || 0;
        if (anom > 0) {
          toast.warning(`Fuzzing complete: ${anom} anomal${anom === 1 ? "y" : "ies"} detected!`);
        } else {
          toast.success(`Fuzzing complete: ${data.total_mutations} mutations tested`);
        }
      } else {
        toast.error(data.error || "Fuzzing failed");
      }
    } catch (err: any) {
      toast.error(err.message || "Fuzzing failed");
    } finally {
      setLoading(false);
    }
  }, [url, method, headers, cookies, params, body, targetParam, targetLocation, maxMutations, initialVulnTypes]);

  const sortedResults = session?.results
    ? [...session.results].sort((a, b) => {
        if (sortBy === "anomaly") return (b.anomaly_score || 0) - (a.anomaly_score || 0);
        if (sortBy === "time") return (b.response_time_ms || 0) - (a.response_time_ms || 0);
        if (sortBy === "status") return (a.status_code || 0) - (b.status_code || 0);
        return 0;
      })
    : session?.results || [];

  const copyValue = (v: string) => {
    navigator.clipboard.writeText(v);
    setCopied(v);
    setTimeout(() => setCopied(null), 2000);
  };

  return (
    <div className="space-y-4">
      {/* Header */}
      <div className="flex items-center gap-2.5">
        <div className="w-8 h-8 rounded-lg bg-gradient-to-br from-[#00A3FF]/20 to-purple-500/10 border border-[#00A3FF]/20 flex items-center justify-center">
          <Zap className="w-4 h-4 text-[#00A3FF]" />
        </div>
        <div>
          <h3 className="text-[11px] font-black text-foreground uppercase tracking-widest">Adaptive Fuzzing Engine</h3>
          <p className="text-[8px] text-muted-foreground font-bold uppercase tracking-widest">
            AI-Guided Parameter Mutation + Anomaly Detection
          </p>
        </div>
      </div>

      {/* Configuration */}
      <div className="grid grid-cols-3 gap-2">
        {/* Target Param */}
        <div className="space-y-1">
          <label htmlFor="fuzz-param" className="text-[8px] font-bold text-muted-foreground uppercase tracking-widest">Target Parameter</label>
          <select
            id="fuzz-param"
            value={`${targetLocation}:${targetParam}`}
            onChange={e => {
              const [loc, name] = e.target.value.split(":", 2);
              setTargetLocation(loc);
              setTargetParam(name);
            }}
            className="w-full bg-background/40 border border-white/10 rounded-lg px-2 py-1.5 text-[10px] font-mono text-muted-foreground focus:border-primary/30 focus:outline-none"
          >
            <option value=":">Select parameter</option>
            {allParams.map(p => (
              <option key={`${p.location}:${p.name}`} value={`${p.location}:${p.name}`}>
                [{p.location}] {p.name}
              </option>
            ))}
            <option value={`param:${targetParam || "custom"}`}>Custom: {targetParam || "type below"}</option>
          </select>
          <input
            className="w-full bg-background/40 border border-white/10 rounded-lg px-2 py-1 text-[10px] font-mono text-muted-foreground placeholder:text-muted-foreground focus:border-primary/30 focus:outline-none"
            placeholder="Or type param name"
            value={targetParam}
            onChange={e => setTargetParam(e.target.value)}
          />
        </div>

        {/* Location */}
        <div className="space-y-1">
          <label htmlFor="fuzz-location" className="text-[8px] font-bold text-muted-foreground uppercase tracking-widest">Location</label>
          <select
            id="fuzz-location"
            value={targetLocation}
            onChange={e => setTargetLocation(e.target.value)}
            className="w-full bg-background/40 border border-white/10 rounded-lg px-2 py-1.5 text-[10px] text-muted-foreground focus:border-primary/30 focus:outline-none"
          >
            <option value="param">Query Param</option>
            <option value="header">Header</option>
            <option value="cookie">Cookie</option>
            <option value="body">Body</option>
          </select>
        </div>

        {/* Max Mutations */}
        <div className="space-y-1">
          <label htmlFor="fuzz-max" className="text-[8px] font-bold text-muted-foreground uppercase tracking-widest">Max Mutations</label>
          <select
            id="fuzz-max"
            value={maxMutations}
            onChange={e => setMaxMutations(Number(e.target.value))}
            className="w-full bg-background/40 border border-white/10 rounded-lg px-2 py-1.5 text-[10px] text-muted-foreground focus:border-primary/30 focus:outline-none"
          >
            <option value={10}>10</option>
            <option value={15}>15</option>
            <option value={20}>20</option>
            <option value={25}>25</option>
            <option value={30}>30</option>
          </select>
        </div>
      </div>

      {/* Start Button */}
      <button
        type="button"
        onClick={startFuzz}
        disabled={loading || !url.trim() || !targetParam.trim()}
        className={cn(
          "w-full flex items-center justify-center gap-2 px-4 py-2.5 rounded-xl text-[10px] font-black uppercase tracking-widest transition-all",
          loading
            ? "bg-[#00A3FF]/10 text-[#00A3FF]/50 cursor-wait"
            : "bg-[#00A3FF]/10 border border-[#00A3FF]/20 text-[#00A3FF] hover:bg-[#00A3FF]/20 active:scale-[0.98]",
          (!url.trim() || !targetParam.trim()) && "opacity-40 cursor-not-allowed"
        )}
      >
        {loading ? <Loader2 className="w-3.5 h-3.5 animate-spin" /> : <Play className="w-3.5 h-3.5" />}
        {loading ? "Fuzzing in progress..." : "Start Adaptive Fuzzing"}
      </button>

      {/* Results */}
      {session && (
        <div className="space-y-3">
          {/* Stats Bar */}
          <div className="flex items-center gap-4 p-3 bg-background/40 border border-white/5 rounded-xl">
            <div className="flex items-center gap-1.5">
              <BarChart3 className="w-3 h-3 text-[#00A3FF]" />
              <span className="text-[9px] font-black text-foreground uppercase tracking-widest">{session.total_mutations}</span>
              <span className="text-[8px] text-muted-foreground">tested</span>
            </div>
            <div className="flex items-center gap-1.5">
              <AlertTriangle className="w-3 h-3 text-yellow-400" />
              <span className="text-[9px] font-black text-yellow-400 uppercase tracking-widest">{session.anomalies_found}</span>
              <span className="text-[8px] text-muted-foreground">anomalies</span>
            </div>
            <div className="flex items-center gap-1.5">
              <span className="text-[8px] text-muted-foreground">Baseline:</span>
              <span className="text-[9px] font-mono text-muted-foreground">{session.baseline.status}</span>
              <span className="text-muted-foreground">|</span>
              <span className="text-[9px] font-mono text-muted-foreground">{session.baseline.length}B</span>
              <span className="text-muted-foreground">|</span>
              <span className="text-[9px] font-mono text-muted-foreground">{session.baseline.time_ms}ms</span>
            </div>

            {/* Sort */}
            <div className="ml-auto flex items-center gap-1">
              <ArrowUpDown className="w-3 h-3 text-muted-foreground" />
              {(["default", "anomaly", "time", "status"] as const).map(s => (
                <button
                  key={s}
                  type="button"
                  onClick={() => setSortBy(s)}
                  className={cn(
                    "px-1.5 py-0.5 rounded text-[7px] font-bold uppercase transition-colors",
                    sortBy === s ? "text-primary bg-primary/10" : "text-muted-foreground hover:text-muted-foreground"
                  )}
                >
                  {s}
                </button>
              ))}
            </div>
          </div>

          {/* Results Table */}
          <div className="space-y-1 max-h-[400px] overflow-y-auto no-scrollbar">
            {sortedResults.map((r, idx) => {
              const isExpanded = expandedResult === idx;

              return (
                <div key={idx} className={cn(
                  "bg-background/30 border rounded-xl overflow-hidden",
                  r.is_anomaly ? "border-yellow-500/20" : "border-white/5"
                )}>
                  <button
                    type="button"
                    onClick={() => setExpandedResult(isExpanded ? null : idx)}
                    className="w-full flex items-center gap-2 px-3 py-2 hover:bg-white/5 transition-colors text-left"
                  >
                    <ChevronRight className={cn("w-3 h-3 text-muted-foreground transition-transform shrink-0", isExpanded && "rotate-90")} />

                    {r.is_anomaly ? (
                      <AlertTriangle className="w-3 h-3 text-yellow-400 shrink-0" />
                    ) : (
                      <CheckCircle className="w-3 h-3 text-muted-foreground shrink-0" />
                    )}

                    <span className="text-[8px] font-bold text-muted-foreground uppercase w-24 shrink-0 truncate">{r.mutation}</span>

                    <span className="text-[9px] font-mono text-muted-foreground flex-1 truncate">{r.payload}</span>

                    {r.status_code && (
                      <span className={cn("px-1.5 py-0.5 rounded text-[8px] font-black shrink-0",
                        r.status_code >= 500 ? "text-red-400 bg-red-500/10" :
                        r.status_code >= 400 ? "text-orange-400 bg-orange-500/10" :
                        r.status_code !== session.baseline.status ? "text-yellow-400 bg-yellow-500/10" :
                        "text-muted-foreground bg-muted/10"
                      )}>
                        {r.status_code}
                      </span>
                    )}

                    {r.response_length !== undefined && (
                      <span className={cn("text-[8px] font-mono shrink-0",
                        Math.abs((r.response_length || 0) - session.baseline.length) > session.baseline.length * 0.2
                          ? "text-yellow-400" : "text-muted-foreground"
                      )}>
                        {r.response_length}B
                      </span>
                    )}

                    {r.response_time_ms !== undefined && (
                      <span className={cn("text-[8px] font-mono shrink-0 flex items-center gap-0.5",
                        (r.response_time_ms || 0) > session.baseline.time_ms * 3
                          ? "text-red-400" : "text-muted-foreground"
                      )}>
                        <Clock className="w-2.5 h-2.5" />
                        {r.response_time_ms}ms
                      </span>
                    )}

                    {r.anomaly_score !== undefined && r.anomaly_score > 0 && (
                      <span className="text-[8px] font-black text-yellow-400">
                        {Math.round(r.anomaly_score * 100)}%
                      </span>
                    )}
                  </button>

                  {/* Expanded Details */}
                  {isExpanded && (
                    <div className="border-t border-white/5 px-3 py-2 space-y-2">
                      {r.anomalies && r.anomalies.length > 0 && (
                        <div className="space-y-1">
                          {r.anomalies.map((a, ai) => (
                            <div key={ai} className={cn("flex items-center gap-2 px-2 py-1.5 rounded-lg border",
                              SEVERITY_COLORS[a.severity] || SEVERITY_COLORS.low
                            )}>
                              <AlertTriangle className="w-3 h-3 shrink-0" />
                              <span className="text-[9px] font-bold flex-1">{a.detail}</span>
                              <span className="text-[7px] font-bold uppercase">{a.severity}</span>
                            </div>
                          ))}
                        </div>
                      )}

                      {r.recommendation && (
                        <p className="text-[9px] text-muted-foreground italic p-2 bg-primary/5 border border-primary/10 rounded-lg">
                          {r.recommendation}
                        </p>
                      )}

                      <div className="flex items-center gap-2">
                        <button
                          type="button"
                          onClick={() => copyValue(r.payload)}
                          className="flex items-center gap-1 px-2 py-1 rounded-lg bg-white/5 text-[8px] font-bold text-muted-foreground hover:text-primary transition-colors"
                        >
                          {copied === r.payload ? <Check className="w-2.5 h-2.5" /> : <Copy className="w-2.5 h-2.5" />}
                          Copy Payload
                        </button>
                        {onSelectPayload && (
                          <button
                            type="button"
                            onClick={() => onSelectPayload(r.payload, r.parameter)}
                            className="flex items-center gap-1 px-2 py-1 rounded-lg bg-primary/10 border border-primary/20 text-[8px] font-bold text-primary hover:bg-primary/20 transition-colors"
                          >
                            Use in Request
                          </button>
                        )}
                      </div>

                      {r.error && (
                        <div className="flex items-center gap-2 text-[9px] text-red-400">
                          <XCircle className="w-3 h-3" />
                          {r.error}
                        </div>
                      )}
                    </div>
                  )}
                </div>
              );
            })}
          </div>
        </div>
      )}
    </div>
  );
}
