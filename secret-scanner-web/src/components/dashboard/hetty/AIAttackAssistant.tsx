"use client";

import React, { useState, useCallback } from "react";
import {
  Brain, Crosshair, Shield, AlertTriangle, ChevronRight,
  Loader2, Sparkles, Target, Zap, Copy, Check,
} from "lucide-react";
import { cn } from "@/lib/utils";
import { toast } from "sonner";

const API_BASE = process.env.NEXT_PUBLIC_API_URL || "http://localhost:8000";

interface AttackVector {
  category: string;
  subcategory: string;
  confidence: number;
  target: string;
  location: string;
  reason: string;
  payloads: string[];
}

interface AnalysisResult {
  attack_vectors: AttackVector[];
  summary: {
    total_vectors: number;
    categories: string[];
    highest_confidence: number;
    attack_points: string[];
  };
  ai_enhanced: boolean;
  ai_recommendation?: string;
  ai_priority_order?: string[];
  ai_additional_vectors?: string[];
}

interface AIAttackAssistantProps {
  method: string;
  url: string;
  headers: Record<string, string>;
  cookies: Record<string, string>;
  params: Record<string, string>;
  body: string;
  onSelectPayload?: (payload: string, param: string, location: string) => void;
  onStartFuzz?: (param: string, location: string, vulnTypes: string[]) => void;
}

const CONFIDENCE_COLORS: Record<string, string> = {
  high: "text-red-400 bg-red-400/10 border-red-400/20",
  medium: "text-yellow-400 bg-yellow-400/10 border-yellow-400/20",
  low: "text-muted-foreground bg-muted/10 border-border/20",
};

const LOCATION_BADGES: Record<string, string> = {
  param: "text-blue-400 bg-blue-400/10",
  header: "text-purple-400 bg-purple-400/10",
  cookie: "text-yellow-400 bg-yellow-400/10",
  body: "text-green-400 bg-green-400/10",
  path: "text-cyan-400 bg-cyan-400/10",
};

export function AIAttackAssistant({
  method, url, headers, cookies, params, body,
  onSelectPayload, onStartFuzz,
}: AIAttackAssistantProps) {
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState<AnalysisResult | null>(null);
  const [expandedVector, setExpandedVector] = useState<number | null>(null);
  const [copied, setCopied] = useState<string | null>(null);

  const analyze = useCallback(async () => {
    if (!url.trim()) {
      toast.error("Enter a URL before analyzing");
      return;
    }

    setLoading(true);
    setResult(null);

    try {
      const res = await fetch(`${API_BASE}/api/hetty/ai/analyze`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ method, url, headers, cookies, params, body }),
        signal: AbortSignal.timeout(15000),
      });

      const data = await res.json();
      if (data.success) {
        setResult(data);
        const count = data.summary?.total_vectors || 0;
        toast.success(`Analysis complete: ${count} attack vector${count !== 1 ? "s" : ""} identified`);
      } else {
        toast.error(data.error || "Analysis failed");
      }
    } catch (err: any) {
      toast.error(err.message || "Analysis failed");
    } finally {
      setLoading(false);
    }
  }, [method, url, headers, cookies, params, body]);

  const copyPayload = (payload: string) => {
    navigator.clipboard.writeText(payload);
    setCopied(payload);
    toast.success("Payload copied");
    setTimeout(() => setCopied(null), 2000);
  };

  const getConfLevel = (confidence: number): string =>
    confidence >= 0.7 ? "high" : confidence >= 0.4 ? "medium" : "low";

  return (
    <div className="space-y-4">
      {/* Header + Analyze Button */}
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-2.5">
          <div className="w-8 h-8 rounded-lg bg-gradient-to-br from-[#00FF88]/20 to-[#00A3FF]/10 border border-primary/20 flex items-center justify-center">
            <Brain className="w-4 h-4 text-primary" />
          </div>
          <div>
            <h3 className="text-[11px] font-black text-foreground uppercase tracking-widest">AI Attack Assistant</h3>
            <p className="text-[8px] text-muted-foreground font-bold uppercase tracking-widest">
              Attack Surface Analysis + Payload Suggestions
            </p>
          </div>
        </div>

        <button
          type="button"
          onClick={analyze}
          disabled={loading || !url.trim()}
          className={cn(
            "flex items-center gap-2 px-4 py-2 rounded-xl text-[9px] font-black uppercase tracking-widest transition-all",
            loading
              ? "bg-primary/10 text-primary/50 cursor-wait"
              : "bg-primary/10 border border-primary/20 text-primary hover:bg-primary/20 active:scale-[0.97]",
            !url.trim() && "opacity-40 cursor-not-allowed"
          )}
        >
          {loading ? <Loader2 className="w-3.5 h-3.5 animate-spin" /> : <Sparkles className="w-3.5 h-3.5" />}
          {loading ? "Analyzing..." : "Analyze Request"}
        </button>
      </div>

      {/* Results */}
      {result && (
        <div className="space-y-3">
          {/* Summary Bar */}
          <div className="flex items-center gap-3 p-3 bg-background/40 border border-white/5 rounded-xl">
            <div className="flex items-center gap-2">
              <Target className="w-4 h-4 text-primary" />
              <span className="text-[10px] font-black text-foreground uppercase tracking-widest">
                {result.summary.total_vectors} Attack Vector{result.summary.total_vectors !== 1 ? "s" : ""}
              </span>
            </div>
            <div className="h-3 w-px bg-white/10" />
            <div className="flex flex-wrap gap-1.5">
              {result.summary.categories.map(cat => (
                <span key={cat} className="px-2 py-0.5 rounded text-[8px] font-bold bg-red-500/10 text-red-400 border border-red-500/20 uppercase tracking-wider">
                  {cat}
                </span>
              ))}
            </div>
            {result.ai_enhanced && (
              <>
                <div className="h-3 w-px bg-white/10" />
                <span className="px-2 py-0.5 rounded text-[8px] font-bold bg-primary/10 text-primary border border-primary/20 uppercase tracking-wider">
                  AI Enhanced
                </span>
              </>
            )}
          </div>

          {/* AI Recommendation */}
          {result.ai_recommendation && (
            <div className="p-3 bg-primary/5 border border-primary/10 rounded-xl">
              <div className="flex items-center gap-1.5 mb-2">
                <Sparkles className="w-3 h-3 text-primary" />
                <span className="text-[9px] font-black text-primary uppercase tracking-widest">AI Recommendation</span>
              </div>
              <p className="text-[10px] text-muted-foreground leading-relaxed">{result.ai_recommendation}</p>
              {result.ai_priority_order && result.ai_priority_order.length > 0 && (
                <div className="flex items-center gap-1.5 mt-2">
                  <span className="text-[8px] text-muted-foreground font-bold uppercase tracking-widest">Priority:</span>
                  {result.ai_priority_order.map((p, i) => (
                    <span key={p} className="text-[8px] text-primary font-bold">
                      {i + 1}. {p}
                    </span>
                  ))}
                </div>
              )}
            </div>
          )}

          {/* Attack Vectors */}
          <div className="space-y-2">
            {result.attack_vectors.map((vector, idx) => {
              const confLevel = getConfLevel(vector.confidence);
              const isExpanded = expandedVector === idx;

              return (
                <div
                  key={`${vector.category}-${vector.target}-${idx}`}
                  className="bg-background/30 border border-white/5 rounded-xl overflow-hidden"
                >
                  {/* Vector Header */}
                  <button
                    type="button"
                    onClick={() => setExpandedVector(isExpanded ? null : idx)}
                    className="w-full flex items-center gap-3 px-4 py-3 hover:bg-white/5 transition-colors text-left"
                  >
                    <ChevronRight className={cn("w-3 h-3 text-muted-foreground transition-transform", isExpanded && "rotate-90")} />

                    <AlertTriangle className={cn("w-3.5 h-3.5 shrink-0",
                      confLevel === "high" ? "text-red-400" : confLevel === "medium" ? "text-yellow-400" : "text-muted-foreground"
                    )} />

                    <div className="flex-1 min-w-0">
                      <div className="flex items-center gap-2">
                        <span className="text-[10px] font-black text-foreground uppercase tracking-widest">{vector.category}</span>
                        <span className="text-[8px] text-muted-foreground">{vector.subcategory}</span>
                      </div>
                      <p className="text-[9px] text-muted-foreground truncate mt-0.5">{vector.reason}</p>
                    </div>

                    <span className={cn("px-1.5 py-0.5 rounded text-[8px] font-bold uppercase tracking-wider", LOCATION_BADGES[vector.location] || LOCATION_BADGES.param)}>
                      {vector.location}
                    </span>

                    <span className="text-[10px] font-mono font-bold text-primary">{vector.target}</span>

                    <span className={cn("px-1.5 py-0.5 rounded border text-[8px] font-bold uppercase", CONFIDENCE_COLORS[confLevel])}>
                      {Math.round(vector.confidence * 100)}%
                    </span>
                  </button>

                  {/* Expanded: Payloads */}
                  {isExpanded && vector.payloads.length > 0 && (
                    <div className="border-t border-white/5 px-4 py-3 space-y-3">
                      <div className="flex items-center justify-between">
                        <span className="text-[9px] font-black text-muted-foreground uppercase tracking-widest">
                          Suggested Payloads ({vector.payloads.length})
                        </span>
                        <div className="flex gap-1.5">
                          {onStartFuzz && (
                            <button
                              type="button"
                              onClick={() => onStartFuzz(vector.target, vector.location, [vector.category])}
                              className="flex items-center gap-1 px-2.5 py-1 rounded-lg bg-[#00A3FF]/10 border border-[#00A3FF]/20 text-[8px] font-black text-[#00A3FF] uppercase tracking-widest hover:bg-[#00A3FF]/20 transition-colors"
                            >
                              <Zap className="w-2.5 h-2.5" />
                              Fuzz This
                            </button>
                          )}
                        </div>
                      </div>

                      <div className="space-y-1">
                        {vector.payloads.map((payload, pIdx) => (
                          <div
                            key={pIdx}
                            className="flex items-center gap-2 p-2 rounded-lg bg-background/40 border border-white/5 group hover:border-primary/20 transition-colors"
                          >
                            <span className="text-[9px] font-mono text-muted-foreground flex-1 truncate select-all">
                              {payload}
                            </span>
                            <button
                              type="button"
                              onClick={() => copyPayload(payload)}
                              className="p-1 text-muted-foreground hover:text-primary opacity-0 group-hover:opacity-100 transition-all"
                              title="Copy payload"
                            >
                              {copied === payload ? <Check className="w-3 h-3 text-primary" /> : <Copy className="w-3 h-3" />}
                            </button>
                            {onSelectPayload && (
                              <button
                                type="button"
                                onClick={() => onSelectPayload(payload, vector.target, vector.location)}
                                className="px-2 py-0.5 rounded text-[8px] font-bold text-primary bg-primary/5 border border-primary/10 opacity-0 group-hover:opacity-100 hover:bg-primary/10 transition-all"
                              >
                                Use
                              </button>
                            )}
                          </div>
                        ))}
                      </div>
                    </div>
                  )}
                </div>
              );
            })}
          </div>

          {result.attack_vectors.length === 0 && (
            <div className="p-6 flex flex-col items-center gap-2 bg-background/20 border border-white/5 rounded-xl">
              <Shield className="w-6 h-6 text-primary" />
              <p className="text-[10px] font-bold text-muted-foreground uppercase tracking-widest">
                No obvious attack vectors detected in this request
              </p>
              <p className="text-[9px] text-muted-foreground">
                Try adding parameters, modifying headers, or changing the endpoint
              </p>
            </div>
          )}
        </div>
      )}

      {/* Empty State */}
      {!result && !loading && (
        <div className="p-6 flex flex-col items-center gap-3 bg-background/20 border border-white/5 rounded-xl">
          <Crosshair className="w-8 h-8 text-muted-foreground" />
          <p className="text-[10px] font-bold text-muted-foreground uppercase tracking-widest text-center">
            Click "Analyze Request" to identify attack surfaces
          </p>
          <p className="text-[9px] text-muted-foreground text-center max-w-sm">
            The AI assistant will analyze parameters, headers, cookies, body, and API structures
            to suggest potential attack vectors and payloads
          </p>
        </div>
      )}
    </div>
  );
}
