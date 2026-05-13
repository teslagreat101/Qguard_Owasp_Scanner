"use client";

import React, { useState, useEffect, useCallback } from "react";
import {
  Globe, Shield, AlertTriangle, Loader2, RefreshCw,
  ChevronDown, ChevronRight, Link2, Target, Zap,
} from "lucide-react";
import { cn } from "@/lib/utils";
import { toast } from "sonner";

const API_BASE = process.env.NEXT_PUBLIC_API_URL || "http://localhost:8000";

/* ------------------------------------------------------------------ */
/*  Types                                                              */
/* ------------------------------------------------------------------ */

interface Finding {
  endpoint: string;
  type: string;
  severity: string;
  confidence: number;
  parameter: string;
}

interface GraphNode {
  id: string;
  label: string;
  type: "root" | "endpoint" | "vulnerability";
  severity?: string;
  confidence?: number;
  parameter?: string;
  vuln_count?: number;
  children: GraphNode[];
}

interface AttackChain {
  name: string;
  steps: string[];
  impact: string;
  severity: string;
}

interface AttackGraphResult {
  tree: GraphNode;
  chains: AttackChain[];
  summary: {
    total_endpoints: number;
    total_vulnerabilities: number;
    critical: number;
    high: number;
    medium: number;
    low: number;
  };
}

interface AttackGraphProps {
  target: string;
  findings: Finding[];
}

/* ------------------------------------------------------------------ */
/*  Severity helpers                                                    */
/* ------------------------------------------------------------------ */

const SEVERITY_COLOR: Record<string, string> = {
  critical: "text-red-400",
  high: "text-orange-400",
  medium: "text-yellow-400",
  low: "text-muted-foreground",
};

const SEVERITY_BORDER: Record<string, string> = {
  critical: "border-red-400/30",
  high: "border-orange-400/30",
  medium: "border-yellow-400/20",
  low: "border-white/10",
};

const SEVERITY_BG: Record<string, string> = {
  critical: "bg-red-400/5",
  high: "bg-orange-400/5",
  medium: "bg-yellow-400/5",
  low: "bg-white/[0.02]",
};

const SEVERITY_DOT: Record<string, string> = {
  critical: "bg-red-400",
  high: "bg-orange-400",
  medium: "bg-yellow-400",
  low: "bg-muted",
};

const SEVERITY_BADGE: Record<string, string> = {
  critical: "text-red-400 bg-red-400/10 border-red-400/20",
  high: "text-orange-400 bg-orange-400/10 border-orange-400/20",
  medium: "text-yellow-400 bg-yellow-400/10 border-yellow-400/20",
  low: "text-muted-foreground bg-muted/10 border-border/20",
};

/* ------------------------------------------------------------------ */
/*  Tree node renderer                                                 */
/* ------------------------------------------------------------------ */

function TreeNode({ node, depth = 0 }: { node: GraphNode; depth?: number }) {
  const [expanded, setExpanded] = useState(depth < 2);
  const hasChildren = node.children && node.children.length > 0;
  const sev = (node.severity || "low").toLowerCase();

  return (
    <div className={cn(depth > 0 && "ml-4 border-l border-primary/10 pl-3")}>
      <button
        onClick={() => hasChildren && setExpanded(!expanded)}
        className={cn(
          "w-full flex items-center gap-1.5 py-1 px-1.5 rounded transition-opacity duration-150",
          hasChildren && "hover:bg-white/[0.02] cursor-pointer",
          !hasChildren && "cursor-default"
        )}
      >
        {/* Expand icon or dot */}
        {hasChildren ? (
          expanded ? (
            <ChevronDown className="h-2.5 w-2.5 text-primary/40 shrink-0" />
          ) : (
            <ChevronRight className="h-2.5 w-2.5 text-primary/40 shrink-0" />
          )
        ) : (
          <div className={cn("w-1.5 h-1.5 rounded-full shrink-0", SEVERITY_DOT[sev] || "bg-muted")} />
        )}

        {/* Node icon */}
        {node.type === "root" && <Globe className="h-3 w-3 text-primary shrink-0" />}
        {node.type === "endpoint" && <Link2 className="h-2.5 w-2.5 text-[#00A3FF] shrink-0" />}
        {node.type === "vulnerability" && <AlertTriangle className={cn("h-2.5 w-2.5 shrink-0", SEVERITY_COLOR[sev])} />}

        {/* Label */}
        <span
          className={cn(
            "text-left truncate",
            node.type === "root" && "text-[10px] font-black uppercase tracking-widest text-primary",
            node.type === "endpoint" && "text-[9px] font-bold text-[#00A3FF]/90 font-mono",
            node.type === "vulnerability" && "text-[8px] text-foreground/60"
          )}
        >
          {node.label}
        </span>

        {/* Vuln count badge for endpoint nodes */}
        {node.type === "endpoint" && node.vuln_count != null && node.vuln_count > 0 && (
          <span className="ml-auto text-[7px] font-black text-primary bg-primary/10 border border-primary/20 rounded px-1 py-0.5">
            {node.vuln_count}
          </span>
        )}

        {/* Severity badge for vulnerability nodes */}
        {node.type === "vulnerability" && node.severity && (
          <span
            className={cn(
              "ml-auto text-[7px] font-black uppercase tracking-widest px-1 py-0.5 rounded border shrink-0",
              SEVERITY_BADGE[sev]
            )}
          >
            {node.severity}
          </span>
        )}

        {/* Parameter badge */}
        {node.type === "vulnerability" && node.parameter && (
          <span className="text-[7px] font-mono text-purple-400/70 bg-purple-400/5 border border-purple-400/10 rounded px-1 py-0.5 shrink-0">
            {node.parameter}
          </span>
        )}
      </button>

      {/* Children */}
      {expanded && hasChildren && (
        <div className="mt-0.5">
          {node.children.map((child, i) => (
            <TreeNode key={`${child.id}-${i}`} node={child} depth={depth + 1} />
          ))}
        </div>
      )}
    </div>
  );
}

/* ------------------------------------------------------------------ */
/*  Main component                                                     */
/* ------------------------------------------------------------------ */

export function AttackGraph({ target, findings }: AttackGraphProps) {
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState<AttackGraphResult | null>(null);
  const [chainsExpanded, setChainsExpanded] = useState(true);

  const fetchGraph = useCallback(async () => {
    if (!target.trim() || findings.length === 0) return;

    setLoading(true);

    try {
      const res = await fetch(`${API_BASE}/api/hetty/ai/attack-graph`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ target, findings }),
      });

      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      const data: AttackGraphResult = await res.json();
      setResult(data);
    } catch (err) {
      toast.error("Attack graph generation failed");
      console.error(err);
    } finally {
      setLoading(false);
    }
  }, [target, findings]);

  useEffect(() => {
    fetchGraph();
  }, [fetchGraph]);

  /* ---------------------------------------------------------------- */
  /*  Render                                                           */
  /* ---------------------------------------------------------------- */

  return (
    <div className="w-full rounded border border-primary/10 bg-background overflow-hidden">
      {/* Header */}
      <div className="flex items-center justify-between px-3 py-2 border-b border-primary/10 bg-primary/[0.03]">
        <div className="flex items-center gap-2">
          <Target className="h-3.5 w-3.5 text-primary" />
          <span className="text-[10px] font-black uppercase tracking-widest text-primary">
            Attack Surface Graph
          </span>
        </div>
        <button
          onClick={fetchGraph}
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

      {/* Loading */}
      {loading && !result && (
        <div className="flex items-center justify-center gap-2 py-8">
          <Loader2 className="h-4 w-4 animate-spin text-primary/60" />
          <span className="text-[9px] font-black uppercase tracking-widest text-primary/40">
            Building attack graph
          </span>
        </div>
      )}

      {/* Empty state */}
      {!loading && !result && (
        <div className="flex items-center justify-center py-8">
          <span className="text-[9px] uppercase tracking-widest text-foreground/20">
            No graph data
          </span>
        </div>
      )}

      {result && (
        <div className="divide-y divide-[#00FF88]/5">
          {/* Severity summary counters */}
          <div className="px-3 py-2 flex items-center gap-3">
            <div className="flex items-center gap-1">
              <Shield className="h-2.5 w-2.5 text-foreground/30" />
              <span className="text-[8px] font-black uppercase tracking-widest text-foreground/40">
                {result.summary.total_endpoints} endpoints
              </span>
            </div>
            <div className="h-3 w-px bg-white/10" />
            {result.summary.critical > 0 && (
              <div className="flex items-center gap-1">
                <div className="w-1.5 h-1.5 rounded-full bg-red-400" />
                <span className="text-[8px] font-black text-red-400">
                  {result.summary.critical}
                </span>
              </div>
            )}
            {result.summary.high > 0 && (
              <div className="flex items-center gap-1">
                <div className="w-1.5 h-1.5 rounded-full bg-orange-400" />
                <span className="text-[8px] font-black text-orange-400">
                  {result.summary.high}
                </span>
              </div>
            )}
            {result.summary.medium > 0 && (
              <div className="flex items-center gap-1">
                <div className="w-1.5 h-1.5 rounded-full bg-yellow-400" />
                <span className="text-[8px] font-black text-yellow-400">
                  {result.summary.medium}
                </span>
              </div>
            )}
            {result.summary.low > 0 && (
              <div className="flex items-center gap-1">
                <div className="w-1.5 h-1.5 rounded-full bg-muted" />
                <span className="text-[8px] font-black text-muted-foreground">
                  {result.summary.low}
                </span>
              </div>
            )}
            <div className="ml-auto text-[8px] font-black uppercase tracking-widest text-foreground/30">
              {result.summary.total_vulnerabilities} vulns
            </div>
          </div>

          {/* Tree visualization */}
          <div className="px-3 py-2 max-h-[400px] overflow-y-auto">
            <TreeNode node={result.tree} depth={0} />
          </div>

          {/* Attack chains */}
          {result.chains && result.chains.length > 0 && (
            <div>
              <button
                onClick={() => setChainsExpanded(!chainsExpanded)}
                className="w-full flex items-center gap-1.5 px-3 py-1.5 hover:bg-white/[0.02] transition-opacity duration-150"
              >
                {chainsExpanded ? (
                  <ChevronDown className="h-2.5 w-2.5 text-primary/50" />
                ) : (
                  <ChevronRight className="h-2.5 w-2.5 text-primary/50" />
                )}
                <Zap className="h-2.5 w-2.5 text-orange-400" />
                <span className="text-[9px] font-black uppercase tracking-widest text-foreground/70">
                  Attack Chains
                </span>
                <span className="ml-auto text-[8px] font-black text-orange-400/60">
                  {result.chains.length}
                </span>
              </button>
              {chainsExpanded && (
                <div className="px-3 pb-2 space-y-2">
                  {result.chains.map((chain, i) => {
                    const sev = (chain.severity || "medium").toLowerCase();
                    return (
                      <div
                        key={i}
                        className={cn(
                          "rounded border px-2.5 py-2",
                          SEVERITY_BORDER[sev],
                          SEVERITY_BG[sev]
                        )}
                      >
                        <div className="flex items-center gap-1.5 mb-1.5">
                          <span
                            className={cn(
                              "text-[7px] font-black uppercase tracking-widest px-1.5 py-0.5 rounded border",
                              SEVERITY_BADGE[sev]
                            )}
                          >
                            {chain.severity}
                          </span>
                          <span className="text-[9px] font-bold text-foreground/80">
                            {chain.name}
                          </span>
                        </div>

                        {/* Chain steps */}
                        <div className="ml-1 border-l border-primary/15 pl-2.5 space-y-1">
                          {chain.steps.map((step, si) => (
                            <div key={si} className="flex items-center gap-1.5">
                              <div className="w-1 h-1 rounded-full bg-primary/40 -ml-[7px]" />
                              <span className="text-[8px] text-foreground/50">{step}</span>
                            </div>
                          ))}
                        </div>

                        {/* Impact */}
                        {chain.impact && (
                          <div className="mt-1.5 flex items-start gap-1">
                            <AlertTriangle className={cn("h-2.5 w-2.5 shrink-0 mt-0.5", SEVERITY_COLOR[sev])} />
                            <span className="text-[8px] text-foreground/40 leading-relaxed">
                              {chain.impact}
                            </span>
                          </div>
                        )}
                      </div>
                    );
                  })}
                </div>
              )}
            </div>
          )}
        </div>
      )}
    </div>
  );
}
