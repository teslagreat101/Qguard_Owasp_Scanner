"use client";

import React, { useState, useCallback } from "react";
import {
  Crosshair, Copy, Check, ChevronDown, ChevronRight,
  Loader2, Shield, Zap, Code2, Lock, Globe, FileText,
  Terminal, Database, Bug, ArrowRight,
} from "lucide-react";
import { cn } from "@/lib/utils";
import { toast } from "sonner";

const API_BASE = process.env.NEXT_PUBLIC_API_URL || "http://localhost:8000";

interface EncodedVariant {
  encoding: string;
  value: string;
}

interface GeneratedPayload {
  id: string;
  payload: string;
  category: string;
  risk_level: string;
  description: string;
  encoding: string;
  encoded_variants: EncodedVariant[];
}

interface AIPayloadGeneratorProps {
  onSelectPayload?: (payload: string) => void;
  currentParam?: string;
  currentValue?: string;
  currentLocation?: string;
}

const VULN_TYPES = [
  { id: "sqli", label: "SQL Injection", icon: Database, color: "text-red-400" },
  { id: "xss", label: "XSS", icon: Code2, color: "text-orange-400" },
  { id: "lfi", label: "LFI / Path Traversal", icon: FileText, color: "text-yellow-400" },
  { id: "ssrf", label: "SSRF", icon: Globe, color: "text-blue-400" },
  { id: "rce", label: "RCE / Command Injection", icon: Terminal, color: "text-purple-400" },
  { id: "ssti", label: "SSTI", icon: Zap, color: "text-cyan-400" },
  { id: "idor", label: "IDOR", icon: Lock, color: "text-green-400" },
  { id: "auth_bypass", label: "Auth Bypass", icon: Shield, color: "text-pink-400" },
];

const RISK_COLORS: Record<string, string> = {
  high: "text-red-400 bg-red-400/10 border-red-400/20",
  medium: "text-yellow-400 bg-yellow-400/10 border-yellow-400/20",
  low: "text-muted-foreground bg-muted/10 border-border/20",
};

export function AIPayloadGenerator({ onSelectPayload, currentParam, currentValue, currentLocation }: AIPayloadGeneratorProps) {
  const [selectedType, setSelectedType] = useState<string>("sqli");
  const [loading, setLoading] = useState(false);
  const [payloads, setPayloads] = useState<GeneratedPayload[]>([]);
  const [expandedPayload, setExpandedPayload] = useState<string | null>(null);
  const [copied, setCopied] = useState<string | null>(null);

  const generate = useCallback(async () => {
    setLoading(true);
    setPayloads([]);

    try {
      const res = await fetch(`${API_BASE}/api/hetty/ai/payloads`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          vuln_type: selectedType,
          current_value: currentValue || "",
          location: currentLocation || "param",
          parameter: currentParam || "",
        }),
        signal: AbortSignal.timeout(10000),
      });

      const data = await res.json();
      if (data.success) {
        setPayloads(data.payloads || []);
        toast.success(`${data.total} payloads generated`);
      } else {
        toast.error(data.error || "Generation failed");
      }
    } catch (err: any) {
      toast.error(err.message || "Generation failed");
    } finally {
      setLoading(false);
    }
  }, [selectedType, currentValue, currentLocation, currentParam]);

  const copyPayload = (value: string) => {
    navigator.clipboard.writeText(value);
    setCopied(value);
    toast.success("Copied");
    setTimeout(() => setCopied(null), 2000);
  };

  return (
    <div className="space-y-4">
      {/* Header */}
      <div className="flex items-center gap-2.5">
        <div className="w-8 h-8 rounded-lg bg-gradient-to-br from-red-500/20 to-orange-500/10 border border-red-500/20 flex items-center justify-center">
          <Crosshair className="w-4 h-4 text-red-400" />
        </div>
        <div>
          <h3 className="text-[11px] font-black text-foreground uppercase tracking-widest">AI Payload Generator</h3>
          <p className="text-[8px] text-muted-foreground font-bold uppercase tracking-widest">
            Context-Aware Attack Payloads
          </p>
        </div>
      </div>

      {/* Vulnerability Type Selector */}
      <div className="flex flex-wrap gap-1.5">
        {VULN_TYPES.map(vt => (
          <button
            key={vt.id}
            type="button"
            onClick={() => setSelectedType(vt.id)}
            className={cn(
              "flex items-center gap-1.5 px-2.5 py-1.5 rounded-lg text-[8px] font-black uppercase tracking-widest border transition-colors",
              selectedType === vt.id
                ? `${vt.color} bg-white/5 border-current`
                : "text-muted-foreground border-white/5 hover:border-white/10 hover:text-muted-foreground"
            )}
          >
            <vt.icon className="w-3 h-3" />
            {vt.label}
          </button>
        ))}
      </div>

      {/* Context Info */}
      {(currentParam || currentValue) && (
        <div className="flex items-center gap-2 p-2 bg-background/30 border border-white/5 rounded-lg">
          <span className="text-[8px] text-muted-foreground font-bold uppercase tracking-widest">Context:</span>
          {currentParam && (
            <span className="text-[9px] font-mono text-primary">{currentParam}</span>
          )}
          {currentValue && (
            <>
              <span className="text-muted-foreground">=</span>
              <span className="text-[9px] font-mono text-muted-foreground truncate max-w-[200px]">{currentValue}</span>
            </>
          )}
          {currentLocation && (
            <span className="px-1.5 py-0.5 rounded text-[7px] font-bold text-blue-400 bg-blue-400/10 uppercase">
              {currentLocation}
            </span>
          )}
        </div>
      )}

      {/* Generate Button */}
      <button
        type="button"
        onClick={generate}
        disabled={loading}
        className={cn(
          "w-full flex items-center justify-center gap-2 px-4 py-2.5 rounded-xl text-[10px] font-black uppercase tracking-widest transition-all",
          loading
            ? "bg-red-500/10 text-red-400/50 cursor-wait"
            : "bg-red-500/10 border border-red-500/20 text-red-400 hover:bg-red-500/20 active:scale-[0.98]"
        )}
      >
        {loading ? <Loader2 className="w-3.5 h-3.5 animate-spin" /> : <Crosshair className="w-3.5 h-3.5" />}
        {loading ? "Generating..." : `Generate ${VULN_TYPES.find(v => v.id === selectedType)?.label || ""} Payloads`}
      </button>

      {/* Payloads List */}
      {payloads.length > 0 && (
        <div className="space-y-1.5 max-h-[400px] overflow-y-auto no-scrollbar">
          {payloads.map(p => {
            const isExpanded = expandedPayload === p.id;

            return (
              <div key={p.id} className="bg-background/30 border border-white/5 rounded-xl overflow-hidden">
                <div className="flex items-center gap-2 px-3 py-2 group">
                  <button
                    type="button"
                    onClick={() => setExpandedPayload(isExpanded ? null : p.id)}
                    className="text-muted-foreground hover:text-foreground transition-colors"
                  >
                    <ChevronRight className={cn("w-3 h-3 transition-transform", isExpanded && "rotate-90")} />
                  </button>

                  <span className={cn("px-1.5 py-0.5 rounded border text-[7px] font-bold uppercase shrink-0", RISK_COLORS[p.risk_level] || RISK_COLORS.low)}>
                    {p.risk_level}
                  </span>

                  <span className="text-[9px] font-mono text-muted-foreground flex-1 truncate select-all">
                    {p.payload}
                  </span>

                  <div className="flex items-center gap-1 opacity-0 group-hover:opacity-100 transition-opacity">
                    <button
                      type="button"
                      onClick={() => copyPayload(p.payload)}
                      className="p-1 text-muted-foreground hover:text-primary transition-colors"
                      title="Copy"
                    >
                      {copied === p.payload ? <Check className="w-3 h-3 text-primary" /> : <Copy className="w-3 h-3" />}
                    </button>
                    {onSelectPayload && (
                      <button
                        type="button"
                        onClick={() => onSelectPayload(p.payload)}
                        className="px-2 py-0.5 rounded text-[8px] font-bold text-primary bg-primary/10 hover:bg-primary/20 transition-colors"
                      >
                        Use
                      </button>
                    )}
                  </div>
                </div>

                {/* Expanded: Description + Encoded Variants */}
                {isExpanded && (
                  <div className="border-t border-white/5 px-3 py-2 space-y-2">
                    <p className="text-[9px] text-muted-foreground">{p.description}</p>

                    {p.encoded_variants.length > 0 && (
                      <div className="space-y-1">
                        <span className="text-[8px] font-bold text-muted-foreground uppercase tracking-widest">Encoded Variants</span>
                        {p.encoded_variants.map((v, i) => (
                          <div key={i} className="flex items-center gap-2 p-1.5 rounded-lg bg-background/40">
                            <span className="text-[8px] font-bold text-purple-400 uppercase shrink-0 w-16">{v.encoding}</span>
                            <span className="text-[8px] font-mono text-muted-foreground flex-1 truncate select-all">{v.value}</span>
                            <button
                              type="button"
                              onClick={() => copyPayload(v.value)}
                              className="p-0.5 text-muted-foreground hover:text-primary transition-colors"
                            >
                              {copied === v.value ? <Check className="w-2.5 h-2.5 text-primary" /> : <Copy className="w-2.5 h-2.5" />}
                            </button>
                          </div>
                        ))}
                      </div>
                    )}
                  </div>
                )}
              </div>
            );
          })}
        </div>
      )}
    </div>
  );
}
