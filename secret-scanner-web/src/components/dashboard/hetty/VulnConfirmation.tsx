"use client";

import React, { useState, useCallback } from "react";
import {
  Shield, Crosshair, Play, ChevronRight, AlertTriangle,
  CheckCircle, Loader2, Zap, Terminal, Copy, Check,
} from "lucide-react";
import { cn } from "@/lib/utils";
import { toast } from "sonner";

const API_BASE = process.env.NEXT_PUBLIC_API_URL || "http://localhost:8000";

interface VerificationStep {
  step: number;
  payload: string;
  expected_result: string;
  description: string;
}

interface ExploitOption {
  id: string;
  label: string;
  payload: string;
}

interface VerificationResponse {
  success: boolean;
  verification_steps: VerificationStep[];
  exploit_options: ExploitOption[];
  error?: string;
}

interface VulnConfirmationProps {
  vulnType: string;
  targetValue: string;
  endpoint: string;
  parameter: string;
  onRunPayload?: (payload: string) => void;
}

export function VulnConfirmation({
  vulnType,
  targetValue,
  endpoint,
  parameter,
  onRunPayload,
}: VulnConfirmationProps) {
  const [loading, setLoading] = useState(false);
  const [steps, setSteps] = useState<VerificationStep[]>([]);
  const [exploitOptions, setExploitOptions] = useState<ExploitOption[]>([]);
  const [error, setError] = useState<string | null>(null);
  const [copiedId, setCopiedId] = useState<string | null>(null);
  const [completedSteps, setCompletedSteps] = useState<Set<number>>(new Set());

  const fetchVerification = useCallback(async () => {
    setLoading(true);
    setError(null);
    setSteps([]);
    setExploitOptions([]);
    setCompletedSteps(new Set());

    try {
      const res = await fetch(`${API_BASE}/api/hetty/ai/verify`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          vuln_type: vulnType,
          target_value: targetValue,
        }),
        signal: AbortSignal.timeout(15000),
      });

      const data: VerificationResponse = await res.json();

      if (data.success) {
        setSteps(data.verification_steps || []);
        setExploitOptions(data.exploit_options || []);
        toast.success("Verification steps loaded");
      } else {
        setError(data.error || "Verification request failed");
        toast.error(data.error || "Verification failed");
      }
    } catch (err) {
      const msg = err instanceof Error ? err.message : "Network error";
      setError(msg);
      toast.error(msg);
    } finally {
      setLoading(false);
    }
  }, [vulnType, targetValue]);

  const handleRunStep = (step: VerificationStep) => {
    onRunPayload?.(step.payload);
    setCompletedSteps((prev) => new Set(prev).add(step.step));
    toast.success(`Step ${step.step} payload sent`);
  };

  const handleRunExploit = (option: ExploitOption) => {
    onRunPayload?.(option.payload);
    toast.success(`Exploit "${option.label}" payload sent`);
  };

  const copyToClipboard = (text: string, id: string) => {
    navigator.clipboard.writeText(text);
    setCopiedId(id);
    setTimeout(() => setCopiedId(null), 1500);
  };

  return (
    <div className="flex flex-col gap-3">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-2">
          <Shield className="w-3.5 h-3.5 text-primary" />
          <span className="text-[10px] font-black uppercase tracking-widest text-foreground/70">
            Vuln Confirmation
          </span>
        </div>
        <div className="flex items-center gap-1.5 text-[8px] text-foreground/40">
          <span className="px-1.5 py-0.5 rounded bg-white/5 border border-white/5">
            {vulnType}
          </span>
          <ChevronRight className="w-2.5 h-2.5" />
          <span className="px-1.5 py-0.5 rounded bg-white/5 border border-white/5 max-w-[120px] truncate">
            {parameter || endpoint}
          </span>
        </div>
      </div>

      {/* Target info bar */}
      <div className="rounded-xl bg-white/[0.02] border border-white/5 px-3 py-2 flex items-center gap-2">
        <Crosshair className="w-3 h-3 text-primary/60 shrink-0" />
        <div className="flex flex-col gap-0.5 min-w-0">
          <span className="text-[8px] font-black uppercase tracking-widest text-foreground/40">
            Target
          </span>
          <span className="text-[10px] text-foreground/80 font-mono truncate">
            {endpoint}
            {parameter && (
              <span className="text-primary/60 ml-1">?{parameter}=</span>
            )}
            <span className="text-yellow-400/70">{targetValue}</span>
          </span>
        </div>
      </div>

      {/* Fetch button */}
      {steps.length === 0 && !loading && (
        <button
          onClick={fetchVerification}
          disabled={loading}
          className={cn(
            "w-full rounded-xl border border-primary/20 bg-primary/5",
            "px-3 py-2.5 flex items-center justify-center gap-2",
            "text-[10px] font-black uppercase tracking-widest text-primary",
            "transition-transform transition-opacity duration-150 ease-out",
            "hover:bg-primary/10 hover:scale-[1.01]",
            "focus-visible:outline-none focus-visible:ring-1 focus-visible:ring-[#00FF88]/40",
            "active:scale-[0.99]"
          )}
        >
          <Zap className="w-3.5 h-3.5" />
          Get Verification Steps
        </button>
      )}

      {/* Loading */}
      {loading && (
        <div className="rounded-xl bg-white/[0.02] border border-white/5 px-4 py-6 flex flex-col items-center gap-2">
          <Loader2 className="w-4 h-4 text-primary animate-spin" />
          <span className="text-[9px] text-foreground/40">
            Generating verification sequence...
          </span>
        </div>
      )}

      {/* Error */}
      {error && (
        <div className="rounded-xl bg-red-500/5 border border-red-400/20 px-3 py-2.5 flex items-center gap-2">
          <AlertTriangle className="w-3.5 h-3.5 text-red-400 shrink-0" />
          <span className="text-[9px] text-red-300">{error}</span>
          <button
            onClick={fetchVerification}
            className="ml-auto text-[8px] font-black uppercase tracking-widest text-red-400 hover:text-red-300 transition-opacity duration-150"
          >
            Retry
          </button>
        </div>
      )}

      {/* Verification Steps */}
      {steps.length > 0 && (
        <div className="flex flex-col gap-1.5">
          <span className="text-[8px] font-black uppercase tracking-widest text-foreground/40 px-1">
            Verification Sequence
          </span>
          {steps.map((step) => {
            const done = completedSteps.has(step.step);
            return (
              <div
                key={step.step}
                className={cn(
                  "rounded-xl border px-3 py-2.5 flex flex-col gap-1.5",
                  done
                    ? "bg-primary/[0.03] border-primary/20"
                    : "bg-white/[0.02] border-white/5"
                )}
              >
                {/* Step header */}
                <div className="flex items-center justify-between">
                  <div className="flex items-center gap-1.5">
                    {done ? (
                      <CheckCircle className="w-3 h-3 text-primary" />
                    ) : (
                      <span className="w-4 h-4 rounded-full bg-white/5 border border-white/10 flex items-center justify-center text-[8px] text-foreground/50 font-black">
                        {step.step}
                      </span>
                    )}
                    <span className="text-[9px] text-foreground/70">
                      {step.description}
                    </span>
                  </div>
                  <div className="flex items-center gap-1">
                    <button
                      onClick={() =>
                        copyToClipboard(step.payload, `step-${step.step}`)
                      }
                      className="p-1 rounded hover:bg-white/5 transition-opacity duration-150 focus-visible:outline-none focus-visible:ring-1 focus-visible:ring-[#00FF88]/40 active:scale-95"
                      title="Copy payload"
                    >
                      {copiedId === `step-${step.step}` ? (
                        <Check className="w-2.5 h-2.5 text-primary" />
                      ) : (
                        <Copy className="w-2.5 h-2.5 text-foreground/30" />
                      )}
                    </button>
                    <button
                      onClick={() => handleRunStep(step)}
                      className={cn(
                        "flex items-center gap-1 px-2 py-0.5 rounded-lg",
                        "text-[8px] font-black uppercase tracking-widest",
                        "transition-transform transition-opacity duration-150 ease-out",
                        "focus-visible:outline-none focus-visible:ring-1 focus-visible:ring-[#00FF88]/40",
                        "active:scale-95",
                        done
                          ? "bg-primary/10 text-primary/60"
                          : "bg-primary/10 text-primary hover:bg-primary/20"
                      )}
                    >
                      <Play className="w-2.5 h-2.5" />
                      Run
                    </button>
                  </div>
                </div>

                {/* Payload */}
                <div className="rounded-lg bg-background/40 border border-white/5 px-2 py-1.5">
                  <code className="text-[9px] text-primary/80 font-mono break-all">
                    {step.payload}
                  </code>
                </div>

                {/* Expected result */}
                <div className="flex items-start gap-1.5 px-1">
                  <ChevronRight className="w-2.5 h-2.5 text-foreground/20 mt-0.5 shrink-0" />
                  <span className="text-[8px] text-foreground/40">
                    <span className="font-black uppercase tracking-widest text-foreground/30">
                      Expected:{" "}
                    </span>
                    {step.expected_result}
                  </span>
                </div>
              </div>
            );
          })}
        </div>
      )}

      {/* Exploit Options */}
      {exploitOptions.length > 0 && (
        <div className="flex flex-col gap-1.5">
          <span className="text-[8px] font-black uppercase tracking-widest text-foreground/40 px-1">
            Exploit Options
          </span>
          <div className="rounded-2xl border border-white/5 bg-white/[0.02] p-2 flex flex-wrap gap-1.5">
            {exploitOptions.map((opt) => (
              <button
                key={opt.id}
                onClick={() => handleRunExploit(opt)}
                className={cn(
                  "flex items-center gap-1.5 px-2.5 py-1.5 rounded-xl",
                  "border border-white/5 bg-white/[0.03]",
                  "text-[9px] text-foreground/60",
                  "transition-transform transition-opacity duration-150 ease-out",
                  "hover:bg-primary/5 hover:border-primary/20 hover:text-primary/80",
                  "focus-visible:outline-none focus-visible:ring-1 focus-visible:ring-[#00FF88]/40",
                  "active:scale-95"
                )}
              >
                <Terminal className="w-3 h-3" />
                {opt.label}
              </button>
            ))}
          </div>
        </div>
      )}

      {/* Reload button when steps are shown */}
      {steps.length > 0 && !loading && (
        <button
          onClick={fetchVerification}
          className="text-[8px] font-black uppercase tracking-widest text-foreground/30 hover:text-foreground/50 transition-opacity duration-150 self-center focus-visible:outline-none active:scale-95"
        >
          Regenerate Steps
        </button>
      )}
    </div>
  );
}
