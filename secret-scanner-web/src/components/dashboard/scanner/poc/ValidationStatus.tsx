"use client";

import { CheckCircle2, AlertCircle, Clock, ShieldCheck, XCircle, Hash, Zap, Activity } from "lucide-react";
import { cn } from "@/lib/utils";

interface VerificationData {
  finding_id?: string;
  endpoint?: string;
  confidence?: number;
  timing_delta_ms?: number;
  strategy?: string;
  evidence_hash?: string;
  verification_status?: string;
}

interface ValidationStatusProps {
  status: "PENDING" | "RUNNING" | "VERIFIED" | "FAILED" | "FALSE_POSITIVE";
  verificationData?: VerificationData;
}

export function ValidationStatus({ status, verificationData }: ValidationStatusProps) {
  const getStatusConfig = () => {
    switch (status) {
      case "VERIFIED":
        return {
          icon: ShieldCheck,
          label: "Exploit Verified",
          description: verificationData
            ? `Confirmed via ${verificationData.strategy || "differential analysis"}`
            : "Vulnerability successfully exploited via live evidence.",
          color: "text-primary",
          bg: "bg-primary/10",
          border: "border-primary/20",
        };
      case "FAILED":
        return {
          icon: XCircle,
          label: "Validation Failed",
          description: "Payload did not trigger expected behavior.",
          color: "text-red-500",
          bg: "bg-red-500/10",
          border: "border-red-500/20",
        };
      case "RUNNING":
        return {
          icon: Clock,
          label: "POC Active",
          description: "Executing live attack workflow on target endpoint.",
          color: "text-blue-500",
          bg: "bg-blue-500/10",
          border: "border-blue-500/20",
          animate: true,
        };
      case "FALSE_POSITIVE":
        return {
          icon: AlertCircle,
          label: "False Positive",
          description: "Analysis indicates no exploitable vulnerability.",
          color: "text-muted-foreground",
          bg: "bg-muted-foreground/10",
          border: "border-muted-foreground/20",
        };
      default:
        return {
          icon: AlertCircle,
          label: "Manual Review Required",
          description: "Detection confirmed. Analyst verification pending.",
          color: "text-orange-500",
          bg: "bg-orange-500/10",
          border: "border-orange-500/20",
        };
    }
  };

  const config = getStatusConfig();
  const Icon = config.icon;
  const hasEvidence = status === "VERIFIED" && verificationData;

  return (
    <div className={cn(
      "p-5 rounded-2xl border backdrop-blur-md transition-all duration-500",
      config.bg,
      config.border
    )}>
      <div className="flex items-start gap-4">
        <div className={cn(
          "p-2.5 rounded-xl bg-background/40 border-border/50 shrink-0",
          (config as any).animate && "animate-pulse"
        )}>
          <Icon className={cn("w-5 h-5", config.color)} />
        </div>
        <div className="space-y-1 min-w-0">
          <h4 className={cn("text-xs font-black uppercase tracking-widest", config.color)}>
            Status: {config.label}
          </h4>
          <p className="text-[10px] text-muted-foreground font-bold leading-relaxed uppercase tracking-tight">
            {config.description}
          </p>
        </div>
      </div>

      {/* Real verification evidence panel */}
      {hasEvidence && (
        <div className="mt-4 pt-4 border-t border-primary/10 space-y-2">
          {verificationData!.confidence !== undefined && (
            <div className="flex items-center justify-between">
              <div className="flex items-center gap-1.5">
                <Activity className="w-3 h-3 text-primary/60" />
                <span className="text-[9px] font-bold text-muted-foreground uppercase tracking-widest">Confidence</span>
              </div>
              <div className="flex items-center gap-2">
                <div className="w-20 h-1 bg-secondary rounded-full overflow-hidden">
                  <div
                    className={cn(
                      "h-full bg-primary rounded-full",
                      (verificationData!.confidence || 0) >= 0.9 ? "w-full" :
                        (verificationData!.confidence || 0) >= 0.75 ? "w-4/5" :
                          (verificationData!.confidence || 0) >= 0.6 ? "w-3/5" :
                            (verificationData!.confidence || 0) >= 0.4 ? "w-2/5" : "w-1/5"
                    )}
                  />
                </div>
                <span className="text-[9px] font-black text-primary">
                  {Math.round((verificationData!.confidence || 0) * 100)}%
                </span>
              </div>
            </div>
          )}

          {verificationData!.timing_delta_ms !== undefined && (
            <div className="flex items-center justify-between">
              <div className="flex items-center gap-1.5">
                <Zap className="w-3 h-3 text-yellow-500/60" />
                <span className="text-[9px] font-bold text-muted-foreground uppercase tracking-widest">Timing Delta</span>
              </div>
              <span className="text-[9px] font-black text-yellow-400">
                {verificationData!.timing_delta_ms}ms
              </span>
            </div>
          )}

          {verificationData!.evidence_hash && (
            <div className="flex items-start gap-1.5 mt-1">
              <Hash className="w-3 h-3 text-muted-foreground shrink-0 mt-0.5" />
              <div className="min-w-0">
                <p className="text-[9px] font-bold text-muted-foreground uppercase tracking-widest mb-0.5">Evidence Hash</p>
                <p className="text-[9px] font-mono text-muted-foreground truncate">
                  {verificationData!.evidence_hash.slice(0, 32)}…
                </p>
              </div>
            </div>
          )}

          {verificationData!.strategy && (
            <div className="flex items-center gap-1.5">
              <CheckCircle2 className="w-3 h-3 text-primary/60 shrink-0" />
              <span className="text-[9px] font-bold text-muted-foreground uppercase tracking-widest">
                Strategy:&nbsp;
              </span>
              <span className="text-[9px] font-black text-primary uppercase tracking-widest">
                {verificationData!.strategy.replace(/_/g, " ")}
              </span>
            </div>
          )}
        </div>
      )}

      {status === "PENDING" && (
        <div className="mt-4 pt-4 border-t border-border flex gap-2">
          <div className="flex-1 h-1 bg-secondary rounded-full overflow-hidden">
            <div className="h-full bg-orange-500 w-1/3 rounded-full animate-[progress_3s_infinite_linear]" />
          </div>
          <style jsx>{`
            @keyframes progress {
              0% { transform: translateX(-100%); }
              100% { transform: translateX(300%); }
            }
          `}</style>
        </div>
      )}
    </div>
  );
}
