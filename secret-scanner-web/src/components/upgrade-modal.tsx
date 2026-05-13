"use client";

import { motion, AnimatePresence } from "framer-motion";
import { Zap, X, AlertTriangle, Check, ArrowRight, Loader2 } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { cn } from "@/lib/utils";

interface UpgradeModalProps {
  isOpen: boolean;
  onClose: () => void;
  currentPlan: string; // "free" | "pro" | "elite"
  scansUsed: number;
  scansLimit: number;
  onUpgrade: (planId: string) => Promise<any>;
  isLoading?: boolean;
}

const PRO_FEATURES = [
  "200 Scans per Month",
  "Advance AI Remediation Co-Pilot",
  "POC Verification",
  "Priority API Access",
  "Email Support",
];

const ELITE_FEATURES = [
  "Unlimited Security Scans",
  "Advance AI Remediation Co-Pilot",
  "POC Verification",
  "Custom Policy Engine",
  "24/7 Technical Support",
];

export function UpgradeModal({
  isOpen,
  onClose,
  currentPlan,
  scansUsed,
  scansLimit,
  onUpgrade,
  isLoading = false,
}: UpgradeModalProps) {
  const isPro = currentPlan === "pro";
  const isElite = currentPlan === "elite";

  const handleUpgrade = async (planId: string) => {
    await onUpgrade(planId);
  };

  if (isElite) return null;

  return (
    <AnimatePresence>
      {isOpen && (
        <>
          {/* Backdrop */}
          <motion.div
            className="fixed inset-0 z-50 bg-black/80 backdrop-blur-sm"
            initial={{ opacity: 0 }}
            animate={{ opacity: 1 }}
            exit={{ opacity: 0 }}
            onClick={onClose}
          />

          {/* Modal */}
          <div className="fixed inset-0 z-50 flex items-center justify-center p-4 pointer-events-none">
            <motion.div
              className="pointer-events-auto w-full max-w-lg"
              initial={{ opacity: 0, scale: 0.92, y: 20 }}
              animate={{ opacity: 1, scale: 1, y: 0 }}
              exit={{ opacity: 0, scale: 0.92, y: 20 }}
              transition={{ type: "spring", damping: 25, stiffness: 300 }}
            >
              <div className="relative rounded-2xl border border-[rgba(255,80,80,0.25)] bg-background shadow-[0_0_60px_rgba(255,80,80,0.12),0_20px_60px_rgba(0,0,0,0.6)] overflow-hidden">
                {/* Top accent bar */}
                <div className="h-1 w-full bg-gradient-to-r from-red-500 via-amber-500 to-[#00FF88]" />

                {/* Header */}
                <div className="p-6 pb-0">
                  <div className="flex items-start justify-between">
                    <div className="flex items-center gap-3">
                      <div className="w-10 h-10 rounded-xl bg-red-500/10 border border-red-500/20 flex items-center justify-center">
                        <AlertTriangle className="w-5 h-5 text-red-400" />
                      </div>
                      <div>
                        <h2 className="text-lg font-black text-white uppercase tracking-tighter">
                          Scan Quota Reached
                        </h2>
                        <p className="text-[10px] text-muted-foreground font-bold uppercase tracking-widest mt-0.5">
                          Upgrade to continue scanning
                        </p>
                      </div>
                    </div>
                    <button
                      onClick={onClose}
                      className="w-8 h-8 rounded-lg bg-white/5 hover:bg-white/10 border border-white/5 flex items-center justify-center transition-colors duration-200"
                    >
                      <X className="w-4 h-4 text-muted-foreground" />
                    </button>
                  </div>

                  {/* Usage summary */}
                  <div className="mt-5 p-4 rounded-xl bg-red-500/5 border border-red-500/15">
                    <div className="flex items-center justify-between text-xs mb-2.5">
                      <span className="text-muted-foreground uppercase tracking-widest font-bold">
                        Monthly scans used
                      </span>
                      <span className="text-red-400 font-black font-mono">
                        {scansUsed} / {scansLimit}
                      </span>
                    </div>
                    <div className="w-full bg-white/5 rounded-full h-2 overflow-hidden border border-white/5">
                      <div
                        className="h-full rounded-full bg-gradient-to-r from-red-500 to-amber-500 shadow-[0_0_8px_rgba(239,68,68,0.5)]"
                        style={{ width: "100%" }}
                      />
                    </div>
                    <p className="text-[10px] text-muted-foreground mt-2 font-medium">
                      Your{" "}
                      <span className="text-muted-foreground font-bold capitalize">{currentPlan}</span>{" "}
                      plan limit has been reached. Upgrade to unlock more scans.
                    </p>
                  </div>
                </div>

                {/* Plan options */}
                <div className={cn("p-6 grid gap-4", isPro ? "grid-cols-1" : "grid-cols-1 sm:grid-cols-2")}>
                  {/* Pro plan — only show for Free users */}
                  {!isPro && (
                    <div className="rounded-xl border border-[rgba(0,255,136,0.2)] bg-[rgba(0,255,136,0.03)] p-4">
                      <div className="flex items-center justify-between mb-3">
                        <div>
                          <h3 className="text-sm font-black text-white uppercase tracking-tighter">
                            Pro
                          </h3>
                          <div className="flex items-baseline gap-1 mt-0.5">
                            <span className="text-xl font-black text-primary tracking-tighter">$5</span>
                            <span className="text-[10px] text-muted-foreground font-mono">/month</span>
                          </div>
                        </div>
                        <Badge className="bg-[rgba(0,255,136,0.1)] text-primary border-[rgba(0,255,136,0.2)] text-[9px] font-black uppercase tracking-widest">
                          Popular
                        </Badge>
                      </div>
                      <ul className="space-y-1.5 mb-4">
                        {PRO_FEATURES.map((f) => (
                          <li key={f} className="flex items-center gap-2 text-[11px] text-muted-foreground">
                            <Check className="w-3 h-3 text-primary flex-shrink-0" />
                            {f}
                          </li>
                        ))}
                      </ul>
                      <Button
                        onClick={() => handleUpgrade("pro")}
                        disabled={isLoading}
                        className="w-full h-9 bg-primary hover:bg-primary/90 text-black font-black text-[10px] uppercase tracking-widest hover:shadow-[0_0_20px_rgba(0,255,136,0.3)] transition-all duration-300"
                      >
                        {isLoading ? (
                          <Loader2 className="w-3.5 h-3.5 animate-spin mr-1.5" />
                        ) : (
                          <ArrowRight className="w-3.5 h-3.5 mr-1.5" />
                        )}
                        Upgrade to Pro
                      </Button>
                    </div>
                  )}

                  {/* Elite plan */}
                  <div className="rounded-xl border border-[rgba(168,85,247,0.3)] bg-[rgba(168,85,247,0.04)] p-4">
                    <div className="flex items-center justify-between mb-3">
                      <div>
                        <div className="flex items-center gap-2">
                          <h3 className="text-sm font-black text-white uppercase tracking-tighter">
                            Elite
                          </h3>
                          <Zap className="w-3.5 h-3.5 text-purple-400 fill-purple-400/30" />
                        </div>
                        <div className="flex items-baseline gap-1 mt-0.5">
                          <span className="text-xl font-black text-purple-400 tracking-tighter">$10</span>
                          <span className="text-[10px] text-muted-foreground font-mono">/month</span>
                        </div>
                      </div>
                      <Badge className="bg-purple-500/10 text-purple-400 border-purple-500/20 text-[9px] font-black uppercase tracking-widest">
                        Unlimited
                      </Badge>
                    </div>
                    <ul className="space-y-1.5 mb-4">
                      {ELITE_FEATURES.map((f) => (
                        <li key={f} className="flex items-center gap-2 text-[11px] text-muted-foreground">
                          <Check className="w-3 h-3 text-purple-400 flex-shrink-0" />
                          {f}
                        </li>
                      ))}
                    </ul>
                    <Button
                      onClick={() => handleUpgrade("elite")}
                      disabled={isLoading}
                      className="w-full h-9 bg-purple-600/20 hover:bg-purple-600/30 text-purple-300 border border-purple-500/30 font-black text-[10px] uppercase tracking-widest hover:shadow-[0_0_20px_rgba(168,85,247,0.2)] transition-all duration-300"
                    >
                      {isLoading ? (
                        <Loader2 className="w-3.5 h-3.5 animate-spin mr-1.5" />
                      ) : (
                        <Zap className="w-3.5 h-3.5 mr-1.5" />
                      )}
                      Upgrade to Elite
                    </Button>
                  </div>
                </div>

                {/* Footer */}
                <div className="px-6 pb-5 flex items-center justify-between">
                  <p className="text-[10px] text-muted-foreground font-medium">
                    Secure checkout via Stripe · Cancel anytime
                  </p>
                  <button
                    onClick={onClose}
                    className="text-[10px] text-muted-foreground hover:text-muted-foreground font-bold uppercase tracking-widest transition-colors duration-200"
                  >
                    Maybe Later
                  </button>
                </div>
              </div>
            </motion.div>
          </div>
        </>
      )}
    </AnimatePresence>
  );
}
