"use client";

import { useState, useEffect, useCallback } from "react";
import { useRouter } from "next/navigation";
import {
  Terminal,
  Zap,
  ChevronDown,
  ChevronUp,
  Activity,
  ExternalLink,
  Copy,
  Check,
  ShieldCheck,
  ChevronRight,
} from "lucide-react";
import { motion, AnimatePresence } from "framer-motion";
import { GlowCard } from "@/components/ui/glow-card";
import { cn } from "@/lib/utils";
import { toast } from "sonner";
import { VulnerabilityHeader } from "./VulnerabilityHeader";
import { EndpointViewer } from "./EndpointViewer";
import { ValidationStatus } from "./ValidationStatus";

interface POCSectionProps {
  findings: any[];
  scanId?: string;
  verifiedFindings?: any[];
}

export function POCSection({ findings, scanId, verifiedFindings = [] }: POCSectionProps) {
  const router = useRouter();
  const [isCollapsed, setIsCollapsed] = useState(false);
  const [selectedVulnerability, setSelectedVulnerability] = useState<any>(null);
  const [copiedEvidence, setCopiedEvidence] = useState(false);
  const [markedVerified, setMarkedVerified] = useState<Set<string>>(new Set());

  useEffect(() => {
    if (findings && findings.length > 0 && !selectedVulnerability) {
      setSelectedVulnerability(findings[0]);
    }
  }, [findings, selectedVulnerability]);

  const hasFindings = findings && findings.length > 0;

  // Copy evidence to clipboard
  const copyEvidence = useCallback(() => {
    if (!selectedVulnerability) return;
    const evidence = selectedVulnerability.matched_content || selectedVulnerability.evidence || selectedVulnerability.payload || "";
    if (!evidence) {
      toast.error("No evidence available to copy");
      return;
    }
    navigator.clipboard.writeText(evidence).then(() => {
      setCopiedEvidence(true);
      toast.success("Evidence copied to clipboard");
      setTimeout(() => setCopiedEvidence(false), 2000);
    });
  }, [selectedVulnerability]);

  // Mark finding as verified (local state)
  const markVerified = useCallback(() => {
    if (!selectedVulnerability?.id) return;
    setMarkedVerified(prev => new Set(prev).add(selectedVulnerability.id));
    toast.success("Finding marked as verified");
  }, [selectedVulnerability]);

  // Redirect to Hetty with finding data
  const manualVerification = useCallback((finding: any) => {
    try {
      sessionStorage.setItem("hetty_finding", JSON.stringify({
        finding: {
          id: finding.id,
          title: finding.title,
          target: finding.target,
          endpoint: finding.endpoint || finding.file || finding.path,
          url: finding.target || finding.endpoint,
          method: finding.method || "GET",
          matched_content: finding.matched_content,
          evidence: finding.evidence,
          severity: finding.severity,
          owasp_category: finding.owasp_category,
          cwe: finding.cwe,
          confidence: finding.confidence,
          vulnerability_type: finding.vuln_type || finding.owasp_category || finding.title,
        },
        scan_id: scanId,
      }));
    } catch { /* sessionStorage full or blocked */ }
    router.push("/dashboard/hetty");
  }, [scanId, router]);

  const evidence = selectedVulnerability?.matched_content || selectedVulnerability?.evidence || selectedVulnerability?.payload || "";
  const isVerified = selectedVulnerability?.id && markedVerified.has(selectedVulnerability.id);

  return (
    <div className="w-full mt-8 relative group">
      <GlowCard
        initial={{ opacity: 0, y: 30 }}
        whileInView={{ opacity: 1, y: 0 }}
        viewport={{ once: true }}
        glowColor="rgba(var(--primary), 0.12)"
        className="p-0 border-primary/20 bg-background/90 backdrop-blur-2xl overflow-hidden"
      >
        {/* Header */}
        <div className="flex items-center justify-between p-5 border-b border-border bg-gradient-to-r from-primary/5 to-transparent">
          <div className="flex items-center gap-4">
            <div className="relative">
              <div className="w-10 h-10 rounded-xl bg-primary/10 border border-primary/20 flex items-center justify-center">
                <Terminal className="w-5 h-5 text-primary" />
              </div>
              {hasFindings && (
                <div className="absolute -bottom-0.5 -right-0.5 w-3 h-3 rounded-full bg-background border border-primary/30 flex items-center justify-center">
                  <div className="w-1.5 h-1.5 rounded-full bg-primary animate-pulse" />
                </div>
              )}
            </div>

            <div>
              <h2 className="text-base font-bold text-foreground uppercase tracking-tight flex items-center gap-2">
                Proof of Concept <span className="text-primary">Verification</span>
              </h2>
              <p className="text-[10px] text-muted-foreground font-medium uppercase tracking-wider">
                {verifiedFindings.length > 0
                  ? `${verifiedFindings.length} exploit(s) verified with proof`
                  : "Manual validation for discovered vulnerabilities"
                }
              </p>
            </div>
          </div>

          <div className="flex items-center gap-3">
            <div className="hidden lg:flex items-center gap-4 px-4 py-1.5 rounded-lg bg-background/40 border border-border">
              <div className="text-center">
                <p className="text-[8px] text-muted-foreground font-bold uppercase tracking-widest">Findings</p>
                <p className="text-sm font-bold text-foreground">{findings.length}</p>
              </div>
              <div className="w-px h-6 bg-border" />
              <div className="text-center">
                <p className="text-[8px] text-muted-foreground font-bold uppercase tracking-widest">Avg Conf</p>
                <p className="text-sm font-bold text-primary">
                  {findings.length > 0 ? (findings.reduce((acc: number, curr: any) => acc + (curr.confidence || 0), 0) / findings.length * 100).toFixed(0) : 0}%
                </p>
              </div>
              {verifiedFindings.length > 0 && (
                <>
                  <div className="w-px h-6 bg-border" />
                  <div className="text-center">
                    <p className="text-[8px] text-muted-foreground font-bold uppercase tracking-widest">Verified</p>
                    <p className="text-sm font-bold text-primary">{verifiedFindings.length}</p>
                  </div>
                </>
              )}
            </div>

            <button
              type="button"
              onClick={() => setIsCollapsed(!isCollapsed)}
              className="p-2 rounded-lg bg-secondary border border-border text-muted-foreground hover:text-foreground hover:border-primary/30 transition-colors"
            >
              {isCollapsed ? <ChevronDown className="w-4 h-4" /> : <ChevronUp className="w-4 h-4" />}
            </button>
          </div>
        </div>

        {/* Main Content */}
        <AnimatePresence>
          {!isCollapsed && (
            <motion.div
              initial={{ height: 0, opacity: 0 }}
              animate={{ height: "auto", opacity: 1 }}
              exit={{ height: 0, opacity: 0 }}
              className="overflow-hidden bg-background"
            >
              {!hasFindings ? (
                <div className="p-10 flex flex-col items-center justify-center text-center space-y-3">
                  <div className="w-14 h-14 rounded-full bg-secondary border border-border flex items-center justify-center">
                    <Activity className="w-7 h-7 text-muted-foreground animate-pulse" />
                  </div>
                  <div className="space-y-1 max-w-sm">
                    <h3 className="text-xs font-bold text-muted-foreground uppercase tracking-widest">Awaiting Findings</h3>
                    <p className="text-[10px] text-muted-foreground/80 leading-relaxed">
                      The verification section activates once vulnerabilities are detected by the scanner.
                    </p>
                  </div>
                </div>
              ) : (
                <div className="p-4">
                  {/* Vulnerability Selector */}
                  <div className="flex gap-2 overflow-x-auto no-scrollbar pb-4 border-b border-border mb-6">
                    {findings.map((f, i) => (
                      <button
                        key={f.id || i}
                        type="button"
                        onClick={() => { setSelectedVulnerability(f); setCopiedEvidence(false); }}
                        className={cn(
                          "px-4 py-2 rounded-lg text-[10px] font-black uppercase tracking-widest transition-all whitespace-nowrap border shrink-0 flex items-center gap-2",
                          selectedVulnerability?.id === f.id
                            ? "bg-primary/10 border-primary/30 text-primary"
                            : "bg-secondary border-border text-muted-foreground hover:text-foreground hover:border-primary/20"
                        )}
                      >
                        {f.title}
                        {markedVerified.has(f.id) && (
                          <ShieldCheck className="w-3 h-3 text-primary" />
                        )}
                      </button>
                    ))}
                  </div>

                  {selectedVulnerability && (
                    <div className="space-y-6">
                      {/* Section 1: Vulnerability Summary */}
                      <VulnerabilityHeader data={selectedVulnerability} />

                      {/* Section 2 + 3: Target + Evidence side by side */}
                      <div className="grid grid-cols-1 xl:grid-cols-2 gap-6">
                        {/* Target Information */}
                        <EndpointViewer data={selectedVulnerability} />

                        {/* Evidence + Validation Status */}
                        <div className="space-y-6">
                          <ValidationStatus
                            status={
                              isVerified ? "VERIFIED" :
                                selectedVulnerability.validationStatus || "PENDING"
                            }
                            verificationData={selectedVulnerability.verification_proof || undefined}
                          />

                          {/* Evidence Block */}
                          {evidence && (
                            <div className="bg-background/40 border border-border rounded-2xl p-5 space-y-4">
                              <div className="flex items-center justify-between">
                                <p className="text-[9px] text-muted-foreground font-bold uppercase tracking-widest">Matched Evidence</p>
                                <button
                                  type="button"
                                  onClick={copyEvidence}
                                  className="flex items-center gap-1.5 px-2.5 py-1 rounded-lg text-[8px] font-black uppercase tracking-widest border transition-colors bg-secondary border-border text-muted-foreground hover:text-primary hover:border-primary/30"
                                >
                                  {copiedEvidence ? <Check className="w-2.5 h-2.5 text-primary" /> : <Copy className="w-2.5 h-2.5" />}
                                  {copiedEvidence ? "Copied" : "Copy"}
                                </button>
                              </div>
                              <code className="block text-[11px] font-mono text-destructive/90 break-all leading-relaxed bg-destructive/10 border border-destructive/20 p-4 rounded-xl max-h-32 overflow-y-auto no-scrollbar select-all">
                                {evidence.slice(0, 500)}{evidence.length > 500 ? "..." : ""}
                              </code>
                            </div>
                          )}
                        </div>
                      </div>

                      {/* Section 4: Actions */}
                      <div className="flex flex-col sm:flex-row gap-3 pt-2">
                        {/* Manual Verification — primary CTA */}
                        <button
                          type="button"
                          onClick={() => manualVerification(selectedVulnerability)}
                          className="flex-1 group/btn relative overflow-hidden flex items-center justify-center gap-3 bg-gradient-to-r from-primary to-blue-500 py-3.5 rounded-xl font-black text-[11px] text-primary-foreground uppercase tracking-widest transition-all hover:scale-[1.01] active:scale-[0.99] shadow-[0_0_20px_rgba(var(--primary),0.2)]"
                        >
                          <ExternalLink className="w-4 h-4" />
                          Manual Verification
                          <ChevronRight className="w-4 h-4" />
                          <div className="absolute -inset-1 bg-white/20 -translate-x-full group-hover/btn:translate-x-full transition-transform duration-1000 skew-x-12" />
                        </button>

                        {/* Copy Evidence */}
                        <button
                          type="button"
                          onClick={copyEvidence}
                          disabled={!evidence}
                          className={cn(
                            "flex items-center justify-center gap-2 px-6 py-3.5 rounded-xl border text-[11px] font-black uppercase tracking-widest transition-colors",
                            copiedEvidence
                              ? "border-primary/30 bg-primary/10 text-primary"
                              : "border-border bg-secondary text-muted-foreground hover:border-primary/30 hover:text-primary disabled:opacity-30 disabled:cursor-not-allowed"
                          )}
                        >
                          {copiedEvidence ? <Check className="w-4 h-4" /> : <Copy className="w-4 h-4" />}
                          {copiedEvidence ? "Copied" : "Copy Evidence"}
                        </button>

                        {/* Mark as Verified */}
                        <button
                          type="button"
                          onClick={markVerified}
                          disabled={isVerified}
                          className={cn(
                            "flex items-center justify-center gap-2 px-6 py-3.5 rounded-xl border text-[11px] font-black uppercase tracking-widest transition-colors",
                            isVerified
                              ? "border-primary/30 bg-primary/10 text-primary"
                              : "border-border bg-secondary text-muted-foreground hover:border-primary/30 hover:text-primary"
                          )}
                        >
                          <ShieldCheck className="w-4 h-4" />
                          {isVerified ? "Verified" : "Mark as Verified"}
                        </button>
                      </div>
                    </div>
                  )}
                </div>
              )}
            </motion.div>
          )}
        </AnimatePresence>
      </GlowCard>
    </div>
  );
}
