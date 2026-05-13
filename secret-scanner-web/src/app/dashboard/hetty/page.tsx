"use client";

import { useState, useEffect } from "react";
import { Sidebar } from "@/components/sidebar";
import { HettyToolkit } from "@/components/dashboard/scanner/poc/HettyToolkit";
import { useRouter } from "next/navigation";
import { motion } from "framer-motion";
import {
  Terminal, ArrowLeft, Shield, Zap, History, Clock,
  ExternalLink, AlertTriangle,
} from "lucide-react";
import { cn } from "@/lib/utils";
import { toast } from "sonner";

interface PassedFinding {
  id?: string;
  title?: string;
  target?: string;
  endpoint?: string;
  url?: string;
  method?: string;
  matched_content?: string;
  evidence?: string;
  severity?: string;
  owasp_category?: string;
  cwe?: string;
  confidence?: number;
  headers?: Record<string, string>;
  params?: Record<string, string>;
  body?: string;
  vulnerability_type?: string;
  scan_id?: string;
}

export default function HettyPage() {
  const router = useRouter();
  const [finding, setFinding] = useState<PassedFinding | null>(null);
  const [scanId, setScanId] = useState<string | undefined>(undefined);
  const [showBanner, setShowBanner] = useState(false);

  // Load finding data from sessionStorage (passed from scanner page)
  useEffect(() => {
    try {
      const raw = sessionStorage.getItem("hetty_finding");
      if (raw) {
        const data = JSON.parse(raw);
        setFinding(data.finding || null);
        setScanId(data.scan_id || undefined);
        setShowBanner(true);
        // Clear after loading so refreshing doesn't re-load stale data
        sessionStorage.removeItem("hetty_finding");
        toast.success("Finding loaded — ready for manual verification");
      }
    } catch {
      // No data or parse error — just show empty Hetty
    }
  }, []);

  return (
    <Sidebar>
      <div className="min-h-screen">
        {/* Page Header */}
        <motion.div
          initial={{ opacity: 0, y: -10 }}
          animate={{ opacity: 1, y: 0 }}
          className="mb-6"
        >
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-4">
              <button
                type="button"
                onClick={() => router.push("/dashboard/scanner")}
                className="p-2 rounded-xl border border-border/20 text-muted-foreground hover:text-primary hover:border-primary/30 transition-colors"
                title="Back to Scanner"
              >
                <ArrowLeft className="w-4 h-4" />
              </button>

              <div className="flex items-center gap-3">
                <div className="relative">
                  <div className="w-11 h-11 rounded-xl bg-primary/10 border border-primary/20 flex items-center justify-center">
                    <Terminal className="w-5 h-5 text-primary" />
                  </div>
                  <div className="absolute -bottom-0.5 -right-0.5 w-3 h-3 rounded-full bg-background border border-primary/30 flex items-center justify-center">
                    <div className="w-1.5 h-1.5 rounded-full bg-primary animate-pulse" />
                  </div>
                </div>

                <div>
                  <h1 className="text-xl font-bold text-foreground uppercase tracking-tight flex items-center gap-2 font-outfit">
                    Quantara <span className="text-primary">Toolkit</span>
                  </h1>
                  <p className="text-[10px] text-muted-foreground font-medium uppercase tracking-wider">
                    Manual Penetration Testing Console — Craft, Send, Intercept, Replay
                  </p>
                </div>
              </div>
            </div>

            <div className="flex items-center gap-2">
              <button
                type="button"
                onClick={() => router.push("/dashboard/scanner")}
                className="flex items-center gap-2 px-4 py-2 rounded-xl border border-border/20 text-muted-foreground text-[10px] font-black uppercase tracking-widest hover:border-primary/30 hover:text-primary transition-colors"
              >
                <Shield className="w-3.5 h-3.5" />
                Scanner
              </button>
            </div>
          </div>
        </motion.div>

        {/* Finding Banner — shown when redirected from scanner */}
        {showBanner && finding && (
          <motion.div
            initial={{ opacity: 0, y: -10 }}
            animate={{ opacity: 1, y: 0 }}
            className="mb-4 p-4 rounded-xl border border-blue-500/30 bg-blue-500/5 flex items-center justify-between"
          >
            <div className="flex items-center gap-3">
              <div className="p-2 rounded-lg bg-blue-500/10 border border-blue-500/20">
                <Zap className="w-4 h-4 text-blue-500" />
              </div>
              <div>
                <p className="text-[11px] font-black text-foreground uppercase tracking-widest">
                  Manual Verification Mode
                </p>
                <p className="text-[9px] text-muted-foreground mt-0.5">
                  {finding.vulnerability_type && (
                    <span className="text-blue-500 font-bold mr-2">[{finding.vulnerability_type}]</span>
                  )}
                  {finding.title || "Finding"} — {finding.target || finding.endpoint || finding.url || "Unknown target"}
                  {finding.severity && (
                    <span className={cn("ml-2 px-1.5 py-0.5 rounded text-[8px] font-black uppercase",
                      finding.severity === "critical" ? "text-red-400 bg-red-400/10" :
                        finding.severity === "high" ? "text-orange-400 bg-orange-400/10" :
                          finding.severity === "medium" ? "text-yellow-400 bg-yellow-400/10" :
                            "text-muted-foreground bg-muted/10"
                    )}>
                      {finding.severity}
                    </span>
                  )}
                </p>
              </div>
            </div>
            <button
              type="button"
              onClick={() => setShowBanner(false)}
              className="text-muted-foreground hover:text-foreground transition-colors p-1"
            >
              <span className="text-[9px] font-bold uppercase tracking-widest">Dismiss</span>
            </button>
          </motion.div>
        )}

        {/* Main Hetty Toolkit */}
        <motion.div
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ delay: 0.1 }}
        >
          <HettyToolkit
            finding={finding || undefined}
            scanId={scanId}
          />
        </motion.div>

        {/* Quick Tips */}
        <motion.div
          initial={{ opacity: 0 }}
          animate={{ opacity: 1 }}
          transition={{ delay: 0.3 }}
          className="mt-6 grid grid-cols-1 md:grid-cols-3 gap-4"
        >
          {[
            {
              icon: Zap,
              title: "Quick Send",
              desc: "Press Ctrl+Enter to send request instantly",
              color: "text-primary",
              bg: "bg-primary/10",
              border: "border-primary/30",
            },
            {
              icon: History,
              title: "Request History",
              desc: "All requests are saved — click History to replay",
              color: "text-blue-500",
              bg: "bg-blue-500/10",
              border: "border-blue-500/30",
            },
            {
              icon: AlertTriangle,
              title: "Auto Detection",
              desc: "Responses are scanned for SQLi, XSS, SSRF, LFI & more",
              color: "text-destructive",
              bg: "bg-destructive/10",
              border: "border-destructive/30",
            },
          ].map((tip) => (
            <div
              key={tip.title}
              className="p-4 rounded-xl bg-secondary border border-border/20 flex items-start gap-3"
            >
              <div
                className={cn("p-2 rounded-lg shrink-0 border", tip.bg, tip.border)}
              >
                <tip.icon className={cn("w-4 h-4", tip.color)} />
              </div>
              <div>
                <p className="text-[10px] font-black text-foreground uppercase tracking-widest">{tip.title}</p>
                <p className="text-[9px] text-muted-foreground mt-0.5">{tip.desc}</p>
              </div>
            </div>
          ))}
        </motion.div>
      </div>
    </Sidebar>
  );
}
