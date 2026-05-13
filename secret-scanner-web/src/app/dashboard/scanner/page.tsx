"use client";

import { useState, useCallback, useEffect, useMemo } from "react";
import { motion, AnimatePresence } from "framer-motion";
import { Sidebar } from "@/components/sidebar";
import {
  useScanHistory,
  AVAILABLE_MODULES
} from "@/hooks/use-scanner";
import { useScannerContext } from "@/contexts/scanner-context";
import { useDashboardStats, useReportDownload, useBilling } from "@/lib/hooks";
import { useSearchParams, useRouter } from "next/navigation";
import { toast } from "sonner";
import { Zap } from "lucide-react";
import { UpgradeModal } from "@/components/upgrade-modal";
import React, { useRef } from "react";

// New Components
import { NavigationTabs } from "@/components/dashboard/scanner/NavigationTabs";
import { MetricsRow } from "@/components/dashboard/scanner/MetricsRow";
import { ScanConfigPanel } from "@/components/dashboard/scanner/ScanConfigPanel";
import { LiveFeedPanel } from "@/components/dashboard/scanner/LiveFeedPanel";
import { ExecutionStream } from "@/components/dashboard/scanner/ExecutionStream";
import { PhaseTracker } from "@/components/dashboard/scanner/PhaseTracker";
import { FindingsTable } from "@/components/dashboard/scanner/FindingsTable";
import { ScanHistory } from "@/components/dashboard/scan-history";
import { AISecurityPanel } from "@/components/dashboard/scanner/ai-copilot/AISecurityPanel";
import { POCSection } from "@/components/dashboard/scanner/poc/POCSection";
import { AttackGraphSection } from "@/components/dashboard/scanner/attack-graph/AttackGraphSection";
import dynamic from "next/dynamic";



export default function ScannerPage() {
  const searchParams = useSearchParams();
  const router = useRouter();
  const [activeTab, setActiveTab] = useState("scanner");

  useEffect(() => {
    const tab = searchParams.get("tab");
    if (tab && ["scanner", "findings", "verification", "history"].includes(tab)) {
      setActiveTab(tab);
    }
  }, [searchParams]);

  // Scanner hooks — shared via context so /scan-results sees the same data
  const {
    isScanning, scanLifecycle, scanStatus, findings, logs, scanId,
    startScan, cancelScan, clearScan,
    // Enterprise intelligence state
    enterpriseTelemetry, payloadsExecuted, verifiedFindings,
    attackChains, aiDecision, riskData, endpointsDiscovered,
  } = useScannerContext();
  const [isPaused, setIsPaused] = useState(false);

  // Billing / quota
  const { subscription, usage, upgrade, checkoutLoading } = useBilling();
  const [showUpgradeModal, setShowUpgradeModal] = useState(false);
  const scansUsed = subscription?.scans_used ?? usage?.scans_this_month ?? 0;
  const scansLimit = subscription?.scans_limit ?? usage?.scans_limit ?? 10;
  const currentPlan = (subscription?.plan_name ?? "free").toLowerCase();

  const handleTogglePause = useCallback(() => {
    setIsPaused(prev => !prev);
    if (!isPaused) {
      toast.info("Scan execution suspended");
    } else {
      toast.success("Scan execution resumed");
    }
  }, [isPaused]);

  useEffect(() => {
    if (!isScanning) {
      setIsPaused(false);
    }
  }, [isScanning]);



  const { scans: scanHistory, refreshScans } = useScanHistory();

  // Dashboard data hooks
  const { refresh: refreshStats } = useDashboardStats();
  const { downloadReport } = useReportDownload();

  // Map modules to new design format
  const mappedModules = useMemo(() => AVAILABLE_MODULES.map(m => ({
    id: m.key,
    name: m.name,
    patternCount: m.patterns || 0,
    description: m.description,
    owasp: m.owasp
  })), []);

  // Handlers
  const handleStartScan = useCallback(
    async (target: string, modules: string[], strategy: string, type: any) => {
      // Pre-flight quota check
      if (scansUsed >= scansLimit) {
        setShowUpgradeModal(true);
        return;
      }
      try {
        await startScan(target, modules, type, strategy);
        refreshScans();
        refreshStats();
      } catch (err: any) {
        // Backend 403 = scan limit hit (fallback safety net)
        if (
          err?.status === 403 ||
          String(err?.message ?? "").toLowerCase().includes("scan limit")
        ) {
          setShowUpgradeModal(true);
        }
        // Other errors are handled in the hook
      }
    },
    [startScan, refreshScans, refreshStats, scansUsed, scansLimit]
  );

  const handleExportFindings = useCallback(() => {
    const json = JSON.stringify(findings, null, 2);
    const blob = new Blob([json], { type: "application/json" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `quantara-findings-${new Date().toISOString().slice(0, 10)}.json`;
    a.click();
    URL.revokeObjectURL(url);
    toast.success("Intelligence data exported successfully");
  }, [findings]);

  const handleDownloadReport = useCallback(async (scanId: string) => {
    await downloadReport(scanId, "html");
    toast.success("Comprehensive report generated and downloaded");
  }, [downloadReport]);

  return (
    <Sidebar>
      <div className="min-h-screen bg-background text-foreground font-sans selection:bg-primary/30 selection:text-foreground">
        <div className="max-w-[1600px] mx-auto space-y-8 pb-12">

          {/* Top Bar: Navigation & Status */}
          <div className="flex flex-col md:flex-row md:items-center justify-between gap-6 pt-2">
            <div className="space-y-1">
              <h1 className="text-2xl font-black text-foreground uppercase tracking-tighter flex items-center gap-3">
                <div className="w-8 h-8 rounded-lg bg-gradient-to-br from-primary to-blue-500 flex items-center justify-center p-0.5">
                  <div className="w-full h-full bg-background rounded-[7px] flex items-center justify-center">
                    <Zap className="w-4 h-4 text-primary fill-primary/20" />
                  </div>
                </div>
                Quantara Security <span className="text-muted-foreground/40 ml-2">v4.0.2</span>
              </h1>
              <p className="text-[10px] text-muted-foreground font-bold uppercase tracking-[0.3em] ml-1">Autonomous Security Intelligence Engine</p>
            </div>

            <div className="flex items-center gap-4">
              <NavigationTabs activeTab={activeTab} onTabChange={setActiveTab} />

              <div className="h-8 w-px bg-border/30 hidden md:block" />

              <div className="flex items-center gap-3">
                {isScanning ? (
                  <div className="flex items-center gap-2 px-4 py-1.5 rounded-full bg-primary/10 border border-primary/20">
                    <div className="w-2 h-2 rounded-full bg-primary animate-ping" />
                    <span className="text-[10px] font-black text-primary uppercase tracking-widest">Active Scan</span>
                  </div>
                ) : (
                  <div className="flex items-center gap-2 px-4 py-1.5 rounded-full bg-secondary border border-border/20">
                    <div className="w-2 h-2 rounded-full bg-muted-foreground" />
                    <span className="text-[10px] font-black text-muted-foreground uppercase tracking-widest">Standby Mode</span>
                  </div>
                )}
              </div>
            </div>
          </div>

          {/* Metrics Row — real-time data from live scan state + enterprise telemetry */}
          <MetricsRow
            assetsAnalyzed={scanStatus?.modules_completed ?? 0}
            issuesDetected={findings.length}
            riskScore={
              riskData?.new_score ??
              (!scanId
                ? 0
                : findings.length > 0
                  ? Math.max(0, 100 - (
                    findings.filter(f => f.severity === 'critical').length * 15 +
                    findings.filter(f => f.severity === 'high').length * 8 +
                    findings.filter(f => f.severity === 'medium').length * 3 +
                    findings.filter(f => f.severity === 'low').length * 1
                  ))
                  : Math.round(scanStatus?.progress ?? 0))
            }
            scanCoverage={scanStatus?.progress ?? 0}
            payloadsFired={payloadsExecuted.reduce((sum, p) => sum + (p.total_payloads_fired || 0), 0)}
            endpointsCount={endpointsDiscovered.length}
          />

          {/* Tab Content */}
          <AnimatePresence mode="wait">
            {activeTab === "scanner" && (
              <motion.div
                key="scanner-view"
                initial={{ opacity: 0, y: 20 }}
                animate={{ opacity: 1, y: 0 }}
                exit={{ opacity: 0, y: -20 }}
                className="space-y-6"
              >
                {/* Upper Section: Config + Live Feed */}
                <div className="grid grid-cols-1 md:grid-cols-12 gap-6">
                  <div className="md:col-span-8 h-full">
                    <ScanConfigPanel
                      onStart={handleStartScan}
                      onCancel={cancelScan}
                      onPause={handleTogglePause}
                      isScanning={isScanning}
                      isPaused={isPaused}
                      availableModules={mappedModules}
                    />
                  </div>
                  <div className="md:col-span-4 h-full">
                    <LiveFeedPanel
                      findings={findings.map(f => ({
                        id: f.id,
                        severity: f.severity as any,
                        title: f.title,
                        target: f.file || "",
                        timestamp: f.timestamp || new Date().toLocaleTimeString(),
                        module: f.module_name || f.module || "",
                        cwe: f.cwe || "",
                        owasp: f.owasp || "",
                        matched_content: f.matched_content || "",
                        description: f.description || "",
                        line_number: f.line_number || null,
                        confidence: f.confidence || null,
                      }))}
                      isScanning={isScanning}
                    />
                  </div>
                </div>

                {/* Lower Section: Stream + Phase Tracker */}
                <div className="grid grid-cols-1 md:grid-cols-12 gap-6 min-h-[400px]">
                  <div className="md:col-span-8 h-full">
                    <ExecutionStream
                      logs={logs.map(l => ({
                        message: l.message,
                        level: l.level,
                        timestamp: l.time,
                        module: l.module,
                      }))}
                      isScanning={isScanning}
                      onClear={clearScan}
                      scanStatus={scanStatus ? {
                        progress: scanStatus.progress,
                        active_module: scanStatus.active_module,
                        modules_completed: scanStatus.modules_completed,
                        modules_total: scanStatus.modules_total,
                        elapsed_seconds: scanStatus.elapsed_seconds,
                      } : null}
                      findingsCount={findings.length}
                      payloadsFired={payloadsExecuted.reduce((sum, p) => sum + p.total_payloads_fired, 0)}
                    />
                  </div>
                  <div className="md:col-span-4 h-full">
                    <PhaseTracker
                      progress={scanStatus?.progress || 0}
                      activeModule={scanStatus?.active_module}
                      modulesCompleted={scanStatus?.modules_completed}
                      modulesTotal={scanStatus?.modules_total}
                      findingsCount={findings.length}
                    />
                  </div>
                </div>

                {/* Bottom Section: Full-Width Findings */}
                <div className="w-full">
                  <FindingsTable
                    findings={findings.map(f => ({
                      id: f.id,
                      severity: f.severity as any,
                      title: f.title,
                      target: f.file || "",
                      module: f.module_name || f.module || "Unknown",
                      confidence: f.confidence || 1.0,
                      timestamp: f.timestamp || new Date().toLocaleString()
                    }))}
                    onExport={handleExportFindings}
                  />
                </div>

                {/* AI Security Co-Pilot Panel */}
                <AISecurityPanel
                  findings={findings}
                  aiDecision={aiDecision}
                  enterpriseTelemetry={enterpriseTelemetry}
                  riskData={riskData}
                  payloadsExecuted={payloadsExecuted}
                />

                {/* Proof of Concept Verification (Enterprise SOC Module) */}
                <POCSection
                  findings={findings}
                  scanId={scanStatus?.scan_id}
                  verifiedFindings={verifiedFindings}
                />

                {/* Attack Path Intelligence — Neo4j Graph Engine + Enterprise Chains */}
                <AttackGraphSection
                  findings={findings}
                  scanId={scanStatus?.scan_id}
                  attackChains={attackChains}
                />
              </motion.div>
            )}

            {activeTab === "findings" && (
              <motion.div
                key="findings-view"
                initial={{ opacity: 0, y: 20 }}
                animate={{ opacity: 1, y: 0 }}
                exit={{ opacity: 0, y: -20 }}
                className="w-full"
              >
                <FindingsTable
                  findings={findings.map(f => ({
                    id: f.id,
                    severity: f.severity as any,
                    title: f.title,
                    target: f.file || "",
                    module: f.module_name || f.module || "Unknown",
                    confidence: f.confidence || 1.0,
                    timestamp: f.timestamp || new Date().toLocaleString()
                  }))}
                  onExport={handleExportFindings}
                />
              </motion.div>
            )}

            {activeTab === "verification" && (
              <motion.div
                key="verification-view"
                initial={{ opacity: 0, y: 20 }}
                animate={{ opacity: 1, y: 0 }}
                exit={{ opacity: 0, y: -20 }}
                className="w-full space-y-0"
              >
                <POCSection
                  findings={findings}
                  scanId={scanStatus?.scan_id}
                  verifiedFindings={verifiedFindings}
                />
                <AttackGraphSection
                  findings={findings}
                  scanId={scanStatus?.scan_id}
                  attackChains={attackChains}
                />
              </motion.div>
            )}



            {activeTab === "history" && (
              <motion.div
                key="history-view"
                initial={{ opacity: 0, y: 20 }}
                animate={{ opacity: 1, y: 0 }}
                exit={{ opacity: 0, y: -20 }}
                className="w-full"
              >
                <ScanHistory
                  scans={scanHistory}
                  onRefresh={refreshScans}
                  onViewScan={(sid) => router.push(`/dashboard/scan-results?scanId=${sid}`)}
                  onDownloadReport={handleDownloadReport}
                />
              </motion.div>
            )}
          </AnimatePresence>
        </div>
      </div>

      {/* Upgrade Modal — fires when scan quota is reached */}
      <UpgradeModal
        isOpen={showUpgradeModal}
        onClose={() => setShowUpgradeModal(false)}
        currentPlan={currentPlan}
        scansUsed={scansUsed}
        scansLimit={scansLimit}
        onUpgrade={upgrade}
        isLoading={checkoutLoading}
      />
    </Sidebar>
  );
}
