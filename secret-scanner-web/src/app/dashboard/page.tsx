"use client";

import Link from "next/link";
import { useState, useCallback, useEffect } from "react";
import { motion } from "framer-motion";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Sidebar } from "@/components/sidebar";
import { RealTimeFindingsPanel } from "@/components/real-time-findings-panel";
import { ScanConsole } from "@/components/scan-console";
import { StatsCards } from "@/components/dashboard/stats-cards";
import { ScanCharts } from "@/components/dashboard/scan-charts";
import { ScanLauncher } from "@/components/dashboard/scan-launcher";
import { FindingsTable } from "@/components/dashboard/findings-table";
import { ScanHistory } from "@/components/dashboard/scan-history";
import {
  useScanHistory,
  useHealthCheck,
  AVAILABLE_MODULES,
} from "@/hooks/use-scanner";
import { useScannerContext } from "@/contexts/scanner-context";
import {
  useDashboardStats,
  useProfiles,
  useReportDownload,
  useCloudHistory,
  useTasks,
  useBilling
} from "@/lib/hooks";
import { useSearchParams } from "next/navigation";
import {
  LayoutDashboard,
  Scan,
  FileSearch,
  Calendar,
  Sparkles,
} from "lucide-react";
import { toast } from "sonner";

export default function DashboardPage() {
  const searchParams = useSearchParams();
  const [activeTab, setActiveTab] = useState("scanner");

  useEffect(() => {
    const tab = searchParams.get("tab");
    if (tab && ["scanner", "findings", "history", "tasks"].includes(tab)) {
      setActiveTab(tab);
    }
  }, [searchParams]);

  // Scanner hooks — shared via context
  const {
    isScanning, scanStatus, findings, logs,
    startScan, cancelScan, clearScan,
  } = useScannerContext();
  const { scans: scanHistory, refreshScans } = useScanHistory();
  const { health } = useHealthCheck();

  // Dashboard data hooks
  const { stats: dashboardStats, refresh: refreshStats } = useDashboardStats();
  const { profiles } = useProfiles();
  const { downloadReport, isDownloading } = useReportDownload();

  // New Cloud Hooks
  const { scans: cloudHistory, loading: historyLoading } = useCloudHistory();
  const { tasks: remediationTasks, loading: tasksLoading, toggleTask } = useTasks();
  const { profile } = useBilling();

  // Compute stats either from dashboard API or local state
  const totalScans = dashboardStats?.total_scans ?? scanHistory.length;
  const completedScans = dashboardStats?.completed_scans ?? scanHistory.filter((s) => s.status === "completed").length;
  const runningScans = dashboardStats?.running_scans ?? (isScanning ? 1 : 0);
  const totalFindings = dashboardStats?.total_findings ?? findings.length;
  const severityCounts = dashboardStats?.severity_counts ?? {
    critical: findings.filter((f) => (f.severity || "").toLowerCase() === "critical").length,
    high: findings.filter((f) => (f.severity || "").toLowerCase() === "high").length,
    medium: findings.filter((f) => (f.severity || "").toLowerCase() === "medium").length,
    low: findings.filter((f) => (f.severity || "").toLowerCase() === "low").length,
    info: findings.filter((f) => (f.severity || "").toLowerCase() === "info").length,
  };
  const securityScore = dashboardStats?.security_score ?? Math.max(0, 100 -
    (severityCounts.critical || 0) * 15 - (severityCounts.high || 0) * 8 - (severityCounts.medium || 0) * 3
  );

  // Handlers
  const handleStartScan = useCallback(
    async (target: string, modules: string[], scanType: string, profile: string) => {
      try {
        await startScan(target, modules, scanType as any);
        refreshScans();
        refreshStats();
      } catch { /* handled in hook */ }
    },
    [startScan, refreshScans, refreshStats]
  );

  const handleExportFindings = useCallback(() => {
    const json = JSON.stringify(findings, null, 2);
    const blob = new Blob([json], { type: "application/json" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `findings-${new Date().toISOString().slice(0, 10)}.json`;
    a.click();
    URL.revokeObjectURL(url);
    toast.success("Findings exported");
  }, [findings]);

  const handleDownloadReport = useCallback(async (scanId: string) => {
    await downloadReport(scanId, "html");
    toast.success("Report downloaded");
  }, [downloadReport]);

  return (
    <Sidebar>
      <div className="space-y-6">
        {/* Header */}
        <motion.div
          initial={{ opacity: 0, y: -20 }}
          animate={{ opacity: 1, y: 0 }}
          className="flex items-center justify-between flex-wrap gap-4"
        >
          <div>
            <h1 className="text-3xl font-bold tracking-tight flex items-center gap-2 text-foreground">
              <LayoutDashboard className="h-8 w-8 text-neon-green" />
              Dashboard
            </h1>
            <p className="text-foreground mt-1">Real-time OWASP security scanning platform</p>
          </div>
          <div className="flex items-center gap-2">
            <Button variant="outline" className="border-border text-foreground">
              <Calendar className="h-4 w-4 mr-2" />
              {health ? `v${health.version}` : "v5.0.0"}
            </Button>
            <Link href="/dashboard/scanner">
              <Button
                className="bg-neon-green/15 hover:bg-neon-green/25 text-neon-green border border-neon-green/30"
              >
                <Sparkles className="h-4 w-4 mr-2" /> Launch Scanner
              </Button>
            </Link>
          </div>
        </motion.div>

        {/* Stats Cards */}
        <StatsCards
          totalScans={totalScans}
          completedScans={completedScans}
          totalFindings={totalFindings}
          criticalFindings={severityCounts.critical || 0}
          securityScore={securityScore}
          runningScans={runningScans}
          plan={profile?.plan}
          scansUsed={profile?.scansUsedThisMonth}
          scansLimit={profile?.scanLimit}
        />

        {/* Charts */}
        <ScanCharts
          severityCounts={severityCounts}
          owaspBreakdown={dashboardStats?.owasp_breakdown ?? {}}
          recentScans={dashboardStats?.recent_scans ?? scanHistory.map((s) => ({
            scan_id: s.scan_id, target: s.target,
            total_findings: s.total_findings, started_at: s.started_at || "",
            status: s.status, duration: s.duration, risk_score: 0,
          }))}
        />
      </div>
    </Sidebar>
  );
}
