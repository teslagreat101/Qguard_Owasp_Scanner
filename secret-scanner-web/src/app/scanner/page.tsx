"use client";

import { useState, useCallback, useMemo } from "react";
import { motion, AnimatePresence } from "framer-motion";
import { Sidebar } from "@/components/sidebar";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Badge } from "@/components/ui/badge";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Checkbox } from "@/components/ui/checkbox";
import { Progress } from "@/components/ui/progress";
import { ScrollArea } from "@/components/ui/scroll-area";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { ScanConsole } from "@/components/scan-console";
import { RealTimeFindingsPanel } from "@/components/real-time-findings-panel";
import { FindingsTable } from "@/components/dashboard/findings-table";
import {
  useScanner, useScanHistory, useHealthCheck, AVAILABLE_MODULES,
} from "@/hooks/use-scanner";
import { useProfiles, useReportDownload } from "@/lib/hooks";
import {
  Scan, Shield, Folder, Upload, FileCode, Terminal, Activity,
  Download, Zap, Target, Layers, CheckCircle, AlertTriangle,
  Clock, ChevronRight, BarChart3, FileSearch,
} from "lucide-react";
import { toast } from "sonner";

const SEVERITY_COLORS: Record<string, string> = {
  critical: "#ef4444", high: "#f97316", medium: "#eab308", low: "#00FF88", info: "#6B7F77",
};

export default function ScannerPage() {
  const {
    isScanning, scanStatus, findings, logs, scanResult, scanId,
    startScan, cancelScan, clearScan,
  } = useScanner();
  const { health, isHealthy } = useHealthCheck();
  const { profiles } = useProfiles();
  const { downloadReport } = useReportDownload();

  const [scanTarget, setScanTarget] = useState("");
  const [selectedModules, setSelectedModules] = useState<string[]>(
    AVAILABLE_MODULES.map((m) => m.key)
  );
  const [scanInputType, setScanInputType] = useState("directory");
  const [selectedProfile, setSelectedProfile] = useState("full");
  const [activeView, setActiveView] = useState<"config" | "console" | "results">("config");

  // Auto-switch to console when scanning starts
  if (isScanning && activeView === "config") {
    setActiveView("console");
  }
  if (!isScanning && scanResult && activeView === "console") {
    setActiveView("results");
  }

  const toggleModule = useCallback((key: string) => {
    setSelectedModules((prev) =>
      prev.includes(key) ? prev.filter((m) => m !== key) : [...prev, key]
    );
  }, []);

  const selectAll = () => setSelectedModules(AVAILABLE_MODULES.map((m) => m.key));
  const selectNone = () => setSelectedModules([]);

  const totalPatterns = useMemo(
    () => AVAILABLE_MODULES.reduce((acc, m) => selectedModules.includes(m.key) ? acc + m.patterns : acc, 0),
    [selectedModules]
  );

  const severityCounts = useMemo(() => {
    const counts: Record<string, number> = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
    findings.forEach((f) => {
      const sev = (f.severity || "info").toLowerCase();
      if (sev in counts) counts[sev]++;
    });
    return counts;
  }, [findings]);

  const handleStartScan = useCallback(async () => {
    if (!scanTarget.trim()) { toast.error("Enter a target path or paste code"); return; }
    if (selectedModules.length === 0) { toast.error("Select at least one module"); return; }

    const isDir = scanInputType === "directory";
    try {
      await startScan(scanTarget.trim(), selectedModules, "code");
      setActiveView("console");
    } catch { /* handled */ }
  }, [scanTarget, selectedModules, scanInputType, startScan]);

  const handleExport = useCallback(() => {
    if (scanId) {
      downloadReport(scanId, "html");
      toast.success("Downloading report...");
    }
  }, [scanId, downloadReport]);

  const handleNewScan = () => {
    clearScan();
    setActiveView("config");
  };

  const estimatedTime = useMemo(() => {
    const secs = selectedModules.length * 3;
    return secs < 60 ? `~${secs}s` : `~${Math.ceil(secs / 60)}m`;
  }, [selectedModules]);

  return (
    <Sidebar>
      <div className="space-y-6">
        {/* Header */}
        <motion.div initial={{ opacity: 0, y: -20 }} animate={{ opacity: 1, y: 0 }}
          className="flex items-center justify-between flex-wrap gap-4">
          <div>
            <h1 className="text-3xl font-bold tracking-tight flex items-center gap-2 text-foreground">
              <Scan className="h-8 w-8 text-primary" /> Quantara Security
            </h1>
            <p className="text-muted-foreground mt-1">
              {health ? `${health.modules} modules · ${health.total_patterns} patterns · v${health.version}` : "Unified security scanner engine"}
            </p>
          </div>
          <div className="flex items-center gap-2">
            {isScanning ? (
              <Badge className="bg-primary/10 text-primary border-primary/30 animate-pulse">
                <Activity className="h-3 w-3 mr-1" /> Scanning...
              </Badge>
            ) : scanResult ? (
              <Badge className="bg-primary/10 text-primary border-primary/20">
                <CheckCircle className="h-3 w-3 mr-1" /> Complete
              </Badge>
            ) : null}
            {(isScanning || scanResult) && (
              <Button variant="outline" onClick={handleNewScan}
                className="border-primary/20 text-foreground hover:text-primary">
                <Zap className="h-4 w-4 mr-2" /> New Scan
              </Button>
            )}
          </div>
        </motion.div>

        {/* Progress Bar (when scanning) */}
        {isScanning && (
          <motion.div initial={{ opacity: 0, height: 0 }} animate={{ opacity: 1, height: "auto" }}>
            <Card className="bg-card border-border">
              <CardContent className="pt-4 pb-4">
                <div className="flex items-center justify-between mb-2">
                  <span className="text-sm text-foreground font-medium">
                    {scanStatus?.active_module ? `Running: ${scanStatus.active_module}` : "Initializing..."}
                  </span>
                  <span className="text-sm text-primary font-mono">{scanStatus?.progress || 0}%</span>
                </div>
                <Progress value={scanStatus?.progress || 0} className="h-2" />
                <div className="flex items-center justify-between mt-2 text-xs text-muted-foreground">
                  <span>Module {scanStatus?.modules_completed || 0}/{scanStatus?.modules_total || 0}</span>
                  <span>{findings.length} findings detected</span>
                </div>
              </CardContent>
            </Card>
          </motion.div>
        )}

        {/* View Tabs */}
        <Tabs value={activeView} onValueChange={(v) => setActiveView(v as any)}>
          <TabsList className="bg-muted border border-border">
            <TabsTrigger value="config" className="data-[state=active]:bg-primary/10 data-[state=active]:text-primary">
              <Target className="h-4 w-4 mr-2" /> Configure
            </TabsTrigger>
            <TabsTrigger value="console" className="data-[state=active]:bg-primary/10 data-[state=active]:text-primary">
              <Terminal className="h-4 w-4 mr-2" /> Console
            </TabsTrigger>
            <TabsTrigger value="results" className="data-[state=active]:bg-primary/10 data-[state=active]:text-primary">
              <BarChart3 className="h-4 w-4 mr-2" /> Results
              {findings.length > 0 && (
                <Badge className="ml-1.5 bg-primary/15 text-primary text-[10px]">{findings.length}</Badge>
              )}
            </TabsTrigger>
          </TabsList>

          {/* Configure Tab */}
          <TabsContent value="config" className="space-y-6">
            <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
              {/* Target Configuration */}
              <Card className="lg:col-span-2 bg-card border-border">
                <CardHeader>
                  <CardTitle className="text-foreground flex items-center gap-2">
                    <Target className="h-5 w-5 text-primary" /> Scan Target
                  </CardTitle>
                </CardHeader>
                <CardContent className="space-y-4">
                  <div className="flex gap-2">
                    {[
                      { key: "directory", label: "Directory", icon: Folder },
                      { key: "upload", label: "Upload", icon: Upload },
                      { key: "paste", label: "Code", icon: FileCode },
                    ].map(({ key, label, icon: Icon }) => (
                      <Button key={key} variant={scanInputType === key ? "default" : "outline"}
                        onClick={() => setScanInputType(key)}
                        className={scanInputType === key
                          ? "bg-primary/15 text-primary border border-primary/30"
                          : "border-border text-muted-foreground hover:text-primary"
                        }>
                        <Icon className="h-4 w-4 mr-1.5" /> {label}
                      </Button>
                    ))}
                  </div>

                  {scanInputType === "directory" && (
                    <Input placeholder="C:/path/to/your/project" value={scanTarget}
                      onChange={(e) => setScanTarget(e.target.value)}
                      className="bg-primary/5 border-border text-foreground focus:border-primary text-sm" />
                  )}
                  {scanInputType === "upload" && (
                    <div className="border-2 border-dashed border-border rounded-2xl p-12 text-center hover:border-primary/40 transition-all cursor-pointer bg-primary/2 group">
                      <Upload className="h-10 w-10 mx-auto text-primary mb-3 group-hover:scale-110 transition-transform" />
                      <p className="text-foreground font-medium">Drop files or click to upload</p>
                      <p className="text-xs text-muted-foreground mt-1">.zip, .tar.gz, or individual files</p>
                    </div>
                  )}
                  {scanInputType === "paste" && (
                    <textarea
                      className="w-full h-48 bg-primary/2 border border-border rounded-xl p-4 font-mono text-sm text-foreground focus:ring-1 focus:ring-primary/30 outline-none"
                      placeholder="// Paste your code here..."
                      value={scanTarget}
                      onChange={(e) => setScanTarget(e.target.value)}
                    />
                  )}

                  {/* Profile */}
                  <div className="flex items-center gap-3">
                    <span className="text-xs text-muted-foreground uppercase tracking-wider">Profile</span>
                    <Select value={selectedProfile} onValueChange={setSelectedProfile}>
                      <SelectTrigger className="bg-primary/5 border-border text-foreground w-52">
                        <SelectValue placeholder="Full Security Sweep" />
                      </SelectTrigger>
                      <SelectContent className="bg-card border-border">
                        {(profiles.length > 0 ? profiles : [
                          { key: "quick", name: "Quick (5 modules)" },
                          { key: "standard", name: "Standard (10 modules)" },
                          { key: "full", name: "Full (All modules)" },
                          { key: "owasp-top-10", name: "OWASP Top 10" },
                        ]).map((p) => (
                          <SelectItem key={p.key} value={p.key} className="text-foreground focus:bg-primary/10">{p.name}</SelectItem>
                        ))}
                      </SelectContent>
                    </Select>
                    <span className="text-xs text-muted-foreground">Est. {estimatedTime}</span>
                  </div>
                </CardContent>
              </Card>

              {/* Module Selection */}
              <Card className="bg-card border-border">
                <CardHeader>
                  <div className="flex items-center justify-between">
                    <CardTitle className="text-foreground text-sm flex items-center gap-2">
                      <Layers className="h-4 w-4 text-primary" /> Modules ({selectedModules.length})
                    </CardTitle>
                    <div className="flex gap-1">
                      <Button variant="ghost" size="sm" onClick={selectAll} className="h-6 text-[10px] text-muted-foreground hover:text-primary">All</Button>
                      <Button variant="ghost" size="sm" onClick={selectNone} className="h-6 text-[10px] text-muted-foreground hover:text-red-400">None</Button>
                    </div>
                  </div>
                </CardHeader>
                <CardContent>
                  <ScrollArea className="h-[300px]">
                    <div className="space-y-1.5">
                      {AVAILABLE_MODULES.map((m) => (
                        <label key={m.key}
                          className={`flex items-center gap-2.5 p-2.5 rounded-lg border cursor-pointer transition-all ${selectedModules.includes(m.key)
                            ? "bg-primary/10 border-primary/25"
                            : "bg-transparent border-primary/10 hover:border-primary/20"
                            }`}>
                          <Checkbox checked={selectedModules.includes(m.key)} onCheckedChange={() => toggleModule(m.key)} />
                          <div className="flex-1 min-w-0">
                            <p className="text-xs font-medium text-foreground truncate">{m.name}</p>
                            <p className="text-[10px] text-muted-foreground">{m.owasp} · {m.patterns} patterns</p>
                          </div>
                        </label>
                      ))}
                    </div>
                  </ScrollArea>
                </CardContent>
              </Card>
            </div>

            {/* Launch Bar */}
            <motion.div initial={{ opacity: 0, y: 20 }} animate={{ opacity: 1, y: 0 }} transition={{ delay: 0.2 }}>
              <Card className="bg-card border-border" style={{ boxShadow: "0 0 30px var(--glow-green-subtle)" }}>
                <CardContent className="pt-4 pb-4">
                  <div className="flex items-center justify-between">
                    <div className="flex items-center gap-4">
                      <div className="w-12 h-12 rounded-xl bg-primary/10 border border-primary/20 flex items-center justify-center">
                        <Shield className="h-6 w-6 text-primary" />
                      </div>
                      <div>
                        <p className="text-foreground font-bold">Ready to Scan</p>
                        <p className="text-xs text-muted-foreground">
                          {selectedModules.length} modules · {totalPatterns} patterns · {estimatedTime}
                        </p>
                      </div>
                    </div>
                    <Button onClick={handleStartScan} disabled={!scanTarget.trim() || selectedModules.length === 0}
                      className="bg-gradient-to-r from-primary/20 to-primary/10 hover:from-primary/30 hover:to-primary/20 text-primary border border-primary/35 font-bold px-10 py-5 text-base disabled:opacity-40"
                      style={{ boxShadow: "0 0 20px var(--glow-green-subtle)" }}>
                      <Zap className="h-5 w-5 mr-2" /> LAUNCH SCAN
                    </Button>
                  </div>
                </CardContent>
              </Card>
            </motion.div>
          </TabsContent>

          {/* Console Tab */}
          <TabsContent value="console" className="space-y-4">
            <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
              <ScanConsole logs={logs} isScanning={isScanning} progress={scanStatus?.progress || 0} onCancel={cancelScan} />
              <RealTimeFindingsPanel findings={findings} isScanning={isScanning} scanStatus={scanStatus} onClear={clearScan} />
            </div>
            {/* Severity Counters */}
            <div className="grid grid-cols-5 gap-3">
              {Object.entries(severityCounts).map(([sev, count]) => (
                <Card key={sev} className="bg-card border-border">
                  <CardContent className="pt-3 pb-3 text-center">
                    <div className="text-xl font-bold" style={{ color: SEVERITY_COLORS[sev] }}>{count}</div>
                    <div className="text-[10px] text-muted-foreground uppercase">{sev}</div>
                  </CardContent>
                </Card>
              ))}
            </div>
          </TabsContent>

          {/* Results Tab */}
          <TabsContent value="results" className="space-y-4">
            {/* Results Summary */}
            {scanResult && (
              <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
                <Card className="bg-card border-border">
                  <CardContent className="pt-4 pb-4 text-center">
                    <div className="text-2xl font-bold text-foreground">{findings.length}</div>
                    <div className="text-xs text-muted-foreground">Total Findings</div>
                  </CardContent>
                </Card>
                <Card className="bg-card border-border">
                  <CardContent className="pt-4 pb-4 text-center">
                    <div className="text-2xl font-bold text-red-500">{severityCounts.critical + severityCounts.high}</div>
                    <div className="text-xs text-muted-foreground">Critical + High</div>
                  </CardContent>
                </Card>
                <Card className="bg-card border-border">
                  <CardContent className="pt-4 pb-4 text-center">
                    <div className="text-2xl font-bold text-primary">{scanResult.duration || 0}s</div>
                    <div className="text-xs text-muted-foreground">Duration</div>
                  </CardContent>
                </Card>
                <Card className="bg-card border-border">
                  <CardContent className="pt-4 pb-4 text-center">
                    <div className="flex justify-center gap-2">
                      <Button size="sm" onClick={handleExport}
                        className="bg-primary/10 text-primary border border-primary/20 text-xs">
                        <Download className="h-3 w-3 mr-1" /> Report
                      </Button>
                    </div>
                    <div className="text-xs text-muted-foreground mt-1">Export</div>
                  </CardContent>
                </Card>
              </div>
            )}

            <FindingsTable findings={findings} onExport={handleExport} onClear={clearScan} />
          </TabsContent>
        </Tabs>
      </div>
    </Sidebar>
  );
}
