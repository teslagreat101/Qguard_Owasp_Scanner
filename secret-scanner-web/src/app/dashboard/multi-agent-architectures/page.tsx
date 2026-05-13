"use client";

import { useState, useEffect, useCallback } from "react";
import { motion, AnimatePresence } from "framer-motion";
import { Sidebar } from "@/components/sidebar";
import {
  Shield,
  Network,
  Server,
  Database,
  Cpu,
  GitBranch,
  HardDrive,
  Zap,
  Code,
  Lock,
  ArrowRight,
  Monitor,
  Workflow,
  Share2,
  Box,
  Layers,
  ChevronRight,
  Activity,
  Gem,
  Pocket,
  Globe,
  Search,
  Target,
  CheckCircle2,
  Terminal,
  AlertTriangle,
  RefreshCw,
  X
} from "lucide-react";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Badge } from "@/components/ui/badge";
import { cn } from "@/lib/utils";
import { AutonomousScanModal } from "@/components/red-team/AutonomousScanModal";
import { ScanProgressPipeline } from "@/components/red-team/ScanProgressPipeline";
import { RealTimeActivity } from "@/components/red-team/RealTimeActivity";
import { VulnerabilityFindings } from "@/components/red-team/VulnerabilityFindings";
import { OrchestrationSwarmGraph } from "@/components/red-team/OrchestrationSwarmGraph";
import { api, LogEntry, Finding, ScanStatus } from "@/lib/api";
import { toast } from "sonner";

const architectureComponents = [
  {
    id: "recon",
    title: "Recon Layer",
    icon: Globe,
    description: "Multi-vector discovery of attack surfaces.",
    modules: ["endpoint_discovery", "subdomain_discovery"]
  },
  {
    id: "analysis",
    title: "Analysis Engine",
    icon: Search,
    description: "Deep semantic analysis of application behavior.",
    modules: ["input_mapper", "endpoint_classifier"]
  },
  {
    id: "fuzzing",
    title: "AI Fuzzing Engine",
    icon: Zap,
    description: "LLM-assisted payload generation and fuzzing.",
    modules: ["mutation_engine", "payload_generator"]
  },
  {
    id: "mutation",
    title: "Self Learning",
    icon: Database,
    description: "Adaptive evolution of payload strategies.",
    modules: ["payload_ranker", "learning_engine"]
  },
  {
    id: "execution",
    title: "Exploit Engine",
    icon: Target,
    description: "Automated vulnerability exploitation.",
    modules: ["attack_executor", "timing_detector"]
  },
  {
    id: "verification",
    title: "AI Verification",
    icon: Shield,
    description: "False positive elimination using AI logic.",
    modules: ["verdict_engine", "impact_analyzer"]
  }
];

const backendInfrastructure = [
  { name: "Task Queue", icon: Workflow, desc: "Asynchronous orchestration via Redis & Celery" },
  { name: "Intelligence DB", icon: Database, desc: "Shared security state and historical knowledge" },
  { name: "Neural Switch", icon: Share2, desc: "Directs tasks to specialized AI agent swarms" },
  { name: "Secure Sandbox", icon: Box, desc: "Isolated environment for POC execution" }
];

export default function MultiAgentArchitecturePage() {
  const [isScanModalOpen, setIsScanModalOpen] = useState(false);
  const [isScanning, setIsScanning] = useState(false);
  const [scanId, setScanId] = useState<string | null>(null);
  const [logs, setLogs] = useState<LogEntry[]>([]);
  const [findings, setFindings] = useState<Finding[]>([]);
  const [activeLayerIndex, setActiveLayerIndex] = useState(0);
  const [scanStatus, setScanStatus] = useState<string>("idle");
  const [activeAgents, setActiveAgents] = useState<string[]>([]);

  const handleStartScan = async (config: any) => {
    setIsScanModalOpen(false);
    setIsScanning(true);
    setScanStatus("running");
    setLogs([]);
    setFindings([]);
    setActiveLayerIndex(0);

    try {
      const response = await api.startScan({
        target: config.targetUrl || config.targetDomain,
        scan_type: "url",
        scan_profile: config.scanDepth,
        modules: config.enabledModules
      });

      setScanId(response.scan_id);
      toast.success("Autonomous AI Scan Initialized");
    } catch (error: any) {
      console.error("Failed to start scan:", error);
      toast.error("Failed to initialize scan engine. Running in simulation mode.");
      // Fallback: Simulation mode for UI testing if backend is not available
      simulateScan();
    }
  };

  const simulateScan = useCallback(() => {
    let currentStage = 0;
    const interval = setInterval(() => {
      if (currentStage < architectureComponents.length) {
        setActiveLayerIndex(currentStage);

        const layer = architectureComponents[currentStage];
        const newLog: LogEntry = {
          time: new Date().toLocaleTimeString(),
          level: "info",
          message: currentStage === 0
            ? `Endpoint discovered: /api/v1/auth/login (DISCOVERY_EVENT)`
            : currentStage === 2
              ? `New payload generated: SQLi_TimeBased_v3 (MUTATION_EVENT)`
              : currentStage === 4
                ? `Attacking identified endpoint with payload cluster (EXECUTION_EVENT)`
                : `${layer.title} → processing intelligence sync...`,
          module: layer.id
        };
        setLogs(prev => [...prev, newLog]);

        const moduleLogs = layer.modules.map(mod => ({
          time: new Date().toLocaleTimeString(),
          level: "success" as const,
          message: `Module ${mod.toUpperCase()} operational. Thread synchronized.`,
          module: mod
        }));
        setLogs(prev => [...prev, ...moduleLogs]);

        // Add dummy findings occasionally
        if (currentStage > 1 && Math.random() > 0.6) {
          const newFinding: Finding = {
            id: Math.random().toString(),
            title: currentStage === 2 ? "Potential XSS Vulnerability" : "Insecure API Endpoint",
            severity: currentStage > 3 ? "Critical" : "High",
            description: "Automated analysis detected a high-risk vulnerability in the target surface.",
            endpoint: "/api/v1/user/profile",
            module: layer.id,
            module_name: layer.title,
            confidence: 0.92,
            timestamp: new Date().toISOString(),
            file: "index.js",
            line_number: 42,
            category: "injection",
            cwe: "CWE-79",
            remediation: "Input sanitization required",
            owasp: "A1",
            tags: ["ai-verified"]
          };
          setFindings(prev => [newFinding, ...prev]);
        }

        currentStage++;
      } else {
        clearInterval(interval);
        setScanStatus("completed");
        toast.success("Autonomous Scan Completed");
      }
    }, 4000);

    return () => clearInterval(interval);
  }, []);

  useEffect(() => {
    if (!scanId) return;

    const cleanup = api.streamScanEvents(scanId, {
      onLog: (log) => setLogs(prev => [...prev, log]),
      onFinding: (finding) => setFindings(prev => [finding, ...prev]),
      onStatus: (status) => {
        setScanStatus(status.status);
        if (status.active_module) {
          // Map active module to layer index
          const index = architectureComponents.findIndex(c => c.modules.includes(status.active_module));
          if (index !== -1) setActiveLayerIndex(index);
        }
      },
      onComplete: () => {
        setScanStatus("completed");
        toast.success("Scan Completed Successfully");
      }
    });

    return cleanup;
  }, [scanId]);

  return (
    <Sidebar>
      <div className="min-h-screen space-y-12 pb-20 overflow-x-hidden">
        {/* Header */}
        <div className="flex flex-col lg:flex-row lg:items-end justify-between gap-6">
          <div className="space-y-4">
            <Badge variant="outline" className="text-primary border-primary/20 bg-primary/5 uppercase tracking-widest text-[10px] font-bold px-3 py-1">
              {isScanning ? "Active Mission" : "Enterprise Architecture"}
            </Badge>
            <h1 className="text-4xl lg:text-5xl font-extrabold font-outfit tracking-tight">
              {isScanning ? (
                <>
                  Autonomous AI <span className="text-primary">Infiltration</span> Stream
                </>
              ) : (
                <>
                  Quantara <span className="text-primary">AI Swarm</span>
                </>
              )}
            </h1>
            <p className="text-muted-foreground max-w-2xl text-lg">
              {isScanning
                ? "Watching the live autonomous AI red team swarm executing an advanced penetration test."
                : "A comprehensive overview of Quantara's distributed intelligence system."
              }
            </p>
          </div>
          <div className="flex gap-3">
            {isScanning ? (
              <Button
                variant="outline"
                onClick={() => { setIsScanning(false); setScanId(null); }}
                className="rounded-full border-red-500/50 text-red-500 hover:bg-red-500/10"
              >
                Terminate Mission
              </Button>
            ) : (
              <>
                <Button variant="outline" className="rounded-full border-border hover:bg-secondary/50">Download Spec PDF</Button>
                <Button
                  onClick={() => setIsScanModalOpen(true)}
                  className="bg-primary text-background font-bold rounded-full px-8 shadow-[0_0_20px_rgba(0,255,136,0.3)] hover:shadow-[0_0_30px_rgba(0,255,136,0.5)] transition-all"
                >
                  Start Scanning
                </Button>
              </>
            )}
          </div>
        </div>

        {isScanning ? (
          <div className="space-y-8 animate-in fade-in slide-in-from-bottom-4 duration-700">
            {/* Active Scan Visualization */}
            <div className="grid grid-cols-1 xl:grid-cols-3 gap-8">
              <div className="xl:col-span-2 space-y-8">
                {/* Orchestration Swarm Visualization */}
                <section className="relative h-[500px] lg:h-[600px] animate-in fade-in duration-1000">
                  <OrchestrationSwarmGraph
                    activeLayerIndex={activeLayerIndex}
                    logs={logs}
                    findings={findings}
                    isScanning={isScanning}
                  />
                </section>

                {/* Progress Pipeline */}
                <section className="bg-[#0B0F0C] border border-white/5 rounded-3xl p-6">
                  <h3 className="text-sm font-bold uppercase tracking-widest text-muted-foreground mb-4">Scanning Pipeline Progress</h3>
                  <ScanProgressPipeline activeStageIndex={activeLayerIndex} />
                </section>

                {/* Live Console */}
                <div className="h-[400px]">
                  <RealTimeActivity
                    logs={logs}
                    activeAgents={architectureComponents[activeLayerIndex].modules.slice(0, 3)}
                    scanStatus={scanStatus}
                  />
                </div>
              </div>

              {/* Right Sidebar: Findings */}
              <div className="xl:col-span-1 h-[calc(100vh-200px)] sticky top-32">
                <VulnerabilityFindings findings={findings} />
              </div>
            </div>
          </div>
        ) : (
          <>
            {/* Main Visual Schema (Default Mode) */}
            <section className="relative rounded-3xl bg-[#0B0F0C] border border-white/5 overflow-hidden h-[400px] lg:h-[600px] flex items-center justify-center group">
              <div className="absolute inset-0 bg-primary/5 blur-[200px] animate-pulse" />
              <div className="absolute inset-0 opacity-40 bg-[url('/multi_agent_security_orchestration.png')] bg-cover bg-center group-hover:scale-105 transition-transform duration-1000" />
              <div className="relative z-10 text-center max-w-xl p-8 backdrop-blur-md bg-[#0B0F0C]/40 rounded-2xl border border-white/10 shadow-2xl">
                <div className="flex justify-center mb-6 gap-2">
                  {[1, 2, 3, 4, 5].map((i) => (
                    <motion.div
                      key={i}
                      initial={{ height: 10 }}
                      animate={{ height: [10, 30, 10] }}
                      transition={{ repeat: Infinity, duration: 1.5, delay: i * 0.2 }}
                      className="w-1.5 bg-primary rounded-full shadow-[0_0_10px_rgba(0,255,136,0.5)]"
                    />
                  ))}
                </div>
                <h2 className="text-2xl font-bold font-outfit mb-4">Orchestration Swarm</h2>
                <p className="text-sm text-gray-400 leading-relaxed font-mono">
                  distributed_agent_registry: initialized
                  neural_network_status: optimizing
                  total_active_neurons: 172.4B
                  latency_optimization: grid_enabled
                </p>
                <Button
                  onClick={() => setIsScanModalOpen(true)}
                  className="mt-8 bg-primary/10 border border-primary/30 text-primary hover:bg-primary/20 font-bold rounded-xl px-8 h-12 group/btn"
                >
                  Launch Simulation <ArrowRight className="ml-2 w-4 h-4 group-hover/btn:translate-x-1 transition-transform" />
                </Button>
              </div>
            </section>

            {/* Primary Layers & Modules */}
            <section className="space-y-8">
              <div className="flex items-center gap-4">
                <div className="h-px flex-1 bg-border" />
                <h2 className="text-2xl font-bold font-outfit uppercase tracking-wider text-muted-foreground text-sm">Modular Ecosystem</h2>
                <div className="h-px flex-1 bg-border" />
              </div>

              <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-8">
                {architectureComponents.map((comp, i) => (
                  <motion.div
                    key={comp.id}
                    initial={{ opacity: 0, scale: 0.95 }}
                    whileInView={{ opacity: 1, scale: 1 }}
                    transition={{ delay: i * 0.1 }}
                    viewport={{ once: true }}
                    className="flex flex-col h-full bg-card/30 border border-white/5 rounded-3xl p-6 hover:shadow-[0_20px_40px_rgba(0,0,0,0.3)] hover:-translate-y-2 transition-all group"
                  >
                    <div className="flex justify-between items-start mb-6">
                      <div className="p-3 bg-secondary rounded-2xl group-hover:bg-primary/10 transition-colors">
                        <comp.icon className="w-8 h-8 text-muted-foreground group-hover:text-primary transition-colors" />
                      </div>
                      <Badge variant="secondary" className="bg-white/5 border-white/10 opacity-50 font-mono text-[10px]">v5.0.{i}</Badge>
                    </div>
                    <h3 className="text-xl font-bold font-outfit mb-2 text-foreground">{comp.title}</h3>
                    <p className="text-sm text-muted-foreground mb-6 line-clamp-2">
                      {comp.description}
                    </p>
                    <div className="mt-auto space-y-3">
                      <p className="text-[10px] font-bold text-primary uppercase tracking-widest">Active Modules</p>
                      <div className="flex flex-wrap gap-2">
                        {comp.modules.map((mod) => (
                          <Badge key={mod} variant="outline" className="text-[9px] py-0 font-medium border-border/50 group-hover:border-primary/20 transition-colors capitalize">
                            {mod}
                          </Badge>
                        ))}
                      </div>
                    </div>
                  </motion.div>
                ))}
              </div>
            </section>

            {/* Backend Infrastructure */}
            <section className="bg-secondary/20 rounded-[40px] p-8 lg:p-16 border border-white/5 relative overflow-hidden">
              <div className="grid grid-cols-1 lg:grid-cols-2 gap-16">
                <div className="space-y-8">
                  <h2 className="text-3xl lg:text-4xl font-black font-outfit tracking-tighter">System Core <br /><span className="text-primary italic">Backbone</span></h2>
                  <p className="text-muted-foreground text-lg leading-relaxed">
                    Underlying our agents is a robust, cloud-native infrastructure designed for sub-second synchronization and extreme data durability.
                  </p>
                  <div className="grid grid-cols-1 sm:grid-cols-2 gap-6">
                    {backendInfrastructure.map((infra) => (
                      <div key={infra.name} className="flex gap-4">
                        <div className="flex-shrink-0 w-12 h-12 rounded-xl bg-primary/10 border border-primary/20 flex items-center justify-center">
                          <infra.icon className="w-6 h-6 text-primary" />
                        </div>
                        <div>
                          <h4 className="font-bold text-foreground">{infra.name}</h4>
                          <p className="text-xs text-muted-foreground">{infra.desc}</p>
                        </div>
                      </div>
                    ))}
                  </div>
                </div>

                <div className="space-y-6 flex flex-col justify-center">
                  <Card className="bg-card/60 backdrop-blur-xl border-white/10 border-l-primary border-l-4">
                    <CardHeader>
                      <CardTitle className="font-bold font-outfit text-xl">Operational Sovereignty</CardTitle>
                    </CardHeader>
                    <CardContent className="space-y-4">
                      <div className="flex justify-between items-center text-sm p-3 bg-white/5 rounded-lg border border-white/10">
                        <span className="text-muted-foreground flex items-center gap-2 px-2"><Shield className="w-4 h-4 text-green-500" /> Data Isolation</span>
                        <span className="font-mono text-xs text-gray-500">ENCRYPTED</span>
                      </div>
                      <div className="flex justify-between items-center text-sm p-3 bg-white/5 rounded-lg border border-white/10">
                        <span className="text-muted-foreground flex items-center gap-2 px-2"><Activity className="w-4 h-4 text-primary" /> Live Telemetry</span>
                        <span className="font-mono text-xs text-primary animate-pulse">STREAMING</span>
                      </div>
                      <div className="flex justify-between items-center text-sm p-3 bg-white/5 rounded-lg border border-white/10">
                        <span className="text-muted-foreground flex items-center gap-2 px-2"><Lock className="w-4 h-4 text-amber-500" /> Role-Based Access</span>
                        <span className="font-mono text-xs text-gray-500">ENFORCED</span>
                      </div>
                    </CardContent>
                  </Card>
                  <p className="text-xs text-center text-muted-foreground italic">
                    "Security is not a feature, it is the foundation of our entire multi-agent mesh architecture."
                  </p>
                </div>
              </div>
            </section>

            {/* Advanced Capabilities List */}
            <section className="space-y-8 pt-6">
              <h2 className="text-3xl font-bold font-outfit text-center">Elite Capabilities & Reasoning</h2>
              <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                {[
                  { title: "Network discovery & pivoting", desc: "Maps internal network reachability through blind server-side requests." },
                  { title: "Zero-day logic flaw detection", desc: "Uses semantic reasoning to bypass multi-step authorization workflows." },
                  { title: "Parser confusion discovery", desc: "Exploits RFC ambiguities between proxies, interpreters and databases." },
                  { title: "Hypothesis-driven exploitation", desc: "Dynamically tests security assumptions rather than static signatures." },
                  { title: "Continuous Learning", desc: "Evolutionary database of successful attack patterns across all target tenants." }
                ].map((cap, i) => (
                  <div key={cap.title} className="flex gap-4 p-5 rounded-2xl bg-[#0B0F0C] border border-white/5 items-start hover:border-primary/40 transition-colors">
                    <div className="mt-1 w-6 h-6 rounded-full bg-primary/20 flex items-center justify-center flex-shrink-0">
                      <CheckCircle2 className="w-4 h-4 text-primary" />
                    </div>
                    <div>
                      <h4 className="font-bold text-foreground mb-1">{cap.title}</h4>
                      <p className="text-xs text-muted-foreground leading-relaxed">{cap.desc}</p>
                    </div>
                  </div>
                ))}
              </div>
            </section>

            {/* Final Action */}
            <section className="border-t border-white/5 pt-12 flex flex-col items-center gap-6">
              <div className="text-center space-y-2">
                <h2 className="text-2xl font-bold font-outfit">Ready to deploy the swarm?</h2>
                <p className="text-muted-foreground">Select a scan target and let the multi-agent system take command.</p>
              </div>
              <Button
                size="lg"
                onClick={() => setIsScanModalOpen(true)}
                className="rounded-full px-12 h-14 bg-primary text-background hover:bg-primary/90 font-extrabold text-lg shadow-[0_0_30px_rgba(0,255,136,0.3)] hover:shadow-[0_0_50px_rgba(0,255,136,0.5)] transition-all"
              >
                Start Scanning
              </Button>
            </section>
          </>
        )}

        <AutonomousScanModal
          isOpen={isScanModalOpen}
          onClose={() => setIsScanModalOpen(false)}
          onStartScan={handleStartScan}
        />
      </div>
    </Sidebar>
  );
}
