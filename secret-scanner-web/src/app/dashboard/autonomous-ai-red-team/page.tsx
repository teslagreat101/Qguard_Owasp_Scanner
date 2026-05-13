"use client";

import { useState, useEffect, useCallback } from "react";
import { motion, AnimatePresence } from "framer-motion";
import { 
  Atom, 
  Shield, 
  Target, 
  Activity, 
  Zap, 
  Cpu, 
  Terminal, 
  Bug, 
  Network,
  LayoutDashboard,
  BarChart3,
  History,
  Brain
} from "lucide-react";
import { Sidebar } from "@/components/sidebar";
import { ScanLaunchModule } from "@/components/red-team/ScanLaunchModule";
import { RealTimeActivity } from "@/components/red-team/RealTimeActivity";
import { VulnerabilityFindings } from "@/components/red-team/VulnerabilityFindings";
import { AttackChainGraph } from "@/components/red-team/AttackChainGraph";
import { AgentSwarm } from "@/components/red-team/AgentSwarm";
import { ScanConfiguration } from "@/components/red-team/ScanConfiguration";
import { api, LogEntry, Finding } from "@/lib/api";
import { Badge } from "@/components/ui/badge";
import { Progress } from "@/components/ui/progress";
import { toast } from "sonner";

export default function AutonomousAIRedTeamPage() {
  const [scanId, setScanId] = useState<string | null>(null);
  const [logs, setLogs] = useState<LogEntry[]>([]);
  const [findings, setFindings] = useState<Finding[]>([]);
  const [activeAgents, setActiveAgents] = useState<string[]>([]);
  const [scanStatus, setScanStatus] = useState<string>("idle");
  const [progress, setProgress] = useState(0);
  const [graphData, setGraphData] = useState<{ nodes: any[], edges: any[] }>({ nodes: [], edges: [] });

  const fetchGraph = useCallback(async (id: string) => {
    try {
      const data = await api.getSwarmAttackGraph(id);
      setGraphData(data);
    } catch (err) {
      console.error("Failed to fetch graph:", err);
    }
  }, []);

  // Connection handling for SSE
  useEffect(() => {
    if (!scanId) return;

    setScanStatus("running");
    
    // Reset data for new scan
    setLogs([]);
    setFindings([]);
    setActiveAgents([]);
    setProgress(0);

    console.log(`📡 Opening swarm telemetry stream for scan: ${scanId}`);

    const stopStream = api.streamSwarmTelemetry(scanId, {
      onLog: (log) => {
        setLogs(prev => [...prev.slice(-200), log]);
      },
      onFinding: (finding) => {
        setFindings(prev => [finding, ...prev].slice(0, 200));
        toast.info(`Vulnerability Detected: ${finding.title}`, {
            icon: <Bug className="w-4 h-4 text-red-500" />,
            style: { background: "#0B0F0C", border: "1px solid rgba(255,0,0,0.2)", color: "#fff" }
        });
      },
      onAgentStatus: (agentStatus) => {
          if (agentStatus.status === 'active') {
              setActiveAgents(prev => prev.includes(agentStatus.node) ? prev : [...prev, agentStatus.node]);
          } else {
              setActiveAgents(prev => prev.filter(a => a !== agentStatus.node));
          }
      },
      onStatus: (status) => {
        if (status.progress) setProgress(status.progress);
        if (status.status) setScanStatus(status.status);
      },
      onGraphUpdate: (graph) => {
        // Real-time attack graph update from SSE stream
        if (graph && graph.nodes && graph.nodes.length > 0) {
          setGraphData({ nodes: graph.nodes, edges: graph.edges || [] });
        }
      },
      onKeepalive: () => {},
      onComplete: (data) => {
        setScanStatus("completed");
        setProgress(100);
        // Final graph fetch to ensure we have the complete graph
        fetchGraph(scanId);
        toast.success("Autonomous Security Assessment Completed.");
      },
      onError: (err) => {
        console.error("Stream error:", err);
        setScanStatus("error");
        toast.error("Telemetry stream disconnected.");
      }
    });

    return () => {
      console.log("🔌 Closing telemetry stream");
      stopStream();
    };
  }, [scanId]);

  return (
    <Sidebar>
      <div className="flex flex-col min-h-screen bg-[#0B0F0C] text-foreground font-outfit selection:bg-primary/30">
        {/* Animated Background Elements */}
        <div className="fixed inset-0 overflow-hidden pointer-events-none opacity-20">
          <div className="absolute top-[-10%] left-[-10%] w-[40%] h-[40%] rounded-full bg-primary/20 blur-[120px] animate-pulse" />
          <div className="absolute bottom-[-10%] right-[-10%] w-[40%] h-[40%] rounded-full bg-blue-500/20 blur-[120px] animate-pulse animation-delay-2000" />
        </div>

        {/* Page Header */}
        <header className="relative z-10 border-b border-white/5 bg-black/40 backdrop-blur-xl px-8 py-6">
          <div className="flex flex-col md:flex-row md:items-center justify-between gap-6">
            <div className="space-y-1">
              <div className="flex items-center gap-3">
                <div className="relative">
                    <div className="absolute inset-0 bg-primary/20 blur-md animate-pulse" />
                    <Atom className="w-8 h-8 text-primary relative" />
                </div>
                <h1 className="text-3xl font-black italic uppercase tracking-tighter text-white">
                  Autonomous AI <span className="text-primary">Red Team</span>
                </h1>
              </div>
              <p className="text-muted-foreground text-sm uppercase tracking-[0.3em] font-medium flex items-center gap-2">
                <Shield className="w-3.5 h-3.5" />
                Strategic Intelligence & Exploitation Center
              </p>
            </div>

            <div className="flex items-center gap-4">
               {scanStatus === "running" && (
                 <div className="flex flex-col items-end gap-1.5 min-w-[200px]">
                    <div className="flex justify-between w-full text-[10px] uppercase font-black tracking-widest text-primary">
                        <span>MISSION PROGRESS</span>
                        <span>{progress}%</span>
                    </div>
                    <Progress value={progress} className="h-1.5 w-full bg-white/5" />
                 </div>
               )}
               <Badge className="bg-primary hover:bg-primary/90 text-background font-black py-1.5 px-4 rounded-lg shadow-[0_0_20px_rgba(0,255,136,0.3)]">
                 V5.2 ENTERPRISE
               </Badge>
            </div>
          </div>
        </header>

        {/* Main Dashboard Layout */}
        <main className="relative z-10 p-8 pt-6 space-y-10 max-w-[1800px] mx-auto w-full">
          
          {/* SECTION 1 — RED TEAM SCAN CONTROL */}
          <section id="scan-control" className="w-full">
            <motion.div
              initial={{ opacity: 0, y: -20 }}
              animate={{ opacity: 1, y: 0 }}
              transition={{ duration: 0.5 }}
            >
              <ScanLaunchModule onScanStarted={setScanId} />
            </motion.div>
          </section>

          {/* SECTION 2 — REAL-TIME SCAN OUTPUT */}
          <section id="scan-output" className="grid grid-cols-1 lg:grid-cols-2 gap-8 items-start">
            {/* LEFT CARD: Live Telemetry & Activity */}
            <motion.div
              initial={{ opacity: 0, x: -20 }}
              animate={{ opacity: 1, x: 0 }}
              transition={{ duration: 0.5, delay: 0.2 }}
              className="h-full min-h-[500px]"
            >
              <RealTimeActivity 
                logs={logs} 
                activeAgents={activeAgents} 
                scanStatus={scanStatus} 
              />
            </motion.div>

            {/* RIGHT CARD: Vulnerability Intelligence */}
            <motion.div
              initial={{ opacity: 0, x: 20 }}
              animate={{ opacity: 1, x: 0 }}
              transition={{ duration: 0.5, delay: 0.3 }}
              className="h-full min-h-[500px]"
            >
              <VulnerabilityFindings findings={findings} />
            </motion.div>
          </section>

          {/* SECTION 3 — AUTONOMOUS AI SWARM */}
          <section id="ai-swarm" className="w-full">
            <motion.div
              initial={{ opacity: 0, y: 20 }}
              animate={{ opacity: 1, y: 0 }}
              transition={{ duration: 0.5, delay: 0.4 }}
            >
              <AgentSwarm activeAgentIds={activeAgents} />
            </motion.div>
          </section>

          {/* SECTION 4 — MULTI-STEP ATTACK CHAIN VISUALIZATION */}
          <section id="attack-chain" className="w-full">
            <motion.div
              initial={{ opacity: 0, y: 20 }}
              animate={{ opacity: 1, y: 0 }}
              transition={{ duration: 0.6, delay: 0.5 }}
              className="min-h-[600px] w-full"
            >
              <AttackChainGraph nodes={graphData.nodes} edges={graphData.edges} />
            </motion.div>
          </section>
        </main>

        {/* Bottom Status Bar */}
        <footer className="relative z-10 mt-auto border-t border-white/5 bg-black/60 backdrop-blur-md px-8 py-3 flex items-center justify-between text-[10px] text-muted-foreground uppercase tracking-[0.2em] font-bold">
          <div className="flex items-center gap-6">
            <div className="flex items-center gap-2">
              <Zap className="w-3 h-3 text-primary" />
              <span>Orchestrator: Cloud-Native Neural Mesh</span>
            </div>
            <div className="flex items-center gap-2">
              <Brain className="w-3 h-3 text-primary" />
              <span>AI Model: Quantara-Prime-Pro v2</span>
            </div>
            <div className="flex items-center gap-2">
              <Shield className="w-3 h-3 text-primary" />
              <span>Safety Guard: Active</span>
            </div>
          </div>
          <div className="flex items-center gap-4">
             <span className="text-primary/70">System Latency: 42ms</span>
             <span className="flex items-center gap-1.5">
                <span className="h-1.5 w-1.5 rounded-full bg-primary" />
                Cloud-Sync Active
             </span>
          </div>
        </footer>
      </div>
    </Sidebar>
  );
}
