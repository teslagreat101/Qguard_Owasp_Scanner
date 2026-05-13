"use client";

import { motion, AnimatePresence } from "framer-motion";
import { 
  Globe, 
  Search, 
  Zap, 
  Database, 
  Target, 
  Shield, 
  Cpu, 
  Activity,
  Bug,
  AlertTriangle,
  Server,
  Network,
  Share2
} from "lucide-react";
import { useEffect, useState, useMemo } from "react";
import { Badge } from "@/components/ui/badge";
import { cn } from "@/lib/utils";
import { LogEntry, Finding } from "@/lib/api";

const NODES = [
  { id: "recon", label: "Recon Layer", icon: Globe, x: -180, y: -120, version: "v5.0.1", modules: ["endpoint_discovery", "subdomain_discovery"] },
  { id: "analysis", label: "Analysis Engine", icon: Search, x: 180, y: -120, version: "v5.0.2", modules: ["input_mapper", "endpoint_classifier"] },
  { id: "fuzzing", label: "Fuzzing Engine", icon: Zap, x: -220, y: 20, version: "v5.0.3", modules: ["mutation_engine", "payload_generator"] },
  { id: "mutation", label: "Self Learning", icon: Database, x: 220, y: 20, version: "v5.0.4", modules: ["payload_ranker", "learning_engine"] },
  { id: "execution", label: "Exploit Engine", icon: Target, x: -150, y: 150, version: "v5.0.5", modules: ["attack_executor", "timing_detector"] },
  { id: "verification", label: "AI Verification", icon: Shield, x: 150, y: 150, version: "v5.0.6", modules: ["verdict_engine", "impact_analyzer"] },
];

interface OrchestrationSwarmGraphProps {
  activeLayerIndex: number;
  logs: LogEntry[];
  findings: Finding[];
  isScanning: boolean;
}

export function OrchestrationSwarmGraph({ activeLayerIndex, logs, findings, isScanning }: OrchestrationSwarmGraphProps) {
  const [discoveredEndpoints, setDiscoveredEndpoints] = useState<number>(0);
  const [payloadsGenerated, setPayloadsGenerated] = useState<number>(0);
  const [attacksAttempted, setAttacksAttempted] = useState<number>(0);

  // Parse logs for real-time stats (simplified for visualization)
  useEffect(() => {
    if (!isScanning) {
      setDiscoveredEndpoints(0);
      setPayloadsGenerated(0);
      setAttacksAttempted(0);
      return;
    }

    const lastLog = logs[logs.length - 1];
    if (lastLog) {
      if (lastLog.message.toLowerCase().includes("discovered") || lastLog.message.toLowerCase().includes("endpoint")) {
        setDiscoveredEndpoints(prev => prev + 1);
      }
      if (lastLog.message.toLowerCase().includes("payload") || lastLog.message.toLowerCase().includes("mutation")) {
        setPayloadsGenerated(prev => prev + (Math.floor(Math.random() * 5) + 1));
      }
      if (lastLog.message.toLowerCase().includes("attacking") || lastLog.message.toLowerCase().includes("executing")) {
        setAttacksAttempted(prev => prev + 1);
      }
    }
  }, [logs, isScanning]);

  return (
    <div className="relative w-full h-full flex items-center justify-center overflow-hidden bg-[#0B0F0C] rounded-3xl border border-primary/20 shadow-[0_0_50px_rgba(0,255,136,0.1)]">
      {/* Background Grid */}
      <div className="absolute inset-0 opacity-10" 
           style={{ backgroundImage: "radial-gradient(var(--primary) 1px, transparent 1px)", backgroundSize: "30px 30px" }} />
      
      {/* Visual Center Glow */}
      <div className="absolute inset-0 bg-primary/5 blur-[100px] pointer-events-none" />

      {/* SVG Connections & Data Flow */}
      <svg className="absolute inset-0 w-full h-full pointer-events-none" viewBox="-300 -200 600 400">
        <defs>
          <linearGradient id="lineGradient" x1="0%" y1="0%" x2="100%" y2="0%">
            <stop offset="0%" stopColor="transparent" />
            <stop offset="50%" stopColor="rgba(0, 255, 136, 0.4)" />
            <stop offset="100%" stopColor="transparent" />
          </linearGradient>
          <filter id="glow">
            <feGaussianBlur stdDeviation="2.5" result="coloredBlur"/>
            <feMerge>
                <feMergeNode in="coloredBlur"/>
                <feMergeNode in="SourceGraphic"/>
            </feMerge>
          </filter>
        </defs>

        {/* Connection Lines from Core to Nodes */}
        {NODES.map((node, i) => {
          const isActive = i === activeLayerIndex && isScanning;
          const isCompleted = i < activeLayerIndex && isScanning;
          
          return (
            <g key={node.id}>
              {/* Static Line */}
              <line 
                x1="0" y1="0" 
                x2={node.x} y2={node.y} 
                stroke={isActive || isCompleted ? "rgba(0, 255, 136, 0.3)" : "rgba(255, 255, 255, 0.05)"}
                strokeWidth="1.5"
              />
              
              {/* Animated Data Stream */}
              {(isActive || (isScanning && !isCompleted && Math.random() > 0.7)) && (
                <motion.circle
                  r="2"
                  fill="var(--primary)"
                  filter="url(#glow)"
                  initial={{ cx: 0, cy: 0 }}
                  animate={{ cx: node.x, cy: node.y }}
                  transition={{ 
                    duration: 1.5, 
                    repeat: Infinity, 
                    ease: "linear",
                    delay: Math.random() * 2
                  }}
                />
              )}
            </g>
          );
        })}

        {/* Inter-node dependencies flow (Recon -> Analysis, etc) */}
        {activeLayerIndex > 0 && isScanning && (
          <motion.path
            d={`M ${NODES[activeLayerIndex - 1].x} ${NODES[activeLayerIndex - 1].y} L ${NODES[activeLayerIndex].x} ${NODES[activeLayerIndex].y}`}
            stroke="var(--primary)"
            strokeWidth="1"
            strokeDasharray="5,5"
            initial={{ strokeDashoffset: 0, opacity: 0 }}
            animate={{ strokeDashoffset: -20, opacity: 0.5 }}
            transition={{ strokeDashoffset: { repeat: Infinity, duration: 1, ease: "linear" }, opacity: { duration: 0.5 } }}
          />
        )}
      </svg>

      {/* Center Node: AI Orchestration Core */}
      <div className="relative z-20">
        <motion.div
          animate={isScanning ? {
            scale: [1, 1.1, 1],
            boxShadow: [
              "0 0 20px rgba(0, 255, 136, 0.2)",
              "0 0 50px rgba(0, 255, 136, 0.5)",
              "0 0 20px rgba(0, 255, 136, 0.2)"
            ]
          } : {}}
          transition={{ duration: 3, repeat: Infinity }}
          className={cn(
            "w-20 h-20 rounded-full flex items-center justify-center border-2 transition-all duration-500",
            isScanning ? "bg-black border-primary text-primary" : "bg-white/5 border-white/10 text-muted-foreground"
          )}
        >
          <Cpu className={cn("w-10 h-10", isScanning && "animate-pulse")} />
          
          {/* Scanning Status Label */}
          <div className="absolute -bottom-8 whitespace-nowrap">
            <Badge variant="outline" className={cn(
              "text-[10px] font-black tracking-widest bg-black/50 backdrop-blur-sm",
              isScanning ? "text-primary border-primary/40 animate-pulse" : "border-white/10 opacity-40"
            )}>
              {isScanning ? "CORE: ACTIVE" : "CORE: STANDBY"}
            </Badge>
          </div>
        </motion.div>
      </div>

      {/* Surround Nodes: Scanning Engines */}
      <div className="absolute inset-0 flex items-center justify-center pointer-events-none">
        {NODES.map((node, i) => {
          const isActive = i === activeLayerIndex && isScanning;
          const isCompleted = i < activeLayerIndex && isScanning;
          const hasVulnerabilities = findings.some(f => f.module === node.id || f.module_name === node.label);
          
          return (
            <motion.div
              key={node.id}
              initial={false}
              animate={{ x: node.x, y: node.y }}
              className="absolute"
            >
              <div className="relative flex flex-col items-center gap-2">
                <motion.div
                  animate={isActive ? { 
                    boxShadow: ["0 0 10px rgba(0,255,136,0.1)", "0 0 30px rgba(0,255,136,0.4)", "0 0 10px rgba(0,255,136,0.1)"] 
                  } : hasVulnerabilities ? {
                    boxShadow: ["0 0 10px rgba(239,68,68,0.2)", "0 0 30px rgba(239,68,68,0.6)", "0 0 10px rgba(239,68,68,0.2)"]
                  } : {}}
                  transition={{ repeat: Infinity, duration: 2 }}
                  className={cn(
                    "w-12 h-12 rounded-2xl flex items-center justify-center border-2 transition-all duration-500",
                    isActive 
                      ? "bg-black border-primary text-primary scale-110" 
                      : isCompleted
                        ? "bg-primary/20 border-primary/40 text-primary"
                        : "bg-black border-white/10 text-muted-foreground/40",
                    hasVulnerabilities && "border-red-500 text-red-500"
                  )}
                >
                  <node.icon className="w-6 h-6" />
                  
                  {/* Vulnerability Indicator */}
                  {hasVulnerabilities && (
                    <div className="absolute -top-1 -right-1 flex h-4 w-4">
                      <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-red-500 opacity-75"></span>
                      <span className="relative inline-flex rounded-full h-4 w-4 bg-red-500 flex items-center justify-center">
                        <Bug className="w-2.5 h-2.5 text-white" />
                      </span>
                    </div>
                  )}
                </motion.div>

                <div className="text-center">
                  <p className={cn(
                    "text-[9px] font-bold uppercase tracking-widest",
                    isActive ? "text-primary transition-all scale-105" : "text-muted-foreground/60"
                  )}>
                    {node.label}
                  </p>
                  <Badge variant="ghost" className="text-[7px] py-0 border-none opacity-40 font-mono tracking-tighter">
                    {node.version}
                  </Badge>
                </div>

                {/* mini stats for active nodes */}
                <AnimatePresence>
                  {isActive && node.id === "recon" && discoveredEndpoints > 0 && (
                    <motion.div 
                      initial={{ opacity: 0, y: 10 }}
                      animate={{ opacity: 1, y: -50 }}
                      exit={{ opacity: 0 }}
                      className="absolute top-0 flex items-center gap-1.5 px-2 py-1 bg-black/80 border border-primary/20 rounded-md whitespace-nowrap"
                    >
                      <Share2 className="w-2.5 h-2.5 text-primary" />
                      <span className="text-[10px] text-primary font-bold">DISCOVERED: {discoveredEndpoints}</span>
                    </motion.div>
                  )}
                  {isActive && node.id === "fuzzing" && payloadsGenerated > 0 && (
                    <motion.div 
                      initial={{ opacity: 0, y: 10 }}
                      animate={{ opacity: 1, y: -50 }}
                      className="absolute top-0 flex items-center gap-1.5 px-2 py-1 bg-black/80 border border-primary/20 rounded-md whitespace-nowrap"
                    >
                      <Zap className="w-2.5 h-2.5 text-primary" />
                      <span className="text-[10px] text-primary font-bold">PAYLOADS: {payloadsGenerated}</span>
                    </motion.div>
                  )}
                  {isActive && node.id === "execution" && attacksAttempted > 0 && (
                    <motion.div 
                      initial={{ opacity: 0, y: 10 }}
                      animate={{ opacity: 1, y: -50 }}
                      className="absolute top-0 flex items-center gap-1.5 px-2 py-1 bg-black/80 border border-primary/20 rounded-md whitespace-nowrap"
                    >
                      <Activity className="w-2.5 h-2.5 text-primary" />
                      <span className="text-[10px] text-primary font-bold">ATTEMPTS: {attacksAttempted}</span>
                    </motion.div>
                  )}
                </AnimatePresence>
              </div>
            </motion.div>
          );
        })}
      </div>

      {/* Dynamic Packets appearing in the background during fuzzing */}
      {isScanning && activeLayerIndex >= 2 && activeLayerIndex <= 4 && (
        <div className="absolute inset-0 pointer-events-none">
          {[...Array(5)].map((_, i) => (
            <motion.div
              key={i}
              className="absolute w-1 h-1 bg-primary rounded-full blur-[1px]"
              initial={{ 
                x: 0, 
                y: 0,
                opacity: 0 
              }}
              animate={{ 
                x: [0, (Math.random() - 0.5) * 600],
                y: [0, (Math.random() - 0.5) * 400],
                opacity: [0, 1, 0]
              }}
              transition={{ 
                duration: 2, 
                repeat: Infinity,
                delay: i * 0.4,
                ease: "linear"
              }}
            />
          ))}
        </div>
      )}

      {/* Target Nodes being scanned (Discovery Visualization) */}
      <AnimatePresence>
        {isScanning && discoveredEndpoints > 0 && (
          <div className="absolute inset-0 pointer-events-none">
            {[...Array(Math.min(discoveredEndpoints, 8))].map((_, i) => {
              const angle = (i * 45) * (Math.PI / 180);
              const r = 180;
              const x = r * Math.cos(angle);
              const y = r * Math.sin(angle);
              return (
                <motion.div
                  key={i}
                  initial={{ opacity: 0, scale: 0 }}
                  animate={{ opacity: 1, scale: 1 }}
                  style={{ x, y }}
                  className="absolute left-1/2 top-1/2 -ml-1 -mt-1 w-2 h-2 rounded-full bg-white/10 border border-white/20"
                />
              );
            })}
          </div>
        )}
      </AnimatePresence>

      {/* Top Left Active Module HUD */}
      <div className="absolute top-4 left-4 p-3 bg-black/60 backdrop-blur-md rounded-xl border border-white/5 font-mono text-[10px] text-primary space-y-2">
        <div className="flex items-center gap-2 opacity-50">
          <Server className="w-3 h-3" />
          <span className="uppercase tracking-widest font-bold">System Status</span>
        </div>
        <div className="space-y-1">
          <p className="flex justify-between gap-8">
            <span className="text-muted-foreground font-medium">MOD_ID:</span>
            <span>{NODES[activeLayerIndex].id.toUpperCase()}</span>
          </p>
          <p className="flex justify-between gap-8">
            <span className="text-muted-foreground font-medium">THREAT_LVL:</span>
            <span className={cn(findings.length > 3 ? "text-red-500" : findings.length > 0 ? "text-yellow-500" : "text-primary")}>
              {findings.length > 3 ? "CRITICAL" : findings.length > 0 ? "ELEVATED" : "SEARCHING"}
            </span>
          </p>
          <p className="flex justify-between gap-8">
            <span className="text-muted-foreground font-medium">NEURAL_SYNC:</span>
            <span className="animate-pulse">{(Math.random() * 0.2 + 0.8).toFixed(4)}%</span>
          </p>
        </div>
      </div>

      {/* Bottom Right Intelligence Stream HUD */}
      <div className="absolute bottom-4 right-4 text-right p-3 bg-black/60 backdrop-blur-md rounded-xl border border-white/5 font-mono text-[10px] text-primary/60">
        <div className="flex items-center justify-end gap-2 mb-1">
          <span className="uppercase tracking-widest font-black text-[8px] animate-pulse">Telemetry Stream</span>
          <Activity className="w-2.5 h-2.5" />
        </div>
        <p className="italic">LATENCY: {(Math.random() * 50 + 10).toFixed(1)} MS</p>
        <p>BUFFER: STABLE</p>
      </div>
    </div>
  );
}
