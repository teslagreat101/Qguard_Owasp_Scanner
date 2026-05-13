"use client";

import { motion } from "framer-motion";
import { 
  ShieldCheck, 
  Search, 
  Cpu, 
  Zap, 
  Terminal, 
  Database, 
  Lock, 
  Globe, 
  Fingerprint, 
  Eye, 
  Bomb, 
  Puzzle,
  Microscope,
  Box,
  BrainCircuit,
  Settings,
  Activity,
  UserCheck,
  Server,
  Target
} from "lucide-react";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { cn } from "@/lib/utils";

const AGENTS = [
  { id: "Recon-X", name: "Recon-X", role: "Surface Discovery Engine", icon: Search, color: "text-blue-400" },
  { id: "Payload-Gen", name: "Payload-Gen", role: "Vector Synthesis Engine", icon: Bomb, color: "text-red-400" },
  { id: "Exploit-Core", name: "Exploit-Core", role: "Active Exploitation Engine", icon: Target, color: "text-orange-400" },
  { id: "Auth-Breach", name: "Auth-Breach", role: "Credential Bypass Engine", icon: Lock, color: "text-pink-400" },
  { id: "WAF-Evasion", name: "WAF-Evasion", role: "Traffic Obfuscation Engine", icon: ShieldCheck, color: "text-yellow-400" },
  { id: "Logic-Probe", name: "Logic-Probe", role: "Business Logic Analysis", icon: Puzzle, color: "text-purple-400" },
  { id: "API-Guardian", name: "API-Guardian", role: "Endpoint Analysis Engine", icon: Box, color: "text-cyan-400" },
  { id: "Cloud-Siphon", name: "Cloud-Siphon", role: "Infrastructure Mapping", icon: Server, color: "text-indigo-400" },
  { id: "Data-Miner", name: "Data-Miner", role: "Sensitive Data Discovery", icon: Database, color: "text-lime-400" },
  { id: "Fuzz-Master", name: "Fuzz-Master", role: "Input Perturbation Engine", icon: Fingerprint, color: "text-emerald-400" },
  { id: "Anomaly-Detection", name: "Anomaly-Detection", role: "Response Analysis Engine", icon: Eye, color: "text-teal-400" },
  { id: "Report-AI", name: "Report-AI", role: "Intelligence Consolidation", icon: Terminal, color: "text-slate-400" },
];

interface AgentSwarmProps {
  activeAgentIds: string[];
}

export function AgentSwarm({ activeAgentIds = [] }: AgentSwarmProps) {
  return (
    <Card className="bg-[#0B0F0C]/80 backdrop-blur-xl border-primary/20 shadow-[0_0_50px_rgba(0,255,136,0.05)] overflow-hidden">
      <CardHeader className="flex flex-row items-center justify-between pb-4 border-b border-white/5 bg-black/20">
        <div className="flex items-center gap-3">
          <div className="p-1.5 rounded-lg bg-primary/10 border border-primary/20">
            <BrainCircuit className="w-4 h-4 text-primary" />
          </div>
          <div>
            <CardTitle className="text-sm font-bold uppercase tracking-widest text-foreground">Autonomous AI Swarm</CardTitle>
            <p className="text-[10px] text-muted-foreground uppercase tracking-widest font-black opacity-50">12 Specialized Intelligence Nodes</p>
          </div>
        </div>
        <div className="flex items-center gap-2">
            <Badge variant="outline" className="text-[10px] py-0 border-primary/20 text-primary bg-primary/5">
                {activeAgentIds.length} ACTIVE
            </Badge>
        </div>
      </CardHeader>
      
      <CardContent className="p-4 bg-gradient-to-b from-black/40 to-transparent">
        <div className="grid grid-cols-2 md:grid-cols-4 xl:grid-cols-6 gap-4">
          {AGENTS.map((agent, i) => {
            const isActive = activeAgentIds.includes(agent.id) || activeAgentIds.includes(agent.name.toLowerCase());
            
            return (
              <motion.div
                key={agent.id}
                initial={{ opacity: 0, scale: 0.9 }}
                animate={{ opacity: 1, scale: 1 }}
                transition={{ delay: i * 0.05 }}
                className={cn(
                  "relative group p-4 rounded-xl border transition-all duration-300 min-h-[140px] flex flex-col justify-between",
                  isActive 
                    ? "bg-primary/5 border-primary/40 shadow-[0_0_15px_rgba(0,255,136,0.1)]" 
                    : "bg-black/40 border-white/5 hover:border-white/10"
                )}
              >
                {isActive && (
                    <div className="absolute top-2 right-2 flex h-2 w-2">
                        <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-primary opacity-75"></span>
                        <span className="relative inline-flex rounded-full h-2 w-2 bg-primary"></span>
                    </div>
                )}
                
                <div className="flex flex-col items-center text-center gap-3">
                  <div className={cn(
                    "p-2.5 rounded-lg bg-black/40 border border-white/5 transition-colors",
                    isActive ? "text-primary border-primary/20 scale-110 shadow-[0_0_15px_rgba(0,255,136,0.2)]" : agent.color
                  )}>
                    <agent.icon className="w-6 h-6" />
                  </div>
                  <div className="space-y-1">
                    <p className={cn(
                        "text-[11px] font-black uppercase tracking-widest",
                        isActive ? "text-primary" : "text-foreground/80"
                    )}>
                      {agent.name}
                    </p>
                    <p className="text-[9px] text-muted-foreground font-medium uppercase tracking-widest opacity-70">
                      {agent.role}
                    </p>
                  </div>
                </div>

                <div className="mt-3 pt-2 border-t border-white/5 flex items-center justify-center">
                    <Badge variant="ghost" className={cn(
                        "text-[8px] font-black tracking-widest",
                        isActive ? "text-primary" : "text-muted-foreground/40"
                    )}>
                        {isActive ? "ACTIVE" : "STANDBY"}
                    </Badge>
                </div>

                {/* Status Indicator Bar */}
                <div className="absolute bottom-0 left-0 right-0 h-1 rounded-b-xl overflow-hidden px-2">
                    <div className={cn(
                        "h-full rounded-full transition-all duration-1000",
                        isActive ? "bg-primary w-full shadow-[0_0_10px_rgba(0,255,136,1)]" : "bg-transparent w-0"
                    )} />
                </div>
              </motion.div>
            );
          })}
        </div>

        <div className="mt-4 p-3 rounded-lg bg-black/40 border border-white/5 flex items-center justify-between">
            <div className="flex items-center gap-3">
                <div className="h-2 w-2 rounded-full bg-primary animate-pulse shadow-[0_0_8px_rgba(0,255,136,0.5)]" />
                <span className="text-[10px] text-muted-foreground uppercase tracking-[0.15em] font-bold italic">
                    {activeAgentIds.length > 0 ? "Synchronization in progress..." : "Swarm standby. Awaiting mission parameters."}
                </span>
            </div>
            <div className="flex items-center gap-1 opacity-40">
                <Settings className="w-3 h-3 text-muted-foreground animate-spin-slow" />
            </div>
        </div>
      </CardContent>
    </Card>
  );
}
