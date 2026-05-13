"use client";

import { useEffect, useRef, useState } from "react";
import { motion, AnimatePresence } from "framer-motion";
import { 
  Terminal, 
  Cpu, 
  Activity, 
  Search, 
  Zap, 
  Bug, 
  CheckCircle2, 
  AlertTriangle,
  Clock,
  ChevronDown,
  ExternalLink,
  ShieldCheck,
  Radar
} from "lucide-react";
import { Badge } from "@/components/ui/badge";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { cn } from "@/lib/utils";
import { LogEntry } from "@/lib/api";

interface RealTimeActivityProps {
  logs: LogEntry[];
  activeAgents: string[];
  scanStatus: string;
}

export function RealTimeActivity({ logs, activeAgents, scanStatus }: RealTimeActivityProps) {
  const scrollRef = useRef<HTMLDivElement>(null);
  
  useEffect(() => {
    if (scrollRef.current) {
      scrollRef.current.scrollTop = scrollRef.current.scrollHeight;
    }
  }, [logs]);

  const getLogIcon = (level: string) => {
    switch (level) {
      case "success": return <CheckCircle2 className="w-3 h-3 text-primary" />;
      case "warn": return <AlertTriangle className="w-3 h-3 text-yellow-500" />;
      case "error": return <AlertTriangle className="w-3 h-3 text-red-500" />;
      default: return <Activity className="w-3 h-3 text-blue-500" />;
    }
  };

  return (
    <Card className="bg-[#0B0F0C]/80 backdrop-blur-xl border-primary/20 shadow-[0_0_50px_rgba(0,255,136,0.05)] h-full flex flex-col">
      <CardHeader className="flex flex-row items-center justify-between pb-2 border-b border-white/5">
        <div className="flex items-center gap-2">
          <Terminal className="w-4 h-4 text-primary" />
          <CardTitle className="text-sm font-bold uppercase tracking-widest text-foreground">Live Telemetry & Activity</CardTitle>
        </div>
        <div className="flex items-center gap-3">
            <Badge variant="outline" className={cn(
                "text-[9px] py-0 border-primary/20 bg-primary/5 text-primary animate-pulse",
                scanStatus !== "running" && "hidden"
            )}>
                PHASE: {scanStatus === "running" ? "INFILTRATION & RECON" : "STANDBY"}
            </Badge>
            <div className="flex items-center gap-1.5">
                <span className="relative flex h-2 w-2">
                    <span className={cn(
                        "animate-ping absolute inline-flex h-full w-full rounded-full opacity-75",
                        scanStatus === "running" ? "bg-primary" : "bg-muted"
                    )}></span>
                    <span className={cn(
                        "relative inline-flex rounded-full h-2 w-2",
                        scanStatus === "running" ? "bg-primary" : "bg-muted"
                    )}></span>
                </span>
                <span className="text-[10px] text-muted-foreground uppercase tracking-widest font-black">
                    {scanStatus === "running" ? "Live Pipeline" : "Idle"}
                </span>
            </div>
        </div>
      </CardHeader>
      
      {/* Active Agents Ribbon */}
      <div className="bg-black/40 border-b border-white/5 py-2 px-4 overflow-hidden">
        <div className="flex items-center gap-2 mb-2">
            <Radar className="w-3 h-3 text-primary animate-pulse" />
            <span className="text-[9px] font-bold text-muted-foreground uppercase tracking-[0.2em]">Active Agent Swarm</span>
        </div>
        <div className="flex gap-2 pb-1 overflow-x-auto no-scrollbar">
            {activeAgents.length > 0 ? (
                activeAgents.map((agent) => (
                    <Badge 
                        key={agent} 
                        variant="outline" 
                        className="text-[9px] py-0 px-2 h-5 bg-primary/5 border-primary/30 text-primary whitespace-nowrap"
                    >
                        {agent}
                    </Badge>
                ))
            ) : (
                <span className="text-[9px] text-muted-foreground italic">No agents currently deployed</span>
            )}
        </div>
      </div>

      <CardContent className="flex-1 overflow-hidden p-0 relative">
        <div 
          ref={scrollRef}
          className="h-[400px] overflow-y-auto p-4 space-y-3 font-mono text-[11px] scroll-smooth no-scrollbar"
        >
          <AnimatePresence initial={false}>
            {logs.length > 0 ? (
                logs.map((log, i) => (
                    <motion.div 
                        key={i}
                        initial={{ opacity: 0, x: -10 }}
                        animate={{ opacity: 1, x: 0 }}
                        className="flex gap-3 group"
                    >
                        <span className="text-muted-foreground/40 shrink-0 select-none">[{log.time}]</span>
                        <div className="flex gap-2">
                            <span className="shrink-0 mt-0.5">{getLogIcon(log.level)}</span>
                            <div className="space-y-1">
                                <p className={cn(
                                    "text-foreground/90 leading-relaxed",
                                    log.level === "success" && "text-primary/90",
                                    log.level === "warn" && "text-yellow-500/90",
                                    log.level === "error" && "text-red-500/90"
                                )}>
                                    <span className="text-blue-400 font-bold mr-1">[{log.module || "SYSTEM"}]</span>
                                    {log.message}
                                </p>
                            </div>
                        </div>
                    </motion.div>
                ))
            ) : (
                <div className="h-full flex flex-col items-center justify-center space-y-4 opacity-50">
                    <Activity className="w-12 h-12 text-primary/20 animate-pulse" />
                    <p className="text-xs text-muted-foreground uppercase tracking-widest">Waiting for telemetry stream...</p>
                </div>
            )}
          </AnimatePresence>
        </div>
        
        {/* Bottom Fade Gradient */}
        <div className="absolute bottom-0 left-0 right-0 h-12 bg-gradient-to-t from-[#0B0F0C] to-transparent pointer-events-none" />
      </CardContent>
    </Card>
  );
}
