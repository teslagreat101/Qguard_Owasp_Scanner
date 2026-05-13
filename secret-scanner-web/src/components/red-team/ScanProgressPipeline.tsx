"use client";

import { motion } from "framer-motion";
import { CheckCircle2, Circle, Globe, Search, Zap, Database, Target, Shield } from "lucide-react";
import { cn } from "@/lib/utils";

const PIPELINE_STAGES = [
  { id: "recon", label: "Recon", icon: Globe },
  { id: "analysis", label: "Analysis", icon: Search },
  { id: "fuzzing", label: "Fuzzing", icon: Zap },
  { id: "mutation", label: "Mutation", icon: Database },
  { id: "exploitation", label: "Exploit", icon: Target },
  { id: "verification", label: "Verification", icon: Shield },
];

interface ScanProgressPipelineProps {
  activeStageIndex: number;
}

export function ScanProgressPipeline({ activeStageIndex }: ScanProgressPipelineProps) {
  return (
    <div className="w-full py-8">
      <div className="relative flex justify-between">
        {/* Background Line */}
        <div className="absolute top-1/2 left-0 w-full h-0.5 bg-white/5 -translate-y-1/2 z-0" />
        
        {/* Progress Line */}
        <motion.div 
          className="absolute top-1/2 left-0 h-0.5 bg-primary -translate-y-1/2 z-0 shadow-[0_0_10px_rgba(0,255,136,0.5)]"
          initial={{ width: "0%" }}
          animate={{ width: `${(activeStageIndex / (PIPELINE_STAGES.length - 1)) * 100}%` }}
          transition={{ duration: 0.5 }}
        />

        {PIPELINE_STAGES.map((stage, index) => {
          const isActive = index === activeStageIndex;
          const isCompleted = index < activeStageIndex;
          
          return (
            <div key={stage.id} className="relative z-10 flex flex-col items-center group">
              <motion.div 
                className={cn(
                  "w-12 h-12 rounded-full flex items-center justify-center border-2 transition-all duration-500",
                  isActive 
                    ? "bg-black border-primary text-primary shadow-[0_0_20px_rgba(0,255,136,0.4)] scale-110" 
                    : isCompleted 
                      ? "bg-primary border-primary text-background" 
                      : "bg-[#0B0F0C] border-white/10 text-muted-foreground"
                )}
                animate={isActive ? { boxShadow: ["0 0 10px rgba(0,255,136,0.2)", "0 0 25px rgba(0,255,136,0.5)", "0 0 10px rgba(0,255,136,0.2)"] } : {}}
                transition={{ repeat: Infinity, duration: 2 }}
              >
                {isCompleted ? <CheckCircle2 className="w-6 h-6" /> : <stage.icon className="w-5 h-5" />}
              </motion.div>
              
              <div className="absolute top-14 text-center whitespace-nowrap">
                <p className={cn(
                  "text-[10px] font-bold uppercase tracking-widest transition-colors duration-500",
                  isActive ? "text-primary" : isCompleted ? "text-primary/70" : "text-muted-foreground"
                )}>
                  {stage.label}
                </p>
                {isActive && (
                    <motion.p 
                        initial={{ opacity: 0 }}
                        animate={{ opacity: 1 }}
                        className="text-[8px] text-primary/50 font-mono animate-pulse mt-1"
                    >
                        EXECUTING...
                    </motion.p>
                )}
              </div>
            </div>
          );
        })}
      </div>
    </div>
  );
}
