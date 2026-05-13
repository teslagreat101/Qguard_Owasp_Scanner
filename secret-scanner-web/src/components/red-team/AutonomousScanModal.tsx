"use client";

import { useState } from "react";
import { motion, AnimatePresence } from "framer-motion";
import { 
  Zap, 
  Target, 
  Search, 
  Shield, 
  Globe, 
  Cpu, 
  X,
  Database,
  Layers,
  ChevronDown
} from "lucide-react";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Badge } from "@/components/ui/badge";
import { 
  Dialog, 
  DialogContent, 
  DialogHeader, 
  DialogTitle, 
  DialogDescription,
  DialogFooter
} from "@/components/ui/dialog";
import { 
  Select, 
  SelectContent, 
  SelectItem, 
  SelectTrigger, 
  SelectValue 
} from "@/components/ui/select";
import { Label } from "@/components/ui/label";
import { Switch } from "@/components/ui/switch";
import { ScrollArea } from "@/components/ui/scroll-area";
import { cn } from "@/lib/utils";

interface AutonomousScanModalProps {
  isOpen: boolean;
  onClose: () => void;
  onStartScan: (config: any) => void;
}

const SCAN_ENGINES = [
  {
    id: "recon",
    title: "Reconnaissance Layer",
    description: "Multi-vector discovery of attack surfaces.",
    version: "v5.0.1",
    icon: Globe,
    modules: ["endpoint_discovery", "api_structure_mapper", "technology_fingerprint", "header_analyzer", "subdomain_discovery"]
  },
  {
    id: "analysis",
    title: "Analysis Engine",
    description: "Deep semantic analysis of application behavior.",
    version: "v5.0.2",
    icon: Search,
    modules: ["input_mapper", "auth_mapper", "response_behavior_analyzer", "endpoint_classifier"]
  },
  {
    id: "fuzzing",
    title: "AI Fuzzing Engine",
    description: "LLM-assisted payload generation and fuzz testing.",
    version: "v5.0.3",
    icon: Zap,
    modules: ["Seed Payload Library", "Mutation Engine", "LLM Payload Generator", "Coverage Analyzer"]
  },
  {
    id: "mutation",
    title: "Self Learning Mutation",
    description: "Adaptive evolution of payload strategies.",
    version: "v5.0.4",
    icon: Database,
    modules: ["payload_mutator", "payload_ranker", "payload_learning_engine"]
  },
  {
    id: "execution",
    title: "Exploit Execution Engine",
    description: "Automated vulnerability exploitation.",
    version: "v5.0.5",
    icon: Target,
    modules: ["attack_executor", "timing_anomaly_detector", "response_diff_engine"]
  },
  {
    id: "verification",
    title: "AI Verification Engine",
    description: "False positive elimination using AI validation.",
    version: "v5.0.6",
    icon: Shield,
    modules: ["verdict_engine", "severity_calculator", "impact_analyzer"]
  }
];

export function AutonomousScanModal({ isOpen, onClose, onStartScan }: AutonomousScanModalProps) {
  const [targetUrl, setTargetUrl] = useState("");
  const [scanDepth, setScanDepth] = useState("standard");
  const [enabledEngines, setEnabledEngines] = useState<string[]>(SCAN_ENGINES.map(e => e.id));

  const toggleEngine = (id: string) => {
    setEnabledEngines(prev => 
      prev.includes(id) ? prev.filter(e => e !== id) : [...prev, id]
    );
  };

  const handleStart = () => {
    // Generate the legacy config format for the current onStartScan implementation
    const enabledModules = SCAN_ENGINES
      .filter(e => enabledEngines.includes(e.id))
      .flatMap(e => e.modules);
      
    onStartScan({
      targetUrl,
      scanDepth,
      enabledModules,
      enabledEngines
    });
  };

  return (
    <Dialog open={isOpen} onOpenChange={onClose}>
      <DialogContent className="max-w-4xl max-h-[90vh] bg-[#0B0F0C] border-primary/20 text-foreground overflow-hidden flex flex-col p-0 gap-0 shadow-[0_0_100px_rgba(0,255,136,0.1)]">
        <DialogHeader className="p-6 border-b border-white/5 bg-gradient-to-b from-primary/5 to-transparent">
          <div className="flex items-center gap-4">
            <div className="p-3 bg-primary/10 rounded-2xl border border-primary/20 shadow-[0_0_20px_rgba(0,255,136,0.1)]">
              <Cpu className="w-8 h-8 text-primary" />
            </div>
            <div>
              <DialogTitle className="text-2xl font-bold font-outfit tracking-tight">Autonomous AI Scan Configuration</DialogTitle>
              <DialogDescription className="text-muted-foreground font-mono text-xs uppercase tracking-widest mt-1">
                Configure the AI Red Team swarm to begin attack surface analysis.
              </DialogDescription>
            </div>
          </div>
        </DialogHeader>

        <ScrollArea className="flex-1 p-6">
          <div className="space-y-8">
            {/* Section 1: Target Definition */}
            <section className="space-y-4">
              <div className="flex items-center gap-2 mb-2">
                <Target className="w-4 h-4 text-primary" />
                <h3 className="text-sm font-bold uppercase tracking-widest">Target Definition</h3>
              </div>
              
              <div className="space-y-2">
                <Label htmlFor="targetUrl" className="text-xs font-bold text-muted-foreground uppercase opacity-70">Target URL / Domain / IP</Label>
                <div className="relative group">
                  <Globe className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-muted-foreground group-focus-within:text-primary transition-colors" />
                  <Input 
                    id="targetUrl" 
                    placeholder="https://example.com or 192.168.1.1"
                    value={targetUrl}
                    onChange={(e) => setTargetUrl(e.target.value)}
                    className="bg-black/40 border-white/10 rounded-xl focus:border-primary/50 h-12 pl-10 text-lg font-medium transition-all"
                  />
                </div>
              </div>
            </section>

            {/* Section 2: AI Swarm Scan Engines */}
            <section className="space-y-4">
              <div className="flex items-center gap-2 mb-2">
                <Layers className="w-4 h-4 text-primary" />
                <h3 className="text-sm font-bold uppercase tracking-widest">AI Swarm Scan Engines</h3>
              </div>

              <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
                {SCAN_ENGINES.map((engine) => {
                  const isEnabled = enabledEngines.includes(engine.id);
                  return (
                    <motion.div 
                      key={engine.id}
                      onClick={() => toggleEngine(engine.id)}
                      whileHover={{ scale: 1.02 }}
                      whileTap={{ scale: 0.98 }}
                      className={cn(
                        "relative p-4 rounded-2xl border transition-all cursor-pointer group",
                        isEnabled 
                          ? "bg-primary/5 border-primary/50 shadow-[0_0_20px_rgba(0,255,136,0.1)]" 
                          : "bg-white/5 border-white/10 hover:border-primary/30"
                      )}
                    >
                      <div className="flex justify-between items-start mb-4">
                        <div className={cn(
                          "p-2 rounded-xl transition-colors",
                          isEnabled ? "bg-primary text-background" : "bg-white/5 text-muted-foreground group-hover:text-primary"
                        )}>
                          <engine.icon className="w-5 h-5" />
                        </div>
                        <div className="flex flex-col items-end gap-2">
                          <Switch 
                            checked={isEnabled}
                            onCheckedChange={() => toggleEngine(engine.id)}
                            className="data-[state=checked]:bg-primary"
                            onClick={(e) => e.stopPropagation()}
                          />
                          <Badge variant="outline" className="text-[8px] py-0 border-white/10 opacity-50">{engine.version}</Badge>
                        </div>
                      </div>
                      
                      <div className="space-y-1">
                        <h4 className={cn(
                          "text-sm font-bold transition-colors",
                          isEnabled ? "text-primary" : "text-foreground group-hover:text-primary"
                        )}>
                          {engine.title}
                        </h4>
                        <p className="text-[10px] text-muted-foreground leading-relaxed line-clamp-2">
                          {engine.description}
                        </p>
                      </div>

                      {isEnabled && (
                        <motion.div 
                          layoutId="glow"
                          className="absolute inset-0 rounded-2xl bg-primary/5 pointer-events-none animate-pulse"
                        />
                      )}
                    </motion.div>
                  );
                })}
              </div>
            </section>

            {/* Section 3: Scan Depth Selector */}
            <section className="space-y-4 pt-2">
              <div className="flex items-center gap-2 mb-2">
                <Zap className="w-4 h-4 text-primary" />
                <h3 className="text-sm font-bold uppercase tracking-widest">Scan Strategy</h3>
              </div>

              <div className="max-w-xs">
                <Label className="text-xs font-bold text-muted-foreground uppercase opacity-70 mb-2 block">Depth Precision</Label>
                <Select value={scanDepth} onValueChange={setScanDepth}>
                  <SelectTrigger className="bg-black/40 border-white/10 rounded-xl h-11 focus:ring-primary/30">
                    <SelectValue placeholder="Select depth" />
                  </SelectTrigger>
                  <SelectContent className="bg-[#0B0F0C] border-white/10 text-foreground">
                    <SelectItem value="light">Light Reconnaissance</SelectItem>
                    <SelectItem value="standard">Standard Scan</SelectItem>
                    <SelectItem value="deep">Deep Attack Simulation</SelectItem>
                  </SelectContent>
                </Select>
              </div>
            </section>
          </div>
        </ScrollArea>

        <DialogFooter className="p-6 border-t border-white/5 bg-black/40 flex items-center justify-between sm:justify-between w-full">
          <Button variant="outline" onClick={onClose} className="rounded-xl border-white/10 hover:bg-white/5 px-8">
            Cancel
          </Button>
          <Button 
            onClick={handleStart}
            disabled={!targetUrl}
            className="rounded-xl px-12 bg-primary text-background font-bold shadow-[0_0_30px_rgba(0,255,136,0.2)] hover:shadow-[0_0_40px_rgba(0,255,136,0.4)] transition-all hover:bg-primary/90 active:scale-95 h-12"
          >
            Scan Now
            <Zap className="ml-2 w-4 h-4 fill-current" />
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}
