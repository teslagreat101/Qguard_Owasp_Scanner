"use client";

import { useState } from "react";
import { motion, AnimatePresence } from "framer-motion";
import { 
  Zap, 
  Target, 
  Search, 
  Shield, 
  Lock, 
  Globe, 
  Server, 
  Cpu, 
  ChevronRight,
  Loader2,
  AlertCircle
} from "lucide-react";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Badge } from "@/components/ui/badge";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { 
  Select, 
  SelectContent, 
  SelectItem, 
  SelectTrigger, 
  SelectValue 
} from "@/components/ui/select";
import { Label } from "@/components/ui/label";
import { useAuth } from "@/contexts/auth-context";
import { api, ScanRequest } from "@/lib/api";
import { toast } from "sonner";
import { Switch } from "@/components/ui/switch";
import { Slider } from "@/components/ui/slider";

interface ScanLaunchModuleProps {
  onScanStarted: (scanId: string) => void;
}

export function ScanLaunchModule({ onScanStarted }: ScanLaunchModuleProps) {
  const { user } = useAuth();
  const [target, setTarget] = useState("");
  const [depth, setDepth] = useState("standard");
  const [strategy, setStrategy] = useState("autonomous");
  const [isLaunching, setIsLaunching] = useState(false);
  const [showAdvanced, setShowAdvanced] = useState(false);
  const [intensity, setIntensity] = useState([70]);
  const [aiFeatures, setAiFeatures] = useState({
    mutation: true,
    correlation: true,
    discovery: false,
    safeMode: true
  });

  const handleLaunch = async () => {
    if (!target) {
      toast.error("Please enter a target URL or Domain");
      return;
    }

    // Basic URL validation if it's meant to be a URL
    if (!target.startsWith("http") && !target.includes(".")) {
        toast.error("Please enter a valid URL or Domain");
        return;
    }

    setIsLaunching(true);
    try {
      // 🔐 Force refresh token to prevent 401 expiration errors
      if (user) {
        const token = await user.getIdToken(true);
        api.setAuthToken(token);
      }

      const request: any = {
        target: target.startsWith("http") ? target : `https://${target}`,
        depth: depth === "deep" ? "deep" : depth === "quick" ? "surface" : "standard",
        strategy: strategy
      };

      const response = await api.startSwarmScan(request);
      toast.success("Autonomous Red Team Scan Launched!");
      onScanStarted(response.scan_id);
    } catch (error: any) {
      console.error("Failed to launch scan:", error);
      toast.error(error.message || "Failed to launch scan. check backend connection.");
    } finally {
      setIsLaunching(false);
    }
  };

  return (
    <Card className="bg-[#0B0F0C]/80 backdrop-blur-xl border-primary/20 shadow-[0_0_50px_rgba(0,255,136,0.05)] overflow-hidden">
      <div className="absolute top-0 left-0 w-full h-1 bg-gradient-to-r from-transparent via-primary/50 to-transparent" />
      <CardHeader>
        <div className="flex items-center gap-3">
          <div className="p-2 rounded-lg bg-primary/10 border border-primary/20">
            <Target className="w-5 h-5 text-primary" />
          </div>
          <div>
            <CardTitle className="text-xl font-bold font-outfit">Launch Red Team Scan</CardTitle>
            <CardDescription className="text-muted-foreground text-xs uppercase tracking-widest mt-1">
              Autonomous Intelligence Orchestration
            </CardDescription>
          </div>
        </div>
      </CardHeader>
      <CardContent className="space-y-6">
        <div className="space-y-2">
          <Label htmlFor="target" className="text-sm font-medium text-foreground/80">Target URL or Domain</Label>
          <div className="relative group">
            <Globe className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-muted-foreground group-focus-within:text-primary transition-colors" />
            <Input
              id="target"
              placeholder="example.com or https://api.target.io"
              value={target}
              onChange={(e) => setTarget(e.target.value)}
              className="pl-10 bg-black/40 border-white/10 focus:border-primary/50 focus:ring-1 focus:ring-primary/50 transition-all rounded-xl h-12 text-foreground"
            />
          </div>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
          <div className="space-y-2">
            <Label className="text-sm font-medium text-foreground/80">Scan Depth</Label>
            <Select value={depth} onValueChange={setDepth}>
              <SelectTrigger className="bg-black/40 border-white/10 rounded-xl h-11 focus:ring-primary/30">
                <SelectValue placeholder="Select depth" />
              </SelectTrigger>
              <SelectContent className="bg-[#0B0F0C] border-white/10 text-foreground">
                <SelectItem value="quick">Quick (Surface Scan)</SelectItem>
                <SelectItem value="standard">Standard (Balanced)</SelectItem>
                <SelectItem value="deep">Deep (Full Exploitation)</SelectItem>
              </SelectContent>
            </Select>
          </div>

          <div className="space-y-2">
            <Label className="text-sm font-medium text-foreground/80">Attack Strategy</Label>
            <Select value={strategy} onValueChange={setStrategy}>
              <SelectTrigger className="bg-black/40 border-white/10 rounded-xl h-11 focus:ring-primary/30">
                <SelectValue placeholder="Select strategy" />
              </SelectTrigger>
              <SelectContent className="bg-[#0B0F0C] border-white/10 text-foreground">
                <SelectItem value="passive">Passive Reconnaissance</SelectItem>
                <SelectItem value="active">Active Scanning</SelectItem>
                <SelectItem value="autonomous">Autonomous AI Agent Swarm</SelectItem>
              </SelectContent>
            </Select>
          </div>
        </div>

        <AnimatePresence>
          {showAdvanced && (
            <motion.div
              initial={{ height: 0, opacity: 0 }}
              animate={{ height: "auto", opacity: 1 }}
              exit={{ height: 0, opacity: 0 }}
              className="space-y-4 pt-2 overflow-hidden"
            >
                <div className="space-y-4 pt-4 border-t border-white/5">
                  <div className="flex items-center justify-between">
                    <Label className="text-[11px] font-bold uppercase tracking-widest text-foreground/80 flex items-center gap-2">
                      <Zap className="w-3.5 h-3.5 text-primary" />
                      Attack Intensity
                    </Label>
                    <Badge variant="outline" className="text-primary border-primary/20 bg-primary/5">{intensity}%</Badge>
                  </div>
                  <Slider 
                    value={intensity} 
                    onValueChange={setIntensity} 
                    max={100} 
                    step={1} 
                    className="[&_.relative]:bg-white/10 [&_.absolute]:bg-primary [&_span]:border-primary"
                  />
                  <div className="flex justify-between text-[9px] text-muted-foreground uppercase font-black">
                    <span>Stealth (Slow)</span>
                    <span>Aggressive (Fast)</span>
                  </div>
                </div>

                <div className="grid grid-cols-1 md:grid-cols-2 gap-x-8 gap-y-4 pt-4">
                  <div className="flex items-center justify-between group">
                    <div className="space-y-0.5">
                      <Label className="text-[11px] font-bold text-foreground/90 group-hover:text-primary transition-colors">Neural Payload Mutation</Label>
                      <p className="text-[9px] text-muted-foreground leading-tight">AI-generated WAF bypass variants</p>
                    </div>
                    <Switch 
                      checked={aiFeatures.mutation} 
                      onCheckedChange={(v) => setAiFeatures({...aiFeatures, mutation: v})} 
                      className="data-[state=checked]:bg-primary" 
                    />
                  </div>
                  
                  <div className="flex items-center justify-between group">
                    <div className="space-y-0.5">
                      <Label className="text-[11px] font-bold text-foreground/90 group-hover:text-primary transition-colors">Cross-Domain Correlation</Label>
                      <p className="text-[9px] text-muted-foreground leading-tight">Map attack chains across subdomains</p>
                    </div>
                    <Switch 
                      checked={aiFeatures.correlation} 
                      onCheckedChange={(v) => setAiFeatures({...aiFeatures, correlation: v})} 
                      className="data-[state=checked]:bg-primary" 
                    />
                  </div>

                  <div className="flex items-center justify-between group">
                    <div className="space-y-0.5">
                      <Label className="text-[11px] font-bold text-foreground/90 group-hover:text-primary transition-colors">Zero-Knowledge Discovery</Label>
                      <p className="text-[9px] text-muted-foreground leading-tight">Autonomous endpoint discovery</p>
                    </div>
                    <Switch 
                      checked={aiFeatures.discovery} 
                      onCheckedChange={(v) => setAiFeatures({...aiFeatures, discovery: v})} 
                      className="data-[state=checked]:bg-primary" 
                    />
                  </div>

                  <div className="flex items-center justify-between group">
                    <div className="space-y-0.5">
                      <Label className="text-[11px] font-bold text-foreground/90 group-hover:text-primary transition-colors">Safe-Exploit Mode</Label>
                      <p className="text-[9px] text-muted-foreground leading-tight">Prevent destructive execution</p>
                    </div>
                    <Switch 
                      checked={aiFeatures.safeMode} 
                      onCheckedChange={(v) => setAiFeatures({...aiFeatures, safeMode: v})} 
                      className="data-[state=checked]:bg-primary" 
                    />
                  </div>
                </div>

                <div className="grid grid-cols-1 md:grid-cols-2 gap-4 border-t border-white/5 pt-4">
                  <div className="space-y-2">
                    <Label className="text-sm font-medium text-foreground/80">Authentication</Label>
                    <div className="relative">
                      <Lock className="absolute left-3 top-1/2 -translate-y-1/2 w-3.5 h-3.5 text-muted-foreground" />
                      <Input 
                        placeholder="Auth Token / Cookie" 
                        className="pl-9 bg-black/20 border-white/5 h-10 text-xs rounded-lg text-foreground"
                      />
                    </div>
                  </div>
                  <div className="space-y-2">
                    <Label className="text-sm font-medium text-foreground/80">Scanning Scope</Label>
                    <div className="relative">
                      <Cpu className="absolute left-3 top-1/2 -translate-y-1/2 w-3.5 h-3.5 text-muted-foreground" />
                      <Input 
                        placeholder="Subdomains, APIs, etc." 
                        className="pl-9 bg-black/20 border-white/5 h-10 text-xs rounded-lg text-foreground"
                      />
                    </div>
                  </div>
                </div>
            </motion.div>
          )}
        </AnimatePresence>

        <div className="flex items-center justify-between pt-2">
          <Button 
            variant="ghost" 
            size="sm" 
            onClick={() => setShowAdvanced(!showAdvanced)}
            className="text-muted-foreground hover:text-primary text-xs"
          >
            {showAdvanced ? "Hide Advanced Options" : "Show Advanced Options"}
          </Button>

          <Button 
            onClick={handleLaunch}
            disabled={isLaunching || !target}
            className="bg-primary hover:bg-primary/90 text-background font-bold px-8 rounded-xl min-w-[160px] h-12 shadow-[0_0_20px_rgba(0,255,136,0.2)] transition-all active:scale-95"
          >
            {isLaunching ? (
              <>
                <Loader2 className="w-4 h-4 mr-2 animate-spin" />
                Initializing...
              </>
            ) : (
              <>
                Launch Autonomous Scan
                <Zap className="ml-2 w-4 h-4 fill-current" />
              </>
            )}
          </Button>
        </div>

        {isLaunching && (
          <motion.div 
            initial={{ opacity: 0 }}
            animate={{ opacity: 1 }}
            className="flex items-center gap-2 p-3 rounded-lg bg-primary/5 border border-primary/10 text-[10px] text-primary/80 uppercase tracking-widest font-bold"
          >
            <Cpu className="w-3 h-3 animate-pulse" />
            Orchestrating AI Swarm: Deploying 12 specialized agents...
          </motion.div>
        )}
      </CardContent>
    </Card>
  );
}
