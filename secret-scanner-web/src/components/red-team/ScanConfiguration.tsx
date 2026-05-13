"use client";

import { motion } from "framer-motion";
import { 
  Settings2, 
  Shield, 
  Zap, 
  Target, 
  Eye, 
  EyeOff, 
  Sliders, 
  Lock,
  Globe,
  Database,
  Terminal,
  Save,
  RefreshCw,
  Cpu
} from "lucide-react";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Switch } from "@/components/ui/switch";
import { Slider } from "@/components/ui/slider";
import { Label } from "@/components/ui/label";
import { useState } from "react";
import { cn } from "@/lib/utils";

export function ScanConfiguration() {
  const [intensity, setIntensity] = useState([70]);

  return (
    <Card className="bg-[#0B0F0C]/80 backdrop-blur-xl border-primary/20 shadow-[0_0_50px_rgba(0,255,136,0.05)] overflow-hidden">
      <CardHeader className="flex flex-row items-center justify-between pb-4 border-b border-white/5 bg-black/20">
        <div className="flex items-center gap-3">
          <div className="p-1.5 rounded-lg bg-primary/10 border border-primary/20">
            <Sliders className="w-4 h-4 text-primary" />
          </div>
          <div>
            <CardTitle className="text-sm font-bold uppercase tracking-widest text-foreground">Advanced Configuration</CardTitle>
            <p className="text-[10px] text-muted-foreground uppercase tracking-widest font-black opacity-50">Precision Targeting Profiles</p>
          </div>
        </div>
        <div className="flex items-center gap-2">
            <Button variant="ghost" size="sm" className="h-7 text-[10px] uppercase tracking-widest font-black text-muted-foreground hover:text-primary">
                RESTORE DEFAULTS
            </Button>
        </div>
      </CardHeader>
      
      <CardContent className="p-5 space-y-6">
        {/* Intensity Slider */}
        <div className="space-y-4">
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

        {/* Feature Toggles */}
        <div className="grid grid-cols-1 md:grid-cols-2 gap-x-8 gap-y-4">
            <div className="flex items-center justify-between group">
                <div className="space-y-0.5">
                    <Label className="text-[11px] font-bold text-foreground/90 group-hover:text-primary transition-colors">Neural Payload Mutation</Label>
                    <p className="text-[9px] text-muted-foreground leading-tight">AI-generated WAF bypass variants</p>
                </div>
                <Switch defaultChecked className="data-[state=checked]:bg-primary" />
            </div>
            
            <div className="flex items-center justify-between group">
                <div className="space-y-0.5">
                    <Label className="text-[11px] font-bold text-foreground/90 group-hover:text-primary transition-colors">Cross-Domain Correlation</Label>
                    <p className="text-[9px] text-muted-foreground leading-tight">Map attack chains across subdomains</p>
                </div>
                <Switch defaultChecked className="data-[state=checked]:bg-primary" />
            </div>

            <div className="flex items-center justify-between group">
                <div className="space-y-0.5">
                    <Label className="text-[11px] font-bold text-foreground/90 group-hover:text-primary transition-colors">Zero-Knowledge Discovery</Label>
                    <p className="text-[9px] text-muted-foreground leading-tight">Autonomous endpoint brute-forcing</p>
                </div>
                <Switch className="data-[state=checked]:bg-primary" />
            </div>

            <div className="flex items-center justify-between group">
                <div className="space-y-0.5">
                    <Label className="text-[11px] font-bold text-foreground/90 group-hover:text-primary transition-colors">Safe-Exploit Mode</Label>
                    <p className="text-[9px] text-muted-foreground leading-tight">Prevent destructive payload execution</p>
                </div>
                <Switch defaultChecked className="data-[state=checked]:bg-primary" />
            </div>
        </div>

        <div className="pt-4 border-t border-white/5 flex items-center justify-between">
            <div className="flex items-center gap-3">
                <Shield className="w-4 h-4 text-primary opacity-50" />
                <span className="text-[10px] text-muted-foreground italic">Configuration synced with Neo Intelligence Layer v5.2</span>
            </div>
            <Button size="sm" className="bg-primary/10 border border-primary/30 text-primary hover:bg-primary/20 text-xs font-bold gap-2">
                <Save className="w-3 h-3" />
                Apply Settings
            </Button>
        </div>
      </CardContent>
    </Card>
  );
}
