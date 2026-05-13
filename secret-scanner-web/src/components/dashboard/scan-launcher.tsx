"use client";

import { useState, useCallback } from "react";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Sparkles, Upload, FileCode, Folder, Activity } from "lucide-react";
import { toast } from "sonner";
import { GlowCard } from "@/components/ui/glow-card";
import { cn } from "@/lib/utils";

interface ScanLauncherProps {
    isScanning: boolean;
    scanStatus: any;
    onStartScan: (target: string, modules: string[], scanType: string, profile: string) => void;
    onCancelScan: () => void;
    modules: { key: string; name: string; owasp?: string; patterns?: number; pattern_count?: number }[];
    profiles: { key: string; name: string; description?: string }[];
}

export function ScanLauncher({ isScanning, scanStatus, onStartScan, onCancelScan, modules, profiles }: ScanLauncherProps) {
    const [scanTarget, setScanTarget] = useState("");
    const [selectedModules, setSelectedModules] = useState<string[]>(["misconfig", "injection", "frontend_js", "endpoint"]);
    const [scanTab, setScanTab] = useState("repo");
    const [selectedProfile, setSelectedProfile] = useState("full");

    const toggleModule = useCallback((key: string) => {
        setSelectedModules((prev) => prev.includes(key) ? prev.filter((m) => m !== key) : [...prev, key]);
    }, []);

    const handleStart = useCallback(() => {
        if (!scanTarget.trim()) { toast.error("Enter a target path"); return; }
        if (selectedModules.length === 0) { toast.error("Select at least one module"); return; }
        const isDir = scanTab === "repo";
        onStartScan(scanTarget.trim(), selectedModules, isDir ? "directory" : "code", selectedProfile);
    }, [scanTarget, selectedModules, scanTab, selectedProfile, onStartScan]);

    const totalPatterns = modules.reduce(
        (acc, m) => selectedModules.includes(m.key) ? acc + (m.pattern_count || m.patterns || 0) : acc, 0
    );

    return (
        <GlowCard className="p-0 border-white/5 bg-background/40" glowColor="rgba(0, 255, 136, 0.05)">
            <div className="p-8">
                <div className="flex items-center gap-3 mb-8">
                    <div className="p-2 rounded-lg bg-primary/10 border border-primary/20">
                        <Sparkles className="h-5 w-5 text-primary" />
                    </div>
                    <div>
                        <h3 className="text-xl font-black text-foreground uppercase tracking-tighter">Deploy Security Engine</h3>
                        <p className="text-[10px] text-muted-foreground uppercase tracking-widest font-bold mt-0.5">Initialize autonomous vulnerability discovery protocol</p>
                    </div>
                </div>

                <div className="space-y-8">
                    {/* Target Input Tabs */}
                    <Tabs value={scanTab} onValueChange={setScanTab} className="w-full">
                        <TabsList className="grid w-full grid-cols-3 bg-background/40 border border-white/5 p-1 rounded-xl">
                            <TabsTrigger value="repo" className="data-[state=active]:bg-primary/10 data-[state=active]:text-primary uppercase text-[10px] font-black tracking-widest rounded-lg"><Folder className="h-3.5 w-3.5 mr-2" />Directory</TabsTrigger>
                            <TabsTrigger value="upload" className="data-[state=active]:bg-primary/10 data-[state=active]:text-primary uppercase text-[10px] font-black tracking-widest rounded-lg"><Upload className="h-3.5 w-3.5 mr-2" />Upload</TabsTrigger>
                            <TabsTrigger value="paste" className="data-[state=active]:bg-primary/10 data-[state=active]:text-primary uppercase text-[10px] font-black tracking-widest rounded-lg"><FileCode className="h-3.5 w-3.5 mr-2" />Code</TabsTrigger>
                        </TabsList>
                        <TabsContent value="repo" className="pt-4 mt-0">
                            <Input placeholder="E.G., C:/SYSTEM/PROTOCOLS/CORE" value={scanTarget} onChange={(e) => setScanTarget(e.target.value)}
                                className="h-14 bg-background/40 border-white/5 text-muted-foreground focus:border-primary font-mono rounded-xl uppercase placeholder:text-muted-foreground" />
                        </TabsContent>
                        <TabsContent value="upload" className="pt-4 mt-0">
                            <div className="border-2 border-dashed border-white/5 rounded-2xl p-12 text-center hover:border-primary/20 transition-all cursor-pointer bg-background/20 group">
                                <Upload className="h-10 w-10 mx-auto text-muted-foreground group-hover:text-primary mb-4 transition-colors" />
                                <p className="text-[10px] text-muted-foreground uppercase font-black tracking-widest">Transmit Encrypted Assets</p>
                            </div>
                        </TabsContent>
                        <TabsContent value="paste" className="pt-4 mt-0">
                            <textarea className="w-full h-40 bg-background/40 border border-white/5 rounded-xl p-6 font-mono text-sm text-muted-foreground focus:ring-1 focus:ring-[#00FF88]/30 outline-none placeholder:text-muted-foreground transition-all"
                                placeholder="// INPUT RAW INTEL HERE..." value={scanTarget} onChange={(e) => setScanTarget(e.target.value)} />
                        </TabsContent>
                    </Tabs>

                    <div className="grid md:grid-cols-12 gap-8 items-end">
                        <div className="md:col-span-4">
                            <label className="text-[10px] uppercase tracking-[0.2em] font-black text-muted-foreground mb-3 block">Operation Profile</label>
                            <Select value={selectedProfile} onValueChange={setSelectedProfile}>
                                <SelectTrigger className="h-12 bg-background/40 border-white/5 text-muted-foreground rounded-xl font-bold uppercase text-[10px] tracking-widest">
                                    <SelectValue />
                                </SelectTrigger>
                                <SelectContent className="bg-[#0A0F0C] border-white/10">
                                    {profiles.map((p) => (
                                        <SelectItem key={p.key} value={p.key} className="text-muted-foreground focus:bg-primary/10 focus:text-primary uppercase text-[10px] font-black tracking-widest">{p.name}</SelectItem>
                                    ))}
                                </SelectContent>
                            </Select>
                        </div>
                        <div className="md:col-span-8">
                            <div className="flex items-center justify-between p-4 rounded-xl bg-background/60 border border-white/5 shadow-inner">
                                <div className="flex items-center gap-4">
                                    <div className={cn(
                                        "p-2 rounded-lg",
                                        isScanning ? "bg-primary/20 animate-pulse" : "bg-white/5"
                                    )}>
                                        <Activity className={cn("h-5 w-5", isScanning ? "text-primary" : "text-muted-foreground")} />
                                    </div>
                                    <div>
                                        <p className="text-[10px] uppercase font-black text-foreground tracking-widest">{isScanning ? "SCAN IN PROGRESS" : "SYSTEM STANDBY"}</p>
                                        <p className="text-[11px] text-muted-foreground font-mono mt-0.5">{isScanning ? `MODULE ${scanStatus?.modules_completed || 0}/${scanStatus?.modules_total || selectedModules.length}` : `${totalPatterns} ACTIVE PATTERNS`}</p>
                                    </div>
                                </div>
                                <div className="flex gap-2">
                                    {isScanning && (
                                        <Button variant="ghost" onClick={onCancelScan} className="h-10 text-red-500 hover:bg-red-500/10 uppercase text-[10px] font-black tracking-widest px-4">
                                            TERMINATE
                                        </Button>
                                    )}
                                    <Button onClick={handleStart} disabled={isScanning || !scanTarget.trim()}
                                        className="h-10 bg-primary text-black font-black uppercase text-[10px] tracking-widest px-6 hover:shadow-[0_0_20px_rgba(0,255,136,0.3)] disabled:opacity-30 transition-all">
                                        {isScanning ? `${scanStatus?.progress || 0}% COMPLETE` : "INITIALIZE SCAN"}
                                    </Button>
                                </div>
                            </div>
                        </div>
                    </div>

                    {/* Module Grid */}
                    <div className="space-y-4">
                        <label className="text-[10px] uppercase tracking-[0.2em] font-black text-muted-foreground block">Intelligence Modules Matrix ({selectedModules.length})</label>
                        <div className="grid grid-cols-2 md:grid-cols-4 lg:grid-cols-6 gap-3">
                            {modules.map((m) => (
                                <button key={m.key}
                                    onClick={() => toggleModule(m.key)}
                                    className={cn(
                                        "flex flex-col items-center justify-center p-4 rounded-xl border transition-all duration-500 text-center gap-1 group",
                                        selectedModules.includes(m.key)
                                            ? "bg-primary/10 border-primary/30 shadow-[0_0_15px_rgba(0,255,136,0.05)]"
                                            : "bg-background/40 border-white/5 hover:border-white/10"
                                    )}>
                                    <p className={cn(
                                        "text-[10px] uppercase font-black tracking-tighter transition-colors",
                                        selectedModules.includes(m.key) ? "text-primary" : "text-muted-foreground group-hover:text-muted-foreground"
                                    )}>{m.name}</p>
                                    <p className="text-[9px] text-muted-foreground font-mono">{m.pattern_count || m.patterns || 0} PTS</p>
                                </button>
                            ))}
                        </div>
                    </div>
                </div>
            </div>
        </GlowCard>
    );
}
