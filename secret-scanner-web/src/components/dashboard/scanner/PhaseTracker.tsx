"use client";

import React from "react";
import { GlowCard } from "./GlowCard";
import { cn } from "@/lib/utils";
import { Check, Shield, Crosshair, Scan, ShieldCheck, BarChart3 } from "lucide-react";
import { motion } from "framer-motion";

interface Phase {
    id: string;
    label: string;
    description: string;
    status: "pending" | "active" | "completed";
    icon: React.ReactNode;
}

interface PhaseTrackerProps {
    progress: number;
    activeModule?: string | null;
    modulesCompleted?: number;
    modulesTotal?: number;
    findingsCount?: number;
}

export function PhaseTracker({ progress, activeModule, modulesCompleted = 0, modulesTotal = 0, findingsCount = 0 }: PhaseTrackerProps) {
    const phases: Phase[] = [
        {
            id: "recon",
            label: "Reconnaissance",
            description: "Surface mapping & signature loading",
            status: progress > 20 ? "completed" : progress > 0 ? "active" : "pending",
            icon: <Crosshair className="w-3 h-3" />,
        },
        {
            id: "analysis",
            label: "Vulnerability Analysis",
            description: "Deep injection & logic testing",
            status: progress > 40 ? "completed" : progress > 20 ? "active" : "pending",
            icon: <Scan className="w-3 h-3" />,
        },
        {
            id: "correlation",
            label: "Cross-Module Correlation",
            description: "Finding dedup & chain analysis",
            status: progress > 70 ? "completed" : progress > 40 ? "active" : "pending",
            icon: <Shield className="w-3 h-3" />,
        },
        {
            id: "verification",
            label: "Integrity Verification",
            description: "Exploit validation & confidence scoring",
            status: progress > 90 ? "completed" : progress > 70 ? "active" : "pending",
            icon: <ShieldCheck className="w-3 h-3" />,
        },
        {
            id: "assessment",
            label: "Risk Assessment",
            description: "Final scoring & report generation",
            status: progress === 100 ? "completed" : progress > 90 ? "active" : "pending",
            icon: <BarChart3 className="w-3 h-3" />,
        },
    ];

    const completedCount = phases.filter(p => p.status === "completed").length;

    return (
        <GlowCard className="h-full flex flex-col" glowColor="rgba(var(--primary), 0.05)">
            {/* Header */}
            <div className="mb-4">
                <h3 className="text-[10px] font-bold text-muted-foreground uppercase tracking-[0.2em] mb-1">Workflow Progress</h3>
                <div className="flex items-center gap-3 text-[9px] font-mono text-muted-foreground">
                    <span>{completedCount}/{phases.length} phases</span>
                    {modulesTotal > 0 && <span>{modulesCompleted}/{modulesTotal} modules</span>}
                    {findingsCount > 0 && <span className="text-destructive/70">{findingsCount} findings</span>}
                </div>
            </div>

            {/* Progress Bar */}
            <div className="mb-5">
                <div className="relative h-1.5 w-full bg-secondary rounded-full overflow-hidden border border-border">
                    <motion.div
                        className="absolute top-0 left-0 h-full bg-gradient-to-r from-primary/30 to-primary shadow-[0_0_12px_rgba(var(--primary),0.4)]"
                        initial={{ width: 0 }}
                        animate={{ width: `${progress}%` }}
                        transition={{ duration: 0.5, ease: "easeOut" }}
                    />
                </div>
                <div className="mt-1.5 flex justify-between items-center">
                    <span className="text-[9px] font-mono text-muted-foreground uppercase tracking-wider">
                        {progress === 100 ? "Complete" : progress > 0 ? "Scanning" : "Ready"}
                    </span>
                    <span className="text-[9px] font-mono text-primary font-bold">{progress}%</span>
                </div>
            </div>

            {/* Phases */}
            <div className="flex-1 flex flex-col justify-between py-1">
                {phases.map((phase, idx) => {
                    const isActive = phase.status === "active";
                    const isCompleted = phase.status === "completed";

                    return (
                        <div key={phase.id} className="relative flex items-start gap-3 group">
                            {/* Connector line */}
                            {idx < phases.length - 1 && (
                                <div
                                    className={cn(
                                        "absolute left-[9px] top-[22px] w-px h-[calc(100%-10px)] z-0 transition-colors duration-500",
                                        isCompleted ? "bg-primary/50" : "bg-border"
                                    )}
                                />
                            )}

                            {/* Status Indicator */}
                            <div className="relative z-10 flex items-center justify-center shrink-0 mt-0.5">
                                {isCompleted ? (
                                    <div className="w-[18px] h-[18px] rounded-full bg-primary/20 border border-primary/40 flex items-center justify-center">
                                        <Check className="w-2.5 h-2.5 text-primary stroke-[3]" />
                                    </div>
                                ) : isActive ? (
                                    <div className="w-[18px] h-[18px] rounded-full bg-background border border-primary/60 flex items-center justify-center">
                                        <motion.div
                                            className="w-2 h-2 rounded-full bg-primary"
                                            animate={{ scale: [1, 1.3, 1], opacity: [1, 0.5, 1] }}
                                            transition={{ repeat: Infinity, duration: 1.2 }}
                                        />
                                    </div>
                                ) : (
                                    <div className="w-[18px] h-[18px] rounded-full bg-background border border-border flex items-center justify-center">
                                        <div className="w-1.5 h-1.5 rounded-full bg-border" />
                                    </div>
                                )}
                            </div>

                            {/* Phase Content */}
                            <div className={cn(
                                "flex-1 rounded-lg px-3 py-1.5 transition-all duration-300 border",
                                isActive
                                    ? "bg-primary/5 border-primary/20"
                                    : "bg-transparent border-transparent group-hover:bg-secondary/50"
                            )}>
                                <div className="flex items-center gap-2">
                                    <span className={cn(
                                        "transition-colors duration-300",
                                        isCompleted ? "text-muted-foreground" : isActive ? "text-primary" : "text-muted-foreground/50"
                                    )}>
                                        {phase.icon}
                                    </span>
                                    <span className={cn(
                                        "text-[10px] font-bold uppercase tracking-wider transition-colors duration-300",
                                        isCompleted ? "text-muted-foreground" : isActive ? "text-primary" : "text-muted-foreground/50"
                                    )}>
                                        {phase.label}
                                    </span>
                                </div>
                                <p className={cn(
                                    "text-[8px] font-mono uppercase tracking-wider mt-0.5 transition-colors",
                                    isActive ? "text-primary/70" : "text-muted-foreground/40"
                                )}>
                                    {isActive && activeModule ? activeModule : phase.description}
                                </p>
                            </div>
                        </div>
                    );
                })}
            </div>
        </GlowCard>
    );
}
