"use client";

import React from "react";
import { motion } from "framer-motion";
import { Target, AlertCircle, Shield, Zap } from "lucide-react";
import { GlowCard } from "@/components/ui/glow-card";
import { cn } from "@/lib/utils";

interface MetricCardProps {
    label: string;
    value: string | number;
    subtext: string;
    icon: React.ElementType;
    iconColorClass: string;
    delay?: number;
}

function MetricCard({ label, value, subtext, icon: Icon, iconColorClass, delay = 0 }: MetricCardProps) {
    return (
        <motion.div
            initial={{ opacity: 0, scale: 0.95 }}
            animate={{ opacity: 1, scale: 1 }}
            transition={{ delay }}
            className="h-full"
        >
            <GlowCard
                className="p-0 border-border h-full"
                glowColor="rgba(var(--primary), 0.1)"
            >
                <div className="flex items-start justify-between">
                    <div className="space-y-1">
                        <p className="text-[9px] uppercase tracking-[0.3em] text-muted-foreground font-black">
                            {label}
                        </p>
                        <h3 className="text-3xl font-black text-foreground font-mono tracking-tighter">
                            {value}
                        </h3>
                        <p className="text-[10px] uppercase font-bold text-muted-foreground tracking-widest mt-2">
                            {subtext}
                        </p>
                    </div>
                    <div
                        className="p-2.5 rounded-xl bg-secondary border border-border/50 shadow-inner"
                    >
                        <Icon className={cn("w-5 h-5", iconColorClass)} />
                    </div>
                </div>
            </GlowCard>
        </motion.div>
    );
}

interface MetricsRowProps {
    assetsAnalyzed?: number;
    issuesDetected?: number;
    riskScore?: number;
    scanCoverage?: number;
    /** Total payloads fired across all modules */
    payloadsFired?: number;
    /** Endpoints discovered during scan */
    endpointsCount?: number;
}

export function MetricsRow({
    assetsAnalyzed = 0,
    issuesDetected = 0,
    riskScore = 100,
    scanCoverage = 0,
    payloadsFired = 0,
    endpointsCount = 0,
}: MetricsRowProps) {
    return (
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4 w-full">
            <MetricCard
                label="Assets Analyzed"
                value={assetsAnalyzed.toLocaleString()}
                subtext={endpointsCount > 0 ? `${endpointsCount} endpoints mapped` : "Telemetry active"}
                icon={Target}
                iconColorClass="text-primary"
                delay={0.1}
            />
            <MetricCard
                label="Issues Detected"
                value={issuesDetected}
                subtext="Total findings"
                icon={AlertCircle}
                iconColorClass="text-destructive"
                delay={0.2}
            />
            <MetricCard
                label="Risk Factor"
                value={riskScore.toFixed(0)}
                subtext={riskScore > 70 ? "SECURE STATUS" : "AT RISK"}
                icon={Shield}
                iconColorClass={riskScore > 70 ? "text-primary" : riskScore > 40 ? "text-amber-500" : "text-destructive"}
                delay={0.3}
            />
            <MetricCard
                label="Intelligence"
                value={payloadsFired > 0 ? payloadsFired.toLocaleString() : `${scanCoverage.toFixed(0)}%`}
                subtext={payloadsFired > 0 ? "Payloads fired" : "Module integrity"}
                icon={Zap}
                iconColorClass="text-blue-500"
                delay={0.4}
            />
        </div>
    );
}
