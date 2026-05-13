"use client";

import React from "react";
import { cn } from "@/lib/utils";
import { LucideIcon } from "lucide-react";

interface InsightCardProps {
    icon: LucideIcon;
    title: string;
    value: string | number;
    label: string;
    trend?: string;
    severity?: "critical" | "high" | "medium" | "low";
    onClick?: () => void;
}

export function InsightCard({
    icon: Icon,
    title,
    value,
    label,
    trend,
    severity,
    onClick
}: InsightCardProps) {
    const sevColors = {
        critical: "text-red-500",
        high: "text-orange-500",
        medium: "text-amber-500",
        low: "text-blue-500",
    };

    return (
        <button
            onClick={onClick}
            className={cn(
                "w-full text-left p-3 rounded-xl border border-border bg-secondary/50",
                "hover:bg-secondary hover:border-border transition-all group"
            )}
        >
            <div className="flex items-center justify-between mb-2">
                <div className="p-1.5 rounded-lg bg-secondary border border-border">
                    <Icon className="w-3.5 h-3.5 text-muted-foreground group-hover:text-foreground transition-colors" />
                </div>
                {severity && <div className={cn("text-[9px] font-black uppercase tracking-widest", sevColors[severity])}>{severity}</div>}
            </div>

            <div className="space-y-0.5">
                <p className="text-[10px] font-bold text-muted-foreground uppercase tracking-tighter">{title}</p>
                <div className="flex items-baseline gap-2">
                    <span className="text-lg font-black text-foreground">{value}</span>
                    <span className="text-[10px] text-muted-foreground font-medium uppercase tracking-widest">{label}</span>
                </div>
            </div>

            {trend && (
                <div className="mt-2 pt-2 border-t border-border flex items-center gap-1.5">
                    <div className="w-1.5 h-1.5 rounded-full bg-primary" />
                    <span className="text-[9px] font-mono text-muted-foreground">{trend}</span>
                </div>
            )}
        </button>
    );
}
