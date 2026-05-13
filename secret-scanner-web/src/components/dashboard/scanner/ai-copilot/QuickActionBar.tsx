"use client";

import React from "react";
import { Search, ShieldCheck, FileText, Zap, HelpCircle, Wrench } from "lucide-react";
import { cn } from "@/lib/utils";

interface QuickActionBarProps {
    onAction: (prompt: string) => void;
}

const actions = [
    { icon: Search, label: "Analyze Findings", prompt: "Perform a deep analysis of all findings detected in the current scan." },
    { icon: ShieldCheck, label: "Prioritize Risks", prompt: "Identify and prioritize the most critical risks that require immediate attention." },
    { icon: Wrench, label: "Remediation Plan", prompt: "Generate a step-by-step remediation plan for the identified vulnerabilities." },
    { icon: FileText, label: "Executive Summary", prompt: "Create a high-level executive summary of the security posture based on this scan." },
    { icon: Zap, label: "Explain Issue", prompt: "Explain the selected security issues and their potential impact on the infrastructure." },
    { icon: HelpCircle, label: "Patch Steps", prompt: "Suggest specific patch implementations for the detected misconfigurations." },
];

export function QuickActionBar({ onAction }: QuickActionBarProps) {
    return (
        <div className="flex flex-wrap gap-2 mb-4">
            {actions.map((action) => (
                <button
                    key={action.label}
                    onClick={() => onAction(action.prompt)}
                    className={cn(
                        "flex items-center gap-2 px-3 py-1.5 rounded-full border border-primary/10 bg-primary/5",
                        "text-[10px] font-bold text-primary uppercase tracking-wider hover:bg-primary/15 hover:border-primary/30 transition-all"
                    )}
                >
                    <action.icon className="w-3 h-3" />
                    {action.label}
                </button>
            ))}
        </div>
    );
}
