"use client";

import React from "react";
import { motion } from "framer-motion";
import { cn } from "@/lib/utils";
import { Scan, AlertTriangle, History, Terminal, Atom } from "lucide-react";

interface NavigationTabsProps {
    activeTab: string;
    onTabChange: (tab: string) => void;
}

export function NavigationTabs({ activeTab, onTabChange }: NavigationTabsProps) {
    const tabs = [
        { id: "scanner", label: "Scanner", icon: Scan },
        { id: "findings", label: "Findings", icon: AlertTriangle },
        { id: "verification", label: "Verification", icon: Terminal },
        { id: "history", label: "History", icon: History },
    ];

    return (
        <div className="flex items-center gap-1.5 p-1 bg-secondary border border-border rounded-full backdrop-blur-xl w-fit">
            {tabs.map((tab) => {
                const Icon = tab.icon;
                const isActive = activeTab === tab.id;

                return (
                    <button
                        key={tab.id}
                        onClick={() => onTabChange(tab.id)}
                        className={cn(
                            "relative flex items-center gap-2 px-6 py-2 rounded-full text-sm font-medium transition-all duration-500",
                            isActive ? "text-primary" : "text-muted-foreground hover:text-foreground"
                        )}
                    >
                        {isActive && (
                            <motion.div
                                layoutId="activeTabScanner"
                                className="absolute inset-0 bg-primary/10 border border-primary/20 rounded-full"
                                transition={{ type: "spring", bounce: 0.2, duration: 0.6 }}
                            />
                        )}
                        <Icon className={cn("w-3.5 h-3.5 relative z-10", isActive && "drop-shadow-[0_0_8px_rgba(var(--primary),0.6)]")} />
                        <span className="relative z-10 uppercase tracking-[0.2em] text-[10px] font-black">{tab.label}</span>
                    </button>
                );
            })}
        </div>
    );
}
