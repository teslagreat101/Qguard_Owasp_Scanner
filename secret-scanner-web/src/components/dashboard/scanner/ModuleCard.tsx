"use client";

import React from "react";
import { cn } from "@/lib/utils";
import { Check } from "lucide-react";
import { motion } from "framer-motion";

interface ModuleCardProps {
    id: string;
    title: string;
    patternCount: number;
    description?: string;
    isSelected: boolean;
    onToggle: (id: string) => void;
    disabled?: boolean;
}

export function ModuleCard({ id, title, patternCount, description, isSelected, onToggle, disabled }: ModuleCardProps) {
    return (
        <motion.button
            whileHover={!disabled ? { scale: 1.02, translateY: -2 } : {}}
            whileTap={!disabled ? { scale: 0.98 } : {}}
            onClick={() => !disabled && onToggle(id)}
            disabled={disabled}
            className={cn(
                "group relative flex items-center justify-between p-4 rounded-xl border transition-all duration-300 text-left",
                isSelected
                    ? "bg-primary/10 border-primary/30 shadow-sm dark:shadow-[0_0_20px_rgba(var(--primary),0.1)]"
                    : "bg-background border-border hover:border-primary/20",
                disabled && "opacity-50 cursor-not-allowed grayscale"
            )}
        >
            <div className="flex-1 mr-4">
                <h4 className={cn(
                    "text-sm font-semibold transition-colors duration-300",
                    isSelected ? "text-primary" : "text-muted-foreground group-hover:text-foreground"
                )}>
                    {title}
                </h4>
                {description && (
                    <p className="text-[10px] text-muted-foreground leading-tight mt-0.5 line-clamp-1 group-hover:line-clamp-none transition-all duration-300">
                        {description}
                    </p>
                )}
                <p className="text-[10px] text-muted-foreground uppercase tracking-tighter mt-1">
                    {patternCount} Active Patterns
                </p>
            </div>

            <div className={cn(
                "w-6 h-6 rounded-full border flex items-center justify-center transition-all duration-300",
                isSelected
                    ? "bg-primary border-primary dark:shadow-[0_0_10px_rgba(var(--primary),0.5)]"
                    : "border-border bg-transparent group-hover:border-primary/50"
            )}>
                {isSelected && (
                    <motion.div
                        initial={{ scale: 0 }}
                        animate={{ scale: 1 }}
                        transition={{ type: "spring", stiffness: 300, damping: 20 }}
                    >
                        <Check className="w-4 h-4 text-primary-foreground stroke-[3]" />
                    </motion.div>
                )}
            </div>

            {isSelected && (
                <div className="absolute inset-0 rounded-xl bg-gradient-to-br from-primary/5 to-transparent pointer-events-none" />
            )}
        </motion.button>
    );
}
