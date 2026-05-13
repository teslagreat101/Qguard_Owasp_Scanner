"use client";

import React from "react";
import { cn } from "@/lib/utils";
import { motion } from "framer-motion";
import { User, Bot, Clock } from "lucide-react";

interface ChatMessageProps {
    role: "user" | "assistant";
    content: string;
    timestamp: string;
}

export function ChatMessage({ role, content, timestamp }: ChatMessageProps) {
    const isAssistant = role === "assistant";

    // Simple formatter to highlight severity and CVEs
    const formatContent = (text: string) => {
        return text.split(/([A-Z]+-20\d{2}-\d+)|(CRITICAL|HIGH|MEDIUM|LOW)/g).map((part, i) => {
            if (!part) return null;
            if (part.match(/[A-Z]+-20\d{2}-\d+/)) {
                return <span key={i} className="text-blue-500 font-mono font-bold bg-blue-500/10 px-1 rounded">{part}</span>;
            }
            if (["CRITICAL", "HIGH", "MEDIUM", "LOW"].includes(part)) {
                const colors = {
                    CRITICAL: "text-red-500 bg-red-500/10",
                    HIGH: "text-orange-500 bg-orange-500/10",
                    MEDIUM: "text-amber-500 bg-amber-500/10",
                    LOW: "text-blue-500 bg-blue-500/10",
                };
                return <span key={i} className={cn("font-bold px-1 rounded text-[10px]", colors[part as keyof typeof colors])}>{part}</span>;
            }
            return part;
        });
    };

    return (
        <motion.div
            initial={{ opacity: 0, y: 10, scale: 0.98 }}
            animate={{ opacity: 1, y: 0, scale: 1 }}
            className={cn(
                "flex w-full gap-3 mb-6",
                isAssistant ? "justify-start" : "justify-end"
            )}
        >
            {isAssistant && (
                <div className="w-8 h-8 rounded-lg bg-primary/10 border border-primary/20 flex items-center justify-center shrink-0">
                    <Bot className="w-4 h-4 text-primary" />
                </div>
            )}

            <div className={cn(
                "max-w-[80%] space-y-2",
                !isAssistant && "flex flex-col items-end"
            )}>
                <div className={cn(
                    "px-4 py-3 rounded-2xl text-sm leading-relaxed",
                    isAssistant
                        ? "bg-secondary border border-border text-foreground rounded-tl-none"
                        : "bg-primary/10 border border-primary/20 text-foreground rounded-tr-none"
                )}>
                    <div className="whitespace-pre-wrap">
                        {isAssistant ? formatContent(content) : content}
                    </div>
                </div>

                <div className="flex items-center gap-1.5 px-1">
                    <Clock className="w-3 h-3 text-muted-foreground" />
                    <span className="text-[10px] text-muted-foreground font-mono uppercase tracking-tighter">{timestamp}</span>
                </div>
            </div>

            {!isAssistant && (
                <div className="w-8 h-8 rounded-lg bg-secondary border border-border flex items-center justify-center shrink-0">
                    <User className="w-4 h-4 text-muted-foreground" />
                </div>
            )}
        </motion.div>
    );
}
