"use client";

import React, { useState, useRef, useEffect } from "react";
import { Send, Paperclip, Loader2, Sparkles } from "lucide-react";
import { cn } from "@/lib/utils";

interface ChatInputProps {
    onSend: (message: string) => void;
    isProcessing: boolean;
}

export function ChatInput({ onSend, isProcessing }: ChatInputProps) {
    const [value, setValue] = useState("");
    const textareaRef = useRef<HTMLTextAreaElement>(null);

    const handleKeyDown = (e: React.KeyboardEvent) => {
        if (e.key === "Enter" && !e.shiftKey) {
            e.preventDefault();
            handleSend();
        }
    };

    const handleSend = () => {
        if (value.trim() && !isProcessing) {
            onSend(value);
            setValue("");
        }
    };

    useEffect(() => {
        if (textareaRef.current) {
            textareaRef.current.style.height = "auto";
            textareaRef.current.style.height = `${Math.min(textareaRef.current.scrollHeight, 120)}px`;
        }
    }, [value]);

    return (
        <div className="relative pt-4 border-t border-border bg-background/80 backdrop-blur-md">
            <div className="flex items-center gap-2 mb-3 px-1">
                <Sparkles className="w-3 h-3 text-primary" />
                <span className="text-[9px] font-bold text-muted-foreground uppercase tracking-widest">
                    Context Aware: Active Scan Telemetry
                </span>
            </div>

            <div className="relative group">
                <textarea
                    ref={textareaRef}
                    value={value}
                    onChange={(e) => setValue(e.target.value)}
                    onKeyDown={handleKeyDown}
                    placeholder="Ask AI for vulnerability analysis or remediation steps..."
                    className={cn(
                        "w-full bg-secondary border border-border rounded-xl py-3 pl-4 pr-24 text-sm text-foreground",
                        "placeholder:text-muted-foreground focus:outline-none focus:border-primary/30 focus:bg-secondary/70 transition-all",
                        "resize-none min-h-[44px] overflow-hidden"
                    )}
                    rows={1}
                />

                <div className="absolute right-2 bottom-1.5 flex items-center gap-1">
                    <button className="p-2 text-muted-foreground hover:text-foreground transition-colors" title="Attach Finding">
                        <Paperclip className="w-4 h-4" />
                    </button>

                    <button
                        onClick={handleSend}
                        disabled={!value.trim() || isProcessing}
                        className={cn(
                            "p-2 rounded-lg transition-all",
                            value.trim() && !isProcessing
                                ? "bg-primary text-primary-foreground shadow-[0_0_15px_rgba(var(--primary),0.3)]"
                                : "bg-secondary text-muted-foreground cursor-not-allowed"
                        )}
                    >
                        {isProcessing ? <Loader2 className="w-4 h-4 animate-spin" /> : <Send className="w-4 h-4" />}
                    </button>
                </div>
            </div>
        </div>
    );
}
