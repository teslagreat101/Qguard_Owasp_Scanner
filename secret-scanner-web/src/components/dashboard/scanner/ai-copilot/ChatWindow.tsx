"use client";

import React, { useRef, useEffect } from "react";
import { ChatMessage } from "./ChatMessage";
import { Loader2 } from "lucide-react";

interface Message {
    id: string;
    role: "user" | "assistant";
    content: string;
    timestamp: string;
}

interface ChatWindowProps {
    messages: Message[];
    isThinking: boolean;
}

export function ChatWindow({ messages, isThinking }: ChatWindowProps) {
    const scrollRef = useRef<HTMLDivElement>(null);

    useEffect(() => {
        if (scrollRef.current) {
            scrollRef.current.scrollTop = scrollRef.current.scrollHeight;
        }
    }, [messages, isThinking]);

    return (
        <div
            ref={scrollRef}
            className="flex-1 overflow-y-auto pr-4 custom-scrollbar space-y-4"
        >
            {messages.length === 0 && (
                <div className="h-full flex flex-col items-center justify-center text-center p-8 space-y-4">
                    <div className="w-16 h-16 rounded-full bg-primary/5 border border-primary/10 flex items-center justify-center animate-pulse">
                        <div className="w-8 h-8 rounded-full bg-primary/20 flex items-center justify-center">
                            <div className="w-3 h-3 rounded-full bg-primary shadow-[0_0_10px_rgba(var(--primary),0.8)]" />
                        </div>
                    </div>
                    <div className="space-y-1">
                        <h3 className="text-sm font-black text-foreground uppercase tracking-widest italic">Co-Pilot Standby</h3>
                        <p className="text-xs text-muted-foreground max-w-xs leading-relaxed font-medium">
                            Awaiting telemetry data or user inquiry. Pulse established with scanner neural core.
                        </p>
                    </div>
                </div>
            )}

            {messages.map((msg) => (
                <ChatMessage
                    key={msg.id}
                    role={msg.role}
                    content={msg.content}
                    timestamp={msg.timestamp}
                />
            ))}

            {isThinking && (
                <div className="flex items-center gap-3 animate-in fade-in duration-500">
                    <div className="w-8 h-8 rounded-lg bg-primary/10 border border-primary/20 flex items-center justify-center shrink-0">
                        <Loader2 className="w-4 h-4 text-primary animate-spin" />
                    </div>
                    <div className="flex gap-1 items-center">
                        <div className="w-1.5 h-1.5 rounded-full bg-primary/40 animate-bounce [animation-delay:-0.3s]" />
                        <div className="w-1.5 h-1.5 rounded-full bg-primary/40 animate-bounce [animation-delay:-0.15s]" />
                        <div className="w-1.5 h-1.5 rounded-full bg-primary/40 animate-bounce" />
                    </div>
                </div>
            )}
        </div>
    );
}
