"use client";

import { useState, useMemo } from "react";
import {
    Bot,
    ChevronDown,
    ChevronUp,
    Trash2,
    Monitor,
    Layout,
    Code,
    Zap,
    Target,
    TrendingUp,
    AlertTriangle,
} from "lucide-react";
import { useAICopilot } from "@/lib/hooks";
import { cn } from "@/lib/utils";
import { ChatWindow } from "./ChatWindow";
import { AIInsightSidebar } from "./AIInsightSidebar";
import { QuickActionBar } from "./QuickActionBar";
import { ChatInput } from "./ChatInput";
import { GlowCard } from "@/components/ui/glow-card";

interface AISecurityPanelProps {
    findings?: any[];
    aiDecision?: any;
    enterpriseTelemetry?: any;
    riskData?: {
        old_score: number;
        new_score: number;
        confidence: string;
        risk_level: string;
        trigger: string;
    } | null;
    payloadsExecuted?: Array<{
        module: string;
        total_payloads_fired: number;
        mutations_generated: number;
        findings_triggered: number;
    }>;
}

export function AISecurityPanel({
    findings = [],
    aiDecision,
    enterpriseTelemetry,
    riskData,
    payloadsExecuted = [],
}: AISecurityPanelProps) {
    const [isCollapsed, setIsCollapsed] = useState(false);
    const { messages, isThinking, sendMessage, clearChat } = useAICopilot();
    const [outputMode, setOutputMode] = useState("Technical");

    // Compute real telemetry stats
    const telemetryStats = useMemo(() => {
        const totalPayloadsFired = payloadsExecuted.reduce((sum, p) => sum + p.total_payloads_fired, 0);
        const totalMutations = payloadsExecuted.reduce((sum, p) => sum + p.mutations_generated, 0);
        const totalHits = payloadsExecuted.reduce((sum, p) => sum + p.findings_triggered, 0);
        return { totalPayloadsFired, totalMutations, totalHits };
    }, [payloadsExecuted]);

    const severitySummary = useMemo(() => ({
        critical: findings.filter(f => f.severity === "critical").length,
        high: findings.filter(f => f.severity === "high").length,
        medium: findings.filter(f => f.severity === "medium").length,
        low: findings.filter(f => f.severity === "low").length,
    }), [findings]);

    const handleSendMessage = (text: string) => {
        const findingContext = findings.length > 0 ? {
            mode: outputMode,
            scan_findings: findings.slice(0, 20).map(f => ({
                title: f.title,
                severity: f.severity,
                file: f.file,
                cwe: f.cwe,
                owasp: f.owasp,
                description: f.description,
                remediation: f.remediation,
            })),
            total_findings: findings.length,
            severity_summary: severitySummary,
            ai_decision: aiDecision ?? null,
            enterprise_engines: enterpriseTelemetry?.engines_available ?? [],
            total_payloads_loaded: enterpriseTelemetry?.total_payloads ?? 0,
            risk_data: riskData ?? null,
        } : { mode: outputMode };
        sendMessage(text, findingContext);
    };

    return (
        <div className="w-full mt-8">
            <GlowCard
                initial={{ opacity: 0, y: 20 }}
                whileInView={{ opacity: 1, y: 0 }}
                viewport={{ once: true }}
                glowColor="rgba(var(--primary), 0.08)"
                className="p-0 border-primary/15"
            >
                {/* Header */}
                <div className="flex items-center justify-between p-5 border-b border-border bg-primary/[0.02]">
                    <div className="flex items-center gap-4">
                        <div className="relative">
                            <div className="w-10 h-10 rounded-xl bg-primary/10 border border-primary/20 flex items-center justify-center">
                                <Bot className="w-5 h-5 text-primary" />
                            </div>
                            <div className="absolute -bottom-0.5 -right-0.5 w-3 h-3 rounded-full bg-background border border-primary/30 flex items-center justify-center">
                                <div className="w-1.5 h-1.5 rounded-full bg-primary animate-pulse" />
                            </div>
                        </div>

                        <div>
                            <h2 className="text-base font-bold text-foreground uppercase tracking-tight flex items-center gap-2">
                                AI Security <span className="text-primary">Co-Pilot</span>
                            </h2>
                            <p className="text-[10px] text-muted-foreground font-medium uppercase tracking-wider">
                                {aiDecision?.rationale
                                    ? String(aiDecision.rationale).slice(0, 80) + (String(aiDecision.rationale).length > 80 ? "…" : "")
                                    : "Contextual analysis & remediation guidance"
                                }
                            </p>
                        </div>
                    </div>

                    {/* Telemetry Badges + Controls */}
                    <div className="flex items-center gap-3">
                        {/* Live telemetry chips */}
                        <div className="hidden lg:flex items-center gap-2">
                            {enterpriseTelemetry && (
                                <div className="flex items-center gap-1 text-[9px] font-bold text-muted-foreground bg-secondary border border-border rounded-md px-2 py-1">
                                    <Zap className="w-3 h-3 text-amber-500" />
                                    <span>{enterpriseTelemetry.total_payloads} sigs</span>
                                </div>
                            )}
                            {telemetryStats.totalPayloadsFired > 0 && (
                                <div className="flex items-center gap-1 text-[9px] font-bold text-muted-foreground bg-secondary border border-border rounded-md px-2 py-1">
                                    <Target className="w-3 h-3 text-blue-400" />
                                    <span>{telemetryStats.totalPayloadsFired} fired</span>
                                </div>
                            )}
                            {riskData && (
                                <div className={cn(
                                    "flex items-center gap-1 text-[9px] font-bold bg-secondary border rounded-md px-2 py-1",
                                    riskData.risk_level === "CRITICAL" ? "text-red-400 border-red-500/20" :
                                        riskData.risk_level === "HIGH" ? "text-orange-400 border-orange-500/20" :
                                            "text-muted-foreground border-border"
                                )}>
                                    <TrendingUp className="w-3 h-3" />
                                    <span>Risk {riskData.new_score}/100</span>
                                </div>
                            )}
                        </div>

                        {/* Output mode toggle */}
                        <div className="flex items-center gap-1 bg-secondary border border-border rounded-lg p-0.5">
                            {[
                                { id: "Technical", icon: Code },
                                { id: "Executive", icon: Layout },
                                { id: "Developer", icon: Monitor }
                            ].map((mode) => (
                                <button
                                    key={mode.id}
                                    type="button"
                                    onClick={() => setOutputMode(mode.id)}
                                    className={cn(
                                        "flex items-center gap-1.5 px-2.5 py-1 rounded-md text-[9px] font-bold uppercase tracking-wider transition-colors",
                                        outputMode === mode.id ? "bg-primary/10 text-primary" : "text-muted-foreground hover:text-foreground"
                                    )}
                                >
                                    <mode.icon className="w-3 h-3" />
                                    {mode.id}
                                </button>
                            ))}
                        </div>

                        <div className="h-6 w-px bg-border" />

                        <button type="button" onClick={clearChat} className="p-1.5 text-muted-foreground hover:text-red-400 transition-colors" title="Clear chat">
                            <Trash2 className="w-3.5 h-3.5" />
                        </button>
                        <button type="button" onClick={() => setIsCollapsed(!isCollapsed)} className="p-1.5 text-muted-foreground hover:text-foreground transition-colors">
                            {isCollapsed ? <ChevronDown className="w-4 h-4" /> : <ChevronUp className="w-4 h-4" />}
                        </button>
                    </div>
                </div>

                {/* AI Decision Banner — shows when AI has a real-time recommendation */}
                {!isCollapsed && aiDecision?.next_action && (
                    <div className="px-5 py-2.5 bg-primary/[0.03] border-b border-border flex items-center gap-3">
                        <AlertTriangle className="w-4 h-4 text-amber-500 shrink-0" />
                        <div className="flex-1 min-w-0">
                            <p className="text-[10px] font-bold text-muted-foreground uppercase tracking-wider">AI Recommendation</p>
                            <p className="text-[11px] text-muted-foreground truncate">
                                {aiDecision.next_action}
                                {aiDecision.confidence != null && (
                                    <span className="ml-2 text-muted-foreground">({(aiDecision.confidence * 100).toFixed(0)}% confidence)</span>
                                )}
                            </p>
                        </div>
                        {aiDecision.priority && (
                            <span className={cn(
                                "text-[9px] font-bold uppercase px-2 py-0.5 rounded border shrink-0",
                                aiDecision.priority === "critical" ? "text-red-400 bg-red-500/10 border-red-500/20" :
                                    aiDecision.priority === "high" ? "text-orange-400 bg-orange-500/10 border-orange-500/20" :
                                        "text-muted-foreground bg-muted/10 border-border/20"
                            )}>
                                {aiDecision.priority}
                            </span>
                        )}
                    </div>
                )}

                {/* Main Interface */}
                {!isCollapsed && (
                    <div className="flex h-[550px] animate-in slide-in-from-top-2 duration-500">
                        {/* LEFT: Chat Area (70%) */}
                        <div className="w-[70%] flex flex-col p-5 border-r border-border">
                            <QuickActionBar onAction={handleSendMessage} />
                            <ChatWindow messages={messages} isThinking={isThinking} />
                            <ChatInput onSend={handleSendMessage} isProcessing={isThinking} />
                        </div>

                        {/* RIGHT: Insight Sidebar (30%) */}
                        <div className="w-[30%] p-5 bg-secondary/10">
                            <AIInsightSidebar findings={findings} onInsightInteract={handleSendMessage} />
                        </div>
                    </div>
                )}
            </GlowCard>
        </div>
    );
}
