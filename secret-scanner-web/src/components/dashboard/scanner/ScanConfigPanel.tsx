"use client";

import React, { useState, useEffect, useMemo } from "react";
import { GlowCard } from "./GlowCard";
import { ModuleCard } from "./ModuleCard";
import { cn } from "@/lib/utils";
import { Code, ChevronDown, Play, ShieldCheck, Loader2, Globe, Square, Pause, Atom } from "lucide-react";
import { motion, AnimatePresence } from "framer-motion";

// ── Module compatibility per scan type ──────────────────────────────────────
// Only show modules that are relevant and functional for each scan type.
const MODULE_COMPATIBILITY: Record<string, string[]> = {
  url: [
    // Phase 6: Quantara HTTP (YAML template engine — full OWASP Top 10)
    "quantara_http",
    // Phase 7: Enterprise Feature Modules (URL execution source)
    "quantara_crawler",   // P1 — BFS recursive crawler, JS endpoint extraction, form discovery
    "quantara_auth",      // P2 — Multi-role auth: form login, JWT, OAuth2, cookie jar, API key
    "quantara_fp_reducer",// P3 — Baseline→Payload→Diff→Reflect→Timing FP reduction pipeline
    "quantara_oast",      // P5 — Out-of-band blind SSRF/XSS/CMDi/XXE via interactsh
    "quantara_chains",    // P8 — Attack chain correlation (SSRF→Cloud, LFI→SQLi, XSS→Admin)
    "quantara_ai",        // P10 — Multi-LLM AI enrichment (Gemini→Claude→GPT)
    "neo_intelligence",   // P9 — Autonomous 5-layer intelligence layer
    // Phase 1: OWASP core modules (HTTP live analysis)
    "misconfig",          // Security headers, info disclosure, HTTP vs HTTPS
    "injection",          // SQL errors, XSS indicators in HTML
    "frontend_js",        // Inline JS secrets, eval, innerHTML
    "endpoint",           // Admin paths, config file refs, API endpoints
    "auth",               // Cookie flags (HttpOnly, Secure, SameSite)
    "access_control",     // IDOR patterns (numeric IDs in URLs)
    "api_security",       // CORS misconfiguration, API endpoint discovery
    "insecure_design",    // CSRF tokens missing from forms
    "sensitive_data",     // Credit cards, SSNs, tokens in response
    "logging",            // Verbose error messages in responses
    "ssrf",               // SSRF indicators
  ],
  code: [
    "misconfig", "injection", "frontend_js", "endpoint", "auth",
    "access_control", "cloud", "api_security", "supply_chain",
    "insecure_design", "integrity", "logging", "exception",
    "sensitive_data", "ssrf", "code_agent", "neo_intelligence",
  ],
};

// Default module selections per strategy × scan type
const STRATEGY_MODULES: Record<string, Record<string, string[]>> = {
  "quick-audit": {
    url: ["quantara_http", "quantara_crawler", "misconfig", "injection", "auth"],
    code: ["injection", "misconfig", "auth"],
  },
  "standard-scan": {
    url: ["quantara_http", "quantara_crawler", "quantara_auth", "quantara_fp_reducer",
      "misconfig", "injection", "frontend_js", "endpoint", "auth", "access_control", "api_security", "ssrf"],
    code: ["injection", "misconfig", "auth", "access_control", "frontend_js",
      "api_security", "supply_chain", "insecure_design", "integrity"],
  },
  "full-assessment": {
    url: MODULE_COMPATIBILITY.url,
    code: MODULE_COMPATIBILITY.code,
  },
  "compliance-check": {
    url: ["auth", "access_control", "misconfig", "insecure_design", "sensitive_data"],
    code: ["auth", "access_control", "integrity", "misconfig", "sensitive_data", "exception"],
  },
};

type SourceType = "url" | "code";

interface ScanConfigPanelProps {
  onStart: (target: string, modules: string[], strategy: string, type: SourceType) => void;
  onCancel: () => void;
  onPause?: () => void;
  isScanning: boolean;
  isPaused?: boolean;
  availableModules: any[];
}

export function ScanConfigPanel({ onStart, onCancel, onPause, isScanning, isPaused, availableModules }: ScanConfigPanelProps) {
  const [sourceType, setSourceType] = useState<SourceType>("url");
  const [targetPath, setTargetPath] = useState("");
  const [selectedStrategy, setSelectedStrategy] = useState("full-assessment");
  const [selectedModules, setSelectedModules] = useState<string[]>([]);
  const [isStrategyOpen, setIsStrategyOpen] = useState(false);

  // Compute compatible modules for this source type
  const compatibleModules = useMemo(() => {
    const allowed = MODULE_COMPATIBILITY[sourceType] || [];
    return availableModules.filter(m => allowed.includes(m.id));
  }, [sourceType, availableModules]);

  // When source type changes: clear target + auto-select modules for current strategy
  useEffect(() => {
    setTargetPath("");
    const strategyMods = STRATEGY_MODULES[selectedStrategy]?.[sourceType] ?? MODULE_COMPATIBILITY[sourceType] ?? [];
    const valid = strategyMods.filter(id => compatibleModules.some(m => m.id === id));
    setSelectedModules(valid);
  }, [sourceType]); // eslint-disable-line react-hooks/exhaustive-deps

  // When strategy changes: update module selection to match
  useEffect(() => {
    const strategyMods = STRATEGY_MODULES[selectedStrategy]?.[sourceType] ?? MODULE_COMPATIBILITY[sourceType] ?? [];
    const valid = strategyMods.filter(id => compatibleModules.some(m => m.id === id));
    setSelectedModules(valid);
  }, [selectedStrategy]); // eslint-disable-line react-hooks/exhaustive-deps

  // Initialise on first mount
  useEffect(() => {
    const mods = STRATEGY_MODULES["full-assessment"]?.url ?? MODULE_COMPATIBILITY.url ?? [];
    const valid = mods.filter(id => availableModules.some(m => m.id === id));
    setSelectedModules(valid);
  }, [availableModules]); // eslint-disable-line react-hooks/exhaustive-deps

  const strategies = [
    { id: "quick-audit", name: "Quick Intelligence Audit" },
    { id: "standard-scan", name: "Standard Security Baseline" },
    { id: "full-assessment", name: "Full Comprehensive Assessment" },
    { id: "compliance-check", name: "Regulatory Compliance Check" },
  ];

  const handleToggleModule = (id: string) => {
    setSelectedModules(prev =>
      prev.includes(id) ? prev.filter(m => m !== id) : [...prev, id]
    );
  };

  const totalPatterns = compatibleModules
    .filter(m => selectedModules.includes(m.id))
    .reduce((acc: number, m: any) => acc + (m.patternCount || 0), 0);

  const sourceTypeLabel: Record<string, string> = {
    url: "URL scan",
    code: "repository / code scan",
  };

  return (
    <GlowCard className="h-full flex flex-col">
      {/* Header */}
      <div className="mb-8">
        <div className="flex items-center gap-3 mb-1">
          <div className="p-2 rounded-lg bg-primary/10">
            <ShieldCheck className="w-5 h-5 text-primary" />
          </div>
          <h2 className="text-xl font-bold text-foreground uppercase tracking-tight">Deploy Security Engine</h2>
        </div>
        <p className="text-sm text-muted-foreground">Configure parameters for security-grade vulnerability detection.</p>
        <div className="mt-4 h-px w-full bg-gradient-to-r from-primary/20 via-transparent to-transparent" />
      </div>

      <div className="space-y-6 flex-1">
        {/* Source Type Selector */}
        <div className="space-y-3">
          <label className="text-[10px] uppercase tracking-[0.2em] text-muted-foreground font-bold ml-1">
            Execution Source
          </label>
          <div className="grid grid-cols-2 gap-1 p-1 bg-background rounded-xl border border-border">
            {([
              { id: "url", label: "URL Scan", icon: Globe, activeColor: "text-primary border-primary/20 bg-primary/10" },
              { id: "code", label: "Repository", icon: Code, activeColor: "text-primary border-primary/20 bg-primary/10" },
            ] as const).map((type) => {
              const Icon = type.icon;
              const isActive = sourceType === type.id;
              return (
                <button
                  type="button"
                  key={type.id}
                  onClick={() => setSourceType(type.id)}
                  className={cn(
                    "flex items-center justify-center gap-1.5 py-2.5 rounded-lg text-[10px] font-semibold transition-all duration-300",
                    isActive
                      ? `border shadow-sm ${type.activeColor}`
                      : "text-muted-foreground hover:text-foreground"
                  )}
                >
                  <Icon className="w-3.5 h-3.5" />
                  {type.label}
                </button>
              );
            })}
          </div>

          {/* Active module summary badge */}
          <p className="text-[10px] text-muted-foreground font-medium ml-1">
            Showing <span className="text-primary font-bold">{compatibleModules.length}</span> modules
            applicable to <span className="text-foreground">{sourceTypeLabel[sourceType]}</span>
          </p>

          <AnimatePresence mode="wait">
            <motion.div
              key={sourceType}
              initial={{ opacity: 0, y: 10 }}
              animate={{ opacity: 1, y: 0 }}
              exit={{ opacity: 0, y: -10 }}
              transition={{ duration: 0.2 }}
              className="relative group"
            >
              <input
                type="text"
                value={targetPath}
                onChange={(e) => setTargetPath(e.target.value)}
                className="w-full bg-secondary/50 border border-border rounded-xl px-4 py-3 text-sm text-foreground focus:outline-none focus:border-primary/40 transition-all duration-300 placeholder:text-muted-foreground/50"
                placeholder={
                  sourceType === "url" ? "Enter target URL (e.g., https://vulnbank.org)..." :
                    "Provide repository URL (e.g., https://github.com/...)..."
                }
              />
              <div className="absolute right-3 top-1/2 -translate-y-1/2 p-1.5 rounded-md text-muted-foreground">
                {sourceType === "url" && <Globe className="w-4 h-4" />}
                {sourceType === "code" && <Code className="w-4 h-4" />}
              </div>
            </motion.div>
          </AnimatePresence>
        </div>

        {/* Strategy Dropdown */}
        <div className="space-y-3 relative">
          <label className="text-[10px] uppercase tracking-[0.2em] text-muted-foreground font-bold ml-1">
            Analysis Vector
          </label>
          <button
            type="button"
            onClick={() => setIsStrategyOpen(!isStrategyOpen)}
            className="w-full flex items-center justify-between bg-secondary/50 border border-border rounded-xl px-4 py-3 text-sm text-foreground hover:border-primary/20 transition-all duration-300"
          >
            <span>{strategies.find(s => s.id === selectedStrategy)?.name}</span>
            <ChevronDown className={cn("w-4 h-4 transition-transform duration-300", isStrategyOpen && "rotate-180")} />
          </button>

          <AnimatePresence>
            {isStrategyOpen && (
              <motion.div
                initial={{ opacity: 0, y: 10, scale: 0.95 }}
                animate={{ opacity: 1, y: 0, scale: 1 }}
                exit={{ opacity: 0, y: 10, scale: 0.95 }}
                className="absolute z-50 top-full left-0 right-0 mt-2 p-1 bg-card border border-border rounded-xl backdrop-blur-2xl shadow-lg"
              >
                {strategies.map((s) => (
                  <button
                    type="button"
                    key={s.id}
                    onClick={() => {
                      setSelectedStrategy(s.id);
                      setIsStrategyOpen(false);
                    }}
                    className={cn(
                      "w-full text-left px-4 py-2.5 rounded-lg text-sm transition-colors",
                      selectedStrategy === s.id
                        ? "bg-primary/10 text-primary"
                        : "text-muted-foreground hover:bg-secondary/50 hover:text-foreground"
                    )}
                  >
                    {s.name}
                  </button>
                ))}
              </motion.div>
            )}
          </AnimatePresence>
        </div>

        {/* Modules Grid — only compatible modules shown */}
        <div className="space-y-3">
          <div className="flex items-center justify-between">
            <label className="text-[10px] uppercase tracking-[0.2em] text-muted-foreground font-bold ml-1">
              Active Modules ({selectedModules.length}/{compatibleModules.length})
            </label>
            <button
              type="button"
              onClick={() =>
                setSelectedModules(
                  selectedModules.length === compatibleModules.length
                    ? []
                    : compatibleModules.map((m: any) => m.id)
                )
              }
              className="text-[10px] uppercase text-primary font-bold hover:underline"
            >
              Toggle All
            </button>
          </div>
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-3">
            {compatibleModules.map((module: any) => (
              <ModuleCard
                key={module.id}
                id={module.id}
                title={module.name}
                patternCount={module.patternCount}
                isSelected={selectedModules.includes(module.id)}
                onToggle={handleToggleModule}
                disabled={isScanning}
              />
            ))}
          </div>
        </div>
      </div>

      {/* Footer */}
      <div className="mt-8 pt-6 border-t border-border flex items-center justify-between">
        <div className="flex flex-col">
          <div className="flex items-center gap-2">
            <div className={cn(
              "w-2 h-2 rounded-full",
              isScanning ? "bg-amber-500 animate-pulse" : "bg-primary dark:shadow-[0_0_8px_rgba(var(--primary),0.6)]"
            )} />
            <span className="text-xs font-bold text-foreground uppercase tracking-wider">
              {isScanning ? (isPaused ? "Scan Paused" : "Processing Analysis") : "Ready for Deployment"}
            </span>
          </div>
          <p className="text-[10px] text-muted-foreground mt-0.5">{totalPatterns.toLocaleString()} security patterns loaded</p>
          <p className="text-[9px] text-amber-500/80 mt-1 uppercase tracking-tighter font-mono">
            ETR: ~{Math.ceil((selectedModules.length * 12 + totalPatterns * 0.05) / 60)}m {Math.ceil((selectedModules.length * 12 + totalPatterns * 0.05) % 60)}s
          </p>
        </div>

        <div className="flex items-center gap-3">
          {isScanning && (
            <>
              <button
                type="button"
                onClick={onPause}
                className="p-3 rounded-xl bg-secondary border border-border text-muted-foreground hover:text-amber-500 hover:border-amber-500/30 transition-colors duration-300"
                title={isPaused ? "Resume Scan" : "Pause Scan"}
              >
                {isPaused ? <Play className="w-4 h-4 fill-current" /> : <Pause className="w-4 h-4 fill-current" />}
              </button>
              <button
                type="button"
                onClick={onCancel}
                className="p-3 rounded-xl bg-secondary border border-border text-muted-foreground hover:text-destructive hover:border-destructive/30 transition-colors duration-300"
                title="Stop Scan"
              >
                <Square className="w-4 h-4 fill-current" />
              </button>
            </>
          )}
          <button
            type="submit"
            onClick={() => onStart(targetPath, selectedModules, selectedStrategy, sourceType)}
            disabled={isScanning || selectedModules.length === 0 || !targetPath.trim()}
            className={cn(
              "group relative px-8 py-3 rounded-xl font-bold uppercase tracking-widest text-sm transition-all duration-300 overflow-hidden",
              isScanning || !targetPath.trim()
                ? "bg-secondary text-muted-foreground cursor-not-allowed"
                : "bg-primary text-primary-foreground dark:hover:shadow-[0_0_30px_rgba(var(--primary),0.4)] active:scale-95 shadow-md"
            )}
          >
            <div className="relative z-10 flex items-center gap-2">
              {isScanning ? (
                <>
                  <Loader2 className="w-5 h-5 animate-spin" />
                  {isPaused ? "Paused" : "Scanning..."}
                </>
              ) : (
                <>
                  <Play className="w-4 h-4 fill-current" />
                  Initialize Scan
                </>
              )}
            </div>
            {!isScanning && targetPath.trim() && (
              <div className="absolute inset-0 bg-gradient-to-r from-white/20 to-transparent translate-x-[-100%] group-hover:translate-x-[100%] transition-transform duration-700 pointer-events-none" />
            )}
          </button>
        </div>
      </div>
    </GlowCard>
  );
}
