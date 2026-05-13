"use client";
import React from "react";
import { motion, AnimatePresence } from "framer-motion";
import { Key, Atom, Lock, Shield, Brain, Bug, Radar, Fingerprint, Server, Eye, Network, ShieldAlert, Wrench, Sparkles, Bot, Zap, CheckCircle2, ShieldCheck, Activity, BrainCircuit, Terminal, Radiation, Microscope, Globe, Search, Layers, Smartphone, UserX, Cloud, Database, Cpu, Target, Share2, Workflow, Box, Play, ChevronRight, X, RefreshCw } from "lucide-react";
import type { LucideIcon } from "lucide-react";
import { GlowCard } from "@/components/ui/glow-card";
import { Badge } from "@/components/ui/badge";
import { cn } from "@/lib/utils";
import { useTheme } from "next-themes";

/* ─── Theme-aware color helpers ─── */
function useThemeColors() {
  const { resolvedTheme } = useTheme();
  const isLight = resolvedTheme === "light";
  return {
    isLight,
    accent: isLight ? "#6c63ff" : "#00FF88",
    accentDim: isLight ? "#5b54e6" : "#00E676",
    accentBg: isLight ? "rgba(108,99,255,0.08)" : "rgba(0,255,136,0.08)",
    accentBorder: isLight ? "rgba(108,99,255,0.15)" : "rgba(0,255,136,0.15)",
    accentGlow: isLight ? "rgba(108,99,255,0.12)" : "rgba(0,255,136,0.3)",
    accentGlowSubtle: isLight ? "rgba(108,99,255,0.06)" : "rgba(0,255,136,0.08)",
    bgDeep: isLight ? "#f6f8fb" : "#0B0F0C",
    bgCard: isLight ? "#ffffff" : "#111716",
    cardBg: isLight ? "rgba(255,255,255,0.9)" : "rgba(255,255,255,0.03)",
    cardBorder: isLight ? "rgba(108,99,255,0.12)" : "rgba(255,255,255,0.08)",
    cardShadow: isLight ? "0 10px 30px rgba(0,0,0,0.06)" : "0 4px 24px rgba(0,0,0,0.3), inset 0 1px 0 rgba(255,255,255,0.06)",
    cardHoverBg: isLight ? "rgba(108,99,255,0.04)" : "rgba(255,255,255,0.06)",
    textPrimary: isLight ? "#1f2937" : "#FFFFFF",
    textSecondary: isLight ? "#4b5563" : "#8A9E96",
    textMuted: isLight ? "#6b7280" : "#6B7F77",
    borderSubtle: isLight ? "#e6e9f2" : "rgba(0,255,136,0.15)",
    borderHover: isLight ? "#c7cce0" : "rgba(0,255,136,0.35)",
    sectionBg: isLight ? "linear-gradient(135deg, #f6f8fb, #eef1ff)" : "#0B0F0C",
  };
}

/* ─── Reusable Glow Title Component ─── */
export function GlowTitle({
  mainText,
  highlightText,
  subtitle,
  className,
  titleClassName
}: {
  mainText: string,
  highlightText: string,
  subtitle?: string,
  className?: string,
  titleClassName?: string
}) {
  const { isLight, accent, accentGlow } = useThemeColors();
  return (
    <motion.div
      initial={{ opacity: 0, y: 20 }}
      whileInView={{ opacity: 1, y: 0 }}
      viewport={{ once: true }}
      className={cn("text-center mb-16 px-6", className)}
    >
      <motion.h2
        className={cn("text-4xl md:text-5xl font-black font-outfit text-text-primary cursor-default select-none group inline-block", titleClassName)}
        whileHover={{
          textShadow: isLight ? "none" : `0 0 25px ${accentGlow}`,
          scale: 1.02
        }}
        transition={{ type: "spring", stiffness: 300 }}
      >
        {mainText} <span className="text-neon-green relative">
          {highlightText}
          <motion.span
            className="absolute -inset-2 blur-xl rounded-full opacity-0 group-hover:opacity-100 transition-opacity duration-500"
            style={{ background: `${accent}33` }}
            animate={{
              scale: [1, 1.2, 1],
            }}
            transition={{ duration: 2, repeat: Infinity }}
          />
        </span>
      </motion.h2>
      {subtitle && (
        <p className="text-text-secondary max-w-3xl mx-auto text-lg mt-4">{subtitle}</p>
      )}
    </motion.div>
  );
}

/* ─── Trust Metrics Strip ─── */
const metrics = [
  {
    icon: Radar,
    title: "AI Agents Vulnerability Intelligence",
    label: "Vulnerability Patterns",
    stat: "500+",
    highlights: [
      "OWASP Top 10:2025 coverage",
      "Exploit Pattern Learning Agent",
      "Secrets & misconfiguration discovery",
      "Unified multi-engine analysis",
      "Continuous Payload Evolution",
      "Payload Optimization Agent",
      "Self Learning Payload Generator Agent",
      "Continuous Learning Memory Agent"
    ]
  },
  {
    icon: ShieldCheck,
    title: "AI-Verified Integrity",
    label: "Scan Accuracy",
    stat: "99.9%",
    highlights: [
      "AI false-positive reduction",
      "Context-aware validation",
      "exploit verification",
      "logic flaw discovery",
      "Reliable remediation insights",
      "AI driven vulnerability discovery",
      "autonomous pentesting workflows",
      "cross-scan intelligence learning",
      "AI-assisted fuzzing"
    ]
  },
];

export function TrustMetrics() {
  const { isLight, accentBg, accentBorder, accent } = useThemeColors();
  return (
    <section className="relative py-20 overflow-hidden">
      <div className="section-divider mb-16" />

      <GlowTitle
        mainText="AI-Powered"
        highlightText="Security Intelligence"
        subtitle="AI-Driven Security Intelligence and Intelligent Remediation built for modern DevSecOps teams."
      />

      <div className="max-w-7xl mx-auto px-6 grid grid-cols-1 lg:grid-cols-2 gap-12 items-center relative z-10">
        {/* Left Column: Video & Descriptions */}
        <div className="flex flex-col gap-8">
          <motion.div
            initial={{ opacity: 0, y: -20 }}
            whileInView={{ opacity: 1, y: 0 }}
            viewport={{ once: true }}
            transition={{ duration: 0.6 }}
            className="space-y-6"
          >
            <div className="space-y-2">
              <h4 className="text-3xl md:text-4xl font-black font-outfit text-text-primary tracking-tight">
                Quantara <span className="text-neon-green">Security Intelligence</span>
              </h4>
              <div className="h-1 w-20 bg-neon-green rounded-full shadow-[0_0_15px_rgba(0,255,136,0.4)]" />
            </div>

            <div className="grid gap-4">
              {[
                "Enterprise-grade protection",
                "Protected vulnerability analytics",
                "Encrypted data processing"
              ].map((item, idx) => (
                <div key={idx} className="flex items-center gap-4 group/item">
                  <div className="w-2 h-2 rounded-full bg-neon-green animate-pulse group-hover/item:scale-125 transition-transform" style={{ boxShadow: "0 0 10px rgba(0,255,136,0.8)" }} />
                  <p className="text-sm font-bold uppercase tracking-[0.2em] text-text-secondary group-hover/item:text-neon-green transition-colors">{item}</p>
                </div>
              ))}
            </div>
          </motion.div>

          <motion.div
            initial={{ opacity: 0, x: -30 }}
            whileInView={{ opacity: 1, x: 0 }}
            transition={{ duration: 0.8, delay: 0.2 }}
            viewport={{ once: true }}
            className="relative group cursor-pointer"
          >
            <div className="absolute -inset-1 bg-gradient-to-r from-neon-green/20 to-cyan-500/20 rounded-[2rem] blur-xl opacity-0 group-hover:opacity-100 transition-opacity duration-700" />
            <div className="relative rounded-[2rem] overflow-hidden border border-neon-green/30 bg-[#0B0F0C] shadow-2xl shadow-neon-green/5 aspect-video flex items-center justify-center">
              <video
                src="/Quantara_AI.mp4"
                autoPlay
                loop
                muted
                playsInline
                className="w-full h-full object-cover"
              />
              {/* Glossy overlay effect */}
              <div className="absolute inset-0 bg-gradient-to-tr from-neon-green/5 via-transparent to-transparent pointer-events-none" />
            </div>
          </motion.div>
        </div>

        {/* Right Column: 3 Cards Stacked (Horizontal internal layout) */}
        <div className="flex flex-col gap-6">
          {metrics.map((m, i) => (
            <GlowCard key={m.title}
              initial={{ opacity: 0, x: 30 }}
              whileInView={{ opacity: 1, x: 0 }}
              transition={{ duration: 0.6, delay: i * 0.15 }}
              viewport={{ once: true }}
              className="group hover:translate-x-2 transition-all duration-500 border-border-green/30 flex flex-row items-center gap-6 p-6 h-full"
            >
              {/* Left: Icon */}
              <div className="flex-shrink-0 flex items-center justify-center w-14 h-14 rounded-2xl" style={{ background: accentBg, border: `1px solid ${accentBorder}` }}>
                <m.icon className="w-7 h-7 text-neon-green drop-shadow-neon group-hover:animate-pulse" />
              </div>

              {/* Right: Content */}
              <div className="flex-grow space-y-2">
                <div className="flex flex-col sm:flex-row sm:items-end gap-2 sm:gap-4">
                  <div className="text-3xl font-black font-outfit text-neon-green glow-green-text leading-none">{m.stat}</div>
                  <h3 className="text-sm font-extrabold text-text-primary font-outfit tracking-tight group-hover:text-neon-green transition-colors leading-tight uppercase tracking-[0.1em]">{m.title}</h3>
                </div>

                <div className="pt-3 border-t border-border-green/10 flex flex-wrap gap-x-4 gap-y-1">
                  {m.highlights.slice(0, 3).map((h, j) => (
                    <div key={j} className="flex items-center gap-2">
                      <CheckCircle2 className="w-3 h-3 text-neon-green/60 shrink-0" />
                      <span className="text-[9px] font-bold uppercase tracking-widest text-text-muted">{h}</span>
                    </div>
                  ))}
                </div>
              </div>

              {/* Decorative scan line like in the image */}
              <div className="absolute right-0 top-0 bottom-0 w-[2px] bg-gradient-to-b from-transparent via-neon-green/20 to-transparent group-hover:via-neon-green/50 transition-colors" />
            </GlowCard>
          ))}
        </div>
      </div>

      {/* Subtle background glow effect for the section */}
      <div className="absolute top-1/2 left-1/2 -translate-x-1/2 -translate-y-1/2 w-full h-[300px] blur-[120px] pointer-events-none" style={{ background: accentBg }} />

      <div className="section-divider mt-16" />
    </section>
  );
}

/* ─── Feature Cards ─── */
const redTeamFeatures = [
  {
    icon: Bot,
    title: "Autonomous AI Swarm",
    desc: "Twelve specialized AI security agents collaborate in real time to discover vulnerabilities, analyze application logic, and simulate attacker behavior."
  },
  {
    icon: Radar,
    title: "Intelligent Surface Discovery",
    desc: "AI reconnaissance continuously discovers hidden APIs, endpoints, subdomains, and attack surfaces across the entire application ecosystem."
  },
  {
    icon: Zap,
    title: "AI-Driven Exploit Generation",
    desc: "Dynamic payload synthesis and exploit testing automatically verify vulnerabilities with realistic attack simulations."
  },
  {
    icon: Sparkles,
    title: "Adaptive Payload Evolution",
    desc: "Quantara evolves attack payloads based on response analysis, enabling continuous discovery of new vulnerability vectors."
  },
  {
    icon: Network,
    title: "Multi-Step Attack Chain Analysis",
    desc: "The AI Attack Graph Engine connects vulnerabilities together to reveal realistic exploit paths and attacker movement across the system."
  },
  {
    icon: Activity,
    title: "Real-Time Security Telemetry",
    desc: "Live telemetry streams show agent activity, discovered assets, vulnerability signals, and exploit validation results as the scan progresses."
  },
];

export function FeatureCards() {
  const { isLight, accentBg, accentBorder } = useThemeColors();
  return (
    <section id="features" className="relative py-24 scroll-mt-24 overflow-hidden">
      {/* Background Section Decor */}
      <div className="absolute inset-0 pointer-events-none overflow-hidden">
        {!isLight && (
          <>
            <div className="absolute top-1/2 left-1/2 -translate-x-1/2 -translate-y-1/2 w-[1000px] h-[1000px] bg-neon-green/5 rounded-full blur-[160px] opacity-40" />
            <div className="absolute inset-0 bg-grid-cyber opacity-[0.3]" />

            {/* Animated network lines */}
            <motion.div
              className="absolute top-0 left-0 w-full h-full"
              initial={{ opacity: 0 }}
              animate={{ opacity: 1 }}
              transition={{ duration: 2 }}
            >
              {[...Array(6)].map((_, i) => (
                <motion.div
                  key={i}
                  className="absolute bg-gradient-to-r from-transparent via-neon-green/10 to-transparent h-[1px]"
                  style={{
                    width: '100%',
                    left: 0,
                    top: `${15 + i * 15}%`,
                    rotate: i % 2 === 0 ? 2 : -2
                  }}
                  animate={{
                    x: ['-100%', '100%'],
                    opacity: [0, 1, 1, 0]
                  }}
                  transition={{
                    duration: 5 + i,
                    repeat: Infinity,
                    delay: i * 2,
                    ease: "linear"
                  }}
                />
              ))}
            </motion.div>
          </>
        )}
      </div>

      <div className="max-w-7xl mx-auto px-6 relative z-10">
        <GlowTitle
          mainText="Autonomous Multi-Agent"
          highlightText="AI Red Team"
          subtitle="A swarm of intelligent security agents working together to discover vulnerabilities, simulate real attacker behavior, and generate multi-step exploit paths automatically."
        />

        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-8">
          {redTeamFeatures.map((f, i) => (
            <GlowCard key={f.title}
              initial={{ opacity: 0, y: 30 }}
              whileInView={{ opacity: 1, y: 0 }}
              transition={{ duration: 0.6, delay: i * 0.1 }}
              viewport={{ once: true }}
              className="p-8 group h-full flex flex-col border-white/5 bg-[rgba(10,15,12,0.3)] backdrop-blur-xl hover:border-neon-green/40 transition-all duration-700"
            >
              <div className="flex flex-col h-full relative z-10">
                {/* Icon with orbital pulse */}
                <div className="relative mb-8 group">
                  <motion.div
                    className="absolute inset-0 bg-neon-green/20 rounded-full blur-xl opacity-0 group-hover:opacity-100 transition-opacity duration-700"
                    animate={{ scale: [1, 1.3, 1] }}
                    transition={{ duration: 2, repeat: Infinity }}
                  />
                  <div className="shrink-0 w-16 h-16 rounded-2xl flex items-center justify-center relative z-10 group-hover:scale-110 group-hover:rotate-3 transition-all duration-500"
                    style={{ background: accentBg, border: `1px solid ${accentBorder}`, boxShadow: "0 0 30px rgba(0,255,136,0.15)" }}>
                    <f.icon className="w-8 h-8 text-neon-green drop-shadow-neon" />
                  </div>

                  {/* Small orbiting particles on hover */}
                  {!isLight && (
                    <div className="absolute -top-2 -right-2 opacity-0 group-hover:opacity-100 transition-opacity duration-700">
                      <div className="w-2 h-2 rounded-full bg-neon-green/60 animate-ping" />
                    </div>
                  )}
                </div>

                <div>
                  <h3 className="text-2xl font-black text-text-primary font-outfit mb-4 group-hover:text-neon-green transition-colors tracking-tight">
                    {f.title}
                  </h3>
                  <p className="text-text-secondary text-base leading-relaxed mb-8 opacity-80 group-hover:opacity-100 transition-opacity">
                    {f.desc}
                  </p>
                </div>

                <div className="mt-auto pt-8 border-t border-white/5 flex items-center justify-between">
                  <div className="flex items-center gap-3">
                    <div className="w-2 h-2 rounded-full bg-neon-green animate-pulse shadow-[0_0_10px_rgba(0,255,136,0.5)]" />
                    <span className="text-[11px] font-black uppercase tracking-[0.25em] text-text-muted group-hover:text-neon-green/70 transition-colors">
                      Active Node
                    </span>
                  </div>
                  <div className="font-mono text-[10px] text-text-muted/40 font-bold">
                    0x{((i + 1) * 1337).toString(16).toUpperCase()}
                  </div>
                </div>
              </div>

              {/* Enhanced scan beam animation */}
              <motion.div
                className="absolute inset-0 z-0 pointer-events-none opacity-0 group-hover:opacity-100 transition-opacity duration-700"
                initial={false}
              >
                <motion.div
                  className="absolute top-0 left-0 w-full h-[3px] bg-gradient-to-r from-transparent via-neon-green/30 to-transparent"
                  animate={{ top: ["0%", "100%", "0%"] }}
                  transition={{ duration: 3, repeat: Infinity, ease: "linear" }}
                />

                {/* Lateral scan beam */}
                <motion.div
                  className="absolute top-0 left-0 h-full w-[2px] bg-gradient-to-b from-transparent via-neon-green/10 to-transparent"
                  animate={{ left: ["0%", "100%", "0%"] }}
                  transition={{ duration: 4, repeat: Infinity, ease: "linear", delay: 0.5 }}
                />
              </motion.div>
            </GlowCard>
          ))}
        </div>
      </div>
    </section>

  );
}


/* ─── Multi-Agent Architecture Section (Replacement) ─── */

const architectureCards = [
  {
    title: "Orchestration Swarm",
    icon: BrainCircuit,
    description: "Autonomous coordination layer powering distributed AI security agents.",
    status: {
      registry: "initialized",
      status: "optimizing",
      neurons: "172.4B",
      latency: "grid_enabled"
    },
    highlights: [
      "distributed AI agent mesh",
      "autonomous task routing",
      "neural workload balancing",
      "sub-second orchestration"
    ],
    color: "rgba(0, 255, 180, 0.25)"
  },
  {
    title: "Modular Security Ecosystem",
    icon: Layers,
    description: "Multi-layered discovery and analysis architecture for full-spectrum security.",
    subSections: [
      {
        name: "Reconnaissance Layer",
        modules: ["endpoint_discovery", "api_structure_mapper", "technology_fingerprint", "header_analyzer", "subdomain_discovery"]
      },
      {
        name: "Analysis Engine",
        modules: ["input_mapper", "auth_mapper", "response_behavior_analyzer", "endpoint_classifier"]
      }
    ],
    color: "rgba(0, 200, 255, 0.25)"
  },
  {
    title: "AI Fuzzing & Exploit Engine",
    icon: Zap,
    description: "LLM-assisted vulnerability discovery and automated exploitation engine.",
    subSections: [
      {
        name: "AI Fuzzing Engine",
        modules: ["Seed Payload Library", "Mutation Engine", "LLM Payload Generator", "Coverage Analyzer"]
      },
      {
        name: "Self-Learning Mutation",
        modules: ["payload_mutator", "payload_ranker", "payload_learning_engine"]
      },
      {
        name: "Exploit Execution",
        modules: ["attack_executor", "timing_anomaly_detector", "response_diff_engine"]
      }
    ],
    color: "rgba(255, 180, 0, 0.25)"
  },
  {
    title: "AI Verification & Intelligence",
    icon: ShieldCheck,
    description: "Enterprise-grade vulnerability validation and security reasoning.",
    subSections: [
      {
        name: "AI Verification",
        modules: ["verdict_engine", "severity_calculator", "impact_analyzer"]
      },
      {
        name: "System Core Infrastructure",
        modules: ["Task Queue → Initializing", "Intelligence DB → shared memory", "Neural Switch → task router", "Secure Sandbox → isolated execute"]
      }
    ],
    color: "rgba(180, 0, 255, 0.25)"
  }
];

const eliteCapabilities = [
  {
    title: "Network Discovery & Pivoting",
    desc: "Maps internal network reachability through blind server-side requests.",
    icon: Globe
  },
  {
    title: "Zero-Day Logic Flaw Detection",
    desc: "Semantic AI reasoning for multi-step authorization bypass.",
    icon: Radiation
  },
  {
    title: "Parser Confusion Discovery",
    desc: "Detects inconsistencies between proxies, interpreters, and databases.",
    icon: Microscope
  },
  {
    title: "Hypothesis-Driven Exploitation",
    desc: "AI dynamically tests security assumptions.",
    icon: Search
  }
];

export function MultiAgentSection() {
  const { isLight } = useThemeColors();

  return (
    <section className="relative py-32 overflow-hidden bg-deep">
      {/* Background Decorative Elements */}
      <div className="absolute inset-0 pointer-events-none">
        <div className="absolute top-0 left-1/4 w-[500px] h-[500px] bg-neon-green/5 rounded-full blur-[120px] opacity-20" />
        <div className="absolute bottom-0 right-1/4 w-[600px] h-[600px] bg-blue-500/5 rounded-full blur-[140px] opacity-20" />

        {/* Animated Network Lines */}
        <div className="absolute inset-0 opacity-10">
          {[...Array(6)].map((_, i) => (
            <motion.div
              key={i}
              className="absolute bg-gradient-to-r from-transparent via-neon-green/30 to-transparent h-[1px] w-full"
              style={{ top: `${15 + i * 15}%`, rotate: i % 2 === 0 ? 1 : -1 }}
              animate={{ x: ['-100%', '100%'] }}
              transition={{ duration: 10 + i * 2, repeat: Infinity, ease: "linear" }}
            />
          ))}
        </div>
      </div>

      <div className="relative z-10 max-w-7xl mx-auto px-6">
        <div className="text-center mb-24">
          <motion.div
            initial={{ opacity: 0, scale: 0.9 }}
            whileInView={{ opacity: 1, scale: 1 }}
            viewport={{ once: true }}
            className="inline-flex items-center gap-2 px-4 py-1.5 rounded-full border border-neon-green/30 bg-neon-green/5 mb-6"
          >
            <Activity className="w-4 h-4 text-neon-green animate-pulse" />
            <span className="text-neon-green text-[10px] font-bold tracking-[0.2em] uppercase">Distributed Multi-Agent Architecture</span>
          </motion.div>
          <motion.h2
            initial={{ opacity: 0, y: 20 }}
            whileInView={{ opacity: 1, y: 0 }}
            viewport={{ once: true }}
            className="text-4xl md:text-6xl font-black font-outfit text-text-primary mb-6"
          >
            Autonomous AI <span className="text-neon-green glow-green-text">Security Swarm</span>
          </motion.h2>
          <p className="text-text-secondary text-lg max-w-2xl mx-auto">
            Experience the next generation of cybersecurity powered by distributed intelligence,
            autonomous reasoning, and self-evolving attack vectors.
          </p>
        </div>

        {/* Feature Cards Grid: 4 Desktop, 2 Tablet, 1 Mobile */}
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6 mb-32">
          {architectureCards.map((card, idx) => (
            <motion.div
              key={card.title}
              initial={{ opacity: 0, y: 40 }}
              whileInView={{ opacity: 1, y: 0 }}
              viewport={{ once: true }}
              transition={{ delay: idx * 0.1 }}
              whileHover={{ y: -8 }}
              className="group relative h-full"
            >
              {/* Card Container with Glassmorphism */}
              <div className="h-full p-8 rounded-[2.5rem] bg-[rgba(20,25,35,0.6)] backdrop-blur-[14px] border border-[rgba(0,255,180,0.25)] shadow-2xl relative overflow-hidden transition-all duration-500 group-hover:border-neon-green/60 group-hover:shadow-[0_0_40px_rgba(0,255,180,0.15)] flex flex-col">

                {/* Visual Flair: Circuit Flow Effect on hover */}
                <div className="absolute top-0 left-0 w-full h-full opacity-0 group-hover:opacity-10 transition-opacity pointer-events-none">
                  <div className="absolute top-0 left-1/2 w-px h-full bg-neon-green" style={{ animation: 'circuit-vertical 3s linear infinite' }} />
                  <div className="absolute left-0 top-1/2 w-full h-px bg-neon-green" style={{ animation: 'circuit-horizontal 4s linear infinite' }} />
                </div>

                {/* Card Icon */}
                <div className="mb-8 p-4 w-16 h-16 rounded-2xl bg-white/5 border border-white/10 flex items-center justify-center group-hover:scale-110 group-hover:bg-neon-green/10 group-hover:border-neon-green/30 transition-all duration-500">
                  <card.icon className="w-8 h-8 text-neon-green" />
                </div>

                <h3 className="text-2xl font-bold font-outfit text-white mb-4 group-hover:text-neon-green transition-colors">
                  {card.title}
                </h3>

                <p className="text-gray-400 text-sm leading-relaxed mb-8 flex-grow">
                  {card.description}
                </p>

                {/* Card Content specific to type */}
                {card.status && (
                  <div className="space-y-4 mb-8">
                    <div className="font-mono text-[10px] space-y-1.5 text-neon-green/70 bg-black/40 p-4 rounded-2xl border border-white/5">
                      <div className="flex justify-between"><span>agent_registry:</span> <span className="text-white">initialized</span></div>
                      <div className="flex justify-between"><span>network_status:</span> <span className="text-white">optimizing</span></div>
                      <div className="flex justify-between"><span>neurons:</span> <span className="text-white">172.4B</span></div>
                      <div className="flex justify-between"><span>latency:</span> <span className="text-white">grid_enabled</span></div>
                    </div>
                  </div>
                )}

                {card.highlights && (
                  <div className="space-y-2.5 mb-8">
                    {card.highlights.map(h => (
                      <div key={h} className="flex items-center gap-2.5 text-[10px] font-bold uppercase tracking-widest text-gray-500">
                        <CheckCircle2 className="w-3.5 h-3.5 text-neon-green/60" />
                        <span>{h}</span>
                      </div>
                    ))}
                  </div>
                )}

                {card.subSections && (
                  <div className="space-y-6 mb-8">
                    {card.subSections.map(sub => (
                      <div key={sub.name} className="space-y-3">
                        <p className="text-[10px] font-black text-neon-green uppercase tracking-[0.2em]">{sub.name}</p>
                        <div className="flex flex-wrap gap-2">
                          {sub.modules.map(mod => (
                            <Badge key={mod} variant="outline" className="text-[9px] px-2.5 py-0.5 border-white/10 bg-white/5 text-gray-400 hover:text-white hover:border-neon-green/30 transition-colors capitalize">
                              {mod.replace(/_/g, " ")}
                            </Badge>
                          ))}
                        </div>
                      </div>
                    ))}
                  </div>
                )}

                {/* Scan Sweep Animation on Hover */}
                <motion.div
                  className="absolute inset-x-0 top-0 h-[2px] bg-gradient-to-r from-transparent via-neon-green/40 to-transparent opacity-0 group-hover:opacity-100 pointer-events-none"
                  animate={{ top: ["0%", "100%", "0%"] }}
                  transition={{ duration: 3, repeat: Infinity, ease: "linear" }}
                />
              </div>
            </motion.div>
          ))}
        </div>

        {/* Operational Sovereignty & Elite Capabilities */}
        <div className="grid lg:grid-cols-12 gap-16 items-start">
          {/* Left: Highlight Panel */}
          <motion.div
            initial={{ opacity: 0, x: -40 }}
            whileInView={{ opacity: 1, x: 0 }}
            viewport={{ once: true }}
            className="lg:col-span-5 space-y-10"
          >
            <div>
              <h3 className="text-4xl font-black font-outfit text-text-primary mb-6">Operational <span className="text-neon-green">Sovereignty</span></h3>
              <p className="text-text-secondary text-lg">Underpinning our architecture is a set of ironclad security guarantees that ensure data integrity and operational safety.</p>
            </div>

            <div className="space-y-4">
              {[
                { label: "Data Isolation", status: "ENCRYPTED", icon: ShieldCheck, color: "text-green-400" },
                { label: "Live Telemetry", status: "STREAMING", icon: Activity, color: "text-neon-green", animate: true },
                { label: "Role-Based Access", status: "ENFORCED", icon: Lock, color: "text-blue-400" }
              ].map(item => (
                <div key={item.label} className="flex justify-between items-center p-5 rounded-3xl bg-white/5 border border-white/10 group hover:border-neon-green/30 transition-all">
                  <div className="flex items-center gap-4">
                    <item.icon className={cn("w-6 h-6", item.color)} />
                    <span className="text-text-primary font-bold font-outfit text-base">{item.label}</span>
                  </div>
                  <span className={cn("font-mono text-xs tracking-[0.2em] font-black", item.animate ? "animate-pulse " + item.color : "text-text-muted")}>
                    {item.status}
                  </span>
                </div>
              ))}
            </div>

            {/* Continuous Learning Indicator */}
            <div className="p-8 rounded-[2.5rem] bg-neon-green/5 border border-neon-green/10 flex items-center gap-6 group hover:bg-neon-green/10 transition-colors">
              <div className="relative shrink-0">
                <div className="w-16 h-16 rounded-full border-2 border-neon-green/20 flex items-center justify-center">
                  <BrainCircuit className="w-8 h-8 text-neon-green animate-pulse" />
                </div>
                <div className="absolute inset-0 border-2 border-neon-green rounded-full border-t-transparent animate-spin" style={{ animation: 'spin 2s linear infinite' }} />
              </div>
              <div>
                <p className="text-text-primary font-black text-lg tracking-tight">Continuous Learning</p>
                <p className="text-[11px] text-text-muted uppercase tracking-[0.2em] font-bold">Evolutionary attack pattern database</p>
              </div>
            </div>
          </motion.div>

          {/* Right: Capabilities Grid */}
          <motion.div
            initial={{ opacity: 0, x: 40 }}
            whileInView={{ opacity: 1, x: 0 }}
            viewport={{ once: true }}
            className="lg:col-span-7 grid md:grid-cols-2 gap-6"
          >
            {eliteCapabilities.map((cap, i) => (
              <div key={cap.title} className="p-8 rounded-[2.5rem] bg-white/5 border border-white/10 hover:border-neon-green/30 hover:bg-white/[0.07] transition-all group flex flex-col items-center text-center">
                <div className="w-14 h-14 rounded-2xl bg-neon-green/10 border border-neon-green/20 flex items-center justify-center mb-6 group-hover:scale-110 group-hover:rotate-3 transition-transform">
                  <cap.icon className="w-7 h-7 text-neon-green" />
                </div>
                <h4 className="text-xl font-bold font-outfit text-text-primary mb-3 group-hover:text-neon-green transition-colors">{cap.title}</h4>
                <p className="text-sm text-text-secondary leading-relaxed opacity-80">{cap.desc}</p>
              </div>
            ))}
          </motion.div>
        </div>

        {/* Tagline & Final Action */}
        <motion.div
          initial={{ opacity: 0, y: 30 }}
          whileInView={{ opacity: 1, y: 0 }}
          viewport={{ once: true }}
          className="mt-32 text-center"
        >
          <p className="text-text-muted italic text-xl max-w-3xl mx-auto mb-16 leading-relaxed">
            "Security is not a feature — it is the foundation of our entire multi-agent mesh architecture."
          </p>
          <div className="h-px w-full max-w-5xl mx-auto bg-gradient-to-r from-transparent via-white/10 to-transparent" />
        </motion.div>
      </div>
      <style jsx>{`
        @keyframes circuit-vertical {
            0% { transform: translateY(-100%); opacity: 0; }
            50% { opacity: 1; }
            100% { transform: translateY(100%); opacity: 0; }
        }
        @keyframes circuit-horizontal {
            0% { transform: translateX(-100%); opacity: 0; }
            50% { opacity: 1; }
            100% { transform: translateX(100%); opacity: 0; }
        }
      `}</style>
    </section>
  );
}


/* ─── Autonomous AI Agent Swarm Components ─── */

const swarmAgents = [
  {
    id: "recon",
    title: "Recon Agent",
    icon: Search,
    label: "Autonomous reconnaissance",
    capabilities: ["Subdomain discovery", "Attack surface mapping", "Asset enumeration"],
    description: "Performs continuous discovery of your digital footprint, identifying exposed assets and hidden attack surfaces before attackers do."
  },
  {
    id: "vuln-scanner",
    title: "Vulnerability Scanner Agent",
    icon: Bug,
    label: "Automated discovery",
    capabilities: ["Web scanning", "API security testing", "Infrastructure weaknesses"],
    description: "Deep-scanning engine that identifies OWASP vulnerabilities, misconfigurations, and logic flaws across all application layers."
  },
  {
    id: "exploit-gen",
    title: "Exploit Generation Agent",
    icon: Terminal,
    label: "AI exploit creation",
    capabilities: ["Payload mutation", "Exploit chain building", "Zero-day pattern detection"],
    description: "Synthesizes custom exploitation code to verify findings, ensuring security teams focus on truly exploitable risks."
  },
  {
    id: "payload-mutation",
    title: "Payload Mutation Agent",
    icon: RefreshCw,
    label: "Polymorphic attacks",
    capabilities: ["Bypass WAFs", "Evade security controls", "Adaptive attack generation"],
    description: "Evolves attack vectors in real-time to bypass detection systems and test the resilience of WAFs and IPS solutions."
  },
  {
    id: "data-miner",
    title: "Data Miner Agent",
    icon: Database,
    label: "Sensitive data extraction",
    capabilities: ["PII discovery", "credential leakage detection", "database exposure discovery", "sensitive file indexing", "internal document scraping"],
    description: "AI agent responsible for discovering and extracting sensitive data exposures across systems."
  },
  {
    id: "attack-graph",
    title: "Attack Graph Agent",
    icon: Network,
    label: "Maps attack chains",
    capabilities: ["Privilege escalation", "Lateral movement", "Enterprise attack paths"],
    description: "Visualizes how multiple low-severity issues can be chained together to achieve full system compromise."
  },
  {
    id: "waf-evasion",
    title: "WAF Evasion Agent",
    icon: ShieldAlert,
    label: "WAF bypass specialist",
    capabilities: ["payload obfuscation", "polymorphic payload mutation", "WAF rule fingerprinting", "adaptive request shaping", "security control bypass simulation"],
    description: "AI agent specialized in bypassing Web Application Firewalls and defensive filtering systems."
  },
  {
    id: "cloud-sec",
    title: "Cloud Security Agent",
    icon: Cloud,
    label: "Cloud analysis",
    capabilities: ["IAM privilege abuse", "Container vulnerabilities", "Misconfiguration discovery"],
    description: "Audits AWS, Azure, and GCP environments for over-privileged identities and exposed cloud-native services."
  },
  {
    id: "zero-day",
    title: "Zero-Day Agent",
    icon: Radiation,
    label: "Unknown vulnerability discovery",
    capabilities: ["zero-day pattern detection", "anomaly based discovery", "exploit primitive generation", "vulnerability mutation testing", "unknown attack surface discovery"],
    description: "Autonomous AI engine focused on discovering previously unknown vulnerabilities."
  },
  {
    id: "threat-intel",
    title: "Threat Intelligence Agent",
    icon: Database,
    label: "Security correlation",
    capabilities: ["CVE ingestion", "Exploit matching", "Threat actor techniques"],
    description: "Correlates findings with the global threat landscape and known adversary tactics, techniques, and procedures (TTPs)."
  },
  {
    id: "orchestrator",
    title: "Autonomous Orchestrator",
    icon: Cpu,
    label: "Swarm coordination",
    capabilities: ["Task scheduling", "Scan distribution", "Result correlation"],
    description: "The central intelligence that distributes tasks across the swarm, ensuring efficient and comprehensive coverage."
  }
];

const platformCapabilities = [
  { title: "Autonomous Red Team Operations", icon: Target },
  { title: "Continuous Attack Surface Monitoring", icon: Eye },
  { title: "AI Generated Exploits", icon: Zap },
  { title: "Multi Agent Security Orchestration", icon: Workflow },
  { title: "Zero-Day Discovery Engine", icon: Radiation },
  { title: "Distributed Scan Workers", icon: Box }
];

export function CoreOfferings() {
  const { isLight, accent, accentBorder, accentBg } = useThemeColors();
  const [activeAgent, setActiveAgent] = React.useState<typeof swarmAgents[0] | null>(null);
  const [hoveredAgent, setHoveredAgent] = React.useState<string | null>(null);

  return (
    <section className="relative py-32 overflow-hidden bg-[#05080A]">
      {/* Background Cyber Grid & Particles */}
      <div className="absolute inset-0 pointer-events-none opacity-20">
        <div className="absolute inset-0 bg-grid-cyber opacity-30" />
        <div className="absolute top-0 left-0 w-full h-full bg-gradient-to-b from-transparent via-neon-green/5 to-transparent" />
        {/* Scrolling Lines */}
        {[...Array(5)].map((_, i) => (
          <motion.div
            key={i}
            className="absolute h-px w-full bg-neon-green/20"
            style={{ top: `${i * 25}%` }}
            animate={{ x: ['-100%', '100%'] }}
            transition={{ duration: 10 + i * 2, repeat: Infinity, ease: "linear" }}
          />
        ))}
      </div>

      <div className="max-w-7xl mx-auto px-6 relative z-10">
        {/* Header Section */}
        <div className="text-center mb-24">
          <motion.div
            initial={{ opacity: 0, y: -20 }}
            whileInView={{ opacity: 1, y: 0 }}
            viewport={{ once: true }}
            className="inline-flex items-center gap-2 px-4 py-1.5 rounded-full border border-neon-green/30 bg-neon-green/5 mb-6 shadow-[0_0_15px_rgba(0,255,136,0.1)]"
          >
            <div className="w-2 h-2 rounded-full bg-neon-green animate-pulse" />
            <span className="text-neon-green text-[10px] font-black tracking-[0.2em] uppercase">AI Powered Red Team – Autonomous Mode</span>
          </motion.div>

          <motion.h2
            initial={{ opacity: 0, y: 20 }}
            whileInView={{ opacity: 1, y: 0 }}
            viewport={{ once: true }}
            className="text-4xl md:text-6xl font-black font-outfit text-white mb-6 tracking-tight"
          >
            Quantara <span className="text-transparent bg-clip-text bg-gradient-to-r from-neon-green via-emerald-400 to-green-600 glow-green-text">AI Swarm </span>
          </motion.h2>

          <motion.p
            initial={{ opacity: 0, y: 20 }}
            whileInView={{ opacity: 1, y: 0 }}
            viewport={{ once: true }}
            transition={{ delay: 0.1 }}
            className="text-gray-400 text-lg max-w-4xl mx-auto leading-relaxed"
          >
            A self-orchestrating swarm of AI security agents performing continuous offensive security testing,
            vulnerability discovery, exploit generation, and attack path simulation across enterprise attack surfaces.
          </motion.p>
        </div>

        {/* Central Visualization Area */}
        <div className="relative h-[800px] flex items-center justify-center">
          {/* Connection Lines Container */}
          <svg className="absolute inset-0 w-full h-full pointer-events-none">
            <defs>
              <linearGradient id="line-gradient" x1="0%" y1="0%" x2="100%" y2="0%">
                <stop offset="0%" stopColor="rgba(0,255,136,0)" />
                <stop offset="50%" stopColor="rgba(0,255,136,0.5)" />
                <stop offset="100%" stopColor="rgba(0,255,136,0)" />
              </linearGradient>
            </defs>
            {swarmAgents.map((agent, i) => {
              const angle = (i / swarmAgents.length) * Math.PI * 2;
              const x2 = 50 + Math.cos(angle) * 35;
              const y2 = 50 + Math.sin(angle) * 35;

              return (
                <React.Fragment key={`group-${agent.id}`}>
                  <motion.line
                    x1="50%"
                    y1="50%"
                    x2={`${x2}%`}
                    y2={`${y2}%`}
                    stroke="url(#line-gradient)"
                    strokeWidth="1.5"
                    initial={{ pathLength: 0, opacity: 0 }}
                    whileInView={{ pathLength: 1, opacity: 1 }}
                    viewport={{ once: true }}
                    transition={{ duration: 1.5, delay: i * 0.1 }}
                  />
                  {/* Pulse Signal */}
                  <motion.circle
                    r="3"
                    fill="#00FF88"
                    initial={{ offset: 0, opacity: 0 }}
                    animate={{
                      opacity: [0, 1, 0],
                      cx: ["50%", `${x2}%`],
                      cy: ["50%", `${y2}%`]
                    }}
                    transition={{
                      duration: 3,
                      repeat: Infinity,
                      delay: i * 0.5,
                      ease: "easeInOut"
                    }}
                  />
                </React.Fragment>
              );
            })}
          </svg>

          {/* AI Swarm Core (The Brain) */}
          <motion.div
            initial={{ scale: 0.8, opacity: 0 }}
            whileInView={{ scale: 1, opacity: 1 }}
            viewport={{ once: true }}
            className="relative z-20 w-80 h-80 flex items-center justify-center"
          >
            {/* Spinning Rings */}
            <motion.div
              animate={{ rotate: 360 }}
              transition={{ duration: 20, repeat: Infinity, ease: "linear" }}
              className="absolute inset-0 border-2 border-dashed border-neon-green/20 rounded-full"
            />
            <motion.div
              animate={{ rotate: -360 }}
              transition={{ duration: 15, repeat: Infinity, ease: "linear" }}
              className="absolute inset-4 border border-neon-green/10 rounded-full shadow-[0_0_50px_rgba(0,255,136,0.1)]"
            />

            {/* Core Neural Module */}
            <div className="relative w-48 h-48 rounded-3xl bg-black border border-neon-green/30 overflow-hidden shadow-[0_0_80px_rgba(0,255,136,0.2)] flex flex-col items-center justify-center group">
              {/* Internal Neural Animation */}
              <div className="absolute inset-0 bg-[url('https://grainy-gradients.vercel.app/noise.svg')] opacity-20" />
              <div className="absolute inset-0 overflow-hidden">
                {[...Array(12)].map((_, i) => (
                  <motion.div
                    key={i}
                    className="absolute bg-neon-green rounded-full"
                    style={{
                      width: Math.random() * 4 + 1 + 'px',
                      height: Math.random() * 4 + 1 + 'px',
                      left: Math.random() * 100 + '%',
                      top: Math.random() * 100 + '%'
                    }}
                    animate={{
                      opacity: [0, 1, 0],
                      scale: [0.5, 1.5, 0.5]
                    }}
                    transition={{
                      duration: 2 + Math.random() * 3,
                      repeat: Infinity,
                      delay: Math.random() * 5
                    }}
                  />
                ))}
              </div>

              <BrainCircuit className="w-16 h-16 text-neon-green relative z-10 mb-2 drop-shadow-[0_0_10px_rgba(0,255,136,0.8)]" />
              <div className="text-[10px] font-black text-neon-green uppercase tracking-[0.4em] relative z-10">AI Swarm Core</div>

              {/* Scanning Pulse Layer */}
              <motion.div
                className="absolute inset-0 bg-gradient-to-t from-neon-green/20 to-transparent pointer-events-none"
                animate={{ top: ['100%', '-100%'] }}
                transition={{ duration: 3, repeat: Infinity, ease: "linear" }}
              />
            </div>

            {/* Orbiting Labels */}
            <div className="absolute -top-12 left-1/2 -translate-x-1/2 whitespace-nowrap px-4 py-1 rounded-full bg-neon-green/10 border border-neon-green/20 text-[9px] font-bold text-neon-green uppercase tracking-widest backdrop-blur-md">
              Synchronizing Neural Mesh
            </div>
          </motion.div>

          {/* Surrounding Agents Mapping */}
          {swarmAgents.map((agent, i) => {
            const angle = (i / swarmAgents.length) * Math.PI * 2;
            const x = Math.cos(angle) * 350;
            const y = Math.sin(angle) * 350;

            return (
              <motion.div
                key={agent.id}
                className={cn(
                  "absolute transition-all duration-300",
                  hoveredAgent === agent.id ? "z-50" : "z-30"
                )}
                style={{ x, y }}
                initial={{ opacity: 0, scale: 0 }}
                whileInView={{ opacity: 1, scale: 1 }}
                viewport={{ once: true }}
                transition={{ delay: i * 0.05, type: "spring", stiffness: 100 }}
              >
                <div
                  className="relative cursor-pointer group"
                  onMouseEnter={() => setHoveredAgent(agent.id)}
                  onMouseLeave={() => setHoveredAgent(null)}
                  onClick={() => setActiveAgent(agent)}
                >
                  <GlowCard
                    className={cn(
                      "w-48 p-4 bg-black/60 backdrop-blur-xl border border-white/5 transition-all duration-500",
                      hoveredAgent === agent.id ? "border-neon-green/50 -translate-y-2 scale-105 shadow-[0_0_30px_rgba(0,255,136,0.2)]" : ""
                    )}
                    glowColor="rgba(0,255,136,0.4)"
                  >
                    <div className="flex flex-col items-center text-center gap-3">
                      <div className="w-10 h-10 rounded-xl bg-neon-green/10 border border-neon-green/20 flex items-center justify-center group-hover:bg-neon-green/20 transition-colors">
                        <agent.icon className="w-5 h-5 text-neon-green" />
                      </div>
                      <div>
                        <div className="text-xs font-bold text-white mb-0.5">{agent.title}</div>
                        <div className="text-[9px] text-gray-500 uppercase tracking-wider">{agent.label}</div>
                      </div>
                    </div>

                    {/* Active Pulse Hole */}
                    <div className="absolute -top-1 -right-1">
                      <div className="w-2 h-2 rounded-full bg-neon-green animate-ping opacity-75" />
                      <div className="absolute inset-0 w-2 h-2 rounded-full bg-neon-green shadow-[0_0_8px_rgba(0,255,136,0.8)]" />
                    </div>
                  </GlowCard>

                  {/* Tooltip-style Capability Preview */}
                  <AnimatePresence>
                    {hoveredAgent === agent.id && (
                      <motion.div
                        initial={{ opacity: 0, scale: 0.9, y: y > 100 ? -10 : 10 }}
                        animate={{ opacity: 1, scale: 1, y: 0 }}
                        exit={{ opacity: 0, scale: 0.9, y: y > 100 ? -10 : 10 }}
                        className={cn(
                          "absolute left-0 right-0 p-3 bg-black/95 border border-neon-green/30 rounded-xl backdrop-blur-2xl z-[60] pointer-events-none shadow-2xl",
                          y > 100 ? "bottom-full mb-4" : "top-full mt-4"
                        )}
                      >
                        <div className="space-y-1.5">
                          {agent.capabilities.map(cap => (
                            <div key={cap} className="flex items-center gap-2">
                              <div className="w-1 h-1 rounded-full bg-neon-green" />
                              <span className="text-[9px] text-gray-300 font-bold uppercase tracking-wider">{cap}</span>
                            </div>
                          ))}
                        </div>
                      </motion.div>
                    )}
                  </AnimatePresence>
                </div>
              </motion.div>
            );
          })}
        </div>

        {/* Bottom Capability Cards */}
        <div className="mt-12 grid grid-cols-2 md:grid-cols-3 lg:grid-cols-6 gap-4">
          {platformCapabilities.map((cap, i) => (
            <motion.div
              key={cap.title}
              initial={{ opacity: 0, y: 20 }}
              whileInView={{ opacity: 1, y: 0 }}
              viewport={{ once: true }}
              transition={{ delay: 0.5 + i * 0.1 }}
              whileHover={{ y: -5, backgroundColor: 'rgba(0,255,136,0.1)' }}
              className="p-4 rounded-2xl bg-white/5 border border-white/10 flex flex-col items-center text-center gap-3 transition-colors cursor-default"
            >
              <cap.icon className="w-5 h-5 text-neon-green" />
              <div className="text-[10px] font-black text-gray-400 uppercase tracking-widest">{cap.title}</div>
            </motion.div>
          ))}
        </div>
      </div>

      {/* Detail Modal */}
      <AnimatePresence>
        {activeAgent && (
          <div className="fixed inset-0 z-[100] flex items-center justify-center p-6">
            <motion.div
              initial={{ opacity: 0 }}
              animate={{ opacity: 1 }}
              exit={{ opacity: 0 }}
              onClick={() => setActiveAgent(null)}
              className="absolute inset-0 bg-black/80 backdrop-blur-sm"
            />
            <motion.div
              initial={{ opacity: 0, scale: 0.9, y: 20 }}
              animate={{ opacity: 1, scale: 1, y: 0 }}
              exit={{ opacity: 0, scale: 0.9, y: 20 }}
              className="relative w-full max-w-lg bg-[#0A0F11] border border-neon-green/30 rounded-3xl p-8 shadow-[0_0_100px_rgba(0,255,136,0.2)]"
            >
              <button
                onClick={() => setActiveAgent(null)}
                className="absolute top-6 right-6 p-2 hover:bg-white/5 rounded-full transition-colors"
              >
                <X className="w-5 h-5 text-gray-400" />
              </button>

              <div className="flex items-center gap-6 mb-8">
                <div className="w-16 h-16 rounded-2xl bg-neon-green/10 border border-neon-green/20 flex items-center justify-center">
                  <activeAgent.icon className="w-8 h-8 text-neon-green" />
                </div>
                <div>
                  <h3 className="text-2xl font-black text-white font-outfit uppercase tracking-tight">{activeAgent.title}</h3>
                  <div className="text-neon-green text-xs font-bold uppercase tracking-[0.2em]">{activeAgent.label}</div>
                </div>
              </div>

              <p className="text-gray-400 text-base leading-relaxed mb-8">
                {activeAgent.description}
              </p>

              <div className="space-y-4">
                <div className="text-[10px] font-black text-gray-500 uppercase tracking-widest">Core Capabilities</div>
                <div className="grid grid-cols-1 gap-2">
                  {activeAgent.capabilities.map(cap => (
                    <div key={cap} className="flex items-center gap-3 p-3 rounded-xl bg-white/5 border border-white/10 group-hover:border-neon-green/30 transition-colors">
                      <div className="w-1.5 h-1.5 rounded-full bg-neon-green" />
                      <span className="text-sm font-bold text-gray-300">{cap}</span>
                    </div>
                  ))}
                </div>
              </div>

              <div className="mt-8 pt-8 border-t border-white/5 flex justify-between items-center text-[10px] font-mono font-bold text-gray-600">
                <span>AGENT_ID: {activeAgent.id.toUpperCase()}</span>
                <span className="text-neon-green/50">ENCRYPTED_DATA_MESH_ENABLED</span>
              </div>
            </motion.div>
          </div>
        )}
      </AnimatePresence>
    </section>
  );
}


/* ─── Comparison Table ─── */
const comparisonRows = [
  "OWASP Top 10 Scanning", "Advanced Vulnerability Detection", "AI-Powered Remediation",
  "Security Posture Analysis", "CI/CD Pipeline Integration",
  "Zero False-Positive Guarantee", "Real-Time Alert System", "Enterprise Compliance",
];

export function ComparisonTable() {
  const { isLight, borderSubtle } = useThemeColors();
  return (
    <section className="relative py-24">
      <div className="max-w-5xl mx-auto px-6">
        <GlowTitle
          mainText="Why"
          highlightText="Quantara Security"
          subtitle="See how we compare against legacy security tools."
        />
        <GlowCard
          initial={{ opacity: 0, y: 20 }}
          whileInView={{ opacity: 1, y: 0 }}
          viewport={{ once: true }}
          className="p-0 rounded-2xl overflow-hidden border-neon-green/20"
        >
          <div className="grid grid-cols-3 text-center text-xs font-bold uppercase tracking-wider py-4 px-6"
            style={{ borderBottom: `1px solid ${borderSubtle}` }}>
            <span className="text-text-secondary">Feature</span>
            <span className="text-neon-green glow-green-text">Quantara Security</span>
            <span className="text-text-muted">Others</span>
          </div>
          {comparisonRows.map((row, i) => (
            <div key={row} className={cn("grid grid-cols-3 text-center py-3.5 px-6 text-sm transition-colors", isLight ? "hover:bg-[#f9fafb]" : "hover:bg-white/[0.02]")}
              style={{ borderBottom: i < comparisonRows.length - 1 ? `1px solid ${borderSubtle}` : "none" }}>
              <span className="text-text-secondary text-left">{row}</span>
              <span className="text-neon-green">
                <svg className="w-5 h-5 mx-auto drop-shadow-neon" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="3"><polyline points="20 6 9 17 4 12" /></svg>
              </span>
              <span className="text-red-400/60">
                {i < 4 ? <svg className="w-5 h-5 mx-auto" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><line x1="18" y1="6" x2="6" y2="18" /><line x1="6" y1="6" x2="18" y2="18" /></svg>
                  : <svg className="w-5 h-5 mx-auto text-yellow-500/50" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><circle cx="12" cy="12" r="10" /><line x1="8" y1="12" x2="16" y2="12" /></svg>}
              </span>
            </div>
          ))}
        </GlowCard>
      </div>
    </section>
  );
}

/* ─── Pricing Section ─── */
const tiers = [
  {
    name: "Free",
    price: "0",
    desc: "Perfect for students and early researchers.",
    features: [
      "10 Scans per Month",
      "Advance AI Remediation Co-Pilot",
      "Autonomous AI Agents",
      "POC Verification",
      "Attack Path Intelligence and Simulation",
      "Quantara HTTP ToolKit",
      "OWASP Top 10 Coverage",
      "Community Support",
    ],
    glow: "rgba(0, 255, 136, 0.05)",
  },
  {
    name: "Pro",
    price: "5",
    desc: "Advanced security for professional developers.",
    features: [
      "200 Scans per Month",
      "Advance AI Remediation Co-Pilot",
      "Autonomous AI Agents",
      "POC Verification",
      "Attack Path Intelligence and Simulation",
      "Priority API Access",
      "Quantara HTTP ToolKit",
      "OWASP Top 10 Coverage",
      "Email Support",
      "Community Support",
    ],
    glow: "rgba(0, 163, 255, 0.1)",
    recommended: true,
  },
  {
    name: "Elite",
    price: "10",
    desc: "Full-scale protection for enterprise teams.",
    features: [
      "Unlimited Security Scans",
      "Advance AI Remediation Co-Pilot",
      "Autonomous AI Agents",
      "POC Verification",
      "Attack Path Intelligence and Simulation",
      "Quantara HTTP ToolKit",
      "Priority API Access",
      "Custom Policy Engine",
      "OWASP Top 10 Coverage",
      "24/7 Technical Support",
      "Email Support",
      "Community Support",
    ],
    glow: "rgba(0, 255, 136, 0.15)",
  },
];

export function Pricing() {
  const { isLight, accent } = useThemeColors();
  return (
    <section id="pricing" className="relative py-24 scroll-mt-24">
      <div className="max-w-7xl mx-auto px-6">
        <GlowTitle
          mainText="Future-Ready"
          highlightText="Pricing"
          subtitle="Scalable security intelligence tailored to your infrastructure needs."
        />

        <div className="grid md:grid-cols-3 gap-8">
          {tiers.map((t, i) => (
            <GlowCard
              key={t.name}
              initial={{ opacity: 0, y: 30 }}
              whileInView={{ opacity: 1, y: 0 }}
              transition={{ duration: 0.6, delay: i * 0.12 }}
              viewport={{ once: true }}
              glowColor={t.glow}
              className={cn(
                "p-8 flex flex-col h-full relative",
                t.recommended ? "border-neon-green/30 shadow-[0_0_40px_rgba(0,255,136,0.1)] scale-105 z-10" : "border-border-green"
              )}
            >
              {t.recommended && (
                <div className="absolute -top-4 left-1/2 -translate-x-1/2 px-4 py-1 rounded-full bg-neon-green text-white text-[10px] font-black uppercase tracking-widest" style={!isLight ? { color: "#0B0F0C" } : undefined}>
                  Most Popular
                </div>
              )}
              <div className="mb-8">
                <h3 className="text-xl font-bold text-text-primary font-outfit uppercase tracking-wider">{t.name}</h3>
                <div className="flex items-baseline gap-1 mt-4">
                  <span className="text-4xl font-black text-text-primary font-outfit">${t.price}</span>
                  <span className="text-text-muted text-sm">/month</span>
                </div>
                <p className="text-text-secondary text-sm mt-4 leading-relaxed">{t.desc}</p>
              </div>

              <div className="space-y-4 flex-1">
                {t.features.map(f => (
                  <div key={f} className="flex items-center gap-3">
                    <div className="w-5 h-5 rounded-full bg-neon-green/10 flex items-center justify-center shrink-0">
                      <svg className="w-3 h-3 text-neon-green" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="4"><polyline points="20 6 9 17 4 12" /></svg>
                    </div>
                    <span className="text-sm text-text-secondary font-medium">{f}</span>
                  </div>
                ))}
              </div>

              <button type="button" className={cn(
                "w-full mt-10 py-4 rounded-xl font-black text-xs uppercase tracking-[0.2em] transition-all",
                t.recommended
                  ? "bg-neon-green text-white shadow-[0_0_20px_rgba(0,255,136,0.4)] hover:shadow-[0_0_30px_rgba(0,255,136,0.6)]"
                  : isLight
                    ? "bg-[#f3f5fb] text-text-primary border border-border-green hover:bg-[#eef1ff]"
                    : "bg-white/5 text-white border border-white/10 hover:bg-white/10"
              )} style={t.recommended && !isLight ? { color: "#0B0F0C" } : undefined}>
                Initialize Plan
              </button>
            </GlowCard>
          ))}
        </div>
      </div>
    </section>
  );
}

/* ─── Social Proof ─── */
const testimonials = [
  { name: "Alex Rivera", role: "CTO, FinVault", quote: "Quantara Security detected 47 exposed credentials our previous tools missed entirely. The advanced vulnerability mapping is a game-changer." },
  { name: "Sarah Chen", role: "Lead Security Engineer, CloudNova", quote: "The AI-powered remediation cut our incident response time by 80%. It's like having a senior security analyst on call 24/7." },
  { name: "Marcus Webb", role: "VP Engineering, DataForge", quote: "Security infrastructure planning used to take months. With the advanced scanning engine, we mapped our entire security posture in under a week." },
];

export function SocialProof() {
  const { borderSubtle } = useThemeColors();
  return (
    <section className="relative py-24 gradient-section-glow">
      <div className="max-w-7xl mx-auto px-6">
        <GlowTitle
          mainText="Trusted by"
          highlightText="1,000+ Developers"
          subtitle="Security experts and engineering teams worldwide rely on Quantara Security."
        />
        <div className="grid md:grid-cols-3 gap-6">
          {testimonials.map((t, i) => (
            <GlowCard key={t.name}
              initial={{ opacity: 0, y: 30 }}
              whileInView={{ opacity: 1, y: 0 }}
              transition={{ duration: 0.6, delay: i * 0.15 }}
              viewport={{ once: true }}
              className="p-8"
            >
              <div className="flex items-center gap-1 mb-4">
                {[...Array(5)].map((_, j) => <svg key={j} className="w-4 h-4 text-neon-green" viewBox="0 0 24 24" fill="currentColor"><path d="M12 2l3.09 6.26L22 9.27l-5 4.87 1.18 6.88L12 17.77l-6.18 3.25L7 14.14 2 9.27l6.91-1.01L12 2z" /></svg>)}
              </div>
              <p className="text-text-secondary text-sm leading-relaxed mb-6 italic">"{t.quote}"</p>
              <div>
                <p className="text-text-primary font-bold text-sm">{t.name}</p>
                <p className="text-text-muted text-xs">{t.role}</p>
              </div>
            </GlowCard>
          ))}
        </div>
        <motion.div initial={{ opacity: 0 }} whileInView={{ opacity: 1 }} viewport={{ once: true }}
          className="flex flex-wrap justify-center gap-8 mt-16 pt-8" style={{ borderTop: `1px solid ${borderSubtle}` }}>
          {[{ n: "1,200+", l: "Active Users" }, { n: "50M+", l: "Scans Completed" }, { n: "99.97%", l: "Uptime SLA" }, { n: "< 2min", l: "Avg Detection" }].map(s => (
            <div key={s.l} className="text-center px-6">
              <div className="text-2xl font-extrabold font-outfit text-neon-green glow-green-text">{s.n}</div>
              <div className="text-xs text-text-muted mt-1 uppercase tracking-wider">{s.l}</div>
            </div>
          ))}
        </motion.div>
      </div>
    </section>
  );
}
