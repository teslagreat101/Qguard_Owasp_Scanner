"use client";

import dynamic from "next/dynamic";
import { useState, useEffect } from "react";
import { motion } from "framer-motion";
import Image from "next/image";
import QuantaraLogo from "@/components/data/Quantara_Logo.png";
import { Button } from "@/components/ui/button";
import { useAppShortcuts } from "@/hooks/use-keyboard-shortcuts";
import { EmailVerificationCheck } from "@/components/email-verification-check";
import { ArrowRight, Cpu } from "lucide-react";
import Link from "next/link";
import { useTheme } from "next-themes";
import { ThemeToggle } from "@/components/theme-toggle";

// Heavy components — lazy-loaded so the shell renders instantly
const PlexusBackground = dynamic(() => import("@/components/homepage/PlexusBackground"), { ssr: false });
const NeuralHeroVisual = dynamic(() => import("@/components/homepage/HeroTerminal"), { ssr: false });
const DottedSurface = dynamic(
  () => import("@/components/ui/dotted-surface").then((m) => ({ default: m.DottedSurface })),
  { ssr: false }
);
const TypewriterEffectSmooth = dynamic(
  () => import("@/components/ui/typewriter-effect").then((m) => ({ default: m.TypewriterEffectSmooth })),
  { ssr: false }
);
const LogoCloud = dynamic(
  () => import("@/components/ui/logo-cloud-4").then((m) => ({ default: m.LogoCloud })),
  { ssr: false }
);

export default function HomePage() {
  useAppShortcuts();
  const [hydrated, setHydrated] = useState(false);
  const { resolvedTheme } = useTheme();
  const isLight = resolvedTheme === "light";

  useEffect(() => {
    setHydrated(true);
  }, []);

  const handleHeroAction = () => {
    window.location.href = "/login";
  };

  // Theme-aware colors
  const accent = isLight ? "#6c63ff" : "#00FF88";
  const accentBg = isLight ? "rgba(108,99,255,0.08)" : "rgba(0,255,136,0.08)";
  const accentBorder = isLight ? "rgba(108,99,255,0.15)" : "rgba(0,255,136,0.15)";
  const accentBorderMed = isLight ? "rgba(108,99,255,0.25)" : "rgba(0,255,136,0.25)";
  const borderSubtle = isLight ? "#e6e9f2" : "rgba(0,255,136,0.08)";

  return (
    <EmailVerificationCheck>
      <div className="min-h-screen bg-deep selection:bg-neon-green/20">

        {/* ─── Navbar — renders immediately (lightweight) ─── */}
        <nav className="fixed top-0 left-0 right-0 z-50 glass-nav">
          <div className="max-w-7xl mx-auto px-6 h-20 flex items-center justify-between">
            <div className="flex items-center gap-3 md:gap-4 group cursor-pointer" onClick={() => window.scrollTo({ top: 0, behavior: 'smooth' })}>
              <div className="relative w-14 h-14 md:w-20 md:h-20 flex-shrink-0 flex items-center justify-center">
                <video
                  src="/Quantara_Animated_Logo.mp4"
                  autoPlay
                  loop
                  muted
                  playsInline
                  aria-label="Quantara Security Logo"
                  className="relative z-10 w-full h-full object-contain group-hover:scale-110 transition-transform drop-shadow-neon rounded-lg"
                />
                {!isLight && <div className="absolute inset-0 bg-neon-green/10 blur-xl rounded-full animate-green-glow" />}
              </div>
              <span className="text-xl font-extrabold font-outfit tracking-tight text-foreground">
                Quantara <span className="text-neon-green">Security</span>
              </span>
            </div>

            <div className="flex items-center gap-8">
              <div className="hidden md:flex items-center gap-6">
                {[
                  { name: "Features", id: "features" },
                  { name: "Compare", id: "compare" },
                  { name: "Pricing", id: "pricing" },
                  { name: "Community", id: "community" },
                ].map((item) => (
                  <span key={item.name}
                    onClick={() => document.getElementById(item.id)?.scrollIntoView({ behavior: 'smooth' })}
                    className="text-[11px] font-bold uppercase tracking-[0.15em] text-muted-foreground hover:text-neon-green cursor-pointer transition-colors duration-300">
                    {item.name}
                  </span>
                ))}
                <Link
                  href="/docs"
                  className="text-[11px] font-bold uppercase tracking-[0.15em] text-muted-foreground hover:text-neon-green transition-colors duration-300"
                >
                  Docs
                </Link>
              </div>
              <ThemeToggle variant="navbar" />
              <div className="h-5 w-px hidden md:block" style={{ background: accentBorder }} />
              <Link href="/login">
                <Button variant="outline"
                  className="h-10 px-6 font-bold tracking-widest uppercase text-[10px] transition-all duration-300 rounded-xl border-neon-green/25 bg-neon-green/5 text-neon-green hover:bg-neon-green/10 hover:border-neon-green/40"
                  style={{ boxShadow: `0 0 15px ${isLight ? "rgba(108,99,255,0.05)" : "rgba(0,255,136,0.05)"}` }}>
                  Access Portal
                </Button>
              </Link>
            </div>
          </div>
        </nav>

        {/* Background — loads async, won't block render */}
        {hydrated && <PlexusBackground />}

        <div className="relative z-10 pb-24 pt-20">

          {/* ─── Hero Section ─── */}
          <section className="relative min-h-[90vh] flex flex-col items-center justify-center px-6 overflow-hidden gradient-hero-green">
            {hydrated && <DottedSurface className="z-0 opacity-70" />}

            {/* Ambient glow orbs */}
            {!isLight && (
              <>
                <div className="absolute top-1/4 left-1/4 w-[500px] h-[500px] rounded-full bg-primary/[0.03] blur-[120px] pointer-events-none" />
                <div className="absolute bottom-1/3 right-1/4 w-[400px] h-[400px] rounded-full bg-[#00C853]/[0.04] blur-[100px] pointer-events-none" />
              </>
            )}

            <div className="max-w-7xl mx-auto w-full grid lg:grid-cols-2 gap-12 items-center">
              <div className="space-y-8 text-left order-2 lg:order-1">
                <motion.div initial={{ opacity: 0, x: -50 }} animate={{ opacity: 1, x: 0 }} transition={{ duration: 1 }}>
                  <div className="inline-flex items-center gap-2 px-4 py-1.5 rounded-full mb-6"
                    style={{ background: accentBg, border: `1px solid ${accentBorderMed}`, boxShadow: `0 0 20px ${accentBg}` }}>
                    <Cpu className="w-3.5 h-3.5 text-neon-green animate-pulse" />
                    <span className="text-neon-green text-[10px] font-bold tracking-widest uppercase">V3.0 Advanced Security Engine</span>
                  </div>

                  <div className="mb-6">
                    {hydrated ? (
                      <TypewriterEffectSmooth
                        words={[
                          { text: "Quantara", className: "text-foreground" },
                          { text: "Security", className: "text-neon-green" },
                        ]}
                        className="text-5xl md:text-7xl font-extrabold font-outfit tracking-tight border-none"
                        cursorClassName="h-8 md:h-12 lg:h-16 bg-neon-green"
                      />
                    ) : (
                      <h1 className="text-5xl md:text-7xl font-extrabold font-outfit tracking-tight">
                        <span className="text-foreground">Quantara </span>
                        <span className="text-neon-green">Security</span>
                      </h1>
                    )}
                  </div>

                  <p className="text-lg md:text-xl text-foreground leading-relaxed max-w-xl mb-8">
                    Identify exposed credentials, API vulnerabilities, and configuration weaknesses with a platform built for modern secure applications.
                  </p>

                  <div className="flex flex-wrap gap-4">
                    <motion.div whileHover={{ scale: 1.03 }} whileTap={{ scale: 0.97 }}>
                      <Button size="lg" onClick={handleHeroAction}
                        className="h-14 px-8 btn-neon text-sm font-extrabold tracking-widest uppercase">
                        Initialize Scan <ArrowRight className="ml-2 w-5 h-5" />
                      </Button>
                    </motion.div>
                  </div>
                </motion.div>
              </div>

              <motion.div initial={{ opacity: 0, scale: 0.85 }} animate={{ opacity: 1, scale: 1 }} transition={{ duration: 1.2, ease: "easeOut" }}
                className="order-1 lg:order-2 flex justify-center items-center">
                {hydrated ? <NeuralHeroVisual /> : (
                  <div className="w-full max-w-lg aspect-[4/3] rounded-xl animate-pulse" style={{ background: accentBg, border: `1px solid ${accentBorder}` }} />
                )}
              </motion.div>
            </div>

            {/* Scroll indicator */}
            <motion.div animate={{ y: [0, 10, 0] }} transition={{ duration: 2, repeat: Infinity }}
              className="absolute bottom-10 left-1/2 -translate-x-1/2">
              <div className="w-6 h-10 rounded-full border border-neon-green/20 flex justify-center p-1">
                <div className="w-1 h-3 bg-neon-green rounded-full animate-bounce" />
              </div>
            </motion.div>
          </section>

          {/* Below-fold sections — lazy loaded */}
          {hydrated && <HomepageSections />}
        </div>

        {/* ─── Footer ─── */}
        <footer className="relative border-t pt-32 overflow-hidden" style={{ borderColor: borderSubtle, background: isLight ? "linear-gradient(180deg, #f6f8fb 0%, #eef1ff 100%)" : "linear-gradient(180deg, rgba(11,15,12,0.6) 0%, rgba(0,0,0,0.9) 100%)" }}>
          {!isLight && <div className="absolute bottom-0 left-1/2 -translate-x-1/2 w-[800px] h-[300px] bg-primary/[0.04] blur-[120px] rounded-full pointer-events-none" />}

          <div className="max-w-4xl mx-auto px-6 mb-32 text-center relative z-10">
            <motion.div initial={{ opacity: 0, scale: 0.9 }} whileInView={{ opacity: 1, scale: 1 }} viewport={{ once: true }}
              className="inline-flex items-center gap-2 px-4 py-1.5 rounded-full mb-10"
              style={{ background: accentBg, border: `1px solid ${accentBorder}` }}>
              <div className="w-1.5 h-1.5 rounded-full bg-neon-green animate-pulse" style={{ boxShadow: `0 0 8px ${accent}` }} />
              <span className="text-neon-green text-[10px] font-bold tracking-[0.2em] uppercase">System Status: Optimal</span>
            </motion.div>

            <h2 className="text-5xl md:text-7xl font-extrabold font-outfit tracking-tight text-foreground mb-0">
              Protect your <span className="text-neon-green glow-green-text">Source Code.</span>
            </h2>
            <p className="text-foreground max-w-2xl mx-auto text-lg leading-relaxed mb-10 mt-6">
              The ultimate engine for detecting leaked secrets, API keys, and credentials before they hit production.
            </p>
            <motion.div whileHover={{ scale: 1.03 }} whileTap={{ scale: 0.97 }} className="inline-block">
              <Link href="/login">
                <Button className="h-14 px-10 btn-neon text-sm font-extrabold tracking-widest uppercase">
                  Get Started Free <ArrowRight className="ml-2 w-5 h-5" />
                </Button>
              </Link>
            </motion.div>
          </div>

          <div className="section-divider-thick mb-20" />

          {/* Footer links */}
          <div className="max-w-7xl mx-auto px-6 mb-20 relative z-10">
            <div className="grid grid-cols-2 md:grid-cols-3 lg:grid-cols-5 gap-12 lg:gap-8">
              <div className="col-span-2 lg:col-span-1 space-y-6">
                <div className="flex items-center gap-2">
                  <div className="w-14 h-14 rounded-lg flex items-center justify-center" style={{ background: accentBg, border: `1px solid ${accentBorderMed}` }}>
                    <Image src={QuantaraLogo} alt="Quantara Security Logo" width={40} height={40} />
                  </div>
                  <span className="text-base font-extrabold font-outfit text-foreground">
                    Quantara <span className="text-neon-green font-mono text-sm ml-1">Security</span>
                  </span>
                </div>
                <p className="text-muted-foreground text-sm leading-relaxed">
                  Enterprise-grade credential detection & security vulnerability scanning for modern dev teams.
                </p>
                <div className="flex gap-3">
                  <a href="https://twitter.com" target="_blank" rel="noopener noreferrer" title="Follow us on Twitter" aria-label="Twitter"
                    className="w-9 h-9 rounded-lg flex items-center justify-center cursor-pointer transition-all duration-300 group/social"
                    style={{ background: accentBg, border: `1px solid ${accentBorder}` }}>
                    <svg className="w-4 h-4 text-muted-foreground group-hover/social:text-neon-green transition-colors" fill="currentColor" viewBox="0 0 24 24">
                      <path d="M18.244 2.25h3.308l-7.227 8.26 8.502 11.24H16.17l-4.714-6.231-5.401 6.231H2.748l7.73-8.835L1.254 2.25H8.08l4.261 5.632 5.903-5.632Zm-1.161 17.52h1.833L7.084 4.126H5.117Z" />
                    </svg>
                  </a>
                  <a href="https://discord.com" target="_blank" rel="noopener noreferrer" title="Join our Discord" aria-label="Discord"
                    className="w-9 h-9 rounded-lg flex items-center justify-center cursor-pointer transition-all duration-300 group/social"
                    style={{ background: accentBg, border: `1px solid ${accentBorder}` }}>
                    <svg className="w-4 h-4 text-muted-foreground group-hover/social:text-neon-green transition-colors" fill="currentColor" viewBox="0 0 24 24">
                      <path d="M20.317 4.37a19.791 19.791 0 0 0-4.885-1.515.074.074 0 0 0-.079.037c-.21.375-.444.864-.608 1.25a18.27 18.27 0 0 0-5.487 0 12.64 12.64 0 0 0-.617-1.25.077.077 0 0 0-.079-.037A19.736 19.736 0 0 0 3.677 4.37a.07.07 0 0 0-.032.027C.533 9.046-.32 13.58.099 18.057c.002.022.015.043.033.054a19.9 19.9 0 0 0 5.993 3.03.078.078 0 0 0 .084-.028c.462-.63.874-1.295 1.226-1.994a.076.076 0 0 0-.041-.106 13.107 13.107 0 0 1-1.872-.892.077.077 0 0 1-.008-.128 10.2 10.2 0 0 0 .372-.292.074.074 0 0 1 .077-.01c3.928 1.793 8.18 1.793 12.062 0a.074.074 0 0 1 .078.01c.12.098.246.198.373.292a.077.077 0 0 1-.006.127 12.299 12.299 0 0 1-1.873.892.077.077 0 0 0-.041.107c.36.698.772 1.362 1.225 1.993a.076.076 0 0 0 .084.028 19.839 19.839 0 0 0 6.002-3.03.077.077 0 0 0 .032-.054c.5-5.177-.838-9.674-3.549-13.66a.061.061 0 0 0-.031-.03ZM8.02 15.33c-1.183 0-2.157-1.085-2.157-2.419 0-1.333.956-2.419 2.157-2.419 1.21 0 2.176 1.096 2.157 2.42 0 1.333-.956 2.418-2.157 2.418Zm7.975 0c-1.183 0-2.157-1.085-2.157-2.419 0-1.333.955-2.419 2.157-2.419 1.21 0 2.176 1.096 2.157 2.42 0 1.333-.946 2.418-2.157 2.418Z" />
                    </svg>
                  </a>
                  <a href="https://youtube.com" target="_blank" rel="noopener noreferrer" title="Watch us on YouTube" aria-label="YouTube"
                    className="w-9 h-9 rounded-lg flex items-center justify-center cursor-pointer transition-all duration-300 group/social"
                    style={{ background: accentBg, border: `1px solid ${accentBorder}` }}>
                    <svg className="w-4 h-4 text-muted-foreground group-hover/social:text-neon-green transition-colors" fill="currentColor" viewBox="0 0 24 24">
                      <path d="M23.498 6.186a3.016 3.016 0 0 0-2.122-2.136C19.505 3.545 12 3.545 12 3.545s-7.505 0-9.377.505A3.017 3.017 0 0 0 .502 6.186C0 8.07 0 12 0 12s0 3.93.502 5.814a3.016 3.016 0 0 0 2.122 2.136c1.871.505 9.376.505 9.376.505s7.505 0 9.377-.505a3.015 3.015 0 0 0 2.122-2.136C24 15.93 24 12 24 12s0-3.93-.502-5.814ZM9.545 15.568V8.432L15.818 12l-6.273 3.568Z" />
                    </svg>
                  </a>
                </div>
              </div>

              {[
                {
                  title: "Product", items: [
                    { label: "Features", href: "#features" },
                    { label: "Integrations", href: "#" },
                    { label: "Pricing", href: "#pricing" },
                    { label: "Roadmap", href: "#" },
                  ]
                },
                {
                  title: "Resources", items: [
                    { label: "Documentation", href: "/docs" },
                    { label: "API Reference", href: "/docs/api-key-setup" },
                  ]
                },
                {
                  title: "Company", items: [
                    { label: "About Us", href: "#" },
                    { label: "Contact", href: "#" },
                    { label: "Legal / Privacy", href: "#" },
                  ]
                },
              ].map(col => (
                <div key={col.title}>
                  <h4 className="text-foreground font-bold text-xs uppercase tracking-[0.2em] mb-8">{col.title}</h4>
                  <ul className="space-y-4 text-muted-foreground text-sm">
                    {col.items.map(item => (
                      <li key={item.label}>
                        <Link href={item.href} className="hover:text-neon-green cursor-pointer transition-colors">
                          {item.label}
                        </Link>
                      </li>
                    ))}
                  </ul>
                </div>
              ))}

              <div className="col-span-2 lg:col-span-1">
                <div className="p-7 rounded-2xl space-y-5" style={{ background: "var(--bg-card)", border: `1px solid ${borderSubtle}` }}>
                  <div>
                    <h4 className="text-foreground font-bold text-lg mb-1 font-outfit">Ready to secure?</h4>
                    <p className="text-muted-foreground text-sm">Join 1,000+ security teams.</p>
                  </div>
                  <Link href="/login">
                    <Button className="w-full h-12 btn-neon text-xs font-extrabold tracking-widest uppercase">GET STARTED</Button>
                  </Link>
                </div>
              </div>
            </div>
          </div>

          {/* Bottom bar */}
          <div className="py-8" style={{ borderTop: `1px solid ${borderSubtle}` }}>
            <div className="max-w-7xl mx-auto px-6 flex flex-col md:flex-row items-center justify-between gap-6">
              <div className="flex items-center gap-3 text-neon-green/50 font-mono text-[10px] tracking-widest font-bold">
                <div className="w-2 h-2 rounded-full bg-neon-green animate-pulse" style={{ boxShadow: `0 0 8px ${accent}` }} />
                ALL SYSTEMS SECURE — SCANNING ACTIVE
              </div>
              <div className="text-muted-foreground/60 text-[10px] font-bold tracking-wider">
                © 2026 Quantara Security. BUILT FOR THE SECURE WEB.
              </div>
              <div className="flex gap-8 text-muted-foreground/60 text-[10px] font-bold tracking-wider">
                {["Privacy", "Terms", "Cookies"].map(item => (
                  <span key={item} className="hover:text-neon-green cursor-pointer transition-colors">{item.toUpperCase()}</span>
                ))}
              </div>
            </div>
          </div>
        </footer>

        <style jsx global>{`
          .font-outfit { font-family: var(--font-outfit), system-ui, sans-serif; }
          .animate-green-glow {
            animation: green-glow 4s ease-in-out infinite;
          }
          @keyframes green-glow {
            0%, 100% { opacity: 0.3; transform: scale(1); }
            50% { opacity: 0.6; transform: scale(1.1); }
          }
        `}</style>
      </div >
    </EmailVerificationCheck >
  );
}

/**
 * Below-fold homepage sections — loaded lazily after hydration.
 * Wrapped in a component so the dynamic import resolves cleanly.
 */
function HomepageSections() {
  const { TrustMetrics, FeatureCards, MultiAgentSection, CoreOfferings, ComparisonTable, SocialProof, Pricing } = require("@/components/homepage/Sections");
  const { LogoCloud, defaultLogos } = require("@/components/ui/logo-cloud-4");

  return (
    <>
      <LogoCloud logos={defaultLogos} />
      <TrustMetrics />
      <FeatureCards />
      <div className="section-divider max-w-5xl mx-auto" />
      <MultiAgentSection />
      <div className="section-divider max-w-5xl mx-auto" />
      <CoreOfferings />
      <div className="section-divider max-w-5xl mx-auto" />
      <div id="compare"><ComparisonTable /></div>
      <div className="section-divider max-w-5xl mx-auto" />
      <Pricing />
      <div className="section-divider max-w-5xl mx-auto" />
      <div id="community"><SocialProof /></div>
    </>
  );
}
