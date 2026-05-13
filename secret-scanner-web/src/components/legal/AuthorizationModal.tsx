"use client";

import React, { useEffect, useRef, useState } from "react";
import { Shield, AlertTriangle, LogOut, ChevronRight, Lock, FileText } from "lucide-react";
import { TermsContent } from "./TermsContent";
import { AgreementCheckbox } from "./AgreementCheckbox";
import { cn } from "@/lib/utils";

export const TERMS_VERSION = "v1.0-2025";

interface AuthorizationModalProps {
  /** Called when the user accepts the terms */
  onAccept: () => void | Promise<void>;
  /** Called when the user declines the terms */
  onDecline: () => void | Promise<void>;
  /** Whether the accept action is loading */
  isLoading?: boolean;
}

export function AuthorizationModal({ onAccept, onDecline, isLoading = false }: AuthorizationModalProps) {
  const [agreed, setAgreed] = useState(false);
  const [accepting, setAccepting] = useState(false);
  const [declining, setDeclining] = useState(false);
  const [scrolledToBottom, setScrolledToBottom] = useState(false);
  const scrollRef = useRef<HTMLDivElement>(null);

  // Disable Escape key — modal is non-dismissible
  useEffect(() => {
    const handleKeyDown = (e: KeyboardEvent) => {
      if (e.key === "Escape") {
        e.preventDefault();
        e.stopPropagation();
      }
    };
    window.addEventListener("keydown", handleKeyDown, { capture: true });
    return () => window.removeEventListener("keydown", handleKeyDown, { capture: true });
  }, []);

  // Lock body scroll
  useEffect(() => {
    const prev = document.body.style.overflow;
    document.body.style.overflow = "hidden";
    return () => { document.body.style.overflow = prev; };
  }, []);

  // Track scroll position
  const handleScroll = () => {
    const el = scrollRef.current;
    if (!el) return;
    const atBottom = el.scrollTop + el.clientHeight >= el.scrollHeight - 40;
    if (atBottom) setScrolledToBottom(true);
  };

  const handleAccept = async () => {
    if (!agreed || accepting) return;
    setAccepting(true);
    try {
      await onAccept();
    } finally {
      setAccepting(false);
    }
  };

  const handleDecline = async () => {
    if (declining) return;
    setDeclining(true);
    try {
      await onDecline();
    } finally {
      setDeclining(false);
    }
  };

  return (
    /* Full-screen overlay — pointer-events-none on outside click area */
    <div
      className="fixed inset-0 z-[200] flex items-center justify-center p-4"
      style={{ background: "rgba(5, 5, 5, 0.92)", backdropFilter: "blur(12px)" }}
      /* No onClick on the outer div — intentionally non-dismissible */
    >
      {/* Ambient glow behind modal */}
      <div className="absolute top-1/4 left-1/2 -translate-x-1/2 w-[600px] h-[400px] rounded-full bg-primary/[0.04] blur-[100px] pointer-events-none" />
      <div className="absolute bottom-1/4 left-1/2 -translate-x-1/2 w-[400px] h-[300px] rounded-full bg-red-500/[0.03] blur-[80px] pointer-events-none" />

      {/* Modal panel */}
      <div
        className={cn(
          "relative w-full max-w-[800px] max-h-[90vh] flex flex-col",
          "rounded-2xl overflow-hidden",
          "bg-background/98 border border-primary/20",
          "shadow-[0_0_80px_rgba(0,255,136,0.08),0_0_0_1px_rgba(0,255,136,0.05),inset_0_1px_0_rgba(0,255,136,0.08)]",
        )}
        role="dialog"
        aria-modal="true"
        aria-labelledby="auth-modal-title"
        aria-describedby="auth-modal-desc"
        /* Prevent clicks inside from bubbling to outer overlay */
        onClick={(e) => e.stopPropagation()}
      >
        {/* ── Top scanning laser ─────────────────────────────── */}
        <div
          className="absolute top-0 left-0 right-0 h-[1px] pointer-events-none"
          style={{
            background: "linear-gradient(90deg, transparent 0%, #00FF88 50%, transparent 100%)",
            boxShadow: "0 0 20px 4px rgba(0,255,136,0.4)",
            animation: "scanline 3s ease-in-out infinite",
          }}
        />

        {/* ── Critical warning banner ─────────────────────────── */}
        <div className="flex items-center gap-3 px-6 py-3 bg-[#FF3B30]/10 border-b border-[#FF3B30]/20 shrink-0">
          <AlertTriangle className="w-4 h-4 text-[#FF3B30] shrink-0 animate-pulse" />
          <p className="text-[10px] font-black text-[#FF3B30] uppercase tracking-[0.15em]">
            CRITICAL LEGAL NOTICE — Unauthorized access to computer systems is a criminal offence.
            This platform is for authorized security professionals only.
          </p>
        </div>

        {/* ── Header ─────────────────────────────────────────── */}
        <div className="flex items-center gap-4 px-6 py-5 border-b border-primary/10 shrink-0 bg-gradient-to-r from-[#00FF88]/5 to-transparent">
          {/* Shield icon */}
          <div className="relative w-12 h-12 flex items-center justify-center shrink-0">
            <div className="absolute inset-0 rounded-xl bg-primary/10 border border-primary/30" />
            <div className="absolute inset-0 rounded-xl bg-primary/5 blur-md" />
            <Shield className="relative w-6 h-6 text-primary z-10" />
          </div>
          <div className="flex-1 min-w-0">
            <div className="flex items-center gap-2 mb-0.5">
              <h2
                id="auth-modal-title"
                className="text-base font-black text-white uppercase tracking-tight"
              >
                Authorization &amp; Legal Terms Agreement
              </h2>
              <span className="text-[9px] font-black text-primary bg-primary/10 border border-primary/20 px-2 py-0.5 rounded-full uppercase tracking-widest">
                {TERMS_VERSION}
              </span>
            </div>
            <p
              id="auth-modal-desc"
              className="text-[10px] text-muted-foreground uppercase tracking-widest font-bold"
            >
              Quantara Security Platform — Mandatory Acceptance Required
            </p>
          </div>
          <div className="flex items-center gap-1.5 shrink-0">
            <Lock className="w-3 h-3 text-primary" />
            <span className="text-[9px] text-muted-foreground uppercase tracking-widest font-bold">
              Non-Dismissible
            </span>
          </div>
        </div>

        {/* ── Scroll indicator ────────────────────────────────── */}
        {!scrolledToBottom && (
          <div className="shrink-0 px-6 py-2 bg-primary/5 border-b border-primary/10 flex items-center gap-2">
            <FileText className="w-3 h-3 text-primary/60" />
            <p className="text-[9px] text-primary/60 uppercase tracking-widest font-bold">
              Scroll to review all terms before accepting
            </p>
          </div>
        )}

        {/* ── Scrollable terms body ────────────────────────────── */}
        <div
          ref={scrollRef}
          onScroll={handleScroll}
          className="flex-1 overflow-y-auto px-6 py-5 min-h-0 custom-scrollbar"
          style={{
            scrollbarWidth: "thin",
            scrollbarColor: "rgba(0,255,136,0.3) rgba(0,255,136,0.05)",
          }}
        >
          <TermsContent />
        </div>

        {/* ── Footer: checkbox + buttons ──────────────────────── */}
        <div className="shrink-0 border-t border-primary/10 bg-background px-6 py-5 space-y-4">
          {/* Agreement checkbox */}
          <AgreementCheckbox
            checked={agreed}
            onChange={setAgreed}
            disabled={accepting || declining}
          />

          {/* Action buttons */}
          <div className="flex items-center gap-3">
            {/* Decline */}
            <button
              type="button"
              onClick={handleDecline}
              disabled={accepting || declining}
              className={cn(
                "flex items-center gap-2 px-5 py-2.5 rounded-xl text-[11px] font-black uppercase tracking-widest",
                "border border-[#FF3B30]/30 text-[#FF3B30]/70",
                "hover:bg-[#FF3B30]/10 hover:border-[#FF3B30]/50 hover:text-[#FF3B30]",
                "disabled:opacity-40 disabled:cursor-not-allowed",
                "transition-all duration-200",
              )}
            >
              {declining ? (
                <div className="w-3 h-3 border-2 border-[#FF3B30]/40 border-t-[#FF3B30] rounded-full animate-spin" />
              ) : (
                <LogOut className="w-3.5 h-3.5" />
              )}
              {declining ? "Logging Out..." : "Decline & Exit"}
            </button>

            {/* Spacer */}
            <div className="flex-1" />

            {/* RBAC role indicator */}
            <div className="text-[9px] text-muted-foreground uppercase tracking-widest font-bold hidden sm:block">
              Role: Security Analyst
            </div>

            {/* Accept */}
            <button
              type="button"
              onClick={handleAccept}
              disabled={!agreed || accepting || declining}
              className={cn(
                "relative flex items-center gap-2.5 px-6 py-2.5 rounded-xl text-[11px] font-black uppercase tracking-widest overflow-hidden",
                "transition-all duration-300",
                agreed
                  ? [
                      "bg-primary/15 border border-primary/50 text-primary",
                      "hover:bg-primary/25 hover:border-primary/80 hover:shadow-[0_0_20px_rgba(0,255,136,0.25)]",
                      "focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-[#00FF88]/50",
                    ]
                  : "bg-white/5 border border-white/10 text-white/30 cursor-not-allowed",
              )}
            >
              {/* Animated glow when active */}
              {agreed && (
                <div className="absolute inset-0 bg-[radial-gradient(ellipse_at_center,rgba(0,255,136,0.15)_0%,transparent_70%)] pointer-events-none" />
              )}
              <div className="relative flex items-center gap-2">
                {accepting ? (
                  <div className="w-3.5 h-3.5 border-2 border-primary/40 border-t-[#00FF88] rounded-full animate-spin" />
                ) : (
                  <Shield className="w-3.5 h-3.5" />
                )}
                <span>{accepting ? "Processing..." : "Accept & Continue"}</span>
                {agreed && !accepting && (
                  <ChevronRight className="w-3.5 h-3.5 opacity-70" />
                )}
              </div>
            </button>
          </div>

          {/* Footer note */}
          <p className="text-[9px] text-[#3D4F48] text-center uppercase tracking-widest">
            This acceptance is cryptographically logged with your IP address, timestamp, and user agent.
            Agreement version: {TERMS_VERSION} • Quantara Security Platform
          </p>
        </div>
      </div>

      {/* Scanline animation */}
      <style jsx global>{`
        @keyframes scanline {
          0% { opacity: 0.3; }
          50% { opacity: 1; }
          100% { opacity: 0.3; }
        }
      `}</style>
    </div>
  );
}
