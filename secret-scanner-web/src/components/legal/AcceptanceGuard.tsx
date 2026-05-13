"use client";

import React, { useEffect, useState, useCallback } from "react";
import { AuthorizationModal, TERMS_VERSION } from "./AuthorizationModal";
import { useAuth } from "@/contexts/auth-context";

const STORAGE_KEY = "quantara_terms_accepted";

interface TermsRecord {
  version: string;
  accepted_at: string;
  user_id?: string;
}

function getStoredRecord(): TermsRecord | null {
  if (typeof window === "undefined") return null;
  try {
    const raw = localStorage.getItem(STORAGE_KEY);
    return raw ? (JSON.parse(raw) as TermsRecord) : null;
  } catch {
    return null;
  }
}

function setStoredRecord(record: TermsRecord): void {
  if (typeof window === "undefined") return;
  localStorage.setItem(STORAGE_KEY, JSON.stringify(record));
}

function clearStoredRecord(): void {
  if (typeof window === "undefined") return;
  localStorage.removeItem(STORAGE_KEY);
}

interface AcceptanceGuardProps {
  children: React.ReactNode;
  /**
   * Called on Decline — defaults to logout + redirect to /login.
   * Override for pre-auth contexts (e.g. login page → redirect to /).
   */
  onDecline?: () => void | Promise<void>;
}

/**
 * AcceptanceGuard
 * ────────────────
 * Wraps protected content and ensures the user has accepted the
 * Authorization & Legal Terms Agreement before rendering children.
 *
 * Check order:
 *   1. localStorage (fast path — avoids backend round-trip on every render)
 *   2. Backend GET /api/v1/terms/status (authoritative check after login)
 *
 * If terms not accepted or version is stale → shows AuthorizationModal.
 * Accept → localStorage + backend POST + hide modal.
 * Decline → calls onDecline prop (default: logout → /login).
 */
export function AcceptanceGuard({ children, onDecline }: AcceptanceGuardProps) {
  const { user, logout } = useAuth();
  const [checking, setChecking] = useState(true);
  const [showModal, setShowModal] = useState(false);

  const checkAcceptance = useCallback(async () => {
    // 1. Fast path: check localStorage
    const stored = getStoredRecord();
    if (stored?.version === TERMS_VERSION) {
      setChecking(false);
      return;
    }

    // 2. Authoritative check: backend (only if logged in)
    if (user) {
      try {
        const apiModule = await import("@/lib/api");
        const api = apiModule.default;
        const res = await api.get<{ accepted: boolean; version: string; accepted_at?: string }>(
          "/api/v1/terms/status"
        );
        if (res.accepted && res.version === TERMS_VERSION) {
          setStoredRecord({
            version: TERMS_VERSION,
            accepted_at: res.accepted_at ?? new Date().toISOString(),
            user_id: user.uid,
          });
          setChecking(false);
          return;
        }
      } catch {
        // Backend unreachable — fall through to show modal
      }
    }

    // Terms not accepted or version mismatch → show modal
    setShowModal(true);
    setChecking(false);
  }, [user]);

  useEffect(() => {
    checkAcceptance();
  }, [checkAcceptance]);

  const handleAccept = async () => {
    // Store in localStorage immediately
    const record: TermsRecord = {
      version: TERMS_VERSION,
      accepted_at: new Date().toISOString(),
      user_id: user?.uid,
    };
    setStoredRecord(record);

    // Persist to backend if authenticated
    if (user) {
      try {
        const apiModule = await import("@/lib/api");
        const api = apiModule.default;
        await api.post("/api/v1/terms/accept", {
          version: TERMS_VERSION,
          user_agent: typeof navigator !== "undefined" ? navigator.userAgent : "",
        });
      } catch {
        // localStorage already saved — non-fatal
      }
    }

    setShowModal(false);
  };

  const handleDecline = async () => {
    clearStoredRecord();
    if (onDecline) {
      await onDecline();
      return;
    }
    // Default: logout and redirect to login
    try {
      await logout();
    } catch {
      /* ignore */
    }
    if (typeof window !== "undefined") {
      window.location.href = "/login";
    }
  };

  // During SSR / initial check — render nothing (avoids flash)
  if (checking) return null;

  return (
    <>
      {showModal && (
        <AuthorizationModal onAccept={handleAccept} onDecline={handleDecline} />
      )}
      {children}
    </>
  );
}
