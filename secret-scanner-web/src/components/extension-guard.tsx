"use client";

import { useEffect } from "react";

/**
 * ExtensionGuard
 * 
 * This component suppresses noisy, non-critical errors originating from browser extensions
 * (like MetaMask) that are injected into the page and can sometimes trigger false-positive
 * runtime errors in the Next.js development overlay.
 */
export function ExtensionGuard() {
  useEffect(() => {
    if (typeof window === "undefined") return;

    const suppressError = (event: ErrorEvent | PromiseRejectionEvent) => {
      // Logic to identify extension-related errors
      const message = "message" in event ? event.message : (event as PromiseRejectionEvent).reason?.message;
      const filename = "filename" in event ? event.filename : "";
      const stack = (event as any).reason?.stack || (event as any).error?.stack || "";

      const isMetaMaskError = 
        message?.includes("MetaMask") || 
        message?.includes("Failed to connect to MetaMask") ||
        stack?.includes("nkbihfbeogaeaoehlefnkodbefgpgknn") || // MetaMask extension ID
        filename?.includes("chrome-extension://");

      if (isMetaMaskError) {
        // Prevent the error from reaching the console and the Next.js error overlay
        event.preventDefault();
        event.stopImmediatePropagation();
        
        // Log locally to the console as a warning instead of an error if in dev
        if (process.env.NODE_ENV === "development") {
          console.warn("🛡️ ExtensionGuard: Suppressed MetaMask/Extension error to prevent UI disruption.");
        }
      }
    };

    // Listen for generic errors
    window.addEventListener("error", suppressError, true);
    // Listen for unhandled promise rejections (often used by extensions)
    window.addEventListener("unhandledrejection", suppressError, true);

    return () => {
      window.removeEventListener("error", suppressError, true);
      window.removeEventListener("unhandledrejection", suppressError, true);
    };
  }, []);

  return null;
}
