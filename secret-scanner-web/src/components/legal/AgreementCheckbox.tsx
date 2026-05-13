"use client";

import React from "react";
import { CheckSquare, Square, ShieldCheck } from "lucide-react";
import { cn } from "@/lib/utils";

interface AgreementCheckboxProps {
  checked: boolean;
  onChange: (checked: boolean) => void;
  disabled?: boolean;
}

export function AgreementCheckbox({ checked, onChange, disabled = false }: AgreementCheckboxProps) {
  return (
    <div
      role="group"
      aria-labelledby="agreement-label"
      className={cn(
        "relative flex items-start gap-4 p-4 rounded-xl border cursor-pointer select-none",
        "bg-primary/5 border-primary/20",
        checked && "bg-primary/10 border-primary/40 shadow-[0_0_20px_rgba(0,255,136,0.08)]",
        disabled && "opacity-50 cursor-not-allowed",
        !disabled && "hover:bg-primary/8 hover:border-primary/30",
        "transition-all duration-300"
      )}
      onClick={() => !disabled && onChange(!checked)}
      onKeyDown={(e) => {
        if (!disabled && (e.key === " " || e.key === "Enter")) {
          e.preventDefault();
          onChange(!checked);
        }
      }}
      tabIndex={disabled ? -1 : 0}
    >
      {/* Hidden native checkbox for accessibility */}
      <input
        type="checkbox"
        checked={checked}
        onChange={(e) => !disabled && onChange(e.target.checked)}
        className="sr-only"
        aria-label="I confirm that I am authorized to perform security testing"
        tabIndex={-1}
      />

      {/* Visual checkbox */}
      <div
        className={cn(
          "mt-0.5 w-5 h-5 rounded-md flex items-center justify-center shrink-0",
          "border-2 transition-all duration-200",
          checked
            ? "bg-primary border-primary shadow-[0_0_12px_rgba(0,255,136,0.5)]"
            : "bg-transparent border-primary/40"
        )}
        aria-hidden
      >
        {checked && (
          <svg
            width="12"
            height="9"
            viewBox="0 0 12 9"
            fill="none"
            className="text-black"
          >
            <path
              d="M1 4L4.5 7.5L11 1"
              stroke="currentColor"
              strokeWidth="2"
              strokeLinecap="round"
              strokeLinejoin="round"
            />
          </svg>
        )}
      </div>

      {/* Label content */}
      <div id="agreement-label" className="flex-1">
        <p className="text-[12px] font-bold text-white leading-snug mb-1">
          I confirm that I am authorized to perform security testing
        </p>
        <p className="text-[10px] text-[#8BA89E] leading-relaxed">
          I have read and understood all sections of this Authorization &amp; Legal Terms Agreement.
          I confirm that I possess written authorization for all targets I intend to scan,
          and I accept full legal responsibility for all activities conducted through this platform.
          I understand this acceptance is logged with my IP address, timestamp, and user agent.
        </p>

        {checked && (
          <div className="flex items-center gap-1.5 mt-2">
            <ShieldCheck className="w-3 h-3 text-primary" />
            <span className="text-[10px] text-primary font-bold uppercase tracking-wider">
              Authorization Confirmed — Access Granted
            </span>
          </div>
        )}
      </div>
    </div>
  );
}
