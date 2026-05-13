"use client";

import { Moon, Sun, Monitor } from "lucide-react";
import { useTheme } from "next-themes";
import { useEffect, useState } from "react";
import { cn } from "@/lib/utils";

interface ThemeToggleProps {
  isCollapsed?: boolean;
  variant?: "sidebar" | "navbar";
}

export function ThemeToggle({ isCollapsed, variant = "sidebar" }: ThemeToggleProps) {
  const { setTheme, resolvedTheme } = useTheme();
  const [mounted, setMounted] = useState(false);

  useEffect(() => setMounted(true), []);

  if (!mounted) return null;

  const isDark = resolvedTheme === "dark";

  if (variant === "navbar") {
    return (
      <button
        type="button"
        onClick={() => setTheme(isDark ? "light" : "dark")}
        className={cn(
          "relative flex items-center gap-2 rounded-full p-1 transition-colors duration-300",
          isDark
            ? "bg-[rgba(0,255,136,0.08)] border border-[rgba(0,255,136,0.2)]"
            : "bg-[#eef1ff] border border-[#e6e9f2]"
        )}
        aria-label="Toggle theme"
      >
        <span
          className={cn(
            "flex items-center gap-1.5 rounded-full px-3 py-1.5 text-xs font-semibold transition-colors duration-300",
            isDark
              ? "bg-[rgba(0,255,136,0.15)] text-primary"
              : "bg-transparent text-[#6b7280]"
          )}
        >
          <Moon className="h-3.5 w-3.5" />
          <span className="hidden sm:inline">Cyber</span>
        </span>
        <span
          className={cn(
            "flex items-center gap-1.5 rounded-full px-3 py-1.5 text-xs font-semibold transition-colors duration-300",
            !isDark
              ? "bg-[#6c63ff] text-white"
              : "bg-transparent text-muted-foreground"
          )}
        >
          <Sun className="h-3.5 w-3.5" />
          <span className="hidden sm:inline">Light</span>
        </span>
      </button>
    );
  }

  // Sidebar variant — compact toggle with three options
  return (
    <div className={cn(
      "flex items-center gap-1 rounded-xl p-1 transition-colors duration-300",
      isDark
        ? "bg-[rgba(0,255,136,0.06)]"
        : "bg-[#f3f5fb]",
      isCollapsed && "lg:flex-col"
    )}>
      <button
        type="button"
        onClick={() => setTheme("dark")}
        className={cn(
          "flex items-center justify-center rounded-lg p-2 transition-colors duration-300",
          isDark
            ? "bg-[rgba(0,255,136,0.12)] text-primary"
            : "text-[#6b7280] hover:text-[#6c63ff] hover:bg-[rgba(108,99,255,0.08)]"
        )}
        aria-label="Cyber theme"
        title="Cyber Theme"
      >
        <Moon className="h-4 w-4" />
      </button>
      <button
        type="button"
        onClick={() => setTheme("light")}
        className={cn(
          "flex items-center justify-center rounded-lg p-2 transition-colors duration-300",
          !isDark
            ? "bg-[#6c63ff] text-white"
            : "text-muted-foreground hover:text-primary hover:bg-[rgba(0,255,136,0.08)]"
        )}
        aria-label="Light theme"
        title="Light Theme"
      >
        <Sun className="h-4 w-4" />
      </button>
    </div>
  );
}
