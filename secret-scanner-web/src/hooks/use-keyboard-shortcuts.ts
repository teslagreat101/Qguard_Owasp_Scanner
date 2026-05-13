"use client";

import { useEffect, useCallback } from "react";
import { toast } from "sonner";

interface ShortcutConfig {
  key: string;
  ctrl?: boolean;
  alt?: boolean;
  shift?: boolean;
  description: string;
  action: () => void;
}

export function useKeyboardShortcuts(shortcuts: ShortcutConfig[]) {
  const handleKeyDown = useCallback(
    (event: KeyboardEvent) => {
      if (!event.key) return;
      shortcuts.forEach((shortcut) => {
        const keyMatch = event.key.toLowerCase() === shortcut.key.toLowerCase();
        const ctrlMatch = shortcut.ctrl ? event.ctrlKey || event.metaKey : !event.ctrlKey && !event.metaKey;
        const altMatch = shortcut.alt ? event.altKey : !event.altKey;
        const shiftMatch = shortcut.shift ? event.shiftKey : !event.shiftKey;

        if (keyMatch && ctrlMatch && altMatch && shiftMatch) {
          event.preventDefault();
          shortcut.action();
          toast.info(`Shortcut: ${shortcut.description}`, {
            duration: 1000,
          });
        }
      });
    },
    [shortcuts]
  );

  useEffect(() => {
    window.addEventListener("keydown", handleKeyDown);
    return () => window.removeEventListener("keydown", handleKeyDown);
  }, [handleKeyDown]);
}

// Default shortcuts for the application
export function useAppShortcuts() {
  useKeyboardShortcuts([
    {
      key: "k",
      ctrl: true,
      description: "Open Command Palette",
      action: () => {
        toast.info("Command palette coming soon!");
      },
    },
    {
      key: "/",
      description: "Focus Search",
      action: () => {
        const searchInput = document.querySelector('[data-search="true"]') as HTMLInputElement;
        if (searchInput) searchInput.focus();
      },
    },
    {
      key: "s",
      ctrl: true,
      description: "Start New Scan",
      action: () => {
        window.location.href = "/";
      },
    },
    {
      key: "d",
      ctrl: true,
      description: "Open Dashboard",
      action: () => {
        window.location.href = "/dashboard";
      },
    },
    {
      key: "t",
      ctrl: true,
      description: "Toggle Theme",
      action: () => {
        const html = document.documentElement;
        const currentTheme = html.classList.contains("dark") ? "dark" : "light";
        const newTheme = currentTheme === "dark" ? "light" : "dark";
        html.classList.remove(currentTheme);
        html.classList.add(newTheme);
        toast.success(`Theme changed to ${newTheme}`);
      },
    },
    {
      key: "?",
      shift: true,
      description: "Show Keyboard Shortcuts",
      action: () => {
        toast.info("Keyboard Shortcuts:\nCtrl+K - Command Palette\n/ - Focus Search\nCtrl+S - Start Scan\nCtrl+D - Dashboard\nCtrl+T - Toggle Theme\nShift+? - Show Help", { duration: 5000 });
      },
    },
  ]);
}
