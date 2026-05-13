"use client";

import React, { useState } from "react";
import { AdminAuthProvider, useAdminAuth } from "@/contexts/AdminAuthContext";
import { useRouter, usePathname } from "next/navigation";
import {
  LayoutDashboard,
  Building2,
  Users,
  ShieldAlert,
  CreditCard,
  Settings,
  LogOut,
  ChevronRight,
  Shield,
  Zap
} from "lucide-react";
import { cn } from "@/lib/utils";
import Link from "next/link";
import { motion } from "framer-motion";

interface AdminLayoutProps {
  children: React.ReactNode;
}

export default function AdminLayout({ children }: AdminLayoutProps) {
  return (
    <AdminAuthProvider>
      <AdminLayoutContent>{children}</AdminLayoutContent>
    </AdminAuthProvider>
  );
}

function AdminLayoutContent({ children }: { children: React.ReactNode }) {
  const { isAuthenticated, isLoading } = useAdminAuth();
  const router = useRouter();
  const pathname = usePathname();

  React.useEffect(() => {
    if (!isLoading && !isAuthenticated && pathname !== "/admin/login") {
      router.push("/admin/login");
    }
  }, [isAuthenticated, isLoading, router, pathname]);

  if (isLoading) {
    return (
      <div className="min-h-screen flex items-center justify-center bg-background">
        <div className="flex flex-col items-center gap-4">
          <div className="w-12 h-12 rounded-xl bg-primary/10 border border-primary/20 flex items-center justify-center animate-spin">
            <Zap className="w-6 h-6 text-primary" />
          </div>
          <span className="text-[10px] uppercase font-black tracking-[0.3em] text-primary">Synchronizing Core</span>
        </div>
      </div>
    );
  }

  // Allow login page to render without sidebar
  if (pathname === "/admin/login") {
    return <>{children}</>;
  }

  if (!isAuthenticated && !isLoading) {
    return null;
  }

  return (
    <div className="min-h-screen bg-[#0A0F0C] text-muted-foreground selection:bg-primary/20 selection:text-primary">
      <AdminSidebar />
      <div className="ml-72 p-10 min-h-screen relative">
        {/* Ambient background glow */}
        <div className="absolute top-0 right-0 w-[500px] h-[500px] bg-primary/[0.02] blur-[150px] rounded-full pointer-events-none" />

        <div className="max-w-[1400px] mx-auto relative z-10">
          {children}
        </div>
      </div>
    </div>
  );
}

function AdminSidebar() {
  const { logout, user } = useAdminAuth();
  const pathname = usePathname();

  const menuItems = [
    { label: "Dashboard", href: "/admin/dashboard", icon: LayoutDashboard },
    { label: "Users", href: "/admin/users", icon: Users },
    { label: "Security Events", href: "/admin/security", icon: ShieldAlert },
    { label: "Billing", href: "/admin/billing", icon: CreditCard },
    { label: "Settings", href: "/admin/settings", icon: Settings },
  ];

  return (
    <aside className="fixed left-6 top-6 bottom-6 w-64 rounded-3xl bg-[rgba(15,20,18,0.4)] backdrop-blur-2xl border border-[rgba(0,255,136,0.12)] overflow-hidden flex flex-col z-50">
      {/* Sidebar Header */}
      <div className="p-8 border-b border-[rgba(0,255,136,0.08)] bg-gradient-to-b from-[#00FF88]/[0.03] to-transparent">
        <div className="flex items-center gap-3 group cursor-default">
          <div className="w-10 h-10 rounded-xl bg-primary/10 border border-primary/20 flex items-center justify-center">
            <Shield className="w-6 h-6 text-primary drop-shadow-[0_0_8px_rgba(0,255,136,0.4)]" />
          </div>
          <div>
            <h1 className="text-lg font-black text-foreground uppercase tracking-tighter leading-none">
              Security <span className="text-primary">Admin</span>
            </h1>
            <p className="text-[10px] text-muted-foreground font-bold uppercase tracking-[0.2em] mt-1">Super Authority</p>
          </div>
        </div>
      </div>

      {/* Navigation */}
      <nav className="flex-1 px-4 py-8 space-y-2 overflow-y-auto custom-scrollbar">
        {menuItems.map((item) => {
          const isActive = pathname === item.href;
          return (
            <Link
              key={item.href}
              href={item.href}
              className={cn(
                "flex items-center justify-between px-4 py-3.5 rounded-2xl transition-all duration-300 group",
                isActive
                  ? "bg-primary/10 text-primary border border-primary/15"
                  : "text-muted-foreground hover:text-muted-foreground hover:bg-white/5 border border-transparent"
              )}
            >
              <div className="flex items-center gap-3">
                <item.icon className={cn("w-5 h-5", isActive ? "text-primary" : "text-muted-foreground group-hover:text-muted-foreground")} />
                <span className="text-[11px] font-black uppercase tracking-widest">{item.label}</span>
              </div>
              {isActive && (
                <motion.div layoutId="sidebar-dot" className="w-1.5 h-1.5 rounded-full bg-primary shadow-[0_0_8px_#00FF88]" />
              )}
            </Link>
          );
        })}
      </nav>

      {/* Sidebar Footer */}
      <div className="p-4 border-t border-[rgba(0,255,136,0.08)] bg-background/20">
        <div className="p-4 rounded-2xl bg-white/[0.02] border border-white/[0.05] mb-4">
          <p className="text-[9px] font-black text-muted-foreground uppercase tracking-widest leading-none">Access Level</p>
          <p className="text-xs font-bold text-foreground mt-2 truncate">{user?.email}</p>
          <div className="mt-2 flex items-center gap-1.5">
            <div className="w-1.5 h-1.5 rounded-full bg-primary animate-pulse" />
            <span className="text-[10px] font-black text-primary uppercase tracking-tighter">Authorized Root</span>
          </div>
        </div>

        <button
          onClick={logout}
          className="w-full flex items-center justify-center gap-2 px-4 py-3.5 bg-white/5 hover:bg-red-500/10 border border-white/5 hover:border-red-500/20 rounded-2xl text-muted-foreground hover:text-red-500 transition-all duration-300 font-black text-[10px] uppercase tracking-widest"
        >
          <LogOut className="w-4 h-4" />
          Terminate Session
        </button>
      </div>
    </aside>
  );
}
