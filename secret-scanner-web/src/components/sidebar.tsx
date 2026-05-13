"use client";

import Link from "next/link";
import Image from "next/image";
import QuantaraLogo from "@/components/data/Quantara_Logo.png";
import { usePathname, useRouter } from "next/navigation";
import { motion } from "framer-motion";
import {
  Shield,
  Scan,
  LayoutDashboard,
  Settings,
  User,
  LogOut,
  Menu,
  X,
  ChevronLeft,
  ChevronRight,
  CreditCard,
  Bell,
  Bug,
  Home,
  BookOpen,
  Atom,
  FileSearch,
  Terminal,
} from "lucide-react";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { useAuth } from "@/contexts/auth-context";
import { useBilling } from "@/lib/hooks";
import { useState } from "react";
import { cn } from "@/lib/utils";
import { ThemeToggle } from "@/components/theme-toggle";
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuLabel,
  DropdownMenuSeparator,
  DropdownMenuTrigger,
} from "@/components/ui/dropdown-menu";
import { Avatar, AvatarFallback } from "@/components/ui/avatar";

const navigation = [
  { name: "Homepage", href: "/", icon: Home },
  { name: "Dashboard", href: "/dashboard", icon: LayoutDashboard },
  { name: "Quantara Scanner", href: "/dashboard/scanner", icon: Bug },
  { name: "Autonomous AI Red Team", href: "/dashboard/autonomous-ai-red-team", icon: Atom },
  { name: "Quantara AI Swarm", href: "/dashboard/multi-agent-architectures", icon: Shield },
  { name: "Quantara Toolkit", href: "/dashboard/hetty", icon: Terminal },
  { name: "Scan Results", href: "/dashboard/scan-results", icon: FileSearch },
  { name: "Documentation", href: "/docs", icon: BookOpen },
  { name: "Settings", href: "/settings", icon: Settings },
  { name: "Billing", href: "/billing", icon: CreditCard },
];

interface SidebarProps {
  children: React.ReactNode;
}

export function Sidebar({ children }: SidebarProps) {
  const [isCollapsed, setIsCollapsed] = useState(false);
  const [isMobileOpen, setIsMobileOpen] = useState(false);
  const pathname = usePathname();
  const router = useRouter();
  const { user, isAuthenticated, logout } = useAuth();
  const { profile } = useBilling();

  const handleLogout = async () => {
    await logout();
    router.push("/login");
  };

  const getTierColor = (tier: string) => {
    switch ((tier || "Free").toLowerCase()) {
      case "elite": return "text-purple-500 border-purple-500/30 bg-purple-500/10";
      case "pro": return "text-primary border-primary/30 bg-primary/10";
      default: return "text-muted-foreground border-border/30 bg-secondary";
    }
  };

  const getInitials = (name: string) => {
    return name
      .split(" ")
      .map((n) => n[0])
      .join("")
      .toUpperCase()
      .slice(0, 2);
  };

  return (
    <div className="flex h-screen overflow-hidden bg-background">
      {/* Mobile Overlay */}
      {isMobileOpen && (
        <motion.div
          initial={{ opacity: 0 }}
          animate={{ opacity: 1 }}
          exit={{ opacity: 0 }}
          className="fixed inset-0 bg-background/80 backdrop-blur-sm z-40 lg:hidden"
          onClick={() => setIsMobileOpen(false)}
        />
      )}

      {/* Mobile Header */}
      <div className="fixed top-0 left-0 right-0 h-16 z-30 lg:hidden flex items-center justify-between px-4 bg-background/80 backdrop-blur-xl border-b border-border">
        <Link href="/" className="flex items-center gap-2 font-bold text-xl">
          <Image
            src={QuantaraLogo}
            alt="Quantara Logo"
            width={28}
            height={28}
            className="drop-shadow-[0_0_8px_rgba(var(--primary),0.4)]"
          />
          <span className="text-foreground font-outfit">Quantara <span className="text-primary">Security</span></span>
        </Link>
        <div className="flex items-center gap-2">
          <ThemeToggle variant="navbar" />
          {isAuthenticated ? (
            <DropdownMenu>
              <DropdownMenuTrigger asChild>
                <Button variant="ghost" size="icon" className="relative">
                  <Avatar className="h-8 w-8">
                    <AvatarFallback className="bg-primary/15 text-primary text-xs font-bold border border-primary/20">
                      {user?.displayName ? getInitials(user.displayName) : user?.email?.[0].toUpperCase() || "U"}
                    </AvatarFallback>
                  </Avatar>
                </Button>
              </DropdownMenuTrigger>
              <DropdownMenuContent align="end" className="w-56 bg-card border-border">
                <DropdownMenuLabel className="text-muted-foreground">My Account</DropdownMenuLabel>
                <DropdownMenuSeparator className="bg-border/50" />
                <div className="px-2 py-1.5">
                  <p className="text-sm font-medium text-foreground">{user?.displayName || "User"}</p>
                  <p className="text-xs text-muted-foreground truncate">{user?.email}</p>
                </div>
                <DropdownMenuSeparator className="bg-border/50" />
                <Link href="/settings">
                  <DropdownMenuItem className="text-muted-foreground hover:!text-primary hover:!bg-primary/10">
                    <User className="mr-2 h-4 w-4" />
                    Profile Settings
                  </DropdownMenuItem>
                </Link>
                <Link href="/billing">
                  <DropdownMenuItem className="text-muted-foreground hover:!text-primary hover:!bg-primary/10">
                    <CreditCard className="mr-2 h-4 w-4" />
                    Billing
                  </DropdownMenuItem>
                </Link>
                <DropdownMenuItem onClick={handleLogout} className="text-red-500 hover:!bg-red-500/10">
                  <LogOut className="mr-2 h-4 w-4" />
                  Log out
                </DropdownMenuItem>
              </DropdownMenuContent>
            </DropdownMenu>
          ) : (
            <Link href="/login">
              <Button
                variant="ghost"
                size="icon"
                className="text-muted-foreground hover:text-primary"
              >
                <User className="h-5 w-5" />
              </Button>
            </Link>
          )}
          <Button
            variant="ghost"
            size="icon"
            onClick={() => setIsMobileOpen(!isMobileOpen)}
            className="text-muted-foreground hover:text-primary"
          >
            {isMobileOpen ? <X className="h-5 w-5" /> : <Menu className="h-5 w-5" />}
          </Button>
        </div>
      </div>

      {/* Sidebar */}
      <motion.aside
        className={cn(
          "fixed lg:static inset-y-0 left-0 z-50 bg-background/80 backdrop-blur-xl border-r border-border",
          "flex flex-col transition-all duration-300",
          isCollapsed ? "w-20" : "w-64",
          isMobileOpen ? "translate-x-0" : "-translate-x-full lg:translate-x-0"
        )}
      >
        {/* Logo */}
        <div className="h-16 flex items-center justify-between px-4 border-b border-border">
          <Link
            href="/"
            className={cn(
              "flex items-center gap-3 font-bold text-xl transition-all",
              isCollapsed && "lg:justify-center lg:gap-0"
            )}
          >
            <div className="relative flex-shrink-0">
              <Image
                src={QuantaraLogo}
                alt="Quantara Logo"
                width={36}
                height={36}
                className="relative z-10 drop-shadow-[0_0_8px_rgba(var(--primary),0.4)]"
              />
              <div className="absolute inset-0 bg-primary/10 blur-xl rounded-full" />
            </div>
            <span className={cn("transition-all text-foreground font-outfit", isCollapsed && "lg:hidden")}>
              Quantara <span className="text-primary">Security</span>
            </span>
          </Link>
          <Button
            variant="ghost"
            size="icon"
            className="hidden lg:flex text-muted-foreground hover:text-primary hover:bg-primary/10"
            onClick={() => setIsCollapsed(!isCollapsed)}
          >
            {isCollapsed ? <ChevronRight className="h-4 w-4" /> : <ChevronLeft className="h-4 w-4" />}
          </Button>
        </div>

        {/* Navigation */}
        <nav className="flex-1 px-3 py-6 space-y-2">
          {navigation.map((item, index) => {
            const isActive = item.href === "/" ? pathname === "/" : item.href === "/dashboard" ? pathname === "/dashboard" : pathname.startsWith(item.href);
            const Icon = item.icon;

            return (
              <motion.div
                key={item.name}
                initial={{ opacity: 0, x: -20 }}
                animate={{ opacity: 1, x: 0 }}
                transition={{ delay: index * 0.1 }}
              >
                <Link
                  href={item.href}
                  onClick={() => setIsMobileOpen(false)}
                  className={cn(
                    "flex items-center gap-3 px-3 py-3 rounded-xl transition-all duration-300 relative",
                    "hover:bg-primary/10 group",
                    isActive
                      ? "bg-primary/10 text-primary font-medium"
                      : "text-muted-foreground"
                  )}
                  style={isActive ? { boxShadow: "0 0 20px rgba(var(--primary), 0.05)" } : undefined}
                >
                  <Icon className={cn("h-5 w-5 transition-colors", isActive ? "text-primary" : "group-hover:text-primary")} />
                  <span className={cn("transition-all", isCollapsed && "lg:hidden")}>
                    {item.name}
                  </span>
                  {isActive && (
                    <motion.div
                      layoutId="activeNav"
                      className="absolute left-0 w-1 h-8 bg-primary rounded-r-full"
                      style={{ boxShadow: "0 0 10px rgba(var(--primary), 0.5)" }}
                    />
                  )}
                </Link>
              </motion.div>
            );
          })}
        </nav>

        {/* Bottom Section */}
        <div className="p-3 space-y-2 border-t border-border">
          {/* Theme Toggle */}
          <div className={cn("flex items-center gap-3 px-3 py-1", isCollapsed && "lg:justify-center lg:px-0")}>
            <ThemeToggle isCollapsed={isCollapsed} />
            {!isCollapsed && <span className="text-xs text-muted-foreground">Theme</span>}
          </div>

          {isAuthenticated ? (
            <DropdownMenu>
              <DropdownMenuTrigger asChild>
                <Button
                  variant="ghost"
                  className={cn(
                    "w-full justify-start gap-3 h-auto py-2 text-muted-foreground hover:bg-primary/10",
                    isCollapsed && "lg:justify-center lg:px-2"
                  )}
                >
                  <Avatar className="h-8 w-8">
                    <AvatarFallback className="bg-primary/15 text-primary text-xs font-bold border border-primary/20">
                      {user?.displayName ? getInitials(user.displayName) : user?.email?.[0].toUpperCase() || "U"}
                    </AvatarFallback>
                  </Avatar>
                  <div className={cn("text-left", isCollapsed && "lg:hidden")}>
                    <div className="flex items-center gap-2">
                      <p className="text-sm font-medium truncate text-foreground">{user?.displayName || "User"}</p>
                      <Badge variant="outline" className={cn("px-1 py-0 text-[10px] uppercase", getTierColor(profile?.subscription_tier))}>
                        {profile?.subscription_tier || "Free"}
                      </Badge>
                    </div>
                    <p className="text-xs text-muted-foreground truncate">{user?.email}</p>
                  </div>
                </Button>
              </DropdownMenuTrigger>
              <DropdownMenuContent side="right" align="end" className="w-56 bg-card border-border">
                <DropdownMenuLabel className="text-muted-foreground">My Account</DropdownMenuLabel>
                <DropdownMenuSeparator className="bg-border/50" />
                <Link href="/settings">
                  <DropdownMenuItem className="text-muted-foreground hover:!text-primary hover:!bg-primary/10">
                    <Settings className="mr-2 h-4 w-4" />
                    Profile Settings
                  </DropdownMenuItem>
                </Link>
                <Link href="/billing">
                  <DropdownMenuItem className="text-muted-foreground hover:!text-primary hover:!bg-primary/10">
                    <CreditCard className="mr-2 h-4 w-4" />
                    Billing & Subscription
                  </DropdownMenuItem>
                </Link>
                <DropdownMenuSeparator className="bg-border/50" />
                <DropdownMenuItem onClick={handleLogout} className="text-red-500 hover:!bg-red-500/10">
                  <LogOut className="mr-2 h-4 w-4" />
                  Log out
                </DropdownMenuItem>
              </DropdownMenuContent>
            </DropdownMenu>
          ) : (
            <Link href="/login" className={cn(
              "w-full flex items-center gap-3 px-3 py-3 rounded-xl transition-all duration-300 text-muted-foreground hover:text-primary hover:bg-primary/10",
              isCollapsed && "lg:justify-center lg:px-2"
            )}>
              <User className="h-5 w-5" />
              <span className={cn("transition-all", isCollapsed && "lg:hidden")}>
                Sign In
              </span>
            </Link>
          )}
        </div>
      </motion.aside>

      {/* Main Content */}
      <main className="flex-1 overflow-auto pt-16 lg:pt-0 bg-background">
        <div className="container mx-auto p-6">{children}</div>
      </main>
    </div>
  );
}
