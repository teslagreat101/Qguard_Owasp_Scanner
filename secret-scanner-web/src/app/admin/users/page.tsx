"use client";

import React, { useEffect, useState, useCallback, useRef } from "react";
import {
  Users,
  RefreshCw,
  Crown,
  Zap,
  User,
  ShieldCheck,
  CreditCard,
  Search,
  AlertCircle,
  ChevronDown,
  ChevronUp,
  Trash2,
  XCircle,
  CalendarPlus,
  ArrowUpCircle,
  X,
  CheckCircle,
  Clock,
  Shield,
  Mail,
  Activity,
  BarChart3,
  AlertTriangle,
} from "lucide-react";
import { GlowCard } from "@/components/ui/glow-card";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { cn } from "@/lib/utils";
import { auth } from "@/lib/firebase";

const API_BASE = process.env.NEXT_PUBLIC_API_URL || "http://localhost:8000";

// ═══════════════════════════════════════════════════════════════════════════════
// Types
// ═══════════════════════════════════════════════════════════════════════════════

interface AdminUser {
  id: string;
  email: string;
  username: string;
  full_name: string;
  subscription_tier: "free" | "pro" | "enterprise";
  subscription_status: string;
  monthly_scan_limit: number;
  total_scans: number;
  is_admin: boolean;
  is_super_admin: boolean;
  is_active: boolean;
  has_stripe: boolean;
  stripe_customer_id: string | null;
  stripe_subscription_id: string | null;
  email_verified: boolean;
  role: string;
  last_login_at: string | null;
  created_at: string | null;
  updated_at: string | null;
  deleted_at: string | null;
}

interface TierDistribution {
  free?: number;
  pro?: number;
  enterprise?: number;
}

interface UserDetailData {
  user: AdminUser;
  stats: { scans_count: number; findings_count: number };
  recent_scans: { scan_id: string; target: string; status: string; created_at: string | null }[];
}

// ═══════════════════════════════════════════════════════════════════════════════
// API helpers
// ═══════════════════════════════════════════════════════════════════════════════

async function fetchWithAuth(path: string, options?: RequestInit) {
  const user = auth.currentUser;
  const token = user ? await user.getIdToken() : "";
  const res = await fetch(`${API_BASE}${path}`, {
    ...options,
    headers: {
      Authorization: `Bearer ${token}`,
      "Content-Type": "application/json",
      ...(options?.headers || {}),
    },
  });
  if (!res.ok) {
    const text = await res.text().catch(() => "");
    throw new Error(text || `HTTP ${res.status}`);
  }
  return res.json();
}

async function adminAction(
  method: string,
  path: string,
  body?: Record<string, unknown>
) {
  return fetchWithAuth(path, {
    method,
    body: body ? JSON.stringify(body) : undefined,
  });
}

// ═══════════════════════════════════════════════════════════════════════════════
// Sub-components
// ═══════════════════════════════════════════════════════════════════════════════

function TierBadge({ tier }: { tier: string }) {
  const map: Record<string, { label: string; cls: string }> = {
    enterprise: {
      label: "Elite",
      cls: "bg-purple-500/10 text-purple-400 border-purple-500/20",
    },
    pro: {
      label: "Pro",
      cls: "bg-[rgba(0,255,136,0.08)] text-primary border-[rgba(0,255,136,0.2)]",
    },
    free: {
      label: "Free",
      cls: "bg-white/5 text-muted-foreground border-white/10",
    },
  };
  const { label, cls } = map[tier] ?? map.free!;
  return (
    <Badge
      className={cn(
        "text-[9px] font-black uppercase tracking-widest border",
        cls
      )}
    >
      {label}
    </Badge>
  );
}

function StatusBadge({ status }: { status: string }) {
  const colorMap: Record<string, string> = {
    active: "text-primary",
    trial: "text-amber-400",
    past_due: "text-red-400",
    cancelled: "text-muted-foreground",
    expired: "text-muted-foreground",
    suspended: "text-red-500",
  };
  return (
    <span
      className={cn(
        "text-[10px] font-bold uppercase tracking-widest",
        colorMap[status] ?? "text-muted-foreground"
      )}
    >
      {status}
    </span>
  );
}

// ═══════════════════════════════════════════════════════════════════════════════
// Confirmation Dialog
// ═══════════════════════════════════════════════════════════════════════════════

function ConfirmDialog({
  open,
  title,
  message,
  confirmLabel,
  confirmColor,
  onConfirm,
  onCancel,
  loading,
}: {
  open: boolean;
  title: string;
  message: string;
  confirmLabel: string;
  confirmColor: string;
  onConfirm: () => void;
  onCancel: () => void;
  loading: boolean;
}) {
  if (!open) return null;
  return (
    <div className="fixed inset-0 z-[100] flex items-center justify-center bg-background/60 backdrop-blur-sm">
      <div className="bg-[#0D1210] border border-white/10 rounded-2xl p-6 max-w-md w-full mx-4 shadow-2xl">
        <h3 className="text-sm font-black text-foreground uppercase tracking-widest mb-2">
          {title}
        </h3>
        <p className="text-xs text-muted-foreground mb-6 leading-relaxed">{message}</p>
        <div className="flex gap-3 justify-end">
          <Button
            variant="ghost"
            size="sm"
            onClick={onCancel}
            disabled={loading}
            className="text-[10px] font-black uppercase tracking-widest text-muted-foreground hover:text-foreground border border-white/10 hover:bg-white/5"
          >
            Cancel
          </Button>
          <Button
            size="sm"
            onClick={onConfirm}
            disabled={loading}
            className={cn(
              "text-[10px] font-black uppercase tracking-widest border",
              confirmColor
            )}
          >
            {loading ? (
              <RefreshCw className="w-3 h-3 animate-spin mr-1.5" />
            ) : null}
            {confirmLabel}
          </Button>
        </div>
      </div>
    </div>
  );
}

// ═══════════════════════════════════════════════════════════════════════════════
// User Detail Panel (Expandable Row)
// ═══════════════════════════════════════════════════════════════════════════════

function UserDetailPanel({
  user,
  detail,
  detailLoading,
  onAction,
  actionLoading,
}: {
  user: AdminUser;
  detail: UserDetailData | null;
  detailLoading: boolean;
  onAction: (action: string, payload?: Record<string, unknown>) => void;
  actionLoading: string | null;
}) {
  const [confirmAction, setConfirmAction] = useState<string | null>(null);
  const [extendDays, setExtendDays] = useState(30);
  const [selectedTier, setSelectedTier] = useState(user.subscription_tier);

  const tierOptions = [
    { value: "free", label: "Free" },
    { value: "pro", label: "Pro" },
    { value: "enterprise", label: "Elite" },
  ];

  const confirmConfigs: Record<
    string,
    { title: string; message: string; label: string; color: string }
  > = {
    delete: {
      title: "Delete User",
      message: `This will permanently deactivate ${user.email}. Their account will be soft-deleted and all access revoked. This action cannot be easily undone.`,
      label: "Delete User",
      color:
        "bg-red-500/10 text-red-400 border-red-500/20 hover:bg-red-500/20",
    },
    cancel: {
      title: "Cancel Subscription",
      message: `This will cancel ${user.email}'s subscription and revert them to the Free tier with 10 scans/month.`,
      label: "Cancel Subscription",
      color:
        "bg-amber-500/10 text-amber-400 border-amber-500/20 hover:bg-amber-500/20",
    },
  };

  return (
    <tr>
      <td colSpan={7} className="p-0">
        <div className="bg-[rgba(0,255,136,0.02)] border-t border-b border-primary/10 px-6 py-5">
          {detailLoading ? (
            <div className="flex items-center gap-3 justify-center py-8">
              <RefreshCw className="w-4 h-4 animate-spin text-primary" />
              <span className="text-[10px] text-muted-foreground uppercase tracking-widest font-bold">
                Loading user profile...
              </span>
            </div>
          ) : (
            <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
              {/* Column 1: User Profile */}
              <div className="space-y-4">
                <h4 className="text-[10px] font-black text-muted-foreground uppercase tracking-widest flex items-center gap-2">
                  <User className="w-3.5 h-3.5" /> Profile Details
                </h4>
                <div className="space-y-2.5">
                  {[
                    {
                      label: "Full Name",
                      value: user.full_name || "\u2014",
                      icon: User,
                    },
                    { label: "Email", value: user.email, icon: Mail },
                    {
                      label: "Username",
                      value: user.username || "\u2014",
                      icon: Shield,
                    },
                    { label: "Role", value: user.role || "member", icon: Shield },
                    {
                      label: "Verified",
                      value: user.email_verified ? "Yes" : "No",
                      icon: CheckCircle,
                    },
                    {
                      label: "Status",
                      value: user.is_active ? "Active" : "Deactivated",
                      icon: Activity,
                    },
                    {
                      label: "Last Login",
                      value: user.last_login_at
                        ? new Date(user.last_login_at).toLocaleString()
                        : "Never",
                      icon: Clock,
                    },
                    {
                      label: "Joined",
                      value: user.created_at
                        ? new Date(user.created_at).toLocaleDateString("en-US", {
                            month: "long",
                            day: "numeric",
                            year: "numeric",
                          })
                        : "\u2014",
                      icon: CalendarPlus,
                    },
                  ].map((item) => (
                    <div key={item.label} className="flex items-center gap-2">
                      <item.icon className="w-3 h-3 text-muted-foreground flex-shrink-0" />
                      <span className="text-[10px] text-muted-foreground font-bold uppercase tracking-widest w-24 flex-shrink-0">
                        {item.label}
                      </span>
                      <span className="text-[11px] text-muted-foreground font-mono truncate">
                        {item.value}
                      </span>
                    </div>
                  ))}
                </div>
              </div>

              {/* Column 2: Subscription & Stats */}
              <div className="space-y-4">
                <h4 className="text-[10px] font-black text-muted-foreground uppercase tracking-widest flex items-center gap-2">
                  <BarChart3 className="w-3.5 h-3.5" /> Subscription & Usage
                </h4>
                <div className="space-y-3">
                  <div className="flex items-center gap-3">
                    <TierBadge tier={user.subscription_tier} />
                    <StatusBadge status={user.subscription_status} />
                  </div>
                  <div className="grid grid-cols-2 gap-3">
                    <div className="bg-white/[0.03] border border-white/5 rounded-xl p-3">
                      <div className="text-[9px] text-muted-foreground uppercase tracking-widest font-bold mb-1">
                        Scan Limit
                      </div>
                      <div className="text-lg font-black text-foreground tracking-tighter">
                        {user.monthly_scan_limit >= 1000000
                          ? "Unlimited"
                          : user.monthly_scan_limit}
                      </div>
                    </div>
                    <div className="bg-white/[0.03] border border-white/5 rounded-xl p-3">
                      <div className="text-[9px] text-muted-foreground uppercase tracking-widest font-bold mb-1">
                        Total Scans
                      </div>
                      <div className="text-lg font-black text-primary tracking-tighter">
                        {user.total_scans}
                      </div>
                    </div>
                    <div className="bg-white/[0.03] border border-white/5 rounded-xl p-3">
                      <div className="text-[9px] text-muted-foreground uppercase tracking-widest font-bold mb-1">
                        Findings
                      </div>
                      <div className="text-lg font-black text-amber-400 tracking-tighter">
                        {detail?.stats?.findings_count ?? "\u2014"}
                      </div>
                    </div>
                    <div className="bg-white/[0.03] border border-white/5 rounded-xl p-3">
                      <div className="text-[9px] text-muted-foreground uppercase tracking-widest font-bold mb-1">
                        Billing
                      </div>
                      <div className="text-sm font-black tracking-tighter">
                        {user.has_stripe ? (
                          <span className="text-primary flex items-center gap-1">
                            <CreditCard className="w-3.5 h-3.5" /> Stripe
                          </span>
                        ) : (
                          <span className="text-muted-foreground">None</span>
                        )}
                      </div>
                    </div>
                  </div>

                  {/* Recent Scans */}
                  {detail?.recent_scans && detail.recent_scans.length > 0 && (
                    <div className="mt-2">
                      <div className="text-[9px] text-muted-foreground uppercase tracking-widest font-bold mb-2">
                        Recent Scans
                      </div>
                      <div className="space-y-1">
                        {detail.recent_scans.slice(0, 3).map((s) => (
                          <div
                            key={s.scan_id}
                            className="flex items-center justify-between bg-white/[0.02] rounded-lg px-3 py-1.5"
                          >
                            <span className="text-[10px] text-muted-foreground font-mono truncate max-w-[180px]">
                              {s.target}
                            </span>
                            <span
                              className={cn(
                                "text-[9px] font-bold uppercase tracking-widest",
                                s.status === "completed"
                                  ? "text-primary"
                                  : s.status === "failed"
                                  ? "text-red-400"
                                  : "text-amber-400"
                              )}
                            >
                              {s.status}
                            </span>
                          </div>
                        ))}
                      </div>
                    </div>
                  )}
                </div>
              </div>

              {/* Column 3: Admin Actions */}
              <div className="space-y-4">
                <h4 className="text-[10px] font-black text-muted-foreground uppercase tracking-widest flex items-center gap-2">
                  <ShieldCheck className="w-3.5 h-3.5" /> Admin Actions
                </h4>
                <div className="space-y-3">
                  {/* Change Tier */}
                  <div className="bg-white/[0.03] border border-white/5 rounded-xl p-3 space-y-2">
                    <div className="text-[9px] text-muted-foreground uppercase tracking-widest font-bold">
                      Change Tier
                    </div>
                    <div className="flex gap-2">
                      {tierOptions.map((t) => (
                        <button
                          key={t.value}
                          onClick={(e) => {
                            e.stopPropagation();
                            setSelectedTier(
                              t.value as "free" | "pro" | "enterprise"
                            );
                          }}
                          className={cn(
                            "px-3 py-1.5 rounded-lg text-[10px] font-black uppercase tracking-widest border transition-colors duration-150",
                            selectedTier === t.value
                              ? "border-[rgba(0,255,136,0.4)] bg-[rgba(0,255,136,0.08)] text-primary"
                              : "border-white/5 bg-white/[0.02] text-muted-foreground hover:border-white/10 hover:text-muted-foreground"
                          )}
                        >
                          {t.label}
                        </button>
                      ))}
                    </div>
                    {selectedTier !== user.subscription_tier && (
                      <Button
                        size="sm"
                        onClick={(e) => {
                          e.stopPropagation();
                          onAction("change-tier", { tier: selectedTier });
                        }}
                        disabled={actionLoading === "change-tier"}
                        className="w-full h-8 text-[10px] font-black uppercase tracking-widest bg-[rgba(0,255,136,0.08)] text-primary border border-[rgba(0,255,136,0.2)] hover:bg-[rgba(0,255,136,0.15)]"
                      >
                        {actionLoading === "change-tier" ? (
                          <RefreshCw className="w-3 h-3 animate-spin mr-1.5" />
                        ) : (
                          <ArrowUpCircle className="w-3 h-3 mr-1.5" />
                        )}
                        Apply Tier Change
                      </Button>
                    )}
                  </div>

                  {/* Extend Subscription */}
                  <div className="bg-white/[0.03] border border-white/5 rounded-xl p-3 space-y-2">
                    <div className="text-[9px] text-muted-foreground uppercase tracking-widest font-bold">
                      Extend Subscription
                    </div>
                    <div className="flex items-center gap-2">
                      <input
                        type="number"
                        value={extendDays}
                        title="Extension days"
                        placeholder="30"
                        onClick={(e) => e.stopPropagation()}
                        onChange={(e) =>
                          setExtendDays(
                            Math.max(1, Math.min(365, Number(e.target.value)))
                          )
                        }
                        className="w-20 px-2 py-1.5 bg-white/5 border border-white/5 rounded-lg text-xs text-muted-foreground font-mono focus:outline-none focus:border-[rgba(0,255,136,0.3)]"
                      />
                      <span className="text-[10px] text-muted-foreground font-bold uppercase tracking-widest">
                        days
                      </span>
                    </div>
                    <Button
                      size="sm"
                      onClick={(e) => {
                        e.stopPropagation();
                        onAction("extend", { days: extendDays });
                      }}
                      disabled={actionLoading === "extend"}
                      className="w-full h-8 text-[10px] font-black uppercase tracking-widest bg-blue-500/10 text-blue-400 border border-blue-500/20 hover:bg-blue-500/15"
                    >
                      {actionLoading === "extend" ? (
                        <RefreshCw className="w-3 h-3 animate-spin mr-1.5" />
                      ) : (
                        <CalendarPlus className="w-3 h-3 mr-1.5" />
                      )}
                      Extend Subscription
                    </Button>
                  </div>

                  {/* Cancel Subscription */}
                  <Button
                    size="sm"
                    onClick={(e) => {
                      e.stopPropagation();
                      setConfirmAction("cancel");
                    }}
                    disabled={
                      actionLoading === "cancel" ||
                      user.subscription_tier === "free"
                    }
                    className="w-full h-8 text-[10px] font-black uppercase tracking-widest bg-amber-500/10 text-amber-400 border border-amber-500/20 hover:bg-amber-500/15 disabled:opacity-30"
                  >
                    {actionLoading === "cancel" ? (
                      <RefreshCw className="w-3 h-3 animate-spin mr-1.5" />
                    ) : (
                      <XCircle className="w-3 h-3 mr-1.5" />
                    )}
                    Cancel Subscription
                  </Button>

                  {/* Delete User */}
                  <Button
                    size="sm"
                    onClick={(e) => {
                      e.stopPropagation();
                      setConfirmAction("delete");
                    }}
                    disabled={
                      actionLoading === "delete" || user.is_super_admin
                    }
                    className="w-full h-8 text-[10px] font-black uppercase tracking-widest bg-red-500/10 text-red-400 border border-red-500/20 hover:bg-red-500/15 disabled:opacity-30"
                  >
                    {actionLoading === "delete" ? (
                      <RefreshCw className="w-3 h-3 animate-spin mr-1.5" />
                    ) : (
                      <Trash2 className="w-3 h-3 mr-1.5" />
                    )}
                    Delete User
                  </Button>
                </div>
              </div>
            </div>
          )}

          {/* Confirm dialogs */}
          {confirmAction && confirmConfigs[confirmAction] && (
            <ConfirmDialog
              open={true}
              title={confirmConfigs[confirmAction].title}
              message={confirmConfigs[confirmAction].message}
              confirmLabel={confirmConfigs[confirmAction].label}
              confirmColor={confirmConfigs[confirmAction].color}
              loading={actionLoading === confirmAction}
              onCancel={() => setConfirmAction(null)}
              onConfirm={() => {
                onAction(confirmAction);
                setConfirmAction(null);
              }}
            />
          )}
        </div>
      </td>
    </tr>
  );
}

// ═══════════════════════════════════════════════════════════════════════════════
// Main Page
// ═══════════════════════════════════════════════════════════════════════════════

export default function AdminUsersPage() {
  const [users, setUsers] = useState<AdminUser[]>([]);
  const [filtered, setFiltered] = useState<AdminUser[]>([]);
  const [tiers, setTiers] = useState<TierDistribution>({});
  const [total, setTotal] = useState(0);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [lastRefresh, setLastRefresh] = useState<Date | null>(null);
  const [search, setSearch] = useState("");

  // Expanded user state
  const [expandedId, setExpandedId] = useState<string | null>(null);
  const [userDetail, setUserDetail] = useState<UserDetailData | null>(null);
  const [detailLoading, setDetailLoading] = useState(false);
  const [actionLoading, setActionLoading] = useState<string | null>(null);

  // Toast notifications
  const [toast, setToast] = useState<{
    message: string;
    type: "success" | "error";
  } | null>(null);
  const toastTimer = useRef<ReturnType<typeof setTimeout>>(null);

  function showToast(message: string, type: "success" | "error" = "success") {
    if (toastTimer.current) clearTimeout(toastTimer.current);
    setToast({ message, type });
    toastTimer.current = setTimeout(() => setToast(null), 4000);
  }

  // Load user list
  const load = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const data = await fetchWithAuth("/api/v1/admin/users?limit=500");
      setUsers(data.users ?? []);
      setFiltered(data.users ?? []);
      setTiers(data.tier_distribution ?? {});
      setTotal(data.total ?? 0);
      setLastRefresh(new Date());
    } catch (e: unknown) {
      const msg =
        e instanceof Error ? e.message : "Failed to load users";
      setError(
        msg.includes("HTTP 404") || msg.includes("Failed to fetch")
          ? "Backend API unavailable \u2014 ensure the Quantara backend server is running on port 8000"
          : msg
      );
    } finally {
      setLoading(false);
    }
  }, []);

  // Initial load + auto-refresh every 30s
  useEffect(() => {
    load();
    const interval = setInterval(load, 30000);
    return () => clearInterval(interval);
  }, [load]);

  // Search filter
  useEffect(() => {
    const q = search.toLowerCase();
    if (!q) {
      setFiltered(users);
    } else {
      setFiltered(
        users.filter(
          (u) =>
            u.email.toLowerCase().includes(q) ||
            u.username.toLowerCase().includes(q) ||
            (u.full_name && u.full_name.toLowerCase().includes(q))
        )
      );
    }
  }, [search, users]);

  // Load user detail when expanding
  const toggleExpand = useCallback(
    async (userId: string) => {
      if (expandedId === userId) {
        setExpandedId(null);
        setUserDetail(null);
        return;
      }
      setExpandedId(userId);
      setUserDetail(null);
      setDetailLoading(true);
      try {
        const data = await fetchWithAuth(`/api/v1/admin/users/${userId}`);
        setUserDetail(data);
      } catch {
        setUserDetail(null);
      } finally {
        setDetailLoading(false);
      }
    },
    [expandedId]
  );

  // Handle admin actions
  const handleAction = useCallback(
    async (
      userId: string,
      action: string,
      payload?: Record<string, unknown>
    ) => {
      setActionLoading(action);
      try {
        let result;
        switch (action) {
          case "delete":
            result = await adminAction(
              "DELETE",
              `/api/v1/admin/users/${userId}`
            );
            showToast("User deleted successfully");
            setExpandedId(null);
            break;
          case "cancel":
            result = await adminAction(
              "POST",
              `/api/v1/admin/users/${userId}/cancel-subscription`,
              { reason: "Admin action" }
            );
            showToast("Subscription cancelled");
            break;
          case "extend":
            result = await adminAction(
              "POST",
              `/api/v1/admin/users/${userId}/extend-subscription`,
              { days: (payload?.days as number) || 30, reason: "Admin action" }
            );
            showToast(
              `Subscription extended by ${(payload?.days as number) || 30} days`
            );
            break;
          case "change-tier":
            result = await adminAction(
              "POST",
              `/api/v1/admin/users/${userId}/change-tier`,
              {
                tier: payload?.tier as string,
                reason: "Admin action",
              }
            );
            showToast(
              `Tier changed to ${String(payload?.tier ?? "").replace("enterprise", "Elite") || "updated"}`
            );
            break;
        }

        // Update local state with returned user data
        if (result?.user) {
          setUsers((prev) =>
            prev
              .map((u) => (u.id === userId ? { ...u, ...result.user } : u))
              .filter((u) => !u.deleted_at)
          );
        }

        // Reload to sync everything
        await load();
      } catch (e: unknown) {
        const msg =
          e instanceof Error ? e.message : "Action failed";
        showToast(msg, "error");
      } finally {
        setActionLoading(null);
      }
    },
    [load]
  );

  const tierLabel = (t: string) =>
    t === "enterprise" ? "Elite" : t.charAt(0).toUpperCase() + t.slice(1);

  return (
    <div className="space-y-8">
      {/* Toast */}
      {toast && (
        <div
          className={cn(
            "fixed top-6 right-6 z-[200] flex items-center gap-3 px-5 py-3 rounded-xl border shadow-2xl",
            toast.type === "success"
              ? "bg-[rgba(0,255,136,0.08)] border-[rgba(0,255,136,0.2)] text-primary"
              : "bg-red-500/10 border-red-500/20 text-red-400"
          )}
        >
          {toast.type === "success" ? (
            <CheckCircle className="w-4 h-4" />
          ) : (
            <AlertTriangle className="w-4 h-4" />
          )}
          <span className="text-xs font-bold uppercase tracking-widest">
            {toast.message}
          </span>
          <button onClick={() => setToast(null)} className="ml-2 opacity-60 hover:opacity-100" title="Dismiss">
            <X className="w-3.5 h-3.5" />
          </button>
        </div>
      )}

      {/* Header */}
      <div className="flex items-end justify-between">
        <div>
          <h1 className="text-3xl font-black text-foreground uppercase tracking-tighter flex items-center gap-3">
            Identity <span className="text-primary">Vault</span>
          </h1>
          <p className="text-xs text-muted-foreground font-bold uppercase tracking-widest mt-1">
            Platform-wide user directory and subscription management
          </p>
        </div>
        <div className="flex items-center gap-3">
          {lastRefresh && (
            <span className="text-[10px] text-muted-foreground font-mono">
              Updated {lastRefresh.toLocaleTimeString()}
            </span>
          )}
          <Button
            variant="ghost"
            size="sm"
            onClick={load}
            disabled={loading}
            className="h-8 px-3 text-primary hover:bg-[rgba(0,255,136,0.08)] border border-[rgba(0,255,136,0.15)] text-[10px] font-black uppercase tracking-widest"
          >
            <RefreshCw
              className={cn(
                "w-3.5 h-3.5 mr-1.5",
                loading && "animate-spin"
              )}
            />
            Refresh
          </Button>
        </div>
      </div>

      {/* Summary KPI cards */}
      <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
        {[
          {
            label: "Total Users",
            value: total,
            icon: Users,
            color: "text-primary",
            glow: "rgba(0,255,136,0.08)",
          },
          {
            label: "Free Tier",
            value: tiers.free ?? 0,
            icon: User,
            color: "text-muted-foreground",
            glow: "rgba(255,255,255,0.02)",
          },
          {
            label: "Pro Tier",
            value: tiers.pro ?? 0,
            icon: Zap,
            color: "text-primary",
            glow: "rgba(0,255,136,0.06)",
          },
          {
            label: "Elite Tier",
            value: tiers.enterprise ?? 0,
            icon: Crown,
            color: "text-purple-400",
            glow: "rgba(168,85,247,0.08)",
          },
        ].map((kpi) => (
          <GlowCard
            key={kpi.label}
            className="p-0 border-primary/10 bg-[rgba(10,15,12,0.5)]"
            glowColor={kpi.glow}
          >
            <div className="flex items-center justify-between mb-3">
              <span className="text-[10px] text-muted-foreground uppercase tracking-widest font-bold">
                {kpi.label}
              </span>
              <kpi.icon className={cn("w-4 h-4", kpi.color)} />
            </div>
            <div
              className={cn(
                "text-3xl font-black tracking-tighter",
                kpi.color
              )}
            >
              {loading ? "\u2014" : kpi.value}
            </div>
          </GlowCard>
        ))}
      </div>

      {/* Error state */}
      {error && (
        <GlowCard
          className="p-4 border-red-500/20 bg-red-500/5"
          glowColor="rgba(239,68,68,0.05)"
        >
          <div className="flex items-center gap-3 text-red-400">
            <AlertCircle className="w-4 h-4 flex-shrink-0" />
            <p className="text-xs font-bold uppercase tracking-widest">
              {error}
            </p>
          </div>
        </GlowCard>
      )}

      {/* Search + Table */}
      <GlowCard
        className="p-0 border-primary/10 bg-[rgba(10,15,12,0.4)] overflow-hidden"
        glowColor="rgba(0,255,136,0.02)"
      >
        {/* Search bar */}
        <div className="p-4 border-b border-[rgba(0,255,136,0.08)]">
          <div className="relative max-w-sm">
            <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-3.5 h-3.5 text-muted-foreground" />
            <input
              value={search}
              onChange={(e) => setSearch(e.target.value)}
              placeholder="Search by email, username, or name..."
              className="w-full pl-9 pr-4 py-2 bg-white/5 border border-white/5 rounded-lg text-xs text-muted-foreground placeholder:text-muted-foreground focus:outline-none focus:border-[rgba(0,255,136,0.3)] font-mono"
            />
          </div>
        </div>

        {/* Table */}
        <div className="overflow-x-auto">
          <table className="w-full text-xs">
            <thead>
              <tr className="border-b border-[rgba(0,255,136,0.06)]">
                {[
                  "User",
                  "Tier",
                  "Status",
                  "Scan Limit",
                  "Total Scans",
                  "Billing",
                  "Joined",
                ].map((h) => (
                  <th
                    key={h}
                    className="px-4 py-3 text-left text-[9px] font-black uppercase tracking-widest text-muted-foreground"
                  >
                    {h}
                  </th>
                ))}
              </tr>
            </thead>
            <tbody>
              {loading && !users.length ? (
                <tr>
                  <td
                    colSpan={7}
                    className="px-4 py-12 text-center text-muted-foreground text-[10px] uppercase tracking-widest"
                  >
                    Loading user directory...
                  </td>
                </tr>
              ) : filtered.length === 0 ? (
                <tr>
                  <td
                    colSpan={7}
                    className="px-4 py-12 text-center text-muted-foreground text-[10px] uppercase tracking-widest"
                  >
                    No users found
                  </td>
                </tr>
              ) : (
                filtered.map((u, i) => (
                  <React.Fragment key={u.id}>
                    <tr
                      onClick={() => toggleExpand(u.id)}
                      className={cn(
                        "border-b border-[rgba(255,255,255,0.03)] transition-colors duration-150 cursor-pointer",
                        expandedId === u.id
                          ? "bg-[rgba(0,255,136,0.04)]"
                          : i % 2 === 0
                          ? "bg-transparent hover:bg-white/[0.02]"
                          : "bg-white/[0.01] hover:bg-white/[0.03]"
                      )}
                    >
                      {/* User */}
                      <td className="px-4 py-3">
                        <div className="flex items-center gap-2.5">
                          <div className="w-7 h-7 rounded-lg bg-[rgba(0,255,136,0.06)] border border-primary/10 flex items-center justify-center flex-shrink-0">
                            {u.is_super_admin ? (
                              <ShieldCheck className="w-3.5 h-3.5 text-primary" />
                            ) : (
                              <User className="w-3.5 h-3.5 text-muted-foreground" />
                            )}
                          </div>
                          <div className="min-w-0">
                            <div className="font-bold text-foreground text-[11px] leading-tight truncate">
                              {u.full_name || u.username || "\u2014"}
                            </div>
                            <div className="text-muted-foreground font-mono text-[10px] truncate">
                              {u.email}
                            </div>
                          </div>
                          <div className="ml-auto flex-shrink-0">
                            {expandedId === u.id ? (
                              <ChevronUp className="w-3.5 h-3.5 text-primary" />
                            ) : (
                              <ChevronDown className="w-3.5 h-3.5 text-muted-foreground" />
                            )}
                          </div>
                        </div>
                      </td>

                      {/* Tier */}
                      <td className="px-4 py-3">
                        <TierBadge tier={u.subscription_tier} />
                      </td>

                      {/* Status */}
                      <td className="px-4 py-3">
                        <StatusBadge status={u.subscription_status} />
                      </td>

                      {/* Scan limit */}
                      <td className="px-4 py-3 font-mono text-muted-foreground">
                        {u.monthly_scan_limit >= 1000000
                          ? "\u221E"
                          : u.monthly_scan_limit}
                      </td>

                      {/* Total scans */}
                      <td className="px-4 py-3 font-mono text-muted-foreground">
                        {u.total_scans}
                      </td>

                      {/* Billing */}
                      <td className="px-4 py-3">
                        {u.has_stripe ? (
                          <span className="flex items-center gap-1 text-primary text-[10px] font-bold">
                            <CreditCard className="w-3 h-3" /> Stripe
                          </span>
                        ) : (
                          <span className="text-muted-foreground text-[10px] font-bold">
                            {"\u2014"}
                          </span>
                        )}
                      </td>

                      {/* Joined */}
                      <td className="px-4 py-3 text-muted-foreground font-mono text-[10px]">
                        {u.created_at
                          ? new Date(u.created_at).toLocaleDateString(
                              "en-US",
                              {
                                month: "short",
                                day: "numeric",
                                year: "2-digit",
                              }
                            )
                          : "\u2014"}
                      </td>
                    </tr>

                    {/* Expanded Detail Panel */}
                    {expandedId === u.id && (
                      <UserDetailPanel
                        user={u}
                        detail={userDetail}
                        detailLoading={detailLoading}
                        actionLoading={actionLoading}
                        onAction={(action, payload) =>
                          handleAction(u.id, action, payload)
                        }
                      />
                    )}
                  </React.Fragment>
                ))
              )}
            </tbody>
          </table>
        </div>

        {/* Footer */}
        {!loading && filtered.length > 0 && (
          <div className="px-4 py-3 border-t border-[rgba(0,255,136,0.06)] flex items-center justify-between">
            <span className="text-[10px] text-muted-foreground font-mono">
              {filtered.length} of {total} users · Click a row to manage ·
              Auto-refreshes every 30s
            </span>
            <div className="flex gap-2">
              {Object.entries(tiers).map(([tier, count]) => (
                <span
                  key={tier}
                  className="text-[9px] font-black uppercase tracking-widest text-muted-foreground"
                >
                  {tierLabel(tier)}: {count}
                </span>
              ))}
            </div>
          </div>
        )}
      </GlowCard>
    </div>
  );
}
