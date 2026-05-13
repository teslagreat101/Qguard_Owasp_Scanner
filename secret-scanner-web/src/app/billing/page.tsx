"use client";

import { useState } from "react";
import { motion } from "framer-motion";
import { Sidebar } from "@/components/sidebar";
import { EmailVerificationCheck } from "@/components/email-verification-check";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import {
  CreditCard,
  Receipt,
  Download,
  AlertCircle,
  Loader2,
  Check,
  ExternalLink,
} from "lucide-react";
import { useBilling } from "@/lib/hooks";
import api, { type Invoice } from "@/lib/api";
import { toast } from "sonner";
import { GlowCard } from "@/components/ui/glow-card";
import { cn } from "@/lib/utils";

export default function BillingPage() {
  const {
    plans,
    subscription,
    paymentMethods,
    invoices,
    usage,
    loading,
    checkoutLoading,
    upgrade,
    cancel,
  } = useBilling();

  const [portalLoading, setPortalLoading] = useState(false);
  const [showCancelConfirm, setShowCancelConfirm] = useState(false);
  const [cancelLoading, setCancelLoading] = useState(false);

  const handleUpgrade = async (planId: string) => {
    const result = await upgrade(planId);
    if (result.success && result.mock) {
      toast.success("Mock upgrade successful! (Stripe not configured)");
    } else if (!result.success) {
      toast.error("Upgrade failed. Please try again.");
    }
  };

  const openBillingPortal = async () => {
    setPortalLoading(true);
    try {
      const { url } = await api.createBillingPortal(
        `${window.location.origin}/billing`
      );
      window.location.href = url;
    } catch (error: any) {
      toast.error(
        error.message ||
        "Failed to open billing portal. Please ensure you have an active subscription."
      );
    } finally {
      setPortalLoading(false);
    }
  };

  const handleDownloadInvoice = (invoice: Invoice) => {
    const url =
      invoice.invoice_pdf || invoice.hosted_invoice_url || invoice.pdf_url;
    if (url) {
      window.open(url, "_blank");
    } else {
      toast.error("Invoice PDF is not available for this transaction.");
    }
  };

  const handleCancel = async () => {
    setCancelLoading(true);
    try {
      const success = await cancel();
      if (success) {
        toast.success("Subscription cancelled successfully.");
        setShowCancelConfirm(false);
      } else {
        toast.error("Failed to cancel subscription. Please try again.");
      }
    } finally {
      setCancelLoading(false);
    }
  };

  const currentPlan = subscription?.plan_name || "Free";
  const scansUsed = subscription?.scans_used ?? usage?.scans_this_month ?? 0;
  const scansLimit = subscription?.scans_limit ?? usage?.scans_limit ?? 10;
  const scansPercent = Math.min(100, (scansUsed / scansLimit) * 100);
  const hasActivePaidSub =
    subscription && currentPlan.toLowerCase() !== "free";

  return (
    <EmailVerificationCheck>
      <Sidebar>
        <div className="space-y-6">
          {/* Header */}
          <motion.div
            initial={{ opacity: 0, y: -20 }}
            animate={{ opacity: 1, y: 0 }}
          >
            <h1 className="text-3xl font-black tracking-tighter flex items-center gap-3 text-foreground uppercase">
              <CreditCard className="h-8 w-8 text-primary" />
              Billing Ledger
            </h1>
            <p className="text-muted-foreground mt-1 text-xs uppercase tracking-widest font-bold">
              Subscription management and transaction history
            </p>
          </motion.div>

          <Tabs defaultValue="subscription" className="space-y-6">
            <TabsList className="grid w-full grid-cols-3 max-w-md bg-primary/5 border border-primary/10">
              <TabsTrigger
                value="subscription"
                className="data-[state=active]:bg-primary/10 data-[state=active]:text-primary uppercase text-[10px] font-bold tracking-widest"
              >
                Subscription
              </TabsTrigger>
              <TabsTrigger
                value="payment"
                className="data-[state=active]:bg-primary/10 data-[state=active]:text-primary uppercase text-[10px] font-bold tracking-widest"
              >
                Methods
              </TabsTrigger>
              <TabsTrigger
                value="invoices"
                className="data-[state=active]:bg-primary/10 data-[state=active]:text-primary uppercase text-[10px] font-bold tracking-widest"
              >
                Invoices
              </TabsTrigger>
            </TabsList>

            {/* ── Subscription Tab ── */}
            <TabsContent value="subscription" className="space-y-6">
              {/* Current Plan Card */}
              <motion.div
                initial={{ opacity: 0, y: 20 }}
                animate={{ opacity: 1, y: 0 }}
              >
                <GlowCard
                  className="p-0 border-primary/15"
                  glowColor="rgba(var(--primary), 0.1)"
                >
                  <div className="p-6">
                    <div className="flex items-center justify-between mb-4">
                      <div>
                        <h3 className="text-xl font-bold text-foreground uppercase tracking-tighter">
                          Current Plan
                        </h3>
                        <p className="text-muted-foreground text-sm font-medium">
                          You are currently on the {currentPlan} plan
                        </p>
                      </div>
                      <div className="flex items-center gap-3">
                        <Badge className="bg-primary/10 text-primary border-primary/20 font-black uppercase tracking-widest">
                          {currentPlan}
                        </Badge>
                        {hasActivePaidSub && !showCancelConfirm && (
                          <Button
                            variant="ghost"
                            size="sm"
                            onClick={() => setShowCancelConfirm(true)}
                            className="text-red-500/60 hover:text-red-400 hover:bg-red-500/10 text-[9px] font-black uppercase tracking-widest"
                          >
                            Cancel
                          </Button>
                        )}
                      </div>
                    </div>

                    {/* Cancel confirmation inline */}
                    {showCancelConfirm && (
                      <div className="mb-4 p-4 border border-red-500/20 rounded-xl bg-red-500/5">
                        <p className="text-xs text-red-400 font-bold uppercase tracking-widest mb-3">
                          Cancel subscription? You will lose access to premium
                          features at the end of the billing period.
                        </p>
                        <div className="flex gap-3">
                          <Button
                            size="sm"
                            onClick={handleCancel}
                            disabled={cancelLoading}
                            className="h-8 px-4 bg-red-500/20 hover:bg-red-500/30 text-red-400 border border-red-500/30 text-[9px] font-black uppercase tracking-widest"
                          >
                            {cancelLoading ? (
                              <Loader2 className="h-3 w-3 animate-spin mr-1" />
                            ) : null}
                            Confirm Cancel
                          </Button>
                          <Button
                            size="sm"
                            variant="ghost"
                            onClick={() => setShowCancelConfirm(false)}
                            className="h-8 px-4 text-muted-foreground hover:text-foreground text-[9px] font-black uppercase tracking-widest"
                          >
                            Keep Plan
                          </Button>
                        </div>
                      </div>
                    )}

                    <div className="space-y-4">
                      <div className="flex items-center justify-between text-xs font-mono">
                        <span className="text-muted-foreground uppercase tracking-widest">
                          Scans used this month
                        </span>
                        <span className="text-primary font-bold">
                          {scansUsed} / {scansLimit}
                        </span>
                      </div>
                      <div className="w-full bg-secondary rounded-full h-1.5 overflow-hidden border border-border/20">
                        <motion.div
                          className="bg-gradient-to-r from-primary to-blue-500 h-full rounded-full shadow-[0_0_10px_rgba(var(--primary),0.5)]"
                          initial={{ width: 0 }}
                          animate={{ width: `${scansPercent}%` }}
                          transition={{ duration: 1, ease: "easeOut" }}
                        />
                      </div>
                      <div className="flex items-center gap-2 text-[10px] text-muted-foreground uppercase tracking-widest">
                        <AlertCircle className="w-3 h-3" />
                        Usage resets on the 1st of each month
                      </div>
                    </div>
                  </div>
                </GlowCard>
              </motion.div>

              {/* Available Plans */}
              <div className="grid md:grid-cols-3 gap-6">
                {loading ? (
                  <div className="col-span-3 flex justify-center py-20">
                    <Loader2 className="h-10 w-10 animate-spin text-primary drop-shadow-[0_0_8px_rgba(0,255,136,0.5)]" />
                  </div>
                ) : (
                  Array.isArray(plans) &&
                  plans.map((plan, index) => (
                    <motion.div
                      key={plan.id}
                      initial={{ opacity: 0, y: 20 }}
                      animate={{ opacity: 1, y: 0 }}
                      transition={{ delay: index * 0.1 }}
                    >
                      <GlowCard
                        className={cn(
                          "h-full flex flex-col p-0 border-primary/10",
                          plan.popular && "border-primary/40"
                        )}
                        glowColor={
                          plan.popular
                            ? "rgba(var(--primary), 0.2)"
                            : "rgba(var(--foreground), 0.02)"
                        }
                      >
                        {plan.popular && (
                          <div className="bg-gradient-to-r from-primary to-blue-500 text-primary-foreground text-[9px] font-black text-center py-1.5 uppercase tracking-widest leading-none">
                            Most Popular Choice
                          </div>
                        )}
                        <div className="p-6 flex-1 flex flex-col">
                          <div className="mb-6">
                            <h4 className="text-xl font-black text-foreground uppercase tracking-tighter">
                              {plan.name}
                            </h4>
                            <div className="flex items-baseline gap-1 mt-2">
                              <span className="text-3xl font-black text-primary tracking-tighter">
                                {plan.price_formatted}
                              </span>
                              {plan.price_cents > 0 && (
                                <span className="text-muted-foreground text-xs font-mono uppercase tracking-widest">
                                  /{plan.interval}
                                </span>
                              )}
                            </div>
                            <p className="text-muted-foreground text-xs mt-3 leading-relaxed font-medium">
                              {plan.description}
                            </p>
                          </div>

                          <div className="h-px bg-border/30 w-full mb-6" />

                          <ul className="space-y-3 mb-8 flex-1">
                            {plan.features.map((feature: string) => (
                              <li
                                key={feature}
                                className="flex items-start gap-3 text-xs"
                              >
                                <div className="p-0.5 rounded-full bg-primary/10 border border-primary/20 mt-0.5">
                                  <Check className="h-3 w-3 text-primary" />
                                </div>
                                <span className="text-foreground font-medium">
                                  {feature}
                                </span>
                              </li>
                            ))}
                          </ul>

                          <Button
                            className={cn(
                              "w-full h-11 uppercase font-black text-[10px] tracking-widest transition-all duration-300",
                              plan.popular
                                ? "bg-primary text-primary-foreground hover:shadow-[0_0_20px_rgba(var(--primary),0.4)]"
                                : "bg-secondary text-foreground hover:bg-secondary/80 border border-border hover:border-border/80"
                            )}
                            onClick={() => handleUpgrade(plan.id)}
                            disabled={
                              plan.name.toLowerCase() ===
                              currentPlan.toLowerCase() || checkoutLoading
                            }
                          >
                            {checkoutLoading ? (
                              <Loader2 className="h-4 w-4 animate-spin mr-2" />
                            ) : null}
                            {plan.name.toLowerCase() ===
                              currentPlan.toLowerCase()
                              ? "Active Sub"
                              : `Activate ${plan.name} Node`}
                          </Button>
                        </div>
                      </GlowCard>
                    </motion.div>
                  ))
                )}
              </div>
            </TabsContent>

            {/* ── Payment Methods Tab ── */}
            <TabsContent value="payment">
              <motion.div
                initial={{ opacity: 0, y: 20 }}
                animate={{ opacity: 1, y: 0 }}
              >
                <GlowCard
                  className="p-0 border-border/20"
                  glowColor="rgba(var(--primary), 0.05)"
                >
                  <div className="p-6">
                    <div className="flex items-center justify-between mb-8">
                      <div>
                        <h3 className="text-xl font-bold text-foreground uppercase tracking-tighter">
                          Secure Payment Methods
                        </h3>
                        <p className="text-muted-foreground text-[10px] uppercase tracking-widest font-bold mt-1">
                          Encrypted financial assets on file
                        </p>
                      </div>
                      <Button
                        onClick={openBillingPortal}
                        disabled={portalLoading}
                        className="h-9 px-4 bg-primary/10 hover:bg-primary/20 text-primary border border-primary/20 text-[10px] font-black uppercase tracking-widest"
                      >
                        {portalLoading ? (
                          <Loader2 className="h-3.5 w-3.5 animate-spin mr-2" />
                        ) : (
                          <CreditCard className="h-3.5 w-3.5 mr-2" />
                        )}
                        Add Method
                      </Button>
                    </div>

                    {paymentMethods.length > 0 ? (
                      <div className="space-y-3">
                        {paymentMethods.map((method) => (
                          <div
                            key={method.id}
                            className="flex items-center justify-between p-4 border border-border/20 rounded-xl hover:border-primary/30 transition-colors bg-secondary/30"
                          >
                            <div className="flex items-center gap-4">
                              <div className="w-12 h-8 bg-secondary rounded-lg flex items-center justify-center border border-border/30">
                                <CreditCard className="h-5 w-5 text-primary" />
                              </div>
                              <div>
                                <p className="font-mono text-sm text-foreground">
                                  {method.brand.toUpperCase()} ••••{" "}
                                  {method.last4}
                                </p>
                                <p className="text-[10px] text-muted-foreground uppercase tracking-widest font-bold">
                                  Expires {method.exp_month}/{method.exp_year}
                                </p>
                              </div>
                            </div>
                            <div className="flex items-center gap-3">
                              {method.is_default && (
                                <Badge className="bg-primary/10 text-primary border-primary/20 text-[9px] font-black uppercase tracking-widest">
                                  Active Default
                                </Badge>
                              )}
                              <Button
                                variant="ghost"
                                size="sm"
                                onClick={openBillingPortal}
                                disabled={portalLoading}
                                className="text-muted-foreground hover:text-primary uppercase text-[9px] font-black tracking-widest"
                              >
                                Edit
                              </Button>
                            </div>
                          </div>
                        ))}
                      </div>
                    ) : (
                      <div className="text-center py-16">
                        <div className="w-16 h-16 bg-secondary border border-border/20 rounded-full flex items-center justify-center mx-auto mb-4">
                          <CreditCard className="h-8 w-8 text-muted-foreground" />
                        </div>
                        <p className="text-muted-foreground text-xs uppercase tracking-widest font-bold mb-6">
                          No payment sources detected
                        </p>
                        <Button
                          onClick={openBillingPortal}
                          disabled={portalLoading}
                          className="h-10 px-6 bg-primary text-primary-foreground font-black uppercase text-[10px] tracking-widest"
                        >
                          {portalLoading ? (
                            <Loader2 className="h-4 w-4 animate-spin mr-2" />
                          ) : null}
                          Initialize First Node
                        </Button>
                      </div>
                    )}
                  </div>
                </GlowCard>
              </motion.div>
            </TabsContent>

            {/* ── Invoices Tab ── */}
            <TabsContent value="invoices">
              <motion.div
                initial={{ opacity: 0, y: 20 }}
                animate={{ opacity: 1, y: 0 }}
              >
                <GlowCard
                  className="p-0 border-border/20"
                  glowColor="rgba(var(--foreground), 0.02)"
                >
                  <div className="p-6">
                    <div className="flex items-center justify-between mb-8">
                      <div>
                        <h3 className="text-xl font-bold text-foreground uppercase tracking-tighter flex items-center gap-2">
                          <Receipt className="h-5 w-5 text-primary" />
                          Intelligence Billing Logs
                        </h3>
                        <p className="text-muted-foreground text-[10px] uppercase tracking-widest font-bold mt-1">
                          Historical transaction telemetry
                        </p>
                      </div>
                      <Button
                        variant="ghost"
                        size="sm"
                        onClick={openBillingPortal}
                        disabled={portalLoading}
                        className="text-blue-500/60 hover:text-blue-500 hover:bg-blue-500/10 text-[9px] font-black uppercase tracking-widest gap-1"
                      >
                        <ExternalLink className="h-3.5 w-3.5" />
                        Manage in Stripe
                      </Button>
                    </div>

                    <div className="space-y-2">
                      {invoices.length > 0 ? (
                        invoices.map((invoice) => (
                          <div
                            key={invoice.id}
                            className="flex items-center justify-between p-4 border border-border/20 rounded-xl hover:bg-secondary/30 transition-colors group"
                          >
                            <div className="flex items-center gap-4">
                              <div className="w-10 h-10 bg-secondary rounded-full flex items-center justify-center border border-border/20 group-hover:border-primary/30 transition-colors">
                                <Receipt className="h-4 w-4 text-muted-foreground group-hover:text-primary" />
                              </div>
                              <div>
                                <p className="font-mono text-sm text-foreground">
                                  {invoice.number || invoice.id}
                                </p>
                                <p className="text-[10px] text-muted-foreground uppercase tracking-widest font-bold">
                                  {invoice.date} • {invoice.plan_name}
                                </p>
                              </div>
                            </div>
                            <div className="flex items-center gap-6">
                              <div className="text-right">
                                <p className="font-mono text-sm text-foreground font-black">
                                  {invoice.amount_formatted}
                                </p>
                                <Badge
                                  className={cn(
                                    "text-[9px] font-black uppercase tracking-widest",
                                    invoice.status === "Paid"
                                      ? "bg-primary/10 text-primary border-primary/20"
                                      : "bg-secondary text-muted-foreground border-border/30"
                                  )}
                                >
                                  {invoice.status}
                                </Badge>
                              </div>
                              <Button
                                variant="ghost"
                                size="icon"
                                onClick={() => handleDownloadInvoice(invoice)}
                                className="text-muted-foreground hover:text-primary hover:bg-primary/10 transition-colors rounded-lg"
                                title="Download invoice PDF"
                              >
                                <Download className="h-4 w-4" />
                              </Button>
                            </div>
                          </div>
                        ))
                      ) : (
                        <div className="text-center py-16">
                          <div className="w-16 h-16 bg-secondary border border-border/20 rounded-full flex items-center justify-center mx-auto mb-4">
                            <Receipt className="h-8 w-8 text-muted-foreground" />
                          </div>
                          <p className="text-muted-foreground text-xs uppercase tracking-widest font-bold">
                            No billing history found
                          </p>
                        </div>
                      )}
                    </div>
                  </div>
                </GlowCard>
              </motion.div>
            </TabsContent>
          </Tabs>
        </div>
      </Sidebar>
    </EmailVerificationCheck>
  );
}
