"use client";

import { useState, useRef } from "react";
import { motion } from "framer-motion";
import { Sidebar } from "@/components/sidebar";
import { useAuth } from "@/contexts/auth-context";
import { EmailVerificationCheck } from "@/components/email-verification-check";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Switch } from "@/components/ui/switch";
import { Avatar, AvatarFallback } from "@/components/ui/avatar";
import { Badge } from "@/components/ui/badge";
import { Separator } from "@/components/ui/separator";
import {
  User,
  Mail,
  Lock,
  Shield,
  Smartphone,
  Loader2,
  CheckCircle,
  AlertCircle,
  Save,
} from "lucide-react";
import {
  updateUserEmail,
  updateUserPassword,
  updateUserProfile,
  createRecaptchaVerifier,
  sendPhone2FACode,
  completePhone2FAEnrollment,
  unenrollPhone2FA,
} from "@/lib/firebase";
import { toast } from "sonner";
import { GlowCard } from "@/components/ui/glow-card";
import { cn } from "@/lib/utils";

export default function SettingsPage() {
  const { user, isEmailVerified, has2FA } = useAuth();

  // Profile form state
  const [displayName, setDisplayName] = useState(user?.displayName || "");
  const [isUpdatingProfile, setIsUpdatingProfile] = useState(false);

  // Email form state
  const [newEmail, setNewEmail] = useState("");
  const [emailPassword, setEmailPassword] = useState("");
  const [isUpdatingEmail, setIsUpdatingEmail] = useState(false);

  // Password form state
  const [currentPassword, setCurrentPassword] = useState("");
  const [newPassword, setNewPassword] = useState("");
  const [confirmNewPassword, setConfirmNewPassword] = useState("");
  const [isUpdatingPassword, setIsUpdatingPassword] = useState(false);

  // 2FA state
  const [is2FAEnabled, setIs2FAEnabled] = useState(has2FA);
  const [isUpdating2FA, setIsUpdating2FA] = useState(false);
  const [phoneNumber, setPhoneNumber] = useState("");
  const [verificationCode, setVerificationCode] = useState("");
  const [verificationId, setVerificationId] = useState<string | null>(null);
  const [show2FASetup, setShow2FASetup] = useState(false);
  const recaptchaRef = useRef<any>(null);

  const getInitials = (name: string) => {
    return name
      .split(" ")
      .map((n) => n[0])
      .join("")
      .toUpperCase()
      .slice(0, 2);
  };

  const handleUpdateProfile = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!user) return;
    setIsUpdatingProfile(true);
    try {
      await updateUserProfile(user, displayName);
    } catch (error) {
      // toast handled in firebase.ts
    } finally {
      setIsUpdatingProfile(false);
    }
  };

  const handleUpdateEmail = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!user) return;
    setIsUpdatingEmail(true);
    try {
      await updateUserEmail(user, newEmail, emailPassword);
      setNewEmail("");
      setEmailPassword("");
    } catch (error) {
      // toast handled in firebase.ts
    } finally {
      setIsUpdatingEmail(false);
    }
  };

  const handleUpdatePassword = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!user) return;
    if (newPassword !== confirmNewPassword) {
      toast.error("New passwords do not match");
      return;
    }
    if (newPassword.length < 6) {
      toast.error("Password must be at least 6 characters");
      return;
    }
    setIsUpdatingPassword(true);
    try {
      await updateUserPassword(user, currentPassword, newPassword);
      setCurrentPassword("");
      setNewPassword("");
      setConfirmNewPassword("");
    } catch (error) {
      // toast handled in firebase.ts
    } finally {
      setIsUpdatingPassword(false);
    }
  };

  const handle2FAToggle = async (enabled: boolean) => {
    if (enabled) {
      setShow2FASetup(true);
      return;
    }
    // Disabling 2FA
    if (!user) return;
    setIsUpdating2FA(true);
    try {
      await unenrollPhone2FA(user);
      setIs2FAEnabled(false);
      setShow2FASetup(false);
      setVerificationId(null);
    } catch (error) {
      // toast handled in firebase.ts
    } finally {
      setIsUpdating2FA(false);
    }
  };

  const handleSend2FACode = async () => {
    if (!user || !phoneNumber.trim()) {
      toast.error("Please enter a valid phone number");
      return;
    }
    setIsUpdating2FA(true);
    try {
      // Clear previous verifier
      if (recaptchaRef.current) {
        recaptchaRef.current.clear();
        recaptchaRef.current = null;
      }
      const appVerifier = createRecaptchaVerifier("recaptcha-container");
      recaptchaRef.current = appVerifier;
      const vid = await sendPhone2FACode(user, phoneNumber, appVerifier);
      setVerificationId(vid);
    } catch (error) {
      // toast handled in firebase.ts
      recaptchaRef.current = null;
    } finally {
      setIsUpdating2FA(false);
    }
  };

  const handleVerify2FA = async () => {
    if (!user || !verificationId || !verificationCode.trim()) {
      toast.error("Please enter the verification code");
      return;
    }
    setIsUpdating2FA(true);
    try {
      await completePhone2FAEnrollment(user, verificationId, verificationCode);
      setIs2FAEnabled(true);
      setShow2FASetup(false);
      setVerificationId(null);
      setVerificationCode("");
      setPhoneNumber("");
    } catch (error) {
      // toast handled in firebase.ts
    } finally {
      setIsUpdating2FA(false);
    }
  };

  const inputClass =
    "bg-secondary/30 border-border/30 text-foreground focus:border-primary focus:ring-1 focus:ring-primary/30 placeholder:text-muted-foreground transition-colors duration-300 rounded-xl py-6";

  const labelClass =
    "text-[10px] uppercase tracking-[0.2em] font-bold text-muted-foreground mb-2 block";

  return (
    <EmailVerificationCheck>
      {/* Invisible recaptcha mount point for phone 2FA */}
      <div id="recaptcha-container" />

      <Sidebar>
        <div className="space-y-6">
          {/* Header */}
          <motion.div
            initial={{ opacity: 0, y: -20 }}
            animate={{ opacity: 1, y: 0 }}
          >
            <h1 className="text-3xl font-black tracking-tighter flex items-center gap-3 text-foreground uppercase">
              <User className="h-8 w-8 text-primary" />
              Security Profile
            </h1>
            <p className="text-muted-foreground mt-1 text-xs uppercase tracking-widest font-bold">
              Identity management and protocol authorization
            </p>
          </motion.div>

          {/* Profile Overview Card */}
          <motion.div
            initial={{ opacity: 0, y: 20 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ delay: 0.1 }}
          >
            <GlowCard
              className="p-0 border-border/20"
              glowColor="rgba(var(--primary), 0.1)"
            >
              <div className="p-6 flex items-center gap-8">
                <div className="relative group">
                  <div className="absolute inset-0 bg-primary rounded-full blur-[20px] opacity-0 group-hover:opacity-20 transition-opacity" />
                  <Avatar className="h-24 w-24 border-2 border-primary/20 group-hover:border-primary/40 transition-all duration-500">
                    <AvatarFallback className="bg-primary/5 text-primary text-3xl font-black font-mono">
                      {user?.displayName
                        ? getInitials(user.displayName)
                        : user?.email?.[0].toUpperCase() || "U"}
                    </AvatarFallback>
                  </Avatar>
                </div>
                <div className="flex-1">
                  <h2 className="text-3xl font-black text-foreground uppercase tracking-tighter">
                    {user?.displayName || "Operator"}
                  </h2>
                  <p className="font-mono text-sm text-muted-foreground mt-1">
                    {user?.email}
                  </p>
                  <div className="flex gap-3 mt-4">
                    <Badge
                      className={cn(
                        "text-[9px] font-black uppercase tracking-widest px-3 py-1",
                        isEmailVerified
                          ? "bg-primary/10 text-primary border-primary/20"
                          : "bg-destructive/10 text-destructive border-destructive/20"
                      )}
                    >
                      {isEmailVerified ? (
                        <>
                          <CheckCircle className="h-3 w-3 mr-1" />
                          Verified Node
                        </>
                      ) : (
                        <>
                          <AlertCircle className="h-3 w-3 mr-1" />
                          Unverified ID
                        </>
                      )}
                    </Badge>
                    {(has2FA || is2FAEnabled) && (
                      <Badge className="bg-blue-500/10 text-blue-500 border-blue-500/20 text-[9px] font-black uppercase tracking-widest px-3 py-1">
                        <Shield className="h-3 w-3 mr-1" />
                        MFA ACTIVE
                      </Badge>
                    )}
                  </div>
                </div>
              </div>
            </GlowCard>
          </motion.div>

          {/* Settings Tabs */}
          <Tabs defaultValue="profile" className="space-y-6">
            <TabsList className="grid w-full grid-cols-3 lg:grid-cols-4 max-w-2xl bg-primary/5 border border-primary/10">
              <TabsTrigger
                value="profile"
                className="data-[state=active]:bg-primary/10 data-[state=active]:text-primary uppercase text-[10px] font-bold tracking-widest"
              >
                Profile
              </TabsTrigger>
              <TabsTrigger
                value="email"
                className="data-[state=active]:bg-primary/10 data-[state=active]:text-primary uppercase text-[10px] font-bold tracking-widest"
              >
                Email
              </TabsTrigger>
              <TabsTrigger
                value="password"
                className="data-[state=active]:bg-primary/10 data-[state=active]:text-primary uppercase text-[10px] font-bold tracking-widest"
              >
                Password
              </TabsTrigger>
              <TabsTrigger
                value="security"
                className="data-[state=active]:bg-primary/10 data-[state=active]:text-primary uppercase text-[10px] font-bold tracking-widest"
              >
                Security
              </TabsTrigger>
            </TabsList>

            {/* ── Profile Tab ── */}
            <TabsContent value="profile">
              <motion.div
                initial={{ opacity: 0, x: -20 }}
                animate={{ opacity: 1, x: 0 }}
              >
                <GlowCard
                  className="p-0 border-border/20"
                  glowColor="rgba(var(--primary), 0.05)"
                >
                  <div className="p-8">
                    <div className="mb-8">
                      <h3 className="text-xl font-bold text-foreground uppercase tracking-tighter">
                        Identity Configuration
                      </h3>
                      <p className="text-muted-foreground text-[10px] uppercase tracking-widest font-bold mt-1">
                        Update primary operator parameters
                      </p>
                    </div>

                    <form onSubmit={handleUpdateProfile} className="space-y-6">
                      <div className="space-y-2">
                        <Label
                          htmlFor="display-name"
                          className={labelClass}
                        >
                          Call Sign (Display Name)
                        </Label>
                        <Input
                          id="display-name"
                          value={displayName}
                          onChange={(e) => setDisplayName(e.target.value)}
                          placeholder="OPERATOR NAME"
                          className={inputClass}
                        />
                      </div>
                      <div className="space-y-2">
                        <Label
                          htmlFor="profile-email"
                          className={labelClass}
                        >
                          Registered Data Link (Email)
                        </Label>
                        <Input
                          id="profile-email"
                          value={user?.email || ""}
                          disabled
                          className="bg-secondary border-border/20 text-muted-foreground rounded-xl py-6 opacity-50 font-mono"
                        />
                        <p className="text-[10px] text-muted-foreground uppercase font-bold tracking-widest ml-1">
                          Email modification requires secure re-authentication
                        </p>
                      </div>
                      <Button
                        type="submit"
                        disabled={isUpdatingProfile}
                        className="h-12 px-8 bg-primary text-primary-foreground font-black uppercase text-[10px] tracking-widest hover:shadow-[0_0_20px_rgba(var(--primary),0.3)] transition-all"
                      >
                        {isUpdatingProfile ? (
                          <Loader2 className="h-4 w-4 animate-spin mr-2" />
                        ) : (
                          <Save className="h-4 w-4 mr-2" />
                        )}
                        Commit Changes
                      </Button>
                    </form>
                  </div>
                </GlowCard>
              </motion.div>
            </TabsContent>

            {/* ── Email Tab ── */}
            <TabsContent value="email">
              <motion.div
                initial={{ opacity: 0, x: -20 }}
                animate={{ opacity: 1, x: 0 }}
              >
                <GlowCard
                  className="p-0 border-border/20"
                  glowColor="rgba(var(--primary), 0.05)"
                >
                  <div className="p-8">
                    <div className="mb-8">
                      <h3 className="text-xl font-bold text-foreground uppercase tracking-tighter flex items-center gap-2">
                        <Mail className="h-5 w-5 text-primary" />
                        Secure Email Migration
                      </h3>
                      <p className="text-muted-foreground text-[10px] uppercase tracking-widest font-bold mt-1">
                        Re-route primary communication channels
                      </p>
                    </div>

                    <form onSubmit={handleUpdateEmail} className="space-y-6">
                      <div className="space-y-2">
                        <Label htmlFor="current-email" className={labelClass}>
                          Origin Address
                        </Label>
                        <Input
                          id="current-email"
                          value={user?.email || ""}
                          disabled
                          className="bg-secondary border-border/20 text-muted-foreground rounded-xl py-6 opacity-50 font-mono"
                        />
                      </div>
                      <div className="space-y-2">
                        <Label htmlFor="new-email" className={labelClass}>
                          Destination Address
                        </Label>
                        <Input
                          id="new-email"
                          type="email"
                          value={newEmail}
                          onChange={(e) => setNewEmail(e.target.value)}
                          placeholder="NEW-LINK@VAULT.COM"
                          required
                          className={inputClass}
                        />
                      </div>
                      <Separator className="bg-white/5" />
                      <div className="space-y-2">
                        <Label
                          htmlFor="email-password"
                          className={labelClass}
                        >
                          Verification Cipher (Current Password)
                        </Label>
                        <Input
                          id="email-password"
                          type="password"
                          value={emailPassword}
                          onChange={(e) => setEmailPassword(e.target.value)}
                          placeholder="ENTER PASSWORD TO AUTHORIZE"
                          required
                          className={inputClass}
                        />
                      </div>
                      <Button
                        type="submit"
                        disabled={isUpdatingEmail}
                        className="h-12 px-8 bg-primary text-primary-foreground font-black uppercase text-[10px] tracking-widest transition-all"
                      >
                        {isUpdatingEmail ? (
                          <Loader2 className="h-4 w-4 animate-spin mr-2" />
                        ) : (
                          <Mail className="h-4 w-4 mr-2" />
                        )}
                        Authorize Migration
                      </Button>
                    </form>
                  </div>
                </GlowCard>
              </motion.div>
            </TabsContent>

            {/* ── Password Tab ── */}
            <TabsContent value="password">
              <motion.div
                initial={{ opacity: 0, x: -20 }}
                animate={{ opacity: 1, x: 0 }}
              >
                <GlowCard
                  className="p-0 border-border/20"
                  glowColor="rgba(var(--destructive), 0.05)"
                >
                  <div className="p-8">
                    <div className="mb-8">
                      <h3 className="text-xl font-bold text-foreground uppercase tracking-tighter flex items-center gap-2">
                        <Lock className="h-5 w-5 text-primary" />
                        Access Key Rotation
                      </h3>
                      <p className="text-muted-foreground text-[10px] uppercase tracking-widest font-bold mt-1">
                        Rotate security credentials to maintain integrity
                      </p>
                    </div>

                    <form
                      onSubmit={handleUpdatePassword}
                      className="space-y-6"
                    >
                      <div className="space-y-2">
                        <Label
                          htmlFor="current-password"
                          className={labelClass}
                        >
                          Old Access Key
                        </Label>
                        <Input
                          id="current-password"
                          type="password"
                          value={currentPassword}
                          onChange={(e) => setCurrentPassword(e.target.value)}
                          placeholder="CURRENT CIPHER"
                          required
                          className={inputClass}
                        />
                      </div>
                      <Separator className="bg-white/5" />
                      <div className="space-y-4">
                        <div className="space-y-2">
                          <Label htmlFor="new-password" className={labelClass}>
                            New Access Key
                          </Label>
                          <Input
                            id="new-password"
                            type="password"
                            value={newPassword}
                            onChange={(e) => setNewPassword(e.target.value)}
                            placeholder="MIN 12 CHARACTERS RECOMMENDED"
                            required
                            minLength={6}
                            className={inputClass}
                          />
                        </div>
                        <div className="space-y-2">
                          <Label
                            htmlFor="confirm-new-password"
                            className={labelClass}
                          >
                            Confirm New Key
                          </Label>
                          <Input
                            id="confirm-new-password"
                            type="password"
                            value={confirmNewPassword}
                            onChange={(e) =>
                              setConfirmNewPassword(e.target.value)
                            }
                            placeholder="REPEAT NEW CIPHER"
                            required
                            className={inputClass}
                          />
                        </div>
                      </div>
                      <Button
                        type="submit"
                        disabled={isUpdatingPassword}
                        className="h-12 px-8 bg-primary text-primary-foreground font-black uppercase text-[10px] tracking-widest"
                      >
                        {isUpdatingPassword ? (
                          <Loader2 className="h-4 w-4 animate-spin mr-2" />
                        ) : (
                          <Lock className="h-4 w-4 mr-2" />
                        )}
                        Execute Rotation
                      </Button>
                    </form>
                  </div>
                </GlowCard>
              </motion.div>
            </TabsContent>

            {/* ── Security Tab ── */}
            <TabsContent value="security">
              <motion.div
                initial={{ opacity: 0, x: -20 }}
                animate={{ opacity: 1, x: 0 }}
                className="space-y-6"
              >
                <GlowCard
                  className="p-0 border-border/20"
                  glowColor="rgba(var(--primary), 0.05)"
                >
                  <div className="p-8">
                    <div className="flex items-center justify-between mb-8">
                      <div>
                        <h3 className="text-xl font-bold text-foreground uppercase tracking-tighter flex items-center gap-2">
                          <Shield className="h-5 w-5 text-primary" />
                          Multi-Factor Auth (MFA)
                        </h3>
                        <p className="text-muted-foreground text-[10px] uppercase tracking-widest font-bold mt-1">
                          Secondary verification protocol
                        </p>
                      </div>
                      <Switch
                        checked={is2FAEnabled}
                        onCheckedChange={handle2FAToggle}
                        disabled={isUpdating2FA}
                      />
                    </div>

                    {show2FASetup && (
                      <motion.div
                        initial={{ opacity: 0, height: 0 }}
                        animate={{ opacity: 1, height: "auto" }}
                        className="space-y-6 pt-6 border-t border-border/20"
                      >
                        {/* Step 1: Enter phone and send code */}
                        <div className="space-y-2">
                          <Label
                            htmlFor="phone-number"
                            className={labelClass}
                          >
                            Communication Link (Phone)
                          </Label>
                          <div className="flex gap-3">
                            <Input
                              id="phone-number"
                              type="tel"
                              value={phoneNumber}
                              onChange={(e) => setPhoneNumber(e.target.value)}
                              placeholder="+1 (555) 000-0000"
                              disabled={!!verificationId}
                              className={inputClass}
                            />
                            <Button
                              type="button"
                              variant="outline"
                              onClick={handleSend2FACode}
                              disabled={isUpdating2FA || !!verificationId}
                              className="border-border/30 text-foreground hover:text-primary hover:border-primary/40 h-14 px-6 uppercase text-[10px] font-black"
                            >
                              {isUpdating2FA && !verificationId ? (
                                <Loader2 className="h-4 w-4 animate-spin" />
                              ) : (
                                "Transmit"
                              )}
                            </Button>
                          </div>
                        </div>

                        {/* Step 2: Enter the received code (visible after sending) */}
                        {verificationId && (
                          <div className="space-y-2">
                            <Label
                              htmlFor="verification-code"
                              className={labelClass}
                            >
                              Received Cipher Code
                            </Label>
                            <Input
                              id="verification-code"
                              value={verificationCode}
                              onChange={(e) =>
                                setVerificationCode(e.target.value)
                              }
                              placeholder="6-DIGIT CODE"
                              maxLength={6}
                              className={cn(
                                inputClass,
                                "text-center tracking-[0.5em] text-2xl"
                              )}
                            />
                          </div>
                        )}

                        <div className="flex gap-3">
                          <Button
                            onClick={handleVerify2FA}
                            disabled={isUpdating2FA || !verificationId}
                            className="h-12 px-8 bg-primary text-primary-foreground font-black uppercase text-[10px] tracking-widest"
                          >
                            {isUpdating2FA && verificationId ? (
                              <Loader2 className="h-4 w-4 animate-spin mr-2" />
                            ) : (
                              <Smartphone className="h-4 w-4 mr-2" />
                            )}
                            Verify & Activate
                          </Button>
                          <Button
                            variant="ghost"
                            onClick={() => {
                              setShow2FASetup(false);
                              setVerificationId(null);
                              setVerificationCode("");
                              setPhoneNumber("");
                            }}
                            className="h-12 px-6 text-muted-foreground hover:text-foreground uppercase text-[10px] font-bold"
                          >
                            Abort
                          </Button>
                        </div>
                      </motion.div>
                    )}
                  </div>
                </GlowCard>

                <GlowCard
                  className="p-0 border-border/20"
                  glowColor="rgba(var(--foreground), 0.02)"
                >
                  <div className="p-8">
                    <h3 className="text-xl font-bold text-foreground uppercase tracking-tighter mb-6">
                      Active Security Sessions
                    </h3>
                    <div className="space-y-3">
                      <div className="flex items-center justify-between p-4 rounded-xl bg-secondary/20 border border-border/20 hover:border-primary/20 transition-colors group">
                        <div className="flex items-center gap-4">
                          <div className="relative">
                            <div className="absolute inset-0 bg-primary rounded-full blur-[8px] animate-pulse opacity-40" />
                            <div className="relative w-2 h-2 bg-primary rounded-full" />
                          </div>
                          <div>
                            <p className="font-mono text-sm text-foreground">
                              CURRENT OPERATOR NODE
                            </p>
                            <p className="text-[10px] text-muted-foreground uppercase font-black tracking-widest">
                              Active Now • This Device
                            </p>
                          </div>
                        </div>
                        <Badge className="bg-primary/10 text-primary border-primary/20 text-[9px] font-black uppercase tracking-widest">
                          ACTIVE
                        </Badge>
                      </div>
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
