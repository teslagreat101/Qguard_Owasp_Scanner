"use client";

import { useState, useEffect } from "react";
import { motion, AnimatePresence } from "framer-motion";
import { Button } from "@/components/ui/button";
import Image from "next/image";
import QuantaraLogo from "@/components/data/Quantara_Logo.png";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { useAuth } from "@/contexts/auth-context";
import {
  Hexagon,
  Brain,
  ShieldCheck,
  Fingerprint,
  Mail,
  Lock,
  User,
  Chrome,
  Loader2,
  Zap,
  Shield,
  ArrowLeft
} from "lucide-react";
import { toast } from "sonner";
import Link from "next/link";
import { AuthorizationModal, TERMS_VERSION } from "@/components/legal/AuthorizationModal";

const TERMS_STORAGE_KEY = "quantara_terms_accepted";

const ScannerIcon = () => (
  <div className="relative w-20 h-20 flex items-center justify-center">
    <motion.div
      animate={{ scale: [1, 1.1, 1] }}
      transition={{ duration: 2, repeat: Infinity, ease: "easeInOut" }}
      className="absolute inset-0 rounded-full border-2 border-primary/30"
    />
    <motion.div
      animate={{ rotate: 360 }}
      transition={{ duration: 4, repeat: Infinity, ease: "linear" }}
      className="absolute inset-0 rounded-full border-t-2 border-primary"
      style={{ filter: "drop-shadow(0 0 8px #00FF88)" }}
    />
    <Zap className="w-8 h-8 text-primary" />
  </div>
);

const LaserLine = () => (
  <motion.div
    animate={{ top: ["-10%", "110%"] }}
    transition={{ duration: 4, repeat: Infinity, ease: "linear" }}
    className="absolute left-0 right-0 h-[2px] bg-primary z-10 pointer-events-none"
    style={{
      boxShadow: "0 0 20px 4px rgba(0, 255, 136, 0.8), 0 0 50px 15px rgba(0, 255, 136, 0.4)",
    }}
  />
);

const GridBackground = () => (
  <div className="absolute inset-0 z-0 pointer-events-none opacity-20"
    style={{
      backgroundImage: `linear-gradient(to right, rgba(0,255,136,0.13) 1px, transparent 1px),
                        linear-gradient(to bottom, rgba(0,255,136,0.13) 1px, transparent 1px)`,
      backgroundSize: "40px 40px",
    }}
  />
);

export default function LoginPage() {
  const [activeTab, setActiveTab] = useState("login");
  const [isLoading, setIsLoading] = useState(false);
  const [showVerification, setShowVerification] = useState(false);
  const [registerEmail, setRegisterEmailState] = useState("");
  const [showTermsModal, setShowTermsModal] = useState(false);
  const { login, register, loginWithGoogle, resendVerificationEmail } = useAuth();

  // Check if terms were already accepted (localStorage fast path)
  useEffect(() => {
    try {
      const raw = localStorage.getItem(TERMS_STORAGE_KEY);
      if (raw) {
        const record = JSON.parse(raw);
        if (record?.version === TERMS_VERSION) {
          // Already accepted — no modal needed
          return;
        }
      }
    } catch {
      // ignore parse errors
    }
    // Not accepted or stale — show modal
    setShowTermsModal(true);
  }, []);

  const handleTermsAccept = () => {
    localStorage.setItem(
      TERMS_STORAGE_KEY,
      JSON.stringify({ version: TERMS_VERSION, accepted_at: new Date().toISOString() })
    );
    setShowTermsModal(false);
  };

  const handleTermsDecline = () => {
    // Pre-auth decline: redirect home — user cannot use the platform
    window.location.href = "/";
  };

  // Login form state
  const [loginEmail, setLoginEmail] = useState("");
  const [loginPassword, setLoginPassword] = useState("");

  // Register form state
  const [registerName, setRegisterName] = useState("");
  const [registerPassword, setRegisterPassword] = useState("");
  const [confirmPassword, setConfirmPassword] = useState("");

  const handleLogin = async (e: React.FormEvent) => {
    e.preventDefault();
    setIsLoading(true);
    try {
      await login(loginEmail, loginPassword);
      window.location.href = "/dashboard";
    } catch (error) {
      // Error handled by auth context
    } finally {
      setIsLoading(false);
    }
  };

  const handleRegister = async (e: React.FormEvent) => {
    e.preventDefault();
    if (registerPassword !== confirmPassword) {
      toast.error("Passwords do not match");
      return;
    }
    if (registerPassword.length < 6) {
      toast.error("Password must be at least 6 characters");
      return;
    }
    setIsLoading(true);
    try {
      await register(registerEmail, registerPassword);
      setRegisterEmailState(registerEmail);
      setShowVerification(true);
    } catch (error) {
      // Error handled by auth context
    } finally {
      setIsLoading(false);
    }
  };

  const handleGoogleSignIn = async () => {
    setIsLoading(true);
    try {
      await loginWithGoogle();
      window.location.href = "/dashboard";
    } catch (error) {
      // Error handled by auth context
    } finally {
      setIsLoading(false);
    }
  };

  const handleResendVerification = async () => {
    setIsLoading(true);
    try {
      await resendVerificationEmail();
    } catch (error) {
      // Error handled by auth context
    } finally {
      setIsLoading(false);
    }
  };

  return (
    <div className="min-h-screen bg-background flex items-center justify-center relative overflow-hidden">
      {/* Authorization & Legal Terms Modal — shown before login form */}
      {showTermsModal && (
        <AuthorizationModal
          onAccept={handleTermsAccept}
          onDecline={handleTermsDecline}
        />
      )}

      {/* Background Effects */}
      <div className="absolute inset-0 bg-[#050505] z-[-2]" />
      <GridBackground />

      {/* Ambient Glow */}
      <div className="absolute top-1/4 left-1/4 w-[500px] h-[500px] rounded-full bg-primary/[0.03] blur-[120px] pointer-events-none" />
      <div className="absolute bottom-1/3 right-1/4 w-[400px] h-[400px] rounded-full bg-[#00C853]/[0.04] blur-[100px] pointer-events-none" />

      {/* Back to Home Link */}
      <Link
        href="/"
        className="absolute top-6 left-6 flex items-center gap-2 text-muted-foreground hover:text-primary transition-colors z-50"
      >
        <ArrowLeft className="w-4 h-4" />
        <span className="text-xs font-bold uppercase tracking-widest">Return to Base</span>
      </Link>

      <Link href="/" className="absolute top-6 left-1/2 -translate-x-1/2 flex items-center gap-2.5 z-50 lg:hidden">
        <div className="relative w-10 h-10 flex items-center justify-center">
          <Image
            src={QuantaraLogo}
            alt="Quantara Security Logo"
            width={32}
            height={32}
            className="relative z-10 drop-shadow-[0_0_8px_rgba(0,255,136,0.5)]"
          />
          <div className="absolute inset-0 bg-primary/15 blur-xl rounded-full animate-pulse" />
        </div>
        <span className="text-xl font-extrabold font-outfit tracking-tight text-foreground">
          Quantara <span className="text-primary">Security</span>
        </span>
      </Link>

      {/* Main Content Container */}
      <div className="relative z-20 w-full max-w-7xl mx-auto px-6 lg:px-12">
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-12 lg:gap-24 items-center">

          {/* Left Column: Strategic Details */}
          <motion.div
            initial={{ opacity: 0, x: -30 }}
            animate={{ opacity: 1, x: 0 }}
            transition={{ duration: 0.8, ease: "easeOut" }}
            className="hidden lg:flex flex-col space-y-12"
          >
            {/* Project Branding */}
            <div className="space-y-4">
              <div className="flex items-center gap-5">
                <div className="relative w-14 h-14 flex items-center justify-center shrink-0">
                  <Image
                    src={QuantaraLogo}
                    alt="Quantara Logo"
                    width={56}
                    height={56}
                    className="relative z-10 drop-shadow-[0_0_12px_rgba(0,255,136,0.5)]"
                  />
                  <div className="absolute inset-0 bg-primary/15 blur-xl rounded-full" />
                </div>
                <div className="flex flex-col">
                  <h2 className="text-2xl font-black text-foreground tracking-tighter uppercase leading-none">
                    Quantara Security Protocol
                  </h2>
                  <span className="text-[10px] text-primary font-bold tracking-[0.4em] uppercase">
                    Advanced Security Platform
                  </span>
                </div>
              </div>
            </div>

            {/* Main Headline */}
            <h3 className="text-5xl font-black text-foreground tracking-tighter leading-[1.1] max-w-lg">
              Secure Access to Your <span className="text-transparent bg-clip-text bg-gradient-to-r from-white to-gray-500">Security Intelligence Console.</span>
            </h3>

            {/* Feature List */}
            <div className="space-y-8">
              <div className="flex items-start gap-5 group">
                <div className="mt-1 w-12 h-12 rounded-xl bg-purple-500/10 border border-purple-500/20 flex items-center justify-center shrink-0 group-hover:bg-purple-500/20 transition-all duration-300">
                  <Fingerprint className="w-6 h-6 text-purple-400 group-hover:scale-110 transition-transform shadow-[0_0_15px_rgba(168,85,247,0.4)]" />
                </div>
                <div className="space-y-1">
                  <h4 className="text-sm font-black text-foreground uppercase tracking-wider">Credential Security</h4>
                  <p className="text-[11px] text-muted-foreground font-medium leading-relaxed">
                    Advanced detection of exposed API keys and leaked credentials.
                  </p>
                </div>
              </div>

              <div className="flex items-start gap-5 group">
                <div className="mt-1 w-12 h-12 rounded-xl bg-blue-500/10 border border-blue-500/20 flex items-center justify-center shrink-0 group-hover:bg-blue-500/20 transition-all duration-300">
                  <Brain className="w-6 h-6 text-blue-400 group-hover:scale-110 transition-transform shadow-[0_0_15px_rgba(59,130,246,0.4)]" />
                </div>
                <div className="space-y-1">
                  <h4 className="text-sm font-black text-foreground uppercase tracking-wider">Strategic Risk Intelligence</h4>
                  <p className="text-[11px] text-muted-foreground font-medium leading-relaxed">
                    OWASP Top 10 vulnerability detection and threat analysis.
                  </p>
                </div>
              </div>

              <div className="flex items-start gap-5 group">
                <div className="mt-1 w-12 h-12 rounded-xl bg-primary/10 border border-primary/20 flex items-center justify-center shrink-0 group-hover:bg-primary/20 transition-all duration-300">
                  <ShieldCheck className="w-6 h-6 text-primary group-hover:scale-110 transition-transform shadow-[0_0_15px_rgba(0,255,136,0.4)]" />
                </div>
                <div className="space-y-1">
                  <h4 className="text-sm font-black text-foreground uppercase tracking-wider">Multi-Agent Code Security Analyzer</h4>
                  <p className="text-[11px] text-muted-foreground font-medium leading-relaxed">
                    Three independent AI security agents discover, verify, and assess vulnerabilities before they ever reach your security team..
                  </p>
                </div>
              </div>
            </div>
          </motion.div>

          {/* Right Column: Login Form */}
          <div className="flex justify-center lg:justify-end">
            <div className="relative w-full max-w-[440px]">
              <div className="relative backdrop-blur-[20px] bg-background/40 border border-[rgba(0,255,136,0.15)] rounded-xl overflow-hidden shadow-[0_0_50px_rgba(0,0,0,0.5)]">
                <LaserLine />
                <AnimatePresence mode="wait">
                  {showVerification ? (
                    <motion.div
                      key="verification"
                      initial={{ opacity: 0, scale: 0.95 }}
                      animate={{ opacity: 1, scale: 1 }}
                      exit={{ opacity: 0, scale: 1.05 }}
                      className="p-8"
                    >
                      <div className="flex flex-col items-center text-center space-y-6">
                        <ScannerIcon />
                        <div className="space-y-2">
                          <h2 className="text-2xl font-bold tracking-tight text-primary">Identity Authentication</h2>
                          <p className="text-muted-foreground">
                            Decryption link sent to <strong>{registerEmail}</strong>.
                            Verify transmission to activate your portal credentials.
                          </p>
                        </div>
                        <div className="space-y-4 w-full">
                          <motion.div whileHover={{ scale: 1.02 }} whileTap={{ scale: 0.98 }}>
                            <Button
                              onClick={handleResendVerification}
                              disabled={isLoading}
                              className="w-full h-12 bg-transparent border border-[rgba(0,255,136,0.4)] text-primary hover:bg-[rgba(0,255,136,0.1)] hover:shadow-[0_0_15px_rgba(0,255,136,0.3)] transition-all duration-300"
                            >
                              {isLoading ? (
                                <Loader2 className="h-4 w-4 animate-spin mr-2" />
                              ) : (
                                <Mail className="h-4 w-4 mr-2" />
                              )}
                              Resend Uplink
                            </Button>
                          </motion.div>
                          <Button
                            variant="ghost"
                            onClick={() => {
                              setShowVerification(false);
                              setActiveTab("login");
                            }}
                            className="w-full text-muted-foreground hover:text-primary"
                          >
                            Return to Access Point
                          </Button>
                        </div>
                      </div>
                    </motion.div>
                  ) : (
                    <motion.div
                      key="auth"
                      initial={{ opacity: 0 }}
                      animate={{ opacity: 1 }}
                      exit={{ opacity: 0 }}
                    >
                      <div className="flex flex-col items-center pt-8 pb-4">
                        <ScannerIcon />
                      </div>

                      <Tabs value={activeTab} onValueChange={setActiveTab} className="w-full">
                        <TabsList className="grid w-full grid-cols-2 bg-white/5 p-1 rounded-none border-y border-primary/10">
                          <TabsTrigger
                            value="login"
                            className="data-[state=active]:bg-[rgba(0,255,136,0.1)] data-[state=active]:text-primary transition-all rounded-none"
                          >
                            LOGIN
                          </TabsTrigger>
                          <TabsTrigger
                            value="register"
                            className="data-[state=active]:bg-[rgba(0,255,136,0.1)] data-[state=active]:text-primary transition-all rounded-none"
                          >
                            REGISTER
                          </TabsTrigger>
                        </TabsList>

                        <div className="p-8 space-y-6">
                          <div className="mb-2 text-center">
                            <h1 className="text-xl font-bold tracking-widest text-primary uppercase">
                              {activeTab === "login" ? "Security Clearance" : "New Security Operator"}
                            </h1>
                          </div>

                          <TabsContent value="login" className="mt-0 space-y-4">
                            <form onSubmit={handleLogin} className="space-y-4">
                              <div className="space-y-2">
                                <Label className="text-xs text-muted-foreground uppercase tracking-tighter">EMAIL</Label>
                                <div className="relative group">
                                  <Mail className="absolute left-3 top-3 h-4 w-4 text-muted-foreground group-focus-within:text-primary transition-colors z-30" />
                                  <Input
                                    id="login-email"
                                    type="email"
                                    placeholder="Security@Operator.com"
                                    value={loginEmail}
                                    onChange={(e) => setLoginEmail(e.target.value)}
                                    className="pl-10 bg-background/40 border-[rgba(0,255,136,0.12)] focus:border-primary focus:ring-1 focus:ring-[rgba(0,255,136,0.3)] text-muted-foreground placeholder:text-[#3D4F48] h-10 transition-all duration-300 hover:border-[rgba(0,255,136,0.3)] hover:shadow-[0_0_10px_rgba(0,255,136,0.15)] focus:shadow-[0_0_15px_rgba(0,255,136,0.3)]"
                                    required
                                  />
                                </div>
                              </div>
                              <div className="space-y-2">
                                <div className="flex justify-between items-center">
                                  <Label className="text-xs text-muted-foreground uppercase tracking-tighter">PASSWORD</Label>
                                  <span className="text-[10px] text-primary/50 hover:text-primary cursor-pointer transition-colors relative group/link">
                                    Forgot?
                                    <span className="absolute bottom-0 left-1/2 w-0 h-[1px] bg-primary group-hover/link:w-full group-hover/link:left-0 transition-all duration-300 shadow-[0_0_5px_#00FF88]"></span>
                                  </span>
                                </div>
                                <div className="relative group">
                                  <Lock className="absolute left-3 top-3 h-4 w-4 text-muted-foreground group-focus-within:text-primary transition-colors z-30" />
                                  <Input
                                    id="login-password"
                                    type="password"
                                    placeholder="••••••••"
                                    value={loginPassword}
                                    onChange={(e) => setLoginPassword(e.target.value)}
                                    className="pl-10 bg-background/40 border-[rgba(0,255,136,0.12)] focus:border-primary focus:ring-1 focus:ring-[rgba(0,255,136,0.3)] text-muted-foreground placeholder:text-[#3D4F48] h-10 transition-all duration-300 hover:border-[rgba(0,255,136,0.3)] hover:shadow-[0_0_10px_rgba(0,255,136,0.15)] focus:shadow-[0_0_15px_rgba(0,255,136,0.3)]"
                                    required
                                  />
                                </div>
                              </div>
                              <motion.div whileHover={{ scale: 1.01 }} whileTap={{ scale: 0.99 }}>
                                <Button
                                  type="submit"
                                  className="w-full h-11 relative overflow-hidden group bg-[rgba(0,255,136,0.12)] hover:bg-[rgba(0,255,136,0.2)] border border-[rgba(0,255,136,0.4)] transition-all duration-500"
                                  disabled={isLoading}
                                >
                                  <span className="relative z-10 flex items-center justify-center font-bold tracking-widest text-primary uppercase group-hover:text-foreground transition-colors duration-300">
                                    {isLoading ? (
                                      <Loader2 className="h-4 w-4 animate-spin mr-2" />
                                    ) : null}
                                    ESTABLISH CONNECTION
                                  </span>
                                  <motion.div
                                    initial={{ opacity: 0, scale: 0 }}
                                    whileHover={{ opacity: 1, scale: 2 }}
                                    transition={{ duration: 0.5, ease: "easeOut" }}
                                    className="absolute inset-0 z-0 bg-[radial-gradient(circle,rgba(0,255,136,0.4)_0%,rgba(0,200,83,0.2)_60%,transparent_100%)] pointer-events-none"
                                  />
                                </Button>
                              </motion.div>

                              <div className="pt-2 text-center">
                                <span
                                  onClick={() => setActiveTab("register")}
                                  className="text-[10px] text-muted-foreground hover:text-primary cursor-pointer transition-colors relative group/link uppercase tracking-widest font-bold"
                                >
                                  New Operator? Register Signal
                                  <span className="absolute -bottom-1 left-1/2 w-0 h-[1px] bg-primary group-hover/link:w-full group-hover/link:left-0 transition-all duration-300 shadow-[0_0_5px_#00FF88]"></span>
                                </span>
                              </div>
                            </form>
                          </TabsContent>

                          <TabsContent value="register" className="mt-0 space-y-4">
                            <form onSubmit={handleRegister} className="space-y-4">
                              <div className="space-y-2">
                                <Label className="text-xs text-muted-foreground uppercase tracking-tighter">Name Handle</Label>
                                <div className="relative group">
                                  <User className="absolute left-3 top-3 h-4 w-4 text-muted-foreground group-focus-within:text-primary transition-colors z-30" />
                                  <Input
                                    id="register-name"
                                    type="text"
                                    placeholder="Security_Agent"
                                    value={registerName}
                                    onChange={(e) => setRegisterName(e.target.value)}
                                    className="pl-10 bg-background/40 border-[rgba(0,255,136,0.12)] focus:border-primary focus:ring-1 focus:ring-[rgba(0,255,136,0.3)] text-muted-foreground placeholder:text-[#3D4F48] h-10 transition-all duration-300 hover:border-[rgba(0,255,136,0.3)] hover:shadow-[0_0_10px_rgba(0,255,136,0.15)] focus:shadow-[0_0_15px_rgba(0,255,136,0.3)]"
                                    required
                                  />
                                </div>
                              </div>
                              <div className="space-y-2">
                                <Label className="text-xs text-muted-foreground uppercase tracking-tighter">EMAIL ADDRESS</Label>
                                <div className="relative group">
                                  <Mail className="absolute left-3 top-3 h-4 w-4 text-muted-foreground group-focus-within:text-primary transition-colors z-30" />
                                  <Input
                                    id="register-email"
                                    type="email"
                                    placeholder="Security@Operator.com"
                                    value={registerEmail}
                                    onChange={(e) => setRegisterEmailState(e.target.value)}
                                    className="pl-10 bg-background/40 border-[rgba(0,255,136,0.12)] focus:border-primary focus:ring-1 focus:ring-[rgba(0,255,136,0.3)] text-muted-foreground placeholder:text-[#3D4F48] h-10 transition-all duration-300 hover:border-[rgba(0,255,136,0.3)] hover:shadow-[0_0_10px_rgba(0,255,136,0.15)] focus:shadow-[0_0_15px_rgba(0,255,136,0.3)]"
                                    required
                                  />
                                </div>
                              </div>
                              <div className="grid grid-cols-2 gap-4">
                                <div className="space-y-2">
                                  <Label className="text-xs text-muted-foreground uppercase tracking-tighter">PASSWORD</Label>
                                  <Input
                                    id="register-password"
                                    type="password"
                                    placeholder="••••"
                                    value={registerPassword}
                                    onChange={(e) => setRegisterPassword(e.target.value)}
                                    className="bg-background/40 border-[rgba(0,255,136,0.12)] focus:border-primary focus:ring-1 focus:ring-[rgba(0,255,136,0.3)] text-muted-foreground placeholder:text-[#3D4F48] h-10 transition-all duration-300 hover:border-[rgba(0,255,136,0.3)] hover:shadow-[0_0_10px_rgba(0,255,136,0.15)] focus:shadow-[0_0_15px_rgba(0,255,136,0.3)]"
                                    required
                                    minLength={6}
                                  />
                                </div>
                                <div className="space-y-2">
                                  <Label className="text-xs text-muted-foreground uppercase tracking-tighter">Confirm</Label>
                                  <Input
                                    id="confirm-password"
                                    type="password"
                                    placeholder="••••"
                                    value={confirmPassword}
                                    onChange={(e) => setConfirmPassword(e.target.value)}
                                    className="bg-background/40 border-[rgba(0,255,136,0.12)] focus:border-primary focus:ring-1 focus:ring-[rgba(0,255,136,0.3)] text-muted-foreground placeholder:text-[#3D4F48] h-10 transition-all duration-300 hover:border-[rgba(0,255,136,0.3)] hover:shadow-[0_0_10px_rgba(0,255,136,0.15)] focus:shadow-[0_0_15px_rgba(0,255,136,0.3)]"
                                    required
                                  />
                                </div>
                              </div>
                              <motion.div whileHover={{ scale: 1.01 }} whileTap={{ scale: 0.99 }}>
                                <Button
                                  type="submit"
                                  className="w-full h-11 relative overflow-hidden group bg-[rgba(0,255,136,0.12)] hover:bg-[rgba(0,255,136,0.2)] border border-[rgba(0,255,136,0.4)] transition-all duration-500"
                                  disabled={isLoading}
                                >
                                  <span className="relative z-10 flex items-center justify-center font-bold tracking-widest text-primary uppercase group-hover:text-foreground transition-colors duration-300">
                                    {isLoading ? (
                                      <Loader2 className="h-4 w-4 animate-spin mr-2" />
                                    ) : null}
                                    INITIALIZE ACCESS
                                  </span>
                                  <motion.div
                                    initial={{ opacity: 0, scale: 0 }}
                                    whileHover={{ opacity: 1, scale: 2 }}
                                    transition={{ duration: 0.5, ease: "easeOut" }}
                                    className="absolute inset-0 z-0 bg-[radial-gradient(circle,rgba(0,255,136,0.4)_0%,rgba(0,200,83,0.2)_60%,transparent_100%)] pointer-events-none"
                                  />
                                </Button>
                              </motion.div>

                              <div className="pt-2 text-center">
                                <span
                                  onClick={() => setActiveTab("login")}
                                  className="text-[10px] text-muted-foreground hover:text-primary cursor-pointer transition-colors relative group/link uppercase tracking-widest font-bold"
                                >
                                  Existing Access? Return to Base
                                  <span className="absolute -bottom-1 left-1/2 w-0 h-[1px] bg-primary group-hover/link:w-full group-hover/link:left-0 transition-all duration-300 shadow-[0_0_5px_#00FF88]"></span>
                                </span>
                              </div>
                            </form>
                          </TabsContent>

                          <div className="relative">
                            <div className="absolute inset-0 flex items-center">
                              <span className="w-full border-t border-primary/10" />
                            </div>
                            <div className="relative flex justify-center text-[10px] uppercase font-bold tracking-[0.2em]">
                              <span className="bg-background px-4 text-muted-foreground">
                                Secure Redirect
                              </span>
                            </div>
                          </div>

                          <motion.div whileHover={{ scale: 1.01 }} whileTap={{ scale: 0.99 }}>
                            <Button
                              variant="outline"
                              type="button"
                              onClick={handleGoogleSignIn}
                              disabled={isLoading}
                              className="w-full h-11 relative overflow-hidden group bg-white/5 border-[rgba(0,255,136,0.12)] hover:bg-[rgba(0,255,136,0.08)] hover:border-[rgba(0,255,136,0.35)] text-muted-foreground hover:text-primary transition-all duration-300"
                            >
                              <span className="relative z-10 flex items-center justify-center font-bold tracking-widest uppercase">
                                <Chrome className="h-4 w-4 mr-2 group-hover:animate-pulse" />
                                OAUTH 2.0 (GOOGLE)
                              </span>
                              <motion.div
                                initial={{ opacity: 0, scale: 0 }}
                                whileHover={{ opacity: 1, scale: 2 }}
                                transition={{ duration: 0.5, ease: "easeOut" }}
                                className="absolute inset-0 z-0 bg-[radial-gradient(circle,rgba(0,255,136,0.2)_0%,transparent_100%)] pointer-events-none"
                              />
                            </Button>
                          </motion.div>

                          <p className="text-[10px] text-center text-[#3D4F48] font-bold tracking-widest uppercase mt-4">
                            Encrypted End-to-End • Enterprise-Grade Auth
                          </p>
                        </div>
                      </Tabs>
                    </motion.div>
                  )}
                </AnimatePresence>
              </div>
            </div>
          </div>
        </div>
      </div>

      <style jsx global>{`
        @keyframes gradient {
          0% { background-position: 0% 50%; }
          50% { background-position: 100% 50%; }
          100% { background-position: 0% 50%; }
        }
        .animate-gradient {
          animation: gradient 3s linear infinite;
        }
        .font-outfit {
          font-family: var(--font-outfit), system-ui, sans-serif;
        }
      `}</style>
    </div>
  );
}
