"use client";

import { useState, useEffect } from "react";
import { motion, AnimatePresence } from "framer-motion";
import { Button } from "@/components/ui/button";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogHeader,
  DialogTitle,
  DialogTrigger,
} from "@/components/ui/dialog";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { useAuth } from "@/contexts/auth-context";
import {
  Mail,
  Lock,
  User,
  Chrome,
  Loader2,
  AlertCircle,
  CheckCircle,
  Zap,
} from "lucide-react";
import { toast } from "sonner";

interface AuthDialogProps {
  trigger?: React.ReactNode;
  defaultOpen?: boolean;
  open?: boolean;
  onOpenChange?: (open: boolean) => void;
}

const ScannerIcon = () => (
  <div className="relative w-16 h-16 flex items-center justify-center">
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
    <Zap className="w-6 h-6 text-primary" />
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

export function AuthDialog({ trigger, defaultOpen = false, open: controlledOpen, onOpenChange: setControlledOpen }: AuthDialogProps) {
  const [internalOpen, setInternalOpen] = useState(defaultOpen);
  const open = controlledOpen !== undefined ? controlledOpen : internalOpen;
  const setOpen = setControlledOpen !== undefined ? setControlledOpen : setInternalOpen;
  const [activeTab, setActiveTab] = useState("login");
  const [isLoading, setIsLoading] = useState(false);
  const { login, register, loginWithGoogle, isEmailVerified, resendVerificationEmail } = useAuth();

  // Login form state
  const [loginEmail, setLoginEmail] = useState("");
  const [loginPassword, setLoginPassword] = useState("");

  // Register form state
  const [registerName, setRegisterName] = useState("");
  const [registerEmail, setRegisterEmail] = useState("");
  const [registerPassword, setRegisterPassword] = useState("");
  const [confirmPassword, setConfirmPassword] = useState("");
  const [showVerification, setShowVerification] = useState(false);

  const handleLogin = async (e: React.FormEvent) => {
    e.preventDefault();
    setIsLoading(true);
    try {
      await login(loginEmail, loginPassword);
      setOpen(false);
      // Redirect to dashboard after successful login
      window.location.href = "/dashboard";
    } catch (error) {
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
      setShowVerification(true);
    } catch (error) {
    } finally {
      setIsLoading(false);
    }
  };

  const handleGoogleSignIn = async () => {
    setIsLoading(true);
    try {
      await loginWithGoogle();
      setOpen(false);
      // Redirect to dashboard after successful Google sign-in
      window.location.href = "/dashboard";
    } catch (error) {
    } finally {
      setIsLoading(false);
    }
  };

  const handleResendVerification = async () => {
    setIsLoading(true);
    try {
      await resendVerificationEmail();
    } catch (error) {
    } finally {
      setIsLoading(false);
    }
  };

  return (
    <Dialog open={open} onOpenChange={setOpen}>
      <DialogTrigger asChild>
        {trigger || (
          <Button variant="outline" size="sm">
            <User className="h-4 w-4 mr-2" />
            Sign In
          </Button>
        )}
      </DialogTrigger>
      <DialogContent className="sm:max-w-[450px] p-0 border-none bg-transparent shadow-2xl overflow-hidden font-mono">
        {/* Background Layer */}
        <div className="absolute inset-0 bg-[#050505] z-[-2]" />
        <GridBackground />
        <LaserLine />

        {/* Main Content Container */}
        <div className="relative z-20 backdrop-blur-[20px] bg-black/40 border border-[rgba(0,255,136,0.15)] rounded-xl overflow-hidden shadow-[0_0_50px_rgba(0,0,0,0.5)]">
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
                  <DialogHeader>
                    <DialogTitle className="text-2xl font-bold tracking-tight text-primary">Identity Authentication</DialogTitle>
                    <DialogDescription className="text-muted-foreground">
                      Decryption link sent to <strong>{registerEmail}</strong>.
                      Verify transmission to activate your portal credentials.
                    </DialogDescription>
                  </DialogHeader>
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
                      ACCESS
                    </TabsTrigger>
                    <TabsTrigger
                      value="register"
                      className="data-[state=active]:bg-[rgba(0,255,136,0.1)] data-[state=active]:text-primary transition-all rounded-none"
                    >
                      INITIALIZE
                    </TabsTrigger>
                  </TabsList>

                  <div className="p-8 space-y-6">
                    <DialogHeader className="mb-2">
                      <DialogTitle className="text-xl font-bold tracking-widest text-center text-primary uppercase">
                        {activeTab === "login" ? "Security Clearance" : "New Operator Signal"}
                      </DialogTitle>
                    </DialogHeader>

                    <TabsContent value="login" className="mt-0 space-y-4">
                      <form onSubmit={handleLogin} className="space-y-4">
                        <div className="space-y-2">
                          <Label className="text-xs text-muted-foreground uppercase tracking-tighter">Terminal ID (Email)</Label>
                          <div className="relative group">
                            <Mail className="absolute left-3 top-3 h-4 w-4 text-muted-foreground group-focus-within:text-primary transition-colors z-30" />
                            <Input
                              id="login-email"
                              type="email"
                              placeholder="operator@nexus.sys"
                              value={loginEmail}
                              onChange={(e) => setLoginEmail(e.target.value)}
                              className="pl-10 bg-black/40 border-[rgba(0,255,136,0.12)] focus:border-primary focus:ring-1 focus:ring-[rgba(0,255,136,0.3)] text-muted-foreground placeholder:text-[#3D4F48] h-10 transition-all duration-300 hover:border-[rgba(0,255,136,0.3)] hover:shadow-[0_0_10px_rgba(0,255,136,0.15)] focus:shadow-[0_0_15px_rgba(0,255,136,0.3)]"
                              required
                            />
                          </div>
                        </div>
                        <div className="space-y-2">
                          <div className="flex justify-between items-center">
                            <Label className="text-xs text-muted-foreground uppercase tracking-tighter">Cipher (Password)</Label>
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
                              className="pl-10 bg-black/40 border-[rgba(0,255,136,0.12)] focus:border-primary focus:ring-1 focus:ring-[rgba(0,255,136,0.3)] text-muted-foreground placeholder:text-[#3D4F48] h-10 transition-all duration-300 hover:border-[rgba(0,255,136,0.3)] hover:shadow-[0_0_10px_rgba(0,255,136,0.15)] focus:shadow-[0_0_15px_rgba(0,255,136,0.3)]"
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
                            <span className="relative z-10 flex items-center justify-center font-bold tracking-widest text-primary uppercase group-hover:text-white transition-colors duration-300">
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
                          <Label className="text-xs text-muted-foreground uppercase tracking-tighter">Operator Handle</Label>
                          <div className="relative group">
                            <User className="absolute left-3 top-3 h-4 w-4 text-muted-foreground group-focus-within:text-primary transition-colors z-30" />
                            <Input
                              id="register-name"
                              type="text"
                              placeholder="GHOST_PROTOCOL"
                              value={registerName}
                              onChange={(e) => setRegisterName(e.target.value)}
                              className="pl-10 bg-black/40 border-[rgba(0,255,136,0.12)] focus:border-primary focus:ring-1 focus:ring-[rgba(0,255,136,0.3)] text-muted-foreground placeholder:text-[#3D4F48] h-10 transition-all duration-300 hover:border-[rgba(0,255,136,0.3)] hover:shadow-[0_0_10px_rgba(0,255,136,0.15)] focus:shadow-[0_0_15px_rgba(0,255,136,0.3)]"
                              required
                            />
                          </div>
                        </div>
                        <div className="space-y-2">
                          <Label className="text-xs text-muted-foreground uppercase tracking-tighter">Terminal ID</Label>
                          <div className="relative group">
                            <Mail className="absolute left-3 top-3 h-4 w-4 text-muted-foreground group-focus-within:text-primary transition-colors z-30" />
                            <Input
                              id="register-email"
                              type="email"
                              placeholder="operator@nexus.sys"
                              value={registerEmail}
                              onChange={(e) => setRegisterEmail(e.target.value)}
                              className="pl-10 bg-black/40 border-[rgba(0,255,136,0.12)] focus:border-primary focus:ring-1 focus:ring-[rgba(0,255,136,0.3)] text-muted-foreground placeholder:text-[#3D4F48] h-10 transition-all duration-300 hover:border-[rgba(0,255,136,0.3)] hover:shadow-[0_0_10px_rgba(0,255,136,0.15)] focus:shadow-[0_0_15px_rgba(0,255,136,0.3)]"
                              required
                            />
                          </div>
                        </div>
                        <div className="grid grid-cols-2 gap-4">
                          <div className="space-y-2">
                            <Label className="text-xs text-muted-foreground uppercase tracking-tighter">Cipher</Label>
                            <Input
                              id="register-password"
                              type="password"
                              placeholder="••••"
                              value={registerPassword}
                              onChange={(e) => setRegisterPassword(e.target.value)}
                              className="bg-black/40 border-[rgba(0,255,136,0.12)] focus:border-primary focus:ring-1 focus:ring-[rgba(0,255,136,0.3)] text-muted-foreground placeholder:text-[#3D4F48] h-10 transition-all duration-300 hover:border-[rgba(0,255,136,0.3)] hover:shadow-[0_0_10px_rgba(0,255,136,0.15)] focus:shadow-[0_0_15px_rgba(0,255,136,0.3)]"
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
                              className="bg-black/40 border-[rgba(0,255,136,0.12)] focus:border-primary focus:ring-1 focus:ring-[rgba(0,255,136,0.3)] text-muted-foreground placeholder:text-[#3D4F48] h-10 transition-all duration-300 hover:border-[rgba(0,255,136,0.3)] hover:shadow-[0_0_10px_rgba(0,255,136,0.15)] focus:shadow-[0_0_15px_rgba(0,255,136,0.3)]"
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
                            <span className="relative z-10 flex items-center justify-center font-bold tracking-widest text-primary uppercase group-hover:text-white transition-colors duration-300">
                              {isLoading ? (
                                <Loader2 className="h-4 w-4 animate-spin mr-2" />
                              ) : null}
                              INITIALIZE PROTOCOL
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
                      Encrypted End-to-End • Secure Authentication                    </p>
                  </div>
                </Tabs>
              </motion.div>
            )}
          </AnimatePresence>
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
        `}</style>
      </DialogContent>
    </Dialog>
  );
}
