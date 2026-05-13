"use client";

import { useAuth } from "@/contexts/auth-context";
import { motion } from "framer-motion";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Mail, Loader2, AlertCircle, CheckCircle } from "lucide-react";
import { useState } from "react";
import { toast } from "sonner";

interface EmailVerificationCheckProps {
  children: React.ReactNode;
}

export function EmailVerificationCheck({ children }: EmailVerificationCheckProps) {
  const { user, isAuthenticated, isEmailVerified, resendVerificationEmail } = useAuth();
  const [isResending, setIsResending] = useState(false);

  const handleResendVerification = async () => {
    setIsResending(true);
    try {
      await resendVerificationEmail();
    } catch (error) {
      // Error handled in context
    } finally {
      setIsResending(false);
    }
  };

  // If not authenticated, show the verification gate anyway - they'll need to log in
  // If authenticated but not verified, show verification required
  if (isAuthenticated && !isEmailVerified) {
    return (
      <div className="min-h-screen flex items-center justify-center p-4 gradient-mesh">
        <motion.div
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.5 }}
          className="w-full max-w-md"
        >
          <Card className="card-elevated">
            <CardHeader className="text-center">
              <div className="mx-auto w-16 h-16 bg-yellow-500/10 rounded-full flex items-center justify-center mb-4">
                <AlertCircle className="h-8 w-8 text-yellow-500" />
              </div>
              <CardTitle className="text-2xl">Email Verification Required</CardTitle>
              <CardDescription>
                Please verify your email address to access the dashboard and tools.
              </CardDescription>
            </CardHeader>
            <CardContent className="space-y-4">
              <div className="p-4 bg-muted rounded-lg">
                <p className="text-sm text-muted-foreground mb-2">
                  We sent a verification email to:
                </p>
                <p className="font-medium text-center">{user?.email}</p>
              </div>

              <p className="text-sm text-muted-foreground text-center">
                Click the verification link in the email to activate your account. 
                If you don&apos;t see the email, check your spam folder or request a new one.
              </p>

              <div className="flex flex-col gap-2">
                <Button 
                  onClick={handleResendVerification} 
                  disabled={isResending}
                  className="w-full"
                >
                  {isResending ? (
                    <>
                      <Loader2 className="h-4 w-4 animate-spin mr-2" />
                      Sending...
                    </>
                  ) : (
                    <>
                      <Mail className="h-4 w-4 mr-2" />
                      Resend Verification Email
                    </>
                  )}
                </Button>
                <Button variant="outline" onClick={() => window.location.reload()}>
                  I&apos;ve Verified My Email
                </Button>
              </div>

              <p className="text-xs text-muted-foreground text-center">
                Need help? Contact support at support@secretscanner.com
              </p>
            </CardContent>
          </Card>
        </motion.div>
      </div>
    );
  }

  return <>{children}</>;
}
